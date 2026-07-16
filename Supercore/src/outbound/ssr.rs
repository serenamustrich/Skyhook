use std::{
    io::Cursor,
    net::SocketAddr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use aes::cipher::{Block, BlockEncrypt, KeyInit as BlockKeyInit};
use aes::{Aes128, Aes192, Aes256};
use anyhow::{anyhow, Context};
use async_trait::async_trait;
use bytes::BytesMut;
use cfb_mode::cipher::KeyIvInit;
use md5::{Digest, Md5};
use sha1::Sha1;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream},
    net::UdpSocket,
    time::timeout,
};

use crate::routing::Destination;

use super::{
    connect_tcp, encode_socks5_destination, parse_socks5_destination_prefix,
    resolve_udp_socket_addr,
    shadowsocks::{
        evp_bytes_to_key, read_http_obfs_response, read_simple_obfs_tls_record,
        wrap_simple_obfs_tls_app_data,
    },
    BoxedStream, Outbound, OutboundCapability,
};

pub(super) struct SsrOutbound {
    name: String,
    server: String,
    port: u16,
    method: String,
    password: String,
    protocol: String,
    obfs: String,
    protocol_param: Option<String>,
    obfs_param: Option<String>,
}

impl SsrOutbound {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        name: String,
        server: String,
        port: u16,
        method: String,
        password: String,
        protocol: String,
        obfs: String,
        protocol_param: Option<String>,
        obfs_param: Option<String>,
    ) -> Self {
        Self {
            name,
            server,
            port,
            method,
            password,
            protocol,
            obfs,
            protocol_param,
            obfs_param,
        }
    }
}

#[async_trait]
impl Outbound for SsrOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "ssr"
    }

    fn capability(&self) -> OutboundCapability {
        let mut limitations = Vec::new();
        let method_supported = SsrCipher::from_method(&self.method).is_ok();
        let protocol = ssr_protocol_kind(&self.protocol);
        let protocol_supported = protocol.is_ok();
        let obfs_supported = ssr_obfs_mode(&self.obfs).is_ok();
        if !method_supported {
            limitations.push(format!("unsupported ssr method {}", self.method));
        }
        if !protocol_supported {
            limitations.push(format!("unsupported ssr protocol {}", self.protocol));
        }
        if !obfs_supported {
            limitations.push(format!("unsupported ssr obfs {}", self.obfs));
        }
        let udp_supported = method_supported
            && obfs_supported
            && protocol
                .as_ref()
                .is_ok_and(|value| *value != SsrProtocolKind::AuthSha1V4);
        if protocol
            .as_ref()
            .is_ok_and(|value| *value == SsrProtocolKind::AuthSha1V4)
        {
            limitations.push("ssr auth_sha1_v4 udp is not supported".to_string());
        }
        OutboundCapability {
            tcp_supported: method_supported && protocol_supported && obfs_supported,
            udp_supported,
            udp_mode: Some(if udp_supported {
                "ssr-datagram-stream-cipher".to_string()
            } else {
                "ssr-authenticated-tcp".to_string()
            }),
            limitations,
        }
    }

    async fn connect(
        &self,
        destination: &Destination,
        timeout_ms: u64,
    ) -> anyhow::Result<BoxedStream> {
        let protocol = ssr_protocol_kind(&self.protocol)?;
        if protocol == SsrProtocolKind::Origin
            && self
                .protocol_param
                .as_deref()
                .is_some_and(|value| !value.trim().is_empty())
        {
            tracing::debug!(name = %self.name, "SSR origin ignores protocol_param");
        }
        let obfs = ssr_obfs_mode(&self.obfs)?;

        let cipher = SsrCipher::from_method(&self.method)?;
        let key = evp_bytes_to_key(self.password.as_bytes(), cipher.key_len());
        let mut iv = vec![0u8; cipher.iv_len()];
        getrandom::fill(&mut iv).map_err(|error| anyhow!("failed to generate ssr iv: {error}"))?;
        let mut upload = cipher.encryptor(&key, &iv)?;
        let mut destination_payload = Vec::new();
        encode_socks5_destination(destination, &mut destination_payload)?;
        let mut protocol_encoder =
            SsrProtocolEncoder::new(protocol, &iv, &key, self.protocol_param.as_deref())?;
        destination_payload = protocol_encoder.encode(&destination_payload)?;
        let protocol_decoder = protocol_encoder.decoder()?;
        upload.apply(&mut destination_payload);

        let mut initial = iv;
        initial.extend_from_slice(&destination_payload);
        if matches!(obfs, SsrObfsMode::HttpSimple | SsrObfsMode::HttpPost) {
            initial = build_ssr_http_obfs_request(
                obfs,
                self.obfs_param.as_deref().unwrap_or(&self.server),
                self.port,
                &initial,
            )?;
        }

        let tcp = connect_tcp(&format!("{}:{}", self.server, self.port), timeout_ms).await?;
        let mut stream: BoxedStream = Box::new(tcp);
        if obfs == SsrObfsMode::Tls12TicketAuth {
            let (client_hello, client_id) = build_ssr_tls12_ticket_client_hello(
                self.obfs_param.as_deref().unwrap_or(&self.server),
                &key,
            )?;
            stream.write_all(&client_hello).await?;
            stream.flush().await?;
            return Ok(Box::new(spawn_ssr_tls12_ticket_stream(
                cipher,
                key,
                upload,
                stream,
                protocol_encoder,
                protocol_decoder,
                initial,
                client_id,
            )));
        }
        stream.write_all(&initial).await?;
        stream.flush().await?;
        Ok(Box::new(spawn_ssr_stream(
            cipher,
            key,
            upload,
            stream,
            obfs,
            protocol_encoder,
            protocol_decoder,
        )))
    }

    async fn udp_exchange(
        &self,
        destination: &Destination,
        payload: &[u8],
        timeout_ms: u64,
    ) -> anyhow::Result<Vec<u8>> {
        let protocol = ssr_protocol_kind(&self.protocol)?;
        if protocol == SsrProtocolKind::AuthSha1V4 {
            return Err(anyhow!("ssr auth_sha1_v4 UDP is not supported"));
        }
        let cipher = SsrCipher::from_method(&self.method)?;
        let key = evp_bytes_to_key(self.password.as_bytes(), cipher.key_len());
        let mut iv = vec![0u8; cipher.iv_len()];
        getrandom::fill(&mut iv)
            .map_err(|error| anyhow!("failed to generate ssr UDP iv: {error}"))?;
        let mut plaintext = Vec::with_capacity(payload.len() + destination.host.len() + 20);
        encode_socks5_destination(destination, &mut plaintext)?;
        plaintext.extend_from_slice(payload);
        let chain_user_key = if ssr_is_auth_chain(protocol) {
            let (uid, user_key) = ssr_chain_user_credentials(self.protocol_param.as_deref(), &key)?;
            plaintext = ssr_auth_chain_udp_encode(&plaintext, &key, &user_key, uid)?;
            Some(user_key)
        } else {
            None
        };
        let response_hash = if let Some(hash) = ssr_auth_hash(protocol) {
            let (uid, user_key) = ssr_user_credentials(hash, self.protocol_param.as_deref(), &key)?;
            plaintext.extend_from_slice(&uid);
            let hmac = hash.hmac(&user_key, &plaintext);
            plaintext.extend_from_slice(&hmac[..4]);
            Some(hash)
        } else {
            None
        };
        cipher.encryptor(&key, &iv)?.apply(&mut plaintext);
        let mut packet = iv;
        packet.extend_from_slice(&plaintext);

        let server = resolve_udp_socket_addr(&self.server, self.port, timeout_ms).await?;
        let bind_addr = match server {
            SocketAddr::V4(_) => "0.0.0.0:0",
            SocketAddr::V6(_) => "[::]:0",
        };
        let socket = UdpSocket::bind(bind_addr)
            .await
            .context("failed to bind SSR UDP socket")?;
        let exchange = async {
            socket
                .send_to(&packet, server)
                .await
                .context("failed to send SSR UDP packet")?;
            let mut response = vec![0u8; 65_535];
            let (length, source) = socket
                .recv_from(&mut response)
                .await
                .context("failed to receive SSR UDP response")?;
            if source != server {
                return Err(anyhow!(
                    "SSR UDP response came from unexpected source {source}"
                ));
            }
            response.truncate(length);
            if response.len() <= cipher.iv_len() {
                return Err(anyhow!("SSR UDP response is too short"));
            }
            let response_iv = response[..cipher.iv_len()].to_vec();
            let mut plaintext = response[cipher.iv_len()..].to_vec();
            cipher.decryptor(&key, &response_iv)?.apply(&mut plaintext);
            if let Some(user_key) = chain_user_key.as_deref() {
                plaintext = ssr_auth_chain_udp_decode(&plaintext, &key, user_key)?;
            }
            if let Some(hash) = response_hash {
                if plaintext.len() <= 4 {
                    return Err(anyhow!("SSR authenticated UDP response is too short"));
                }
                let hmac_offset = plaintext.len() - 4;
                let expected = hash.hmac(&key, &plaintext[..hmac_offset]);
                if plaintext[hmac_offset..] != expected[..4] {
                    return Err(anyhow!("SSR authenticated UDP response HMAC failed"));
                }
                plaintext.truncate(hmac_offset);
            }
            let (_source, payload_offset) = parse_socks5_destination_prefix(&plaintext)?;
            Ok(plaintext[payload_offset..].to_vec())
        };
        timeout(Duration::from_millis(timeout_ms), exchange)
            .await
            .context("SSR UDP exchange timed out")?
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SsrObfsMode {
    Plain,
    HttpSimple,
    HttpPost,
    Tls12TicketAuth,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SsrProtocolKind {
    Origin,
    VerifySimple,
    AuthSimple,
    AuthSha1,
    AuthSha1V2,
    AuthSha1V4,
    AuthAes128Md5,
    AuthAes128Sha1,
    AuthChainA,
    AuthChainB,
    AuthChainC,
    AuthChainD,
    AuthChainE,
    AuthChainF,
}

fn ssr_is_auth_chain(kind: SsrProtocolKind) -> bool {
    matches!(
        kind,
        SsrProtocolKind::AuthChainA
            | SsrProtocolKind::AuthChainB
            | SsrProtocolKind::AuthChainC
            | SsrProtocolKind::AuthChainD
            | SsrProtocolKind::AuthChainE
            | SsrProtocolKind::AuthChainF
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SsrAuthHash {
    Md5,
    Sha1,
}

impl SsrAuthHash {
    fn hmac(self, key: &[u8], message: &[u8]) -> Vec<u8> {
        match self {
            Self::Md5 => ssr_hmac_md5(key, message).to_vec(),
            Self::Sha1 => ssr_hmac_sha1(key, message).to_vec(),
        }
    }

    fn hash(self, value: &[u8]) -> Vec<u8> {
        match self {
            Self::Md5 => Md5::digest(value).to_vec(),
            Self::Sha1 => Sha1::digest(value).to_vec(),
        }
    }
}

struct SsrProtocolEncoder {
    kind: SsrProtocolKind,
    request_iv: Vec<u8>,
    key: Vec<u8>,
    client_id: [u8; 4],
    legacy_client_id: [u8; 8],
    connection_id: u32,
    sent_header: bool,
    user_key: Vec<u8>,
    uid: [u8; 4],
    pack_id: u32,
    chain_cipher: Option<SsrStreamCipher>,
    chain_key_hash: [u8; 16],
    chain_f_epoch: u64,
    last_client_hash: [u8; 16],
    last_server_hash: [u8; 16],
}

impl SsrProtocolEncoder {
    fn new(
        kind: SsrProtocolKind,
        request_iv: &[u8],
        key: &[u8],
        protocol_param: Option<&str>,
    ) -> anyhow::Result<Self> {
        let mut client_id = [0u8; 4];
        getrandom::fill(&mut client_id)
            .map_err(|error| anyhow!("failed to generate SSR client id: {error}"))?;
        let mut legacy_client_id = [0u8; 8];
        getrandom::fill(&mut legacy_client_id)
            .map_err(|error| anyhow!("failed to generate SSR legacy client id: {error}"))?;
        let mut connection_id = [0u8; 4];
        getrandom::fill(&mut connection_id)
            .map_err(|error| anyhow!("failed to generate SSR connection id: {error}"))?;
        let (uid, user_key) = match ssr_auth_hash(kind) {
            Some(hash) => ssr_user_credentials(hash, protocol_param, key)?,
            None if ssr_is_auth_chain(kind) => ssr_chain_user_credentials(protocol_param, key)?,
            None => ([0u8; 4], key.to_vec()),
        };
        Ok(Self {
            kind,
            request_iv: request_iv.to_vec(),
            key: key.to_vec(),
            client_id,
            legacy_client_id,
            connection_id: u32::from_le_bytes(connection_id) & 0x00ff_ffff,
            sent_header: false,
            user_key,
            uid,
            pack_id: 1,
            chain_cipher: None,
            chain_key_hash: [0u8; 16],
            chain_f_epoch: ssr_auth_chain_f_epoch(protocol_param),
            last_client_hash: [0u8; 16],
            last_server_hash: [0u8; 16],
        })
    }

    fn decoder(&self) -> anyhow::Result<SsrProtocolDecoder> {
        let chain_cipher = if ssr_is_auth_chain(self.kind) {
            Some(ssr_auth_chain_rc4(&self.user_key, &self.chain_key_hash)?)
        } else {
            None
        };
        Ok(SsrProtocolDecoder::new(
            self.kind,
            self.key.clone(),
            self.user_key.clone(),
            chain_cipher,
            self.chain_f_epoch,
            self.last_server_hash,
        ))
    }

    fn encode(&mut self, payload: &[u8]) -> anyhow::Result<Vec<u8>> {
        match self.kind {
            SsrProtocolKind::Origin => Ok(payload.to_vec()),
            SsrProtocolKind::VerifySimple => build_ssr_legacy_crc_data(payload),
            SsrProtocolKind::AuthSimple if !self.sent_header => {
                self.sent_header = true;
                self.connection_id = self.connection_id.wrapping_add(1);
                build_ssr_auth_simple_header(payload, self.legacy_client_id, self.connection_id)
            }
            SsrProtocolKind::AuthSimple => build_ssr_legacy_crc_data(payload),
            SsrProtocolKind::AuthSha1 if !self.sent_header => {
                self.sent_header = true;
                self.connection_id = self.connection_id.wrapping_add(1);
                build_ssr_auth_sha1_header(
                    payload,
                    &self.request_iv,
                    &self.key,
                    self.client_id,
                    self.connection_id,
                )
            }
            SsrProtocolKind::AuthSha1 => build_ssr_legacy_adler_data(payload, false),
            SsrProtocolKind::AuthSha1V2 if !self.sent_header => {
                self.sent_header = true;
                self.connection_id = self.connection_id.wrapping_add(1);
                build_ssr_auth_sha1_v2_header(
                    payload,
                    &self.request_iv,
                    &self.key,
                    self.legacy_client_id,
                    self.connection_id,
                )
            }
            SsrProtocolKind::AuthSha1V2 => build_ssr_legacy_adler_data(payload, true),
            SsrProtocolKind::AuthSha1V4 if !self.sent_header => {
                self.sent_header = true;
                self.connection_id = self.connection_id.wrapping_add(1);
                build_ssr_auth_sha1_v4_header(
                    payload,
                    &self.request_iv,
                    &self.key,
                    self.client_id,
                    self.connection_id,
                )
            }
            SsrProtocolKind::AuthSha1V4 => build_ssr_auth_sha1_v4_data(payload),
            SsrProtocolKind::AuthAes128Md5 | SsrProtocolKind::AuthAes128Sha1
                if !self.sent_header =>
            {
                self.sent_header = true;
                self.connection_id = self.connection_id.wrapping_add(1);
                build_ssr_auth_aes128_header(
                    self.kind,
                    payload,
                    &self.request_iv,
                    &self.key,
                    &self.user_key,
                    self.uid,
                    self.client_id,
                    self.connection_id,
                )
            }
            SsrProtocolKind::AuthAes128Md5 | SsrProtocolKind::AuthAes128Sha1 => {
                let packet =
                    build_ssr_auth_aes128_data(self.kind, payload, &self.user_key, self.pack_id)?;
                self.pack_id = self.pack_id.wrapping_add(1);
                Ok(packet)
            }
            kind if ssr_is_auth_chain(kind) && !self.sent_header => {
                self.sent_header = true;
                self.connection_id = self.connection_id.wrapping_add(1);
                self.encode_auth_chain_header(payload)
            }
            kind if ssr_is_auth_chain(kind) => self.encode_auth_chain_data(payload),
            _ => Err(anyhow!("invalid SSR protocol state")),
        }
    }

    fn encode_auth_chain_header(&mut self, payload: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut output = vec![0u8; 36];
        getrandom::fill(&mut output[..4])
            .map_err(|error| anyhow!("failed to generate SSR auth-chain prefix: {error}"))?;
        let mut mac_key = self.request_iv.clone();
        mac_key.extend_from_slice(&self.key);
        self.last_client_hash = ssr_hmac_md5(&mac_key, &output[..4]);
        self.chain_key_hash = self.last_client_hash;
        output[4..12].copy_from_slice(&self.last_client_hash[..8]);

        let mut auth_plaintext = [0u8; 16];
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32;
        auth_plaintext[..4].copy_from_slice(&timestamp.to_le_bytes());
        auth_plaintext[4..8].copy_from_slice(&self.client_id);
        auth_plaintext[8..12].copy_from_slice(&self.connection_id.to_le_bytes());
        auth_plaintext[12..14].copy_from_slice(&4u16.to_le_bytes());

        let mut aes_password = ssr_base64(&self.user_key);
        aes_password.push_str(match self.kind {
            SsrProtocolKind::AuthChainA => "auth_chain_a",
            SsrProtocolKind::AuthChainB => "auth_chain_b",
            SsrProtocolKind::AuthChainC => "auth_chain_c",
            SsrProtocolKind::AuthChainD => "auth_chain_d",
            SsrProtocolKind::AuthChainE => "auth_chain_e",
            SsrProtocolKind::AuthChainF => "auth_chain_f",
            _ => return Err(anyhow!("invalid SSR auth-chain protocol")),
        });
        let aes_key = evp_bytes_to_key(aes_password.as_bytes(), 16);
        let encrypted_auth = ssr_aes128_cbc_encrypt_block(&aes_key, auth_plaintext)?;
        let mut auth = [0u8; 20];
        for index in 0..4 {
            auth[index] = self.uid[index] ^ self.last_client_hash[8 + index];
        }
        auth[4..].copy_from_slice(&encrypted_auth);
        self.last_server_hash = ssr_hmac_md5(&self.user_key, &auth);
        output[12..32].copy_from_slice(&auth);
        output[32..36].copy_from_slice(&self.last_server_hash[..4]);
        self.chain_cipher = Some(ssr_auth_chain_rc4(&self.user_key, &self.chain_key_hash)?);
        output.extend_from_slice(&self.encode_auth_chain_data(payload)?);
        Ok(output)
    }

    fn encode_auth_chain_data(&mut self, payload: &[u8]) -> anyhow::Result<Vec<u8>> {
        let (rand_len, start) = ssr_auth_chain_padding(
            self.kind,
            &self.key,
            payload.len(),
            &self.last_client_hash,
            self.chain_f_epoch,
        );
        let mut output = vec![0u8; 2 + rand_len + payload.len()];
        output[0] = (payload.len() as u8) ^ self.last_client_hash[14];
        output[1] = ((payload.len() >> 8) as u8) ^ self.last_client_hash[15];
        if rand_len > 0 {
            getrandom::fill(&mut output[2..2 + rand_len])
                .map_err(|error| anyhow!("failed to generate SSR auth-chain padding: {error}"))?;
        }
        if !payload.is_empty() {
            let mut encrypted = payload.to_vec();
            self.chain_cipher
                .as_mut()
                .ok_or_else(|| anyhow!("SSR auth-chain cipher is not initialized"))?
                .apply(&mut encrypted);
            output.splice(2 + start..2 + start, encrypted);
            output.truncate(2 + rand_len + payload.len());
        }
        let mut packet_key = self.user_key.clone();
        packet_key.extend_from_slice(&self.pack_id.to_le_bytes());
        self.last_client_hash = ssr_hmac_md5(&packet_key, &output);
        output.extend_from_slice(&self.last_client_hash[..2]);
        self.pack_id = self.pack_id.wrapping_add(1);
        Ok(output)
    }
}

struct SsrProtocolDecoder {
    kind: SsrProtocolKind,
    buffered: BytesMut,
    server_key: Vec<u8>,
    user_key: Vec<u8>,
    recv_id: u32,
    chain_cipher: Option<SsrStreamCipher>,
    chain_f_epoch: u64,
    last_server_hash: [u8; 16],
}

impl SsrProtocolDecoder {
    fn new(
        kind: SsrProtocolKind,
        server_key: Vec<u8>,
        user_key: Vec<u8>,
        chain_cipher: Option<SsrStreamCipher>,
        chain_f_epoch: u64,
        last_server_hash: [u8; 16],
    ) -> Self {
        Self {
            kind,
            buffered: BytesMut::new(),
            server_key,
            user_key,
            recv_id: 1,
            chain_cipher,
            chain_f_epoch,
            last_server_hash,
        }
    }

    fn decode(&mut self, payload: &[u8]) -> anyhow::Result<Vec<Vec<u8>>> {
        if self.kind == SsrProtocolKind::Origin {
            return Ok((!payload.is_empty())
                .then(|| vec![payload.to_vec()])
                .unwrap_or_default());
        }
        if matches!(
            self.kind,
            SsrProtocolKind::VerifySimple | SsrProtocolKind::AuthSimple
        ) {
            return self.decode_legacy_crc(payload);
        }
        if matches!(
            self.kind,
            SsrProtocolKind::AuthSha1 | SsrProtocolKind::AuthSha1V2
        ) {
            return self.decode_legacy_adler(payload);
        }
        if let Some(hash) = ssr_auth_hash(self.kind) {
            self.buffered.extend_from_slice(payload);
            let mut output = Vec::new();
            while self.buffered.len() >= 4 {
                let length = u16::from_le_bytes([self.buffered[0], self.buffered[1]]) as usize;
                if !(8..8192).contains(&length) {
                    return Err(anyhow!(
                        "invalid SSR authenticated response length {length}"
                    ));
                }
                let mut packet_key = self.user_key.clone();
                packet_key.extend_from_slice(&self.recv_id.to_le_bytes());
                let prefix_hmac = hash.hmac(&packet_key, &self.buffered[..2]);
                if self.buffered[2..4] != prefix_hmac[..2] {
                    return Err(anyhow!("SSR authenticated response prefix HMAC failed"));
                }
                if self.buffered.len() < length {
                    break;
                }
                let frame = self.buffered.split_to(length);
                let frame_hmac = hash.hmac(&packet_key, &frame[..length - 4]);
                if frame[length - 4..] != frame_hmac[..4] {
                    return Err(anyhow!("SSR authenticated response HMAC failed"));
                }
                self.recv_id = self.recv_id.wrapping_add(1);
                let rand_len = if frame[4] == 0xff {
                    if length < 11 {
                        return Err(anyhow!("SSR authenticated padding is truncated"));
                    }
                    u16::from_le_bytes([frame[5], frame[6]]) as usize
                } else {
                    frame[4] as usize
                };
                let payload_offset = 4usize
                    .checked_add(rand_len)
                    .ok_or_else(|| anyhow!("SSR authenticated padding overflow"))?;
                if payload_offset > length - 4 {
                    return Err(anyhow!("SSR authenticated response padding is invalid"));
                }
                let data = frame[payload_offset..length - 4].to_vec();
                if !data.is_empty() {
                    output.push(data);
                }
            }
            return Ok(output);
        }
        if ssr_is_auth_chain(self.kind) {
            self.buffered.extend_from_slice(payload);
            let mut output = Vec::new();
            while self.buffered.len() >= 4 {
                let data_len = usize::from(self.buffered[0] ^ self.last_server_hash[14])
                    | (usize::from(self.buffered[1] ^ self.last_server_hash[15]) << 8);
                let (rand_len, start) = ssr_auth_chain_padding(
                    self.kind,
                    &self.server_key,
                    data_len,
                    &self.last_server_hash,
                    self.chain_f_epoch,
                );
                let frame_len = 2usize
                    .checked_add(rand_len)
                    .and_then(|value| value.checked_add(data_len))
                    .and_then(|value| value.checked_add(2))
                    .ok_or_else(|| anyhow!("SSR auth-chain response length overflow"))?;
                if frame_len > 32 * 1024 {
                    return Err(anyhow!("SSR auth-chain response is too large"));
                }
                if self.buffered.len() < frame_len {
                    break;
                }
                let frame = self.buffered.split_to(frame_len);
                let mut packet_key = self.user_key.clone();
                packet_key.extend_from_slice(&self.recv_id.to_le_bytes());
                let hmac = ssr_hmac_md5(&packet_key, &frame[..frame_len - 2]);
                if frame[frame_len - 2..] != hmac[..2] {
                    return Err(anyhow!("SSR auth-chain response HMAC failed"));
                }
                let mut data = frame[2 + start..2 + start + data_len].to_vec();
                self.chain_cipher
                    .as_mut()
                    .ok_or_else(|| anyhow!("SSR auth-chain decoder is not initialized"))?
                    .apply(&mut data);
                self.last_server_hash = hmac;
                if self.recv_id == 1 {
                    if data.len() < 2 {
                        return Err(anyhow!("SSR auth-chain first response is too short"));
                    }
                    data.drain(..2);
                }
                self.recv_id = self.recv_id.wrapping_add(1);
                if !data.is_empty() {
                    output.push(data);
                }
            }
            return Ok(output);
        }
        self.buffered.extend_from_slice(payload);
        let mut output = Vec::new();
        while self.buffered.len() >= 4 {
            let length = u16::from_be_bytes([self.buffered[0], self.buffered[1]]) as usize;
            if !(8..8192).contains(&length) {
                return Err(anyhow!("invalid auth_sha1_v4 response length {length}"));
            }
            let expected_crc = ssr_crc32(&self.buffered[..2]) as u16;
            let received_crc = u16::from_le_bytes([self.buffered[2], self.buffered[3]]);
            if expected_crc != received_crc {
                return Err(anyhow!("auth_sha1_v4 response CRC check failed"));
            }
            if self.buffered.len() < length {
                break;
            }
            let frame = self.buffered.split_to(length);
            let received_adler = u32::from_le_bytes(frame[length - 4..length].try_into()?);
            if ssr_adler32(&frame[..length - 4]) != received_adler {
                return Err(anyhow!("auth_sha1_v4 response Adler-32 check failed"));
            }
            let rand_len = if frame[4] == 0xff {
                if length < 11 {
                    return Err(anyhow!("auth_sha1_v4 extended padding is truncated"));
                }
                u16::from_be_bytes([frame[5], frame[6]]) as usize
            } else {
                frame[4] as usize
            };
            let payload_offset = 4usize
                .checked_add(rand_len)
                .ok_or_else(|| anyhow!("auth_sha1_v4 padding overflow"))?;
            if payload_offset > length - 4 {
                return Err(anyhow!("auth_sha1_v4 response padding is invalid"));
            }
            let data = frame[payload_offset..length - 4].to_vec();
            if !data.is_empty() {
                output.push(data);
            }
        }
        Ok(output)
    }

    fn decode_legacy_crc(&mut self, payload: &[u8]) -> anyhow::Result<Vec<Vec<u8>>> {
        self.buffered.extend_from_slice(payload);
        let mut output = Vec::new();
        while self.buffered.len() > 2 {
            let length = u16::from_be_bytes([self.buffered[0], self.buffered[1]]) as usize;
            if !(7..8192).contains(&length) {
                return Err(anyhow!("invalid SSR legacy CRC response length {length}"));
            }
            if self.buffered.len() < length {
                break;
            }
            let frame = self.buffered.split_to(length);
            if ssr_crc32(&frame) != u32::MAX {
                return Err(anyhow!("SSR legacy CRC response checksum failed"));
            }
            let offset = 2usize
                .checked_add(frame[2] as usize)
                .ok_or_else(|| anyhow!("SSR legacy CRC padding overflow"))?;
            if offset > length - 4 {
                return Err(anyhow!("SSR legacy CRC response padding is invalid"));
            }
            let data = frame[offset..length - 4].to_vec();
            if !data.is_empty() {
                output.push(data);
            }
        }
        Ok(output)
    }

    fn decode_legacy_adler(&mut self, payload: &[u8]) -> anyhow::Result<Vec<Vec<u8>>> {
        self.buffered.extend_from_slice(payload);
        let mut output = Vec::new();
        while self.buffered.len() > 2 {
            let length = u16::from_be_bytes([self.buffered[0], self.buffered[1]]) as usize;
            if !(7..8192).contains(&length) {
                return Err(anyhow!("invalid SSR legacy Adler response length {length}"));
            }
            if self.buffered.len() < length {
                break;
            }
            let frame = self.buffered.split_to(length);
            let expected = u32::from_le_bytes(frame[length - 4..].try_into()?);
            if ssr_adler32(&frame[..length - 4]) != expected {
                return Err(anyhow!("SSR legacy Adler response checksum failed"));
            }
            let offset = if self.kind == SsrProtocolKind::AuthSha1V2 && frame[2] == 0xff {
                if length < 9 {
                    return Err(anyhow!("SSR auth_sha1_v2 response padding is truncated"));
                }
                2 + u16::from_be_bytes([frame[3], frame[4]]) as usize
            } else {
                2 + frame[2] as usize
            };
            if offset > length - 4 {
                return Err(anyhow!("SSR legacy Adler response padding is invalid"));
            }
            let data = frame[offset..length - 4].to_vec();
            if !data.is_empty() {
                output.push(data);
            }
        }
        Ok(output)
    }
}

fn ssr_protocol_kind(value: &str) -> anyhow::Result<SsrProtocolKind> {
    match value.trim().to_ascii_lowercase().as_str() {
        "origin" => Ok(SsrProtocolKind::Origin),
        "verify_simple" => Ok(SsrProtocolKind::VerifySimple),
        "auth_simple" => Ok(SsrProtocolKind::AuthSimple),
        "auth_sha1" => Ok(SsrProtocolKind::AuthSha1),
        "auth_sha1_v2" => Ok(SsrProtocolKind::AuthSha1V2),
        "auth_sha1_v4" => Ok(SsrProtocolKind::AuthSha1V4),
        "auth_aes128_md5" => Ok(SsrProtocolKind::AuthAes128Md5),
        "auth_aes128_sha1" => Ok(SsrProtocolKind::AuthAes128Sha1),
        "auth_chain_a" => Ok(SsrProtocolKind::AuthChainA),
        "auth_chain_b" => Ok(SsrProtocolKind::AuthChainB),
        "auth_chain_c" => Ok(SsrProtocolKind::AuthChainC),
        "auth_chain_d" => Ok(SsrProtocolKind::AuthChainD),
        "auth_chain_e" => Ok(SsrProtocolKind::AuthChainE),
        "auth_chain_f" => Ok(SsrProtocolKind::AuthChainF),
        value => Err(anyhow!(
            "ssr protocol {value} is not implemented safely yet; supported: origin, verify_simple, auth_simple, auth_sha1, auth_sha1_v2, auth_sha1_v4, auth_aes128_md5, auth_aes128_sha1, auth_chain_a, auth_chain_b, auth_chain_c, auth_chain_d, auth_chain_e, auth_chain_f"
        )),
    }
}

fn ssr_obfs_mode(value: &str) -> anyhow::Result<SsrObfsMode> {
    match value.trim().to_ascii_lowercase().as_str() {
        "" | "plain" => Ok(SsrObfsMode::Plain),
        "http_simple" | "http-simple" => Ok(SsrObfsMode::HttpSimple),
        "http_post" | "http-post" => Ok(SsrObfsMode::HttpPost),
        "tls1.2_ticket_auth" | "tls1.2-ticket-auth" => Ok(SsrObfsMode::Tls12TicketAuth),
        value => Err(anyhow!(
            "ssr obfs {value} is not implemented safely yet; supported: plain, http_simple, http_post, tls1.2_ticket_auth"
        )),
    }
}

fn build_ssr_http_obfs_request(
    mode: SsrObfsMode,
    configured_host: &str,
    port: u16,
    payload: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let host = configured_host
        .split(['#', ','])
        .next()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("SSR HTTP obfs host is empty"))?;
    let host_header = if port == 80 || host.contains(':') {
        host.to_string()
    } else {
        format!("{host}:{port}")
    };
    let mut random = [0u8; 1];
    getrandom::fill(&mut random)
        .map_err(|error| anyhow!("failed to generate SSR HTTP obfs padding: {error}"))?;
    let head_size = payload.len().min(30 + usize::from(random[0] & 0x3f));
    let mut encoded = String::with_capacity(head_size * 3);
    for byte in &payload[..head_size] {
        use std::fmt::Write as _;
        write!(&mut encoded, "%{byte:02x}")?;
    }
    let method = if mode == SsrObfsMode::HttpPost {
        "POST"
    } else {
        "GET"
    };
    let header = format!(
        "{method} /{encoded} HTTP/1.1\r\n\
         Host: {host_header}\r\n\
         User-Agent: Mozilla/5.0\r\n\
         Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n\
         Accept-Language: en-US,en;q=0.8\r\n\
         Accept-Encoding: gzip, deflate\r\n\
         DNT: 1\r\n\
         Connection: keep-alive\r\n\
         \r\n"
    );
    let mut output = header.into_bytes();
    output.extend_from_slice(&payload[head_size..]);
    Ok(output)
}

fn build_ssr_tls12_ticket_client_hello(
    host: &str,
    server_key: &[u8],
) -> anyhow::Result<(Vec<u8>, [u8; 32])> {
    let host = host
        .split(',')
        .next()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("SSR TLS ticket obfs host is empty"))?;
    if host.len() > u16::MAX as usize {
        return Err(anyhow!("SSR TLS ticket obfs host is too long"));
    }

    let mut client_id = [0u8; 32];
    getrandom::fill(&mut client_id)
        .map_err(|error| anyhow!("failed to generate SSR TLS client id: {error}"))?;
    let mut auth_data = [0u8; 32];
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32;
    auth_data[..4].copy_from_slice(&timestamp.to_be_bytes());
    getrandom::fill(&mut auth_data[4..22])
        .map_err(|error| anyhow!("failed to generate SSR TLS auth data: {error}"))?;
    let mut hmac_key = server_key.to_vec();
    hmac_key.extend_from_slice(&client_id);
    let auth_hmac = ssr_hmac_sha1(&hmac_key, &auth_data[..22]);
    auth_data[22..].copy_from_slice(&auth_hmac[..10]);

    const CIPHER_AND_COMPRESSION: &[u8] = &[
        0x00, 0x1c, 0xc0, 0x2b, 0xc0, 0x2f, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0x14, 0xcc, 0x13, 0xc0,
        0x0a, 0xc0, 0x14, 0xc0, 0x09, 0xc0, 0x13, 0x00, 0x9c, 0x00, 0x35, 0x00, 0x2f, 0x00, 0x0a,
        0x01, 0x00,
    ];
    const OTHER_EXTENSIONS: &[u8] = &[
        0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x17, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x16, 0x00, 0x14,
        0x06, 0x01, 0x06, 0x03, 0x05, 0x01, 0x05, 0x03, 0x04, 0x01, 0x04, 0x03, 0x03, 0x01, 0x03,
        0x03, 0x02, 0x01, 0x02, 0x03, 0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x12, 0x00, 0x00, 0x75, 0x50, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00, 0x00, 0x0a,
        0x00, 0x06, 0x00, 0x04, 0x00, 0x17, 0x00, 0x18,
    ];

    let mut extensions = Vec::new();
    extensions.extend_from_slice(&OTHER_EXTENSIONS[..5]);
    let host_bytes = host.as_bytes();
    extensions.extend_from_slice(&[0x00, 0x00]);
    extensions.extend_from_slice(&((host_bytes.len() + 5) as u16).to_be_bytes());
    extensions.extend_from_slice(&((host_bytes.len() + 3) as u16).to_be_bytes());
    extensions.push(0);
    extensions.extend_from_slice(&(host_bytes.len() as u16).to_be_bytes());
    extensions.extend_from_slice(host_bytes);
    extensions.extend_from_slice(&[0x00, 0x23]);
    let mut ticket = [0u8; 64];
    getrandom::fill(&mut ticket)
        .map_err(|error| anyhow!("failed to generate SSR TLS ticket: {error}"))?;
    extensions.extend_from_slice(&(ticket.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&ticket);
    extensions.extend_from_slice(&OTHER_EXTENSIONS[5..]);

    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(&auth_data);
    body.push(client_id.len() as u8);
    body.extend_from_slice(&client_id);
    body.extend_from_slice(CIPHER_AND_COMPRESSION);
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);
    if body.len() > 0x00ff_ffff {
        return Err(anyhow!("SSR TLS ticket ClientHello is too large"));
    }

    let mut handshake = Vec::with_capacity(body.len() + 4);
    handshake.push(0x01);
    handshake.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    handshake.extend_from_slice(&body);
    if handshake.len() > u16::MAX as usize {
        return Err(anyhow!("SSR TLS ticket handshake record is too large"));
    }
    let mut record = Vec::with_capacity(handshake.len() + 5);
    record.extend_from_slice(&[0x16, 0x03, 0x01]);
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    Ok((record, client_id))
}

fn build_ssr_tls12_ticket_finish(
    server_key: &[u8],
    client_id: &[u8; 32],
) -> anyhow::Result<Vec<u8>> {
    const FINISH_LEN: usize = 32;
    let mut output = vec![
        0x14,
        0x03,
        0x03,
        0x00,
        0x01,
        0x01,
        0x16,
        0x03,
        0x03,
        0x00,
        FINISH_LEN as u8,
    ];
    let random_len = FINISH_LEN - 10;
    let start = output.len();
    output.resize(start + random_len, 0);
    getrandom::fill(&mut output[start..])
        .map_err(|error| anyhow!("failed to generate SSR TLS finished data: {error}"))?;
    let mut hmac_key = server_key.to_vec();
    hmac_key.extend_from_slice(client_id);
    let hmac = ssr_hmac_sha1(&hmac_key, &output);
    output.extend_from_slice(&hmac[..10]);
    Ok(output)
}

async fn read_ssr_tls12_ticket_server_handshake<R>(
    reader: &mut R,
    server_key: &[u8],
    client_id: &[u8; 32],
) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut handshake = Vec::new();
    let mut saw_change_cipher = false;
    loop {
        let Some((content_type, version, payload)) = read_simple_obfs_tls_record(reader).await?
        else {
            return Err(anyhow!("SSR TLS ticket server closed during handshake"));
        };
        if !matches!(content_type, 0x14 | 0x16) {
            return Err(anyhow!(
                "SSR TLS ticket server returned unexpected record type {content_type}"
            ));
        }
        handshake.push(content_type);
        handshake.extend_from_slice(&version);
        handshake.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        handshake.extend_from_slice(&payload);
        if handshake.len() > 256 * 1024 {
            return Err(anyhow!("SSR TLS ticket server handshake is too large"));
        }
        if content_type == 0x14 {
            saw_change_cipher = true;
        } else if saw_change_cipher {
            break;
        }
    }
    if handshake.len() < 76 || handshake[0] != 0x16 {
        return Err(anyhow!("SSR TLS ticket server handshake is truncated"));
    }
    let mut hmac_key = server_key.to_vec();
    hmac_key.extend_from_slice(client_id);
    let auth_hmac = ssr_hmac_sha1(&hmac_key, &handshake[11..33]);
    if handshake[33..43] != auth_hmac[..10] {
        return Err(anyhow!("SSR TLS ticket server auth HMAC failed"));
    }
    if handshake[43] != 32 || handshake[44..76] != client_id[..] {
        return Err(anyhow!("SSR TLS ticket server session id mismatch"));
    }
    let final_offset = handshake.len() - 10;
    let final_hmac = ssr_hmac_sha1(&hmac_key, &handshake[..final_offset]);
    if handshake[final_offset..] != final_hmac[..10] {
        return Err(anyhow!("SSR TLS ticket server finished HMAC failed"));
    }
    Ok(())
}

fn spawn_ssr_tls12_ticket_stream(
    cipher: SsrCipher,
    key: Vec<u8>,
    mut upload: SsrStreamCipher,
    stream: BoxedStream,
    mut protocol_encoder: SsrProtocolEncoder,
    protocol_decoder: SsrProtocolDecoder,
    initial: Vec<u8>,
    client_id: [u8; 32],
) -> DuplexStream {
    let (app_side, relay_side) = tokio::io::duplex(64 * 1024);
    let (mut local_read, mut local_write) = tokio::io::split(relay_side);
    let (mut remote_read, mut remote_write) = tokio::io::split(stream);
    let (ready_sender, ready_receiver) = tokio::sync::oneshot::channel();
    let upload_key = key.clone();
    let upload_client_id = client_id;

    tokio::spawn(async move {
        if ready_receiver.await.is_err() {
            let _ = remote_write.shutdown().await;
            return;
        }
        let finish = match build_ssr_tls12_ticket_finish(&upload_key, &upload_client_id) {
            Ok(finish) => finish,
            Err(_) => {
                let _ = remote_write.shutdown().await;
                return;
            }
        };
        if remote_write.write_all(&finish).await.is_err()
            || remote_write
                .write_all(&wrap_simple_obfs_tls_app_data(&initial))
                .await
                .is_err()
            || remote_write.flush().await.is_err()
        {
            return;
        }
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            match local_read.read(&mut buf).await {
                Ok(0) => {
                    let _ = remote_write.shutdown().await;
                    break;
                }
                Ok(length) => {
                    let Ok(mut payload) = protocol_encoder.encode(&buf[..length]) else {
                        break;
                    };
                    upload.apply(&mut payload);
                    let framed = wrap_simple_obfs_tls_app_data(&payload);
                    if remote_write.write_all(&framed).await.is_err()
                        || remote_write.flush().await.is_err()
                    {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    tokio::spawn(async move {
        if read_ssr_tls12_ticket_server_handshake(&mut remote_read, &key, &client_id)
            .await
            .is_err()
        {
            let _ = local_write.shutdown().await;
            return;
        }
        if ready_sender.send(()).is_err() {
            let _ = local_write.shutdown().await;
            return;
        }

        let (mut plaintext_writer, mut plaintext_reader) = tokio::io::duplex(64 * 1024);
        let relay = tokio::spawn(async move {
            let mut protocol_decoder = protocol_decoder;
            relay_ssr_download(
                cipher,
                &key,
                &mut protocol_decoder,
                &mut plaintext_reader,
                &mut local_write,
            )
            .await;
        });
        loop {
            match read_simple_obfs_tls_record(&mut remote_read).await {
                Ok(Some((0x17, _, payload))) => {
                    if plaintext_writer.write_all(&payload).await.is_err() {
                        break;
                    }
                }
                Ok(None) => break,
                _ => break,
            }
        }
        let _ = plaintext_writer.shutdown().await;
        let _ = relay.await;
    });

    app_side
}

fn build_ssr_auth_sha1_v4_header(
    payload: &[u8],
    request_iv: &[u8],
    key: &[u8],
    client_id: [u8; 4],
    connection_id: u32,
) -> anyhow::Result<Vec<u8>> {
    const SALT: &[u8] = b"auth_sha1_v4";
    const RAND_LEN: usize = 1;
    const HMAC_LEN: usize = 10;
    let data_offset = RAND_LEN + 6;
    let frame_len = data_offset
        .checked_add(12)
        .and_then(|value| value.checked_add(payload.len()))
        .and_then(|value| value.checked_add(HMAC_LEN))
        .ok_or_else(|| anyhow!("auth_sha1_v4 header length overflow"))?;
    if frame_len >= u16::MAX as usize {
        return Err(anyhow!("auth_sha1_v4 header is too large"));
    }
    let mut frame = vec![0u8; frame_len];
    frame[..2].copy_from_slice(&(frame_len as u16).to_be_bytes());
    let mut crc_input = Vec::with_capacity(2 + SALT.len() + key.len());
    crc_input.extend_from_slice(&frame[..2]);
    crc_input.extend_from_slice(SALT);
    crc_input.extend_from_slice(key);
    frame[2..6].copy_from_slice(&ssr_crc32(&crc_input).to_le_bytes());
    frame[6] = RAND_LEN as u8;
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32;
    frame[data_offset..data_offset + 4].copy_from_slice(&timestamp.to_le_bytes());
    frame[data_offset + 4..data_offset + 8].copy_from_slice(&client_id);
    frame[data_offset + 8..data_offset + 12].copy_from_slice(&connection_id.to_le_bytes());
    let payload_offset = data_offset + 12;
    frame[payload_offset..payload_offset + payload.len()].copy_from_slice(payload);
    let mut hmac_key = Vec::with_capacity(request_iv.len() + key.len());
    hmac_key.extend_from_slice(request_iv);
    hmac_key.extend_from_slice(key);
    let digest = ssr_hmac_sha1(&hmac_key, &frame[..frame_len - HMAC_LEN]);
    frame[frame_len - HMAC_LEN..].copy_from_slice(&digest[..HMAC_LEN]);
    Ok(frame)
}

fn build_ssr_auth_sha1_v4_data(payload: &[u8]) -> anyhow::Result<Vec<u8>> {
    const RAND_LEN: usize = 1;
    let frame_len = RAND_LEN
        .checked_add(payload.len())
        .and_then(|value| value.checked_add(8))
        .ok_or_else(|| anyhow!("auth_sha1_v4 data length overflow"))?;
    if frame_len >= 8192 {
        return Err(anyhow!("auth_sha1_v4 data frame is too large"));
    }
    let mut frame = vec![0u8; frame_len];
    frame[..2].copy_from_slice(&(frame_len as u16).to_be_bytes());
    let crc = ssr_crc32(&frame[..2]) as u16;
    frame[2..4].copy_from_slice(&crc.to_le_bytes());
    frame[4] = RAND_LEN as u8;
    frame[5..5 + payload.len()].copy_from_slice(payload);
    let adler = ssr_adler32(&frame[..frame_len - 4]);
    frame[frame_len - 4..].copy_from_slice(&adler.to_le_bytes());
    Ok(frame)
}

fn ssr_auth_hash(kind: SsrProtocolKind) -> Option<SsrAuthHash> {
    match kind {
        SsrProtocolKind::AuthAes128Md5 => Some(SsrAuthHash::Md5),
        SsrProtocolKind::AuthAes128Sha1 => Some(SsrAuthHash::Sha1),
        SsrProtocolKind::Origin
        | SsrProtocolKind::VerifySimple
        | SsrProtocolKind::AuthSimple
        | SsrProtocolKind::AuthSha1
        | SsrProtocolKind::AuthSha1V2
        | SsrProtocolKind::AuthSha1V4
        | SsrProtocolKind::AuthChainA
        | SsrProtocolKind::AuthChainB
        | SsrProtocolKind::AuthChainC
        | SsrProtocolKind::AuthChainD
        | SsrProtocolKind::AuthChainE
        | SsrProtocolKind::AuthChainF => None,
    }
}

fn ssr_user_credentials(
    hash: SsrAuthHash,
    protocol_param: Option<&str>,
    server_key: &[u8],
) -> anyhow::Result<([u8; 4], Vec<u8>)> {
    if let Some((uid, password)) = protocol_param
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .and_then(|value| value.split_once(':'))
    {
        let uid = uid
            .trim()
            .parse::<u32>()
            .with_context(|| format!("invalid SSR protocol_param uid {uid:?}"))?;
        let password = password.trim();
        if password.is_empty() {
            return Err(anyhow!("SSR protocol_param user password is empty"));
        }
        return Ok((uid.to_le_bytes(), hash.hash(password.as_bytes())));
    }
    let mut uid = [0u8; 4];
    getrandom::fill(&mut uid)
        .map_err(|error| anyhow!("failed to generate SSR user id: {error}"))?;
    Ok((uid, server_key.to_vec()))
}

fn ssr_chain_user_credentials(
    protocol_param: Option<&str>,
    server_key: &[u8],
) -> anyhow::Result<([u8; 4], Vec<u8>)> {
    if let Some((uid, password)) = protocol_param
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .and_then(|value| value.split_once(':'))
    {
        let uid = uid
            .trim()
            .parse::<u32>()
            .with_context(|| format!("invalid SSR auth-chain uid {uid:?}"))?;
        let password = password.trim();
        if password.is_empty() {
            return Err(anyhow!("SSR auth-chain user password is empty"));
        }
        return Ok((uid.to_le_bytes(), password.as_bytes().to_vec()));
    }
    let mut uid = [0u8; 4];
    getrandom::fill(&mut uid)
        .map_err(|error| anyhow!("failed to generate SSR auth-chain uid: {error}"))?;
    Ok((uid, server_key.to_vec()))
}

fn ssr_base64(value: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(value)
}

fn ssr_auth_chain_rc4(
    user_key: &[u8],
    last_client_hash: &[u8; 16],
) -> anyhow::Result<SsrStreamCipher> {
    let mut password = ssr_base64(user_key);
    password.push_str(&ssr_base64(last_client_hash));
    let key = evp_bytes_to_key(password.as_bytes(), 16);
    let key = rc4::Key::<rc4::consts::U16>::from_slice(&key);
    Ok(SsrStreamCipher::Rc4Enc(rc4::Rc4::<rc4::consts::U16>::new(
        key,
    )))
}

#[derive(Clone, Copy)]
struct SsrShift128Plus {
    values: [u64; 2],
}

impl SsrShift128Plus {
    fn from_hash(hash: &[u8; 16], data_len: Option<usize>) -> Self {
        let mut bytes = *hash;
        if let Some(data_len) = data_len {
            bytes[0] = data_len as u8;
            bytes[1] = (data_len >> 8) as u8;
        }
        let mut state = Self {
            values: [
                u64::from_le_bytes(bytes[..8].try_into().expect("8-byte slice")),
                u64::from_le_bytes(bytes[8..].try_into().expect("8-byte slice")),
            ],
        };
        if data_len.is_some() {
            for _ in 0..4 {
                state.next();
            }
        }
        state
    }

    fn next(&mut self) -> u64 {
        let mut x = self.values[0];
        let y = self.values[1];
        self.values[0] = y;
        x ^= x << 23;
        x ^= y ^ (x >> 17) ^ (y >> 26);
        self.values[1] = x;
        x.wrapping_add(y)
    }
}

fn ssr_auth_chain_padding(
    kind: SsrProtocolKind,
    server_key: &[u8],
    data_len: usize,
    hash: &[u8; 16],
    chain_f_epoch: u64,
) -> (usize, usize) {
    let mut random = SsrShift128Plus::from_hash(hash, Some(data_len));
    let rand_len = match kind {
        SsrProtocolKind::AuthChainA => ssr_auth_chain_a_rand_len(data_len, &mut random),
        SsrProtocolKind::AuthChainB => ssr_auth_chain_b_rand_len(server_key, data_len, &mut random),
        SsrProtocolKind::AuthChainC => ssr_auth_chain_c_rand_len(server_key, data_len, &mut random),
        SsrProtocolKind::AuthChainD => {
            ssr_auth_chain_d_rand_len(server_key, data_len, &mut random, None)
        }
        SsrProtocolKind::AuthChainE => ssr_auth_chain_e_rand_len(server_key, data_len, None),
        SsrProtocolKind::AuthChainF => {
            ssr_auth_chain_e_rand_len(server_key, data_len, Some(chain_f_epoch))
        }
        _ => 0,
    };
    if rand_len == 0 {
        return (0, 0);
    }
    let start = (random.next() % 8_589_934_609 % rand_len as u64) as usize;
    (rand_len, start)
}

fn ssr_auth_chain_a_rand_len(data_len: usize, random: &mut SsrShift128Plus) -> usize {
    if data_len > 1440 {
        return 0;
    }
    if data_len > 1300 {
        (random.next() % 31) as usize
    } else if data_len > 900 {
        (random.next() % 127) as usize
    } else if data_len > 400 {
        (random.next() % 521) as usize
    } else {
        (random.next() % 1021) as usize
    }
}

fn ssr_auth_chain_b_rand_len(
    server_key: &[u8],
    data_len: usize,
    random: &mut SsrShift128Plus,
) -> usize {
    if data_len >= 1440 {
        return 0;
    }
    let (sizes, sizes2) = ssr_auth_chain_b_size_lists(server_key);
    let target = data_len + 4;
    let pos = sizes.partition_point(|value| *value < target);
    let final_pos = pos + (random.next() % sizes.len() as u64) as usize;
    if final_pos < sizes.len() {
        return sizes[final_pos] - target;
    }

    let pos2 = sizes2.partition_point(|value| *value < target);
    let final_pos2 = pos2 + (random.next() % sizes2.len() as u64) as usize;
    if final_pos2 < sizes2.len() {
        return sizes2[final_pos2] - target;
    }
    if final_pos2 < pos2 + sizes2.len() - 1 {
        return 0;
    }
    ssr_auth_chain_a_rand_len(data_len, random)
}

fn ssr_auth_chain_b_size_lists(server_key: &[u8]) -> (Vec<usize>, Vec<usize>) {
    let mut seed = [0u8; 16];
    let copy_len = server_key.len().min(seed.len());
    seed[..copy_len].copy_from_slice(&server_key[..copy_len]);
    let mut random = SsrShift128Plus::from_hash(&seed, None);

    let first_len = (random.next() % 8 + 4) as usize;
    let mut first = Vec::with_capacity(first_len);
    for _ in 0..first_len {
        first.push((random.next() % 2340 % 2040 % 1440) as usize);
    }
    first.sort_unstable();

    let second_len = (random.next() % 16 + 8) as usize;
    let mut second = Vec::with_capacity(second_len);
    for _ in 0..second_len {
        second.push((random.next() % 2340 % 2040 % 1440) as usize);
    }
    second.sort_unstable();
    (first, second)
}

fn ssr_auth_chain_c_rand_len(
    server_key: &[u8],
    data_len: usize,
    random: &mut SsrShift128Plus,
) -> usize {
    let sizes = ssr_auth_chain_c_size_list(server_key, false, None);
    let target = data_len + 4;
    if target >= *sizes.last().expect("auth-chain size list") {
        return ssr_auth_chain_a_rand_len(data_len, random);
    }
    let pos = sizes.partition_point(|value| *value < target);
    let final_pos = pos + (random.next() % (sizes.len() - pos) as u64) as usize;
    sizes[final_pos] - target
}

fn ssr_auth_chain_d_rand_len(
    server_key: &[u8],
    data_len: usize,
    random: &mut SsrShift128Plus,
    epoch: Option<u64>,
) -> usize {
    let sizes = ssr_auth_chain_c_size_list(server_key, true, epoch);
    let target = data_len + 4;
    if target >= *sizes.last().expect("auth-chain size list") {
        return 0;
    }
    let pos = sizes.partition_point(|value| *value < target);
    let final_pos = pos + (random.next() % (sizes.len() - pos) as u64) as usize;
    sizes[final_pos] - target
}

fn ssr_auth_chain_e_rand_len(server_key: &[u8], data_len: usize, epoch: Option<u64>) -> usize {
    let sizes = ssr_auth_chain_c_size_list(server_key, true, epoch);
    let target = data_len + 4;
    if target >= *sizes.last().expect("auth-chain size list") {
        return 0;
    }
    let pos = sizes.partition_point(|value| *value < target);
    sizes[pos] - target
}

fn ssr_auth_chain_c_size_list(
    server_key: &[u8],
    patch_to_1300: bool,
    epoch: Option<u64>,
) -> Vec<usize> {
    let mut seed = [0u8; 16];
    let copy_len = server_key.len().min(seed.len());
    seed[..copy_len].copy_from_slice(&server_key[..copy_len]);
    if let Some(epoch) = epoch {
        for (target, value) in seed.iter_mut().take(8).zip(epoch.to_be_bytes()) {
            *target ^= value;
        }
    }
    let mut random = SsrShift128Plus::from_hash(&seed, None);
    let length = (random.next() % 24 + 12) as usize;
    let mut sizes = Vec::with_capacity(if patch_to_1300 { 64 } else { length });
    for _ in 0..length {
        sizes.push((random.next() % 2340 % 2040 % 1440) as usize);
    }
    sizes.sort_unstable();
    if patch_to_1300 {
        while sizes.last().copied().unwrap_or_default() < 1300 && sizes.len() < 64 {
            sizes.push((random.next() % 2340 % 2040 % 1440) as usize);
        }
        sizes.sort_unstable();
    }
    sizes
}

fn ssr_auth_chain_f_epoch(protocol_param: Option<&str>) -> u64 {
    let interval = protocol_param
        .and_then(|value| value.split_once('#').map(|(_, suffix)| suffix))
        .and_then(|value| value.split('#').next())
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(86_400);
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        / interval
}

fn ssr_auth_chain_udp_rand_len(hash: &[u8; 16]) -> usize {
    let mut random = SsrShift128Plus::from_hash(hash, None);
    (random.next() % 127) as usize
}

fn ssr_auth_chain_udp_encode(
    payload: &[u8],
    server_key: &[u8],
    user_key: &[u8],
    uid: [u8; 4],
) -> anyhow::Result<Vec<u8>> {
    let mut auth_data = [0u8; 3];
    getrandom::fill(&mut auth_data)
        .map_err(|error| anyhow!("failed to generate SSR auth-chain UDP auth data: {error}"))?;
    let hash = ssr_hmac_md5(server_key, &auth_data);
    let rand_len = ssr_auth_chain_udp_rand_len(&hash);
    let mut encrypted = payload.to_vec();
    ssr_auth_chain_rc4(user_key, &hash)?.apply(&mut encrypted);
    let mut output = Vec::with_capacity(payload.len() + rand_len + 8);
    output.extend_from_slice(&encrypted);
    let padding_offset = output.len();
    output.resize(padding_offset + rand_len, 0);
    if rand_len > 0 {
        getrandom::fill(&mut output[padding_offset..])
            .map_err(|error| anyhow!("failed to generate SSR auth-chain UDP padding: {error}"))?;
    }
    output.extend_from_slice(&auth_data);
    for index in 0..4 {
        output.push(uid[index] ^ hash[index]);
    }
    let hmac = ssr_hmac_md5(user_key, &output);
    output.push(hmac[0]);
    Ok(output)
}

fn ssr_auth_chain_udp_decode(
    packet: &[u8],
    server_key: &[u8],
    user_key: &[u8],
) -> anyhow::Result<Vec<u8>> {
    if packet.len() <= 8 {
        return Err(anyhow!("SSR auth-chain UDP response is too short"));
    }
    let expected = ssr_hmac_md5(user_key, &packet[..packet.len() - 1]);
    if packet[packet.len() - 1] != expected[0] {
        return Err(anyhow!("SSR auth-chain UDP response HMAC failed"));
    }
    let auth_data = &packet[packet.len() - 8..packet.len() - 1];
    let hash = ssr_hmac_md5(server_key, auth_data);
    let rand_len = ssr_auth_chain_udp_rand_len(&hash);
    let payload_len = packet
        .len()
        .checked_sub(rand_len + 8)
        .ok_or_else(|| anyhow!("SSR auth-chain UDP response padding is invalid"))?;
    let mut payload = packet[..payload_len].to_vec();
    ssr_auth_chain_rc4(user_key, &hash)?.apply(&mut payload);
    Ok(payload)
}

fn ssr_legacy_random_len(mask: u16) -> anyhow::Result<usize> {
    let mut random = [0u8; 2];
    getrandom::fill(&mut random)
        .map_err(|error| anyhow!("failed to generate SSR legacy padding length: {error}"))?;
    Ok(usize::from(u16::from_le_bytes(random) & mask) + 1)
}

fn build_ssr_legacy_crc_data(payload: &[u8]) -> anyhow::Result<Vec<u8>> {
    let rand_len = ssr_legacy_random_len(0x0f)?;
    let frame_len = 2usize
        .checked_add(rand_len)
        .and_then(|value| value.checked_add(payload.len()))
        .and_then(|value| value.checked_add(4))
        .ok_or_else(|| anyhow!("SSR legacy CRC frame length overflow"))?;
    if frame_len >= 8192 {
        return Err(anyhow!("SSR legacy CRC frame is too large"));
    }
    let mut frame = vec![0u8; frame_len];
    frame[..2].copy_from_slice(&(frame_len as u16).to_be_bytes());
    getrandom::fill(&mut frame[2..2 + rand_len])
        .map_err(|error| anyhow!("failed to generate SSR legacy CRC padding: {error}"))?;
    frame[2] = rand_len as u8;
    frame[2 + rand_len..2 + rand_len + payload.len()].copy_from_slice(payload);
    let checksum = !ssr_crc32(&frame[..frame_len - 4]);
    frame[frame_len - 4..].copy_from_slice(&checksum.to_le_bytes());
    Ok(frame)
}

fn build_ssr_auth_simple_header(
    payload: &[u8],
    client_id: [u8; 8],
    connection_id: u32,
) -> anyhow::Result<Vec<u8>> {
    let rand_len = ssr_legacy_random_len(0x0f)?;
    let frame_len = 2usize
        .checked_add(rand_len)
        .and_then(|value| value.checked_add(12))
        .and_then(|value| value.checked_add(payload.len()))
        .and_then(|value| value.checked_add(4))
        .ok_or_else(|| anyhow!("SSR auth_simple frame length overflow"))?;
    if frame_len >= 8192 {
        return Err(anyhow!("SSR auth_simple frame is too large"));
    }
    let mut frame = vec![0u8; frame_len];
    frame[..2].copy_from_slice(&(frame_len as u16).to_be_bytes());
    getrandom::fill(&mut frame[2..2 + rand_len])
        .map_err(|error| anyhow!("failed to generate SSR auth_simple padding: {error}"))?;
    frame[2] = rand_len as u8;
    let auth_offset = 2 + rand_len;
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32;
    frame[auth_offset..auth_offset + 4].copy_from_slice(&timestamp.to_le_bytes());
    frame[auth_offset + 4..auth_offset + 8].copy_from_slice(&client_id[..4]);
    frame[auth_offset + 8..auth_offset + 12].copy_from_slice(&connection_id.to_le_bytes());
    frame[auth_offset + 12..auth_offset + 12 + payload.len()].copy_from_slice(payload);
    let checksum = !ssr_crc32(&frame[..frame_len - 4]);
    frame[frame_len - 4..].copy_from_slice(&checksum.to_le_bytes());
    Ok(frame)
}

fn build_ssr_auth_sha1_header(
    payload: &[u8],
    request_iv: &[u8],
    server_key: &[u8],
    client_id: [u8; 4],
    connection_id: u32,
) -> anyhow::Result<Vec<u8>> {
    let rand_len = ssr_legacy_random_len(0x7f)?;
    let data_offset = rand_len + 6;
    let frame_len = data_offset
        .checked_add(12)
        .and_then(|value| value.checked_add(payload.len()))
        .and_then(|value| value.checked_add(10))
        .ok_or_else(|| anyhow!("SSR auth_sha1 frame length overflow"))?;
    if frame_len >= 8192 {
        return Err(anyhow!("SSR auth_sha1 frame is too large"));
    }
    let mut frame = vec![0u8; frame_len];
    frame[..4].copy_from_slice(&ssr_crc32(server_key).to_le_bytes());
    frame[4..6].copy_from_slice(&(frame_len as u16).to_be_bytes());
    frame[6] = rand_len as u8;
    if rand_len > 1 {
        getrandom::fill(&mut frame[7..6 + rand_len])
            .map_err(|error| anyhow!("failed to generate SSR auth_sha1 padding: {error}"))?;
    }
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32;
    frame[data_offset..data_offset + 4].copy_from_slice(&timestamp.to_le_bytes());
    frame[data_offset + 4..data_offset + 8].copy_from_slice(&client_id);
    frame[data_offset + 8..data_offset + 12].copy_from_slice(&connection_id.to_le_bytes());
    frame[data_offset + 12..data_offset + 12 + payload.len()].copy_from_slice(payload);
    let mut hmac_key = request_iv.to_vec();
    hmac_key.extend_from_slice(server_key);
    let hmac = ssr_hmac_sha1(&hmac_key, &frame[..frame_len - 10]);
    frame[frame_len - 10..].copy_from_slice(&hmac[..10]);
    Ok(frame)
}

fn build_ssr_auth_sha1_v2_header(
    payload: &[u8],
    request_iv: &[u8],
    server_key: &[u8],
    client_id: [u8; 8],
    connection_id: u32,
) -> anyhow::Result<Vec<u8>> {
    let rand_len = ssr_legacy_random_len(if payload.len() > 400 { 0x7f } else { 0x03ff })?;
    let data_offset = rand_len + 6;
    let frame_len = data_offset
        .checked_add(12)
        .and_then(|value| value.checked_add(payload.len()))
        .and_then(|value| value.checked_add(10))
        .ok_or_else(|| anyhow!("SSR auth_sha1_v2 frame length overflow"))?;
    if frame_len >= 8192 {
        return Err(anyhow!("SSR auth_sha1_v2 frame is too large"));
    }
    let mut crc_input = b"auth_sha1_v2".to_vec();
    crc_input.extend_from_slice(server_key);
    let mut frame = vec![0u8; frame_len];
    frame[..4].copy_from_slice(&ssr_crc32(&crc_input).to_le_bytes());
    frame[4..6].copy_from_slice(&(frame_len as u16).to_be_bytes());
    if rand_len < 128 {
        frame[6] = rand_len as u8;
    } else {
        frame[6] = 0xff;
        frame[7..9].copy_from_slice(&(rand_len as u16).to_be_bytes());
    }
    let padding_header = if rand_len < 128 { 1 } else { 3 };
    if rand_len > padding_header {
        getrandom::fill(&mut frame[6 + padding_header..6 + rand_len])
            .map_err(|error| anyhow!("failed to generate SSR auth_sha1_v2 padding: {error}"))?;
    }
    frame[data_offset..data_offset + 8].copy_from_slice(&client_id);
    frame[data_offset + 8..data_offset + 12].copy_from_slice(&connection_id.to_le_bytes());
    frame[data_offset + 12..data_offset + 12 + payload.len()].copy_from_slice(payload);
    let mut hmac_key = request_iv.to_vec();
    hmac_key.extend_from_slice(server_key);
    let hmac = ssr_hmac_sha1(&hmac_key, &frame[..frame_len - 10]);
    frame[frame_len - 10..].copy_from_slice(&hmac[..10]);
    Ok(frame)
}

fn build_ssr_legacy_adler_data(payload: &[u8], extended: bool) -> anyhow::Result<Vec<u8>> {
    let mask = if payload.len() > 1300 {
        0
    } else if payload.len() > 400 {
        0x7f
    } else if extended {
        0x03ff
    } else {
        0x0f
    };
    let rand_len = ssr_legacy_random_len(mask)?;
    let frame_len = 2usize
        .checked_add(rand_len)
        .and_then(|value| value.checked_add(payload.len()))
        .and_then(|value| value.checked_add(4))
        .ok_or_else(|| anyhow!("SSR legacy Adler frame length overflow"))?;
    if frame_len >= 8192 {
        return Err(anyhow!("SSR legacy Adler frame is too large"));
    }
    let mut frame = vec![0u8; frame_len];
    frame[..2].copy_from_slice(&(frame_len as u16).to_be_bytes());
    if extended && rand_len >= 128 {
        frame[2] = 0xff;
        frame[3..5].copy_from_slice(&(rand_len as u16).to_be_bytes());
        if rand_len > 3 {
            getrandom::fill(&mut frame[5..2 + rand_len])
                .map_err(|error| anyhow!("failed to generate SSR legacy Adler padding: {error}"))?;
        }
    } else {
        getrandom::fill(&mut frame[2..2 + rand_len])
            .map_err(|error| anyhow!("failed to generate SSR legacy Adler padding: {error}"))?;
        frame[2] = rand_len as u8;
    }
    frame[2 + rand_len..2 + rand_len + payload.len()].copy_from_slice(payload);
    let checksum = ssr_adler32(&frame[..frame_len - 4]);
    frame[frame_len - 4..].copy_from_slice(&checksum.to_le_bytes());
    Ok(frame)
}

fn build_ssr_auth_aes128_header(
    kind: SsrProtocolKind,
    payload: &[u8],
    request_iv: &[u8],
    server_key: &[u8],
    user_key: &[u8],
    uid: [u8; 4],
    client_id: [u8; 4],
    connection_id: u32,
) -> anyhow::Result<Vec<u8>> {
    let hash =
        ssr_auth_hash(kind).ok_or_else(|| anyhow!("invalid SSR AES authentication protocol"))?;
    let salt = match kind {
        SsrProtocolKind::AuthAes128Md5 => "auth_aes128_md5",
        SsrProtocolKind::AuthAes128Sha1 => "auth_aes128_sha1",
        _ => return Err(anyhow!("invalid SSR AES authentication protocol")),
    };
    const RAND_LEN: usize = 0;
    let payload_offset = 31 + RAND_LEN;
    let frame_len = payload_offset
        .checked_add(payload.len())
        .and_then(|value| value.checked_add(4))
        .ok_or_else(|| anyhow!("SSR authenticated header length overflow"))?;
    if frame_len >= u16::MAX as usize {
        return Err(anyhow!("SSR authenticated header is too large"));
    }

    let mut frame = vec![0u8; frame_len];
    getrandom::fill(&mut frame[..1])
        .map_err(|error| anyhow!("failed to generate SSR auth prefix: {error}"))?;
    let mut request_hmac_key = Vec::with_capacity(request_iv.len() + server_key.len());
    request_hmac_key.extend_from_slice(request_iv);
    request_hmac_key.extend_from_slice(server_key);
    let prefix_hmac = hash.hmac(&request_hmac_key, &frame[..1]);
    frame[1..7].copy_from_slice(&prefix_hmac[..6]);

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32;
    let mut auth_plaintext = [0u8; 16];
    auth_plaintext[..4].copy_from_slice(&timestamp.to_le_bytes());
    auth_plaintext[4..8].copy_from_slice(&client_id);
    auth_plaintext[8..12].copy_from_slice(&connection_id.to_le_bytes());
    auth_plaintext[12..14].copy_from_slice(&(frame_len as u16).to_le_bytes());
    auth_plaintext[14..16].copy_from_slice(&(RAND_LEN as u16).to_le_bytes());

    use base64::Engine as _;
    let mut aes_password = base64::engine::general_purpose::STANDARD.encode(user_key);
    aes_password.push_str(salt);
    let aes_key = evp_bytes_to_key(aes_password.as_bytes(), 16);
    let encrypted_auth = ssr_aes128_cbc_encrypt_block(&aes_key, auth_plaintext)?;
    frame[7..11].copy_from_slice(&uid);
    frame[11..27].copy_from_slice(&encrypted_auth);
    let auth_hmac = hash.hmac(&request_hmac_key, &frame[7..27]);
    frame[27..31].copy_from_slice(&auth_hmac[..4]);
    frame[payload_offset..payload_offset + payload.len()].copy_from_slice(payload);
    let final_hmac = hash.hmac(user_key, &frame[..frame_len - 4]);
    frame[frame_len - 4..].copy_from_slice(&final_hmac[..4]);
    Ok(frame)
}

fn build_ssr_auth_aes128_data(
    kind: SsrProtocolKind,
    payload: &[u8],
    user_key: &[u8],
    packet_id: u32,
) -> anyhow::Result<Vec<u8>> {
    let hash =
        ssr_auth_hash(kind).ok_or_else(|| anyhow!("invalid SSR AES authentication protocol"))?;
    const RAND_LEN: usize = 1;
    let frame_len = RAND_LEN
        .checked_add(payload.len())
        .and_then(|value| value.checked_add(8))
        .ok_or_else(|| anyhow!("SSR authenticated data length overflow"))?;
    if frame_len >= 8192 {
        return Err(anyhow!("SSR authenticated data frame is too large"));
    }
    let mut packet_key = user_key.to_vec();
    packet_key.extend_from_slice(&packet_id.to_le_bytes());
    let mut frame = vec![0u8; frame_len];
    frame[..2].copy_from_slice(&(frame_len as u16).to_le_bytes());
    let prefix_hmac = hash.hmac(&packet_key, &frame[..2]);
    frame[2..4].copy_from_slice(&prefix_hmac[..2]);
    frame[4] = RAND_LEN as u8;
    frame[5..5 + payload.len()].copy_from_slice(payload);
    let frame_hmac = hash.hmac(&packet_key, &frame[..frame_len - 4]);
    frame[frame_len - 4..].copy_from_slice(&frame_hmac[..4]);
    Ok(frame)
}

fn ssr_aes128_cbc_encrypt_block(key: &[u8], plaintext: [u8; 16]) -> anyhow::Result<[u8; 16]> {
    let cipher = Aes128::new_from_slice(key)
        .map_err(|_| anyhow!("invalid SSR AES-128-CBC authentication key"))?;
    let mut block = Block::<Aes128>::clone_from_slice(&plaintext);
    cipher.encrypt_block(&mut block);
    Ok(block.into())
}

fn ssr_crc32(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                0xedb8_8320 ^ (crc >> 1)
            } else {
                crc >> 1
            };
        }
    }
    crc ^ 0xffff_ffff
}

fn ssr_adler32(data: &[u8]) -> u32 {
    const MOD: u32 = 65_521;
    let mut a = 1u32;
    let mut b = 0u32;
    for byte in data {
        a = (a + u32::from(*byte)) % MOD;
        b = (b + a) % MOD;
    }
    (b << 16) | a
}

fn ssr_hmac_md5(key: &[u8], message: &[u8]) -> [u8; 16] {
    const BLOCK_SIZE: usize = 64;
    let mut normalized = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        let digest = Md5::digest(key);
        normalized[..digest.len()].copy_from_slice(&digest);
    } else {
        normalized[..key.len()].copy_from_slice(key);
    }
    let mut inner_pad = [0x36u8; BLOCK_SIZE];
    let mut outer_pad = [0x5cu8; BLOCK_SIZE];
    for index in 0..BLOCK_SIZE {
        inner_pad[index] ^= normalized[index];
        outer_pad[index] ^= normalized[index];
    }
    let mut inner = Md5::new();
    inner.update(inner_pad);
    inner.update(message);
    let inner_digest = inner.finalize();
    let mut outer = Md5::new();
    outer.update(outer_pad);
    outer.update(inner_digest);
    outer.finalize().into()
}

fn ssr_hmac_sha1(key: &[u8], message: &[u8]) -> [u8; 20] {
    const BLOCK_SIZE: usize = 64;
    let mut normalized = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        let digest = Sha1::digest(key);
        normalized[..digest.len()].copy_from_slice(&digest);
    } else {
        normalized[..key.len()].copy_from_slice(key);
    }
    let mut inner_pad = [0x36u8; BLOCK_SIZE];
    let mut outer_pad = [0x5cu8; BLOCK_SIZE];
    for index in 0..BLOCK_SIZE {
        inner_pad[index] ^= normalized[index];
        outer_pad[index] ^= normalized[index];
    }
    let mut inner = Sha1::new();
    inner.update(inner_pad);
    inner.update(message);
    let inner_digest = inner.finalize();
    let mut outer = Sha1::new();
    outer.update(outer_pad);
    outer.update(inner_digest);
    outer.finalize().into()
}

fn spawn_ssr_stream(
    cipher: SsrCipher,
    key: Vec<u8>,
    mut upload: SsrStreamCipher,
    stream: BoxedStream,
    obfs: SsrObfsMode,
    mut protocol_encoder: SsrProtocolEncoder,
    mut protocol_decoder: SsrProtocolDecoder,
) -> DuplexStream {
    let (app_side, relay_side) = tokio::io::duplex(64 * 1024);
    let (mut local_read, mut local_write) = tokio::io::split(relay_side);
    let (mut remote_read, mut remote_write) = tokio::io::split(stream);

    tokio::spawn(async move {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            match local_read.read(&mut buf).await {
                Ok(0) => {
                    let _ = remote_write.shutdown().await;
                    break;
                }
                Ok(n) => {
                    let Ok(mut chunk) = protocol_encoder.encode(&buf[..n]) else {
                        break;
                    };
                    upload.apply(&mut chunk);
                    if remote_write.write_all(&chunk).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    tokio::spawn(async move {
        if matches!(obfs, SsrObfsMode::HttpSimple | SsrObfsMode::HttpPost) {
            let leftover = match read_http_obfs_response(&mut remote_read).await {
                Ok(leftover) => leftover,
                Err(_) => {
                    let _ = local_write.shutdown().await;
                    return;
                }
            };
            let cursor = Cursor::new(leftover);
            let mut chained = cursor.chain(remote_read);
            relay_ssr_download(
                cipher,
                &key,
                &mut protocol_decoder,
                &mut chained,
                &mut local_write,
            )
            .await;
            return;
        }
        relay_ssr_download(
            cipher,
            &key,
            &mut protocol_decoder,
            &mut remote_read,
            &mut local_write,
        )
        .await;
    });

    app_side
}

async fn relay_ssr_download<R, W>(
    cipher: SsrCipher,
    key: &[u8],
    protocol_decoder: &mut SsrProtocolDecoder,
    reader: &mut R,
    writer: &mut W,
) where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut iv = vec![0u8; cipher.iv_len()];
    if reader.read_exact(&mut iv).await.is_err() {
        let _ = writer.shutdown().await;
        return;
    }
    let Ok(mut download) = cipher.decryptor(&key, &iv) else {
        let _ = writer.shutdown().await;
        return;
    };
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        match reader.read(&mut buf).await {
            Ok(0) => {
                let _ = writer.shutdown().await;
                break;
            }
            Ok(n) => {
                let mut chunk = buf[..n].to_vec();
                download.apply(&mut chunk);
                let packets = match protocol_decoder.decode(&chunk) {
                    Ok(packets) => packets,
                    Err(_) => {
                        let _ = writer.shutdown().await;
                        break;
                    }
                };
                for packet in packets {
                    if writer.write_all(&packet).await.is_err() {
                        return;
                    }
                }
            }
            Err(_) => {
                let _ = writer.shutdown().await;
                break;
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SsrCipher {
    Aes128Cfb,
    Aes192Cfb,
    Aes256Cfb,
    Rc4Md5,
    Chacha20Legacy,
    Chacha20Ietf,
}

impl SsrCipher {
    fn from_method(method: &str) -> anyhow::Result<Self> {
        match method.to_ascii_lowercase().as_str() {
            "aes-128-cfb" => Ok(Self::Aes128Cfb),
            "aes-192-cfb" => Ok(Self::Aes192Cfb),
            "aes-256-cfb" => Ok(Self::Aes256Cfb),
            "rc4-md5" => Ok(Self::Rc4Md5),
            "chacha20" => Ok(Self::Chacha20Legacy),
            "chacha20-ietf" => Ok(Self::Chacha20Ietf),
            _ => Err(anyhow!("unsupported ssr method {method}")),
        }
    }

    fn key_len(self) -> usize {
        match self {
            Self::Aes128Cfb => 16,
            Self::Aes192Cfb => 24,
            Self::Aes256Cfb => 32,
            Self::Rc4Md5 => 16,
            Self::Chacha20Legacy | Self::Chacha20Ietf => 32,
        }
    }

    fn iv_len(self) -> usize {
        match self {
            Self::Chacha20Legacy => 8,
            Self::Chacha20Ietf => 12,
            _ => 16,
        }
    }

    fn encryptor(self, key: &[u8], iv: &[u8]) -> anyhow::Result<SsrStreamCipher> {
        match self {
            Self::Aes128Cfb => Ok(SsrStreamCipher::Aes128Enc(
                cfb_mode::BufEncryptor::<Aes128>::new_from_slices(key, iv)
                    .map_err(|_| anyhow!("invalid aes-128-cfb key/iv"))?,
            )),
            Self::Aes192Cfb => Ok(SsrStreamCipher::Aes192Enc(
                cfb_mode::BufEncryptor::<Aes192>::new_from_slices(key, iv)
                    .map_err(|_| anyhow!("invalid aes-192-cfb key/iv"))?,
            )),
            Self::Aes256Cfb => Ok(SsrStreamCipher::Aes256Enc(
                cfb_mode::BufEncryptor::<Aes256>::new_from_slices(key, iv)
                    .map_err(|_| anyhow!("invalid aes-256-cfb key/iv"))?,
            )),
            Self::Rc4Md5 => {
                let rc4_key = rc4_md5_derive_key(key, iv);
                let key_arr = rc4::Key::<rc4::consts::U16>::from_slice(&rc4_key);
                Ok(SsrStreamCipher::Rc4Enc(rc4::Rc4::<rc4::consts::U16>::new(
                    key_arr,
                )))
            }
            Self::Chacha20Legacy => {
                let chacha_key = if key.len() == 16 {
                    let mut extended = vec![0u8; 32];
                    extended[..16].copy_from_slice(key);
                    extended[16..].copy_from_slice(key);
                    extended
                } else {
                    key.to_vec()
                };
                Ok(SsrStreamCipher::Chacha20LegacyEnc(
                    chacha20::ChaCha20Legacy::new_from_slices(&chacha_key, iv)
                        .map_err(|_| anyhow!("invalid chacha20 key/iv"))?,
                ))
            }
            Self::Chacha20Ietf => {
                let chacha_key = if key.len() == 16 {
                    let mut extended = vec![0u8; 32];
                    extended[..16].copy_from_slice(key);
                    extended[16..].copy_from_slice(key);
                    extended
                } else {
                    key.to_vec()
                };
                Ok(SsrStreamCipher::Chacha20IetfEnc(
                    chacha20::ChaCha20::new_from_slices(&chacha_key, iv)
                        .map_err(|_| anyhow!("invalid chacha20-ietf key/iv"))?,
                ))
            }
        }
    }

    fn decryptor(self, key: &[u8], iv: &[u8]) -> anyhow::Result<SsrStreamCipher> {
        match self {
            Self::Aes128Cfb => Ok(SsrStreamCipher::Aes128Dec(
                cfb_mode::BufDecryptor::<Aes128>::new_from_slices(key, iv)
                    .map_err(|_| anyhow!("invalid aes-128-cfb key/iv"))?,
            )),
            Self::Aes192Cfb => Ok(SsrStreamCipher::Aes192Dec(
                cfb_mode::BufDecryptor::<Aes192>::new_from_slices(key, iv)
                    .map_err(|_| anyhow!("invalid aes-192-cfb key/iv"))?,
            )),
            Self::Aes256Cfb => Ok(SsrStreamCipher::Aes256Dec(
                cfb_mode::BufDecryptor::<Aes256>::new_from_slices(key, iv)
                    .map_err(|_| anyhow!("invalid aes-256-cfb key/iv"))?,
            )),
            Self::Rc4Md5 => {
                let rc4_key = rc4_md5_derive_key(key, iv);
                let key_arr = rc4::Key::<rc4::consts::U16>::from_slice(&rc4_key);
                Ok(SsrStreamCipher::Rc4Dec(rc4::Rc4::<rc4::consts::U16>::new(
                    key_arr,
                )))
            }
            Self::Chacha20Legacy => {
                let chacha_key = if key.len() == 16 {
                    let mut extended = vec![0u8; 32];
                    extended[..16].copy_from_slice(key);
                    extended[16..].copy_from_slice(key);
                    extended
                } else {
                    key.to_vec()
                };
                Ok(SsrStreamCipher::Chacha20LegacyDec(
                    chacha20::ChaCha20Legacy::new_from_slices(&chacha_key, iv)
                        .map_err(|_| anyhow!("invalid chacha20 key/iv"))?,
                ))
            }
            Self::Chacha20Ietf => {
                let chacha_key = if key.len() == 16 {
                    let mut extended = vec![0u8; 32];
                    extended[..16].copy_from_slice(key);
                    extended[16..].copy_from_slice(key);
                    extended
                } else {
                    key.to_vec()
                };
                Ok(SsrStreamCipher::Chacha20IetfDec(
                    chacha20::ChaCha20::new_from_slices(&chacha_key, iv)
                        .map_err(|_| anyhow!("invalid chacha20-ietf key/iv"))?,
                ))
            }
        }
    }
}

fn rc4_md5_derive_key(key: &[u8], iv: &[u8]) -> Vec<u8> {
    use md5::{Digest, Md5};
    let mut hasher = Md5::new();
    hasher.update(key);
    hasher.update(iv);
    hasher.finalize().to_vec()
}

enum SsrStreamCipher {
    Aes128Enc(cfb_mode::BufEncryptor<Aes128>),
    Aes192Enc(cfb_mode::BufEncryptor<Aes192>),
    Aes256Enc(cfb_mode::BufEncryptor<Aes256>),
    Aes128Dec(cfb_mode::BufDecryptor<Aes128>),
    Aes192Dec(cfb_mode::BufDecryptor<Aes192>),
    Aes256Dec(cfb_mode::BufDecryptor<Aes256>),
    Rc4Enc(rc4::Rc4<rc4::consts::U16>),
    Rc4Dec(rc4::Rc4<rc4::consts::U16>),
    Chacha20LegacyEnc(chacha20::ChaCha20Legacy),
    Chacha20LegacyDec(chacha20::ChaCha20Legacy),
    Chacha20IetfEnc(chacha20::ChaCha20),
    Chacha20IetfDec(chacha20::ChaCha20),
}

impl SsrStreamCipher {
    fn apply(&mut self, data: &mut [u8]) {
        use cipher::StreamCipher;
        match self {
            Self::Aes128Enc(cipher) => cipher.encrypt(data),
            Self::Aes192Enc(cipher) => cipher.encrypt(data),
            Self::Aes256Enc(cipher) => cipher.encrypt(data),
            Self::Aes128Dec(cipher) => cipher.decrypt(data),
            Self::Aes192Dec(cipher) => cipher.decrypt(data),
            Self::Aes256Dec(cipher) => cipher.decrypt(data),
            Self::Rc4Enc(cipher) => cipher.apply_keystream(data),
            Self::Rc4Dec(cipher) => cipher.apply_keystream(data),
            Self::Chacha20LegacyEnc(cipher) => cipher.apply_keystream(data),
            Self::Chacha20LegacyDec(cipher) => cipher.apply_keystream(data),
            Self::Chacha20IetfEnc(cipher) => cipher.apply_keystream(data),
            Self::Chacha20IetfDec(cipher) => cipher.apply_keystream(data),
        }
    }
}
