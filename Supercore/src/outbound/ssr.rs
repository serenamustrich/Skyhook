use std::{net::SocketAddr, time::Duration};

use anyhow::{anyhow, Context};
use async_trait::async_trait;
use tokio::{io::AsyncWriteExt, net::UdpSocket, time::timeout};

use crate::routing::Destination;

use super::{
    build_ssr_http_obfs_request, build_ssr_tls12_ticket_client_hello, connect_tcp,
    encode_socks5_destination, evp_bytes_to_key, parse_socks5_destination_prefix,
    resolve_udp_socket_addr, spawn_ssr_stream, spawn_ssr_tls12_ticket_stream,
    ssr_auth_chain_udp_decode, ssr_auth_chain_udp_encode, ssr_auth_hash,
    ssr_chain_user_credentials, ssr_is_auth_chain, ssr_obfs_mode, ssr_protocol_kind,
    ssr_user_credentials, BoxedStream, Outbound, OutboundCapability, SsrCipher, SsrObfsMode,
    SsrProtocolEncoder, SsrProtocolKind,
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
