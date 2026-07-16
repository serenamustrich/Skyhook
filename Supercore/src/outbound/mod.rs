use std::{
    collections::{BTreeMap, HashMap},
    io::{Cursor, Error, ErrorKind, IoSliceMut},
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{Arc, Mutex as StdMutex},
    task::{Context as TaskContext, Poll},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use aes::cipher::{Block, BlockDecrypt, BlockEncrypt, KeyInit as BlockKeyInit};
use aes::{Aes128, Aes192, Aes256};
use aes_gcm::{aead::Aead, Aes128Gcm, Aes256Gcm};
use anyhow::{anyhow, Context};
use argon2::{
    Algorithm as Argon2Algorithm, Argon2, Params as Argon2Params, Version as Argon2Version,
};
use async_trait::async_trait;
use blake2::{digest::VariableOutput, Blake2bVar};
use bytes::{Bytes, BytesMut};
use cfb_mode::cipher::KeyIvInit;
use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305};
use hkdf::Hkdf;
use ipnet::IpNet;
use md5::{Digest, Md5};
use russh::{client as ssh_client, ChannelMsg, Disconnect};
use rustls::{
    client::{DangerousClientHelloSessionIdProvider, Resumption},
    crypto::{aws_lc_rs, ActiveKeyExchange, SharedSecret, SupportedKxGroup},
    ffdhe_groups::FfdheGroup,
    ClientConfig, Error as RustlsError, NamedGroup, ProtocolVersion, RootCertStore,
};
use rustls_pki_types::ServerName;
use sha1::Sha1;
use sha2::{Sha224, Sha256};
use sha3::{
    digest::{ExtendableOutput, XofReader},
    Shake128,
};
use tokio::{
    io::{
        AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf, ReadHalf,
        WriteHalf,
    },
    net::{lookup_host, UdpSocket},
    sync::Mutex as TokioMutex,
    task::JoinHandle,
    time::timeout,
};
use tokio_rustls::TlsConnector;
use uuid::Uuid;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

use crate::{
    config::{OutboundConfig, ShadowsocksPluginConfig},
    routing::Destination,
    telemetry::Telemetry,
};

mod anytls;
pub mod context;
mod direct;
pub mod error;
mod factory;
mod group;
mod http_proxy;
mod naive;
mod pool;
mod registry;
mod reject;
mod shadowsocks;
mod shadowtls;
mod snell;
mod socks5;
mod ssh;
mod ssr;
mod target;
mod traits;
mod transports;
mod udp;
mod unsupported;
mod wireguard;

use anytls::AnyTlsOutbound;
use direct::DirectOutbound;
use http_proxy::HttpOutbound;
use naive::NaiveOutbound;
use pool::IdlePool;
use registry::{attach_groups, insert_leaf};
use reject::RejectOutbound;
use shadowsocks::ShadowsocksOutbound;
use shadowtls::ShadowTlsOutbound;
use snell::SnellOutbound;
use socks5::Socks5Outbound;
use ssh::SshOutbound;
use ssr::SsrOutbound;
use target::{parse_socks5_destination_prefix, read_socks5_destination_after_atyp};
use transports::{
    connect_tcp, open_grpc_tunnel, open_h2_tunnel, open_http_upgrade_tunnel,
    perform_websocket_handshake, perform_websocket_handshake_with_headers, quic_client_config,
    spawn_websocket_stream, tls_client_config, NoCertificateVerification,
};
use udp::{resolve_udp_socket_addr, RoundRobinSessionPool};
use unsupported::UnsupportedProtocolOutbound;
use wireguard::WireGuardOutbound;

pub use factory::build_outbounds;
pub use target::encode_socks5_destination;
pub use traits::{BoxedStream, Outbound, OutboundCapability, OutboundMap, ProxyStream};

#[cfg(test)]
use self::{
    context::DialContext,
    error::{OutboundError, OutboundErrorKind},
};

#[cfg(test)]
use group::GroupOutbound;

#[cfg(test)]
use transports::{
    read_websocket_frame, render_transport_headers, websocket_accept_key,
    write_websocket_binary_frame, write_websocket_frame,
};

const UDP_SESSION_POOL_SIZE: usize = 4;

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

const SNELL_V4_POOL_SIZE: usize = 10;
const SNELL_V4_POOL_IDLE_AGE: Duration = Duration::from_secs(15);

struct SnellV4ConnectionPool {
    idle: IdlePool<SnellV4PooledConnection>,
}

impl Default for SnellV4ConnectionPool {
    fn default() -> Self {
        Self {
            idle: IdlePool::new(SNELL_V4_POOL_SIZE, SNELL_V4_POOL_IDLE_AGE),
        }
    }
}

impl SnellV4ConnectionPool {
    fn take(&mut self) -> Option<SnellV4PooledConnection> {
        self.idle.take()
    }

    fn put(&mut self, connection: SnellV4PooledConnection) {
        self.idle.put(connection);
    }
}

struct SnellV4PooledConnection {
    reader: SnellV4PooledReader,
    writer: SnellV4PooledWriter,
}

impl SnellV4PooledConnection {
    fn new(
        stream: BoxedStream,
        psk: &[u8],
        plugin: Option<ShadowsocksPluginConfig>,
        server: String,
        port: u16,
    ) -> anyhow::Result<Self> {
        let mut salt = [0u8; SNELL_V4_SALT_LEN];
        getrandom::fill(&mut salt)
            .map_err(|error| anyhow!("failed to generate snell v4 reuse salt: {error}"))?;
        let upload_key = derive_snell_subkey(SsCipher::Aes128Gcm, psk, &salt)?;
        let (remote_read, remote_write) = tokio::io::split(stream);
        Ok(Self {
            reader: SnellV4PooledReader {
                remote: remote_read,
                plugin: plugin.clone(),
                psk: psk.to_vec(),
                download_key: None,
                download_nonce: [0u8; SS_NONCE_LEN],
                http_initialized: false,
                http_leftover: BytesMut::new(),
                tls_decoder: SimpleObfsTlsDecoder::new(),
            },
            writer: SnellV4PooledWriter {
                remote: remote_write,
                plugin,
                server,
                port,
                upload_key,
                upload_nonce: [0u8; SS_NONCE_LEN],
                salt,
                started: false,
            },
        })
    }
}

struct SnellV4PooledReader {
    remote: ReadHalf<BoxedStream>,
    plugin: Option<ShadowsocksPluginConfig>,
    psk: Vec<u8>,
    download_key: Option<Vec<u8>>,
    download_nonce: [u8; SS_NONCE_LEN],
    http_initialized: bool,
    http_leftover: BytesMut,
    tls_decoder: SimpleObfsTlsDecoder,
}

impl SnellV4PooledReader {
    async fn read_transport_exact(&mut self, length: usize) -> anyhow::Result<Vec<u8>> {
        if plugin_is_tls_obfs(self.plugin.as_ref()) {
            return self
                .tls_decoder
                .read_exact_or_eof(&mut self.remote, length)
                .await?
                .ok_or_else(|| anyhow!("snell v4 reuse TLS-obfs stream ended unexpectedly"));
        }

        if plugin_is_http_obfs(self.plugin.as_ref()) && !self.http_initialized {
            let leftover = read_http_obfs_response(&mut self.remote).await?;
            self.http_leftover.extend_from_slice(&leftover);
            self.http_initialized = true;
        }

        let mut output = vec![0u8; length];
        let buffered = length.min(self.http_leftover.len());
        if buffered > 0 {
            let chunk = self.http_leftover.split_to(buffered);
            output[..buffered].copy_from_slice(&chunk);
        }
        if buffered < length {
            self.remote
                .read_exact(&mut output[buffered..])
                .await
                .context("snell v4 reuse stream ended unexpectedly")?;
        }
        Ok(output)
    }

    async fn read_frame(&mut self) -> anyhow::Result<Vec<u8>> {
        if self.download_key.is_none() {
            let salt = self.read_transport_exact(SNELL_V4_SALT_LEN).await?;
            self.download_key = Some(derive_snell_subkey(SsCipher::Aes128Gcm, &self.psk, &salt)?);
        }
        let key = self
            .download_key
            .as_ref()
            .expect("snell v4 download key initialized")
            .clone();
        let header_cipher = self
            .read_transport_exact(SNELL_V4_HEADER_CIPHER_LEN)
            .await?;
        let header = SsCipher::Aes128Gcm.decrypt(&key, &self.download_nonce, &header_cipher)?;
        increment_nonce(&mut self.download_nonce);
        if header.len() != SNELL_V4_HEADER_PLAIN_LEN || header[0] != 4 {
            return Err(anyhow!("invalid snell v4 reuse frame header"));
        }
        let padding_len = u16::from_be_bytes([header[3], header[4]]) as usize;
        let payload_len = u16::from_be_bytes([header[5], header[6]]) as usize;
        if payload_len == 0 {
            if padding_len != 0 {
                return Err(anyhow!("snell v4 reuse zero chunk cannot contain padding"));
            }
            return Ok(Vec::new());
        }
        if payload_len > SS_CHUNK_SIZE || padding_len > SS_CHUNK_SIZE {
            return Err(anyhow!("snell v4 reuse frame is too large"));
        }
        let mut frame = self
            .read_transport_exact(padding_len + payload_len + SS_TAG_LEN)
            .await?;
        let (padding, payload_cipher) = frame.split_at_mut(padding_len);
        swap_snell_v4_padding(padding, payload_cipher);
        let payload = SsCipher::Aes128Gcm.decrypt(&key, &self.download_nonce, payload_cipher)?;
        increment_nonce(&mut self.download_nonce);
        Ok(payload)
    }
}

struct SnellV4PooledWriter {
    remote: WriteHalf<BoxedStream>,
    plugin: Option<ShadowsocksPluginConfig>,
    server: String,
    port: u16,
    upload_key: Vec<u8>,
    upload_nonce: [u8; SS_NONCE_LEN],
    salt: [u8; SNELL_V4_SALT_LEN],
    started: bool,
}

impl SnellV4PooledWriter {
    async fn write_request(
        &mut self,
        destination: &Destination,
        version: u8,
    ) -> anyhow::Result<()> {
        let request = build_snell_tcp_handshake_with_reuse(destination, Some(version), true)?;
        let padding = if self.started {
            0
        } else {
            snell_v4_initial_padding_len()?
        };
        self.write_frame(&request, padding).await
    }

    async fn write_payload(&mut self, payload: &[u8]) -> anyhow::Result<()> {
        for chunk in payload.chunks(SS_CHUNK_SIZE) {
            self.write_frame(chunk, 0).await?;
        }
        Ok(())
    }

    async fn write_zero(&mut self) -> anyhow::Result<()> {
        self.write_frame(&[], 0).await
    }

    async fn write_frame(&mut self, payload: &[u8], padding: usize) -> anyhow::Result<()> {
        let first_frame = !self.started;
        let encrypted =
            encode_snell_v4_frame(&self.upload_key, &mut self.upload_nonce, payload, padding)?;
        let wire = if first_frame {
            let mut initial = self.salt.to_vec();
            initial.extend_from_slice(&encrypted);
            if let Some(plugin) = self.plugin.as_ref() {
                apply_shadowsocks_plugin_request(plugin, &self.server, self.port, initial)?
            } else {
                initial
            }
        } else if plugin_is_tls_obfs(self.plugin.as_ref()) {
            wrap_simple_obfs_tls_app_data(&encrypted)
        } else {
            encrypted
        };
        self.remote.write_all(&wire).await?;
        self.remote.flush().await?;
        self.started = true;
        Ok(())
    }
}

const SNELL_COMMAND_CONNECT: u8 = 1;
const SNELL_COMMAND_CONNECT_REUSE: u8 = 5;
const SNELL_COMMAND_UDP: u8 = 6;
const SNELL_COMMAND_UDP_FORWARD: u8 = 1;
const SNELL_V4_SALT_LEN: usize = 16;
const SNELL_V4_HEADER_PLAIN_LEN: usize = 7;
const SNELL_V4_HEADER_CIPHER_LEN: usize = SNELL_V4_HEADER_PLAIN_LEN + SS_TAG_LEN;

fn validate_snell_version(version: Option<u8>) -> anyhow::Result<u8> {
    let version = version.unwrap_or(3);
    if matches!(version, 1..=5) {
        Ok(version)
    } else {
        Err(anyhow!(
            "unsupported snell version {version}; supported: 1, 2, 3, 4, 5"
        ))
    }
}

fn snell_cipher(version: u8, method: Option<&str>) -> anyhow::Result<SsCipher> {
    if version >= 4 {
        let method = method
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("aes-128-gcm");
        if !method.eq_ignore_ascii_case("aes-128-gcm") {
            return Err(anyhow!(
                "snell v4/v5 requires aes-128-gcm; configured method is {method}"
            ));
        }
        return Ok(SsCipher::Aes128Gcm);
    }
    let default_method = if version == 1 {
        "chacha20-ietf-poly1305"
    } else {
        "aes-128-gcm"
    };
    let method = method
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(default_method);
    let cipher = SsCipher::from_method(method)
        .with_context(|| format!("unsupported snell method {method}"))?;
    if cipher.is_blake3() {
        return Err(anyhow!(
            "snell does not support Shadowsocks 2022 method {method}"
        ));
    }
    Ok(cipher)
}

fn snell_obfs_plugin(
    obfs: Option<&str>,
    obfs_host: Option<&str>,
    server: &str,
) -> anyhow::Result<Option<ShadowsocksPluginConfig>> {
    let Some(obfs) = obfs.map(str::trim).filter(|value| {
        !value.is_empty()
            && !value.eq_ignore_ascii_case("none")
            && !value.eq_ignore_ascii_case("off")
    }) else {
        return Ok(None);
    };
    let mode = match obfs.to_ascii_lowercase().as_str() {
        "http" | "http_simple" | "http-simple" => "http_simple",
        "tls" | "simple-obfs-tls" | "obfs-tls" => "tls",
        _ => {
            return Err(anyhow!(
                "unsupported snell obfs {obfs}; supported: http, tls"
            ))
        }
    };
    Ok(Some(ShadowsocksPluginConfig {
        mode: mode.to_string(),
        host: Some(
            obfs_host
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .unwrap_or(server)
                .to_string(),
        ),
        path: None,
        tls: false,
        skip_cert_verify: false,
    }))
}

fn build_snell_tcp_handshake(
    destination: &Destination,
    snell_version: Option<u8>,
) -> anyhow::Result<Vec<u8>> {
    build_snell_tcp_handshake_with_reuse(destination, snell_version, false)
}

fn build_snell_tcp_handshake_with_reuse(
    destination: &Destination,
    snell_version: Option<u8>,
    reuse: bool,
) -> anyhow::Result<Vec<u8>> {
    if destination.host.len() > 255 {
        return Err(anyhow!("snell destination host is too long"));
    }
    let command = match snell_version.unwrap_or(3) {
        2 => SNELL_COMMAND_CONNECT_REUSE,
        4 | 5 if reuse => SNELL_COMMAND_CONNECT_REUSE,
        1 | 3 | 4 | 5 => SNELL_COMMAND_CONNECT,
        version => {
            return Err(anyhow!(
                "unsupported snell version {version}; supported: 1, 2, 3, 4, 5"
            ))
        }
    };
    let mut output = Vec::with_capacity(4 + destination.host.len() + 2);
    output.push(1);
    output.push(command);
    output.push(0);
    output.push(destination.host.len() as u8);
    output.extend_from_slice(destination.host.as_bytes());
    output.extend_from_slice(&destination.port.to_be_bytes());
    Ok(output)
}

fn build_snell_udp_packet(destination: &Destination, payload: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut output = Vec::with_capacity(destination.host.len() + payload.len() + 24);
    output.push(SNELL_COMMAND_UDP_FORWARD);
    match destination.host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            output.extend_from_slice(&[0, 4]);
            output.extend_from_slice(&ip.octets());
        }
        Ok(IpAddr::V6(ip)) => {
            output.extend_from_slice(&[0, 6]);
            output.extend_from_slice(&ip.octets());
        }
        Err(_) => {
            if destination.host.len() > u8::MAX as usize {
                return Err(anyhow!("snell UDP destination host is too long"));
            }
            output.push(destination.host.len() as u8);
            output.extend_from_slice(destination.host.as_bytes());
        }
    }
    output.extend_from_slice(&destination.port.to_be_bytes());
    output.extend_from_slice(payload);
    Ok(output)
}

fn parse_snell_udp_response(packet: &[u8]) -> anyhow::Result<Vec<u8>> {
    if packet.is_empty() {
        return Err(anyhow!("snell UDP response is empty"));
    }
    let mut offset = 0;
    if packet[0] == SNELL_COMMAND_UDP_FORWARD {
        offset += 1;
        let address_len = *packet
            .get(offset)
            .ok_or_else(|| anyhow!("snell UDP response is missing address length"))?
            as usize;
        offset += 1;
        if address_len == 0 {
            let version = *packet
                .get(offset)
                .ok_or_else(|| anyhow!("snell UDP response is missing IP version"))?;
            offset += 1;
            offset += match version {
                4 => 4,
                6 => 16,
                _ => return Err(anyhow!("invalid snell UDP IP version {version}")),
            };
        } else {
            offset += address_len;
        }
    } else {
        offset += match packet[0] {
            4 => 1 + 4,
            6 => 1 + 16,
            version => return Err(anyhow!("invalid snell UDP response IP version {version}")),
        };
    }
    offset = offset
        .checked_add(2)
        .ok_or_else(|| anyhow!("snell UDP response offset overflow"))?;
    if offset > packet.len() {
        return Err(anyhow!("snell UDP response address is truncated"));
    }
    Ok(packet[offset..].to_vec())
}

fn validate_snell_response(response: &[u8], operation: &str) -> anyhow::Result<()> {
    match response.first().copied() {
        Some(0) => Ok(()),
        Some(2) => {
            let message = response
                .get(3..)
                .and_then(|bytes| std::str::from_utf8(bytes).ok())
                .unwrap_or("server error");
            Err(anyhow!("snell {operation} rejected: {message}"))
        }
        Some(code) => Err(anyhow!(
            "snell {operation} returned unsupported response {code}"
        )),
        None => Err(anyhow!("snell {operation} response is empty")),
    }
}

fn derive_snell_subkey(cipher: SsCipher, password: &[u8], salt: &[u8]) -> anyhow::Result<Vec<u8>> {
    let params = Argon2Params::new(8, 3, 1, Some(32))
        .map_err(|error| anyhow!("invalid snell argon2 params: {error}"))?;
    let argon2 = Argon2::new(Argon2Algorithm::Argon2id, Argon2Version::V0x13, params);
    let mut output = vec![0u8; 32];
    argon2
        .hash_password_into(password, salt, &mut output)
        .map_err(|error| anyhow!("failed to derive snell session key: {error}"))?;
    output.truncate(cipher.key_len());
    Ok(output)
}

fn snell_v4_initial_padding_len() -> anyhow::Result<usize> {
    let mut random = [0u8; 2];
    getrandom::fill(&mut random)
        .map_err(|error| anyhow!("failed to generate snell v4 padding length: {error}"))?;
    Ok(0x100 + usize::from(u16::from_le_bytes(random) % 0x100))
}

fn encode_snell_v4_frame(
    key: &[u8],
    nonce: &mut [u8],
    payload: &[u8],
    padding_len: usize,
) -> anyhow::Result<Vec<u8>> {
    if payload.len() > SS_CHUNK_SIZE || padding_len > SS_CHUNK_SIZE {
        return Err(anyhow!("snell v4 frame is too large"));
    }
    if payload.is_empty() && padding_len != 0 {
        return Err(anyhow!("snell v4 zero chunk cannot contain padding"));
    }
    let mut header = [0u8; SNELL_V4_HEADER_PLAIN_LEN];
    header[0] = 4;
    header[3..5].copy_from_slice(&(padding_len as u16).to_be_bytes());
    header[5..7].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    let header_cipher = SsCipher::Aes128Gcm.encrypt(key, nonce, &header)?;
    increment_nonce(nonce);

    let mut payload_cipher = if payload.is_empty() {
        Vec::new()
    } else {
        let encrypted = SsCipher::Aes128Gcm.encrypt(key, nonce, payload)?;
        increment_nonce(nonce);
        encrypted
    };
    let mut padding = vec![0u8; padding_len];
    if padding_len > 0 {
        getrandom::fill(&mut padding)
            .map_err(|error| anyhow!("failed to generate snell v4 padding: {error}"))?;
        swap_snell_v4_padding(&mut padding, &mut payload_cipher);
    }

    let mut frame = Vec::with_capacity(header_cipher.len() + padding.len() + payload_cipher.len());
    frame.extend_from_slice(&header_cipher);
    frame.extend_from_slice(&padding);
    frame.extend_from_slice(&payload_cipher);
    Ok(frame)
}

fn swap_snell_v4_padding(padding: &mut [u8], payload_cipher: &mut [u8]) {
    let limit = padding.len().min(payload_cipher.len());
    for index in (0..limit).step_by(2) {
        std::mem::swap(&mut padding[index], &mut payload_cipher[index]);
    }
}

async fn read_snell_v4_frame<R>(
    reader: &mut R,
    key: &[u8],
    nonce: &mut [u8],
) -> anyhow::Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut header_cipher = [0u8; SNELL_V4_HEADER_CIPHER_LEN];
    reader.read_exact(&mut header_cipher).await?;
    let header = SsCipher::Aes128Gcm.decrypt(key, nonce, &header_cipher)?;
    increment_nonce(nonce);
    if header.len() != SNELL_V4_HEADER_PLAIN_LEN || header[0] != 4 {
        return Err(anyhow!("invalid snell v4 frame header"));
    }
    let padding_len = u16::from_be_bytes([header[3], header[4]]) as usize;
    let payload_len = u16::from_be_bytes([header[5], header[6]]) as usize;
    if payload_len == 0 {
        if padding_len != 0 {
            return Err(anyhow!("snell v4 zero chunk cannot contain padding"));
        }
        return Ok(Vec::new());
    }
    if payload_len > SS_CHUNK_SIZE || padding_len > SS_CHUNK_SIZE {
        return Err(anyhow!("snell v4 frame is too large"));
    }
    let mut frame = vec![0u8; padding_len + payload_len + SS_TAG_LEN];
    reader.read_exact(&mut frame).await?;
    let (padding, payload_cipher) = frame.split_at_mut(padding_len);
    swap_snell_v4_padding(padding, payload_cipher);
    let payload = SsCipher::Aes128Gcm.decrypt(key, nonce, payload_cipher)?;
    increment_nonce(nonce);
    Ok(payload)
}

async fn read_snell_v4_frame_from_tls_obfs<R>(
    decoder: &mut SimpleObfsTlsDecoder,
    reader: &mut R,
    key: &[u8],
    nonce: &mut [u8],
) -> anyhow::Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let header_cipher = decoder
        .read_exact_or_eof(reader, SNELL_V4_HEADER_CIPHER_LEN)
        .await?
        .ok_or_else(|| anyhow!("snell v4 TLS-obfs stream ended before frame header"))?;
    let header = SsCipher::Aes128Gcm.decrypt(key, nonce, &header_cipher)?;
    increment_nonce(nonce);
    if header.len() != SNELL_V4_HEADER_PLAIN_LEN || header[0] != 4 {
        return Err(anyhow!("invalid snell v4 frame header"));
    }
    let padding_len = u16::from_be_bytes([header[3], header[4]]) as usize;
    let payload_len = u16::from_be_bytes([header[5], header[6]]) as usize;
    if payload_len == 0 {
        if padding_len != 0 {
            return Err(anyhow!("snell v4 zero chunk cannot contain padding"));
        }
        return Ok(Vec::new());
    }
    if payload_len > SS_CHUNK_SIZE || padding_len > SS_CHUNK_SIZE {
        return Err(anyhow!("snell v4 frame is too large"));
    }
    let mut frame = decoder
        .read_exact_or_eof(reader, padding_len + payload_len + SS_TAG_LEN)
        .await?
        .ok_or_else(|| anyhow!("snell v4 TLS-obfs stream ended before frame payload"))?;
    let (padding, payload_cipher) = frame.split_at_mut(padding_len);
    swap_snell_v4_padding(padding, payload_cipher);
    let payload = SsCipher::Aes128Gcm.decrypt(key, nonce, payload_cipher)?;
    increment_nonce(nonce);
    Ok(payload)
}

type ShadowsocksUdpPool = RoundRobinSessionPool<ShadowsocksUdpSession>;

struct ShadowsocksUdpSession {
    udp: UdpSocket,
    server: SocketAddr,
    ss2022: Option<Ss2022UdpState>,
}

struct Ss2022UdpState {
    client_session_id: [u8; 8],
    next_packet_id: u64,
    server_sessions: HashMap<[u8; 8], Ss2022ServerSession>,
}

struct Ss2022ServerSession {
    replay: Ss2022ReplayWindow,
    last_seen: Instant,
}

#[derive(Default)]
struct Ss2022ReplayWindow {
    initialized: bool,
    highest: u64,
    bitmap: u64,
}

impl Ss2022UdpState {
    fn new() -> anyhow::Result<Self> {
        let mut client_session_id = [0u8; 8];
        getrandom::fill(&mut client_session_id).map_err(|error| {
            anyhow!("failed to generate shadowsocks 2022 UDP session ID: {error}")
        })?;
        Ok(Self {
            client_session_id,
            next_packet_id: 0,
            server_sessions: HashMap::new(),
        })
    }

    fn next_client_packet(&mut self) -> anyhow::Result<([u8; 8], u64)> {
        let packet_id = self.next_packet_id;
        self.next_packet_id = self
            .next_packet_id
            .checked_add(1)
            .ok_or_else(|| anyhow!("shadowsocks 2022 UDP packet ID exhausted"))?;
        Ok((self.client_session_id, packet_id))
    }

    fn accept_server_packet(
        &mut self,
        server_session_id: [u8; 8],
        packet_id: u64,
    ) -> anyhow::Result<()> {
        let now = Instant::now();
        self.server_sessions
            .retain(|_, session| now.duration_since(session.last_seen) < Duration::from_secs(60));
        if self.server_sessions.len() >= 64
            && !self.server_sessions.contains_key(&server_session_id)
        {
            return Err(anyhow!(
                "too many active shadowsocks 2022 UDP server sessions"
            ));
        }
        let session = self
            .server_sessions
            .entry(server_session_id)
            .or_insert_with(|| Ss2022ServerSession {
                replay: Ss2022ReplayWindow::default(),
                last_seen: now,
            });
        if !session.replay.accept(packet_id) {
            return Err(anyhow!(
                "shadowsocks 2022 UDP replayed or out-of-window packet"
            ));
        }
        session.last_seen = now;
        Ok(())
    }
}

impl Ss2022ReplayWindow {
    fn accept(&mut self, packet_id: u64) -> bool {
        if !self.initialized {
            self.initialized = true;
            self.highest = packet_id;
            self.bitmap = 1;
            return true;
        }
        if packet_id > self.highest {
            let shift = packet_id - self.highest;
            self.bitmap = if shift >= 64 {
                1
            } else {
                (self.bitmap << shift) | 1
            };
            self.highest = packet_id;
            return true;
        }
        let distance = self.highest - packet_id;
        if distance >= 64 {
            return false;
        }
        let mask = 1u64 << distance;
        if self.bitmap & mask != 0 {
            return false;
        }
        self.bitmap |= mask;
        true
    }
}

struct TrojanOutbound {
    name: String,
    server: String,
    port: u16,
    password: String,
    sni: Option<String>,
    skip_cert_verify: bool,
    network: Option<String>,
    ws_path: Option<String>,
    ws_host: Option<String>,
    grpc_service_name: Option<String>,
    transport_headers: BTreeMap<String, String>,
    alpn: Vec<String>,
    udp_sessions: TokioMutex<TrojanUdpPool>,
}

type TrojanUdpPool = RoundRobinSessionPool<TrojanUdpSession>;

struct TrojanUdpSession {
    stream: BoxedStream,
}

struct VmessOutbound {
    name: String,
    server: String,
    port: u16,
    uuid: String,
    cipher: String,
    tls: bool,
    sni: Option<String>,
    skip_cert_verify: bool,
    network: Option<String>,
    ws_path: Option<String>,
    ws_host: Option<String>,
    grpc_service_name: Option<String>,
    udp_sessions: TokioMutex<VmessUdpPool>,
}

struct VlessOutbound {
    name: String,
    server: String,
    port: u16,
    uuid: String,
    flow: Option<String>,
    security: Option<String>,
    tls: bool,
    sni: Option<String>,
    skip_cert_verify: bool,
    network: Option<String>,
    ws_path: Option<String>,
    ws_host: Option<String>,
    grpc_service_name: Option<String>,
    reality_public_key: Option<String>,
    reality_short_id: Option<String>,
    reality_fingerprint: Option<String>,
    reality_spider_x: Option<String>,
    udp_sessions: TokioMutex<VlessUdpPool>,
}

#[derive(Default)]
struct VmessUdpPool {
    buckets: HashMap<String, UdpSessionBucket<VmessUdpSession>>,
}

#[derive(Default)]
struct VlessUdpPool {
    buckets: HashMap<String, UdpSessionBucket<VlessUdpSession>>,
}

struct UdpSessionBucket<T> {
    sessions: Vec<Arc<TokioMutex<T>>>,
    next_index: usize,
}

impl<T> Default for UdpSessionBucket<T> {
    fn default() -> Self {
        Self {
            sessions: Vec::new(),
            next_index: 0,
        }
    }
}

struct VmessUdpSession {
    stream: BoxedStream,
    upload: VmessUploadState,
    download: VmessDownloadState,
    response_header_read: bool,
}

struct VlessUdpSession {
    stream: BoxedStream,
    response_header_read: bool,
}

struct Hysteria2Outbound {
    name: String,
    server: String,
    port: u16,
    password: String,
    sni: Option<String>,
    skip_cert_verify: bool,
    obfs: Option<String>,
    obfs_password: Option<String>,
    alpn: Option<String>,
    udp_sessions: TokioMutex<Hysteria2UdpPool>,
}

type Hysteria2UdpPool = RoundRobinSessionPool<Hysteria2UdpSession>;

struct Hysteria2UdpSession {
    _endpoint: quinn::Endpoint,
    connection: quinn::Connection,
    h3_driver: JoinHandle<()>,
    session_id: u32,
    next_packet_id: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Hysteria2ObfsKind {
    Salamander,
    Gecko,
}

#[derive(Debug, Clone)]
struct Hysteria2ObfsConfig {
    kind: Hysteria2ObfsKind,
    key: Vec<u8>,
}

impl Drop for Hysteria2UdpSession {
    fn drop(&mut self) {
        self.connection
            .close(quinn::VarInt::from_u32(0), b"supercore close");
        self.h3_driver.abort();
    }
}

struct TuicOutbound {
    name: String,
    server: String,
    port: u16,
    uuid: String,
    password: String,
    sni: Option<String>,
    skip_cert_verify: bool,
    congestion_control: Option<String>,
    udp_relay_mode: Option<String>,
    alpn: Option<String>,
    udp_sessions: TokioMutex<TuicUdpPool>,
}

#[derive(Default)]
struct TuicUdpPool {
    mode: Option<String>,
    sessions: RoundRobinSessionPool<TuicUdpSession>,
}

struct TuicUdpSession {
    _endpoint: quinn::Endpoint,
    connection: quinn::Connection,
    mode: String,
    associate_id: u16,
    next_packet_id: u16,
}

impl Drop for TuicUdpSession {
    fn drop(&mut self) {
        self.connection
            .close(quinn::VarInt::from_u32(0), b"supercore close");
    }
}

#[async_trait]
impl Outbound for VmessOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "vmess"
    }

    fn capability(&self) -> OutboundCapability {
        OutboundCapability::tcp_udp("vmess-command-udp-session-pool")
    }

    async fn connect(
        &self,
        destination: &Destination,
        timeout_ms: u64,
    ) -> anyhow::Result<BoxedStream> {
        let user_id = Uuid::parse_str(&self.uuid)
            .map_err(|error| anyhow!("invalid vmess uuid for {}: {error}", self.name))?;
        let cipher = VmessCipher::from_name(&self.cipher)?;
        let stream = self.open_transport(timeout_ms).await?;
        setup_vmess_stream(stream, &user_id, cipher, destination).await
    }

    async fn udp_exchange(
        &self,
        destination: &Destination,
        payload: &[u8],
        timeout_ms: u64,
    ) -> anyhow::Result<Vec<u8>> {
        let session_handle = self.vmess_udp_session(destination, timeout_ms).await?;
        let exchange = {
            let mut session = session_handle.lock().await;
            let VmessUdpSession {
                stream,
                upload,
                download,
                response_header_read,
            } = &mut *session;
            timeout(Duration::from_millis(timeout_ms), async {
                write_vmess_chunk(stream, upload, payload).await?;
                if !*response_header_read {
                    read_vmess_response_header(stream, download).await?;
                    *response_header_read = true;
                }
                read_vmess_chunk(stream, download)
                    .await?
                    .ok_or_else(|| anyhow!("vmess udp response ended before payload"))
            })
            .await
            .context("vmess udp exchange timed out")?
        };
        if exchange.is_err() {
            self.remove_vmess_udp_session(destination, &session_handle)
                .await;
        }
        exchange
    }
}

impl VmessOutbound {
    async fn open_transport(&self, timeout_ms: u64) -> anyhow::Result<BoxedStream> {
        let network = self
            .network
            .as_deref()
            .unwrap_or("tcp")
            .to_ascii_lowercase();
        if !matches!(
            network.as_str(),
            "tcp" | "ws" | "websocket" | "grpc" | "h2" | "http"
        ) {
            return Err(anyhow!("unsupported vmess network {network}"));
        }
        let tcp = connect_tcp(&format!("{}:{}", self.server, self.port), timeout_ms).await?;

        if self.tls {
            let server_name = self.sni.as_deref().unwrap_or(&self.server).to_string();
            let mut tls_config = tls_client_config(self.skip_cert_verify)?;
            if matches!(network.as_str(), "grpc" | "h2" | "http") {
                tls_config.alpn_protocols = vec![b"h2".to_vec()];
            }
            let connector = TlsConnector::from(Arc::new(tls_config));
            let tls_server_name = ServerName::try_from(server_name.clone())
                .map_err(|error| anyhow!("invalid vmess server name: {error}"))?;
            let mut stream = timeout(
                Duration::from_millis(timeout_ms),
                connector.connect(tls_server_name, tcp),
            )
            .await
            .context("vmess tls handshake timed out")?
            .context("vmess tls handshake failed")?;
            if network == "ws" || network == "websocket" {
                perform_websocket_handshake(
                    &mut stream,
                    self.ws_host.as_deref().unwrap_or(&server_name),
                    self.ws_path.as_deref().unwrap_or("/"),
                )
                .await?;
                return Ok(Box::new(spawn_websocket_stream(stream)));
            }
            if network == "grpc" {
                return open_grpc_tunnel(
                    stream,
                    self.ws_host.as_deref().unwrap_or(&server_name),
                    self.grpc_service_name.as_deref(),
                    timeout_ms,
                )
                .await
                .map(|stream| Box::new(stream) as BoxedStream);
            }
            if matches!(network.as_str(), "h2" | "http") {
                return open_h2_tunnel(
                    stream,
                    self.ws_host.as_deref().unwrap_or(&server_name),
                    self.ws_path.as_deref().unwrap_or("/"),
                    timeout_ms,
                )
                .await
                .map(|stream| Box::new(stream) as BoxedStream);
            }
            Ok(Box::new(stream))
        } else {
            let mut stream = tcp;
            if network == "ws" || network == "websocket" {
                perform_websocket_handshake(
                    &mut stream,
                    self.ws_host.as_deref().unwrap_or(&self.server),
                    self.ws_path.as_deref().unwrap_or("/"),
                )
                .await?;
                return Ok(Box::new(spawn_websocket_stream(stream)));
            }
            if network == "grpc" {
                return open_grpc_tunnel(
                    stream,
                    self.ws_host.as_deref().unwrap_or(&self.server),
                    self.grpc_service_name.as_deref(),
                    timeout_ms,
                )
                .await
                .map(|stream| Box::new(stream) as BoxedStream);
            }
            if matches!(network.as_str(), "h2" | "http") {
                return open_h2_tunnel(
                    stream,
                    self.ws_host.as_deref().unwrap_or(&self.server),
                    self.ws_path.as_deref().unwrap_or("/"),
                    timeout_ms,
                )
                .await
                .map(|stream| Box::new(stream) as BoxedStream);
            }
            Ok(Box::new(stream))
        }
    }

    async fn vmess_udp_session(
        &self,
        destination: &Destination,
        timeout_ms: u64,
    ) -> anyhow::Result<Arc<TokioMutex<VmessUdpSession>>> {
        let key = destination.authority();
        let mut pool = self.udp_sessions.lock().await;
        let bucket = pool.buckets.entry(key.clone()).or_default();
        if bucket.sessions.len() < UDP_SESSION_POOL_SIZE {
            let session = Arc::new(TokioMutex::new(
                self.open_vmess_udp_session(destination, timeout_ms).await?,
            ));
            bucket.sessions.push(session.clone());
            bucket.next_index = bucket.sessions.len() % UDP_SESSION_POOL_SIZE;
            return Ok(session);
        }
        let index = bucket.next_index % bucket.sessions.len();
        bucket.next_index = (bucket.next_index + 1) % bucket.sessions.len();
        Ok(bucket.sessions[index].clone())
    }

    async fn open_vmess_udp_session(
        &self,
        destination: &Destination,
        timeout_ms: u64,
    ) -> anyhow::Result<VmessUdpSession> {
        let user_id = Uuid::parse_str(&self.uuid)
            .map_err(|error| anyhow!("invalid vmess uuid for {}: {error}", self.name))?;
        let cipher = VmessCipher::from_name(&self.cipher)?;
        let mut stream = self.open_transport(timeout_ms).await?;
        let setup = build_vmess_setup_with_command(&user_id, cipher, destination, VMESS_CMD_UDP)?;
        timeout(Duration::from_millis(timeout_ms), async {
            stream.write_all(&setup.request).await?;
            stream.flush().await
        })
        .await
        .context("vmess udp session setup timed out")??;
        Ok(VmessUdpSession {
            stream,
            upload: setup.upload,
            download: setup.download,
            response_header_read: false,
        })
    }

    async fn remove_vmess_udp_session(
        &self,
        destination: &Destination,
        target: &Arc<TokioMutex<VmessUdpSession>>,
    ) {
        let mut pool = self.udp_sessions.lock().await;
        let key = destination.authority();
        let Some(bucket) = pool.buckets.get_mut(&key) else {
            return;
        };
        bucket
            .sessions
            .retain(|session| !Arc::ptr_eq(session, target));
        if !bucket.sessions.is_empty() {
            bucket.next_index %= bucket.sessions.len();
        } else {
            pool.buckets.remove(&key);
        }
    }
}

#[async_trait]
impl Outbound for VlessOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "vless"
    }

    fn capability(&self) -> OutboundCapability {
        if self
            .security
            .as_deref()
            .is_some_and(|value| value.eq_ignore_ascii_case("reality"))
            && self
                .reality_public_key
                .as_deref()
                .unwrap_or_default()
                .trim()
                .is_empty()
        {
            OutboundCapability::unsupported("VLESS Reality public key is required")
        } else {
            OutboundCapability::tcp_udp("vless-command-udp-session-pool")
        }
    }

    async fn connect(
        &self,
        destination: &Destination,
        timeout_ms: u64,
    ) -> anyhow::Result<BoxedStream> {
        let user_id = Uuid::parse_str(&self.uuid)
            .map_err(|error| anyhow!("invalid vless uuid for {}: {error}", self.name))?;
        let network = self
            .network
            .as_deref()
            .unwrap_or("tcp")
            .to_ascii_lowercase();
        if !matches!(
            network.as_str(),
            "tcp" | "ws" | "websocket" | "grpc" | "h2" | "http"
        ) {
            return Err(anyhow!("unsupported vless network {network}"));
        }
        let security = self
            .security
            .as_deref()
            .unwrap_or(if self.tls { "tls" } else { "none" })
            .to_ascii_lowercase();
        if !matches!(security.as_str(), "tls" | "none" | "" | "reality") {
            return Err(anyhow!("unsupported vless security {security}"));
        }
        let flow = self
            .flow
            .as_deref()
            .map(str::trim)
            .filter(|flow| !flow.is_empty());
        if let Some(flow) = flow {
            if flow != "xtls-rprx-vision" {
                return Err(anyhow!("unsupported vless flow {flow}"));
            }
            if (!self.tls && security != "reality") || network != "tcp" {
                return Err(anyhow!(
                    "vless flow {flow} requires tls/reality over tcp transport"
                ));
            }
        }
        let request = build_vless_request_with_flow(&user_id, destination, flow)?;
        let mut stream = self.open_transport(&network, timeout_ms).await?;
        stream.write_all(&request).await?;
        read_vless_response_header(&mut stream).await?;
        Ok(stream)
    }

    async fn udp_exchange(
        &self,
        destination: &Destination,
        payload: &[u8],
        timeout_ms: u64,
    ) -> anyhow::Result<Vec<u8>> {
        let user_id = Uuid::parse_str(&self.uuid)
            .map_err(|error| anyhow!("invalid vless uuid for {}: {error}", self.name))?;
        let network = self.network_name()?;
        let security = self.security_name();
        if !matches!(security.as_str(), "tls" | "none" | "" | "reality") {
            return Err(anyhow!("unsupported vless security {security}"));
        }
        if self
            .flow
            .as_deref()
            .map(str::trim)
            .filter(|flow| !flow.is_empty())
            .is_some()
        {
            return Err(anyhow!("vless udp does not support xtls flow addons"));
        }

        let packet = encode_length_prefixed_packet(payload, "vless udp")?;
        let session_handle = self
            .vless_udp_session(&user_id, destination, &network, timeout_ms)
            .await?;
        let exchange = {
            let mut session = session_handle.lock().await;
            timeout(Duration::from_millis(timeout_ms), async {
                session.stream.write_all(&packet).await?;
                session.stream.flush().await?;
                if !session.response_header_read {
                    read_vless_response_header(&mut session.stream).await?;
                    session.response_header_read = true;
                }
                read_length_prefixed_packet(&mut session.stream, "vless udp").await
            })
            .await
            .context("vless udp exchange timed out")?
        };
        if exchange.is_err() {
            self.remove_vless_udp_session(destination, &session_handle)
                .await;
        }
        exchange
    }
}

impl VlessOutbound {
    fn network_name(&self) -> anyhow::Result<String> {
        let network = self
            .network
            .as_deref()
            .unwrap_or("tcp")
            .to_ascii_lowercase();
        if !matches!(
            network.as_str(),
            "tcp" | "ws" | "websocket" | "grpc" | "h2" | "http"
        ) {
            return Err(anyhow!("unsupported vless network {network}"));
        }
        Ok(network)
    }

    fn security_name(&self) -> String {
        self.security
            .as_deref()
            .unwrap_or(if self.tls { "tls" } else { "none" })
            .to_ascii_lowercase()
    }

    async fn open_transport(&self, network: &str, timeout_ms: u64) -> anyhow::Result<BoxedStream> {
        let tcp = connect_tcp(&format!("{}:{}", self.server, self.port), timeout_ms).await?;
        let security = self.security_name();
        let tls_enabled = self.tls || security == "reality";
        if security == "reality" && matches!(network, "ws" | "websocket") {
            return Err(anyhow!(
                "vless reality does not support websocket transport"
            ));
        }
        if tls_enabled {
            let server_name = self.sni.as_deref().unwrap_or(&self.server).to_string();
            let mut tls_config = if security == "reality" {
                reality_tls_client_config(
                    self.skip_cert_verify,
                    self.reality_public_key.as_deref(),
                    self.reality_short_id.as_deref(),
                    self.reality_fingerprint.as_deref(),
                    self.reality_spider_x.as_deref(),
                )?
            } else {
                tls_client_config(self.skip_cert_verify)?
            };
            if matches!(network, "grpc" | "h2" | "http") {
                tls_config.alpn_protocols = vec![b"h2".to_vec()];
            }
            let connector = TlsConnector::from(Arc::new(tls_config));
            let tls_server_name = ServerName::try_from(server_name.clone())
                .map_err(|error| anyhow!("invalid vless server name: {error}"))?;
            let mut stream = timeout(
                Duration::from_millis(timeout_ms),
                connector.connect(tls_server_name, tcp),
            )
            .await
            .context("vless tls handshake timed out")?
            .context("vless tls handshake failed")?;
            if network == "ws" || network == "websocket" {
                perform_websocket_handshake(
                    &mut stream,
                    self.ws_host.as_deref().unwrap_or(&server_name),
                    self.ws_path.as_deref().unwrap_or("/"),
                )
                .await?;
                return Ok(Box::new(spawn_websocket_stream(stream)));
            }
            if network == "grpc" {
                return open_grpc_tunnel(
                    stream,
                    self.ws_host.as_deref().unwrap_or(&server_name),
                    self.grpc_service_name.as_deref(),
                    timeout_ms,
                )
                .await
                .map(|stream| Box::new(stream) as BoxedStream);
            }
            if matches!(network, "h2" | "http") {
                return open_h2_tunnel(
                    stream,
                    self.ws_host.as_deref().unwrap_or(&server_name),
                    self.ws_path.as_deref().unwrap_or("/"),
                    timeout_ms,
                )
                .await
                .map(|stream| Box::new(stream) as BoxedStream);
            }
            Ok(Box::new(stream))
        } else {
            let mut stream = tcp;
            if network == "ws" || network == "websocket" {
                perform_websocket_handshake(
                    &mut stream,
                    self.ws_host.as_deref().unwrap_or(&self.server),
                    self.ws_path.as_deref().unwrap_or("/"),
                )
                .await?;
                return Ok(Box::new(spawn_websocket_stream(stream)));
            }
            if network == "grpc" {
                return open_grpc_tunnel(
                    stream,
                    self.ws_host.as_deref().unwrap_or(&self.server),
                    self.grpc_service_name.as_deref(),
                    timeout_ms,
                )
                .await
                .map(|stream| Box::new(stream) as BoxedStream);
            }
            if matches!(network, "h2" | "http") {
                return open_h2_tunnel(
                    stream,
                    self.ws_host.as_deref().unwrap_or(&self.server),
                    self.ws_path.as_deref().unwrap_or("/"),
                    timeout_ms,
                )
                .await
                .map(|stream| Box::new(stream) as BoxedStream);
            }
            Ok(Box::new(stream))
        }
    }

    async fn vless_udp_session(
        &self,
        user_id: &Uuid,
        destination: &Destination,
        network: &str,
        timeout_ms: u64,
    ) -> anyhow::Result<Arc<TokioMutex<VlessUdpSession>>> {
        let key = destination.authority();
        let mut pool = self.udp_sessions.lock().await;
        let bucket = pool.buckets.entry(key.clone()).or_default();
        if bucket.sessions.len() < UDP_SESSION_POOL_SIZE {
            let session = Arc::new(TokioMutex::new(
                self.open_vless_udp_session(user_id, destination, network, timeout_ms)
                    .await?,
            ));
            bucket.sessions.push(session.clone());
            bucket.next_index = bucket.sessions.len() % UDP_SESSION_POOL_SIZE;
            return Ok(session);
        }
        let index = bucket.next_index % bucket.sessions.len();
        bucket.next_index = (bucket.next_index + 1) % bucket.sessions.len();
        Ok(bucket.sessions[index].clone())
    }

    async fn open_vless_udp_session(
        &self,
        user_id: &Uuid,
        destination: &Destination,
        network: &str,
        timeout_ms: u64,
    ) -> anyhow::Result<VlessUdpSession> {
        let mut stream = self.open_transport(network, timeout_ms).await?;
        let request =
            build_vless_request_with_command_and_flow(user_id, destination, None, VLESS_CMD_UDP)?;
        timeout(Duration::from_millis(timeout_ms), async {
            stream.write_all(&request).await?;
            stream.flush().await
        })
        .await
        .context("vless udp session setup timed out")??;
        Ok(VlessUdpSession {
            stream,
            response_header_read: false,
        })
    }

    async fn remove_vless_udp_session(
        &self,
        destination: &Destination,
        target: &Arc<TokioMutex<VlessUdpSession>>,
    ) {
        let mut pool = self.udp_sessions.lock().await;
        let key = destination.authority();
        let Some(bucket) = pool.buckets.get_mut(&key) else {
            return;
        };
        bucket
            .sessions
            .retain(|session| !Arc::ptr_eq(session, target));
        if !bucket.sessions.is_empty() {
            bucket.next_index %= bucket.sessions.len();
        } else {
            pool.buckets.remove(&key);
        }
    }
}

#[async_trait]
impl Outbound for Hysteria2Outbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "hysteria2"
    }

    fn capability(&self) -> OutboundCapability {
        match hysteria2_obfs_config(self.obfs.as_deref(), self.obfs_password.as_deref()) {
            Ok(config) => OutboundCapability::tcp_udp(match config.map(|item| item.kind) {
                Some(Hysteria2ObfsKind::Salamander) => "quic-datagram-salamander-session-pool",
                Some(Hysteria2ObfsKind::Gecko) => "quic-datagram-gecko-session-pool",
                None => "quic-datagram-session-pool",
            }),
            Err(error) => OutboundCapability::unsupported(error.to_string()),
        }
    }

    async fn connect(
        &self,
        destination: &Destination,
        timeout_ms: u64,
    ) -> anyhow::Result<BoxedStream> {
        let obfs_config =
            hysteria2_obfs_config(self.obfs.as_deref(), self.obfs_password.as_deref())?;
        let connection = open_hysteria2_connection(
            &self.server,
            self.port,
            self.sni.as_deref(),
            self.skip_cert_verify,
            &self.password,
            self.alpn.as_deref(),
            obfs_config.as_ref(),
            timeout_ms,
        )
        .await?;
        let (mut send, mut recv) = timeout(
            Duration::from_millis(timeout_ms),
            connection.connection.open_bi(),
        )
        .await
        .context("hysteria2 open stream timed out")?
        .context("hysteria2 failed to open bidirectional stream")?;
        let request = build_hysteria2_tcp_request(destination)?;
        send.write_all(&request).await?;
        send.flush().await?;
        read_hysteria2_tcp_response(&mut recv).await?;
        Ok(Box::new(Hysteria2TcpStream {
            _endpoint: connection.endpoint,
            connection: connection.connection,
            h3_driver: connection.h3_driver,
            recv,
            send,
        }))
    }

    async fn udp_exchange(
        &self,
        destination: &Destination,
        payload: &[u8],
        timeout_ms: u64,
    ) -> anyhow::Result<Vec<u8>> {
        let obfs_config =
            hysteria2_obfs_config(self.obfs.as_deref(), self.obfs_password.as_deref())?;
        let session_handle = self
            .hysteria2_udp_session(obfs_config.as_ref(), timeout_ms)
            .await?;

        let exchange = {
            let mut session = session_handle.lock().await;
            async {
                let packet_id = session.next_packet_id;
                session.next_packet_id = session.next_packet_id.wrapping_add(1);
                let messages = build_hysteria2_udp_messages(
                    session.session_id,
                    packet_id,
                    destination,
                    payload,
                    session.connection.max_datagram_size(),
                )?;
                for message in messages {
                    timeout(
                        Duration::from_millis(timeout_ms),
                        session.connection.send_datagram_wait(Bytes::from(message)),
                    )
                    .await
                    .context("hysteria2 udp send timed out")?
                    .map_err(|error| anyhow!("hysteria2 udp send failed: {error}"))?;
                }
                timeout(Duration::from_millis(timeout_ms), async {
                    let mut reassembly = Hysteria2UdpReassembly::default();
                    loop {
                        let datagram = session.connection.read_datagram().await?;
                        if let Some(payload) = parse_hysteria2_udp_message(
                            &datagram,
                            session.session_id,
                            &mut reassembly,
                        )? {
                            return Ok::<Vec<u8>, anyhow::Error>(payload);
                        }
                    }
                })
                .await
                .context("hysteria2 udp receive timed out")?
            }
            .await
        };
        if exchange.is_err() {
            self.remove_hysteria2_udp_session(&session_handle).await;
        }
        exchange
    }
}

impl Hysteria2Outbound {
    async fn hysteria2_udp_session(
        &self,
        obfs_config: Option<&Hysteria2ObfsConfig>,
        timeout_ms: u64,
    ) -> anyhow::Result<Arc<TokioMutex<Hysteria2UdpSession>>> {
        let mut pool = self.udp_sessions.lock().await;
        if pool.len() < UDP_SESSION_POOL_SIZE {
            let connection = open_hysteria2_connection(
                &self.server,
                self.port,
                self.sni.as_deref(),
                self.skip_cert_verify,
                &self.password,
                self.alpn.as_deref(),
                obfs_config,
                timeout_ms,
            )
            .await?;
            if !connection.udp_supported {
                connection
                    .connection
                    .close(quinn::VarInt::from_u32(0), b"supercore close");
                connection.h3_driver.abort();
                return Err(anyhow!("hysteria2 server does not support udp relay"));
            }
            let session = Arc::new(TokioMutex::new(Hysteria2UdpSession {
                _endpoint: connection.endpoint,
                connection: connection.connection,
                h3_driver: connection.h3_driver,
                session_id: random_u32()?,
                next_packet_id: random_u16()?,
            }));
            pool.push(session.clone());
            return Ok(session);
        }
        pool.next()
            .ok_or_else(|| anyhow!("hysteria2 UDP session pool is unexpectedly empty"))
    }

    async fn remove_hysteria2_udp_session(&self, target: &Arc<TokioMutex<Hysteria2UdpSession>>) {
        let mut pool = self.udp_sessions.lock().await;
        pool.remove(target);
    }
}

struct Hysteria2Connection {
    endpoint: quinn::Endpoint,
    connection: quinn::Connection,
    h3_driver: JoinHandle<()>,
    udp_supported: bool,
}

#[derive(Debug)]
struct SalamanderUdpSocket {
    inner: Arc<dyn quinn::AsyncUdpSocket>,
    key: Arc<[u8]>,
    kind: Hysteria2ObfsKind,
    gecko: StdMutex<GeckoState>,
}

impl SalamanderUdpSocket {
    fn new(inner: Arc<dyn quinn::AsyncUdpSocket>, key: &[u8], kind: Hysteria2ObfsKind) -> Self {
        Self {
            inner,
            key: Arc::from(key.to_vec().into_boxed_slice()),
            kind,
            gecko: StdMutex::new(GeckoState::default()),
        }
    }

    fn encode_salamander_packet(&self, payload: &[u8]) -> std::io::Result<Vec<u8>> {
        let mut salt = [0u8; 8];
        getrandom::fill(&mut salt)
            .map_err(|error| Error::new(ErrorKind::Other, format!("salt failed: {error}")))?;
        let mask = salamander_mask(&self.key, &salt)?;
        let mut packet = Vec::with_capacity(8 + payload.len());
        packet.extend_from_slice(&salt);
        for (index, byte) in payload.iter().enumerate() {
            packet.push(byte ^ mask[index % mask.len()]);
        }
        Ok(packet)
    }

    fn decode_salamander_packet(&self, packet: &mut [u8], len: usize) -> std::io::Result<usize> {
        if len < 8 {
            return Ok(0);
        }
        let mut salt = [0u8; 8];
        salt.copy_from_slice(&packet[..8]);
        let mask = salamander_mask(&self.key, &salt)?;
        let payload_len = len - 8;
        for payload_index in 0..payload_len {
            packet[payload_index] = packet[payload_index + 8] ^ mask[payload_index % mask.len()];
        }
        Ok(payload_len)
    }
}

impl quinn::AsyncUdpSocket for SalamanderUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn quinn::UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &quinn::udp::Transmit) -> std::io::Result<()> {
        if transmit.segment_size.is_some() {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "hysteria2 obfs does not support segmented udp transmits",
            ));
        }
        let packets = if self.kind == Hysteria2ObfsKind::Gecko
            && transmit
                .contents
                .first()
                .map(|byte| byte & 0x80 != 0)
                .unwrap_or(false)
        {
            let mut state = self
                .gecko
                .lock()
                .map_err(|_| Error::new(ErrorKind::Other, "gecko state lock poisoned"))?;
            build_gecko_fragments(&mut state, transmit.contents)?
        } else {
            vec![transmit.contents.to_vec()]
        };
        for payload in packets {
            let packet = self.encode_salamander_packet(&payload)?;
            let transmit = quinn::udp::Transmit {
                destination: transmit.destination,
                ecn: transmit.ecn,
                contents: &packet,
                segment_size: None,
                src_ip: transmit.src_ip,
            };
            self.inner.try_send(&transmit)?;
        }
        Ok(())
    }

    fn poll_recv(
        &self,
        cx: &mut TaskContext<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> Poll<std::io::Result<usize>> {
        match self.inner.poll_recv(cx, bufs, meta) {
            Poll::Ready(Ok(count)) => {
                for index in 0..count {
                    if meta[index].len < 8 {
                        meta[index].len = 0;
                        meta[index].stride = 0;
                        continue;
                    }
                    let len = meta[index].len;
                    let packet = &mut bufs[index][..len];
                    let payload_len = match self.decode_salamander_packet(packet, len) {
                        Ok(payload_len) => payload_len,
                        Err(error) => return Poll::Ready(Err(error)),
                    };
                    if payload_len == 0 {
                        meta[index].len = 0;
                        meta[index].stride = 0;
                        continue;
                    }
                    if self.kind == Hysteria2ObfsKind::Gecko && packet[0] & 0x80 != 0 {
                        let reassembled = {
                            let mut state = match self.gecko.lock() {
                                Ok(state) => state,
                                Err(_) => {
                                    return Poll::Ready(Err(Error::new(
                                        ErrorKind::Other,
                                        "gecko state lock poisoned",
                                    )));
                                }
                            };
                            match parse_gecko_fragment(
                                &mut state,
                                meta[index].addr,
                                &packet[..payload_len],
                            ) {
                                Ok(reassembled) => reassembled,
                                Err(error) => return Poll::Ready(Err(error)),
                            }
                        };
                        let Some(reassembled) = reassembled else {
                            meta[index].len = 0;
                            meta[index].stride = 0;
                            continue;
                        };
                        if reassembled.len() > bufs[index].len() {
                            return Poll::Ready(Err(Error::new(
                                ErrorKind::InvalidData,
                                "gecko reassembled packet exceeds receive buffer",
                            )));
                        }
                        bufs[index][..reassembled.len()].copy_from_slice(&reassembled);
                        meta[index].len = reassembled.len();
                        meta[index].stride = reassembled.len();
                    } else {
                        meta[index].len = payload_len;
                        meta[index].stride = payload_len;
                    }
                }
                Poll::Ready(Ok(count))
            }
            other => other,
        }
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        1
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

#[derive(Default, Debug)]
struct GeckoState {
    next_msg_id: u8,
    reassembly: HashMap<(SocketAddr, u8), GeckoFragmentSet>,
}

#[derive(Debug)]
struct GeckoFragmentSet {
    total: u8,
    chunks: Vec<Option<Vec<u8>>>,
}

fn build_gecko_fragments(state: &mut GeckoState, payload: &[u8]) -> std::io::Result<Vec<Vec<u8>>> {
    if payload.len() < 2 {
        return Ok(vec![payload.to_vec()]);
    }
    let max_fragments = payload.len().min(8).max(2);
    let mut random = [0u8; 1];
    getrandom::fill(&mut random)
        .map_err(|error| Error::new(ErrorKind::Other, format!("gecko random failed: {error}")))?;
    let total = 2 + (random[0] as usize % (max_fragments - 1));
    let msg_id = state.next_msg_id;
    state.next_msg_id = state.next_msg_id.wrapping_add(1);

    let mut offset = 0usize;
    let mut frames = Vec::with_capacity(total);
    for index in 0..total {
        let remaining = payload.len() - offset;
        let remaining_fragments = total - index;
        let chunk_len = if remaining_fragments == 1 {
            remaining
        } else {
            let max_len = remaining - (remaining_fragments - 1);
            let mut random = [0u8; 2];
            getrandom::fill(&mut random).map_err(|error| {
                Error::new(
                    ErrorKind::Other,
                    format!("gecko chunk random failed: {error}"),
                )
            })?;
            1 + (u16::from_be_bytes(random) as usize % max_len)
        };
        let chunk = &payload[offset..offset + chunk_len];
        offset += chunk_len;

        let mut random = [0u8; 1];
        getrandom::fill(&mut random).map_err(|error| {
            Error::new(
                ErrorKind::Other,
                format!("gecko padding random failed: {error}"),
            )
        })?;
        let pad_len = random[0] as usize % 64;
        let mut frame = Vec::with_capacity(5 + pad_len + chunk.len());
        frame.push(0x80);
        frame.push(msg_id);
        frame.push(((index as u8) << 4) | total as u8);
        frame.extend_from_slice(&(pad_len as u16).to_be_bytes());
        if pad_len > 0 {
            let mut padding = vec![0u8; pad_len];
            getrandom::fill(&mut padding).map_err(|error| {
                Error::new(ErrorKind::Other, format!("gecko padding failed: {error}"))
            })?;
            frame.extend_from_slice(&padding);
        }
        frame.extend_from_slice(chunk);
        frames.push(frame);
    }
    Ok(frames)
}

fn parse_gecko_fragment(
    state: &mut GeckoState,
    source: SocketAddr,
    frame: &[u8],
) -> std::io::Result<Option<Vec<u8>>> {
    if frame.len() < 5 || frame[0] != 0x80 {
        return Ok(None);
    }
    let msg_id = frame[1];
    let chunk_idx = frame[2] >> 4;
    let total = frame[2] & 0x0f;
    if !(2..=8).contains(&total) || chunk_idx >= total {
        return Ok(None);
    }
    let pad_len = u16::from_be_bytes([frame[3], frame[4]]) as usize;
    if 5 + pad_len > frame.len() {
        return Ok(None);
    }
    let chunk = frame[5 + pad_len..].to_vec();
    if state.reassembly.len() > 256 {
        state.reassembly.clear();
    }
    let key = (source, msg_id);
    let entry = state
        .reassembly
        .entry(key)
        .or_insert_with(|| GeckoFragmentSet {
            total,
            chunks: vec![None; total as usize],
        });
    if entry.total != total {
        state.reassembly.remove(&key);
        return Ok(None);
    }
    entry.chunks[chunk_idx as usize] = Some(chunk);
    if !entry.chunks.iter().all(Option::is_some) {
        return Ok(None);
    }
    let entry = state
        .reassembly
        .remove(&key)
        .ok_or_else(|| Error::new(ErrorKind::Other, "gecko reassembly entry missing"))?;
    let mut output = Vec::new();
    for chunk in entry.chunks {
        output.extend_from_slice(
            &chunk.ok_or_else(|| Error::new(ErrorKind::Other, "gecko fragment missing"))?,
        );
    }
    Ok(Some(output))
}

fn salamander_mask(key: &[u8], salt: &[u8; 8]) -> std::io::Result<[u8; 32]> {
    let mut hasher = Blake2bVar::new(32)
        .map_err(|error| Error::new(ErrorKind::Other, format!("blake2b init failed: {error}")))?;
    blake2::digest::Update::update(&mut hasher, key);
    blake2::digest::Update::update(&mut hasher, salt);
    let mut output = [0u8; 32];
    hasher
        .finalize_variable(&mut output)
        .map_err(|error| Error::new(ErrorKind::Other, format!("blake2b failed: {error}")))?;
    Ok(output)
}

fn hysteria2_obfs_config(
    obfs: Option<&str>,
    obfs_password: Option<&str>,
) -> anyhow::Result<Option<Hysteria2ObfsConfig>> {
    let Some(obfs) = obfs.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    match obfs.to_ascii_lowercase().as_str() {
        "salamander" | "gecko" => {
            let password = obfs_password
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| anyhow!("hysteria2 {obfs} obfs password is required"))?;
            let kind = if obfs.eq_ignore_ascii_case("gecko") {
                Hysteria2ObfsKind::Gecko
            } else {
                Hysteria2ObfsKind::Salamander
            };
            Ok(Some(Hysteria2ObfsConfig {
                kind,
                key: password.as_bytes().to_vec(),
            }))
        }
        other => Err(anyhow!("unsupported hysteria2 obfs mode {other}")),
    }
}

struct Hysteria2TcpStream {
    _endpoint: quinn::Endpoint,
    connection: quinn::Connection,
    h3_driver: JoinHandle<()>,
    recv: quinn::RecvStream,
    send: quinn::SendStream,
}

impl Drop for Hysteria2TcpStream {
    fn drop(&mut self) {
        self.connection
            .close(quinn::VarInt::from_u32(0), b"supercore close");
        self.h3_driver.abort();
    }
}

impl AsyncRead for Hysteria2TcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), Error>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for Hysteria2TcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        AsyncWrite::poll_write(Pin::new(&mut self.send), cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Result<(), Error>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.send), cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Result<(), Error>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.send), cx)
    }
}

async fn open_hysteria2_connection(
    server: &str,
    port: u16,
    sni: Option<&str>,
    skip_cert_verify: bool,
    password: &str,
    alpn: Option<&str>,
    obfs_config: Option<&Hysteria2ObfsConfig>,
    timeout_ms: u64,
) -> anyhow::Result<Hysteria2Connection> {
    if password.is_empty() {
        return Err(anyhow!("hysteria2 password is empty"));
    }
    let remote = lookup_host((server, port))
        .await
        .with_context(|| format!("failed to resolve hysteria2 server {server}:{port}"))?
        .next()
        .ok_or_else(|| anyhow!("hysteria2 server {server}:{port} did not resolve"))?;
    let bind = if remote.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    }
    .parse::<SocketAddr>()
    .expect("valid quic bind address");
    let mut endpoint = if let Some(obfs_config) = obfs_config {
        let socket =
            std::net::UdpSocket::bind(bind).context("failed to bind hysteria2 obfs udp socket")?;
        socket
            .set_nonblocking(true)
            .context("failed to set hysteria2 obfs udp socket nonblocking")?;
        let runtime: Arc<dyn quinn::Runtime> = Arc::new(quinn::TokioRuntime);
        let inner = runtime
            .wrap_udp_socket(socket)
            .context("failed to wrap hysteria2 obfs udp socket")?;
        let socket = Arc::new(SalamanderUdpSocket::new(
            inner,
            &obfs_config.key,
            obfs_config.kind,
        ));
        quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            None,
            socket,
            runtime,
        )
        .context("failed to create hysteria2 obfs quic endpoint")?
    } else {
        quinn::Endpoint::client(bind).context("failed to create quic endpoint")?
    };
    endpoint.set_default_client_config(quic_client_config(skip_cert_verify, alpn)?);
    let server_name = sni.unwrap_or(server).to_string();
    let connection = timeout(
        Duration::from_millis(timeout_ms),
        endpoint.connect(remote, &server_name)?,
    )
    .await
    .context("hysteria2 quic connect timed out")?
    .context("hysteria2 quic connect failed")?;

    let h3_connection = h3_quinn::Connection::new(connection.clone());
    let (mut h3_connection, mut send_request) = h3::client::new(h3_connection)
        .await
        .context("hysteria2 http/3 client init failed")?;
    let h3_driver = tokio::spawn(async move {
        let _ = h3_connection.wait_idle().await;
    });

    let request = http::Request::builder()
        .method(http::Method::POST)
        .uri("https://hysteria/auth")
        .header("hysteria-auth", password)
        .header("hysteria-cc-rx", "0")
        .header("hysteria-padding", "supercore")
        .body(())
        .context("failed to build hysteria2 auth request")?;
    let mut stream = match timeout(
        Duration::from_millis(timeout_ms),
        send_request.send_request(request),
    )
    .await
    .context("hysteria2 auth request timed out")?
    {
        Ok(stream) => stream,
        Err(error) => {
            h3_driver.abort();
            return Err(anyhow!("hysteria2 auth request failed: {error}"));
        }
    };
    if let Err(error) = stream.finish().await {
        h3_driver.abort();
        return Err(anyhow!("hysteria2 auth finish failed: {error}"));
    }
    let response = match timeout(Duration::from_millis(timeout_ms), stream.recv_response()).await {
        Ok(Ok(response)) => response,
        Ok(Err(error)) => {
            h3_driver.abort();
            return Err(anyhow!("hysteria2 auth response failed: {error}"));
        }
        Err(_) => {
            h3_driver.abort();
            return Err(anyhow!("hysteria2 auth response timed out"));
        }
    };
    if response.status().as_u16() != 233 {
        h3_driver.abort();
        return Err(anyhow!(
            "hysteria2 authentication failed with status {}",
            response.status()
        ));
    }

    let udp_supported = response
        .headers()
        .get("hysteria-udp")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.eq_ignore_ascii_case("true"))
        .unwrap_or(true);

    Ok(Hysteria2Connection {
        endpoint,
        connection,
        h3_driver,
        udp_supported,
    })
}

fn build_hysteria2_tcp_request(destination: &Destination) -> anyhow::Result<Vec<u8>> {
    let address = destination_socket_addr(destination);
    let mut output = Vec::with_capacity(address.len() + 16);
    encode_quic_varint(0x401, &mut output)?;
    encode_quic_varint(address.len() as u64, &mut output)?;
    output.extend_from_slice(address.as_bytes());
    encode_quic_varint(0, &mut output)?;
    Ok(output)
}

async fn read_hysteria2_tcp_response<R>(reader: &mut R) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut status = [0u8; 1];
    reader.read_exact(&mut status).await?;
    let message_len = read_quic_varint(reader).await?;
    if message_len > 4096 {
        return Err(anyhow!("hysteria2 tcp response message is too large"));
    }
    let mut message = vec![0u8; message_len as usize];
    reader.read_exact(&mut message).await?;
    let padding_len = read_quic_varint(reader).await?;
    if padding_len > 16 * 1024 {
        return Err(anyhow!("hysteria2 tcp response padding is too large"));
    }
    let mut padding = vec![0u8; padding_len as usize];
    reader.read_exact(&mut padding).await?;
    if status[0] != 0x00 {
        let message = String::from_utf8_lossy(&message);
        return Err(anyhow!("hysteria2 tcp request failed: {message}"));
    }
    Ok(())
}

#[derive(Default)]
struct Hysteria2UdpReassembly {
    packets: HashMap<u16, Hysteria2UdpFragmentSet>,
}

struct Hysteria2UdpFragmentSet {
    total: u8,
    fragments: Vec<Option<Vec<u8>>>,
}

fn build_hysteria2_udp_messages(
    session_id: u32,
    packet_id: u16,
    destination: &Destination,
    payload: &[u8],
    max_datagram_size: Option<usize>,
) -> anyhow::Result<Vec<Vec<u8>>> {
    let address = destination_socket_addr(destination);
    let single =
        build_hysteria2_udp_message_fragment(session_id, packet_id, 0, 1, &address, payload)?;
    let Some(max_size) = max_datagram_size else {
        return Ok(vec![single]);
    };
    if single.len() <= max_size {
        return Ok(vec![single]);
    }

    let header_len =
        build_hysteria2_udp_message_fragment(session_id, packet_id, 0, 1, &address, &[])?.len();
    if header_len >= max_size {
        return Err(anyhow!(
            "hysteria2 udp header is too large for quic datagram: {} >= {}",
            header_len,
            max_size
        ));
    }
    let max_payload_len = max_size - header_len;
    let fragment_count = payload.len().div_ceil(max_payload_len);
    if fragment_count > u8::MAX as usize {
        return Err(anyhow!(
            "hysteria2 udp payload needs too many fragments: {fragment_count}"
        ));
    }
    let mut messages = Vec::with_capacity(fragment_count);
    for (index, chunk) in payload.chunks(max_payload_len).enumerate() {
        messages.push(build_hysteria2_udp_message_fragment(
            session_id,
            packet_id,
            index as u8,
            fragment_count as u8,
            &address,
            chunk,
        )?);
    }
    Ok(messages)
}

fn build_hysteria2_udp_message_fragment(
    session_id: u32,
    packet_id: u16,
    fragment_id: u8,
    fragment_count: u8,
    address: &str,
    payload: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let mut output = Vec::with_capacity(12 + address.len() + payload.len());
    output.extend_from_slice(&session_id.to_be_bytes());
    output.extend_from_slice(&packet_id.to_be_bytes());
    output.push(fragment_id);
    output.push(fragment_count);
    encode_quic_varint(address.len() as u64, &mut output)?;
    output.extend_from_slice(address.as_bytes());
    output.extend_from_slice(payload);
    Ok(output)
}

fn parse_hysteria2_udp_message(
    datagram: &[u8],
    expected_session_id: u32,
    reassembly: &mut Hysteria2UdpReassembly,
) -> anyhow::Result<Option<Vec<u8>>> {
    if datagram.len() < 8 {
        return Ok(None);
    }
    let session_id = u32::from_be_bytes([datagram[0], datagram[1], datagram[2], datagram[3]]);
    if session_id != expected_session_id {
        return Ok(None);
    }
    let packet_id = u16::from_be_bytes([datagram[4], datagram[5]]);
    let fragment_id = datagram[6];
    let fragment_count = datagram[7];
    if fragment_count == 0 || fragment_id >= fragment_count {
        return Err(anyhow!(
            "invalid hysteria2 udp fragment id/count: {fragment_id}/{fragment_count}"
        ));
    }
    let mut cursor = 8;
    let address_len = read_quic_varint_from_slice(datagram, &mut cursor)? as usize;
    if cursor + address_len > datagram.len() {
        return Err(anyhow!("hysteria2 udp address length exceeds datagram"));
    }
    cursor += address_len;
    let payload = datagram[cursor..].to_vec();
    if fragment_count == 1 {
        return Ok(Some(payload));
    }
    push_hysteria2_udp_fragment(reassembly, packet_id, fragment_id, fragment_count, payload)
}

fn push_hysteria2_udp_fragment(
    reassembly: &mut Hysteria2UdpReassembly,
    packet_id: u16,
    fragment_id: u8,
    fragment_count: u8,
    payload: Vec<u8>,
) -> anyhow::Result<Option<Vec<u8>>> {
    if reassembly.packets.len() > 64 {
        reassembly.packets.clear();
    }
    let entry = reassembly
        .packets
        .entry(packet_id)
        .or_insert_with(|| Hysteria2UdpFragmentSet {
            total: fragment_count,
            fragments: vec![None; fragment_count as usize],
        });
    if entry.total != fragment_count {
        reassembly.packets.remove(&packet_id);
        return Err(anyhow!("inconsistent hysteria2 udp fragment count"));
    }
    entry.fragments[fragment_id as usize] = Some(payload);
    if !entry.fragments.iter().all(Option::is_some) {
        return Ok(None);
    }
    let entry = reassembly
        .packets
        .remove(&packet_id)
        .ok_or_else(|| anyhow!("missing hysteria2 udp reassembly entry"))?;
    let mut output = Vec::new();
    for fragment in entry.fragments {
        output
            .extend_from_slice(&fragment.ok_or_else(|| anyhow!("missing hysteria2 udp fragment"))?);
    }
    Ok(Some(output))
}

fn encode_quic_varint(value: u64, output: &mut Vec<u8>) -> anyhow::Result<()> {
    match value {
        0..=0x3f => output.push(value as u8),
        0x40..=0x3fff => output.extend_from_slice(&((value as u16) | 0x4000).to_be_bytes()),
        0x4000..=0x3fff_ffff => {
            output.extend_from_slice(&((value as u32) | 0x8000_0000).to_be_bytes())
        }
        0x4000_0000..=0x3fff_ffff_ffff_ffff => {
            output.extend_from_slice(&(value | 0xc000_0000_0000_0000).to_be_bytes())
        }
        _ => return Err(anyhow!("quic varint value is too large")),
    }
    Ok(())
}

async fn read_quic_varint<R>(reader: &mut R) -> anyhow::Result<u64>
where
    R: AsyncRead + Unpin,
{
    let mut first = [0u8; 1];
    reader.read_exact(&mut first).await?;
    let tag = first[0] >> 6;
    let len = 1usize << tag;
    let mut value = (first[0] & 0x3f) as u64;
    for _ in 1..len {
        let mut byte = [0u8; 1];
        reader.read_exact(&mut byte).await?;
        value = (value << 8) | byte[0] as u64;
    }
    Ok(value)
}

fn read_quic_varint_from_slice(input: &[u8], cursor: &mut usize) -> anyhow::Result<u64> {
    if *cursor >= input.len() {
        return Err(anyhow!("quic varint is missing"));
    }
    let first = input[*cursor];
    let tag = first >> 6;
    let len = 1usize << tag;
    if *cursor + len > input.len() {
        return Err(anyhow!("quic varint is truncated"));
    }
    *cursor += 1;
    let mut value = (first & 0x3f) as u64;
    for _ in 1..len {
        value = (value << 8) | input[*cursor] as u64;
        *cursor += 1;
    }
    Ok(value)
}

fn random_u16() -> anyhow::Result<u16> {
    let mut bytes = [0u8; 2];
    getrandom::fill(&mut bytes).context("failed to generate random u16")?;
    Ok(u16::from_be_bytes(bytes))
}

fn random_u32() -> anyhow::Result<u32> {
    let mut bytes = [0u8; 4];
    getrandom::fill(&mut bytes).context("failed to generate random u32")?;
    Ok(u32::from_be_bytes(bytes))
}

#[async_trait]
impl Outbound for TuicOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "tuic"
    }

    fn capability(&self) -> OutboundCapability {
        OutboundCapability::tcp_udp(format!(
            "{}-session-pool",
            self.udp_relay_mode.as_deref().unwrap_or("native")
        ))
    }

    async fn connect(
        &self,
        destination: &Destination,
        timeout_ms: u64,
    ) -> anyhow::Result<BoxedStream> {
        let _udp_mode = self.udp_relay_mode.as_deref().unwrap_or("native");
        let _congestion_control = self.congestion_control.as_deref().unwrap_or("default");
        let user_id = Uuid::parse_str(&self.uuid)
            .map_err(|error| anyhow!("invalid tuic uuid for {}: {error}", self.name))?;
        let connection = open_tuic_connection(
            &self.server,
            self.port,
            self.sni.as_deref(),
            self.skip_cert_verify,
            self.alpn.as_deref(),
            &user_id,
            &self.password,
            timeout_ms,
        )
        .await?;
        let (mut send, recv) = timeout(
            Duration::from_millis(timeout_ms),
            connection.connection.open_bi(),
        )
        .await
        .context("tuic open stream timed out")?
        .context("tuic failed to open bidirectional stream")?;
        let request = build_tuic_connect_request(destination)?;
        send.write_all(&request).await?;
        send.flush().await?;
        Ok(Box::new(TuicTcpStream {
            _endpoint: connection.endpoint,
            connection: connection.connection,
            recv,
            send,
        }))
    }

    async fn udp_exchange(
        &self,
        destination: &Destination,
        payload: &[u8],
        timeout_ms: u64,
    ) -> anyhow::Result<Vec<u8>> {
        let mode = self
            .udp_relay_mode
            .as_deref()
            .unwrap_or("native")
            .to_ascii_lowercase();
        if !matches!(mode.as_str(), "native" | "quic") {
            return Err(anyhow!("unsupported tuic udp relay mode {mode}"));
        }
        let session_handle = self.tuic_udp_session(&mode, timeout_ms).await?;

        let exchange = {
            let mut session = session_handle.lock().await;
            async {
                let packet_id = session.next_packet_id;
                session.next_packet_id = session.next_packet_id.wrapping_add(1);
                let messages = build_tuic_packet_messages(
                    session.associate_id,
                    packet_id,
                    destination,
                    payload,
                    if session.mode == "quic" {
                        None
                    } else {
                        session.connection.max_datagram_size()
                    },
                )?;
                if session.mode == "quic" {
                    for message in messages {
                        let mut stream = timeout(
                            Duration::from_millis(timeout_ms),
                            session.connection.open_uni(),
                        )
                        .await
                        .context("tuic udp stream open timed out")?
                        .context("tuic failed to open udp stream")?;
                        stream.write_all(&message).await?;
                        stream.finish()?;
                    }
                    timeout(Duration::from_millis(timeout_ms), async {
                        let mut reassembly = TuicUdpReassembly::default();
                        loop {
                            let mut incoming = session.connection.accept_uni().await?;
                            let data = incoming
                                .read_to_end(65_535 + 512)
                                .await
                                .map_err(|error| anyhow!("tuic udp stream read failed: {error}"))?;
                            if let Some(payload) = parse_tuic_packet_message(
                                &data,
                                session.associate_id,
                                &mut reassembly,
                            )? {
                                return Ok::<Vec<u8>, anyhow::Error>(payload);
                            }
                        }
                    })
                    .await
                    .context("tuic udp stream receive timed out")?
                } else {
                    for message in messages {
                        timeout(
                            Duration::from_millis(timeout_ms),
                            session.connection.send_datagram_wait(Bytes::from(message)),
                        )
                        .await
                        .context("tuic udp send timed out")?
                        .map_err(|error| anyhow!("tuic udp send failed: {error}"))?;
                    }
                    timeout(Duration::from_millis(timeout_ms), async {
                        let mut reassembly = TuicUdpReassembly::default();
                        loop {
                            let datagram = session.connection.read_datagram().await?;
                            if let Some(payload) = parse_tuic_packet_message(
                                &datagram,
                                session.associate_id,
                                &mut reassembly,
                            )? {
                                return Ok::<Vec<u8>, anyhow::Error>(payload);
                            }
                        }
                    })
                    .await
                    .context("tuic udp datagram receive timed out")?
                }
            }
            .await
        };
        if exchange.is_err() {
            self.remove_tuic_udp_session(&session_handle).await;
        }
        exchange
    }
}

impl TuicOutbound {
    async fn tuic_udp_session(
        &self,
        mode: &str,
        timeout_ms: u64,
    ) -> anyhow::Result<Arc<TokioMutex<TuicUdpSession>>> {
        let mut pool = self.udp_sessions.lock().await;
        if pool.mode.as_deref() != Some(mode) {
            pool.sessions.clear();
            pool.mode = Some(mode.to_string());
        }
        if pool.sessions.len() < UDP_SESSION_POOL_SIZE {
            let user_id = Uuid::parse_str(&self.uuid)
                .map_err(|error| anyhow!("invalid tuic uuid for {}: {error}", self.name))?;
            let connection = open_tuic_connection(
                &self.server,
                self.port,
                self.sni.as_deref(),
                self.skip_cert_verify,
                self.alpn.as_deref(),
                &user_id,
                &self.password,
                timeout_ms,
            )
            .await?;
            let session = Arc::new(TokioMutex::new(TuicUdpSession {
                _endpoint: connection.endpoint,
                connection: connection.connection,
                mode: mode.to_string(),
                associate_id: random_u16()?,
                next_packet_id: random_u16()?,
            }));
            pool.sessions.push(session.clone());
            return Ok(session);
        }
        pool.sessions
            .next()
            .ok_or_else(|| anyhow!("tuic UDP session pool is unexpectedly empty"))
    }

    async fn remove_tuic_udp_session(&self, target: &Arc<TokioMutex<TuicUdpSession>>) {
        let mut pool = self.udp_sessions.lock().await;
        pool.sessions.remove(target);
    }
}

struct TuicConnection {
    endpoint: quinn::Endpoint,
    connection: quinn::Connection,
}

struct TuicTcpStream {
    _endpoint: quinn::Endpoint,
    connection: quinn::Connection,
    recv: quinn::RecvStream,
    send: quinn::SendStream,
}

impl Drop for TuicTcpStream {
    fn drop(&mut self) {
        self.connection
            .close(quinn::VarInt::from_u32(0), b"supercore close");
    }
}

impl AsyncRead for TuicTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), Error>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for TuicTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        AsyncWrite::poll_write(Pin::new(&mut self.send), cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Result<(), Error>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.send), cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Result<(), Error>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.send), cx)
    }
}

async fn open_tuic_connection(
    server: &str,
    port: u16,
    sni: Option<&str>,
    skip_cert_verify: bool,
    alpn: Option<&str>,
    user_id: &Uuid,
    password: &str,
    timeout_ms: u64,
) -> anyhow::Result<TuicConnection> {
    if password.is_empty() {
        return Err(anyhow!("tuic password is empty"));
    }
    let remote = lookup_host((server, port))
        .await
        .with_context(|| format!("failed to resolve tuic server {server}:{port}"))?
        .next()
        .ok_or_else(|| anyhow!("tuic server {server}:{port} did not resolve"))?;
    let bind = if remote.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    }
    .parse::<SocketAddr>()
    .expect("valid quic bind address");
    let mut endpoint = quinn::Endpoint::client(bind).context("failed to create quic endpoint")?;
    endpoint.set_default_client_config(quic_client_config(skip_cert_verify, alpn.or(Some("h3")))?);
    let server_name = sni.unwrap_or(server).to_string();
    let connection = timeout(
        Duration::from_millis(timeout_ms),
        endpoint.connect(remote, &server_name)?,
    )
    .await
    .context("tuic quic connect timed out")?
    .context("tuic quic connect failed")?;

    let mut token = [0u8; 32];
    connection
        .export_keying_material(&mut token, user_id.as_bytes(), password.as_bytes())
        .map_err(|_| anyhow!("tuic token export failed"))?;
    let mut auth = Vec::with_capacity(2 + 16 + 32);
    auth.extend_from_slice(&[0x05, 0x00]);
    auth.extend_from_slice(user_id.as_bytes());
    auth.extend_from_slice(&token);
    let mut stream = timeout(Duration::from_millis(timeout_ms), connection.open_uni())
        .await
        .context("tuic auth stream timed out")?
        .context("tuic failed to open auth stream")?;
    stream.write_all(&auth).await?;
    stream.finish()?;

    Ok(TuicConnection {
        endpoint,
        connection,
    })
}

fn build_tuic_connect_request(destination: &Destination) -> anyhow::Result<Vec<u8>> {
    let mut output = Vec::with_capacity(32 + destination.host.len());
    output.extend_from_slice(&[0x05, 0x01]);
    encode_tuic_address(destination, &mut output)?;
    Ok(output)
}

#[derive(Default)]
struct TuicUdpReassembly {
    packets: HashMap<u16, TuicUdpFragmentSet>,
}

struct TuicUdpFragmentSet {
    total: u8,
    fragments: Vec<Option<Vec<u8>>>,
}

fn build_tuic_packet_messages(
    associate_id: u16,
    packet_id: u16,
    destination: &Destination,
    payload: &[u8],
    max_datagram_size: Option<usize>,
) -> anyhow::Result<Vec<Vec<u8>>> {
    let single = build_tuic_packet_fragment(associate_id, packet_id, 1, 0, destination, payload)?;
    let header_len =
        build_tuic_packet_fragment(associate_id, packet_id, 1, 0, destination, &[])?.len();
    let max_payload_len = match max_datagram_size {
        Some(max_size) => {
            if single.len() <= max_size {
                return Ok(vec![single]);
            }
            if header_len >= max_size {
                return Err(anyhow!(
                    "tuic udp header is too large for quic datagram: {} >= {}",
                    header_len,
                    max_size
                ));
            }
            (max_size - header_len).min(u16::MAX as usize)
        }
        None => {
            if payload.len() <= u16::MAX as usize {
                return Ok(vec![single]);
            }
            u16::MAX as usize
        }
    };
    let fragment_total = payload.len().div_ceil(max_payload_len);
    if fragment_total > u8::MAX as usize {
        return Err(anyhow!(
            "tuic udp payload needs too many fragments: {fragment_total}"
        ));
    }
    let mut messages = Vec::with_capacity(fragment_total);
    for (index, chunk) in payload.chunks(max_payload_len).enumerate() {
        messages.push(build_tuic_packet_fragment(
            associate_id,
            packet_id,
            fragment_total as u8,
            index as u8,
            destination,
            chunk,
        )?);
    }
    Ok(messages)
}

fn build_tuic_packet_fragment(
    associate_id: u16,
    packet_id: u16,
    fragment_total: u8,
    fragment_id: u8,
    destination: &Destination,
    payload: &[u8],
) -> anyhow::Result<Vec<u8>> {
    if payload.len() > u16::MAX as usize {
        return Err(anyhow!("tuic udp fragment payload is too large"));
    }
    let mut output = Vec::with_capacity(48 + destination.host.len() + payload.len());
    output.extend_from_slice(&[0x05, 0x02]);
    output.extend_from_slice(&associate_id.to_be_bytes());
    output.extend_from_slice(&packet_id.to_be_bytes());
    output.push(fragment_total);
    output.push(fragment_id);
    output.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    encode_tuic_address(destination, &mut output)?;
    output.extend_from_slice(payload);
    Ok(output)
}

fn parse_tuic_packet_message(
    data: &[u8],
    expected_associate_id: u16,
    reassembly: &mut TuicUdpReassembly,
) -> anyhow::Result<Option<Vec<u8>>> {
    if data.len() < 10 || data[0] != 0x05 || data[1] != 0x02 {
        return Ok(None);
    }
    let associate_id = u16::from_be_bytes([data[2], data[3]]);
    if associate_id != expected_associate_id {
        return Ok(None);
    }
    let packet_id = u16::from_be_bytes([data[4], data[5]]);
    let fragment_total = data[6];
    let fragment_id = data[7];
    if fragment_total == 0 || fragment_id >= fragment_total {
        return Err(anyhow!(
            "invalid tuic udp fragment id/count: {fragment_id}/{fragment_total}"
        ));
    }
    let payload_len = u16::from_be_bytes([data[8], data[9]]) as usize;
    let mut cursor = 10;
    skip_tuic_address(data, &mut cursor)?;
    if cursor + payload_len > data.len() {
        return Err(anyhow!("tuic udp payload length exceeds packet"));
    }
    let payload = data[cursor..cursor + payload_len].to_vec();
    if fragment_total == 1 {
        return Ok(Some(payload));
    }
    push_tuic_udp_fragment(reassembly, packet_id, fragment_id, fragment_total, payload)
}

fn push_tuic_udp_fragment(
    reassembly: &mut TuicUdpReassembly,
    packet_id: u16,
    fragment_id: u8,
    fragment_total: u8,
    payload: Vec<u8>,
) -> anyhow::Result<Option<Vec<u8>>> {
    if reassembly.packets.len() > 64 {
        reassembly.packets.clear();
    }
    let entry = reassembly
        .packets
        .entry(packet_id)
        .or_insert_with(|| TuicUdpFragmentSet {
            total: fragment_total,
            fragments: vec![None; fragment_total as usize],
        });
    if entry.total != fragment_total {
        reassembly.packets.remove(&packet_id);
        return Err(anyhow!("inconsistent tuic udp fragment count"));
    }
    entry.fragments[fragment_id as usize] = Some(payload);
    if !entry.fragments.iter().all(Option::is_some) {
        return Ok(None);
    }
    let entry = reassembly
        .packets
        .remove(&packet_id)
        .ok_or_else(|| anyhow!("missing tuic udp reassembly entry"))?;
    let mut output = Vec::new();
    for fragment in entry.fragments {
        output.extend_from_slice(&fragment.ok_or_else(|| anyhow!("missing tuic udp fragment"))?);
    }
    Ok(Some(output))
}

fn encode_tuic_address(destination: &Destination, output: &mut Vec<u8>) -> anyhow::Result<()> {
    if let Ok(addr) = destination.host.parse::<SocketAddr>() {
        match addr {
            SocketAddr::V4(addr) => {
                output.push(0x01);
                output.extend_from_slice(&addr.ip().octets());
                output.extend_from_slice(&addr.port().to_be_bytes());
            }
            SocketAddr::V6(addr) => {
                output.push(0x02);
                output.extend_from_slice(&addr.ip().octets());
                output.extend_from_slice(&addr.port().to_be_bytes());
            }
        }
    } else if let Ok(ip) = destination.host.parse::<std::net::IpAddr>() {
        match ip {
            std::net::IpAddr::V4(ip) => {
                output.push(0x01);
                output.extend_from_slice(&ip.octets());
            }
            std::net::IpAddr::V6(ip) => {
                output.push(0x02);
                output.extend_from_slice(&ip.octets());
            }
        }
        output.extend_from_slice(&destination.port.to_be_bytes());
    } else {
        if destination.host.len() > 255 {
            return Err(anyhow!("domain name too long"));
        }
        output.push(0x00);
        output.push(destination.host.len() as u8);
        output.extend_from_slice(destination.host.as_bytes());
        output.extend_from_slice(&destination.port.to_be_bytes());
    }
    Ok(())
}

fn skip_tuic_address(input: &[u8], cursor: &mut usize) -> anyhow::Result<()> {
    if *cursor >= input.len() {
        return Err(anyhow!("tuic address is missing"));
    }
    let address_type = input[*cursor];
    *cursor += 1;
    match address_type {
        0xff => Ok(()),
        0x00 => {
            if *cursor >= input.len() {
                return Err(anyhow!("tuic domain length is missing"));
            }
            let len = input[*cursor] as usize;
            *cursor += 1;
            if *cursor + len + 2 > input.len() {
                return Err(anyhow!("tuic domain address is truncated"));
            }
            *cursor += len + 2;
            Ok(())
        }
        0x01 => {
            if *cursor + 4 + 2 > input.len() {
                return Err(anyhow!("tuic ipv4 address is truncated"));
            }
            *cursor += 4 + 2;
            Ok(())
        }
        0x02 => {
            if *cursor + 16 + 2 > input.len() {
                return Err(anyhow!("tuic ipv6 address is truncated"));
            }
            *cursor += 16 + 2;
            Ok(())
        }
        other => Err(anyhow!("unsupported tuic address type {other}")),
    }
}

#[async_trait]
impl Outbound for TrojanOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "trojan"
    }

    fn capability(&self) -> OutboundCapability {
        let network = self
            .network
            .as_deref()
            .unwrap_or("tcp")
            .trim()
            .to_ascii_lowercase();
        match trojan_alpn_protocols(&network, &self.alpn) {
            Ok(_) => OutboundCapability::tcp_udp("trojan-udp-associate-stream-pool"),
            Err(error) => OutboundCapability::unsupported(error.to_string()),
        }
    }

    async fn connect(
        &self,
        destination: &Destination,
        timeout_ms: u64,
    ) -> anyhow::Result<BoxedStream> {
        let mut stream = self.open_transport(timeout_ms).await?;
        let request = build_trojan_request(&self.password, destination)?;
        stream.write_all(&request).await?;
        stream.flush().await?;
        Ok(stream)
    }

    async fn udp_exchange(
        &self,
        destination: &Destination,
        payload: &[u8],
        timeout_ms: u64,
    ) -> anyhow::Result<Vec<u8>> {
        let session_handle = self.trojan_udp_session(timeout_ms).await?;
        let mut session = session_handle.lock().await;
        let packet = encode_trojan_udp_packet(destination, payload)?;
        let exchange = timeout(Duration::from_millis(timeout_ms), async {
            session.stream.write_all(&packet).await?;
            session.stream.flush().await?;
            let (_response_destination, response) =
                read_trojan_udp_packet(&mut session.stream).await?;
            anyhow::Ok(response)
        })
        .await
        .context("trojan udp exchange timed out")?;
        if exchange.is_err() {
            drop(session);
            self.remove_trojan_udp_session(&session_handle).await;
        }
        exchange
    }
}

impl TrojanOutbound {
    async fn open_transport(&self, timeout_ms: u64) -> anyhow::Result<BoxedStream> {
        let network = self
            .network
            .as_deref()
            .unwrap_or("tcp")
            .trim()
            .to_ascii_lowercase();
        if !matches!(
            network.as_str(),
            "tcp" | "ws" | "websocket" | "grpc" | "h2" | "http" | "httpupgrade" | "http-upgrade"
        ) {
            return Err(anyhow!("unsupported trojan network {network}"));
        }

        let tcp = connect_tcp(&format!("{}:{}", self.server, self.port), timeout_ms).await?;
        let server_name = self.sni.as_deref().unwrap_or(&self.server).to_string();
        let mut tls_config = tls_client_config(self.skip_cert_verify)?;
        tls_config.alpn_protocols = trojan_alpn_protocols(&network, &self.alpn)?;
        let connector = TlsConnector::from(Arc::new(tls_config));
        let tls_server_name = ServerName::try_from(server_name.clone())
            .map_err(|error| anyhow!("invalid trojan server name: {error}"))?;
        let mut stream = timeout(
            Duration::from_millis(timeout_ms),
            connector.connect(tls_server_name, tcp),
        )
        .await
        .context("trojan tls handshake timed out")?
        .context("trojan tls handshake failed")?;

        match network.as_str() {
            "tcp" => Ok(Box::new(stream)),
            "ws" | "websocket" => {
                perform_websocket_handshake_with_headers(
                    &mut stream,
                    self.ws_host.as_deref().unwrap_or(&server_name),
                    self.ws_path.as_deref().unwrap_or("/"),
                    &self.transport_headers,
                )
                .await?;
                Ok(Box::new(spawn_websocket_stream(stream)))
            }
            "grpc" => open_grpc_tunnel(
                stream,
                self.ws_host.as_deref().unwrap_or(&server_name),
                self.grpc_service_name.as_deref(),
                timeout_ms,
            )
            .await
            .map(|stream| Box::new(stream) as BoxedStream),
            "h2" | "http" => open_h2_tunnel(
                stream,
                self.ws_host.as_deref().unwrap_or(&server_name),
                self.ws_path.as_deref().unwrap_or("/"),
                timeout_ms,
            )
            .await
            .map(|stream| Box::new(stream) as BoxedStream),
            "httpupgrade" | "http-upgrade" => open_http_upgrade_tunnel(
                stream,
                self.ws_host.as_deref().unwrap_or(&server_name),
                self.ws_path.as_deref().unwrap_or("/"),
                &self.transport_headers,
            )
            .await
            .map(|stream| Box::new(stream) as BoxedStream),
            _ => unreachable!("trojan network was validated"),
        }
    }

    async fn trojan_udp_session(
        &self,
        timeout_ms: u64,
    ) -> anyhow::Result<Arc<TokioMutex<TrojanUdpSession>>> {
        let mut pool = self.udp_sessions.lock().await;
        if pool.len() < UDP_SESSION_POOL_SIZE {
            let session = Arc::new(TokioMutex::new(
                self.open_trojan_udp_session(timeout_ms).await?,
            ));
            pool.push(session.clone());
            return Ok(session);
        }
        pool.next()
            .ok_or_else(|| anyhow!("trojan UDP session pool is unexpectedly empty"))
    }

    async fn open_trojan_udp_session(&self, timeout_ms: u64) -> anyhow::Result<TrojanUdpSession> {
        let mut stream = self.open_transport(timeout_ms).await?;
        let request = build_trojan_request_with_command(
            &self.password,
            &Destination::new("0.0.0.0", 0),
            TROJAN_CMD_UDP_ASSOCIATE,
        )?;
        stream.write_all(&request).await?;
        stream.flush().await?;
        Ok(TrojanUdpSession { stream })
    }

    async fn remove_trojan_udp_session(&self, target: &Arc<TokioMutex<TrojanUdpSession>>) {
        let mut pool = self.udp_sessions.lock().await;
        pool.remove(target);
    }
}

fn trojan_alpn_protocols(network: &str, configured: &[String]) -> anyhow::Result<Vec<Vec<u8>>> {
    let mut protocols = Vec::new();
    for value in configured {
        for protocol in value
            .split(',')
            .map(str::trim)
            .filter(|item| !item.is_empty())
        {
            if !protocol.is_ascii() || protocol.len() > u8::MAX as usize {
                return Err(anyhow!("invalid trojan ALPN value {protocol:?}"));
            }
            if !protocols
                .iter()
                .any(|existing: &Vec<u8>| existing.as_slice() == protocol.as_bytes())
            {
                protocols.push(protocol.as_bytes().to_vec());
            }
        }
    }

    if protocols.is_empty() {
        return Ok(match network {
            "grpc" | "h2" | "http" => vec![b"h2".to_vec()],
            "ws" | "websocket" | "httpupgrade" | "http-upgrade" => {
                vec![b"http/1.1".to_vec()]
            }
            _ => Vec::new(),
        });
    }
    if matches!(network, "grpc" | "h2" | "http")
        && !protocols.iter().any(|item| item.as_slice() == b"h2")
    {
        return Err(anyhow!("trojan {network} transport requires h2 in ALPN"));
    }
    if matches!(network, "ws" | "websocket" | "httpupgrade" | "http-upgrade")
        && !protocols.iter().any(|item| item.as_slice() == b"http/1.1")
    {
        return Err(anyhow!(
            "trojan {network} transport requires http/1.1 in ALPN"
        ));
    }
    Ok(protocols)
}

fn destination_socket_addr(destination: &Destination) -> String {
    if destination.host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{}]:{}", destination.host, destination.port)
    } else {
        destination.authority()
    }
}

fn reality_tls_client_config(
    skip_cert_verify: bool,
    public_key: Option<&str>,
    short_id: Option<&str>,
    fingerprint: Option<&str>,
    spider_x: Option<&str>,
) -> anyhow::Result<ClientConfig> {
    let public_key = public_key.ok_or_else(|| anyhow!("vless reality public key is required"))?;
    validate_reality_fingerprint(fingerprint)?;
    validate_reality_spider_x(spider_x)?;
    let mut provider = aws_lc_rs::default_provider();
    provider.kx_groups = vec![&REALITY_X25519_KX_GROUP];
    let builder = ClientConfig::builder_with_provider(provider.into())
        .with_protocol_versions(&[&rustls::version::TLS13])?;
    let mut config = if skip_cert_verify {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
            .with_no_client_auth()
    } else {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        builder.with_root_certificates(roots).with_no_client_auth()
    };
    config.alpn_protocols.clear();
    config.resumption = Resumption::disabled();
    config
        .dangerous()
        .set_client_hello_session_id_provider(Arc::new(RealitySessionIdProvider {
            public_key: decode_reality_public_key(public_key)?.to_bytes(),
            short_id: decode_reality_short_id(short_id)?,
        }));
    Ok(config)
}

const VMESS_TAG_LEN: usize = 16;
const VMESS_MAX_CHUNK_PLAINTEXT: usize = 8192;
const VMESS_CMD_TCP: u8 = 0x01;
const VMESS_CMD_UDP: u8 = 0x02;
type VmessMaskReader = digest::core_api::XofReaderCoreWrapper<sha3::Shake128ReaderCore>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VmessCipher {
    Aes128Gcm,
    Chacha20Poly1305,
    None,
}

struct VmessSetup {
    request: Vec<u8>,
    upload: VmessUploadState,
    download: VmessDownloadState,
}

struct VmessUploadState {
    cipher: Option<VmessAeadState>,
    length_mask: VmessLengthMask,
}

struct VmessDownloadState {
    response_header_key: [u8; 16],
    response_header_iv: [u8; 16],
    response_authentication: u8,
    cipher: Option<VmessAeadState>,
    length_mask: VmessLengthMask,
}

struct VmessLengthMask {
    reader: VmessMaskReader,
}

struct VmessAeadState {
    cipher: VmessCipher,
    key: Vec<u8>,
    nonce: [u8; 12],
    counter: u16,
}

impl VmessCipher {
    fn from_name(name: &str) -> anyhow::Result<Self> {
        match name.to_ascii_lowercase().as_str() {
            "auto" | "chacha20-poly1305" | "chacha20-ietf-poly1305" => Ok(Self::Chacha20Poly1305),
            "aes-128-gcm" => Ok(Self::Aes128Gcm),
            "none" => Ok(Self::None),
            _ => Err(anyhow!("unsupported vmess cipher {name}")),
        }
    }

    fn method_byte(self) -> u8 {
        match self {
            Self::Aes128Gcm => 3,
            Self::Chacha20Poly1305 => 4,
            Self::None => 5,
        }
    }

    fn tag_len(self) -> usize {
        match self {
            Self::None => 0,
            Self::Aes128Gcm | Self::Chacha20Poly1305 => VMESS_TAG_LEN,
        }
    }
}

impl VmessLengthMask {
    fn new(seed: &[u8]) -> Self {
        let mut shake = Shake128::default();
        sha3::digest::Update::update(&mut shake, seed);
        Self {
            reader: shake.finalize_xof(),
        }
    }

    fn next(&mut self) -> u16 {
        let mut mask = [0u8; 2];
        self.reader.read(&mut mask);
        u16::from_be_bytes(mask)
    }
}

impl VmessAeadState {
    fn new(cipher: VmessCipher, key: &[u8], iv: &[u8]) -> anyhow::Result<Option<Self>> {
        if cipher == VmessCipher::None {
            return Ok(None);
        }
        if iv.len() < 12 {
            return Err(anyhow!("vmess iv is too short"));
        }
        let mut nonce = [0u8; 12];
        nonce[2..].copy_from_slice(&iv[2..12]);
        let key = match cipher {
            VmessCipher::Aes128Gcm => key.to_vec(),
            VmessCipher::Chacha20Poly1305 => vmess_chacha_key(key).to_vec(),
            VmessCipher::None => unreachable!(),
        };
        Ok(Some(Self {
            cipher,
            key,
            nonce,
            counter: 0,
        }))
    }

    fn next_nonce(&mut self) -> [u8; 12] {
        let mut nonce = self.nonce;
        nonce[0..2].copy_from_slice(&self.counter.to_be_bytes());
        self.counter = self.counter.wrapping_add(1);
        nonce
    }

    fn encrypt(&mut self, plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
        let nonce = self.next_nonce();
        match self.cipher {
            VmessCipher::Aes128Gcm => Aes128Gcm::new_from_slice(&self.key)
                .map_err(|_| anyhow!("invalid vmess aes-128-gcm key"))?
                .encrypt(aes_gcm::Nonce::from_slice(&nonce), plaintext)
                .map_err(|_| anyhow!("vmess encrypt failed")),
            VmessCipher::Chacha20Poly1305 => ChaCha20Poly1305::new_from_slice(&self.key)
                .map_err(|_| anyhow!("invalid vmess chacha20-poly1305 key"))?
                .encrypt(chacha20poly1305::Nonce::from_slice(&nonce), plaintext)
                .map_err(|_| anyhow!("vmess encrypt failed")),
            VmessCipher::None => Ok(plaintext.to_vec()),
        }
    }

    fn decrypt(&mut self, ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
        let nonce = self.next_nonce();
        match self.cipher {
            VmessCipher::Aes128Gcm => Aes128Gcm::new_from_slice(&self.key)
                .map_err(|_| anyhow!("invalid vmess aes-128-gcm key"))?
                .decrypt(aes_gcm::Nonce::from_slice(&nonce), ciphertext)
                .map_err(|_| anyhow!("vmess decrypt failed")),
            VmessCipher::Chacha20Poly1305 => ChaCha20Poly1305::new_from_slice(&self.key)
                .map_err(|_| anyhow!("invalid vmess chacha20-poly1305 key"))?
                .decrypt(chacha20poly1305::Nonce::from_slice(&nonce), ciphertext)
                .map_err(|_| anyhow!("vmess decrypt failed")),
            VmessCipher::None => Ok(ciphertext.to_vec()),
        }
    }
}

async fn setup_vmess_stream<S>(
    mut stream: S,
    user_id: &Uuid,
    cipher: VmessCipher,
    destination: &Destination,
) -> anyhow::Result<BoxedStream>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let setup = build_vmess_setup(user_id, cipher, destination)?;
    stream.write_all(&setup.request).await?;
    stream.flush().await?;
    Ok(Box::new(spawn_vmess_stream(
        stream,
        setup.upload,
        setup.download,
    )))
}

fn spawn_vmess_stream<S>(
    stream: S,
    mut upload_state: VmessUploadState,
    mut download_state: VmessDownloadState,
) -> DuplexStream
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (app_side, relay_side) = tokio::io::duplex(64 * 1024);
    let (mut local_read, mut local_write) = tokio::io::split(relay_side);
    let (mut remote_read, mut remote_write) = tokio::io::split(stream);

    tokio::spawn(async move {
        let mut buf = [0u8; 16 * 1024];
        loop {
            match local_read.read(&mut buf).await {
                Ok(0) => {
                    let _ = write_vmess_chunk(&mut remote_write, &mut upload_state, &[]).await;
                    let _ = remote_write.shutdown().await;
                    break;
                }
                Ok(n) => {
                    for chunk in buf[..n].chunks(VMESS_MAX_CHUNK_PLAINTEXT) {
                        if write_vmess_chunk(&mut remote_write, &mut upload_state, chunk)
                            .await
                            .is_err()
                        {
                            return;
                        }
                    }
                }
                Err(_) => break,
            }
        }
    });

    tokio::spawn(async move {
        if read_vmess_response_header(&mut remote_read, &download_state)
            .await
            .is_err()
        {
            let _ = local_write.shutdown().await;
            return;
        }
        loop {
            match read_vmess_chunk(&mut remote_read, &mut download_state).await {
                Ok(Some(chunk)) => {
                    if local_write.write_all(&chunk).await.is_err() {
                        break;
                    }
                }
                Ok(None) => {
                    let _ = local_write.shutdown().await;
                    break;
                }
                Err(_) => {
                    let _ = local_write.shutdown().await;
                    break;
                }
            }
        }
    });

    app_side
}

async fn write_vmess_chunk<W>(
    writer: &mut W,
    state: &mut VmessUploadState,
    payload: &[u8],
) -> anyhow::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let body = match &mut state.cipher {
        Some(cipher) => cipher.encrypt(payload)?,
        None => payload.to_vec(),
    };
    if body.len() > u16::MAX as usize {
        return Err(anyhow!("vmess chunk is too large"));
    }
    let masked_len = (body.len() as u16) ^ state.length_mask.next();
    writer.write_all(&masked_len.to_be_bytes()).await?;
    writer.write_all(&body).await?;
    writer.flush().await?;
    Ok(())
}

async fn read_vmess_chunk<R>(
    reader: &mut R,
    state: &mut VmessDownloadState,
) -> anyhow::Result<Option<Vec<u8>>>
where
    R: AsyncRead + Unpin,
{
    let mut length = [0u8; 2];
    if !read_exact_or_eof(reader, &mut length).await? {
        return Ok(None);
    }
    let body_len = (u16::from_be_bytes(length) ^ state.length_mask.next()) as usize;
    let tag_len = state
        .cipher
        .as_ref()
        .map(|cipher| cipher.cipher.tag_len())
        .unwrap_or(0);
    if body_len == tag_len {
        let mut eof = vec![0u8; body_len];
        if body_len > 0 {
            reader.read_exact(&mut eof).await?;
        }
        return Ok(None);
    }
    if body_len > u16::MAX as usize {
        return Err(anyhow!("vmess response chunk is too large"));
    }
    if body_len < tag_len {
        return Err(anyhow!("vmess response chunk is shorter than tag"));
    }
    let mut body = vec![0u8; body_len];
    reader.read_exact(&mut body).await?;
    match &mut state.cipher {
        Some(cipher) => cipher.decrypt(&body).map(Some),
        None => Ok(Some(body)),
    }
}

async fn read_vmess_response_header<R>(
    reader: &mut R,
    state: &VmessDownloadState,
) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin,
{
    let len_key = vmess_kdf(&state.response_header_key, &[b"AEAD Resp Header Len Key"]);
    let len_nonce = vmess_kdf(&state.response_header_iv, &[b"AEAD Resp Header Len IV"]);
    let mut encrypted_len = [0u8; 2 + VMESS_TAG_LEN];
    reader.read_exact(&mut encrypted_len).await?;
    let len = vmess_aes128gcm_decrypt(&len_key[..16], &len_nonce[..12], &[], &encrypted_len)?;
    if len.len() != 2 {
        return Err(anyhow!("invalid vmess response header length"));
    }
    let header_len = u16::from_be_bytes([len[0], len[1]]) as usize;

    let header_key = vmess_kdf(&state.response_header_key, &[b"AEAD Resp Header Key"]);
    let header_nonce = vmess_kdf(&state.response_header_iv, &[b"AEAD Resp Header IV"]);
    let mut encrypted_header = vec![0u8; header_len + VMESS_TAG_LEN];
    reader.read_exact(&mut encrypted_header).await?;
    let header = vmess_aes128gcm_decrypt(
        &header_key[..16],
        &header_nonce[..12],
        &[],
        &encrypted_header,
    )?;
    if header.len() < 4 {
        return Err(anyhow!("vmess response header is too short"));
    }
    if header[0] != state.response_authentication {
        return Err(anyhow!(
            "invalid vmess response auth value: expected {}, got {}",
            state.response_authentication,
            header[0]
        ));
    }
    Ok(())
}

fn build_vmess_setup(
    user_id: &Uuid,
    cipher: VmessCipher,
    destination: &Destination,
) -> anyhow::Result<VmessSetup> {
    build_vmess_setup_with_command(user_id, cipher, destination, VMESS_CMD_TCP)
}

fn build_vmess_setup_with_command(
    user_id: &Uuid,
    cipher: VmessCipher,
    destination: &Destination,
    command: u8,
) -> anyhow::Result<VmessSetup> {
    let instruction_key = vmess_instruction_key(user_id);
    let auth_id = vmess_auth_id(&instruction_key)?;

    let mut data_iv = [0u8; 16];
    let mut data_key = [0u8; 16];
    getrandom::fill(&mut data_iv)
        .map_err(|error| anyhow!("failed to generate vmess iv: {error}"))?;
    getrandom::fill(&mut data_key)
        .map_err(|error| anyhow!("failed to generate vmess key: {error}"))?;
    let mut response_auth = [0u8; 1];
    getrandom::fill(&mut response_auth)
        .map_err(|error| anyhow!("failed to generate vmess response auth: {error}"))?;

    let response_header_iv = vmess_sha256_16(&data_iv);
    let response_header_key = vmess_sha256_16(&data_key);

    let mut header = Vec::with_capacity(316);
    header.push(0x01);
    header.extend_from_slice(&data_iv);
    header.extend_from_slice(&data_key);
    header.push(response_auth[0]);
    header.push(0x01 | 0x04);
    header.push(cipher.method_byte());
    header.push(0x00);
    header.push(command);
    encode_vmess_destination(destination, &mut header)?;
    let checksum = vmess_fnv1a(&header).to_be_bytes();
    header.extend_from_slice(&checksum);

    let mut nonce = [0u8; 8];
    getrandom::fill(&mut nonce)
        .map_err(|error| anyhow!("failed to generate vmess header nonce: {error}"))?;

    let len_key = vmess_kdf(
        &instruction_key,
        &[b"VMess Header AEAD Key_Length", &auth_id, &nonce],
    );
    let len_nonce = vmess_kdf(
        &instruction_key,
        &[b"VMess Header AEAD Nonce_Length", &auth_id, &nonce],
    );
    let encrypted_len = vmess_aes128gcm_encrypt(
        &len_key[..16],
        &len_nonce[..12],
        &auth_id,
        &(header.len() as u16).to_be_bytes(),
    )?;

    let header_key = vmess_kdf(
        &instruction_key,
        &[b"VMess Header AEAD Key", &auth_id, &nonce],
    );
    let header_nonce = vmess_kdf(
        &instruction_key,
        &[b"VMess Header AEAD Nonce", &auth_id, &nonce],
    );
    let encrypted_header =
        vmess_aes128gcm_encrypt(&header_key[..16], &header_nonce[..12], &auth_id, &header)?;

    let mut request =
        Vec::with_capacity(16 + encrypted_len.len() + nonce.len() + encrypted_header.len());
    request.extend_from_slice(&auth_id);
    request.extend_from_slice(&encrypted_len);
    request.extend_from_slice(&nonce);
    request.extend_from_slice(&encrypted_header);

    Ok(VmessSetup {
        request,
        upload: VmessUploadState {
            cipher: VmessAeadState::new(cipher, &data_key, &data_iv)?,
            length_mask: VmessLengthMask::new(&data_iv),
        },
        download: VmessDownloadState {
            response_header_key,
            response_header_iv,
            response_authentication: response_auth[0],
            cipher: VmessAeadState::new(cipher, &response_header_key, &response_header_iv)?,
            length_mask: VmessLengthMask::new(&response_header_iv),
        },
    })
}

fn encode_vmess_destination(destination: &Destination, output: &mut Vec<u8>) -> anyhow::Result<()> {
    output.extend_from_slice(&destination.port.to_be_bytes());
    if let Ok(ip) = destination.host.parse::<std::net::IpAddr>() {
        match ip {
            std::net::IpAddr::V4(ip) => {
                output.push(0x01);
                output.extend_from_slice(&ip.octets());
            }
            std::net::IpAddr::V6(ip) => {
                output.push(0x03);
                output.extend_from_slice(&ip.octets());
            }
        }
        return Ok(());
    }
    let host = destination.host.as_bytes();
    if host.len() > u8::MAX as usize {
        return Err(anyhow!("vmess destination host is too long"));
    }
    output.push(0x02);
    output.push(host.len() as u8);
    output.extend_from_slice(host);
    Ok(())
}

fn vmess_instruction_key(user_id: &Uuid) -> [u8; 16] {
    let mut data = user_id.as_bytes().to_vec();
    data.extend_from_slice(b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
    Md5::digest(&data).into()
}

fn vmess_auth_id(instruction_key: &[u8; 16]) -> anyhow::Result<[u8; 16]> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| anyhow!("system time before unix epoch: {error}"))?
        .as_secs();
    let mut auth = [0u8; 16];
    auth[0..8].copy_from_slice(&now.to_be_bytes());
    getrandom::fill(&mut auth[8..12])
        .map_err(|error| anyhow!("failed to generate vmess auth random: {error}"))?;
    let checksum = crc32c::crc32c(&auth[0..12]).to_be_bytes();
    auth[12..16].copy_from_slice(&checksum);

    let key = vmess_kdf(instruction_key, &[b"AES Auth ID Encryption"]);
    let cipher =
        Aes128::new_from_slice(&key[..16]).map_err(|_| anyhow!("invalid vmess auth key"))?;
    cipher.encrypt_block((&mut auth).into());
    Ok(auth)
}

fn vmess_aes128gcm_encrypt(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> anyhow::Result<Vec<u8>> {
    Aes128Gcm::new_from_slice(key)
        .map_err(|_| anyhow!("invalid vmess aes-gcm key"))?
        .encrypt(
            aes_gcm::Nonce::from_slice(nonce),
            aes_gcm::aead::Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| anyhow!("vmess aes-gcm encrypt failed"))
}

fn vmess_aes128gcm_decrypt(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> anyhow::Result<Vec<u8>> {
    Aes128Gcm::new_from_slice(key)
        .map_err(|_| anyhow!("invalid vmess aes-gcm key"))?
        .decrypt(
            aes_gcm::Nonce::from_slice(nonce),
            aes_gcm::aead::Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| anyhow!("vmess aes-gcm decrypt failed"))
}

fn vmess_kdf(key: &[u8], path: &[&[u8]]) -> [u8; 32] {
    let mut keys = Vec::with_capacity(path.len() + 1);
    keys.push(b"VMess AEAD KDF".as_slice());
    keys.extend_from_slice(path);
    vmess_recursive_hash(&keys, keys.len(), key)
}

fn vmess_recursive_hash(keys: &[&[u8]], level: usize, data: &[u8]) -> [u8; 32] {
    if level == 0 {
        return Sha256::digest(data).into();
    }
    let (inner_pad, outer_pad) = vmess_hmac_pads(keys[level - 1]);
    let mut inner_input = Vec::with_capacity(inner_pad.len() + data.len());
    inner_input.extend_from_slice(&inner_pad);
    inner_input.extend_from_slice(data);
    let inner_digest = vmess_recursive_hash(keys, level - 1, &inner_input);

    let mut outer_input = Vec::with_capacity(outer_pad.len() + inner_digest.len());
    outer_input.extend_from_slice(&outer_pad);
    outer_input.extend_from_slice(&inner_digest);
    vmess_recursive_hash(keys, level - 1, &outer_input)
}

fn vmess_hmac_pads(key: &[u8]) -> ([u8; 64], [u8; 64]) {
    let key_material = if key.len() > 64 {
        Sha256::digest(key).to_vec()
    } else {
        key.to_vec()
    };
    let mut inner = [0x36u8; 64];
    let mut outer = [0x5cu8; 64];
    for (index, byte) in key_material.iter().enumerate() {
        inner[index] ^= byte;
        outer[index] ^= byte;
    }
    (inner, outer)
}

fn vmess_sha256_16(data: &[u8]) -> [u8; 16] {
    let digest = Sha256::digest(data);
    let mut output = [0u8; 16];
    output.copy_from_slice(&digest[..16]);
    output
}

fn vmess_chacha_key(data: &[u8]) -> [u8; 32] {
    let first: [u8; 16] = Md5::digest(data).into();
    let second: [u8; 16] = Md5::digest(first).into();
    let mut output = [0u8; 32];
    output[..16].copy_from_slice(&first);
    output[16..].copy_from_slice(&second);
    output
}

fn vmess_fnv1a(data: &[u8]) -> u32 {
    let mut hash = 0x811c9dc5u32;
    for byte in data {
        hash ^= *byte as u32;
        hash = hash.wrapping_mul(16_777_619);
    }
    hash
}

const TROJAN_CMD_CONNECT: u8 = 0x01;
const TROJAN_CMD_UDP_ASSOCIATE: u8 = 0x03;

fn build_trojan_request(password: &str, destination: &Destination) -> anyhow::Result<Vec<u8>> {
    build_trojan_request_with_command(password, destination, TROJAN_CMD_CONNECT)
}

fn build_trojan_request_with_command(
    password: &str,
    destination: &Destination,
    command: u8,
) -> anyhow::Result<Vec<u8>> {
    let mut hasher = Sha224::new();
    hasher.update(password.as_bytes());
    let password_hash = hasher.finalize();
    let mut request = hex_lower(&password_hash).into_bytes();
    request.extend_from_slice(b"\r\n");
    request.push(command);
    encode_socks5_destination(destination, &mut request)?;
    request.extend_from_slice(b"\r\n");
    Ok(request)
}

fn encode_trojan_udp_packet(destination: &Destination, payload: &[u8]) -> anyhow::Result<Vec<u8>> {
    if payload.len() > u16::MAX as usize {
        return Err(anyhow!("trojan udp payload is too large"));
    }
    let mut packet = Vec::with_capacity(1 + 255 + 2 + 2 + 2 + payload.len());
    encode_socks5_destination(destination, &mut packet)?;
    packet.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    packet.extend_from_slice(b"\r\n");
    packet.extend_from_slice(payload);
    Ok(packet)
}

async fn read_trojan_udp_packet<R>(reader: &mut R) -> anyhow::Result<(Destination, Vec<u8>)>
where
    R: AsyncRead + Unpin,
{
    let mut atyp = [0u8; 1];
    reader.read_exact(&mut atyp).await?;
    let destination = read_socks5_destination_after_atyp(reader, atyp[0]).await?;
    let mut length = [0u8; 2];
    reader.read_exact(&mut length).await?;
    let payload_len = u16::from_be_bytes(length) as usize;
    let mut crlf = [0u8; 2];
    reader.read_exact(&mut crlf).await?;
    if crlf != *b"\r\n" {
        return Err(anyhow!("invalid trojan udp packet separator"));
    }
    let mut payload = vec![0u8; payload_len];
    reader.read_exact(&mut payload).await?;
    Ok((destination, payload))
}

const VLESS_CMD_TCP: u8 = 0x01;
const VLESS_CMD_UDP: u8 = 0x02;

#[cfg(test)]
fn build_vless_request(user_id: &Uuid, destination: &Destination) -> anyhow::Result<Vec<u8>> {
    build_vless_request_with_flow(user_id, destination, None)
}

fn build_vless_request_with_flow(
    user_id: &Uuid,
    destination: &Destination,
    flow: Option<&str>,
) -> anyhow::Result<Vec<u8>> {
    build_vless_request_with_command_and_flow(user_id, destination, flow, VLESS_CMD_TCP)
}

fn build_vless_request_with_command_and_flow(
    user_id: &Uuid,
    destination: &Destination,
    flow: Option<&str>,
    command: u8,
) -> anyhow::Result<Vec<u8>> {
    let mut request = Vec::with_capacity(32 + destination.host.len());
    request.push(0x00);
    request.extend_from_slice(user_id.as_bytes());
    let addons = encode_vless_addons(flow)?;
    if addons.len() > u8::MAX as usize {
        return Err(anyhow!("vless addons are too large"));
    }
    request.push(addons.len() as u8);
    request.extend_from_slice(&addons);
    request.push(command);
    encode_vless_destination(destination, &mut request)?;
    Ok(request)
}

fn encode_length_prefixed_packet(payload: &[u8], context: &str) -> anyhow::Result<Vec<u8>> {
    if payload.len() > u16::MAX as usize {
        return Err(anyhow!("{context} payload is too large"));
    }
    let mut packet = Vec::with_capacity(2 + payload.len());
    packet.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    packet.extend_from_slice(payload);
    Ok(packet)
}

async fn read_length_prefixed_packet<R>(reader: &mut R, context: &str) -> anyhow::Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut length = [0u8; 2];
    reader
        .read_exact(&mut length)
        .await
        .with_context(|| format!("failed to read {context} packet length"))?;
    let payload_len = u16::from_be_bytes(length) as usize;
    let mut payload = vec![0u8; payload_len];
    reader
        .read_exact(&mut payload)
        .await
        .with_context(|| format!("failed to read {context} packet payload"))?;
    Ok(payload)
}

fn encode_vless_addons(flow: Option<&str>) -> anyhow::Result<Vec<u8>> {
    let Some(flow) = flow.map(str::trim).filter(|flow| !flow.is_empty()) else {
        return Ok(Vec::new());
    };
    if flow != "xtls-rprx-vision" {
        return Err(anyhow!("unsupported vless flow {flow}"));
    }
    let mut output = Vec::with_capacity(flow.len() + 2);
    output.push(0x0a);
    encode_protobuf_varint(flow.len() as u64, &mut output);
    output.extend_from_slice(flow.as_bytes());
    Ok(output)
}

fn encode_protobuf_varint(mut value: u64, output: &mut Vec<u8>) {
    while value >= 0x80 {
        output.push((value as u8) | 0x80);
        value >>= 7;
    }
    output.push(value as u8);
}

fn encode_vless_destination(destination: &Destination, output: &mut Vec<u8>) -> anyhow::Result<()> {
    output.extend_from_slice(&destination.port.to_be_bytes());
    if let Ok(addr) = destination.host.parse::<SocketAddr>() {
        match addr {
            SocketAddr::V4(v4) => {
                output.push(0x01);
                output.extend_from_slice(&v4.ip().octets());
            }
            SocketAddr::V6(v6) => {
                output.push(0x03);
                output.extend_from_slice(&v6.ip().octets());
            }
        }
    } else if let Ok(ip) = destination.host.parse::<std::net::IpAddr>() {
        match ip {
            std::net::IpAddr::V4(ip) => {
                output.push(0x01);
                output.extend_from_slice(&ip.octets());
            }
            std::net::IpAddr::V6(ip) => {
                output.push(0x03);
                output.extend_from_slice(&ip.octets());
            }
        }
    } else {
        if destination.host.len() > 255 {
            return Err(anyhow!("domain name too long"));
        }
        output.push(0x02);
        output.push(destination.host.len() as u8);
        output.extend_from_slice(destination.host.as_bytes());
    }
    Ok(())
}

const REALITY_CLIENT_VERSION: [u8; 3] = [1, 8, 24];
static REALITY_X25519_KX_GROUP: RealityX25519KxGroup = RealityX25519KxGroup;

#[derive(Debug)]
struct RealityX25519KxGroup;

impl SupportedKxGroup for RealityX25519KxGroup {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, RustlsError> {
        let secret = X25519StaticSecret::random();
        let public = X25519PublicKey::from(&secret).to_bytes();
        Ok(Box::new(RealityX25519KeyExchange { secret, public }))
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::X25519
    }

    fn usable_for_version(&self, version: ProtocolVersion) -> bool {
        version == ProtocolVersion::TLSv1_3
    }
}

struct RealityX25519KeyExchange {
    secret: X25519StaticSecret,
    public: [u8; 32],
}

impl ActiveKeyExchange for RealityX25519KeyExchange {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, RustlsError> {
        reality_x25519_shared_secret(&self.secret, peer_pub_key)
    }

    fn dangerous_shared_secret_for_client_hello(
        &self,
        peer_pub_key: &[u8],
    ) -> Option<Result<SharedSecret, RustlsError>> {
        Some(reality_x25519_shared_secret(&self.secret, peer_pub_key))
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519
    }

    fn pub_key(&self) -> &[u8] {
        &self.public
    }
}

fn reality_x25519_shared_secret(
    secret: &X25519StaticSecret,
    peer_pub_key: &[u8],
) -> Result<SharedSecret, RustlsError> {
    let peer_pub_key: [u8; 32] = peer_pub_key
        .try_into()
        .map_err(|_| RustlsError::General("invalid X25519 peer key share".into()))?;
    let peer = X25519PublicKey::from(peer_pub_key);
    Ok(SharedSecret::from(
        secret.diffie_hellman(&peer).as_bytes().as_slice(),
    ))
}

#[derive(Debug)]
struct RealitySessionIdProvider {
    public_key: [u8; 32],
    short_id: Vec<u8>,
}

impl DangerousClientHelloSessionIdProvider for RealitySessionIdProvider {
    fn plaintext_session_id(&self) -> [u8; 32] {
        let unix_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs().min(u32::MAX as u64) as u32)
            .unwrap_or(0);
        let mut session_id = [0u8; 32];
        session_id[..3].copy_from_slice(&REALITY_CLIENT_VERSION);
        session_id[3] = 0;
        session_id[4..8].copy_from_slice(&unix_time.to_be_bytes());
        session_id[8..8 + self.short_id.len()].copy_from_slice(&self.short_id);
        session_id
    }

    fn seal_session_id(
        &self,
        client_hello_random: &[u8; 32],
        client_hello_raw: &[u8],
        key_exchange: &dyn ActiveKeyExchange,
    ) -> Result<[u8; 32], RustlsError> {
        let shared_secret = key_exchange
            .dangerous_shared_secret_for_client_hello(&self.public_key)
            .ok_or_else(|| {
                RustlsError::General("Reality X25519 shared secret is not available".into())
            })??;
        seal_reality_session_id_from_client_hello(
            shared_secret.secret_bytes(),
            client_hello_random,
            client_hello_raw,
        )
        .map_err(|error| RustlsError::General(format!("Reality session id failed: {error}")))
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct RealityClientHelloMaterial {
    session_id: [u8; 32],
    auth_key: [u8; 32],
    client_public_key: [u8; 32],
    unix_time: u32,
}

#[allow(dead_code)]
fn build_reality_client_hello_material(
    public_key: &str,
    short_id: Option<&str>,
    hello_random: &[u8; 32],
    hello_raw: &[u8],
) -> anyhow::Result<RealityClientHelloMaterial> {
    let server_public_key = decode_reality_public_key(public_key)?;
    let short_id = decode_reality_short_id(short_id)?;
    let client_secret = X25519StaticSecret::random();
    let client_public_key = X25519PublicKey::from(&client_secret).to_bytes();
    let shared_secret = client_secret.diffie_hellman(&server_public_key);
    let unix_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before unix epoch")?
        .as_secs()
        .min(u32::MAX as u64) as u32;
    let (session_id, auth_key) = seal_reality_session_id(
        shared_secret.as_bytes(),
        &short_id,
        hello_random,
        hello_raw,
        unix_time,
    )?;
    Ok(RealityClientHelloMaterial {
        session_id,
        auth_key,
        client_public_key,
        unix_time,
    })
}

fn seal_reality_session_id_from_client_hello(
    shared_secret: &[u8],
    hello_random: &[u8; 32],
    hello_raw: &[u8],
) -> anyhow::Result<[u8; 32]> {
    if shared_secret.len() != 32 {
        return Err(anyhow!("vless reality shared secret must be 32 bytes"));
    }
    if hello_raw.len() < 55 {
        return Err(anyhow!("vless reality ClientHello is too short"));
    }
    let mut shared = [0u8; 32];
    shared.copy_from_slice(shared_secret);
    let mut auth_key = [0u8; 32];
    Hkdf::<Sha256>::new(Some(&hello_random[..20]), &shared)
        .expand(b"REALITY", &mut auth_key)
        .map_err(|_| anyhow!("failed to derive vless reality auth key"))?;

    let cipher = Aes256Gcm::new_from_slice(&auth_key)
        .map_err(|_| anyhow!("failed to initialize vless reality aead"))?;
    let encrypted = cipher
        .encrypt(
            aes_gcm::Nonce::from_slice(&hello_random[20..]),
            aes_gcm::aead::Payload {
                msg: &hello_raw[39..55],
                aad: hello_raw,
            },
        )
        .map_err(|_| anyhow!("failed to seal vless reality session id"))?;
    encrypted
        .try_into()
        .map_err(|_| anyhow!("vless reality sealed session id has invalid length"))
}

fn decode_reality_public_key(value: &str) -> anyhow::Result<X25519PublicKey> {
    let value = value.trim();
    if value.is_empty() {
        return Err(anyhow!("vless reality public key is empty"));
    }
    let bytes = base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, value)
        .or_else(|_| base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE, value))
        .or_else(|_| base64::Engine::decode(&base64::engine::general_purpose::STANDARD, value))
        .map_err(|error| anyhow!("invalid vless reality public key: {error}"))?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow!("vless reality public key must decode to 32 bytes"))?;
    Ok(X25519PublicKey::from(bytes))
}

fn decode_reality_short_id(value: Option<&str>) -> anyhow::Result<Vec<u8>> {
    let value = value.map(str::trim).unwrap_or("");
    if value.is_empty() {
        return Ok(Vec::new());
    }
    if value.len() > 16 {
        return Err(anyhow!("vless reality short_id cannot exceed 8 bytes"));
    }
    if value.len() % 2 != 0 {
        return Err(anyhow!(
            "vless reality short_id must be hex with even length"
        ));
    }
    let mut output = Vec::with_capacity(value.len() / 2);
    let bytes = value.as_bytes();
    for index in (0..bytes.len()).step_by(2) {
        let high = decode_hex_nibble(bytes[index])
            .ok_or_else(|| anyhow!("vless reality short_id contains non-hex character"))?;
        let low = decode_hex_nibble(bytes[index + 1])
            .ok_or_else(|| anyhow!("vless reality short_id contains non-hex character"))?;
        output.push((high << 4) | low);
    }
    Ok(output)
}

fn validate_reality_fingerprint(value: Option<&str>) -> anyhow::Result<()> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(());
    };
    let supported = matches!(
        value.to_ascii_lowercase().as_str(),
        "chrome"
            | "firefox"
            | "safari"
            | "ios"
            | "android"
            | "edge"
            | "qq"
            | "random"
            | "randomized"
    );
    if supported {
        Ok(())
    } else {
        Err(anyhow!("unsupported vless reality fingerprint {value}"))
    }
}

fn validate_reality_spider_x(value: Option<&str>) -> anyhow::Result<()> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(());
    };
    if value.starts_with('/') {
        Ok(())
    } else {
        Err(anyhow!("vless reality spider_x must start with /"))
    }
}

fn decode_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[allow(dead_code)]
fn seal_reality_session_id(
    shared_secret: &[u8; 32],
    short_id: &[u8],
    hello_random: &[u8; 32],
    hello_raw: &[u8],
    unix_time: u32,
) -> anyhow::Result<([u8; 32], [u8; 32])> {
    if short_id.len() > 8 {
        return Err(anyhow!("vless reality short_id cannot exceed 8 bytes"));
    }
    let mut auth_key = [0u8; 32];
    Hkdf::<Sha256>::new(Some(&hello_random[..20]), shared_secret)
        .expand(b"REALITY", &mut auth_key)
        .map_err(|_| anyhow!("failed to derive vless reality auth key"))?;

    let mut plaintext = [0u8; 16];
    plaintext[..3].copy_from_slice(&REALITY_CLIENT_VERSION);
    plaintext[3] = 0;
    plaintext[4..8].copy_from_slice(&unix_time.to_be_bytes());
    plaintext[8..8 + short_id.len()].copy_from_slice(short_id);

    let cipher = Aes256Gcm::new_from_slice(&auth_key)
        .map_err(|_| anyhow!("failed to initialize vless reality aead"))?;
    let encrypted = cipher
        .encrypt(
            aes_gcm::Nonce::from_slice(&hello_random[20..]),
            aes_gcm::aead::Payload {
                msg: &plaintext,
                aad: hello_raw,
            },
        )
        .map_err(|_| anyhow!("failed to seal vless reality session id"))?;
    let session_id: [u8; 32] = encrypted
        .try_into()
        .map_err(|_| anyhow!("vless reality sealed session id has invalid length"))?;
    Ok((session_id, auth_key))
}

async fn read_vless_response_header<R>(reader: &mut R) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; 2];
    reader.read_exact(&mut header).await?;
    if header[0] != 0x00 {
        return Err(anyhow!("unsupported vless response version {}", header[0]));
    }
    if header[1] > 0 {
        let mut addon = vec![0u8; header[1] as usize];
        reader.read_exact(&mut addon).await?;
    }
    Ok(())
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

const SS_CHUNK_SIZE: usize = 0x3fff;
const SS_TAG_LEN: usize = 16;
const SS_NONCE_LEN: usize = 12;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SsCipher {
    Aes128Gcm,
    Aes256Gcm,
    Chacha20IetfPoly1305,
    Blake3Aes128Gcm,
    Blake3Aes256Gcm,
    Blake3Chacha20IetfPoly1305,
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

impl SsCipher {
    fn from_method(method: &str) -> anyhow::Result<Self> {
        match method.to_ascii_lowercase().as_str() {
            "aes-128-gcm" => Ok(Self::Aes128Gcm),
            "aes-256-gcm" => Ok(Self::Aes256Gcm),
            "chacha20-ietf-poly1305" | "chacha20-poly1305" => Ok(Self::Chacha20IetfPoly1305),
            "2022-blake3-aes-128-gcm" => Ok(Self::Blake3Aes128Gcm),
            "2022-blake3-aes-256-gcm" => Ok(Self::Blake3Aes256Gcm),
            "2022-blake3-chacha20-poly1305" => Ok(Self::Blake3Chacha20IetfPoly1305),
            _ => Err(anyhow!("unsupported shadowsocks method {method}")),
        }
    }

    fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm | Self::Blake3Aes128Gcm => 16,
            Self::Aes256Gcm | Self::Chacha20IetfPoly1305 => 32,
            Self::Blake3Aes256Gcm | Self::Blake3Chacha20IetfPoly1305 => 32,
        }
    }

    fn salt_len(self) -> usize {
        match self {
            Self::Blake3Aes128Gcm | Self::Blake3Aes256Gcm | Self::Blake3Chacha20IetfPoly1305 => {
                self.key_len()
            }
            _ => self.key_len(),
        }
    }

    fn nonce_len(self) -> usize {
        SS_NONCE_LEN
    }

    fn is_blake3(self) -> bool {
        matches!(
            self,
            Self::Blake3Aes128Gcm | Self::Blake3Aes256Gcm | Self::Blake3Chacha20IetfPoly1305
        )
    }

    fn master_key(self, password: &[u8]) -> anyhow::Result<Vec<u8>> {
        if !self.is_blake3() {
            return Ok(evp_bytes_to_key(password, self.key_len()));
        }
        self.psk_chain(password)?
            .into_iter()
            .last()
            .ok_or_else(|| anyhow!("shadowsocks 2022 PSK is empty"))
    }

    fn psk_chain(self, password: &[u8]) -> anyhow::Result<Vec<Vec<u8>>> {
        if !self.is_blake3() {
            return Ok(vec![evp_bytes_to_key(password, self.key_len())]);
        }
        let password = std::str::from_utf8(password)
            .map_err(|_| anyhow!("shadowsocks 2022 PSK must be base64 text"))?;
        let mut keys = Vec::new();
        for encoded in password.split(':').map(str::trim) {
            if encoded.is_empty() {
                return Err(anyhow!("shadowsocks 2022 PSK chain contains an empty key"));
            }
            let decoded = [
                &base64::engine::general_purpose::STANDARD,
                &base64::engine::general_purpose::STANDARD_NO_PAD,
                &base64::engine::general_purpose::URL_SAFE,
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            ]
            .into_iter()
            .find_map(|engine| base64::Engine::decode(engine, encoded).ok())
            .ok_or_else(|| anyhow!("shadowsocks 2022 PSK is not valid base64"))?;
            if decoded.len() != self.key_len() {
                return Err(anyhow!(
                    "shadowsocks 2022 PSK has {} bytes, expected {}",
                    decoded.len(),
                    self.key_len()
                ));
            }
            keys.push(decoded);
        }
        if keys.is_empty() {
            return Err(anyhow!("shadowsocks 2022 PSK is empty"));
        }
        Ok(keys)
    }

    fn derive_subkey(self, master_key: &[u8], salt: &[u8]) -> anyhow::Result<Vec<u8>> {
        if self.is_blake3() {
            let mut key_material = Vec::with_capacity(master_key.len() + salt.len());
            key_material.extend_from_slice(master_key);
            key_material.extend_from_slice(salt);
            let derived = blake3::derive_key("shadowsocks 2022 session subkey", &key_material);
            Ok(derived[..self.key_len()].to_vec())
        } else {
            let hkdf = Hkdf::<Sha1>::new(Some(salt), master_key);
            let mut subkey = vec![0u8; self.key_len()];
            hkdf.expand(b"ss-subkey", &mut subkey)
                .map_err(|_| anyhow!("failed to derive shadowsocks subkey"))?;
            Ok(subkey)
        }
    }

    fn encrypt(self, key: &[u8], nonce: &[u8], plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
        match self {
            Self::Aes128Gcm | Self::Blake3Aes128Gcm => Aes128Gcm::new_from_slice(key)
                .map_err(|_| anyhow!("invalid aes-128-gcm key"))?
                .encrypt(aes_gcm::Nonce::from_slice(nonce), plaintext)
                .map_err(|_| anyhow!("shadowsocks encrypt failed")),
            Self::Aes256Gcm | Self::Blake3Aes256Gcm => Aes256Gcm::new_from_slice(key)
                .map_err(|_| anyhow!("invalid aes-256-gcm key"))?
                .encrypt(aes_gcm::Nonce::from_slice(nonce), plaintext)
                .map_err(|_| anyhow!("shadowsocks encrypt failed")),
            Self::Chacha20IetfPoly1305 | Self::Blake3Chacha20IetfPoly1305 => {
                ChaCha20Poly1305::new_from_slice(key)
                    .map_err(|_| anyhow!("invalid chacha20-ietf-poly1305 key"))?
                    .encrypt(chacha20poly1305::Nonce::from_slice(nonce), plaintext)
                    .map_err(|_| anyhow!("shadowsocks encrypt failed"))
            }
        }
    }

    fn decrypt(self, key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
        match self {
            Self::Aes128Gcm | Self::Blake3Aes128Gcm => Aes128Gcm::new_from_slice(key)
                .map_err(|_| anyhow!("invalid aes-128-gcm key"))?
                .decrypt(aes_gcm::Nonce::from_slice(nonce), ciphertext)
                .map_err(|_| anyhow!("shadowsocks decrypt failed")),
            Self::Aes256Gcm | Self::Blake3Aes256Gcm => Aes256Gcm::new_from_slice(key)
                .map_err(|_| anyhow!("invalid aes-256-gcm key"))?
                .decrypt(aes_gcm::Nonce::from_slice(nonce), ciphertext)
                .map_err(|_| anyhow!("shadowsocks decrypt failed")),
            Self::Chacha20IetfPoly1305 | Self::Blake3Chacha20IetfPoly1305 => {
                ChaCha20Poly1305::new_from_slice(key)
                    .map_err(|_| anyhow!("invalid chacha20-ietf-poly1305 key"))?
                    .decrypt(chacha20poly1305::Nonce::from_slice(nonce), ciphertext)
                    .map_err(|_| anyhow!("shadowsocks decrypt failed"))
            }
        }
    }

    fn max_chunk_size(self) -> usize {
        if self.is_blake3() {
            u16::MAX as usize
        } else {
            SS_CHUNK_SIZE
        }
    }
}

fn evp_bytes_to_key(password: &[u8], key_len: usize) -> Vec<u8> {
    let mut key = Vec::with_capacity(key_len);
    let mut previous = Vec::new();
    while key.len() < key_len {
        let mut digest = Md5::new();
        if !previous.is_empty() {
            digest.update(&previous);
        }
        digest.update(password);
        previous = digest.finalize().to_vec();
        key.extend_from_slice(&previous);
    }
    key.truncate(key_len);
    key
}

fn increment_nonce(nonce: &mut [u8]) {
    for item in nonce.iter_mut() {
        let (next, overflow) = item.overflowing_add(1);
        *item = next;
        if !overflow {
            break;
        }
    }
}

const SS2022_CLIENT_STREAM_TYPE: u8 = 0;
const SS2022_SERVER_STREAM_TYPE: u8 = 1;
const SS2022_MAX_CLOCK_SKEW_SECS: u64 = 30;

fn current_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn validate_ss2022_timestamp(timestamp: u64) -> anyhow::Result<()> {
    let now = current_unix_timestamp();
    if now.abs_diff(timestamp) > SS2022_MAX_CLOCK_SKEW_SECS {
        return Err(anyhow!(
            "shadowsocks 2022 timestamp is outside the allowed clock skew"
        ));
    }
    Ok(())
}

fn build_ss2022_request_header(
    cipher: SsCipher,
    subkey: &[u8],
    nonce: &mut [u8],
    destination: &Destination,
) -> anyhow::Result<Vec<u8>> {
    let mut variable_header = Vec::new();
    encode_socks5_destination(destination, &mut variable_header)?;

    let mut random = [0u8; 1];
    getrandom::fill(&mut random)
        .map_err(|error| anyhow!("failed to generate shadowsocks 2022 padding: {error}"))?;
    let padding_length = 1 + (random[0] as usize % 32);
    variable_header.extend_from_slice(&(padding_length as u16).to_be_bytes());
    let padding_start = variable_header.len();
    variable_header.resize(padding_start + padding_length, 0);
    getrandom::fill(&mut variable_header[padding_start..])
        .map_err(|error| anyhow!("failed to generate shadowsocks 2022 padding: {error}"))?;
    if variable_header.len() > u16::MAX as usize {
        return Err(anyhow!("shadowsocks 2022 request header is too large"));
    }

    let mut fixed_header = Vec::with_capacity(11);
    fixed_header.push(SS2022_CLIENT_STREAM_TYPE);
    fixed_header.extend_from_slice(&current_unix_timestamp().to_be_bytes());
    fixed_header.extend_from_slice(&(variable_header.len() as u16).to_be_bytes());

    let mut output = cipher.encrypt(subkey, nonce, &fixed_header)?;
    increment_nonce(nonce);
    output.extend_from_slice(&cipher.encrypt(subkey, nonce, &variable_header)?);
    increment_nonce(nonce);
    Ok(output)
}

fn build_ss2022_tcp_identity_headers(
    cipher: SsCipher,
    psk_chain: &[Vec<u8>],
    salt: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let mut output = Vec::with_capacity(psk_chain.len().saturating_sub(1) * 16);
    for pair in psk_chain.windows(2) {
        let mut key_material = Vec::with_capacity(pair[0].len() + salt.len());
        key_material.extend_from_slice(&pair[0]);
        key_material.extend_from_slice(salt);
        let identity_subkey = blake3::derive_key("shadowsocks 2022 identity subkey", &key_material);
        let next_hash = blake3::hash(&pair[1]);
        let plaintext: [u8; 16] = next_hash.as_bytes()[..16].try_into()?;
        let encrypted =
            ss2022_identity_aes_block(&identity_subkey[..cipher.key_len()], &plaintext, true)?;
        output.extend_from_slice(&encrypted);
    }
    Ok(output)
}

async fn read_ss2022_response_header<R>(
    cipher: SsCipher,
    subkey: &[u8],
    nonce: &mut [u8],
    request_salt: &[u8],
    reader: &mut R,
) -> anyhow::Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let fixed_header_length = 1 + 8 + request_salt.len() + 2;
    let mut encrypted_fixed_header = vec![0u8; fixed_header_length + SS_TAG_LEN];
    reader.read_exact(&mut encrypted_fixed_header).await?;
    let fixed_header = cipher.decrypt(subkey, nonce, &encrypted_fixed_header)?;
    increment_nonce(nonce);
    if fixed_header.len() != fixed_header_length {
        return Err(anyhow!(
            "invalid shadowsocks 2022 response fixed header length"
        ));
    }
    if fixed_header[0] != SS2022_SERVER_STREAM_TYPE {
        return Err(anyhow!(
            "invalid shadowsocks 2022 response stream type {}",
            fixed_header[0]
        ));
    }
    let timestamp = u64::from_be_bytes(fixed_header[1..9].try_into()?);
    validate_ss2022_timestamp(timestamp)?;
    let salt_end = 9 + request_salt.len();
    if &fixed_header[9..salt_end] != request_salt {
        return Err(anyhow!(
            "shadowsocks 2022 response does not match request salt"
        ));
    }
    let payload_length =
        u16::from_be_bytes(fixed_header[salt_end..salt_end + 2].try_into()?) as usize;
    let mut encrypted_payload = vec![0u8; payload_length + SS_TAG_LEN];
    reader.read_exact(&mut encrypted_payload).await?;
    let payload = cipher.decrypt(subkey, nonce, &encrypted_payload)?;
    increment_nonce(nonce);
    Ok(payload)
}

fn encode_shadowsocks_udp_packet(
    cipher: SsCipher,
    password: &[u8],
    destination: &Destination,
    payload: &[u8],
    ss2022_state: Option<&mut Ss2022UdpState>,
) -> anyhow::Result<Vec<u8>> {
    if cipher.is_blake3() {
        return encode_ss2022_udp_packet(
            cipher,
            password,
            destination,
            payload,
            ss2022_state.ok_or_else(|| anyhow!("missing shadowsocks 2022 UDP session state"))?,
        );
    }
    let master_key = cipher.master_key(password)?;
    let mut salt = vec![0u8; cipher.salt_len()];
    getrandom::fill(&mut salt)
        .map_err(|error| anyhow!("failed to generate shadowsocks udp salt: {error}"))?;
    let subkey = cipher.derive_subkey(&master_key, &salt)?;
    let mut plaintext = Vec::with_capacity(1 + 255 + 2 + payload.len());
    encode_socks5_destination(destination, &mut plaintext)?;
    plaintext.extend_from_slice(payload);
    let nonce = [0u8; SS_NONCE_LEN];
    let encrypted = cipher.encrypt(&subkey, &nonce, &plaintext)?;
    let mut packet = Vec::with_capacity(salt.len() + encrypted.len());
    packet.extend_from_slice(&salt);
    packet.extend_from_slice(&encrypted);
    Ok(packet)
}

fn decode_shadowsocks_udp_packet(
    cipher: SsCipher,
    password: &[u8],
    packet: &[u8],
    ss2022_state: Option<&mut Ss2022UdpState>,
) -> anyhow::Result<(Destination, Vec<u8>)> {
    if cipher.is_blake3() {
        return decode_ss2022_udp_packet(
            cipher,
            password,
            packet,
            ss2022_state.ok_or_else(|| anyhow!("missing shadowsocks 2022 UDP session state"))?,
        );
    }
    let salt_len = cipher.salt_len();
    if packet.len() < salt_len + SS_TAG_LEN {
        return Err(anyhow!("short shadowsocks udp packet"));
    }
    let master_key = cipher.master_key(password)?;
    let subkey = cipher.derive_subkey(&master_key, &packet[..salt_len])?;
    let nonce = [0u8; SS_NONCE_LEN];
    let plaintext = cipher.decrypt(&subkey, &nonce, &packet[salt_len..])?;
    let (destination, payload_offset) = parse_socks5_destination_prefix(&plaintext)?;
    Ok((destination, plaintext[payload_offset..].to_vec()))
}

fn encode_ss2022_udp_packet(
    cipher: SsCipher,
    password: &[u8],
    destination: &Destination,
    payload: &[u8],
    state: &mut Ss2022UdpState,
) -> anyhow::Result<Vec<u8>> {
    let psk_chain = cipher.psk_chain(password)?;
    let psk = psk_chain
        .last()
        .ok_or_else(|| anyhow!("shadowsocks 2022 PSK chain is empty"))?;
    let (client_session_id, packet_id) = state.next_client_packet()?;
    if cipher == SsCipher::Blake3Chacha20IetfPoly1305 {
        if psk_chain.len() > 1 {
            return Err(anyhow!(
                "SIP023 identity headers are not defined for Shadowsocks 2022 chacha UDP"
            ));
        }
        let mut nonce = [0u8; 24];
        getrandom::fill(&mut nonce)
            .map_err(|error| anyhow!("failed to generate shadowsocks 2022 UDP nonce: {error}"))?;
        let mut body = Vec::new();
        body.extend_from_slice(&client_session_id);
        body.extend_from_slice(&packet_id.to_be_bytes());
        body.push(0);
        body.extend_from_slice(&current_unix_timestamp().to_be_bytes());
        body.extend_from_slice(&0u16.to_be_bytes());
        encode_socks5_destination(destination, &mut body)?;
        body.extend_from_slice(payload);
        let encrypted = XChaCha20Poly1305::new_from_slice(psk)
            .map_err(|_| anyhow!("invalid shadowsocks 2022 chacha PSK"))?
            .encrypt(chacha20poly1305::XNonce::from_slice(&nonce), body.as_ref())
            .map_err(|_| anyhow!("shadowsocks 2022 UDP encryption failed"))?;
        let mut packet = nonce.to_vec();
        packet.extend_from_slice(&encrypted);
        return Ok(packet);
    }

    let mut separate_header = [0u8; 16];
    separate_header[..8].copy_from_slice(&client_session_id);
    separate_header[8..].copy_from_slice(&packet_id.to_be_bytes());
    let encrypted_header = ss2022_aes_block(cipher, &psk_chain[0], &separate_header, true)?;
    let subkey = cipher.derive_subkey(psk, &client_session_id)?;
    let nonce = &separate_header[4..16];
    let mut body = Vec::new();
    body.push(0);
    body.extend_from_slice(&current_unix_timestamp().to_be_bytes());
    body.extend_from_slice(&0u16.to_be_bytes());
    encode_socks5_destination(destination, &mut body)?;
    body.extend_from_slice(payload);
    let encrypted_body = cipher.encrypt(&subkey, nonce, &body)?;
    let mut packet = encrypted_header.to_vec();
    for pair in psk_chain.windows(2) {
        let next_hash = blake3::hash(&pair[1]);
        let mut plaintext: [u8; 16] = next_hash.as_bytes()[..16].try_into()?;
        for (byte, header_byte) in plaintext.iter_mut().zip(separate_header) {
            *byte ^= header_byte;
        }
        packet.extend_from_slice(&ss2022_identity_aes_block(&pair[0], &plaintext, true)?);
    }
    packet.extend_from_slice(&encrypted_body);
    Ok(packet)
}

fn decode_ss2022_udp_packet(
    cipher: SsCipher,
    password: &[u8],
    packet: &[u8],
    state: &mut Ss2022UdpState,
) -> anyhow::Result<(Destination, Vec<u8>)> {
    let psk = cipher.master_key(password)?;
    let (server_session_id, packet_id, body) = if cipher == SsCipher::Blake3Chacha20IetfPoly1305 {
        if packet.len() < 24 + SS_TAG_LEN {
            return Err(anyhow!("short shadowsocks 2022 chacha UDP packet"));
        }
        let nonce = &packet[..24];
        let body = XChaCha20Poly1305::new_from_slice(&psk)
            .map_err(|_| anyhow!("invalid shadowsocks 2022 chacha PSK"))?
            .decrypt(chacha20poly1305::XNonce::from_slice(nonce), &packet[24..])
            .map_err(|_| anyhow!("shadowsocks 2022 UDP decryption failed"))?;
        if body.len() < 16 {
            return Err(anyhow!("short shadowsocks 2022 chacha UDP message header"));
        }
        let server_session_id: [u8; 8] = body[..8].try_into()?;
        let packet_id = u64::from_be_bytes(body[8..16].try_into()?);
        (server_session_id, packet_id, body[16..].to_vec())
    } else {
        if packet.len() < 16 + SS_TAG_LEN {
            return Err(anyhow!("short shadowsocks 2022 AES UDP packet"));
        }
        let encrypted_header: [u8; 16] = packet[..16].try_into()?;
        let separate_header = ss2022_aes_block(cipher, &psk, &encrypted_header, false)?;
        let server_session_id: [u8; 8] = separate_header[..8].try_into()?;
        let packet_id = u64::from_be_bytes(separate_header[8..].try_into()?);
        let subkey = cipher.derive_subkey(&psk, &server_session_id)?;
        let body = cipher.decrypt(&subkey, &separate_header[4..16], &packet[16..])?;
        (server_session_id, packet_id, body)
    };

    if body.len() < 1 + 8 + 8 + 2 {
        return Err(anyhow!("short shadowsocks 2022 UDP response header"));
    }
    if body[0] != 1 {
        return Err(anyhow!(
            "invalid shadowsocks 2022 UDP response type {}",
            body[0]
        ));
    }
    let timestamp = u64::from_be_bytes(body[1..9].try_into()?);
    validate_ss2022_timestamp(timestamp)?;
    if body[9..17] != state.client_session_id {
        return Err(anyhow!(
            "shadowsocks 2022 UDP response has the wrong client session ID"
        ));
    }
    let padding_length = u16::from_be_bytes(body[17..19].try_into()?) as usize;
    let destination_offset = 19usize
        .checked_add(padding_length)
        .ok_or_else(|| anyhow!("shadowsocks 2022 UDP padding length overflow"))?;
    if destination_offset > body.len() {
        return Err(anyhow!("shadowsocks 2022 UDP padding is truncated"));
    }
    let (destination, destination_length) =
        parse_socks5_destination_prefix(&body[destination_offset..])?;
    let payload_offset = destination_offset + destination_length;
    state.accept_server_packet(server_session_id, packet_id)?;
    Ok((destination, body[payload_offset..].to_vec()))
}

fn ss2022_aes_block(
    cipher: SsCipher,
    psk: &[u8],
    input: &[u8; 16],
    encrypt: bool,
) -> anyhow::Result<[u8; 16]> {
    if !matches!(
        cipher,
        SsCipher::Blake3Aes128Gcm | SsCipher::Blake3Aes256Gcm
    ) {
        return Err(anyhow!("shadowsocks 2022 UDP AES block method required"));
    }
    ss2022_identity_aes_block(psk, input, encrypt)
}

fn ss2022_identity_aes_block(
    key: &[u8],
    input: &[u8; 16],
    encrypt: bool,
) -> anyhow::Result<[u8; 16]> {
    let mut output = [0u8; 16];
    match key.len() {
        16 => {
            let cipher = Aes128::new_from_slice(key)
                .map_err(|_| anyhow!("invalid shadowsocks 2022 AES-128 PSK"))?;
            let mut block = Block::<Aes128>::default();
            block.copy_from_slice(input);
            if encrypt {
                cipher.encrypt_block(&mut block);
            } else {
                cipher.decrypt_block(&mut block);
            }
            output.copy_from_slice(&block);
        }
        32 => {
            let cipher = Aes256::new_from_slice(key)
                .map_err(|_| anyhow!("invalid shadowsocks 2022 AES-256 PSK"))?;
            let mut block = Block::<Aes256>::default();
            block.copy_from_slice(input);
            if encrypt {
                cipher.encrypt_block(&mut block);
            } else {
                cipher.decrypt_block(&mut block);
            }
            output.copy_from_slice(&block);
        }
        length => {
            return Err(anyhow!(
                "shadowsocks 2022 identity key has invalid length {length}"
            ))
        }
    }
    Ok(output)
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

fn spawn_shadowsocks_stream(
    cipher: SsCipher,
    master_key: Vec<u8>,
    request_salt: Vec<u8>,
    upload_key: Vec<u8>,
    upload_nonce: Vec<u8>,
    stream: BoxedStream,
    plugin: Option<ShadowsocksPluginConfig>,
) -> DuplexStream {
    let (app_side, relay_side) = tokio::io::duplex(64 * 1024);
    let (mut local_read, mut local_write) = tokio::io::split(relay_side);
    let (mut remote_read, mut remote_write) = tokio::io::split(stream);

    let upload_tls_obfs = plugin_is_tls_obfs(plugin.as_ref());
    tokio::spawn(async move {
        let mut nonce = upload_nonce;
        let mut buf = vec![0u8; SS_CHUNK_SIZE];
        loop {
            match local_read.read(&mut buf).await {
                Ok(0) => {
                    let _ = remote_write.shutdown().await;
                    break;
                }
                Ok(n) => {
                    if write_ss_plugin_chunk(
                        cipher,
                        &upload_key,
                        &mut nonce,
                        &mut remote_write,
                        &buf[..n],
                        upload_tls_obfs,
                    )
                    .await
                    .is_err()
                    {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    tokio::spawn(async move {
        if plugin_is_http_obfs(plugin.as_ref()) {
            match read_http_obfs_response(&mut remote_read).await {
                Ok(leftover) => {
                    let cursor = Cursor::new(leftover);
                    let mut chained = cursor.chain(remote_read);
                    relay_shadowsocks_download_with_response_salt(
                        cipher,
                        &master_key,
                        &request_salt,
                        &mut chained,
                        &mut local_write,
                    )
                    .await;
                }
                Err(_) => {
                    let _ = local_write.shutdown().await;
                }
            }
        } else if plugin_is_tls_obfs(plugin.as_ref()) {
            relay_shadowsocks_tls_download_with_response_salt(
                cipher,
                &master_key,
                &request_salt,
                remote_read,
                local_write,
            )
            .await;
        } else {
            relay_shadowsocks_download_with_response_salt(
                cipher,
                &master_key,
                &request_salt,
                &mut remote_read,
                &mut local_write,
            )
            .await;
        }
    });

    app_side
}

fn spawn_snell_v4_reuse_stream(
    connection: SnellV4PooledConnection,
    pool: Arc<TokioMutex<SnellV4ConnectionPool>>,
    initial_payload: Vec<u8>,
) -> DuplexStream {
    let (app_side, relay_side) = tokio::io::duplex(64 * 1024);
    let (mut local_read, mut local_write) = tokio::io::split(relay_side);
    let SnellV4PooledConnection {
        mut reader,
        mut writer,
    } = connection;

    tokio::spawn(async move {
        let mut clean = true;
        let mut upload_closed = false;
        let mut peer_closed = false;
        if !initial_payload.is_empty() && local_write.write_all(&initial_payload).await.is_err() {
            clean = false;
        }

        let mut buffer = vec![0u8; SS_CHUNK_SIZE];
        while clean && !peer_closed {
            tokio::select! {
                local_result = local_read.read(&mut buffer), if !upload_closed => {
                    match local_result {
                        Ok(0) => {
                            if writer.write_zero().await.is_err() {
                                clean = false;
                            }
                            upload_closed = true;
                        }
                        Ok(length) => {
                            if writer.write_payload(&buffer[..length]).await.is_err() {
                                clean = false;
                            }
                        }
                        Err(_) => clean = false,
                    }
                }
                remote_result = reader.read_frame() => {
                    match remote_result {
                        Ok(payload) if payload.is_empty() => {
                            peer_closed = true;
                        }
                        Ok(payload) => {
                            if local_write.write_all(&payload).await.is_err() {
                                clean = false;
                            }
                        }
                        Err(_) => clean = false,
                    }
                }
            }
        }

        if clean && peer_closed && !upload_closed {
            if writer.write_zero().await.is_err() {
                clean = false;
            }
            upload_closed = true;
        }

        if clean && upload_closed && peer_closed {
            pool.lock()
                .await
                .put(SnellV4PooledConnection { reader, writer });
        }
        let _ = local_write.shutdown().await;
    });

    app_side
}

fn spawn_snell_v4_stream(
    psk: Vec<u8>,
    upload_key: Vec<u8>,
    upload_nonce: [u8; SS_NONCE_LEN],
    stream: BoxedStream,
    plugin: Option<ShadowsocksPluginConfig>,
) -> DuplexStream {
    let (app_side, relay_side) = tokio::io::duplex(64 * 1024);
    let (mut local_read, mut local_write) = tokio::io::split(relay_side);
    let (mut remote_read, mut remote_write) = tokio::io::split(stream);

    let upload_tls_obfs = plugin_is_tls_obfs(plugin.as_ref());
    tokio::spawn(async move {
        let mut nonce = upload_nonce;
        let mut buf = vec![0u8; SS_CHUNK_SIZE];
        loop {
            match local_read.read(&mut buf).await {
                Ok(0) => {
                    let _ = remote_write.shutdown().await;
                    break;
                }
                Ok(length) => {
                    let Ok(frame) =
                        encode_snell_v4_frame(&upload_key, &mut nonce, &buf[..length], 0)
                    else {
                        break;
                    };
                    let write_result = if upload_tls_obfs {
                        remote_write
                            .write_all(&wrap_simple_obfs_tls_app_data(&frame))
                            .await
                    } else {
                        remote_write.write_all(&frame).await
                    };
                    if write_result.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    tokio::spawn(async move {
        if plugin_is_http_obfs(plugin.as_ref()) {
            match read_http_obfs_response(&mut remote_read).await {
                Ok(leftover) => {
                    let cursor = Cursor::new(leftover);
                    let mut chained = cursor.chain(remote_read);
                    relay_snell_v4_download(&psk, &mut chained, &mut local_write).await;
                }
                Err(_) => {
                    let _ = local_write.shutdown().await;
                }
            }
        } else if plugin_is_tls_obfs(plugin.as_ref()) {
            relay_snell_v4_tls_download(&psk, remote_read, local_write).await;
        } else {
            relay_snell_v4_download(&psk, &mut remote_read, &mut local_write).await;
        }
    });

    app_side
}

async fn relay_snell_v4_download<R, W>(psk: &[u8], reader: &mut R, writer: &mut W)
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut response_salt = [0u8; SNELL_V4_SALT_LEN];
    if reader.read_exact(&mut response_salt).await.is_err() {
        let _ = writer.shutdown().await;
        return;
    }
    let Ok(key) = derive_snell_subkey(SsCipher::Aes128Gcm, psk, &response_salt) else {
        let _ = writer.shutdown().await;
        return;
    };
    let mut nonce = [0u8; SS_NONCE_LEN];
    let response = match read_snell_v4_frame(reader, &key, &mut nonce).await {
        Ok(response) => response,
        Err(_) => {
            let _ = writer.shutdown().await;
            return;
        }
    };
    if validate_snell_response(&response, "TCP connect").is_err() {
        let _ = writer.shutdown().await;
        return;
    }
    if response.len() > 1 && writer.write_all(&response[1..]).await.is_err() {
        return;
    }
    loop {
        match read_snell_v4_frame(reader, &key, &mut nonce).await {
            Ok(payload) if payload.is_empty() => {
                let _ = writer.shutdown().await;
                break;
            }
            Ok(payload) => {
                if writer.write_all(&payload).await.is_err() {
                    break;
                }
            }
            Err(_) => {
                let _ = writer.shutdown().await;
                break;
            }
        }
    }
}

async fn relay_snell_v4_tls_download<R, W>(psk: &[u8], mut reader: R, mut writer: W)
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut decoder = SimpleObfsTlsDecoder::new();
    let response_salt = match decoder
        .read_exact_or_eof(&mut reader, SNELL_V4_SALT_LEN)
        .await
    {
        Ok(Some(value)) => value,
        _ => {
            let _ = writer.shutdown().await;
            return;
        }
    };
    let Ok(key) = derive_snell_subkey(SsCipher::Aes128Gcm, psk, &response_salt) else {
        let _ = writer.shutdown().await;
        return;
    };
    let mut nonce = [0u8; SS_NONCE_LEN];
    let response = match read_snell_v4_frame_from_tls_obfs(
        &mut decoder,
        &mut reader,
        &key,
        &mut nonce,
    )
    .await
    {
        Ok(response) => response,
        Err(_) => {
            let _ = writer.shutdown().await;
            return;
        }
    };
    if validate_snell_response(&response, "TCP connect").is_err() {
        let _ = writer.shutdown().await;
        return;
    }
    if response.len() > 1 && writer.write_all(&response[1..]).await.is_err() {
        return;
    }
    loop {
        match read_snell_v4_frame_from_tls_obfs(&mut decoder, &mut reader, &key, &mut nonce).await {
            Ok(payload) if payload.is_empty() => {
                let _ = writer.shutdown().await;
                break;
            }
            Ok(payload) => {
                if writer.write_all(&payload).await.is_err() {
                    break;
                }
            }
            Err(_) => {
                let _ = writer.shutdown().await;
                break;
            }
        }
    }
}

fn spawn_snell_stream(
    cipher: SsCipher,
    psk: Vec<u8>,
    upload_key: Vec<u8>,
    upload_nonce: Vec<u8>,
    stream: BoxedStream,
    plugin: Option<ShadowsocksPluginConfig>,
) -> DuplexStream {
    let (app_side, relay_side) = tokio::io::duplex(64 * 1024);
    let (mut local_read, mut local_write) = tokio::io::split(relay_side);
    let (mut remote_read, mut remote_write) = tokio::io::split(stream);

    let upload_tls_obfs = plugin_is_tls_obfs(plugin.as_ref());
    tokio::spawn(async move {
        let mut nonce = upload_nonce;
        let mut buf = vec![0u8; SS_CHUNK_SIZE];
        loop {
            match local_read.read(&mut buf).await {
                Ok(0) => {
                    let _ = remote_write.shutdown().await;
                    break;
                }
                Ok(n) => {
                    if write_ss_plugin_chunk(
                        cipher,
                        &upload_key,
                        &mut nonce,
                        &mut remote_write,
                        &buf[..n],
                        upload_tls_obfs,
                    )
                    .await
                    .is_err()
                    {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    tokio::spawn(async move {
        if plugin_is_http_obfs(plugin.as_ref()) {
            match read_http_obfs_response(&mut remote_read).await {
                Ok(leftover) => {
                    let cursor = Cursor::new(leftover);
                    let mut chained = cursor.chain(remote_read);
                    relay_snell_download_with_response_salt(
                        cipher,
                        &psk,
                        &mut chained,
                        &mut local_write,
                    )
                    .await;
                }
                Err(_) => {
                    let _ = local_write.shutdown().await;
                }
            }
        } else if plugin_is_tls_obfs(plugin.as_ref()) {
            relay_snell_tls_download_with_response_salt(cipher, &psk, remote_read, local_write)
                .await;
        } else {
            relay_snell_download_with_response_salt(
                cipher,
                &psk,
                &mut remote_read,
                &mut local_write,
            )
            .await;
        }
    });

    app_side
}

async fn relay_snell_download_with_response_salt<R, W>(
    cipher: SsCipher,
    psk: &[u8],
    reader: &mut R,
    writer: &mut W,
) where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut response_salt = vec![0u8; cipher.salt_len()];
    if reader.read_exact(&mut response_salt).await.is_err() {
        let _ = writer.shutdown().await;
        return;
    }
    let Ok(response_key) = derive_snell_subkey(cipher, psk, &response_salt) else {
        let _ = writer.shutdown().await;
        return;
    };
    let mut nonce = vec![0u8; cipher.nonce_len()];
    let response = match read_ss_chunk(cipher, &response_key, &mut nonce, reader).await {
        Ok(Some(response)) => response,
        _ => {
            let _ = writer.shutdown().await;
            return;
        }
    };
    if validate_snell_response(&response, "TCP connect").is_err() {
        let _ = writer.shutdown().await;
        return;
    }
    if response.len() > 1 && writer.write_all(&response[1..]).await.is_err() {
        return;
    }
    relay_shadowsocks_download(cipher, response_key, nonce, reader, writer).await;
}

async fn relay_snell_tls_download_with_response_salt<R, W>(
    cipher: SsCipher,
    psk: &[u8],
    mut reader: R,
    mut writer: W,
) where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut decoder = SimpleObfsTlsDecoder::new();
    let response_salt = match decoder
        .read_exact_or_eof(&mut reader, cipher.salt_len())
        .await
    {
        Ok(Some(value)) => value,
        _ => {
            let _ = writer.shutdown().await;
            return;
        }
    };
    let Ok(response_key) = derive_snell_subkey(cipher, psk, &response_salt) else {
        let _ = writer.shutdown().await;
        return;
    };
    let mut nonce = vec![0u8; cipher.nonce_len()];
    let response = match read_ss_chunk_from_tls_obfs(
        cipher,
        &response_key,
        &mut nonce,
        &mut decoder,
        &mut reader,
    )
    .await
    {
        Ok(Some(response)) => response,
        _ => {
            let _ = writer.shutdown().await;
            return;
        }
    };
    if validate_snell_response(&response, "TCP connect").is_err() {
        let _ = writer.shutdown().await;
        return;
    }
    if response.len() > 1 && writer.write_all(&response[1..]).await.is_err() {
        return;
    }
    loop {
        match read_ss_chunk_from_tls_obfs(
            cipher,
            &response_key,
            &mut nonce,
            &mut decoder,
            &mut reader,
        )
        .await
        {
            Ok(Some(plaintext)) => {
                if writer.write_all(&plaintext).await.is_err() {
                    break;
                }
            }
            Ok(None) => {
                let _ = writer.shutdown().await;
                break;
            }
            Err(_) => {
                let _ = writer.shutdown().await;
                break;
            }
        }
    }
}

async fn relay_shadowsocks_download_with_response_salt<R, W>(
    cipher: SsCipher,
    master_key: &[u8],
    request_salt: &[u8],
    reader: &mut R,
    writer: &mut W,
) where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut response_salt = vec![0u8; cipher.salt_len()];
    if reader.read_exact(&mut response_salt).await.is_err() {
        let _ = writer.shutdown().await;
        return;
    }
    let Ok(response_key) = cipher.derive_subkey(master_key, &response_salt) else {
        let _ = writer.shutdown().await;
        return;
    };
    let mut nonce = vec![0u8; cipher.nonce_len()];
    if cipher.is_blake3() {
        match read_ss2022_response_header(cipher, &response_key, &mut nonce, request_salt, reader)
            .await
        {
            Ok(initial_payload) => {
                if !initial_payload.is_empty() && writer.write_all(&initial_payload).await.is_err()
                {
                    return;
                }
            }
            Err(_) => {
                let _ = writer.shutdown().await;
                return;
            }
        }
    }
    relay_shadowsocks_download(cipher, response_key, nonce, reader, writer).await;
}

async fn relay_shadowsocks_tls_download_with_response_salt<R, W>(
    cipher: SsCipher,
    master_key: &[u8],
    request_salt: &[u8],
    mut reader: R,
    mut writer: W,
) where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut decoder = SimpleObfsTlsDecoder::new();
    let response_salt = match decoder
        .read_exact_or_eof(&mut reader, cipher.salt_len())
        .await
    {
        Ok(Some(value)) => value,
        _ => {
            let _ = writer.shutdown().await;
            return;
        }
    };
    let Ok(response_key) = cipher.derive_subkey(master_key, &response_salt) else {
        let _ = writer.shutdown().await;
        return;
    };
    let mut nonce = vec![0u8; cipher.nonce_len()];
    if cipher.is_blake3() {
        match read_ss2022_response_header_from_tls_obfs(
            cipher,
            &response_key,
            &mut nonce,
            request_salt,
            &mut decoder,
            &mut reader,
        )
        .await
        {
            Ok(initial_payload) => {
                if !initial_payload.is_empty() && writer.write_all(&initial_payload).await.is_err()
                {
                    return;
                }
            }
            Err(_) => {
                let _ = writer.shutdown().await;
                return;
            }
        }
    }
    loop {
        match read_ss_chunk_from_tls_obfs(
            cipher,
            &response_key,
            &mut nonce,
            &mut decoder,
            &mut reader,
        )
        .await
        {
            Ok(Some(plaintext)) => {
                if writer.write_all(&plaintext).await.is_err() {
                    break;
                }
            }
            Ok(None) => {
                let _ = writer.shutdown().await;
                break;
            }
            Err(_) => {
                let _ = writer.shutdown().await;
                break;
            }
        }
    }
}

async fn read_ss2022_response_header_from_tls_obfs<R>(
    cipher: SsCipher,
    subkey: &[u8],
    nonce: &mut [u8],
    request_salt: &[u8],
    decoder: &mut SimpleObfsTlsDecoder,
    reader: &mut R,
) -> anyhow::Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let fixed_header_length = 1 + 8 + request_salt.len() + 2;
    let encrypted_fixed_header = decoder
        .read_exact_or_eof(reader, fixed_header_length + SS_TAG_LEN)
        .await?
        .ok_or_else(|| anyhow!("missing shadowsocks 2022 response fixed header"))?;
    let fixed_header = cipher.decrypt(subkey, nonce, &encrypted_fixed_header)?;
    increment_nonce(nonce);
    if fixed_header.len() != fixed_header_length
        || fixed_header.first().copied() != Some(SS2022_SERVER_STREAM_TYPE)
    {
        return Err(anyhow!("invalid shadowsocks 2022 response fixed header"));
    }
    let timestamp = u64::from_be_bytes(fixed_header[1..9].try_into()?);
    validate_ss2022_timestamp(timestamp)?;
    let salt_end = 9 + request_salt.len();
    if &fixed_header[9..salt_end] != request_salt {
        return Err(anyhow!(
            "shadowsocks 2022 response does not match request salt"
        ));
    }
    let payload_length =
        u16::from_be_bytes(fixed_header[salt_end..salt_end + 2].try_into()?) as usize;
    let encrypted_payload = decoder
        .read_exact_or_eof(reader, payload_length + SS_TAG_LEN)
        .await?
        .ok_or_else(|| anyhow!("missing shadowsocks 2022 response payload"))?;
    let payload = cipher.decrypt(subkey, nonce, &encrypted_payload)?;
    increment_nonce(nonce);
    Ok(payload)
}

async fn relay_shadowsocks_download<R, W>(
    cipher: SsCipher,
    subkey: Vec<u8>,
    mut nonce: Vec<u8>,
    mut reader: R,
    mut writer: W,
) where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    loop {
        match read_ss_chunk(cipher, &subkey, &mut nonce, &mut reader).await {
            Ok(Some(plaintext)) => {
                if writer.write_all(&plaintext).await.is_err() {
                    break;
                }
            }
            Ok(None) => {
                let _ = writer.shutdown().await;
                break;
            }
            Err(_) => {
                let _ = writer.shutdown().await;
                break;
            }
        }
    }
}

fn encode_ss_chunk(
    cipher: SsCipher,
    subkey: &[u8],
    nonce: &mut [u8],
    plaintext: &[u8],
) -> anyhow::Result<Vec<u8>> {
    if plaintext.len() > cipher.max_chunk_size() {
        return Err(anyhow!("shadowsocks chunk is too large"));
    }
    let length = (plaintext.len() as u16).to_be_bytes();
    let encrypted_length = cipher.encrypt(subkey, nonce, &length)?;
    increment_nonce(nonce);
    let encrypted_payload = cipher.encrypt(subkey, nonce, plaintext)?;
    increment_nonce(nonce);
    let mut output = Vec::with_capacity(encrypted_length.len() + encrypted_payload.len());
    output.extend_from_slice(&encrypted_length);
    output.extend_from_slice(&encrypted_payload);
    Ok(output)
}

#[cfg(test)]
async fn write_ss_chunk<W>(
    cipher: SsCipher,
    subkey: &[u8],
    nonce: &mut [u8],
    writer: &mut W,
    plaintext: &[u8],
) -> anyhow::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let chunk = encode_ss_chunk(cipher, subkey, nonce, plaintext)?;
    writer.write_all(&chunk).await?;
    Ok(())
}

async fn write_ss_plugin_chunk<W>(
    cipher: SsCipher,
    subkey: &[u8],
    nonce: &mut [u8],
    writer: &mut W,
    plaintext: &[u8],
    tls_obfs: bool,
) -> anyhow::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let chunk = encode_ss_chunk(cipher, subkey, nonce, plaintext)?;
    if tls_obfs {
        writer
            .write_all(&wrap_simple_obfs_tls_app_data(&chunk))
            .await?;
    } else {
        writer.write_all(&chunk).await?;
    }
    Ok(())
}

async fn read_ss_chunk<R>(
    cipher: SsCipher,
    subkey: &[u8],
    nonce: &mut [u8],
    reader: &mut R,
) -> anyhow::Result<Option<Vec<u8>>>
where
    R: AsyncRead + Unpin,
{
    let mut encrypted_length = [0u8; 2 + SS_TAG_LEN];
    if !read_exact_or_eof(reader, &mut encrypted_length).await? {
        return Ok(None);
    }
    let length = cipher.decrypt(subkey, nonce, &encrypted_length)?;
    increment_nonce(nonce);
    if length.len() != 2 {
        return Err(anyhow!("invalid shadowsocks length block"));
    }
    let payload_len = u16::from_be_bytes([length[0], length[1]]) as usize;
    if payload_len > cipher.max_chunk_size() {
        return Err(anyhow!("shadowsocks chunk length is too large"));
    }
    let mut encrypted_payload = vec![0u8; payload_len + SS_TAG_LEN];
    read_exact_or_eof(reader, &mut encrypted_payload)
        .await?
        .then_some(())
        .ok_or_else(|| anyhow!("unexpected eof while reading shadowsocks payload"))?;
    let payload = cipher.decrypt(subkey, nonce, &encrypted_payload)?;
    increment_nonce(nonce);
    Ok(Some(payload))
}

async fn read_ss_chunk_from_tls_obfs<R>(
    cipher: SsCipher,
    subkey: &[u8],
    nonce: &mut [u8],
    decoder: &mut SimpleObfsTlsDecoder,
    reader: &mut R,
) -> anyhow::Result<Option<Vec<u8>>>
where
    R: AsyncRead + Unpin,
{
    let encrypted_length = match decoder.read_exact_or_eof(reader, 2 + SS_TAG_LEN).await? {
        Some(value) => value,
        None => return Ok(None),
    };
    let length = cipher.decrypt(subkey, nonce, &encrypted_length)?;
    increment_nonce(nonce);
    if length.len() != 2 {
        return Err(anyhow!("invalid shadowsocks length block"));
    }
    let payload_len = u16::from_be_bytes([length[0], length[1]]) as usize;
    if payload_len > cipher.max_chunk_size() {
        return Err(anyhow!("shadowsocks chunk length is too large"));
    }
    let encrypted_payload = decoder
        .read_exact_or_eof(reader, payload_len + SS_TAG_LEN)
        .await?
        .ok_or_else(|| anyhow!("unexpected eof while reading shadowsocks payload"))?;
    let payload = cipher.decrypt(subkey, nonce, &encrypted_payload)?;
    increment_nonce(nonce);
    Ok(Some(payload))
}

async fn read_exact_or_eof<R>(reader: &mut R, buf: &mut [u8]) -> anyhow::Result<bool>
where
    R: AsyncRead + Unpin,
{
    let mut offset = 0;
    while offset < buf.len() {
        let n = reader.read(&mut buf[offset..]).await?;
        if n == 0 {
            if offset == 0 {
                return Ok(false);
            }
            return Err(Error::new(ErrorKind::UnexpectedEof, "partial read").into());
        }
        offset += n;
    }
    Ok(true)
}

fn apply_shadowsocks_plugin_request(
    plugin: &ShadowsocksPluginConfig,
    server: &str,
    port: u16,
    payload: Vec<u8>,
) -> anyhow::Result<Vec<u8>> {
    if plugin_is_tls_obfs(Some(plugin)) {
        let host = plugin.host.as_deref().unwrap_or(server);
        return build_simple_obfs_tls_client_hello(host, &payload);
    }
    if plugin_is_v2ray_ws(Some(plugin)) {
        let host = plugin.host.as_deref().unwrap_or(server);
        let ws_path = plugin.path.as_deref().unwrap_or("/");
        let host_header = if host.contains(':') || port == 80 || port == 443 {
            host.to_string()
        } else {
            format!("{host}:{port}")
        };
        let ws_key = "dGhlIHNhbXBsZSBub25jZQ==";
        let header = format!(
            "GET {ws_path} HTTP/1.1\r\n\
             Host: {host_header}\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: {ws_key}\r\n\
             Sec-WebSocket-Version: 13\r\n\
             \r\n"
        );
        let mut output = header.into_bytes();
        output.extend_from_slice(&payload);
        return Ok(output);
    }
    if !plugin_is_http_obfs(Some(plugin)) {
        return Err(anyhow!(
            "unsupported shadowsocks plugin mode {}",
            plugin.mode
        ));
    }
    let host = plugin.host.as_deref().unwrap_or(server);
    let host_header = if host.contains(':') || port == 80 || port == 443 {
        host.to_string()
    } else {
        format!("{host}:{port}")
    };
    let websocket_key = "U3VwZXJjb3JlU2ltcGxlT2Jmcw==";
    let header = format!(
        "GET / HTTP/1.1\r\n\
         Host: {host_header}\r\n\
         User-Agent: curl/8.5.0\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: {websocket_key}\r\n\
         Content-Length: {}\r\n\
         \r\n",
        payload.len()
    );
    let mut output = header.into_bytes();
    output.extend_from_slice(&payload);
    Ok(output)
}

const SIMPLE_OBFS_TLS_CIPHER_SUITES: [u8; 56] = [
    0xc0, 0x2c, 0xc0, 0x30, 0x00, 0x9f, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0xaa, 0xc0, 0x2b, 0xc0, 0x2f,
    0x00, 0x9e, 0xc0, 0x24, 0xc0, 0x28, 0x00, 0x6b, 0xc0, 0x23, 0xc0, 0x27, 0x00, 0x67, 0xc0, 0x0a,
    0xc0, 0x14, 0x00, 0x39, 0xc0, 0x09, 0xc0, 0x13, 0x00, 0x33, 0x00, 0x9d, 0x00, 0x9c, 0x00, 0x3d,
    0x00, 0x3c, 0x00, 0x35, 0x00, 0x2f, 0x00, 0xff,
];

const SIMPLE_OBFS_TLS_OTHER_EXTENSIONS: [u8; 66] = [
    0x00, 0x0b, 0x00, 0x04, 0x03, 0x01, 0x00, 0x02, 0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x1d,
    0x00, 0x17, 0x00, 0x19, 0x00, 0x18, 0x00, 0x0d, 0x00, 0x20, 0x00, 0x1e, 0x06, 0x01, 0x06, 0x02,
    0x06, 0x03, 0x05, 0x01, 0x05, 0x02, 0x05, 0x03, 0x04, 0x01, 0x04, 0x02, 0x04, 0x03, 0x03, 0x01,
    0x03, 0x02, 0x03, 0x03, 0x02, 0x01, 0x02, 0x02, 0x02, 0x03, 0x00, 0x16, 0x00, 0x00, 0x00, 0x17,
    0x00, 0x00,
];

const SIMPLE_OBFS_TLS_FIXED_CLIENT_HELLO_LEN: usize = 138;
const SIMPLE_OBFS_TLS_SESSION_TICKET_HEADER_LEN: usize = 4;
const SIMPLE_OBFS_TLS_SNI_HEADER_LEN: usize = 9;
const SIMPLE_OBFS_TLS_MAX_APP_DATA_LEN: usize = 16 * 1024;

fn build_simple_obfs_tls_client_hello(host: &str, payload: &[u8]) -> anyhow::Result<Vec<u8>> {
    let host = host.trim();
    if host.is_empty() {
        return Err(anyhow!("simple-obfs tls host is empty"));
    }
    let host_bytes = host.as_bytes();
    if host_bytes.len() > u16::MAX as usize {
        return Err(anyhow!("simple-obfs tls host is too long"));
    }
    if payload.len() > u16::MAX as usize {
        return Err(anyhow!("simple-obfs tls first packet is too large"));
    }

    let extensions_len = SIMPLE_OBFS_TLS_SESSION_TICKET_HEADER_LEN
        + payload.len()
        + SIMPLE_OBFS_TLS_SNI_HEADER_LEN
        + host_bytes.len()
        + SIMPLE_OBFS_TLS_OTHER_EXTENSIONS.len();
    if extensions_len > u16::MAX as usize {
        return Err(anyhow!("simple-obfs tls extensions are too large"));
    }
    let tls_len = SIMPLE_OBFS_TLS_FIXED_CLIENT_HELLO_LEN + extensions_len;
    let record_len = tls_len
        .checked_sub(5)
        .ok_or_else(|| anyhow!("invalid simple-obfs tls record length"))?;
    if record_len > u16::MAX as usize {
        return Err(anyhow!("simple-obfs tls record is too large"));
    }
    let handshake_len = tls_len
        .checked_sub(9)
        .ok_or_else(|| anyhow!("invalid simple-obfs tls handshake length"))?;
    if handshake_len > 0x00ff_ffff {
        return Err(anyhow!("simple-obfs tls handshake is too large"));
    }

    let mut output = Vec::with_capacity(tls_len);
    output.extend_from_slice(&[0x16, 0x03, 0x01]);
    output.extend_from_slice(&(record_len as u16).to_be_bytes());
    output.push(0x01);
    output.extend_from_slice(&(handshake_len as u32).to_be_bytes()[1..]);
    output.extend_from_slice(&[0x03, 0x03]);

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32;
    output.extend_from_slice(&now.to_be_bytes());
    let mut random = [0u8; 28];
    getrandom::fill(&mut random)
        .map_err(|error| anyhow!("failed to generate simple-obfs tls random: {error}"))?;
    output.extend_from_slice(&random);
    output.push(32);
    let mut session_id = [0u8; 32];
    getrandom::fill(&mut session_id)
        .map_err(|error| anyhow!("failed to generate simple-obfs tls session id: {error}"))?;
    output.extend_from_slice(&session_id);
    output.extend_from_slice(&(SIMPLE_OBFS_TLS_CIPHER_SUITES.len() as u16).to_be_bytes());
    output.extend_from_slice(&SIMPLE_OBFS_TLS_CIPHER_SUITES);
    output.extend_from_slice(&[0x01, 0x00]);
    output.extend_from_slice(&(extensions_len as u16).to_be_bytes());

    output.extend_from_slice(&[0x00, 0x23]);
    output.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    output.extend_from_slice(payload);

    let sni_ext_len = host_bytes.len() + 5;
    let sni_list_len = host_bytes.len() + 3;
    output.extend_from_slice(&[0x00, 0x00]);
    output.extend_from_slice(&(sni_ext_len as u16).to_be_bytes());
    output.extend_from_slice(&(sni_list_len as u16).to_be_bytes());
    output.push(0x00);
    output.extend_from_slice(&(host_bytes.len() as u16).to_be_bytes());
    output.extend_from_slice(host_bytes);

    output.extend_from_slice(&SIMPLE_OBFS_TLS_OTHER_EXTENSIONS);
    debug_assert_eq!(output.len(), tls_len);
    Ok(output)
}

fn wrap_simple_obfs_tls_app_data(payload: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(
        payload.len() + (payload.len() / SIMPLE_OBFS_TLS_MAX_APP_DATA_LEN + 1) * 5,
    );
    if payload.is_empty() {
        return output;
    }
    for chunk in payload.chunks(SIMPLE_OBFS_TLS_MAX_APP_DATA_LEN) {
        output.extend_from_slice(&[0x17, 0x03, 0x03]);
        output.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
        output.extend_from_slice(chunk);
    }
    output
}

fn plugin_is_http_obfs(plugin: Option<&ShadowsocksPluginConfig>) -> bool {
    plugin.map_or(false, |p| {
        let mode = p.mode.to_ascii_lowercase();
        mode == "http_simple" || mode == "http_post"
    })
}

fn plugin_is_v2ray_ws(plugin: Option<&ShadowsocksPluginConfig>) -> bool {
    plugin.map_or(false, |p| {
        let mode = p.mode.to_ascii_lowercase();
        mode == "v2ray-plugin" || mode == "websocket"
    })
}

fn plugin_is_tls_obfs(plugin: Option<&ShadowsocksPluginConfig>) -> bool {
    plugin
        .map(|plugin| {
            matches!(
                plugin.mode.to_ascii_lowercase().as_str(),
                "tls" | "obfs-tls" | "simple-obfs-tls"
            )
        })
        .unwrap_or(false)
}

async fn read_http_obfs_response<R>(reader: &mut R) -> anyhow::Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut data = Vec::with_capacity(1024);
    let mut buf = [0u8; 512];
    while data.len() < 64 * 1024 {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            return Err(anyhow!("unexpected eof while reading obfs http response"));
        }
        data.extend_from_slice(&buf[..n]);
        if let Some(index) = find_header_end(&data) {
            return Ok(data.split_off(index));
        }
    }
    Err(anyhow!("obfs http response header is too large"))
}

fn find_header_end(data: &[u8]) -> Option<usize> {
    data.windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SimpleObfsTlsReadStage {
    ServerHello,
    AppData,
}

struct SimpleObfsTlsDecoder {
    stage: SimpleObfsTlsReadStage,
    plain: BytesMut,
}

impl SimpleObfsTlsDecoder {
    fn new() -> Self {
        Self {
            stage: SimpleObfsTlsReadStage::ServerHello,
            plain: BytesMut::new(),
        }
    }

    async fn read_exact_or_eof<R>(
        &mut self,
        reader: &mut R,
        len: usize,
    ) -> anyhow::Result<Option<Vec<u8>>>
    where
        R: AsyncRead + Unpin,
    {
        while self.plain.len() < len {
            if !self.read_next_plain_record(reader).await? {
                if self.plain.is_empty() {
                    return Ok(None);
                }
                return Err(anyhow!(
                    "unexpected eof while reading simple-obfs tls payload"
                ));
            }
        }
        Ok(Some(self.plain.split_to(len).to_vec()))
    }

    async fn read_next_plain_record<R>(&mut self, reader: &mut R) -> anyhow::Result<bool>
    where
        R: AsyncRead + Unpin,
    {
        match self.stage {
            SimpleObfsTlsReadStage::ServerHello => {
                let Some((content_type, _version, _payload)) =
                    read_simple_obfs_tls_record(reader).await?
                else {
                    return Ok(false);
                };
                if content_type != 0x16 {
                    return Err(anyhow!("invalid simple-obfs tls server hello record"));
                }

                let Some((content_type, _version, payload)) =
                    read_simple_obfs_tls_record(reader).await?
                else {
                    return Err(anyhow!("unexpected eof after simple-obfs tls server hello"));
                };
                if content_type == 0x14 {
                    if payload != [0x01] {
                        return Err(anyhow!("invalid simple-obfs tls change cipher spec"));
                    }
                    let Some((handshake_type, _version, payload)) =
                        read_simple_obfs_tls_record(reader).await?
                    else {
                        return Err(anyhow!(
                            "unexpected eof after simple-obfs tls change cipher spec"
                        ));
                    };
                    if handshake_type != 0x16 {
                        return Err(anyhow!("invalid simple-obfs tls encrypted handshake"));
                    }
                    self.plain.extend_from_slice(&payload);
                } else if content_type == 0x16 {
                    self.plain.extend_from_slice(&payload);
                } else {
                    return Err(anyhow!("invalid simple-obfs tls response record"));
                }
                self.stage = SimpleObfsTlsReadStage::AppData;
                Ok(true)
            }
            SimpleObfsTlsReadStage::AppData => {
                let Some((content_type, _version, payload)) =
                    read_simple_obfs_tls_record(reader).await?
                else {
                    return Ok(false);
                };
                if content_type != 0x17 {
                    return Err(anyhow!("invalid simple-obfs tls app data record"));
                }
                self.plain.extend_from_slice(&payload);
                Ok(true)
            }
        }
    }
}

async fn read_simple_obfs_tls_record<R>(
    reader: &mut R,
) -> anyhow::Result<Option<(u8, [u8; 2], Vec<u8>)>>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; 5];
    if !read_exact_or_eof(reader, &mut header).await? {
        return Ok(None);
    }
    if header[1] != 0x03 {
        return Err(anyhow!("invalid simple-obfs tls record version"));
    }
    let len = u16::from_be_bytes([header[3], header[4]]) as usize;
    if header[0] == 0x17 && len > SIMPLE_OBFS_TLS_MAX_APP_DATA_LEN {
        return Err(anyhow!("simple-obfs tls app data frame is too large"));
    }
    let mut payload = vec![0u8; len];
    read_exact_or_eof(reader, &mut payload)
        .await?
        .then_some(())
        .ok_or_else(|| anyhow!("unexpected eof while reading simple-obfs tls record"))?;
    Ok(Some((header[0], [header[1], header[2]], payload)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::ServerConfig;
    use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    struct ContextRecordingOutbound {
        trace_id: Arc<StdMutex<Option<String>>>,
    }

    struct PendingOutbound;

    #[async_trait]
    impl Outbound for PendingOutbound {
        fn name(&self) -> &str {
            "pending"
        }

        fn kind(&self) -> &'static str {
            "test"
        }

        fn capability(&self) -> OutboundCapability {
            OutboundCapability::tcp_only("test outbound")
        }

        async fn connect(
            &self,
            _destination: &Destination,
            _timeout_ms: u64,
        ) -> anyhow::Result<BoxedStream> {
            std::future::pending().await
        }
    }

    #[async_trait]
    impl Outbound for ContextRecordingOutbound {
        fn name(&self) -> &str {
            "context-recorder"
        }

        fn kind(&self) -> &'static str {
            "test"
        }

        fn capability(&self) -> OutboundCapability {
            OutboundCapability::tcp_only("test outbound")
        }

        async fn connect(
            &self,
            _destination: &Destination,
            _timeout_ms: u64,
        ) -> anyhow::Result<BoxedStream> {
            let (stream, peer) = tokio::io::duplex(64);
            drop(peer);
            Ok(Box::new(stream))
        }

        async fn connect_context(&self, context: &DialContext) -> anyhow::Result<BoxedStream> {
            *self.trace_id.lock().expect("trace lock") = Some(context.trace_id.clone());
            self.connect(&context.destination, context.timeout_ms())
                .await
        }
    }

    #[tokio::test]
    async fn group_propagates_dial_context_to_selected_member() {
        let recorded = Arc::new(StdMutex::new(None));
        let member: Arc<dyn Outbound> = Arc::new(ContextRecordingOutbound {
            trace_id: Arc::clone(&recorded),
        });
        let group = GroupOutbound::new(
            "group".to_string(),
            "select".to_string(),
            vec![member],
            None,
        );
        let context = DialContext::new(Destination::new("example.com", 443), 500);
        let expected = context.trace_id.clone();
        group
            .connect_context(&context)
            .await
            .expect("group connect");
        assert_eq!(
            recorded.lock().expect("trace lock").as_deref(),
            Some(expected.as_str())
        );
    }

    #[tokio::test]
    async fn dial_context_cancellation_stops_pending_outbound() {
        let outbound = PendingOutbound;
        let context = DialContext::new(Destination::new("example.com", 443), 30_000);
        context.cancel();
        let error = match outbound.connect_context(&context).await {
            Ok(_) => panic!("cancelled dial should fail"),
            Err(error) => error,
        };
        assert_eq!(
            error
                .downcast_ref::<OutboundError>()
                .map(|error| error.kind),
            Some(OutboundErrorKind::Cancelled)
        );
    }

    #[tokio::test]
    async fn shadowsocks_outbound_encrypts_tcp_stream() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let password = "correct horse battery staple".to_string();
        let destination = Destination::new("target.example", 443);
        let mut expected_destination = Vec::new();
        encode_socks5_destination(&destination, &mut expected_destination).unwrap();
        let server_password = password.clone();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let cipher = SsCipher::Aes128Gcm;
            let master_key = evp_bytes_to_key(server_password.as_bytes(), cipher.key_len());
            let mut salt = vec![0u8; cipher.salt_len()];
            stream.read_exact(&mut salt).await.unwrap();
            let subkey = cipher.derive_subkey(&master_key, &salt).unwrap();

            let mut inbound_nonce = [0u8; SS_NONCE_LEN];
            let destination_payload =
                read_ss_chunk(cipher, &subkey, &mut inbound_nonce, &mut stream)
                    .await
                    .unwrap()
                    .unwrap();
            assert_eq!(destination_payload, expected_destination);

            let payload = read_ss_chunk(cipher, &subkey, &mut inbound_nonce, &mut stream)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(payload, b"ping");

            let response_salt = vec![0x42; cipher.salt_len()];
            let response_key = cipher.derive_subkey(&master_key, &response_salt).unwrap();
            stream.write_all(&response_salt).await.unwrap();
            let mut outbound_nonce = [0u8; SS_NONCE_LEN];
            write_ss_chunk(
                cipher,
                &response_key,
                &mut outbound_nonce,
                &mut stream,
                b"pong",
            )
            .await
            .unwrap();
        });

        let outbound = ShadowsocksOutbound::new(
            "ss-test".to_string(),
            "127.0.0.1".to_string(),
            listen_addr.port(),
            "aes-128-gcm".to_string(),
            password,
            None,
        );
        let mut stream = outbound.connect(&destination, 1000).await.unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut response = [0u8; 4];
        stream.read_exact(&mut response).await.unwrap();

        assert_eq!(&response, b"pong");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn shadowsocks_simple_obfs_http_wraps_first_packet() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let password = "secret".to_string();
        let destination = Destination::new("target.example", 443);
        let mut expected_destination = Vec::new();
        encode_socks5_destination(&destination, &mut expected_destination).unwrap();
        let server_password = password.clone();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut first_packet = Vec::new();
            let mut buf = [0u8; 512];
            loop {
                let n = stream.read(&mut buf).await.unwrap();
                assert!(n > 0);
                first_packet.extend_from_slice(&buf[..n]);
                if let Some(index) = find_header_end(&first_packet) {
                    let header_bytes = first_packet[..index].to_vec();
                    let mut body = first_packet[index..].to_vec();
                    let header = String::from_utf8(header_bytes).unwrap();
                    assert!(header.starts_with("GET / HTTP/1.1"));
                    assert!(header.contains("Host: edge.example.com"));
                    assert!(header.contains("Upgrade: websocket"));
                    let content_length = header
                        .lines()
                        .find_map(|line| {
                            line.split_once(':').and_then(|(name, value)| {
                                name.eq_ignore_ascii_case("content-length")
                                    .then(|| value.trim().parse::<usize>().ok())
                                    .flatten()
                            })
                        })
                        .unwrap();
                    while body.len() < content_length {
                        let n = stream.read(&mut buf).await.unwrap();
                        assert!(n > 0);
                        body.extend_from_slice(&buf[..n]);
                    }

                    let cipher = SsCipher::Aes128Gcm;
                    let master_key = evp_bytes_to_key(server_password.as_bytes(), cipher.key_len());
                    let salt = body[..cipher.salt_len()].to_vec();
                    let subkey = cipher.derive_subkey(&master_key, &salt).unwrap();
                    let mut inbound_nonce = [0u8; SS_NONCE_LEN];
                    let mut body_reader = Cursor::new(body.split_off(cipher.salt_len()));
                    let destination_payload =
                        read_ss_chunk(cipher, &subkey, &mut inbound_nonce, &mut body_reader)
                            .await
                            .unwrap()
                            .unwrap();
                    assert_eq!(destination_payload, expected_destination);

                    stream
                        .write_all(
                            b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\n\r\n",
                        )
                        .await
                        .unwrap();
                    let response_salt = vec![0x42; cipher.salt_len()];
                    let response_key = cipher.derive_subkey(&master_key, &response_salt).unwrap();
                    stream.write_all(&response_salt).await.unwrap();
                    let mut outbound_nonce = [0u8; SS_NONCE_LEN];
                    write_ss_chunk(
                        cipher,
                        &response_key,
                        &mut outbound_nonce,
                        &mut stream,
                        b"pong",
                    )
                    .await
                    .unwrap();
                    break;
                }
            }
        });

        let outbound = ShadowsocksOutbound::new(
            "ss-obfs-test".to_string(),
            "127.0.0.1".to_string(),
            listen_addr.port(),
            "aes-128-gcm".to_string(),
            password,
            Some(ShadowsocksPluginConfig {
                mode: "http_simple".to_string(),
                host: Some("edge.example.com".to_string()),
                path: None,
                tls: false,
                skip_cert_verify: false,
            }),
        );
        let mut stream = outbound.connect(&destination, 1000).await.unwrap();
        let mut response = [0u8; 4];
        stream.read_exact(&mut response).await.unwrap();

        assert_eq!(&response, b"pong");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn shadowsocks_simple_obfs_tls_wraps_stream() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let password = "secret".to_string();
        let destination = Destination::new("target.example", 443);
        let mut expected_destination = Vec::new();
        encode_socks5_destination(&destination, &mut expected_destination).unwrap();
        let server_password = password.clone();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (record_type, _version, client_hello) = read_simple_obfs_tls_record(&mut stream)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(record_type, 0x16);
            assert_eq!(client_hello[0], 0x01);
            assert_eq!(&client_hello[4..6], &[0x03, 0x03]);
            assert!(client_hello
                .windows("edge.example.com".len())
                .any(|window| window == b"edge.example.com"));
            let ticket_offset = SIMPLE_OBFS_TLS_FIXED_CLIENT_HELLO_LEN - 5;
            assert_eq!(
                &client_hello[ticket_offset..ticket_offset + 2],
                &[0x00, 0x23]
            );
            let ticket_len = u16::from_be_bytes([
                client_hello[ticket_offset + 2],
                client_hello[ticket_offset + 3],
            ]) as usize;
            let body_start = ticket_offset + SIMPLE_OBFS_TLS_SESSION_TICKET_HEADER_LEN;
            let body_end = body_start + ticket_len;
            let body = client_hello[body_start..body_end].to_vec();

            let cipher = SsCipher::Aes128Gcm;
            let master_key = evp_bytes_to_key(server_password.as_bytes(), cipher.key_len());
            let salt = body[..cipher.salt_len()].to_vec();
            let subkey = cipher.derive_subkey(&master_key, &salt).unwrap();
            let mut inbound_nonce = [0u8; SS_NONCE_LEN];
            let mut body_reader = Cursor::new(body[cipher.salt_len()..].to_vec());
            let destination_payload =
                read_ss_chunk(cipher, &subkey, &mut inbound_nonce, &mut body_reader)
                    .await
                    .unwrap()
                    .unwrap();
            assert_eq!(destination_payload, expected_destination);

            let (record_type, _version, upload) = read_simple_obfs_tls_record(&mut stream)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(record_type, 0x17);
            let mut upload_reader = Cursor::new(upload);
            let payload = read_ss_chunk(cipher, &subkey, &mut inbound_nonce, &mut upload_reader)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(payload, b"ping");

            let response_salt = vec![0x42; cipher.salt_len()];
            let response_key = cipher.derive_subkey(&master_key, &response_salt).unwrap();
            let mut outbound_nonce = [0u8; SS_NONCE_LEN];
            let response_chunk =
                encode_ss_chunk(cipher, &response_key, &mut outbound_nonce, b"pong").unwrap();
            let mut response_payload = response_salt;
            response_payload.extend_from_slice(&response_chunk);
            let mut response = vec![
                0x16, 0x03, 0x01, 0x00, 0x00, 0x14, 0x03, 0x03, 0x00, 0x01, 0x01,
            ];
            response.extend_from_slice(&[0x16, 0x03, 0x03]);
            response.extend_from_slice(&(response_payload.len() as u16).to_be_bytes());
            response.extend_from_slice(&response_payload);
            stream.write_all(&response).await.unwrap();
        });

        let outbound = ShadowsocksOutbound::new(
            "ss-obfs-tls-test".to_string(),
            "127.0.0.1".to_string(),
            listen_addr.port(),
            "aes-128-gcm".to_string(),
            password,
            Some(ShadowsocksPluginConfig {
                mode: "tls".to_string(),
                host: Some("edge.example.com".to_string()),
                path: None,
                tls: false,
                skip_cert_verify: false,
            }),
        );
        let mut stream = outbound.connect(&destination, 1000).await.unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut response = [0u8; 4];
        stream.read_exact(&mut response).await.unwrap();

        assert_eq!(&response, b"pong");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn shadowsocks_v2ray_plugin_websocket_real_dial() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let password = "secret".to_string();
        let server_password = password.clone();
        let destination = Destination::new("target.example", 443);
        let mut expected_destination = Vec::new();
        encode_socks5_destination(&destination, &mut expected_destination).unwrap();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buffer = [0u8; 512];
            let header_end = loop {
                let count = stream.read(&mut buffer).await.unwrap();
                assert!(count > 0);
                request.extend_from_slice(&buffer[..count]);
                if let Some(index) = find_header_end(&request) {
                    break index;
                }
            };
            let header = String::from_utf8(request[..header_end].to_vec()).unwrap();
            assert!(header.starts_with("GET /ss HTTP/1.1"));
            assert!(header.contains("Host: cdn.example.com"));
            let key = header
                .lines()
                .find_map(|line| {
                    line.split_once(':').and_then(|(name, value)| {
                        name.eq_ignore_ascii_case("sec-websocket-key")
                            .then(|| value.trim().to_string())
                    })
                })
                .unwrap();
            let response = format!(
                "HTTP/1.1 101 Switching Protocols\r\n\
                 Upgrade: websocket\r\n\
                 Connection: Upgrade\r\n\
                 Sec-WebSocket-Accept: {}\r\n\
                 \r\n",
                websocket_accept_key(&key)
            );
            stream.write_all(response.as_bytes()).await.unwrap();

            let request = read_websocket_frame(&mut stream).await.unwrap().unwrap();
            let cipher = SsCipher::Aes128Gcm;
            let master_key = cipher.master_key(server_password.as_bytes()).unwrap();
            let request_salt = &request[..cipher.salt_len()];
            let request_key = cipher.derive_subkey(&master_key, request_salt).unwrap();
            let mut request_nonce = vec![0u8; cipher.nonce_len()];
            let mut request_reader = Cursor::new(&request[cipher.salt_len()..]);
            let target = read_ss_chunk(
                cipher,
                &request_key,
                &mut request_nonce,
                &mut request_reader,
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(target, expected_destination);

            let payload = read_websocket_frame(&mut stream).await.unwrap().unwrap();
            let mut payload_reader = Cursor::new(payload);
            let payload = read_ss_chunk(
                cipher,
                &request_key,
                &mut request_nonce,
                &mut payload_reader,
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(payload, b"ping");

            let response_salt = vec![0x42; cipher.salt_len()];
            let response_key = cipher.derive_subkey(&master_key, &response_salt).unwrap();
            let mut response_nonce = vec![0u8; cipher.nonce_len()];
            let response_chunk =
                encode_ss_chunk(cipher, &response_key, &mut response_nonce, b"pong").unwrap();
            let mut response = response_salt;
            response.extend_from_slice(&response_chunk);
            write_websocket_frame(&mut stream, 0x2, &response)
                .await
                .unwrap();
        });

        let outbound = ShadowsocksOutbound::new(
            "ss-v2ray-plugin-test".to_string(),
            "127.0.0.1".to_string(),
            listen_addr.port(),
            "aes-128-gcm".to_string(),
            password,
            Some(ShadowsocksPluginConfig {
                mode: "v2ray-plugin".to_string(),
                host: Some("cdn.example.com".to_string()),
                path: Some("/ss".to_string()),
                tls: false,
                skip_cert_verify: false,
            }),
        );
        let mut stream = outbound.connect(&destination, 1000).await.unwrap();
        stream.write_all(b"ping").await.unwrap();
        stream.flush().await.unwrap();
        let mut response = [0u8; 4];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"pong");
        server.await.unwrap();
    }

    #[test]
    fn shadowsocks_rejects_unsupported_method() {
        let error = SsCipher::from_method("rc4-md5").unwrap_err();
        assert!(error.to_string().contains("unsupported shadowsocks method"));
    }

    #[tokio::test]
    async fn trojan_outbound_sends_valid_connect_request_over_tls() {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_der = CertificateDer::from(cert.cert.der().to_vec());
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()));
        let provider = aws_lc_rs::default_provider();
        let server_config = ServerConfig::builder_with_provider(provider.into())
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let destination = Destination::new("target.example", 443);
        let mut expected_destination = Vec::new();
        encode_socks5_destination(&destination, &mut expected_destination).unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = acceptor.accept(stream).await.unwrap();
            let mut request = Vec::new();
            let mut buf = [0u8; 512];
            loop {
                let n = stream.read(&mut buf).await.unwrap();
                assert!(n > 0);
                request.extend_from_slice(&buf[..n]);
                if request.ends_with(b"\r\n")
                    && request.len() >= 56 + 2 + 1 + expected_destination.len() + 2
                {
                    break;
                }
            }

            let expected_hash = hex_lower(&Sha224::digest(b"secret"));
            assert_eq!(&request[..56], expected_hash.as_bytes());
            assert_eq!(&request[56..58], b"\r\n");
            assert_eq!(request[58], 0x01);
            assert_eq!(
                &request[59..59 + expected_destination.len()],
                expected_destination.as_slice()
            );
            assert_eq!(
                &request[59 + expected_destination.len()..61 + expected_destination.len()],
                b"\r\n"
            );
            stream.write_all(b"pong").await.unwrap();
        });

        let outbound = TrojanOutbound {
            name: "trojan-test".to_string(),
            server: "127.0.0.1".to_string(),
            port: listen_addr.port(),
            password: "secret".to_string(),
            sni: Some("localhost".to_string()),
            skip_cert_verify: true,
            network: None,
            ws_path: None,
            ws_host: None,
            grpc_service_name: None,
            transport_headers: BTreeMap::new(),
            alpn: Vec::new(),
            udp_sessions: TokioMutex::new(TrojanUdpPool::default()),
        };
        let mut stream = outbound.connect(&destination, 1000).await.unwrap();
        let mut response = [0u8; 4];
        stream.read_exact(&mut response).await.unwrap();

        assert_eq!(&response, b"pong");
        server.await.unwrap();
    }

    #[test]
    fn trojan_request_uses_sha224_password_hash() {
        let request =
            build_trojan_request("secret", &Destination::new("example.com", 443)).unwrap();

        assert_eq!(
            &request[..56],
            hex_lower(&Sha224::digest(b"secret")).as_bytes()
        );
        assert_eq!(&request[56..58], b"\r\n");
        assert_eq!(request[58], 0x01);
    }

    #[test]
    fn trojan_transport_alpn_rejects_incompatible_protocols() {
        let grpc_error = trojan_alpn_protocols("grpc", &["http/1.1".to_string()])
            .expect_err("gRPC without h2 must fail");
        assert!(grpc_error.to_string().contains("requires h2"));

        let ws_error = trojan_alpn_protocols("ws", &["h2".to_string()])
            .expect_err("WebSocket without http/1.1 must fail");
        assert!(ws_error.to_string().contains("requires http/1.1"));
    }

    #[test]
    fn transport_headers_reject_line_injection() {
        let headers =
            BTreeMap::from([("X-Test".to_string(), "safe\r\nInjected: true".to_string())]);
        let error = render_transport_headers(&headers, &[])
            .expect_err("header line injection must be rejected");
        assert!(error.to_string().contains("invalid transport header value"));
    }

    #[test]
    fn shadowsocks_2022_udp_replay_window_rejects_duplicates_and_old_packets() {
        let mut window = Ss2022ReplayWindow::default();
        assert!(window.accept(100));
        assert!(!window.accept(100));
        assert!(window.accept(99));
        assert!(window.accept(164));
        assert!(!window.accept(99));
        assert!(!window.accept(90));
    }

    #[tokio::test]
    async fn vless_outbound_sends_valid_tcp_request_over_tls_and_strips_response_header() {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_der = CertificateDer::from(cert.cert.der().to_vec());
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()));
        let provider = aws_lc_rs::default_provider();
        let server_config = ServerConfig::builder_with_provider(provider.into())
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let destination = Destination::new("target.example", 443);
        let user_id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = acceptor.accept(stream).await.unwrap();
            let mut fixed = [0u8; 1 + 16 + 1 + 1 + 2 + 1];
            stream.read_exact(&mut fixed).await.unwrap();
            assert_eq!(fixed[0], 0x00);
            assert_eq!(&fixed[1..17], user_id.as_bytes());
            assert_eq!(fixed[17], 0x00);
            assert_eq!(fixed[18], 0x01);
            assert_eq!(u16::from_be_bytes([fixed[19], fixed[20]]), 443);
            assert_eq!(fixed[21], 0x02);

            let mut domain_len = [0u8; 1];
            stream.read_exact(&mut domain_len).await.unwrap();
            let mut domain = vec![0u8; domain_len[0] as usize];
            stream.read_exact(&mut domain).await.unwrap();
            assert_eq!(domain, b"target.example");

            stream.write_all(&[0x00, 0x00]).await.unwrap();
            let mut payload = [0u8; 4];
            stream.read_exact(&mut payload).await.unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong").await.unwrap();
        });

        let outbound = VlessOutbound {
            name: "vless-test".to_string(),
            server: "127.0.0.1".to_string(),
            port: listen_addr.port(),
            uuid: "11111111-1111-1111-1111-111111111111".to_string(),
            flow: None,
            security: None,
            tls: true,
            sni: Some("localhost".to_string()),
            skip_cert_verify: true,
            network: None,
            ws_path: None,
            ws_host: None,
            grpc_service_name: None,
            reality_public_key: None,
            reality_short_id: None,
            reality_fingerprint: None,
            reality_spider_x: None,
            udp_sessions: TokioMutex::new(VlessUdpPool::default()),
        };
        let mut stream = outbound.connect(&destination, 1000).await.unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut response = [0u8; 4];
        stream.read_exact(&mut response).await.unwrap();

        assert_eq!(&response, b"pong");
        server.await.unwrap();
    }

    #[test]
    fn websocket_accept_key_matches_rfc_example() {
        assert_eq!(
            websocket_accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[tokio::test]
    async fn websocket_client_frames_are_masked_and_decodable() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let writer = tokio::spawn(async move {
            write_websocket_binary_frame(&mut client, b"hello")
                .await
                .unwrap();
        });

        let mut header = [0u8; 2];
        server.read_exact(&mut header).await.unwrap();
        assert_eq!(header[0], 0x82);
        assert_eq!(header[1] & 0x80, 0x80);
        assert_eq!(header[1] & 0x7f, 5);
        let mut mask = [0u8; 4];
        server.read_exact(&mut mask).await.unwrap();
        let mut payload = [0u8; 5];
        server.read_exact(&mut payload).await.unwrap();
        for (index, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask[index % 4];
        }
        assert_eq!(&payload, b"hello");
        writer.await.unwrap();
    }

    #[tokio::test]
    async fn vless_outbound_supports_websocket_transport() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let destination = Destination::new("target.example", 443);
        let user_id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buf = [0u8; 512];
            let header_end = loop {
                let n = stream.read(&mut buf).await.unwrap();
                assert!(n > 0);
                request.extend_from_slice(&buf[..n]);
                if let Some(index) = find_header_end(&request) {
                    break index;
                }
            };
            let header = String::from_utf8(request[..header_end].to_vec()).unwrap();
            assert!(header.starts_with("GET /ray HTTP/1.1"));
            assert!(header.contains("Host: cdn.example.com"));
            let key = header
                .lines()
                .find_map(|line| {
                    line.split_once(':').and_then(|(name, value)| {
                        name.eq_ignore_ascii_case("sec-websocket-key")
                            .then(|| value.trim().to_string())
                    })
                })
                .unwrap();
            let response = format!(
                "HTTP/1.1 101 Switching Protocols\r\n\
                 Upgrade: websocket\r\n\
                 Connection: Upgrade\r\n\
                 Sec-WebSocket-Accept: {}\r\n\
                 \r\n",
                websocket_accept_key(&key)
            );
            stream.write_all(response.as_bytes()).await.unwrap();

            let request_payload = read_websocket_frame(&mut stream).await.unwrap().unwrap();
            assert_eq!(request_payload[0], 0x00);
            assert_eq!(&request_payload[1..17], user_id.as_bytes());
            assert_eq!(request_payload[17], 0x00);
            assert_eq!(request_payload[18], 0x01);
            assert_eq!(
                u16::from_be_bytes([request_payload[19], request_payload[20]]),
                443
            );
            assert_eq!(request_payload[21], 0x02);
            assert_eq!(request_payload[22], "target.example".len() as u8);
            assert_eq!(&request_payload[23..], b"target.example");

            write_websocket_frame(&mut stream, 0x2, &[0x00, 0x00])
                .await
                .unwrap();
            let payload = read_websocket_frame(&mut stream).await.unwrap().unwrap();
            assert_eq!(payload, b"ping");
            write_websocket_frame(&mut stream, 0x2, b"pong")
                .await
                .unwrap();
        });

        let outbound = VlessOutbound {
            name: "vless-ws-test".to_string(),
            server: "127.0.0.1".to_string(),
            port: listen_addr.port(),
            uuid: "11111111-1111-1111-1111-111111111111".to_string(),
            flow: None,
            security: None,
            tls: false,
            sni: None,
            skip_cert_verify: false,
            network: Some("ws".to_string()),
            ws_path: Some("/ray".to_string()),
            ws_host: Some("cdn.example.com".to_string()),
            grpc_service_name: None,
            reality_public_key: None,
            reality_short_id: None,
            reality_fingerprint: None,
            reality_spider_x: None,
            udp_sessions: TokioMutex::new(VlessUdpPool::default()),
        };
        let mut stream = outbound.connect(&destination, 1000).await.unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut response = [0u8; 4];
        stream.read_exact(&mut response).await.unwrap();

        assert_eq!(&response, b"pong");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn vless_outbound_supports_grpc_transport() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let destination = Destination::new("target.example", 443);
        let user_id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut h2 = h2::server::handshake(stream).await.unwrap();
            let (request, mut respond) = h2.accept().await.unwrap().unwrap();
            let handler = tokio::spawn(async move {
                assert_eq!(request.uri().path(), "/ray/Tun");
                assert_eq!(
                    request
                        .headers()
                        .get(http::header::CONTENT_TYPE)
                        .and_then(|value| value.to_str().ok()),
                    Some("application/grpc")
                );
                let mut body = request.into_body();
                let request_payload = read_grpc_message_for_test(&mut body).await;
                assert_eq!(request_payload[0], 0x00);
                assert_eq!(&request_payload[1..17], user_id.as_bytes());
                assert_eq!(request_payload[17], 0x00);
                assert_eq!(request_payload[18], 0x01);
                assert_eq!(
                    u16::from_be_bytes([request_payload[19], request_payload[20]]),
                    443
                );
                assert_eq!(request_payload[21], 0x02);
                assert_eq!(request_payload[22], "target.example".len() as u8);
                assert_eq!(&request_payload[23..], b"target.example");

                let response = http::Response::builder()
                    .status(200)
                    .header(http::header::CONTENT_TYPE, "application/grpc")
                    .body(())
                    .unwrap();
                let mut send = respond.send_response(response, false).unwrap();
                send.send_data(grpc_frame_for_test(&[0x00, 0x00]), false)
                    .unwrap();

                let payload = read_grpc_message_for_test(&mut body).await;
                assert_eq!(payload, b"ping");
                send.send_data(grpc_frame_for_test(b"pong"), false).unwrap();
            });
            let driver = tokio::spawn(async move { while h2.accept().await.is_some() {} });
            handler.await.unwrap();
            driver.abort();
        });

        let outbound = VlessOutbound {
            name: "vless-grpc-test".to_string(),
            server: "127.0.0.1".to_string(),
            port: listen_addr.port(),
            uuid: "11111111-1111-1111-1111-111111111111".to_string(),
            flow: None,
            security: None,
            tls: false,
            sni: None,
            skip_cert_verify: false,
            network: Some("grpc".to_string()),
            ws_path: None,
            ws_host: Some("cdn.example.com".to_string()),
            grpc_service_name: Some("ray".to_string()),
            reality_public_key: None,
            reality_short_id: None,
            reality_fingerprint: None,
            reality_spider_x: None,
            udp_sessions: TokioMutex::new(VlessUdpPool::default()),
        };
        let mut stream =
            tokio::time::timeout(Duration::from_secs(2), outbound.connect(&destination, 1000))
                .await
                .expect("vless grpc connect timed out")
                .unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut response = [0u8; 4];
        tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut response))
            .await
            .expect("vless grpc read timed out")
            .unwrap();

        assert_eq!(&response, b"pong");
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("vless grpc server timed out")
            .unwrap();
    }

    #[tokio::test]
    async fn vless_outbound_supports_h2_transport() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let destination = Destination::new("target.example", 443);
        let user_id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut h2 = h2::server::handshake(stream).await.unwrap();
            let (request, mut respond) = h2.accept().await.unwrap().unwrap();
            let handler = tokio::spawn(async move {
                assert_eq!(request.method(), http::Method::PUT);
                assert_eq!(request.uri().path(), "/h2");
                let mut body = H2BodyReaderForTest::new(request.into_body());
                let mut fixed = [0u8; 23];
                body.read_exact(&mut fixed).await.unwrap();
                assert_eq!(fixed[0], 0x00);
                assert_eq!(&fixed[1..17], user_id.as_bytes());
                assert_eq!(fixed[17], 0x00);
                assert_eq!(fixed[18], 0x01);
                assert_eq!(u16::from_be_bytes([fixed[19], fixed[20]]), 443);
                assert_eq!(fixed[21], 0x02);
                assert_eq!(fixed[22], "target.example".len() as u8);
                let mut domain = vec![0u8; "target.example".len()];
                body.read_exact(&mut domain).await.unwrap();
                assert_eq!(domain, b"target.example");

                let response = http::Response::builder().status(200).body(()).unwrap();
                let mut send = respond.send_response(response, false).unwrap();
                send.send_data(Bytes::from_static(&[0x00, 0x00]), false)
                    .unwrap();

                let mut payload = [0u8; 4];
                body.read_exact(&mut payload).await.unwrap();
                assert_eq!(&payload, b"ping");
                send.send_data(Bytes::from_static(b"pong"), false).unwrap();
            });
            let driver = tokio::spawn(async move { while h2.accept().await.is_some() {} });
            handler.await.unwrap();
            driver.abort();
        });

        let outbound = VlessOutbound {
            name: "vless-h2-test".to_string(),
            server: "127.0.0.1".to_string(),
            port: listen_addr.port(),
            uuid: "11111111-1111-1111-1111-111111111111".to_string(),
            flow: None,
            security: None,
            tls: false,
            sni: None,
            skip_cert_verify: false,
            network: Some("h2".to_string()),
            ws_path: Some("/h2".to_string()),
            ws_host: Some("cdn.example.com".to_string()),
            grpc_service_name: None,
            reality_public_key: None,
            reality_short_id: None,
            reality_fingerprint: None,
            reality_spider_x: None,
            udp_sessions: TokioMutex::new(VlessUdpPool::default()),
        };
        let mut stream =
            tokio::time::timeout(Duration::from_secs(2), outbound.connect(&destination, 1000))
                .await
                .expect("vless h2 connect timed out")
                .unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut response = [0u8; 4];
        tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut response))
            .await
            .expect("vless h2 read timed out")
            .unwrap();

        assert_eq!(&response, b"pong");
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("vless h2 server timed out")
            .unwrap();
    }

    #[tokio::test]
    async fn vmess_outbound_supports_tcp_aead_stream() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let destination = Destination::new("target.example", 443);
        let expected_destination = destination.clone();
        let user_id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let setup = read_vmess_client_setup_for_test(&mut stream, &user_id).await;
            assert_eq!(setup.destination, expected_destination);
            assert_eq!(setup.cipher, VmessCipher::Chacha20Poly1305);

            let mut client_reader = VmessDownloadState {
                response_header_key: [0u8; 16],
                response_header_iv: [0u8; 16],
                response_authentication: setup.response_authentication,
                cipher: VmessAeadState::new(setup.cipher, &setup.data_key, &setup.data_iv).unwrap(),
                length_mask: VmessLengthMask::new(&setup.data_iv),
            };
            let payload = read_vmess_chunk(&mut stream, &mut client_reader)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(payload, b"ping");

            write_vmess_response_header_for_test(
                &mut stream,
                &setup.response_header_key,
                &setup.response_header_iv,
                setup.response_authentication,
            )
            .await;
            let mut server_writer = VmessUploadState {
                cipher: VmessAeadState::new(
                    setup.cipher,
                    &setup.response_header_key,
                    &setup.response_header_iv,
                )
                .unwrap(),
                length_mask: VmessLengthMask::new(&setup.response_header_iv),
            };
            write_vmess_chunk(&mut stream, &mut server_writer, b"pong")
                .await
                .unwrap();
        });

        let outbound = VmessOutbound {
            name: "vmess-test".to_string(),
            server: "127.0.0.1".to_string(),
            port: listen_addr.port(),
            uuid: "11111111-1111-1111-1111-111111111111".to_string(),
            cipher: "auto".to_string(),
            tls: false,
            sni: None,
            skip_cert_verify: false,
            network: None,
            ws_path: None,
            ws_host: None,
            grpc_service_name: None,
            udp_sessions: TokioMutex::new(VmessUdpPool::default()),
        };
        let mut stream = outbound.connect(&destination, 1000).await.unwrap();
        stream.write_all(b"ping").await.unwrap();
        stream.flush().await.unwrap();
        let mut response = [0u8; 4];
        stream.read_exact(&mut response).await.unwrap();

        assert_eq!(&response, b"pong");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn vmess_outbound_supports_grpc_transport() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let destination = Destination::new("target.example", 443);
        let expected_destination = destination.clone();
        let user_id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut h2 = h2::server::handshake(stream).await.unwrap();
            let (request, mut respond) = h2.accept().await.unwrap().unwrap();
            let handler = tokio::spawn(async move {
                assert_eq!(request.uri().path(), "/vmess/Tun");
                let mut body = GrpcBodyReaderForTest::new(request.into_body());
                let setup = read_vmess_client_setup_for_test(&mut body, &user_id).await;
                assert_eq!(setup.destination, expected_destination);
                assert_eq!(setup.cipher, VmessCipher::Chacha20Poly1305);

                let response = http::Response::builder()
                    .status(200)
                    .header(http::header::CONTENT_TYPE, "application/grpc")
                    .body(())
                    .unwrap();
                let mut send = respond.send_response(response, false).unwrap();
                let mut response_header = Vec::new();
                write_vmess_response_header_for_test(
                    &mut response_header,
                    &setup.response_header_key,
                    &setup.response_header_iv,
                    setup.response_authentication,
                )
                .await;
                send.send_data(grpc_frame_for_test(&response_header), false)
                    .unwrap();

                let mut client_reader = VmessDownloadState {
                    response_header_key: [0u8; 16],
                    response_header_iv: [0u8; 16],
                    response_authentication: setup.response_authentication,
                    cipher: VmessAeadState::new(setup.cipher, &setup.data_key, &setup.data_iv)
                        .unwrap(),
                    length_mask: VmessLengthMask::new(&setup.data_iv),
                };
                let payload = read_vmess_chunk(&mut body, &mut client_reader)
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(payload, b"ping");

                let mut server_writer = VmessUploadState {
                    cipher: VmessAeadState::new(
                        setup.cipher,
                        &setup.response_header_key,
                        &setup.response_header_iv,
                    )
                    .unwrap(),
                    length_mask: VmessLengthMask::new(&setup.response_header_iv),
                };
                let mut response_payload = Vec::new();
                write_vmess_chunk(&mut response_payload, &mut server_writer, b"pong")
                    .await
                    .unwrap();
                send.send_data(grpc_frame_for_test(&response_payload), false)
                    .unwrap();
            });
            let driver = tokio::spawn(async move { while h2.accept().await.is_some() {} });
            handler.await.unwrap();
            driver.abort();
        });

        let outbound = VmessOutbound {
            name: "vmess-grpc-test".to_string(),
            server: "127.0.0.1".to_string(),
            port: listen_addr.port(),
            uuid: "11111111-1111-1111-1111-111111111111".to_string(),
            cipher: "auto".to_string(),
            tls: false,
            sni: None,
            skip_cert_verify: false,
            network: Some("grpc".to_string()),
            ws_path: None,
            ws_host: Some("cdn.example.com".to_string()),
            grpc_service_name: Some("vmess".to_string()),
            udp_sessions: TokioMutex::new(VmessUdpPool::default()),
        };
        let mut stream =
            tokio::time::timeout(Duration::from_secs(2), outbound.connect(&destination, 1000))
                .await
                .expect("vmess grpc connect timed out")
                .unwrap();
        stream.write_all(b"ping").await.unwrap();
        stream.flush().await.unwrap();
        let mut response = [0u8; 4];
        tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut response))
            .await
            .expect("vmess grpc read timed out")
            .unwrap();

        assert_eq!(&response, b"pong");
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("vmess grpc server timed out")
            .unwrap();
    }

    #[tokio::test]
    async fn vmess_outbound_supports_h2_transport() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let destination = Destination::new("target.example", 443);
        let expected_destination = destination.clone();
        let user_id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut h2 = h2::server::handshake(stream).await.unwrap();
            let (request, mut respond) = h2.accept().await.unwrap().unwrap();
            let handler = tokio::spawn(async move {
                assert_eq!(request.method(), http::Method::PUT);
                assert_eq!(request.uri().path(), "/vmess-h2");
                let mut body = H2BodyReaderForTest::new(request.into_body());
                let setup = read_vmess_client_setup_for_test(&mut body, &user_id).await;
                assert_eq!(setup.destination, expected_destination);
                assert_eq!(setup.cipher, VmessCipher::Chacha20Poly1305);

                let response = http::Response::builder().status(200).body(()).unwrap();
                let mut send = respond.send_response(response, false).unwrap();
                let mut response_header = Vec::new();
                write_vmess_response_header_for_test(
                    &mut response_header,
                    &setup.response_header_key,
                    &setup.response_header_iv,
                    setup.response_authentication,
                )
                .await;
                send.send_data(Bytes::from(response_header), false).unwrap();

                let mut client_reader = VmessDownloadState {
                    response_header_key: [0u8; 16],
                    response_header_iv: [0u8; 16],
                    response_authentication: setup.response_authentication,
                    cipher: VmessAeadState::new(setup.cipher, &setup.data_key, &setup.data_iv)
                        .unwrap(),
                    length_mask: VmessLengthMask::new(&setup.data_iv),
                };
                let payload = read_vmess_chunk(&mut body, &mut client_reader)
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(payload, b"ping");

                let mut server_writer = VmessUploadState {
                    cipher: VmessAeadState::new(
                        setup.cipher,
                        &setup.response_header_key,
                        &setup.response_header_iv,
                    )
                    .unwrap(),
                    length_mask: VmessLengthMask::new(&setup.response_header_iv),
                };
                let mut response_payload = Vec::new();
                write_vmess_chunk(&mut response_payload, &mut server_writer, b"pong")
                    .await
                    .unwrap();
                send.send_data(Bytes::from(response_payload), false)
                    .unwrap();
            });
            let driver = tokio::spawn(async move { while h2.accept().await.is_some() {} });
            handler.await.unwrap();
            driver.abort();
        });

        let outbound = VmessOutbound {
            name: "vmess-h2-test".to_string(),
            server: "127.0.0.1".to_string(),
            port: listen_addr.port(),
            uuid: "11111111-1111-1111-1111-111111111111".to_string(),
            cipher: "auto".to_string(),
            tls: false,
            sni: None,
            skip_cert_verify: false,
            network: Some("h2".to_string()),
            ws_path: Some("/vmess-h2".to_string()),
            ws_host: Some("cdn.example.com".to_string()),
            grpc_service_name: None,
            udp_sessions: TokioMutex::new(VmessUdpPool::default()),
        };
        let mut stream =
            tokio::time::timeout(Duration::from_secs(2), outbound.connect(&destination, 1000))
                .await
                .expect("vmess h2 connect timed out")
                .unwrap();
        stream.write_all(b"ping").await.unwrap();
        stream.flush().await.unwrap();
        let mut response = [0u8; 4];
        tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut response))
            .await
            .expect("vmess h2 read timed out")
            .unwrap();

        assert_eq!(&response, b"pong");
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("vmess h2 server timed out")
            .unwrap();
    }

    async fn read_grpc_message_for_test(body: &mut h2::RecvStream) -> Vec<u8> {
        let mut data = BytesMut::new();
        loop {
            let chunk = body.data().await.unwrap().unwrap();
            let len = chunk.len();
            data.extend_from_slice(&chunk);
            body.flow_control().release_capacity(len).unwrap();
            if data.len() < 5 {
                continue;
            }
            let payload_len = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;
            if data.len() < 5 + payload_len {
                continue;
            }
            assert_eq!(data[0], 0);
            bytes::Buf::advance(&mut data, 5);
            return data.split_to(payload_len).to_vec();
        }
    }

    fn grpc_frame_for_test(payload: &[u8]) -> Bytes {
        let mut frame = Vec::with_capacity(5 + payload.len());
        frame.push(0);
        frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        frame.extend_from_slice(payload);
        Bytes::from(frame)
    }

    struct H2BodyReaderForTest {
        body: h2::RecvStream,
        read_buffer: BytesMut,
    }

    impl H2BodyReaderForTest {
        fn new(body: h2::RecvStream) -> Self {
            Self {
                body,
                read_buffer: BytesMut::new(),
            }
        }
    }

    impl AsyncRead for H2BodyReaderForTest {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut TaskContext<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<Result<(), Error>> {
            if buf.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }
            loop {
                if !self.read_buffer.is_empty() {
                    let len = self.read_buffer.len().min(buf.remaining());
                    let chunk = self.read_buffer.split_to(len);
                    buf.put_slice(&chunk);
                    return Poll::Ready(Ok(()));
                }
                match self.body.poll_data(cx) {
                    Poll::Ready(Some(Ok(chunk))) => {
                        let len = chunk.len();
                        self.read_buffer.extend_from_slice(&chunk);
                        let _ = self.body.flow_control().release_capacity(len);
                    }
                    Poll::Ready(Some(Err(error))) => {
                        return Poll::Ready(Err(Error::new(
                            ErrorKind::ConnectionAborted,
                            format!("h2 body failed: {error}"),
                        )));
                    }
                    Poll::Ready(None) => return Poll::Ready(Ok(())),
                    Poll::Pending => return Poll::Pending,
                }
            }
        }
    }

    struct GrpcBodyReaderForTest {
        body: h2::RecvStream,
        incoming: BytesMut,
        read_buffer: BytesMut,
    }

    impl GrpcBodyReaderForTest {
        fn new(body: h2::RecvStream) -> Self {
            Self {
                body,
                incoming: BytesMut::new(),
                read_buffer: BytesMut::new(),
            }
        }

        fn decode_next_message(&mut self) -> bool {
            if self.incoming.len() < 5 {
                return false;
            }
            let payload_len = u32::from_be_bytes([
                self.incoming[1],
                self.incoming[2],
                self.incoming[3],
                self.incoming[4],
            ]) as usize;
            if self.incoming.len() < 5 + payload_len {
                return false;
            }
            assert_eq!(self.incoming[0], 0);
            bytes::Buf::advance(&mut self.incoming, 5);
            let payload = self.incoming.split_to(payload_len);
            self.read_buffer.extend_from_slice(&payload);
            true
        }
    }

    impl AsyncRead for GrpcBodyReaderForTest {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut TaskContext<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<Result<(), Error>> {
            if buf.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }
            loop {
                if !self.read_buffer.is_empty() {
                    let len = self.read_buffer.len().min(buf.remaining());
                    let chunk = self.read_buffer.split_to(len);
                    buf.put_slice(&chunk);
                    return Poll::Ready(Ok(()));
                }
                if self.decode_next_message() {
                    continue;
                }
                match self.body.poll_data(cx) {
                    Poll::Ready(Some(Ok(chunk))) => {
                        let len = chunk.len();
                        self.incoming.extend_from_slice(&chunk);
                        let _ = self.body.flow_control().release_capacity(len);
                    }
                    Poll::Ready(Some(Err(error))) => {
                        return Poll::Ready(Err(Error::new(
                            ErrorKind::ConnectionAborted,
                            format!("grpc body failed: {error}"),
                        )));
                    }
                    Poll::Ready(None) => return Poll::Ready(Ok(())),
                    Poll::Pending => return Poll::Pending,
                }
            }
        }
    }

    struct VmessClientSetupForTest {
        destination: Destination,
        cipher: VmessCipher,
        data_iv: [u8; 16],
        data_key: [u8; 16],
        response_header_iv: [u8; 16],
        response_header_key: [u8; 16],
        response_authentication: u8,
    }

    async fn read_vmess_client_setup_for_test<S>(
        stream: &mut S,
        user_id: &Uuid,
    ) -> VmessClientSetupForTest
    where
        S: AsyncRead + Unpin,
    {
        let instruction_key = vmess_instruction_key(user_id);
        let mut auth_id = [0u8; 16];
        stream.read_exact(&mut auth_id).await.unwrap();
        let mut encrypted_len = [0u8; 18];
        stream.read_exact(&mut encrypted_len).await.unwrap();
        let mut nonce = [0u8; 8];
        stream.read_exact(&mut nonce).await.unwrap();

        let len_key = vmess_kdf(
            &instruction_key,
            &[b"VMess Header AEAD Key_Length", &auth_id, &nonce],
        );
        let len_nonce = vmess_kdf(
            &instruction_key,
            &[b"VMess Header AEAD Nonce_Length", &auth_id, &nonce],
        );
        let len =
            vmess_aes128gcm_decrypt(&len_key[..16], &len_nonce[..12], &auth_id, &encrypted_len)
                .unwrap();
        let header_len = u16::from_be_bytes([len[0], len[1]]) as usize;
        let mut encrypted_header = vec![0u8; header_len + VMESS_TAG_LEN];
        stream.read_exact(&mut encrypted_header).await.unwrap();
        let header_key = vmess_kdf(
            &instruction_key,
            &[b"VMess Header AEAD Key", &auth_id, &nonce],
        );
        let header_nonce = vmess_kdf(
            &instruction_key,
            &[b"VMess Header AEAD Nonce", &auth_id, &nonce],
        );
        let header = vmess_aes128gcm_decrypt(
            &header_key[..16],
            &header_nonce[..12],
            &auth_id,
            &encrypted_header,
        )
        .unwrap();

        assert_eq!(header[0], 0x01);
        assert_eq!(header[34] & 0x01, 0x01);
        assert_eq!(header[34] & 0x04, 0x04);
        assert_eq!(header[37], 0x01);
        let mut data_iv = [0u8; 16];
        data_iv.copy_from_slice(&header[1..17]);
        let mut data_key = [0u8; 16];
        data_key.copy_from_slice(&header[17..33]);
        let response_authentication = header[33];
        let cipher = match header[35] & 0x0f {
            3 => VmessCipher::Aes128Gcm,
            4 => VmessCipher::Chacha20Poly1305,
            5 => VmessCipher::None,
            other => panic!("unexpected vmess cipher {other}"),
        };

        let mut cursor = 38;
        let port = u16::from_be_bytes([header[cursor], header[cursor + 1]]);
        cursor += 2;
        let host = match header[cursor] {
            0x01 => {
                cursor += 1;
                let host = std::net::Ipv4Addr::new(
                    header[cursor],
                    header[cursor + 1],
                    header[cursor + 2],
                    header[cursor + 3],
                )
                .to_string();
                cursor += 4;
                host
            }
            0x02 => {
                cursor += 1;
                let len = header[cursor] as usize;
                cursor += 1;
                let host = std::str::from_utf8(&header[cursor..cursor + len])
                    .unwrap()
                    .to_string();
                cursor += len;
                host
            }
            0x03 => {
                cursor += 1;
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&header[cursor..cursor + 16]);
                cursor += 16;
                std::net::Ipv6Addr::from(octets).to_string()
            }
            other => panic!("unexpected vmess address type {other}"),
        };
        let margin_len = (header[35] >> 4) as usize;
        cursor += margin_len;
        let expected_checksum = u32::from_be_bytes([
            header[cursor],
            header[cursor + 1],
            header[cursor + 2],
            header[cursor + 3],
        ]);
        assert_eq!(expected_checksum, vmess_fnv1a(&header[..cursor]));

        VmessClientSetupForTest {
            destination: Destination::new(host, port),
            cipher,
            data_iv,
            data_key,
            response_header_iv: vmess_sha256_16(&data_iv),
            response_header_key: vmess_sha256_16(&data_key),
            response_authentication,
        }
    }

    async fn write_vmess_response_header_for_test<S>(
        stream: &mut S,
        response_header_key: &[u8; 16],
        response_header_iv: &[u8; 16],
        response_authentication: u8,
    ) where
        S: AsyncWrite + Unpin,
    {
        let response_header = [response_authentication, 0x00, 0x00, 0x00];
        let len_key = vmess_kdf(response_header_key, &[b"AEAD Resp Header Len Key"]);
        let len_nonce = vmess_kdf(response_header_iv, &[b"AEAD Resp Header Len IV"]);
        let encrypted_len = vmess_aes128gcm_encrypt(
            &len_key[..16],
            &len_nonce[..12],
            &[],
            &(response_header.len() as u16).to_be_bytes(),
        )
        .unwrap();
        let header_key = vmess_kdf(response_header_key, &[b"AEAD Resp Header Key"]);
        let header_nonce = vmess_kdf(response_header_iv, &[b"AEAD Resp Header IV"]);
        let encrypted_header = vmess_aes128gcm_encrypt(
            &header_key[..16],
            &header_nonce[..12],
            &[],
            &response_header,
        )
        .unwrap();
        stream.write_all(&encrypted_len).await.unwrap();
        stream.write_all(&encrypted_header).await.unwrap();
        stream.flush().await.unwrap();
    }

    #[test]
    fn vless_request_uses_port_then_vless_address_type() {
        let user_id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        let request =
            build_vless_request(&user_id, &Destination::new("example.com", 8443)).unwrap();

        assert_eq!(request[0], 0x00);
        assert_eq!(&request[1..17], user_id.as_bytes());
        assert_eq!(request[17], 0x00);
        assert_eq!(request[18], 0x01);
        assert_eq!(u16::from_be_bytes([request[19], request[20]]), 8443);
        assert_eq!(request[21], 0x02);
        assert_eq!(request[22], "example.com".len() as u8);
    }

    #[test]
    fn vless_request_encodes_vision_flow_addon() {
        let user_id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        let request = build_vless_request_with_flow(
            &user_id,
            &Destination::new("example.com", 8443),
            Some("xtls-rprx-vision"),
        )
        .unwrap();

        assert_eq!(request[0], 0x00);
        assert_eq!(&request[1..17], user_id.as_bytes());
        assert_eq!(request[17], 18);
        assert_eq!(&request[18..36], b"\x0a\x10xtls-rprx-vision");
        assert_eq!(request[36], 0x01);
        assert_eq!(u16::from_be_bytes([request[37], request[38]]), 8443);
        assert_eq!(request[39], 0x02);
    }

    #[test]
    fn hysteria2_tcp_request_encodes_command_address_and_padding() {
        let request = build_hysteria2_tcp_request(&Destination::new("example.com", 443)).unwrap();

        assert_eq!(&request[0..2], &[0x44, 0x01]);
        assert_eq!(request[2], b"example.com:443".len() as u8);
        assert_eq!(&request[3..18], b"example.com:443");
        assert_eq!(request[18], 0x00);
    }

    #[test]
    fn hysteria2_udp_message_round_trips_payload() {
        let request = build_hysteria2_udp_messages(
            0x0102_0304,
            0x0506,
            &Destination::new("example.com", 53),
            b"dns",
            None,
        )
        .unwrap()
        .remove(0);

        assert_eq!(&request[0..4], &[1, 2, 3, 4]);
        assert_eq!(&request[4..8], &[5, 6, 0, 1]);
        assert_eq!(request[8], b"example.com:53".len() as u8);
        assert_eq!(&request[9..23], b"example.com:53");
        assert_eq!(&request[23..], b"dns");
        let mut reassembly = Hysteria2UdpReassembly::default();
        assert_eq!(
            parse_hysteria2_udp_message(&request, 0x0102_0304, &mut reassembly)
                .unwrap()
                .unwrap(),
            b"dns"
        );
        assert!(parse_hysteria2_udp_message(
            &request,
            0x9999_0000,
            &mut Hysteria2UdpReassembly::default()
        )
        .unwrap()
        .is_none());
    }

    #[test]
    fn tuic_connect_request_encodes_domain_target() {
        let request = build_tuic_connect_request(&Destination::new("example.com", 443)).unwrap();

        assert_eq!(&request[0..3], &[0x05, 0x01, 0x00]);
        assert_eq!(request[3], b"example.com".len() as u8);
        assert_eq!(&request[4..15], b"example.com");
        assert_eq!(u16::from_be_bytes([request[15], request[16]]), 443);
    }

    #[test]
    fn tuic_connect_request_encodes_ip_target() {
        let request = build_tuic_connect_request(&Destination::new("1.2.3.4", 53)).unwrap();

        assert_eq!(&request, &[0x05, 0x01, 0x01, 1, 2, 3, 4, 0, 53]);
    }

    #[test]
    fn tuic_packet_request_round_trips_payload() {
        let request = build_tuic_packet_messages(
            0x0102,
            0x0304,
            &Destination::new("example.com", 53),
            b"dns",
            None,
        )
        .unwrap()
        .remove(0);

        assert_eq!(&request[0..10], &[0x05, 0x02, 1, 2, 3, 4, 1, 0, 0, 3]);
        assert_eq!(request[10], 0x00);
        assert_eq!(request[11], b"example.com".len() as u8);
        assert_eq!(&request[12..23], b"example.com");
        assert_eq!(u16::from_be_bytes([request[23], request[24]]), 53);
        assert_eq!(&request[25..], b"dns");
        let mut reassembly = TuicUdpReassembly::default();
        assert_eq!(
            parse_tuic_packet_message(&request, 0x0102, &mut reassembly)
                .unwrap()
                .unwrap(),
            b"dns"
        );
        assert!(
            parse_tuic_packet_message(&request, 0x9999, &mut TuicUdpReassembly::default())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn reality_decodes_public_key_and_short_id() {
        let server_secret = X25519StaticSecret::from([9u8; 32]);
        let server_public = X25519PublicKey::from(&server_secret).to_bytes();
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            server_public,
        );

        assert_eq!(
            decode_reality_public_key(&encoded).unwrap().to_bytes(),
            server_public
        );
        assert_eq!(
            decode_reality_short_id(Some("01aB")).unwrap(),
            vec![0x01, 0xab]
        );
        assert!(decode_reality_short_id(Some("abc")).is_err());
        assert!(decode_reality_short_id(Some("001122334455667788")).is_err());
    }

    #[test]
    fn reality_session_id_seals_version_time_and_short_id() {
        let server_secret = X25519StaticSecret::from([9u8; 32]);
        let server_public = X25519PublicKey::from(&server_secret);
        let client_secret = X25519StaticSecret::from([7u8; 32]);
        let shared_secret = client_secret.diffie_hellman(&server_public);
        let mut hello_random = [0u8; 32];
        hello_random
            .iter_mut()
            .enumerate()
            .for_each(|(index, byte)| *byte = index as u8);
        let hello_raw = b"synthetic client hello";
        let (session_id, auth_key) = seal_reality_session_id(
            shared_secret.as_bytes(),
            &[0x01, 0xab],
            &hello_random,
            hello_raw,
            0x0102_0304,
        )
        .unwrap();

        let cipher = Aes256Gcm::new_from_slice(&auth_key).unwrap();
        let plaintext = cipher
            .decrypt(
                aes_gcm::Nonce::from_slice(&hello_random[20..]),
                aes_gcm::aead::Payload {
                    msg: &session_id,
                    aad: hello_raw,
                },
            )
            .unwrap();
        assert_eq!(&plaintext[..3], &REALITY_CLIENT_VERSION);
        assert_eq!(plaintext[3], 0);
        assert_eq!(&plaintext[4..8], &[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(&plaintext[8..10], &[0x01, 0xab]);
        assert_eq!(&plaintext[10..], &[0u8; 6]);
    }
}
