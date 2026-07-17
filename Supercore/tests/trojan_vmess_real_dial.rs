//! P1 §6.4.2 Trojan + §6.4.3 VMess 真实拨号测试
//!
//! 这些测试**只通过公开 API** (`supercore::outbound::build_outbounds` +
//! `supercore::config::OutboundConfig::{Trojan,Vmess}`) 拨号到 127.0.0.1 mock server，
//! 在 mock server 侧用公开 crypto crates (aes-gcm / sha2 / sha3 / md5 / crc32fast) 解码客户端
//! 发上来的 wire bytes 来验证协议格式正确。
//!
//! ## 覆盖矩阵
//!
//! | 测试 | 协议 | transport | 说明 |
//! |------|------|-----------|------|
//! | `trojan_tcp_real_dial` | Trojan | TLS over TCP | 完整 hex(SHA224) 头解析 |
//! | `trojan_ws_transport_real_dial` | Trojan | TLS + WebSocket | Upgrade + Trojan header |
//! | `trojan_grpc_transport_real_dial` | Trojan | TLS + gRPC | h2 framing + Trojan header |
//! | `trojan_h2_transport_real_dial` | Trojan | TLS + HTTP/2 | h2 stream + Trojan header |
//! | `trojan_http_upgrade_transport_real_dial` | Trojan | TLS + HTTPUpgrade | HTTP 101 + raw stream |
//! | `trojan_udp_real_dial` | Trojan | TLS-TCP tunnel + UDP relay | UDP 包回环 |
//! | `trojan_udp_over_ws_real_dial` | Trojan | TLS + WebSocket + UDP relay | transport 内 UDP 回环 |
//! | `vmess_tcp_aead_real_dial` | VMess | TCP (alterId=0, AEAD) | 解密 header + chunk |
//! | `vmess_alterid_zero_explicit` | VMess | TCP | alterId=0 显式覆盖 |
//! | `vmess_legacy_alter_id_real_dial` | VMess | TCP (legacy) | alterId 派生认证 + CFB header |
//! | `vmess_large_bidirectional_stream_and_half_close` | VMess | TCP | 96KB 多帧 + 认证 EOF |
//! | `vmess_ws_transport_real_dial` | VMess | WebSocket (plain) | Upgrade 握手 + 解密 |
//! | `vmess_grpc_transport_real_dial` | VMess | gRPC (plain) | h2 + 解密 |
//! | `vmess_h2_transport_real_dial` | VMess | HTTP/2 (plain) | h2 PUT + 解密 |
//! | `vmess_http_camouflage_real_dial` | VMess | HTTP/1.1 | 首包伪装 + prefetched response |
//! | `vmess_http_upgrade_real_dial` | VMess | HTTPUpgrade | 101 + raw stream |
//! | `vmess_udp_real_dial` | VMess | TCP-tunneled UDP | AEAD chunk 解析 + 回包 |
//! | `vmess_udp_keeps_destinations_in_separate_associations` | VMess | UDP | 多目的 session 隔离 |
//! | `vmess_udp_timeout_evicts_stale_session` | VMess | UDP | 超时淘汰与恢复 |
//!
//! 所有 test 都使用 `127.0.0.1`，不连接真实互联网。

use std::{
    collections::BTreeMap,
    io::{Error, ErrorKind},
    pin::Pin,
    sync::Arc,
    task::{Context as TaskContext, Poll},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use aes::{cipher::BlockDecrypt, Aes128};
use aes_gcm::{
    aead::{Aead, Payload},
    Aes128Gcm, KeyInit, Nonce,
};
use anyhow::anyhow;
use bytes::{Buf, Bytes, BytesMut};
use cfb_mode::cipher::KeyIvInit as _;
use crc32fast::hash as crc32_ieee;
use h2::server::handshake as h2_server_handshake;
use http::{Request, Response};
use md5::{Digest, Md5};
use rcgen::generate_simple_self_signed;
use rustls::{ServerConfig, SupportedProtocolVersion};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha1::Sha1;
use sha2::{Sha224, Sha256};
use sha3::digest::{ExtendableOutput, Update};
use sha3::{Shake128, Shake128Reader};
use supercore::{config::OutboundConfig, outbound::build_outbounds, routing::Destination};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadBuf},
    net::TcpListener,
    time::timeout,
};
use tokio_rustls::TlsAcceptor;

// ============================================================
// 通用工具
// ============================================================

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// VMess server-side 解密 header 所需的 KDF (从 src/outbound/mod.rs 移植)
fn vmess_kdf(key: &[u8], path: &[&[u8]]) -> [u8; 32] {
    let mut keys: Vec<&[u8]> = Vec::with_capacity(path.len() + 1);
    keys.push(b"VMess AEAD KDF");
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

fn vmess_md5_16(data: &[u8]) -> [u8; 16] {
    Md5::digest(data).into()
}

fn vmess_instruction_key(user_id: &[u8; 16]) -> [u8; 16] {
    let mut data = user_id.to_vec();
    data.extend_from_slice(b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
    Md5::digest(&data).into()
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
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| anyhow!("vmess aes-gcm decrypt failed"))
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
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| anyhow!("vmess aes-gcm encrypt failed"))
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

/// Compute the Sec-WebSocket-Accept value for a given client key (RFC 6455).
fn websocket_accept_key(key: &str) -> String {
    use sha1::Digest as _;
    let mut hasher = Sha1::new();
    Digest::update(&mut hasher, key.as_bytes());
    Digest::update(&mut hasher, b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        hasher.finalize(),
    )
}

fn find_http_header_end(data: &[u8]) -> Option<usize> {
    data.windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
}

struct LengthMask {
    reader: Shake128Reader,
}

impl LengthMask {
    fn new(seed: &[u8]) -> Self {
        let mut shake = Shake128::default();
        Update::update(&mut shake, seed);
        Self {
            reader: shake.finalize_xof(),
        }
    }

    fn next(&mut self) -> u16 {
        let mut mask = [0u8; 2];
        use sha3::digest::XofReader;
        self.reader.read(&mut mask);
        u16::from_be_bytes(mask)
    }
}

/// 解密 VMess client 端发出的第一个请求 (auth_id + encrypted_len + nonce + encrypted_header)
/// 返回 (data_iv, data_key, response_auth, command, destination, cipher_method)
#[derive(Debug)]
struct VmessDecryptedRequest {
    data_iv: [u8; 16],
    data_key: [u8; 16],
    response_authentication: u8,
    command: u8,
    destination_host: String,
    destination_port: u16,
    cipher_method: u8,
}

async fn read_vmess_request<R>(
    reader: &mut R,
    user_id: &[u8; 16],
) -> anyhow::Result<VmessDecryptedRequest>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let instruction_key = vmess_instruction_key(user_id);

    let mut auth_id = [0u8; 16];
    reader.read_exact(&mut auth_id).await?;
    let auth_key = vmess_kdf(&instruction_key, &[b"AES Auth ID Encryption"]);
    let auth_cipher = Aes128::new_from_slice(&auth_key[..16])?;
    let mut auth_plaintext = auth_id;
    auth_cipher.decrypt_block((&mut auth_plaintext).into());
    let timestamp = u64::from_be_bytes(auth_plaintext[..8].try_into()?);
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    if now.abs_diff(timestamp) > 120 {
        return Err(anyhow!("VMess AuthID clock skew exceeds 120 seconds"));
    }
    if auth_plaintext[12..] != crc32_ieee(&auth_plaintext[..12]).to_be_bytes() {
        return Err(anyhow!("VMess AuthID CRC32 IEEE mismatch"));
    }

    let mut encrypted_len = [0u8; 2 + 16]; // 18 bytes (2 len + 16 tag)
    reader.read_exact(&mut encrypted_len).await?;

    let mut nonce = [0u8; 8];
    reader.read_exact(&mut nonce).await?;

    let len_key = vmess_kdf(
        &instruction_key,
        &[b"VMess Header AEAD Key_Length", &auth_id, &nonce],
    );
    let len_nonce = vmess_kdf(
        &instruction_key,
        &[b"VMess Header AEAD Nonce_Length", &auth_id, &nonce],
    );
    let len_bytes =
        vmess_aes128gcm_decrypt(&len_key[..16], &len_nonce[..12], &auth_id, &encrypted_len)?;
    if len_bytes.len() != 2 {
        return Err(anyhow!("invalid vmess request header length"));
    }
    let header_len = u16::from_be_bytes([len_bytes[0], len_bytes[1]]) as usize;

    let mut encrypted_header = vec![0u8; header_len + 16];
    reader.read_exact(&mut encrypted_header).await?;

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
    )?;

    parse_vmess_request_header(&header)
}

fn parse_vmess_request_header(header: &[u8]) -> anyhow::Result<VmessDecryptedRequest> {
    // Header layout (matches the public VMess request format):
    //   byte 0         = version (0x01)
    //   bytes 1..17    = data_iv (16)
    //   bytes 17..33   = data_key (16)
    //   byte 33        = response_auth
    //   byte 34        = options
    //   byte 35        = (padding_len << 4) | cipher_method
    //   byte 36        = reserved (0)
    //   byte 37        = command
    //   bytes 38..     = port(2) + atyp(1) + [domain_len(1) + domain(N) | ipv4(4) | ipv6(16)]
    //   then padding_len bytes of random padding
    //   then 4 bytes FNV1a checksum over header[..cursor]
    if header.is_empty() {
        return Err(anyhow!("empty vmess header"));
    }
    if header[0] != 1 {
        return Err(anyhow!("unexpected vmess header version {}", header[0]));
    }
    let data_iv: [u8; 16] = header[1..17].try_into()?;
    let data_key: [u8; 16] = header[17..33].try_into()?;
    let response_authentication = header[33];
    let _options = header[34];
    let cipher_byte = header[35];
    let padding_len = (cipher_byte >> 4) as usize;
    let cipher_method = cipher_byte & 0x0f;
    // byte 36 = reserved (unused)
    let command = header[37];

    let mut cursor = 38;
    if header.len() < cursor + 2 + 1 {
        return Err(anyhow!("vmess header too short for address"));
    }
    let port = u16::from_be_bytes([header[cursor], header[cursor + 1]]);
    cursor += 2;
    let atyp = header[cursor];
    cursor += 1;
    let host = match atyp {
        0x01 => {
            if header.len() < cursor + 4 {
                return Err(anyhow!("vmess ipv4 truncated"));
            }
            let ip = format!(
                "{}.{}.{}.{}",
                header[cursor],
                header[cursor + 1],
                header[cursor + 2],
                header[cursor + 3]
            );
            cursor += 4;
            ip
        }
        0x02 => {
            let len = header[cursor] as usize;
            cursor += 1;
            if header.len() < cursor + len {
                return Err(anyhow!("vmess domain truncated"));
            }
            let host = std::str::from_utf8(&header[cursor..cursor + len])?.to_string();
            cursor += len;
            host
        }
        0x03 => {
            if header.len() < cursor + 16 {
                return Err(anyhow!("vmess ipv6 truncated"));
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&header[cursor..cursor + 16]);
            cursor += 16;
            std::net::Ipv6Addr::from(octets).to_string()
        }
        other => return Err(anyhow!("unsupported vmess atyp {other}")),
    };
    cursor += padding_len;
    if header.len() < cursor + 4 {
        return Err(anyhow!("vmess header missing checksum"));
    }
    let stored_checksum = u32::from_be_bytes([
        header[cursor],
        header[cursor + 1],
        header[cursor + 2],
        header[cursor + 3],
    ]);
    let computed_checksum = vmess_fnv1a(&header[..cursor]);
    if stored_checksum != computed_checksum {
        return Err(anyhow!(
            "vmess header fnv1a mismatch: stored={stored_checksum:#x} computed={computed_checksum:#x}"
        ));
    }

    Ok(VmessDecryptedRequest {
        data_iv,
        data_key,
        response_authentication,
        command,
        destination_host: host,
        destination_port: port,
        cipher_method,
    })
}

async fn read_legacy_vmess_request<R>(
    reader: &mut R,
    primary_user_id: &[u8; 16],
    alter_id_count: u16,
) -> anyhow::Result<VmessDecryptedRequest>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut authentication = [0u8; 16];
    reader.read_exact(&mut authentication).await?;

    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let accepted_user_ids = legacy_vmess_user_ids(primary_user_id, alter_id_count);
    let timestamp = (now.saturating_sub(120)..=now.saturating_add(120))
        .find(|timestamp| {
            accepted_user_ids.iter().any(|user_id| {
                legacy_vmess_hmac_md5(user_id, &timestamp.to_be_bytes()) == authentication
            })
        })
        .ok_or_else(|| anyhow!("legacy vmess authentication id did not match clock window"))?;

    let instruction_key = vmess_instruction_key(primary_user_id);
    let timestamp_iv = legacy_vmess_timestamp_iv(timestamp);
    let mut decryptor =
        cfb_mode::BufDecryptor::<Aes128>::new_from_slices(&instruction_key, &timestamp_iv)
            .map_err(|_| anyhow!("invalid legacy vmess header key or iv"))?;

    let mut header = vec![0u8; 41];
    reader.read_exact(&mut header).await?;
    decryptor.decrypt(&mut header);
    let padding_len = (header[35] >> 4) as usize;
    let address_len = match header[40] {
        0x01 => 4,
        0x02 => {
            let mut length = [0u8; 1];
            reader.read_exact(&mut length).await?;
            decryptor.decrypt(&mut length);
            header.push(length[0]);
            length[0] as usize
        }
        0x03 => 16,
        other => return Err(anyhow!("unsupported legacy vmess atyp {other}")),
    };
    let mut tail = vec![0u8; address_len + padding_len + 4];
    reader.read_exact(&mut tail).await?;
    decryptor.decrypt(&mut tail);
    header.extend_from_slice(&tail);
    parse_vmess_request_header(&header)
}

fn legacy_vmess_user_ids(primary_user_id: &[u8; 16], alter_id_count: u16) -> Vec<[u8; 16]> {
    let mut accepted = Vec::with_capacity(alter_id_count as usize + 1);
    accepted.push(*primary_user_id);
    let mut current = *primary_user_id;
    for _ in 0..alter_id_count {
        current = legacy_vmess_next_user_id(&current);
        accepted.push(current);
    }
    accepted
}

fn legacy_vmess_next_user_id(user_id: &[u8; 16]) -> [u8; 16] {
    let mut input = user_id.to_vec();
    input.extend_from_slice(b"16167dc8-16b6-4e6d-b8bb-65dd68113a81");
    let mut next: [u8; 16] = Md5::digest(&input).into();
    if &next == user_id {
        input.extend_from_slice(b"533eff8a-4113-4b10-b5ce-0f5d76b98cd2");
        next = Md5::digest(&input).into();
    }
    next
}

fn legacy_vmess_timestamp_iv(timestamp: u64) -> [u8; 16] {
    let timestamp = timestamp.to_be_bytes();
    let mut input = [0u8; 32];
    for chunk in input.chunks_exact_mut(timestamp.len()) {
        chunk.copy_from_slice(&timestamp);
    }
    Md5::digest(input).into()
}

fn legacy_vmess_hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
    let key = if key.len() > 64 {
        Md5::digest(key).to_vec()
    } else {
        key.to_vec()
    };
    let mut inner = [0x36u8; 64];
    let mut outer = [0x5cu8; 64];
    for (index, byte) in key.iter().enumerate() {
        inner[index] ^= *byte;
        outer[index] ^= *byte;
    }
    let mut inner_input = inner.to_vec();
    inner_input.extend_from_slice(data);
    let inner_hash = Md5::digest(inner_input);
    let mut outer_input = outer.to_vec();
    outer_input.extend_from_slice(&inner_hash);
    Md5::digest(outer_input).into()
}

/// Server-side 解密 VMess chunk (post-handshake)
fn vmess_decrypt_chunk(
    cipher_method: u8,
    data_key: &[u8; 16],
    data_iv: &[u8; 16],
    body_with_tag: &[u8],
) -> anyhow::Result<Vec<u8>> {
    vmess_decrypt_chunk_at(cipher_method, data_key, data_iv, 0, body_with_tag)
}

fn vmess_decrypt_chunk_at(
    cipher_method: u8,
    data_key: &[u8; 16],
    data_iv: &[u8; 16],
    counter: u16,
    body_with_tag: &[u8],
) -> anyhow::Result<Vec<u8>> {
    // Chunk format: 2-byte masked length + body (with 16-byte tag if AEAD)
    // We expect the length and body to be passed separately by the caller; here we just decrypt body.
    let key = match cipher_method {
        3 => data_key.to_vec(),
        4 => vmess_chacha_key(data_key).to_vec(),
        5 => return Ok(body_with_tag.to_vec()), // "none"
        m => return Err(anyhow!("unsupported vmess cipher method {m}")),
    };
    // Construct nonce: first 2 bytes = counter (big-endian), rest = data_iv[2..12]
    let mut nonce = [0u8; 12];
    nonce[2..].copy_from_slice(&data_iv[2..12]);
    nonce[0..2].copy_from_slice(&counter.to_be_bytes());

    // For AEAD methods use aes-gcm
    if cipher_method == 3 {
        Aes128Gcm::new_from_slice(&key)
            .map_err(|_| anyhow!("vmess aes key"))?
            .decrypt(Nonce::from_slice(&nonce), body_with_tag)
            .map_err(|_| anyhow!("vmess chunk aes decrypt failed"))
    } else if cipher_method == 4 {
        use chacha20poly1305::ChaCha20Poly1305;
        ChaCha20Poly1305::new_from_slice(&key)
            .map_err(|_| anyhow!("vmess chacha key"))?
            .decrypt(chacha20poly1305::Nonce::from_slice(&nonce), body_with_tag)
            .map_err(|_| anyhow!("vmess chunk chacha decrypt failed"))
    } else {
        Err(anyhow!("unsupported vmess cipher method {cipher_method}"))
    }
}

/// Server-side 解密第一段 chunk (带 masked length)
fn vmess_decrypt_first_chunk(
    cipher_method: u8,
    data_key: &[u8; 16],
    data_iv: &[u8; 16],
    raw: &[u8],
) -> anyhow::Result<Vec<u8>> {
    if raw.len() < 2 {
        return Err(anyhow!("vmess chunk too short"));
    }
    let masked_len = u16::from_be_bytes([raw[0], raw[1]]);
    // Length mask is derived from data_iv via Shake128. The client uses its own length-mask state
    // for upload chunks (initialised from data_iv, starts fresh per stream). So the server-side
    // decoder uses a freshly-initialised mask on data_iv and applies mask[0] to the first chunk.
    let mut fresh_mask = LengthMask::new(data_iv);
    let first_mask = fresh_mask.next();
    let actual_len = (masked_len ^ first_mask) as usize;

    let body_with_tag = &raw[2..];
    if body_with_tag.len() < actual_len {
        return Err(anyhow!(
            "vmess chunk body too short: {} < {}",
            body_with_tag.len(),
            actual_len
        ));
    }
    let chunk_body = &body_with_tag[..actual_len];
    vmess_decrypt_chunk(cipher_method, data_key, data_iv, chunk_body)
}

async fn read_vmess_first_chunk<R>(
    reader: &mut R,
    cipher_method: u8,
    data_key: &[u8; 16],
    data_iv: &[u8; 16],
) -> anyhow::Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut masked_length = [0u8; 2];
    reader.read_exact(&mut masked_length).await?;
    let mut length_mask = LengthMask::new(data_iv);
    let body_length = (u16::from_be_bytes(masked_length) ^ length_mask.next()) as usize;
    let mut body = vec![0u8; body_length];
    reader.read_exact(&mut body).await?;
    vmess_decrypt_chunk(cipher_method, data_key, data_iv, &body)
}

async fn read_legacy_vmess_first_chunk<R>(
    reader: &mut R,
    cipher_method: u8,
    data_key: &[u8; 16],
    data_iv: &[u8; 16],
) -> anyhow::Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut length = [0u8; 2];
    reader.read_exact(&mut length).await?;
    let body_length = u16::from_be_bytes(length) as usize;
    let mut body = vec![0u8; body_length];
    reader.read_exact(&mut body).await?;
    vmess_decrypt_chunk(cipher_method, data_key, data_iv, &body)
}

/// Build a server-side VMess response header (encrypted with response_header_key/iv)
async fn build_vmess_response_header(
    response_header_key: &[u8; 16],
    response_header_iv: &[u8; 16],
    response_authentication: u8,
) -> anyhow::Result<Vec<u8>> {
    // Response header format: response_auth + 3 reserved bytes (matches supercore's in-file test)
    let header = [response_authentication, 0x00, 0x00, 0x00];

    let len_key = vmess_kdf(response_header_key, &[b"AEAD Resp Header Len Key"]);
    let len_nonce = vmess_kdf(response_header_iv, &[b"AEAD Resp Header Len IV"]);
    let encrypted_len = vmess_aes128gcm_encrypt(
        &len_key[..16],
        &len_nonce[..12],
        &[],
        &(header.len() as u16).to_be_bytes(),
    )?;

    let header_key = vmess_kdf(response_header_key, &[b"AEAD Resp Header Key"]);
    let header_nonce = vmess_kdf(response_header_iv, &[b"AEAD Resp Header IV"]);
    let encrypted_header =
        vmess_aes128gcm_encrypt(&header_key[..16], &header_nonce[..12], &[], &header)?;

    let mut out = Vec::new();
    out.extend_from_slice(&encrypted_len);
    out.extend_from_slice(&encrypted_header);
    Ok(out)
}

fn build_legacy_vmess_response_header(
    response_header_key: &[u8; 16],
    response_header_iv: &[u8; 16],
    response_authentication: u8,
) -> anyhow::Result<Vec<u8>> {
    let mut header = vec![response_authentication, 0x00, 0x00, 0x00];
    let mut encryptor =
        cfb_mode::BufEncryptor::<Aes128>::new_from_slices(response_header_key, response_header_iv)
            .map_err(|_| anyhow!("invalid legacy vmess response key or iv"))?;
    encryptor.encrypt(&mut header);
    Ok(header)
}

/// Server-side VMess chunk writer
fn vmess_write_chunk(
    cipher_method: u8,
    key: &[u8],
    iv: &[u8],
    length_mask_seed: &[u8],
    payload: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let mut mask = LengthMask::new(length_mask_seed);
    vmess_write_chunk_at(cipher_method, key, iv, 0, mask.next(), payload)
}

fn vmess_write_chunk_at(
    cipher_method: u8,
    key: &[u8],
    iv: &[u8],
    counter: u16,
    length_mask: u16,
    payload: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let body_with_tag = match cipher_method {
        3 => {
            let mut nonce = [0u8; 12];
            nonce[2..].copy_from_slice(&iv[2..12]);
            nonce[0..2].copy_from_slice(&counter.to_be_bytes());
            Aes128Gcm::new_from_slice(key)
                .map_err(|_| anyhow!("aes key"))?
                .encrypt(Nonce::from_slice(&nonce), payload)
                .map_err(|_| anyhow!("vmess aes encrypt"))?
        }
        4 => {
            use chacha20poly1305::ChaCha20Poly1305;
            let mut nonce = [0u8; 12];
            nonce[2..].copy_from_slice(&iv[2..12]);
            nonce[0..2].copy_from_slice(&counter.to_be_bytes());
            ChaCha20Poly1305::new_from_slice(key)
                .map_err(|_| anyhow!("chacha key"))?
                .encrypt(chacha20poly1305::Nonce::from_slice(&nonce), payload)
                .map_err(|_| anyhow!("vmess chacha encrypt"))?
        }
        5 => payload.to_vec(),
        m => return Err(anyhow!("unsupported vmess cipher method {m}")),
    };

    let masked_len = (body_with_tag.len() as u16) ^ length_mask;
    let mut out = Vec::with_capacity(2 + body_with_tag.len());
    out.extend_from_slice(&masked_len.to_be_bytes());
    out.extend_from_slice(&body_with_tag);
    Ok(out)
}

fn vmess_write_unmasked_chunk(
    cipher_method: u8,
    key: &[u8],
    iv: &[u8],
    payload: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let mut chunk = vmess_write_chunk(cipher_method, key, iv, &[], payload)?;
    let body = chunk.split_off(2);
    let mut output = Vec::with_capacity(2 + body.len());
    output.extend_from_slice(&(body.len() as u16).to_be_bytes());
    output.extend_from_slice(&body);
    Ok(output)
}

struct StatefulVmessChunkReader {
    cipher_method: u8,
    key: [u8; 16],
    iv: [u8; 16],
    length_mask: LengthMask,
    counter: u16,
}

impl StatefulVmessChunkReader {
    fn new(cipher_method: u8, key: [u8; 16], iv: [u8; 16]) -> Self {
        Self {
            cipher_method,
            key,
            iv,
            length_mask: LengthMask::new(&iv),
            counter: 0,
        }
    }

    async fn read<R>(&mut self, reader: &mut R) -> anyhow::Result<Option<Vec<u8>>>
    where
        R: AsyncRead + Unpin,
    {
        let mut masked_length = [0u8; 2];
        reader.read_exact(&mut masked_length).await?;
        let body_length = (u16::from_be_bytes(masked_length) ^ self.length_mask.next()) as usize;
        let mut body = vec![0u8; body_length];
        reader.read_exact(&mut body).await?;
        let plaintext =
            vmess_decrypt_chunk_at(self.cipher_method, &self.key, &self.iv, self.counter, &body)?;
        self.counter = self.counter.wrapping_add(1);
        if plaintext.is_empty() {
            Ok(None)
        } else {
            Ok(Some(plaintext))
        }
    }
}

struct StatefulVmessChunkWriter {
    cipher_method: u8,
    key: Vec<u8>,
    iv: [u8; 16],
    length_mask: LengthMask,
    counter: u16,
}

impl StatefulVmessChunkWriter {
    fn new(cipher_method: u8, key: Vec<u8>, iv: [u8; 16]) -> Self {
        Self {
            cipher_method,
            key,
            iv,
            length_mask: LengthMask::new(&iv),
            counter: 0,
        }
    }

    fn write(&mut self, payload: &[u8]) -> anyhow::Result<Vec<u8>> {
        let chunk = vmess_write_chunk_at(
            self.cipher_method,
            &self.key,
            &self.iv,
            self.counter,
            self.length_mask.next(),
            payload,
        )?;
        self.counter = self.counter.wrapping_add(1);
        Ok(chunk)
    }
}

/// Self-signed TLS cert builder + acceptor
fn make_tls_acceptor() -> anyhow::Result<TlsAcceptor> {
    make_tls_acceptor_with_alpn(&[])
}

fn make_tls_acceptor_with_alpn(alpn_protocols: &[&[u8]]) -> anyhow::Result<TlsAcceptor> {
    let cert = generate_simple_self_signed(vec!["localhost".to_string()])
        .map_err(|e| anyhow!("rcgen: {e}"))?;
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()));
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let versions: Vec<&'static SupportedProtocolVersion> =
        vec![&rustls::version::TLS13, &rustls::version::TLS12];
    let mut server_config = ServerConfig::builder_with_provider(provider.into())
        .with_protocol_versions(&versions)
        .map_err(|e| anyhow!("tls versions: {e}"))?
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .map_err(|e| anyhow!("tls cert: {e}"))?;
    server_config.alpn_protocols = alpn_protocols
        .iter()
        .map(|protocol| protocol.to_vec())
        .collect();
    Ok(TlsAcceptor::from(Arc::new(server_config)))
}

async fn read_and_assert_trojan_connect<R>(
    reader: &mut R,
    password: &str,
    expected_destination: &Destination,
) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut password_hash = [0u8; 56];
    reader.read_exact(&mut password_hash).await?;
    let expected_hash = hex_lower(&Sha224::digest(password.as_bytes()));
    assert_eq!(password_hash.as_slice(), expected_hash.as_bytes());

    let mut separator = [0u8; 2];
    reader.read_exact(&mut separator).await?;
    assert_eq!(&separator, b"\r\n");

    let mut command = [0u8; 1];
    reader.read_exact(&mut command).await?;
    assert_eq!(command[0], 0x01, "Trojan cmd should be CONNECT=1");

    let mut address_type = [0u8; 1];
    reader.read_exact(&mut address_type).await?;
    let host = match address_type[0] {
        0x01 => {
            let mut address = [0u8; 4];
            reader.read_exact(&mut address).await?;
            std::net::Ipv4Addr::from(address).to_string()
        }
        0x03 => {
            let mut length = [0u8; 1];
            reader.read_exact(&mut length).await?;
            let mut domain = vec![0u8; length[0] as usize];
            reader.read_exact(&mut domain).await?;
            String::from_utf8(domain)?
        }
        0x04 => {
            let mut address = [0u8; 16];
            reader.read_exact(&mut address).await?;
            std::net::Ipv6Addr::from(address).to_string()
        }
        other => return Err(anyhow!("unsupported Trojan address type {other}")),
    };
    let mut port = [0u8; 2];
    reader.read_exact(&mut port).await?;
    let port = u16::from_be_bytes(port);
    reader.read_exact(&mut separator).await?;
    assert_eq!(&separator, b"\r\n");
    assert_eq!(host, expected_destination.host);
    assert_eq!(port, expected_destination.port);
    Ok(())
}

fn assert_trojan_udp_associate_request(request: &[u8], password: &str) -> anyhow::Result<()> {
    if request.len() != 68 {
        return Err(anyhow!(
            "unexpected Trojan UDP associate request length {}",
            request.len()
        ));
    }
    let expected_hash = hex_lower(&Sha224::digest(password.as_bytes()));
    assert_eq!(&request[..56], expected_hash.as_bytes());
    assert_eq!(&request[56..58], b"\r\n");
    assert_eq!(request[58], 0x03);
    assert_eq!(request[59], 0x01);
    assert_eq!(&request[60..64], &[0, 0, 0, 0]);
    assert_eq!(&request[64..66], &[0, 0]);
    assert_eq!(&request[66..68], b"\r\n");
    Ok(())
}

fn parse_trojan_udp_test_packet(packet: &[u8]) -> anyhow::Result<(Destination, Vec<u8>)> {
    if packet.len() < 1 + 2 + 2 + 2 {
        return Err(anyhow!("Trojan UDP packet is too short"));
    }
    let mut cursor = 0;
    let host = match packet[cursor] {
        0x01 => {
            cursor += 1;
            let address: [u8; 4] = packet
                .get(cursor..cursor + 4)
                .ok_or_else(|| anyhow!("truncated IPv4 address"))?
                .try_into()?;
            cursor += 4;
            std::net::Ipv4Addr::from(address).to_string()
        }
        0x03 => {
            cursor += 1;
            let length = *packet
                .get(cursor)
                .ok_or_else(|| anyhow!("missing domain length"))? as usize;
            cursor += 1;
            let domain = packet
                .get(cursor..cursor + length)
                .ok_or_else(|| anyhow!("truncated domain"))?;
            cursor += length;
            std::str::from_utf8(domain)?.to_string()
        }
        0x04 => {
            cursor += 1;
            let address: [u8; 16] = packet
                .get(cursor..cursor + 16)
                .ok_or_else(|| anyhow!("truncated IPv6 address"))?
                .try_into()?;
            cursor += 16;
            std::net::Ipv6Addr::from(address).to_string()
        }
        other => return Err(anyhow!("unsupported Trojan UDP address type {other}")),
    };
    let port = u16::from_be_bytes(
        packet
            .get(cursor..cursor + 2)
            .ok_or_else(|| anyhow!("missing Trojan UDP port"))?
            .try_into()?,
    );
    cursor += 2;
    let payload_length = u16::from_be_bytes(
        packet
            .get(cursor..cursor + 2)
            .ok_or_else(|| anyhow!("missing Trojan UDP payload length"))?
            .try_into()?,
    ) as usize;
    cursor += 2;
    if packet.get(cursor..cursor + 2) != Some(b"\r\n") {
        return Err(anyhow!("invalid Trojan UDP packet separator"));
    }
    cursor += 2;
    let payload = packet
        .get(cursor..cursor + payload_length)
        .ok_or_else(|| anyhow!("truncated Trojan UDP payload"))?
        .to_vec();
    Ok((Destination::new(host, port), payload))
}

async fn read_trojan_udp_test_packet<R>(reader: &mut R) -> anyhow::Result<(Destination, Vec<u8>)>
where
    R: AsyncRead + Unpin,
{
    let mut address_type = [0u8; 1];
    reader.read_exact(&mut address_type).await?;
    let host = match address_type[0] {
        0x01 => {
            let mut address = [0u8; 4];
            reader.read_exact(&mut address).await?;
            std::net::Ipv4Addr::from(address).to_string()
        }
        0x03 => {
            let mut length = [0u8; 1];
            reader.read_exact(&mut length).await?;
            let mut domain = vec![0u8; length[0] as usize];
            reader.read_exact(&mut domain).await?;
            String::from_utf8(domain)?
        }
        0x04 => {
            let mut address = [0u8; 16];
            reader.read_exact(&mut address).await?;
            std::net::Ipv6Addr::from(address).to_string()
        }
        other => return Err(anyhow!("unsupported Trojan UDP address type {other}")),
    };
    let mut port = [0u8; 2];
    reader.read_exact(&mut port).await?;
    let port = u16::from_be_bytes(port);
    let mut payload_length = [0u8; 2];
    reader.read_exact(&mut payload_length).await?;
    let payload_length = u16::from_be_bytes(payload_length) as usize;
    let mut separator = [0u8; 2];
    reader.read_exact(&mut separator).await?;
    if &separator != b"\r\n" {
        return Err(anyhow!("invalid Trojan UDP packet separator"));
    }
    let mut payload = vec![0u8; payload_length];
    reader.read_exact(&mut payload).await?;
    Ok((Destination::new(host, port), payload))
}

fn build_trojan_udp_test_packet(
    destination: &Destination,
    payload: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let mut packet = Vec::new();
    if let Ok(ip) = destination.host.parse::<std::net::IpAddr>() {
        match ip {
            std::net::IpAddr::V4(ip) => {
                packet.push(0x01);
                packet.extend_from_slice(&ip.octets());
            }
            std::net::IpAddr::V6(ip) => {
                packet.push(0x04);
                packet.extend_from_slice(&ip.octets());
            }
        }
    } else {
        if destination.host.len() > u8::MAX as usize {
            return Err(anyhow!("Trojan UDP test domain is too long"));
        }
        packet.push(0x03);
        packet.push(destination.host.len() as u8);
        packet.extend_from_slice(destination.host.as_bytes());
    }
    packet.extend_from_slice(&destination.port.to_be_bytes());
    packet.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    packet.extend_from_slice(b"\r\n");
    packet.extend_from_slice(payload);
    Ok(packet)
}

// ============================================================
// Trojan tests
// ============================================================

fn trojan_test_config(
    name: &str,
    port: u16,
    password: &str,
    network: Option<&str>,
) -> OutboundConfig {
    OutboundConfig::Trojan {
        name: name.to_string(),
        server: "127.0.0.1".to_string(),
        port,
        password: password.to_string(),
        sni: Some("localhost".to_string()),
        skip_cert_verify: true,
        network: network.map(ToString::to_string),
        ws_path: None,
        ws_host: None,
        grpc_service_name: None,
        transport_headers: BTreeMap::new(),
        alpn: Vec::new(),
    }
}

/// Trojan TCP real dial: mock TLS server 接收 client 请求，验证 hex(SHA224) 头解析正确。
#[tokio::test]
async fn trojan_tcp_real_dial() -> anyhow::Result<()> {
    let acceptor = make_tls_acceptor()?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let listen_addr = listener.local_addr()?;
    let password = "trojan-secret-pass";

    let destination = Destination::new("target.example", 443);

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await?;
        let mut stream = acceptor.accept(stream).await?;

        // Trojan request: hex(SHA224(password)) + "\r\n" + cmd(1) + socks5-atyp + addr + port + "\r\n"
        let mut buf = Vec::new();
        let mut tmp = [0u8; 512];
        loop {
            let n = stream.read(&mut tmp).await?;
            if n == 0 {
                return Err(anyhow!("server got EOF before complete request"));
            }
            buf.extend_from_slice(&tmp[..n]);
            // Minimum: 56 (hex) + 2 (crlf) + 1 (cmd) + 1 (atyp) + 4 (ipv4) + 2 (port) + 2 (crlf) = 68
            if buf.len() >= 68 && buf.ends_with(b"\r\n") && buf[56..58] == *b"\r\n" {
                break;
            }
        }

        let expected_hash = hex_lower(&Sha224::digest(password.as_bytes()));
        assert_eq!(
            std::str::from_utf8(&buf[..56]).unwrap(),
            expected_hash,
            "Trojan hex(SHA224) header mismatch"
        );
        assert_eq!(buf[56..58], *b"\r\n", "Trojan missing CRLF after hash");
        assert_eq!(buf[58], 0x01, "Trojan cmd should be CONNECT=1");
        assert_eq!(buf[59], 0x03, "Trojan atyp should be DOMAIN=3");
        let domain_len = buf[60] as usize;
        let domain_end = 61 + domain_len;
        let domain = std::str::from_utf8(&buf[61..domain_end])
            .map_err(|e| anyhow!("domain utf8: {e}"))?
            .to_string();
        assert_eq!(domain, "target.example");
        let port = u16::from_be_bytes([buf[domain_end], buf[domain_end + 1]]);
        assert_eq!(port, 443);
        assert_eq!(&buf[domain_end + 2..domain_end + 4], b"\r\n");

        stream.write_all(b"pong").await?;
        stream.flush().await?;
        Ok::<_, anyhow::Error>(())
    });

    let outbounds = build_outbounds(
        &[OutboundConfig::Trojan {
            name: "trojan-tcp-test".to_string(),
            server: "127.0.0.1".to_string(),
            port: listen_addr.port(),
            password: password.to_string(),
            sni: Some("localhost".to_string()),
            skip_cert_verify: true,
            network: None,
            ws_path: None,
            ws_host: None,
            grpc_service_name: None,
            transport_headers: BTreeMap::new(),
            alpn: Vec::new(),
        }],
        None,
    )?;
    let outbound = outbounds
        .get("trojan-tcp-test")
        .ok_or_else(|| anyhow!("trojan outbound not built"))?;

    let mut stream =
        timeout(Duration::from_secs(3), outbound.connect(&destination, 3000)).await??;

    let mut response = [0u8; 4];
    timeout(Duration::from_secs(3), stream.read_exact(&mut response)).await??;
    assert_eq!(&response, b"pong");
    let _ = timeout(Duration::from_secs(3), server).await??;
    Ok(())
}

#[tokio::test]
async fn trojan_tcp_relays_large_stream_and_propagates_half_close() -> anyhow::Result<()> {
    const PAYLOAD_LEN: usize = 96 * 1024;

    let acceptor = make_tls_acceptor_with_alpn(&[b"h2", b"http/1.1"])?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let listen_addr = listener.local_addr()?;
    let password = "trojan-large-stream-pass";
    let destination = Destination::new("large.example", 443);
    let payload = (0..PAYLOAD_LEN)
        .map(|index| (index % 251) as u8)
        .collect::<Vec<_>>();
    let response = payload.iter().map(|byte| byte ^ 0x5a).collect::<Vec<_>>();
    let server_payload = payload.clone();
    let server_response = response.clone();
    let server_destination = destination.clone();

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await?;
        let mut stream = acceptor.accept(stream).await?;
        assert_eq!(stream.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
        read_and_assert_trojan_connect(&mut stream, password, &server_destination).await?;

        let mut upload = vec![0u8; PAYLOAD_LEN];
        stream.read_exact(&mut upload).await?;
        assert_eq!(upload, server_payload);
        for chunk in server_response.chunks(12 * 1024) {
            stream.write_all(chunk).await?;
        }
        stream.flush().await?;

        let mut after_close = [0u8; 1];
        assert_eq!(stream.read(&mut after_close).await?, 0);
        anyhow::Ok(())
    });

    let mut config = trojan_test_config(
        "trojan-large-stream",
        listen_addr.port(),
        password,
        Some("   "),
    );
    if let OutboundConfig::Trojan { sni, .. } = &mut config {
        *sni = Some("   ".to_string());
    }
    let outbounds = build_outbounds(&[config], None)?;
    let mut stream = outbounds
        .get("trojan-large-stream")
        .ok_or_else(|| anyhow!("large-stream Trojan outbound not built"))?
        .connect(&destination, 3000)
        .await?;
    stream.write_all(&payload).await?;
    stream.flush().await?;
    let mut actual = vec![0u8; PAYLOAD_LEN];
    timeout(Duration::from_secs(3), stream.read_exact(&mut actual)).await??;
    assert_eq!(actual, response);
    stream.shutdown().await?;
    timeout(Duration::from_secs(3), server).await???;
    Ok(())
}

#[tokio::test]
async fn trojan_wrong_password_is_rejected_by_server() -> anyhow::Result<()> {
    let acceptor = make_tls_acceptor()?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let listen_addr = listener.local_addr()?;
    let expected_password = "trojan-correct-password";

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await?;
        let mut stream = acceptor.accept(stream).await?;
        let mut password_hash = [0u8; 56];
        stream.read_exact(&mut password_hash).await?;
        let expected_hash = hex_lower(&Sha224::digest(expected_password.as_bytes()));
        assert_ne!(password_hash.as_slice(), expected_hash.as_bytes());
        stream.shutdown().await?;
        anyhow::Ok(())
    });

    let outbounds = build_outbounds(
        &[trojan_test_config(
            "trojan-wrong-password",
            listen_addr.port(),
            "trojan-wrong-password",
            None,
        )],
        None,
    )?;
    let mut stream = outbounds
        .get("trojan-wrong-password")
        .ok_or_else(|| anyhow!("wrong-password Trojan outbound not built"))?
        .connect(&Destination::new("target.example", 443), 3000)
        .await?;
    let mut response = [0u8; 1];
    let count = timeout(Duration::from_secs(3), stream.read(&mut response)).await??;
    assert_eq!(count, 0);
    timeout(Duration::from_secs(3), server).await???;
    Ok(())
}

#[tokio::test]
async fn trojan_invalid_configuration_is_rejected_before_dial() -> anyhow::Result<()> {
    for (name, password, network, expected) in [
        (
            "trojan-empty-password",
            "",
            None,
            "password must not be empty",
        ),
        (
            "trojan-unknown-network",
            "password",
            Some("not-a-network"),
            "unsupported trojan network",
        ),
    ] {
        let outbounds = build_outbounds(&[trojan_test_config(name, 1, password, network)], None)?;
        let outbound = outbounds
            .get(name)
            .ok_or_else(|| anyhow!("invalid-config Trojan outbound not built"))?;
        let capability = outbound.capability();
        assert!(!capability.tcp_supported);
        assert!(!capability.udp_supported);
        assert!(capability
            .limitations
            .iter()
            .any(|value| value.contains(expected)));
        let error = match outbound
            .connect(&Destination::new("target.example", 443), 100)
            .await
        {
            Ok(_) => return Err(anyhow!("invalid Trojan configuration dialed")),
            Err(error) => error,
        };
        assert!(error.to_string().contains(expected));
    }
    Ok(())
}

#[tokio::test]
async fn trojan_oversized_udp_is_rejected_before_dial() -> anyhow::Result<()> {
    let outbounds = build_outbounds(
        &[trojan_test_config("trojan-large-udp", 1, "password", None)],
        None,
    )?;
    let error = outbounds
        .get("trojan-large-udp")
        .ok_or_else(|| anyhow!("large-UDP Trojan outbound not built"))?
        .udp_exchange(&Destination::new("udp.example", 443), &[0u8; 8193], 100)
        .await
        .expect_err("oversized Trojan UDP unexpectedly dialed");
    assert!(error.to_string().contains("exceeds 8192"));
    Ok(())
}

/// Trojan over TLS + WebSocket transport.
#[tokio::test]
async fn trojan_ws_transport_real_dial() -> anyhow::Result<()> {
    let acceptor = make_tls_acceptor_with_alpn(&[b"http/1.1"])?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let listen_addr = listener.local_addr()?;
    let destination = Destination::new("target.example", 443);
    let expected_destination = destination.clone();
    let password = "trojan-ws-secret";

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await?;
        let mut stream = acceptor.accept(stream).await?;
        assert_eq!(
            stream.get_ref().1.alpn_protocol(),
            Some(b"http/1.1".as_slice())
        );

        let mut request = Vec::new();
        let mut buf = [0u8; 512];
        while find_http_header_end(&request).is_none() {
            let count = stream.read(&mut buf).await?;
            if count == 0 {
                return Err(anyhow!("websocket request ended before headers"));
            }
            request.extend_from_slice(&buf[..count]);
        }
        let text = std::str::from_utf8(&request)?;
        assert!(text.starts_with("GET /trojan-ws HTTP/1.1\r\n"));
        assert!(text
            .lines()
            .any(|line| line.eq_ignore_ascii_case("Host: cdn.example.com")));
        assert!(text
            .lines()
            .any(|line| line.eq_ignore_ascii_case("X-Supercore-Test: websocket")));
        let websocket_key = text
            .lines()
            .find_map(|line| {
                line.split_once(':').and_then(|(name, value)| {
                    name.eq_ignore_ascii_case("Sec-WebSocket-Key")
                        .then(|| value.trim().to_string())
                })
            })
            .ok_or_else(|| anyhow!("missing Sec-WebSocket-Key"))?;
        let accept = websocket_accept_key(&websocket_key);
        let response = format!(
            "HTTP/1.1 101 Switching Protocols\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Accept: {accept}\r\n\
             \r\n"
        );
        stream.write_all(response.as_bytes()).await?;
        stream.flush().await?;

        let frame = read_websocket_binary_frame(&mut stream).await?;
        read_and_assert_trojan_connect(&mut &frame[..], password, &expected_destination).await?;
        let response = build_websocket_binary_frame(b"pong");
        stream.write_all(&response).await?;
        stream.flush().await?;
        Ok::<_, anyhow::Error>(())
    });

    let outbounds = build_outbounds(
        &[OutboundConfig::Trojan {
            name: "trojan-ws-test".to_string(),
            server: "127.0.0.1".to_string(),
            port: listen_addr.port(),
            password: password.to_string(),
            sni: Some("localhost".to_string()),
            skip_cert_verify: true,
            network: Some("ws".to_string()),
            ws_path: Some("/trojan-ws".to_string()),
            ws_host: Some("cdn.example.com".to_string()),
            grpc_service_name: None,
            transport_headers: BTreeMap::from([(
                "X-Supercore-Test".to_string(),
                "websocket".to_string(),
            )]),
            alpn: vec!["http/1.1".to_string()],
        }],
        None,
    )?;
    let outbound = outbounds.get("trojan-ws-test").unwrap();
    let mut stream =
        timeout(Duration::from_secs(3), outbound.connect(&destination, 3000)).await??;
    let mut response = [0u8; 4];
    timeout(Duration::from_secs(3), stream.read_exact(&mut response)).await??;
    assert_eq!(&response, b"pong");
    timeout(Duration::from_secs(3), server).await???;
    Ok(())
}

/// Trojan over TLS + gRPC transport.
#[tokio::test]
async fn trojan_grpc_transport_real_dial() -> anyhow::Result<()> {
    let acceptor = make_tls_acceptor_with_alpn(&[b"h2"])?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let listen_addr = listener.local_addr()?;
    let destination = Destination::new("target.example", 443);
    let expected_destination = destination.clone();
    let password = "trojan-grpc-secret";

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await?;
        let stream = acceptor.accept(stream).await?;
        assert_eq!(stream.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
        let mut h2 = h2_server_handshake(stream).await?;
        let (request, mut respond) = h2
            .accept()
            .await
            .ok_or_else(|| anyhow!("no h2 request"))??;
        let handler = tokio::spawn(async move {
            assert_eq!(request.method(), http::Method::POST);
            assert_eq!(request.uri().path(), "/trojan-grpc/Tun");
            assert_eq!(
                request
                    .headers()
                    .get(http::header::CONTENT_TYPE)
                    .map(|value| value.to_str().unwrap_or("")),
                Some("application/grpc")
            );
            let mut body = GrpcBodyReader::new(request.into_body());
            read_and_assert_trojan_connect(&mut body, password, &expected_destination).await?;

            let response: Response<()> = Response::builder()
                .status(200)
                .header(http::header::CONTENT_TYPE, "application/grpc")
                .body(())?;
            let mut send = respond.send_response(response, false)?;
            send.send_data(Bytes::from(grpc_wrap(b"pong")), false)?;
            Ok::<_, anyhow::Error>(())
        });
        let driver = tokio::spawn(async move { while h2.accept().await.is_some() {} });
        handler.await??;
        driver.abort();
        Ok::<_, anyhow::Error>(())
    });

    let outbounds = build_outbounds(
        &[OutboundConfig::Trojan {
            name: "trojan-grpc-test".to_string(),
            server: "127.0.0.1".to_string(),
            port: listen_addr.port(),
            password: password.to_string(),
            sni: Some("localhost".to_string()),
            skip_cert_verify: true,
            network: Some("grpc".to_string()),
            ws_path: None,
            ws_host: Some("cdn.example.com".to_string()),
            grpc_service_name: Some("trojan-grpc".to_string()),
            transport_headers: BTreeMap::new(),
            alpn: vec!["h2".to_string()],
        }],
        None,
    )?;
    let outbound = outbounds.get("trojan-grpc-test").unwrap();
    let mut stream =
        timeout(Duration::from_secs(3), outbound.connect(&destination, 3000)).await??;
    let mut response = [0u8; 4];
    timeout(Duration::from_secs(3), stream.read_exact(&mut response)).await??;
    assert_eq!(&response, b"pong");
    timeout(Duration::from_secs(3), server).await???;
    Ok(())
}

#[tokio::test]
async fn trojan_grpc_surfaces_nonzero_trailer_status() -> anyhow::Result<()> {
    let acceptor = make_tls_acceptor_with_alpn(&[b"h2"])?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let listen_addr = listener.local_addr()?;
    let destination = Destination::new("target.example", 443);
    let expected_destination = destination.clone();
    let password = "trojan-grpc-reject-secret";

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await?;
        let stream = acceptor.accept(stream).await?;
        let mut h2 = h2_server_handshake(stream).await?;
        let (request, mut respond) = h2
            .accept()
            .await
            .ok_or_else(|| anyhow!("no h2 request"))??;
        let handler = tokio::spawn(async move {
            let mut body = GrpcBodyReader::new(request.into_body());
            read_and_assert_trojan_connect(&mut body, password, &expected_destination).await?;

            let response: Response<()> = Response::builder()
                .status(200)
                .header(http::header::CONTENT_TYPE, "application/grpc")
                .body(())?;
            let mut send = respond.send_response(response, false)?;
            let mut trailers = http::HeaderMap::new();
            trailers.insert("grpc-status", http::HeaderValue::from_static("7"));
            trailers.insert(
                "grpc-message",
                http::HeaderValue::from_static("permission denied"),
            );
            send.send_trailers(trailers)?;
            Ok::<_, anyhow::Error>(())
        });
        let driver = tokio::spawn(async move { while h2.accept().await.is_some() {} });
        handler.await??;
        driver.abort();
        Ok::<_, anyhow::Error>(())
    });

    let outbounds = build_outbounds(
        &[OutboundConfig::Trojan {
            name: "trojan-grpc-reject-test".to_string(),
            server: "127.0.0.1".to_string(),
            port: listen_addr.port(),
            password: password.to_string(),
            sni: Some("localhost".to_string()),
            skip_cert_verify: true,
            network: Some("grpc".to_string()),
            ws_path: None,
            ws_host: Some("cdn.example.com".to_string()),
            grpc_service_name: Some("trojan-grpc".to_string()),
            transport_headers: BTreeMap::new(),
            alpn: vec!["h2".to_string()],
        }],
        None,
    )?;
    let outbound = outbounds.get("trojan-grpc-reject-test").unwrap();
    let mut stream = outbound.connect(&destination, 3000).await?;
    let mut response = [0u8; 1];
    let error = stream
        .read(&mut response)
        .await
        .expect_err("nonzero grpc-status must fail the tunnel");
    assert!(error.to_string().contains("grpc-status 7"));
    assert!(error.to_string().contains("permission denied"));
    timeout(Duration::from_secs(3), server).await???;
    Ok(())
}

/// Trojan over TLS + raw HTTP/2 transport.
#[tokio::test]
async fn trojan_h2_transport_real_dial() -> anyhow::Result<()> {
    let acceptor = make_tls_acceptor_with_alpn(&[b"h2"])?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let listen_addr = listener.local_addr()?;
    let destination = Destination::new("target.example", 443);
    let expected_destination = destination.clone();
    let password = "trojan-h2-secret";

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await?;
        let stream = acceptor.accept(stream).await?;
        assert_eq!(stream.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
        let mut h2 = h2_server_handshake(stream).await?;
        let (request, mut respond) = h2
            .accept()
            .await
            .ok_or_else(|| anyhow!("no h2 request"))??;
        let handler = tokio::spawn(async move {
            assert_eq!(request.method(), http::Method::PUT);
            assert_eq!(request.uri().path(), "/trojan-h2");
            let mut body = H2BodyReader::new(request.into_body());
            read_and_assert_trojan_connect(&mut body, password, &expected_destination).await?;

            let response: Response<()> = Response::builder().status(200).body(())?;
            let mut send = respond.send_response(response, false)?;
            send.send_data(Bytes::from_static(b"pong"), false)?;
            Ok::<_, anyhow::Error>(())
        });
        let driver = tokio::spawn(async move { while h2.accept().await.is_some() {} });
        handler.await??;
        driver.abort();
        Ok::<_, anyhow::Error>(())
    });

    let outbounds = build_outbounds(
        &[OutboundConfig::Trojan {
            name: "trojan-h2-test".to_string(),
            server: "127.0.0.1".to_string(),
            port: listen_addr.port(),
            password: password.to_string(),
            sni: Some("localhost".to_string()),
            skip_cert_verify: true,
            network: Some("h2".to_string()),
            ws_path: Some("/trojan-h2".to_string()),
            ws_host: Some("cdn.example.com".to_string()),
            grpc_service_name: None,
            transport_headers: BTreeMap::new(),
            alpn: vec!["h2".to_string()],
        }],
        None,
    )?;
    let outbound = outbounds.get("trojan-h2-test").unwrap();
    let mut stream =
        timeout(Duration::from_secs(3), outbound.connect(&destination, 3000)).await??;
    let mut response = [0u8; 4];
    timeout(Duration::from_secs(3), stream.read_exact(&mut response)).await??;
    assert_eq!(&response, b"pong");
    timeout(Duration::from_secs(3), server).await???;
    Ok(())
}

/// Trojan over TLS + HTTP/1.1 Upgrade transport.
#[tokio::test]
async fn trojan_http_upgrade_transport_real_dial() -> anyhow::Result<()> {
    let acceptor = make_tls_acceptor_with_alpn(&[b"http/1.1"])?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let listen_addr = listener.local_addr()?;
    let destination = Destination::new("target.example", 443);
    let expected_destination = destination.clone();
    let password = "trojan-http-upgrade-secret";

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await?;
        let mut stream = acceptor.accept(stream).await?;
        assert_eq!(
            stream.get_ref().1.alpn_protocol(),
            Some(b"http/1.1".as_slice())
        );

        let mut request = Vec::new();
        let mut buffer = [0u8; 512];
        while find_http_header_end(&request).is_none() {
            let count = stream.read(&mut buffer).await?;
            if count == 0 {
                return Err(anyhow!("http upgrade request ended before headers"));
            }
            request.extend_from_slice(&buffer[..count]);
        }
        let text = std::str::from_utf8(&request)?;
        assert!(text.starts_with("GET /trojan-upgrade HTTP/1.1\r\n"));
        assert!(text
            .lines()
            .any(|line| line.eq_ignore_ascii_case("Host: cdn.example.com")));
        assert!(text
            .lines()
            .any(|line| line.eq_ignore_ascii_case("Connection: Upgrade")));
        assert!(text
            .lines()
            .any(|line| line.eq_ignore_ascii_case("Upgrade: websocket")));
        assert!(text
            .lines()
            .any(|line| line.eq_ignore_ascii_case("X-Supercore-Test: httpupgrade")));
        stream
            .write_all(
                b"HTTP/1.1 101 Switching Protocols\r\n\
                  Connection: Upgrade\r\n\
                  Upgrade: websocket\r\n\
                  \r\n",
            )
            .await?;
        stream.flush().await?;

        read_and_assert_trojan_connect(&mut stream, password, &expected_destination).await?;
        stream.write_all(b"pong").await?;
        stream.flush().await?;
        Ok::<_, anyhow::Error>(())
    });

    let outbounds = build_outbounds(
        &[OutboundConfig::Trojan {
            name: "trojan-http-upgrade-test".to_string(),
            server: "127.0.0.1".to_string(),
            port: listen_addr.port(),
            password: password.to_string(),
            sni: Some("localhost".to_string()),
            skip_cert_verify: true,
            network: Some("httpupgrade".to_string()),
            ws_path: Some("/trojan-upgrade".to_string()),
            ws_host: Some("cdn.example.com".to_string()),
            grpc_service_name: None,
            transport_headers: BTreeMap::from([(
                "X-Supercore-Test".to_string(),
                "httpupgrade".to_string(),
            )]),
            alpn: vec!["http/1.1".to_string()],
        }],
        None,
    )?;
    let outbound = outbounds.get("trojan-http-upgrade-test").unwrap();
    let mut stream =
        timeout(Duration::from_secs(3), outbound.connect(&destination, 3000)).await??;
    let mut response = [0u8; 4];
    timeout(Duration::from_secs(3), stream.read_exact(&mut response)).await??;
    assert_eq!(&response, b"pong");
    timeout(Duration::from_secs(3), server).await???;
    Ok(())
}

#[tokio::test]
async fn trojan_http_upgrade_rejects_non_switching_response() -> anyhow::Result<()> {
    let acceptor = make_tls_acceptor_with_alpn(&[b"http/1.1"])?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let listen_addr = listener.local_addr()?;

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await?;
        let mut stream = acceptor.accept(stream).await?;
        let mut request = Vec::new();
        let mut buffer = [0u8; 512];
        while find_http_header_end(&request).is_none() {
            let count = stream.read(&mut buffer).await?;
            if count == 0 {
                return Err(anyhow!("http upgrade request ended before headers"));
            }
            request.extend_from_slice(&buffer[..count]);
        }
        stream
            .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            .await?;
        stream.flush().await?;
        Ok::<_, anyhow::Error>(())
    });

    let outbounds = build_outbounds(
        &[OutboundConfig::Trojan {
            name: "trojan-http-upgrade-reject-test".to_string(),
            server: "127.0.0.1".to_string(),
            port: listen_addr.port(),
            password: "secret".to_string(),
            sni: Some("localhost".to_string()),
            skip_cert_verify: true,
            network: Some("httpupgrade".to_string()),
            ws_path: Some("/trojan-upgrade".to_string()),
            ws_host: Some("cdn.example.com".to_string()),
            grpc_service_name: None,
            transport_headers: BTreeMap::new(),
            alpn: vec!["http/1.1".to_string()],
        }],
        None,
    )?;
    let outbound = outbounds.get("trojan-http-upgrade-reject-test").unwrap();
    let error = match outbound
        .connect(&Destination::new("target.example", 443), 3000)
        .await
    {
        Ok(_) => return Err(anyhow!("HTTPUpgrade accepted a non-101 response")),
        Err(error) => error,
    };
    assert!(error.to_string().contains("403 Forbidden"));
    timeout(Duration::from_secs(3), server).await???;
    Ok(())
}

#[tokio::test]
async fn trojan_rejects_untrusted_tls_certificate() -> anyhow::Result<()> {
    let acceptor = make_tls_acceptor()?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let listen_addr = listener.local_addr()?;

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await?;
        let result = acceptor.accept(stream).await;
        assert!(
            result.is_err(),
            "client must abort the untrusted TLS handshake"
        );
        Ok::<_, anyhow::Error>(())
    });

    let outbounds = build_outbounds(
        &[OutboundConfig::Trojan {
            name: "trojan-untrusted-tls-test".to_string(),
            server: "127.0.0.1".to_string(),
            port: listen_addr.port(),
            password: "secret".to_string(),
            sni: Some("localhost".to_string()),
            skip_cert_verify: false,
            network: None,
            ws_path: None,
            ws_host: None,
            grpc_service_name: None,
            transport_headers: BTreeMap::new(),
            alpn: Vec::new(),
        }],
        None,
    )?;
    let outbound = outbounds.get("trojan-untrusted-tls-test").unwrap();
    let error = match outbound
        .connect(&Destination::new("target.example", 443), 3000)
        .await
    {
        Ok(_) => return Err(anyhow!("self-signed Trojan certificate was accepted")),
        Err(error) => error,
    };
    assert!(error.to_string().contains("trojan tls handshake failed"));
    timeout(Duration::from_secs(3), server).await???;
    Ok(())
}

#[tokio::test]
async fn trojan_tls_handshake_respects_timeout() -> anyhow::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let listen_addr = listener.local_addr()?;
    let server = tokio::spawn(async move {
        let (_stream, _) = listener.accept().await?;
        tokio::time::sleep(Duration::from_secs(1)).await;
        Ok::<_, anyhow::Error>(())
    });

    let outbounds = build_outbounds(
        &[OutboundConfig::Trojan {
            name: "trojan-timeout-test".to_string(),
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
        }],
        None,
    )?;
    let outbound = outbounds.get("trojan-timeout-test").unwrap();
    let error = match outbound
        .connect(&Destination::new("target.example", 443), 50)
        .await
    {
        Ok(_) => return Err(anyhow!("stalled Trojan TLS handshake did not time out")),
        Err(error) => error,
    };
    assert!(
        error.to_string().contains("trojan tls handshake timed out"),
        "unexpected timeout error: {error:#}"
    );
    server.abort();
    Ok(())
}

/// Trojan UDP: UDP 包通过 TLS-over-TCP tunnel 中转。
/// mock server 接收 UDP-associate 请求，然后接收 UDP packet，回包。
#[tokio::test]
async fn trojan_udp_real_dial() -> anyhow::Result<()> {
    let acceptor = make_tls_acceptor()?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let listen_addr = listener.local_addr()?;
    let password = "udp-secret";

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await?;
        let mut stream = acceptor.accept(stream).await?;

        // Read Trojan UDP-associate request:
        //   hex(SHA224(pw)) + "\r\n" + 0x03 (UDP_ASSOCIATE) + socks5-dest(0.0.0.0:0) + "\r\n"
        let mut buf = Vec::new();
        let mut tmp = [0u8; 256];
        loop {
            let n = stream.read(&mut tmp).await?;
            if n == 0 {
                return Err(anyhow!("trojan udp: server got EOF"));
            }
            buf.extend_from_slice(&tmp[..n]);
            if buf.len() >= 56 + 2 + 1 + 4 + 2 + 2 && buf.ends_with(b"\r\n") {
                break;
            }
        }
        let expected_hash = hex_lower(&Sha224::digest(password.as_bytes()));
        assert_eq!(
            std::str::from_utf8(&buf[..56]).unwrap(),
            expected_hash,
            "Trojan UDP hash header mismatch"
        );
        assert_eq!(buf[58], 0x03, "Trojan UDP cmd should be UDP_ASSOCIATE=3");

        // Wait for first UDP packet over the TLS tunnel:
        // Trojan UDP packet: atyp(1) + socks5-addr + len(2) + "\r\n" + payload
        let mut atyp = [0u8; 1];
        stream.read_exact(&mut atyp).await?;
        assert_eq!(atyp[0], 0x03, "expected DOMAIN atyp");
        let mut dlen = [0u8; 1];
        stream.read_exact(&mut dlen).await?;
        let mut domain = vec![0u8; dlen[0] as usize];
        stream.read_exact(&mut domain).await?;
        assert_eq!(std::str::from_utf8(&domain).unwrap(), "echo.example");
        let mut port = [0u8; 2];
        stream.read_exact(&mut port).await?;
        assert_eq!(u16::from_be_bytes(port), 7777);
        let mut length = [0u8; 2];
        stream.read_exact(&mut length).await?;
        let payload_len = u16::from_be_bytes(length) as usize;
        let mut crlf = [0u8; 2];
        stream.read_exact(&mut crlf).await?;
        assert_eq!(&crlf, b"\r\n");
        let mut payload = vec![0u8; payload_len];
        stream.read_exact(&mut payload).await?;
        assert_eq!(payload, b"hello-udp");

        // Reply: build a Trojan UDP response packet
        // Format: socks5-addr + payload_len(2) + "\r\n" + payload
        let mut reply = Vec::new();
        reply.push(0x03); // DOMAIN
        reply.push(domain.len() as u8);
        reply.extend_from_slice(&domain);
        reply.extend_from_slice(&port);
        reply.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        reply.extend_from_slice(b"\r\n");
        reply.extend_from_slice(&payload);
        stream.write_all(&reply).await?;
        stream.flush().await?;
        Ok::<_, anyhow::Error>(())
    });

    let outbounds = build_outbounds(
        &[OutboundConfig::Trojan {
            name: "trojan-udp-test".to_string(),
            server: "127.0.0.1".to_string(),
            port: listen_addr.port(),
            password: password.to_string(),
            sni: Some("localhost".to_string()),
            skip_cert_verify: true,
            network: None,
            ws_path: None,
            ws_host: None,
            grpc_service_name: None,
            transport_headers: BTreeMap::new(),
            alpn: Vec::new(),
        }],
        None,
    )?;
    let outbound = outbounds.get("trojan-udp-test").unwrap();

    let destination = Destination::new("echo.example", 7777);
    let response = timeout(
        Duration::from_secs(5),
        outbound.udp_exchange(&destination, b"hello-udp", 3000),
    )
    .await??;
    assert_eq!(response, b"hello-udp");
    let _ = timeout(Duration::from_secs(3), server).await??;
    Ok(())
}

#[tokio::test]
async fn trojan_udp_reuses_idle_tls_session() -> anyhow::Result<()> {
    let acceptor = make_tls_acceptor()?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let listen_addr = listener.local_addr()?;
    let password = "udp-session-reuse-secret";

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await?;
        let mut stream = acceptor.accept(stream).await?;
        let mut associate = [0u8; 68];
        stream.read_exact(&mut associate).await?;
        assert_trojan_udp_associate_request(&associate, password)?;

        for expected in [b"first".as_slice(), b"second".as_slice()] {
            let (destination, payload) = read_trojan_udp_test_packet(&mut stream).await?;
            assert_eq!(payload, expected);
            let reply = build_trojan_udp_test_packet(&destination, &payload)?;
            stream.write_all(&reply).await?;
            stream.flush().await?;
        }
        anyhow::Ok(())
    });

    let outbounds = build_outbounds(
        &[trojan_test_config(
            "trojan-udp-session-reuse",
            listen_addr.port(),
            password,
            None,
        )],
        None,
    )?;
    let outbound = outbounds
        .get("trojan-udp-session-reuse")
        .ok_or_else(|| anyhow!("session-reuse Trojan outbound not built"))?;
    let destination = Destination::new("echo.example", 7777);
    for payload in [b"first".as_slice(), b"second".as_slice()] {
        let response = outbound.udp_exchange(&destination, payload, 3000).await?;
        assert_eq!(response, payload);
    }
    timeout(Duration::from_secs(3), server).await???;
    Ok(())
}

#[tokio::test]
async fn trojan_udp_timeout_evicts_stale_session() -> anyhow::Result<()> {
    let acceptor = make_tls_acceptor()?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let listen_addr = listener.local_addr()?;
    let password = "udp-timeout-eviction-secret";

    let server = tokio::spawn(async move {
        let mut stalled = Vec::new();
        for index in 0..5 {
            let (stream, _) = listener.accept().await?;
            let mut stream = acceptor.accept(stream).await?;
            let mut associate = [0u8; 68];
            stream.read_exact(&mut associate).await?;
            assert_trojan_udp_associate_request(&associate, password)?;
            let (destination, payload) = read_trojan_udp_test_packet(&mut stream).await?;
            if index < 4 {
                stalled.push(stream);
                continue;
            }

            let reply = build_trojan_udp_test_packet(&destination, &payload)?;
            stream.write_all(&reply).await?;
            stream.flush().await?;
        }
        anyhow::Ok(())
    });

    let outbounds = build_outbounds(
        &[trojan_test_config(
            "trojan-udp-timeout-eviction",
            listen_addr.port(),
            password,
            None,
        )],
        None,
    )?;
    let outbound = outbounds
        .get("trojan-udp-timeout-eviction")
        .ok_or_else(|| anyhow!("timeout-eviction Trojan outbound not built"))?;
    let destination = Destination::new("echo.example", 7777);
    for _ in 0..4 {
        let error = outbound
            .udp_exchange(&destination, b"timeout", 30)
            .await
            .expect_err("stalled Trojan UDP exchange unexpectedly succeeded");
        assert!(error.to_string().contains("trojan udp exchange timed out"));
    }

    let response = outbound
        .udp_exchange(&destination, b"recovered", 3000)
        .await?;
    assert_eq!(response, b"recovered");
    timeout(Duration::from_secs(3), server).await???;
    Ok(())
}

#[tokio::test]
async fn trojan_udp_over_ws_real_dial() -> anyhow::Result<()> {
    let acceptor = make_tls_acceptor_with_alpn(&[b"http/1.1"])?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let listen_addr = listener.local_addr()?;
    let password = "udp-over-ws-secret";

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await?;
        let mut stream = acceptor.accept(stream).await?;

        let mut request = Vec::new();
        let mut buffer = [0u8; 512];
        while find_http_header_end(&request).is_none() {
            let count = stream.read(&mut buffer).await?;
            if count == 0 {
                return Err(anyhow!("websocket request ended before headers"));
            }
            request.extend_from_slice(&buffer[..count]);
        }
        let text = std::str::from_utf8(&request)?;
        let websocket_key = text
            .lines()
            .find_map(|line| {
                line.split_once(':').and_then(|(name, value)| {
                    name.eq_ignore_ascii_case("Sec-WebSocket-Key")
                        .then(|| value.trim().to_string())
                })
            })
            .ok_or_else(|| anyhow!("missing Sec-WebSocket-Key"))?;
        let accept = websocket_accept_key(&websocket_key);
        let response = format!(
            "HTTP/1.1 101 Switching Protocols\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Accept: {accept}\r\n\
             \r\n"
        );
        stream.write_all(response.as_bytes()).await?;
        stream.flush().await?;

        let mut incoming = Vec::new();
        while incoming.len() < 68 {
            incoming.extend_from_slice(&read_websocket_binary_frame(&mut stream).await?);
        }
        assert_trojan_udp_associate_request(&incoming[..68], password)?;

        let mut packet = incoming.split_off(68);
        let (destination, payload) = loop {
            match parse_trojan_udp_test_packet(&packet) {
                Ok(parsed) => break parsed,
                Err(_) if packet.len() < 64 * 1024 => {
                    packet.extend_from_slice(&read_websocket_binary_frame(&mut stream).await?);
                }
                Err(error) => return Err(error),
            }
        };
        assert_eq!(destination, Destination::new("echo.example", 7777));
        assert_eq!(payload, b"hello-udp-over-ws");

        let reply = build_trojan_udp_test_packet(&destination, b"echo-over-ws")?;
        stream
            .write_all(&build_websocket_binary_frame(&reply))
            .await?;
        stream.flush().await?;
        Ok::<_, anyhow::Error>(())
    });

    let outbounds = build_outbounds(
        &[OutboundConfig::Trojan {
            name: "trojan-udp-over-ws-test".to_string(),
            server: "127.0.0.1".to_string(),
            port: listen_addr.port(),
            password: password.to_string(),
            sni: Some("localhost".to_string()),
            skip_cert_verify: true,
            network: Some("ws".to_string()),
            ws_path: Some("/trojan-udp".to_string()),
            ws_host: Some("cdn.example.com".to_string()),
            grpc_service_name: None,
            transport_headers: BTreeMap::new(),
            alpn: vec!["http/1.1".to_string()],
        }],
        None,
    )?;
    let outbound = outbounds.get("trojan-udp-over-ws-test").unwrap();
    let destination = Destination::new("echo.example", 7777);
    let response = timeout(
        Duration::from_secs(5),
        outbound.udp_exchange(&destination, b"hello-udp-over-ws", 3000),
    )
    .await??;
    assert_eq!(response, b"echo-over-ws");
    timeout(Duration::from_secs(3), server).await???;
    Ok(())
}

#[tokio::test]
async fn trojan_udp_over_grpc_real_dial() -> anyhow::Result<()> {
    let acceptor = make_tls_acceptor_with_alpn(&[b"h2"])?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let listen_addr = listener.local_addr()?;
    let password = "udp-over-grpc-secret";

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await?;
        let stream = acceptor.accept(stream).await?;
        let mut h2 = h2_server_handshake(stream).await?;
        let (request, mut respond) = h2
            .accept()
            .await
            .ok_or_else(|| anyhow!("no h2 request"))??;
        let handler = tokio::spawn(async move {
            let mut body = GrpcBodyReader::new(request.into_body());
            let mut associate = [0u8; 68];
            body.read_exact(&mut associate).await?;
            assert_trojan_udp_associate_request(&associate, password)?;

            let response: Response<()> = Response::builder()
                .status(200)
                .header(http::header::CONTENT_TYPE, "application/grpc")
                .body(())?;
            let mut send = respond.send_response(response, false)?;

            let (destination, payload) = read_trojan_udp_test_packet(&mut body).await?;
            assert_eq!(destination, Destination::new("echo.example", 7777));
            assert_eq!(payload, b"hello-udp-over-grpc");
            let reply = build_trojan_udp_test_packet(&destination, b"echo-over-grpc")?;
            send.send_data(Bytes::from(grpc_wrap(&reply)), false)?;
            Ok::<_, anyhow::Error>(())
        });
        let driver = tokio::spawn(async move { while h2.accept().await.is_some() {} });
        handler.await??;
        driver.abort();
        Ok::<_, anyhow::Error>(())
    });

    let outbounds = build_outbounds(
        &[OutboundConfig::Trojan {
            name: "trojan-udp-over-grpc-test".to_string(),
            server: "127.0.0.1".to_string(),
            port: listen_addr.port(),
            password: password.to_string(),
            sni: Some("localhost".to_string()),
            skip_cert_verify: true,
            network: Some("grpc".to_string()),
            ws_path: None,
            ws_host: Some("cdn.example.com".to_string()),
            grpc_service_name: Some("trojan-udp".to_string()),
            transport_headers: BTreeMap::new(),
            alpn: vec!["h2".to_string()],
        }],
        None,
    )?;
    let outbound = outbounds.get("trojan-udp-over-grpc-test").unwrap();
    let destination = Destination::new("echo.example", 7777);
    let response = timeout(
        Duration::from_secs(5),
        outbound.udp_exchange(&destination, b"hello-udp-over-grpc", 3000),
    )
    .await??;
    assert_eq!(response, b"echo-over-grpc");
    timeout(Duration::from_secs(3), server).await???;
    Ok(())
}

// ============================================================
// VMess tests
// ============================================================

const TEST_UUID_BYTES: [u8; 16] = [
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
];
const TEST_UUID_STR: &str = "11111111-1111-1111-1111-111111111111";

fn vmess_tcp_test_config(name: &str, port: u16) -> OutboundConfig {
    OutboundConfig::Vmess {
        name: name.to_string(),
        server: "127.0.0.1".to_string(),
        port,
        uuid: TEST_UUID_STR.to_string(),
        alter_id: 0,
        cipher: "auto".to_string(),
        tls: false,
        sni: None,
        skip_cert_verify: false,
        network: None,
        ws_path: None,
        ws_host: None,
        grpc_service_name: None,
        transport_headers: BTreeMap::new(),
        alpn: Vec::new(),
    }
}

async fn serve_vmess_tcp_inner(
    listener: TcpListener,
    expected_cipher: u8,
    expected_dest: (String, u16),
    response_payload: &[u8],
) -> anyhow::Result<()> {
    let (mut stream, _) = listener.accept().await?;
    let request = read_vmess_request(&mut stream, &TEST_UUID_BYTES).await?;
    assert_eq!(
        request.cipher_method, expected_cipher,
        "expected cipher method {expected_cipher}"
    );
    assert_eq!(request.command, 0x01, "expected TCP command");
    assert_eq!(request.destination_host, expected_dest.0);
    assert_eq!(request.destination_port, expected_dest.1);

    // Read first chunk
    let mut chunk_buf = Vec::new();
    let mut tmp = [0u8; 256];
    loop {
        let n = timeout(Duration::from_secs(2), stream.read(&mut tmp)).await??;
        if n == 0 {
            return Err(anyhow!("server got EOF before first chunk"));
        }
        chunk_buf.extend_from_slice(&tmp[..n]);
        // First chunk has 2-byte masked length + body-with-tag (for AES-128-GCM: body + 16 tag)
        // For "ping" plaintext (4 bytes), AEAD produces 20 bytes; total chunk = 22 bytes.
        if chunk_buf.len() >= 2 {
            let masked = u16::from_be_bytes([chunk_buf[0], chunk_buf[1]]);
            let mut m = LengthMask::new(&request.data_iv);
            let first = m.next();
            let body_len = (masked ^ first) as usize;
            let total = 2 + body_len;
            if chunk_buf.len() >= total {
                break;
            }
        }
    }
    let payload = vmess_decrypt_first_chunk(
        request.cipher_method,
        &request.data_key,
        &request.data_iv,
        &chunk_buf,
    )?;
    assert_eq!(payload, b"ping");

    // Send VMess response header
    let response_header_key = vmess_sha256_16(&request.data_key);
    let response_header_iv = vmess_sha256_16(&request.data_iv);
    let response_header = build_vmess_response_header(
        &response_header_key,
        &response_header_iv,
        request.response_authentication,
    )
    .await?;
    stream.write_all(&response_header).await?;

    // Send VMess chunk with "pong"
    // Client's download AEAD state uses response_header_key (sha256(data_key)[:16]) as the key
    // for both AES and chacha methods (chacha applies its own key derivation on top).
    let response_key = match request.cipher_method {
        3 => response_header_key.to_vec(),
        4 => vmess_chacha_key(&response_header_key).to_vec(),
        _ => return Err(anyhow!("unsupported cipher for response")),
    };
    let chunk = vmess_write_chunk(
        request.cipher_method,
        &response_key,
        &response_header_iv,
        &response_header_iv,
        response_payload,
    )?;
    stream.write_all(&chunk).await?;
    stream.flush().await?;
    Ok(())
}

async fn serve_multi_destination_vmess_udp_exchange(
    mut stream: tokio::net::TcpStream,
) -> anyhow::Result<Destination> {
    let request = read_vmess_request(&mut stream, &TEST_UUID_BYTES).await?;
    assert_eq!(request.command, 0x02, "expected UDP command");
    let destination = Destination::new(request.destination_host.clone(), request.destination_port);
    let (expected_payload, response_payload): (&[u8], &[u8]) =
        match destination.authority().as_str() {
            "one.example:1001" => (b"one", b"reply-one"),
            "two.example:2002" => (b"two", b"reply-two"),
            other => return Err(anyhow!("unexpected VMess UDP destination {other}")),
        };
    let payload = read_vmess_first_chunk(
        &mut stream,
        request.cipher_method,
        &request.data_key,
        &request.data_iv,
    )
    .await?;
    assert_eq!(payload, expected_payload);

    let response_header_key = vmess_sha256_16(&request.data_key);
    let response_header_iv = vmess_sha256_16(&request.data_iv);
    stream
        .write_all(
            &build_vmess_response_header(
                &response_header_key,
                &response_header_iv,
                request.response_authentication,
            )
            .await?,
        )
        .await?;
    let response_key = match request.cipher_method {
        4 => vmess_chacha_key(&response_header_key).to_vec(),
        3 => response_header_key.to_vec(),
        _ => return Err(anyhow!("unsupported cipher")),
    };
    stream
        .write_all(&vmess_write_chunk(
            request.cipher_method,
            &response_key,
            &response_header_iv,
            &response_header_iv,
            response_payload,
        )?)
        .await?;
    stream.flush().await?;
    Ok(destination)
}

/// VMess TCP AEAD (alterId=0, default cipher chacha20-poly1305)
#[tokio::test]
async fn vmess_tcp_aead_real_dial() -> anyhow::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let listen_addr = listener.local_addr()?;

    let server = tokio::spawn(async move {
        serve_vmess_tcp_inner(
            listener,
            4, // chacha20-poly1305
            ("target.example".to_string(), 443),
            b"pong",
        )
        .await
    });

    let outbounds = build_outbounds(
        &[OutboundConfig::Vmess {
            name: "vmess-tcp-test".to_string(),
            server: "127.0.0.1".to_string(),
            port: listen_addr.port(),
            uuid: TEST_UUID_STR.to_string(),
            alter_id: 0,
            cipher: "auto".to_string(),
            tls: false,
            sni: None,
            skip_cert_verify: false,
            network: None,
            ws_path: None,
            ws_host: None,
            grpc_service_name: None,
            transport_headers: BTreeMap::new(),
            alpn: Vec::new(),
        }],
        None,
    )?;
    let outbound = outbounds.get("vmess-tcp-test").unwrap();
    let destination = Destination::new("target.example", 443);

    let mut stream =
        timeout(Duration::from_secs(8), outbound.connect(&destination, 8000)).await??;
    stream.write_all(b"ping").await?;
    stream.flush().await?;

    let mut response = [0u8; 4];
    timeout(Duration::from_secs(3), stream.read_exact(&mut response)).await??;
    assert_eq!(&response, b"pong");
    let _ = timeout(Duration::from_secs(3), server).await??;
    Ok(())
}

#[tokio::test]
async fn vmess_large_bidirectional_stream_and_half_close() -> anyhow::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let listen_addr = listener.local_addr()?;
    let upload: Vec<u8> = (0..96 * 1024).map(|index| (index % 251) as u8).collect();
    let download: Vec<u8> = upload.iter().map(|byte| byte ^ 0x5a).collect();
    let expected_upload = upload.clone();
    let expected_download = download.clone();

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let request = read_vmess_request(&mut stream, &TEST_UUID_BYTES).await?;
        let mut reader =
            StatefulVmessChunkReader::new(request.cipher_method, request.data_key, request.data_iv);
        let mut received = Vec::with_capacity(expected_upload.len());
        while received.len() < expected_upload.len() {
            let chunk = reader
                .read(&mut stream)
                .await?
                .ok_or_else(|| anyhow!("VMess upload ended before 96KB"))?;
            received.extend_from_slice(&chunk);
        }
        assert_eq!(received, expected_upload);
        assert!(
            reader.read(&mut stream).await?.is_none(),
            "VMess half-close did not send an authenticated EOF chunk"
        );

        let response_header_key = vmess_sha256_16(&request.data_key);
        let response_header_iv = vmess_sha256_16(&request.data_iv);
        stream
            .write_all(
                &build_vmess_response_header(
                    &response_header_key,
                    &response_header_iv,
                    request.response_authentication,
                )
                .await?,
            )
            .await?;
        let response_key = match request.cipher_method {
            4 => vmess_chacha_key(&response_header_key).to_vec(),
            3 => response_header_key.to_vec(),
            _ => return Err(anyhow!("unsupported cipher")),
        };
        let mut writer =
            StatefulVmessChunkWriter::new(request.cipher_method, response_key, response_header_iv);
        for chunk in expected_download.chunks(8192) {
            stream.write_all(&writer.write(chunk)?).await?;
        }
        stream.write_all(&writer.write(&[])?).await?;
        stream.flush().await?;
        Ok::<_, anyhow::Error>(())
    });

    let outbounds = build_outbounds(
        &[vmess_tcp_test_config(
            "vmess-large-stream-test",
            listen_addr.port(),
        )],
        None,
    )?;
    let outbound = outbounds.get("vmess-large-stream-test").unwrap();
    let mut stream = outbound
        .connect(&Destination::new("large.example", 443), 3000)
        .await?;
    stream.write_all(&upload).await?;
    stream.shutdown().await?;
    let mut response = Vec::new();
    timeout(Duration::from_secs(5), stream.read_to_end(&mut response)).await??;
    assert_eq!(response, download);
    timeout(Duration::from_secs(3), server).await???;
    Ok(())
}

#[tokio::test]
async fn vmess_wrong_uuid_is_rejected_by_peer() -> anyhow::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let listen_addr = listener.local_addr()?;
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let wrong_uuid = [0x22; 16];
        let error = read_vmess_request(&mut stream, &wrong_uuid)
            .await
            .expect_err("VMess request authenticated with the wrong UUID");
        assert!(
            error.to_string().contains("AuthID"),
            "unexpected wrong-UUID error: {error}"
        );
        Ok::<_, anyhow::Error>(())
    });

    let outbounds = build_outbounds(
        &[vmess_tcp_test_config(
            "vmess-wrong-uuid-test",
            listen_addr.port(),
        )],
        None,
    )?;
    let outbound = outbounds.get("vmess-wrong-uuid-test").unwrap();
    let mut stream = outbound
        .connect(&Destination::new("target.example", 443), 3000)
        .await?;
    timeout(Duration::from_secs(3), server).await???;
    let mut byte = [0u8; 1];
    let read = timeout(Duration::from_secs(3), stream.read(&mut byte)).await??;
    assert_eq!(read, 0, "wrong UUID connection did not close");
    Ok(())
}

/// Legacy VMess with a derived alter ID and unmasked chunk lengths.
#[tokio::test]
async fn vmess_legacy_alter_id_real_dial() -> anyhow::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let listen_addr = listener.local_addr()?;

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let request = read_legacy_vmess_request(&mut stream, &TEST_UUID_BYTES, 1).await?;
        assert_eq!(request.cipher_method, 3, "expected AES-128-GCM");
        assert_eq!(request.command, 0x01, "expected TCP command");
        assert_eq!(request.destination_host, "legacy.example");
        assert_eq!(request.destination_port, 8443);

        let payload = read_legacy_vmess_first_chunk(
            &mut stream,
            request.cipher_method,
            &request.data_key,
            &request.data_iv,
        )
        .await?;
        assert_eq!(payload, b"legacy-ping");

        let response_header_key = vmess_md5_16(&request.data_key);
        let response_header_iv = vmess_md5_16(&request.data_iv);
        let response_header = build_legacy_vmess_response_header(
            &response_header_key,
            &response_header_iv,
            request.response_authentication,
        )?;
        stream.write_all(&response_header).await?;
        stream
            .write_all(&vmess_write_unmasked_chunk(
                request.cipher_method,
                &response_header_key,
                &response_header_iv,
                b"legacy-pong",
            )?)
            .await?;
        stream.flush().await?;
        Ok::<_, anyhow::Error>(())
    });

    let outbounds = build_outbounds(
        &[OutboundConfig::Vmess {
            name: "vmess-legacy-test".to_string(),
            server: "127.0.0.1".to_string(),
            port: listen_addr.port(),
            uuid: TEST_UUID_STR.to_string(),
            alter_id: 1,
            cipher: "aes-128-gcm".to_string(),
            tls: false,
            sni: None,
            skip_cert_verify: false,
            network: None,
            ws_path: None,
            ws_host: None,
            grpc_service_name: None,
            transport_headers: BTreeMap::new(),
            alpn: Vec::new(),
        }],
        None,
    )?;
    let outbound = outbounds.get("vmess-legacy-test").unwrap();
    let destination = Destination::new("legacy.example", 8443);
    let mut stream =
        timeout(Duration::from_secs(8), outbound.connect(&destination, 8000)).await??;
    stream.write_all(b"legacy-ping").await?;
    stream.flush().await?;

    let mut response = [0u8; 11];
    timeout(Duration::from_secs(3), stream.read_exact(&mut response)).await??;
    assert_eq!(&response, b"legacy-pong");
    timeout(Duration::from_secs(3), server).await???;
    Ok(())
}

/// VMess alterId=0 explicit: alterId=0 是 VMess AEAD 模式的强制要求，
/// cipher="none" 走无加密 body path。
#[tokio::test]
async fn vmess_alterid_zero_explicit() -> anyhow::Result<()> {
    // alterId=0 + cipher=none: server sees raw TCP body with no AEAD overhead.
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let listen_addr = listener.local_addr()?;

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let request = read_vmess_request(&mut stream, &TEST_UUID_BYTES).await?;
        // alterId is signalled via the options byte (bit 0x08 = no AEAD legacy chunking)
        // and the cipher method byte. cipher="none" => method byte 5.
        assert_eq!(
            request.cipher_method, 5,
            "alterId=0 with cipher=none should yield method byte 5"
        );
        assert_eq!(request.destination_host, "target.example");
        assert_eq!(request.destination_port, 443);

        // cipher=none: first chunk body is plaintext (no 16-byte tag)
        let mut chunk_buf = Vec::new();
        let mut tmp = [0u8; 256];
        loop {
            let n = timeout(Duration::from_secs(2), stream.read(&mut tmp)).await??;
            if n == 0 {
                return Err(anyhow!("got EOF"));
            }
            chunk_buf.extend_from_slice(&tmp[..n]);
            if chunk_buf.len() >= 2 {
                let masked = u16::from_be_bytes([chunk_buf[0], chunk_buf[1]]);
                let mut m = LengthMask::new(&request.data_iv);
                let first = m.next();
                let body_len = (masked ^ first) as usize;
                let total = 2 + body_len;
                if chunk_buf.len() >= total {
                    break;
                }
            }
        }
        // For cipher=none, body_with_tag is just plaintext (no 16-byte tag)
        let masked_len = u16::from_be_bytes([chunk_buf[0], chunk_buf[1]]);
        let mut m = LengthMask::new(&request.data_iv);
        let first = m.next();
        let body_len = (masked_len ^ first) as usize;
        assert_eq!(&chunk_buf[2..2 + body_len], b"ping");

        // Send response header
        let response_header_key = vmess_sha256_16(&request.data_key);
        let response_header_iv = vmess_sha256_16(&request.data_iv);
        let response_header = build_vmess_response_header(
            &response_header_key,
            &response_header_iv,
            request.response_authentication,
        )
        .await?;
        stream.write_all(&response_header).await?;

        // Send response chunk (cipher=none)
        let chunk = vmess_write_chunk(5, &[], &response_header_iv, &response_header_iv, b"pong")?;
        stream.write_all(&chunk).await?;
        stream.flush().await?;
        Ok::<_, anyhow::Error>(())
    });

    let outbounds = build_outbounds(
        &[OutboundConfig::Vmess {
            name: "vmess-alterid-zero-test".to_string(),
            server: "127.0.0.1".to_string(),
            port: listen_addr.port(),
            uuid: TEST_UUID_STR.to_string(),
            alter_id: 0,
            cipher: "none".to_string(),
            tls: false,
            sni: None,
            skip_cert_verify: false,
            network: None,
            ws_path: None,
            ws_host: None,
            grpc_service_name: None,
            transport_headers: BTreeMap::new(),
            alpn: Vec::new(),
        }],
        None,
    )?;
    let outbound = outbounds.get("vmess-alterid-zero-test").unwrap();
    let destination = Destination::new("target.example", 443);
    let mut stream =
        timeout(Duration::from_secs(8), outbound.connect(&destination, 8000)).await??;
    stream.write_all(b"ping").await?;
    stream.flush().await?;

    let mut response = [0u8; 4];
    timeout(Duration::from_secs(3), stream.read_exact(&mut response)).await??;
    assert_eq!(&response, b"pong");
    let _ = timeout(Duration::from_secs(3), server).await??;
    Ok(())
}

/// VMess HTTP/1.1 camouflage sends the request header as the first HTTP body.
#[tokio::test]
async fn vmess_http_camouflage_real_dial() -> anyhow::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let listen_addr = listener.local_addr()?;

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let mut request_bytes = Vec::new();
        let mut buffer = [0u8; 1024];
        let header_end = loop {
            if let Some(header_end) = find_http_header_end(&request_bytes) {
                break header_end;
            }
            let count = stream.read(&mut buffer).await?;
            if count == 0 {
                return Err(anyhow!("http camouflage request ended before headers"));
            }
            request_bytes.extend_from_slice(&buffer[..count]);
        };
        let headers = std::str::from_utf8(&request_bytes[..header_end])?;
        assert!(headers.starts_with("GET /vmess-http HTTP/1.1\r\n"));
        assert!(headers
            .lines()
            .any(|line| line.eq_ignore_ascii_case("Host: cdn.example.com")));
        assert!(headers
            .lines()
            .any(|line| line.eq_ignore_ascii_case("X-Supercore-Test: http")));
        let content_length = headers
            .lines()
            .find_map(|line| {
                line.split_once(':').and_then(|(name, value)| {
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>())
                })
            })
            .transpose()?
            .ok_or_else(|| anyhow!("http camouflage request missing Content-Length"))?;
        while request_bytes.len() < header_end + content_length {
            let count = stream.read(&mut buffer).await?;
            if count == 0 {
                return Err(anyhow!("http camouflage request body was truncated"));
            }
            request_bytes.extend_from_slice(&buffer[..count]);
        }
        let mut request_body = &request_bytes[header_end..header_end + content_length];
        let request = read_vmess_request(&mut request_body, &TEST_UUID_BYTES).await?;
        assert_eq!(request.cipher_method, 3, "expected AES-128-GCM");
        assert_eq!(request.destination_host, "http.example");
        assert_eq!(request.destination_port, 443);

        let response_header_key = vmess_sha256_16(&request.data_key);
        let response_header_iv = vmess_sha256_16(&request.data_iv);
        let response_header = build_vmess_response_header(
            &response_header_key,
            &response_header_iv,
            request.response_authentication,
        )
        .await?;
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .await?;
        stream.write_all(&response_header).await?;
        stream.flush().await?;

        let payload = read_vmess_first_chunk(
            &mut stream,
            request.cipher_method,
            &request.data_key,
            &request.data_iv,
        )
        .await?;
        assert_eq!(payload, b"http-ping");
        stream
            .write_all(&vmess_write_chunk(
                request.cipher_method,
                &response_header_key,
                &response_header_iv,
                &response_header_iv,
                b"http-pong",
            )?)
            .await?;
        stream.flush().await?;
        Ok::<_, anyhow::Error>(())
    });

    let outbounds = build_outbounds(
        &[OutboundConfig::Vmess {
            name: "vmess-http-test".to_string(),
            server: "127.0.0.1".to_string(),
            port: listen_addr.port(),
            uuid: TEST_UUID_STR.to_string(),
            alter_id: 0,
            cipher: "aes-128-gcm".to_string(),
            tls: false,
            sni: None,
            skip_cert_verify: false,
            network: Some("http".to_string()),
            ws_path: Some("/vmess-http".to_string()),
            ws_host: Some("cdn.example.com".to_string()),
            grpc_service_name: None,
            transport_headers: BTreeMap::from([(
                "X-Supercore-Test".to_string(),
                "http".to_string(),
            )]),
            alpn: Vec::new(),
        }],
        None,
    )?;
    let outbound = outbounds.get("vmess-http-test").unwrap();
    let destination = Destination::new("http.example", 443);
    let mut stream =
        timeout(Duration::from_secs(8), outbound.connect(&destination, 8000)).await??;
    stream.write_all(b"http-ping").await?;
    stream.flush().await?;
    let mut response = [0u8; 9];
    timeout(Duration::from_secs(3), stream.read_exact(&mut response)).await??;
    assert_eq!(&response, b"http-pong");
    timeout(Duration::from_secs(3), server).await???;
    Ok(())
}

#[tokio::test]
async fn vmess_http_upgrade_real_dial() -> anyhow::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let listen_addr = listener.local_addr()?;

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let mut headers = Vec::new();
        let mut buffer = [0u8; 512];
        while find_http_header_end(&headers).is_none() {
            let count = stream.read(&mut buffer).await?;
            if count == 0 {
                return Err(anyhow!("vmess HTTPUpgrade ended before headers"));
            }
            headers.extend_from_slice(&buffer[..count]);
        }
        let headers = std::str::from_utf8(&headers)?;
        assert!(headers.starts_with("GET /vmess-upgrade HTTP/1.1\r\n"));
        assert!(headers
            .lines()
            .any(|line| line.eq_ignore_ascii_case("Host: cdn.example.com")));
        assert!(headers
            .lines()
            .any(|line| line.eq_ignore_ascii_case("X-Supercore-Test: httpupgrade")));
        stream
            .write_all(
                b"HTTP/1.1 101 Switching Protocols\r\n\
                  Connection: Upgrade\r\n\
                  Upgrade: websocket\r\n\
                  \r\n",
            )
            .await?;
        stream.flush().await?;

        let request = read_vmess_request(&mut stream, &TEST_UUID_BYTES).await?;
        assert_eq!(request.destination_host, "upgrade.example");
        assert_eq!(request.destination_port, 443);
        let payload = read_vmess_first_chunk(
            &mut stream,
            request.cipher_method,
            &request.data_key,
            &request.data_iv,
        )
        .await?;
        assert_eq!(payload, b"upgrade-ping");

        let response_header_key = vmess_sha256_16(&request.data_key);
        let response_header_iv = vmess_sha256_16(&request.data_iv);
        stream
            .write_all(
                &build_vmess_response_header(
                    &response_header_key,
                    &response_header_iv,
                    request.response_authentication,
                )
                .await?,
            )
            .await?;
        let response_key = vmess_chacha_key(&response_header_key);
        stream
            .write_all(&vmess_write_chunk(
                request.cipher_method,
                &response_key,
                &response_header_iv,
                &response_header_iv,
                b"upgrade-pong",
            )?)
            .await?;
        stream.flush().await?;
        Ok::<_, anyhow::Error>(())
    });

    let outbounds = build_outbounds(
        &[OutboundConfig::Vmess {
            name: "vmess-http-upgrade-test".to_string(),
            server: "127.0.0.1".to_string(),
            port: listen_addr.port(),
            uuid: TEST_UUID_STR.to_string(),
            alter_id: 0,
            cipher: "auto".to_string(),
            tls: false,
            sni: None,
            skip_cert_verify: false,
            network: Some("httpupgrade".to_string()),
            ws_path: Some("/vmess-upgrade".to_string()),
            ws_host: Some("cdn.example.com".to_string()),
            grpc_service_name: None,
            transport_headers: BTreeMap::from([(
                "X-Supercore-Test".to_string(),
                "httpupgrade".to_string(),
            )]),
            alpn: Vec::new(),
        }],
        None,
    )?;
    let outbound = outbounds.get("vmess-http-upgrade-test").unwrap();
    let destination = Destination::new("upgrade.example", 443);
    let mut stream =
        timeout(Duration::from_secs(8), outbound.connect(&destination, 8000)).await??;
    stream.write_all(b"upgrade-ping").await?;
    stream.flush().await?;
    let mut response = [0u8; 12];
    timeout(Duration::from_secs(3), stream.read_exact(&mut response)).await??;
    assert_eq!(&response, b"upgrade-pong");
    timeout(Duration::from_secs(3), server).await???;
    Ok(())
}

/// VMess WS transport (plain WebSocket, no TLS)
#[tokio::test]
async fn vmess_ws_transport_real_dial() -> anyhow::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let listen_addr = listener.local_addr()?;

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;

        // Read HTTP request up to "\r\n\r\n"
        let mut buf = Vec::new();
        let mut tmp = [0u8; 1024];
        loop {
            let n = stream.read(&mut tmp).await?;
            if n == 0 {
                return Err(anyhow!("got EOF during WS upgrade"));
            }
            buf.extend_from_slice(&tmp[..n]);
            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
            if buf.len() > 4096 {
                return Err(anyhow!("WS upgrade request too large"));
            }
        }
        let req_str = std::str::from_utf8(&buf)?;
        assert!(
            req_str.starts_with("GET "),
            "WS upgrade must start with GET, got: {req_str}"
        );
        assert!(
            req_str.to_ascii_lowercase().contains("upgrade: websocket"),
            "WS upgrade missing Upgrade: websocket"
        );
        assert!(
            req_str
                .to_ascii_lowercase()
                .contains("host: cdn.example.com"),
            "WS upgrade missing Host header"
        );
        assert!(
            req_str.contains("/vmess-ws"),
            "WS upgrade path should match configured ws_path"
        );

        // Extract Sec-WebSocket-Key and compute the expected Sec-WebSocket-Accept response.
        let ws_key = req_str
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                if name.eq_ignore_ascii_case("sec-websocket-key") {
                    Some(value.trim().to_string())
                } else {
                    None
                }
            })
            .ok_or_else(|| anyhow!("WS upgrade missing Sec-WebSocket-Key"))?;
        let accept = websocket_accept_key(&ws_key);

        // Send 101 Switching Protocols
        let response = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
        );
        stream.write_all(response.as_bytes()).await?;
        stream.flush().await?;

        // Now read VMess AEAD request frames (wrapped in WebSocket binary frames).
        let vmess_bytes = read_websocket_binary_frame(&mut stream).await?;
        let request = read_vmess_request(&mut &vmess_bytes[..], &TEST_UUID_BYTES).await?;
        assert_eq!(request.destination_host, "target.example");
        assert_eq!(request.destination_port, 443);

        // Read ping chunk (wrapped in WebSocket binary frame)
        let chunk_bytes = read_websocket_binary_frame(&mut stream).await?;
        let payload = vmess_decrypt_first_chunk(
            request.cipher_method,
            &request.data_key,
            &request.data_iv,
            &chunk_bytes,
        )?;
        assert_eq!(payload, b"ping");

        // Send response header (binary frame)
        let response_header_key = vmess_sha256_16(&request.data_key);
        let response_header_iv = vmess_sha256_16(&request.data_iv);
        let response_header = build_vmess_response_header(
            &response_header_key,
            &response_header_iv,
            request.response_authentication,
        )
        .await?;
        let header_frame = build_websocket_binary_frame(&response_header);
        stream.write_all(&header_frame).await?;

        // Send response chunk (binary frame) - client decrypts with response_header_key
        let response_key = match request.cipher_method {
            4 => vmess_chacha_key(&response_header_key).to_vec(),
            3 => response_header_key.to_vec(),
            _ => return Err(anyhow!("unsupported cipher")),
        };
        let chunk = vmess_write_chunk(
            request.cipher_method,
            &response_key,
            &response_header_iv,
            &response_header_iv,
            b"pong",
        )?;
        let chunk_frame = build_websocket_binary_frame(&chunk);
        stream.write_all(&chunk_frame).await?;
        stream.flush().await?;
        Ok::<_, anyhow::Error>(())
    });

    let outbounds = build_outbounds(
        &[OutboundConfig::Vmess {
            name: "vmess-ws-test".to_string(),
            server: "127.0.0.1".to_string(),
            port: listen_addr.port(),
            uuid: TEST_UUID_STR.to_string(),
            alter_id: 0,
            cipher: "auto".to_string(),
            tls: false,
            sni: None,
            skip_cert_verify: false,
            network: Some("ws".to_string()),
            ws_path: Some("/vmess-ws".to_string()),
            ws_host: Some("cdn.example.com".to_string()),
            grpc_service_name: None,
            transport_headers: BTreeMap::new(),
            alpn: Vec::new(),
        }],
        None,
    )?;
    let outbound = outbounds.get("vmess-ws-test").unwrap();
    let destination = Destination::new("target.example", 443);

    let mut stream =
        timeout(Duration::from_secs(8), outbound.connect(&destination, 8000)).await??;
    stream.write_all(b"ping").await?;
    stream.flush().await?;

    let mut response = [0u8; 4];
    timeout(Duration::from_secs(3), stream.read_exact(&mut response)).await??;
    assert_eq!(&response, b"pong");
    let _ = timeout(Duration::from_secs(3), server).await??;
    Ok(())
}

/// VMess gRPC transport (plain HTTP/2, no TLS)
#[tokio::test]
async fn vmess_grpc_transport_real_dial() -> anyhow::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let listen_addr = listener.local_addr()?;

    let server = tokio::spawn(async move {
        let stream = listener.accept().await?.0;
        let mut h2 = h2_server_handshake(stream).await?;
        let (request, mut respond) = h2
            .accept()
            .await
            .ok_or_else(|| anyhow!("no h2 request"))??;
        let handler = tokio::spawn(async move {
            assert_eq!(request.method(), http::Method::POST);
            let path = request.uri().path().to_string();
            assert!(
                path.starts_with("/vmess-grpc/"),
                "expected gRPC service path, got {path}"
            );
            assert_eq!(
                request
                    .headers()
                    .get(http::header::CONTENT_TYPE)
                    .map(|v| v.to_str().unwrap_or("")),
                Some("application/grpc")
            );

            let mut body = GrpcBodyReader::new(request.into_body());
            let request_meta = read_vmess_request(&mut body, &TEST_UUID_BYTES).await?;
            assert_eq!(request_meta.destination_host, "target.example");
            assert_eq!(request_meta.destination_port, 443);

            let response: Response<()> = Response::builder()
                .status(200)
                .header(http::header::CONTENT_TYPE, "application/grpc")
                .body(())
                .map_err(|e| anyhow!("build resp: {e}"))?;
            let mut send = respond.send_response(response, false)?;
            let response_header_key = vmess_sha256_16(&request_meta.data_key);
            let response_header_iv = vmess_sha256_16(&request_meta.data_iv);
            let response_header = build_vmess_response_header(
                &response_header_key,
                &response_header_iv,
                request_meta.response_authentication,
            )
            .await?;
            send.send_data(Bytes::from(grpc_wrap(&response_header)), false)?;

            let ping = read_vmess_first_chunk(
                &mut body,
                request_meta.cipher_method,
                &request_meta.data_key,
                &request_meta.data_iv,
            )
            .await?;
            assert_eq!(ping, b"ping");

            let response_key = match request_meta.cipher_method {
                4 => vmess_chacha_key(&response_header_key).to_vec(),
                3 => response_header_key.to_vec(),
                _ => return Err(anyhow!("unsupported cipher")),
            };
            let chunk = vmess_write_chunk(
                request_meta.cipher_method,
                &response_key,
                &response_header_iv,
                &response_header_iv,
                b"pong",
            )?;
            send.send_data(Bytes::from(grpc_wrap(&chunk)), false)?;
            Ok::<_, anyhow::Error>(())
        });
        let driver = tokio::spawn(async move { while h2.accept().await.is_some() {} });
        handler.await??;
        driver.abort();
        Ok::<_, anyhow::Error>(())
    });

    let outbounds = build_outbounds(
        &[OutboundConfig::Vmess {
            name: "vmess-grpc-test".to_string(),
            server: "127.0.0.1".to_string(),
            port: listen_addr.port(),
            uuid: TEST_UUID_STR.to_string(),
            alter_id: 0,
            cipher: "auto".to_string(),
            tls: false,
            sni: None,
            skip_cert_verify: false,
            network: Some("grpc".to_string()),
            ws_path: None,
            ws_host: Some("cdn.example.com".to_string()),
            grpc_service_name: Some("vmess-grpc".to_string()),
            transport_headers: BTreeMap::new(),
            alpn: Vec::new(),
        }],
        None,
    )?;
    let outbound = outbounds.get("vmess-grpc-test").unwrap();
    let destination = Destination::new("target.example", 443);

    let mut stream =
        timeout(Duration::from_secs(8), outbound.connect(&destination, 8000)).await??;
    stream.write_all(b"ping").await?;
    stream.flush().await?;

    let mut response = [0u8; 4];
    timeout(Duration::from_secs(3), stream.read_exact(&mut response)).await??;
    assert_eq!(&response, b"pong");
    let _ = timeout(Duration::from_secs(3), server).await??;
    Ok(())
}

/// VMess H2 transport (plain HTTP/2 PUT, no TLS)
#[tokio::test]
async fn vmess_h2_transport_real_dial() -> anyhow::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let listen_addr = listener.local_addr()?;

    let server = tokio::spawn(async move {
        let stream = listener.accept().await?.0;
        let mut h2 = h2_server_handshake(stream).await?;
        let (request, mut respond) = h2
            .accept()
            .await
            .ok_or_else(|| anyhow!("no h2 request"))??;
        let handler = tokio::spawn(async move {
            assert_eq!(request.method(), http::Method::PUT);
            assert_eq!(request.uri().path(), "/vmess-h2");

            let mut body = H2BodyReader::new(request.into_body());
            let request_meta = read_vmess_request(&mut body, &TEST_UUID_BYTES).await?;
            assert_eq!(request_meta.destination_host, "target.example");
            assert_eq!(request_meta.destination_port, 443);

            let response: Response<()> = Response::builder().status(200).body(()).unwrap();
            let mut send = respond.send_response(response, false)?;
            let response_header_key = vmess_sha256_16(&request_meta.data_key);
            let response_header_iv = vmess_sha256_16(&request_meta.data_iv);
            let response_header = build_vmess_response_header(
                &response_header_key,
                &response_header_iv,
                request_meta.response_authentication,
            )
            .await?;
            send.send_data(Bytes::from(response_header), false)?;

            let ping = read_vmess_first_chunk(
                &mut body,
                request_meta.cipher_method,
                &request_meta.data_key,
                &request_meta.data_iv,
            )
            .await?;
            assert_eq!(ping, b"ping");

            let response_key = match request_meta.cipher_method {
                4 => vmess_chacha_key(&response_header_key).to_vec(),
                3 => response_header_key.to_vec(),
                _ => return Err(anyhow!("unsupported cipher")),
            };
            let chunk = vmess_write_chunk(
                request_meta.cipher_method,
                &response_key,
                &response_header_iv,
                &response_header_iv,
                b"pong",
            )?;
            send.send_data(Bytes::from(chunk), false)?;
            Ok::<_, anyhow::Error>(())
        });
        let driver = tokio::spawn(async move { while h2.accept().await.is_some() {} });
        handler.await??;
        driver.abort();
        Ok::<_, anyhow::Error>(())
    });

    let outbounds = build_outbounds(
        &[OutboundConfig::Vmess {
            name: "vmess-h2-test".to_string(),
            server: "127.0.0.1".to_string(),
            port: listen_addr.port(),
            uuid: TEST_UUID_STR.to_string(),
            alter_id: 0,
            cipher: "auto".to_string(),
            tls: false,
            sni: None,
            skip_cert_verify: false,
            network: Some("h2".to_string()),
            ws_path: Some("/vmess-h2".to_string()),
            ws_host: Some("cdn.example.com".to_string()),
            grpc_service_name: None,
            transport_headers: BTreeMap::new(),
            alpn: Vec::new(),
        }],
        None,
    )?;
    let outbound = outbounds.get("vmess-h2-test").unwrap();
    let destination = Destination::new("target.example", 443);

    let mut stream =
        timeout(Duration::from_secs(8), outbound.connect(&destination, 8000)).await??;
    stream.write_all(b"ping").await?;
    stream.flush().await?;

    let mut response = [0u8; 4];
    timeout(Duration::from_secs(3), stream.read_exact(&mut response)).await??;
    assert_eq!(&response, b"pong");
    let _ = timeout(Duration::from_secs(3), server).await??;
    Ok(())
}

/// VMess UDP (Command-UDP, plain TCP tunnel)
#[tokio::test]
async fn vmess_udp_real_dial() -> anyhow::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let listen_addr = listener.local_addr()?;

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let request_meta = read_vmess_request(&mut stream, &TEST_UUID_BYTES).await?;
        // VMess UDP session must use command byte 0x02
        assert_eq!(
            request_meta.command, 0x02,
            "VMess UDP session setup must use cmd=UDP(2)"
        );
        assert_eq!(request_meta.destination_host, "any.target");
        assert_eq!(request_meta.destination_port, 9999);

        let payload = read_vmess_first_chunk(
            &mut stream,
            request_meta.cipher_method,
            &request_meta.data_key,
            &request_meta.data_iv,
        )
        .await?;
        assert_eq!(payload, b"hello-vmess-udp");

        let response_header_key = vmess_sha256_16(&request_meta.data_key);
        let response_header_iv = vmess_sha256_16(&request_meta.data_iv);
        let response_header = build_vmess_response_header(
            &response_header_key,
            &response_header_iv,
            request_meta.response_authentication,
        )
        .await?;
        stream.write_all(&response_header).await?;

        let response_key = match request_meta.cipher_method {
            4 => vmess_chacha_key(&response_header_key).to_vec(),
            3 => response_header_key.to_vec(),
            _ => return Err(anyhow!("unsupported cipher")),
        };
        let chunk = vmess_write_chunk(
            request_meta.cipher_method,
            &response_key,
            &response_header_iv,
            &response_header_iv,
            b"echo",
        )?;
        stream.write_all(&chunk).await?;
        stream.flush().await?;
        Ok::<_, anyhow::Error>(())
    });

    let outbounds = build_outbounds(
        &[OutboundConfig::Vmess {
            name: "vmess-udp-test".to_string(),
            server: "127.0.0.1".to_string(),
            port: listen_addr.port(),
            uuid: TEST_UUID_STR.to_string(),
            alter_id: 0,
            cipher: "auto".to_string(),
            tls: false,
            sni: None,
            skip_cert_verify: false,
            network: None,
            ws_path: None,
            ws_host: None,
            grpc_service_name: None,
            transport_headers: BTreeMap::new(),
            alpn: Vec::new(),
        }],
        None,
    )?;
    let outbound = outbounds.get("vmess-udp-test").unwrap();

    let destination = Destination::new("any.target", 9999);
    let response = timeout(
        Duration::from_secs(5),
        outbound.udp_exchange(&destination, b"hello-vmess-udp", 3000),
    )
    .await??;
    assert_eq!(response, b"echo");
    let _ = timeout(Duration::from_secs(3), server).await??;
    Ok(())
}

#[tokio::test]
async fn vmess_oversized_udp_is_rejected_before_dial() -> anyhow::Result<()> {
    let outbounds = build_outbounds(&[vmess_tcp_test_config("vmess-large-udp", 1)], None)?;
    let error = outbounds
        .get("vmess-large-udp")
        .ok_or_else(|| anyhow!("large-UDP VMess outbound not built"))?
        .udp_exchange(&Destination::new("udp.example", 443), &[0u8; 8193], 100)
        .await
        .expect_err("oversized VMess UDP unexpectedly dialed");
    assert!(error.to_string().contains("exceeds 8192"));
    Ok(())
}

#[tokio::test]
async fn vmess_udp_timeout_evicts_stale_session() -> anyhow::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let listen_addr = listener.local_addr()?;
    let server = tokio::spawn(async move {
        let mut stalled = Vec::new();
        for index in 0..5 {
            let (mut stream, _) = listener.accept().await?;
            let request = read_vmess_request(&mut stream, &TEST_UUID_BYTES).await?;
            assert_eq!(request.command, 0x02);
            let payload = read_vmess_first_chunk(
                &mut stream,
                request.cipher_method,
                &request.data_key,
                &request.data_iv,
            )
            .await?;
            if index < 4 {
                assert_eq!(payload, b"timeout");
                stalled.push(stream);
                continue;
            }
            assert_eq!(payload, b"recovered");
            let response_header_key = vmess_sha256_16(&request.data_key);
            let response_header_iv = vmess_sha256_16(&request.data_iv);
            stream
                .write_all(
                    &build_vmess_response_header(
                        &response_header_key,
                        &response_header_iv,
                        request.response_authentication,
                    )
                    .await?,
                )
                .await?;
            let response_key = vmess_chacha_key(&response_header_key);
            stream
                .write_all(&vmess_write_chunk(
                    request.cipher_method,
                    &response_key,
                    &response_header_iv,
                    &response_header_iv,
                    b"recovered",
                )?)
                .await?;
            stream.flush().await?;
        }
        Ok::<_, anyhow::Error>(())
    });

    let outbounds = build_outbounds(
        &[vmess_tcp_test_config(
            "vmess-udp-timeout-eviction",
            listen_addr.port(),
        )],
        None,
    )?;
    let outbound = outbounds
        .get("vmess-udp-timeout-eviction")
        .ok_or_else(|| anyhow!("timeout-eviction VMess outbound not built"))?;
    let destination = Destination::new("echo.example", 7777);
    for _ in 0..4 {
        let error = outbound
            .udp_exchange(&destination, b"timeout", 30)
            .await
            .expect_err("stalled VMess UDP exchange unexpectedly succeeded");
        let message = error.to_string();
        assert!(message.contains("vmess udp exchange") && message.contains("timed out"));
    }
    let response = outbound
        .udp_exchange(&destination, b"recovered", 3000)
        .await?;
    assert_eq!(response, b"recovered");
    timeout(Duration::from_secs(3), server).await???;
    Ok(())
}

#[tokio::test]
async fn vmess_udp_keeps_destinations_in_separate_associations() -> anyhow::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let listen_addr = listener.local_addr()?;
    let first_destination = Destination::new("one.example", 1001);
    let second_destination = Destination::new("two.example", 2002);
    let server = tokio::spawn(async move {
        let first = listener.accept().await?.0;
        let second = listener.accept().await?.0;
        let first = tokio::spawn(serve_multi_destination_vmess_udp_exchange(first));
        let second = tokio::spawn(serve_multi_destination_vmess_udp_exchange(second));
        let first_destination = first.await??;
        let second_destination = second.await??;
        assert_ne!(first_destination, second_destination);
        Ok::<_, anyhow::Error>(())
    });

    let outbounds = build_outbounds(
        &[OutboundConfig::Vmess {
            name: "vmess-multi-udp-test".to_string(),
            server: "127.0.0.1".to_string(),
            port: listen_addr.port(),
            uuid: TEST_UUID_STR.to_string(),
            alter_id: 0,
            cipher: "auto".to_string(),
            tls: false,
            sni: None,
            skip_cert_verify: false,
            network: None,
            ws_path: None,
            ws_host: None,
            grpc_service_name: None,
            transport_headers: BTreeMap::new(),
            alpn: Vec::new(),
        }],
        None,
    )?;
    let outbound = outbounds.get("vmess-multi-udp-test").unwrap();
    let (first, second) = tokio::join!(
        outbound.udp_exchange(&first_destination, b"one", 3000),
        outbound.udp_exchange(&second_destination, b"two", 3000)
    );
    assert_eq!(first?, b"reply-one");
    assert_eq!(second?, b"reply-two");
    timeout(Duration::from_secs(3), server).await???;
    Ok(())
}

// ============================================================
// WebSocket / gRPC frame helpers
// ============================================================

async fn read_websocket_binary_frame<R>(reader: &mut R) -> anyhow::Result<Vec<u8>>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut header = [0u8; 2];
    reader.read_exact(&mut header).await?;
    let opcode = header[0] & 0x0F;
    assert_eq!(opcode, 0x2, "expected binary frame, got opcode {opcode}");
    let masked = (header[1] & 0x80) != 0;
    let mut len = (header[1] & 0x7F) as usize;
    if len == 126 {
        let mut ext = [0u8; 2];
        reader.read_exact(&mut ext).await?;
        len = u16::from_be_bytes(ext) as usize;
    } else if len == 127 {
        let mut ext = [0u8; 8];
        reader.read_exact(&mut ext).await?;
        len = u64::from_be_bytes(ext) as usize;
    }
    let mut mask = [0u8; 4];
    if masked {
        reader.read_exact(&mut mask).await?;
    }
    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload).await?;
    if masked {
        for (i, b) in payload.iter_mut().enumerate() {
            *b ^= mask[i % 4];
        }
    }
    Ok(payload)
}

fn build_websocket_binary_frame(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 10);
    out.push(0x82); // FIN + binary opcode
    if payload.len() < 126 {
        out.push(payload.len() as u8);
    } else if payload.len() <= 0xFFFF {
        out.push(126);
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    } else {
        out.push(127);
        out.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    }
    out.extend_from_slice(payload);
    out
}

fn grpc_wrap(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + payload.len());
    out.push(0); // compression flag
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

struct H2BodyReader {
    body: h2::RecvStream,
    read_buffer: BytesMut,
}

impl H2BodyReader {
    fn new(body: h2::RecvStream) -> Self {
        Self {
            body,
            read_buffer: BytesMut::new(),
        }
    }
}

impl AsyncRead for H2BodyReader {
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
                let length = self.read_buffer.len().min(buf.remaining());
                let chunk = self.read_buffer.split_to(length);
                buf.put_slice(&chunk);
                return Poll::Ready(Ok(()));
            }
            match self.body.poll_data(cx) {
                Poll::Ready(Some(Ok(chunk))) => {
                    let length = chunk.len();
                    self.read_buffer.extend_from_slice(&chunk);
                    self.body
                        .flow_control()
                        .release_capacity(length)
                        .map_err(|error| {
                            Error::new(
                                ErrorKind::ConnectionAborted,
                                format!("h2 flow control failed: {error}"),
                            )
                        })?;
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

struct GrpcBodyReader {
    body: h2::RecvStream,
    incoming: BytesMut,
    read_buffer: BytesMut,
}

impl GrpcBodyReader {
    fn new(body: h2::RecvStream) -> Self {
        Self {
            body,
            incoming: BytesMut::new(),
            read_buffer: BytesMut::new(),
        }
    }

    fn decode_next_message(&mut self) -> Result<bool, Error> {
        if self.incoming.len() < 5 {
            return Ok(false);
        }
        if self.incoming[0] != 0 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "compressed gRPC test frames are not supported",
            ));
        }
        let payload_length = u32::from_be_bytes([
            self.incoming[1],
            self.incoming[2],
            self.incoming[3],
            self.incoming[4],
        ]) as usize;
        if self.incoming.len() < 5 + payload_length {
            return Ok(false);
        }
        self.incoming.advance(5);
        let payload = self.incoming.split_to(payload_length);
        self.read_buffer.extend_from_slice(&payload);
        Ok(true)
    }
}

impl AsyncRead for GrpcBodyReader {
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
                let length = self.read_buffer.len().min(buf.remaining());
                let chunk = self.read_buffer.split_to(length);
                buf.put_slice(&chunk);
                return Poll::Ready(Ok(()));
            }
            match self.decode_next_message() {
                Ok(true) => continue,
                Ok(false) => {}
                Err(error) => return Poll::Ready(Err(error)),
            }
            match self.body.poll_data(cx) {
                Poll::Ready(Some(Ok(chunk))) => {
                    let length = chunk.len();
                    self.incoming.extend_from_slice(&chunk);
                    self.body
                        .flow_control()
                        .release_capacity(length)
                        .map_err(|error| {
                            Error::new(
                                ErrorKind::ConnectionAborted,
                                format!("gRPC flow control failed: {error}"),
                            )
                        })?;
                }
                Poll::Ready(Some(Err(error))) => {
                    return Poll::Ready(Err(Error::new(
                        ErrorKind::ConnectionAborted,
                        format!("gRPC body failed: {error}"),
                    )));
                }
                Poll::Ready(None) => {
                    if self.incoming.is_empty() {
                        return Poll::Ready(Ok(()));
                    }
                    return Poll::Ready(Err(Error::new(
                        ErrorKind::UnexpectedEof,
                        "truncated gRPC frame",
                    )));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

// ============================================================
// Smoke test (no mock): ensure test infra compiles
// ============================================================

#[tokio::test]
async fn smoke_outbound_builds() {
    let outbounds = build_outbounds(
        &[OutboundConfig::Vmess {
            name: "smoke".to_string(),
            server: "127.0.0.1".to_string(),
            port: 1,
            uuid: TEST_UUID_STR.to_string(),
            alter_id: 0,
            cipher: "auto".to_string(),
            tls: false,
            sni: None,
            skip_cert_verify: false,
            network: None,
            ws_path: None,
            ws_host: None,
            grpc_service_name: None,
            transport_headers: BTreeMap::new(),
            alpn: Vec::new(),
        }],
        None,
    )
    .expect("build vmess outbound");
    assert!(outbounds.contains_key("smoke"));
}

#[allow(dead_code)]
fn _silence_request_unused() -> anyhow::Result<Request<()>> {
    Request::builder().body(()).map_err(Into::into)
}
