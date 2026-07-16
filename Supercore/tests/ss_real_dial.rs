//! 6.4.1 + 6.4.7 Shadowsocks / ShadowsocksR 真实拨号测试
//!
//! 覆盖：
//! - SS AEAD 3 cipher (aes-128-gcm / aes-256-gcm / chacha20-ietf-poly1305) 真实握手
//! - SS 2022-blake3-aes-128-gcm 配置解析
//! - SSR 配置 build 不 panic
//! - SSR UDP 显式 unsupported
//! - Shadowsocks plugin 配置解析
//!
//! 关键约束：
//! - 内部 cipher (SsCipher) 是 mod.rs private，不直接 import
//! - mock server 用 RustCrypto crate (aes-gcm, chacha20poly1305) 重新实现等价 AEAD
//! - 用 build_outbounds 拿真实 ShadowsocksOutbound，调真实 connect 路径

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use aes::{
    cipher::{Block, BlockDecrypt, BlockEncrypt, KeyInit as BlockKeyInit},
    Aes128, Aes256,
};
use aes_gcm::{aead::Aead, Aes128Gcm, Aes256Gcm, Nonce as AesNonce};
use base64::Engine;
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaNonce, XChaCha20Poly1305};
use hkdf::Hkdf;
use md5::{Digest, Md5};
use sha1::Sha1;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
    time::timeout,
};

use supercore::{
    config::{CoreConfig, OutboundConfig, SuperConfig},
    outbound::{build_outbounds, OutboundMap},
    routing::Destination,
};

// ---------------------------------------------------------------------------
// Test-side cipher helpers (mirror src/outbound/mod.rs:7000-7111)
// ---------------------------------------------------------------------------
// (The mock server only DECRYPTS the production client's first frame, so we
// don't need a symmetric ss_handshake_send helper.  The dead `ss_handshake_send`
// helper has been removed; production key derivation is in mod.rs.)

/// Server-side: read salt + encrypted addr, decrypt, parse SOCKS5-style addr.
async fn ss_server_handshake(
    stream: &mut tokio::net::TcpStream,
    method: &str,
    password: &[u8],
) -> anyhow::Result<(String, u16, Vec<u8>, Vec<u8>)> {
    let key_len = match method {
        "aes-128-gcm" => 16,
        "aes-256-gcm" | "chacha20-ietf-poly1305" => 32,
        _ => return Err(anyhow::anyhow!("unsupported {method}")),
    };
    let master_key = evp_bytes_to_key_test(password, key_len);
    let mut salt = vec![0u8; key_len];
    stream.read_exact(&mut salt).await?;
    let subkey = legacy_ss_subkey(&master_key, &salt, key_len)?;
    let mut nonce = vec![0u8; 12];
    let plaintext = read_legacy_ss_chunk(stream, method, &subkey, &mut nonce).await?;
    if plaintext.is_empty() {
        return Err(anyhow::anyhow!("empty Shadowsocks request"));
    }
    let atyp = plaintext[0];
    let mut pos = 1;
    let host = match atyp {
        0x01 => {
            let ip = std::net::Ipv4Addr::new(
                plaintext[pos],
                plaintext[pos + 1],
                plaintext[pos + 2],
                plaintext[pos + 3],
            );
            pos += 4;
            format!("{ip}")
        }
        0x03 => {
            let len = plaintext[pos] as usize;
            pos += 1;
            let s = std::str::from_utf8(&plaintext[pos..pos + len])?.to_string();
            pos += len;
            s
        }
        _ => return Err(anyhow::anyhow!("bad atyp {atyp}")),
    };
    if plaintext.len() < pos + 2 {
        return Err(anyhow::anyhow!("short port"));
    }
    let port = u16::from_be_bytes([plaintext[pos], plaintext[pos + 1]]);
    Ok((host, port, subkey, nonce))
}

fn evp_bytes_to_key_test(password: &[u8], key_len: usize) -> Vec<u8> {
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

fn legacy_ss_subkey(master_key: &[u8], salt: &[u8], key_len: usize) -> anyhow::Result<Vec<u8>> {
    let hkdf = Hkdf::<Sha1>::new(Some(salt), master_key);
    let mut subkey = vec![0u8; key_len];
    hkdf.expand(b"ss-subkey", &mut subkey)
        .map_err(|_| anyhow::anyhow!("legacy Shadowsocks subkey derivation failed"))?;
    Ok(subkey)
}

fn legacy_ss_decrypt(
    method: &str,
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
) -> anyhow::Result<Vec<u8>> {
    match method {
        "aes-128-gcm" => Ok(Aes128Gcm::new_from_slice(key)?
            .decrypt(AesNonce::from_slice(nonce), ciphertext)
            .map_err(|_| anyhow::anyhow!("legacy aes-128 decrypt failed"))?),
        "aes-256-gcm" => Ok(Aes256Gcm::new_from_slice(key)?
            .decrypt(AesNonce::from_slice(nonce), ciphertext)
            .map_err(|_| anyhow::anyhow!("legacy aes-256 decrypt failed"))?),
        "chacha20-ietf-poly1305" => Ok(ChaCha20Poly1305::new_from_slice(key)?
            .decrypt(ChaNonce::from_slice(nonce), ciphertext)
            .map_err(|_| anyhow::anyhow!("legacy chacha decrypt failed"))?),
        _ => Err(anyhow::anyhow!("unsupported legacy method {method}")),
    }
}

fn legacy_ss_encrypt(
    method: &str,
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
) -> anyhow::Result<Vec<u8>> {
    match method {
        "aes-128-gcm" => Ok(Aes128Gcm::new_from_slice(key)?
            .encrypt(AesNonce::from_slice(nonce), plaintext)
            .map_err(|_| anyhow::anyhow!("legacy aes-128 encrypt failed"))?),
        "aes-256-gcm" => Ok(Aes256Gcm::new_from_slice(key)?
            .encrypt(AesNonce::from_slice(nonce), plaintext)
            .map_err(|_| anyhow::anyhow!("legacy aes-256 encrypt failed"))?),
        "chacha20-ietf-poly1305" => Ok(ChaCha20Poly1305::new_from_slice(key)?
            .encrypt(ChaNonce::from_slice(nonce), plaintext)
            .map_err(|_| anyhow::anyhow!("legacy chacha encrypt failed"))?),
        _ => Err(anyhow::anyhow!("unsupported legacy method {method}")),
    }
}

async fn read_legacy_ss_chunk(
    stream: &mut tokio::net::TcpStream,
    method: &str,
    key: &[u8],
    nonce: &mut [u8],
) -> anyhow::Result<Vec<u8>> {
    let mut encrypted_length = [0u8; 18];
    stream.read_exact(&mut encrypted_length).await?;
    let length = legacy_ss_decrypt(method, key, nonce, &encrypted_length)?;
    increment_nonce(nonce);
    if length.len() != 2 {
        return Err(anyhow::anyhow!("invalid Shadowsocks length chunk"));
    }
    let payload_length = u16::from_be_bytes([length[0], length[1]]) as usize;
    let mut encrypted_payload = vec![0u8; payload_length + 16];
    stream.read_exact(&mut encrypted_payload).await?;
    let payload = legacy_ss_decrypt(method, key, nonce, &encrypted_payload)?;
    increment_nonce(nonce);
    Ok(payload)
}

fn encode_legacy_ss_chunk(
    method: &str,
    key: &[u8],
    nonce: &mut [u8],
    payload: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let mut output = legacy_ss_encrypt(method, key, nonce, &(payload.len() as u16).to_be_bytes())?;
    increment_nonce(nonce);
    output.extend_from_slice(&legacy_ss_encrypt(method, key, nonce, payload)?);
    increment_nonce(nonce);
    Ok(output)
}

fn increment_nonce(nonce: &mut [u8]) {
    for byte in nonce {
        let (next, overflow) = byte.overflowing_add(1);
        *byte = next;
        if !overflow {
            break;
        }
    }
}

fn ss2022_subkey(psk: &[u8], salt: &[u8], key_len: usize) -> Vec<u8> {
    let mut material = Vec::with_capacity(psk.len() + salt.len());
    material.extend_from_slice(psk);
    material.extend_from_slice(salt);
    blake3::derive_key("shadowsocks 2022 session subkey", &material)[..key_len].to_vec()
}

fn ss2022_decrypt(
    method: &str,
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
) -> anyhow::Result<Vec<u8>> {
    match method {
        "2022-blake3-aes-128-gcm" => Ok(Aes128Gcm::new_from_slice(key)?
            .decrypt(AesNonce::from_slice(nonce), ciphertext)
            .map_err(|_| anyhow::anyhow!("ss2022 aes-128 decrypt failed"))?),
        "2022-blake3-aes-256-gcm" => Ok(Aes256Gcm::new_from_slice(key)?
            .decrypt(AesNonce::from_slice(nonce), ciphertext)
            .map_err(|_| anyhow::anyhow!("ss2022 aes-256 decrypt failed"))?),
        "2022-blake3-chacha20-poly1305" => Ok(ChaCha20Poly1305::new_from_slice(key)?
            .decrypt(ChaNonce::from_slice(nonce), ciphertext)
            .map_err(|_| anyhow::anyhow!("ss2022 chacha decrypt failed"))?),
        _ => Err(anyhow::anyhow!("unsupported ss2022 method {method}")),
    }
}

fn ss2022_encrypt(
    method: &str,
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
) -> anyhow::Result<Vec<u8>> {
    match method {
        "2022-blake3-aes-128-gcm" => Ok(Aes128Gcm::new_from_slice(key)?
            .encrypt(AesNonce::from_slice(nonce), plaintext)
            .map_err(|_| anyhow::anyhow!("ss2022 aes-128 encrypt failed"))?),
        "2022-blake3-aes-256-gcm" => Ok(Aes256Gcm::new_from_slice(key)?
            .encrypt(AesNonce::from_slice(nonce), plaintext)
            .map_err(|_| anyhow::anyhow!("ss2022 aes-256 encrypt failed"))?),
        "2022-blake3-chacha20-poly1305" => Ok(ChaCha20Poly1305::new_from_slice(key)?
            .encrypt(ChaNonce::from_slice(nonce), plaintext)
            .map_err(|_| anyhow::anyhow!("ss2022 chacha encrypt failed"))?),
        _ => Err(anyhow::anyhow!("unsupported ss2022 method {method}")),
    }
}

fn parse_test_destination(input: &[u8]) -> anyhow::Result<(Destination, usize)> {
    let mut cursor = 1;
    let host = match input.first().copied() {
        Some(0x01) => {
            let address: [u8; 4] = input[cursor..cursor + 4].try_into()?;
            cursor += 4;
            std::net::Ipv4Addr::from(address).to_string()
        }
        Some(0x03) => {
            let length = input[cursor] as usize;
            cursor += 1;
            let host = std::str::from_utf8(&input[cursor..cursor + length])?.to_string();
            cursor += length;
            host
        }
        Some(0x04) => {
            let address: [u8; 16] = input[cursor..cursor + 16].try_into()?;
            cursor += 16;
            std::net::Ipv6Addr::from(address).to_string()
        }
        other => return Err(anyhow::anyhow!("unsupported destination type {other:?}")),
    };
    let port = u16::from_be_bytes(input[cursor..cursor + 2].try_into()?);
    cursor += 2;
    Ok((Destination::new(host, port), cursor))
}

async fn run_ss2022_tcp_real_dial(method: &'static str, keys: Vec<Vec<u8>>) -> anyhow::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let listen_addr = listener.local_addr()?;
    let key_len = keys
        .last()
        .ok_or_else(|| anyhow::anyhow!("missing ss2022 key"))?
        .len();
    let expected_destination = Destination::new("target.example", 443);
    let server_destination = expected_destination.clone();
    let server_keys = keys.clone();

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let mut request_salt = vec![0u8; key_len];
        stream.read_exact(&mut request_salt).await?;
        for pair in server_keys.windows(2) {
            let mut encrypted_identity = [0u8; 16];
            stream.read_exact(&mut encrypted_identity).await?;
            let mut material = Vec::new();
            material.extend_from_slice(&pair[0]);
            material.extend_from_slice(&request_salt);
            let identity_key = blake3::derive_key("shadowsocks 2022 identity subkey", &material);
            let identity = ss2022_identity_block_test(
                &identity_key[..pair[0].len()],
                &encrypted_identity,
                false,
            )?;
            assert_eq!(&identity, &blake3::hash(&pair[1]).as_bytes()[..16]);
        }
        let server_key = server_keys
            .last()
            .ok_or_else(|| anyhow::anyhow!("missing ss2022 user key"))?;
        let request_key = ss2022_subkey(&server_key, &request_salt, key_len);
        let mut request_nonce = [0u8; 12];

        let mut fixed = vec![0u8; 11 + 16];
        stream.read_exact(&mut fixed).await?;
        let fixed = ss2022_decrypt(method, &request_key, &request_nonce, &fixed)?;
        increment_nonce(&mut request_nonce);
        assert_eq!(fixed[0], 0);
        let timestamp = u64::from_be_bytes(fixed[1..9].try_into()?);
        assert!(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)?
                .as_secs()
                .abs_diff(timestamp)
                <= 30
        );
        let variable_length = u16::from_be_bytes(fixed[9..11].try_into()?) as usize;

        let mut variable = vec![0u8; variable_length + 16];
        stream.read_exact(&mut variable).await?;
        let variable = ss2022_decrypt(method, &request_key, &request_nonce, &variable)?;
        increment_nonce(&mut request_nonce);
        let (destination, cursor) = parse_test_destination(&variable)?;
        assert_eq!(destination, server_destination);
        let padding_length = u16::from_be_bytes(variable[cursor..cursor + 2].try_into()?) as usize;
        assert!(padding_length > 0);
        assert_eq!(cursor + 2 + padding_length, variable.len());

        let mut encrypted_length = [0u8; 18];
        stream.read_exact(&mut encrypted_length).await?;
        let length = ss2022_decrypt(method, &request_key, &request_nonce, &encrypted_length)?;
        increment_nonce(&mut request_nonce);
        if length.len() != 2 {
            return Err(anyhow::anyhow!("invalid ss2022 payload length block"));
        }
        let payload_length = u16::from_be_bytes([length[0], length[1]]) as usize;
        let mut encrypted_payload = vec![0u8; payload_length + 16];
        stream.read_exact(&mut encrypted_payload).await?;
        let payload = ss2022_decrypt(method, &request_key, &request_nonce, &encrypted_payload)?;
        assert_eq!(payload, b"ping");

        let response_salt = vec![0x42; key_len];
        let response_key = ss2022_subkey(&server_key, &response_salt, key_len);
        let mut response_nonce = [0u8; 12];
        let mut response_header = Vec::with_capacity(1 + 8 + key_len + 2);
        response_header.push(1);
        response_header.extend_from_slice(
            &SystemTime::now()
                .duration_since(UNIX_EPOCH)?
                .as_secs()
                .to_be_bytes(),
        );
        response_header.extend_from_slice(&request_salt);
        response_header.extend_from_slice(&4u16.to_be_bytes());
        let encrypted_header =
            ss2022_encrypt(method, &response_key, &response_nonce, &response_header)?;
        increment_nonce(&mut response_nonce);
        let encrypted_payload = ss2022_encrypt(method, &response_key, &response_nonce, b"pong")?;
        let mut response = response_salt;
        response.extend_from_slice(&encrypted_header);
        response.extend_from_slice(&encrypted_payload);
        stream.write_all(&response).await?;
        stream.flush().await?;
        Ok::<_, anyhow::Error>(())
    });

    let password = keys
        .iter()
        .map(|key| base64::engine::general_purpose::STANDARD.encode(key))
        .collect::<Vec<_>>()
        .join(":");
    let config = SuperConfig {
        core: CoreConfig {
            default_outbound: "ss".to_string(),
            ..CoreConfig::default()
        },
        outbounds: vec![OutboundConfig::Shadowsocks {
            name: "ss".to_string(),
            server: "127.0.0.1".to_string(),
            port: listen_addr.port(),
            method: method.to_string(),
            password,
            plugin: None,
        }],
        ..SuperConfig::default()
    };
    let outbounds = build_outbounds(&config.outbounds, None)?;
    let outbound = get_outbound(&outbounds, "ss");
    let mut stream = outbound.connect(&expected_destination, 3000).await?;
    stream.write_all(b"ping").await?;
    stream.flush().await?;
    let mut response = [0u8; 4];
    timeout(Duration::from_secs(3), stream.read_exact(&mut response)).await??;
    assert_eq!(&response, b"pong");
    timeout(Duration::from_secs(3), server).await???;
    Ok(())
}

fn ss2022_aes_block_test(
    method: &str,
    key: &[u8],
    input: &[u8; 16],
    encrypt: bool,
) -> anyhow::Result<[u8; 16]> {
    if !matches!(
        method,
        "2022-blake3-aes-128-gcm" | "2022-blake3-aes-256-gcm"
    ) {
        return Err(anyhow::anyhow!("AES Shadowsocks 2022 method required"));
    }
    ss2022_identity_block_test(key, input, encrypt)
}

fn ss2022_identity_block_test(
    key: &[u8],
    input: &[u8; 16],
    encrypt: bool,
) -> anyhow::Result<[u8; 16]> {
    let mut output = [0u8; 16];
    match key.len() {
        16 => {
            let cipher = Aes128::new_from_slice(key)?;
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
            let cipher = Aes256::new_from_slice(key)?;
            let mut block = Block::<Aes256>::default();
            block.copy_from_slice(input);
            if encrypt {
                cipher.encrypt_block(&mut block);
            } else {
                cipher.decrypt_block(&mut block);
            }
            output.copy_from_slice(&block);
        }
        length => return Err(anyhow::anyhow!("invalid identity key length {length}")),
    }
    Ok(output)
}

async fn run_ss2022_udp_real_dial(method: &'static str, keys: Vec<Vec<u8>>) -> anyhow::Result<()> {
    let server = UdpSocket::bind("127.0.0.1:0").await?;
    let listen_addr = server.local_addr()?;
    let server_keys = keys.clone();
    let expected_destination = Destination::new("dns.example", 53);
    let server_destination = expected_destination.clone();

    let server_task = tokio::spawn(async move {
        let mut buffer = vec![0u8; 65_535];
        let (length, peer) = server.recv_from(&mut buffer).await?;
        let packet = &buffer[..length];
        let (client_session_id, packet_id, body) = if method == "2022-blake3-chacha20-poly1305" {
            assert_eq!(server_keys.len(), 1);
            let server_key = &server_keys[0];
            let nonce = &packet[..24];
            let body = XChaCha20Poly1305::new_from_slice(server_key)?
                .decrypt(chacha20poly1305::XNonce::from_slice(nonce), &packet[24..])
                .map_err(|_| anyhow::anyhow!("ss2022 UDP request decrypt failed"))?;
            let client_session_id: [u8; 8] = body[..8].try_into()?;
            let packet_id = u64::from_be_bytes(body[8..16].try_into()?);
            (client_session_id, packet_id, body[16..].to_vec())
        } else {
            let encrypted_header: [u8; 16] = packet[..16].try_into()?;
            let separate_header =
                ss2022_aes_block_test(method, &server_keys[0], &encrypted_header, false)?;
            let client_session_id: [u8; 8] = separate_header[..8].try_into()?;
            let packet_id = u64::from_be_bytes(separate_header[8..].try_into()?);
            let mut body_offset = 16;
            for pair in server_keys.windows(2) {
                let encrypted_identity: [u8; 16] =
                    packet[body_offset..body_offset + 16].try_into()?;
                body_offset += 16;
                let mut identity =
                    ss2022_identity_block_test(&pair[0], &encrypted_identity, false)?;
                for (byte, header_byte) in identity.iter_mut().zip(separate_header) {
                    *byte ^= header_byte;
                }
                assert_eq!(&identity, &blake3::hash(&pair[1]).as_bytes()[..16]);
            }
            let server_key = server_keys
                .last()
                .ok_or_else(|| anyhow::anyhow!("missing ss2022 user key"))?;
            let request_key = ss2022_subkey(server_key, &client_session_id, server_key.len());
            let body = ss2022_decrypt(
                method,
                &request_key,
                &separate_header[4..16],
                &packet[body_offset..],
            )?;
            (client_session_id, packet_id, body)
        };
        assert_eq!(packet_id, 0);
        assert_eq!(body[0], 0);
        let timestamp = u64::from_be_bytes(body[1..9].try_into()?);
        assert!(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)?
                .as_secs()
                .abs_diff(timestamp)
                <= 30
        );
        let padding_length = u16::from_be_bytes(body[9..11].try_into()?) as usize;
        let destination_offset = 11 + padding_length;
        let (destination, destination_length) =
            parse_test_destination(&body[destination_offset..])?;
        assert_eq!(destination, server_destination);
        assert_eq!(
            &body[destination_offset + destination_length..],
            b"hello-ss2022-udp"
        );

        let server_session_id = [0x44; 8];
        let server_packet_id = 0u64;
        let mut response_main = Vec::new();
        response_main.push(1);
        response_main.extend_from_slice(
            &SystemTime::now()
                .duration_since(UNIX_EPOCH)?
                .as_secs()
                .to_be_bytes(),
        );
        response_main.extend_from_slice(&client_session_id);
        response_main.extend_from_slice(&0u16.to_be_bytes());
        let mut destination_bytes = Vec::new();
        destination_bytes.push(0x03);
        destination_bytes.push("dns.example".len() as u8);
        destination_bytes.extend_from_slice(b"dns.example");
        destination_bytes.extend_from_slice(&53u16.to_be_bytes());
        response_main.extend_from_slice(&destination_bytes);
        response_main.extend_from_slice(b"echo-ss2022-udp");

        let response = if method == "2022-blake3-chacha20-poly1305" {
            let server_key = server_keys
                .last()
                .ok_or_else(|| anyhow::anyhow!("missing ss2022 user key"))?;
            let nonce = [0x55; 24];
            let mut body = Vec::new();
            body.extend_from_slice(&server_session_id);
            body.extend_from_slice(&server_packet_id.to_be_bytes());
            body.extend_from_slice(&response_main);
            let encrypted = XChaCha20Poly1305::new_from_slice(server_key)?
                .encrypt(chacha20poly1305::XNonce::from_slice(&nonce), body.as_ref())
                .map_err(|_| anyhow::anyhow!("ss2022 UDP response encrypt failed"))?;
            let mut response = nonce.to_vec();
            response.extend_from_slice(&encrypted);
            response
        } else {
            let server_key = server_keys
                .last()
                .ok_or_else(|| anyhow::anyhow!("missing ss2022 user key"))?;
            let mut separate_header = [0u8; 16];
            separate_header[..8].copy_from_slice(&server_session_id);
            separate_header[8..].copy_from_slice(&server_packet_id.to_be_bytes());
            let encrypted_header =
                ss2022_aes_block_test(method, server_key, &separate_header, true)?;
            let response_key = ss2022_subkey(server_key, &server_session_id, server_key.len());
            let encrypted_body = ss2022_encrypt(
                method,
                &response_key,
                &separate_header[4..16],
                &response_main,
            )?;
            let mut response = encrypted_header.to_vec();
            response.extend_from_slice(&encrypted_body);
            response
        };
        server.send_to(&response, peer).await?;
        Ok::<_, anyhow::Error>(())
    });

    let password = keys
        .iter()
        .map(|key| base64::engine::general_purpose::STANDARD.encode(key))
        .collect::<Vec<_>>()
        .join(":");
    let config = SuperConfig {
        core: CoreConfig {
            default_outbound: "ss".to_string(),
            ..CoreConfig::default()
        },
        outbounds: vec![OutboundConfig::Shadowsocks {
            name: "ss".to_string(),
            server: "127.0.0.1".to_string(),
            port: listen_addr.port(),
            method: method.to_string(),
            password,
            plugin: None,
        }],
        ..SuperConfig::default()
    };
    let outbounds = build_outbounds(&config.outbounds, None)?;
    let outbound = get_outbound(&outbounds, "ss");
    let response = outbound
        .udp_exchange(&expected_destination, b"hello-ss2022-udp", 3000)
        .await?;
    assert_eq!(response, b"echo-ss2022-udp");
    timeout(Duration::from_secs(3), server_task).await???;
    Ok(())
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn build_just_ss(method: &str, port: u16) -> SuperConfig {
    SuperConfig {
        core: CoreConfig {
            default_outbound: "ss".to_string(),
            ..CoreConfig::default()
        },
        outbounds: vec![
            OutboundConfig::Direct {
                name: "direct".to_string(),
            },
            OutboundConfig::Shadowsocks {
                name: "ss".to_string(),
                server: "127.0.0.1".to_string(),
                port,
                method: method.to_string(),
                password: "supersecret".to_string(),
                plugin: None,
            },
        ],
        ..SuperConfig::default()
    }
}

fn build_just_ssr() -> SuperConfig {
    SuperConfig {
        core: CoreConfig {
            default_outbound: "ssr".to_string(),
            ..CoreConfig::default()
        },
        outbounds: vec![
            OutboundConfig::Direct {
                name: "direct".to_string(),
            },
            OutboundConfig::Ssr {
                name: "ssr".to_string(),
                server: "127.0.0.1".to_string(),
                port: 8388,
                method: "aes-128-cfb".to_string(),
                password: "pwd".to_string(),
                protocol: "auth_aes128_md5".to_string(),
                obfs: "http_simple".to_string(),
                protocol_param: None,
                obfs_param: None,
            },
        ],
        ..SuperConfig::default()
    }
}

fn get_outbound(map: &OutboundMap, name: &str) -> Arc<dyn supercore::outbound::Outbound> {
    map.get(name)
        .unwrap_or_else(|| panic!("missing outbound {name}"))
        .clone()
}

/// Spawn a mock SS server that:
/// 1. Reads the request, decrypts, parses the embedded target
/// 2. Replies with a tiny echo (best-effort)
/// 3. Closes
async fn spawn_ss_mock(
    method: &'static str,
    password: &'static str,
    expected_destination: Destination,
) -> (SocketAddr, tokio::task::JoinHandle<anyhow::Result<()>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let (host, port, request_key, mut request_nonce) =
            ss_server_handshake(&mut stream, method, password.as_bytes()).await?;
        assert_eq!(Destination::new(host, port), expected_destination);
        let payload =
            read_legacy_ss_chunk(&mut stream, method, &request_key, &mut request_nonce).await?;
        assert_eq!(payload, b"ping");

        let key_len = if method == "aes-128-gcm" { 16 } else { 32 };
        let master_key = evp_bytes_to_key_test(password.as_bytes(), key_len);
        let response_salt = vec![0x42; key_len];
        let response_key = legacy_ss_subkey(&master_key, &response_salt, key_len)?;
        let mut response_nonce = vec![0u8; 12];
        let response_chunk =
            encode_legacy_ss_chunk(method, &response_key, &mut response_nonce, b"pong")?;
        stream.write_all(&response_salt).await?;
        stream.write_all(&response_chunk).await?;
        stream.flush().await?;
        Ok(())
    });
    (addr, handle)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ss_aes_128_gcm_real_dial_against_mock() {
    let destination = Destination::new("example.com", 443);
    let (addr, server) = spawn_ss_mock("aes-128-gcm", "supersecret", destination.clone()).await;
    let cfg = build_just_ss("aes-128-gcm", addr.port());
    let map = build_outbounds(&cfg.outbounds, None).unwrap();
    let outbound = get_outbound(&map, "ss");
    let mut stream = timeout(Duration::from_secs(3), outbound.connect(&destination, 2000))
        .await
        .unwrap()
        .unwrap();
    stream.write_all(b"ping").await.unwrap();
    stream.flush().await.unwrap();
    let mut response = [0u8; 4];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"pong");
    server.await.unwrap().unwrap();
}

#[tokio::test]
async fn ss_aes_256_gcm_real_dial_against_mock() {
    let destination = Destination::new("test.example", 80);
    let (addr, server) = spawn_ss_mock("aes-256-gcm", "supersecret", destination.clone()).await;
    let cfg = build_just_ss("aes-256-gcm", addr.port());
    let map = build_outbounds(&cfg.outbounds, None).unwrap();
    let outbound = get_outbound(&map, "ss");
    let mut stream = timeout(Duration::from_secs(3), outbound.connect(&destination, 2000))
        .await
        .unwrap()
        .unwrap();
    stream.write_all(b"ping").await.unwrap();
    stream.flush().await.unwrap();
    let mut response = [0u8; 4];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"pong");
    server.await.unwrap().unwrap();
}

#[tokio::test]
async fn ss_chacha20_ietf_poly1305_real_dial_against_mock() {
    let destination = Destination::new("github.com", 22);
    let (addr, server) =
        spawn_ss_mock("chacha20-ietf-poly1305", "supersecret", destination.clone()).await;
    let cfg = build_just_ss("chacha20-ietf-poly1305", addr.port());
    let map = build_outbounds(&cfg.outbounds, None).unwrap();
    let outbound = get_outbound(&map, "ss");
    let mut stream = timeout(Duration::from_secs(3), outbound.connect(&destination, 2000))
        .await
        .unwrap()
        .unwrap();
    stream.write_all(b"ping").await.unwrap();
    stream.flush().await.unwrap();
    let mut response = [0u8; 4];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"pong");
    server.await.unwrap().unwrap();
}

#[tokio::test]
async fn ss_2022_blake3_aes_128_gcm_real_dial() -> anyhow::Result<()> {
    run_ss2022_tcp_real_dial("2022-blake3-aes-128-gcm", vec![vec![0x11; 16]]).await
}

#[tokio::test]
async fn ss_2022_blake3_aes_256_gcm_real_dial() -> anyhow::Result<()> {
    run_ss2022_tcp_real_dial("2022-blake3-aes-256-gcm", vec![vec![0x22; 32]]).await
}

#[tokio::test]
async fn ss_2022_blake3_chacha20_poly1305_real_dial() -> anyhow::Result<()> {
    run_ss2022_tcp_real_dial("2022-blake3-chacha20-poly1305", vec![vec![0x33; 32]]).await
}

#[tokio::test]
async fn ss_2022_tcp_sip023_identity_headers_real_dial() -> anyhow::Result<()> {
    run_ss2022_tcp_real_dial(
        "2022-blake3-aes-128-gcm",
        vec![vec![0x10; 16], vec![0x20; 16], vec![0x30; 16]],
    )
    .await
}

#[tokio::test]
async fn ss_2022_blake3_aes_128_gcm_udp_real_dial() -> anyhow::Result<()> {
    run_ss2022_udp_real_dial("2022-blake3-aes-128-gcm", vec![vec![0x11; 16]]).await
}

#[tokio::test]
async fn ss_2022_blake3_aes_256_gcm_udp_real_dial() -> anyhow::Result<()> {
    run_ss2022_udp_real_dial("2022-blake3-aes-256-gcm", vec![vec![0x22; 32]]).await
}

#[tokio::test]
async fn ss_2022_blake3_chacha20_poly1305_udp_real_dial() -> anyhow::Result<()> {
    run_ss2022_udp_real_dial("2022-blake3-chacha20-poly1305", vec![vec![0x33; 32]]).await
}

#[tokio::test]
async fn ss_2022_udp_sip023_identity_headers_real_dial() -> anyhow::Result<()> {
    run_ss2022_udp_real_dial(
        "2022-blake3-aes-128-gcm",
        vec![vec![0x10; 16], vec![0x20; 16], vec![0x30; 16]],
    )
    .await
}

#[tokio::test]
async fn ssr_build_outbound_does_not_panic() {
    let cfg = build_just_ssr();
    let result = build_outbounds(&cfg.outbounds, None);
    assert!(result.is_ok(), "SSR build failed: {:?}", result.err());
    let map = result.unwrap();
    assert!(map.contains_key("ssr"));
}

#[tokio::test]
async fn ssr_auth_sha1_v4_udp_exchange_reports_unsupported() {
    let mut cfg = build_just_ssr();
    for outbound in &mut cfg.outbounds {
        if let OutboundConfig::Ssr { protocol, .. } = outbound {
            *protocol = "auth_sha1_v4".to_string();
        }
    }
    let map = build_outbounds(&cfg.outbounds, None).unwrap();
    let outbound = get_outbound(&map, "ssr");
    let dest = Destination::new("test.example", 53);
    let result = outbound.udp_exchange(&dest, b"ping", 1000).await;
    assert!(
        result.is_err(),
        "auth_sha1_v4 UDP must return Err, got Ok: {:?}",
        result
    );
    let err = result.unwrap_err().to_string().to_lowercase();
    assert!(
        err.contains("udp") || err.contains("not implement") || err.contains("unsupported"),
        "SSR UDP error msg should mention 'udp' / 'not implement' / 'unsupported', got: {err}"
    );
}

#[tokio::test]
async fn ss_plugin_config_parses() {
    let mut cfg = build_just_ss("aes-128-gcm", 8388);
    // 替换 SS 的 plugin 字段
    for ob in cfg.outbounds.iter_mut() {
        if let OutboundConfig::Shadowsocks { plugin, .. } = ob {
            *plugin = Some(supercore::config::ShadowsocksPluginConfig {
                mode: "obfs-local".to_string(),
                host: Some("example.com".to_string()),
                path: None,
                tls: false,
                skip_cert_verify: false,
            });
        }
    }
    let result = build_outbounds(&cfg.outbounds, None);
    assert!(
        result.is_ok(),
        "plugin config build failed: {:?}",
        result.err()
    );
}

#[tokio::test]
async fn ss_cargo_test_smoke() {
    // 最小冒烟: 验证关键类型都 import 到
    let _ = std::any::type_name::<HashMap<String, Arc<dyn supercore::outbound::Outbound>>>();
    let _ = build_just_ss("aes-128-gcm", 0);
    let _ = build_just_ssr();
}
