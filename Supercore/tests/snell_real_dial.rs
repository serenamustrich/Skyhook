use std::time::Duration;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes128Gcm, Aes256Gcm,
};
use anyhow::{anyhow, Context};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::ChaCha20Poly1305;
use supercore::{config::OutboundConfig, outbound::build_outbounds, routing::Destination};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};

const TAG_LEN: usize = 16;
const V4_SALT_LEN: usize = 16;
const V4_HEADER_PLAIN_LEN: usize = 7;
const V4_HEADER_CIPHER_LEN: usize = V4_HEADER_PLAIN_LEN + TAG_LEN;

#[derive(Clone, Copy)]
enum TestCipher {
    Aes128Gcm,
    Aes256Gcm,
    Chacha20Poly1305,
}

impl TestCipher {
    fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            Self::Aes256Gcm | Self::Chacha20Poly1305 => 32,
        }
    }

    fn encrypt(self, key: &[u8], nonce: &[u8], plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
        match self {
            Self::Aes128Gcm => Ok(Aes128Gcm::new_from_slice(key)?
                .encrypt(aes_gcm::Nonce::from_slice(nonce), plaintext)
                .map_err(|_| anyhow!("Snell AES-128-GCM encrypt failed"))?),
            Self::Aes256Gcm => Ok(Aes256Gcm::new_from_slice(key)?
                .encrypt(aes_gcm::Nonce::from_slice(nonce), plaintext)
                .map_err(|_| anyhow!("Snell AES-256-GCM encrypt failed"))?),
            Self::Chacha20Poly1305 => Ok(ChaCha20Poly1305::new_from_slice(key)?
                .encrypt(chacha20poly1305::Nonce::from_slice(nonce), plaintext)
                .map_err(|_| anyhow!("Snell ChaCha20-Poly1305 encrypt failed"))?),
        }
    }

    fn decrypt(self, key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
        match self {
            Self::Aes128Gcm => Ok(Aes128Gcm::new_from_slice(key)?
                .decrypt(aes_gcm::Nonce::from_slice(nonce), ciphertext)
                .map_err(|_| anyhow!("Snell AES-128-GCM decrypt failed"))?),
            Self::Aes256Gcm => Ok(Aes256Gcm::new_from_slice(key)?
                .decrypt(aes_gcm::Nonce::from_slice(nonce), ciphertext)
                .map_err(|_| anyhow!("Snell AES-256-GCM decrypt failed"))?),
            Self::Chacha20Poly1305 => Ok(ChaCha20Poly1305::new_from_slice(key)?
                .decrypt(chacha20poly1305::Nonce::from_slice(nonce), ciphertext)
                .map_err(|_| anyhow!("Snell ChaCha20-Poly1305 decrypt failed"))?),
        }
    }
}

#[derive(Clone, Copy)]
enum TestObfs {
    Plain,
    Http,
    Tls,
}

fn derive_snell_key(cipher: TestCipher, psk: &[u8], salt: &[u8]) -> anyhow::Result<Vec<u8>> {
    let params = Params::new(8, 3, 1, Some(32))
        .map_err(|error| anyhow!("invalid Argon2 params: {error}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut output = vec![0u8; 32];
    argon2
        .hash_password_into(psk, salt, &mut output)
        .map_err(|error| anyhow!("Snell key derivation failed: {error}"))?;
    output.truncate(cipher.key_len());
    Ok(output)
}

fn increment_nonce(nonce: &mut [u8]) {
    for byte in nonce {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            break;
        }
    }
}

fn encode_chunk(
    cipher: TestCipher,
    key: &[u8],
    nonce: &mut [u8],
    payload: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let mut output = cipher.encrypt(key, nonce, &(payload.len() as u16).to_be_bytes())?;
    increment_nonce(nonce);
    output.extend_from_slice(&cipher.encrypt(key, nonce, payload)?);
    increment_nonce(nonce);
    Ok(output)
}

fn swap_v4_padding(padding: &mut [u8], payload_cipher: &mut [u8]) {
    let limit = padding.len().min(payload_cipher.len());
    for index in (0..limit).step_by(2) {
        std::mem::swap(&mut padding[index], &mut payload_cipher[index]);
    }
}

fn encode_v4_frame(
    key: &[u8],
    nonce: &mut [u8],
    payload: &[u8],
    padding_len: usize,
) -> anyhow::Result<Vec<u8>> {
    let mut header = [0u8; V4_HEADER_PLAIN_LEN];
    header[0] = 4;
    header[3..5].copy_from_slice(&(padding_len as u16).to_be_bytes());
    header[5..7].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    let mut output = TestCipher::Aes128Gcm.encrypt(key, nonce, &header)?;
    increment_nonce(nonce);
    let mut payload_cipher = if payload.is_empty() {
        Vec::new()
    } else {
        let encrypted = TestCipher::Aes128Gcm.encrypt(key, nonce, payload)?;
        increment_nonce(nonce);
        encrypted
    };
    let mut padding = vec![0x6d; padding_len];
    swap_v4_padding(&mut padding, &mut payload_cipher);
    output.extend_from_slice(&padding);
    output.extend_from_slice(&payload_cipher);
    Ok(output)
}

async fn decode_v4_frame(
    stream: &mut TcpStream,
    prefetched: &mut Vec<u8>,
    key: &[u8],
    nonce: &mut [u8],
) -> anyhow::Result<Vec<u8>> {
    let header_cipher = take_exact(stream, prefetched, V4_HEADER_CIPHER_LEN).await?;
    let header = TestCipher::Aes128Gcm.decrypt(key, nonce, &header_cipher)?;
    increment_nonce(nonce);
    if header.len() != V4_HEADER_PLAIN_LEN || header[0] != 4 {
        return Err(anyhow!("invalid Snell v4 test frame header"));
    }
    let padding_len = u16::from_be_bytes(header[3..5].try_into()?) as usize;
    let payload_len = u16::from_be_bytes(header[5..7].try_into()?) as usize;
    let mut frame = take_exact(stream, prefetched, padding_len + payload_len + TAG_LEN).await?;
    let (padding, payload_cipher) = frame.split_at_mut(padding_len);
    swap_v4_padding(padding, payload_cipher);
    let payload = TestCipher::Aes128Gcm.decrypt(key, nonce, payload_cipher)?;
    increment_nonce(nonce);
    Ok(payload)
}

async fn take_exact(
    stream: &mut TcpStream,
    prefetched: &mut Vec<u8>,
    length: usize,
) -> anyhow::Result<Vec<u8>> {
    while prefetched.len() < length {
        let mut buffer = [0u8; 4096];
        let count = stream.read(&mut buffer).await?;
        if count == 0 {
            return Err(anyhow!("unexpected EOF while reading Snell test frame"));
        }
        prefetched.extend_from_slice(&buffer[..count]);
    }
    Ok(prefetched.drain(..length).collect())
}

async fn decode_chunk(
    stream: &mut TcpStream,
    prefetched: &mut Vec<u8>,
    cipher: TestCipher,
    key: &[u8],
    nonce: &mut [u8],
) -> anyhow::Result<Vec<u8>> {
    let encrypted_length = take_exact(stream, prefetched, 2 + TAG_LEN).await?;
    let length = cipher.decrypt(key, nonce, &encrypted_length)?;
    increment_nonce(nonce);
    let length = u16::from_be_bytes(
        length
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("invalid Snell encrypted length"))?,
    ) as usize;
    let encrypted_payload = take_exact(stream, prefetched, length + TAG_LEN).await?;
    let payload = cipher.decrypt(key, nonce, &encrypted_payload)?;
    increment_nonce(nonce);
    Ok(payload)
}

fn tls_record(content_type: u8, payload: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(payload.len() + 5);
    output.extend_from_slice(&[content_type, 0x03, 0x03]);
    output.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    output.extend_from_slice(payload);
    output
}

async fn read_tls_record(stream: &mut TcpStream) -> anyhow::Result<(u8, Vec<u8>)> {
    let mut header = [0u8; 5];
    stream.read_exact(&mut header).await?;
    if header[1] != 0x03 {
        return Err(anyhow!("invalid TLS-obfs record version"));
    }
    let mut payload = vec![0u8; u16::from_be_bytes([header[3], header[4]]) as usize];
    stream.read_exact(&mut payload).await?;
    Ok((header[0], payload))
}

fn extract_tls_ticket(client_hello: &[u8]) -> anyhow::Result<Vec<u8>> {
    if client_hello.len() < 9 || client_hello[0] != 0x16 || client_hello[5] != 0x01 {
        return Err(anyhow!("invalid Snell TLS-obfs ClientHello"));
    }
    let body = &client_hello[9..];
    let mut offset = 2 + 32;
    let session_id_len = *body
        .get(offset)
        .ok_or_else(|| anyhow!("missing ClientHello session id length"))?
        as usize;
    offset += 1 + session_id_len;
    let cipher_len = u16::from_be_bytes(
        body.get(offset..offset + 2)
            .ok_or_else(|| anyhow!("missing ClientHello cipher length"))?
            .try_into()?,
    ) as usize;
    offset += 2 + cipher_len;
    let compression_len = *body
        .get(offset)
        .ok_or_else(|| anyhow!("missing ClientHello compression length"))?
        as usize;
    offset += 1 + compression_len;
    let extensions_len = u16::from_be_bytes(
        body.get(offset..offset + 2)
            .ok_or_else(|| anyhow!("missing ClientHello extension length"))?
            .try_into()?,
    ) as usize;
    offset += 2;
    let extensions_end = offset + extensions_len;
    while offset + 4 <= extensions_end {
        let extension_type = u16::from_be_bytes(body[offset..offset + 2].try_into()?);
        let extension_len = u16::from_be_bytes(body[offset + 2..offset + 4].try_into()?) as usize;
        offset += 4;
        let extension = body
            .get(offset..offset + extension_len)
            .ok_or_else(|| anyhow!("truncated ClientHello extension"))?;
        if extension_type == 0x0023 {
            return Ok(extension.to_vec());
        }
        offset += extension_len;
    }
    Err(anyhow!("Snell TLS-obfs ClientHello has no session ticket"))
}

async fn read_initial_payload(stream: &mut TcpStream, obfs: TestObfs) -> anyhow::Result<Vec<u8>> {
    match obfs {
        TestObfs::Plain => Ok(Vec::new()),
        TestObfs::Http => {
            let mut data = Vec::new();
            let header_end = loop {
                let mut buffer = [0u8; 1024];
                let count = stream.read(&mut buffer).await?;
                if count == 0 {
                    return Err(anyhow!("Snell HTTP-obfs request ended early"));
                }
                data.extend_from_slice(&buffer[..count]);
                if let Some(index) = data.windows(4).position(|item| item == b"\r\n\r\n") {
                    break index + 4;
                }
            };
            let header = std::str::from_utf8(&data[..header_end])?;
            assert!(header.starts_with("GET / HTTP/1.1\r\n"));
            assert!(header.contains("Host: obfs.example"));
            Ok(data.split_off(header_end))
        }
        TestObfs::Tls => {
            let (content_type, payload) = read_tls_record(stream).await?;
            if content_type != 0x16 {
                return Err(anyhow!("expected TLS-obfs ClientHello"));
            }
            let mut record = tls_record(content_type, &payload);
            record[1] = 0x03;
            record[2] = 0x01;
            extract_tls_ticket(&record)
        }
    }
}

async fn read_next_payload(
    stream: &mut TcpStream,
    prefetched: &mut Vec<u8>,
    obfs: TestObfs,
    cipher: TestCipher,
    key: &[u8],
    nonce: &mut [u8],
) -> anyhow::Result<Vec<u8>> {
    if matches!(obfs, TestObfs::Tls) {
        let (content_type, payload) = read_tls_record(stream).await?;
        if content_type != 0x17 {
            return Err(anyhow!("expected TLS-obfs application data"));
        }
        prefetched.extend_from_slice(&payload);
    }
    decode_chunk(stream, prefetched, cipher, key, nonce).await
}

async fn read_next_v4_payload(
    stream: &mut TcpStream,
    prefetched: &mut Vec<u8>,
    obfs: TestObfs,
    key: &[u8],
    nonce: &mut [u8],
) -> anyhow::Result<Vec<u8>> {
    if matches!(obfs, TestObfs::Tls) {
        let (content_type, payload) = read_tls_record(stream).await?;
        if content_type != 0x17 {
            return Err(anyhow!("expected TLS-obfs application data"));
        }
        prefetched.extend_from_slice(&payload);
    }
    decode_v4_frame(stream, prefetched, key, nonce).await
}

async fn send_server_bytes(
    stream: &mut TcpStream,
    obfs: TestObfs,
    first: &[u8],
    subsequent: &[u8],
) -> anyhow::Result<()> {
    match obfs {
        TestObfs::Plain => {
            stream.write_all(first).await?;
            stream.write_all(subsequent).await?;
        }
        TestObfs::Http => {
            stream
                .write_all(b"HTTP/1.1 101 Switching Protocols\r\nContent-Length: 0\r\n\r\n")
                .await?;
            stream.write_all(first).await?;
            stream.write_all(subsequent).await?;
        }
        TestObfs::Tls => {
            stream.write_all(&tls_record(0x16, &[0x02])).await?;
            stream.write_all(&tls_record(0x16, first)).await?;
            stream.write_all(&tls_record(0x17, subsequent)).await?;
        }
    }
    stream.flush().await?;
    Ok(())
}

async fn run_snell_tcp(
    version: u8,
    method: Option<&str>,
    cipher: TestCipher,
    obfs: TestObfs,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let psk = b"snell-test-psk".to_vec();
    let server_psk = psk.clone();

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let mut prefetched = read_initial_payload(&mut stream, obfs).await?;
        let request_salt = take_exact(&mut stream, &mut prefetched, cipher.key_len()).await?;
        let request_key = derive_snell_key(cipher, &server_psk, &request_salt)?;
        let mut request_nonce = [0u8; 12];
        let handshake = decode_chunk(
            &mut stream,
            &mut prefetched,
            cipher,
            &request_key,
            &mut request_nonce,
        )
        .await?;
        assert_eq!(handshake[0], 1);
        assert_eq!(handshake[1], if version == 2 { 5 } else { 1 });
        assert_eq!(handshake[2], 0);
        assert_eq!(handshake[3] as usize, "target.example".len());
        assert_eq!(&handshake[4..4 + "target.example".len()], b"target.example");

        let response_salt = vec![0x90 + version; cipher.key_len()];
        assert_ne!(response_salt, request_salt);
        let response_key = derive_snell_key(cipher, &server_psk, &response_salt)?;
        let mut response_nonce = [0u8; 12];
        let status = encode_chunk(cipher, &response_key, &mut response_nonce, &[0])?;

        let upload = read_next_payload(
            &mut stream,
            &mut prefetched,
            obfs,
            cipher,
            &request_key,
            &mut request_nonce,
        )
        .await?;
        assert_eq!(upload, b"ping");
        let pong = encode_chunk(cipher, &response_key, &mut response_nonce, b"pong")?;

        let mut first = response_salt;
        first.extend_from_slice(&status);
        send_server_bytes(&mut stream, obfs, &first, &pong).await?;
        anyhow::Ok(())
    });

    let outbounds = build_outbounds(
        &[OutboundConfig::Snell {
            name: "snell".to_string(),
            server: "127.0.0.1".to_string(),
            port: address.port(),
            psk: String::from_utf8(psk)?,
            method: method.map(ToString::to_string),
            version: Some(version),
            obfs: match obfs {
                TestObfs::Plain => None,
                TestObfs::Http => Some("http".to_string()),
                TestObfs::Tls => Some("tls".to_string()),
            },
            obfs_host: Some("obfs.example".to_string()),
        }],
        None,
    )?;
    let outbound = outbounds
        .get("snell")
        .context("missing Snell test outbound")?;
    let mut tunnel = outbound
        .connect(&Destination::new("target.example", 443), 3000)
        .await?;
    tunnel.write_all(b"ping").await?;
    tunnel.flush().await?;
    let mut response = [0u8; 4];
    timeout(Duration::from_secs(3), tunnel.read_exact(&mut response))
        .await
        .context("Snell TCP response timed out")??;
    assert_eq!(&response, b"pong");
    server.await??;
    Ok(())
}

async fn run_snell_v4_tcp(version: u8, obfs: TestObfs) -> anyhow::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let psk = b"snell-v4-test-psk".to_vec();
    let server_psk = psk.clone();

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let mut prefetched = read_initial_payload(&mut stream, obfs).await?;
        let request_salt = take_exact(&mut stream, &mut prefetched, V4_SALT_LEN).await?;
        let request_key = derive_snell_key(TestCipher::Aes128Gcm, &server_psk, &request_salt)?;
        let mut request_nonce = [0u8; 12];
        let handshake = decode_v4_frame(
            &mut stream,
            &mut prefetched,
            &request_key,
            &mut request_nonce,
        )
        .await?;
        assert_eq!(handshake[0], 1);
        assert_eq!(handshake[1], 1);
        assert_eq!(handshake[2], 0);
        assert_eq!(handshake[3] as usize, "target.example".len());
        assert_eq!(&handshake[4..4 + "target.example".len()], b"target.example");

        let upload = read_next_v4_payload(
            &mut stream,
            &mut prefetched,
            obfs,
            &request_key,
            &mut request_nonce,
        )
        .await?;
        assert_eq!(upload, b"ping");

        let response_salt = [0xe0 + version; V4_SALT_LEN];
        let response_key = derive_snell_key(TestCipher::Aes128Gcm, &server_psk, &response_salt)?;
        let mut response_nonce = [0u8; 12];
        let status = encode_v4_frame(&response_key, &mut response_nonce, &[0], 300)?;
        let pong = encode_v4_frame(&response_key, &mut response_nonce, b"pong", 0)?;
        let mut first = response_salt.to_vec();
        first.extend_from_slice(&status);
        send_server_bytes(&mut stream, obfs, &first, &pong).await?;
        anyhow::Ok(())
    });

    let outbounds = build_outbounds(
        &[OutboundConfig::Snell {
            name: "snell-v4".to_string(),
            server: "127.0.0.1".to_string(),
            port: address.port(),
            psk: String::from_utf8(psk)?,
            method: None,
            version: Some(version),
            obfs: match obfs {
                TestObfs::Plain => None,
                TestObfs::Http => Some("http".to_string()),
                TestObfs::Tls => Some("tls".to_string()),
            },
            obfs_host: Some("obfs.example".to_string()),
        }],
        None,
    )?;
    let mut tunnel = outbounds
        .get("snell-v4")
        .context("missing Snell v4 outbound")?
        .connect(&Destination::new("target.example", 443), 3000)
        .await?;
    tunnel.write_all(b"ping").await?;
    tunnel.flush().await?;
    let mut response = [0u8; 4];
    timeout(Duration::from_secs(3), tunnel.read_exact(&mut response))
        .await
        .context("Snell v4 TCP response timed out")??;
    assert_eq!(&response, b"pong");
    server.await??;
    Ok(())
}

#[tokio::test]
async fn snell_v1_chacha20_tcp_real_dial() -> anyhow::Result<()> {
    run_snell_tcp(1, None, TestCipher::Chacha20Poly1305, TestObfs::Plain).await
}

#[tokio::test]
async fn snell_v2_aes128_tcp_real_dial() -> anyhow::Result<()> {
    run_snell_tcp(2, None, TestCipher::Aes128Gcm, TestObfs::Plain).await
}

#[tokio::test]
async fn snell_v3_aes128_tcp_real_dial() -> anyhow::Result<()> {
    run_snell_tcp(3, None, TestCipher::Aes128Gcm, TestObfs::Plain).await
}

#[tokio::test]
async fn snell_v3_aes256_http_obfs_real_dial() -> anyhow::Result<()> {
    run_snell_tcp(
        3,
        Some("aes-256-gcm"),
        TestCipher::Aes256Gcm,
        TestObfs::Http,
    )
    .await
}

#[tokio::test]
async fn snell_v3_tls_obfs_real_dial() -> anyhow::Result<()> {
    run_snell_tcp(3, None, TestCipher::Aes128Gcm, TestObfs::Tls).await
}

#[tokio::test]
async fn snell_v4_tcp_real_dial() -> anyhow::Result<()> {
    run_snell_v4_tcp(4, TestObfs::Plain).await
}

#[tokio::test]
async fn snell_v5_v4_compatible_tcp_real_dial() -> anyhow::Result<()> {
    run_snell_v4_tcp(5, TestObfs::Plain).await
}

#[tokio::test]
async fn snell_v4_http_obfs_real_dial() -> anyhow::Result<()> {
    run_snell_v4_tcp(4, TestObfs::Http).await
}

#[tokio::test]
async fn snell_v4_tls_obfs_real_dial() -> anyhow::Result<()> {
    run_snell_v4_tcp(4, TestObfs::Tls).await
}

#[tokio::test]
async fn snell_v3_udp_over_tcp_real_dial() -> anyhow::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let psk = b"snell-udp-psk".to_vec();
    let server_psk = psk.clone();

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let mut prefetched = Vec::new();
        let request_salt = take_exact(&mut stream, &mut prefetched, 16).await?;
        let request_key = derive_snell_key(TestCipher::Aes128Gcm, &server_psk, &request_salt)?;
        let mut request_nonce = [0u8; 12];
        let handshake = decode_chunk(
            &mut stream,
            &mut prefetched,
            TestCipher::Aes128Gcm,
            &request_key,
            &mut request_nonce,
        )
        .await?;
        assert_eq!(handshake, [1, 6, 0]);

        let response_salt = vec![0xa3; 16];
        let response_key = derive_snell_key(TestCipher::Aes128Gcm, &server_psk, &response_salt)?;
        let mut response_nonce = [0u8; 12];
        let status = encode_chunk(
            TestCipher::Aes128Gcm,
            &response_key,
            &mut response_nonce,
            &[0],
        )?;
        stream.write_all(&response_salt).await?;
        stream.write_all(&status).await?;
        stream.flush().await?;

        let packet = decode_chunk(
            &mut stream,
            &mut prefetched,
            TestCipher::Aes128Gcm,
            &request_key,
            &mut request_nonce,
        )
        .await?;
        assert_eq!(packet[0], 1);
        assert_eq!(packet[1] as usize, "dns.example".len());
        let host_end = 2 + "dns.example".len();
        assert_eq!(&packet[2..host_end], b"dns.example");
        assert_eq!(
            u16::from_be_bytes(packet[host_end..host_end + 2].try_into()?),
            53
        );
        assert_eq!(&packet[host_end + 2..], b"query");

        let mut response = vec![4, 1, 1, 1, 1];
        response.extend_from_slice(&53u16.to_be_bytes());
        response.extend_from_slice(b"answer");
        let response = encode_chunk(
            TestCipher::Aes128Gcm,
            &response_key,
            &mut response_nonce,
            &response,
        )?;
        stream.write_all(&response).await?;
        stream.flush().await?;
        anyhow::Ok(())
    });

    let outbounds = build_outbounds(
        &[OutboundConfig::Snell {
            name: "snell-udp".to_string(),
            server: "127.0.0.1".to_string(),
            port: address.port(),
            psk: String::from_utf8(psk)?,
            method: None,
            version: Some(3),
            obfs: None,
            obfs_host: None,
        }],
        None,
    )?;
    let response = outbounds
        .get("snell-udp")
        .context("missing Snell UDP outbound")?
        .udp_exchange(&Destination::new("dns.example", 53), b"query", 3000)
        .await?;
    assert_eq!(response, b"answer");
    server.await??;
    Ok(())
}

async fn run_snell_v4_udp(version: u8) -> anyhow::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let psk = b"snell-v4-udp-psk".to_vec();
    let server_psk = psk.clone();

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let mut prefetched = Vec::new();
        let request_salt = take_exact(&mut stream, &mut prefetched, V4_SALT_LEN).await?;
        let request_key = derive_snell_key(TestCipher::Aes128Gcm, &server_psk, &request_salt)?;
        let mut request_nonce = [0u8; 12];
        let handshake = decode_v4_frame(
            &mut stream,
            &mut prefetched,
            &request_key,
            &mut request_nonce,
        )
        .await?;
        assert_eq!(handshake, [1, 6, 0]);

        let response_salt = [0xf0 + version; V4_SALT_LEN];
        let response_key = derive_snell_key(TestCipher::Aes128Gcm, &server_psk, &response_salt)?;
        let mut response_nonce = [0u8; 12];
        let status = encode_v4_frame(&response_key, &mut response_nonce, &[0], 288)?;
        stream.write_all(&response_salt).await?;
        stream.write_all(&status).await?;
        stream.flush().await?;

        let packet = decode_v4_frame(
            &mut stream,
            &mut prefetched,
            &request_key,
            &mut request_nonce,
        )
        .await?;
        assert_eq!(packet[0], 1);
        assert_eq!(packet[1] as usize, "dns.example".len());
        let host_end = 2 + "dns.example".len();
        assert_eq!(&packet[2..host_end], b"dns.example");
        assert_eq!(
            u16::from_be_bytes(packet[host_end..host_end + 2].try_into()?),
            53
        );
        assert_eq!(&packet[host_end + 2..], b"query");

        let mut response = vec![4, 1, 1, 1, 1];
        response.extend_from_slice(&53u16.to_be_bytes());
        response.extend_from_slice(b"answer");
        let response = encode_v4_frame(&response_key, &mut response_nonce, &response, 0)?;
        stream.write_all(&response).await?;
        stream.flush().await?;
        anyhow::Ok(())
    });

    let outbounds = build_outbounds(
        &[OutboundConfig::Snell {
            name: "snell-v4-udp".to_string(),
            server: "127.0.0.1".to_string(),
            port: address.port(),
            psk: String::from_utf8(psk)?,
            method: None,
            version: Some(version),
            obfs: None,
            obfs_host: None,
        }],
        None,
    )?;
    let response = outbounds
        .get("snell-v4-udp")
        .context("missing Snell v4 UDP outbound")?
        .udp_exchange(&Destination::new("dns.example", 53), b"query", 3000)
        .await?;
    assert_eq!(response, b"answer");
    server.await??;
    Ok(())
}

#[tokio::test]
async fn snell_v4_udp_over_tcp_real_dial() -> anyhow::Result<()> {
    run_snell_v4_udp(4).await
}

#[tokio::test]
async fn snell_v5_v4_compatible_udp_real_dial() -> anyhow::Result<()> {
    run_snell_v4_udp(5).await
}

#[tokio::test]
async fn snell_v2_udp_is_rejected_before_dial() -> anyhow::Result<()> {
    let outbounds = build_outbounds(
        &[OutboundConfig::Snell {
            name: "snell-v2".to_string(),
            server: "127.0.0.1".to_string(),
            port: 1,
            psk: "psk".to_string(),
            method: None,
            version: Some(2),
            obfs: None,
            obfs_host: None,
        }],
        None,
    )?;
    let error = outbounds
        .get("snell-v2")
        .context("missing Snell v2 outbound")?
        .udp_exchange(&Destination::new("dns.example", 53), b"query", 100)
        .await
        .expect_err("Snell v2 UDP must be rejected");
    assert!(error.to_string().contains("requires version 3"));
    Ok(())
}
