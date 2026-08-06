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
    if payload_len == 0 {
        if padding_len != 0 {
            return Err(anyhow!("Snell v4 zero frame contains padding"));
        }
        return Ok(Vec::new());
    }
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
    configured_version: Option<u8>,
    method: Option<&str>,
    cipher: TestCipher,
    obfs: TestObfs,
) -> anyhow::Result<()> {
    let version = configured_version.unwrap_or(1);
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
            version: configured_version,
            obfs: match obfs {
                TestObfs::Plain => None,
                TestObfs::Http => Some("http".to_string()),
                TestObfs::Tls => Some("tls".to_string()),
            },
            obfs_host: Some("obfs.example".to_string()),
            reuse: false,
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
            reuse: false,
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
async fn snell_v4_relays_large_bidirectional_stream() -> anyhow::Result<()> {
    const PAYLOAD_LEN: usize = 96 * 1024;

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let psk = b"snell-v4-large-stream-psk".to_vec();
    let server_psk = psk.clone();
    let payload = (0..PAYLOAD_LEN)
        .map(|index| (index % 251) as u8)
        .collect::<Vec<_>>();
    let server_payload = payload.clone();

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
        assert_eq!(handshake[1], 1);

        let response_salt = [0xd1; V4_SALT_LEN];
        let response_key = derive_snell_key(TestCipher::Aes128Gcm, &server_psk, &response_salt)?;
        let mut response_nonce = [0u8; 12];
        let status = encode_v4_frame(&response_key, &mut response_nonce, &[0], 0)?;
        stream.write_all(&response_salt).await?;
        stream.write_all(&status).await?;
        stream.flush().await?;

        let mut upload = Vec::with_capacity(PAYLOAD_LEN);
        while upload.len() < PAYLOAD_LEN {
            upload.extend_from_slice(
                &decode_v4_frame(
                    &mut stream,
                    &mut prefetched,
                    &request_key,
                    &mut request_nonce,
                )
                .await?,
            );
        }
        assert_eq!(upload, server_payload);

        for chunk in server_payload.chunks(12 * 1024) {
            let frame = encode_v4_frame(&response_key, &mut response_nonce, chunk, 0)?;
            stream.write_all(&frame).await?;
        }
        stream.flush().await?;
        anyhow::Ok(())
    });

    let outbounds = build_outbounds(
        &[OutboundConfig::Snell {
            name: "snell-v4-large".to_string(),
            server: "127.0.0.1".to_string(),
            port: address.port(),
            psk: String::from_utf8(psk)?,
            method: None,
            version: Some(4),
            obfs: None,
            obfs_host: None,
            reuse: false,
        }],
        None,
    )?;
    let mut tunnel = outbounds
        .get("snell-v4-large")
        .context("missing large-stream Snell outbound")?
        .connect(&Destination::new("large.example", 443), 3000)
        .await?;
    tunnel.write_all(&payload).await?;
    tunnel.flush().await?;
    let mut response = vec![0u8; PAYLOAD_LEN];
    timeout(Duration::from_secs(3), tunnel.read_exact(&mut response))
        .await
        .context("Snell large response timed out")??;
    assert_eq!(response, payload);
    server.await??;
    Ok(())
}

async fn send_reused_v4_server_frame(
    stream: &mut TcpStream,
    obfs: TestObfs,
    frame: &[u8],
) -> anyhow::Result<()> {
    if matches!(obfs, TestObfs::Tls) {
        stream.write_all(&tls_record(0x17, frame)).await?;
    } else {
        stream.write_all(frame).await?;
    }
    stream.flush().await?;
    Ok(())
}

async fn run_snell_v4_reuse(version: u8, obfs: TestObfs) -> anyhow::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let psk = b"snell-v4-reuse-test-psk".to_vec();
    let server_psk = psk.clone();

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let mut prefetched = read_initial_payload(&mut stream, obfs).await?;
        let request_salt = take_exact(&mut stream, &mut prefetched, V4_SALT_LEN).await?;
        let request_key = derive_snell_key(TestCipher::Aes128Gcm, &server_psk, &request_salt)?;
        let mut request_nonce = [0u8; 12];

        let response_salt = [0xb0 + version; V4_SALT_LEN];
        let response_key = derive_snell_key(TestCipher::Aes128Gcm, &server_psk, &response_salt)?;
        let mut response_nonce = [0u8; 12];

        let requests = [
            ("first.example", 443u16, b"first-request".as_slice()),
            ("second.example", 8443u16, b"second-request".as_slice()),
        ];
        for (index, (host, port, payload)) in requests.into_iter().enumerate() {
            let handshake = if index == 0 {
                decode_v4_frame(
                    &mut stream,
                    &mut prefetched,
                    &request_key,
                    &mut request_nonce,
                )
                .await?
            } else {
                read_next_v4_payload(
                    &mut stream,
                    &mut prefetched,
                    obfs,
                    &request_key,
                    &mut request_nonce,
                )
                .await?
            };
            assert_eq!(handshake[0], 1);
            assert_eq!(handshake[1], 5);
            assert_eq!(handshake[2], 0);
            let host_len = handshake[3] as usize;
            assert_eq!(&handshake[4..4 + host_len], host.as_bytes());
            assert_eq!(
                u16::from_be_bytes(handshake[4 + host_len..6 + host_len].try_into()?),
                port
            );

            let status = encode_v4_frame(&response_key, &mut response_nonce, &[0], 0)?;
            if index == 0 {
                let mut first = response_salt.to_vec();
                first.extend_from_slice(&status);
                send_server_bytes(&mut stream, obfs, &first, &[]).await?;
            } else {
                send_reused_v4_server_frame(&mut stream, obfs, &status).await?;
            }

            let upload = read_next_v4_payload(
                &mut stream,
                &mut prefetched,
                obfs,
                &request_key,
                &mut request_nonce,
            )
            .await?;
            assert_eq!(upload, payload);
            let echo = encode_v4_frame(&response_key, &mut response_nonce, payload, 0)?;
            send_reused_v4_server_frame(&mut stream, obfs, &echo).await?;

            let client_zero = read_next_v4_payload(
                &mut stream,
                &mut prefetched,
                obfs,
                &request_key,
                &mut request_nonce,
            )
            .await?;
            assert!(client_zero.is_empty());
            let server_zero = encode_v4_frame(&response_key, &mut response_nonce, &[], 0)?;
            send_reused_v4_server_frame(&mut stream, obfs, &server_zero).await?;
        }
        anyhow::Ok(())
    });

    let outbounds = build_outbounds(
        &[OutboundConfig::Snell {
            name: "snell-v4-reuse".to_string(),
            server: "127.0.0.1".to_string(),
            port: address.port(),
            psk: String::from_utf8(psk)?,
            method: Some("aes-128-gcm".to_string()),
            version: Some(version),
            obfs: match obfs {
                TestObfs::Plain => None,
                TestObfs::Http => Some("http".to_string()),
                TestObfs::Tls => Some("tls".to_string()),
            },
            obfs_host: Some("obfs.example".to_string()),
            reuse: true,
        }],
        None,
    )?;
    let outbound = outbounds
        .get("snell-v4-reuse")
        .context("missing Snell v4 reuse outbound")?;

    for (host, port, payload) in [
        ("first.example", 443u16, b"first-request".as_slice()),
        ("second.example", 8443u16, b"second-request".as_slice()),
    ] {
        let mut tunnel = outbound
            .connect(&Destination::new(host, port), 3000)
            .await?;
        tunnel.write_all(payload).await?;
        tunnel.shutdown().await?;
        let mut response = Vec::new();
        timeout(Duration::from_secs(3), tunnel.read_to_end(&mut response))
            .await
            .context("Snell v4 reuse response timed out")??;
        assert_eq!(response, payload);
    }

    server.await??;
    Ok(())
}

async fn serve_one_plain_v4_reuse_request(
    mut stream: TcpStream,
    psk: &[u8],
    expected_host: &str,
    expected_payload: &[u8],
    response_salt: [u8; V4_SALT_LEN],
) -> anyhow::Result<()> {
    let mut prefetched = Vec::new();
    let request_salt = take_exact(&mut stream, &mut prefetched, V4_SALT_LEN).await?;
    let request_key = derive_snell_key(TestCipher::Aes128Gcm, psk, &request_salt)?;
    let mut request_nonce = [0u8; 12];
    let handshake = decode_v4_frame(
        &mut stream,
        &mut prefetched,
        &request_key,
        &mut request_nonce,
    )
    .await?;
    assert_eq!(handshake[1], 5);
    let host_len = handshake[3] as usize;
    assert_eq!(&handshake[4..4 + host_len], expected_host.as_bytes());

    let response_key = derive_snell_key(TestCipher::Aes128Gcm, psk, &response_salt)?;
    let mut response_nonce = [0u8; 12];
    let status = encode_v4_frame(&response_key, &mut response_nonce, &[0], 0)?;
    stream.write_all(&response_salt).await?;
    stream.write_all(&status).await?;
    stream.flush().await?;

    let upload = decode_v4_frame(
        &mut stream,
        &mut prefetched,
        &request_key,
        &mut request_nonce,
    )
    .await?;
    assert_eq!(upload, expected_payload);
    let echo = encode_v4_frame(&response_key, &mut response_nonce, expected_payload, 0)?;
    stream.write_all(&echo).await?;

    let zero = decode_v4_frame(
        &mut stream,
        &mut prefetched,
        &request_key,
        &mut request_nonce,
    )
    .await?;
    assert!(zero.is_empty());
    let zero = encode_v4_frame(&response_key, &mut response_nonce, &[], 0)?;
    stream.write_all(&zero).await?;
    stream.flush().await?;
    Ok(())
}

async fn serve_concurrent_plain_v4_reuse_request(
    mut stream: TcpStream,
    psk: &[u8],
    response_salt: [u8; V4_SALT_LEN],
) -> anyhow::Result<String> {
    let mut prefetched = Vec::new();
    let request_salt = take_exact(&mut stream, &mut prefetched, V4_SALT_LEN).await?;
    let request_key = derive_snell_key(TestCipher::Aes128Gcm, psk, &request_salt)?;
    let mut request_nonce = [0u8; 12];
    let handshake = decode_v4_frame(
        &mut stream,
        &mut prefetched,
        &request_key,
        &mut request_nonce,
    )
    .await?;
    assert_eq!(handshake[1], 5);
    let host_len = handshake[3] as usize;
    let host = String::from_utf8(handshake[4..4 + host_len].to_vec())?;

    let response_key = derive_snell_key(TestCipher::Aes128Gcm, psk, &response_salt)?;
    let mut response_nonce = [0u8; 12];
    let status = encode_v4_frame(&response_key, &mut response_nonce, &[0], 0)?;
    stream.write_all(&response_salt).await?;
    stream.write_all(&status).await?;
    stream.flush().await?;

    let upload = decode_v4_frame(
        &mut stream,
        &mut prefetched,
        &request_key,
        &mut request_nonce,
    )
    .await?;
    let echo = encode_v4_frame(&response_key, &mut response_nonce, &upload, 0)?;
    stream.write_all(&echo).await?;

    let zero = decode_v4_frame(
        &mut stream,
        &mut prefetched,
        &request_key,
        &mut request_nonce,
    )
    .await?;
    assert!(zero.is_empty());
    let zero = encode_v4_frame(&response_key, &mut response_nonce, &[], 0)?;
    stream.write_all(&zero).await?;
    stream.flush().await?;
    Ok(host)
}

#[tokio::test]
async fn snell_v4_reuse_supports_concurrent_streams() -> anyhow::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let psk = b"snell-v4-concurrent-reuse-psk".to_vec();
    let server_psk = psk.clone();

    let server = tokio::spawn(async move {
        let mut handlers = Vec::new();
        for index in 0..4u8 {
            let (stream, _) = listener.accept().await?;
            let psk = server_psk.clone();
            handlers.push(tokio::spawn(async move {
                serve_concurrent_plain_v4_reuse_request(stream, &psk, [0xe0 + index; V4_SALT_LEN])
                    .await
            }));
        }
        let mut hosts = Vec::new();
        for handler in handlers {
            hosts.push(handler.await??);
        }
        hosts.sort();
        assert_eq!(
            hosts,
            [
                "concurrent-0.example",
                "concurrent-1.example",
                "concurrent-2.example",
                "concurrent-3.example",
            ]
        );
        anyhow::Ok(())
    });

    let outbounds = build_outbounds(
        &[OutboundConfig::Snell {
            name: "snell-v4-concurrent".to_string(),
            server: "127.0.0.1".to_string(),
            port: address.port(),
            psk: String::from_utf8(psk)?,
            method: None,
            version: Some(4),
            obfs: None,
            obfs_host: None,
            reuse: true,
        }],
        None,
    )?;
    let outbound = outbounds
        .get("snell-v4-concurrent")
        .context("missing concurrent Snell outbound")?;
    let destinations = [
        Destination::new("concurrent-0.example", 443),
        Destination::new("concurrent-1.example", 443),
        Destination::new("concurrent-2.example", 443),
        Destination::new("concurrent-3.example", 443),
    ];
    let (first, second, third, fourth) = tokio::join!(
        outbound.connect(&destinations[0], 3000),
        outbound.connect(&destinations[1], 3000),
        outbound.connect(&destinations[2], 3000),
        outbound.connect(&destinations[3], 3000),
    );
    let mut tunnels = [first?, second?, third?, fourth?];
    let payloads = [b"stream-0", b"stream-1", b"stream-2", b"stream-3"];
    for (tunnel, payload) in tunnels.iter_mut().zip(payloads) {
        tunnel.write_all(payload).await?;
        tunnel.shutdown().await?;
    }
    for (tunnel, payload) in tunnels.iter_mut().zip(payloads) {
        let mut response = Vec::new();
        timeout(Duration::from_secs(3), tunnel.read_to_end(&mut response))
            .await
            .context("concurrent Snell response timed out")??;
        assert_eq!(response, payload);
    }

    server.await??;
    Ok(())
}

#[tokio::test]
async fn snell_v4_reuse_retries_stale_pooled_connection() -> anyhow::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let psk = b"snell-v4-stale-pool-psk".to_vec();
    let server_psk = psk.clone();

    let server = tokio::spawn(async move {
        let (first, _) = listener.accept().await?;
        serve_one_plain_v4_reuse_request(
            first,
            &server_psk,
            "first.example",
            b"first",
            [0xc1; V4_SALT_LEN],
        )
        .await?;
        let (second, _) = listener.accept().await?;
        serve_one_plain_v4_reuse_request(
            second,
            &server_psk,
            "second.example",
            b"second",
            [0xc2; V4_SALT_LEN],
        )
        .await?;
        anyhow::Ok(())
    });

    let outbounds = build_outbounds(
        &[OutboundConfig::Snell {
            name: "snell-v4-stale".to_string(),
            server: "127.0.0.1".to_string(),
            port: address.port(),
            psk: String::from_utf8(psk)?,
            method: Some("aes-128-gcm".to_string()),
            version: Some(4),
            obfs: None,
            obfs_host: None,
            reuse: true,
        }],
        None,
    )?;
    let outbound = outbounds
        .get("snell-v4-stale")
        .context("missing stale-pool Snell outbound")?;

    for (host, payload) in [
        ("first.example", b"first".as_slice()),
        ("second.example", b"second".as_slice()),
    ] {
        let mut tunnel = outbound.connect(&Destination::new(host, 443), 3000).await?;
        tunnel.write_all(payload).await?;
        tunnel.shutdown().await?;
        let mut response = Vec::new();
        timeout(Duration::from_secs(3), tunnel.read_to_end(&mut response))
            .await
            .context("Snell stale-pool response timed out")??;
        assert_eq!(response, payload);
    }

    server.await??;
    Ok(())
}

#[tokio::test]
async fn snell_v1_chacha20_tcp_real_dial() -> anyhow::Result<()> {
    run_snell_tcp(Some(1), None, TestCipher::Chacha20Poly1305, TestObfs::Plain).await
}

#[tokio::test]
async fn snell_defaults_to_v1_chacha20_tcp_real_dial() -> anyhow::Result<()> {
    run_snell_tcp(None, None, TestCipher::Chacha20Poly1305, TestObfs::Plain).await
}

#[tokio::test]
async fn snell_empty_psk_is_rejected_before_dial() -> anyhow::Result<()> {
    let outbounds = build_outbounds(
        &[OutboundConfig::Snell {
            name: "snell-empty-psk".to_string(),
            server: "127.0.0.1".to_string(),
            port: 1,
            psk: String::new(),
            method: None,
            version: Some(3),
            obfs: None,
            obfs_host: None,
            reuse: false,
        }],
        None,
    )?;
    let outbound = outbounds
        .get("snell-empty-psk")
        .context("missing empty-PSK Snell outbound")?;
    let capability = outbound.capability();
    assert!(!capability.tcp_supported);
    assert!(!capability.udp_supported);
    assert!(capability
        .limitations
        .iter()
        .any(|limitation| limitation.contains("PSK must not be empty")));

    let tcp_error = match outbound
        .connect(&Destination::new("target.example", 443), 100)
        .await
    {
        Ok(_) => return Err(anyhow!("empty Snell PSK unexpectedly dialed TCP")),
        Err(error) => error,
    };
    assert!(tcp_error.to_string().contains("PSK must not be empty"));
    let udp_error = outbound
        .udp_exchange(&Destination::new("dns.example", 53), b"query", 100)
        .await
        .expect_err("empty Snell PSK unexpectedly dialed UDP");
    assert!(udp_error.to_string().contains("PSK must not be empty"));
    Ok(())
}

#[tokio::test]
async fn snell_wrong_psk_cannot_authenticate() -> anyhow::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let server_psk = b"snell-correct-psk".to_vec();

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let mut prefetched = Vec::new();
        let request_salt = take_exact(&mut stream, &mut prefetched, 32).await?;
        let request_key =
            derive_snell_key(TestCipher::Chacha20Poly1305, &server_psk, &request_salt)?;
        let mut request_nonce = [0u8; 12];
        let result = decode_chunk(
            &mut stream,
            &mut prefetched,
            TestCipher::Chacha20Poly1305,
            &request_key,
            &mut request_nonce,
        )
        .await;
        assert!(
            result.is_err(),
            "wrong Snell PSK authenticated unexpectedly"
        );
        anyhow::Ok(())
    });

    let outbounds = build_outbounds(
        &[OutboundConfig::Snell {
            name: "snell-wrong-psk".to_string(),
            server: "127.0.0.1".to_string(),
            port: address.port(),
            psk: "snell-wrong-psk".to_string(),
            method: None,
            version: Some(1),
            obfs: None,
            obfs_host: None,
            reuse: false,
        }],
        None,
    )?;
    let mut tunnel = outbounds
        .get("snell-wrong-psk")
        .context("missing wrong-PSK Snell outbound")?
        .connect(&Destination::new("target.example", 443), 3000)
        .await?;
    tunnel.write_all(b"must-not-pass").await?;
    tunnel.flush().await?;
    let mut response = [0u8; 1];
    let count = timeout(Duration::from_secs(3), tunnel.read(&mut response))
        .await
        .context("wrong-PSK Snell stream did not close")??;
    assert_eq!(count, 0);
    server.await??;
    Ok(())
}

#[tokio::test]
async fn snell_server_close_propagates_eof() -> anyhow::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let psk = b"snell-server-close-psk".to_vec();
    let server_psk = psk.clone();

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let mut prefetched = Vec::new();
        let request_salt = take_exact(&mut stream, &mut prefetched, 32).await?;
        let request_key =
            derive_snell_key(TestCipher::Chacha20Poly1305, &server_psk, &request_salt)?;
        let mut request_nonce = [0u8; 12];
        let handshake = decode_chunk(
            &mut stream,
            &mut prefetched,
            TestCipher::Chacha20Poly1305,
            &request_key,
            &mut request_nonce,
        )
        .await?;
        assert_eq!(handshake[1], 1);
        anyhow::Ok(())
    });

    let outbounds = build_outbounds(
        &[OutboundConfig::Snell {
            name: "snell-server-close".to_string(),
            server: "127.0.0.1".to_string(),
            port: address.port(),
            psk: String::from_utf8(psk)?,
            method: None,
            version: Some(1),
            obfs: None,
            obfs_host: None,
            reuse: false,
        }],
        None,
    )?;
    let mut tunnel = outbounds
        .get("snell-server-close")
        .context("missing server-close Snell outbound")?
        .connect(&Destination::new("target.example", 443), 3000)
        .await?;
    let mut response = [0u8; 1];
    let count = timeout(Duration::from_secs(3), tunnel.read(&mut response))
        .await
        .context("closed Snell server did not propagate EOF")??;
    assert_eq!(count, 0);
    server.await??;
    Ok(())
}

#[tokio::test]
async fn snell_v2_aes128_tcp_real_dial() -> anyhow::Result<()> {
    run_snell_tcp(Some(2), None, TestCipher::Aes128Gcm, TestObfs::Plain).await
}

#[tokio::test]
async fn snell_v3_aes128_tcp_real_dial() -> anyhow::Result<()> {
    run_snell_tcp(Some(3), None, TestCipher::Aes128Gcm, TestObfs::Plain).await
}

#[tokio::test]
async fn snell_v3_aes256_http_obfs_real_dial() -> anyhow::Result<()> {
    run_snell_tcp(
        Some(3),
        Some("aes-256-gcm"),
        TestCipher::Aes256Gcm,
        TestObfs::Http,
    )
    .await
}

#[tokio::test]
async fn snell_v3_tls_obfs_real_dial() -> anyhow::Result<()> {
    run_snell_tcp(Some(3), None, TestCipher::Aes128Gcm, TestObfs::Tls).await
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
async fn snell_v4_connection_reuse_real_dial() -> anyhow::Result<()> {
    run_snell_v4_reuse(4, TestObfs::Plain).await
}

#[tokio::test]
async fn snell_v5_connection_reuse_real_dial() -> anyhow::Result<()> {
    run_snell_v4_reuse(5, TestObfs::Plain).await
}

#[tokio::test]
async fn snell_v4_http_obfs_connection_reuse_real_dial() -> anyhow::Result<()> {
    run_snell_v4_reuse(4, TestObfs::Http).await
}

#[tokio::test]
async fn snell_v4_tls_obfs_connection_reuse_real_dial() -> anyhow::Result<()> {
    run_snell_v4_reuse(4, TestObfs::Tls).await
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
            reuse: false,
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
            reuse: false,
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
            reuse: false,
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
