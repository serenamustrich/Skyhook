use std::{io::Cursor, sync::Arc, time::Duration};

use anyhow::{anyhow, Context};
use async_trait::async_trait;
use rustls_pki_types::ServerName;
use sha1::{Digest, Sha1};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream},
    time::timeout,
};

use crate::routing::Destination;

use super::{
    io::read_exact_or_eof,
    target::encode_socks5_destination,
    transports::{connect_tcp, tls_client_config},
    BoxedStream, Outbound, OutboundCapability,
};

const TLS_HEADER_LEN: usize = 5;
const TLS_FRAME_MAX_LEN: usize = TLS_HEADER_LEN + 65_535;
const CONTENT_TYPE_HANDSHAKE: u8 = 0x16;
const CONTENT_TYPE_APPLICATION_DATA: u8 = 0x17;
const CONTENT_TYPE_ALERT: u8 = 0x15;
const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;
const HANDSHAKE_TYPE_SERVER_HELLO: u8 = 0x02;
const MAX_WRITE_PAYLOAD_LEN: usize = 16_380;

pub(super) struct ShadowTlsOutbound {
    name: String,
    server: String,
    port: u16,
    password: String,
    version: Option<u8>,
    sni: Option<String>,
    skip_cert_verify: bool,
}

impl ShadowTlsOutbound {
    pub(super) fn new(
        name: String,
        server: String,
        port: u16,
        password: String,
        version: Option<u8>,
        sni: Option<String>,
        skip_cert_verify: bool,
    ) -> Self {
        Self {
            name,
            server,
            port,
            password,
            version,
            sni,
            skip_cert_verify,
        }
    }
}

#[async_trait]
impl Outbound for ShadowTlsOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "shadowtls"
    }

    fn capability(&self) -> OutboundCapability {
        if self.version.unwrap_or(3) == 3 {
            OutboundCapability::tcp_only("shadowtls udp is not supported")
        } else {
            OutboundCapability::unsupported("only shadowtls v3 is supported")
        }
    }

    async fn connect(
        &self,
        destination: &Destination,
        timeout_ms: u64,
    ) -> anyhow::Result<BoxedStream> {
        let version = self.version.unwrap_or(3);
        if version != 3 {
            return Err(anyhow!(
                "unsupported shadowtls version {version}; supported: 3"
            ));
        }
        if self.password.is_empty() {
            return Err(anyhow!("shadowtls password is empty"));
        }
        let tcp = connect_tcp(&format!("{}:{}", self.server, self.port), timeout_ms).await?;
        let server_name = self.sni.as_deref().unwrap_or(&self.server).to_string();
        let tunnel = setup_v3_tunnel(
            tcp,
            self.password.as_bytes(),
            &server_name,
            self.skip_cert_verify,
            timeout_ms,
        )
        .await?;
        let mut initial_payload = Vec::new();
        encode_socks5_destination(destination, &mut initial_payload)?;
        Ok(Box::new(spawn_stream(tunnel, initial_payload)))
    }
}

#[derive(Clone)]
struct ShadowTlsHmac {
    inner: Sha1,
    outer_pad: [u8; 64],
}

impl ShadowTlsHmac {
    fn new(key: &[u8]) -> Self {
        let key = if key.len() > 64 {
            Sha1::digest(key).to_vec()
        } else {
            key.to_vec()
        };
        let mut inner_pad = [0x36u8; 64];
        let mut outer_pad = [0x5cu8; 64];
        for (index, byte) in key.iter().enumerate() {
            inner_pad[index] ^= byte;
            outer_pad[index] ^= byte;
        }
        let mut inner = Sha1::new();
        inner.update(inner_pad);
        Self { inner, outer_pad }
    }

    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    fn digest(&self) -> [u8; 4] {
        let inner_digest = self.inner.clone().finalize();
        let mut outer = Sha1::new();
        outer.update(self.outer_pad);
        outer.update(inner_digest);
        let digest = outer.finalize();
        [digest[0], digest[1], digest[2], digest[3]]
    }

    fn finalized_digest(self) -> [u8; 4] {
        self.digest()
    }
}

struct ShadowTlsTunnel<S> {
    stream: S,
    read_hmac: ShadowTlsHmac,
    write_hmac: ShadowTlsHmac,
    handshake_hmac: ShadowTlsHmac,
}

async fn setup_v3_tunnel<S>(
    mut stream: S,
    password: &[u8],
    server_name: &str,
    skip_cert_verify: bool,
    timeout_ms: u64,
) -> anyhow::Result<ShadowTlsTunnel<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let tls_config = tls_client_config(skip_cert_verify)?;
    let tls_server_name = ServerName::try_from(server_name.to_string())
        .map_err(|error| anyhow!("invalid shadowtls server name: {error}"))?;
    let mut client_conn = rustls::ClientConnection::new(Arc::new(tls_config), tls_server_name)
        .map_err(|error| anyhow!("failed to create shadowtls client hello: {error}"))?;

    let mut client_hello = Vec::with_capacity(1024);
    client_conn
        .write_tls(&mut client_hello)
        .map_err(|error| anyhow!("failed to build shadowtls client hello: {error}"))?;
    let initial_hmac = ShadowTlsHmac::new(password);
    let modified_client_hello = modify_client_hello(&client_hello, &initial_hmac)?;
    stream.write_all(&modified_client_hello).await?;
    stream.flush().await?;

    let server_hello = timeout(
        Duration::from_millis(timeout_ms),
        read_tls_record(&mut stream),
    )
    .await
    .context("shadowtls server hello timed out")?
    .context("failed to read shadowtls server hello")?
    .ok_or_else(|| anyhow!("shadowtls server closed before server hello"))?;
    let server_random = parse_server_hello_random(&server_hello)?;
    feed_rustls_client_connection(&mut client_conn, &server_hello)?;
    client_conn
        .process_new_packets()
        .map_err(|error| anyhow!("shadowtls failed to process server hello: {error}"))?;

    let mut hmac_server_random = initial_hmac.clone();
    hmac_server_random.update(&server_random);
    let mut write_hmac = hmac_server_random.clone();
    write_hmac.update(b"C");
    let mut read_hmac = hmac_server_random.clone();
    read_hmac.update(b"S");

    while client_conn.is_handshaking() {
        if client_conn.wants_write() {
            let mut output = Vec::new();
            let n = client_conn
                .write_tls(&mut output)
                .map_err(|error| anyhow!("shadowtls tls write failed: {error}"))?;
            if n > 0 {
                stream.write_all(&output).await?;
                stream.flush().await?;
            }
            continue;
        }

        let frame = timeout(
            Duration::from_millis(timeout_ms),
            read_tls_record(&mut stream),
        )
        .await
        .context("shadowtls handshake frame timed out")?
        .context("failed to read shadowtls handshake frame")?
        .ok_or_else(|| anyhow!("shadowtls server closed during handshake"))?;
        match frame[0] {
            CONTENT_TYPE_APPLICATION_DATA => {
                let payload_len = u16::from_be_bytes([frame[3], frame[4]]) as usize;
                if payload_len < 5 {
                    return Err(anyhow!("shadowtls handshake app-data frame is too short"));
                }
                let received = &frame[TLS_HEADER_LEN..TLS_HEADER_LEN + 4];
                let payload = &frame[TLS_HEADER_LEN + 4..TLS_HEADER_LEN + payload_len];
                hmac_server_random.update(payload);
                if hmac_server_random.digest() != received {
                    return Err(anyhow!("shadowtls handshake hmac check failed"));
                }
                break;
            }
            CONTENT_TYPE_ALERT => {
                return Err(anyhow!("shadowtls server sent alert during handshake"));
            }
            _ => {
                feed_rustls_client_connection(&mut client_conn, &frame)?;
                client_conn
                    .process_new_packets()
                    .map_err(|error| anyhow!("shadowtls failed to process handshake: {error}"))?;
            }
        }
    }

    Ok(ShadowTlsTunnel {
        stream,
        read_hmac,
        write_hmac,
        handshake_hmac: hmac_server_random,
    })
}

fn modify_client_hello(
    original_frame: &[u8],
    initial_hmac: &ShadowTlsHmac,
) -> anyhow::Result<Vec<u8>> {
    if original_frame.len() < TLS_HEADER_LEN {
        return Err(anyhow!("shadowtls client hello frame is too short"));
    }
    if original_frame[0] != CONTENT_TYPE_HANDSHAKE {
        return Err(anyhow!("shadowtls expected TLS ClientHello record"));
    }
    let original_payload_len = u16::from_be_bytes([original_frame[3], original_frame[4]]) as usize;
    if original_frame.len() != TLS_HEADER_LEN + original_payload_len {
        return Err(anyhow!("shadowtls client hello length mismatch"));
    }
    let payload = &original_frame[TLS_HEADER_LEN..];
    if payload.len() < 42 {
        return Err(anyhow!("shadowtls client hello payload is too short"));
    }
    if payload[0] != HANDSHAKE_TYPE_CLIENT_HELLO {
        return Err(anyhow!("shadowtls expected ClientHello message"));
    }
    let client_hello_payload_len =
        ((payload[1] as usize) << 16) | ((payload[2] as usize) << 8) | payload[3] as usize;
    if client_hello_payload_len + 4 != payload.len() {
        return Err(anyhow!("shadowtls client hello message length mismatch"));
    }
    if payload[4] != 0x03 || payload[5] != 0x03 {
        return Err(anyhow!("shadowtls requires TLS1.3-style ClientHello"));
    }
    let mut offset = 4 + 2 + 32;
    if offset >= payload.len() {
        return Err(anyhow!("shadowtls client hello has no session id"));
    }
    let original_session_id_len = payload[offset] as usize;
    offset += 1;
    if original_session_id_len != 0 {
        if original_session_id_len != 32 {
            return Err(anyhow!(
                "shadowtls original ClientHello session id is not 32 bytes"
            ));
        }
        offset += 32;
    }
    if offset > payload.len() {
        return Err(anyhow!("shadowtls client hello session id exceeds payload"));
    }
    let remaining = &payload[offset..];
    let new_client_hello_payload_len = client_hello_payload_len + (32 - original_session_id_len);
    let new_record_payload_len = new_client_hello_payload_len + 4;
    if new_record_payload_len > u16::MAX as usize {
        return Err(anyhow!("shadowtls modified ClientHello is too large"));
    }
    let mut modified = vec![0u8; TLS_HEADER_LEN + new_record_payload_len];
    modified[0] = CONTENT_TYPE_HANDSHAKE;
    modified[1] = original_frame[1];
    modified[2] = original_frame[2];
    modified[3..5].copy_from_slice(&(new_record_payload_len as u16).to_be_bytes());
    modified[5] = HANDSHAKE_TYPE_CLIENT_HELLO;
    modified[6..9].copy_from_slice(&(new_client_hello_payload_len as u32).to_be_bytes()[1..]);
    modified[9] = 0x03;
    modified[10] = 0x03;
    modified[11..43].copy_from_slice(&payload[6..38]);
    modified[43] = 32;
    getrandom::fill(&mut modified[44..72])
        .map_err(|error| anyhow!("failed to generate shadowtls session id: {error}"))?;
    modified[72..76].copy_from_slice(&[0, 0, 0, 0]);
    modified[76..].copy_from_slice(remaining);
    let mut hmac = initial_hmac.clone();
    hmac.update(&modified[TLS_HEADER_LEN..]);
    let digest = hmac.finalized_digest();
    modified[72..76].copy_from_slice(&digest);
    Ok(modified)
}

fn parse_server_hello_random(frame: &[u8]) -> anyhow::Result<[u8; 32]> {
    if frame.len() < TLS_HEADER_LEN + 4 + 2 + 32 {
        return Err(anyhow!("shadowtls server hello is too short"));
    }
    if frame[0] != CONTENT_TYPE_HANDSHAKE || frame[TLS_HEADER_LEN] != HANDSHAKE_TYPE_SERVER_HELLO {
        return Err(anyhow!("shadowtls expected TLS ServerHello"));
    }
    let mut random = [0u8; 32];
    random.copy_from_slice(&frame[TLS_HEADER_LEN + 4 + 2..][..32]);
    Ok(random)
}

fn feed_rustls_client_connection(
    connection: &mut rustls::ClientConnection,
    data: &[u8],
) -> anyhow::Result<()> {
    let mut cursor = Cursor::new(data);
    while cursor.position() < data.len() as u64 {
        let n = connection
            .read_tls(&mut cursor)
            .map_err(|error| anyhow!("rustls read_tls failed: {error}"))?;
        if n == 0 {
            break;
        }
    }
    Ok(())
}

async fn read_tls_record<R>(reader: &mut R) -> anyhow::Result<Option<Vec<u8>>>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; TLS_HEADER_LEN];
    if !read_exact_or_eof(reader, &mut header).await? {
        return Ok(None);
    }
    let payload_len = u16::from_be_bytes([header[3], header[4]]) as usize;
    if payload_len > TLS_FRAME_MAX_LEN - TLS_HEADER_LEN {
        return Err(anyhow!("shadowtls TLS record is too large"));
    }
    let mut frame = Vec::with_capacity(TLS_HEADER_LEN + payload_len);
    frame.extend_from_slice(&header);
    frame.resize(TLS_HEADER_LEN + payload_len, 0);
    reader.read_exact(&mut frame[TLS_HEADER_LEN..]).await?;
    Ok(Some(frame))
}

fn spawn_stream<S>(tunnel: ShadowTlsTunnel<S>, initial_payload: Vec<u8>) -> DuplexStream
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (app_side, relay_side) = tokio::io::duplex(64 * 1024);
    let (mut local_read, mut local_write) = tokio::io::split(relay_side);
    let (mut remote_read, mut remote_write) = tokio::io::split(tunnel.stream);
    let mut write_hmac = tunnel.write_hmac;
    let mut read_hmac = tunnel.read_hmac;
    let mut handshake_hmac = Some(tunnel.handshake_hmac);

    tokio::spawn(async move {
        if !initial_payload.is_empty()
            && write_app_data(&mut remote_write, &mut write_hmac, &initial_payload)
                .await
                .is_err()
        {
            let _ = remote_write.shutdown().await;
            return;
        }
        let mut buf = vec![0u8; MAX_WRITE_PAYLOAD_LEN];
        loop {
            match local_read.read(&mut buf).await {
                Ok(0) => {
                    let _ = remote_write.shutdown().await;
                    break;
                }
                Ok(n) => {
                    if write_app_data(&mut remote_write, &mut write_hmac, &buf[..n])
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
        loop {
            match read_app_data(&mut remote_read, &mut read_hmac, &mut handshake_hmac).await {
                Ok(Some(payload)) => {
                    if local_write.write_all(&payload).await.is_err() {
                        break;
                    }
                }
                Ok(None) | Err(_) => {
                    let _ = local_write.shutdown().await;
                    break;
                }
            }
        }
    });

    app_side
}

async fn write_app_data<W>(
    writer: &mut W,
    hmac: &mut ShadowTlsHmac,
    payload: &[u8],
) -> anyhow::Result<()>
where
    W: AsyncWrite + Unpin,
{
    for chunk in payload.chunks(MAX_WRITE_PAYLOAD_LEN) {
        hmac.update(chunk);
        let digest = hmac.digest();
        hmac.update(&digest);
        let frame_len = 4 + chunk.len();
        let mut header = [0u8; TLS_HEADER_LEN];
        header[0] = CONTENT_TYPE_APPLICATION_DATA;
        header[1] = 0x03;
        header[2] = 0x03;
        header[3..5].copy_from_slice(&(frame_len as u16).to_be_bytes());
        writer.write_all(&header).await?;
        writer.write_all(&digest).await?;
        writer.write_all(chunk).await?;
        writer.flush().await?;
    }
    Ok(())
}

async fn read_app_data<R>(
    reader: &mut R,
    read_hmac: &mut ShadowTlsHmac,
    handshake_hmac: &mut Option<ShadowTlsHmac>,
) -> anyhow::Result<Option<Vec<u8>>>
where
    R: AsyncRead + Unpin,
{
    loop {
        let Some(frame) = read_tls_record(reader).await? else {
            return Ok(None);
        };
        match frame[0] {
            CONTENT_TYPE_ALERT => return Ok(None),
            CONTENT_TYPE_APPLICATION_DATA => {
                let payload_len = u16::from_be_bytes([frame[3], frame[4]]) as usize;
                if payload_len < 4 {
                    return Err(anyhow!("shadowtls app-data frame is too short"));
                }
                let received = &frame[TLS_HEADER_LEN..TLS_HEADER_LEN + 4];
                let payload = &frame[TLS_HEADER_LEN + 4..TLS_HEADER_LEN + payload_len];
                if let Some(current) = handshake_hmac.as_ref() {
                    let mut candidate = current.clone();
                    candidate.update(payload);
                    if candidate.digest() == received {
                        *handshake_hmac = Some(candidate);
                        continue;
                    }
                    *handshake_hmac = None;
                }
                read_hmac.update(payload);
                let expected = read_hmac.digest();
                if received != expected {
                    return Err(anyhow!("shadowtls app-data hmac check failed"));
                }
                read_hmac.update(&expected);
                return Ok(Some(payload.to_vec()));
            }
            _ if handshake_hmac.is_some() => continue,
            _ => return Err(anyhow!("shadowtls unexpected TLS record type {}", frame[0])),
        }
    }
}
