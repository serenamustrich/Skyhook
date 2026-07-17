use std::{
    io::{Cursor, Read as _, Write as _},
    sync::Arc,
    time::Duration,
};

use anyhow::{anyhow, Context};
use async_trait::async_trait;
use rustls::{
    client::DangerousClientHelloSessionIdProvider, crypto::ActiveKeyExchange, Error as RustlsError,
};
use rustls_pki_types::ServerName;
use sha1::{Digest, Sha1};
use sha2::Sha256;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream},
    time::{timeout_at, Instant as TokioInstant},
};

use crate::routing::Destination;

use super::{
    context::active_dial_context,
    io::read_exact_or_eof,
    target::encode_socks5_destination,
    transports::{connect_tcp, tls13_client_config},
    BoxedStream, Outbound, OutboundCapability,
};

const TLS_HEADER_LEN: usize = 5;
const TLS_FRAME_MAX_LEN: usize = TLS_HEADER_LEN + 65_535;
const CONTENT_TYPE_HANDSHAKE: u8 = 0x16;
const CONTENT_TYPE_APPLICATION_DATA: u8 = 0x17;
const CONTENT_TYPE_ALERT: u8 = 0x15;
const HANDSHAKE_TYPE_SERVER_HELLO: u8 = 0x02;
const TLS13_HELLO_RETRY_REQUEST_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];
const CLIENT_HELLO_SESSION_ID_LENGTH_INDEX: usize = 1 + 3 + 2 + 32;
const CLIENT_HELLO_SESSION_ID_START: usize = CLIENT_HELLO_SESSION_ID_LENGTH_INDEX + 1;
const SHADOWTLS_SESSION_ID_LENGTH: usize = 32;
const SHADOWTLS_SESSION_ID_RANDOM_LENGTH: usize = 28;
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

    fn validate_configuration(&self) -> anyhow::Result<()> {
        let version = self.version.unwrap_or(3);
        if version != 3 {
            return Err(anyhow!(
                "unsupported shadowtls version {version}; supported: 3"
            ));
        }
        if self.server.trim().is_empty() || self.port == 0 {
            return Err(anyhow!("shadowtls server and port are required"));
        }
        if self.password.is_empty() {
            return Err(anyhow!("shadowtls password is empty"));
        }
        if self
            .sni
            .as_deref()
            .is_some_and(|server_name| server_name.trim().is_empty())
        {
            return Err(anyhow!("shadowtls SNI must not be empty"));
        }
        Ok(())
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
        if let Err(error) = self.validate_configuration() {
            return OutboundCapability::unsupported(error.to_string());
        }
        let mut capability =
            OutboundCapability::tcp_only("ShadowTLS v3 is a TCP-only transport by design");
        capability.limitations.push(
            "standalone mode requires a SOCKS5 data backend; use it as a Shadowsocks plugin or dialer-proxy for a raw backend"
                .to_string(),
        );
        capability
    }

    async fn connect(
        &self,
        destination: &Destination,
        timeout_ms: u64,
    ) -> anyhow::Result<BoxedStream> {
        self.validate_configuration()?;
        let tcp = connect_tcp(&format!("{}:{}", self.server, self.port), timeout_ms).await?;
        let server_name = self.sni.as_deref().unwrap_or(&self.server).to_string();
        let mut initial_payload = Vec::new();
        let chained_transport =
            active_dial_context().is_some_and(|context| context.dialer_chain.len() > 1);
        if !chained_transport {
            encode_socks5_destination(destination, &mut initial_payload)?;
        }
        open_v3_transport_with_initial_payload(
            tcp,
            self.password.as_bytes(),
            &server_name,
            self.skip_cert_verify,
            timeout_ms,
            initial_payload,
        )
        .await
    }
}

#[derive(Debug)]
struct ShadowTlsSessionIdProvider {
    password: Vec<u8>,
    plaintext_session_id: [u8; SHADOWTLS_SESSION_ID_LENGTH],
}

impl ShadowTlsSessionIdProvider {
    fn new(password: &[u8]) -> anyhow::Result<Self> {
        let mut plaintext_session_id = [0u8; SHADOWTLS_SESSION_ID_LENGTH];
        getrandom::fill(&mut plaintext_session_id[..SHADOWTLS_SESSION_ID_RANDOM_LENGTH])
            .map_err(|error| anyhow!("failed to generate shadowtls session id: {error}"))?;
        Ok(Self {
            password: password.to_vec(),
            plaintext_session_id,
        })
    }
}

impl DangerousClientHelloSessionIdProvider for ShadowTlsSessionIdProvider {
    fn plaintext_session_id(&self) -> [u8; 32] {
        self.plaintext_session_id
    }

    fn seal_session_id(
        &self,
        client_hello_random: &[u8; 32],
        client_hello_raw: &[u8],
        _key_exchange: &dyn ActiveKeyExchange,
    ) -> Result<[u8; 32], RustlsError> {
        seal_client_hello_session_id(
            &self.password,
            self.plaintext_session_id,
            client_hello_random,
            client_hello_raw,
        )
        .map_err(|error| RustlsError::General(error.to_string()))
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

struct ShadowTlsHandshakeState {
    server_random: [u8; 32],
    hmac: ShadowTlsHmac,
    xor_key: [u8; 32],
}

pub(super) async fn open_v3_transport<S>(
    stream: S,
    password: &[u8],
    server_name: &str,
    skip_cert_verify: bool,
    timeout_ms: u64,
) -> anyhow::Result<BoxedStream>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    open_v3_transport_with_initial_payload(
        stream,
        password,
        server_name,
        skip_cert_verify,
        timeout_ms,
        Vec::new(),
    )
    .await
}

async fn open_v3_transport_with_initial_payload<S>(
    stream: S,
    password: &[u8],
    server_name: &str,
    skip_cert_verify: bool,
    timeout_ms: u64,
    initial_payload: Vec<u8>,
) -> anyhow::Result<BoxedStream>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let tunnel =
        setup_v3_tunnel(stream, password, server_name, skip_cert_verify, timeout_ms).await?;
    Ok(Box::new(spawn_stream(tunnel, initial_payload)))
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
    let mut tls_config = tls13_client_config(skip_cert_verify)?;
    let session_id_provider = Arc::new(ShadowTlsSessionIdProvider::new(password)?);
    tls_config
        .dangerous()
        .set_client_hello_session_id_provider(session_id_provider);
    let tls_server_name = ServerName::try_from(server_name.to_string())
        .map_err(|error| anyhow!("invalid shadowtls server name: {error}"))?;
    let mut client_conn = rustls::ClientConnection::new(Arc::new(tls_config), tls_server_name)
        .map_err(|error| anyhow!("failed to create shadowtls client hello: {error}"))?;
    let deadline = TokioInstant::now() + Duration::from_millis(timeout_ms);
    flush_client_tls(&mut client_conn, &mut stream, deadline).await?;

    let mut handshake_state = None;
    let mut authorized = false;
    let mut hijacked = false;

    while client_conn.is_handshaking() {
        flush_client_tls(&mut client_conn, &mut stream, deadline).await?;
        let frame = timeout_at(deadline, read_tls_record(&mut stream))
            .await
            .context("shadowtls handshake frame timed out")?
            .context("failed to read shadowtls handshake frame")?
            .ok_or_else(|| anyhow!("shadowtls server closed during handshake"))?;

        if frame[0] == CONTENT_TYPE_HANDSHAKE && handshake_state.is_none() {
            let server_random = parse_server_hello_random(&frame)?;
            if server_random != TLS13_HELLO_RETRY_REQUEST_RANDOM {
                let mut hmac = ShadowTlsHmac::new(password);
                hmac.update(&server_random);
                handshake_state = Some(ShadowTlsHandshakeState {
                    server_random,
                    hmac,
                    xor_key: shadowtls_handshake_xor_key(password, &server_random),
                });
            }
        }

        let frame = if frame[0] == CONTENT_TYPE_APPLICATION_DATA {
            let state = handshake_state.as_mut().ok_or_else(|| {
                anyhow!("shadowtls received handshake app-data before ServerHello")
            })?;
            let (frame, frame_authorized) = decode_handshake_app_data(frame, state)?;
            authorized |= frame_authorized;
            hijacked |= !frame_authorized;
            frame
        } else {
            frame
        };
        feed_rustls_client_connection(&mut client_conn, &frame)?;
        client_conn
            .process_new_packets()
            .map_err(|error| anyhow!("shadowtls backend TLS handshake failed: {error}"))?;
    }

    flush_client_tls(&mut client_conn, &mut stream, deadline).await?;
    if hijacked || !authorized {
        let camouflage_result =
            perform_camouflage_request(&mut client_conn, &mut stream, server_name, deadline).await;
        return Err(anyhow!(
            "shadowtls server did not authenticate its backend TLS handshake; camouflage request {}",
            if camouflage_result.is_ok() {
                "completed"
            } else {
                "failed"
            }
        ));
    }
    let handshake_state = handshake_state
        .ok_or_else(|| anyhow!("shadowtls handshake completed without ServerHello"))?;
    let mut write_hmac = ShadowTlsHmac::new(password);
    write_hmac.update(&handshake_state.server_random);
    write_hmac.update(b"C");
    let mut read_hmac = ShadowTlsHmac::new(password);
    read_hmac.update(&handshake_state.server_random);
    read_hmac.update(b"S");

    Ok(ShadowTlsTunnel {
        stream,
        read_hmac,
        write_hmac,
        handshake_hmac: handshake_state.hmac,
    })
}

fn seal_client_hello_session_id(
    password: &[u8],
    plaintext_session_id: [u8; SHADOWTLS_SESSION_ID_LENGTH],
    client_hello_random: &[u8; 32],
    client_hello_raw: &[u8],
) -> anyhow::Result<[u8; SHADOWTLS_SESSION_ID_LENGTH]> {
    let session_id_end = CLIENT_HELLO_SESSION_ID_START + SHADOWTLS_SESSION_ID_LENGTH;
    if client_hello_raw.len() < session_id_end
        || client_hello_raw.first() != Some(&0x01)
        || client_hello_raw[CLIENT_HELLO_SESSION_ID_LENGTH_INDEX]
            != SHADOWTLS_SESSION_ID_LENGTH as u8
    {
        return Err(anyhow!(
            "shadowtls rustls ClientHello has no 32-byte compatibility session id"
        ));
    }
    let encoded_length = ((client_hello_raw[1] as usize) << 16)
        | ((client_hello_raw[2] as usize) << 8)
        | client_hello_raw[3] as usize;
    if encoded_length + 4 != client_hello_raw.len() {
        return Err(anyhow!("shadowtls rustls ClientHello length mismatch"));
    }
    if client_hello_raw.get(6..38) != Some(client_hello_random.as_slice()) {
        return Err(anyhow!("shadowtls rustls ClientHello random mismatch"));
    }
    if client_hello_raw.get(CLIENT_HELLO_SESSION_ID_START..session_id_end)
        != Some(plaintext_session_id.as_slice())
        || plaintext_session_id[SHADOWTLS_SESSION_ID_RANDOM_LENGTH..]
            != [0; SHADOWTLS_SESSION_ID_LENGTH - SHADOWTLS_SESSION_ID_RANDOM_LENGTH]
    {
        return Err(anyhow!(
            "shadowtls rustls ClientHello session id placeholder mismatch"
        ));
    }

    let mut hmac = ShadowTlsHmac::new(password);
    hmac.update(client_hello_raw);
    let digest = hmac.finalized_digest();
    let mut sealed = plaintext_session_id;
    sealed[SHADOWTLS_SESSION_ID_RANDOM_LENGTH..].copy_from_slice(&digest);
    Ok(sealed)
}

fn shadowtls_handshake_xor_key(password: &[u8], server_random: &[u8; 32]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(password);
    hash.update(server_random);
    hash.finalize().into()
}

fn xor_repeating(payload: &mut [u8], key: &[u8]) {
    for (index, byte) in payload.iter_mut().enumerate() {
        *byte ^= key[index % key.len()];
    }
}

fn decode_handshake_app_data(
    frame: Vec<u8>,
    state: &mut ShadowTlsHandshakeState,
) -> anyhow::Result<(Vec<u8>, bool)> {
    let payload_len = u16::from_be_bytes([frame[3], frame[4]]) as usize;
    if frame.len() != TLS_HEADER_LEN + payload_len {
        return Err(anyhow!("shadowtls handshake app-data length mismatch"));
    }
    if payload_len <= 4 {
        return Ok((frame, false));
    }
    let received = &frame[TLS_HEADER_LEN..TLS_HEADER_LEN + 4];
    let protected_payload = &frame[TLS_HEADER_LEN + 4..];
    let mut candidate = state.hmac.clone();
    candidate.update(protected_payload);
    if candidate.digest().as_slice() != received {
        return Ok((frame, false));
    }
    state.hmac = candidate;

    let decoded_len = payload_len - 4;
    let mut decoded = Vec::with_capacity(TLS_HEADER_LEN + decoded_len);
    decoded.extend_from_slice(&frame[..TLS_HEADER_LEN]);
    decoded[3..5].copy_from_slice(&(decoded_len as u16).to_be_bytes());
    decoded.extend_from_slice(protected_payload);
    xor_repeating(&mut decoded[TLS_HEADER_LEN..], &state.xor_key);
    Ok((decoded, true))
}

async fn perform_camouflage_request<S>(
    connection: &mut rustls::ClientConnection,
    stream: &mut S,
    server_name: &str,
    deadline: TokioInstant,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut entropy = [0u8; 192];
    getrandom::fill(&mut entropy)
        .map_err(|error| anyhow!("failed to generate shadowtls camouflage request: {error}"))?;
    let cookie_len = 64 + usize::from(entropy[0] % 128);
    let cookie = entropy[1..=cookie_len]
        .iter()
        .map(|byte| char::from(b'a' + byte % 26))
        .collect::<String>();
    let request = format!(
        "GET / HTTP/1.1\r\nHost: {server_name}\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/109.0.0.0 Safari/537.36\r\nAccept: gzip, deflate, br\r\nConnection: close\r\nCookie: sessionid={cookie}\r\n\r\n"
    );
    connection
        .writer()
        .write_all(request.as_bytes())
        .context("failed to queue shadowtls camouflage request")?;
    connection.send_close_notify();
    flush_client_tls(connection, stream, deadline).await?;

    let mut response_bytes = 0usize;
    while response_bytes < 64 * 1024 {
        let frame = match timeout_at(deadline, read_tls_record(stream)).await {
            Ok(Ok(Some(frame))) => frame,
            Ok(Ok(None)) => break,
            Ok(Err(error)) => return Err(error.context("camouflage response read failed")),
            Err(_) => break,
        };
        feed_rustls_client_connection(connection, &frame)?;
        connection
            .process_new_packets()
            .map_err(|error| anyhow!("camouflage TLS response failed: {error}"))?;
        let mut plaintext = [0u8; 4_096];
        loop {
            match connection.reader().read(&mut plaintext) {
                Ok(0) => break,
                Ok(length) => response_bytes += length,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => {
                    return Err(anyhow!("camouflage response decode failed: {error}"));
                }
            }
        }
    }
    Ok(())
}

async fn flush_client_tls<S>(
    connection: &mut rustls::ClientConnection,
    stream: &mut S,
    deadline: TokioInstant,
) -> anyhow::Result<()>
where
    S: AsyncWrite + Unpin,
{
    while connection.wants_write() {
        let mut output = Vec::with_capacity(4_096);
        let written = connection
            .write_tls(&mut output)
            .map_err(|error| anyhow!("shadowtls rustls write failed: {error}"))?;
        if written == 0 {
            break;
        }
        timeout_at(deadline, stream.write_all(&output))
            .await
            .context("shadowtls TLS handshake write timed out")?
            .context("shadowtls TLS handshake write failed")?;
    }
    timeout_at(deadline, stream.flush())
        .await
        .context("shadowtls TLS handshake flush timed out")?
        .context("shadowtls TLS handshake flush failed")
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
