use std::net::Ipv6Addr;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use anyhow::{anyhow, Context};
use async_trait::async_trait;
use base64::Engine as _;
use bytes::{Buf, Bytes, BytesMut};
use futures::future::poll_fn;
use rustls_pki_types::ServerName;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream},
    sync::Mutex,
};
use tokio_rustls::TlsConnector;

use crate::routing::Destination;

use super::{
    transports::{
        active_tcp_dialer_is_set, connect_quic_endpoint, connect_tcp, create_quic_endpoint,
        quic_client_config_with_resumption, resolve_quic_remote, run_dial_phase, tls_client_config,
    },
    BoxedStream, Outbound, OutboundCapability,
};

const NAIVE_PADDING_FRAMES: usize = 8;
const NAIVE_MAX_PAYLOAD_SIZE: usize = u16::MAX as usize;
const NAIVE_RELAY_BUFFER_SIZE: usize = 16 * 1024;
const NAIVE_DUPLEX_CAPACITY: usize = 256 * 1024;
const NAIVE_MAX_HEADER_SIZE: usize = 32 * 1024;
const NON_INDEX_HEADER_CODES: &[u8; 17] = b"!\"#$&'()*+,;<>?@[";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NaiveTransport {
    Http1,
    Http2,
    Http3,
}

pub(crate) struct NaiveOutbound {
    name: String,
    server: String,
    port: u16,
    username: Option<String>,
    password: Option<String>,
    sni: Option<String>,
    skip_cert_verify: bool,
    alpn: Vec<String>,
    h2_session: Mutex<Option<Arc<NaiveH2Session>>>,
    h3_session: Mutex<Option<Arc<NaiveH3Session>>>,
}

impl NaiveOutbound {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        name: String,
        server: String,
        port: u16,
        username: Option<String>,
        password: Option<String>,
        sni: Option<String>,
        skip_cert_verify: bool,
        alpn: Vec<String>,
    ) -> Self {
        Self {
            name,
            server,
            port,
            username,
            password,
            sni,
            skip_cert_verify,
            alpn,
            h2_session: Mutex::new(None),
            h3_session: Mutex::new(None),
        }
    }

    fn validate_configuration(&self) -> anyhow::Result<NaiveTransport> {
        if self.server.trim().is_empty() || self.port == 0 {
            return Err(anyhow!("naive server and port are required"));
        }
        if self
            .sni
            .as_deref()
            .is_some_and(|server_name| server_name.trim().is_empty())
        {
            return Err(anyhow!("naive SNI must not be empty"));
        }
        match (&self.username, &self.password) {
            (Some(username), Some(_)) if username.is_empty() => {
                return Err(anyhow!("naive username must not be empty"));
            }
            (Some(_), None) => return Err(anyhow!("naive password is required with username")),
            (None, Some(_)) => return Err(anyhow!("naive username is required with password")),
            _ => {}
        }

        let protocols = self
            .alpn
            .iter()
            .map(|value| value.trim().to_ascii_lowercase())
            .filter(|value| !value.is_empty())
            .collect::<Vec<_>>();
        if protocols.is_empty() {
            return Ok(NaiveTransport::Http2);
        }
        let has_h3 = protocols
            .iter()
            .any(|value| matches!(value.as_str(), "h3" | "http/3" | "quic"));
        let has_h2 = protocols
            .iter()
            .any(|value| matches!(value.as_str(), "h2" | "http/2"));
        let has_h1 = protocols
            .iter()
            .any(|value| matches!(value.as_str(), "http/1.1" | "http1.1" | "http/1" | "http1"));
        if protocols.iter().any(|value| {
            !matches!(
                value.as_str(),
                "h3" | "http/3"
                    | "quic"
                    | "h2"
                    | "http/2"
                    | "http/1.1"
                    | "http1.1"
                    | "http/1"
                    | "http1"
            )
        }) {
            return Err(anyhow!("naive ALPN contains an unsupported protocol"));
        }
        if has_h3 && (has_h2 || has_h1) {
            return Err(anyhow!(
                "naive HTTP/3 cannot be combined with TCP ALPN values"
            ));
        }
        if has_h3 {
            Ok(NaiveTransport::Http3)
        } else if has_h2 {
            Ok(NaiveTransport::Http2)
        } else if has_h1 {
            Ok(NaiveTransport::Http1)
        } else {
            Err(anyhow!("naive transport could not be selected"))
        }
    }

    fn server_name(&self) -> String {
        self.sni.as_deref().unwrap_or(&self.server).to_string()
    }

    fn authorization(&self) -> Option<String> {
        self.username
            .as_ref()
            .zip(self.password.as_ref())
            .map(|(username, password)| {
                let encoded = base64::engine::general_purpose::STANDARD
                    .encode(format!("{username}:{password}"));
                format!("Basic {encoded}")
            })
    }

    async fn connect_http1(
        &self,
        destination: &Destination,
        timeout_ms: u64,
    ) -> anyhow::Result<BoxedStream> {
        let tcp = connect_tcp(&format!("{}:{}", self.server, self.port), timeout_ms).await?;
        let mut tls_config = tls_client_config(self.skip_cert_verify)?;
        tls_config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let tls_server_name = ServerName::try_from(self.server_name())
            .map_err(|error| anyhow!("invalid naive server name: {error}"))?;
        let mut stream = run_dial_phase(
            timeout_ms,
            "naive HTTP/1.1 TLS handshake",
            TlsConnector::from(Arc::new(tls_config)).connect(tls_server_name, tcp),
        )
        .await??;
        let padding_header = naive_padding_header()?;
        let authority = naive_authority(destination);
        let mut request = format!(
            "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nPadding: {padding_header}\r\nPadding-Type-Request: 1, 0\r\n"
        );
        if let Some(authorization) = self.authorization() {
            request.push_str("Proxy-Authorization: ");
            request.push_str(&authorization);
            request.push_str("\r\n");
        }
        request.push_str("\r\n");
        run_dial_phase(
            timeout_ms,
            "naive HTTP/1.1 CONNECT write",
            stream.write_all(request.as_bytes()),
        )
        .await??;
        run_dial_phase(timeout_ms, "naive HTTP/1.1 CONNECT flush", stream.flush()).await??;
        let (headers, leftover) = run_dial_phase(
            timeout_ms,
            "naive HTTP/1.1 CONNECT response",
            read_http1_connect_response(&mut stream),
        )
        .await??;
        let padding = parse_padding_negotiation(&headers)?;
        Ok(Box::new(spawn_raw_naive_stream(stream, leftover, padding)))
    }

    async fn connect_http2(
        &self,
        destination: &Destination,
        timeout_ms: u64,
    ) -> anyhow::Result<BoxedStream> {
        let authorization = self.authorization();
        let server_name = self.server_name();
        for attempt in 0..2 {
            let session = self.h2_session(timeout_ms, &server_name).await?;
            match session
                .open(destination, authorization.as_deref(), timeout_ms)
                .await
            {
                Ok(stream) => return Ok(Box::new(stream)),
                Err(error) if attempt == 0 && retryable_session_error(&error) => {
                    let mut stored = self.h2_session.lock().await;
                    if stored
                        .as_ref()
                        .is_some_and(|current| Arc::ptr_eq(current, &session))
                    {
                        stored.take();
                    }
                    tracing::debug!(error = %error, "rebuilding stale naive HTTP/2 session");
                }
                Err(error) => return Err(error),
            }
        }
        Err(anyhow!("naive HTTP/2 session retry exhausted"))
    }

    async fn h2_session(
        &self,
        timeout_ms: u64,
        server_name: &str,
    ) -> anyhow::Result<Arc<NaiveH2Session>> {
        let mut stored = self.h2_session.lock().await;
        if let Some(session) = stored.as_ref().filter(|session| !session.is_closed()) {
            return Ok(Arc::clone(session));
        }
        let session = Arc::new(
            NaiveH2Session::connect(
                &self.server,
                self.port,
                server_name,
                self.skip_cert_verify,
                timeout_ms,
            )
            .await?,
        );
        *stored = Some(Arc::clone(&session));
        Ok(session)
    }

    async fn connect_http3(
        &self,
        destination: &Destination,
        timeout_ms: u64,
    ) -> anyhow::Result<BoxedStream> {
        if active_tcp_dialer_is_set() {
            return Err(anyhow!(
                "naive HTTP/3 cannot use a TCP dialer-proxy; select HTTP/2 or remove dialer-proxy"
            ));
        }
        let authorization = self.authorization();
        let server_name = self.server_name();
        for attempt in 0..2 {
            let session = self.h3_session(timeout_ms, &server_name).await?;
            match session
                .open(destination, authorization.as_deref(), timeout_ms)
                .await
            {
                Ok(stream) => return Ok(Box::new(stream)),
                Err(error) if attempt == 0 && retryable_session_error(&error) => {
                    let mut stored = self.h3_session.lock().await;
                    if stored
                        .as_ref()
                        .is_some_and(|current| Arc::ptr_eq(current, &session))
                    {
                        stored.take();
                    }
                    tracing::debug!(error = %error, "rebuilding stale naive HTTP/3 session");
                }
                Err(error) => return Err(error),
            }
        }
        Err(anyhow!("naive HTTP/3 session retry exhausted"))
    }

    async fn h3_session(
        &self,
        timeout_ms: u64,
        server_name: &str,
    ) -> anyhow::Result<Arc<NaiveH3Session>> {
        let mut stored = self.h3_session.lock().await;
        if let Some(session) = stored.as_ref().filter(|session| !session.is_closed()) {
            return Ok(Arc::clone(session));
        }
        let session = Arc::new(
            NaiveH3Session::connect(
                &self.server,
                self.port,
                server_name,
                self.skip_cert_verify,
                timeout_ms,
            )
            .await?,
        );
        *stored = Some(Arc::clone(&session));
        Ok(session)
    }
}

#[async_trait]
impl Outbound for NaiveOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "naive"
    }

    fn capability(&self) -> OutboundCapability {
        if let Err(error) = self.validate_configuration() {
            return OutboundCapability::unsupported(error.to_string());
        }
        OutboundCapability::tcp_only(
            "NaiveProxy tunnels TCP streams; CONNECT-UDP is not part of the protocol",
        )
    }

    async fn connect(
        &self,
        destination: &Destination,
        timeout_ms: u64,
    ) -> anyhow::Result<BoxedStream> {
        match self.validate_configuration()? {
            NaiveTransport::Http1 => self.connect_http1(destination, timeout_ms).await,
            NaiveTransport::Http2 => self.connect_http2(destination, timeout_ms).await,
            NaiveTransport::Http3 => self.connect_http3(destination, timeout_ms).await,
        }
    }
}

struct NaiveH2Session {
    sender: h2::client::SendRequest<Bytes>,
    closed: Arc<AtomicBool>,
}

impl NaiveH2Session {
    async fn connect(
        server: &str,
        port: u16,
        server_name: &str,
        skip_cert_verify: bool,
        timeout_ms: u64,
    ) -> anyhow::Result<Self> {
        let tcp = connect_tcp(&format!("{server}:{port}"), timeout_ms).await?;
        let mut tls_config = tls_client_config(skip_cert_verify)?;
        tls_config.alpn_protocols = vec![b"h2".to_vec()];
        let tls_server_name = ServerName::try_from(server_name.to_string())
            .map_err(|error| anyhow!("invalid naive server name: {error}"))?;
        let stream = run_dial_phase(
            timeout_ms,
            "naive HTTP/2 TLS handshake",
            TlsConnector::from(Arc::new(tls_config)).connect(tls_server_name, tcp),
        )
        .await??;
        if stream.get_ref().1.alpn_protocol() != Some(b"h2".as_slice()) {
            return Err(anyhow!("naive server did not negotiate HTTP/2"));
        }
        let (sender, connection) = run_dial_phase(
            timeout_ms,
            "naive HTTP/2 client handshake",
            h2::client::Builder::new().handshake(stream),
        )
        .await??;
        let closed = Arc::new(AtomicBool::new(false));
        let driver_closed = Arc::clone(&closed);
        tokio::spawn(async move {
            if let Err(error) = connection.await {
                tracing::debug!(error = %error, "naive HTTP/2 connection ended");
            }
            driver_closed.store(true, Ordering::Release);
        });
        Ok(Self { sender, closed })
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    async fn open(
        &self,
        destination: &Destination,
        authorization: Option<&str>,
        timeout_ms: u64,
    ) -> anyhow::Result<DuplexStream> {
        if self.is_closed() {
            return Err(anyhow!("naive HTTP/2 session is closed"));
        }
        let mut sender = run_dial_phase(
            timeout_ms,
            "naive HTTP/2 stream readiness",
            self.sender.clone().ready(),
        )
        .await??;
        let request =
            build_naive_connect_request(destination, authorization, http::Version::HTTP_2)?;
        let (response, send) = sender
            .send_request(request, false)
            .context("failed to open naive HTTP/2 CONNECT stream")?;
        let response =
            run_dial_phase(timeout_ms, "naive HTTP/2 CONNECT response", response).await??;
        validate_connect_status(response.status())?;
        let padding = parse_padding_negotiation(response.headers())?;
        Ok(spawn_h2_naive_stream(send, response.into_body(), padding))
    }
}

struct NaiveH3Session {
    _endpoint: quinn::Endpoint,
    connection: quinn::Connection,
    sender: Mutex<h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>>,
    closed: Arc<AtomicBool>,
}

impl NaiveH3Session {
    async fn connect(
        server: &str,
        port: u16,
        server_name: &str,
        skip_cert_verify: bool,
        timeout_ms: u64,
    ) -> anyhow::Result<Self> {
        let remote = resolve_quic_remote("naive HTTP/3", server, port).await?;
        let endpoint = create_quic_endpoint(remote)?;
        let (endpoint, connection) = connect_quic_endpoint(
            endpoint,
            remote,
            server_name,
            quic_client_config_with_resumption(skip_cert_verify, Some("h3"), None, None, false)?,
            timeout_ms,
            "naive HTTP/3",
        )
        .await?;
        let (mut driver, sender) = run_dial_phase(
            timeout_ms,
            "naive HTTP/3 client init",
            h3::client::new(h3_quinn::Connection::new(connection.clone())),
        )
        .await??;
        let closed = Arc::new(AtomicBool::new(false));
        let driver_closed = Arc::clone(&closed);
        tokio::spawn(async move {
            let _ = driver.wait_idle().await;
            driver_closed.store(true, Ordering::Release);
        });
        Ok(Self {
            _endpoint: endpoint,
            connection,
            sender: Mutex::new(sender),
            closed,
        })
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire) || self.connection.close_reason().is_some()
    }

    async fn open(
        &self,
        destination: &Destination,
        authorization: Option<&str>,
        timeout_ms: u64,
    ) -> anyhow::Result<DuplexStream> {
        if self.is_closed() {
            return Err(anyhow!("naive HTTP/3 session is closed"));
        }
        let request =
            build_naive_connect_request(destination, authorization, http::Version::HTTP_3)?;
        let mut sender = self.sender.lock().await;
        let mut stream = run_dial_phase(
            timeout_ms,
            "naive HTTP/3 CONNECT request",
            sender.send_request(request),
        )
        .await??;
        drop(sender);
        let response = run_dial_phase(
            timeout_ms,
            "naive HTTP/3 CONNECT response",
            stream.recv_response(),
        )
        .await??;
        validate_connect_status(response.status())?;
        let padding = parse_padding_negotiation(response.headers())?;
        Ok(spawn_h3_naive_stream(stream, padding))
    }
}

fn build_naive_connect_request(
    destination: &Destination,
    authorization: Option<&str>,
    version: http::Version,
) -> anyhow::Result<http::Request<()>> {
    let mut builder = http::Request::builder()
        .method(http::Method::CONNECT)
        .version(version)
        .uri(naive_authority(destination))
        .header("padding", naive_padding_header()?)
        .header("padding-type-request", "1, 0");
    if let Some(authorization) = authorization {
        builder = builder.header(http::header::PROXY_AUTHORIZATION, authorization);
    }
    builder
        .body(())
        .context("failed to build naive CONNECT request")
}

fn naive_authority(destination: &Destination) -> String {
    if destination.host.parse::<Ipv6Addr>().is_ok() {
        format!("[{}]:{}", destination.host, destination.port)
    } else {
        destination.authority()
    }
}

fn naive_padding_header() -> anyhow::Result<String> {
    let mut entropy = [0u8; 17];
    getrandom::fill(&mut entropy).context("failed to generate naive header padding")?;
    let length = 16 + usize::from(entropy[0] % 17);
    let mut output = Vec::with_capacity(length);
    for byte in entropy.iter().skip(1).take(length.min(16)) {
        output.push(NON_INDEX_HEADER_CODES[usize::from(byte & 0x0f)]);
    }
    output.resize(length, NON_INDEX_HEADER_CODES[16]);
    String::from_utf8(output).context("naive header padding is not UTF-8")
}

fn validate_connect_status(status: http::StatusCode) -> anyhow::Result<()> {
    if status.is_success() {
        Ok(())
    } else if status == http::StatusCode::PROXY_AUTHENTICATION_REQUIRED {
        Err(anyhow!("naive proxy authentication failed with status 407"))
    } else {
        Err(anyhow!("naive CONNECT failed with status {status}"))
    }
}

fn retryable_session_error(error: &anyhow::Error) -> bool {
    let message = error.to_string();
    !message.contains("status 407")
        && !message.contains("CONNECT failed with status")
        && !message.contains("invalid padding type")
}

fn parse_padding_negotiation(headers: &http::HeaderMap) -> anyhow::Result<bool> {
    if let Some(value) = headers.get("padding-type-reply") {
        return match value
            .to_str()
            .context("naive padding-type-reply is not valid ASCII")?
            .trim()
        {
            "1" => Ok(true),
            "0" => Ok(false),
            value => Err(anyhow!(
                "naive server returned invalid padding type {value}"
            )),
        };
    }
    Ok(headers.contains_key("padding"))
}

async fn read_http1_connect_response<S>(
    stream: &mut S,
) -> anyhow::Result<(http::HeaderMap, Vec<u8>)>
where
    S: AsyncRead + Unpin,
{
    let mut response = Vec::with_capacity(2_048);
    let header_end = loop {
        if response.len() >= NAIVE_MAX_HEADER_SIZE {
            return Err(anyhow!("naive HTTP/1.1 CONNECT response is too large"));
        }
        let mut chunk = [0u8; 1_024];
        let length = stream.read(&mut chunk).await?;
        if length == 0 {
            return Err(anyhow!(
                "naive HTTP/1.1 server closed before CONNECT response"
            ));
        }
        response.extend_from_slice(&chunk[..length]);
        if let Some(position) = response.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
    };
    let header_text = std::str::from_utf8(&response[..header_end])
        .context("naive HTTP/1.1 CONNECT response is not UTF-8")?;
    let mut lines = header_text.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| anyhow!("naive HTTP/1.1 CONNECT response has no status"))?;
    let status = status_line
        .split_ascii_whitespace()
        .nth(1)
        .ok_or_else(|| anyhow!("naive HTTP/1.1 CONNECT status is missing"))?
        .parse::<u16>()
        .context("naive HTTP/1.1 CONNECT status is invalid")?;
    validate_connect_status(http::StatusCode::from_u16(status)?)?;
    let mut headers = http::HeaderMap::new();
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| anyhow!("naive HTTP/1.1 CONNECT header is malformed"))?;
        headers.append(
            http::header::HeaderName::from_bytes(name.trim().as_bytes())?,
            http::header::HeaderValue::from_str(value.trim())?,
        );
    }
    Ok((headers, response[header_end..].to_vec()))
}

fn spawn_raw_naive_stream<S>(stream: S, initial_remote: Vec<u8>, padding: bool) -> DuplexStream
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (app_side, relay_side) = tokio::io::duplex(NAIVE_DUPLEX_CAPACITY);
    let (mut local_read, mut local_write) = tokio::io::split(relay_side);
    let (mut remote_read, mut remote_write) = tokio::io::split(stream);
    tokio::spawn(async move {
        let mut frame_index = 0usize;
        let mut buffer = vec![0u8; NAIVE_RELAY_BUFFER_SIZE];
        loop {
            match local_read.read(&mut buffer).await {
                Ok(0) => {
                    let _ = remote_write.shutdown().await;
                    return;
                }
                Ok(length) => {
                    let frame =
                        match encode_naive_payload(&buffer[..length], &mut frame_index, padding) {
                            Ok(frame) => frame,
                            Err(_) => return,
                        };
                    if remote_write.write_all(&frame).await.is_err()
                        || remote_write.flush().await.is_err()
                    {
                        return;
                    }
                }
                Err(_) => return,
            }
        }
    });
    tokio::spawn(async move {
        let mut decoder = NaivePaddingDecoder::new(padding);
        if !initial_remote.is_empty()
            && write_decoded_payload(&mut local_write, &mut decoder, &initial_remote)
                .await
                .is_err()
        {
            return;
        }
        let mut buffer = vec![0u8; NAIVE_RELAY_BUFFER_SIZE];
        loop {
            match remote_read.read(&mut buffer).await {
                Ok(0) => {
                    let _ = decoder.finish();
                    let _ = local_write.shutdown().await;
                    return;
                }
                Ok(length) => {
                    if write_decoded_payload(&mut local_write, &mut decoder, &buffer[..length])
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
                Err(_) => return,
            }
        }
    });
    app_side
}

fn spawn_h2_naive_stream(
    mut send: h2::SendStream<Bytes>,
    mut recv: h2::RecvStream,
    padding: bool,
) -> DuplexStream {
    let (app_side, relay_side) = tokio::io::duplex(NAIVE_DUPLEX_CAPACITY);
    let (mut local_read, mut local_write) = tokio::io::split(relay_side);
    tokio::spawn(async move {
        let mut frame_index = 0usize;
        let mut buffer = vec![0u8; NAIVE_RELAY_BUFFER_SIZE];
        loop {
            match local_read.read(&mut buffer).await {
                Ok(0) => {
                    let _ = send.send_data(Bytes::new(), true);
                    return;
                }
                Ok(length) => {
                    let frame =
                        match encode_naive_payload(&buffer[..length], &mut frame_index, padding) {
                            Ok(frame) => frame,
                            Err(_) => return,
                        };
                    if send_h2_data(&mut send, frame).await.is_err() {
                        return;
                    }
                }
                Err(_) => return,
            }
        }
    });
    tokio::spawn(async move {
        let mut decoder = NaivePaddingDecoder::new(padding);
        while let Some(chunk) = recv.data().await {
            let chunk = match chunk {
                Ok(chunk) => chunk,
                Err(_) => return,
            };
            let length = chunk.len();
            if write_decoded_payload(&mut local_write, &mut decoder, &chunk)
                .await
                .is_err()
            {
                return;
            }
            let _ = recv.flow_control().release_capacity(length);
        }
        let _ = decoder.finish();
        let _ = local_write.shutdown().await;
    });
    app_side
}

async fn send_h2_data(
    send: &mut h2::SendStream<Bytes>,
    mut payload: Vec<u8>,
) -> anyhow::Result<()> {
    while !payload.is_empty() {
        send.reserve_capacity(payload.len());
        let capacity = poll_fn(|cx| send.poll_capacity(cx))
            .await
            .ok_or_else(|| anyhow!("naive HTTP/2 send stream closed"))??;
        if capacity == 0 {
            continue;
        }
        let length = capacity.min(payload.len());
        let remainder = payload.split_off(length);
        send.send_data(Bytes::from(payload), false)?;
        payload = remainder;
    }
    Ok(())
}

fn spawn_h3_naive_stream(
    stream: h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    padding: bool,
) -> DuplexStream {
    let (app_side, relay_side) = tokio::io::duplex(NAIVE_DUPLEX_CAPACITY);
    let (mut local_read, mut local_write) = tokio::io::split(relay_side);
    let (mut send, mut recv) = stream.split();
    tokio::spawn(async move {
        let mut frame_index = 0usize;
        let mut buffer = vec![0u8; NAIVE_RELAY_BUFFER_SIZE];
        loop {
            match local_read.read(&mut buffer).await {
                Ok(0) => {
                    let _ = send.finish().await;
                    return;
                }
                Ok(length) => {
                    let frame =
                        match encode_naive_payload(&buffer[..length], &mut frame_index, padding) {
                            Ok(frame) => frame,
                            Err(_) => return,
                        };
                    if send.send_data(Bytes::from(frame)).await.is_err() {
                        return;
                    }
                }
                Err(_) => return,
            }
        }
    });
    tokio::spawn(async move {
        let mut decoder = NaivePaddingDecoder::new(padding);
        loop {
            match recv.recv_data().await {
                Ok(Some(mut chunk)) => {
                    let bytes = chunk.copy_to_bytes(chunk.remaining());
                    if write_decoded_payload(&mut local_write, &mut decoder, &bytes)
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
                Ok(None) => {
                    let _ = decoder.finish();
                    let _ = local_write.shutdown().await;
                    return;
                }
                Err(_) => return,
            }
        }
    });
    app_side
}

fn encode_naive_payload(
    payload: &[u8],
    frame_index: &mut usize,
    padding: bool,
) -> anyhow::Result<Vec<u8>> {
    if !padding || *frame_index >= NAIVE_PADDING_FRAMES {
        return Ok(payload.to_vec());
    }
    if payload.len() > NAIVE_MAX_PAYLOAD_SIZE {
        return Err(anyhow!("naive payload exceeds 65535 bytes"));
    }
    let mut random = [0u8; 1];
    getrandom::fill(&mut random).context("failed to generate naive payload padding")?;
    let padding_size = usize::from(random[0]);
    let mut frame = Vec::with_capacity(3 + payload.len() + padding_size);
    frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    frame.push(random[0]);
    frame.extend_from_slice(payload);
    frame.resize(frame.len() + padding_size, 0);
    *frame_index += 1;
    Ok(frame)
}

struct NaivePaddingDecoder {
    enabled: bool,
    frames: usize,
    buffer: BytesMut,
}

impl NaivePaddingDecoder {
    fn new(enabled: bool) -> Self {
        Self {
            enabled,
            frames: 0,
            buffer: BytesMut::new(),
        }
    }

    fn push(&mut self, input: &[u8]) -> anyhow::Result<Vec<u8>> {
        if !self.enabled || self.frames >= NAIVE_PADDING_FRAMES {
            return Ok(input.to_vec());
        }
        self.buffer.extend_from_slice(input);
        let mut output = Vec::new();
        while self.frames < NAIVE_PADDING_FRAMES {
            if self.buffer.len() < 3 {
                break;
            }
            let payload_size = u16::from_be_bytes([self.buffer[0], self.buffer[1]]) as usize;
            let padding_size = usize::from(self.buffer[2]);
            let frame_size = 3usize
                .checked_add(payload_size)
                .and_then(|size| size.checked_add(padding_size))
                .ok_or_else(|| anyhow!("naive padded frame length overflow"))?;
            if self.buffer.len() < frame_size {
                break;
            }
            let frame = self.buffer.split_to(frame_size);
            if frame[3 + payload_size..].iter().any(|byte| *byte != 0) {
                return Err(anyhow!("naive payload padding contains non-zero bytes"));
            }
            output.extend_from_slice(&frame[3..3 + payload_size]);
            self.frames += 1;
        }
        if self.frames >= NAIVE_PADDING_FRAMES && !self.buffer.is_empty() {
            output.extend_from_slice(&self.buffer.split().freeze());
        }
        Ok(output)
    }

    fn finish(&self) -> anyhow::Result<()> {
        if self.enabled && self.frames < NAIVE_PADDING_FRAMES && !self.buffer.is_empty() {
            Err(anyhow!(
                "naive padded stream ended with an incomplete frame"
            ))
        } else {
            Ok(())
        }
    }
}

async fn write_decoded_payload<W>(
    writer: &mut W,
    decoder: &mut NaivePaddingDecoder,
    input: &[u8],
) -> anyhow::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let payload = decoder.push(input)?;
    if !payload.is_empty() {
        writer.write_all(&payload).await?;
        writer.flush().await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{encode_naive_payload, naive_authority, naive_padding_header, NaivePaddingDecoder};
    use crate::routing::Destination;

    #[test]
    fn header_padding_uses_official_non_index_symbols_and_length() {
        for _ in 0..32 {
            let padding = naive_padding_header().expect("padding");
            assert!((16..=32).contains(&padding.len()));
            assert!(padding
                .bytes()
                .all(|byte| b"!\"#$&'()*+,;<>?@[".contains(&byte)));
        }
    }

    #[test]
    fn payload_padding_round_trips_fragmented_first_eight_frames_then_raw() {
        let mut encoded = Vec::new();
        let mut frame_index = 0;
        let mut expected = Vec::new();
        for index in 0..10 {
            let payload = vec![index as u8; 97 + index];
            expected.extend_from_slice(&payload);
            encoded.extend_from_slice(
                &encode_naive_payload(&payload, &mut frame_index, true).expect("encode"),
            );
        }
        assert_eq!(frame_index, 8);
        let mut decoder = NaivePaddingDecoder::new(true);
        let mut decoded = Vec::new();
        for chunk in encoded.chunks(13) {
            decoded.extend_from_slice(&decoder.push(chunk).expect("decode"));
        }
        decoder.finish().expect("complete framing");
        assert_eq!(decoded, expected);
    }

    #[test]
    fn connect_authority_brackets_ipv6_addresses() {
        assert_eq!(
            naive_authority(&Destination::new("2001:db8::1", 443)),
            "[2001:db8::1]:443"
        );
        assert_eq!(
            naive_authority(&Destination::new("example.com", 443)),
            "example.com:443"
        );
    }
}
