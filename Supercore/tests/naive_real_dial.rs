use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use anyhow::{anyhow, Context};
use base64::Engine as _;
use bytes::{Buf, Bytes, BytesMut};
use futures::future::poll_fn;
use rustls::{
    crypto::aws_lc_rs,
    pki_types::{CertificateDer, PrivatePkcs8KeyDer},
    ServerConfig,
};
use supercore::{config::OutboundConfig, outbound::build_outbounds, routing::Destination};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::oneshot,
    task::JoinSet,
    time::timeout,
};
use tokio_rustls::TlsAcceptor;

const USERNAME: &str = "naive-user";
const PASSWORD: &str = "naive-password";
const TARGET: &str = "target.example:443";
const PADDING_FRAMES: usize = 8;
const NON_INDEX_HEADER_CODES: &[u8] = b"!\"#$&'()*+,;<>?@[";

fn naive_config(port: u16, alpn: &str, password: &str) -> OutboundConfig {
    OutboundConfig::Naive {
        name: format!("naive-{alpn}"),
        server: "127.0.0.1".to_string(),
        port,
        username: Some(USERNAME.to_string()),
        password: Some(password.to_string()),
        sni: Some("naive.test".to_string()),
        skip_cert_verify: true,
        alpn: vec![alpn.to_string()],
    }
}

fn expected_authorization() -> String {
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{USERNAME}:{PASSWORD}"))
    )
}

fn assert_naive_request<B>(request: &http::Request<B>) {
    assert_eq!(request.method(), http::Method::CONNECT);
    assert_eq!(
        request.uri().authority().map(|value| value.as_str()),
        Some(TARGET)
    );
    assert_eq!(
        request.headers()[http::header::PROXY_AUTHORIZATION],
        expected_authorization()
    );
    assert_eq!(request.headers()["padding-type-request"], "1, 0");
    let padding = request.headers()["padding"].as_bytes();
    assert!((16..=32).contains(&padding.len()));
    assert!(padding
        .iter()
        .all(|byte| NON_INDEX_HEADER_CODES.contains(byte)));
}

fn test_payload(seed: u8) -> Vec<u8> {
    (0..96 * 1024)
        .map(|index| seed.wrapping_add((index % 251) as u8))
        .collect()
}

async fn exchange(
    outbound: Arc<dyn supercore::outbound::Outbound>,
    payload: Vec<u8>,
) -> anyhow::Result<Vec<u8>> {
    let mut stream = outbound
        .connect(&Destination::new("target.example", 443), 3_000)
        .await?;
    for chunk in payload.chunks(8 * 1024) {
        stream.write_all(chunk).await?;
        stream.flush().await?;
        tokio::task::yield_now().await;
    }
    stream.shutdown().await?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;
    Ok(response)
}

struct ReferencePaddingDecoder {
    frames: usize,
    buffer: BytesMut,
}

impl ReferencePaddingDecoder {
    fn new() -> Self {
        Self {
            frames: 0,
            buffer: BytesMut::new(),
        }
    }

    fn push(&mut self, input: &[u8]) -> anyhow::Result<Vec<u8>> {
        if self.frames >= PADDING_FRAMES {
            return Ok(input.to_vec());
        }
        self.buffer.extend_from_slice(input);
        let mut output = Vec::new();
        while self.frames < PADDING_FRAMES && self.buffer.len() >= 3 {
            let payload_size = u16::from_be_bytes([self.buffer[0], self.buffer[1]]) as usize;
            let padding_size = usize::from(self.buffer[2]);
            let frame_size = 3 + payload_size + padding_size;
            if self.buffer.len() < frame_size {
                break;
            }
            let frame = self.buffer.split_to(frame_size);
            if frame[3 + payload_size..].iter().any(|byte| *byte != 0) {
                return Err(anyhow!("client sent non-zero Naive padding"));
            }
            output.extend_from_slice(&frame[3..3 + payload_size]);
            self.frames += 1;
        }
        if self.frames == PADDING_FRAMES && !self.buffer.is_empty() {
            output.extend_from_slice(&self.buffer.split().freeze());
        }
        Ok(output)
    }
}

fn reference_encode(payload: &[u8], frame: &mut usize) -> Vec<u8> {
    if *frame >= PADDING_FRAMES {
        return payload.to_vec();
    }
    let padding_size = (*frame * 17 + 11) % 256;
    let mut encoded = Vec::with_capacity(3 + payload.len() + padding_size);
    encoded.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    encoded.push(padding_size as u8);
    encoded.extend_from_slice(payload);
    encoded.resize(encoded.len() + padding_size, 0);
    *frame += 1;
    encoded
}

fn tls_server_config(alpn: &[u8]) -> ServerConfig {
    let certificate = rcgen::generate_simple_self_signed(vec!["naive.test".to_string()]).unwrap();
    let certificate_der = CertificateDer::from(certificate.cert.der().to_vec());
    let private_key = PrivatePkcs8KeyDer::from(certificate.key_pair.serialize_der());
    let provider = aws_lc_rs::default_provider();
    let mut config = ServerConfig::builder_with_provider(provider.into())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![certificate_der], private_key.into())
        .unwrap();
    config.alpn_protocols = vec![alpn.to_vec()];
    config
}

async fn send_h2_data(stream: &mut h2::SendStream<Bytes>, mut data: Vec<u8>) -> anyhow::Result<()> {
    while !data.is_empty() {
        stream.reserve_capacity(data.len());
        let capacity = poll_fn(|cx| stream.poll_capacity(cx))
            .await
            .ok_or_else(|| anyhow!("H2 response stream closed"))??;
        if capacity == 0 {
            continue;
        }
        let remainder = data.split_off(capacity.min(data.len()));
        stream.send_data(Bytes::from(data), false)?;
        data = remainder;
    }
    Ok(())
}

async fn handle_h2_echo(
    request: http::Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
) -> anyhow::Result<()> {
    assert_naive_request(&request);
    let response = http::Response::builder()
        .status(http::StatusCode::OK)
        .header("padding-type-reply", "1")
        .header("padding", "[".repeat(16))
        .body(())?;
    let mut send = respond.send_response(response, false)?;
    let mut body = request.into_body();
    let mut decoder = ReferencePaddingDecoder::new();
    let mut payload = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk?;
        let length = chunk.len();
        payload.extend_from_slice(&decoder.push(&chunk)?);
        body.flow_control().release_capacity(length)?;
    }
    let mut frame = 0;
    for chunk in payload.chunks(12 * 1024) {
        send_h2_data(&mut send, reference_encode(chunk, &mut frame)).await?;
    }
    send.send_data(Bytes::new(), true)?;
    Ok(())
}

async fn start_h2_server(
    connections: Arc<AtomicUsize>,
) -> anyhow::Result<(
    u16,
    oneshot::Sender<()>,
    tokio::task::JoinHandle<anyhow::Result<()>>,
)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let acceptor = TlsAcceptor::from(Arc::new(tls_server_config(b"h2")));
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await?;
        connections.fetch_add(1, Ordering::SeqCst);
        let stream = acceptor.accept(stream).await?;
        assert_eq!(stream.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
        let mut connection = h2::server::handshake(stream).await?;
        let mut streams = JoinSet::new();
        for _ in 0..2 {
            let (request, respond) = connection
                .accept()
                .await
                .ok_or_else(|| anyhow!("H2 client closed before both streams"))??;
            streams.spawn(handle_h2_echo(request, respond));
        }
        while !streams.is_empty() {
            tokio::select! {
                result = streams.join_next() => {
                    result.ok_or_else(|| anyhow!("missing H2 stream task"))???;
                }
                incoming = connection.accept() => {
                    if let Some(Err(error)) = incoming {
                        return Err(error.into());
                    }
                }
            }
        }
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                incoming = connection.accept() => {
                    match incoming {
                        Some(Err(error)) => return Err(error.into()),
                        Some(Ok(_)) => return Err(anyhow!("unexpected third H2 stream")),
                        None => break,
                    }
                }
            }
        }
        Ok(())
    });
    Ok((port, shutdown_tx, server))
}

#[tokio::test]
async fn naive_h2_multiplexes_authenticated_padded_tcp_streams() {
    let connections = Arc::new(AtomicUsize::new(0));
    let (port, shutdown, server) = start_h2_server(Arc::clone(&connections)).await.unwrap();
    let name = "naive-h2";
    let outbounds = build_outbounds(&[naive_config(port, "h2", PASSWORD)], None).unwrap();
    let outbound = Arc::clone(outbounds.get(name).unwrap());
    let first = test_payload(17);
    let second = test_payload(91);
    let (first_result, second_result) = tokio::join!(
        exchange(Arc::clone(&outbound), first.clone()),
        exchange(outbound, second.clone())
    );
    assert_payload(first_result.unwrap(), &first);
    assert_payload(second_result.unwrap(), &second);
    let _ = shutdown.send(());
    timeout(Duration::from_secs(3), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(connections.load(Ordering::SeqCst), 1);
}

fn assert_payload(actual: Vec<u8>, expected: &[u8]) {
    assert!(
        actual == expected,
        "payload mismatch: actual={} expected={}",
        actual.len(),
        expected.len()
    );
}

async fn handle_h3_echo(
    request: http::Request<()>,
    mut stream: h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
) -> anyhow::Result<()> {
    assert_naive_request(&request);
    stream
        .send_response(
            http::Response::builder()
                .status(http::StatusCode::OK)
                .header("padding-type-reply", "1")
                .header("padding", "[".repeat(16))
                .body(())?,
        )
        .await?;
    let mut decoder = ReferencePaddingDecoder::new();
    let mut payload = Vec::new();
    while let Some(mut chunk) = stream.recv_data().await? {
        let chunk = chunk.copy_to_bytes(chunk.remaining());
        payload.extend_from_slice(&decoder.push(&chunk)?);
    }
    let mut frame = 0;
    for chunk in payload.chunks(12 * 1024) {
        stream
            .send_data(Bytes::from(reference_encode(chunk, &mut frame)))
            .await?;
    }
    stream.finish().await?;
    Ok(())
}

fn start_h3_server(
    connections: Arc<AtomicUsize>,
) -> anyhow::Result<(u16, tokio::task::JoinHandle<anyhow::Result<()>>)> {
    let server_crypto = tls_server_config(b"h3");
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)?,
    ));
    server_config.transport_config(Arc::new(quinn::TransportConfig::default()));
    let endpoint = quinn::Endpoint::server(
        server_config,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
    )?;
    let port = endpoint.local_addr()?.port();
    let server = tokio::spawn(async move {
        let connection = endpoint
            .accept()
            .await
            .ok_or_else(|| anyhow!("H3 endpoint closed"))?
            .await?;
        connections.fetch_add(1, Ordering::SeqCst);
        let mut h3_connection: h3::server::Connection<h3_quinn::Connection, Bytes> =
            h3::server::builder()
                .build(h3_quinn::Connection::new(connection))
                .await?;
        let mut streams = JoinSet::new();
        for _ in 0..2 {
            let resolver = h3_connection
                .accept()
                .await?
                .ok_or_else(|| anyhow!("H3 client closed before both streams"))?;
            let (request, stream) = resolver.resolve_request().await?;
            streams.spawn(handle_h3_echo(request, stream));
        }
        while !streams.is_empty() {
            tokio::select! {
                result = streams.join_next() => {
                    result.ok_or_else(|| anyhow!("missing H3 stream task"))???;
                }
                incoming = h3_connection.accept() => {
                    if let Err(error) = incoming {
                        return Err(error.into());
                    }
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
        Ok(())
    });
    Ok((port, server))
}

#[tokio::test]
async fn naive_h3_multiplexes_authenticated_padded_tcp_streams() {
    let connections = Arc::new(AtomicUsize::new(0));
    let (port, server) = start_h3_server(Arc::clone(&connections)).unwrap();
    let name = "naive-h3";
    let outbounds = build_outbounds(&[naive_config(port, "h3", PASSWORD)], None).unwrap();
    let outbound = Arc::clone(outbounds.get(name).unwrap());
    let first = test_payload(23);
    let second = test_payload(117);
    let (first_result, second_result) = tokio::join!(
        exchange(Arc::clone(&outbound), first.clone()),
        exchange(outbound, second.clone())
    );
    assert_payload(first_result.unwrap(), &first);
    assert_payload(second_result.unwrap(), &second);
    timeout(Duration::from_secs(3), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(connections.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn naive_h2_reports_authentication_failure_without_reconnecting() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let connections = Arc::new(AtomicUsize::new(0));
    let server_connections = Arc::clone(&connections);
    let acceptor = TlsAcceptor::from(Arc::new(tls_server_config(b"h2")));
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await?;
        server_connections.fetch_add(1, Ordering::SeqCst);
        let stream = acceptor.accept(stream).await?;
        let mut connection = h2::server::handshake(stream).await?;
        let (request, mut respond) = connection
            .accept()
            .await
            .ok_or_else(|| anyhow!("missing authentication request"))??;
        assert_ne!(
            request.headers()[http::header::PROXY_AUTHORIZATION],
            expected_authorization()
        );
        respond.send_response(
            http::Response::builder()
                .status(http::StatusCode::PROXY_AUTHENTICATION_REQUIRED)
                .body(())?,
            true,
        )?;
        let _ = timeout(Duration::from_millis(500), connection.accept()).await;
        Ok::<_, anyhow::Error>(())
    });
    let outbounds = build_outbounds(&[naive_config(port, "h2", "definitely-wrong")], None).unwrap();
    let error = outbounds["naive-h2"]
        .connect(&Destination::new("target.example", 443), 2_000)
        .await
        .err()
        .expect("wrong credentials must fail");
    assert!(
        error.to_string().contains("authentication failed"),
        "unexpected error: {error:#}"
    );
    timeout(Duration::from_secs(2), server)
        .await
        .context("authentication server timed out")
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(connections.load(Ordering::SeqCst), 1);
}
