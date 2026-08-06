use std::{net::IpAddr, sync::{atomic::{AtomicBool, Ordering}, Arc}, time::Duration};

use anyhow::anyhow;
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use bytes::{Buf, Bytes};
use rustls_pki_types::ServerName;
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::UdpSocket, sync::Mutex, time::timeout};
use tokio_rustls::TlsConnector;

use crate::routing::Destination;

use super::{
    target::destination_socket_addr,
    transports::{connect_quic_endpoint, connect_tcp, create_quic_endpoint, open_h2_connect, quic_client_config_with_resumption, resolve_quic_remote, run_dial_phase, tls_client_config},
    udp::resolve_udp_socket_addr,
    BoxedStream, Outbound, OutboundCapability,
};

const UDP_PSEUDO_HOST: &str = "_udp2";

pub(crate) struct TrustTunnelOutbound {
    name: String,
    server: String,
    port: u16,
    username: String,
    password: String,
    sni: Option<String>,
    skip_cert_verify: bool,
    transport: String,
    h3_session: Mutex<Option<Arc<TrustTunnelH3Session>>>,
}

impl TrustTunnelOutbound {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        name: String,
        server: String,
        port: u16,
        username: String,
        password: String,
        sni: Option<String>,
        skip_cert_verify: bool,
        transport: Option<String>,
    ) -> Self {
        Self {
            name,
            server,
            port,
            username,
            password,
            sni,
            skip_cert_verify,
            transport: transport.unwrap_or_else(|| "h2".to_string()).to_ascii_lowercase(),
            h3_session: Mutex::new(None),
        }
    }

    fn validate(&self) -> anyhow::Result<()> {
        if self.server.trim().is_empty() || self.port == 0 {
            return Err(anyhow!("TrustTunnel server and port are required"));
        }
        if self.username.is_empty() {
            return Err(anyhow!("TrustTunnel username is required"));
        }
        if self.password.is_empty() {
            return Err(anyhow!("TrustTunnel password is required"));
        }
        if !matches!(self.transport.as_str(), "h2" | "http2" | "h3" | "http3" | "quic") {
            return Err(anyhow!(
                "TrustTunnel transport '{}' is not implemented; use h2 or h3",
                self.transport
            ));
        }
        Ok(())
    }

    fn authorization(&self) -> String {
        let credentials = STANDARD.encode(format!("{}:{}", self.username, self.password));
        format!("Basic {credentials}")
    }

    async fn open_stream(&self, authority: &str, user_agent: &str, timeout_ms: u64) -> anyhow::Result<super::transports::Http2TunnelStream> {
        let tcp = connect_tcp(&destination_socket_addr(&Destination::new(&self.server, self.port)), timeout_ms).await?;
        let mut tls_config = tls_client_config(self.skip_cert_verify)?;
        tls_config.alpn_protocols = vec![b"h2".to_vec()];
        let server_name = ServerName::try_from(self.sni.clone().unwrap_or_else(|| self.server.clone()))
            .map_err(|error| anyhow!("invalid TrustTunnel SNI: {error}"))?;
        let tls = run_dial_phase(
            timeout_ms,
            "TrustTunnel TLS handshake",
            TlsConnector::from(Arc::new(tls_config)).connect(server_name, tcp),
        )
        .await??;
        if tls.get_ref().1.alpn_protocol() != Some(b"h2".as_slice()) {
            return Err(anyhow!("TrustTunnel endpoint did not negotiate HTTP/2"));
        }
        open_h2_connect(
            tls,
            authority,
            Some(&self.authorization()),
            user_agent,
            timeout_ms,
        )
        .await
    }

    async fn open_h3_stream(&self, authority: &str, timeout_ms: u64) -> anyhow::Result<tokio::io::DuplexStream> {
        let sni = self.sni.as_deref().unwrap_or(&self.server);
        let mut stored = self.h3_session.lock().await;
        let session = if let Some(session) = stored.as_ref().filter(|session| !session.is_closed()) {
            Arc::clone(session)
        } else {
            let session = Arc::new(TrustTunnelH3Session::connect(&self.server, self.port, sni, self.skip_cert_verify, timeout_ms).await?);
            *stored = Some(Arc::clone(&session));
            session
        };
        drop(stored);
        session.open(authority, Some(&self.authorization()), timeout_ms).await
    }
}

#[async_trait]
impl Outbound for TrustTunnelOutbound {
    fn name(&self) -> &str { &self.name }

    fn kind(&self) -> &'static str { "trusttunnel" }

    fn capability(&self) -> OutboundCapability {
        match self.validate() {
            Ok(()) => OutboundCapability::tcp_udp(if matches!(self.transport.as_str(), "h3" | "http3" | "quic") { "h3-connect-and-udp2" } else { "h2-connect-and-udp2" }),
            Err(error) => OutboundCapability::unsupported(error.to_string()),
        }
    }

    async fn connect(&self, destination: &Destination, timeout_ms: u64) -> anyhow::Result<BoxedStream> {
        self.validate()?;
        if matches!(self.transport.as_str(), "h3" | "http3" | "quic") {
            return Ok(Box::new(self.open_h3_stream(&destination_socket_addr(destination), timeout_ms).await?));
        }
        let stream = self.open_stream(&destination_socket_addr(destination), "Skyhook/TrustTunnel", timeout_ms).await?;
        Ok(Box::new(stream))
    }

    async fn udp_exchange(&self, destination: &Destination, payload: &[u8], timeout_ms: u64) -> anyhow::Result<Vec<u8>> {
        self.validate()?;
        if payload.len() > u32::MAX as usize {
            return Err(anyhow!("TrustTunnel UDP payload is too large"));
        }
        let target = resolve_udp_socket_addr(&destination.host, destination.port, timeout_ms).await?;
        let socket = UdpSocket::bind(if target.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }).await?;
        let source = socket.local_addr()?;
        let mut stream: Box<dyn super::ProxyStream> = if matches!(self.transport.as_str(), "h3" | "http3" | "quic") {
            Box::new(self.open_h3_stream(UDP_PSEUDO_HOST, timeout_ms).await?)
        } else {
            Box::new(self.open_stream(UDP_PSEUDO_HOST, "Skyhook _udp2", timeout_ms).await?)
        };
        let frame = encode_udp_frame(source, target, payload)?;
        stream.write_all(&frame).await?;
        stream.flush().await?;
        let length = timeout(Duration::from_millis(timeout_ms.max(1)), stream.read_u32()).await?? as usize;
        if !(36..=4 * 1024 * 1024).contains(&length) {
            return Err(anyhow!("TrustTunnel UDP response frame length {length} is invalid"));
        }
        let mut response = vec![0u8; length];
        timeout(Duration::from_millis(timeout_ms.max(1)), stream.read_exact(&mut response)).await??;
        Ok(response[36..].to_vec())
    }
}

struct TrustTunnelH3Session {
    _endpoint: quinn::Endpoint,
    connection: quinn::Connection,
    sender: Mutex<h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>>,
    closed: Arc<AtomicBool>,
}

impl TrustTunnelH3Session {
    async fn connect(server: &str, port: u16, sni: &str, skip_cert_verify: bool, timeout_ms: u64) -> anyhow::Result<Self> {
        let remote = resolve_quic_remote("TrustTunnel HTTP/3", server, port).await?;
        let endpoint = create_quic_endpoint(remote)?;
        let (endpoint, connection) = connect_quic_endpoint(
            endpoint,
            remote,
            sni,
            quic_client_config_with_resumption(skip_cert_verify, Some("h3"), None, None, false)?,
            timeout_ms,
            "TrustTunnel HTTP/3",
        ).await?;
        let mut builder = h3::client::builder();
        builder.enable_extended_connect(true);
        let (mut driver, sender) = run_dial_phase(
            timeout_ms,
            "TrustTunnel HTTP/3 initialization",
            builder.build::<_, _, Bytes>(h3_quinn::Connection::new(connection.clone())),
        ).await??;
        let closed = Arc::new(AtomicBool::new(false));
        let driver_closed = Arc::clone(&closed);
        tokio::spawn(async move { let _ = driver.wait_idle().await; driver_closed.store(true, Ordering::Release); });
        Ok(Self { _endpoint: endpoint, connection, sender: Mutex::new(sender), closed })
    }

    fn is_closed(&self) -> bool { self.closed.load(Ordering::Acquire) || self.connection.close_reason().is_some() }

    async fn open(&self, authority: &str, authorization: Option<&str>, timeout_ms: u64) -> anyhow::Result<tokio::io::DuplexStream> {
        if self.is_closed() { return Err(anyhow!("TrustTunnel HTTP/3 session is closed")); }
        let mut request = http::Request::builder()
            .method(http::Method::CONNECT)
            .version(http::Version::HTTP_3)
            .uri(format!("https://{authority}"));
        if let Some(authorization) = authorization { request = request.header(http::header::PROXY_AUTHORIZATION, authorization); }
        let request = request.body(())?;
        let mut sender = self.sender.lock().await;
        let mut stream = run_dial_phase(timeout_ms, "TrustTunnel HTTP/3 CONNECT request", sender.send_request(request)).await??;
        drop(sender);
        let response = run_dial_phase(timeout_ms, "TrustTunnel HTTP/3 CONNECT response", stream.recv_response()).await??;
        if !response.status().is_success() { return Err(anyhow!("TrustTunnel HTTP/3 CONNECT failed with status {}", response.status())); }
        Ok(spawn_trusttunnel_h3_stream(stream))
    }
}

fn spawn_trusttunnel_h3_stream(stream: h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>) -> tokio::io::DuplexStream {
    let (app_side, relay_side) = tokio::io::duplex(256 * 1024);
    let (mut local_read, mut local_write) = tokio::io::split(relay_side);
    let (mut send, mut recv) = stream.split();
    tokio::spawn(async move {
        let mut buffer = vec![0u8; 32 * 1024];
        loop {
            match local_read.read(&mut buffer).await {
                Ok(0) => { let _ = send.finish().await; return; }
                Ok(length) if send.send_data(Bytes::copy_from_slice(&buffer[..length])).await.is_err() => return,
                Ok(_) => {}
                Err(_) => return,
            }
        }
    });
    tokio::spawn(async move {
        loop {
            match recv.recv_data().await {
                Ok(Some(mut chunk)) => {
                    let bytes = chunk.copy_to_bytes(chunk.remaining());
                    if local_write.write_all(&bytes).await.is_err() { return; }
                }
                Ok(None) => { let _ = local_write.shutdown().await; return; }
                Err(_) => return,
            }
        }
    });
    app_side
}

fn encode_udp_frame(source: std::net::SocketAddr, target: std::net::SocketAddr, payload: &[u8]) -> anyhow::Result<Vec<u8>> {
    let body_len = 16 + 2 + 16 + 2 + 1 + payload.len();
    let mut frame = Vec::with_capacity(4 + body_len);
    frame.extend_from_slice(&(body_len as u32).to_be_bytes());
    frame.extend_from_slice(&encode_ip(source.ip()));
    frame.extend_from_slice(&source.port().to_be_bytes());
    frame.extend_from_slice(&encode_ip(target.ip()));
    frame.extend_from_slice(&target.port().to_be_bytes());
    frame.push(0);
    frame.extend_from_slice(payload);
    Ok(frame)
}

fn encode_ip(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V4(ip) => {
            let mut result = [0u8; 16];
            result[12..].copy_from_slice(&ip.octets());
            result
        }
        IpAddr::V6(ip) => ip.octets(),
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use bytes::Bytes;
    use rcgen::generate_simple_self_signed;
    use rustls::{crypto::aws_lc_rs, ServerConfig};
    use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    use super::*;

    #[test]
    fn encodes_trusttunnel_udp_frame_with_padded_ipv4_addresses() {
        let frame = encode_udp_frame(
            (Ipv4Addr::UNSPECIFIED, 1234).into(),
            (Ipv4Addr::new(1, 1, 1, 1), 53).into(),
            b"dns",
        )
        .expect("frame");
        assert_eq!(u32::from_be_bytes(frame[..4].try_into().unwrap()), 16 + 2 + 16 + 2 + 1 + 3);
        assert_eq!(&frame[4..16], &[0; 12]);
        assert_eq!(&frame[20..22], &[4, 210]);
        assert_eq!(&frame[22..34], &[0; 12]);
        assert_eq!(&frame[34..38], &[1, 1, 1, 1]);
        assert_eq!(&frame[38..40], &[0, 53]);
        assert_eq!(&frame[40..], &[0, b'd', b'n', b's']);
    }

    #[tokio::test]
    async fn trusttunnel_h2_tls_connect_round_trips_real_stream() {
        let certificate = generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let certificate_der = CertificateDer::from(certificate.cert.der().to_vec());
        let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            certificate.key_pair.serialize_der(),
        ));
        let provider = aws_lc_rs::default_provider();
        let mut server_config = ServerConfig::builder_with_provider(provider.into())
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![certificate_der], private_key)
            .unwrap();
        server_config.alpn_protocols = vec![b"h2".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let tls = acceptor.accept(tcp).await.unwrap();
            let mut connection = h2::server::handshake(tls).await.unwrap();
            let (request, mut respond) = connection.accept().await.unwrap().unwrap();
            let driver = tokio::spawn(async move {
                while connection.accept().await.is_some() {}
            });
            assert_eq!(request.method(), http::Method::CONNECT);
            assert_eq!(request.uri().authority().map(|value| value.as_str()), Some("target.example:443"));
            assert_eq!(request.headers().get(http::header::PROXY_AUTHORIZATION).unwrap(), "Basic dXNlcjpwYXNz");
            let response = http::Response::builder().status(200).body(()).unwrap();
            let mut send = respond.send_response(response, false).unwrap();
            send.send_data(Bytes::from_static(b"pong"), true).unwrap();
            let mut body = request.into_body();
            let mut payload = Vec::new();
            while let Some(chunk) = body.data().await {
                let chunk = chunk.unwrap();
                let length = chunk.len();
                payload.extend_from_slice(&chunk);
                body.flow_control().release_capacity(length).unwrap();
            }
            assert_eq!(payload, b"ping");
            driver.abort();
        });

        let outbound = TrustTunnelOutbound::new(
            "trust-h2".to_string(),
            "127.0.0.1".to_string(),
            port,
            "user".to_string(),
            "pass".to_string(),
            Some("localhost".to_string()),
            true,
            Some("h2".to_string()),
        );
        let mut stream = tokio::time::timeout(
            Duration::from_secs(2),
            outbound.connect(&Destination::new("target.example", 443), 2_000),
        )
        .await
        .expect("TrustTunnel connect timed out")
        .unwrap();
        tokio::time::timeout(Duration::from_secs(2), stream.write_all(b"ping"))
            .await
            .expect("TrustTunnel write timed out")
            .unwrap();
        let mut response = [0u8; 4];
        tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut response))
            .await
            .expect("TrustTunnel read timed out")
            .unwrap();
        assert_eq!(&response, b"pong");
        tokio::time::timeout(Duration::from_secs(2), stream.shutdown())
            .await
            .expect("TrustTunnel shutdown timed out")
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("TrustTunnel server timed out")
            .unwrap();
    }

    #[tokio::test]
    async fn trusttunnel_h3_connect_round_trips_real_stream() {
        let certificate = generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let certificate_der = CertificateDer::from(certificate.cert.der().to_vec());
        let private_key = PrivatePkcs8KeyDer::from(certificate.key_pair.serialize_der());
        let provider = aws_lc_rs::default_provider();
        let mut server_crypto = ServerConfig::builder_with_provider(provider.into())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![certificate_der], private_key.into())
            .unwrap();
        server_crypto.alpn_protocols = vec![b"h3".to_vec()];
        let server_config = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto).unwrap(),
        ));
        let endpoint = quinn::Endpoint::server(
            server_config,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        )
        .unwrap();
        let port = endpoint.local_addr().unwrap().port();

        let server = tokio::spawn(async move {
            let connection = endpoint
                .accept()
                .await
                .expect("TrustTunnel H3 server did not receive a connection")
                .await
                .unwrap();
            let mut h3_builder = h3::server::builder();
            h3_builder.enable_extended_connect(true);
            let mut h3_connection = h3_builder
                .build::<_, Bytes>(h3_quinn::Connection::new(connection))
                .await
                .unwrap();
            let resolver = h3_connection.accept().await.unwrap().unwrap();
            let (request, mut stream) = resolver.resolve_request().await.unwrap();
            assert_eq!(request.method(), http::Method::CONNECT);
            assert_eq!(request.version(), http::Version::HTTP_3);
            assert_eq!(request.uri().authority().map(|value| value.as_str()), Some("target.example:443"));
            assert_eq!(request.headers().get(http::header::PROXY_AUTHORIZATION).unwrap(), "Basic dXNlcjpwYXNz");
            stream
                .send_response(http::Response::builder().status(200).body(()).unwrap())
                .await
                .unwrap();

            let mut payload = Vec::new();
            while let Some(mut chunk) = timeout(Duration::from_secs(2), stream.recv_data())
                .await
                .expect("TrustTunnel H3 server did not receive DATA")
                .unwrap()
            {
                payload.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
                if payload.len() >= 4 {
                    break;
                }
            }
            assert_eq!(&payload, b"ping");
            stream.send_data(Bytes::from_static(b"pong")).await.unwrap();
            stream.finish().await.unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;
        });

        let outbound = TrustTunnelOutbound::new(
            "trust-h3".to_string(),
            "127.0.0.1".to_string(),
            port,
            "user".to_string(),
            "pass".to_string(),
            Some("localhost".to_string()),
            true,
            Some("h3".to_string()),
        );
        let mut stream = tokio::time::timeout(
            Duration::from_secs(2),
            outbound.connect(&Destination::new("target.example", 443), 2_000),
        )
        .await
        .expect("TrustTunnel H3 connect timed out")
        .unwrap();
        tokio::time::timeout(Duration::from_secs(2), stream.write_all(b"ping"))
            .await
            .expect("TrustTunnel H3 write timed out")
            .unwrap();
        let mut response = [0u8; 4];
        tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut response))
            .await
            .expect("TrustTunnel H3 read timed out")
            .unwrap();
        assert_eq!(&response, b"pong");
        tokio::time::timeout(Duration::from_secs(2), stream.shutdown())
            .await
            .expect("TrustTunnel H3 shutdown timed out")
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("TrustTunnel H3 server timed out")
            .unwrap();
    }

    #[tokio::test]
    async fn trusttunnel_h3_udp2_round_trips_real_datagram() {
        let certificate = generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let certificate_der = CertificateDer::from(certificate.cert.der().to_vec());
        let private_key = PrivatePkcs8KeyDer::from(certificate.key_pair.serialize_der());
        let provider = aws_lc_rs::default_provider();
        let mut server_crypto = ServerConfig::builder_with_provider(provider.into())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![certificate_der], private_key.into())
            .unwrap();
        server_crypto.alpn_protocols = vec![b"h3".to_vec()];
        let server_config = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto).unwrap(),
        ));
        let endpoint = quinn::Endpoint::server(
            server_config,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        )
        .unwrap();
        let port = endpoint.local_addr().unwrap().port();

        let server = tokio::spawn(async move {
            let connection = endpoint
                .accept()
                .await
                .expect("TrustTunnel H3 UDP server did not receive a connection")
                .await
                .unwrap();
            let mut h3_builder = h3::server::builder();
            h3_builder.enable_extended_connect(true);
            let mut h3_connection = h3_builder
                .build::<_, Bytes>(h3_quinn::Connection::new(connection))
                .await
                .unwrap();
            let resolver = h3_connection.accept().await.unwrap().unwrap();
            let (request, mut stream) = resolver.resolve_request().await.unwrap();
            assert_eq!(request.method(), http::Method::CONNECT);
            assert_eq!(request.uri().authority().map(|value| value.as_str()), Some(UDP_PSEUDO_HOST));
            assert_eq!(request.headers().get(http::header::PROXY_AUTHORIZATION).unwrap(), "Basic dXNlcjpwYXNz");
            stream
                .send_response(http::Response::builder().status(200).body(()).unwrap())
                .await
                .unwrap();

            let mut frame = Vec::new();
            while let Some(mut chunk) = timeout(Duration::from_secs(2), stream.recv_data())
                .await
                .expect("TrustTunnel H3 UDP server did not receive DATA")
                .unwrap()
            {
                frame.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
                if frame.len() >= 4 {
                    let body_length = u32::from_be_bytes(frame[..4].try_into().unwrap()) as usize;
                    if frame.len() >= body_length + 4 {
                        break;
                    }
                }
            }
            assert_eq!(u32::from_be_bytes(frame[..4].try_into().unwrap()) as usize, frame.len() - 4);
            assert_eq!(&frame[frame.len() - 3..], b"dns");
            let mut response = Vec::with_capacity(4 + 36 + 3);
            response.extend_from_slice(&39u32.to_be_bytes());
            response.extend_from_slice(&frame[4..40]);
            response.extend_from_slice(b"dns");
            stream.send_data(Bytes::from(response)).await.unwrap();
            stream.finish().await.unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;
        });

        let outbound = TrustTunnelOutbound::new(
            "trust-h3-udp".to_string(),
            "127.0.0.1".to_string(),
            port,
            "user".to_string(),
            "pass".to_string(),
            Some("localhost".to_string()),
            true,
            Some("h3".to_string()),
        );
        let response = outbound
            .udp_exchange(&Destination::new("127.0.0.1", 53), b"dns", 2_000)
            .await
            .unwrap();
        assert_eq!(response, b"dns");
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("TrustTunnel H3 UDP server timed out")
            .unwrap();
    }
}
