use std::{sync::Arc, time::Duration};

use anyhow::{anyhow, Context};
use base64::Engine as _;
use rustls::{
    crypto::aws_lc_rs,
    pki_types::{CertificateDer, PrivatePkcs8KeyDer},
    ServerConfig,
};
use supercore::{config::OutboundConfig, outbound::build_outbounds, routing::Destination};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpListener,
    task::JoinHandle,
    time::timeout,
};
use tokio_rustls::TlsAcceptor;

const USERNAME: &str = "http-user";
const PASSWORD: &str = "http-password";
const PREFETCHED: &[u8] = b"proxy-prefetched-data";

fn http_config(port: u16, tls: bool, skip_cert_verify: bool) -> OutboundConfig {
    OutboundConfig::Http {
        name: if tls {
            "https-proxy".to_string()
        } else {
            "http-proxy".to_string()
        },
        server: "127.0.0.1".to_string(),
        port,
        username: Some(USERNAME.to_string()),
        password: Some(PASSWORD.to_string()),
        tls,
        sni: tls.then(|| "proxy.test".to_string()),
        skip_cert_verify,
    }
}

fn test_payload() -> Vec<u8> {
    (0..96 * 1024).map(|index| (index % 251) as u8).collect()
}

fn tls_server_config() -> ServerConfig {
    let certificate = rcgen::generate_simple_self_signed(vec!["proxy.test".to_string()]).unwrap();
    let certificate_der = CertificateDer::from(certificate.cert.der().to_vec());
    let private_key = PrivatePkcs8KeyDer::from(certificate.key_pair.serialize_der());
    let provider = aws_lc_rs::default_provider();
    let mut config = ServerConfig::builder_with_provider(provider.into())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![certificate_der], private_key.into())
        .unwrap();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config
}

async fn read_headers<S>(stream: &mut S) -> anyhow::Result<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let mut request = Vec::new();
    let mut byte = [0u8; 1];
    while !request.ends_with(b"\r\n\r\n") {
        if request.len() >= 64 * 1024 {
            return Err(anyhow!("proxy request headers are too large"));
        }
        stream.read_exact(&mut byte).await?;
        request.push(byte[0]);
    }
    Ok(request)
}

async fn serve_connect<S>(
    mut stream: S,
    expected_authority: &str,
    payload: &[u8],
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request = String::from_utf8(read_headers(&mut stream).await?)?;
    assert!(request.starts_with(&format!("CONNECT {expected_authority} HTTP/1.1\r\n")));
    assert!(request.contains(&format!("Host: {expected_authority}\r\n")));
    let token = base64::engine::general_purpose::STANDARD.encode(format!("{USERNAME}:{PASSWORD}"));
    assert!(request.contains(&format!("Proxy-Authorization: Basic {token}\r\n")));

    let mut response = b"HTTP/1.1 200 Connection established\r\n\r\n".to_vec();
    response.extend_from_slice(PREFETCHED);
    stream.write_all(&response).await?;
    stream.flush().await?;

    let mut received = vec![0u8; payload.len()];
    stream.read_exact(&mut received).await?;
    assert_eq!(received, payload);
    stream.write_all(&received).await?;
    stream.shutdown().await?;
    Ok(())
}

async fn start_plain_proxy(
    expected_authority: &'static str,
    payload: Vec<u8>,
) -> anyhow::Result<(u16, JoinHandle<anyhow::Result<()>>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await?;
        serve_connect(stream, expected_authority, &payload).await
    });
    Ok((port, task))
}

async fn start_https_proxy(
    expected_authority: &'static str,
    payload: Vec<u8>,
) -> anyhow::Result<(u16, JoinHandle<anyhow::Result<()>>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let acceptor = TlsAcceptor::from(Arc::new(tls_server_config()));
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await?;
        let stream = acceptor.accept(stream).await?;
        assert_eq!(
            stream.get_ref().1.alpn_protocol(),
            Some(b"http/1.1".as_slice())
        );
        serve_connect(stream, expected_authority, &payload).await
    });
    Ok((port, task))
}

async fn exchange(
    config: OutboundConfig,
    destination: Destination,
    payload: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let name = config.name().to_string();
    let outbounds = build_outbounds(&[config], None)?;
    let mut stream = outbounds
        .get(&name)
        .context("missing HTTP outbound")?
        .connect(&destination, 3_000)
        .await?;
    stream.write_all(payload).await?;
    stream.flush().await?;
    let mut response = vec![0u8; PREFETCHED.len() + payload.len()];
    stream.read_exact(&mut response).await?;
    stream.shutdown().await?;
    Ok(response)
}

#[tokio::test]
async fn plain_http_connect_preserves_prefetch_and_ipv6_authority() {
    let payload = test_payload();
    let (port, server) = start_plain_proxy("[2001:db8::7]:443", payload.clone())
        .await
        .unwrap();
    let response = exchange(
        http_config(port, false, false),
        Destination::new("2001:db8::7", 443),
        &payload,
    )
    .await
    .unwrap();
    assert_eq!(&response[..PREFETCHED.len()], PREFETCHED);
    assert_eq!(&response[PREFETCHED.len()..], payload);
    timeout(Duration::from_secs(3), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn https_connect_negotiates_tls_and_transfers_large_payload() {
    let payload = test_payload();
    let (port, server) = start_https_proxy("target.example:8443", payload.clone())
        .await
        .unwrap();
    let response = exchange(
        http_config(port, true, true),
        Destination::new("target.example", 8443),
        &payload,
    )
    .await
    .unwrap();
    assert_eq!(&response[..PREFETCHED.len()], PREFETCHED);
    assert_eq!(&response[PREFETCHED.len()..], payload);
    timeout(Duration::from_secs(3), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn connect_reports_proxy_status_and_certificate_failures() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let rejection = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let _ = read_headers(&mut stream).await?;
        stream
            .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
            .await?;
        Ok::<_, anyhow::Error>(())
    });
    let config = http_config(port, false, false);
    let name = config.name().to_string();
    let outbounds = build_outbounds(&[config], None).unwrap();
    let error = match outbounds[&name]
        .connect(&Destination::new("target.example", 443), 3_000)
        .await
    {
        Ok(_) => panic!("HTTP proxy unexpectedly accepted a 407 response"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("407"), "{error:#}");
    rejection.await.unwrap().unwrap();

    let (tls_port, tls_server) = start_https_proxy("target.example:443", Vec::new())
        .await
        .unwrap();
    let config = http_config(tls_port, true, false);
    let name = config.name().to_string();
    let outbounds = build_outbounds(&[config], None).unwrap();
    let error = match outbounds[&name]
        .connect(&Destination::new("target.example", 443), 3_000)
        .await
    {
        Ok(_) => panic!("HTTPS proxy unexpectedly trusted a self-signed certificate"),
        Err(error) => error,
    };
    assert!(
        error.to_string().contains("certificate") || format!("{error:#}").contains("UnknownIssuer"),
        "{error:#}"
    );
    let server_result = timeout(Duration::from_secs(3), tls_server)
        .await
        .unwrap()
        .unwrap();
    assert!(server_result.is_err());
}
