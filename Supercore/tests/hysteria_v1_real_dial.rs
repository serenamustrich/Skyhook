use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use anyhow::{anyhow, Context};
use bytes::Bytes;
use rustls::{
    crypto::aws_lc_rs,
    pki_types::{CertificateDer, PrivatePkcs8KeyDer},
    ServerConfig,
};
use supercore::{config::OutboundConfig, outbound::build_outbounds, routing::Destination};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    task::JoinHandle,
    time::timeout,
};

const AUTH: &str = "hysteria-v1-auth";
const UPLOAD_RATE: u64 = 12_500_000;
const DOWNLOAD_RATE: u64 = 25_000_000;

fn hysteria_config(port: u16, auth: &str, fast_open: bool) -> OutboundConfig {
    OutboundConfig::Hysteria {
        name: "hy1-local".to_string(),
        server: "127.0.0.1".to_string(),
        port,
        auth: Some(auth.to_string()),
        auth_str: None,
        protocol: Some("udp".to_string()),
        up: Some("100 Mbps".to_string()),
        down: Some("200 Mbps".to_string()),
        sni: Some("localhost".to_string()),
        skip_cert_verify: true,
        obfs: None,
        alpn: Some("hysteria".to_string()),
        receive_window_conn: Some(16 * 1024 * 1024),
        receive_window: Some(40 * 1024 * 1024),
        disable_mtu_discovery: true,
        fast_open,
    }
}

fn local_hysteria_server() -> anyhow::Result<(quinn::Endpoint, SocketAddr)> {
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    let certificate_der = CertificateDer::from(certificate.cert.der().to_vec());
    let private_key = PrivatePkcs8KeyDer::from(certificate.key_pair.serialize_der());
    let provider = aws_lc_rs::default_provider();
    let mut server_crypto = ServerConfig::builder_with_provider(provider.into())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(vec![certificate_der], private_key.into())?;
    server_crypto.alpn_protocols = vec![b"hysteria".to_vec()];
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)?,
    ));
    let mut transport = quinn::TransportConfig::default();
    transport.datagram_receive_buffer_size(Some(4 * 1024 * 1024));
    transport.datagram_send_buffer_size(4 * 1024 * 1024);
    server_config.transport_config(Arc::new(transport));
    let endpoint = quinn::Endpoint::server(
        server_config,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
    )?;
    let address = endpoint.local_addr()?;
    Ok((endpoint, address))
}

async fn accept_connection(endpoint: &quinn::Endpoint) -> anyhow::Result<quinn::Connection> {
    endpoint
        .accept()
        .await
        .context("hysteria v1 server endpoint closed")?
        .await
        .context("hysteria v1 QUIC handshake failed")
}

async fn read_client_hello(
    connection: &quinn::Connection,
) -> anyhow::Result<(quinn::SendStream, quinn::RecvStream, Vec<u8>)> {
    let (send, mut recv) = connection.accept_bi().await?;
    let mut version = [0u8; 1];
    recv.read_exact(&mut version).await?;
    if version[0] != 3 {
        return Err(anyhow!(
            "unexpected Hysteria protocol version {}",
            version[0]
        ));
    }
    let upload = read_u64(&mut recv).await?;
    let download = read_u64(&mut recv).await?;
    if upload != UPLOAD_RATE || download != DOWNLOAD_RATE {
        return Err(anyhow!("unexpected Hysteria rates {upload}/{download}"));
    }
    let auth_len = read_u16(&mut recv).await? as usize;
    let mut auth = vec![0u8; auth_len];
    recv.read_exact(&mut auth).await?;
    Ok((send, recv, auth))
}

async fn write_server_hello(
    send: &mut quinn::SendStream,
    accepted: bool,
    message: &str,
) -> anyhow::Result<()> {
    let mut response = Vec::with_capacity(19 + message.len());
    response.push(u8::from(accepted));
    response.extend_from_slice(&DOWNLOAD_RATE.to_be_bytes());
    response.extend_from_slice(&UPLOAD_RATE.to_be_bytes());
    response.extend_from_slice(&(message.len() as u16).to_be_bytes());
    response.extend_from_slice(message.as_bytes());
    send.write_all(&response).await?;
    send.flush().await?;
    Ok(())
}

async fn read_client_request(
    connection: &quinn::Connection,
) -> anyhow::Result<(quinn::SendStream, quinn::RecvStream, bool, Destination)> {
    let (send, mut recv) = connection.accept_bi().await?;
    let mut udp = [0u8; 1];
    recv.read_exact(&mut udp).await?;
    let host_len = read_u16(&mut recv).await? as usize;
    let mut host = vec![0u8; host_len];
    recv.read_exact(&mut host).await?;
    let port = read_u16(&mut recv).await?;
    Ok((
        send,
        recv,
        udp[0] == 1,
        Destination::new(String::from_utf8(host)?, port),
    ))
}

async fn write_server_response(
    send: &mut quinn::SendStream,
    accepted: bool,
    udp_session_id: u32,
    message: &str,
) -> anyhow::Result<()> {
    let mut response = Vec::with_capacity(7 + message.len());
    response.push(u8::from(accepted));
    response.extend_from_slice(&udp_session_id.to_be_bytes());
    response.extend_from_slice(&(message.len() as u16).to_be_bytes());
    response.extend_from_slice(message.as_bytes());
    send.write_all(&response).await?;
    send.flush().await?;
    Ok(())
}

async fn read_u16(reader: &mut quinn::RecvStream) -> anyhow::Result<u16> {
    let mut bytes = [0u8; 2];
    reader.read_exact(&mut bytes).await?;
    Ok(u16::from_be_bytes(bytes))
}

async fn read_u64(reader: &mut quinn::RecvStream) -> anyhow::Result<u64> {
    let mut bytes = [0u8; 8];
    reader.read_exact(&mut bytes).await?;
    Ok(u64::from_be_bytes(bytes))
}

async fn await_server(task: JoinHandle<anyhow::Result<()>>) {
    timeout(Duration::from_secs(3), task)
        .await
        .expect("hysteria v1 server timed out")
        .expect("hysteria v1 server task panicked")
        .expect("hysteria v1 server failed");
}

#[tokio::test]
async fn hysteria_v1_auth_tcp_udp_share_one_real_quic_connection() {
    let (endpoint, address) = local_hysteria_server().unwrap();
    let server = tokio::spawn(async move {
        let connection = accept_connection(&endpoint).await?;
        let (mut control_send, _control_recv, auth) = read_client_hello(&connection).await?;
        assert_eq!(auth, AUTH.as_bytes());
        write_server_hello(&mut control_send, true, "ok").await?;

        let (mut tcp_send, mut tcp_recv, udp, destination) =
            read_client_request(&connection).await?;
        assert!(!udp);
        assert_eq!(destination, Destination::new("target.example", 443));
        write_server_response(&mut tcp_send, true, 0, "").await?;
        let mut payload = [0u8; 4];
        tcp_recv.read_exact(&mut payload).await?;
        assert_eq!(&payload, b"ping");
        tcp_send.write_all(b"pong").await?;
        tcp_send.finish()?;

        let (mut udp_send, _udp_recv, udp, destination) = read_client_request(&connection).await?;
        assert!(udp);
        assert_eq!(destination, Destination::new("", 0));
        write_server_response(&mut udp_send, true, 0x1020_3040, "").await?;
        let datagram = connection.read_datagram().await?;
        assert_eq!(&datagram[..4], &0x1020_3040u32.to_be_bytes());
        connection
            .send_datagram_wait(Bytes::copy_from_slice(&datagram))
            .await?;
        tokio::time::sleep(Duration::from_millis(50)).await;
        Ok(())
    });

    let outbounds = build_outbounds(&[hysteria_config(address.port(), AUTH, false)], None).unwrap();
    let outbound = outbounds.get("hy1-local").unwrap();
    assert_eq!(outbound.kind(), "hysteria");
    assert!(outbound.capability().tcp_supported);
    assert!(outbound.capability().udp_supported);

    let mut stream = outbound
        .connect(&Destination::new("target.example", 443), 2_000)
        .await
        .unwrap();
    stream.write_all(b"ping").await.unwrap();
    let mut response = [0u8; 4];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"pong");
    assert_eq!(
        outbound
            .udp_exchange(&Destination::new("dns.example", 53), b"dns-query", 2_000)
            .await
            .unwrap(),
        b"dns-query"
    );
    await_server(server).await;
}

#[tokio::test]
async fn hysteria_v1_rejects_bad_auth_before_opening_target_stream() {
    let (endpoint, address) = local_hysteria_server().unwrap();
    let server = tokio::spawn(async move {
        let connection = accept_connection(&endpoint).await?;
        let (mut control_send, _control_recv, auth) = read_client_hello(&connection).await?;
        assert_eq!(auth, b"bad-auth");
        write_server_hello(&mut control_send, false, "denied").await?;
        tokio::time::sleep(Duration::from_millis(50)).await;
        Ok(())
    });

    let outbounds =
        build_outbounds(&[hysteria_config(address.port(), "bad-auth", false)], None).unwrap();
    let error = outbounds["hy1-local"]
        .connect(&Destination::new("target.example", 443), 2_000)
        .await
        .err()
        .expect("bad auth must fail");
    assert!(error.to_string().contains("authentication failed: denied"));
    await_server(server).await;
}

#[tokio::test]
async fn hysteria_v1_fast_open_sends_payload_before_server_response() {
    let (endpoint, address) = local_hysteria_server().unwrap();
    let server = tokio::spawn(async move {
        let connection = accept_connection(&endpoint).await?;
        let (mut control_send, _control_recv, auth) = read_client_hello(&connection).await?;
        assert_eq!(auth, AUTH.as_bytes());
        write_server_hello(&mut control_send, true, "ok").await?;

        let (mut tcp_send, mut tcp_recv, udp, destination) =
            read_client_request(&connection).await?;
        assert!(!udp);
        assert_eq!(destination, Destination::new("fast.example", 8443));
        let mut payload = [0u8; 4];
        timeout(Duration::from_secs(1), tcp_recv.read_exact(&mut payload)).await??;
        assert_eq!(&payload, b"ping");
        write_server_response(&mut tcp_send, true, 0, "").await?;
        tcp_send.write_all(b"pong").await?;
        tcp_send.finish()?;
        tokio::time::sleep(Duration::from_millis(50)).await;
        Ok(())
    });

    let outbounds = build_outbounds(&[hysteria_config(address.port(), AUTH, true)], None).unwrap();
    let mut stream = outbounds["hy1-local"]
        .connect(&Destination::new("fast.example", 8443), 2_000)
        .await
        .unwrap();
    stream.write_all(b"ping").await.unwrap();
    stream.flush().await.unwrap();
    let mut response = [0u8; 4];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"pong");
    await_server(server).await;
}

#[tokio::test]
async fn hysteria_v1_silent_auth_phase_obeys_dial_timeout() {
    let (endpoint, address) = local_hysteria_server().unwrap();
    let server = tokio::spawn(async move {
        let connection = accept_connection(&endpoint).await?;
        let (_control_send, _control_recv, auth) = read_client_hello(&connection).await?;
        assert_eq!(auth, AUTH.as_bytes());
        tokio::time::sleep(Duration::from_millis(400)).await;
        Ok(())
    });

    let outbounds = build_outbounds(&[hysteria_config(address.port(), AUTH, false)], None).unwrap();
    let started = tokio::time::Instant::now();
    let error = outbounds["hy1-local"]
        .connect(&Destination::new("target.example", 443), 100)
        .await
        .err()
        .expect("silent auth must time out");
    assert!(error.to_string().contains("timed out"), "got {error}");
    assert!(started.elapsed() < Duration::from_secs(1));
    await_server(server).await;
}
