//! Env-gated Hysteria v1 real-server tests.
//!
//! Required environment:
//! - SKYHOOK_HYSTERIA_V1_SERVER
//! - SKYHOOK_HYSTERIA_V1_PORT, optional, default 443
//! - SKYHOOK_HYSTERIA_V1_AUTH or SKYHOOK_HYSTERIA_V1_AUTH_STR
//! - SKYHOOK_HYSTERIA_V1_OBFS, optional

use std::time::Duration;

use skyhook::{config::OutboundConfig, outbound::build_outbounds, routing::Destination};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
#[ignore = "requires a reachable Hysteria v1 server"]
async fn hysteria_v1_real_tcp_roundtrip() {
    let outbound = build_hysteria_outbound();
    let dest = Destination::new("httpbin.org".to_string(), 80);
    let mut stream = outbound
        .connect(&dest, 5_000)
        .await
        .expect("hysteria v1 tcp connect");

    stream
        .write_all(b"GET /status/204 HTTP/1.1\r\nHost: httpbin.org\r\nConnection: close\r\n\r\n")
        .await
        .expect("write http request");

    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(Duration::from_secs(8), stream.read(&mut buf))
        .await
        .expect("tcp read timeout")
        .expect("tcp read");

    assert!(n > 0, "real Hysteria v1 TCP should return bytes");
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(
        response.starts_with("HTTP/1.1") || response.starts_with("HTTP/2"),
        "unexpected HTTP response over Hysteria v1: {response:?}"
    );
}

#[tokio::test]
#[ignore = "requires a reachable Hysteria v1 server"]
async fn hysteria_v1_real_udp_roundtrip() {
    let outbound = build_hysteria_outbound();
    let response = outbound
        .udp_exchange(
            &Destination::new("8.8.8.8".to_string(), 53),
            &dns_query("example.com"),
            5_000,
        )
        .await
        .expect("hysteria v1 udp exchange");

    assert!(
        !response.is_empty(),
        "real Hysteria v1 UDP should return bytes"
    );
}

fn build_hysteria_outbound() -> std::sync::Arc<dyn skyhook::outbound::Outbound> {
    let server = std::env::var("SKYHOOK_HYSTERIA_V1_SERVER").expect("SKYHOOK_HYSTERIA_V1_SERVER");
    let port = std::env::var("SKYHOOK_HYSTERIA_V1_PORT")
        .unwrap_or_else(|_| "443".to_string())
        .parse()
        .expect("SKYHOOK_HYSTERIA_V1_PORT must be a u16");
    let auth = std::env::var("SKYHOOK_HYSTERIA_V1_AUTH").ok();
    let auth_str = std::env::var("SKYHOOK_HYSTERIA_V1_AUTH_STR").ok();

    let outbounds = build_outbounds(
        &[OutboundConfig::Hysteria {
            name: "hysteria-real".to_string(),
            server: server.clone(),
            port,
            auth,
            auth_str,
            protocol: None,
            up: None,
            down: None,
            sni: Some(server),
            skip_cert_verify: true,
            obfs: std::env::var("SKYHOOK_HYSTERIA_V1_OBFS").ok(),
        }],
        None,
    )
    .expect("build hysteria outbound");
    outbounds.get("hysteria-real").expect("outbound").clone()
}

fn dns_query(domain: &str) -> Vec<u8> {
    let mut query = vec![
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    for label in domain.split('.') {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.extend_from_slice(&[0x00, 0x00, 0x01, 0x00, 0x01]);
    query
}
