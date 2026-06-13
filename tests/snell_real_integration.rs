//! Env-gated Snell real-server tests.

use std::time::Duration;

use skyhook::{config::OutboundConfig, outbound::build_outbounds, routing::Destination};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
#[ignore = "requires a reachable Snell server"]
async fn snell_real_tcp_roundtrip() {
    let outbound = build_snell_outbound();
    let mut stream = outbound
        .connect(&Destination::new("httpbin.org".to_string(), 80), 5_000)
        .await
        .expect("snell tcp connect");

    stream
        .write_all(b"GET /status/204 HTTP/1.1\r\nHost: httpbin.org\r\nConnection: close\r\n\r\n")
        .await
        .expect("write http request");

    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(Duration::from_secs(8), stream.read(&mut buf))
        .await
        .expect("snell read timeout")
        .expect("snell read");
    assert!(n > 0, "real Snell TCP should return bytes");
}

fn build_snell_outbound() -> std::sync::Arc<dyn skyhook::outbound::Outbound> {
    let server = std::env::var("SKYHOOK_SNELL_SERVER").expect("SKYHOOK_SNELL_SERVER");
    let port = std::env::var("SKYHOOK_SNELL_PORT")
        .unwrap_or_else(|_| "8388".to_string())
        .parse()
        .expect("SKYHOOK_SNELL_PORT must be a u16");
    let psk = std::env::var("SKYHOOK_SNELL_PSK").expect("SKYHOOK_SNELL_PSK");
    let outbounds = build_outbounds(
        &[OutboundConfig::Snell {
            name: "snell-real".to_string(),
            server,
            port,
            psk,
            method: std::env::var("SKYHOOK_SNELL_METHOD").ok(),
            version: std::env::var("SKYHOOK_SNELL_VERSION")
                .ok()
                .and_then(|value| value.parse().ok())
                .or(Some(3)),
            obfs: std::env::var("SKYHOOK_SNELL_OBFS").ok(),
            obfs_host: std::env::var("SKYHOOK_SNELL_OBFS_HOST").ok(),
        }],
        None,
    )
    .expect("build snell outbound");
    outbounds.get("snell-real").expect("outbound").clone()
}
