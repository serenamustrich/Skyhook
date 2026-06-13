//! Env-gated SSR real-server tests.

use std::time::Duration;

use skyhook::{config::OutboundConfig, outbound::build_outbounds, routing::Destination};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
#[ignore = "requires a reachable SSR server"]
async fn ssr_real_tcp_roundtrip() {
    let outbound = build_ssr_outbound();
    let mut stream = outbound
        .connect(&Destination::new("httpbin.org".to_string(), 80), 5_000)
        .await
        .expect("ssr tcp connect");

    stream
        .write_all(b"GET /status/204 HTTP/1.1\r\nHost: httpbin.org\r\nConnection: close\r\n\r\n")
        .await
        .expect("write http request");

    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(Duration::from_secs(8), stream.read(&mut buf))
        .await
        .expect("ssr read timeout")
        .expect("ssr read");
    assert!(n > 0, "real SSR TCP should return bytes");
}

fn build_ssr_outbound() -> std::sync::Arc<dyn skyhook::outbound::Outbound> {
    let server = std::env::var("SKYHOOK_SSR_SERVER").expect("SKYHOOK_SSR_SERVER");
    let port = std::env::var("SKYHOOK_SSR_PORT")
        .unwrap_or_else(|_| "8388".to_string())
        .parse()
        .expect("SKYHOOK_SSR_PORT must be a u16");
    let password = std::env::var("SKYHOOK_SSR_PASSWORD").expect("SKYHOOK_SSR_PASSWORD");
    let outbounds = build_outbounds(
        &[OutboundConfig::Ssr {
            name: "ssr-real".to_string(),
            server,
            port,
            password,
            method: std::env::var("SKYHOOK_SSR_METHOD")
                .unwrap_or_else(|_| "aes-256-cfb".to_string()),
            protocol: std::env::var("SKYHOOK_SSR_PROTOCOL")
                .unwrap_or_else(|_| "origin".to_string()),
            protocol_param: std::env::var("SKYHOOK_SSR_PROTOCOL_PARAM").ok(),
            obfs: std::env::var("SKYHOOK_SSR_OBFS").unwrap_or_else(|_| "plain".to_string()),
            obfs_param: std::env::var("SKYHOOK_SSR_OBFS_PARAM").ok(),
        }],
        None,
    )
    .expect("build ssr outbound");
    outbounds.get("ssr-real").expect("outbound").clone()
}
