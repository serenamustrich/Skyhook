use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use skyhook::config::OutboundConfig;
use skyhook::outbound::build_outbounds;
use skyhook::routing::Destination;

#[tokio::test]
async fn direct_tcp_echo() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 1024];
        loop {
            match stream.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    stream.write_all(&buf[..n]).await.unwrap();
                }
                Err(_) => break,
            }
        }
    });

    let config = OutboundConfig::Direct {
        name: "direct".to_string(),
    };

    let outbounds = build_outbounds(&[config], None).unwrap();
    let outbound = outbounds.get("direct").unwrap();
    let dest = Destination::new(server_addr.ip().to_string(), server_addr.port());

    let mut stream = tokio::time::timeout(Duration::from_secs(5), outbound.connect(&dest, 5000))
        .await
        .expect("direct connect should not timeout")
        .expect("direct connect should succeed");

    stream.write_all(b"hello").await.unwrap();
    let mut buf = vec![0u8; 1024];
    let n = stream.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"hello", "echo should return same data");
}

#[tokio::test]
async fn shadowsocks_aead_config_parse() {
    let config = OutboundConfig::Shadowsocks {
        name: "test-ss".to_string(),
        server: "127.0.0.1".to_string(),
        port: 8388,
        password: "test-password".to_string(),
        method: "aes-256-gcm".to_string(),
        plugin: None,
    };

    let outbounds = build_outbounds(&[config], None).unwrap();
    assert!(outbounds.contains_key("test-ss"));
    assert_eq!(outbounds.get("test-ss").unwrap().kind(), "shadowsocks");
}

#[tokio::test]
async fn socks5_config_parse() {
    let config = OutboundConfig::Socks5 {
        name: "test-socks5".to_string(),
        server: "127.0.0.1".to_string(),
        port: 1080,
        username: None,
        password: None,
    };

    let outbounds = build_outbounds(&[config], None).unwrap();
    assert!(outbounds.contains_key("test-socks5"));
    assert_eq!(outbounds.get("test-socks5").unwrap().kind(), "socks5");
}

#[tokio::test]
async fn trojan_config_parse() {
    let config = OutboundConfig::Trojan {
        name: "test-trojan".to_string(),
        server: "127.0.0.1".to_string(),
        port: 443,
        password: "test-password".to_string(),
        sni: Some("example.com".to_string()),
        skip_cert_verify: false,
    };

    let outbounds = build_outbounds(&[config], None).unwrap();
    assert!(outbounds.contains_key("test-trojan"));
    assert_eq!(outbounds.get("test-trojan").unwrap().kind(), "trojan");
}

#[tokio::test]
async fn vmess_config_parse() {
    let config = OutboundConfig::Vmess {
        name: "test-vmess".to_string(),
        server: "127.0.0.1".to_string(),
        port: 443,
        uuid: "00000000-0000-0000-0000-000000000000".to_string(),
        cipher: "auto".to_string(),
        tls: false,
        sni: None,
        skip_cert_verify: false,
        network: None,
        ws_path: None,
        ws_host: None,
        grpc_service_name: None,
    };

    let outbounds = build_outbounds(&[config], None).unwrap();
    assert!(outbounds.contains_key("test-vmess"));
    assert_eq!(outbounds.get("test-vmess").unwrap().kind(), "vmess");
}

#[tokio::test]
async fn hysteria2_config_parse() {
    let config = OutboundConfig::Hysteria2 {
        name: "test-hysteria2".to_string(),
        server: "127.0.0.1".to_string(),
        port: 443,
        password: "test-password".to_string(),
        sni: Some("example.com".to_string()),
        skip_cert_verify: false,
        obfs: None,
        obfs_password: None,
        alpn: None,
    };

    let outbounds = build_outbounds(&[config], None).unwrap();
    assert!(outbounds.contains_key("test-hysteria2"));
    assert_eq!(outbounds.get("test-hysteria2").unwrap().kind(), "hysteria2");
}

#[tokio::test]
async fn ssr_config_parse() {
    let config = OutboundConfig::Ssr {
        name: "test-ssr".to_string(),
        server: "127.0.0.1".to_string(),
        port: 8388,
        password: "test-password".to_string(),
        method: "aes-256-cfb".to_string(),
        protocol: "origin".to_string(),
        protocol_param: None,
        obfs: "plain".to_string(),
        obfs_param: None,
    };

    let outbounds = build_outbounds(&[config], None).unwrap();
    assert!(outbounds.contains_key("test-ssr"));
    assert_eq!(outbounds.get("test-ssr").unwrap().kind(), "ssr");
}
