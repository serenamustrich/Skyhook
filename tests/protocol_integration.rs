//! Integration tests that require real servers.
//! Run with environment variables set:
//!   SKYHOOK_HYSTERIA_V1_SERVER=x SKYHOOK_HYSTERIA_V1_PORT=x SKYHOOK_HYSTERIA_V1_AUTH=x cargo test --test protocol_integration

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
#[ignore = "requires SKYHOOK_HYSTERIA_V1_SERVER/PORT/AUTH env vars"]
async fn hysteria_v1_tcp_roundtrip() {
    let server = match std::env::var("SKYHOOK_HYSTERIA_V1_SERVER") {
        Ok(s) => s,
        Err(_) => {
            eprintln!("SKYHOOK_HYSTERIA_V1_SERVER not set, skipping");
            return;
        }
    };
    let port: u16 = std::env::var("SKYHOOK_HYSTERIA_V1_PORT")
        .unwrap_or_else(|_| "443".to_string())
        .parse()
        .unwrap();
    let auth = std::env::var("SKYHOOK_HYSTERIA_V1_AUTH").unwrap_or_default();

    use skyhook::config::OutboundConfig;
    use skyhook::outbound::build_outbounds;
    use skyhook::routing::Destination;

    let config = OutboundConfig::Hysteria {
        name: "test-hysteria".to_string(),
        server: server.clone(),
        port,
        auth: Some(auth),
        auth_str: None,
        protocol: None,
        up: None,
        down: None,
        sni: None,
        skip_cert_verify: true,
        obfs: None,
    };

    let outbounds = build_outbounds(&[config], None).unwrap();
    let outbound = outbounds.get("test-hysteria").unwrap();

    let dest = Destination::new("httpbin.org".to_string(), 80);
    let mut stream = outbound
        .connect(&dest, 5000)
        .await
        .expect("hysteria v1 tcp connect failed");

    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: httpbin.org\r\n\r\n")
        .await
        .unwrap();

    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
        .await
        .unwrap()
        .unwrap();

    assert!(n > 0, "should receive HTTP response");
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(
        response.contains("HTTP/1.1") || response.contains("HTTP/2"),
        "unexpected response: {}",
        &response[..100.min(response.len())]
    );
}

#[tokio::test]
#[ignore = "requires SKYHOOK_HYSTERIA_V1_SERVER/PORT/AUTH env vars"]
async fn hysteria_v1_udp_roundtrip() {
    let server = match std::env::var("SKYHOOK_HYSTERIA_V1_SERVER") {
        Ok(s) => s,
        Err(_) => {
            eprintln!("SKYHOOK_HYSTERIA_V1_SERVER not set, skipping");
            return;
        }
    };
    let port: u16 = std::env::var("SKYHOOK_HYSTERIA_V1_PORT")
        .unwrap_or_else(|_| "443".to_string())
        .parse()
        .unwrap();
    let auth = std::env::var("SKYHOOK_HYSTERIA_V1_AUTH").unwrap_or_default();

    use skyhook::config::OutboundConfig;
    use skyhook::outbound::build_outbounds;
    use skyhook::routing::Destination;

    let config = OutboundConfig::Hysteria {
        name: "test-hysteria".to_string(),
        server: server.clone(),
        port,
        auth: Some(auth),
        auth_str: None,
        protocol: None,
        up: None,
        down: None,
        sni: None,
        skip_cert_verify: true,
        obfs: None,
    };

    let outbounds = build_outbounds(&[config], None).unwrap();
    let outbound = outbounds.get("test-hysteria").unwrap();

    let dns_query = build_dns_query("example.com");
    let dest = Destination::new("8.8.8.8".to_string(), 53);

    let response = outbound
        .udp_exchange(&dest, &dns_query, 5000)
        .await
        .expect("hysteria v1 udp exchange failed");

    assert!(!response.is_empty(), "should receive DNS response");
}

#[tokio::test]
#[ignore = "requires SKYHOOK_OPENVPN_SERVER/PORT env vars"]
async fn openvpn_connects_to_real_server() {
    let server = match std::env::var("SKYHOOK_OPENVPN_SERVER") {
        Ok(s) => s,
        Err(_) => {
            eprintln!("SKYHOOK_OPENVPN_SERVER not set, skipping");
            return;
        }
    };
    let port: u16 = std::env::var("SKYHOOK_OPENVPN_PORT")
        .unwrap_or_else(|_| "1194".to_string())
        .parse()
        .unwrap();

    use skyhook::l3::openvpn::OpenVpnControlChannel;

    let mut channel = OpenVpnControlChannel::new(server.clone(), port);
    let result = tokio::time::timeout(Duration::from_secs(10), channel.connect()).await;

    match result {
        Ok(Ok(())) => eprintln!("OpenVPN control channel connected to {server}:{port}"),
        Ok(Err(e)) => panic!("OpenVPN connection failed: {e}"),
        Err(_) => panic!("OpenVPN connection timed out"),
    }
}

#[test]
fn openvpn_data_channel_encrypt_decrypt() {
    use skyhook::l3::openvpn::{DataCipher, OpenVpnDataChannel};

    // AES-128-GCM
    let key16 = vec![0x42u8; 16];
    let mut channel = OpenVpnDataChannel::new(DataCipher::Aes128Gcm, key16.clone(), key16).unwrap();
    let plaintext = b"test data for openvpn data channel";
    let encrypted = channel.encrypt(plaintext).unwrap();
    let decrypted = channel.decrypt(&encrypted).unwrap();
    assert_eq!(plaintext.to_vec(), decrypted);

    // AES-256-GCM
    let key32 = vec![0x42u8; 32];
    let mut channel = OpenVpnDataChannel::new(DataCipher::Aes256Gcm, key32.clone(), key32).unwrap();
    let encrypted = channel.encrypt(plaintext).unwrap();
    let decrypted = channel.decrypt(&encrypted).unwrap();
    assert_eq!(plaintext.to_vec(), decrypted);

    // ChaCha20-Poly1305
    let key32 = vec![0x42u8; 32];
    let mut channel =
        OpenVpnDataChannel::new(DataCipher::ChaCha20Poly1305, key32.clone(), key32).unwrap();
    let encrypted = channel.encrypt(plaintext).unwrap();
    let decrypted = channel.decrypt(&encrypted).unwrap();
    assert_eq!(plaintext.to_vec(), decrypted);
}

fn build_dns_query(domain: &str) -> Vec<u8> {
    let mut query = vec![
        0x00, 0x01, // Transaction ID
        0x01, 0x00, // Flags: standard query
        0x00, 0x01, // Questions: 1
        0x00, 0x00, // Answers: 0
        0x00, 0x00, // Authority: 0
        0x00, 0x00, // Additional: 0
    ];
    for label in domain.split('.') {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0x00); // Root
    query.extend_from_slice(&[0x00, 0x01]); // Type A
    query.extend_from_slice(&[0x00, 0x01]); // Class IN
    query
}
