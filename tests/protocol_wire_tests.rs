use skyhook::config::OutboundConfig;
use skyhook::outbound::build_outbounds;

#[test]
fn tuic_config_parse() {
    let config = OutboundConfig::Tuic {
        name: "test-tuic".to_string(),
        server: "127.0.0.1".to_string(),
        port: 443,
        password: "test-password".to_string(),
        uuid: "00000000-0000-0000-0000-000000000000".to_string(),
        sni: Some("example.com".to_string()),
        skip_cert_verify: false,
        congestion_control: None,
        udp_relay_mode: None,
        alpn: None,
    };

    let outbounds = build_outbounds(&[config], None).unwrap();
    let outbound = outbounds.get("test-tuic").unwrap();
    assert_eq!(outbound.kind(), "tuic");
}

#[test]
fn ssh_config_parse() {
    let config = OutboundConfig::Ssh {
        name: "test-ssh".to_string(),
        server: "127.0.0.1".to_string(),
        port: 22,
        username: "testuser".to_string(),
        password: Some("testpass".to_string()),
        private_key: None,
        private_key_passphrase: None,
    };

    let outbounds = build_outbounds(&[config], None).unwrap();
    let outbound = outbounds.get("test-ssh").unwrap();
    assert_eq!(outbound.kind(), "ssh");
}

#[test]
fn anytls_config_parse() {
    let config = OutboundConfig::AnyTls {
        name: "test-anytls".to_string(),
        server: "127.0.0.1".to_string(),
        port: 443,
        password: "test-password".to_string(),
        sni: Some("example.com".to_string()),
        skip_cert_verify: false,
        alpn: vec![],
    };

    let outbounds = build_outbounds(&[config], None).unwrap();
    let outbound = outbounds.get("test-anytls").unwrap();
    assert_eq!(outbound.kind(), "anytls");
}

#[test]
fn shadowtls_config_parse() {
    let config = OutboundConfig::ShadowTls {
        name: "test-shadowtls".to_string(),
        server: "127.0.0.1".to_string(),
        port: 443,
        password: "test-password".to_string(),
        version: Some(3),
        sni: Some("example.com".to_string()),
        skip_cert_verify: false,
    };

    let outbounds = build_outbounds(&[config], None).unwrap();
    let outbound = outbounds.get("test-shadowtls").unwrap();
    assert_eq!(outbound.kind(), "shadowtls");
}

#[test]
fn naive_config_parse() {
    let config = OutboundConfig::Naive {
        name: "test-naive".to_string(),
        server: "127.0.0.1".to_string(),
        port: 443,
        username: Some("user".to_string()),
        password: Some("pass".to_string()),
        sni: Some("example.com".to_string()),
        skip_cert_verify: false,
        alpn: vec![],
    };

    let outbounds = build_outbounds(&[config], None).unwrap();
    let outbound = outbounds.get("test-naive").unwrap();
    assert_eq!(outbound.kind(), "naive");
}
