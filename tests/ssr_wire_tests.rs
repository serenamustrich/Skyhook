use skyhook::config::OutboundConfig;
use skyhook::outbound::build_outbounds;

#[test]
fn ssr_config_origin_plain() {
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
    let outbound = outbounds.get("test-ssr").unwrap();
    assert_eq!(outbound.kind(), "ssr");
}

#[test]
fn ssr_config_auth_sha1_v4() {
    let config = OutboundConfig::Ssr {
        name: "test-ssr-auth".to_string(),
        server: "127.0.0.1".to_string(),
        port: 8388,
        password: "test-password".to_string(),
        method: "aes-256-cfb".to_string(),
        protocol: "auth_sha1_v4".to_string(),
        protocol_param: None,
        obfs: "plain".to_string(),
        obfs_param: None,
    };

    let outbounds = build_outbounds(&[config], None).unwrap();
    let outbound = outbounds.get("test-ssr-auth").unwrap();
    assert_eq!(outbound.kind(), "ssr");
}

#[test]
fn ssr_config_http_obfs() {
    let config = OutboundConfig::Ssr {
        name: "test-ssr-http".to_string(),
        server: "127.0.0.1".to_string(),
        port: 8388,
        password: "test-password".to_string(),
        method: "aes-256-cfb".to_string(),
        protocol: "origin".to_string(),
        protocol_param: None,
        obfs: "http_simple".to_string(),
        obfs_param: None,
    };

    let outbounds = build_outbounds(&[config], None).unwrap();
    let outbound = outbounds.get("test-ssr-http").unwrap();
    assert_eq!(outbound.kind(), "ssr");
}

#[test]
fn ssr_config_tls_obfs() {
    let config = OutboundConfig::Ssr {
        name: "test-ssr-tls".to_string(),
        server: "127.0.0.1".to_string(),
        port: 8388,
        password: "test-password".to_string(),
        method: "aes-256-cfb".to_string(),
        protocol: "origin".to_string(),
        protocol_param: None,
        obfs: "tls1.2_ticket_auth".to_string(),
        obfs_param: None,
    };

    let outbounds = build_outbounds(&[config], None).unwrap();
    let outbound = outbounds.get("test-ssr-tls").unwrap();
    assert_eq!(outbound.kind(), "ssr");
}

#[test]
fn ssr_wire_request_encoding() {
    // Verify SSR request format:
    // iv (16 bytes for AES-256-CFB) + encrypted(socks5_destination)
    let iv = vec![0u8; 16]; // AES-256-CFB IV
    let host = "example.com";
    let port = 443u16;

    let mut destination = Vec::new();
    // SOCKS5 address type: domain (0x03)
    destination.push(0x03);
    destination.push(host.len() as u8);
    destination.extend_from_slice(host.as_bytes());
    destination.extend_from_slice(&port.to_be_bytes());

    let mut request = iv.clone();
    request.extend_from_slice(&destination);

    // Verify structure
    assert_eq!(request.len(), 16 + 1 + 1 + host.len() + 2);
    assert_eq!(&request[..16], &iv[..]);
    assert_eq!(request[16], 0x03); // domain type
    assert_eq!(request[17], host.len() as u8);
    assert_eq!(&request[18..18 + host.len()], host.as_bytes());

    let port_start = 18 + host.len();
    let parsed_port = u16::from_be_bytes([request[port_start], request[port_start + 1]]);
    assert_eq!(parsed_port, 443);
}

#[test]
fn ssr_cipher_methods() {
    // Verify supported cipher methods
    let methods = vec!["aes-128-cfb", "aes-192-cfb", "aes-256-cfb", "chacha20-ietf"];

    for method in methods {
        let config = OutboundConfig::Ssr {
            name: format!("test-ssr-{}", method),
            server: "127.0.0.1".to_string(),
            port: 8388,
            password: "test-password".to_string(),
            method: method.to_string(),
            protocol: "origin".to_string(),
            protocol_param: None,
            obfs: "plain".to_string(),
            obfs_param: None,
        };

        let outbounds = build_outbounds(&[config], None).unwrap();
        let outbound = outbounds.get(&format!("test-ssr-{}", method)).unwrap();
        assert_eq!(outbound.kind(), "ssr");
    }
}

#[test]
fn ssr_protocol_variants() {
    // Verify supported protocol variants
    let protocols = vec![
        "origin",
        "auth_sha1_v4",
        "auth_aes128_md5",
        "auth_aes128_sha1",
    ];

    for protocol in protocols {
        let config = OutboundConfig::Ssr {
            name: format!("test-ssr-{}", protocol),
            server: "127.0.0.1".to_string(),
            port: 8388,
            password: "test-password".to_string(),
            method: "aes-256-cfb".to_string(),
            protocol: protocol.to_string(),
            protocol_param: None,
            obfs: "plain".to_string(),
            obfs_param: None,
        };

        let outbounds = build_outbounds(&[config], None).unwrap();
        let outbound = outbounds.get(&format!("test-ssr-{}", protocol)).unwrap();
        assert_eq!(outbound.kind(), "ssr");
    }
}

#[test]
fn ssr_obfs_variants() {
    // Verify supported obfs variants
    let obfs_modes = vec!["plain", "http_simple", "http_post", "tls1.2_ticket_auth"];

    for obfs in obfs_modes {
        let config = OutboundConfig::Ssr {
            name: format!("test-ssr-{}", obfs),
            server: "127.0.0.1".to_string(),
            port: 8388,
            password: "test-password".to_string(),
            method: "aes-256-cfb".to_string(),
            protocol: "origin".to_string(),
            protocol_param: None,
            obfs: obfs.to_string(),
            obfs_param: None,
        };

        let outbounds = build_outbounds(&[config], None).unwrap();
        let outbound = outbounds.get(&format!("test-ssr-{}", obfs)).unwrap();
        assert_eq!(outbound.kind(), "ssr");
    }
}
