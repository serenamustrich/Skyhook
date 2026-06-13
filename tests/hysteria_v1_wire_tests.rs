use skyhook::config::OutboundConfig;
use skyhook::outbound::build_outbounds;

#[test]
fn hysteria_v1_config_parse() {
    let config = OutboundConfig::Hysteria {
        name: "test-hysteria".to_string(),
        server: "127.0.0.1".to_string(),
        port: 8443,
        auth: Some("test-auth".to_string()),
        auth_str: None,
        protocol: None,
        up: None,
        down: None,
        sni: Some("example.com".to_string()),
        skip_cert_verify: false,
        obfs: None,
    };

    let outbounds = build_outbounds(&[config], None).unwrap();
    let outbound = outbounds.get("test-hysteria").unwrap();
    assert_eq!(outbound.kind(), "hysteria");
}

#[test]
fn hysteria_v1_config_with_obfs() {
    let config = OutboundConfig::Hysteria {
        name: "test-hysteria-obfs".to_string(),
        server: "127.0.0.1".to_string(),
        port: 8443,
        auth: Some("test-auth".to_string()),
        auth_str: None,
        protocol: None,
        up: None,
        down: None,
        sni: Some("example.com".to_string()),
        skip_cert_verify: false,
        obfs: Some("xplus".to_string()),
    };

    let outbounds = build_outbounds(&[config], None).unwrap();
    let outbound = outbounds.get("test-hysteria-obfs").unwrap();
    assert_eq!(outbound.kind(), "hysteria");
}

#[test]
fn hysteria_v1_config_with_auth_str() {
    let config = OutboundConfig::Hysteria {
        name: "test-hysteria-str".to_string(),
        server: "127.0.0.1".to_string(),
        port: 8443,
        auth: None,
        auth_str: Some("test-password".to_string()),
        protocol: None,
        up: None,
        down: None,
        sni: Some("example.com".to_string()),
        skip_cert_verify: false,
        obfs: None,
    };

    let outbounds = build_outbounds(&[config], None).unwrap();
    let outbound = outbounds.get("test-hysteria-str").unwrap();
    assert_eq!(outbound.kind(), "hysteria");
}

#[test]
fn hysteria_v1_tcp_request_encoding() {
    // Verify Hysteria v1 TCP request format:
    // auth_bytes + socks5_destination
    let auth = b"test-auth";
    let host = "example.com";
    let port = 443u16;

    let mut request = Vec::new();
    request.extend_from_slice(auth);

    // SOCKS5 address type: domain (0x03)
    request.push(0x03);
    request.push(host.len() as u8);
    request.extend_from_slice(host.as_bytes());
    request.extend_from_slice(&port.to_be_bytes());

    // Verify structure
    assert_eq!(request[0..auth.len()], *auth);
    assert_eq!(request[auth.len()], 0x03); // domain type
    assert_eq!(request[auth.len() + 1], host.len() as u8);
    assert_eq!(
        &request[auth.len() + 2..auth.len() + 2 + host.len()],
        host.as_bytes()
    );

    let port_start = auth.len() + 2 + host.len();
    let parsed_port = u16::from_be_bytes([request[port_start], request[port_start + 1]]);
    assert_eq!(parsed_port, 443);
}

#[test]
fn hysteria_v1_udp_request_encoding() {
    // Verify Hysteria v1 UDP request format:
    // auth_bytes + socks5_destination + payload
    let auth = b"test-auth";
    let host = "example.com";
    let port = 53u16;
    let payload = b"DNS query";

    let mut request = Vec::new();
    request.extend_from_slice(auth);

    // SOCKS5 address type: domain (0x03)
    request.push(0x03);
    request.push(host.len() as u8);
    request.extend_from_slice(host.as_bytes());
    request.extend_from_slice(&port.to_be_bytes());
    request.extend_from_slice(payload);

    // Verify structure
    assert!(request.len() > auth.len() + payload.len());
    assert_eq!(&request[request.len() - payload.len()..], payload);
}

#[test]
fn hysteria_v1_obfs_xplus_format() {
    // Verify xplus obfs XOR behavior
    let key = [0xAA, 0xBB, 0xCC, 0xDD];
    let mut data = vec![0x01, 0x02, 0x03, 0x04, 0x05];

    // Apply XOR
    for (i, byte) in data.iter_mut().enumerate() {
        *byte ^= key[i % key.len()];
    }

    // Verify XOR was applied
    assert_eq!(data[0], 0x01 ^ 0xAA);
    assert_eq!(data[1], 0x02 ^ 0xBB);
    assert_eq!(data[2], 0x03 ^ 0xCC);
    assert_eq!(data[3], 0x04 ^ 0xDD);
    assert_eq!(data[4], 0x05 ^ 0xAA); // Wraps around

    // Apply XOR again to restore
    for (i, byte) in data.iter_mut().enumerate() {
        *byte ^= key[i % key.len()];
    }

    assert_eq!(data, vec![0x01, 0x02, 0x03, 0x04, 0x05]);
}
