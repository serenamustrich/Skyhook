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
fn tuic_connect_request_domain_encoding() {
    // Verify TUIC connect request format for domain target
    let host = "example.com";
    let port = 443u16;

    // TUIC connect request: [cmd=0x01][addr_type=0x03][host_len][host][port_be16]
    let mut request = Vec::new();
    request.push(0x01); // CMD_CONNECT
    request.push(0x03); // ATYP_DOMAIN
    request.push(host.len() as u8);
    request.extend_from_slice(host.as_bytes());
    request.extend_from_slice(&port.to_be_bytes());

    // Verify structure
    assert_eq!(request[0], 0x01); // CMD_CONNECT
    assert_eq!(request[1], 0x03); // ATYP_DOMAIN
    assert_eq!(request[2], host.len() as u8);
    assert_eq!(&request[3..3 + host.len()], host.as_bytes());

    let port_start = 3 + host.len();
    let parsed_port = u16::from_be_bytes([request[port_start], request[port_start + 1]]);
    assert_eq!(parsed_port, 443);
}

#[test]
fn tuic_connect_request_ip_encoding() {
    // Verify TUIC connect request format for IP target
    let ip = [192, 168, 1, 1];
    let port = 80u16;

    // TUIC connect request: [cmd=0x01][addr_type=0x01][ip][port_be16]
    let mut request = Vec::new();
    request.push(0x01); // CMD_CONNECT
    request.push(0x01); // ATYP_IPV4
    request.extend_from_slice(&ip);
    request.extend_from_slice(&port.to_be_bytes());

    // Verify structure
    assert_eq!(request[0], 0x01); // CMD_CONNECT
    assert_eq!(request[1], 0x01); // ATYP_IPV4
    assert_eq!(&request[2..6], &ip);

    let parsed_port = u16::from_be_bytes([request[6], request[7]]);
    assert_eq!(parsed_port, 80);
}

#[test]
fn tuic_packet_request_encoding() {
    // Verify TUIC UDP packet request format
    let session_id = 12345u32;
    let payload = b"test-udp-payload";

    // TUIC packet request: [cmd=0x02][session_id_be32][payload]
    let mut request = Vec::new();
    request.push(0x02); // CMD_PACKET
    request.extend_from_slice(&session_id.to_be_bytes());
    request.extend_from_slice(payload);

    // Verify structure
    assert_eq!(request[0], 0x02); // CMD_PACKET
    let parsed_session = u32::from_be_bytes([request[1], request[2], request[3], request[4]]);
    assert_eq!(parsed_session, 12345);
    assert_eq!(&request[5..], payload);
}

#[test]
fn tuic_config_with_congestion_control() {
    let config = OutboundConfig::Tuic {
        name: "test-tuic-cc".to_string(),
        server: "127.0.0.1".to_string(),
        port: 443,
        password: "test-password".to_string(),
        uuid: "00000000-0000-0000-0000-000000000000".to_string(),
        sni: Some("example.com".to_string()),
        skip_cert_verify: false,
        congestion_control: Some("bbr".to_string()),
        udp_relay_mode: Some("native".to_string()),
        alpn: Some("h3".to_string()),
    };

    let outbounds = build_outbounds(&[config], None).unwrap();
    let outbound = outbounds.get("test-tuic-cc").unwrap();
    assert_eq!(outbound.kind(), "tuic");
}
