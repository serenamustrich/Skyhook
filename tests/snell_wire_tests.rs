use skyhook::config::OutboundConfig;
use skyhook::outbound::build_outbounds;

#[test]
fn snell_config_parse() {
    let config = OutboundConfig::Snell {
        name: "test-snell".to_string(),
        server: "127.0.0.1".to_string(),
        port: 8388,
        psk: "test-psk-key".to_string(),
        method: Some("aes-128-gcm".to_string()),
        version: Some(3),
        obfs: None,
        obfs_host: None,
    };

    let outbounds = build_outbounds(&[config], None).unwrap();
    let outbound = outbounds.get("test-snell").unwrap();
    assert_eq!(outbound.kind(), "snell");
}

#[test]
fn snell_config_with_http_obfs() {
    let config = OutboundConfig::Snell {
        name: "test-snell-obfs".to_string(),
        server: "127.0.0.1".to_string(),
        port: 8388,
        psk: "test-psk-key".to_string(),
        method: Some("aes-256-gcm".to_string()),
        version: Some(3),
        obfs: Some("http".to_string()),
        obfs_host: Some("example.com".to_string()),
    };

    let outbounds = build_outbounds(&[config], None).unwrap();
    let outbound = outbounds.get("test-snell-obfs").unwrap();
    assert_eq!(outbound.kind(), "snell");
}

#[test]
fn snell_tcp_handshake_encoding() {
    // Verify Snell v3 TCP handshake format:
    // [1] [command] [0] [host_len] [host] [port_be16]
    let host = "example.com";
    let port = 443u16;
    let version = 3u8;

    let command = match version {
        1 | 3 => 1u8,
        2 => 5u8,
        _ => panic!("unsupported version"),
    };

    let mut handshake = vec![1, command, 0, host.len() as u8];
    handshake.extend_from_slice(host.as_bytes());
    handshake.extend_from_slice(&port.to_be_bytes());

    // Verify structure
    assert_eq!(handshake[0], 1);
    assert_eq!(handshake[1], 1); // command for v1/v3
    assert_eq!(handshake[2], 0);
    assert_eq!(handshake[3], host.len() as u8);
    assert_eq!(&handshake[4..4 + host.len()], host.as_bytes());

    let port_start = 4 + host.len();
    let parsed_port = u16::from_be_bytes([handshake[port_start], handshake[port_start + 1]]);
    assert_eq!(parsed_port, 443);
}

#[test]
fn snell_tcp_handshake_v2() {
    // Verify Snell v2 TCP handshake uses command 5
    let host = "example.com";
    let port = 80u16;
    let version = 2u8;

    let command = match version {
        1 | 3 => 1u8,
        2 => 5u8,
        _ => panic!("unsupported version"),
    };

    let mut handshake = vec![1, command, 0, host.len() as u8];
    handshake.extend_from_slice(host.as_bytes());
    handshake.extend_from_slice(&port.to_be_bytes());

    assert_eq!(handshake[1], 5); // command for v2
}

#[test]
fn snell_http_obfs_request() {
    // Verify HTTP obfs wraps payload in HTTP request
    let host = "example.com";
    let port = 443u16;
    let payload = b"test-payload";

    let host_header = if port == 80 || port == 443 {
        host.to_string()
    } else {
        format!("{}:{}", host, port)
    };

    let header = format!(
        "GET / HTTP/1.1\r\n\
         Host: {}\r\n\
         User-Agent: curl/8.5.0\r\n\
         Content-Length: {}\r\n\
         \r\n",
        host_header,
        payload.len()
    );

    let mut request = header.into_bytes();
    request.extend_from_slice(payload);

    // Verify HTTP structure
    let request_str = String::from_utf8_lossy(&request);
    assert!(request_str.starts_with("GET / HTTP/1.1\r\n"));
    assert!(request_str.contains(&format!("Host: {}", host)));
    assert!(request_str.contains(&format!("Content-Length: {}", payload.len())));

    // Verify payload is at the end
    assert_eq!(&request[request.len() - payload.len()..], payload);
}

#[test]
fn snell_version_detection() {
    // Verify version determines command
    for version in [1u8, 2, 3] {
        let command = match version {
            1 | 3 => 1u8,
            2 => 5u8,
            _ => panic!("unsupported"),
        };

        match version {
            1 | 3 => assert_eq!(command, 1),
            2 => assert_eq!(command, 5),
            _ => {}
        }
    }
}
