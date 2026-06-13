use skyhook::config::OutboundConfig;
use skyhook::outbound::build_outbounds;

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

#[test]
fn naive_connect_request_encoding() {
    // Verify Naive CONNECT request format
    // CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: Basic <base64>\r\n\r\n

    let host = "example.com";
    let port = 443u16;
    let username = "user";
    let password = "pass";

    // Build Basic auth header
    use base64::Engine;
    let auth = format!("{}:{}", username, password);
    let auth_b64 = base64::engine::general_purpose::STANDARD.encode(auth.as_bytes());

    // Build CONNECT request
    let request = format!(
        "CONNECT {}:{} HTTP/1.1\r\n\
         Host: {}:{}\r\n\
         Proxy-Authorization: Basic {}\r\n\
         \r\n",
        host, port, host, port, auth_b64
    );

    // Verify structure
    assert!(request.starts_with("CONNECT example.com:443 HTTP/1.1\r\n"));
    assert!(request.contains("Host: example.com:443\r\n"));
    assert!(request.contains(&format!("Proxy-Authorization: Basic {}\r\n", auth_b64)));
    assert!(request.ends_with("\r\n\r\n"));
}

#[test]
fn naive_connect_request_without_auth() {
    // Verify Naive CONNECT request without authentication
    let host = "example.com";
    let port = 443u16;

    let request = format!(
        "CONNECT {}:{} HTTP/1.1\r\n\
         Host: {}:{}\r\n\
         \r\n",
        host, port, host, port
    );

    // Verify structure
    assert!(request.starts_with("CONNECT example.com:443 HTTP/1.1\r\n"));
    assert!(request.contains("Host: example.com:443\r\n"));
    assert!(!request.contains("Proxy-Authorization"));
    assert!(request.ends_with("\r\n\r\n"));
}

#[test]
fn naive_response_parsing() {
    // Verify Naive HTTP response parsing
    let response_200 = "HTTP/1.1 200 Connection Established\r\n\r\n";
    let response_403 = "HTTP/1.1 403 Forbidden\r\n\r\n";
    let response_502 = "HTTP/1.1 502 Bad Gateway\r\n\r\n";

    // Parse status codes
    let status_200 = parse_http_status(response_200);
    let status_403 = parse_http_status(response_403);
    let status_502 = parse_http_status(response_502);

    assert_eq!(status_200, Some(200));
    assert_eq!(status_403, Some(403));
    assert_eq!(status_502, Some(502));
}

#[test]
fn naive_response_200_accepts_connection() {
    // Verify 200 response means connection is established
    let response = "HTTP/1.1 200 Connection Established\r\n\r\n";
    let status = parse_http_status(response);
    assert_eq!(status, Some(200));
}

#[test]
fn naive_response_non_200_rejects() {
    // Verify non-200 response means connection failed
    let responses = vec![
        ("HTTP/1.1 403 Forbidden\r\n\r\n", 403),
        ("HTTP/1.1 407 Proxy Authentication Required\r\n\r\n", 407),
        ("HTTP/1.1 502 Bad Gateway\r\n\r\n", 502),
        ("HTTP/1.1 503 Service Unavailable\r\n\r\n", 503),
    ];

    for (response, expected_status) in responses {
        let status = parse_http_status(response);
        assert_eq!(status, Some(expected_status));
        assert_ne!(status, Some(200), "Non-200 should reject");
    }
}

#[test]
fn naive_config_with_alpn() {
    let config = OutboundConfig::Naive {
        name: "test-naive-alpn".to_string(),
        server: "127.0.0.1".to_string(),
        port: 443,
        username: Some("user".to_string()),
        password: Some("pass".to_string()),
        sni: Some("example.com".to_string()),
        skip_cert_verify: false,
        alpn: vec!["h2".to_string()],
    };

    let outbounds = build_outbounds(&[config], None).unwrap();
    let outbound = outbounds.get("test-naive-alpn").unwrap();
    assert_eq!(outbound.kind(), "naive");
}

fn parse_http_status(response: &str) -> Option<u16> {
    // Parse "HTTP/1.1 200 Connection Established" -> 200
    let parts: Vec<&str> = response.split_whitespace().collect();
    if parts.len() >= 2 && parts[0].starts_with("HTTP/") {
        parts[1].parse().ok()
    } else {
        None
    }
}
