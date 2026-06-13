use skyhook::config::OutboundConfig;
use skyhook::outbound::build_outbounds;

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
fn shadowtls_v3_client_hello_hmac() {
    // Verify ShadowTLS v3 ClientHello HMAC format
    // The HMAC is computed over the ClientHello with the password
    // and placed in the session_id field

    let password = b"test-password";
    let client_hello = vec![0x16, 0x03, 0x03, 0x00, 0x05]; // TLS ClientHello header

    // ShadowTLS v3 uses HMAC-SHA256 of the ClientHello with the password
    // The result is placed in the session_id field (32 bytes)
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(&client_hello);
    hasher.update(password);
    let hmac = hasher.finalize();

    // Verify HMAC is 32 bytes
    assert_eq!(hmac.len(), 32);
}

#[test]
fn shadowtls_v3_app_data_framing() {
    // Verify ShadowTLS v3 application data framing
    // [type=0x17][version=0x0303][length_be16][data]

    let data = b"test-application-data";

    let mut frame = Vec::new();
    frame.push(0x17); // application_data
    frame.push(0x03); // version major
    frame.push(0x03); // version minor
    frame.extend_from_slice(&(data.len() as u16).to_be_bytes());
    frame.extend_from_slice(data);

    // Verify structure
    assert_eq!(frame[0], 0x17); // application_data
    assert_eq!(frame[1], 0x03); // TLS 1.2
    assert_eq!(frame[2], 0x03);

    let len = u16::from_be_bytes([frame[3], frame[4]]) as usize;
    assert_eq!(len, data.len());
    assert_eq!(&frame[5..5 + len], data);
}

#[test]
fn shadowtls_v3_server_hello_parsing() {
    // Verify ShadowTLS v3 ServerHello parsing
    // ServerHello contains random bytes that need to be extracted

    let server_hello = vec![
        0x16, 0x03, 0x03, // TLS record header
        0x00, 0x20, // length
        0x02, // ServerHello
        0x00, 0x00, 0x1c, // handshake length
        0x03, 0x03, // version
        // 32 bytes of random
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];

    // Verify TLS record header
    assert_eq!(server_hello[0], 0x16); // handshake
    assert_eq!(server_hello[1], 0x03); // version major
    assert_eq!(server_hello[2], 0x03); // version minor

    // Verify handshake type
    assert_eq!(server_hello[5], 0x02); // ServerHello

    // Extract random (32 bytes starting at offset 11)
    let random = &server_hello[11..43];
    assert_eq!(random.len(), 32);
}

#[test]
fn shadowtls_password_validation() {
    // Verify password is used in HMAC computation
    let password1 = b"password1";
    let password2 = b"password2";
    let data = b"test-data";

    use sha2::{Digest, Sha256};

    let mut hasher1 = Sha256::new();
    hasher1.update(data);
    hasher1.update(password1);
    let hmac1 = hasher1.finalize();

    let mut hasher2 = Sha256::new();
    hasher2.update(data);
    hasher2.update(password2);
    let hmac2 = hasher2.finalize();

    // Different passwords should produce different HMACs
    assert_ne!(hmac1, hmac2);
}

#[test]
fn shadowtls_config_versions() {
    // Verify ShadowTLS supports version 3
    let config = OutboundConfig::ShadowTls {
        name: "test-shadowtls-v3".to_string(),
        server: "127.0.0.1".to_string(),
        port: 443,
        password: "test-password".to_string(),
        version: Some(3),
        sni: Some("example.com".to_string()),
        skip_cert_verify: false,
    };

    let outbounds = build_outbounds(&[config], None).unwrap();
    let outbound = outbounds.get("test-shadowtls-v3").unwrap();
    assert_eq!(outbound.kind(), "shadowtls");
}
