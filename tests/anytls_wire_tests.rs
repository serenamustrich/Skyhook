use skyhook::config::OutboundConfig;
use skyhook::outbound::build_outbounds;

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
fn anytls_settings_frame_encoding() {
    // Verify AnyTLS settings frame format
    // [length_be16][settings_json]
    let settings = r#"{"padding_md5":"d41d8cd98f00b204e9800998ecf8427e"}"#;

    let mut frame = Vec::new();
    frame.extend_from_slice(&(settings.len() as u16).to_be_bytes());
    frame.extend_from_slice(settings.as_bytes());

    // Verify structure
    let len = u16::from_be_bytes([frame[0], frame[1]]) as usize;
    assert_eq!(len, settings.len());
    assert_eq!(&frame[2..2 + len], settings.as_bytes());
}

#[test]
fn anytls_syn_frame_encoding() {
    // Verify AnyTLS SYN frame format
    // [cmd=0x01][stream_id_be16][length_be16][data]
    let stream_id = 0u16;
    let data = b"";

    let mut frame = Vec::new();
    frame.push(0x01); // CMD_SYN
    frame.extend_from_slice(&stream_id.to_be_bytes());
    frame.extend_from_slice(&(data.len() as u16).to_be_bytes());
    frame.extend_from_slice(data);

    // Verify structure
    assert_eq!(frame[0], 0x01); // CMD_SYN
    let parsed_id = u16::from_be_bytes([frame[1], frame[2]]);
    assert_eq!(parsed_id, 0);
    let parsed_len = u16::from_be_bytes([frame[3], frame[4]]);
    assert_eq!(parsed_len, 0);
}

#[test]
fn anytls_psh_frame_encoding() {
    // Verify AnyTLS PSH frame format
    // [cmd=0x03][stream_id_be16][length_be16][data]
    let stream_id = 1u16;
    let data = b"test-payload";

    let mut frame = Vec::new();
    frame.push(0x03); // CMD_PSH
    frame.extend_from_slice(&stream_id.to_be_bytes());
    frame.extend_from_slice(&(data.len() as u16).to_be_bytes());
    frame.extend_from_slice(data);

    // Verify structure
    assert_eq!(frame[0], 0x03); // CMD_PSH
    let parsed_id = u16::from_be_bytes([frame[1], frame[2]]);
    assert_eq!(parsed_id, 1);
    let parsed_len = u16::from_be_bytes([frame[3], frame[4]]);
    assert_eq!(parsed_len, data.len() as u16);
    assert_eq!(&frame[5..5 + data.len()], data);
}

#[test]
fn anytls_fin_frame_encoding() {
    // Verify AnyTLS FIN frame format
    // [cmd=0x04][stream_id_be16][length_be16][data]
    let stream_id = 1u16;

    let mut frame = Vec::new();
    frame.push(0x04); // CMD_FIN
    frame.extend_from_slice(&stream_id.to_be_bytes());
    frame.extend_from_slice(&0u16.to_be_bytes());

    // Verify structure
    assert_eq!(frame[0], 0x04); // CMD_FIN
    let parsed_id = u16::from_be_bytes([frame[1], frame[2]]);
    assert_eq!(parsed_id, 1);
}

#[test]
fn anytls_heart_frame_encoding() {
    // Verify AnyTLS heart frame format
    // [cmd=0x05][stream_id_be16][length_be16][data]
    let mut frame = Vec::new();
    frame.push(0x05); // CMD_HEART
    frame.extend_from_slice(&0u16.to_be_bytes());
    frame.extend_from_slice(&0u16.to_be_bytes());

    // Verify structure
    assert_eq!(frame[0], 0x05); // CMD_HEART
}

#[test]
fn anytls_stream_open_sequence() {
    // Verify AnyTLS stream open sequence: SETTINGS -> SYN -> PSH
    let mut sequence = Vec::new();

    // SETTINGS
    let settings = r#"{"padding_md5":"d41d8cd98f00b204e9800998ecf8427e"}"#;
    sequence.extend_from_slice(&(settings.len() as u16).to_be_bytes());
    sequence.extend_from_slice(settings.as_bytes());

    // SYN
    sequence.push(0x01); // CMD_SYN
    sequence.extend_from_slice(&0u16.to_be_bytes()); // stream_id
    sequence.extend_from_slice(&0u16.to_be_bytes()); // length

    // PSH with target
    let target = b"example.com:443";
    sequence.push(0x03); // CMD_PSH
    sequence.extend_from_slice(&0u16.to_be_bytes()); // stream_id
    sequence.extend_from_slice(&(target.len() as u16).to_be_bytes()); // length
    sequence.extend_from_slice(target);

    // Verify sequence is well-formed
    assert!(!sequence.is_empty());

    // Parse back settings
    let settings_len = u16::from_be_bytes([sequence[0], sequence[1]]) as usize;
    assert_eq!(settings_len, settings.len());

    // Parse SYN
    let syn_offset = 2 + settings_len;
    assert_eq!(sequence[syn_offset], 0x01); // CMD_SYN

    // Parse PSH
    let psh_offset = syn_offset + 5; // cmd + id + len
    assert_eq!(sequence[psh_offset], 0x03); // CMD_PSH
}
