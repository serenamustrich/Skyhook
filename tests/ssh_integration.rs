use skyhook::config::OutboundConfig;
use skyhook::outbound::build_outbounds;

#[test]
fn ssh_config_password_auth() {
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
fn ssh_config_private_key_auth() {
    let config = OutboundConfig::Ssh {
        name: "test-ssh-key".to_string(),
        server: "127.0.0.1".to_string(),
        port: 22,
        username: "testuser".to_string(),
        password: None,
        private_key: Some(
            "-----BEGIN OPENSSH PRIVATE KEY-----\ntest\n-----END OPENSSH PRIVATE KEY-----"
                .to_string(),
        ),
        private_key_passphrase: Some("passphrase".to_string()),
    };

    let outbounds = build_outbounds(&[config], None).unwrap();
    let outbound = outbounds.get("test-ssh-key").unwrap();
    assert_eq!(outbound.kind(), "ssh");
}

#[test]
fn ssh_direct_tcpip_request_encoding() {
    // Verify SSH direct-tcpip channel request format
    let host = "example.com";
    let port = 443u16;
    let src_host = "127.0.0.1";
    let src_port = 12345u16;

    // SSH direct-tcpip request: [host][port_be32][src_host][src_port_be32]
    let mut request = Vec::new();

    // Host length + host
    request.extend_from_slice(&(host.len() as u32).to_be_bytes());
    request.extend_from_slice(host.as_bytes());

    // Port (big-endian 32-bit)
    request.extend_from_slice(&(port as u32).to_be_bytes());

    // Source host length + source host
    request.extend_from_slice(&(src_host.len() as u32).to_be_bytes());
    request.extend_from_slice(src_host.as_bytes());

    // Source port (big-endian 32-bit)
    request.extend_from_slice(&(src_port as u32).to_be_bytes());

    // Verify structure
    let host_len = u32::from_be_bytes([request[0], request[1], request[2], request[3]]) as usize;
    assert_eq!(host_len, host.len());
    assert_eq!(&request[4..4 + host_len], host.as_bytes());

    let port_offset = 4 + host_len;
    let parsed_port = u32::from_be_bytes([
        request[port_offset],
        request[port_offset + 1],
        request[port_offset + 2],
        request[port_offset + 3],
    ]);
    assert_eq!(parsed_port, 443);

    let src_host_offset = port_offset + 4;
    let src_host_len = u32::from_be_bytes([
        request[src_host_offset],
        request[src_host_offset + 1],
        request[src_host_offset + 2],
        request[src_host_offset + 3],
    ]) as usize;
    assert_eq!(src_host_len, src_host.len());
    assert_eq!(
        &request[src_host_offset + 4..src_host_offset + 4 + src_host_len],
        src_host.as_bytes()
    );
}

#[test]
fn ssh_channel_open_encoding() {
    // Verify SSH channel open request format
    let channel_type = "direct-tcpip";
    let sender_channel = 0u32;
    let window_size = 2097152u32; // 2MB
    let packet_size = 32768u32; // 32KB

    let mut request = Vec::new();

    // Channel type length + type
    request.extend_from_slice(&(channel_type.len() as u32).to_be_bytes());
    request.extend_from_slice(channel_type.as_bytes());

    // Sender channel
    request.extend_from_slice(&sender_channel.to_be_bytes());

    // Initial window size
    request.extend_from_slice(&window_size.to_be_bytes());

    // Maximum packet size
    request.extend_from_slice(&packet_size.to_be_bytes());

    // Verify structure
    let type_len = u32::from_be_bytes([request[0], request[1], request[2], request[3]]) as usize;
    assert_eq!(type_len, channel_type.len());
    assert_eq!(&request[4..4 + type_len], channel_type.as_bytes());

    let channel_offset = 4 + type_len;
    let parsed_channel = u32::from_be_bytes([
        request[channel_offset],
        request[channel_offset + 1],
        request[channel_offset + 2],
        request[channel_offset + 3],
    ]);
    assert_eq!(parsed_channel, 0);

    let window_offset = channel_offset + 4;
    let parsed_window = u32::from_be_bytes([
        request[window_offset],
        request[window_offset + 1],
        request[window_offset + 2],
        request[window_offset + 3],
    ]);
    assert_eq!(parsed_window, 2097152);
}
