use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

use skyhook::inbound::native_tun_dispatcher::NativeL4Dispatcher;
use skyhook::inbound::native_tun_flow::{FlowKey, FlowProtocol};
use skyhook::inbound::native_tun_metrics::NativeTunMetrics;

/// Test TCP direct echo through Native TUN dispatcher
/// Requires: real TUN interface (sudo)
#[tokio::test]
#[ignore]
async fn native_tun_tcp_direct_echo() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 1024];
        loop {
            match stream.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    stream.write_all(&buf[..n]).await.unwrap();
                }
                Err(_) => break,
            }
        }
    });

    let metrics = NativeTunMetrics::new(true, "native-l3".to_string(), true, true);
    let mut dispatcher = NativeL4Dispatcher::new(metrics);
    let runtime = create_test_runtime();

    let client_ip: std::net::Ipv4Addr = "10.0.0.1".parse().unwrap();
    let server_ip: std::net::Ipv4Addr = server_addr.ip().to_string().parse().unwrap();
    let server_port = server_addr.port();

    let flow_key = FlowKey {
        protocol: FlowProtocol::Tcp,
        src: std::net::SocketAddr::new(client_ip.into(), 12345),
        dst: std::net::SocketAddr::new(server_ip.into(), server_port),
    };

    // SYN
    let syn = build_tcp_packet(
        client_ip,
        12345,
        server_ip,
        server_port,
        &[],
        true,
        false,
        1000,
        0,
    );
    let _ = dispatcher.dispatch_packet(syn, &flow_key, &runtime).await;

    // ACK
    let ack = build_tcp_packet(
        client_ip,
        12345,
        server_ip,
        server_port,
        &[],
        false,
        true,
        1001,
        1001,
    );
    let _ = dispatcher.dispatch_packet(ack, &flow_key, &runtime).await;

    // Data
    let data = build_tcp_packet(
        client_ip,
        12345,
        server_ip,
        server_port,
        b"hello",
        false,
        true,
        1001,
        1001,
    );
    let _result = dispatcher.dispatch_packet(data, &flow_key, &runtime).await;

    // Verify session is active
    assert!(
        dispatcher.tcp_session_count() > 0,
        "TCP session should be active"
    );
}

/// Test UDP direct echo through Native TUN dispatcher
/// Requires: real TUN interface (sudo)
#[tokio::test]
#[ignore]
async fn native_tun_udp_direct_echo() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = socket.local_addr().unwrap();

    tokio::spawn(async move {
        let mut buf = vec![0u8; 1024];
        let (n, src) = socket.recv_from(&mut buf).await.unwrap();
        socket.send_to(&buf[..n], src).await.unwrap();
    });

    let metrics = NativeTunMetrics::new(true, "native-l3".to_string(), true, true);
    let mut dispatcher = NativeL4Dispatcher::new(metrics);
    let runtime = create_test_runtime();

    let client_ip: std::net::Ipv4Addr = "10.0.0.1".parse().unwrap();
    let server_ip: std::net::Ipv4Addr = server_addr.ip().to_string().parse().unwrap();

    let flow_key = FlowKey {
        protocol: FlowProtocol::Udp,
        src: std::net::SocketAddr::new(client_ip.into(), 12345),
        dst: std::net::SocketAddr::new(server_ip.into(), server_addr.port()),
    };

    let udp_packet = build_udp_packet(client_ip, 12345, server_ip, server_addr.port(), b"hello");
    let result = dispatcher
        .dispatch_packet(udp_packet, &flow_key, &runtime)
        .await;

    assert!(
        !result.egress_packets.is_empty(),
        "should have UDP echo response"
    );
}

/// Test IPv6 UDP echo through Native TUN dispatcher
/// Requires: real TUN interface with IPv6 (sudo)
#[tokio::test]
#[ignore]
async fn native_tun_ipv6_udp_echo() {
    let socket = match UdpSocket::bind("[::1]:0").await {
        Ok(socket) => socket,
        Err(_) => return,
    };
    let server_addr = socket.local_addr().unwrap();

    tokio::spawn(async move {
        let mut buf = vec![0u8; 1024];
        let (n, src) = socket.recv_from(&mut buf).await.unwrap();
        socket.send_to(&buf[..n], src).await.unwrap();
    });

    let metrics = NativeTunMetrics::new(true, "native-l3".to_string(), true, true);
    let mut dispatcher = NativeL4Dispatcher::new(metrics);
    let runtime = create_test_runtime();

    let client_ip: std::net::Ipv6Addr = "fd00::1".parse().unwrap();
    let server_ip = match server_addr.ip() {
        std::net::IpAddr::V6(ip) => ip,
        _ => return,
    };

    let flow_key = FlowKey {
        protocol: FlowProtocol::Udp,
        src: std::net::SocketAddr::new(client_ip.into(), 12345),
        dst: std::net::SocketAddr::new(server_ip.into(), server_addr.port()),
    };

    let udp_packet =
        build_ipv6_udp_packet(client_ip, 12345, server_ip, server_addr.port(), b"hello");
    let result = dispatcher
        .dispatch_packet(udp_packet, &flow_key, &runtime)
        .await;

    assert!(
        !result.egress_packets.is_empty(),
        "should have IPv6 UDP echo response"
    );
}

#[allow(clippy::too_many_arguments)]
fn build_tcp_packet(
    src_ip: std::net::Ipv4Addr,
    src_port: u16,
    dst_ip: std::net::Ipv4Addr,
    dst_port: u16,
    data: &[u8],
    syn: bool,
    ack: bool,
    seq: u32,
    ack_num: u32,
) -> Vec<u8> {
    let mut flags = 0u8;
    if syn {
        flags |= 0x02;
    }
    if ack {
        flags |= 0x10;
    }
    build_tcp_packet_raw(
        src_ip, src_port, dst_ip, dst_port, data, flags, seq, ack_num,
    )
}

#[allow(clippy::too_many_arguments)]
fn build_tcp_packet_raw(
    src_ip: std::net::Ipv4Addr,
    src_port: u16,
    dst_ip: std::net::Ipv4Addr,
    dst_port: u16,
    data: &[u8],
    flags: u8,
    seq: u32,
    ack_num: u32,
) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.push(0x45);
    packet.push(0x00);
    let total_len = (20 + 20 + data.len()) as u16;
    packet.extend_from_slice(&total_len.to_be_bytes());
    packet.extend_from_slice(&[0x00, 0x00, 0x40, 0x00, 64, 6, 0x00, 0x00]);
    packet.extend_from_slice(&src_ip.octets());
    packet.extend_from_slice(&dst_ip.octets());
    packet.extend_from_slice(&src_port.to_be_bytes());
    packet.extend_from_slice(&dst_port.to_be_bytes());
    packet.extend_from_slice(&seq.to_be_bytes());
    packet.extend_from_slice(&ack_num.to_be_bytes());
    packet.push(0x50);
    packet.push(flags);
    packet.extend_from_slice(&[0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00]);
    packet.extend_from_slice(data);
    packet
}

fn build_udp_packet(
    src_ip: std::net::Ipv4Addr,
    src_port: u16,
    dst_ip: std::net::Ipv4Addr,
    dst_port: u16,
    data: &[u8],
) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.push(0x45);
    packet.push(0x00);
    let total_len = (20 + 8 + data.len()) as u16;
    packet.extend_from_slice(&total_len.to_be_bytes());
    packet.extend_from_slice(&[0x00, 0x00, 0x40, 0x00, 64, 17, 0x00, 0x00]);
    packet.extend_from_slice(&src_ip.octets());
    packet.extend_from_slice(&dst_ip.octets());
    packet.extend_from_slice(&src_port.to_be_bytes());
    packet.extend_from_slice(&dst_port.to_be_bytes());
    let udp_len = (8 + data.len()) as u16;
    packet.extend_from_slice(&udp_len.to_be_bytes());
    packet.extend_from_slice(&[0x00, 0x00]);
    packet.extend_from_slice(data);
    packet
}

fn build_ipv6_udp_packet(
    src_ip: std::net::Ipv6Addr,
    src_port: u16,
    dst_ip: std::net::Ipv6Addr,
    dst_port: u16,
    data: &[u8],
) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.push(0x60);
    packet.extend_from_slice(&[0x00, 0x00, 0x00]);
    let payload_len = (8 + data.len()) as u16;
    packet.extend_from_slice(&payload_len.to_be_bytes());
    packet.push(17); // UDP
    packet.push(64); // hop limit
    packet.extend_from_slice(&src_ip.octets());
    packet.extend_from_slice(&dst_ip.octets());
    packet.extend_from_slice(&src_port.to_be_bytes());
    packet.extend_from_slice(&dst_port.to_be_bytes());
    packet.extend_from_slice(&payload_len.to_be_bytes());
    packet.extend_from_slice(&[0x00, 0x00]);
    packet.extend_from_slice(data);
    packet
}

fn create_test_runtime() -> std::sync::Arc<skyhook::core::Runtime> {
    use skyhook::config::SuperConfig;
    std::sync::Arc::new(skyhook::core::Runtime::new(SuperConfig::default()).unwrap())
}
