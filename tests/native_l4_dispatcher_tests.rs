use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

use skyhook::inbound::native_tun_dispatcher::NativeL4Dispatcher;
use skyhook::inbound::native_tun_flow::{FlowKey, FlowProtocol};
use skyhook::inbound::native_tun_metrics::NativeTunMetrics;
use skyhook::inbound::native_tun_packet::{parse_ip_packet, parse_udp_datagram, TunIpPacket};

#[tokio::test(flavor = "multi_thread")]
async fn dispatcher_tcp_syn_returns_syn_ack() {
    let metrics = NativeTunMetrics::new(true, "native-l3".to_string(), true, true);
    let mut dispatcher = NativeL4Dispatcher::new(metrics);
    let runtime = create_test_runtime();

    let client_ip: std::net::Ipv4Addr = "10.0.0.1".parse().unwrap();
    let server_ip: std::net::Ipv4Addr = "192.168.1.1".parse().unwrap();

    let syn = build_tcp_packet(client_ip, 12345, server_ip, 80, &[], true, false, 1000, 0);

    let flow_key = FlowKey {
        protocol: FlowProtocol::Tcp,
        src: std::net::SocketAddr::new(client_ip.into(), 12345),
        dst: std::net::SocketAddr::new(server_ip.into(), 80),
    };

    let result = dispatcher.dispatch_packet(syn, &flow_key, &runtime).await;

    assert!(
        !result.egress_packets.is_empty(),
        "should have SYN-ACK response"
    );

    let syn_ack = &result.egress_packets[0];
    assert_eq!(syn_ack[33] & 0x12, 0x12, "should be SYN-ACK");
    assert_ipv4_tcp_checksums_valid(syn_ack);
}

#[tokio::test(flavor = "multi_thread")]
async fn dispatcher_tcp_ack_triggers_connect() {
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

    // Data - send "hello"
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
    let result = dispatcher.dispatch_packet(data, &flow_key, &runtime).await;

    // The first dispatch after data may contain ACK, echo comes in next poll
    // Just verify session is still active and we got some response
    assert!(!result.egress_packets.is_empty());
    assert!(
        dispatcher.tcp_session_count() > 0,
        "TCP session should be active"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn dispatcher_udp_direct_echo() {
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

    let response = &result.egress_packets[0];
    match parse_ip_packet(response).unwrap() {
        TunIpPacket::Ipv4(ipv4) => {
            assert_eq!(ipv4.source, server_ip);
            assert_eq!(ipv4.destination, client_ip);
            let udp = parse_udp_datagram(&ipv4.payload).unwrap();
            assert_eq!(udp.payload, b"hello");
        }
        _ => panic!("expected IPv4 UDP response"),
    }
}

#[tokio::test]
async fn dispatcher_classify_packet() {
    let tcp = build_tcp_packet(
        "10.0.0.1".parse().unwrap(),
        12345,
        "192.168.1.1".parse().unwrap(),
        80,
        &[],
        true,
        false,
        1000,
        0,
    );
    assert_eq!(
        NativeL4Dispatcher::classify_packet(&tcp),
        Some(FlowProtocol::Tcp)
    );

    let udp = build_udp_packet(
        "10.0.0.1".parse().unwrap(),
        12345,
        "192.168.1.1".parse().unwrap(),
        53,
        b"dns query",
    );
    assert_eq!(
        NativeL4Dispatcher::classify_packet(&udp),
        Some(FlowProtocol::Udp)
    );
}

#[tokio::test]
async fn dispatcher_is_tcp_packet() {
    let tcp = build_tcp_packet(
        "10.0.0.1".parse().unwrap(),
        12345,
        "192.168.1.1".parse().unwrap(),
        80,
        &[],
        true,
        false,
        1000,
        0,
    );
    assert!(NativeL4Dispatcher::is_tcp_packet(&tcp));

    let udp = build_udp_packet(
        "10.0.0.1".parse().unwrap(),
        12345,
        "192.168.1.1".parse().unwrap(),
        53,
        b"dns query",
    );
    assert!(!NativeL4Dispatcher::is_tcp_packet(&udp));
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

fn create_test_runtime() -> std::sync::Arc<skyhook::core::Runtime> {
    use skyhook::config::SuperConfig;
    std::sync::Arc::new(skyhook::core::Runtime::new(SuperConfig::default()).unwrap())
}

fn assert_ipv4_tcp_checksums_valid(packet: &[u8]) {
    assert!(
        packet.len() >= 40,
        "IPv4 TCP packet should be at least 40 bytes"
    );
    assert_eq!(packet[0] >> 4, 4, "expected IPv4 packet");
    assert_eq!(packet[9], 6, "expected TCP protocol");

    assert_eq!(
        ones_complement_checksum(&packet[..20]),
        0,
        "IPv4 header checksum should validate"
    );

    let src = [packet[12], packet[13], packet[14], packet[15]];
    let dst = [packet[16], packet[17], packet[18], packet[19]];
    let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    let tcp_segment = &packet[20..total_len];
    let mut pseudo = Vec::with_capacity(12 + tcp_segment.len() + 1);
    pseudo.extend_from_slice(&src);
    pseudo.extend_from_slice(&dst);
    pseudo.push(0);
    pseudo.push(6);
    pseudo.extend_from_slice(&(tcp_segment.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(tcp_segment);
    if pseudo.len() % 2 != 0 {
        pseudo.push(0);
    }

    assert_eq!(
        ones_complement_checksum(&pseudo),
        0,
        "TCP checksum should validate"
    );
}

fn ones_complement_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in data.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]]) as u32
        } else {
            (chunk[0] as u32) << 8
        };
        sum = sum.wrapping_add(word);
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}
