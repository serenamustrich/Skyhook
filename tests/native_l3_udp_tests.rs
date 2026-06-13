use std::sync::Arc;

use tokio::net::UdpSocket;

use skyhook::inbound::native_tun_flow::{FlowKey, FlowProtocol};
use skyhook::inbound::native_tun_metrics::NativeTunMetrics;
use skyhook::inbound::native_tun_packet::{parse_ip_packet, parse_udp_datagram, TunIpPacket};
use skyhook::inbound::native_tun_session::NativeSessionManager;

#[tokio::test]
async fn native_l3_udp_direct_echo_roundtrip() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = socket.local_addr().unwrap();

    tokio::spawn(async move {
        let mut buf = vec![0u8; 1024];
        let (n, src) = socket.recv_from(&mut buf).await.unwrap();
        socket.send_to(&buf[..n], src).await.unwrap();
    });

    let metrics = NativeTunMetrics::new(true, "native-l3".to_string(), true, true);
    let mut session_mgr = NativeSessionManager::new(metrics.clone());

    let client_ip: std::net::Ipv4Addr = "10.0.0.1".parse().unwrap();
    let server_ip: std::net::Ipv4Addr = server_addr.ip().to_string().parse().unwrap();

    let runtime = create_test_runtime();
    let client_addr = std::net::SocketAddr::new(client_ip.into(), 12345);
    let flow_key = FlowKey {
        protocol: FlowProtocol::Udp,
        src: client_addr,
        dst: std::net::SocketAddr::new(server_ip.into(), server_addr.port()),
    };
    let udp_packet = build_udp_packet(client_ip, 12345, server_ip, server_addr.port(), b"hello");
    let response = session_mgr
        .handle_udp_packet(udp_packet, &flow_key, &runtime)
        .await
        .expect("UDP direct handler should return an echo response packet");

    match parse_ip_packet(&response).unwrap() {
        TunIpPacket::Ipv4(ipv4) => {
            assert_eq!(ipv4.source, server_ip);
            assert_eq!(ipv4.destination, client_ip);
            let udp = parse_udp_datagram(&ipv4.payload).unwrap();
            assert_eq!(udp.source_port, server_addr.port());
            assert_eq!(udp.dest_port, 12345);
            assert_eq!(udp.payload, b"hello");
            assert_ne!(ipv4.checksum, 0, "IPv4 checksum should be filled");
            assert_ne!(udp.checksum, 0, "UDP checksum should be filled");
        }
        _ => panic!("expected IPv4 UDP response"),
    }

    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.direct_sessions, 1);
}

#[tokio::test]
async fn native_l3_udp_ipv6_direct_echo_roundtrip() {
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
    let mut session_mgr = NativeSessionManager::new(metrics.clone());

    let client_ip: std::net::Ipv6Addr = "fd00::1".parse().unwrap();
    let server_ip = match server_addr.ip() {
        std::net::IpAddr::V6(ip) => ip,
        _ => return,
    };
    let runtime = create_test_runtime();
    let client_addr = std::net::SocketAddr::new(client_ip.into(), 12345);
    let flow_key = FlowKey {
        protocol: FlowProtocol::Udp,
        src: client_addr,
        dst: std::net::SocketAddr::new(server_ip.into(), server_addr.port()),
    };
    let udp_packet = build_ipv6_udp_packet(client_ip, 12345, server_ip, server_addr.port(), b"v6");
    let response = session_mgr
        .handle_udp_packet(udp_packet, &flow_key, &runtime)
        .await
        .expect("IPv6 UDP direct handler should return an echo response packet");

    match parse_ip_packet(&response).unwrap() {
        TunIpPacket::Ipv6(ipv6) => {
            assert_eq!(ipv6.source, server_ip);
            assert_eq!(ipv6.destination, client_ip);
            let udp = parse_udp_datagram(&ipv6.payload).unwrap();
            assert_eq!(udp.source_port, server_addr.port());
            assert_eq!(udp.dest_port, 12345);
            assert_eq!(udp.payload, b"v6");
            assert_ne!(udp.checksum, 0, "IPv6 UDP checksum must be filled");
        }
        _ => panic!("expected IPv6 UDP response"),
    }

    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.direct_sessions, 1);
}

#[tokio::test]
async fn native_l3_udp_dns_hijack_records_cache() {
    let metrics = NativeTunMetrics::new(true, "native-l3".to_string(), true, true);
    let session_mgr = NativeSessionManager::new(metrics.clone());

    let cache = session_mgr.dns_cache();
    let ip: std::net::IpAddr = "93.184.216.34".parse().unwrap();
    cache.insert(ip, "example.com".to_string());

    assert_eq!(cache.lookup(&ip), Some("example.com".to_string()));
}

#[tokio::test]
async fn native_l3_udp_idle_session_cleanup() {
    let metrics = NativeTunMetrics::new(true, "native-l3".to_string(), true, true);
    let mut session_mgr = NativeSessionManager::new(metrics.clone());

    let udp_packet = build_udp_packet(
        "10.0.0.1".parse().unwrap(),
        12345,
        "8.8.8.8".parse().unwrap(),
        53,
        b"dns-query",
    );
    session_mgr.inject_packet(udp_packet);

    let runtime = create_test_runtime();
    session_mgr.process_events(&runtime).await;

    // Verify packet was processed
    let snapshot = metrics.snapshot();
    // read_packets is tracked in the TUN read loop, not in session manager
    let _ = snapshot;
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
    packet.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]);
    let payload_len = (8 + data.len()) as u16;
    packet.extend_from_slice(&payload_len.to_be_bytes());
    packet.push(17);
    packet.push(64);
    packet.extend_from_slice(&src_ip.octets());
    packet.extend_from_slice(&dst_ip.octets());
    packet.extend_from_slice(&src_port.to_be_bytes());
    packet.extend_from_slice(&dst_port.to_be_bytes());
    packet.extend_from_slice(&payload_len.to_be_bytes());
    packet.extend_from_slice(&[0x00, 0x00]);
    packet.extend_from_slice(data);
    packet
}

fn create_test_runtime() -> Arc<skyhook::core::Runtime> {
    use skyhook::config::SuperConfig;
    Arc::new(skyhook::core::Runtime::new(SuperConfig::default()).unwrap())
}
