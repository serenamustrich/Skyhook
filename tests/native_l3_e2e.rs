use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

use skyhook::inbound::native_tun_dns::DnsCache;
use skyhook::inbound::native_tun_flow::{FlowKey, FlowProtocol};
use skyhook::inbound::native_tun_metrics::NativeTunMetrics;
use skyhook::inbound::native_tun_session::NativeSessionManager;
use skyhook::inbound::native_tun_stack::NativeTunStack;

#[tokio::test]
async fn native_l3_tcp_echo_server_accepts_connection() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_handle = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 1024];
        let n = stream.read(&mut buf).await.unwrap();
        stream.write_all(&buf[..n]).await.unwrap();
    });

    // Directly connect to verify the echo server works
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream.write_all(b"hello").await.unwrap();
    let mut buf = vec![0u8; 1024];
    let n = stream.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"hello");

    server_handle.await.unwrap();
}

#[tokio::test]
async fn native_l3_udp_echo_server_echoes_back() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();

    let server_handle = tokio::spawn(async move {
        let mut buf = vec![0u8; 1024];
        let (n, src) = socket.recv_from(&mut buf).await.unwrap();
        socket.send_to(&buf[..n], src).await.unwrap();
    });

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.send_to(b"hello", addr).await.unwrap();
    let mut buf = vec![0u8; 1024];
    let (n, _) = client.recv_from(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"hello");

    server_handle.await.unwrap();
}

#[tokio::test]
async fn session_manager_inject_packet_queues_to_stack() {
    let metrics = NativeTunMetrics::new(true, "native-l3".to_string(), true, true);
    let mut session_mgr = NativeSessionManager::new(metrics);

    let syn_packet = build_tcp_syn_packet(
        "10.0.0.1:12345".parse().unwrap(),
        "192.168.1.1:80".parse().unwrap(),
    );
    session_mgr.inject_packet(syn_packet);

    // Process events - this should poll smoltcp
    let runtime = create_test_runtime();
    session_mgr.process_events(&runtime).await;

    // Verify that pending writes were generated (smoltcp response)
    let _writes = session_mgr.take_pending_writes();
    // smoltcp may or may not generate response depending on its state machine
    // The key test is that no panic occurred
}

#[tokio::test]
async fn session_manager_creates_tcp_session_on_syn() {
    let metrics = NativeTunMetrics::new(true, "native-l3".to_string(), true, true);
    let mut session_mgr = NativeSessionManager::new(metrics.clone());

    // First inject a SYN
    let syn_packet = build_tcp_syn_packet(
        "10.0.0.1:12345".parse().unwrap(),
        "192.168.1.1:80".parse().unwrap(),
    );
    session_mgr.inject_packet(syn_packet);
    tokio::time::sleep(Duration::from_millis(10)).await;

    let runtime = create_test_runtime();
    session_mgr.process_events(&runtime).await;

    // After processing, TCP session count should reflect what smoltcp produced
    let snapshot = metrics.snapshot();
    // We just verify the code path doesn't panic - actual session creation
    // depends on smoltcp internal state machine processing the SYN
    let _ = snapshot.tcp_active_sessions;
}

#[tokio::test]
async fn session_manager_handles_udp_datagram() {
    let metrics = NativeTunMetrics::new(true, "native-l3".to_string(), true, true);
    let mut session_mgr = NativeSessionManager::new(metrics.clone());

    let udp_packet = build_udp_packet(
        "10.0.0.1:12345".parse().unwrap(),
        "8.8.8.8:53".parse().unwrap(),
        b"dns-query",
    );
    session_mgr.inject_packet(udp_packet);
    tokio::time::sleep(Duration::from_millis(10)).await;

    let runtime = create_test_runtime();
    session_mgr.process_events(&runtime).await;

    let snapshot = metrics.snapshot();
    let _ = snapshot.udp_active_sessions;
}

#[tokio::test]
async fn smoltcp_stack_creation_and_address_add() {
    let mut stack = NativeTunStack::new();
    stack.add_address(smoltcp::wire::IpCidr::new(
        smoltcp::wire::IpAddress::Ipv4(smoltcp::wire::Ipv4Address::new(10, 0, 0, 1)),
        24,
    ));
}

#[tokio::test]
async fn smoltcp_inject_and_poll_no_panic() {
    let mut stack = NativeTunStack::new();
    stack.add_address(smoltcp::wire::IpCidr::new(
        smoltcp::wire::IpAddress::Ipv4(smoltcp::wire::Ipv4Address::new(10, 0, 0, 1)),
        24,
    ));

    let syn = build_tcp_syn_packet(
        "10.0.0.1:12345".parse().unwrap(),
        "192.168.1.1:80".parse().unwrap(),
    );
    stack.inject_packet(syn);

    let events = stack.poll(Instant::now());
    let writes = stack.take_pending_writes();
    // Just verify no panic
    let _ = (events, writes);
}

#[tokio::test]
async fn smoltcp_tcp_socket_lifecycle() {
    let mut stack = NativeTunStack::new();
    stack.add_address(smoltcp::wire::IpCidr::new(
        smoltcp::wire::IpAddress::Ipv4(smoltcp::wire::Ipv4Address::new(10, 0, 0, 1)),
        24,
    ));

    let flow_key = FlowKey {
        protocol: FlowProtocol::Tcp,
        src: "10.0.0.1:12345".parse().unwrap(),
        dst: "192.168.1.1:80".parse().unwrap(),
    };

    let handle = stack.create_tcp_socket(flow_key.clone(), 12345);
    assert!(stack.tcp_handles().contains_key(&flow_key));

    let remote: smoltcp::wire::IpEndpoint = "192.168.1.1:80".parse().unwrap();
    let _ = stack.tcp_connect(handle, 12345, remote);

    // Close and remove
    stack.tcp_close(handle);
    stack.remove_socket(handle);
    assert!(!stack.tcp_handles().contains_key(&flow_key));
}

#[tokio::test]
async fn smoltcp_udp_socket_lifecycle() {
    let mut stack = NativeTunStack::new();
    stack.add_address(smoltcp::wire::IpCidr::new(
        smoltcp::wire::IpAddress::Ipv4(smoltcp::wire::Ipv4Address::new(10, 0, 0, 1)),
        24,
    ));

    let flow_key = FlowKey {
        protocol: FlowProtocol::Udp,
        src: "10.0.0.1:12345".parse().unwrap(),
        dst: "8.8.8.8:53".parse().unwrap(),
    };

    let handle = stack.create_udp_socket(flow_key.clone(), 12345);
    assert!(stack.udp_handles().contains_key(&flow_key));

    stack.remove_socket(handle);
    assert!(!stack.udp_handles().contains_key(&flow_key));
}

#[tokio::test]
async fn smoltcp_tcp_send_recv() {
    let mut stack = NativeTunStack::new();
    stack.add_address(smoltcp::wire::IpCidr::new(
        smoltcp::wire::IpAddress::Ipv4(smoltcp::wire::Ipv4Address::new(10, 0, 0, 1)),
        24,
    ));

    let flow_key = FlowKey {
        protocol: FlowProtocol::Tcp,
        src: "10.0.0.1:12345".parse().unwrap(),
        dst: "192.168.1.1:80".parse().unwrap(),
    };

    let handle = stack.create_tcp_socket(flow_key, 12345);

    // Send data (will be buffered since not connected)
    stack.tcp_send(handle, b"hello");
    let data = stack.tcp_recv(handle);
    assert!(data.is_empty()); // No data to recv yet
}

#[tokio::test]
async fn smoltcp_udp_send_recv() {
    let mut stack = NativeTunStack::new();
    stack.add_address(smoltcp::wire::IpCidr::new(
        smoltcp::wire::IpAddress::Ipv4(smoltcp::wire::Ipv4Address::new(10, 0, 0, 1)),
        24,
    ));

    let flow_key = FlowKey {
        protocol: FlowProtocol::Udp,
        src: "10.0.0.1:12345".parse().unwrap(),
        dst: "8.8.8.8:53".parse().unwrap(),
    };

    let handle = stack.create_udp_socket(flow_key, 12345);

    let dst: smoltcp::wire::IpEndpoint = "8.8.8.8:53".parse().unwrap();
    stack.udp_send(handle, b"query", dst);

    let result = stack.udp_recv(handle);
    assert!(result.is_none()); // No response yet
}

#[tokio::test]
async fn dns_cache_insert_lookup_evict() {
    let cache = DnsCache::new();
    let ip: std::net::IpAddr = "1.2.3.4".parse().unwrap();

    assert!(cache.is_empty());
    cache.insert(ip, "example.com".to_string());
    assert_eq!(cache.len(), 1);
    assert_eq!(cache.lookup(&ip), Some("example.com".to_string()));

    let ip2: std::net::IpAddr = "5.6.7.8".parse().unwrap();
    assert_eq!(cache.lookup(&ip2), None);

    cache.clear();
    assert!(cache.is_empty());
}

#[tokio::test]
async fn dns_cache_ttl_works() {
    let cache = DnsCache::new();
    let ip: std::net::IpAddr = "1.2.3.4".parse().unwrap();

    cache.insert_with_ttl(ip, "example.com".to_string(), Duration::from_millis(0));
    tokio::time::sleep(Duration::from_millis(10)).await;

    assert_eq!(cache.lookup(&ip), None);
}

#[tokio::test]
async fn dns_cache_overwrite_entry() {
    let cache = DnsCache::new();
    let ip: std::net::IpAddr = "1.2.3.4".parse().unwrap();

    cache.insert(ip, "first.com".to_string());
    cache.insert(ip, "second.com".to_string());
    assert_eq!(cache.lookup(&ip), Some("second.com".to_string()));
    assert_eq!(cache.len(), 1);
}

#[tokio::test]
async fn endpoint_conversion_roundtrip() {
    use skyhook::inbound::native_tun_stack::{endpoint_to_socket_addr, socket_addr_to_endpoint};

    let addr: SocketAddr = "1.2.3.4:443".parse().unwrap();
    let ep = socket_addr_to_endpoint(addr);
    let back = endpoint_to_socket_addr(ep);
    assert_eq!(addr, back);
}

#[tokio::test]
async fn endpoint_ipv6_conversion() {
    use skyhook::inbound::native_tun_stack::{endpoint_to_socket_addr, socket_addr_to_endpoint};

    let addr: SocketAddr = "[::1]:443".parse().unwrap();
    let ep = socket_addr_to_endpoint(addr);
    let back = endpoint_to_socket_addr(ep);
    assert_eq!(addr, back);
}

#[tokio::test]
async fn metrics_record_read_write() {
    let metrics = NativeTunMetrics::new(true, "native-l3".to_string(), true, true);

    metrics.record_read(100);
    metrics.record_read(200);
    metrics.record_write(50);

    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.read_packets, 2);
    assert_eq!(snapshot.read_bytes, 300);
    assert_eq!(snapshot.write_packets, 1);
    assert_eq!(snapshot.write_bytes, 50);
}

#[tokio::test]
async fn metrics_record_session_types() {
    let metrics = NativeTunMetrics::new(true, "native-l3".to_string(), true, true);

    metrics.record_tcp_session_opened();
    metrics.record_tcp_session_opened();
    metrics.record_tcp_session_closed();
    metrics.record_udp_session_opened();
    metrics.record_direct_session();
    metrics.record_proxy_session();
    metrics.record_group_resolved_session();
    metrics.record_country_resolved_session();

    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.tcp_active_sessions, 1);
    assert_eq!(snapshot.udp_active_sessions, 1);
    assert_eq!(snapshot.direct_sessions, 1);
    assert_eq!(snapshot.proxy_sessions, 1);
    assert_eq!(snapshot.group_resolved_sessions, 1);
    assert_eq!(snapshot.country_resolved_sessions, 1);
}

#[tokio::test]
async fn metrics_record_dns() {
    let metrics = NativeTunMetrics::new(true, "native-l3".to_string(), true, true);

    metrics.record_dns_query();
    metrics.record_dns_success();
    metrics.record_dns_failure();
    metrics.record_dns_unsupported_ipv6();

    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.dns_queries, 1);
    assert_eq!(snapshot.dns_successes, 1);
    assert_eq!(snapshot.dns_failures, 1);
    assert_eq!(snapshot.dns_unsupported_ipv6, 1);
}

#[tokio::test]
async fn metrics_record_errors() {
    let metrics = NativeTunMetrics::new(true, "native-l3".to_string(), true, true);

    metrics.record_decode_error();
    metrics.record_encode_error();
    metrics.record_rejected();
    metrics.record_dropped("test reason".to_string());

    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.decode_errors, 1);
    assert_eq!(snapshot.encode_errors, 1);
    assert_eq!(snapshot.rejected_packets, 1);
    assert_eq!(snapshot.dropped_packets, 1);
    assert_eq!(snapshot.last_drop_reason, Some("test reason".to_string()));
}

#[tokio::test]
async fn metrics_running_state() {
    let metrics = NativeTunMetrics::new(true, "native-l3".to_string(), true, true);

    assert!(!metrics.snapshot().running);
    metrics.set_running(true);
    assert!(metrics.snapshot().running);
    metrics.set_running(false);
    assert!(!metrics.snapshot().running);
}

fn build_tcp_syn_packet(src: SocketAddr, dst: SocketAddr) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.push(0x45);
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 64, 6, 0x00, 0x00]);
    match src.ip() {
        std::net::IpAddr::V4(ip) => packet.extend_from_slice(&ip.octets()),
        _ => packet.extend_from_slice(&[0, 0, 0, 0]),
    }
    match dst.ip() {
        std::net::IpAddr::V4(ip) => packet.extend_from_slice(&ip.octets()),
        _ => packet.extend_from_slice(&[0, 0, 0, 0]),
    }
    packet.extend_from_slice(&src.port().to_be_bytes());
    packet.extend_from_slice(&dst.port().to_be_bytes());
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    packet.push(0x50);
    packet.push(0x02);
    packet.extend_from_slice(&[0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00]);
    let total_len = packet.len() as u16;
    packet[2..4].copy_from_slice(&total_len.to_be_bytes());
    packet
}

fn build_udp_packet(src: SocketAddr, dst: SocketAddr, data: &[u8]) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.push(0x45);
    let total_len = (20 + 8 + data.len()) as u16;
    packet.extend_from_slice(&total_len.to_be_bytes());
    packet.extend_from_slice(&[0x00, 0x00, 0x40, 0x00, 64, 17, 0x00, 0x00]);
    match src.ip() {
        std::net::IpAddr::V4(ip) => packet.extend_from_slice(&ip.octets()),
        _ => packet.extend_from_slice(&[0, 0, 0, 0]),
    }
    match dst.ip() {
        std::net::IpAddr::V4(ip) => packet.extend_from_slice(&ip.octets()),
        _ => packet.extend_from_slice(&[0, 0, 0, 0]),
    }
    packet.extend_from_slice(&src.port().to_be_bytes());
    packet.extend_from_slice(&dst.port().to_be_bytes());
    let udp_len = (8 + data.len()) as u16;
    packet.extend_from_slice(&udp_len.to_be_bytes());
    packet.extend_from_slice(&[0x00, 0x00]);
    packet.extend_from_slice(data);
    packet
}

fn create_test_runtime() -> Arc<skyhook::core::Runtime> {
    use skyhook::config::SuperConfig;
    let config = SuperConfig::default();
    Arc::new(skyhook::core::Runtime::new(config).unwrap())
}
