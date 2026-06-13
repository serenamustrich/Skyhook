use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

use skyhook::inbound::native_tun_metrics::NativeTunMetrics;
use skyhook::inbound::native_tun_tcp_forward::NativeTcpForwarder;

/// Verifies actual bidirectional TCP data flow through the forwarder.
/// Client sends "hello" → forwarder → echo server → forwarder → client receives "hello"
#[tokio::test(flavor = "multi_thread")]
async fn tcp_forwarder_bidirectional_echo() {
    // Start echo server
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

    let (egress_tx, mut egress_rx) = mpsc::channel::<Vec<u8>>(128);
    let metrics = NativeTunMetrics::new(true, "native-l3".to_string(), true, true);
    let mut forwarder = NativeTcpForwarder::new(egress_tx, metrics);
    let runtime = create_test_runtime();

    let client_ip: std::net::Ipv4Addr = "10.0.0.1".parse().unwrap();
    let server_ip: std::net::Ipv4Addr = server_addr.ip().to_string().parse().unwrap();
    let server_port = server_addr.port();

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
    forwarder.handle_packet(&syn, &runtime);

    // Collect SYN-ACK
    tokio::time::sleep(Duration::from_millis(10)).await;
    let syn_ack = egress_rx.recv().await.expect("SYN-ACK");
    assert_eq!(syn_ack[33] & 0x12, 0x12, "should be SYN-ACK");

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
    forwarder.handle_packet(&ack, &runtime);

    // Connect and pump
    let pending = forwarder.pending_connect_sessions();
    for fk in pending {
        forwarder.connect_and_pump(&fk, &runtime).await;
    }

    // Send data "hello"
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
    forwarder.handle_packet(&data, &runtime);

    let ack = tokio::time::timeout(Duration::from_secs(1), egress_rx.recv())
        .await
        .expect("ACK should arrive")
        .expect("ACK packet");
    assert_eq!(ack[33] & 0x10, 0x10, "ACK flag should be set");
    assert_ipv4_tcp_checksums_valid(&ack);

    // The echo server must send "hello" back through the forwarder.
    let packet = tokio::time::timeout(Duration::from_secs(1), egress_rx.recv())
        .await
        .expect("echo response should arrive")
        .expect("echo response packet");
    assert_ipv4_tcp_checksums_valid(&packet);

    let tcp_header_len = ((packet[32] >> 4) as usize) * 4;
    let payload = &packet[20 + tcp_header_len..];
    assert_eq!(payload, b"hello", "echo response should match");

    let response_seq = u32::from_be_bytes([packet[24], packet[25], packet[26], packet[27]]);
    let response_ack = u32::from_be_bytes([packet[28], packet[29], packet[30], packet[31]]);
    assert_ne!(response_seq, 0, "response sequence should be tracked");
    assert_eq!(
        response_ack, 1006,
        "response ACK should advance past client payload"
    );
}

/// Test SYN-ACK flag is correct
#[tokio::test]
async fn tcp_forwarder_syn_ack_flags() {
    let (egress_tx, mut egress_rx) = mpsc::channel::<Vec<u8>>(128);
    let metrics = NativeTunMetrics::new(true, "native-l3".to_string(), true, true);
    let mut forwarder = NativeTcpForwarder::new(egress_tx, metrics);
    let runtime = create_test_runtime();

    let syn = build_tcp_packet(
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
    forwarder.handle_packet(&syn, &runtime);

    let packet = egress_rx.recv().await.unwrap();
    let flags = packet[33];
    assert_eq!(flags & 0x02, 0x02, "SYN flag should be set");
    assert_eq!(flags & 0x10, 0x10, "ACK flag should be set");
    assert_ipv4_tcp_checksums_valid(&packet);
}

/// Test FIN handling
#[tokio::test]
async fn tcp_forwarder_fin_handling() {
    let (egress_tx, mut egress_rx) = mpsc::channel::<Vec<u8>>(128);
    let metrics = NativeTunMetrics::new(true, "native-l3".to_string(), true, true);
    let mut forwarder = NativeTcpForwarder::new(egress_tx, metrics);
    let runtime = create_test_runtime();

    let client: std::net::Ipv4Addr = "10.0.0.1".parse().unwrap();
    let server: std::net::Ipv4Addr = "192.168.1.1".parse().unwrap();

    // SYN
    forwarder.handle_packet(
        &build_tcp_packet(client, 12345, server, 80, &[], true, false, 1000, 0),
        &runtime,
    );
    let syn_ack = egress_rx.recv().await.unwrap();
    assert_eq!(syn_ack[33] & 0x12, 0x12, "should be SYN-ACK");

    // ACK
    forwarder.handle_packet(
        &build_tcp_packet(client, 12345, server, 80, &[], false, true, 1001, 1001),
        &runtime,
    );

    // FIN+ACK (no data first)
    forwarder.handle_packet(
        &build_tcp_packet_raw(client, 12345, server, 80, &[], 0x11, 1001, 1001),
        &runtime,
    );

    // Get FIN-ACK
    let fin_ack = egress_rx.recv().await.unwrap();
    let fin_flags = fin_ack[33];
    assert!(
        fin_flags & 0x01 != 0,
        "FIN flag should be set, got {:#x}",
        fin_flags
    );
    assert!(
        fin_flags & 0x10 != 0,
        "ACK flag should be set, got {:#x}",
        fin_flags
    );
}

/// Test RST handling
#[tokio::test]
async fn tcp_forwarder_rst_handling() {
    let (egress_tx, _egress_rx) = mpsc::channel::<Vec<u8>>(128);
    let metrics = NativeTunMetrics::new(true, "native-l3".to_string(), true, true);
    let mut forwarder = NativeTcpForwarder::new(egress_tx, metrics);
    let runtime = create_test_runtime();

    // SYN
    forwarder.handle_packet(
        &build_tcp_packet(
            "10.0.0.1".parse().unwrap(),
            12345,
            "192.168.1.1".parse().unwrap(),
            80,
            &[],
            true,
            false,
            1000,
            0,
        ),
        &runtime,
    );
    assert_eq!(forwarder.session_count(), 1);

    // RST
    let mut flags = 0u8;
    flags |= 0x04; // RST
    forwarder.handle_packet(
        &build_tcp_packet_raw(
            "10.0.0.1".parse().unwrap(),
            12345,
            "192.168.1.1".parse().unwrap(),
            80,
            &[],
            flags,
            1001,
            0,
        ),
        &runtime,
    );
    assert_eq!(forwarder.session_count(), 0);
}

/// Test FIN packet parsing
#[test]
fn fin_packet_parsing() {
    use skyhook::inbound::native_tun_packet::parse_ip_packet;

    let packet = build_tcp_packet_raw(
        "10.0.0.1".parse().unwrap(),
        12345,
        "192.168.1.1".parse().unwrap(),
        80,
        &[],
        0x11,
        1001,
        1001,
    );
    let parsed = parse_ip_packet(&packet).unwrap();

    match parsed {
        skyhook::inbound::native_tun_packet::TunIpPacket::Ipv4(ipv4) => {
            // TCP flags are at payload[13]
            let flags = ipv4.payload[13];
            assert_eq!(flags & 0x01, 0x01, "FIN flag should be set");
            assert_eq!(flags & 0x10, 0x10, "ACK flag should be set");
            assert_eq!(flags & 0x02, 0x00, "SYN flag should not be set");
        }
        _ => panic!("expected IPv4"),
    }
}
#[test]
fn ipv4_tcp_packet_parsing() {
    use skyhook::inbound::native_tun_packet::parse_ip_packet;

    let packet = build_tcp_packet(
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
    let parsed = parse_ip_packet(&packet).unwrap();

    match parsed {
        skyhook::inbound::native_tun_packet::TunIpPacket::Ipv4(ipv4) => {
            assert_eq!(ipv4.source, std::net::Ipv4Addr::new(10, 0, 0, 1));
            assert_eq!(ipv4.destination, std::net::Ipv4Addr::new(192, 168, 1, 1));
            assert_eq!(ipv4.protocol, 6); // TCP
        }
        _ => panic!("expected IPv4"),
    }
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

/// Test that duplicate SYN packets don't create multiple sessions
#[tokio::test]
async fn tcp_forwarder_duplicate_syn_handling() {
    let (egress_tx, mut egress_rx) = mpsc::channel::<Vec<u8>>(128);
    let metrics = NativeTunMetrics::new(true, "native-l3".to_string(), true, true);
    let mut forwarder = NativeTcpForwarder::new(egress_tx, metrics);
    let runtime = create_test_runtime();

    let client: std::net::Ipv4Addr = "10.0.0.1".parse().unwrap();
    let server: std::net::Ipv4Addr = "192.168.1.1".parse().unwrap();

    // Send first SYN
    forwarder.handle_packet(
        &build_tcp_packet(client, 12345, server, 80, &[], true, false, 1000, 0),
        &runtime,
    );
    assert_eq!(
        forwarder.session_count(),
        1,
        "should have 1 session after first SYN"
    );

    // Send duplicate SYN with different seq
    forwarder.handle_packet(
        &build_tcp_packet(client, 12345, server, 80, &[], true, false, 2000, 0),
        &runtime,
    );
    // Should still have only 1 session
    assert_eq!(
        forwarder.session_count(),
        1,
        "duplicate SYN should not create second session"
    );

    // Should get 2 SYN-ACKs (one for each SYN)
    let syn_ack1 = egress_rx.recv().await.unwrap();
    assert_eq!(syn_ack1[33] & 0x12, 0x12, "first SYN-ACK");
    let syn_ack2 = egress_rx.recv().await.unwrap();
    assert_eq!(
        syn_ack2[33] & 0x12,
        0x12,
        "second SYN-ACK for duplicate SYN"
    );
}

/// Test that RST immediately removes session
#[tokio::test]
async fn tcp_forwarder_rst_immediate_cleanup() {
    let (egress_tx, _egress_rx) = mpsc::channel::<Vec<u8>>(128);
    let metrics = NativeTunMetrics::new(true, "native-l3".to_string(), true, true);
    let mut forwarder = NativeTcpForwarder::new(egress_tx, metrics);
    let runtime = create_test_runtime();

    let client: std::net::Ipv4Addr = "10.0.0.1".parse().unwrap();
    let server: std::net::Ipv4Addr = "192.168.1.1".parse().unwrap();

    // Create session
    forwarder.handle_packet(
        &build_tcp_packet(client, 12345, server, 80, &[], true, false, 1000, 0),
        &runtime,
    );
    assert_eq!(forwarder.session_count(), 1);

    // Send RST
    forwarder.handle_packet(
        &build_tcp_packet_raw(client, 12345, server, 80, &[], 0x04, 1001, 0),
        &runtime,
    );
    assert_eq!(forwarder.session_count(), 0);
}

/// Test that data after FIN is ignored
#[tokio::test]
async fn tcp_forwarder_data_after_fin_ignored() {
    let (egress_tx, mut egress_rx) = mpsc::channel::<Vec<u8>>(128);
    let metrics = NativeTunMetrics::new(true, "native-l3".to_string(), true, true);
    let mut forwarder = NativeTcpForwarder::new(egress_tx, metrics);
    let runtime = create_test_runtime();

    let client: std::net::Ipv4Addr = "10.0.0.1".parse().unwrap();
    let server: std::net::Ipv4Addr = "192.168.1.1".parse().unwrap();

    // Create session
    forwarder.handle_packet(
        &build_tcp_packet(client, 12345, server, 80, &[], true, false, 1000, 0),
        &runtime,
    );
    let _ = egress_rx.recv().await;

    // ACK
    forwarder.handle_packet(
        &build_tcp_packet(client, 12345, server, 80, &[], false, true, 1001, 1001),
        &runtime,
    );

    // FIN
    forwarder.handle_packet(
        &build_tcp_packet_raw(client, 12345, server, 80, &[], 0x11, 1001, 1001),
        &runtime,
    );
    let _ = egress_rx.recv().await;

    // Data after FIN should be ignored (no panic)
    forwarder.handle_packet(
        &build_tcp_packet(
            client,
            12345,
            server,
            80,
            b"late data",
            false,
            true,
            1001,
            1001,
        ),
        &runtime,
    );
}

/// Test session count tracking
#[tokio::test]
async fn tcp_forwarder_session_count_tracking() {
    let (egress_tx, _egress_rx) = mpsc::channel::<Vec<u8>>(128);
    let metrics = NativeTunMetrics::new(true, "native-l3".to_string(), true, true);
    let mut forwarder = NativeTcpForwarder::new(egress_tx, metrics);
    let runtime = create_test_runtime();

    assert_eq!(forwarder.session_count(), 0);

    // Create multiple sessions
    for i in 0..5 {
        let client: std::net::Ipv4Addr = format!("10.0.0.{}", i + 1).parse().unwrap();
        forwarder.handle_packet(
            &build_tcp_packet(
                client,
                12345 + i as u16,
                "192.168.1.1".parse().unwrap(),
                80,
                &[],
                true,
                false,
                1000,
                0,
            ),
            &runtime,
        );
    }
    assert_eq!(forwarder.session_count(), 5);
}

/// Test metrics tracking
#[tokio::test]
async fn tcp_forwarder_metrics_tracking() {
    let (egress_tx, _egress_rx) = mpsc::channel::<Vec<u8>>(128);
    let metrics = NativeTunMetrics::new(true, "native-l3".to_string(), true, true);
    let mut forwarder = NativeTcpForwarder::new(egress_tx, metrics.clone());
    let runtime = create_test_runtime();

    let client: std::net::Ipv4Addr = "10.0.0.1".parse().unwrap();
    let server: std::net::Ipv4Addr = "192.168.1.1".parse().unwrap();

    // Create session
    forwarder.handle_packet(
        &build_tcp_packet(client, 12345, server, 80, &[], true, false, 1000, 0),
        &runtime,
    );

    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.tcp_active_sessions, 1);
}
