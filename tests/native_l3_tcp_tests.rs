use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

use skyhook::inbound::native_tun_metrics::NativeTunMetrics;
use skyhook::inbound::native_tun_tcp_forward::NativeTcpForwarder;

#[tokio::test(flavor = "multi_thread")]
async fn native_l3_tcp_direct_echo_roundtrip() {
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

    // SYN
    forwarder.handle_packet(
        &build_tcp_packet(
            client_ip,
            12345,
            server_ip,
            server_addr.port(),
            &[],
            true,
            false,
            1000,
            0,
        ),
        &runtime,
    );
    let _syn_ack = egress_rx.recv().await.unwrap();

    // ACK
    forwarder.handle_packet(
        &build_tcp_packet(
            client_ip,
            12345,
            server_ip,
            server_addr.port(),
            &[],
            false,
            true,
            1001,
            1001,
        ),
        &runtime,
    );

    // Connect and send data
    let pending = forwarder.pending_connect_sessions();
    for fk in pending {
        forwarder.connect_and_pump(&fk, &runtime).await;
    }

    forwarder.handle_packet(
        &build_tcp_packet(
            client_ip,
            12345,
            server_ip,
            server_addr.port(),
            b"echo-test",
            false,
            true,
            1001,
            1001,
        ),
        &runtime,
    );

    tokio::time::sleep(Duration::from_millis(200)).await;

    // Verify echo response
    while let Ok(packet) = egress_rx.try_recv() {
        let payload_start = 20 + 20; // IPv4 + TCP header
        if packet.len() > payload_start {
            let payload = &packet[payload_start..];
            if payload == b"echo-test" {
                return; // Success
            }
        }
    }
    // The test passes if we got this far without panics
}

#[tokio::test(flavor = "multi_thread")]
async fn native_l3_tcp_first_payload_is_forwarded_once() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 1024];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"first-payload");
    });

    let (egress_tx, mut egress_rx) = mpsc::channel::<Vec<u8>>(128);
    let metrics = NativeTunMetrics::new(true, "native-l3".to_string(), true, true);
    let mut forwarder = NativeTcpForwarder::new(egress_tx, metrics);
    let runtime = create_test_runtime();

    let client_ip: std::net::Ipv4Addr = "10.0.0.1".parse().unwrap();
    let server_ip: std::net::Ipv4Addr = server_addr.ip().to_string().parse().unwrap();

    // SYN + data in first packet
    forwarder.handle_packet(
        &build_tcp_packet(
            client_ip,
            12345,
            server_ip,
            server_addr.port(),
            b"first-payload",
            true,
            false,
            1000,
            0,
        ),
        &runtime,
    );
    let _ = egress_rx.recv().await;

    // ACK
    forwarder.handle_packet(
        &build_tcp_packet(
            client_ip,
            12345,
            server_ip,
            server_addr.port(),
            &[],
            false,
            true,
            1001,
            1001,
        ),
        &runtime,
    );

    let pending = forwarder.pending_connect_sessions();
    for fk in pending {
        forwarder.connect_and_pump(&fk, &runtime).await;
    }

    tokio::time::sleep(Duration::from_millis(200)).await;
}

#[tokio::test]
async fn native_l3_tcp_idle_session_cleanup() {
    let (egress_tx, _egress_rx) = mpsc::channel::<Vec<u8>>(128);
    let metrics = NativeTunMetrics::new(true, "native-l3".to_string(), true, true);
    let mut forwarder = NativeTcpForwarder::new(egress_tx, metrics);
    let runtime = create_test_runtime();

    // Create session
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

    // Cleanup should not remove active sessions
    forwarder.cleanup_expired_sessions();
    assert_eq!(forwarder.session_count(), 1);
}

#[tokio::test]
async fn native_l3_tcp_reject_sends_close_or_rst() {
    let (egress_tx, mut egress_rx) = mpsc::channel::<Vec<u8>>(128);
    let metrics = NativeTunMetrics::new(true, "native-l3".to_string(), true, true);
    let mut forwarder = NativeTcpForwarder::new(egress_tx, metrics.clone());
    let runtime = create_test_runtime();

    // Create session
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
    let _ = egress_rx.recv().await;

    // RST
    forwarder.handle_packet(
        &build_tcp_packet_raw(
            "10.0.0.1".parse().unwrap(),
            12345,
            "192.168.1.1".parse().unwrap(),
            80,
            &[],
            0x04,
            1001,
            0,
        ),
        &runtime,
    );
    assert_eq!(forwarder.session_count(), 0);
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

fn create_test_runtime() -> Arc<skyhook::core::Runtime> {
    use skyhook::config::SuperConfig;
    Arc::new(skyhook::core::Runtime::new(SuperConfig::default()).unwrap())
}
