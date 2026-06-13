use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use skyhook::inbound::native_tun_dispatcher::NativeL4Dispatcher;
use skyhook::inbound::native_tun_flow::{FlowKey, FlowProtocol};
use skyhook::inbound::native_tun_metrics::NativeTunMetrics;

/// 10k short TCP connections soak test
/// Requires: real TUN interface (sudo)
/// Set SKYHOOK_TUN_SOAK_ITERATIONS to control iteration count (default: 100)
#[tokio::test]
#[ignore]
async fn native_tun_soak_10k_tcp() {
    let iterations: usize = std::env::var("SKYHOOK_TUN_SOAK_ITERATIONS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(100);

    let metrics = NativeTunMetrics::new(true, "native-l3".to_string(), true, true);
    let runtime = create_test_runtime();

    let mut success_count = 0;
    let mut fail_count = 0;

    for i in 0..iterations {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = vec![0u8; 1024];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => {
                            let _ = stream.write_all(&buf[..n]).await;
                        }
                        Err(_) => break,
                    }
                }
            }
        });

        let mut dispatcher = NativeL4Dispatcher::new(metrics.clone());
        let client_ip: std::net::Ipv4Addr = format!("10.0.{}.{}", (i / 256) % 256, i % 256)
            .parse()
            .unwrap();
        let server_ip: std::net::Ipv4Addr = server_addr.ip().to_string().parse().unwrap();

        let flow_key = FlowKey {
            protocol: FlowProtocol::Tcp,
            src: std::net::SocketAddr::new(client_ip.into(), 12345),
            dst: std::net::SocketAddr::new(server_ip.into(), server_addr.port()),
        };

        // SYN
        let syn = build_tcp_packet(
            client_ip,
            12345,
            server_ip,
            server_addr.port(),
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
            server_addr.port(),
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
            server_addr.port(),
            b"test",
            false,
            true,
            1001,
            1001,
        );
        let _result = dispatcher.dispatch_packet(data, &flow_key, &runtime).await;

        if dispatcher.tcp_session_count() > 0 {
            success_count += 1;
        } else {
            fail_count += 1;
        }
    }

    let snapshot = metrics.snapshot();
    println!(
        "Soak test completed: {} iterations, {} success, {} fail",
        iterations, success_count, fail_count
    );
    println!(
        "Metrics: read={}, errors={}",
        snapshot.read_bytes, snapshot.decode_errors
    );

    assert!(
        success_count > 0,
        "At least some connections should succeed"
    );
}

/// 30-minute soak test controlled by env var
/// Set SKYHOOK_TUN_SOAK_SECONDS=1800 to run for 30 minutes
#[tokio::test]
#[ignore]
async fn native_tun_soak_30min() {
    let seconds: u64 = std::env::var("SKYHOOK_TUN_SOAK_SECONDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(60);

    let start = std::time::Instant::now();
    let duration = Duration::from_secs(seconds);

    let metrics = NativeTunMetrics::new(true, "native-l3".to_string(), true, true);
    let runtime = create_test_runtime();

    let mut total_iterations = 0u64;
    let mut total_success = 0u64;
    let mut total_fail = 0u64;

    // Reuse a small set of IPs to avoid exhausting address space
    let client_ip: std::net::Ipv4Addr = "10.0.0.1".parse().unwrap();
    let server_ip: std::net::Ipv4Addr = "127.0.0.1".parse().unwrap();
    let server_port = 18080u16;

    // Create a single echo server
    let listener = TcpListener::bind(format!("127.0.0.1:{}", server_port))
        .await
        .unwrap();

    tokio::spawn(async move {
        loop {
            if let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 1024];
                    loop {
                        match stream.read(&mut buf).await {
                            Ok(0) => break,
                            Ok(n) => {
                                let _ = stream.write_all(&buf[..n]).await;
                            }
                            Err(_) => break,
                        }
                    }
                });
            }
        }
    });

    while start.elapsed() < duration {
        let mut dispatcher = NativeL4Dispatcher::new(metrics.clone());
        let src_port = 12345u16.wrapping_add((total_iterations % 50000) as u16);

        let flow_key = FlowKey {
            protocol: FlowProtocol::Tcp,
            src: std::net::SocketAddr::new(client_ip.into(), src_port),
            dst: std::net::SocketAddr::new(server_ip.into(), server_port),
        };

        let syn = build_tcp_packet(
            client_ip,
            src_port,
            server_ip,
            server_port,
            &[],
            true,
            false,
            1000,
            0,
        );
        let _ = dispatcher.dispatch_packet(syn, &flow_key, &runtime).await;

        let ack = build_tcp_packet(
            client_ip,
            src_port,
            server_ip,
            server_port,
            &[],
            false,
            true,
            1001,
            1001,
        );
        let _ = dispatcher.dispatch_packet(ack, &flow_key, &runtime).await;

        if dispatcher.tcp_session_count() > 0 {
            total_success += 1;
        } else {
            total_fail += 1;
        }

        total_iterations += 1;

        if total_iterations.is_multiple_of(1000) {
            println!(
                "Progress: {} iterations, elapsed {:?}",
                total_iterations,
                start.elapsed()
            );
        }
    }

    let snapshot = metrics.snapshot();
    println!(
        "Soak test completed: {} iterations in {:?}, {} success, {} fail",
        total_iterations,
        start.elapsed(),
        total_success,
        total_fail
    );
    println!(
        "Final metrics: read={}, errors={}",
        snapshot.read_bytes, snapshot.decode_errors
    );

    assert!(
        total_success > 0,
        "At least some connections should succeed"
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

fn create_test_runtime() -> std::sync::Arc<skyhook::core::Runtime> {
    use skyhook::config::SuperConfig;
    std::sync::Arc::new(skyhook::core::Runtime::new(SuperConfig::default()).unwrap())
}
