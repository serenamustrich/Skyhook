use criterion::{black_box, criterion_group, criterion_main, Criterion};
use tokio::net::UdpSocket;

use skyhook::inbound::native_tun_dispatcher::NativeL4Dispatcher;
use skyhook::inbound::native_tun_flow::{FlowKey, FlowProtocol};
use skyhook::inbound::native_tun_metrics::NativeTunMetrics;

fn udp_relay_benchmark(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    c.bench_function("udp_direct_echo", |b| {
        b.iter(|| {
            rt.block_on(async {
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

                let udp_packet =
                    build_udp_packet(client_ip, 12345, server_ip, server_addr.port(), b"bench");
                let result = dispatcher
                    .dispatch_packet(udp_packet, &flow_key, &runtime)
                    .await;
                black_box(result);
            })
        })
    });
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

criterion_group!(benches, udp_relay_benchmark);
criterion_main!(benches);
