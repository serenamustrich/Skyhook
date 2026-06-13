use criterion::{black_box, criterion_group, criterion_main, Criterion};
use tokio::sync::mpsc;

use skyhook::inbound::native_tun_metrics::NativeTunMetrics;
use skyhook::inbound::native_tun_tcp_forward::NativeTcpForwarder;

fn tcp_forwarder_benchmark(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    c.bench_function("tcp_forwarder_syn_ack", |b| {
        b.iter(|| {
            rt.block_on(async {
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
                black_box(egress_rx.recv().await);
            })
        })
    });
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

criterion_group!(benches, tcp_forwarder_benchmark);
criterion_main!(benches);
