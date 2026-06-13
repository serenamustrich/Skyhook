use std::{
    io::{Read, Write},
    net::TcpListener,
    thread,
};

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use skyhook::{
    config::{OutboundConfig, SuperConfig},
    core::{ProbeOptions, Runtime},
};

fn probe_outbounds_benchmark(c: &mut Criterion) {
    let server = ProbeServer::start();
    let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
    let skyhook = Runtime::new(config_with_direct_outbounds(100)).expect("skyhook runtime");
    let url = format!("http://{}/generate_204", server.addr);

    c.bench_function("probe_100_direct_outbounds", |b| {
        b.iter(|| {
            runtime.block_on(async {
                let results = skyhook
                    .probe_all_outbounds_with(ProbeOptions {
                        url: Some(url.clone()),
                        timeout_ms: Some(500),
                        concurrency: Some(32),
                        include_unsupported: true,
                        include_failed: true,
                    })
                    .await;
                black_box(results);
            })
        })
    });
}

fn config_with_direct_outbounds(count: usize) -> SuperConfig {
    let mut config = SuperConfig::default();
    config.core.default_outbound = "direct-0".to_string();
    config.smart_rules.direct_outbound = "direct-0".to_string();
    config.smart_rules.proxy_outbound = Some("direct-0".to_string());
    config.rules.clear();
    config.outbounds = (0..count)
        .map(|index| OutboundConfig::Direct {
            name: format!("direct-{index}"),
        })
        .collect();
    config
}

struct ProbeServer {
    addr: std::net::SocketAddr,
    handle: Option<thread::JoinHandle<()>>,
}

impl ProbeServer {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind probe server");
        let addr = listener.local_addr().expect("probe server addr");
        listener
            .set_nonblocking(true)
            .expect("set probe server nonblocking");
        let handle = thread::spawn(move || loop {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    thread::spawn(move || {
                        let mut buffer = [0u8; 1024];
                        let _ = stream.read(&mut buffer);
                        let response = b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n";
                        let _ = stream.write_all(response);
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(std::time::Duration::from_millis(1));
                }
                Err(_) => break,
            }
        });
        Self {
            addr,
            handle: Some(handle),
        }
    }
}

impl Drop for ProbeServer {
    fn drop(&mut self) {
        // The listener thread is intentionally detached; benchmarks are short-lived
        // and the process exits immediately after Criterion finishes.
        let _ = self.handle.take();
    }
}

criterion_group!(benches, probe_outbounds_benchmark);
criterion_main!(benches);
