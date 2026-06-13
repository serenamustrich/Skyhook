use criterion::{black_box, criterion_group, criterion_main, Criterion};
use skyhook::config::SuperConfig;
use skyhook::core::Runtime;
use skyhook::routing::Destination;

fn routing_decision_benchmark(c: &mut Criterion) {
    let config = SuperConfig::default();
    let runtime = Runtime::new(config).unwrap();

    c.bench_function("routing_decision_direct", |b| {
        b.iter(|| {
            let dest = Destination::new("example.com".to_string(), 443);
            black_box(runtime.decide(&dest));
        })
    });

    c.bench_function("routing_decision_ip", |b| {
        b.iter(|| {
            let dest = Destination::new("8.8.8.8".to_string(), 53);
            black_box(runtime.decide(&dest));
        })
    });
}

criterion_group!(benches, routing_decision_benchmark);
criterion_main!(benches);
