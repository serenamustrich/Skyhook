use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::net::IpAddr;
use std::sync::Arc;

use skyhook::inbound::native_tun_dns::DnsCache;

fn dns_benchmark(c: &mut Criterion) {
    let cache = Arc::new(DnsCache::new());

    // Pre-populate cache
    for i in 0..1000 {
        let ip: IpAddr = format!("10.0.{}.{}", i / 256, i % 256).parse().unwrap();
        cache.insert(ip, format!("domain{}.example.com", i));
    }

    c.bench_function("dns_cache_hit", |b| {
        b.iter(|| {
            let ip: IpAddr = "10.0.3.232".parse().unwrap();
            black_box(cache.lookup(&ip));
        })
    });

    c.bench_function("dns_cache_miss", |b| {
        b.iter(|| {
            let ip: IpAddr = "192.168.1.1".parse().unwrap();
            black_box(cache.lookup(&ip));
        })
    });

    c.bench_function("dns_cache_insert", |b| {
        let mut counter = 0u32;
        b.iter(|| {
            counter = counter.wrapping_add(1);
            let ip: IpAddr = format!("10.1.{}.{}", counter / 256, counter % 256)
                .parse()
                .unwrap();
            cache.insert(ip, format!("new{}.example.com", counter));
        })
    });
}

criterion_group!(benches, dns_benchmark);
criterion_main!(benches);
