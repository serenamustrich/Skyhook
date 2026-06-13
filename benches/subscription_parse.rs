use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn subscription_parse_benchmark(c: &mut Criterion) {
    c.bench_function("subscription_store_load", |b| {
        let temp_dir = tempfile::tempdir().unwrap();
        let store = skyhook::subscription_store::SubscriptionStore::new(temp_dir.path());

        // Import a subscription
        let yaml_content = r#"
proxies:
  - name: "proxy-1"
    type: ss
    server: proxy1.example.com
    port: 8388
    cipher: aes-256-gcm
    password: test-password
rules:
  - MATCH,DIRECT
"#;
        let _ = store.import_text(Some("test-sub".to_string()), None, yaml_content, true);

        b.iter(|| {
            let _ = black_box(store.index());
        })
    });
}

criterion_group!(benches, subscription_parse_benchmark);
criterion_main!(benches);
