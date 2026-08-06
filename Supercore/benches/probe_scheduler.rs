use std::{hint::black_box, time::Instant};

use supercore::{
    config::SuperConfig,
    core::{ProbeOptions, Runtime},
};

fn main() {
    let runtime = Runtime::new(SuperConfig::default()).expect("default runtime");
    let names = (0..1_000).map(|index| format!("node-{index}")).collect();
    let options = ProbeOptions {
        url: Some("http://127.0.0.1:1/generate_204".to_string()),
        timeout_ms: Some(500),
        concurrency: Some(50),
        names: Some(names),
    };
    let start = Instant::now();
    let count = black_box(runtime.probe_target_count(black_box(&options)));
    println!("probe scheduler 1000 requested nodes: {:?} (count={count})", start.elapsed());
}
