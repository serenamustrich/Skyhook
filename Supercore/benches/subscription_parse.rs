use std::{hint::black_box, time::Instant};

use supercore::subscription::parse_subscription;

fn fixture() -> String {
    let mut output = String::from("proxies:\n");
    for index in 0..1_000 {
        output.push_str(&format!(
            "  - name: node-{index}\n    type: socks5\n    server: edge-{index}.example.com\n    port: 443\n"
        ));
    }
    output
}

fn main() {
    let text = fixture();
    let start = Instant::now();
    let document = black_box(parse_subscription(black_box(&text)).expect("subscription"));
    println!("subscription parse 1000 nodes: {:?} (nodes={})", start.elapsed(), document.nodes.len());
}
