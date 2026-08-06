use std::{hint::black_box, time::Instant};

use supercore::{outbound::encode_socks5_destination, routing::Destination};

fn main() {
    let destinations = (0..10_000)
        .map(|index| Destination::new(format!("edge-{index}.example.com"), 443))
        .collect::<Vec<_>>();
    let start = Instant::now();
    let mut bytes = 0usize;
    let mut encoded = Vec::with_capacity(256);
    for destination in &destinations {
        encoded.clear();
        encode_socks5_destination(black_box(destination), &mut encoded).expect("destination");
        bytes += black_box(&encoded).len();
    }
    println!("SOCKS5 destination framing 10000 addresses: {:?} (bytes={bytes})", start.elapsed());
}
