use std::{hint::black_box, time::Instant};

use supercore::{
    config::{RouteRule, RuleTarget},
    routing::{Destination, Router},
};

fn main() {
    let rules = (0..1_000)
        .map(|index| RouteRule {
            target: RuleTarget::DomainSuffix,
            value: format!("edge-{index}.example.com"),
            outbound: "proxy".to_string(),
        })
        .collect();
    let router = Router::new(rules, "direct".to_string(), Vec::new(), None, Vec::new());
    let destination = Destination::new("cdn.edge-999.example.com", 443);
    let start = Instant::now();
    let mut checksum = 0usize;
    for _ in 0..10_000 {
        checksum ^= black_box(router.decide(black_box(&destination)).outbound.len());
    }
    println!("routing 1000 rules / 10000 decisions: {:?} (checksum={checksum})", start.elapsed());
}
