use std::{hint::black_box, time::Instant};

use supercore::{config::FakeIpFilterMode, inbound::fakeip::FakeIpStore};

fn main() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    runtime.block_on(async {
        let store = FakeIpStore::new(300, Vec::new(), FakeIpFilterMode::Blacklist);
        let start = Instant::now();
        let mut checksum = 0u32;
        for index in 0..10_000 {
            if let Some(address) = store
                .lookup_or_create(black_box(&format!("node-{index}.example.com")))
                .await
            {
                checksum ^= u32::from(address);
            }
        }
        println!("fake-ip 10000 entries: {:?} (checksum={checksum})", start.elapsed());
    });
}
