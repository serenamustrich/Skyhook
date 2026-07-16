use std::time::Duration;

use anyhow::Context;
use tokio::{net::TcpStream, time::timeout};

pub(crate) async fn connect_tcp(addr: &str, timeout_ms: u64) -> anyhow::Result<TcpStream> {
    timeout(Duration::from_millis(timeout_ms), TcpStream::connect(addr))
        .await
        .context("tcp connect timed out")?
        .with_context(|| format!("failed to connect {addr}"))
}
