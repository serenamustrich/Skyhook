use std::{net::SocketAddr, time::Duration};

use anyhow::{anyhow, Context};
use tokio::{net::lookup_host, time::timeout};

pub(crate) async fn resolve_udp_socket_addr(
    host: &str,
    port: u16,
    timeout_ms: u64,
) -> anyhow::Result<SocketAddr> {
    let mut resolved = timeout(Duration::from_millis(timeout_ms), lookup_host((host, port)))
        .await
        .context("udp target resolve timed out")?
        .with_context(|| format!("failed to resolve udp target {host}:{port}"))?;
    resolved
        .next()
        .ok_or_else(|| anyhow!("udp target {host}:{port} resolved to no addresses"))
}
