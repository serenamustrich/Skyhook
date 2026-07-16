use std::{net::SocketAddr, time::Duration};

use anyhow::{anyhow, Context};
use tokio::{net::lookup_host, time::timeout};

use crate::outbound::{context::active_dial_context, transports::order_addresses};

pub(crate) async fn resolve_udp_socket_addr(
    host: &str,
    port: u16,
    timeout_ms: u64,
) -> anyhow::Result<SocketAddr> {
    let active = active_dial_context();
    let timeout_budget = active
        .as_ref()
        .map(|context| Duration::from_millis(timeout_ms).min(context.remaining_timeout()))
        .unwrap_or_else(|| Duration::from_millis(timeout_ms));
    if timeout_budget.is_zero() {
        return Err(anyhow!("udp target resolve deadline expired"));
    }
    let cancellation = active
        .as_ref()
        .map(|context| context.cancellation.clone())
        .unwrap_or_default();
    let strategy = active
        .as_ref()
        .map(|context| context.ip_version)
        .unwrap_or_default();
    let resolved = tokio::select! {
        _ = cancellation.cancelled() => return Err(anyhow!("udp target resolve cancelled")),
        result = timeout(timeout_budget, lookup_host((host, port))) => {
            result
                .context("udp target resolve timed out")?
                .with_context(|| format!("failed to resolve udp target {host}:{port}"))?
                .collect::<Vec<_>>()
        }
    };
    order_addresses(resolved, strategy)
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("udp target {host}:{port} resolved to no addresses"))
}
