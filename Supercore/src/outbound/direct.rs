use std::time::Duration;

use anyhow::Context;
use async_trait::async_trait;
use tokio::time::timeout;

use crate::routing::Destination;

use super::{
    transports::connect_tcp,
    udp::{create_bound_udp, resolve_udp_socket_addr},
    BoxedStream, Outbound, OutboundCapability,
};

pub(crate) struct DirectOutbound {
    name: String,
}

impl DirectOutbound {
    pub(crate) fn new(name: String) -> Self {
        Self { name }
    }
}

#[async_trait]
impl Outbound for DirectOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "direct"
    }

    fn capability(&self) -> OutboundCapability {
        OutboundCapability::tcp_udp("native")
    }

    async fn connect(
        &self,
        destination: &Destination,
        timeout_ms: u64,
    ) -> anyhow::Result<BoxedStream> {
        connect_tcp(&destination.authority(), timeout_ms).await
    }

    async fn udp_exchange(
        &self,
        destination: &Destination,
        payload: &[u8],
        timeout_ms: u64,
    ) -> anyhow::Result<Vec<u8>> {
        let target = resolve_udp_socket_addr(&destination.host, destination.port, timeout_ms)
            .await
            .with_context(|| format!("failed to resolve {}", destination.authority()))?;
        let socket = create_bound_udp(target).with_context(|| {
            format!("failed to bind udp socket for {}", destination.authority())
        })?;
        timeout(
            Duration::from_millis(timeout_ms),
            socket.send_to(payload, target),
        )
        .await
        .context("udp send timed out")?
        .with_context(|| format!("failed to send udp packet to {target}"))?;
        let mut buf = vec![0u8; 65_535];
        let (len, _) = timeout(
            Duration::from_millis(timeout_ms),
            socket.recv_from(&mut buf),
        )
        .await
        .context("udp receive timed out")?
        .with_context(|| {
            format!(
                "failed to receive udp packet from {}",
                destination.authority()
            )
        })?;
        buf.truncate(len);
        Ok(buf)
    }
}
