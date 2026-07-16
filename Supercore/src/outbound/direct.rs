use std::time::Duration;

use anyhow::Context;
use async_trait::async_trait;
use tokio::{net::UdpSocket, time::timeout};

use crate::routing::Destination;

use super::{transports::connect_tcp, BoxedStream, Outbound, OutboundCapability};

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
        Ok(Box::new(
            connect_tcp(&destination.authority(), timeout_ms).await?,
        ))
    }

    async fn udp_exchange(
        &self,
        destination: &Destination,
        payload: &[u8],
        timeout_ms: u64,
    ) -> anyhow::Result<Vec<u8>> {
        let bind_addr = if destination.host.parse::<std::net::Ipv6Addr>().is_ok() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let socket = UdpSocket::bind(bind_addr).await.with_context(|| {
            format!("failed to bind udp socket for {}", destination.authority())
        })?;
        let target = destination_socket_addr(destination);
        timeout(
            Duration::from_millis(timeout_ms),
            socket.send_to(payload, target.as_str()),
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

fn destination_socket_addr(destination: &Destination) -> String {
    if destination.host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{}]:{}", destination.host, destination.port)
    } else {
        destination.authority()
    }
}
