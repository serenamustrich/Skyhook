use std::{collections::HashMap, sync::Arc};

use anyhow::anyhow;
use async_trait::async_trait;

use crate::{routing::Destination, telemetry::Telemetry};

use super::{context::DialContext, BoxedStream, Outbound, OutboundCapability};

pub(crate) struct GroupOutbound {
    name: String,
    kind: String,
    members: Vec<Arc<dyn Outbound>>,
    telemetry: Option<Arc<Telemetry>>,
}

impl GroupOutbound {
    pub(crate) fn new(
        name: String,
        kind: String,
        members: Vec<Arc<dyn Outbound>>,
        telemetry: Option<Arc<Telemetry>>,
    ) -> Self {
        Self {
            name,
            kind,
            members,
            telemetry,
        }
    }

    async fn ordered_members(&self) -> Vec<Arc<dyn Outbound>> {
        if !group_uses_health_order(&self.kind) {
            return self.members.clone();
        }
        let Some(telemetry) = &self.telemetry else {
            return self.members.clone();
        };
        let health = telemetry
            .outbound_health()
            .await
            .into_iter()
            .map(|item| (item.name.clone(), item))
            .collect::<HashMap<_, _>>();
        let mut indexed = self
            .members
            .iter()
            .enumerate()
            .map(|(index, member)| {
                let item = health.get(member.name());
                let healthy = item
                    .map(|health| health.successes > 0 && health.last_error.is_none())
                    .unwrap_or(false);
                let latency = item.and_then(|health| health.last_latency_ms);
                let score = item.map(|health| health.score);
                (index, healthy, latency, score, member.clone())
            })
            .collect::<Vec<_>>();
        indexed.sort_by(|lhs, rhs| {
            rhs.1
                .cmp(&lhs.1)
                .then_with(|| lhs.2.unwrap_or(u64::MAX).cmp(&rhs.2.unwrap_or(u64::MAX)))
                .then_with(|| rhs.3.unwrap_or(0).cmp(&lhs.3.unwrap_or(0)))
                .then_with(|| lhs.0.cmp(&rhs.0))
        });
        indexed
            .into_iter()
            .map(|(_, _, _, _, member)| member)
            .collect()
    }
}

#[async_trait]
impl Outbound for GroupOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "group"
    }

    fn capability(&self) -> OutboundCapability {
        let capabilities = self
            .members
            .iter()
            .map(|member| member.capability())
            .collect::<Vec<_>>();
        let tcp_supported = capabilities.iter().any(|item| item.tcp_supported);
        let udp_supported = capabilities.iter().any(|item| item.udp_supported);
        let mut limitations = Vec::new();
        if !tcp_supported {
            limitations.push("group has no TCP-capable members".to_string());
        }
        if !udp_supported {
            limitations.push("group has no UDP-capable members".to_string());
        }
        OutboundCapability {
            tcp_supported,
            udp_supported,
            udp_mode: udp_supported.then(|| format!("group-{}-delegated", self.kind)),
            limitations,
        }
    }

    async fn connect(
        &self,
        destination: &Destination,
        timeout_ms: u64,
    ) -> anyhow::Result<BoxedStream> {
        let context = DialContext::new(destination.clone(), timeout_ms);
        self.connect_context(&context).await
    }

    async fn connect_context(&self, context: &DialContext) -> anyhow::Result<BoxedStream> {
        let members = self.ordered_members().await;

        let mut errors = Vec::new();
        for member in members {
            match member.connect_context(context).await {
                Ok(stream) => return Ok(stream),
                Err(error) => errors.push(format!("{}: {error}", member.name())),
            }
        }
        Err(anyhow!(
            "group {} failed to connect via {}: {}",
            self.name,
            self.kind,
            errors.join("; ")
        ))
    }

    async fn udp_exchange(
        &self,
        destination: &Destination,
        payload: &[u8],
        timeout_ms: u64,
    ) -> anyhow::Result<Vec<u8>> {
        let context = DialContext::new(destination.clone(), timeout_ms);
        self.udp_exchange_context(&context, payload).await
    }

    async fn udp_exchange_context(
        &self,
        context: &DialContext,
        payload: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        let members = self.ordered_members().await;

        let mut errors = Vec::new();
        for member in members {
            match member.udp_exchange_context(context, payload).await {
                Ok(response) => return Ok(response),
                Err(error) => errors.push(format!("{}: {error}", member.name())),
            }
        }
        Err(anyhow!(
            "group {} failed to exchange udp via {}: {}",
            self.name,
            self.kind,
            errors.join("; ")
        ))
    }
}

fn group_uses_health_order(kind: &str) -> bool {
    matches!(
        kind.to_ascii_lowercase().as_str(),
        "select" | "url-test" | "fallback" | "load-balance" | "auto" | "latency"
    )
}
