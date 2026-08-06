use async_trait::async_trait;

use crate::routing::Destination;

use super::{BoxedStream, Outbound, OutboundCapability, RematchTarget};

pub(crate) struct RematchOutbound {
    name: String,
    target: RematchTarget,
}

impl RematchOutbound {
    pub(crate) fn new(
        name: String,
        target_rematch_name: Option<String>,
        target_sub_rule: Option<String>,
    ) -> anyhow::Result<Self> {
        let rematch_name = target_rematch_name
            .filter(|value| !value.trim().is_empty())
            .or_else(|| {
                target_sub_rule
                    .filter(|value| !value.trim().is_empty())
                    .map(|value| format!("sub-rule:{value}"))
            });
        if rematch_name.is_none() {
            return Err(anyhow::anyhow!(
                "rematch {name} requires target-rematch-name or target-sub-rule"
            ));
        }
        Ok(Self {
            name,
            target: RematchTarget { rematch_name },
        })
    }
}

#[async_trait]
impl Outbound for RematchOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "rematch"
    }

    fn capability(&self) -> OutboundCapability {
        OutboundCapability::tcp_udp("rule-control")
    }

    fn rematch_target(&self) -> Option<RematchTarget> {
        Some(self.target.clone())
    }

    async fn connect(
        &self,
        _destination: &Destination,
        _timeout_ms: u64,
    ) -> anyhow::Result<BoxedStream> {
        Err(anyhow::anyhow!(
            "rematch outbound is a rule-control hop and cannot carry traffic"
        ))
    }
}
