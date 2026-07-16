use anyhow::anyhow;
use async_trait::async_trait;

use crate::routing::Destination;

use super::{BoxedStream, Outbound};

pub(crate) struct UnsupportedProtocolOutbound {
    name: String,
    protocol: String,
}

impl UnsupportedProtocolOutbound {
    pub(crate) fn new(name: String, protocol: String) -> Self {
        Self { name, protocol }
    }
}

#[async_trait]
impl Outbound for UnsupportedProtocolOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "unsupported-protocol"
    }

    async fn connect(
        &self,
        _destination: &Destination,
        _timeout_ms: u64,
    ) -> anyhow::Result<BoxedStream> {
        Err(anyhow!(
            "protocol {} is recognized but native dialing is not implemented yet",
            self.protocol
        ))
    }
}
