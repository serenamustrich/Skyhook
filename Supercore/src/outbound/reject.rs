use anyhow::anyhow;
use async_trait::async_trait;

use crate::routing::Destination;

use super::{BoxedStream, Outbound};

pub(crate) struct RejectOutbound {
    name: String,
}

impl RejectOutbound {
    pub(crate) fn new(name: String) -> Self {
        Self { name }
    }
}

#[async_trait]
impl Outbound for RejectOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "reject"
    }

    async fn connect(
        &self,
        destination: &Destination,
        _timeout_ms: u64,
    ) -> anyhow::Result<BoxedStream> {
        Err(anyhow!(
            "rejected by outbound rule for {}",
            destination.authority()
        ))
    }
}
