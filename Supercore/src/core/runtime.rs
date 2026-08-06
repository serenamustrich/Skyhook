use std::sync::{Arc, RwLock};

use tokio_util::sync::CancellationToken;

use crate::{
    config::SuperConfig, inbound::fakeip::FakeIpStore, outbound::OutboundMap, routing::Router,
    smart::SmartRuleEngine, telemetry::Telemetry,
};

pub struct Runtime {
    pub(super) base_config: RwLock<SuperConfig>,
    pub(super) state: RwLock<RuntimeState>,
    pub(super) smart_rules: Arc<SmartRuleEngine>,
    pub(super) telemetry: Arc<Telemetry>,
    pub(super) fakeip_store: FakeIpStore,
    pub(super) shutdown: CancellationToken,
    pub(super) tun_status: RwLock<TunRuntimeStatus>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunRuntimeStatus {
    Disabled,
    Starting,
    Running,
    Failed(String),
}

impl TunRuntimeStatus {
    pub fn state(&self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Starting => "starting",
            Self::Running => "running",
            Self::Failed(_) => "failed",
        }
    }

    pub fn error(&self) -> Option<&str> {
        match self {
            Self::Failed(error) => Some(error),
            Self::Disabled | Self::Starting | Self::Running => None,
        }
    }
}

pub(super) struct RuntimeState {
    pub(super) config: SuperConfig,
    pub(super) router: Router,
    pub(super) outbounds: OutboundMap,
}
