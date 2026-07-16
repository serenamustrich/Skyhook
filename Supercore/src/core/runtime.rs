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
}

pub(super) struct RuntimeState {
    pub(super) config: SuperConfig,
    pub(super) router: Router,
    pub(super) outbounds: OutboundMap,
}
