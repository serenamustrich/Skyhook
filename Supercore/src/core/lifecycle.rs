use std::sync::Arc;

use tokio_util::sync::CancellationToken;

use crate::{
    config::SuperConfig,
    inbound::fakeip::FakeIpStore,
    smart::SmartRuleEngine,
    subscription_store::SubscriptionStore,
    telemetry::{ConnectionSubscription, Telemetry},
};

use super::{
    reload::{build_runtime_state, effective_smart_config},
    Runtime,
};

impl Runtime {
    pub fn new(config: SuperConfig) -> anyhow::Result<Self> {
        Self::new_with_base(config.clone(), config)
    }

    pub fn new_with_base(base_config: SuperConfig, config: SuperConfig) -> anyhow::Result<Self> {
        let telemetry = Arc::new(Telemetry::default());
        let state = build_runtime_state(config, telemetry.clone())?;
        let smart_config = effective_smart_config(&state.config);
        let smart_rules = Arc::new(SmartRuleEngine::new(smart_config));
        let fakeip_store = FakeIpStore::new(
            state.config.dns.fake_ip_ttl as u64,
            state.config.dns.fake_ip_filter.clone(),
            state.config.dns.fake_ip_filter_mode,
        );
        Ok(Self {
            base_config: std::sync::RwLock::new(base_config),
            state: std::sync::RwLock::new(state),
            smart_rules,
            telemetry,
            fakeip_store,
            shutdown: CancellationToken::new(),
        })
    }

    pub fn base_config(&self) -> SuperConfig {
        self.base_config
            .read()
            .map(|config| config.clone())
            .unwrap_or_else(|_| SuperConfig::default())
    }

    pub fn config(&self) -> SuperConfig {
        self.state
            .read()
            .map(|state| state.config.clone())
            .unwrap_or_else(|_| SuperConfig::default())
    }

    pub fn telemetry(&self) -> Arc<Telemetry> {
        self.telemetry.clone()
    }

    pub fn fakeip_store(&self) -> &FakeIpStore {
        &self.fakeip_store
    }

    pub fn cancellation_token(&self) -> CancellationToken {
        self.shutdown.child_token()
    }

    pub fn is_shutting_down(&self) -> bool {
        self.shutdown.is_cancelled()
    }

    pub fn shutdown(&self) {
        if self.shutdown.is_cancelled() {
            return;
        }
        self.shutdown.cancel();
        self.telemetry
            .publish_event("status_changed", serde_json::json!({ "state": "stopping" }));
    }

    pub(super) fn active_subscription_context(&self) -> Option<ConnectionSubscription> {
        let base_config = self.base_config();
        let meta = SubscriptionStore::new(base_config.subscriptions.store_path)
            .active_meta()
            .ok()
            .flatten()?;
        Some(ConnectionSubscription {
            id: meta.id,
            name: meta.name,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio::time::{timeout, Duration};

    use crate::config::SuperConfig;

    use super::Runtime;

    #[tokio::test]
    async fn shutdown_cancels_children_and_background_probe_loop() {
        let mut config = SuperConfig::default();
        config.core.probe_interval_secs = 3_600;
        let runtime = Arc::new(Runtime::new(config).unwrap());
        let child = runtime.cancellation_token();
        let probe = tokio::spawn(runtime.clone().background_probe_loop());

        runtime.shutdown();

        assert!(runtime.is_shutting_down());
        assert!(child.is_cancelled());
        timeout(Duration::from_secs(1), probe)
            .await
            .expect("background probe loop should stop")
            .expect("background probe task should not panic");
    }
}
