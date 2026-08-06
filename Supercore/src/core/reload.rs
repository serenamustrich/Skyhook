use std::sync::Arc;

use anyhow::anyhow;

use crate::{
    config::SuperConfig, outbound::build_outbounds_with_options_and_dns, routing::Router,
    telemetry::Telemetry,
};

use super::{Runtime, RuntimeState};

impl Runtime {
    pub fn reload_config(&self, config: SuperConfig) -> anyhow::Result<SuperConfig> {
        let next_state = build_runtime_state(config, self.telemetry.clone())?;
        let next_config = next_state.config.clone();
        let next_smart_config = effective_smart_config(&next_state.config);
        self.fakeip_store.reconfigure(
            next_state.config.dns.fake_ip_ttl as u64,
            next_state.config.dns.fake_ip_filter.clone(),
            next_state.config.dns.fake_ip_filter_mode,
        )?;

        let mut state = self
            .state
            .write()
            .map_err(|_| anyhow!("runtime state lock poisoned"))?;
        self.smart_rules.update_config(next_smart_config);
        *state = next_state;
        drop(state);

        self.telemetry.publish_event(
            "status_changed",
            serde_json::json!({
                "state": "running",
                "summary": next_config.summary(),
                "default_outbound": next_config.core.default_outbound,
                "outbounds": next_config.outbounds.len(),
                "rules": next_config.rules.len(),
            }),
        );
        Ok(next_config)
    }

    pub fn set_base_config(&self, config: SuperConfig) -> anyhow::Result<()> {
        *self
            .base_config
            .write()
            .map_err(|_| anyhow!("runtime base config lock poisoned"))? = config;
        Ok(())
    }
}

pub(super) fn build_runtime_state(
    config: SuperConfig,
    telemetry: Arc<Telemetry>,
) -> anyhow::Result<RuntimeState> {
    let outbounds = build_outbounds_with_options_and_dns(
        &config.outbounds,
        &config.outbound_options,
        Some(telemetry),
        Some(&config.dns),
    )?;
    if !outbounds.contains_key(&config.core.default_outbound) {
        return Err(anyhow!(
            "default outbound '{}' is not defined",
            config.core.default_outbound
        ));
    }
    for rule in &config.rules {
        if !outbounds.contains_key(&rule.outbound) {
            return Err(anyhow!(
                "rule references undefined outbound '{}'",
                rule.outbound
            ));
        }
    }
    if config.smart_rules.enabled {
        if !outbounds.contains_key(&config.smart_rules.direct_outbound) {
            return Err(anyhow!(
                "smart direct outbound '{}' is not defined",
                config.smart_rules.direct_outbound
            ));
        }
        if let Some(proxy_outbound) = &config.smart_rules.proxy_outbound {
            if !outbounds.contains_key(proxy_outbound) {
                return Err(anyhow!(
                    "smart proxy outbound '{}' is not defined",
                    proxy_outbound
                ));
            }
        }
        for rule in &config.smart_rules.rules {
            if !outbounds.contains_key(&rule.outbound) {
                return Err(anyhow!(
                    "smart rule references undefined outbound '{}'",
                    rule.outbound
                ));
            }
        }
    }
    let router = Router::new(
        config.rules.clone(),
        config.core.default_outbound.clone(),
        config.rule_sets.clone(),
        config.geoip_database.clone(),
        config.geoip.clone(),
    );
    Ok(RuntimeState {
        config,
        router,
        outbounds,
    })
}

pub(super) fn effective_smart_config(config: &SuperConfig) -> crate::config::SmartRulesConfig {
    let mut smart_config = config.smart_rules.clone();
    if smart_config.proxy_outbound.is_none()
        && config.core.default_outbound != smart_config.direct_outbound
    {
        smart_config.proxy_outbound = Some(config.core.default_outbound.clone());
    }
    smart_config
}

#[cfg(test)]
mod tests {
    use crate::config::SuperConfig;

    use super::Runtime;

    #[test]
    fn failed_reload_keeps_the_previous_runtime_state() {
        let runtime = Runtime::new(SuperConfig::default()).unwrap();
        let previous = runtime.config();
        let mut invalid = previous.clone();
        invalid.core.default_outbound = "missing-outbound".to_string();

        assert!(runtime.reload_config(invalid).is_err());
        let current = runtime.config();
        assert_eq!(
            current.core.default_outbound,
            previous.core.default_outbound
        );
        assert_eq!(current.outbounds.len(), previous.outbounds.len());
        assert_eq!(current.rules.len(), previous.rules.len());
    }
}
