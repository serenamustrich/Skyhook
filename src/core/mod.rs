use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, RwLock},
    time::Instant,
};

use anyhow::{anyhow, Context};
use rustls::{crypto::aws_lc_rs, ClientConfig, RootCertStore};
use rustls_pki_types::ServerName;
use serde::Serialize;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    sync::Semaphore,
    task::JoinSet,
    time::{sleep, timeout, Duration},
};
use tokio_rustls::TlsConnector;
use url::Url;

use crate::{
    background_tasks::BackgroundScheduler,
    config::{OutboundConfig, SmartRouteRule, SuperConfig},
    inbound::native_tun_metrics::NativeTunMetrics,
    l3::{L3Manager, L3Snapshot, L3TunnelStatus},
    outbound::{build_outbounds, BoxedStream, Outbound, OutboundMap},
    routing::{Destination, RouteDecision, Router},
    runtime_state::RuntimeStateStore,
    smart::{self, DirectProbeRequest, SmartRecommendationAction, SmartRuleEngine, SmartSnapshot},
    subscription_store::SubscriptionStore,
    telemetry::{ConnectionSubscription, OutboundHealth, Telemetry},
    traffic_store::TrafficStore,
};

pub struct Runtime {
    base_config: RwLock<SuperConfig>,
    state: RwLock<RuntimeState>,
    smart_rules: Arc<SmartRuleEngine>,
    direct_probe_limit: Arc<Semaphore>,
    l3_manager: L3Manager,
    telemetry: Arc<Telemetry>,
    tun_metrics: NativeTunMetrics,
    runtime_state: Arc<RuntimeStateStore>,
    background_scheduler: Arc<BackgroundScheduler>,
    traffic_store: Arc<TrafficStore>,
}

struct RuntimeState {
    config: SuperConfig,
    router: Router,
    outbounds: OutboundMap,
}

#[derive(Debug, Clone, Serialize)]
pub struct TunReloadResult {
    pub ok: bool,
    pub changed: bool,
    pub requires_restart: bool,
    pub warnings: Vec<String>,
    pub details: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProbeResult {
    pub name: String,
    pub kind: String,
    pub success: bool,
    pub latency_ms: Option<u64>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProxyGroupSnapshot {
    pub name: String,
    pub kind: String,
    pub auto_select: bool,
    pub selected_member: Option<String>,
    pub selection_reason: String,
    pub members: Vec<ProxyGroupMemberSnapshot>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProxyGroupMemberSnapshot {
    pub name: String,
    pub kind: String,
    pub healthy: bool,
    pub attempts: u64,
    pub successes: u64,
    pub failures: u64,
    pub last_latency_ms: Option<u64>,
    pub last_error: Option<String>,
    pub score: Option<u8>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CountryGroupSnapshot {
    pub code: String,
    pub name: String,
    pub node_count: usize,
    pub best_outbound: Option<String>,
    pub members: Vec<ProxyGroupMemberSnapshot>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OutboundCapabilitySnapshot {
    pub name: String,
    pub kind: String,
    pub tcp_supported: bool,
    pub udp_supported: bool,
    pub udp_mode: Option<String>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct ProbeOptions {
    pub url: Option<String>,
    pub timeout_ms: Option<u64>,
    pub concurrency: Option<usize>,
    pub include_unsupported: bool,
    pub include_failed: bool,
}

#[derive(Debug, Clone)]
struct ProbeTarget {
    destination: Destination,
    host_header: String,
    request_target: String,
}

impl Runtime {
    pub fn new(config: SuperConfig) -> anyhow::Result<Self> {
        Self::new_with_base(config.clone(), config)
    }

    pub fn new_with_base(base_config: SuperConfig, config: SuperConfig) -> anyhow::Result<Self> {
        let telemetry = Arc::new(Telemetry::default());
        let state = build_runtime_state(config, telemetry.clone())?;
        let smart_config = effective_smart_config(&state.config);
        let direct_probe_limit = Arc::new(Semaphore::new(sanitize_probe_concurrency(
            smart_config.direct_probe_concurrency,
        )));
        let smart_rules = Arc::new(SmartRuleEngine::new(smart_config));
        let l3_manager = L3Manager::new(&state.config);
        let tun_config = &state.config.tun;
        let tun_metrics = NativeTunMetrics::new(
            tun_config.enabled,
            format!("{:?}", tun_config.backend),
            tun_config.setup,
            tun_config.auto_route,
        );

        let state_path = dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".skyhook")
            .join("runtime-state.json");
        let runtime_state = Arc::new(RuntimeStateStore::new(&state_path));

        let background_scheduler = Arc::new(BackgroundScheduler::new_with_defaults());

        let traffic_path = dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".skyhook")
            .join("traffic.json");
        let traffic_store = Arc::new(TrafficStore::new(&traffic_path));

        Ok(Self {
            base_config: RwLock::new(base_config),
            state: RwLock::new(state),
            smart_rules,
            direct_probe_limit,
            l3_manager,
            telemetry,
            tun_metrics,
            runtime_state,
            background_scheduler,
            traffic_store,
        })
    }

    pub fn reload_config(&self, config: SuperConfig) -> anyhow::Result<SuperConfig> {
        let state = build_runtime_state(config, self.telemetry.clone())?;
        let config = state.config.clone();
        self.smart_rules
            .update_config(effective_smart_config(&state.config));
        self.l3_manager.reconcile_config(&state.config);
        *self
            .state
            .write()
            .map_err(|_| anyhow!("runtime state lock poisoned"))? = state;
        Ok(config)
    }

    pub fn base_config(&self) -> SuperConfig {
        self.base_config
            .read()
            .map(|config| config.clone())
            .unwrap_or_else(|_| SuperConfig::default())
    }

    pub fn set_base_config(&self, config: SuperConfig) -> anyhow::Result<()> {
        *self
            .base_config
            .write()
            .map_err(|_| anyhow!("runtime base config lock poisoned"))? = config;
        Ok(())
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

    pub fn background_scheduler(&self) -> &Arc<BackgroundScheduler> {
        &self.background_scheduler
    }

    pub fn traffic_store(&self) -> &Arc<TrafficStore> {
        &self.traffic_store
    }

    pub fn runtime_state_store(&self) -> &Arc<RuntimeStateStore> {
        &self.runtime_state
    }

    pub fn tun_metrics(&self) -> &NativeTunMetrics {
        &self.tun_metrics
    }

    pub fn native_tun_metrics(
        &self,
    ) -> crate::inbound::native_tun_metrics::NativeTunMetricsSnapshot {
        self.tun_metrics.snapshot()
    }

    pub fn tun_reload(&self, new_config: SuperConfig) -> TunReloadResult {
        let old_config = self.config();
        let mut changed = Vec::new();
        let mut warnings = Vec::new();
        let mut requires_restart = false;

        // Check route_exclude changes
        if old_config.tun.route_exclude_address != new_config.tun.route_exclude_address {
            changed.push("route_exclude_address".to_string());
        }

        // Check bypass changes
        if old_config.tun.bypass != new_config.tun.bypass {
            changed.push("bypass".to_string());
        }

        // Check MTU changes - requires restart
        if old_config.tun.mtu != new_config.tun.mtu {
            changed.push("mtu".to_string());
            requires_restart = true;
            warnings.push("MTU change requires TUN restart".to_string());
        }

        // Check interface name changes - requires restart
        if old_config.tun.name != new_config.tun.name {
            changed.push("name".to_string());
            requires_restart = true;
            warnings.push("Interface name change requires TUN restart".to_string());
        }

        // Check setup changes
        if old_config.tun.setup != new_config.tun.setup {
            changed.push("setup".to_string());
        }

        // Check auto_route changes
        if old_config.tun.auto_route != new_config.tun.auto_route {
            changed.push("auto_route".to_string());
            requires_restart = true;
            warnings.push("auto_route change requires TUN restart".to_string());
        }

        // Check inet4_route_address changes
        if old_config.tun.inet4_route_address != new_config.tun.inet4_route_address {
            changed.push("inet4_route_address".to_string());
        }

        // Check inet6_route_address changes
        if old_config.tun.inet6_route_address != new_config.tun.inet6_route_address {
            changed.push("inet6_route_address".to_string());
        }

        // Check l3_profile changes - requires restart
        if old_config.tun.l3_profile != new_config.tun.l3_profile {
            changed.push("l3_profile".to_string());
            requires_restart = true;
            warnings.push("l3_profile change requires TUN restart".to_string());
        }

        if changed.is_empty() {
            return TunReloadResult {
                ok: true,
                changed: false,
                requires_restart: false,
                warnings: Vec::new(),
                details: "No changes detected".to_string(),
            };
        }

        // If requires restart, don't apply changes
        if requires_restart {
            return TunReloadResult {
                ok: true,
                changed: true,
                requires_restart: true,
                warnings,
                details: format!(
                    "Changes detected in: {}. Restart required.",
                    changed.join(", ")
                ),
            };
        }

        // Apply hot-reloadable changes
        match self.reload_config(new_config) {
            Ok(_) => TunReloadResult {
                ok: true,
                changed: true,
                requires_restart: false,
                warnings,
                details: format!("Reloaded: {}", changed.join(", ")),
            },
            Err(e) => TunReloadResult {
                ok: false,
                changed: true,
                requires_restart: false,
                warnings: vec![format!("Reload failed: {}", e)],
                details: format!("Failed to reload: {}", e),
            },
        }
    }

    pub async fn open_connection_record(
        &self,
        inbound: &'static str,
        destination: Destination,
        outbound: String,
        matched_rule: Option<String>,
        protocol: crate::telemetry::Protocol,
    ) -> uuid::Uuid {
        self.telemetry
            .open_connection(
                inbound,
                destination,
                outbound,
                self.active_subscription_context(),
                matched_rule,
                protocol,
            )
            .await
    }

    pub async fn close_connection_record(&self, id: uuid::Uuid) {
        let Some(record) = self.telemetry.close_connection(id).await else {
            return;
        };
        let duration_ms = record
            .closed_at
            .unwrap_or_else(chrono::Utc::now)
            .signed_duration_since(record.started_at)
            .num_milliseconds()
            .max(0);
        self.telemetry
            .log(
                "info",
                format!(
                    "connection closed id={} target={} outbound={} up={} down={} duration={}ms rule={}",
                    record.id,
                    record.destination.authority(),
                    record.outbound,
                    record.uploaded,
                    record.downloaded,
                    duration_ms,
                    record.matched_rule.as_deref().unwrap_or("-")
                ),
            )
            .await;
        self.traffic_store
            .add_global_traffic(record.uploaded, record.downloaded);
        self.traffic_store.add_outbound_traffic(
            &record.outbound,
            record.uploaded,
            record.downloaded,
        );
        let Some(subscription) = record.subscription else {
            return;
        };
        self.traffic_store.add_subscription_traffic(
            &subscription.id,
            record.uploaded,
            record.downloaded,
        );
        let store = SubscriptionStore::new(self.base_config().subscriptions.store_path);
        if let Err(error) = store.add_traffic(&subscription.id, record.uploaded, record.downloaded)
        {
            self.telemetry
                .log(
                    "warn",
                    format!(
                        "failed to persist traffic for subscription {}: {error}",
                        subscription.id
                    ),
                )
                .await;
        }
    }

    pub fn smart_snapshot(&self) -> SmartSnapshot {
        self.smart_rules.snapshot()
    }

    pub fn smart_record_direct_probe(
        &self,
        value: &str,
        target: crate::config::RuleTarget,
        success: bool,
        latency_ms: u64,
    ) {
        self.smart_rules
            .record_direct_probe(value, target, success, latency_ms);
    }

    pub fn upsert_smart_rule(&self, rule: SmartRouteRule) -> anyhow::Result<Vec<SmartRouteRule>> {
        let has_outbound = self
            .state
            .read()
            .map_err(|_| anyhow!("runtime state lock poisoned"))?
            .outbounds
            .contains_key(&rule.outbound);
        if !has_outbound {
            return Err(anyhow!(
                "smart rule references undefined outbound '{}'",
                rule.outbound
            ));
        }
        Ok(self.smart_rules.upsert_rule(rule))
    }

    pub fn set_smart_rule_enabled(
        &self,
        target: crate::config::RuleTarget,
        value: &str,
        enabled: bool,
    ) -> anyhow::Result<Vec<SmartRouteRule>> {
        self.smart_rules.set_rule_enabled(target, value, enabled)
    }

    pub fn delete_smart_rule(
        &self,
        target: crate::config::RuleTarget,
        value: &str,
    ) -> anyhow::Result<Vec<SmartRouteRule>> {
        self.smart_rules.delete_rule(target, value)
    }

    pub fn apply_smart_recommendations(
        &self,
        action: Option<SmartRecommendationAction>,
    ) -> Vec<SmartRouteRule> {
        self.smart_rules.apply_recommendations(action)
    }

    pub fn apply_smart_recommendation(
        &self,
        target: crate::config::RuleTarget,
        value: &str,
    ) -> anyhow::Result<Vec<SmartRouteRule>> {
        self.smart_rules.apply_recommendation(target, value)
    }

    pub fn add_rule(
        &self,
        target: crate::config::RuleTarget,
        value: &str,
        outbound: &str,
    ) -> anyhow::Result<Vec<crate::config::RouteRule>> {
        let has_outbound = self
            .state
            .read()
            .map_err(|_| anyhow!("runtime state lock poisoned"))?
            .outbounds
            .contains_key(outbound);
        if !has_outbound {
            return Err(anyhow!("rule references undefined outbound '{}'", outbound));
        }
        let mut config = self.config();
        config.rules.push(crate::config::RouteRule {
            target,
            value: value.to_string(),
            outbound: outbound.to_string(),
        });
        self.reload_config(config.clone())?;
        Ok(config.rules)
    }

    pub fn delete_rule(&self, index: usize) -> anyhow::Result<Vec<crate::config::RouteRule>> {
        let mut config = self.config();
        if index >= config.rules.len() {
            return Err(anyhow!(
                "rule index {} out of range (total {})",
                index,
                config.rules.len()
            ));
        }
        config.rules.remove(index);
        self.reload_config(config.clone())?;
        Ok(config.rules)
    }

    pub fn reorder_rules(
        &self,
        from: usize,
        to: usize,
    ) -> anyhow::Result<Vec<crate::config::RouteRule>> {
        let mut config = self.config();
        let len = config.rules.len();
        if from >= len {
            return Err(anyhow!("from index {} out of range (total {})", from, len));
        }
        if to >= len {
            return Err(anyhow!("to index {} out of range (total {})", to, len));
        }
        if from == to {
            return Ok(config.rules);
        }
        let rule = config.rules.remove(from);
        config.rules.insert(to, rule);
        self.reload_config(config.clone())?;
        Ok(config.rules)
    }

    pub fn decide(&self, destination: &Destination) -> RouteDecision {
        if let Some(decision) = self.smart_rules.decide(destination) {
            return decision;
        }
        match self.state.read() {
            Ok(state) => state.router.decide(destination),
            Err(_) => RouteDecision {
                outbound: "direct".to_string(),
                matched_rule: None,
                source: crate::routing::RouteDecisionSource::Default,
            },
        }
    }

    pub async fn connect_outbound(
        &self,
        destination: &Destination,
    ) -> anyhow::Result<(BoxedStream, RouteDecision, String)> {
        let (decision, outbound, connect_timeout_ms) = {
            let state = self
                .state
                .read()
                .map_err(|_| anyhow!("runtime state lock poisoned"))?;
            let decision = if let Some(decision) = self.smart_rules.decide(destination) {
                decision
            } else {
                state.router.decide(destination)
            };
            let outbound = state
                .outbounds
                .get(&decision.outbound)
                .cloned()
                .ok_or_else(|| anyhow!("selected outbound '{}' is missing", decision.outbound))?;
            (decision, outbound, state.config.core.connect_timeout_ms)
        };
        let outbound_name = outbound.name().to_string();
        let outbound_kind = outbound.kind().to_string();
        let started = Instant::now();
        match outbound.connect(destination, connect_timeout_ms).await {
            Ok(stream) => {
                let latency_ms = started.elapsed().as_millis() as u64;
                self.telemetry
                    .record_outbound_result(
                        outbound_name.clone(),
                        outbound_kind.clone(),
                        true,
                        Some(latency_ms),
                        None,
                    )
                    .await;
                self.telemetry
                    .log(
                        "info",
                        format!(
                            "route ok target={} outbound={} actual={} kind={} source={:?} rule={} latency={}ms",
                            destination.authority(),
                            decision.outbound,
                            outbound_name,
                            outbound_kind,
                            decision.source,
                            decision.matched_rule.as_deref().unwrap_or("-"),
                            latency_ms
                        ),
                    )
                    .await;
                if self
                    .smart_rules
                    .record_connect_success(destination, &decision, latency_ms)
                    == DirectProbeRequest::Needed
                {
                    self.spawn_direct_probe(destination.clone());
                }
                Ok((stream, decision, outbound_name))
            }
            Err(error) => {
                let latency_ms = started.elapsed().as_millis() as u64;
                let error_text = error.to_string();
                self.telemetry
                    .record_outbound_result(
                        outbound_name.clone(),
                        outbound_kind.clone(),
                        false,
                        Some(latency_ms),
                        Some(error_text.clone()),
                    )
                    .await;
                self.telemetry
                    .log(
                        "warn",
                        format!(
                            "route failed target={} outbound={} actual={} kind={} source={:?} rule={} latency={}ms error={}",
                            destination.authority(),
                            decision.outbound,
                            outbound_name,
                            outbound_kind,
                            decision.source,
                            decision.matched_rule.as_deref().unwrap_or("-"),
                            latency_ms,
                            error_text
                        ),
                    )
                    .await;
                self.smart_rules
                    .record_connect_failure(destination, &decision);
                Err(error)
            }
        }
    }

    pub async fn connect_named_outbound(
        &self,
        outbound_name: &str,
        destination: &Destination,
    ) -> anyhow::Result<BoxedStream> {
        let (outbound, connect_timeout_ms) = {
            let state = self
                .state
                .read()
                .map_err(|_| anyhow!("runtime state lock poisoned"))?;
            let outbound = state
                .outbounds
                .get(outbound_name)
                .cloned()
                .ok_or_else(|| anyhow!("outbound '{}' not found", outbound_name))?;
            (outbound, state.config.core.connect_timeout_ms)
        };

        let kind = outbound.kind().to_string();
        let started = Instant::now();
        match outbound.connect(destination, connect_timeout_ms).await {
            Ok(stream) => {
                let latency_ms = started.elapsed().as_millis() as u64;
                self.telemetry
                    .record_outbound_result(
                        outbound_name.to_string(),
                        kind.clone(),
                        true,
                        Some(latency_ms),
                        None,
                    )
                    .await;
                Ok(stream)
            }
            Err(error) => {
                let latency_ms = started.elapsed().as_millis() as u64;
                self.telemetry
                    .record_outbound_result(
                        outbound_name.to_string(),
                        kind,
                        false,
                        Some(latency_ms),
                        Some(error.to_string()),
                    )
                    .await;
                Err(error)
            }
        }
    }

    pub async fn udp_exchange_named_outbound(
        &self,
        outbound_name: &str,
        destination: &Destination,
        payload: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        let (outbound, timeout_ms) = {
            let state = self
                .state
                .read()
                .map_err(|_| anyhow!("runtime state lock poisoned"))?;
            let outbound = state
                .outbounds
                .get(outbound_name)
                .cloned()
                .ok_or_else(|| anyhow!("outbound '{}' not found", outbound_name))?;
            (outbound, state.config.core.connect_timeout_ms)
        };

        outbound
            .udp_exchange(destination, payload, timeout_ms)
            .await
    }

    pub async fn resolve_group_member(&self, group_name: &str) -> anyhow::Result<String> {
        let state = self
            .state
            .read()
            .map_err(|_| anyhow!("runtime state lock poisoned"))?;

        let group_config = state
            .config
            .outbounds
            .iter()
            .find(|o| o.name() == group_name)
            .ok_or_else(|| anyhow!("group '{}' not found", group_name))?;

        let members = match group_config {
            crate::config::OutboundConfig::Group { members, .. } => members.clone(),
            _ => return Err(anyhow!("'{}' is not a group", group_name)),
        };

        let health = self.telemetry.outbound_health_sync();

        let mut candidates: Vec<(&String, Option<u64>)> = members
            .iter()
            .map(|m| {
                let latency = health
                    .iter()
                    .find(|h| h.name == *m)
                    .and_then(|h| h.last_latency_ms);
                (m, latency)
            })
            .collect();

        candidates.sort_by_key(|(_, latency)| latency.unwrap_or(u64::MAX));

        candidates
            .first()
            .map(|(name, _)| (*name).clone())
            .ok_or_else(|| anyhow!("group '{}' has no members", group_name))
    }

    pub async fn resolve_country_best(&self, code: &str) -> anyhow::Result<String> {
        let config = self.config();
        let probe_timeout_ms = config.core.probe_timeout_ms;
        let health_vec = self.telemetry.outbound_health().await;
        let health: std::collections::HashMap<String, crate::telemetry::OutboundHealth> =
            health_vec
                .into_iter()
                .map(|h| (h.name.clone(), h))
                .collect();
        let groups = country_groups_from_config(&config, &health);

        let group = groups
            .iter()
            .find(|g| g.code.eq_ignore_ascii_case(code))
            .ok_or_else(|| anyhow!("country group '{}' not found", code))?;

        let best = group
            .members
            .iter()
            .filter(|m| m.healthy)
            .filter(|m| m.last_latency_ms.unwrap_or(u64::MAX) <= probe_timeout_ms)
            .min_by_key(|m| m.last_latency_ms.unwrap_or(u64::MAX))
            .or_else(|| group.members.first())
            .ok_or_else(|| anyhow!("country group '{}' has no members", code))?;

        Ok(best.name.clone())
    }

    pub fn outbound_health_sync(&self) -> Vec<crate::telemetry::OutboundHealth> {
        self.telemetry.outbound_health_sync()
    }

    pub async fn exchange_udp(
        &self,
        inbound: &'static str,
        destination: Destination,
        payload: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        let (decision, outbound, connect_timeout_ms) = {
            let state = self
                .state
                .read()
                .map_err(|_| anyhow!("runtime state lock poisoned"))?;
            let decision = if let Some(decision) = self.smart_rules.decide(&destination) {
                decision
            } else {
                state.router.decide(&destination)
            };
            let outbound = state
                .outbounds
                .get(&decision.outbound)
                .cloned()
                .ok_or_else(|| anyhow!("selected outbound '{}' is missing", decision.outbound))?;
            (decision, outbound, state.config.core.connect_timeout_ms)
        };
        let outbound_name = outbound.name().to_string();
        let outbound_kind = outbound.kind().to_string();
        let id = self
            .open_connection_record(
                inbound,
                destination.clone(),
                outbound_name.clone(),
                decision.matched_rule.clone(),
                crate::telemetry::Protocol::Udp,
            )
            .await;
        let started = Instant::now();
        let result = outbound
            .udp_exchange(&destination, payload, connect_timeout_ms)
            .await;
        let latency_ms = started.elapsed().as_millis() as u64;
        match result {
            Ok(response) => {
                self.telemetry
                    .record_outbound_result(
                        outbound_name.clone(),
                        outbound_kind.clone(),
                        true,
                        Some(latency_ms),
                        None,
                    )
                    .await;
                self.telemetry
                    .add_transfer(
                        id,
                        payload.len() as u64,
                        response.len() as u64,
                        crate::telemetry::Protocol::Udp,
                        &outbound_name,
                    )
                    .await;
                self.telemetry
                    .log(
                        "info",
                        format!(
                            "udp route ok target={} outbound={} actual={} kind={} source={:?} rule={} latency={}ms bytes_up={} bytes_down={}",
                            destination.authority(),
                            decision.outbound,
                            outbound_name,
                            outbound_kind,
                            decision.source,
                            decision.matched_rule.as_deref().unwrap_or("-"),
                            latency_ms,
                            payload.len(),
                            response.len()
                        ),
                    )
                    .await;
                self.close_connection_record(id).await;
                Ok(response)
            }
            Err(error) => {
                let error_text = error.to_string();
                self.telemetry
                    .record_outbound_result(
                        outbound_name.clone(),
                        outbound_kind.clone(),
                        false,
                        Some(latency_ms),
                        Some(error_text.clone()),
                    )
                    .await;
                self.telemetry
                    .log(
                        "warn",
                        format!(
                            "udp route failed target={} outbound={} actual={} kind={} source={:?} rule={} latency={}ms error={}",
                            destination.authority(),
                            decision.outbound,
                            outbound_name,
                            outbound_kind,
                            decision.source,
                            decision.matched_rule.as_deref().unwrap_or("-"),
                            latency_ms,
                            error_text
                        ),
                    )
                    .await;
                self.close_connection_record(id).await;
                Err(error)
            }
        }
    }

    pub async fn probe_all_outbounds(&self) -> Vec<ProbeResult> {
        self.probe_all_outbounds_with(ProbeOptions::default()).await
    }

    pub fn l3_snapshot(&self) -> L3Snapshot {
        self.l3_manager.snapshot()
    }

    pub fn collect_l3_endpoints(&self) -> Vec<String> {
        let snapshot = self.l3_manager.snapshot();
        snapshot
            .profiles
            .iter()
            .filter_map(|p| p.endpoint.clone())
            .collect()
    }

    pub fn is_l3_profile(&self, name: &str) -> bool {
        let snapshot = self.l3_manager.snapshot();
        snapshot.profiles.iter().any(|p| p.name == name)
    }

    pub fn is_proxy_group(&self, name: &str) -> bool {
        let config = self.config();
        config.outbounds.iter().any(|o| {
            matches!(o, crate::config::OutboundConfig::Group { name: group_name, .. } if group_name == name)
        })
    }

    pub async fn is_country_group(&self, name: &str) -> bool {
        let config = self.config();
        let health_vec = self.telemetry.outbound_health().await;
        let health: HashMap<String, OutboundHealth> = health_vec
            .into_iter()
            .map(|h| (h.name.clone(), h))
            .collect();
        let country_groups = country_groups_from_config(&config, &health);
        country_groups.iter().any(|g| g.code == name)
    }

    pub async fn send_l3_ip_packet(
        &self,
        profile: &str,
        packet: Vec<u8>,
    ) -> crate::l3::L3PacketSubmitResult {
        self.l3_manager.send_ip_packet(profile, packet).await
    }

    pub fn subscribe_l3_ip_packets(
        &self,
        profile: &str,
    ) -> anyhow::Result<tokio::sync::broadcast::Receiver<crate::l3::L3Packet>> {
        self.l3_manager.subscribe_ip_packets(profile)
    }

    pub async fn start_l3_all(&self) -> Vec<L3TunnelStatus> {
        self.l3_manager.start_all().await
    }

    pub async fn stop_l3_all(&self) -> Vec<L3TunnelStatus> {
        self.l3_manager.stop_all().await
    }

    pub async fn start_l3(&self, name: &str) -> L3TunnelStatus {
        self.l3_manager.start(name).await
    }

    pub fn stop_l3(&self, name: &str) -> L3TunnelStatus {
        self.l3_manager.stop(name)
    }

    pub async fn proxy_groups(&self) -> Vec<ProxyGroupSnapshot> {
        let config = self.config();
        let health = self
            .telemetry
            .outbound_health()
            .await
            .into_iter()
            .map(|item| (item.name.clone(), item))
            .collect::<HashMap<_, _>>();
        let kinds = config
            .outbounds
            .iter()
            .map(|item| (item.name().to_string(), outbound_config_kind(item)))
            .collect::<HashMap<_, _>>();

        config
            .outbounds
            .iter()
            .filter_map(|item| {
                let OutboundConfig::Group {
                    name,
                    kind,
                    members,
                } = item
                else {
                    return None;
                };
                let auto_select = group_kind_is_auto_select(kind);
                let member_snapshots = members
                    .iter()
                    .map(|member| group_member_snapshot(member, &kinds, &health))
                    .collect::<Vec<_>>();
                let (selected_member, selection_reason) =
                    select_group_member(kind, &member_snapshots);
                Some(ProxyGroupSnapshot {
                    name: name.clone(),
                    kind: kind.clone(),
                    auto_select,
                    selected_member,
                    selection_reason,
                    members: member_snapshots,
                })
            })
            .collect()
    }

    pub async fn country_groups(&self) -> Vec<CountryGroupSnapshot> {
        let config = self.config();
        let health = self
            .telemetry
            .outbound_health()
            .await
            .into_iter()
            .map(|item| (item.name.clone(), item))
            .collect::<HashMap<_, _>>();
        country_groups_from_config(&config, &health)
    }

    pub fn outbound_capabilities(&self) -> Vec<OutboundCapabilitySnapshot> {
        self.config()
            .outbounds
            .iter()
            .map(outbound_capability_snapshot)
            .collect()
    }

    pub fn use_outbound(&self, name: &str) -> anyhow::Result<SuperConfig> {
        let mut config = self.config();
        let has_outbound = config.outbounds.iter().any(|item| item.name() == name);
        if !has_outbound {
            return Err(anyhow!("outbound {name} does not exist"));
        }
        config.core.default_outbound = name.to_string();
        for rule in &mut config.rules {
            if rule.target == crate::config::RuleTarget::Match {
                rule.outbound = name.to_string();
            }
        }
        self.reload_config(config)
    }

    pub async fn use_country_group(&self, code: &str) -> anyhow::Result<SuperConfig> {
        let code = code.to_ascii_uppercase();
        let mut config = self.config();
        let health = self
            .telemetry
            .outbound_health()
            .await
            .into_iter()
            .map(|item| (item.name.clone(), item))
            .collect::<HashMap<_, _>>();
        let groups = country_groups_from_config(&config, &health);
        let group = groups
            .into_iter()
            .find(|group| group.code.eq_ignore_ascii_case(&code))
            .ok_or_else(|| anyhow!("country group {code} has no nodes"))?;
        let group_name = format!("country:{}", group.code);
        let members = group
            .members
            .iter()
            .map(|member| member.name.clone())
            .collect::<Vec<_>>();
        if let Some(existing) = config
            .outbounds
            .iter_mut()
            .find(|item| item.name() == group_name)
        {
            *existing = OutboundConfig::Group {
                name: group_name.clone(),
                kind: "url-test".to_string(),
                members,
            };
        } else {
            config.outbounds.push(OutboundConfig::Group {
                name: group_name.clone(),
                kind: "url-test".to_string(),
                members,
            });
        }
        config.core.default_outbound = group_name;
        self.reload_config(config)
    }

    pub async fn probe_all_outbounds_with(&self, options: ProbeOptions) -> Vec<ProbeResult> {
        let health = self
            .telemetry
            .outbound_health()
            .await
            .into_iter()
            .map(|item| (item.name.clone(), item))
            .collect::<HashMap<_, _>>();
        let (probe_url, probe_timeout_ms, probe_concurrency, outbounds) = {
            let state = match self.state.read() {
                Ok(state) => state,
                Err(_) => return Vec::new(),
            };
            let failure_threshold = state.config.core.probe_failure_threshold.max(1);
            let include_unsupported =
                options.include_unsupported || !state.config.core.probe_only_supported;
            (
                options
                    .url
                    .unwrap_or_else(|| state.config.core.probe_url.clone()),
                sanitize_probe_timeout_ms(
                    options
                        .timeout_ms
                        .unwrap_or(state.config.core.probe_timeout_ms),
                ),
                sanitize_probe_concurrency(
                    options
                        .concurrency
                        .unwrap_or(state.config.core.probe_concurrency),
                ),
                state
                    .outbounds
                    .values()
                    .filter(|outbound| outbound.kind() != "reject")
                    .filter(|outbound| {
                        include_unsupported
                            || !matches!(outbound.kind(), "unsupported-protocol" | "l3-tunnel")
                    })
                    .filter(|outbound| {
                        if options.include_failed {
                            return true;
                        }
                        health
                            .get(outbound.name())
                            .map(|item| {
                                !(item.last_error.is_some()
                                    && item.failures >= failure_threshold
                                    && item.successes == 0)
                            })
                            .unwrap_or(true)
                    })
                    .cloned()
                    .collect::<Vec<_>>(),
            )
        };
        let target = match ProbeTarget::from_url(&probe_url) {
            Ok(target) => target,
            Err(error) => {
                self.telemetry
                    .log("warn", format!("invalid probe url: {error:#}"))
                    .await;
                return outbounds
                    .into_iter()
                    .map(|outbound| ProbeResult {
                        name: outbound.name().to_string(),
                        kind: outbound.kind().to_string(),
                        success: false,
                        latency_ms: None,
                        error: Some(format!("invalid probe url: {error:#}")),
                    })
                    .collect();
            }
        };

        let mut jobs = JoinSet::new();
        let mut pending = outbounds.into_iter();
        for _ in 0..probe_concurrency {
            let Some(outbound) = pending.next() else {
                break;
            };
            spawn_probe_job(
                &mut jobs,
                outbound,
                target.clone(),
                probe_timeout_ms,
                self.telemetry.clone(),
            );
        }

        let mut results = Vec::new();
        while let Some(result) = jobs.join_next().await {
            match result {
                Ok(probe) => results.push(probe),
                Err(error) => results.push(ProbeResult {
                    name: "unknown".to_string(),
                    kind: "unknown".to_string(),
                    success: false,
                    latency_ms: None,
                    error: Some(format!("probe task failed: {error}")),
                }),
            }
            if let Some(outbound) = pending.next() {
                spawn_probe_job(
                    &mut jobs,
                    outbound,
                    target.clone(),
                    probe_timeout_ms,
                    self.telemetry.clone(),
                );
            }
        }
        results.sort_by(|lhs, rhs| lhs.name.cmp(&rhs.name));
        results
    }

    fn spawn_direct_probe(&self, destination: Destination) {
        let Ok(permit) = self.direct_probe_limit.clone().try_acquire_owned() else {
            return;
        };
        let engine = self.smart_rules.clone();
        let timeout_ms = self
            .state
            .read()
            .map(|state| {
                sanitize_probe_timeout_ms(state.config.smart_rules.direct_probe_timeout_ms)
            })
            .unwrap_or(500);
        tokio::spawn(async move {
            let _permit = permit;
            let outcome = smart::probe_direct_tcp(destination.clone(), timeout_ms).await;
            engine.record_direct_probe_result(&destination, outcome);
        });
    }

    pub async fn background_probe_loop(self: Arc<Self>) {
        let interval_secs = self
            .state
            .read()
            .map(|state| state.config.core.probe_interval_secs)
            .unwrap_or(0);
        if interval_secs == 0 {
            return;
        }

        sleep(Duration::from_secs(1)).await;
        loop {
            let results = self
                .probe_all_outbounds_with(ProbeOptions {
                    include_failed: false,
                    include_unsupported: false,
                    ..ProbeOptions::default()
                })
                .await;
            let ok_count = results.iter().filter(|item| item.success).count();
            self.telemetry
                .log(
                    "info",
                    format!(
                        "probe complete: {ok_count}/{} outbounds healthy",
                        results.len()
                    ),
                )
                .await;
            sleep(Duration::from_secs(interval_secs)).await;
        }
    }

    pub async fn tunnel(
        &self,
        inbound: &'static str,
        destination: Destination,
        client: TcpStream,
    ) -> anyhow::Result<()> {
        let (remote, decision, outbound_name) = self.connect_outbound(&destination).await?;
        let id = self
            .open_connection_record(
                inbound,
                destination.clone(),
                outbound_name.clone(),
                decision.matched_rule.clone(),
                crate::telemetry::Protocol::Tcp,
            )
            .await;
        self.telemetry
            .log(
                "info",
                format!(
                    "connection opened inbound={} target={} actual={} selected={} source={:?} rule={}",
                    inbound,
                    destination.authority(),
                    outbound_name,
                    decision.outbound,
                    decision.source,
                    decision.matched_rule.as_deref().unwrap_or("-")
                ),
            )
            .await;

        let result = relay_bidirectional(
            self.telemetry.clone(),
            id,
            client,
            remote,
            &outbound_name,
            crate::telemetry::Protocol::Tcp,
        )
        .await;
        self.close_connection_record(id).await;
        result
    }

    pub async fn exchange_dns_over_tcp(&self, query: &[u8]) -> anyhow::Result<Vec<u8>> {
        if query.len() > u16::MAX as usize {
            return Err(anyhow!("dns query is too large"));
        }
        let config = self.config();
        if !config.dns.enabled {
            return Err(anyhow!("dns proxy is disabled"));
        }
        match dns_upstream(&config) {
            DnsUpstream::Https(url) => {
                timeout(Duration::from_millis(config.dns.timeout_ms), async {
                    let client = reqwest::Client::builder()
                        .build()
                        .context("failed to build doh client")?;
                    let response = client
                        .post(url)
                        .header("accept", "application/dns-message")
                        .header("content-type", "application/dns-message")
                        .body(query.to_vec())
                        .send()
                        .await?
                        .error_for_status()?
                        .bytes()
                        .await?;
                    Ok::<_, anyhow::Error>(response.to_vec())
                })
                .await
                .map_err(|_| anyhow!("doh query timed out after {}ms", config.dns.timeout_ms))?
            }
            DnsUpstream::Tls { host, port, sni } => {
                timeout(Duration::from_millis(config.dns.timeout_ms), async {
                    let tcp = TcpStream::connect((host.as_str(), port))
                        .await
                        .with_context(|| format!("failed to connect dot upstream {host}:{port}"))?;
                    let connector = TlsConnector::from(Arc::new(dns_tls_client_config()?));
                    let server_name = ServerName::try_from(sni.clone())
                        .map_err(|error| anyhow!("invalid dot server name: {error}"))?;
                    let mut stream = connector
                        .connect(server_name, tcp)
                        .await
                        .context("dot tls handshake failed")?;
                    let mut framed = Vec::with_capacity(query.len() + 2);
                    framed.extend_from_slice(&(query.len() as u16).to_be_bytes());
                    framed.extend_from_slice(query);
                    stream.write_all(&framed).await?;

                    let mut len = [0u8; 2];
                    stream.read_exact(&mut len).await?;
                    let response_len = u16::from_be_bytes(len) as usize;
                    let mut response = vec![0u8; response_len];
                    stream.read_exact(&mut response).await?;
                    Ok::<_, anyhow::Error>(response)
                })
                .await
                .map_err(|_| anyhow!("dot query timed out after {}ms", config.dns.timeout_ms))?
            }
            DnsUpstream::Plain(destination) => {
                timeout(Duration::from_millis(config.dns.timeout_ms), async {
                    let (mut stream, _decision, _outbound_name) =
                        self.connect_outbound(&destination).await?;
                    let mut framed = Vec::with_capacity(query.len() + 2);
                    framed.extend_from_slice(&(query.len() as u16).to_be_bytes());
                    framed.extend_from_slice(query);
                    stream.write_all(&framed).await?;

                    let mut len = [0u8; 2];
                    stream.read_exact(&mut len).await?;
                    let response_len = u16::from_be_bytes(len) as usize;
                    let mut response = vec![0u8; response_len];
                    stream.read_exact(&mut response).await?;
                    Ok::<_, anyhow::Error>(response)
                })
                .await
                .map_err(|_| anyhow!("dns over tcp timed out after {}ms", config.dns.timeout_ms))?
            }
        }
    }
}

enum DnsUpstream {
    Plain(Destination),
    Https(String),
    Tls {
        host: String,
        port: u16,
        sni: String,
    },
}

fn dns_upstream(config: &SuperConfig) -> DnsUpstream {
    config
        .dns
        .nameserver
        .iter()
        .chain(config.dns.default_nameserver.iter())
        .find_map(|item| parse_dns_upstream(item))
        .unwrap_or_else(|| {
            DnsUpstream::Plain(Destination::new(
                config.dns.server.ip().to_string(),
                config.dns.server.port(),
            ))
        })
}

fn parse_dns_upstream(value: &str) -> Option<DnsUpstream> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    if let Ok(url) = Url::parse(value) {
        let scheme = url.scheme().to_ascii_lowercase();
        if matches!(scheme.as_str(), "https" | "doh") {
            let mut url = url;
            if scheme == "doh" {
                url.set_scheme("https").ok()?;
            }
            return Some(DnsUpstream::Https(url.to_string()));
        }
        if matches!(scheme.as_str(), "tls" | "dot") {
            let host = url.host_str()?.trim_matches(['[', ']']).to_string();
            let port = url.port().unwrap_or(853);
            let sni = url
                .query_pairs()
                .find_map(|(key, value)| {
                    matches!(key.as_ref(), "sni" | "servername").then(|| value.into_owned())
                })
                .unwrap_or_else(|| host.clone());
            return Some(DnsUpstream::Tls { host, port, sni });
        }
    }
    parse_dns_plain_destination(value).map(DnsUpstream::Plain)
}

fn parse_dns_plain_destination(value: &str) -> Option<Destination> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    if let Ok(addr) = value.parse::<std::net::SocketAddr>() {
        return Some(Destination::new(addr.ip().to_string(), addr.port()));
    }
    if let Ok(url) = Url::parse(value) {
        let scheme = url.scheme().to_ascii_lowercase();
        if !matches!(scheme.as_str(), "udp" | "tcp" | "dns") {
            return None;
        }
        let host = url.host_str()?.trim_matches(['[', ']']).to_string();
        let port = url.port().unwrap_or(53);
        return Some(Destination::new(host, port));
    }
    let (host, port) = value
        .rsplit_once(':')
        .and_then(|(host, port)| port.parse::<u16>().ok().map(|port| (host, port)))
        .unwrap_or((value, 53));
    Some(Destination::new(host.trim_matches(['[', ']']), port))
}

fn dns_tls_client_config() -> anyhow::Result<ClientConfig> {
    let provider = aws_lc_rs::default_provider();
    let builder = ClientConfig::builder_with_provider(provider.into())
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])?;
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut config = builder.with_root_certificates(roots).with_no_client_auth();
    config.alpn_protocols.clear();
    Ok(config)
}

impl Runtime {
    fn active_subscription_context(&self) -> Option<ConnectionSubscription> {
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

fn build_runtime_state(
    config: SuperConfig,
    telemetry: Arc<Telemetry>,
) -> anyhow::Result<RuntimeState> {
    let outbounds = build_outbounds(&config.outbounds, Some(telemetry))?;
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

fn effective_smart_config(config: &SuperConfig) -> crate::config::SmartRulesConfig {
    let mut smart_config = config.smart_rules.clone();
    if smart_config.proxy_outbound.is_none()
        && config.core.default_outbound != smart_config.direct_outbound
    {
        smart_config.proxy_outbound = Some(config.core.default_outbound.clone());
    }
    smart_config
}

fn sanitize_probe_timeout_ms(value: u64) -> u64 {
    value.clamp(1, 60_000)
}

fn sanitize_probe_concurrency(value: usize) -> usize {
    value.clamp(1, 1024)
}

fn spawn_probe_job(
    jobs: &mut JoinSet<ProbeResult>,
    outbound: Arc<dyn Outbound>,
    target: ProbeTarget,
    timeout_ms: u64,
    telemetry: Arc<Telemetry>,
) {
    jobs.spawn(async move { probe_one(outbound, target, timeout_ms, telemetry).await });
}

fn outbound_config_kind(config: &OutboundConfig) -> String {
    match config {
        OutboundConfig::Direct { .. } => "direct".to_string(),
        OutboundConfig::Reject { .. } => "reject".to_string(),
        OutboundConfig::Http { .. } => "http".to_string(),
        OutboundConfig::Socks5 { .. } => "socks5".to_string(),
        OutboundConfig::Shadowsocks { .. } => "shadowsocks".to_string(),
        OutboundConfig::Trojan { .. } => "trojan".to_string(),
        OutboundConfig::Vmess { .. } => "vmess".to_string(),
        OutboundConfig::Vless { .. } => "vless".to_string(),
        OutboundConfig::Hysteria2 { .. } => "hysteria2".to_string(),
        OutboundConfig::Tuic { .. } => "tuic".to_string(),
        OutboundConfig::Naive { .. } => "naive".to_string(),
        OutboundConfig::Ssr { .. } => "ssr".to_string(),
        OutboundConfig::Snell { .. } => "snell".to_string(),
        OutboundConfig::Hysteria { .. } => "hysteria".to_string(),
        OutboundConfig::AnyTls { .. } => "anytls".to_string(),
        OutboundConfig::ShadowTls { .. } => "shadowtls".to_string(),
        OutboundConfig::WireGuard { .. } => "wireguard".to_string(),
        OutboundConfig::Ssh { .. } => "ssh".to_string(),
        OutboundConfig::Mieru { .. } => "mieru".to_string(),
        OutboundConfig::Juicity { .. } => "juicity".to_string(),
        OutboundConfig::Masque { .. } => "masque".to_string(),
        OutboundConfig::OpenVpn { .. } => "openvpn".to_string(),
        OutboundConfig::Unknown { protocol, .. } => format!("unknown:{protocol}"),
        OutboundConfig::Group { kind, .. } => format!("group:{kind}"),
    }
}

fn outbound_capability_snapshot(config: &OutboundConfig) -> OutboundCapabilitySnapshot {
    let mut limitations = Vec::new();
    let (tcp_supported, udp_supported, udp_mode) = match config {
        OutboundConfig::Direct { .. } => (true, true, Some("native".to_string())),
        OutboundConfig::Reject { .. } => {
            limitations.push("reject outbound intentionally blocks traffic".to_string());
            (false, false, None)
        }
        OutboundConfig::Http { .. } => {
            limitations.push("http proxy udp is not supported".to_string());
            (true, false, None)
        }
        OutboundConfig::Socks5 { .. } => (
            true,
            true,
            Some("socks5-udp-associate-session-pool".to_string()),
        ),
        OutboundConfig::Shadowsocks { plugin, .. } => {
            if plugin.is_some() {
                limitations.push("shadowsocks simple-obfs udp is not supported".to_string());
                (true, false, None)
            } else {
                (
                    true,
                    true,
                    Some("shadowsocks-aead-udp-socket-pool".to_string()),
                )
            }
        }
        OutboundConfig::Trojan { .. } => (
            true,
            true,
            Some("trojan-udp-associate-stream-pool".to_string()),
        ),
        OutboundConfig::Vmess { .. } => (
            true,
            true,
            Some("vmess-command-udp-session-pool".to_string()),
        ),
        OutboundConfig::Vless {
            security,
            reality_public_key,
            ..
        } => {
            if security
                .as_deref()
                .map(|value| value.eq_ignore_ascii_case("reality"))
                .unwrap_or(false)
            {
                if reality_public_key
                    .as_deref()
                    .unwrap_or("")
                    .trim()
                    .is_empty()
                {
                    limitations.push("vless reality public key is missing".to_string());
                }
                (
                    true,
                    true,
                    Some("vless-reality-command-udp-session-pool".to_string()),
                )
            } else {
                (
                    true,
                    true,
                    Some("vless-command-udp-session-pool".to_string()),
                )
            }
        }
        OutboundConfig::Hysteria2 { obfs, .. } => {
            let obfs = obfs
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(|value| value.to_ascii_lowercase());
            if obfs.is_some() && !matches!(obfs.as_deref(), Some("salamander" | "gecko")) {
                limitations.push("unsupported hysteria2 obfuscation mode".to_string());
                (false, false, None)
            } else {
                let mode = match obfs.as_deref() {
                    Some("salamander") => "quic-datagram-salamander-session-pool",
                    Some("gecko") => "quic-datagram-gecko-session-pool",
                    _ => "quic-datagram-session-pool",
                };
                (true, true, Some(mode.to_string()))
            }
        }
        OutboundConfig::Tuic { udp_relay_mode, .. } => (
            true,
            true,
            Some(format!(
                "{}-session-pool",
                udp_relay_mode.as_deref().unwrap_or("native")
            )),
        ),
        OutboundConfig::Naive { .. } => {
            limitations.push("naive udp is not supported".to_string());
            (true, false, Some("tls-http-connect".to_string()))
        }
        OutboundConfig::Ssr {
            method,
            protocol,
            obfs,
            ..
        } => {
            let method_supported = matches!(
                method.to_ascii_lowercase().as_str(),
                "aes-128-cfb" | "aes-192-cfb" | "aes-256-cfb"
            );
            let protocol_supported = matches!(protocol.to_ascii_lowercase().as_str(), "origin");
            let obfs_supported = matches!(
                obfs.to_ascii_lowercase().as_str(),
                "plain" | "" | "http" | "http_simple" | "http_post" | "http-post"
            );
            if !method_supported {
                limitations.push(format!("unsupported ssr method {method}"));
            }
            if !protocol_supported {
                limitations.push(format!("unsupported ssr protocol {protocol}"));
            }
            if !obfs_supported {
                limitations.push(format!("unsupported ssr obfs {obfs}"));
            }
            limitations.push("ssr udp is not supported".to_string());
            (
                method_supported && protocol_supported && obfs_supported,
                false,
                Some("ssr-origin-cfb-tcp-http-obfs".to_string()),
            )
        }
        OutboundConfig::Snell { method, obfs, .. } => {
            let method = method.as_deref().unwrap_or("aes-128-gcm");
            let method_supported = matches!(
                method.to_ascii_lowercase().as_str(),
                "aes-128-gcm" | "aes-256-gcm" | "chacha20-ietf-poly1305" | "chacha20-poly1305"
            );
            let obfs_supported = obfs
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(|value| {
                    matches!(
                        value.to_ascii_lowercase().as_str(),
                        "http"
                            | "http_simple"
                            | "obfs-http"
                            | "simple-obfs-http"
                            | "tls"
                            | "tls1.2_ticket_auth"
                            | "obfs-tls"
                            | "simple-obfs-tls"
                    )
                })
                .unwrap_or(true);
            if !method_supported {
                limitations.push(format!("unsupported snell method {method}"));
            }
            if !obfs_supported {
                limitations.push("snell unknown obfs is not supported".to_string());
            }
            limitations.push("snell udp is tunneled over tcp".to_string());
            (
                method_supported && obfs_supported,
                method_supported && obfs_supported,
                Some("snell-aead-tcp-udp-http-tls-obfs".to_string()),
            )
        }
        OutboundConfig::Hysteria {
            auth,
            auth_str,
            obfs,
            ..
        } => {
            let auth_present = auth
                .as_deref()
                .map(str::trim)
                .is_some_and(|v| !v.is_empty())
                || auth_str
                    .as_deref()
                    .map(str::trim)
                    .is_some_and(|v| !v.is_empty());
            if !auth_present {
                limitations.push("hysteria auth or auth_str is required".to_string());
            }
            let obfs_present = obfs
                .as_deref()
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .is_some();
            if obfs_present {
                limitations.push("hysteria obfs is not implemented yet".to_string());
            }
            (
                auth_present && !obfs_present,
                auth_present && !obfs_present,
                Some("quic-hysteria-tcp-udp".to_string()),
            )
        }
        OutboundConfig::AnyTls { .. } => {
            limitations.push("anytls udp is not supported".to_string());
            (true, false, Some("tls-anytls-session".to_string()))
        }
        OutboundConfig::ShadowTls { version, .. } => {
            let version_supported = version.unwrap_or(3) == 3;
            if !version_supported {
                limitations.push("only shadowtls v3 is supported".to_string());
            }
            limitations.push("shadowtls udp is not supported".to_string());
            limitations.push("standalone shadowtls uses socks-address target handoff".to_string());
            (
                version_supported,
                false,
                Some("shadowtls-v3-tcp-transport".to_string()),
            )
        }
        OutboundConfig::WireGuard { .. } => l3_tunnel_capability("wireguard", &mut limitations),
        OutboundConfig::Ssh { .. } => {
            limitations.push("ssh udp is not supported".to_string());
            (true, false, Some("ssh-direct-tcpip".to_string()))
        }
        OutboundConfig::Mieru { .. } => unsupported_protocol_capability("mieru", &mut limitations),
        OutboundConfig::Juicity { .. } => {
            unsupported_protocol_capability("juicity", &mut limitations)
        }
        OutboundConfig::Masque { .. } => {
            unsupported_protocol_capability("masque", &mut limitations)
        }
        OutboundConfig::OpenVpn { .. } => l3_tunnel_capability("openvpn", &mut limitations),
        OutboundConfig::Unknown { protocol, .. } => {
            unsupported_protocol_capability(protocol, &mut limitations)
        }
        OutboundConfig::Group { kind, .. } => (true, true, Some(format!("group-{kind}-delegated"))),
    };
    OutboundCapabilitySnapshot {
        name: config.name().to_string(),
        kind: outbound_config_kind(config),
        tcp_supported,
        udp_supported,
        udp_mode,
        limitations,
    }
}

fn unsupported_protocol_capability(
    protocol: &str,
    limitations: &mut Vec<String>,
) -> (bool, bool, Option<String>) {
    limitations.push(format!(
        "{protocol} is recognized in config/subscriptions but native dialing is not implemented yet"
    ));
    (false, false, None)
}

fn l3_tunnel_capability(
    protocol: &str,
    limitations: &mut Vec<String>,
) -> (bool, bool, Option<String>) {
    let detail = match protocol {
        "wireguard" => {
            "wireguard runs through the native L3 manager with a WireGuard Noise packet engine; it is not a per-connection stream adapter"
        }
        "openvpn" => {
            "openvpn is registered in the L3 manager while native OpenVPN TLS/control/data channels are being built; it is not a per-connection stream adapter"
        }
        _ => {
            "this protocol is controlled by the L3 manager and is not a per-connection stream adapter"
        }
    };
    limitations.push(detail.to_string());
    (false, false, Some("l3-tunnel-manager".to_string()))
}

fn group_member_snapshot(
    member: &str,
    kinds: &HashMap<String, String>,
    health: &HashMap<String, OutboundHealth>,
) -> ProxyGroupMemberSnapshot {
    let health = health.get(member);
    ProxyGroupMemberSnapshot {
        name: member.to_string(),
        kind: kinds
            .get(member)
            .cloned()
            .unwrap_or_else(|| "unknown".to_string()),
        healthy: health
            .map(|item| item.successes > 0 && item.last_error.is_none())
            .unwrap_or(false),
        attempts: health.map(|item| item.attempts).unwrap_or(0),
        successes: health.map(|item| item.successes).unwrap_or(0),
        failures: health.map(|item| item.failures).unwrap_or(0),
        last_latency_ms: health.and_then(|item| item.last_latency_ms),
        last_error: health.and_then(|item| item.last_error.clone()),
        score: health.map(|item| item.score),
    }
}

fn select_group_member(
    kind: &str,
    members: &[ProxyGroupMemberSnapshot],
) -> (Option<String>, String) {
    if members.is_empty() {
        return (None, "empty group".to_string());
    }
    let kind = kind.to_ascii_lowercase();
    if !group_kind_is_auto_select(&kind) {
        return (
            members.first().map(|item| item.name.clone()),
            "manual group uses first configured member until the client selects a member"
                .to_string(),
        );
    }

    match kind.as_str() {
        "fallback" => {
            if let Some(best) = members.iter().find(|item| item.healthy) {
                return (
                    Some(best.name.clone()),
                    "first healthy member in configured fallback order".to_string(),
                );
            }
        }
        "load-balance" => {
            if let Some(best) = members
                .iter()
                .filter(|item| item.healthy)
                .max_by_key(|item| {
                    (
                        item.score.unwrap_or(0),
                        std::cmp::Reverse(item.failures),
                        std::cmp::Reverse(item.last_latency_ms.unwrap_or(u64::MAX)),
                    )
                })
            {
                return (
                    Some(best.name.clone()),
                    "highest health score from telemetry".to_string(),
                );
            }
        }
        _ => {
            if let Some(best) = members
                .iter()
                .filter(|item| item.healthy)
                .min_by_key(|item| {
                    (
                        item.last_latency_ms.unwrap_or(u64::MAX),
                        100u8 - item.score.unwrap_or(0),
                    )
                })
            {
                return (
                    Some(best.name.clone()),
                    "lowest healthy latency from telemetry".to_string(),
                );
            }
        }
    }

    (
        members.first().map(|item| item.name.clone()),
        "no healthy telemetry yet; fallback to first configured member".to_string(),
    )
}

fn group_kind_is_auto_select(kind: &str) -> bool {
    matches!(
        kind.to_ascii_lowercase().as_str(),
        "select" | "url-test" | "fallback" | "load-balance" | "auto" | "latency"
    )
}

fn country_groups_from_config(
    config: &SuperConfig,
    health: &HashMap<String, OutboundHealth>,
) -> Vec<CountryGroupSnapshot> {
    let kinds = config
        .outbounds
        .iter()
        .map(|item| (item.name().to_string(), outbound_config_kind(item)))
        .collect::<HashMap<_, _>>();
    let mut grouped: HashMap<String, (String, Vec<ProxyGroupMemberSnapshot>)> = HashMap::new();
    for outbound in &config.outbounds {
        if matches!(
            outbound,
            OutboundConfig::Direct { .. }
                | OutboundConfig::Reject { .. }
                | OutboundConfig::Group { .. }
        ) {
            continue;
        }
        let Some((code, name)) = country_for_outbound(outbound) else {
            continue;
        };
        grouped
            .entry(code.to_string())
            .or_insert_with(|| (name.to_string(), Vec::new()))
            .1
            .push(group_member_snapshot(outbound.name(), &kinds, health));
    }

    let mut groups = grouped
        .into_iter()
        .map(|(code, (name, mut members))| {
            members.sort_by(|lhs, rhs| {
                lhs.last_latency_ms
                    .unwrap_or(u64::MAX)
                    .cmp(&rhs.last_latency_ms.unwrap_or(u64::MAX))
                    .then_with(|| rhs.score.unwrap_or(0).cmp(&lhs.score.unwrap_or(0)))
                    .then_with(|| lhs.name.cmp(&rhs.name))
            });
            let best_outbound = members
                .iter()
                .find(|member| member.healthy)
                .or_else(|| members.first())
                .map(|member| member.name.clone());
            CountryGroupSnapshot {
                code,
                name,
                node_count: members.len(),
                best_outbound,
                members,
            }
        })
        .collect::<Vec<_>>();
    groups.sort_by(|lhs, rhs| lhs.code.cmp(&rhs.code));
    groups
}

fn country_for_outbound(outbound: &OutboundConfig) -> Option<(&'static str, &'static str)> {
    let mut haystack = outbound.name().to_string();
    if let Some(server) = outbound_server(outbound) {
        haystack.push(' ');
        haystack.push_str(server);
    }
    detect_country(&haystack)
}

fn outbound_server(outbound: &OutboundConfig) -> Option<&str> {
    match outbound {
        OutboundConfig::Http { server, .. }
        | OutboundConfig::Socks5 { server, .. }
        | OutboundConfig::Shadowsocks { server, .. }
        | OutboundConfig::Trojan { server, .. }
        | OutboundConfig::Vmess { server, .. }
        | OutboundConfig::Vless { server, .. }
        | OutboundConfig::Hysteria2 { server, .. }
        | OutboundConfig::Tuic { server, .. }
        | OutboundConfig::Naive { server, .. }
        | OutboundConfig::Ssr { server, .. }
        | OutboundConfig::Snell { server, .. }
        | OutboundConfig::Hysteria { server, .. }
        | OutboundConfig::AnyTls { server, .. }
        | OutboundConfig::ShadowTls { server, .. }
        | OutboundConfig::WireGuard { server, .. }
        | OutboundConfig::Ssh { server, .. }
        | OutboundConfig::Mieru { server, .. }
        | OutboundConfig::Juicity { server, .. }
        | OutboundConfig::Masque { server, .. } => Some(server),
        OutboundConfig::Unknown { server, .. } => server.as_deref(),
        OutboundConfig::Direct { .. }
        | OutboundConfig::Reject { .. }
        | OutboundConfig::OpenVpn { .. }
        | OutboundConfig::Group { .. } => None,
    }
}

fn detect_country(value: &str) -> Option<(&'static str, &'static str)> {
    let lower = value.to_ascii_lowercase();
    let upper_tokens = value
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter(|item| !item.is_empty())
        .map(|item| item.to_ascii_uppercase())
        .collect::<Vec<_>>();
    let defs: &[(&str, &str, &[&str], &[&str])] = &[
        (
            "HK",
            "Hong Kong",
            &["香港", "港", "hong kong"],
            &["HK", "HKG"],
        ),
        (
            "JP",
            "Japan",
            &["日本", "东京", "大阪", "japan", "tokyo", "osaka"],
            &["JP", "JPN"],
        ),
        (
            "US",
            "United States",
            &[
                "美国",
                "美國",
                "洛杉矶",
                "洛杉磯",
                "西雅图",
                "纽约",
                "united states",
                "america",
                "los angeles",
                "new york",
                "seattle",
            ],
            &["US", "USA"],
        ),
        (
            "SG",
            "Singapore",
            &["新加坡", "狮城", "獅城", "singapore"],
            &["SG", "SGP"],
        ),
        (
            "TW",
            "Taiwan",
            &["台湾", "台灣", "台北", "taiwan", "taipei"],
            &["TW", "TWN"],
        ),
        (
            "KR",
            "South Korea",
            &["韩国", "韓國", "首尔", "首爾", "korea", "seoul"],
            &["KR", "KOR"],
        ),
        (
            "GB",
            "United Kingdom",
            &["英国", "英國", "伦敦", "倫敦", "united kingdom", "london"],
            &["GB", "UK"],
        ),
        (
            "DE",
            "Germany",
            &[
                "德国",
                "德國",
                "法兰克福",
                "法蘭克福",
                "germany",
                "frankfurt",
            ],
            &["DE", "DEU"],
        ),
        (
            "FR",
            "France",
            &["法国", "法國", "巴黎", "france", "paris"],
            &["FR", "FRA"],
        ),
        (
            "CA",
            "Canada",
            &["加拿大", "多伦多", "多倫多", "canada", "toronto"],
            &["CA", "CAN"],
        ),
        (
            "AU",
            "Australia",
            &["澳大利亚", "澳洲", "悉尼", "australia", "sydney"],
            &["AU", "AUS"],
        ),
        (
            "NL",
            "Netherlands",
            &["荷兰", "荷蘭", "netherlands", "amsterdam"],
            &["NL", "NLD"],
        ),
        (
            "RU",
            "Russia",
            &["俄罗斯", "俄羅斯", "russia", "moscow"],
            &["RU", "RUS"],
        ),
        ("IN", "India", &["印度", "india", "mumbai"], &["IN", "IND"]),
        (
            "TH",
            "Thailand",
            &["泰国", "泰國", "thailand", "bangkok"],
            &["TH", "THA"],
        ),
        ("VN", "Vietnam", &["越南", "vietnam"], &["VN", "VNM"]),
        (
            "TR",
            "Turkey",
            &["土耳其", "turkey", "istanbul"],
            &["TR", "TUR"],
        ),
    ];
    for (code, name, phrases, tokens) in defs {
        if phrases.iter().any(|phrase| lower.contains(phrase)) {
            return Some((code, name));
        }
        if tokens
            .iter()
            .any(|token| upper_tokens.iter().any(|item| item == token))
        {
            return Some((code, name));
        }
    }
    None
}

impl ProbeTarget {
    fn from_url(value: &str) -> anyhow::Result<Self> {
        let url = Url::parse(value)?;
        if url.scheme() != "http" {
            return Err(anyhow!("probe_url currently supports http only"));
        }
        let host = url
            .host_str()
            .ok_or_else(|| anyhow!("probe_url is missing host"))?
            .to_string();
        let port = url.port_or_known_default().unwrap_or(80);
        let host_header = match url.port() {
            Some(port) => format!("{host}:{port}"),
            None => host.clone(),
        };
        let request_target = match (url.path(), url.query()) {
            ("", None) => "/".to_string(),
            (path, None) => path.to_string(),
            (path, Some(query)) => format!("{path}?{query}"),
        };
        Ok(Self {
            destination: Destination::new(host, port),
            host_header,
            request_target,
        })
    }

    fn http_request(&self) -> Vec<u8> {
        format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: Skyhook/{}\r\nConnection: close\r\n\r\n",
            self.request_target,
            self.host_header,
            env!("CARGO_PKG_VERSION")
        )
        .into_bytes()
    }
}

async fn probe_one(
    outbound: Arc<dyn Outbound>,
    target: ProbeTarget,
    timeout_ms: u64,
    telemetry: Arc<Telemetry>,
) -> ProbeResult {
    let name = outbound.name().to_string();
    let kind = outbound.kind().to_string();
    let started = Instant::now();
    let result = timeout(Duration::from_millis(timeout_ms), async {
        let mut stream = outbound.connect(&target.destination, timeout_ms).await?;
        stream.write_all(&target.http_request()).await?;
        let mut data = [0u8; 512];
        let n = stream.read(&mut data).await?;
        if n == 0 {
            return Err(anyhow!("empty probe response"));
        }
        let status_line = std::str::from_utf8(&data[..n])
            .unwrap_or("")
            .lines()
            .next()
            .unwrap_or("");
        if probe_status_is_healthy(status_line) {
            Ok(())
        } else {
            Err(anyhow!("unhealthy probe response: {status_line}"))
        }
    })
    .await;

    let latency_ms = started.elapsed().as_millis() as u64;
    match result {
        Ok(Ok(())) => {
            telemetry
                .record_outbound_result(name.clone(), kind.clone(), true, Some(latency_ms), None)
                .await;
            ProbeResult {
                name,
                kind,
                success: true,
                latency_ms: Some(latency_ms),
                error: None,
            }
        }
        Ok(Err(error)) => {
            let error = error.to_string();
            telemetry
                .record_outbound_result(
                    name.clone(),
                    kind.clone(),
                    false,
                    Some(latency_ms),
                    Some(error.clone()),
                )
                .await;
            ProbeResult {
                name,
                kind,
                success: false,
                latency_ms: Some(latency_ms),
                error: Some(error),
            }
        }
        Err(_) => {
            let error = format!("probe timed out after {timeout_ms}ms");
            telemetry
                .record_outbound_result(
                    name.clone(),
                    kind.clone(),
                    false,
                    Some(timeout_ms),
                    Some(error.clone()),
                )
                .await;
            ProbeResult {
                name,
                kind,
                success: false,
                latency_ms: Some(timeout_ms),
                error: Some(error),
            }
        }
    }
}

fn probe_status_is_healthy(status_line: &str) -> bool {
    let mut parts = status_line.split_whitespace();
    let Some(version) = parts.next() else {
        return false;
    };
    if !version.starts_with("HTTP/") {
        return false;
    }
    let Some(status) = parts.next() else {
        return false;
    };
    status
        .parse::<u16>()
        .map(|code| (200..400).contains(&code))
        .unwrap_or(false)
}

async fn relay_bidirectional(
    telemetry: Arc<Telemetry>,
    id: uuid::Uuid,
    client: TcpStream,
    remote: BoxedStream,
    outbound: &str,
    protocol: crate::telemetry::Protocol,
) -> anyhow::Result<()> {
    let (mut client_read, mut client_write) = tokio::io::split(client);
    let (mut remote_read, mut remote_write) = tokio::io::split(remote);

    let ob = outbound.to_string();
    let upload = copy_counted(
        &mut client_read,
        &mut remote_write,
        telemetry.clone(),
        id,
        true,
        &ob,
        protocol,
    );
    let download = copy_counted(
        &mut remote_read,
        &mut client_write,
        telemetry,
        id,
        false,
        &ob,
        protocol,
    );
    tokio::select! {
        result = upload => result?,
        result = download => result?,
    }
    Ok(())
}

async fn copy_counted<R, W>(
    reader: &mut R,
    writer: &mut W,
    telemetry: Arc<Telemetry>,
    id: uuid::Uuid,
    upload: bool,
    outbound: &str,
    protocol: crate::telemetry::Protocol,
) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = [0u8; 16 * 1024];
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            let _ = writer.shutdown().await;
            return Ok(());
        }
        writer.write_all(&buf[..n]).await?;
        if upload {
            telemetry
                .add_transfer(id, n as u64, 0, protocol, outbound)
                .await;
        } else {
            telemetry
                .add_transfer(id, 0, n as u64, protocol, outbound)
                .await;
        }
    }
}
