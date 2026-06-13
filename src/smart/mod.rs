use std::{
    collections::HashMap,
    fs,
    io::ErrorKind,
    path::Path,
    sync::{Mutex, RwLock},
    time::{Duration, Instant},
};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::{net::TcpStream, time::timeout};

use crate::{
    config::{RuleTarget, SmartRouteRule, SmartRulesConfig},
    routing::{target_matches, Destination, RouteDecision, RouteDecisionSource},
};

#[derive(Debug)]
pub struct SmartRuleEngine {
    config: RwLock<SmartRulesConfig>,
    rules: RwLock<Vec<SmartRouteRule>>,
    observations: RwLock<HashMap<String, SmartObservation>>,
    last_persist_instant: Mutex<Option<Instant>>,
    last_persist_error: RwLock<Option<String>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SmartSnapshot {
    pub enabled: bool,
    pub auto_probe: bool,
    pub auto_apply_recommendations: bool,
    pub direct_outbound: String,
    pub proxy_outbound: Option<String>,
    pub direct_probe_timeout_ms: u64,
    pub direct_probe_concurrency: usize,
    pub probe_cooldown_secs: u64,
    pub min_samples: u32,
    pub direct_success_min_ratio: f64,
    pub proxy_failure_min_ratio: f64,
    pub auto_apply_min_confidence: f64,
    pub direct_max_latency_ms: u64,
    pub state_path: String,
    pub persist_interval_secs: u64,
    pub max_observations: usize,
    pub last_persist_error: Option<String>,
    pub stats: SmartStats,
    pub rules: Vec<SmartRouteRule>,
    pub observations: Vec<SmartObservation>,
    pub recommendations: Vec<SmartRecommendation>,
    pub recommendation_buckets: SmartRecommendationBuckets,
}

#[derive(Debug, Clone, Serialize)]
pub struct SmartStats {
    pub observed_targets: usize,
    pub total_visits: u64,
    pub direct_probe_attempts: u64,
    pub direct_probe_successes: u64,
    pub direct_probe_failures: u64,
    pub direct_probe_success_ratio: f64,
    pub enabled_rules: usize,
    pub enabled_direct_rules: usize,
    pub enabled_proxy_rules: usize,
    pub recommended_direct_targets: usize,
    pub recommended_proxy_targets: usize,
    pub proxy_routed_targets: usize,
    pub proxy_routed_but_direct_available_targets: usize,
    pub proxy_routed_but_direct_available_ratio: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct SmartRecommendationBuckets {
    pub direct: Vec<SmartRecommendation>,
    pub proxy: Vec<SmartRecommendation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmartObservation {
    pub key: String,
    pub target: RuleTarget,
    pub value: String,
    pub visits: u64,
    pub direct_routed_hits: u64,
    pub proxy_routed_hits: u64,
    pub direct_probe_attempts: u64,
    pub direct_probe_successes: u64,
    pub direct_probe_failures: u64,
    pub last_outbound: Option<String>,
    pub last_direct_latency_ms: Option<u64>,
    pub last_error: Option<String>,
    pub last_seen_at: DateTime<Utc>,
    pub last_probe_at: Option<DateTime<Utc>>,
    #[serde(skip)]
    last_probe_instant: Option<Instant>,
    // New fields
    #[serde(default = "Utc::now")]
    pub first_seen_at: DateTime<Utc>,
    pub last_proxy_outbound: Option<String>,
    pub last_selected_group: Option<String>,
    pub last_selected_country: Option<String>,
    pub app_name: Option<String>,
    pub app_bundle_id: Option<String>,
    pub app_path: Option<String>,
    pub resolved_ip: Option<String>,
    pub sni: Option<String>,
    pub http_host: Option<String>,
    pub dns_name: Option<String>,
    pub proxy_success_count: u64,
    pub proxy_failure_count: u64,
    #[serde(default)]
    pub recommendation_state: RecommendationState,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum RecommendationState {
    #[default]
    Pending,
    Enabled,
    Ignored,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmartRecommendation {
    pub target: RuleTarget,
    pub value: String,
    pub recommended_outbound: String,
    pub action: SmartRecommendationAction,
    pub confidence: f64,
    pub reason: String,
    pub latency_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum SmartRecommendationAction {
    Direct,
    Proxy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SmartStateFile {
    version: u32,
    saved_at: DateTime<Utc>,
    rules: Vec<SmartRouteRule>,
    observations: Vec<SmartObservation>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectProbeRequest {
    Needed,
    NotNeeded,
}

#[derive(Debug, Clone)]
pub struct DirectProbeOutcome {
    pub success: bool,
    pub latency_ms: u64,
    pub error: Option<String>,
}

impl SmartRuleEngine {
    pub fn new(config: SmartRulesConfig) -> Self {
        let (rules, observations, last_persist_error) = load_state(&config);
        Self {
            rules: RwLock::new(rules),
            observations: RwLock::new(observations),
            last_persist_instant: Mutex::new(None),
            last_persist_error: RwLock::new(last_persist_error),
            config: RwLock::new(config),
        }
    }

    pub fn config(&self) -> SmartRulesConfig {
        self.config.read().expect("smart config lock").clone()
    }

    pub fn update_config(&self, config: SmartRulesConfig) {
        *self.config.write().expect("smart config lock") = config;
    }

    pub fn decide(&self, destination: &Destination) -> Option<RouteDecision> {
        let config = self.config();
        if !config.enabled {
            return None;
        }

        for rule in self.rules.read().expect("smart rules lock").iter() {
            if rule.enabled && target_matches(rule.target, &rule.value, destination) {
                return Some(RouteDecision {
                    outbound: rule.outbound.clone(),
                    matched_rule: Some(format!("Smart:{:?}:{}", rule.target, rule.value)),
                    source: RouteDecisionSource::Smart,
                });
            }
        }

        if !config.auto_apply_recommendations {
            return None;
        }

        let observations = self.observations.read().expect("smart observations lock");
        for (target, value) in observation_targets(destination) {
            let key = observation_key(target, &value);
            let Some(observation) = observations.get(&key) else {
                continue;
            };
            if let Some(recommendation) = self.recommendation_for(observation, true) {
                if recommendation.confidence < clamp_ratio(config.auto_apply_min_confidence) {
                    continue;
                }
                return Some(RouteDecision {
                    outbound: recommendation.recommended_outbound,
                    matched_rule: Some(format!("SmartAuto:{target:?}:{value}")),
                    source: RouteDecisionSource::Smart,
                });
            }
        }

        None
    }

    pub fn upsert_rule(&self, rule: SmartRouteRule) -> Vec<SmartRouteRule> {
        let rules = {
            let mut rules = self.rules.write().expect("smart rules lock");
            upsert_rule_locked(&mut rules, rule);
            rules.clone()
        };
        self.persist_state_force();
        rules
    }

    pub fn set_rule_enabled(
        &self,
        target: RuleTarget,
        value: &str,
        enabled: bool,
    ) -> anyhow::Result<Vec<SmartRouteRule>> {
        let value = normalized_value(target, value);
        let rules = {
            let mut rules = self.rules.write().expect("smart rules lock");
            let Some(rule) = rules.iter_mut().find(|item| {
                item.target == target && normalized_value(item.target, &item.value) == value
            }) else {
                return Err(anyhow::anyhow!(
                    "smart rule {:?}:{} does not exist",
                    target,
                    value
                ));
            };
            rule.enabled = enabled;
            rules.clone()
        };
        self.persist_state_force();
        Ok(rules)
    }

    pub fn delete_rule(
        &self,
        target: RuleTarget,
        value: &str,
    ) -> anyhow::Result<Vec<SmartRouteRule>> {
        let value = normalized_value(target, value);
        let rules = {
            let mut rules = self.rules.write().expect("smart rules lock");
            let before = rules.len();
            rules.retain(|item| {
                !(item.target == target && normalized_value(item.target, &item.value) == value)
            });
            if rules.len() == before {
                return Err(anyhow::anyhow!(
                    "smart rule {:?}:{} does not exist",
                    target,
                    value
                ));
            }
            rules.clone()
        };
        self.persist_state_force();
        Ok(rules)
    }

    pub fn apply_recommendations(
        &self,
        action: Option<SmartRecommendationAction>,
    ) -> Vec<SmartRouteRule> {
        let observations = self
            .observations
            .read()
            .expect("smart observations lock")
            .values()
            .cloned()
            .collect::<Vec<_>>();
        let recommendations = observations
            .iter()
            .filter_map(|item| self.recommendation_for(item, false))
            .filter(|item| {
                action
                    .as_ref()
                    .map(|action| action == &item.action)
                    .unwrap_or(true)
            })
            .collect::<Vec<_>>();

        let rules = {
            let mut rules = self.rules.write().expect("smart rules lock");
            for recommendation in recommendations {
                upsert_rule_locked(
                    &mut rules,
                    SmartRouteRule {
                        target: recommendation.target,
                        value: recommendation.value,
                        outbound: recommendation.recommended_outbound,
                        enabled: true,
                        note: Some(format!("smart recommendation: {}", recommendation.reason)),
                    },
                );
            }
            rules.clone()
        };
        self.persist_state_force();
        rules
    }

    pub fn apply_recommendation(
        &self,
        target: RuleTarget,
        value: &str,
    ) -> anyhow::Result<Vec<SmartRouteRule>> {
        let value = normalized_value(target, value);
        let recommendation = {
            let observations = self.observations.read().expect("smart observations lock");
            let key = observation_key(target, &value);
            let observation = observations
                .get(&key)
                .ok_or_else(|| anyhow::anyhow!("smart recommendation {key} does not exist"))?;
            self.recommendation_for(observation, false)
                .ok_or_else(|| anyhow::anyhow!("smart recommendation {key} is not actionable"))?
        };
        Ok(self.upsert_rule(SmartRouteRule {
            target: recommendation.target,
            value: recommendation.value,
            outbound: recommendation.recommended_outbound,
            enabled: true,
            note: Some(format!("smart recommendation: {}", recommendation.reason)),
        }))
    }

    pub fn record_connect_success(
        &self,
        destination: &Destination,
        decision: &RouteDecision,
        latency_ms: u64,
    ) -> DirectProbeRequest {
        let config = self.config();
        if !config.enabled {
            return DirectProbeRequest::NotNeeded;
        }

        let routed_direct = decision.outbound == config.direct_outbound;
        let mut needs_probe = false;
        {
            let mut observations = self.observations.write().expect("smart observations lock");
            for (target, value) in observation_targets(destination) {
                let key = observation_key(target, &value);
                let item = observations
                    .entry(key.clone())
                    .or_insert_with(|| SmartObservation::new(key, target, value));
                item.visits = item.visits.saturating_add(1);
                item.last_outbound = Some(decision.outbound.clone());
                item.last_seen_at = Utc::now();
                if routed_direct {
                    item.direct_routed_hits = item.direct_routed_hits.saturating_add(1);
                    item.record_direct_probe(true, latency_ms, None);
                } else {
                    item.proxy_routed_hits = item.proxy_routed_hits.saturating_add(1);
                    item.proxy_success_count = item.proxy_success_count.saturating_add(1);
                    item.last_proxy_outbound = Some(decision.outbound.clone());
                    if is_host_target(target) && self.should_probe_observation(item) {
                        needs_probe = true;
                        item.last_probe_instant = Some(Instant::now());
                        item.last_probe_at = Some(Utc::now());
                    }
                }
            }
            trim_observations(&mut observations, config.max_observations);
        }
        self.persist_state_throttled();

        if config.auto_probe && needs_probe {
            DirectProbeRequest::Needed
        } else {
            DirectProbeRequest::NotNeeded
        }
    }

    pub fn record_connect_failure(&self, destination: &Destination, decision: &RouteDecision) {
        let config = self.config();
        if !config.enabled {
            return;
        }

        let routed_direct = decision.outbound == config.direct_outbound;
        let mut observations = self.observations.write().expect("smart observations lock");
        for (target, value) in observation_targets(destination) {
            let key = observation_key(target, &value);
            let item = observations
                .entry(key.clone())
                .or_insert_with(|| SmartObservation::new(key, target, value));
            item.visits = item.visits.saturating_add(1);
            item.last_outbound = Some(decision.outbound.clone());
            item.last_seen_at = Utc::now();
            if routed_direct {
                item.record_direct_probe(false, 0, Some("direct outbound failed".to_string()));
            } else {
                item.proxy_failure_count = item.proxy_failure_count.saturating_add(1);
            }
        }
        trim_observations(&mut observations, config.max_observations);
        drop(observations);
        self.persist_state_throttled();
    }

    pub fn record_direct_probe(
        &self,
        value: &str,
        target: RuleTarget,
        success: bool,
        latency_ms: u64,
    ) {
        let config = self.config();
        if !config.enabled {
            return;
        }

        let key = observation_key(target, value);
        let mut observations = self.observations.write().expect("smart observations lock");
        let item = observations
            .entry(key.clone())
            .or_insert_with(|| SmartObservation::new(key, target, value.to_string()));
        item.record_direct_probe(success, latency_ms, None);
        item.last_probe_at = Some(Utc::now());
        item.last_probe_instant = Some(Instant::now());
        trim_observations(&mut observations, config.max_observations);
        drop(observations);
        self.persist_state_force();
    }

    pub fn record_direct_probe_result(
        &self,
        destination: &Destination,
        outcome: DirectProbeOutcome,
    ) {
        let config = self.config();
        if !config.enabled {
            return;
        }

        let mut observations = self.observations.write().expect("smart observations lock");
        for (target, value) in observation_targets(destination) {
            let key = observation_key(target, &value);
            let item = observations
                .entry(key.clone())
                .or_insert_with(|| SmartObservation::new(key, target, value));
            item.record_direct_probe(outcome.success, outcome.latency_ms, outcome.error.clone());
            item.last_probe_at = Some(Utc::now());
            item.last_probe_instant = Some(Instant::now());
        }
        trim_observations(&mut observations, config.max_observations);
        drop(observations);
        self.persist_state_force();
    }

    pub fn snapshot(&self) -> SmartSnapshot {
        let config = self.config();
        let rules = self.rules.read().expect("smart rules lock").clone();
        let mut observations = self
            .observations
            .read()
            .expect("smart observations lock")
            .values()
            .cloned()
            .collect::<Vec<_>>();
        observations.sort_by(|lhs, rhs| lhs.key.cmp(&rhs.key));
        let recommendations = observations
            .iter()
            .filter_map(|item| self.recommendation_for(item, false))
            .collect::<Vec<_>>();
        let stats = self.stats(&observations, &recommendations);
        let recommendation_buckets = SmartRecommendationBuckets {
            direct: recommendations
                .iter()
                .filter(|item| item.action == SmartRecommendationAction::Direct)
                .cloned()
                .collect(),
            proxy: recommendations
                .iter()
                .filter(|item| item.action == SmartRecommendationAction::Proxy)
                .cloned()
                .collect(),
        };
        SmartSnapshot {
            enabled: config.enabled,
            auto_probe: config.auto_probe,
            auto_apply_recommendations: config.auto_apply_recommendations,
            direct_outbound: config.direct_outbound.clone(),
            proxy_outbound: config.proxy_outbound.clone(),
            direct_probe_timeout_ms: config.direct_probe_timeout_ms,
            direct_probe_concurrency: config.direct_probe_concurrency,
            probe_cooldown_secs: config.probe_cooldown_secs,
            min_samples: config.min_samples,
            direct_success_min_ratio: config.direct_success_min_ratio,
            proxy_failure_min_ratio: config.proxy_failure_min_ratio,
            auto_apply_min_confidence: config.auto_apply_min_confidence,
            direct_max_latency_ms: config.direct_max_latency_ms,
            state_path: config.state_path.display().to_string(),
            persist_interval_secs: config.persist_interval_secs,
            max_observations: config.max_observations,
            last_persist_error: self
                .last_persist_error
                .read()
                .expect("persist error lock")
                .clone(),
            stats,
            rules,
            observations,
            recommendations,
            recommendation_buckets,
        }
    }

    fn persist_state_throttled(&self) {
        let config = self.config();
        if config.persist_interval_secs == 0 {
            self.persist_state_force();
            return;
        }

        let should_persist = {
            let mut last = self
                .last_persist_instant
                .lock()
                .expect("smart persist instant lock");
            match *last {
                Some(time)
                    if time.elapsed() < Duration::from_secs(config.persist_interval_secs) =>
                {
                    false
                }
                _ => {
                    *last = Some(Instant::now());
                    true
                }
            }
        };

        if should_persist {
            self.persist_state_force();
        }
    }

    fn persist_state_force(&self) {
        let result = self.persist_state();
        match result {
            Ok(()) => {
                *self.last_persist_error.write().expect("persist error lock") = None;
                *self
                    .last_persist_instant
                    .lock()
                    .expect("smart persist instant lock") = Some(Instant::now());
            }
            Err(error) => {
                *self.last_persist_error.write().expect("persist error lock") =
                    Some(error.to_string());
            }
        }
    }

    fn persist_state(&self) -> anyhow::Result<()> {
        let config = self.config();
        if config.state_path.as_os_str().is_empty() {
            return Ok(());
        }
        let state = SmartStateFile {
            version: 1,
            saved_at: Utc::now(),
            rules: self.rules.read().expect("smart rules lock").clone(),
            observations: self
                .observations
                .read()
                .expect("smart observations lock")
                .values()
                .cloned()
                .collect(),
        };
        write_state_file(&config.state_path, &state)
    }

    fn should_probe_observation(&self, observation: &SmartObservation) -> bool {
        let config = self.config();
        if !config.auto_probe {
            return false;
        }
        match observation.last_probe_instant {
            Some(last_probe) => {
                last_probe.elapsed() >= Duration::from_secs(config.probe_cooldown_secs)
            }
            None => true,
        }
    }

    fn recommendation_for(
        &self,
        observation: &SmartObservation,
        require_min_samples: bool,
    ) -> Option<SmartRecommendation> {
        let config = self.config();
        let attempts = observation.direct_probe_attempts;
        if attempts == 0 {
            return None;
        }
        if require_min_samples && attempts < config.min_samples as u64 {
            return None;
        }
        let success_ratio = ratio(observation.direct_probe_successes, attempts);
        let failure_ratio = ratio(observation.direct_probe_failures, attempts);
        let latency_ok = observation
            .last_direct_latency_ms
            .map(|latency| latency <= config.direct_max_latency_ms)
            .unwrap_or(false);

        if observation.direct_probe_successes > 0
            && success_ratio >= clamp_ratio(config.direct_success_min_ratio)
            && latency_ok
        {
            return Some(SmartRecommendation {
                target: observation.target,
                value: observation.value.clone(),
                recommended_outbound: config.direct_outbound.clone(),
                action: SmartRecommendationAction::Direct,
                confidence: confidence(observation.direct_probe_successes, attempts),
                reason: format!(
                    "direct tcp probe success ratio {:.0}% and latency <= {}ms",
                    success_ratio * 100.0,
                    config.direct_max_latency_ms
                ),
                latency_ms: observation.last_direct_latency_ms,
            });
        }

        if observation.direct_probe_failures > 0
            && failure_ratio >= clamp_ratio(config.proxy_failure_min_ratio)
        {
            let proxy_outbound = config.proxy_outbound.clone()?;
            return Some(SmartRecommendation {
                target: observation.target,
                value: observation.value.clone(),
                recommended_outbound: proxy_outbound,
                action: SmartRecommendationAction::Proxy,
                confidence: confidence(observation.direct_probe_failures, attempts),
                reason: observation.last_error.clone().unwrap_or_else(|| {
                    format!(
                        "direct tcp probe failure ratio {:.0}%",
                        failure_ratio * 100.0
                    )
                }),
                latency_ms: observation.last_direct_latency_ms,
            });
        }

        None
    }

    fn stats(
        &self,
        observations: &[SmartObservation],
        recommendations: &[SmartRecommendation],
    ) -> SmartStats {
        let config = self.config();
        let proxy_routed_targets = observations
            .iter()
            .filter(|item| item.proxy_routed_hits > 0)
            .count();
        let proxy_routed_but_direct_available_targets = observations
            .iter()
            .filter(|item| item.proxy_routed_hits > 0 && item.direct_probe_successes > 0)
            .count();
        let proxy_routed_but_direct_available_ratio = if proxy_routed_targets == 0 {
            0.0
        } else {
            proxy_routed_but_direct_available_targets as f64 / proxy_routed_targets as f64
        };
        let direct_probe_attempts = observations
            .iter()
            .map(|item| item.direct_probe_attempts)
            .sum::<u64>();
        let direct_probe_successes = observations
            .iter()
            .map(|item| item.direct_probe_successes)
            .sum::<u64>();
        let direct_probe_failures = observations
            .iter()
            .map(|item| item.direct_probe_failures)
            .sum::<u64>();
        let direct_probe_success_ratio = if direct_probe_attempts == 0 {
            0.0
        } else {
            direct_probe_successes as f64 / direct_probe_attempts as f64
        };
        let rules = self.rules.read().expect("smart rules lock");

        SmartStats {
            observed_targets: observations.len(),
            total_visits: observations.iter().map(|item| item.visits).sum(),
            direct_probe_attempts,
            direct_probe_successes,
            direct_probe_failures,
            direct_probe_success_ratio,
            enabled_rules: rules.iter().filter(|item| item.enabled).count(),
            enabled_direct_rules: rules
                .iter()
                .filter(|item| item.enabled && item.outbound == config.direct_outbound)
                .count(),
            enabled_proxy_rules: rules
                .iter()
                .filter(|item| {
                    item.enabled
                        && config
                            .proxy_outbound
                            .as_ref()
                            .map(|proxy| &item.outbound == proxy)
                            .unwrap_or(false)
                })
                .count(),
            recommended_direct_targets: recommendations
                .iter()
                .filter(|item| item.action == SmartRecommendationAction::Direct)
                .count(),
            recommended_proxy_targets: recommendations
                .iter()
                .filter(|item| item.action == SmartRecommendationAction::Proxy)
                .count(),
            proxy_routed_targets,
            proxy_routed_but_direct_available_targets,
            proxy_routed_but_direct_available_ratio,
        }
    }
}

impl SmartObservation {
    fn new(key: String, target: RuleTarget, value: String) -> Self {
        let now = Utc::now();
        Self {
            key,
            target,
            value,
            visits: 0,
            direct_routed_hits: 0,
            proxy_routed_hits: 0,
            direct_probe_attempts: 0,
            direct_probe_successes: 0,
            direct_probe_failures: 0,
            last_outbound: None,
            last_direct_latency_ms: None,
            last_error: None,
            last_seen_at: now,
            last_probe_at: None,
            last_probe_instant: None,
            first_seen_at: now,
            last_proxy_outbound: None,
            last_selected_group: None,
            last_selected_country: None,
            app_name: None,
            app_bundle_id: None,
            app_path: None,
            resolved_ip: None,
            sni: None,
            http_host: None,
            dns_name: None,
            proxy_success_count: 0,
            proxy_failure_count: 0,
            recommendation_state: RecommendationState::Pending,
        }
    }

    fn record_direct_probe(&mut self, success: bool, latency_ms: u64, error: Option<String>) {
        self.direct_probe_attempts = self.direct_probe_attempts.saturating_add(1);
        self.last_direct_latency_ms = Some(latency_ms);
        if success {
            self.direct_probe_successes = self.direct_probe_successes.saturating_add(1);
            self.last_error = None;
        } else {
            self.direct_probe_failures = self.direct_probe_failures.saturating_add(1);
            self.last_error = error;
        }
    }
}

pub async fn probe_direct_tcp(destination: Destination, timeout_ms: u64) -> DirectProbeOutcome {
    let started = Instant::now();
    let result = timeout(
        Duration::from_millis(timeout_ms),
        TcpStream::connect(destination.authority()),
    )
    .await;
    let latency_ms = started.elapsed().as_millis() as u64;
    match result {
        Ok(Ok(_stream)) => DirectProbeOutcome {
            success: true,
            latency_ms,
            error: None,
        },
        Ok(Err(error)) => DirectProbeOutcome {
            success: false,
            latency_ms,
            error: Some(error.to_string()),
        },
        Err(_) => DirectProbeOutcome {
            success: false,
            latency_ms: timeout_ms,
            error: Some(format!("direct probe timed out after {timeout_ms}ms")),
        },
    }
}

fn load_state(
    config: &SmartRulesConfig,
) -> (
    Vec<SmartRouteRule>,
    HashMap<String, SmartObservation>,
    Option<String>,
) {
    let mut rules = Vec::new();
    let mut observations = HashMap::new();
    let mut load_error = None;

    match fs::read_to_string(&config.state_path) {
        Ok(text) => match serde_json::from_str::<SmartStateFile>(&text) {
            Ok(state) => {
                for mut rule in state.rules {
                    rule.value = normalized_value(rule.target, &rule.value);
                    append_rule_locked(&mut rules, rule);
                }
                for mut observation in state.observations {
                    observation.value = normalized_value(observation.target, &observation.value);
                    observation.key = observation_key(observation.target, &observation.value);
                    observation.last_probe_instant = None;
                    observations.insert(observation.key.clone(), observation);
                }
            }
            Err(error) => {
                load_error = Some(format!(
                    "failed to parse smart state {}: {error}",
                    config.state_path.display()
                ));
            }
        },
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => {
            load_error = Some(format!(
                "failed to read smart state {}: {error}",
                config.state_path.display()
            ));
        }
    }

    for rule in &config.rules {
        append_rule_if_missing_locked(&mut rules, rule.clone());
    }
    trim_observations(&mut observations, config.max_observations);
    (rules, observations, load_error)
}

fn write_state_file(path: &Path, state: &SmartStateFile) -> anyhow::Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    let mut tmp_path = path.to_path_buf();
    let tmp_extension = path
        .extension()
        .and_then(|item| item.to_str())
        .map(|item| format!("{item}.tmp"))
        .unwrap_or_else(|| "tmp".to_string());
    tmp_path.set_extension(tmp_extension);
    let text = serde_json::to_string_pretty(state)?;
    fs::write(&tmp_path, text)?;
    fs::rename(&tmp_path, path)?;
    Ok(())
}

fn upsert_rule_locked(rules: &mut Vec<SmartRouteRule>, mut rule: SmartRouteRule) {
    rule.value = normalized_value(rule.target, &rule.value);
    if let Some(existing) = rules.iter_mut().find(|item| {
        item.target == rule.target && normalized_value(item.target, &item.value) == rule.value
    }) {
        *existing = rule;
    } else {
        rules.insert(0, rule);
    }
}

fn append_rule_locked(rules: &mut Vec<SmartRouteRule>, mut rule: SmartRouteRule) {
    rule.value = normalized_value(rule.target, &rule.value);
    if let Some(existing) = rules.iter_mut().find(|item| {
        item.target == rule.target && normalized_value(item.target, &item.value) == rule.value
    }) {
        *existing = rule;
    } else {
        rules.push(rule);
    }
}

fn append_rule_if_missing_locked(rules: &mut Vec<SmartRouteRule>, mut rule: SmartRouteRule) {
    rule.value = normalized_value(rule.target, &rule.value);
    if !rules.iter().any(|item| {
        item.target == rule.target && normalized_value(item.target, &item.value) == rule.value
    }) {
        rules.push(rule);
    }
}

fn trim_observations(
    observations: &mut HashMap<String, SmartObservation>,
    max_observations: usize,
) {
    if max_observations == 0 {
        observations.clear();
        return;
    }
    if observations.len() <= max_observations {
        return;
    }

    let mut keys = observations
        .values()
        .map(|item| (item.last_seen_at, item.key.clone()))
        .collect::<Vec<_>>();
    keys.sort_by_key(|lhs| lhs.0);
    let remove_count = observations.len().saturating_sub(max_observations);
    for (_, key) in keys.into_iter().take(remove_count) {
        observations.remove(&key);
    }
}

fn observation_targets(destination: &Destination) -> Vec<(RuleTarget, String)> {
    let mut targets = Vec::new();
    if let Some(app) = &destination.app {
        if let Some(bundle_id) = app.bundle_id.as_deref().filter(|item| !item.is_empty()) {
            targets.push((
                RuleTarget::AppBundle,
                normalized_value(RuleTarget::AppBundle, bundle_id),
            ));
        }
        if let Some(name) = app.name.as_deref().filter(|item| !item.is_empty()) {
            targets.push((
                RuleTarget::AppName,
                normalized_value(RuleTarget::AppName, name),
            ));
        }
        if let Some(path) = app.path.as_deref().filter(|item| !item.is_empty()) {
            targets.push((
                RuleTarget::AppPath,
                normalized_value(RuleTarget::AppPath, path),
            ));
        }
    }
    targets.extend(host_observation_targets(destination));
    targets
}

fn host_observation_targets(destination: &Destination) -> Vec<(RuleTarget, String)> {
    let target = if destination.host.parse::<std::net::IpAddr>().is_ok() {
        RuleTarget::Ip
    } else {
        RuleTarget::Domain
    };
    vec![(target, normalized_value(target, &destination.host))]
}

fn is_host_target(target: RuleTarget) -> bool {
    matches!(target, RuleTarget::Domain | RuleTarget::Ip)
}

fn observation_key(target: RuleTarget, value: &str) -> String {
    format!("{target:?}:{}", normalized_value(target, value))
}

fn normalized_value(target: RuleTarget, value: &str) -> String {
    match target {
        RuleTarget::Domain
        | RuleTarget::DomainSuffix
        | RuleTarget::DomainKeyword
        | RuleTarget::Ip
        | RuleTarget::AppName
        | RuleTarget::AppPath
        | RuleTarget::AppBundle
        | RuleTarget::RuleSet
        | RuleTarget::GeoIp => value.to_ascii_lowercase(),
        RuleTarget::IpCidr | RuleTarget::Match => value.to_string(),
    }
}

fn confidence(matches: u64, attempts: u64) -> f64 {
    if attempts == 0 {
        0.0
    } else {
        matches as f64 / attempts as f64
    }
}

fn ratio(count: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else {
        count as f64 / total as f64
    }
}

fn clamp_ratio(value: f64) -> f64 {
    if value.is_finite() {
        value.clamp(0.0, 1.0)
    } else {
        1.0
    }
}
