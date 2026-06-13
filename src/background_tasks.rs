use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use serde::Serialize;
use tokio::sync::RwLock;

use crate::core::Runtime;
use crate::subscription_store::SubscriptionStore;

#[derive(Debug, Clone, Serialize)]
pub struct BackgroundTaskInfo {
    pub name: String,
    pub interval_secs: u64,
    pub enabled: bool,
    pub running: bool,
    pub last_run_at: Option<String>,
    pub last_started_at: Option<String>,
    pub last_finished_at: Option<String>,
    pub last_duration_ms: Option<u64>,
    pub last_error: Option<String>,
    pub run_count: u64,
    pub success_count: u64,
    pub failure_count: u64,
    pub next_run_at: Option<String>,
}

#[derive(Debug)]
struct TaskState {
    info: BackgroundTaskInfo,
    enabled: bool,
    running: bool,
}

pub struct BackgroundScheduler {
    tasks: RwLock<HashMap<String, TaskState>>,
}

impl Default for BackgroundScheduler {
    fn default() -> Self {
        Self::new()
    }
}

impl BackgroundScheduler {
    pub fn new() -> Self {
        Self {
            tasks: RwLock::new(HashMap::new()),
        }
    }

    pub fn new_with_defaults() -> Self {
        let mut tasks = HashMap::new();
        for (name, interval_secs) in [
            ("subscription_update", 3600),
            ("outbound_probe", 300),
            ("country_refresh", 1800),
            ("smart_probe", 600),
            ("traffic_persist", 60),
            ("session_cleanup", 300),
        ] {
            tasks.insert(
                name.to_string(),
                TaskState {
                    info: BackgroundTaskInfo {
                        name: name.to_string(),
                        interval_secs,
                        enabled: true,
                        running: false,
                        last_run_at: None,
                        last_started_at: None,
                        last_finished_at: None,
                        last_duration_ms: None,
                        last_error: None,
                        run_count: 0,
                        success_count: 0,
                        failure_count: 0,
                        next_run_at: None,
                    },
                    enabled: true,
                    running: false,
                },
            );
        }
        Self {
            tasks: RwLock::new(tasks),
        }
    }

    pub async fn register(&self, name: &str, interval_secs: u64) {
        let mut tasks = self.tasks.write().await;
        tasks.insert(
            name.to_string(),
            TaskState {
                info: BackgroundTaskInfo {
                    name: name.to_string(),
                    interval_secs,
                    enabled: true,
                    running: false,
                    last_run_at: None,
                    last_started_at: None,
                    last_finished_at: None,
                    last_duration_ms: None,
                    last_error: None,
                    run_count: 0,
                    success_count: 0,
                    failure_count: 0,
                    next_run_at: None,
                },
                enabled: true,
                running: false,
            },
        );
    }

    pub async fn pause(&self, name: &str) -> bool {
        let mut tasks = self.tasks.write().await;
        if let Some(task) = tasks.get_mut(name) {
            task.enabled = false;
            task.info.enabled = false;
            true
        } else {
            false
        }
    }

    pub async fn resume(&self, name: &str) -> bool {
        let mut tasks = self.tasks.write().await;
        if let Some(task) = tasks.get_mut(name) {
            task.enabled = true;
            task.info.enabled = true;
            true
        } else {
            false
        }
    }

    pub async fn list(&self) -> Vec<BackgroundTaskInfo> {
        let tasks = self.tasks.read().await;
        tasks.values().map(|t| t.info.clone()).collect()
    }

    pub async fn is_enabled(&self, name: &str) -> bool {
        let tasks = self.tasks.read().await;
        tasks.get(name).map(|t| t.enabled).unwrap_or(false)
    }

    pub async fn record_run(&self, name: &str, duration_ms: u64, error: Option<String>) {
        let mut tasks = self.tasks.write().await;
        if let Some(task) = tasks.get_mut(name) {
            let now = chrono::Utc::now().to_rfc3339();
            task.info.last_run_at = Some(now.clone());
            task.info.last_finished_at = Some(now);
            task.info.last_duration_ms = Some(duration_ms);
            task.info.last_error = error.clone();
            task.info.run_count += 1;
            task.running = false;
            if error.is_some() {
                task.info.failure_count += 1;
            } else {
                task.info.success_count += 1;
            }
        }
    }

    pub async fn mark_running(&self, name: &str) {
        let mut tasks = self.tasks.write().await;
        if let Some(task) = tasks.get_mut(name) {
            task.running = true;
            task.info.running = true;
            task.info.last_started_at = Some(chrono::Utc::now().to_rfc3339());
        }
    }

    pub async fn update_interval(&self, name: &str, interval_secs: u64) -> bool {
        let mut tasks = self.tasks.write().await;
        if let Some(task) = tasks.get_mut(name) {
            task.info.interval_secs = interval_secs;
            true
        } else {
            false
        }
    }
}

pub async fn run_subscription_update(runtime: &Arc<Runtime>, scheduler: &Arc<BackgroundScheduler>) {
    let name = "subscription_update";
    if !scheduler.is_enabled(name).await {
        return;
    }

    let started = Instant::now();
    let subscription_config = runtime.config().subscriptions;
    let result = SubscriptionStore::new(subscription_config.store_path.clone())
        .update_all_from_urls_with((&subscription_config).into())
        .await;
    let duration_ms = started.elapsed().as_millis() as u64;
    match result {
        Ok(results) => {
            let updated = results.iter().filter(|item| item.updated).count();
            runtime
                .telemetry()
                .log(
                    "info",
                    format!(
                        "background task subscription_update: updated {updated}/{} subscriptions",
                        results.len()
                    ),
                )
                .await;
            scheduler.record_run(name, duration_ms, None).await;
        }
        Err(error) => {
            let error = error.to_string();
            runtime
                .telemetry()
                .log(
                    "warn",
                    format!("background task subscription_update failed: {error}"),
                )
                .await;
            scheduler.record_run(name, duration_ms, Some(error)).await;
        }
    }
}

pub async fn run_outbound_probe(runtime: &Arc<Runtime>, scheduler: &Arc<BackgroundScheduler>) {
    let name = "outbound_probe";
    if !scheduler.is_enabled(name).await {
        return;
    }

    let started = Instant::now();
    let results = runtime
        .probe_all_outbounds_with(crate::core::ProbeOptions {
            include_failed: false,
            include_unsupported: false,
            ..Default::default()
        })
        .await;
    let duration_ms = started.elapsed().as_millis() as u64;
    let ok_count = results.iter().filter(|r| r.success).count();
    runtime
        .telemetry()
        .log(
            "info",
            format!(
                "background task outbound_probe: {ok_count}/{} outbounds healthy",
                results.len()
            ),
        )
        .await;
    scheduler.record_run(name, duration_ms, None).await;
}

pub async fn run_country_refresh(runtime: &Arc<Runtime>, scheduler: &Arc<BackgroundScheduler>) {
    let name = "country_refresh";
    if !scheduler.is_enabled(name).await {
        return;
    }

    let started = Instant::now();
    let _groups = runtime.country_groups().await;
    let duration_ms = started.elapsed().as_millis() as u64;
    scheduler.record_run(name, duration_ms, None).await;
}

pub async fn run_smart_probe(runtime: &Arc<Runtime>, scheduler: &Arc<BackgroundScheduler>) {
    let name = "smart_probe";
    if !scheduler.is_enabled(name).await {
        return;
    }

    let started = Instant::now();
    let config = runtime.config();
    let smart_config = &config.smart_rules;

    if !smart_config.enabled || !smart_config.auto_probe {
        let duration_ms = started.elapsed().as_millis() as u64;
        scheduler.record_run(name, duration_ms, None).await;
        return;
    }

    let snapshot = runtime.smart_snapshot();
    let probe_timeout_ms = smart_config.direct_probe_timeout_ms;
    let cooldown_secs = smart_config.probe_cooldown_secs;

    let mut probe_count = 0;
    let mut success_count = 0;
    let mut failure_count = 0;

    for obs in &snapshot.observations {
        if obs.recommendation_state != crate::smart::RecommendationState::Pending {
            continue;
        }

        if let Some(last_probe) = obs.last_probe_at {
            let elapsed = chrono::Utc::now().signed_duration_since(last_probe);
            if elapsed.num_seconds() < cooldown_secs as i64 {
                continue;
            }
        }

        let target_host = match obs.target {
            crate::config::RuleTarget::Domain => obs.value.clone(),
            crate::config::RuleTarget::Ip => obs.value.clone(),
            _ => continue,
        };

        probe_count += 1;

        let probe_result = tokio::time::timeout(
            std::time::Duration::from_millis(probe_timeout_ms),
            tokio::net::TcpStream::connect(format!("{}:443", target_host)),
        )
        .await;

        match probe_result {
            Ok(Ok(_)) => {
                success_count += 1;
                runtime.smart_record_direct_probe(&obs.value, obs.target, true, probe_timeout_ms);
            }
            Ok(Err(e)) => {
                failure_count += 1;
                runtime.smart_record_direct_probe(&obs.value, obs.target, false, probe_timeout_ms);
                tracing::debug!(
                    target = %target_host,
                    error = %e,
                    "smart_probe: direct probe failed"
                );
            }
            Err(_) => {
                failure_count += 1;
                runtime.smart_record_direct_probe(&obs.value, obs.target, false, probe_timeout_ms);
                tracing::debug!(
                    target = %target_host,
                    "smart_probe: direct probe timed out"
                );
            }
        }
    }

    let message = format!(
        "background task smart_probe completed: probed={}, success={}, failure={}",
        probe_count, success_count, failure_count
    );
    runtime.telemetry().log("info", message).await;

    let duration_ms = started.elapsed().as_millis() as u64;
    if failure_count > 0 && success_count == 0 {
        scheduler
            .record_run(
                name,
                duration_ms,
                Some(format!("{} probes failed", failure_count)),
            )
            .await;
    } else {
        scheduler.record_run(name, duration_ms, None).await;
    }
}

pub async fn run_traffic_persist(runtime: &Arc<Runtime>, scheduler: &Arc<BackgroundScheduler>) {
    let name = "traffic_persist";
    if !scheduler.is_enabled(name).await {
        return;
    }

    let started = Instant::now();
    let result = runtime.traffic_store().persist();
    let duration_ms = started.elapsed().as_millis() as u64;
    match result {
        Ok(()) => scheduler.record_run(name, duration_ms, None).await,
        Err(error) => {
            let error = error.to_string();
            runtime
                .telemetry()
                .log(
                    "warn",
                    format!("background task traffic_persist failed: {error}"),
                )
                .await;
            scheduler.record_run(name, duration_ms, Some(error)).await;
        }
    }
}

pub async fn run_session_cleanup(runtime: &Arc<Runtime>, scheduler: &Arc<BackgroundScheduler>) {
    let name = "session_cleanup";
    if !scheduler.is_enabled(name).await {
        return;
    }

    let started = Instant::now();
    runtime
        .telemetry()
        .log(
            "debug",
            "background task session_cleanup: native session cleanup is performed by TUN dispatcher intervals",
        )
        .await;
    let duration_ms = started.elapsed().as_millis() as u64;
    scheduler.record_run(name, duration_ms, None).await;
}
