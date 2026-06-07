use std::{path::PathBuf, sync::Arc};

use axum::{
    extract::State,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use tower_http::trace::TraceLayer;

use crate::{
    config::{OutboundConfig, RuleTarget, SmartRouteRule, SuperConfig},
    core::{ProbeOptions, Runtime},
    routing::Destination,
    smart::SmartRecommendationAction,
    subscription_store::SubscriptionStore,
};

#[derive(Debug, Serialize)]
struct VersionResponse {
    name: &'static str,
    version: &'static str,
    engine: &'static str,
}

#[derive(Debug, Serialize)]
struct StatusResponse {
    mixed_listen: String,
    control_listen: String,
    outbounds: usize,
    rules: usize,
    smart_rules_enabled: bool,
    traffic: crate::telemetry::TrafficSnapshot,
}

#[derive(Debug, Deserialize)]
struct ProbeRequest {
    url: Option<String>,
    timeout_ms: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct SmartRuleRequest {
    target: RuleTarget,
    value: String,
    outbound: String,
    #[serde(default = "default_enabled")]
    enabled: bool,
    #[serde(default)]
    note: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ApplySmartRecommendationsRequest {
    action: Option<SmartRecommendationAction>,
}

#[derive(Debug, Deserialize)]
struct ApplySmartRecommendationRequest {
    target: RuleTarget,
    value: String,
}

#[derive(Debug, Deserialize)]
struct SmartRuleEnabledRequest {
    target: RuleTarget,
    value: String,
    enabled: bool,
}

#[derive(Debug, Deserialize)]
struct SmartRuleDeleteRequest {
    target: RuleTarget,
    value: String,
}

#[derive(Debug, Deserialize)]
struct SubscriptionImportRequest {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    switch: bool,
}

#[derive(Debug, Deserialize)]
struct SubscriptionUseRequest {
    id: String,
}

#[derive(Debug, Deserialize)]
struct CountryUseRequest {
    code: String,
}

#[derive(Debug, Deserialize)]
struct OutboundUseRequest {
    name: String,
}

#[derive(Debug, Deserialize)]
struct ActiveSubscriptionConfigRequest {
    #[serde(default)]
    use_first_node: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct ConfigReloadRequest {
    #[serde(default)]
    path: Option<PathBuf>,
    #[serde(default)]
    yaml: Option<String>,
}

pub async fn serve(runtime: Arc<Runtime>) -> anyhow::Result<()> {
    let control_listen = runtime.config().core.control_listen;
    let app = Router::new()
        .route("/health", get(health))
        .route("/version", get(version))
        .route("/traffic", get(traffic))
        .route("/connections", get(connections))
        .route("/logs", get(logs))
        .route("/proxies", get(compat_proxies))
        .route("/rules", get(compat_rules))
        .route("/providers/proxies", get(compat_proxy_providers))
        .route("/providers/rules", get(compat_rule_providers))
        .route("/skyhook/version", get(version))
        .route("/skyhook/status", get(status))
        .route("/skyhook/connections", get(connections))
        .route(
            "/skyhook/traffic/subscriptions",
            get(subscription_traffic),
        )
        .route("/skyhook/outbounds", get(outbounds))
        .route("/skyhook/outbounds/use", post(use_outbound))
        .route("/skyhook/groups", get(groups))
        .route("/skyhook/countries", get(countries))
        .route("/skyhook/countries/use", post(use_country))
        .route("/skyhook/probe/outbounds", post(probe_outbounds))
        .route("/skyhook/route/decision", post(route_decision))
        .route("/skyhook/subscriptions", get(subscriptions))
        .route("/skyhook/subscriptions/import", post(import_subscription))
        .route("/skyhook/subscriptions/use", post(use_subscription))
        .route(
            "/skyhook/subscriptions/reload-active",
            post(reload_active_subscription),
        )
        .route(
            "/skyhook/subscriptions/update-all",
            post(update_all_subscriptions),
        )
        .route(
            "/skyhook/subscriptions/active-config",
            post(active_subscription_config),
        )
        .route(
            "/skyhook/smart-rules",
            get(smart_rules).post(upsert_smart_rule),
        )
        .route(
            "/skyhook/smart-rules/enabled",
            post(set_smart_rule_enabled),
        )
        .route("/skyhook/smart-rules/delete", post(delete_smart_rule))
        .route(
            "/skyhook/smart-rules/apply-recommendations",
            post(apply_smart_recommendations),
        )
        .route(
            "/skyhook/smart-rules/apply-recommendation",
            post(apply_smart_recommendation),
        )
        .route("/skyhook/logs", get(logs))
        .route("/skyhook/config", get(config))
        .route("/skyhook/config/reload", post(reload_config))
        .layer(TraceLayer::new_for_http())
        .with_state(runtime);
    let listener = tokio::net::TcpListener::bind(control_listen).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "ok": true }))
}

async fn version() -> Json<VersionResponse> {
    Json(VersionResponse {
        name: "Skyhook",
        version: env!("CARGO_PKG_VERSION"),
        engine: "rust-native",
    })
}

async fn status(State(runtime): State<Arc<Runtime>>) -> Json<StatusResponse> {
    Json(StatusResponse {
        mixed_listen: runtime.config().core.mixed_listen.to_string(),
        control_listen: runtime.config().core.control_listen.to_string(),
        outbounds: runtime.config().outbounds.len(),
        rules: runtime.config().rules.len(),
        smart_rules_enabled: runtime.config().smart_rules.enabled,
        traffic: runtime.telemetry().traffic(),
    })
}

async fn connections(State(runtime): State<Arc<Runtime>>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "traffic": runtime.telemetry().traffic(),
        "connections": runtime.telemetry().connections().await,
    }))
}

async fn traffic(State(runtime): State<Arc<Runtime>>) -> Json<crate::telemetry::TrafficSnapshot> {
    Json(runtime.telemetry().traffic())
}

async fn subscription_traffic(State(runtime): State<Arc<Runtime>>) -> Json<serde_json::Value> {
    match subscription_store(&runtime).index() {
        Ok(index) => Json(serde_json::json!({
            "ok": true,
            "active_id": index.active_id,
            "subscriptions": index.subscriptions.into_iter().map(|item| {
                serde_json::json!({
                    "id": item.id,
                    "name": item.name,
                    "upload_total": item.traffic_upload_total,
                    "download_total": item.traffic_download_total,
                    "total": item.traffic_upload_total.saturating_add(item.traffic_download_total),
                })
            }).collect::<Vec<_>>(),
        })),
        Err(error) => Json(serde_json::json!({
            "ok": false,
            "error": error.to_string(),
        })),
    }
}

async fn outbounds(State(runtime): State<Arc<Runtime>>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "outbounds": runtime.telemetry().outbound_health().await,
        "groups": runtime.proxy_groups().await,
        "capabilities": runtime.outbound_capabilities(),
    }))
}

async fn compat_proxies(State(runtime): State<Arc<Runtime>>) -> Json<serde_json::Value> {
    let config = runtime.config();
    let groups = runtime.proxy_groups().await;
    let capabilities = runtime
        .outbound_capabilities()
        .into_iter()
        .map(|item| (item.name.clone(), item))
        .collect::<std::collections::HashMap<_, _>>();
    let health = runtime
        .telemetry()
        .outbound_health()
        .await
        .into_iter()
        .map(|item| (item.name.clone(), item))
        .collect::<std::collections::HashMap<_, _>>();
    let group_map = groups
        .iter()
        .map(|group| (group.name.clone(), group))
        .collect::<std::collections::HashMap<_, _>>();
    let proxies = config
        .outbounds
        .iter()
        .map(|outbound| {
            let name = outbound.name().to_string();
            let capability = capabilities.get(&name);
            let health = health.get(&name);
            let group = group_map.get(&name);
            (
                name.clone(),
                serde_json::json!({
                    "name": name,
                    "type": outbound_api_kind(outbound),
                    "udp": capability.map(|item| item.udp_supported).unwrap_or(false),
                    "tcp": capability.map(|item| item.tcp_supported).unwrap_or(false),
                    "now": group.and_then(|item| item.selected_member.clone()),
                    "all": group.map(|item| item.members.iter().map(|member| member.name.clone()).collect::<Vec<_>>()).unwrap_or_default(),
                    "history": health.and_then(|item| item.last_latency_ms).map(|latency| vec![serde_json::json!({ "time": item_time(), "delay": latency })]).unwrap_or_default(),
                    "alive": health.map(|item| item.successes > 0 && item.last_error.is_none()).unwrap_or(false),
                    "lastDelay": health.and_then(|item| item.last_latency_ms),
                    "lastError": health.and_then(|item| item.last_error.clone()),
                    "limitations": capability.map(|item| item.limitations.clone()).unwrap_or_default(),
                }),
            )
        })
        .collect::<serde_json::Map<_, _>>();
    Json(serde_json::json!({
        "proxies": proxies,
    }))
}

async fn compat_rules(State(runtime): State<Arc<Runtime>>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "rules": runtime.config().rules,
        "smart": runtime.smart_snapshot(),
    }))
}

async fn compat_proxy_providers(State(runtime): State<Arc<Runtime>>) -> Json<serde_json::Value> {
    let subscriptions = subscription_store(&runtime)
        .index()
        .map(|index| index.subscriptions)
        .unwrap_or_default();
    Json(serde_json::json!({
        "providers": {
            "subscriptions": {
                "name": "subscriptions",
                "type": "Subscription",
                "subscriptions": subscriptions,
                "vehicleType": "HTTP",
            }
        }
    }))
}

async fn compat_rule_providers(State(runtime): State<Arc<Runtime>>) -> Json<serde_json::Value> {
    let providers = runtime
        .config()
        .rule_sets
        .into_iter()
        .map(|provider| {
            (
                provider.name.clone(),
                serde_json::json!({
                    "name": provider.name,
                    "behavior": provider.behavior,
                    "ruleCount": provider.rules.len(),
                    "rules": provider.rules,
                    "vehicleType": "Inline",
                }),
            )
        })
        .collect::<serde_json::Map<_, _>>();
    Json(serde_json::json!({
        "providers": providers,
    }))
}

async fn groups(State(runtime): State<Arc<Runtime>>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "groups": runtime.proxy_groups().await,
    }))
}

async fn countries(State(runtime): State<Arc<Runtime>>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "countries": runtime.country_groups().await,
    }))
}

async fn use_country(
    State(runtime): State<Arc<Runtime>>,
    Json(request): Json<CountryUseRequest>,
) -> Json<serde_json::Value> {
    match runtime.use_country_group(&request.code).await {
        Ok(config) => Json(serde_json::json!({
            "ok": true,
            "runtime": {
                "reloaded": true,
                "summary": config.summary(),
                "default_outbound": config.core.default_outbound,
            },
        })),
        Err(error) => Json(serde_json::json!({
            "ok": false,
            "error": error.to_string(),
        })),
    }
}

async fn probe_outbounds(
    State(runtime): State<Arc<Runtime>>,
    request: Option<Json<ProbeRequest>>,
) -> Json<serde_json::Value> {
    let options = request
        .map(|Json(request)| ProbeOptions {
            url: request.url,
            timeout_ms: request.timeout_ms,
        })
        .unwrap_or_default();
    Json(serde_json::json!({
        "results": runtime.probe_all_outbounds_with(options).await,
    }))
}

async fn route_decision(
    State(runtime): State<Arc<Runtime>>,
    Json(destination): Json<Destination>,
) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "destination": destination,
        "decision": runtime.decide(&destination),
    }))
}

async fn smart_rules(State(runtime): State<Arc<Runtime>>) -> Json<serde_json::Value> {
    Json(serde_json::json!(runtime.smart_snapshot()))
}

async fn subscriptions(State(runtime): State<Arc<Runtime>>) -> Json<serde_json::Value> {
    match subscription_store(&runtime).index() {
        Ok(index) => Json(serde_json::json!({
            "ok": true,
            "index": index,
        })),
        Err(error) => Json(serde_json::json!({
            "ok": false,
            "error": error.to_string(),
        })),
    }
}

async fn import_subscription(
    State(runtime): State<Arc<Runtime>>,
    Json(request): Json<SubscriptionImportRequest>,
) -> Json<serde_json::Value> {
    let url = request.url.clone();
    let update_timeout_secs = runtime.config().subscriptions.update_timeout_secs;
    let text = match subscription_source_text(request.text, request.url, update_timeout_secs).await
    {
        Ok(text) => text,
        Err(error) => {
            return Json(serde_json::json!({
                "ok": false,
                "error": error.to_string(),
            }))
        }
    };

    match subscription_store(&runtime).import_text_with_id(
        request.id,
        request.name,
        url,
        &text,
        request.switch,
    ) {
        Ok(result) => {
            let reload = if result.active_changed {
                reload_active_subscription_config(&runtime).map(
                    |config| serde_json::json!({ "reloaded": true, "summary": config.summary() }),
                )
            } else {
                Ok(serde_json::json!({ "reloaded": false }))
            };
            match reload {
                Ok(reload) => Json(serde_json::json!({
                    "ok": true,
                    "result": result,
                    "runtime": reload,
                })),
                Err(error) => Json(serde_json::json!({
                    "ok": false,
                    "result": result,
                    "error": error.to_string(),
                })),
            }
        }
        Err(error) => Json(serde_json::json!({
            "ok": false,
            "error": error.to_string(),
        })),
    }
}

async fn use_outbound(
    State(runtime): State<Arc<Runtime>>,
    Json(request): Json<OutboundUseRequest>,
) -> Json<serde_json::Value> {
    match runtime.use_outbound(&request.name) {
        Ok(config) => Json(serde_json::json!({
            "ok": true,
            "runtime": {
                "reloaded": true,
                "summary": config.summary(),
                "default_outbound": config.core.default_outbound,
            },
        })),
        Err(error) => Json(serde_json::json!({
            "ok": false,
            "error": error.to_string(),
        })),
    }
}

async fn use_subscription(
    State(runtime): State<Arc<Runtime>>,
    Json(request): Json<SubscriptionUseRequest>,
) -> Json<serde_json::Value> {
    match subscription_store(&runtime).set_active(&request.id) {
        Ok(meta) => match reload_active_subscription_config(&runtime) {
            Ok(config) => Json(serde_json::json!({
                "ok": true,
                "subscription": meta,
                "runtime": {
                    "reloaded": true,
                    "summary": config.summary(),
                },
            })),
            Err(error) => Json(serde_json::json!({
                "ok": false,
                "subscription": meta,
                "error": error.to_string(),
            })),
        },
        Err(error) => Json(serde_json::json!({
            "ok": false,
            "error": error.to_string(),
        })),
    }
}

async fn update_all_subscriptions(State(runtime): State<Arc<Runtime>>) -> Json<serde_json::Value> {
    let store = subscription_store(&runtime);
    let options = (&runtime.config().subscriptions).into();
    match store.update_all_from_urls_with(options).await {
        Ok(results) => {
            let updated = results.iter().any(|item| item.updated);
            let reload = if updated {
                reload_active_subscription_config(&runtime).map(
                    |config| serde_json::json!({ "reloaded": true, "summary": config.summary() }),
                )
            } else {
                Ok(serde_json::json!({ "reloaded": false }))
            };
            match reload {
                Ok(reload) => Json(serde_json::json!({
                    "ok": true,
                    "results": results,
                    "runtime": reload,
                })),
                Err(error) => Json(serde_json::json!({
                    "ok": false,
                    "results": results,
                    "error": error.to_string(),
                })),
            }
        }
        Err(error) => Json(serde_json::json!({
            "ok": false,
            "error": error.to_string(),
        })),
    }
}

async fn reload_active_subscription(
    State(runtime): State<Arc<Runtime>>,
) -> Json<serde_json::Value> {
    match reload_active_subscription_config(&runtime) {
        Ok(config) => Json(serde_json::json!({
            "ok": true,
            "runtime": {
                "reloaded": true,
                "summary": config.summary(),
            },
        })),
        Err(error) => Json(serde_json::json!({
            "ok": false,
            "error": error.to_string(),
        })),
    }
}

async fn active_subscription_config(
    State(runtime): State<Arc<Runtime>>,
    request: Option<Json<ActiveSubscriptionConfigRequest>>,
) -> Json<serde_json::Value> {
    let base_config = runtime.base_config();
    let use_first_node = request
        .and_then(|Json(request)| request.use_first_node)
        .unwrap_or(base_config.subscriptions.use_first_node_as_default);
    match SubscriptionStore::new(base_config.subscriptions.store_path.clone())
        .active_runtime_config(base_config, use_first_node)
    {
        Ok(config) => Json(serde_json::json!({
            "ok": true,
            "config": config,
        })),
        Err(error) => Json(serde_json::json!({
            "ok": false,
            "error": error.to_string(),
        })),
    }
}

async fn upsert_smart_rule(
    State(runtime): State<Arc<Runtime>>,
    Json(request): Json<SmartRuleRequest>,
) -> Json<serde_json::Value> {
    let result = runtime.upsert_smart_rule(SmartRouteRule {
        target: request.target,
        value: request.value,
        outbound: request.outbound,
        enabled: request.enabled,
        note: request.note,
    });
    match result {
        Ok(rules) => Json(serde_json::json!({
            "ok": true,
            "rules": rules,
        })),
        Err(error) => Json(serde_json::json!({
            "ok": false,
            "error": error.to_string(),
        })),
    }
}

async fn set_smart_rule_enabled(
    State(runtime): State<Arc<Runtime>>,
    Json(request): Json<SmartRuleEnabledRequest>,
) -> Json<serde_json::Value> {
    match runtime.set_smart_rule_enabled(request.target, &request.value, request.enabled) {
        Ok(rules) => Json(serde_json::json!({
            "ok": true,
            "rules": rules,
        })),
        Err(error) => Json(serde_json::json!({
            "ok": false,
            "error": error.to_string(),
        })),
    }
}

async fn delete_smart_rule(
    State(runtime): State<Arc<Runtime>>,
    Json(request): Json<SmartRuleDeleteRequest>,
) -> Json<serde_json::Value> {
    match runtime.delete_smart_rule(request.target, &request.value) {
        Ok(rules) => Json(serde_json::json!({
            "ok": true,
            "rules": rules,
        })),
        Err(error) => Json(serde_json::json!({
            "ok": false,
            "error": error.to_string(),
        })),
    }
}

async fn apply_smart_recommendations(
    State(runtime): State<Arc<Runtime>>,
    request: Option<Json<ApplySmartRecommendationsRequest>>,
) -> Json<serde_json::Value> {
    let action = request.and_then(|Json(request)| request.action);
    let rules = runtime.apply_smart_recommendations(action);
    Json(serde_json::json!({
        "ok": true,
        "rules": rules,
    }))
}

async fn apply_smart_recommendation(
    State(runtime): State<Arc<Runtime>>,
    Json(request): Json<ApplySmartRecommendationRequest>,
) -> Json<serde_json::Value> {
    match runtime.apply_smart_recommendation(request.target, &request.value) {
        Ok(rules) => Json(serde_json::json!({
            "ok": true,
            "rules": rules,
        })),
        Err(error) => Json(serde_json::json!({
            "ok": false,
            "error": error.to_string(),
        })),
    }
}

async fn logs(State(runtime): State<Arc<Runtime>>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "logs": runtime.telemetry().logs().await,
    }))
}

async fn config(State(runtime): State<Arc<Runtime>>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "core": runtime.config().core,
        "tun": runtime.config().tun,
        "dns": runtime.config().dns,
        "smart_rules": runtime.config().smart_rules,
        "subscriptions": runtime.config().subscriptions,
        "outbounds": runtime.config().outbounds.iter().map(|item| item.name().to_string()).collect::<Vec<_>>(),
        "rule_sets": runtime.config().rule_sets,
        "rules": runtime.config().rules,
    }))
}

async fn reload_config(
    State(runtime): State<Arc<Runtime>>,
    Json(request): Json<ConfigReloadRequest>,
) -> Json<serde_json::Value> {
    let base_config = match (request.path, request.yaml) {
        (Some(path), None) => SuperConfig::load(&path),
        (None, Some(yaml)) => serde_yaml::from_str(&yaml).map_err(Into::into),
        (Some(_), Some(_)) => Err(anyhow::anyhow!("provide path or yaml, not both")),
        (None, None) => Err(anyhow::anyhow!("provide path or yaml")),
    };
    let base_config = match base_config {
        Ok(config) => config,
        Err(error) => {
            return Json(serde_json::json!({
                "ok": false,
                "error": error.to_string(),
            }))
        }
    };
    if let Err(error) = runtime.set_base_config(base_config) {
        return Json(serde_json::json!({
            "ok": false,
            "error": error.to_string(),
        }));
    }
    match reload_active_subscription_config(&runtime) {
        Ok(config) => Json(serde_json::json!({
            "ok": true,
            "runtime": {
                "reloaded": true,
                "summary": config.summary(),
                "default_outbound": config.core.default_outbound,
            },
        })),
        Err(error) => Json(serde_json::json!({
            "ok": false,
            "error": error.to_string(),
        })),
    }
}

fn default_enabled() -> bool {
    true
}

fn subscription_store(runtime: &Runtime) -> SubscriptionStore {
    SubscriptionStore::new(runtime.config().subscriptions.store_path.clone())
}

fn reload_active_subscription_config(
    runtime: &Runtime,
) -> anyhow::Result<crate::config::SuperConfig> {
    let base_config = runtime.base_config();
    let store = SubscriptionStore::new(base_config.subscriptions.store_path.clone());
    let config = store.active_runtime_config(
        base_config,
        runtime.config().subscriptions.use_first_node_as_default,
    )?;
    runtime.reload_config(config)
}

fn outbound_api_kind(config: &OutboundConfig) -> String {
    match config {
        OutboundConfig::Direct { .. } => "Direct".to_string(),
        OutboundConfig::Reject { .. } => "Reject".to_string(),
        OutboundConfig::Http { .. } => "HTTP".to_string(),
        OutboundConfig::Socks5 { .. } => "Socks5".to_string(),
        OutboundConfig::Shadowsocks { .. } => "Shadowsocks".to_string(),
        OutboundConfig::Ssr { .. } => "ShadowsocksR".to_string(),
        OutboundConfig::Snell { .. } => "Snell".to_string(),
        OutboundConfig::Trojan { .. } => "Trojan".to_string(),
        OutboundConfig::Vmess { .. } => "VMess".to_string(),
        OutboundConfig::Vless { .. } => "VLESS".to_string(),
        OutboundConfig::Hysteria { .. } => "Hysteria".to_string(),
        OutboundConfig::Hysteria2 { .. } => "Hysteria2".to_string(),
        OutboundConfig::Tuic { .. } => "TUIC".to_string(),
        OutboundConfig::WireGuard { .. } => "WireGuard".to_string(),
        OutboundConfig::AnyTls { .. } => "AnyTLS".to_string(),
        OutboundConfig::ShadowTls { .. } => "ShadowTLS".to_string(),
        OutboundConfig::Naive { .. } => "Naive".to_string(),
        OutboundConfig::Ssh { .. } => "SSH".to_string(),
        OutboundConfig::Mieru { .. } => "Mieru".to_string(),
        OutboundConfig::Juicity { .. } => "Juicity".to_string(),
        OutboundConfig::Masque { .. } => "MASQUE".to_string(),
        OutboundConfig::OpenVpn { .. } => "OpenVPN".to_string(),
        OutboundConfig::Unknown { protocol, .. } => format!("Unknown:{protocol}"),
        OutboundConfig::Group { kind, .. } => kind.clone(),
    }
}

fn item_time() -> String {
    chrono::Utc::now().to_rfc3339()
}

async fn subscription_source_text(
    text: Option<String>,
    url: Option<String>,
    timeout_secs: u64,
) -> anyhow::Result<String> {
    if let Some(text) = text.filter(|item| !item.trim().is_empty()) {
        return Ok(text);
    }
    let Some(url) = url else {
        return Err(anyhow::anyhow!("provide text or url"));
    };
    fetch_subscription_url(url, timeout_secs).await
}

async fn fetch_subscription_url(url: String, timeout_secs: u64) -> anyhow::Result<String> {
    let response = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(timeout_secs.max(1)))
        .build()?
        .get(url)
        .header(
            "User-Agent",
            concat!("Skyhook/", env!("CARGO_PKG_VERSION")),
        )
        .send()
        .await?
        .error_for_status()?;
    Ok(response.text().await?)
}
