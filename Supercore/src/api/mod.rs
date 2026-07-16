use std::{collections::HashMap, collections::HashSet, path::PathBuf, sync::Arc};

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
    concurrency: Option<usize>,
    names: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct ProbeGroupRequest {
    group: String,
    url: Option<String>,
    timeout_ms: Option<u64>,
    concurrency: Option<usize>,
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
        .route("/supercore/version", get(version))
        .route("/supercore/status", get(status))
        .route("/supercore/connections", get(connections))
        .route(
            "/supercore/traffic/subscriptions",
            get(subscription_traffic),
        )
        .route("/supercore/outbounds", get(outbounds))
        .route("/supercore/outbounds/use", post(use_outbound))
        .route("/supercore/groups", get(groups))
        .route("/supercore/countries", get(countries))
        .route("/supercore/countries/use", post(use_country))
        .route("/supercore/probe/outbounds", post(probe_outbounds))
        .route("/supercore/probe/groups/{name}", post(probe_group))
        .route("/supercore/probe/group", post(probe_group_body))
        .route("/supercore/route/decision", post(route_decision))
        .route("/supercore/subscriptions", get(subscriptions))
        .route("/supercore/subscriptions/import", post(import_subscription))
        .route("/supercore/subscriptions/use", post(use_subscription))
        .route(
            "/supercore/subscriptions/reload-active",
            post(reload_active_subscription),
        )
        .route(
            "/supercore/subscriptions/update-all",
            post(update_all_subscriptions),
        )
        .route(
            "/supercore/subscriptions/active-config",
            post(active_subscription_config),
        )
        .route(
            "/supercore/smart-rules",
            get(smart_rules).post(upsert_smart_rule),
        )
        .route(
            "/supercore/smart-rules/enabled",
            post(set_smart_rule_enabled),
        )
        .route("/supercore/smart-rules/delete", post(delete_smart_rule))
        .route(
            "/supercore/smart-rules/apply-recommendations",
            post(apply_smart_recommendations),
        )
        .route(
            "/supercore/smart-rules/apply-recommendation",
            post(apply_smart_recommendation),
        )
        .route("/supercore/logs", get(logs))
        .route("/supercore/config", get(config))
        .route("/supercore/config/reload", post(reload_config))
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
        name: "Supercore",
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
            concurrency: request.concurrency,
            names: request.names,
        })
        .unwrap_or_default();
    let results = runtime.probe_all_outbounds_with(options).await;
    let failure_summary = build_probe_failure_summary(&results);
    Json(serde_json::json!({
        "results": results,
        "failure_summary": failure_summary,
    }))
}

async fn probe_group(
    State(runtime): State<Arc<Runtime>>,
    axum::extract::Path(name): axum::extract::Path<String>,
    request: Option<Json<ProbeRequest>>,
) -> Json<serde_json::Value> {
    let config = runtime.config();
    let member_names = collect_group_probe_members(&config, &name);
    if member_names.is_empty() {
        return Json(serde_json::json!({
            "ok": false,
            "error": format!("group '{}' has no probeable members", name),
        }));
    }
    let request = request.map(|Json(request)| request);
    let mut names = request
        .as_ref()
        .and_then(|request| request.names.clone())
        .filter(|items| !items.is_empty())
        .unwrap_or_else(Vec::new);
    if names.is_empty() {
        names = member_names;
    }
    let request_url = request.as_ref().and_then(|request| request.url.clone());
    let request_timeout_ms = request.as_ref().and_then(|request| request.timeout_ms);
    let request_concurrency = request.as_ref().and_then(|request| request.concurrency);
    let options = ProbeOptions {
        url: request_url,
        timeout_ms: request_timeout_ms,
        concurrency: request_concurrency,
        names: Some(names),
    };
    let results = runtime.probe_all_outbounds_with(options).await;
    let failure_summary = build_probe_failure_summary(&results);
    Json(serde_json::json!({
        "ok": true,
        "group": name,
        "results": results,
        "failure_summary": failure_summary,
    }))
}

async fn probe_group_body(
    State(runtime): State<Arc<Runtime>>,
    Json(request): Json<ProbeGroupRequest>,
) -> Json<serde_json::Value> {
    let config = runtime.config();
    let member_names = collect_group_probe_members(&config, &request.group);
    if member_names.is_empty() {
        return Json(serde_json::json!({
            "ok": false,
            "error": format!("group '{}' has no probeable members", request.group),
        }));
    }
    let options = ProbeOptions {
        url: request.url,
        timeout_ms: request.timeout_ms,
        concurrency: request.concurrency,
        names: Some(member_names),
    };
    let results = runtime.probe_all_outbounds_with(options).await;
    let failure_summary = build_probe_failure_summary(&results);
    Json(serde_json::json!({
        "ok": true,
        "group": request.group,
        "results": results,
        "failure_summary": failure_summary,
    }))
}

fn build_probe_failure_summary(results: &[crate::core::ProbeResult]) -> HashMap<String, usize> {
    let mut summary: HashMap<String, usize> = HashMap::new();
    for result in results.iter().filter(|result| !result.success) {
        let kind = result
            .failure_kind
            .clone()
            .unwrap_or_else(|| "unknown".to_string());
        *summary.entry(kind).or_insert(0) += 1;
    }
    summary
}

fn collect_group_probe_members(config: &SuperConfig, group_name: &str) -> Vec<String> {
    let outbound_map: HashMap<&str, &OutboundConfig> = config
        .outbounds
        .iter()
        .map(|outbound| (outbound.name(), outbound))
        .collect();
    let Some(OutboundConfig::Group {
        members: root_members,
        ..
    }) = outbound_map.get(group_name)
    else {
        return Vec::new();
    };

    let mut visited = HashSet::new();
    let mut members = Vec::new();
    collect_group_members(
        root_members.as_slice(),
        &outbound_map,
        &mut visited,
        &mut members,
    );
    members
}

fn collect_group_members(
    members: &[String],
    outbound_map: &HashMap<&str, &OutboundConfig>,
    visited: &mut HashSet<String>,
    output: &mut Vec<String>,
) {
    for name in members {
        let trimmed = name.trim();
        if trimmed.is_empty() {
            continue;
        }
        if !visited.insert(trimmed.to_string()) {
            continue;
        }

        if trimmed.eq_ignore_ascii_case("direct") || trimmed.eq_ignore_ascii_case("reject") {
            continue;
        }

        let Some(outbound) = outbound_map.get(trimmed) else {
            output.push(trimmed.to_string());
            continue;
        };

        if let OutboundConfig::Group { members, .. } = outbound {
            collect_group_members(members, outbound_map, visited, output);
        } else {
            output.push(trimmed.to_string());
        }
    }
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
            concat!("Supercore/", env!("CARGO_PKG_VERSION")),
        )
        .send()
        .await?
        .error_for_status()?;
    Ok(response.text().await?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_collect_group_probe_members_flattens_nested_groups() {
        let mut config = SuperConfig::default();
        config.outbounds = vec![
            OutboundConfig::Direct {
                name: "direct".to_string(),
            },
            OutboundConfig::Reject {
                name: "reject".to_string(),
            },
            OutboundConfig::Group {
                name: "node-group".to_string(),
                kind: "url-test".to_string(),
                members: vec![
                    "direct".to_string(),
                    "reject".to_string(),
                    "proxy-a".to_string(),
                    "child-group".to_string(),
                ],
            },
            OutboundConfig::Shadowsocks {
                name: "proxy-a".to_string(),
                server: "proxy.example".to_string(),
                port: 443,
                method: "chacha20-ietf-poly1305".to_string(),
                password: "password".to_string(),
                plugin: None,
            },
            OutboundConfig::Group {
                name: "child-group".to_string(),
                kind: "url-test".to_string(),
                members: vec!["proxy-b".to_string(), "direct".to_string()],
            },
            OutboundConfig::Ssr {
                name: "proxy-b".to_string(),
                server: "proxy2.example".to_string(),
                port: 443,
                method: "aes-128-cfb".to_string(),
                password: "password".to_string(),
                protocol: "origin".to_string(),
                obfs: "plain".to_string(),
                protocol_param: None,
                obfs_param: None,
            },
        ];

        let members = collect_group_probe_members(&config, "node-group");
        assert_eq!(members, vec!["proxy-a".to_string(), "proxy-b".to_string()]);
    }

    #[test]
    fn test_collect_group_probe_members_skips_cycles_and_unknown_members() {
        let mut config = SuperConfig::default();
        config.outbounds = vec![
            OutboundConfig::Group {
                name: "cyclic-group-a".to_string(),
                kind: "url-test".to_string(),
                members: vec![
                    "cyclic-group-b".to_string(),
                    "missing".to_string(),
                    " ".to_string(),
                ],
            },
            OutboundConfig::Group {
                name: "cyclic-group-b".to_string(),
                kind: "url-test".to_string(),
                members: vec!["cyclic-group-a".to_string(), "direct".to_string()],
            },
        ];

        let members = collect_group_probe_members(&config, "cyclic-group-a");
        assert_eq!(members, vec!["missing".to_string()]);
    }

    #[test]
    fn test_collect_group_probe_members_handles_slash_in_group_name() {
        let mut config = SuperConfig::default();
        config.outbounds = vec![
            OutboundConfig::Group {
                name: "group/a".to_string(),
                kind: "select".to_string(),
                members: vec!["proxy-a".to_string(), "direct".to_string()],
            },
            OutboundConfig::Shadowsocks {
                name: "proxy-a".to_string(),
                server: "example.com".to_string(),
                port: 443,
                method: "chacha20-ietf-poly1305".to_string(),
                password: "password".to_string(),
                plugin: None,
            },
        ];

        let members = collect_group_probe_members(&config, "group/a");
        assert_eq!(members, vec!["proxy-a".to_string()]);
    }

    #[test]
    fn test_collect_group_probe_members_handles_unicode_group_name() {
        let mut config = SuperConfig::default();
        config.outbounds = vec![
            OutboundConfig::Group {
                name: "香港节点".to_string(),
                kind: "select".to_string(),
                members: vec!["proxy-b".to_string(), "reject".to_string()],
            },
            OutboundConfig::Shadowsocks {
                name: "proxy-b".to_string(),
                server: "example.com".to_string(),
                port: 443,
                method: "chacha20-ietf-poly1305".to_string(),
                password: "password".to_string(),
                plugin: None,
            },
        ];

        let members = collect_group_probe_members(&config, "香港节点");
        assert_eq!(members, vec!["proxy-b".to_string()]);
    }

    #[test]
    fn test_collect_group_probe_members_handles_emoji_group_name() {
        let mut config = SuperConfig::default();
        config.outbounds = vec![
            OutboundConfig::Group {
                name: "🚀-group".to_string(),
                kind: "select".to_string(),
                members: vec!["proxy-c".to_string()],
            },
            OutboundConfig::Shadowsocks {
                name: "proxy-c".to_string(),
                server: "example.com".to_string(),
                port: 443,
                method: "chacha20-ietf-poly1305".to_string(),
                password: "password".to_string(),
                plugin: None,
            },
        ];

        let members = collect_group_probe_members(&config, "🚀-group");
        assert_eq!(members, vec!["proxy-c".to_string()]);
    }
}
