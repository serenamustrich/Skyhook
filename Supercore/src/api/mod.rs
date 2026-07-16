use std::{collections::HashMap, collections::HashSet, path::PathBuf, sync::Arc};

use anyhow::anyhow;
use axum::{
    extract::{Request, State},
    http::{header::AUTHORIZATION, HeaderMap, Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use tower_http::trace::TraceLayer;

use crate::{
    config::{OutboundConfig, RuleTarget, SmartRouteRule, SuperConfig},
    core::{ProbeOptions, Runtime},
    outbound::error::{classify_message, OutboundErrorKind},
    routing::Destination,
    smart::SmartRecommendationAction,
    subscription_store::SubscriptionStore,
};

const CONTROL_TOKEN_ENV: &str = "SKYHOOK_CONTROL_TOKEN";
const CONTROL_TOKEN_FILE_ENV: &str = "SKYHOOK_CONTROL_TOKEN_FILE";
const MIN_CONTROL_TOKEN_BYTES: usize = 32;

#[derive(Clone)]
struct ControlAuthState {
    token: Option<Arc<str>>,
}

#[derive(Debug, Serialize)]
struct VersionResponse {
    name: &'static str,
    version: &'static str,
    engine: &'static str,
}

#[derive(Debug, Serialize)]
struct ApiErrorResponse {
    code: &'static str,
    kind: &'static str,
    message: String,
    retryable: bool,
    trace_id: String,
    details: serde_json::Value,
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
    validate_control_listen(control_listen)?;
    let auth = ControlAuthState {
        token: load_control_token()?,
    };
    if auth.token.is_none() {
        tracing::warn!(
            "control API write operations are disabled because no control token was configured"
        );
    }
    let app = Router::new()
        .route("/health", get(health))
        .route("/v1/version", get(version))
        .route("/v1/status", get(status))
        .route("/v1/outbounds", get(outbounds))
        .route("/v1/outbounds/use", post(use_outbound))
        .route("/v1/groups", get(groups))
        .route("/v1/countries", get(countries))
        .route("/v1/countries/use", post(use_country))
        .route("/v1/probes", post(probe_outbounds))
        .route("/v1/probes/group", post(probe_group_body))
        .route("/v1/route/decision", post(route_decision))
        .route("/v1/subscriptions", get(subscriptions))
        .route("/v1/subscriptions/import", post(import_subscription))
        .route("/v1/subscriptions/use", post(use_subscription))
        .route(
            "/v1/subscriptions/reload-active",
            post(reload_active_subscription),
        )
        .route(
            "/v1/subscriptions/update-all",
            post(update_all_subscriptions),
        )
        .route(
            "/v1/subscriptions/active-config",
            post(active_subscription_config),
        )
        .route("/v1/providers/proxies", get(proxy_providers))
        .route("/v1/providers/rules", get(rule_providers))
        .route("/v1/rules", get(rules_snapshot))
        .route("/v1/smart-rules", get(smart_rules).post(upsert_smart_rule))
        .route("/v1/smart-rules/enabled", post(set_smart_rule_enabled))
        .route("/v1/smart-rules/delete", post(delete_smart_rule))
        .route(
            "/v1/smart-rules/apply-recommendations",
            post(apply_smart_recommendations),
        )
        .route(
            "/v1/smart-rules/apply-recommendation",
            post(apply_smart_recommendation),
        )
        .route("/v1/traffic", get(traffic))
        .route("/v1/traffic/subscriptions", get(subscription_traffic))
        .route("/v1/connections", get(connections))
        .route("/v1/logs", get(logs))
        .route("/v1/config", get(config))
        .route("/v1/config/reload", post(reload_config))
        .route("/v1/tun", get(tun_status))
        .route("/v1/doctor", get(doctor))
        .layer(middleware::from_fn_with_state(auth, authorize_writes))
        .layer(TraceLayer::new_for_http())
        .with_state(runtime);
    let listener = tokio::net::TcpListener::bind(control_listen).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

fn validate_control_listen(control_listen: std::net::SocketAddr) -> anyhow::Result<()> {
    if control_listen.ip().is_loopback() {
        Ok(())
    } else {
        Err(anyhow!(
            "control API must listen on loopback; configured address is {control_listen}"
        ))
    }
}

fn load_control_token() -> anyhow::Result<Option<Arc<str>>> {
    if let Some(token) = normalized_control_token(std::env::var(CONTROL_TOKEN_ENV).ok())? {
        return Ok(Some(token));
    }
    let Some(path) = std::env::var_os(CONTROL_TOKEN_FILE_ENV) else {
        return Ok(None);
    };
    let path = PathBuf::from(path);
    let token = std::fs::read_to_string(&path).map_err(|error| {
        anyhow!(
            "failed to read control token file '{}': {error}",
            path.display()
        )
    })?;
    normalized_control_token(Some(token))
}

fn normalized_control_token(token: Option<String>) -> anyhow::Result<Option<Arc<str>>> {
    let Some(token) = token else {
        return Ok(None);
    };
    let token = token.trim();
    if token.is_empty() {
        return Ok(None);
    }
    if token.as_bytes().len() < MIN_CONTROL_TOKEN_BYTES {
        return Err(anyhow!(
            "control token must contain at least {MIN_CONTROL_TOKEN_BYTES} bytes"
        ));
    }
    Ok(Some(Arc::from(token)))
}

async fn authorize_writes(
    State(auth): State<ControlAuthState>,
    request: Request,
    next: Next,
) -> Response {
    if !is_write_method(request.method()) {
        return next.run(request).await;
    }
    if request_has_valid_token(request.headers(), auth.token.as_deref()) {
        return next.run(request).await;
    }

    let trace_id = request
        .headers()
        .get("x-skyhook-trace-id")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.trim().is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let (code, message) = if auth.token.is_some() {
        (
            "control_auth_invalid",
            "a valid bearer token is required for this control operation",
        )
    } else {
        (
            "control_auth_unconfigured",
            "control API write operations are disabled until a control token is configured",
        )
    };
    let body = ApiErrorResponse {
        code,
        kind: "authentication",
        message: message.to_string(),
        retryable: false,
        trace_id,
        details: serde_json::json!({}),
    };
    (StatusCode::UNAUTHORIZED, Json(body)).into_response()
}

fn is_write_method(method: &Method) -> bool {
    method != Method::GET && method != Method::HEAD && method != Method::OPTIONS
}

fn request_has_valid_token(headers: &HeaderMap, expected: Option<&str>) -> bool {
    let Some(expected) = expected else {
        return false;
    };
    let Some(provided) = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
    else {
        return false;
    };
    constant_time_eq(provided.as_bytes(), expected.as_bytes())
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right.iter())
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn json_response(value: serde_json::Value) -> Response {
    Json(value).into_response()
}

fn api_error_response(
    status: StatusCode,
    code: &'static str,
    kind: OutboundErrorKind,
    message: impl Into<String>,
    details: serde_json::Value,
) -> Response {
    let body = ApiErrorResponse {
        code,
        kind: kind.as_str(),
        message: message.into(),
        retryable: kind.retryable(),
        trace_id: uuid::Uuid::new_v4().to_string(),
        details,
    };
    (status, Json(body)).into_response()
}

fn classified_api_error(code: &'static str, error: impl std::fmt::Display) -> Response {
    let message = error.to_string();
    let kind = classify_message(&message);
    let status = match kind {
        OutboundErrorKind::Authentication => StatusCode::UNAUTHORIZED,
        OutboundErrorKind::Timeout => StatusCode::GATEWAY_TIMEOUT,
        OutboundErrorKind::Dns
        | OutboundErrorKind::Tcp
        | OutboundErrorKind::Tls
        | OutboundErrorKind::HttpStatus
        | OutboundErrorKind::EmptyResponse => StatusCode::BAD_GATEWAY,
        OutboundErrorKind::Cancelled => StatusCode::CONFLICT,
        OutboundErrorKind::Protocol | OutboundErrorKind::Unsupported => {
            StatusCode::UNPROCESSABLE_ENTITY
        }
        OutboundErrorKind::Internal => StatusCode::INTERNAL_SERVER_ERROR,
    };
    api_error_response(status, code, kind, message, serde_json::json!({}))
}

fn invalid_request(code: &'static str, message: impl Into<String>) -> Response {
    api_error_response(
        StatusCode::BAD_REQUEST,
        code,
        OutboundErrorKind::Protocol,
        message,
        serde_json::json!({}),
    )
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

async fn tun_status(State(runtime): State<Arc<Runtime>>) -> Json<serde_json::Value> {
    let config = runtime.config();
    Json(serde_json::json!({
        "tun": config.tun,
        "dns": config.dns,
    }))
}

async fn doctor(State(runtime): State<Arc<Runtime>>) -> Json<serde_json::Value> {
    let config = runtime.config();
    Json(serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "summary": config.summary(),
        "capabilities": runtime.outbound_capabilities(),
        "outbound_health": runtime.telemetry().outbound_health().await,
        "tun": config.tun,
        "dns": config.dns,
    }))
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

async fn subscription_traffic(State(runtime): State<Arc<Runtime>>) -> Response {
    match subscription_store(&runtime).index() {
        Ok(index) => json_response(serde_json::json!({
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
        Err(error) => classified_api_error("subscription_traffic_read_failed", error),
    }
}

async fn outbounds(State(runtime): State<Arc<Runtime>>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "outbounds": runtime.telemetry().outbound_health().await,
        "groups": runtime.proxy_groups().await,
        "capabilities": runtime.outbound_capabilities(),
    }))
}

async fn rules_snapshot(State(runtime): State<Arc<Runtime>>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "rules": runtime.config().rules,
        "smart": runtime.smart_snapshot(),
    }))
}

async fn proxy_providers(State(runtime): State<Arc<Runtime>>) -> Json<serde_json::Value> {
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

async fn rule_providers(State(runtime): State<Arc<Runtime>>) -> Json<serde_json::Value> {
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
) -> Response {
    match runtime.use_country_group(&request.code).await {
        Ok(config) => json_response(serde_json::json!({
            "ok": true,
            "runtime": {
                "reloaded": true,
                "summary": config.summary(),
                "default_outbound": config.core.default_outbound,
            },
        })),
        Err(error) => classified_api_error("country_selection_failed", error),
    }
}

async fn probe_outbounds(
    State(runtime): State<Arc<Runtime>>,
    request: Option<Json<ProbeRequest>>,
) -> Response {
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
    json_response(serde_json::json!({
        "results": results,
        "failure_summary": failure_summary,
    }))
}

async fn probe_group_body(
    State(runtime): State<Arc<Runtime>>,
    Json(request): Json<ProbeGroupRequest>,
) -> Response {
    let config = runtime.config();
    let member_names = collect_group_probe_members(&config, &request.group);
    if member_names.is_empty() {
        return invalid_request(
            "probe_group_empty",
            format!("group '{}' has no probeable members", request.group),
        );
    }
    let options = ProbeOptions {
        url: request.url,
        timeout_ms: request.timeout_ms,
        concurrency: request.concurrency,
        names: Some(member_names),
    };
    let results = runtime.probe_all_outbounds_with(options).await;
    let failure_summary = build_probe_failure_summary(&results);
    json_response(serde_json::json!({
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
) -> Response {
    json_response(serde_json::json!({
        "destination": destination,
        "decision": runtime.decide(&destination),
    }))
}

async fn smart_rules(State(runtime): State<Arc<Runtime>>) -> Json<serde_json::Value> {
    Json(serde_json::json!(runtime.smart_snapshot()))
}

async fn subscriptions(State(runtime): State<Arc<Runtime>>) -> Response {
    match subscription_store(&runtime).index() {
        Ok(index) => json_response(serde_json::json!({
            "ok": true,
            "index": index,
        })),
        Err(error) => classified_api_error("subscription_index_read_failed", error),
    }
}

async fn import_subscription(
    State(runtime): State<Arc<Runtime>>,
    Json(request): Json<SubscriptionImportRequest>,
) -> Response {
    let url = request.url.clone();
    let update_timeout_secs = runtime.config().subscriptions.update_timeout_secs;
    let text = match subscription_source_text(request.text, request.url, update_timeout_secs).await
    {
        Ok(text) => text,
        Err(error) => {
            return classified_api_error("subscription_download_failed", error);
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
                Ok(reload) => json_response(serde_json::json!({
                    "ok": true,
                    "result": result,
                    "runtime": reload,
                })),
                Err(error) => api_error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "subscription_reload_failed",
                    classify_message(&error.to_string()),
                    error.to_string(),
                    serde_json::json!({ "result": result }),
                ),
            }
        }
        Err(error) => classified_api_error("subscription_import_failed", error),
    }
}

async fn use_outbound(
    State(runtime): State<Arc<Runtime>>,
    Json(request): Json<OutboundUseRequest>,
) -> Response {
    match runtime.use_outbound(&request.name) {
        Ok(config) => json_response(serde_json::json!({
            "ok": true,
            "runtime": {
                "reloaded": true,
                "summary": config.summary(),
                "default_outbound": config.core.default_outbound,
            },
        })),
        Err(error) => classified_api_error("outbound_selection_failed", error),
    }
}

async fn use_subscription(
    State(runtime): State<Arc<Runtime>>,
    Json(request): Json<SubscriptionUseRequest>,
) -> Response {
    match subscription_store(&runtime).set_active(&request.id) {
        Ok(meta) => match reload_active_subscription_config(&runtime) {
            Ok(config) => json_response(serde_json::json!({
                "ok": true,
                "subscription": meta,
                "runtime": {
                    "reloaded": true,
                    "summary": config.summary(),
                },
            })),
            Err(error) => api_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "subscription_reload_failed",
                classify_message(&error.to_string()),
                error.to_string(),
                serde_json::json!({ "subscription": meta }),
            ),
        },
        Err(error) => classified_api_error("subscription_selection_failed", error),
    }
}

async fn update_all_subscriptions(State(runtime): State<Arc<Runtime>>) -> Response {
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
                Ok(reload) => json_response(serde_json::json!({
                    "ok": true,
                    "results": results,
                    "runtime": reload,
                })),
                Err(error) => api_error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "subscription_reload_failed",
                    classify_message(&error.to_string()),
                    error.to_string(),
                    serde_json::json!({ "results": results }),
                ),
            }
        }
        Err(error) => classified_api_error("subscription_update_failed", error),
    }
}

async fn reload_active_subscription(State(runtime): State<Arc<Runtime>>) -> Response {
    match reload_active_subscription_config(&runtime) {
        Ok(config) => json_response(serde_json::json!({
            "ok": true,
            "runtime": {
                "reloaded": true,
                "summary": config.summary(),
            },
        })),
        Err(error) => classified_api_error("subscription_reload_failed", error),
    }
}

async fn active_subscription_config(
    State(runtime): State<Arc<Runtime>>,
    request: Option<Json<ActiveSubscriptionConfigRequest>>,
) -> Response {
    let base_config = runtime.base_config();
    let use_first_node = request
        .and_then(|Json(request)| request.use_first_node)
        .unwrap_or(base_config.subscriptions.use_first_node_as_default);
    match SubscriptionStore::new(base_config.subscriptions.store_path.clone())
        .active_runtime_config(base_config, use_first_node)
    {
        Ok(config) => json_response(serde_json::json!({
            "ok": true,
            "config": config,
        })),
        Err(error) => classified_api_error("subscription_config_failed", error),
    }
}

async fn upsert_smart_rule(
    State(runtime): State<Arc<Runtime>>,
    Json(request): Json<SmartRuleRequest>,
) -> Response {
    let result = runtime.upsert_smart_rule(SmartRouteRule {
        target: request.target,
        value: request.value,
        outbound: request.outbound,
        enabled: request.enabled,
        note: request.note,
    });
    match result {
        Ok(rules) => json_response(serde_json::json!({
            "ok": true,
            "rules": rules,
        })),
        Err(error) => classified_api_error("smart_rule_upsert_failed", error),
    }
}

async fn set_smart_rule_enabled(
    State(runtime): State<Arc<Runtime>>,
    Json(request): Json<SmartRuleEnabledRequest>,
) -> Response {
    match runtime.set_smart_rule_enabled(request.target, &request.value, request.enabled) {
        Ok(rules) => json_response(serde_json::json!({
            "ok": true,
            "rules": rules,
        })),
        Err(error) => classified_api_error("smart_rule_update_failed", error),
    }
}

async fn delete_smart_rule(
    State(runtime): State<Arc<Runtime>>,
    Json(request): Json<SmartRuleDeleteRequest>,
) -> Response {
    match runtime.delete_smart_rule(request.target, &request.value) {
        Ok(rules) => json_response(serde_json::json!({
            "ok": true,
            "rules": rules,
        })),
        Err(error) => classified_api_error("smart_rule_delete_failed", error),
    }
}

async fn apply_smart_recommendations(
    State(runtime): State<Arc<Runtime>>,
    request: Option<Json<ApplySmartRecommendationsRequest>>,
) -> Response {
    let action = request.and_then(|Json(request)| request.action);
    let rules = runtime.apply_smart_recommendations(action);
    json_response(serde_json::json!({
        "ok": true,
        "rules": rules,
    }))
}

async fn apply_smart_recommendation(
    State(runtime): State<Arc<Runtime>>,
    Json(request): Json<ApplySmartRecommendationRequest>,
) -> Response {
    match runtime.apply_smart_recommendation(request.target, &request.value) {
        Ok(rules) => json_response(serde_json::json!({
            "ok": true,
            "rules": rules,
        })),
        Err(error) => classified_api_error("smart_recommendation_apply_failed", error),
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
) -> Response {
    let base_config = match (request.path, request.yaml) {
        (Some(path), None) => SuperConfig::load(&path),
        (None, Some(yaml)) => serde_yaml::from_str(&yaml).map_err(Into::into),
        (Some(_), Some(_)) => Err(anyhow::anyhow!("provide path or yaml, not both")),
        (None, None) => Err(anyhow::anyhow!("provide path or yaml")),
    };
    let base_config = match base_config {
        Ok(config) => config,
        Err(error) => {
            return invalid_request("config_load_failed", error.to_string());
        }
    };
    if let Err(error) = runtime.set_base_config(base_config) {
        return invalid_request("config_validation_failed", error.to_string());
    }
    match reload_active_subscription_config(&runtime) {
        Ok(config) => json_response(serde_json::json!({
            "ok": true,
            "runtime": {
                "reloaded": true,
                "summary": config.summary(),
                "default_outbound": config.core.default_outbound,
            },
        })),
        Err(error) => classified_api_error("config_reload_failed", error),
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
    use axum::http::HeaderValue;

    #[test]
    fn control_api_accepts_loopback_only() {
        assert!(validate_control_listen("127.0.0.1:9197".parse().unwrap()).is_ok());
        assert!(validate_control_listen("[::1]:9197".parse().unwrap()).is_ok());
        assert!(validate_control_listen("0.0.0.0:9197".parse().unwrap()).is_err());
    }

    #[test]
    fn write_auth_requires_matching_bearer_token() {
        let token = "0123456789abcdef0123456789abcdef";
        let mut headers = HeaderMap::new();
        assert!(!request_has_valid_token(&headers, Some(token)));
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer incorrect-token-value-000000"),
        );
        assert!(!request_has_valid_token(&headers, Some(token)));
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer 0123456789abcdef0123456789abcdef"),
        );
        assert!(request_has_valid_token(&headers, Some(token)));
        assert!(!request_has_valid_token(&headers, None));
    }

    #[test]
    fn control_token_rejects_short_values() {
        assert!(normalized_control_token(None).unwrap().is_none());
        assert!(normalized_control_token(Some(" ".to_string()))
            .unwrap()
            .is_none());
        assert!(normalized_control_token(Some("too-short".to_string())).is_err());
        assert!(
            normalized_control_token(Some("a".repeat(MIN_CONTROL_TOKEN_BYTES)))
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn control_token_comparison_is_exact() {
        assert!(constant_time_eq(b"same-value", b"same-value"));
        assert!(!constant_time_eq(b"same-value", b"different!"));
        assert!(!constant_time_eq(b"short", b"longer"));
    }

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
