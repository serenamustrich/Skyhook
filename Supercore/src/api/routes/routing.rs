use std::sync::Arc;

use axum::{extract::State, response::Response, Json};

use crate::{core::Runtime, routing::Destination};

use super::super::{
    classified_api_error, invalid_request, json_response, paginate_values, smart_route_rule,
    stable_value_id, ApplySmartRecommendationRequest, ApplySmartRecommendationsRequest,
    CountryUseRequest, ListQuery, OutboundUseRequest, SmartRuleDeleteRequest,
    SmartRuleEnabledRequest, SmartRuleRequest, SortOrder,
};

pub(super) async fn outbounds(State(runtime): State<Arc<Runtime>>, query: ListQuery) -> Response {
    let mut health = runtime
        .telemetry()
        .outbound_health()
        .await
        .into_iter()
        .map(|item| {
            (
                item.name.clone(),
                serde_json::to_value(item).unwrap_or(serde_json::Value::Null),
            )
        })
        .collect::<std::collections::HashMap<_, _>>();
    let mut runtime_stats = runtime.outbound_runtime_stats();
    let items = runtime
        .outbound_capabilities()
        .into_iter()
        .map(|capability| {
            let name = capability.name.clone();
            let kind = capability.kind.clone();
            let health = health.remove(&name);
            let stats = runtime_stats.remove(&name);
            serde_json::json!({
                "name": name,
                "kind": kind,
                "health": health,
                "capability": capability,
                "runtime": stats,
            })
        })
        .collect();
    let page = match paginate_values(
        "outbounds",
        items,
        query,
        "name",
        SortOrder::Asc,
        &["name", "kind", "health.last_latency_ms", "health.score"],
        "name",
    ) {
        Ok(page) => page,
        Err(error) => return invalid_request("invalid_pagination", error.to_string()),
    };
    json_response(page.envelope("outbounds", serde_json::Map::new()))
}

pub(super) async fn rules_snapshot(
    State(runtime): State<Arc<Runtime>>,
    query: ListQuery,
) -> Response {
    let items = runtime
        .config()
        .rules
        .into_iter()
        .map(|rule| {
            let mut value = serde_json::to_value(rule).unwrap_or(serde_json::Value::Null);
            let id = stable_value_id("rule", &value);
            if let Some(object) = value.as_object_mut() {
                object.insert("id".to_string(), serde_json::Value::String(id));
            }
            value
        })
        .collect();
    let page = match paginate_values(
        "rules",
        items,
        query,
        "value",
        SortOrder::Asc,
        &["id", "target", "value", "outbound"],
        "id",
    ) {
        Ok(page) => page,
        Err(error) => return invalid_request("invalid_pagination", error.to_string()),
    };
    let mut extras = serde_json::Map::new();
    extras.insert("smart".to_string(), smart_summary_value(&runtime));
    json_response(page.envelope("rules", extras))
}

pub(super) async fn groups(State(runtime): State<Arc<Runtime>>, query: ListQuery) -> Response {
    let items = runtime
        .proxy_groups()
        .await
        .into_iter()
        .map(|group| serde_json::to_value(group).unwrap_or(serde_json::Value::Null))
        .collect();
    let page = match paginate_values(
        "groups",
        items,
        query,
        "name",
        SortOrder::Asc,
        &["name", "kind", "selected_member"],
        "name",
    ) {
        Ok(page) => page,
        Err(error) => return invalid_request("invalid_pagination", error.to_string()),
    };
    json_response(page.envelope("groups", serde_json::Map::new()))
}

pub(super) async fn countries(State(runtime): State<Arc<Runtime>>, query: ListQuery) -> Response {
    let items = runtime
        .country_groups()
        .await
        .into_iter()
        .map(|country| serde_json::to_value(country).unwrap_or(serde_json::Value::Null))
        .collect();
    let page = match paginate_values(
        "countries",
        items,
        query,
        "code",
        SortOrder::Asc,
        &["code", "name", "node_count", "best_outbound"],
        "code",
    ) {
        Ok(page) => page,
        Err(error) => return invalid_request("invalid_pagination", error.to_string()),
    };
    json_response(page.envelope("countries", serde_json::Map::new()))
}

pub(super) async fn use_country(
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

pub(super) async fn route_decision(
    State(runtime): State<Arc<Runtime>>,
    Json(destination): Json<Destination>,
) -> Response {
    json_response(serde_json::json!({
        "destination": destination,
        "decision": runtime.decide(&destination),
    }))
}

pub(super) async fn smart_rules(State(runtime): State<Arc<Runtime>>) -> Json<serde_json::Value> {
    Json(smart_summary_value(&runtime))
}

fn smart_summary_value(runtime: &Runtime) -> serde_json::Value {
    let mut snapshot =
        serde_json::to_value(runtime.smart_snapshot()).unwrap_or_else(|_| serde_json::json!({}));
    if let Some(snapshot) = snapshot.as_object_mut() {
        snapshot.insert("rules".to_string(), serde_json::json!([]));
        snapshot.insert("observations".to_string(), serde_json::json!([]));
        snapshot.insert("recommendations".to_string(), serde_json::json!([]));
        snapshot.remove("recommendation_buckets");
    }
    snapshot
}

pub(super) async fn smart_rule_list(
    State(runtime): State<Arc<Runtime>>,
    query: ListQuery,
) -> Response {
    let items = runtime
        .smart_snapshot()
        .rules
        .into_iter()
        .map(|rule| {
            let mut value = serde_json::to_value(rule).unwrap_or(serde_json::Value::Null);
            let id = stable_value_id("smart-rule", &value);
            if let Some(object) = value.as_object_mut() {
                object.insert("id".to_string(), serde_json::Value::String(id));
            }
            value
        })
        .collect();
    let page = match paginate_values(
        "smart-rules",
        items,
        query,
        "value",
        SortOrder::Asc,
        &["id", "target", "value", "outbound", "enabled"],
        "id",
    ) {
        Ok(page) => page,
        Err(error) => return invalid_request("invalid_pagination", error.to_string()),
    };
    json_response(page.envelope("rules", serde_json::Map::new()))
}

pub(super) async fn smart_observations(
    State(runtime): State<Arc<Runtime>>,
    query: ListQuery,
) -> Response {
    let items = runtime
        .smart_snapshot()
        .observations
        .into_iter()
        .map(|observation| serde_json::to_value(observation).unwrap_or(serde_json::Value::Null))
        .collect();
    let page = match paginate_values(
        "smart-observations",
        items,
        query,
        "last_seen_at",
        SortOrder::Desc,
        &[
            "key",
            "target",
            "value",
            "visits",
            "last_outbound",
            "last_direct_latency_ms",
            "last_seen_at",
            "last_probe_at",
        ],
        "key",
    ) {
        Ok(page) => page,
        Err(error) => return invalid_request("invalid_pagination", error.to_string()),
    };
    json_response(page.envelope("observations", serde_json::Map::new()))
}

pub(super) async fn smart_recommendations(
    State(runtime): State<Arc<Runtime>>,
    query: ListQuery,
) -> Response {
    let items = runtime
        .smart_snapshot()
        .recommendations
        .into_iter()
        .map(|recommendation| {
            let mut value = serde_json::to_value(recommendation).unwrap_or(serde_json::Value::Null);
            let id = stable_value_id("smart-recommendation", &value);
            if let Some(object) = value.as_object_mut() {
                object.insert("id".to_string(), serde_json::Value::String(id));
            }
            value
        })
        .collect();
    let page = match paginate_values(
        "smart-recommendations",
        items,
        query,
        "confidence",
        SortOrder::Desc,
        &[
            "id",
            "target",
            "value",
            "recommended_outbound",
            "action",
            "confidence",
            "latency_ms",
        ],
        "id",
    ) {
        Ok(page) => page,
        Err(error) => return invalid_request("invalid_pagination", error.to_string()),
    };
    json_response(page.envelope("recommendations", serde_json::Map::new()))
}

pub(super) async fn use_outbound(
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

pub(super) async fn upsert_smart_rule(
    State(runtime): State<Arc<Runtime>>,
    Json(request): Json<SmartRuleRequest>,
) -> Response {
    match runtime.upsert_smart_rule(smart_route_rule(request)) {
        Ok(rules) => json_response(serde_json::json!({
            "ok": true,
            "rules": rules,
        })),
        Err(error) => classified_api_error("smart_rule_upsert_failed", error),
    }
}

pub(super) async fn set_smart_rule_enabled(
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

pub(super) async fn delete_smart_rule(
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

pub(super) async fn apply_smart_recommendations(
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

pub(super) async fn apply_smart_recommendation(
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
