use std::sync::Arc;

use axum::{extract::State, response::Response, Json};

use crate::{core::Runtime, routing::Destination};

use super::super::{
    classified_api_error, json_response, smart_route_rule, ApplySmartRecommendationRequest,
    ApplySmartRecommendationsRequest, CountryUseRequest, OutboundUseRequest,
    SmartRuleDeleteRequest, SmartRuleEnabledRequest, SmartRuleRequest,
};

pub(super) async fn outbounds(State(runtime): State<Arc<Runtime>>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "outbounds": runtime.telemetry().outbound_health().await,
        "groups": runtime.proxy_groups().await,
        "capabilities": runtime.outbound_capabilities(),
    }))
}

pub(super) async fn rules_snapshot(State(runtime): State<Arc<Runtime>>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "rules": runtime.config().rules,
        "smart": runtime.smart_snapshot(),
    }))
}

pub(super) async fn groups(State(runtime): State<Arc<Runtime>>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "groups": runtime.proxy_groups().await,
    }))
}

pub(super) async fn countries(State(runtime): State<Arc<Runtime>>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "countries": runtime.country_groups().await,
    }))
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
    Json(serde_json::json!(runtime.smart_snapshot()))
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
