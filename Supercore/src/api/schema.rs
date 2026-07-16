use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::{
    config::{RuleTarget, SmartRouteRule},
    smart::SmartRecommendationAction,
};

#[derive(Debug, Serialize)]
pub(super) struct VersionResponse {
    pub name: &'static str,
    pub version: &'static str,
    pub engine: &'static str,
}

#[derive(Debug, Serialize)]
pub(super) struct ApiErrorResponse {
    pub code: &'static str,
    pub kind: &'static str,
    pub message: String,
    pub retryable: bool,
    pub trace_id: String,
    pub details: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub(super) struct StatusResponse {
    pub mixed_listen: String,
    pub control_listen: String,
    pub outbounds: usize,
    pub rules: usize,
    pub smart_rules_enabled: bool,
    pub traffic: crate::telemetry::TrafficSnapshot,
}

#[derive(Debug, Deserialize)]
pub(super) struct ProbeRequest {
    pub url: Option<String>,
    pub timeout_ms: Option<u64>,
    pub concurrency: Option<usize>,
    pub names: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub(super) struct ProbeGroupRequest {
    pub group: String,
    pub url: Option<String>,
    pub timeout_ms: Option<u64>,
    pub concurrency: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub(super) struct SmartRuleRequest {
    pub target: RuleTarget,
    pub value: String,
    pub outbound: String,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct ApplySmartRecommendationsRequest {
    pub action: Option<SmartRecommendationAction>,
}

#[derive(Debug, Deserialize)]
pub(super) struct ApplySmartRecommendationRequest {
    pub target: RuleTarget,
    pub value: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct SmartRuleEnabledRequest {
    pub target: RuleTarget,
    pub value: String,
    pub enabled: bool,
}

#[derive(Debug, Deserialize)]
pub(super) struct SmartRuleDeleteRequest {
    pub target: RuleTarget,
    pub value: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct SubscriptionImportRequest {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub text: Option<String>,
    #[serde(default)]
    pub switch: bool,
}

#[derive(Debug, Deserialize)]
pub(super) struct SubscriptionUseRequest {
    pub id: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct SubscriptionUpdateRequest {
    pub id: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct CountryUseRequest {
    pub code: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct OutboundUseRequest {
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct ActiveSubscriptionConfigRequest {
    #[serde(default)]
    pub use_first_node: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub(super) struct ProviderUpdateRequest {
    #[serde(default)]
    pub subscription_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct ConfigReloadRequest {
    #[serde(default)]
    pub path: Option<PathBuf>,
    #[serde(default)]
    pub yaml: Option<String>,
}

pub(super) fn default_enabled() -> bool {
    true
}

pub(super) fn smart_route_rule(request: SmartRuleRequest) -> SmartRouteRule {
    SmartRouteRule {
        target: request.target,
        value: request.value,
        outbound: request.outbound,
        enabled: request.enabled,
        note: request.note,
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct ControlRouteSpec {
    pub method: &'static str,
    pub path: &'static str,
    pub operation_id: &'static str,
    pub tag: &'static str,
    pub write: bool,
    pub task: bool,
}

macro_rules! route {
    ($method:literal, $path:literal, $operation_id:literal, $tag:literal) => {
        ControlRouteSpec {
            method: $method,
            path: $path,
            operation_id: $operation_id,
            tag: $tag,
            write: false,
            task: false,
        }
    };
    ($method:literal, $path:literal, $operation_id:literal, $tag:literal, write) => {
        ControlRouteSpec {
            method: $method,
            path: $path,
            operation_id: $operation_id,
            tag: $tag,
            write: true,
            task: false,
        }
    };
    ($method:literal, $path:literal, $operation_id:literal, $tag:literal, task) => {
        ControlRouteSpec {
            method: $method,
            path: $path,
            operation_id: $operation_id,
            tag: $tag,
            write: true,
            task: true,
        }
    };
}

pub(super) const CONTROL_ROUTE_SPECS: &[ControlRouteSpec] = &[
    route!("GET", "/health", "health", "system"),
    route!("GET", "/v1/schema", "controlSchema", "system"),
    route!("GET", "/v1/version", "version", "system"),
    route!("GET", "/v1/status", "status", "system"),
    route!("GET", "/v1/outbounds", "listOutbounds", "routing"),
    route!("POST", "/v1/outbounds/use", "useOutbound", "routing", write),
    route!("GET", "/v1/groups", "listGroups", "routing"),
    route!("GET", "/v1/countries", "listCountries", "routing"),
    route!("POST", "/v1/countries/use", "useCountry", "routing", write),
    route!("POST", "/v1/probes", "probeOutbounds", "probes", task),
    route!("POST", "/v1/probes/group", "probeGroup", "probes", task),
    route!(
        "POST",
        "/v1/route/decision",
        "routeDecision",
        "routing",
        write
    ),
    route!(
        "GET",
        "/v1/subscriptions",
        "listSubscriptions",
        "subscriptions"
    ),
    route!(
        "POST",
        "/v1/subscriptions/import",
        "importSubscription",
        "subscriptions",
        task
    ),
    route!(
        "POST",
        "/v1/subscriptions/use",
        "useSubscription",
        "subscriptions",
        write
    ),
    route!(
        "POST",
        "/v1/subscriptions/reload-active",
        "reloadActiveSubscription",
        "subscriptions",
        write
    ),
    route!(
        "POST",
        "/v1/subscriptions/update",
        "updateSubscription",
        "subscriptions",
        task
    ),
    route!(
        "POST",
        "/v1/subscriptions/update-all",
        "updateAllSubscriptions",
        "subscriptions",
        task
    ),
    route!(
        "POST",
        "/v1/subscriptions/active-config",
        "activeSubscriptionConfig",
        "subscriptions",
        write
    ),
    route!(
        "GET",
        "/v1/providers/proxies",
        "listProxyProviders",
        "providers"
    ),
    route!(
        "GET",
        "/v1/providers/rules",
        "listRuleProviders",
        "providers"
    ),
    route!(
        "POST",
        "/v1/providers/update",
        "updateProviders",
        "providers",
        task
    ),
    route!(
        "POST",
        "/v1/providers/update-all",
        "updateAllProviders",
        "providers",
        task
    ),
    route!("GET", "/v1/rules", "listRules", "routing"),
    route!("GET", "/v1/smart-rules", "listSmartRules", "routing"),
    route!(
        "POST",
        "/v1/smart-rules",
        "upsertSmartRule",
        "routing",
        write
    ),
    route!(
        "POST",
        "/v1/smart-rules/enabled",
        "setSmartRuleEnabled",
        "routing",
        write
    ),
    route!(
        "POST",
        "/v1/smart-rules/delete",
        "deleteSmartRule",
        "routing",
        write
    ),
    route!(
        "POST",
        "/v1/smart-rules/apply-recommendations",
        "applySmartRecommendations",
        "routing",
        write
    ),
    route!(
        "POST",
        "/v1/smart-rules/apply-recommendation",
        "applySmartRecommendation",
        "routing",
        write
    ),
    route!("GET", "/v1/traffic", "traffic", "telemetry"),
    route!(
        "GET",
        "/v1/traffic/subscriptions",
        "subscriptionTraffic",
        "telemetry"
    ),
    route!("GET", "/v1/connections", "connections", "telemetry"),
    route!("GET", "/v1/logs", "logs", "telemetry"),
    route!("GET", "/v1/config", "config", "system"),
    route!("POST", "/v1/config/reload", "reloadConfig", "system", write),
    route!("GET", "/v1/tun", "tunStatus", "system"),
    route!("GET", "/v1/doctor", "doctor", "system"),
    route!("POST", "/v1/doctor/run", "runDoctor", "system", task),
    route!(
        "POST",
        "/v1/diagnostics/export",
        "exportDiagnostics",
        "system",
        task
    ),
    route!("POST", "/v1/geo/update", "updateGeo", "system", task),
    route!("GET", "/v1/tasks", "listTasks", "tasks"),
    route!("GET", "/v1/tasks/{id}", "taskStatus", "tasks"),
    route!(
        "POST",
        "/v1/tasks/{id}/cancel",
        "cancelTask",
        "tasks",
        write
    ),
    route!("GET", "/v1/events", "events", "events"),
];

pub(super) fn openapi_document() -> Value {
    let mut paths = Map::new();
    for route in CONTROL_ROUTE_SPECS {
        let operation = json!({
            "operationId": route.operation_id,
            "tags": [route.tag],
            "security": if route.write {
                json!([{ "bearerAuth": [] }])
            } else {
                json!([])
            },
            "responses": operation_responses(route),
        });
        let path = paths
            .entry(route.path.to_string())
            .or_insert_with(|| Value::Object(Map::new()));
        if let Value::Object(path_item) = path {
            path_item.insert(route.method.to_ascii_lowercase(), operation);
        }
    }

    json!({
        "openapi": "3.1.0",
        "info": {
            "title": "Skyhook Control API",
            "version": env!("CARGO_PKG_VERSION"),
            "description": "Versioned loopback control plane for the Skyhook proxy core."
        },
        "servers": [{
            "url": "http://127.0.0.1:{port}",
            "variables": { "port": { "default": "9197" } }
        }],
        "paths": paths,
        "components": {
            "securitySchemes": {
                "bearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": "opaque-token"
                }
            },
            "schemas": {
                "ApiError": {
                    "type": "object",
                    "required": ["code", "kind", "message", "retryable", "trace_id", "details"],
                    "properties": {
                        "code": { "type": "string" },
                        "kind": { "type": "string" },
                        "message": { "type": "string" },
                        "retryable": { "type": "boolean" },
                        "trace_id": { "type": "string" },
                        "details": {}
                    }
                },
                "TaskAccepted": {
                    "type": "object",
                    "required": ["task_id", "trace_id", "status"],
                    "properties": {
                        "task_id": { "type": "string" },
                        "trace_id": { "type": "string" },
                        "status": { "const": "queued" }
                    }
                }
            }
        }
    })
}

fn operation_responses(route: &ControlRouteSpec) -> Value {
    let mut responses = Map::new();
    let success_status = if route.task { "202" } else { "200" };
    let success_schema = if route.task {
        json!({ "$ref": "#/components/schemas/TaskAccepted" })
    } else {
        json!({ "type": "object" })
    };
    responses.insert(
        success_status.to_string(),
        json!({
            "description": if route.task {
                "Operation accepted as a cancellable task."
            } else {
                "Successful response."
            },
            "content": {
                "application/json": {
                    "schema": success_schema
                }
            }
        }),
    );
    if route.write {
        responses.insert(
            "401".to_string(),
            error_response("Missing or invalid control bearer token."),
        );
    }
    responses.insert(
        "default".to_string(),
        error_response("Structured control API error."),
    );
    Value::Object(responses)
}

fn error_response(description: &str) -> Value {
    json!({
        "description": description,
        "content": {
            "application/json": {
                "schema": { "$ref": "#/components/schemas/ApiError" }
            }
        }
    })
}
