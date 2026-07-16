use std::path::PathBuf;

use serde::{Deserialize, Serialize};

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
