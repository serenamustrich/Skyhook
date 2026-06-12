use serde::Serialize;

use crate::core::Runtime;
use crate::routing::RouteDecision;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub enum NativeRouteTarget {
    Direct,
    Reject { reason: String },
    Outbound { name: String },
    Group { name: String },
    Country { code: String },
    L3Profile { name: String },
}

#[derive(Debug, Clone, Serialize)]
pub struct NativeRouteDecision {
    pub target: NativeRouteTarget,
    pub source: String,
    pub matched_rule: Option<String>,
}

pub async fn resolve_native_route(
    runtime: &Runtime,
    decision: &RouteDecision,
) -> NativeRouteDecision {
    let outbound = &decision.outbound;

    if outbound == "direct" || outbound == "DIRECT" {
        return NativeRouteDecision {
            target: NativeRouteTarget::Direct,
            source: format!("{:?}", decision.source),
            matched_rule: decision.matched_rule.clone(),
        };
    }

    if outbound == "reject" || outbound == "REJECT" {
        return NativeRouteDecision {
            target: NativeRouteTarget::Reject {
                reason: "matched reject rule".to_string(),
            },
            source: format!("{:?}", decision.source),
            matched_rule: decision.matched_rule.clone(),
        };
    }

    if runtime.is_l3_profile(outbound) {
        return NativeRouteDecision {
            target: NativeRouteTarget::L3Profile {
                name: outbound.clone(),
            },
            source: format!("{:?}", decision.source),
            matched_rule: decision.matched_rule.clone(),
        };
    }

    if runtime.is_proxy_group(outbound) {
        return NativeRouteDecision {
            target: NativeRouteTarget::Group {
                name: outbound.clone(),
            },
            source: format!("{:?}", decision.source),
            matched_rule: decision.matched_rule.clone(),
        };
    }

    if runtime.is_country_group(outbound).await {
        return NativeRouteDecision {
            target: NativeRouteTarget::Country {
                code: outbound.clone(),
            },
            source: format!("{:?}", decision.source),
            matched_rule: decision.matched_rule.clone(),
        };
    }

    NativeRouteDecision {
        target: NativeRouteTarget::Outbound {
            name: outbound.clone(),
        },
        source: format!("{:?}", decision.source),
        matched_rule: decision.matched_rule.clone(),
    }
}
