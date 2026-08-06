use std::collections::{BTreeMap, HashMap, HashSet};

use anyhow::anyhow;
use serde::Serialize;

use crate::{
    config::{OutboundConfig, SmartRouteRule, SuperConfig},
    routing::{Destination, RouteDecision},
    smart::{SmartRecommendationAction, SmartSnapshot},
    telemetry::OutboundHealth,
};

use super::Runtime;

#[derive(Debug, Clone, Serialize)]
pub struct ProxyGroupSnapshot {
    pub name: String,
    pub kind: String,
    pub auto_select: bool,
    pub selected_member: Option<String>,
    pub selection_reason: String,
    pub members: Vec<ProxyGroupMemberSnapshot>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProxyGroupMemberSnapshot {
    pub name: String,
    pub kind: String,
    pub healthy: bool,
    pub attempts: u64,
    pub successes: u64,
    pub failures: u64,
    pub last_latency_ms: Option<u64>,
    pub last_error: Option<String>,
    pub score: Option<u8>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CountryGroupSnapshot {
    pub code: String,
    pub name: String,
    pub node_count: usize,
    pub best_outbound: Option<String>,
    pub members: Vec<ProxyGroupMemberSnapshot>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OutboundCapabilitySnapshot {
    pub name: String,
    pub kind: String,
    pub tcp_supported: bool,
    pub udp_supported: bool,
    pub udp_mode: Option<String>,
    pub limitations: Vec<String>,
}

impl Runtime {
    pub fn smart_snapshot(&self) -> SmartSnapshot {
        self.smart_rules.snapshot()
    }

    pub fn upsert_smart_rule(&self, rule: SmartRouteRule) -> anyhow::Result<Vec<SmartRouteRule>> {
        let has_outbound = self
            .state
            .read()
            .map_err(|_| anyhow!("runtime state lock poisoned"))?
            .outbounds
            .contains_key(&rule.outbound);
        if !has_outbound {
            return Err(anyhow!(
                "smart rule references undefined outbound '{}'",
                rule.outbound
            ));
        }
        Ok(self.smart_rules.upsert_rule(rule))
    }

    pub fn set_smart_rule_enabled(
        &self,
        target: crate::config::RuleTarget,
        value: &str,
        enabled: bool,
    ) -> anyhow::Result<Vec<SmartRouteRule>> {
        self.smart_rules.set_rule_enabled(target, value, enabled)
    }

    pub fn delete_smart_rule(
        &self,
        target: crate::config::RuleTarget,
        value: &str,
    ) -> anyhow::Result<Vec<SmartRouteRule>> {
        self.smart_rules.delete_rule(target, value)
    }

    pub fn apply_smart_recommendations(
        &self,
        action: Option<SmartRecommendationAction>,
    ) -> Vec<SmartRouteRule> {
        self.smart_rules.apply_recommendations(action)
    }

    pub fn apply_smart_recommendation(
        &self,
        target: crate::config::RuleTarget,
        value: &str,
    ) -> anyhow::Result<Vec<SmartRouteRule>> {
        self.smart_rules.apply_recommendation(target, value)
    }

    pub fn decide(&self, destination: &Destination) -> RouteDecision {
        self.resolve_route(destination)
            .unwrap_or_else(|_| RouteDecision {
                outbound: "direct".to_string(),
                matched_rule: None,
                source: crate::routing::RouteDecisionSource::Default,
            })
    }

    pub fn resolve_route(&self, destination: &Destination) -> anyhow::Result<RouteDecision> {
        const MAX_REMATCH_DEPTH: usize = 8;
        let mut current = destination.clone();
        let mut visited = HashSet::new();
        for _ in 0..=MAX_REMATCH_DEPTH {
            let (decision, rematch) = {
                let state = self
                    .state
                    .read()
                    .map_err(|_| anyhow!("runtime state lock poisoned"))?;
                let decision = if let Some(decision) = self.smart_rules.decide(&current) {
                    decision
                } else {
                    state.router.decide(&current)
                };
                let rematch = state
                    .outbounds
                    .get(&decision.outbound)
                    .and_then(|outbound| outbound.rematch_target());
                (decision, rematch)
            };
            let Some(rematch) = rematch else {
                return Ok(decision);
            };
            if !visited.insert(decision.outbound.clone()) {
                return Err(anyhow!(
                    "rematch cycle detected at outbound '{}'",
                    decision.outbound
                ));
            }
            let Some(name) = rematch.rematch_name else {
                return Err(anyhow!("rematch outbound has no target context"));
            };
            current.rematch_name = Some(name);
        }
        Err(anyhow!(
            "rematch exceeded maximum depth of {}",
            MAX_REMATCH_DEPTH
        ))
    }

    pub async fn proxy_groups(&self) -> Vec<ProxyGroupSnapshot> {
        let config = self.config();
        let health = self
            .telemetry
            .outbound_health()
            .await
            .into_iter()
            .map(|item| (item.name.clone(), item))
            .collect::<HashMap<_, _>>();
        let kinds = config
            .outbounds
            .iter()
            .map(|item| (item.name().to_string(), outbound_config_kind(item)))
            .collect::<HashMap<_, _>>();

        config
            .outbounds
            .iter()
            .filter_map(|item| {
                let OutboundConfig::Group {
                    name,
                    kind,
                    members,
                } = item
                else {
                    return None;
                };
                let auto_select = group_kind_is_auto_select(kind);
                let member_snapshots = members
                    .iter()
                    .map(|member| group_member_snapshot(member, &kinds, &health))
                    .collect::<Vec<_>>();
                let (selected_member, selection_reason) =
                    select_group_member(kind, &member_snapshots);
                Some(ProxyGroupSnapshot {
                    name: name.clone(),
                    kind: kind.clone(),
                    auto_select,
                    selected_member,
                    selection_reason,
                    members: member_snapshots,
                })
            })
            .collect()
    }

    pub async fn country_groups(&self) -> Vec<CountryGroupSnapshot> {
        let config = self.config();
        let health = self
            .telemetry
            .outbound_health()
            .await
            .into_iter()
            .map(|item| (item.name.clone(), item))
            .collect::<HashMap<_, _>>();
        country_groups_from_config(&config, &health)
    }

    pub fn outbound_capabilities(&self) -> Vec<OutboundCapabilitySnapshot> {
        let state = match self.state.read() {
            Ok(state) => state,
            Err(_) => return Vec::new(),
        };
        state
            .config
            .outbounds
            .iter()
            .map(|config| {
                let capability = state
                    .outbounds
                    .get(config.name())
                    .map(|outbound| outbound.capability())
                    .unwrap_or_else(|| {
                        crate::outbound::OutboundCapability::unsupported(
                            "outbound implementation is missing from runtime",
                        )
                    });
                OutboundCapabilitySnapshot {
                    name: config.name().to_string(),
                    kind: outbound_config_kind(config),
                    tcp_supported: capability.tcp_supported,
                    udp_supported: capability.udp_supported,
                    udp_mode: capability.udp_mode,
                    limitations: capability.limitations,
                }
            })
            .collect()
    }

    pub fn outbound_runtime_stats(&self) -> BTreeMap<String, serde_json::Value> {
        let state = match self.state.read() {
            Ok(state) => state,
            Err(_) => return BTreeMap::new(),
        };
        state
            .outbounds
            .iter()
            .filter_map(|(name, outbound)| {
                outbound.runtime_stats().map(|stats| (name.clone(), stats))
            })
            .collect()
    }

    pub fn use_outbound(&self, name: &str) -> anyhow::Result<SuperConfig> {
        let mut config = self.config();
        let has_outbound = config.outbounds.iter().any(|item| item.name() == name);
        if !has_outbound {
            return Err(anyhow!("outbound {name} does not exist"));
        }
        config.core.default_outbound = name.to_string();
        for rule in &mut config.rules {
            if rule.target == crate::config::RuleTarget::Match {
                rule.outbound = name.to_string();
            }
        }
        self.reload_config(config)
    }

    pub async fn use_country_group(&self, code: &str) -> anyhow::Result<SuperConfig> {
        let code = code.to_ascii_uppercase();
        let mut config = self.config();
        let health = self
            .telemetry
            .outbound_health()
            .await
            .into_iter()
            .map(|item| (item.name.clone(), item))
            .collect::<HashMap<_, _>>();
        let groups = country_groups_from_config(&config, &health);
        let group = groups
            .into_iter()
            .find(|group| group.code.eq_ignore_ascii_case(&code))
            .ok_or_else(|| anyhow!("country group {code} has no nodes"))?;
        let group_name = format!("country:{}", group.code);
        let members = group
            .members
            .iter()
            .map(|member| member.name.clone())
            .collect::<Vec<_>>();
        if let Some(existing) = config
            .outbounds
            .iter_mut()
            .find(|item| item.name() == group_name)
        {
            *existing = OutboundConfig::Group {
                name: group_name.clone(),
                kind: "url-test".to_string(),
                members,
            };
        } else {
            config.outbounds.push(OutboundConfig::Group {
                name: group_name.clone(),
                kind: "url-test".to_string(),
                members,
            });
        }
        config.core.default_outbound = group_name;
        self.reload_config(config)
    }
}

fn group_member_snapshot(
    member: &str,
    kinds: &HashMap<String, String>,
    health: &HashMap<String, OutboundHealth>,
) -> ProxyGroupMemberSnapshot {
    let health = health.get(member);
    ProxyGroupMemberSnapshot {
        name: member.to_string(),
        kind: kinds
            .get(member)
            .cloned()
            .unwrap_or_else(|| "unknown".to_string()),
        healthy: health
            .map(|item| item.successes > 0 && item.last_error.is_none())
            .unwrap_or(false),
        attempts: health.map(|item| item.attempts).unwrap_or(0),
        successes: health.map(|item| item.successes).unwrap_or(0),
        failures: health.map(|item| item.failures).unwrap_or(0),
        last_latency_ms: health.and_then(|item| item.last_latency_ms),
        last_error: health.and_then(|item| item.last_error.clone()),
        score: health.map(|item| item.score),
    }
}

fn select_group_member(
    kind: &str,
    members: &[ProxyGroupMemberSnapshot],
) -> (Option<String>, String) {
    if members.is_empty() {
        return (None, "empty group".to_string());
    }
    if !group_kind_is_auto_select(kind) {
        return (
            members.first().map(|item| item.name.clone()),
            "ordered group uses first configured member".to_string(),
        );
    }

    if let Some(best) = members
        .iter()
        .filter(|item| item.healthy)
        .min_by_key(|item| {
            (
                item.last_latency_ms.unwrap_or(u64::MAX),
                100u8 - item.score.unwrap_or(0),
            )
        })
    {
        return (
            Some(best.name.clone()),
            "lowest healthy latency from telemetry".to_string(),
        );
    }

    (
        members.first().map(|item| item.name.clone()),
        "no healthy telemetry yet; fallback to first configured member".to_string(),
    )
}

fn group_kind_is_auto_select(kind: &str) -> bool {
    matches!(
        kind.to_ascii_lowercase().as_str(),
        "select" | "url-test" | "load-balance" | "auto" | "latency"
    )
}

fn country_groups_from_config(
    config: &SuperConfig,
    health: &HashMap<String, OutboundHealth>,
) -> Vec<CountryGroupSnapshot> {
    let kinds = config
        .outbounds
        .iter()
        .map(|item| (item.name().to_string(), outbound_config_kind(item)))
        .collect::<HashMap<_, _>>();
    let mut grouped: HashMap<String, (String, Vec<ProxyGroupMemberSnapshot>)> = HashMap::new();
    for outbound in &config.outbounds {
        if matches!(
            outbound,
            OutboundConfig::Direct { .. }
                | OutboundConfig::Dns { .. }
                | OutboundConfig::Rematch { .. }
                | OutboundConfig::Reject { .. }
                | OutboundConfig::Group { .. }
        ) {
            continue;
        }
        let Some((code, name)) = country_for_outbound(outbound) else {
            continue;
        };
        grouped
            .entry(code.to_string())
            .or_insert_with(|| (name.to_string(), Vec::new()))
            .1
            .push(group_member_snapshot(outbound.name(), &kinds, health));
    }

    let mut groups = grouped
        .into_iter()
        .map(|(code, (name, mut members))| {
            members.sort_by(|lhs, rhs| {
                lhs.last_latency_ms
                    .unwrap_or(u64::MAX)
                    .cmp(&rhs.last_latency_ms.unwrap_or(u64::MAX))
                    .then_with(|| rhs.score.unwrap_or(0).cmp(&lhs.score.unwrap_or(0)))
                    .then_with(|| lhs.name.cmp(&rhs.name))
            });
            let best_outbound = members
                .iter()
                .find(|member| member.healthy)
                .or_else(|| members.first())
                .map(|member| member.name.clone());
            CountryGroupSnapshot {
                code,
                name,
                node_count: members.len(),
                best_outbound,
                members,
            }
        })
        .collect::<Vec<_>>();
    groups.sort_by(|lhs, rhs| lhs.code.cmp(&rhs.code));
    groups
}

fn country_for_outbound(outbound: &OutboundConfig) -> Option<(&'static str, &'static str)> {
    let mut haystack = outbound.name().to_string();
    if let Some(server) = outbound_server(outbound) {
        haystack.push(' ');
        haystack.push_str(server);
    }
    detect_country(&haystack)
}

fn outbound_server(outbound: &OutboundConfig) -> Option<&str> {
    match outbound {
        OutboundConfig::Http { server, .. }
        | OutboundConfig::Socks5 { server, .. }
        | OutboundConfig::Shadowsocks { server, .. }
        | OutboundConfig::Trojan { server, .. }
        | OutboundConfig::Vmess { server, .. }
        | OutboundConfig::Vless { server, .. }
        | OutboundConfig::Hysteria2 { server, .. }
        | OutboundConfig::Tuic { server, .. }
        | OutboundConfig::Naive { server, .. }
        | OutboundConfig::Ssr { server, .. }
        | OutboundConfig::Snell { server, .. }
        | OutboundConfig::Hysteria { server, .. }
        | OutboundConfig::AnyTls { server, .. }
        | OutboundConfig::ShadowTls { server, .. }
        | OutboundConfig::WireGuard { server, .. }
        | OutboundConfig::Ssh { server, .. }
        | OutboundConfig::Mieru { server, .. }
        | OutboundConfig::Juicity { server, .. }
        | OutboundConfig::Masque { server, .. }
        | OutboundConfig::TrustTunnel { server, .. }
        | OutboundConfig::Sudoku { server, .. } => Some(server),
        OutboundConfig::Unknown { server, .. } => server.as_deref(),
        OutboundConfig::Direct { .. }
        | OutboundConfig::Dns { .. }
        | OutboundConfig::Rematch { .. }
        | OutboundConfig::Reject { .. }
        | OutboundConfig::OpenVpn { .. }
        | OutboundConfig::Tailscale { .. }
        | OutboundConfig::Group { .. } => None,
    }
}

fn detect_country(value: &str) -> Option<(&'static str, &'static str)> {
    let lower = value.to_ascii_lowercase();
    let upper_tokens = value
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter(|item| !item.is_empty())
        .map(|item| item.to_ascii_uppercase())
        .collect::<Vec<_>>();
    let defs: &[(&str, &str, &[&str], &[&str])] = &[
        (
            "HK",
            "Hong Kong",
            &["香港", "港", "hong kong"],
            &["HK", "HKG"],
        ),
        (
            "JP",
            "Japan",
            &["日本", "东京", "大阪", "japan", "tokyo", "osaka"],
            &["JP", "JPN"],
        ),
        (
            "US",
            "United States",
            &[
                "美国",
                "美國",
                "洛杉矶",
                "洛杉磯",
                "西雅图",
                "纽约",
                "united states",
                "america",
                "los angeles",
                "new york",
                "seattle",
            ],
            &["US", "USA"],
        ),
        (
            "SG",
            "Singapore",
            &["新加坡", "狮城", "獅城", "singapore"],
            &["SG", "SGP"],
        ),
        (
            "TW",
            "Taiwan",
            &["台湾", "台灣", "台北", "taiwan", "taipei"],
            &["TW", "TWN"],
        ),
        (
            "KR",
            "South Korea",
            &["韩国", "韓國", "首尔", "首爾", "korea", "seoul"],
            &["KR", "KOR"],
        ),
        (
            "GB",
            "United Kingdom",
            &["英国", "英國", "伦敦", "倫敦", "united kingdom", "london"],
            &["GB", "UK"],
        ),
        (
            "DE",
            "Germany",
            &[
                "德国",
                "德國",
                "法兰克福",
                "法蘭克福",
                "germany",
                "frankfurt",
            ],
            &["DE", "DEU"],
        ),
        (
            "FR",
            "France",
            &["法国", "法國", "巴黎", "france", "paris"],
            &["FR", "FRA"],
        ),
        (
            "CA",
            "Canada",
            &["加拿大", "多伦多", "多倫多", "canada", "toronto"],
            &["CA", "CAN"],
        ),
        (
            "AU",
            "Australia",
            &["澳大利亚", "澳洲", "悉尼", "australia", "sydney"],
            &["AU", "AUS"],
        ),
        (
            "NL",
            "Netherlands",
            &["荷兰", "荷蘭", "netherlands", "amsterdam"],
            &["NL", "NLD"],
        ),
        (
            "RU",
            "Russia",
            &["俄罗斯", "俄羅斯", "russia", "moscow"],
            &["RU", "RUS"],
        ),
        ("IN", "India", &["印度", "india", "mumbai"], &["IN", "IND"]),
        (
            "TH",
            "Thailand",
            &["泰国", "泰國", "thailand", "bangkok"],
            &["TH", "THA"],
        ),
        ("VN", "Vietnam", &["越南", "vietnam"], &["VN", "VNM"]),
        (
            "TR",
            "Turkey",
            &["土耳其", "turkey", "istanbul"],
            &["TR", "TUR"],
        ),
    ];
    for (code, name, phrases, tokens) in defs {
        if phrases.iter().any(|phrase| lower.contains(phrase)) {
            return Some((code, name));
        }
        if tokens
            .iter()
            .any(|token| upper_tokens.iter().any(|item| item == token))
        {
            return Some((code, name));
        }
    }
    None
}

fn outbound_config_kind(config: &OutboundConfig) -> String {
    match config {
        OutboundConfig::Direct { .. } => "direct".to_string(),
        OutboundConfig::Dns { .. } => "dns".to_string(),
        OutboundConfig::Rematch { .. } => "rematch".to_string(),
        OutboundConfig::Reject { .. } => "reject".to_string(),
        OutboundConfig::Http { .. } => "http".to_string(),
        OutboundConfig::Socks5 { .. } => "socks5".to_string(),
        OutboundConfig::Shadowsocks { .. } => "shadowsocks".to_string(),
        OutboundConfig::Trojan { .. } => "trojan".to_string(),
        OutboundConfig::Vmess { .. } => "vmess".to_string(),
        OutboundConfig::Vless { .. } => "vless".to_string(),
        OutboundConfig::Hysteria2 { .. } => "hysteria2".to_string(),
        OutboundConfig::Tuic { .. } => "tuic".to_string(),
        OutboundConfig::Naive { .. } => "naive".to_string(),
        OutboundConfig::Ssr { .. } => "ssr".to_string(),
        OutboundConfig::Snell { .. } => "snell".to_string(),
        OutboundConfig::Hysteria { .. } => "hysteria".to_string(),
        OutboundConfig::AnyTls { .. } => "anytls".to_string(),
        OutboundConfig::ShadowTls { .. } => "shadowtls".to_string(),
        OutboundConfig::WireGuard { .. } => "wireguard".to_string(),
        OutboundConfig::Ssh { .. } => "ssh".to_string(),
        OutboundConfig::Mieru { .. } => "mieru".to_string(),
        OutboundConfig::Juicity { .. } => "juicity".to_string(),
        OutboundConfig::Masque { .. } => "masque".to_string(),
        OutboundConfig::OpenVpn { .. } => "openvpn".to_string(),
        OutboundConfig::Tailscale { .. } => "tailscale".to_string(),
        OutboundConfig::TrustTunnel { .. } => "trusttunnel".to_string(),
        OutboundConfig::Sudoku { .. } => "sudoku".to_string(),
        OutboundConfig::Unknown { protocol, .. } => format!("unknown:{protocol}"),
        OutboundConfig::Group { kind, .. } => format!("group:{kind}"),
    }
}
