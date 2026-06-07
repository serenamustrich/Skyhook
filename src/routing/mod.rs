use std::{collections::HashMap, fmt, net::IpAddr, path::PathBuf, sync::Arc};

use ipnet::IpNet;
use maxminddb::Reader;
use serde::{Deserialize, Serialize};

use crate::config::{GeoIpCountryConfig, RouteRule, RuleSetBehavior, RuleSetConfig, RuleTarget};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Destination {
    pub host: String,
    pub port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app: Option<AppIdentity>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct AppIdentity {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle_id: Option<String>,
}

impl Destination {
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
            app: None,
        }
    }

    pub fn with_app(mut self, app: AppIdentity) -> Self {
        self.app = Some(app);
        self
    }

    pub fn authority(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RouteDecision {
    pub outbound: String,
    pub matched_rule: Option<String>,
    pub source: RouteDecisionSource,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RouteDecisionSource {
    Static,
    Default,
    Smart,
}

#[derive(Debug, Clone)]
pub struct Router {
    rules: Vec<RouteRule>,
    rule_sets: HashMap<String, CompiledRuleSet>,
    geoip: HashMap<String, Vec<IpNet>>,
    geoip_database: Option<GeoIpDatabase>,
    default_outbound: String,
}

#[derive(Debug, Clone)]
struct CompiledRuleSet {
    behavior: RuleSetBehavior,
    entries: Vec<RuleSetEntry>,
}

#[derive(Debug, Clone)]
enum RuleSetEntry {
    Domain(String),
    DomainSuffix(String),
    DomainKeyword(String),
    IpNet(IpNet),
}

#[derive(Clone)]
struct GeoIpDatabase {
    path: PathBuf,
    reader: Arc<Reader<Vec<u8>>>,
}

impl fmt::Debug for GeoIpDatabase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GeoIpDatabase")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl Router {
    pub fn new(
        rules: Vec<RouteRule>,
        default_outbound: String,
        rule_sets: Vec<RuleSetConfig>,
        geoip_database: Option<PathBuf>,
        geoip: Vec<GeoIpCountryConfig>,
    ) -> Self {
        Self {
            rules,
            rule_sets: rule_sets
                .into_iter()
                .map(|item| (item.name.to_ascii_lowercase(), compile_rule_set(item)))
                .collect(),
            geoip: geoip
                .into_iter()
                .map(|item| (item.country.to_ascii_uppercase(), item.cidrs))
                .collect(),
            geoip_database: geoip_database.and_then(load_geoip_database),
            default_outbound,
        }
    }

    pub fn decide(&self, destination: &Destination) -> RouteDecision {
        for rule in &self.rules {
            if self.rule_matches(rule, destination) {
                return RouteDecision {
                    outbound: rule.outbound.clone(),
                    matched_rule: Some(format!("{:?}:{}", rule.target, rule.value)),
                    source: RouteDecisionSource::Static,
                };
            }
        }
        RouteDecision {
            outbound: self.default_outbound.clone(),
            matched_rule: None,
            source: RouteDecisionSource::Default,
        }
    }

    fn rule_matches(&self, rule: &RouteRule, destination: &Destination) -> bool {
        if rule.target == RuleTarget::RuleSet {
            return self
                .rule_sets
                .get(&rule.value.to_ascii_lowercase())
                .map(|rule_set| rule_set.matches(destination))
                .unwrap_or(false);
        }
        if rule.target == RuleTarget::GeoIp {
            let Ok(ip) = destination.host.parse::<IpAddr>() else {
                return false;
            };
            if self
                .geoip
                .get(&rule.value.to_ascii_uppercase())
                .map(|cidrs| cidrs.iter().any(|cidr| cidr.contains(&ip)))
                .unwrap_or(false)
            {
                return true;
            }
            return self
                .geoip_database
                .as_ref()
                .and_then(|database| database.country_code(ip))
                .map(|country| country.eq_ignore_ascii_case(&rule.value))
                .unwrap_or(false);
        }
        rule_matches(rule, destination)
    }
}

pub fn rule_matches(rule: &RouteRule, destination: &Destination) -> bool {
    target_matches(rule.target, &rule.value, destination)
}

pub fn target_matches(target: RuleTarget, value: &str, destination: &Destination) -> bool {
    let host = destination.host.to_ascii_lowercase();
    let value = value.to_ascii_lowercase();
    match target {
        RuleTarget::Match => true,
        RuleTarget::Domain => host == value,
        RuleTarget::DomainSuffix => host == value || host.ends_with(&format!(".{value}")),
        RuleTarget::DomainKeyword => host.contains(&value),
        RuleTarget::Ip => host.parse::<IpAddr>().is_ok() && host == value,
        RuleTarget::IpCidr => {
            let Ok(ip) = host.parse::<IpAddr>() else {
                return false;
            };
            value
                .parse::<IpNet>()
                .map(|net| net.contains(&ip))
                .unwrap_or(false)
        }
        RuleTarget::AppName => destination
            .app
            .as_ref()
            .and_then(|app| app.name.as_ref())
            .map(|name| name.eq_ignore_ascii_case(&value))
            .unwrap_or(false),
        RuleTarget::AppPath => destination
            .app
            .as_ref()
            .and_then(|app| app.path.as_ref())
            .map(|path| path.eq_ignore_ascii_case(&value))
            .unwrap_or(false),
        RuleTarget::AppBundle => destination
            .app
            .as_ref()
            .and_then(|app| app.bundle_id.as_ref())
            .map(|bundle_id| bundle_id.eq_ignore_ascii_case(&value))
            .unwrap_or(false),
        RuleTarget::RuleSet | RuleTarget::GeoIp => false,
    }
}

impl CompiledRuleSet {
    fn matches(&self, destination: &Destination) -> bool {
        match self.behavior {
            RuleSetBehavior::Domain | RuleSetBehavior::Classical => self
                .entries
                .iter()
                .any(|entry| rule_set_entry_matches(entry, destination)),
            RuleSetBehavior::IpCidr => {
                let Ok(ip) = destination.host.parse::<IpAddr>() else {
                    return false;
                };
                self.entries.iter().any(|entry| match entry {
                    RuleSetEntry::IpNet(net) => net.contains(&ip),
                    _ => false,
                })
            }
        }
    }
}

fn compile_rule_set(config: RuleSetConfig) -> CompiledRuleSet {
    let entries = config
        .rules
        .iter()
        .filter_map(|rule| compile_rule_set_entry(config.behavior, rule))
        .collect();
    CompiledRuleSet {
        behavior: config.behavior,
        entries,
    }
}

fn compile_rule_set_entry(behavior: RuleSetBehavior, rule: &str) -> Option<RuleSetEntry> {
    let rule = rule.trim();
    if rule.is_empty() || rule.starts_with('#') {
        return None;
    }
    match behavior {
        RuleSetBehavior::Domain => compile_domain_rule_set_entry(rule),
        RuleSetBehavior::IpCidr => rule.parse::<IpNet>().ok().map(RuleSetEntry::IpNet),
        RuleSetBehavior::Classical => compile_classical_rule_set_entry(rule),
    }
}

fn compile_domain_rule_set_entry(rule: &str) -> Option<RuleSetEntry> {
    let value = rule
        .trim_start_matches('+')
        .trim_start_matches('.')
        .to_ascii_lowercase();
    if value.is_empty() {
        None
    } else if rule.starts_with('.') || rule.starts_with("+.") {
        Some(RuleSetEntry::DomainSuffix(value))
    } else {
        Some(RuleSetEntry::Domain(value))
    }
}

fn compile_classical_rule_set_entry(rule: &str) -> Option<RuleSetEntry> {
    let parts = rule.split(',').map(str::trim).collect::<Vec<_>>();
    if parts.len() < 2 {
        return compile_domain_rule_set_entry(rule);
    }
    match parts[0].to_ascii_uppercase().as_str() {
        "DOMAIN" => Some(RuleSetEntry::Domain(parts[1].to_ascii_lowercase())),
        "DOMAIN-SUFFIX" => Some(RuleSetEntry::DomainSuffix(
            parts[1].trim_start_matches('.').to_ascii_lowercase(),
        )),
        "DOMAIN-KEYWORD" => Some(RuleSetEntry::DomainKeyword(parts[1].to_ascii_lowercase())),
        "IP-CIDR" | "IP-CIDR6" => parts[1].parse::<IpNet>().ok().map(RuleSetEntry::IpNet),
        _ => None,
    }
}

fn rule_set_entry_matches(entry: &RuleSetEntry, destination: &Destination) -> bool {
    let host = destination.host.to_ascii_lowercase();
    match entry {
        RuleSetEntry::Domain(value) => host == *value,
        RuleSetEntry::DomainSuffix(value) => host == *value || host.ends_with(&format!(".{value}")),
        RuleSetEntry::DomainKeyword(value) => host.contains(value),
        RuleSetEntry::IpNet(net) => host
            .parse::<IpAddr>()
            .map(|ip| net.contains(&ip))
            .unwrap_or(false),
    }
}

fn load_geoip_database(path: PathBuf) -> Option<GeoIpDatabase> {
    match Reader::open_readfile(&path) {
        Ok(reader) => Some(GeoIpDatabase {
            path,
            reader: Arc::new(reader),
        }),
        Err(error) => {
            tracing::warn!(path = %path.display(), error = %error, "failed to load geoip database");
            None
        }
    }
}

impl GeoIpDatabase {
    fn country_code(&self, ip: IpAddr) -> Option<String> {
        let result = self.reader.lookup(ip).ok()?;
        let country = result
            .decode_path::<&str>(&maxminddb::path!["country", "iso_code"])
            .ok()
            .flatten()
            .or_else(|| {
                result
                    .decode_path::<&str>(&maxminddb::path!["registered_country", "iso_code"])
                    .ok()
                    .flatten()
            })?;
        Some(country.to_ascii_uppercase())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_suffix_matches_subdomains() {
        let router = Router::new(
            vec![RouteRule {
                target: RuleTarget::DomainSuffix,
                value: "example.com".to_string(),
                outbound: "proxy".to_string(),
            }],
            "direct".to_string(),
            Vec::new(),
            None,
            Vec::new(),
        );

        assert_eq!(
            router
                .decide(&Destination::new("api.example.com", 443))
                .outbound,
            "proxy"
        );
        assert_eq!(
            router
                .decide(&Destination::new("example.org", 443))
                .outbound,
            "direct"
        );
    }

    #[test]
    fn app_and_ip_rules_match() {
        let app = AppIdentity {
            name: Some("Safari".to_string()),
            path: Some("/Applications/Safari.app".to_string()),
            bundle_id: Some("com.apple.Safari".to_string()),
        };
        assert!(target_matches(
            RuleTarget::AppBundle,
            "com.apple.safari",
            &Destination::new("example.com", 443).with_app(app.clone())
        ));
        assert!(target_matches(
            RuleTarget::AppName,
            "safari",
            &Destination::new("example.com", 443).with_app(app)
        ));
        assert!(target_matches(
            RuleTarget::Ip,
            "1.1.1.1",
            &Destination::new("1.1.1.1", 443)
        ));
        assert!(!target_matches(
            RuleTarget::Ip,
            "1.1.1.2",
            &Destination::new("1.1.1.1", 443)
        ));
    }

    #[test]
    fn rule_set_matches_domain_and_ip_entries() {
        let router = Router::new(
            vec![
                RouteRule {
                    target: RuleTarget::RuleSet,
                    value: "apple".to_string(),
                    outbound: "direct".to_string(),
                },
                RouteRule {
                    target: RuleTarget::RuleSet,
                    value: "private".to_string(),
                    outbound: "reject".to_string(),
                },
                RouteRule {
                    target: RuleTarget::GeoIp,
                    value: "CN".to_string(),
                    outbound: "direct".to_string(),
                },
            ],
            "proxy".to_string(),
            vec![
                RuleSetConfig {
                    name: "apple".to_string(),
                    behavior: RuleSetBehavior::Domain,
                    rules: vec!["+.apple.com".to_string()],
                },
                RuleSetConfig {
                    name: "private".to_string(),
                    behavior: RuleSetBehavior::IpCidr,
                    rules: vec!["10.0.0.0/8".to_string()],
                },
            ],
            None,
            vec![GeoIpCountryConfig {
                country: "CN".to_string(),
                cidrs: vec!["1.2.0.0/16".parse().unwrap()],
            }],
        );

        assert_eq!(
            router
                .decide(&Destination::new("cdn.apple.com", 443))
                .outbound,
            "direct"
        );
        assert_eq!(
            router.decide(&Destination::new("10.1.2.3", 443)).outbound,
            "reject"
        );
        assert_eq!(
            router.decide(&Destination::new("1.2.3.4", 443)).outbound,
            "direct"
        );
        assert_eq!(
            router
                .decide(&Destination::new("example.com", 443))
                .outbound,
            "proxy"
        );
    }
}
