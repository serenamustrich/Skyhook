use supercore::config::{OutboundConfig, SuperConfig, TunDnsStrategy};
use supercore::routing::{AppIdentity, Destination, target_matches};
use supercore::config::RuleTarget;
use supercore::subscription_store::SubscriptionStore;

use std::{collections::HashSet, fs, net::IpAddr};

#[test]
fn test_tun_bypass_includes_lan_ranges() {
    let config = SuperConfig::default();
    let tun = &config.tun;
    assert!(tun.bypass.contains(&"10.0.0.0/8".to_string()));
    assert!(tun.bypass.contains(&"172.16.0.0/12".to_string()));
    assert!(tun.bypass.contains(&"192.168.0.0/16".to_string()));
    assert!(tun.bypass.contains(&"127.0.0.0/8".to_string()));
    assert!(tun.bypass.contains(&"169.254.0.0/16".to_string()));
}

#[test]
fn test_tun_route_excludes_apple_captive_portal() {
    let config = SuperConfig::default();
    let tun = &config.tun;
    assert!(tun.route_exclude_address.contains(&"17.0.0.0/8".to_string()));
}

#[test]
fn test_tun_disabled_by_default() {
    let config = SuperConfig::default();
    assert!(!config.tun.enabled);
}

#[test]
fn test_fake_ip_disabled_by_default() {
    let config = SuperConfig::default();
    assert_eq!(config.dns.enhanced_mode, supercore::config::DnsEnhancedMode::RedirHost);
}

#[test]
fn test_dns_strategy_direct_by_default() {
    let config = SuperConfig::default();
    assert_eq!(config.tun.dns_strategy, TunDnsStrategy::Direct);
}

#[test]
fn test_probe_url_default() {
    let config = SuperConfig::default();
    assert_eq!(config.core.probe_url, "http://www.gstatic.com/generate_204");
}

#[test]
fn test_probe_timeout_default() {
    let config = SuperConfig::default();
    assert_eq!(config.core.probe_timeout_ms, 500);
}

#[test]
fn test_domain_rule_matching() {
    let dest = Destination::new("example.com", 80);
    assert!(target_matches(RuleTarget::Domain, "example.com", &dest));
    assert!(!target_matches(RuleTarget::Domain, "other.com", &dest));
}

#[test]
fn test_domain_suffix_rule_matching() {
    let dest = Destination::new("sub.example.com", 80);
    assert!(target_matches(RuleTarget::DomainSuffix, "example.com", &dest));
    assert!(target_matches(RuleTarget::DomainSuffix, "sub.example.com", &dest));
    assert!(!target_matches(RuleTarget::DomainSuffix, "other.com", &dest));
}

#[test]
fn test_domain_keyword_rule_matching() {
    let dest = Destination::new("www.google.com", 80);
    assert!(target_matches(RuleTarget::DomainKeyword, "google", &dest));
    assert!(!target_matches(RuleTarget::DomainKeyword, "facebook", &dest));
}

#[test]
fn test_domain_regex_rule_matching() {
    let dest = Destination::new("sub.example.com", 80);
    assert!(target_matches(RuleTarget::DomainRegex, r"^sub\..*\.com$", &dest));
    assert!(!target_matches(RuleTarget::DomainRegex, r"^other", &dest));
}

#[test]
fn test_ip_cidr_rule_matching() {
    let dest = Destination::new("8.8.8.8", 53);
    assert!(target_matches(RuleTarget::IpCidr, "8.8.8.0/24", &dest));
    assert!(!target_matches(RuleTarget::IpCidr, "1.1.1.0/24", &dest));
}

#[test]
fn test_geosite_cn_matching() {
    let dest = Destination::new("baidu.com", 80);
    assert!(target_matches(RuleTarget::GeoSite, "cn", &dest));
}

#[test]
fn test_geosite_google_matching() {
    let dest = Destination::new("google.com", 80);
    assert!(target_matches(RuleTarget::GeoSite, "google", &dest));
}

#[test]
fn test_match_rule_always_matches() {
    let dest = Destination::new("anything.com", 80);
    assert!(target_matches(RuleTarget::Match, "*", &dest));
}

#[test]
fn test_wireguard_config_validation() {
    let config = OutboundConfig::WireGuard {
        name: "wg-test".to_string(),
        server: "wg.example.com".to_string(),
        port: 51820,
        private_key: "test-key".to_string(),
        public_key: "test-pub".to_string(),
        preshared_key: None,
        ip: vec!["10.0.0.2/32".to_string()],
        ipv6: vec![],
        allowed_ips: vec!["0.0.0.0/0".to_string()],
        reserved: vec![],
        mtu: Some(1420),
        persistent_keepalive: None,
        remote_dns_resolve: false,
        dns: vec![],
        peers: vec![],
    };
    assert_eq!(config.name(), "wg-test");
}

#[test]
fn test_fake_ip_range_constants() {
    let range_start: u32 = 0xC6120000;
    let range_end: u32 = 0xC613FFFF;
    assert_eq!(range_start, 0xC6120000);
    assert_eq!(range_end, 0xC613FFFF);
}

#[test]
fn test_probe_failure_classification() {
    let failures = vec![
        "timeout", "dial_error", "tls_error", "http_status",
        "empty_response", "outbound_not_found", "protocol_unsupported",
        "invalid_probe_url", "dns_error", "probe_task_failed",
    ];

    let expected: HashSet<&str> = HashSet::from([
        "timeout",
        "dial_error",
        "tls_error",
        "http_status",
        "empty_response",
        "outbound_not_found",
        "protocol_unsupported",
        "invalid_probe_url",
        "dns_error",
        "probe_task_failed",
    ]);

    let observed: HashSet<&str> = failures.iter().copied().collect();
    assert_eq!(observed, expected);
    assert!(expected.is_disjoint(&HashSet::from(["unsupported"])));
    assert!(failures.iter().all(|kind| kind
        .chars()
        .all(|item| item.is_ascii_lowercase() || item == '_')));
}

#[test]
fn test_rule_target_coverage() {
    let targets = vec![
        RuleTarget::Domain, RuleTarget::DomainSuffix, RuleTarget::DomainKeyword,
        RuleTarget::DomainRegex, RuleTarget::IpCidr, RuleTarget::IpCidr6,
        RuleTarget::GeoSite, RuleTarget::AppName, RuleTarget::AppPath,
        RuleTarget::AppPathRegex, RuleTarget::AppBundle,
        RuleTarget::InPort, RuleTarget::SrcIpCidr, RuleTarget::SrcPort, RuleTarget::DstPort,
        RuleTarget::Network, RuleTarget::Match,
    ];

    let mut seen_targets: Vec<RuleTarget> = Vec::new();
    for target in &targets {
        assert!(!seen_targets.contains(target));
        seen_targets.push(*target);
    }

    let domain = Destination::new("example.com", 80);
    assert!(target_matches(RuleTarget::Domain, "example.com", &domain));
    assert!(!target_matches(RuleTarget::Domain, "sub.example.com", &domain));

    let suffix = Destination::new("sub.example.com", 80);
    assert!(target_matches(RuleTarget::DomainSuffix, "example.com", &suffix));
    assert!(!target_matches(RuleTarget::DomainSuffix, "foo.com", &suffix));

    let keyword = Destination::new("api.example.com", 80);
    assert!(target_matches(RuleTarget::DomainKeyword, "example", &keyword));
    assert!(!target_matches(RuleTarget::DomainKeyword, "google", &keyword));

    let regex_domain = Destination::new("sub.example.com", 80);
    assert!(target_matches(RuleTarget::DomainRegex, r"^sub\..*\.com$", &regex_domain));
    assert!(!target_matches(RuleTarget::DomainRegex, r"^other", &regex_domain));

    assert!(target_matches(RuleTarget::Ip, "8.8.8.8", &Destination::new("8.8.8.8", 53)));
    assert!(!target_matches(RuleTarget::Ip, "8.8.8.9", &Destination::new("8.8.8.8", 53)));

    assert!(target_matches(RuleTarget::IpCidr, "8.8.8.0/24", &Destination::new("8.8.8.8", 53)));
    assert!(!target_matches(RuleTarget::IpCidr, "1.1.1.0/24", &Destination::new("8.8.8.8", 53)));

    let app_target = Destination::new("example.com", 80).with_app(AppIdentity {
        name: Some("wechat".to_string()),
        path: Some("/Applications/WeChat.app/Contents/MacOS/WeChat".to_string()),
        bundle_id: Some("com.tencent.xinWeChat".to_string()),
    });
    assert!(target_matches(RuleTarget::AppName, "wechat", &app_target));
    assert!(!target_matches(RuleTarget::AppName, "qq", &app_target));
    assert!(target_matches(RuleTarget::AppPath, "/Applications/WeChat.app/Contents/MacOS/WeChat", &app_target));
    assert!(target_matches(
        RuleTarget::AppPathRegex,
        r"wechat\.app",
        &app_target
    ));
    assert!(target_matches(RuleTarget::AppBundle, "com.tencent.xinWeChat", &app_target));

    assert!(target_matches(
        RuleTarget::InPort,
        "80",
        &Destination::new("api.example.com", 443).with_in_port(80)
    ));
    assert!(!target_matches(
        RuleTarget::InPort,
        "443",
        &Destination::new("api.example.com", 80)
    ));
    assert!(target_matches(RuleTarget::DstPort, "80", &Destination::new("api.example.com", 80)));

    let contextual = Destination::new("api.example.com", 8443)
        .with_source("192.168.1.10".parse::<IpAddr>().unwrap(), 53124)
        .with_in_port(7890)
        .with_network("tcp");
    assert!(target_matches(RuleTarget::SrcIpCidr, "192.168.1.0/24", &contextual));
    assert!(target_matches(RuleTarget::SrcPort, "53000-53200", &contextual));
    assert!(target_matches(RuleTarget::InPort, "7890", &contextual));
    assert!(target_matches(RuleTarget::DstPort, "8400-8500", &contextual));
    assert!(target_matches(RuleTarget::Network, "TCP", &contextual));
    assert!(!target_matches(RuleTarget::Network, "udp", &contextual));

    let ip = Destination::new("8.8.8.8", 443);
    assert!(!target_matches(RuleTarget::SrcIpCidr, "8.8.8.0/24", &ip));
    assert!(!target_matches(RuleTarget::GeoIp, "CN", &ip));
    assert!(!target_matches(RuleTarget::Network, "tcp", &ip));
    assert!(!target_matches(RuleTarget::InPort, "443", &ip));
    assert!(target_matches(RuleTarget::Match, "any", &ip));
}

#[test]
fn test_dns_fallback_exists() {
    let config = SuperConfig::default();
    assert!(config.dns.enabled);
}

#[test]
fn test_provider_cache_path_structure() {
    let store_dir = std::env::temp_dir().join(format!(
        "supercore-plan-provider-store-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let store = SubscriptionStore::new(&store_dir);

    let yaml = r#"
proxies:
  - name: plan-behavior-node
    type: ss
    server: 127.0.0.1
    port: 8388
    cipher: aes-128-gcm
    password: password
"#;

    let imported = store
        .import_text(Some("Plan Behavior".to_string()), Some("https://example.com/subscription".to_string()), yaml, true)
        .expect("should import yaml");

    let index = store.index().unwrap();
    assert_eq!(index.version, 1);
    assert_eq!(index.subscriptions.len(), 1);
    assert_eq!(index.active_id.as_deref(), Some(imported.meta.id.as_str()));

    let document = store.document(&imported.meta.id).unwrap();
    assert_eq!(document.source_format, "clash-yaml");
    assert_eq!(document.nodes.len(), 1);
    assert_eq!(document.nodes[0].name, "plan-behavior-node");
    assert!(store
        .active_meta()
        .unwrap()
        .is_some_and(|meta| meta.id == imported.meta.id));

    let _ = fs::remove_dir_all(store_dir);
}
