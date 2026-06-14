use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use skyhook::{
    config::{OutboundConfig, RuleTarget, SuperConfig},
    subscription::parse_subscription,
    subscription_store::{runtime_config_from_document, SubscriptionStore},
};

const FIRST_SUB: &str = r#"
proxies:
  - name: HK-01
    type: ss
    server: hk.example.com
    port: 8388
    cipher: aes-128-gcm
    password: secret
proxy-groups:
  - name: First Group
    type: select
    proxies:
      - HK-01
rules:
  - MATCH,HK-01
"#;

const SECOND_SUB: &str = r#"
proxies:
  - name: SG-01
    type: trojan
    server: sg.example.com
    port: 443
    password: secret
    sni: sg.example.com
proxy-groups:
  - name: Second Group
    type: url-test
    proxies:
      - SG-01
"#;

const RULE_SUB: &str = r#"
proxies:
  - name: HK-01
    type: ss
    server: hk.example.com
    port: 8388
    cipher: aes-128-gcm
    password: secret
proxy-groups:
  - name: Auto
    type: url-test
    proxies:
      - HK-01
      - DIRECT
rule-providers:
  apple:
    type: inline
    behavior: domain
    payload:
      - "+.apple.com"
  private:
    type: inline
    behavior: ipcidr
    payload:
      - 10.0.0.0/8
rules:
  - DOMAIN-SUFFIX,example.com,Auto
  - IP-CIDR,10.0.0.0/8,DIRECT,no-resolve
  - DOMAIN-SUFFIX,blocked.example,REJECT
  - RULE-SET,apple,DIRECT
  - GEOIP,CN,DIRECT
  - MATCH,Auto
"#;

#[test]
fn first_import_becomes_active_but_later_import_does_not_switch() {
    let root = unique_store_dir("first-active");
    let store = SubscriptionStore::new(&root);

    let first = store
        .import_text(
            Some("First".to_string()),
            Some("https://example.com/first".to_string()),
            FIRST_SUB,
            false,
        )
        .expect("first import");
    let second = store
        .import_text(
            Some("Second".to_string()),
            Some("https://example.com/second".to_string()),
            SECOND_SUB,
            false,
        )
        .expect("second import");

    assert!(first.active_changed);
    assert!(!second.active_changed);

    let index = store.index().expect("index");
    assert_eq!(index.subscriptions.len(), 2);
    assert_eq!(index.active_id.as_deref(), Some(first.meta.id.as_str()));

    fs::remove_dir_all(root).ok();
}

#[test]
fn fixed_id_import_replaces_existing_subscription_without_losing_traffic() {
    let root = unique_store_dir("fixed-id");
    let store = SubscriptionStore::new(&root);
    let first = store
        .import_text_with_id(
            Some("profile-a".to_string()),
            Some("First".to_string()),
            Some("https://example.com/one".to_string()),
            FIRST_SUB,
            true,
        )
        .expect("import first");
    store
        .add_traffic(&first.meta.id, 100, 200)
        .expect("traffic");

    let second = store
        .import_text_with_id(
            Some("profile-a".to_string()),
            Some("Second".to_string()),
            Some("https://example.com/two".to_string()),
            RULE_SUB,
            true,
        )
        .expect("replace");

    assert_eq!(second.meta.id, "profile-a");
    assert_eq!(second.meta.name, "Second");
    assert_eq!(second.meta.traffic_upload_total, 100);
    assert_eq!(second.meta.traffic_download_total, 200);

    let index = store.index().expect("index");
    assert_eq!(index.subscriptions.len(), 1);
    assert_eq!(index.active_id.as_deref(), Some("profile-a"));
}

#[test]
fn active_subscription_can_be_switched_explicitly() {
    let root = unique_store_dir("switch-active");
    let store = SubscriptionStore::new(&root);
    let first = store
        .import_text(Some("First".to_string()), None, FIRST_SUB, false)
        .expect("first import");
    let second = store
        .import_text(Some("Second".to_string()), None, SECOND_SUB, false)
        .expect("second import");

    let active = store.set_active(&second.meta.id).expect("set active");

    assert_eq!(active.id, second.meta.id);
    assert_ne!(active.id, first.meta.id);
    assert_eq!(
        store.index().expect("index").active_id.as_deref(),
        Some(second.meta.id.as_str())
    );

    fs::remove_dir_all(root).ok();
}

#[test]
fn active_runtime_config_adds_subscription_outbounds_and_can_pick_default() {
    let root = unique_store_dir("runtime-config");
    let store = SubscriptionStore::new(&root);
    let imported = store
        .import_text(Some("First".to_string()), None, FIRST_SUB, false)
        .expect("import");

    let config = store
        .active_runtime_config(SuperConfig::default(), true)
        .expect("runtime config");

    assert_eq!(config.core.default_outbound, "HK-01");
    assert!(config
        .rules
        .iter()
        .any(|rule| rule.target == RuleTarget::Match && rule.outbound == "HK-01"));
    assert!(config
        .outbounds
        .iter()
        .any(|item| matches!(item, OutboundConfig::Direct { name } if name == "direct")));
    assert!(config
        .outbounds
        .iter()
        .any(|item| matches!(item, OutboundConfig::Shadowsocks { name, .. } if name == "HK-01")));
    assert!(config.outbounds.iter().any(|item| {
        matches!(
            item,
            OutboundConfig::Group { name, kind, members }
                if name == "First Group" && kind == "select" && members == &vec!["HK-01".to_string()]
        )
    }));
    assert_eq!(imported.meta.supported_outbound_count, 1);

    fs::remove_dir_all(root).ok();
}

#[test]
fn proxy_provider_only_subscription_resolves_nodes_and_group_use() {
    let root = unique_store_dir("proxy-provider");
    let provider_path = root.join("provider.yaml");
    fs::create_dir_all(&root).expect("store dir");
    fs::write(
        &provider_path,
        r#"
proxies:
  - name: Provider-HK
    type: ss
    server: hk.example.com
    port: 8388
    cipher: aes-128-gcm
    password: secret
"#,
    )
    .expect("provider file");
    let subscription = format!(
        r#"
proxy-providers:
  airport:
    type: file
    path: "{}"
proxy-groups:
  - name: Proxy
    type: select
    use:
      - airport
rules:
  - MATCH,Proxy
"#,
        provider_path.display()
    );
    let store = SubscriptionStore::new(&root);

    let imported = store
        .import_text(Some("Provider".to_string()), None, &subscription, false)
        .expect("import");
    let document = store.document(&imported.meta.id).expect("document");
    let config = store
        .active_runtime_config(SuperConfig::default(), true)
        .expect("runtime config");

    assert_eq!(imported.meta.node_count, 1);
    assert_eq!(imported.meta.supported_outbound_count, 1);
    assert_eq!(document.proxy_providers[0].nodes[0].name, "Provider-HK");
    assert!(config.outbounds.iter().any(|item| {
        matches!(item, OutboundConfig::Shadowsocks { name, .. } if name == "Provider-HK")
    }));
    assert!(config.outbounds.iter().any(|item| {
        matches!(
            item,
            OutboundConfig::Group { name, members, .. }
                if name == "Proxy" && members == &vec!["Provider-HK".to_string()]
        )
    }));

    fs::remove_dir_all(root).ok();
}

#[test]
fn replace_text_refreshes_counts_without_changing_identity() {
    let root = unique_store_dir("replace");
    let store = SubscriptionStore::new(&root);
    let imported = store
        .import_text(Some("First".to_string()), None, FIRST_SUB, false)
        .expect("import");

    let updated = store
        .replace_text(&imported.meta.id, SECOND_SUB)
        .expect("replace");

    assert_eq!(updated.id, imported.meta.id);
    assert_eq!(updated.name, "First");
    assert_eq!(updated.node_count, 1);
    assert_eq!(updated.supported_outbound_count, 1);
    assert!(updated.updated_at >= imported.meta.updated_at);

    let document = store.document(&updated.id).expect("document");
    assert_eq!(document.nodes[0].name, "SG-01");

    fs::remove_dir_all(root).ok();
}

#[test]
fn subscription_rules_keep_base_custom_rules_first() {
    let document = parse_subscription(RULE_SUB).expect("subscription");
    let base = SuperConfig {
        rules: vec![
            skyhook::config::RouteRule {
                target: RuleTarget::DomainSuffix,
                value: "custom.example".to_string(),
                outbound: "direct".to_string(),
            },
            skyhook::config::RouteRule {
                target: RuleTarget::Match,
                value: "*".to_string(),
                outbound: "direct".to_string(),
            },
        ],
        ..Default::default()
    };

    let config = runtime_config_from_document(base, &document, true);

    assert_eq!(config.rules[0].target, RuleTarget::DomainSuffix);
    assert_eq!(config.rules[0].value, "custom.example");
    assert_eq!(config.rules[1].target, RuleTarget::DomainSuffix);
    assert_eq!(config.rules.last().unwrap().target, RuleTarget::Match);
}

#[test]
fn subscription_traffic_accumulates_and_survives_replace() {
    let root = unique_store_dir("traffic");
    let store = SubscriptionStore::new(&root);
    let imported = store
        .import_text(Some("First".to_string()), None, FIRST_SUB, false)
        .expect("import");

    store
        .add_traffic(&imported.meta.id, 100, 250)
        .expect("traffic");
    store
        .add_traffic(&imported.meta.id, 25, 50)
        .expect("traffic");
    let updated = store
        .replace_text(&imported.meta.id, SECOND_SUB)
        .expect("replace");

    assert_eq!(updated.traffic_upload_total, 125);
    assert_eq!(updated.traffic_download_total, 300);
    let index = store.index().expect("index");
    assert_eq!(index.subscriptions[0].traffic_upload_total, 125);
    assert_eq!(index.subscriptions[0].traffic_download_total, 300);

    fs::remove_dir_all(root).ok();
}

#[test]
fn active_runtime_config_uses_convertible_subscription_rules() {
    let root = unique_store_dir("subscription-rules");
    let store = SubscriptionStore::new(&root);
    store
        .import_text(Some("Rules".to_string()), None, RULE_SUB, false)
        .expect("import");

    let config = store
        .active_runtime_config(SuperConfig::default(), true)
        .expect("runtime config");

    assert!(config.rules.iter().any(|rule| {
        rule.target == RuleTarget::DomainSuffix
            && rule.value == "example.com"
            && rule.outbound == "Auto"
    }));
    assert!(config.rules.iter().any(|rule| {
        rule.target == RuleTarget::IpCidr && rule.value == "10.0.0.0/8" && rule.outbound == "direct"
    }));
    assert!(config.rules.iter().any(|rule| {
        rule.target == RuleTarget::DomainSuffix
            && rule.value == "blocked.example"
            && rule.outbound == "reject"
    }));
    assert!(config
        .rules
        .iter()
        .any(|rule| rule.target == RuleTarget::RuleSet && rule.value == "apple"));
    assert!(config
        .rules
        .iter()
        .any(|rule| rule.target == RuleTarget::GeoIp && rule.value == "CN"));
    assert!(config
        .rule_sets
        .iter()
        .any(|set| set.name == "apple" && set.rules.iter().any(|rule| rule == "+.apple.com")));
    assert!(config
        .rule_sets
        .iter()
        .any(|set| set.name == "private" && set.rules.iter().any(|rule| rule == "10.0.0.0/8")));
    assert!(config
        .rules
        .iter()
        .any(|rule| rule.target == RuleTarget::Match && rule.outbound == "Auto"));

    fs::remove_dir_all(root).ok();
}

fn unique_store_dir(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("skyhook-store-{name}-{nanos}"))
}
