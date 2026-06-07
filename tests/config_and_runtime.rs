use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use skyhook::{
    config::{OutboundConfig, RouteRule, RuleTarget, SmartRouteRule, SuperConfig},
    core::{ProbeOptions, Runtime},
    routing::{AppIdentity, Destination, RouteDecision, RouteDecisionSource},
    smart::SmartRecommendationAction,
    subscription_store::SubscriptionStore,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    time::{sleep, Duration},
};

#[test]
fn example_config_parses() {
    let config: SuperConfig =
        serde_yaml::from_str(include_str!("../skyhook.example.yaml")).expect("example config");

    assert_eq!(config.core.default_outbound, "direct");
    assert_eq!(config.outbounds.len(), 2);
    assert!(config
        .outbounds
        .iter()
        .any(|item| matches!(item, OutboundConfig::Reject { name } if name == "reject")));
    assert_eq!(config.rules.len(), 7);
    assert_eq!(config.rule_sets.len(), 1);
    assert_eq!(config.geoip.len(), 1);
    assert_eq!(config.smart_rules.rules.len(), 1);
}

#[tokio::test]
async fn reject_outbound_refuses_connections() {
    let mut config = SuperConfig::default();
    isolate_smart_state(&mut config, "reject-outbound");
    config.core.default_outbound = "reject".to_string();
    config.rules = vec![RouteRule {
        target: RuleTarget::Match,
        value: "*".to_string(),
        outbound: "reject".to_string(),
    }];
    let runtime = Runtime::new(config).expect("runtime");
    let error = match runtime
        .connect_outbound(&Destination::new("example.com", 443))
        .await
    {
        Ok(_) => panic!("reject should fail"),
        Err(error) => error,
    };

    assert!(error.to_string().contains("rejected by outbound rule"));
}

#[test]
fn runtime_rejects_missing_default_outbound() {
    let mut config = SuperConfig::default();
    config.core.default_outbound = "missing".to_string();

    let error = Runtime::new(config)
        .err()
        .expect("missing default outbound should fail");

    assert!(error.to_string().contains("default outbound"));
}

#[test]
fn route_decision_uses_structured_rules() {
    let mut config: SuperConfig =
        serde_yaml::from_str(include_str!("../skyhook.example.yaml")).expect("example config");
    isolate_smart_state(&mut config, "route-decision");
    let runtime = Runtime::new(config).expect("runtime");

    let decision = runtime.decide(&Destination::new("hello.local", 80));

    assert_eq!(
        decision,
        RouteDecision {
            outbound: "direct".to_string(),
            matched_rule: Some("DomainSuffix:local".to_string()),
            source: RouteDecisionSource::Static,
        }
    );
}

#[test]
fn smart_rule_overrides_static_rules() {
    let mut config = SuperConfig::default();
    isolate_smart_state(&mut config, "smart-override");
    config.rules = vec![RouteRule {
        target: RuleTarget::Match,
        value: "*".to_string(),
        outbound: "direct".to_string(),
    }];
    config.smart_rules.rules = vec![SmartRouteRule {
        target: RuleTarget::Domain,
        value: "example.com".to_string(),
        outbound: "direct".to_string(),
        enabled: true,
        note: None,
    }];

    let runtime = Runtime::new(config).expect("runtime");
    let decision = runtime.decide(&Destination::new("example.com", 443));

    assert_eq!(decision.source, RouteDecisionSource::Smart);
    assert_eq!(
        decision.matched_rule,
        Some("Smart:Domain:example.com".to_string())
    );
}

#[test]
fn app_and_ip_rules_can_route_to_named_outbound() {
    let mut config = SuperConfig::default();
    isolate_smart_state(&mut config, "app-ip");
    config.rules = vec![
        RouteRule {
            target: RuleTarget::AppBundle,
            value: "com.apple.Safari".to_string(),
            outbound: "direct".to_string(),
        },
        RouteRule {
            target: RuleTarget::Ip,
            value: "1.1.1.1".to_string(),
            outbound: "direct".to_string(),
        },
    ];
    let runtime = Runtime::new(config).expect("runtime");

    let app_decision =
        runtime.decide(&Destination::new("example.com", 443).with_app(AppIdentity {
            name: Some("Safari".to_string()),
            path: Some("/Applications/Safari.app".to_string()),
            bundle_id: Some("com.apple.Safari".to_string()),
        }));
    let ip_decision = runtime.decide(&Destination::new("1.1.1.1", 443));

    assert_eq!(app_decision.source, RouteDecisionSource::Static);
    assert_eq!(
        app_decision.matched_rule,
        Some("AppBundle:com.apple.Safari".to_string())
    );
    assert_eq!(ip_decision.source, RouteDecisionSource::Static);
    assert_eq!(ip_decision.matched_rule, Some("Ip:1.1.1.1".to_string()));
}

#[test]
fn runtime_reload_replaces_router_and_outbounds_for_new_connections() {
    let mut config = SuperConfig::default();
    isolate_smart_state(&mut config, "runtime-reload-before");
    let runtime = Runtime::new(config).expect("runtime");

    let mut next = SuperConfig::default();
    isolate_smart_state(&mut next, "runtime-reload-after");
    next.core.default_outbound = "direct-alt".to_string();
    next.outbounds = vec![
        OutboundConfig::Direct {
            name: "direct".to_string(),
        },
        OutboundConfig::Direct {
            name: "direct-alt".to_string(),
        },
    ];
    next.rules = vec![RouteRule {
        target: RuleTarget::Match,
        value: "*".to_string(),
        outbound: "direct-alt".to_string(),
    }];

    runtime.reload_config(next).expect("reload");
    let decision = runtime.decide(&Destination::new("example.com", 443));

    assert_eq!(decision.outbound, "direct-alt");
}

#[test]
fn runtime_can_switch_default_outbound_for_new_decisions() {
    let mut config = SuperConfig::default();
    isolate_smart_state(&mut config, "runtime-use-outbound");
    config.core.default_outbound = "direct".to_string();
    config.outbounds = vec![
        OutboundConfig::Direct {
            name: "direct".to_string(),
        },
        OutboundConfig::Direct {
            name: "node-a".to_string(),
        },
    ];
    config.rules = vec![RouteRule {
        target: RuleTarget::Match,
        value: "*".to_string(),
        outbound: "direct".to_string(),
    }];

    let runtime = Runtime::new(config).expect("runtime");
    let config = runtime.use_outbound("node-a").expect("use outbound");
    let decision = runtime.decide(&Destination::new("example.com", 443));

    assert_eq!(config.core.default_outbound, "node-a");
    assert_eq!(decision.outbound, "node-a");
}

#[tokio::test]
async fn group_outbound_can_connect_through_member() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (_stream, _) = listener.accept().await.unwrap();
    });

    let mut config = SuperConfig::default();
    isolate_smart_state(&mut config, "group-outbound");
    config.core.default_outbound = "auto".to_string();
    config.outbounds = vec![
        OutboundConfig::Direct {
            name: "direct".to_string(),
        },
        OutboundConfig::Group {
            name: "auto".to_string(),
            kind: "url-test".to_string(),
            members: vec!["direct".to_string()],
        },
    ];
    config.rules.clear();

    let runtime = Runtime::new(config).expect("runtime");
    let (stream, decision, outbound) = runtime
        .connect_outbound(&Destination::new(addr.ip().to_string(), addr.port()))
        .await
        .expect("group connect");
    drop(stream);

    assert_eq!(outbound, "auto");
    assert_eq!(decision.outbound, "auto");
}

#[tokio::test]
async fn url_test_group_uses_first_successful_member() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (_stream, _) = listener.accept().await.unwrap();
    });

    let mut config = SuperConfig::default();
    isolate_smart_state(&mut config, "group-url-test");
    config.core.default_outbound = "auto".to_string();
    config.core.connect_timeout_ms = 300;
    config.outbounds = vec![
        OutboundConfig::Http {
            name: "bad-http".to_string(),
            server: "127.0.0.1".to_string(),
            port: 1,
            username: None,
            password: None,
        },
        OutboundConfig::Direct {
            name: "direct".to_string(),
        },
        OutboundConfig::Group {
            name: "auto".to_string(),
            kind: "url-test".to_string(),
            members: vec!["bad-http".to_string(), "direct".to_string()],
        },
    ];
    config.rules.clear();

    let runtime = Runtime::new(config).expect("runtime");
    let (stream, decision, outbound) = runtime
        .connect_outbound(&Destination::new(addr.ip().to_string(), addr.port()))
        .await
        .expect("group connect");
    drop(stream);

    assert_eq!(outbound, "auto");
    assert_eq!(decision.outbound, "auto");
}

#[tokio::test]
async fn select_group_uses_first_successful_member() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (_stream, _) = listener.accept().await.unwrap();
    });

    let mut config = SuperConfig::default();
    isolate_smart_state(&mut config, "group-select");
    config.core.default_outbound = "manual-group".to_string();
    config.core.connect_timeout_ms = 300;
    config.outbounds = vec![
        OutboundConfig::Http {
            name: "bad-http".to_string(),
            server: "127.0.0.1".to_string(),
            port: 1,
            username: None,
            password: None,
        },
        OutboundConfig::Direct {
            name: "direct".to_string(),
        },
        OutboundConfig::Group {
            name: "manual-group".to_string(),
            kind: "select".to_string(),
            members: vec!["bad-http".to_string(), "direct".to_string()],
        },
    ];
    config.rules.clear();

    let runtime = Runtime::new(config).expect("runtime");
    let (stream, decision, outbound) = runtime
        .connect_outbound(&Destination::new(addr.ip().to_string(), addr.port()))
        .await
        .expect("group connect");
    drop(stream);

    assert_eq!(outbound, "manual-group");
    assert_eq!(decision.outbound, "manual-group");
}

#[tokio::test]
async fn proxy_group_snapshot_reports_members_and_best_latency() {
    let mut config = SuperConfig::default();
    isolate_smart_state(&mut config, "group-snapshot");
    config.core.default_outbound = "auto".to_string();
    config.rules.clear();
    config.outbounds = vec![
        OutboundConfig::Direct {
            name: "direct".to_string(),
        },
        OutboundConfig::Direct {
            name: "slow".to_string(),
        },
        OutboundConfig::Direct {
            name: "fast".to_string(),
        },
        OutboundConfig::Group {
            name: "auto".to_string(),
            kind: "url-test".to_string(),
            members: vec!["slow".to_string(), "fast".to_string()],
        },
    ];

    let runtime = Runtime::new(config).expect("runtime");
    runtime
        .telemetry()
        .record_outbound_result("slow", "direct", true, Some(180), None)
        .await;
    runtime
        .telemetry()
        .record_outbound_result("fast", "direct", true, Some(30), None)
        .await;

    let groups = runtime.proxy_groups().await;

    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].name, "auto");
    assert!(groups[0].auto_select);
    assert_eq!(groups[0].selected_member.as_deref(), Some("fast"));
    assert_eq!(groups[0].members.len(), 2);
    assert!(groups[0].members.iter().all(|item| item.healthy));
}

#[tokio::test]
async fn select_group_snapshot_reports_best_latency() {
    let mut config = SuperConfig::default();
    isolate_smart_state(&mut config, "select-group-snapshot");
    config.core.default_outbound = "manual-group".to_string();
    config.rules.clear();
    config.outbounds = vec![
        OutboundConfig::Direct {
            name: "direct".to_string(),
        },
        OutboundConfig::Direct {
            name: "slow".to_string(),
        },
        OutboundConfig::Direct {
            name: "fast".to_string(),
        },
        OutboundConfig::Group {
            name: "manual-group".to_string(),
            kind: "select".to_string(),
            members: vec!["slow".to_string(), "fast".to_string()],
        },
    ];

    let runtime = Runtime::new(config).expect("runtime");
    runtime
        .telemetry()
        .record_outbound_result("slow", "direct", true, Some(180), None)
        .await;
    runtime
        .telemetry()
        .record_outbound_result("fast", "direct", true, Some(30), None)
        .await;

    let groups = runtime.proxy_groups().await;

    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].name, "manual-group");
    assert!(groups[0].auto_select);
    assert_eq!(groups[0].selected_member.as_deref(), Some("fast"));
}

#[tokio::test]
async fn country_groups_detect_nodes_and_can_be_selected() {
    let mut config = SuperConfig::default();
    isolate_smart_state(&mut config, "country-groups");
    config.rules.clear();
    config.outbounds = vec![
        OutboundConfig::Direct {
            name: "direct".to_string(),
        },
        OutboundConfig::Socks5 {
            name: "HK-01 香港".to_string(),
            server: "hk.example.com".to_string(),
            port: 1080,
            username: None,
            password: None,
        },
        OutboundConfig::Socks5 {
            name: "JP-01 Tokyo".to_string(),
            server: "jp.example.com".to_string(),
            port: 1080,
            username: None,
            password: None,
        },
        OutboundConfig::Socks5 {
            name: "JP-02 Osaka".to_string(),
            server: "jp2.example.com".to_string(),
            port: 1080,
            username: None,
            password: None,
        },
    ];

    let runtime = Runtime::new(config).expect("runtime");
    runtime
        .telemetry()
        .record_outbound_result("JP-01 Tokyo", "socks5", true, Some(70), None)
        .await;
    runtime
        .telemetry()
        .record_outbound_result("JP-02 Osaka", "socks5", true, Some(25), None)
        .await;

    let countries = runtime.country_groups().await;
    let jp = countries
        .iter()
        .find(|country| country.code == "JP")
        .expect("JP group");
    assert_eq!(jp.node_count, 2);
    assert_eq!(jp.best_outbound.as_deref(), Some("JP-02 Osaka"));
    assert!(countries.iter().any(|country| country.code == "HK"));

    let config = runtime.use_country_group("jp").await.expect("use country");
    assert_eq!(config.core.default_outbound, "country:JP");
    assert!(config
        .outbounds
        .iter()
        .any(|item| item.name() == "country:JP"));
}

#[tokio::test]
async fn runtime_close_persists_traffic_to_active_subscription() {
    let root = unique_test_dir("runtime-traffic");
    let store = SubscriptionStore::new(&root);
    let imported = store
        .import_text(
            Some("Traffic Sub".to_string()),
            None,
            r#"
proxies:
  - name: HK-01
    type: ss
    server: hk.example.com
    port: 8388
    cipher: aes-128-gcm
    password: secret
"#,
            false,
        )
        .expect("import");

    let mut config = SuperConfig::default();
    isolate_smart_state(&mut config, "runtime-traffic");
    config.subscriptions.store_path = root.clone();
    let runtime = Runtime::new(config).expect("runtime");
    let id = runtime
        .open_connection_record(
            "test",
            Destination::new("example.com", 443),
            "direct".to_string(),
            None,
        )
        .await;
    runtime.telemetry().add_transfer(id, 64, 128).await;
    runtime.close_connection_record(id).await;

    let index = store.index().expect("index");
    let meta = index
        .subscriptions
        .iter()
        .find(|item| item.id == imported.meta.id)
        .expect("meta");
    assert_eq!(meta.traffic_upload_total, 64);
    assert_eq!(meta.traffic_download_total, 128);

    fs::remove_dir_all(root).ok();
}

#[tokio::test]
async fn probe_all_outbounds_records_direct_latency() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = [0u8; 512];
        let _ = stream.read(&mut request).await.unwrap();
        stream
            .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
    });

    let mut config = SuperConfig::default();
    isolate_smart_state(&mut config, "probe-direct-latency");
    config.core.probe_url = format!("http://{addr}/generate_204");
    config.core.probe_timeout_ms = 500;

    let runtime = Runtime::new(config).expect("runtime");
    let results = runtime.probe_all_outbounds().await;

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].name, "direct");
    assert!(results[0].success, "{results:?}");

    let health = runtime.telemetry().outbound_health().await;
    assert_eq!(health.len(), 1);
    assert_eq!(health[0].successes, 1);
}

#[tokio::test]
async fn dns_exchange_uses_tcp_framing_through_runtime() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut len = [0u8; 2];
        stream.read_exact(&mut len).await.unwrap();
        let query_len = u16::from_be_bytes(len) as usize;
        let mut query = vec![0u8; query_len];
        stream.read_exact(&mut query).await.unwrap();
        assert_eq!(query, b"dns-query");
        stream.write_all(&[0, 8]).await.unwrap();
        stream.write_all(b"dns-repl").await.unwrap();
    });

    let mut config = SuperConfig::default();
    isolate_smart_state(&mut config, "dns-over-tcp");
    config.dns.server = addr;

    let runtime = Runtime::new(config).expect("runtime");
    let response = runtime
        .exchange_dns_over_tcp(b"dns-query")
        .await
        .expect("dns exchange");

    assert_eq!(response, b"dns-repl");
}

#[tokio::test]
async fn probe_timeout_can_be_overridden_per_request() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = [0u8; 512];
        let _ = stream.read(&mut request).await.unwrap();
        sleep(Duration::from_millis(100)).await;
        let _ = stream
            .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
            .await;
    });

    let mut config = SuperConfig::default();
    isolate_smart_state(&mut config, "probe-timeout");
    config.core.probe_url = format!("http://{addr}/generate_204");
    config.core.probe_timeout_ms = 500;

    let runtime = Runtime::new(config).expect("runtime");
    let results = runtime
        .probe_all_outbounds_with(ProbeOptions {
            url: None,
            timeout_ms: Some(10),
        })
        .await;

    assert_eq!(results.len(), 1);
    assert!(!results[0].success, "{results:?}");
    assert_eq!(results[0].latency_ms, Some(10));
}

#[tokio::test]
async fn smart_learning_records_direct_recommendation() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (_stream, _) = listener.accept().await.unwrap();
    });

    let mut config = SuperConfig::default();
    let state_path = isolate_smart_state(&mut config, "smart-learning");
    let runtime = Runtime::new(config).expect("runtime");
    let (stream, _decision, _outbound) = runtime
        .connect_outbound(&Destination::new(addr.ip().to_string(), addr.port()))
        .await
        .expect("direct connect");
    drop(stream);

    let snapshot = runtime.smart_snapshot();
    assert_eq!(snapshot.stats.recommended_direct_targets, 1);
    assert_eq!(snapshot.stats.total_visits, 1);
    assert_eq!(snapshot.stats.direct_probe_successes, 1);
    assert_eq!(snapshot.recommendation_buckets.direct.len(), 1);
    assert_eq!(snapshot.recommendations[0].recommended_outbound, "direct");
    let rules = runtime
        .apply_smart_recommendation(RuleTarget::Ip, &addr.ip().to_string())
        .expect("apply one recommendation");
    assert_eq!(rules[0].target, RuleTarget::Ip);
    assert_eq!(rules[0].outbound, "direct");
    let _ = fs::remove_file(state_path);
}

#[tokio::test]
async fn smart_state_persists_observations_and_applied_recommendations() {
    let state_path = unique_test_path("smart-state");
    let _ = fs::remove_file(&state_path);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (_stream, _) = listener.accept().await.unwrap();
    });

    let mut config = SuperConfig::default();
    config.smart_rules.state_path = state_path.clone();
    config.smart_rules.persist_interval_secs = 0;

    let runtime = Runtime::new(config.clone()).expect("runtime");
    let (stream, _decision, _outbound) = runtime
        .connect_outbound(&Destination::new(addr.ip().to_string(), addr.port()))
        .await
        .expect("direct connect");
    drop(stream);
    let rules = runtime.apply_smart_recommendations(Some(SmartRecommendationAction::Direct));
    assert_eq!(rules[0].target, RuleTarget::Ip);

    let reloaded = Runtime::new(config).expect("reloaded runtime");
    let snapshot = reloaded.smart_snapshot();

    assert_eq!(snapshot.observations.len(), 1);
    assert_eq!(snapshot.rules.len(), 1);
    assert_eq!(snapshot.rules[0].target, RuleTarget::Ip);
    assert!(snapshot.last_persist_error.is_none(), "{snapshot:?}");
    let _ = fs::remove_file(state_path);
}

fn unique_test_path(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("skyhook-{name}-{nanos}.json"))
}

fn unique_test_dir(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("skyhook-{name}-{nanos}"))
}

fn isolate_smart_state(config: &mut SuperConfig, name: &str) -> PathBuf {
    let path = unique_test_path(name);
    let _ = fs::remove_file(&path);
    config.smart_rules.state_path = path.clone();
    config.smart_rules.persist_interval_secs = 0;
    path
}
