use std::time::Duration;

use skyhook::{
    config::{RuleTarget, SuperConfig},
    subscription::parse_subscription,
    subscription_store::{runtime_config_from_document, SubscriptionStore},
};

#[test]
fn realistic_mixed_subscription_fixture_builds_runtime_config() {
    let text = include_str!("fixtures/realistic_mixed_subscription.yaml");
    let document = parse_subscription(text).expect("fixture parses");

    assert_eq!(document.nodes.len(), 6);
    assert_eq!(document.supported_outbounds().len(), 6);
    assert!(
        document.unsupported.is_empty(),
        "{:?}",
        document.unsupported
    );

    assert!(document.nodes.iter().any(|n| n.name == "MI-Unsupported-01"));
    assert!(document.nodes.iter().any(|n| n.name == "JU-Unsupported-01"));

    let config = runtime_config_from_document(SuperConfig::default(), &document, true);
    assert!(config.outbounds.iter().any(|item| item.name() == "Auto"));
    assert!(config
        .rules
        .iter()
        .any(|rule| rule.target == RuleTarget::DomainSuffix && rule.outbound == "Auto"));
    assert_eq!(config.core.default_outbound, "HK-SS-01");
}

#[tokio::test]
#[ignore = "set SKYHOOK_TEST_SUBSCRIPTION_URLS to newline or comma separated URLs"]
async fn external_subscription_urls_parse_without_persisting_source() {
    let urls = std::env::var("SKYHOOK_TEST_SUBSCRIPTION_URLS")
        .expect("SKYHOOK_TEST_SUBSCRIPTION_URLS is required");
    let urls = urls
        .split([',', '\n'])
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .collect::<Vec<_>>();
    assert!(!urls.is_empty(), "provide at least one URL");

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .build()
        .expect("client");
    for url in urls {
        let text = client
            .get(url)
            .header("User-Agent", "SkyhookRealSubscriptionCompat/0.1")
            .send()
            .await
            .expect("fetch")
            .error_for_status()
            .expect("status")
            .text()
            .await
            .expect("text");
        let document = parse_subscription(&text).expect("parse");
        let supported = document.supported_outbounds().len();
        assert!(
            !document.nodes.is_empty(),
            "subscription returned no parseable nodes: {url}"
        );
        assert!(
            supported > 0,
            "subscription returned no supported nodes: {url}"
        );

        let root = tempfile_dir("skyhook-real-sub");
        let store = SubscriptionStore::new(&root);
        let imported = store
            .import_text(
                Some("external".to_string()),
                Some(url.to_string()),
                &text,
                false,
            )
            .expect("import");
        assert_eq!(imported.meta.node_count, document.nodes.len());
        let _ = std::fs::remove_dir_all(root);
    }
}

fn tempfile_dir(name: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("{name}-{nanos}"))
}
