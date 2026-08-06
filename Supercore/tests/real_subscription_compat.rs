use std::time::Duration;

use supercore::{
    config::{RuleTarget, SuperConfig},
    subscription::parse_subscription,
    subscription_store::{runtime_config_from_document, SubscriptionStore},
};
use tokio_util::sync::CancellationToken;

#[test]
fn realistic_mixed_subscription_fixture_builds_runtime_config() {
    let text = include_str!("fixtures/realistic_mixed_subscription.yaml");
    let document = parse_subscription(text).expect("fixture parses");

    assert_eq!(document.nodes.len(), 4);
    assert_eq!(document.supported_outbounds().len(), 4);
    assert!(
        document.unsupported.is_empty(),
        "{:?}",
        document.unsupported
    );

    let config = runtime_config_from_document(SuperConfig::default(), &document, true)
        .expect("runtime config");
    assert!(config.outbounds.iter().any(|item| item.name() == "Auto"));
    assert!(config
        .rules
        .iter()
        .any(|rule| rule.target == RuleTarget::DomainSuffix && rule.outbound == "Auto"));
    assert_eq!(config.core.default_outbound, "HK-SS-01");
}

#[tokio::test]
#[ignore = "set SUPERCORE_TEST_SUBSCRIPTION_URLS to newline or comma separated URLs"]
async fn external_subscription_urls_parse_without_persisting_source() {
    let urls = std::env::var("SUPERCORE_TEST_SUBSCRIPTION_URLS")
        .expect("SUPERCORE_TEST_SUBSCRIPTION_URLS is required");
    let urls = urls
        .split([',', '\n'])
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .collect::<Vec<_>>();
    assert!(!urls.is_empty(), "provide at least one URL");

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .no_proxy()
        .build()
        .expect("client");
    for url in urls {
        let response = client
            .get(url)
            .header("User-Agent", "SupercoreRealSubscriptionCompat/0.1")
            .send()
            .await
            .expect("fetch")
            .error_for_status()
            .expect("status");
        let status = response.status();
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("<missing>")
            .to_string();
        let body = response
            .bytes()
            .await
            .expect("text");
        assert!(
            !body.is_empty(),
            "external subscription response body is empty (status={status}, content-type={content_type})"
        );
        let text = String::from_utf8(body.to_vec()).expect("utf8");
        let root = TempDirGuard(tempfile_dir("supercore-real-sub"));
        let store = SubscriptionStore::new(&root.0);
        let imported = store
            .import_text_with_id_async(
                Some("external".to_string()),
                Some("external".to_string()),
                Some(url.to_string()),
                &text,
                false,
                20,
                &CancellationToken::new(),
            )
            .await
            .expect("import");
        let document = store.document("external").expect("stored document");
        assert!(
            !document.nodes.is_empty(),
            "subscription import returned no parseable nodes"
        );
        assert!(
            !document.supported_outbounds().is_empty(),
            "subscription import returned no supported nodes"
        );
        assert_eq!(imported.meta.node_count, document.nodes.len());
    }
}

struct TempDirGuard(std::path::PathBuf);

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn tempfile_dir(name: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("{name}-{nanos}"))
}
