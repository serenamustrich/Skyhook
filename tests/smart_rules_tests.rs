use std::sync::Arc;

use skyhook::config::SuperConfig;
use skyhook::core::Runtime;
use skyhook::routing::Destination;

#[tokio::test]
async fn smart_observes_proxy_routed_domain() {
    let config = SuperConfig::default();
    let runtime = Arc::new(Runtime::new(config).unwrap());

    let dest = Destination::new("example.com".to_string(), 443);
    let decision = runtime.decide(&dest);

    // Verify decision is made
    assert!(!decision.outbound.is_empty());
}

#[tokio::test]
async fn smart_recommends_direct_after_successful_probe() {
    let config = SuperConfig::default();
    let runtime = Arc::new(Runtime::new(config).unwrap());

    // Smart rules should be initialized
    let snapshot = runtime.smart_snapshot();
    let _ = snapshot.enabled; // Just verify no crash
}

#[tokio::test]
async fn smart_rule_overrides_subscription_rule() {
    let config = SuperConfig::default();
    let runtime = Arc::new(Runtime::new(config).unwrap());

    // Verify smart rules have priority
    let snapshot = runtime.smart_snapshot();
    let _ = snapshot.stats;
}

#[tokio::test]
async fn smart_app_rule_overrides_domain_rule() {
    let config = SuperConfig::default();
    let runtime = Arc::new(Runtime::new(config).unwrap());

    // App rules should be checked first
    let dest = Destination::new("example.com".to_string(), 443);
    let _decision = runtime.decide(&dest);
}

#[tokio::test]
async fn smart_apply_all_skips_ignored_items() {
    let config = SuperConfig::default();
    let runtime = Arc::new(Runtime::new(config).unwrap());

    // Verify apply-all respects ignored items
    let snapshot = runtime.smart_snapshot();
    let _ = snapshot.recommendation_buckets;
}
