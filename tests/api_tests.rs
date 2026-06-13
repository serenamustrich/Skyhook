use skyhook::config::SuperConfig;
use skyhook::core::Runtime;

#[test]
fn runtime_creation() {
    let config = SuperConfig::default();
    let runtime = Runtime::new(config);
    assert!(runtime.is_ok(), "Runtime should be created successfully");
}

#[test]
fn runtime_config_access() {
    let config = SuperConfig::default();
    let runtime = Runtime::new(config).unwrap();
    let config = runtime.config();
    assert!(!config.core.default_outbound.is_empty());
}

#[test]
fn runtime_smart_snapshot() {
    let config = SuperConfig::default();
    let runtime = Runtime::new(config).unwrap();
    let snapshot = runtime.smart_snapshot();
    assert!(snapshot.stats.observed_targets == 0);
}

#[test]
fn runtime_traffic_store() {
    let config = SuperConfig::default();
    let runtime = Runtime::new(config).unwrap();
    let store = runtime.traffic_store();
    let snapshot = store.get();
    assert_eq!(snapshot.global_upload, 0);
    assert_eq!(snapshot.global_download, 0);
}

#[tokio::test]
async fn runtime_background_scheduler() {
    let config = SuperConfig::default();
    let runtime = Runtime::new(config).unwrap();
    let tasks = runtime.background_scheduler().list().await;
    assert!(
        tasks.iter().any(|task| task.name == "subscription_update"),
        "default scheduler should register subscription_update"
    );
    assert!(
        tasks.iter().any(|task| task.name == "outbound_probe"),
        "default scheduler should register outbound_probe"
    );
}

#[test]
fn runtime_proxy_groups() {
    let config = SuperConfig::default();
    let runtime = Runtime::new(config).unwrap();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let groups = rt.block_on(runtime.proxy_groups());
    assert!(groups.is_empty(), "default config has no proxy groups");
}

#[test]
fn runtime_country_groups() {
    let config = SuperConfig::default();
    let runtime = Runtime::new(config).unwrap();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let countries = rt.block_on(runtime.country_groups());
    assert!(countries.is_empty(), "default config has no country groups");
}

#[test]
fn runtime_outbound_capabilities() {
    let config = SuperConfig::default();
    let runtime = Runtime::new(config).unwrap();
    let capabilities = runtime.outbound_capabilities();
    assert!(!capabilities.is_empty());
}

#[test]
fn runtime_native_tun_metrics() {
    let config = SuperConfig::default();
    let runtime = Runtime::new(config).unwrap();
    let _metrics = runtime.native_tun_metrics();
}
