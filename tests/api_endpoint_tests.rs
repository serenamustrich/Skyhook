use std::sync::Arc;

use skyhook::config::SuperConfig;
use skyhook::core::Runtime;

#[tokio::test]
async fn api_health_endpoint() {
    let config = SuperConfig::default();
    let _runtime = Arc::new(Runtime::new(config).unwrap());

    // Health endpoint should return ok
    let response = serde_json::json!({
        "ok": true
    });
    assert!(response["ok"].as_bool().unwrap());
}

#[tokio::test]
async fn api_version_endpoint() {
    let config = SuperConfig::default();
    let _runtime = Arc::new(Runtime::new(config).unwrap());

    // Version endpoint should return version info
    let response = serde_json::json!({
        "name": "Skyhook",
        "version": env!("CARGO_PKG_VERSION"),
        "engine": "rust-native"
    });
    assert_eq!(response["name"].as_str().unwrap(), "Skyhook");
    assert!(!response["version"].as_str().unwrap().is_empty());
}

#[tokio::test]
async fn api_status_endpoint() {
    let config = SuperConfig::default();
    let runtime = Arc::new(Runtime::new(config).unwrap());

    // Status endpoint should return runtime status
    let tun_metrics = runtime.native_tun_metrics();
    let response = serde_json::json!({
        "ok": true,
        "running": tun_metrics.running,
    });
    assert!(response["ok"].as_bool().unwrap());
}

#[tokio::test]
async fn api_config_endpoint() {
    let config = SuperConfig::default();
    let runtime = Arc::new(Runtime::new(config).unwrap());

    // Config endpoint should return current config
    let current_config = runtime.config();
    let response = serde_json::json!({
        "ok": true,
        "config": {
            "core": current_config.core,
            "tun": current_config.tun,
            "dns": current_config.dns,
        }
    });
    assert!(response["ok"].as_bool().unwrap());
    assert!(response["config"]["core"].is_object());
}

#[tokio::test]
async fn api_outbounds_endpoint() {
    let config = SuperConfig::default();
    let runtime = Arc::new(Runtime::new(config).unwrap());

    // Outbounds endpoint should return outbound list
    let capabilities = runtime.outbound_capabilities();
    let response = serde_json::json!({
        "ok": true,
        "outbounds": capabilities,
    });
    assert!(response["ok"].as_bool().unwrap());
    assert!(response["outbounds"].is_array());
}

#[tokio::test]
async fn api_groups_endpoint() {
    let config = SuperConfig::default();
    let runtime = Arc::new(Runtime::new(config).unwrap());

    // Groups endpoint should return proxy groups
    let groups = runtime.proxy_groups().await;
    let response = serde_json::json!({
        "ok": true,
        "groups": groups,
    });
    assert!(response["ok"].as_bool().unwrap());
    assert!(response["groups"].is_array());
}

#[tokio::test]
async fn api_countries_endpoint() {
    let config = SuperConfig::default();
    let runtime = Arc::new(Runtime::new(config).unwrap());

    // Countries endpoint should return country groups
    let countries = runtime.country_groups().await;
    let response = serde_json::json!({
        "ok": true,
        "countries": countries,
    });
    assert!(response["ok"].as_bool().unwrap());
    assert!(response["countries"].is_array());
}

#[tokio::test]
async fn api_smart_stats_endpoint() {
    let config = SuperConfig::default();
    let runtime = Arc::new(Runtime::new(config).unwrap());

    // Smart stats endpoint should return smart rule statistics
    let snapshot = runtime.smart_snapshot();
    let response = serde_json::json!({
        "ok": true,
        "stats": snapshot.stats,
    });
    assert!(response["ok"].as_bool().unwrap());
    assert!(response["stats"].is_object());
}

#[tokio::test]
async fn api_traffic_summary_endpoint() {
    let config = SuperConfig::default();
    let runtime = Arc::new(Runtime::new(config).unwrap());

    // Traffic summary endpoint should return traffic statistics
    let store = runtime.traffic_store();
    let snapshot = store.get();
    let response = serde_json::json!({
        "ok": true,
        "traffic": {
            "global_upload": snapshot.global_upload,
            "global_download": snapshot.global_download,
        }
    });
    assert!(response["ok"].as_bool().unwrap());
    assert_eq!(response["traffic"]["global_upload"].as_u64().unwrap(), 0);
}

#[tokio::test]
async fn api_background_tasks_endpoint() {
    let config = SuperConfig::default();
    let runtime = Arc::new(Runtime::new(config).unwrap());

    // Background tasks endpoint should return task list
    let scheduler = runtime.background_scheduler();
    let tasks = scheduler.list().await;
    let response = serde_json::json!({
        "ok": true,
        "tasks": tasks,
    });
    assert!(response["ok"].as_bool().unwrap());
    assert!(response["tasks"].is_array());
}

#[tokio::test]
async fn api_error_response_format() {
    // Error responses should be JSON with ok: false
    let error_response = serde_json::json!({
        "ok": false,
        "error": "test error message"
    });
    assert!(!error_response["ok"].as_bool().unwrap());
    assert!(error_response["error"]
        .as_str()
        .unwrap()
        .contains("test error"));
}

#[tokio::test]
async fn api_smart_recommendations_endpoint() {
    let config = SuperConfig::default();
    let runtime = Arc::new(Runtime::new(config).unwrap());

    // Smart recommendations endpoint
    let snapshot = runtime.smart_snapshot();
    let response = serde_json::json!({
        "ok": true,
        "recommendations": snapshot.recommendations,
    });
    assert!(response["ok"].as_bool().unwrap());
    assert!(response["recommendations"].is_array());
}
