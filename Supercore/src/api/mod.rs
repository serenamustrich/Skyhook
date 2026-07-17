mod auth;
mod diagnostics;
mod error;
mod events;
mod pagination;
mod routes;
mod schema;
mod tasks;

use std::sync::Arc;

use axum::extract::FromRef;

use crate::core::Runtime;

use auth::*;
use diagnostics::{build_doctor_report, export_diagnostic_report};
use error::*;
use events::*;
use pagination::*;
use routes::build_router_with_tasks;
#[cfg(test)]
use routes::collect_group_probe_members;
use schema::*;
use tasks::TaskManager;

#[derive(Clone)]
struct ApiState {
    runtime: Arc<Runtime>,
    tasks: TaskManager,
}

impl ApiState {
    fn new(runtime: Arc<Runtime>, tasks: TaskManager) -> Self {
        Self { runtime, tasks }
    }

    fn runtime(&self) -> &Runtime {
        &self.runtime
    }

    fn runtime_handle(&self) -> Arc<Runtime> {
        self.runtime.clone()
    }

    fn tasks(&self) -> &TaskManager {
        &self.tasks
    }

    fn task_manager(&self) -> TaskManager {
        self.tasks.clone()
    }
}

impl FromRef<ApiState> for Arc<Runtime> {
    fn from_ref(state: &ApiState) -> Self {
        state.runtime_handle()
    }
}

impl FromRef<ApiState> for TaskManager {
    fn from_ref(state: &ApiState) -> Self {
        state.task_manager()
    }
}

pub async fn serve(runtime: Arc<Runtime>) -> anyhow::Result<()> {
    let control_listen = runtime.config().core.control_listen;
    let shutdown = runtime.cancellation_token();
    validate_control_listen(control_listen)?;
    let auth = ControlAuthState {
        token: load_control_token()?,
    };
    if auth.token.is_none() {
        tracing::warn!(
            "control API write operations are disabled because no control token was configured"
        );
    }
    let tasks = TaskManager::default();
    let app = build_router_with_tasks(runtime, auth, tasks.clone());
    let listener = tokio::net::TcpListener::bind(control_listen).await?;
    let result = axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            shutdown.cancelled().await;
        })
        .await;
    tasks.cancel_all("control server stopped").await;
    result?;
    Ok(())
}

#[cfg(test)]
fn build_router(runtime: Arc<Runtime>, auth: ControlAuthState) -> axum::Router {
    build_router_with_tasks(runtime, auth, TaskManager::default())
}

#[cfg(test)]
mod tests {
    use std::{path::PathBuf, time::Duration};

    use super::*;
    use axum::{
        body::{to_bytes, Body},
        http::{header::AUTHORIZATION, HeaderMap, HeaderValue, Method, Request, StatusCode},
        Router,
    };
    use tokio_stream::StreamExt;
    use tower::ServiceExt;

    use crate::{
        config::{OutboundConfig, SuperConfig},
        subscription_store::SubscriptionStore,
    };

    #[test]
    fn control_api_accepts_loopback_only() {
        assert!(validate_control_listen("127.0.0.1:9197".parse().unwrap()).is_ok());
        assert!(validate_control_listen("[::1]:9197".parse().unwrap()).is_ok());
        assert!(validate_control_listen("0.0.0.0:9197".parse().unwrap()).is_err());
    }

    #[test]
    fn write_auth_requires_matching_bearer_token() {
        let token = "0123456789abcdef0123456789abcdef";
        let mut headers = HeaderMap::new();
        assert!(!request_has_valid_token(&headers, Some(token)));
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer incorrect-token-value-000000"),
        );
        assert!(!request_has_valid_token(&headers, Some(token)));
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer 0123456789abcdef0123456789abcdef"),
        );
        assert!(request_has_valid_token(&headers, Some(token)));
        assert!(!request_has_valid_token(&headers, None));
    }

    #[test]
    fn control_token_rejects_short_values() {
        assert!(normalized_control_token(None).unwrap().is_none());
        assert!(normalized_control_token(Some(" ".to_string()))
            .unwrap()
            .is_none());
        assert!(normalized_control_token(Some("too-short".to_string())).is_err());
        assert!(
            normalized_control_token(Some("a".repeat(MIN_CONTROL_TOKEN_BYTES)))
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn control_token_comparison_is_exact() {
        assert!(constant_time_eq(b"same-value", b"same-value"));
        assert!(!constant_time_eq(b"same-value", b"different!"));
        assert!(!constant_time_eq(b"short", b"longer"));
    }

    #[tokio::test]
    async fn router_enforces_write_auth_and_accepts_task_requests() {
        let runtime = Arc::new(Runtime::new(SuperConfig::default()).unwrap());
        let token: Arc<str> = Arc::from("0123456789abcdef0123456789abcdef");
        let app = build_router(
            runtime,
            ControlAuthState {
                token: Some(token.clone()),
            },
        );

        let public_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/version")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(public_response.status(), StatusCode::OK);

        let event_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/events")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(event_response.status(), StatusCode::OK);
        assert_eq!(
            event_response
                .headers()
                .get("content-type")
                .and_then(|value| value.to_str().ok()),
            Some("text/event-stream")
        );

        let unauthorized = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/v1/probes")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

        let accepted = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/v1/probes")
                    .header(AUTHORIZATION, format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"names":["direct"],"timeout_ms":50,"concurrency":1}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(accepted.status(), StatusCode::ACCEPTED);
        let body = to_bytes(accepted.into_body(), 64 * 1024).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let task_id = body["task_id"].as_str().unwrap();

        let mut snapshot = serde_json::Value::Null;
        for _ in 0..50 {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(format!("/v1/tasks/{task_id}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
            snapshot = serde_json::from_slice(&body).unwrap();
            if snapshot["status"] == "succeeded" {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(snapshot["status"], "succeeded");
        assert_eq!(
            snapshot["result"]["results"].as_array().map(Vec::len),
            Some(1)
        );
    }

    #[tokio::test]
    async fn control_schema_is_openapi_31_and_tracks_registered_paths() {
        let runtime = Arc::new(Runtime::new(SuperConfig::default()).unwrap());
        let app = build_router(runtime, ControlAuthState { token: None });
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/schema")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 2 * 1024 * 1024)
            .await
            .unwrap();
        let schema: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(schema["openapi"], "3.1.0");
        assert!(schema["components"]["schemas"]["Pagination"].is_object());
        assert_eq!(
            schema["paths"]["/v1/outbounds"]["get"]["parameters"]
                .as_array()
                .map(Vec::len),
            Some(5)
        );
        assert_eq!(
            schema["paths"]["/v1/outbounds"]["get"]["responses"]["200"]["content"]
                ["application/json"]["schema"]["properties"]["pagination"]["$ref"],
            "#/components/schemas/Pagination"
        );
        assert!(schema["paths"]["/v1/status"]["get"]["parameters"].is_null());

        let route_source = include_str!("routes/mod.rs");
        for spec in CONTROL_ROUTE_SPECS {
            assert!(
                schema["paths"][spec.path][spec.method.to_ascii_lowercase()].is_object(),
                "schema is missing {} {}",
                spec.method,
                spec.path
            );
            let axum_path = spec.path.replace("{id}", ":id");
            assert!(
                route_source.contains(&format!("\"{axum_path}\"")),
                "router is missing {} {}",
                spec.method,
                spec.path
            );
        }
    }

    #[tokio::test]
    async fn list_routes_share_stable_pagination_and_structured_cursor_errors() {
        let runtime = Arc::new(Runtime::new(SuperConfig::default()).unwrap());
        runtime.telemetry().log("info", "older log").await;
        tokio::time::sleep(Duration::from_millis(2)).await;
        runtime.telemetry().log("warn", "newer log").await;
        let app = build_router(runtime, ControlAuthState { token: None });

        let first = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/outbounds?limit=1&sort=name&order=asc")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::OK);
        let first = to_bytes(first.into_body(), 256 * 1024).await.unwrap();
        let first: serde_json::Value = serde_json::from_slice(&first).unwrap();
        assert_eq!(first["outbounds"].as_array().map(Vec::len), Some(1));
        assert!(first["pagination"]["total"].as_u64().unwrap() >= 2);
        let cursor = first["pagination"]["next_cursor"].as_str().unwrap();

        let second = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/v1/outbounds?limit=1&sort=name&order=asc&cursor={cursor}"
                    ))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(second.status(), StatusCode::OK);
        let second = to_bytes(second.into_body(), 256 * 1024).await.unwrap();
        let second: serde_json::Value = serde_json::from_slice(&second).unwrap();
        assert_eq!(second["outbounds"].as_array().map(Vec::len), Some(1));
        assert_ne!(
            first["outbounds"][0]["name"],
            second["outbounds"][0]["name"]
        );

        let stale = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/v1/outbounds?limit=1&sort=name&filter=direct&cursor={cursor}"
                    ))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(stale.status(), StatusCode::BAD_REQUEST);
        let stale = to_bytes(stale.into_body(), 64 * 1024).await.unwrap();
        let stale: serde_json::Value = serde_json::from_slice(&stale).unwrap();
        assert_eq!(stale["code"], "invalid_pagination");
        assert!(stale["message"].as_str().unwrap().contains("stale"));

        let invalid = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/logs?limit=501")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
        let invalid = to_bytes(invalid.into_body(), 64 * 1024).await.unwrap();
        let invalid: serde_json::Value = serde_json::from_slice(&invalid).unwrap();
        assert_eq!(invalid["code"], "invalid_pagination");

        let malformed = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/logs?order=sideways")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(malformed.status(), StatusCode::BAD_REQUEST);
        let malformed = to_bytes(malformed.into_body(), 64 * 1024).await.unwrap();
        let malformed: serde_json::Value = serde_json::from_slice(&malformed).unwrap();
        assert_eq!(malformed["code"], "invalid_pagination");

        let logs = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/logs?limit=1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(logs.status(), StatusCode::OK);
        let logs = to_bytes(logs.into_body(), 64 * 1024).await.unwrap();
        let logs: serde_json::Value = serde_json::from_slice(&logs).unwrap();
        assert_eq!(logs["logs"][0]["message"], "newer log");
        assert_eq!(logs["pagination"]["order"], "desc");

        let summary = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/smart-rules")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let summary = to_bytes(summary.into_body(), 64 * 1024).await.unwrap();
        let summary: serde_json::Value = serde_json::from_slice(&summary).unwrap();
        assert_eq!(summary["rules"].as_array().map(Vec::len), Some(0));
        assert_eq!(summary["observations"].as_array().map(Vec::len), Some(0));
        assert_eq!(summary["recommendations"].as_array().map(Vec::len), Some(0));

        for (path, key) in [
            ("/v1/smart-rules/rules", "rules"),
            ("/v1/smart-rules/observations", "observations"),
            ("/v1/smart-rules/recommendations", "recommendations"),
        ] {
            let response = app
                .clone()
                .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let response = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
            let response: serde_json::Value = serde_json::from_slice(&response).unwrap();
            assert_eq!(response[key].as_array().map(Vec::len), Some(0));
            assert_eq!(response["pagination"]["total"], 0);
        }
    }

    #[tokio::test]
    async fn probe_task_returns_missing_nodes_even_when_probe_url_is_invalid() {
        let runtime = Arc::new(Runtime::new(SuperConfig::default()).unwrap());
        let token: Arc<str> = Arc::from("0123456789abcdef0123456789abcdef");
        let app = build_router(
            runtime,
            ControlAuthState {
                token: Some(token.clone()),
            },
        );
        let accepted = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/v1/probes")
                    .header(AUTHORIZATION, format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{
                            "url":"://invalid",
                            "names":["direct","missing","direct"," "],
                            "timeout_ms":500,
                            "concurrency":2
                        }"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(accepted.status(), StatusCode::ACCEPTED);
        let body = to_bytes(accepted.into_body(), 64 * 1024).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let task_id = body["task_id"].as_str().unwrap();

        let mut snapshot = serde_json::Value::Null;
        for _ in 0..50 {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(format!("/v1/tasks/{task_id}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
            snapshot = serde_json::from_slice(&body).unwrap();
            if snapshot["status"] == "succeeded" {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        assert_eq!(snapshot["status"], "succeeded");
        assert_eq!(snapshot["total"], 2);
        assert_eq!(snapshot["current"], 2);
        let results = snapshot["result"]["results"].as_array().unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0]["name"], "direct");
        assert_eq!(results[0]["failure_kind"], "invalid_probe_url");
        assert_eq!(results[1]["name"], "missing");
        assert_eq!(results[1]["failure_kind"], "outbound_not_found");
    }

    #[tokio::test]
    async fn task_cancel_route_cancels_the_operation_token() {
        let runtime = Arc::new(Runtime::new(SuperConfig::default()).unwrap());
        let token: Arc<str> = Arc::from("0123456789abcdef0123456789abcdef");
        let tasks = TaskManager::default();
        let (record, cancellation) = tasks.create("long_operation", None).await;
        tasks.mark_running(&record.id, "running").await;
        let app = build_router_with_tasks(
            runtime,
            ControlAuthState {
                token: Some(token.clone()),
            },
            tasks.clone(),
        );

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("/v1/tasks/{}/cancel", record.id))
                    .header(AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert!(cancellation.is_cancelled());
        assert_eq!(
            tasks.get(&record.id).await.unwrap().status,
            tasks::TaskStatus::Cancelled
        );
    }

    #[tokio::test]
    async fn event_stream_forwards_versioned_telemetry_events() {
        let runtime = Arc::new(Runtime::new(SuperConfig::default()).unwrap());
        let app = build_router(
            runtime.clone(),
            ControlAuthState {
                token: Some(Arc::from("0123456789abcdef0123456789abcdef")),
            },
        );
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/events")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let mut stream = response.into_body().into_data_stream();

        runtime.telemetry().log("info", "event test").await;
        let chunk = tokio::time::timeout(Duration::from_secs(1), stream.next())
            .await
            .expect("SSE should produce a telemetry event")
            .expect("SSE stream should stay open")
            .expect("SSE event body should be readable");
        let text = String::from_utf8(chunk.to_vec()).unwrap();
        assert!(text.contains("event: log_appended"));
        assert!(text.contains("id:"));
        assert!(text.contains("\"schema_version\":1"));
        assert!(text.contains("\"message\":\"event test\""));
    }

    #[tokio::test]
    async fn remaining_long_operation_routes_complete_as_tasks_and_export_redacted_diagnostics() {
        let root = std::env::temp_dir().join(format!(
            "skyhook-api-long-operations-{}",
            uuid::Uuid::new_v4().simple()
        ));
        let mut config = SuperConfig::default();
        config.subscriptions.store_path = root.clone();
        let store = SubscriptionStore::new(&root);
        store
            .import_text(
                Some("Private Subscription".to_string()),
                Some("https://secret.example/api-secret/subscription".to_string()),
                r#"
proxies:
  - name: Private-Node
    type: ss
    server: private.example
    port: 8388
    cipher: aes-128-gcm
    password: test-password
rules:
  - MATCH,Private-Node
"#,
                false,
            )
            .unwrap();
        let runtime = Arc::new(Runtime::new(config).unwrap());
        let token: Arc<str> = Arc::from("0123456789abcdef0123456789abcdef");
        let app = build_router(
            runtime,
            ControlAuthState {
                token: Some(token.clone()),
            },
        );

        let import_body = serde_json::json!({
            "name": "Imported Task",
            "text": r#"
proxies:
  - name: Imported-Node
    type: ss
    server: imported.example
    port: 8388
    cipher: aes-128-gcm
    password: imported-password
"#,
            "switch": false,
        })
        .to_string();
        let imported = run_task_request(
            app.clone(),
            token.as_ref(),
            "/v1/subscriptions/import",
            Some(&import_body),
        )
        .await;
        assert_eq!(imported["status"], "succeeded");
        assert_eq!(
            imported["result"]["result"]["active_changed"],
            serde_json::Value::Bool(false)
        );
        let imported_id = imported["result"]["result"]["meta"]["id"].as_str().unwrap();
        let update_body = serde_json::json!({ "id": imported_id }).to_string();
        let updated = run_task_request(
            app.clone(),
            token.as_ref(),
            "/v1/subscriptions/update",
            Some(&update_body),
        )
        .await;
        assert_eq!(updated["status"], "succeeded");
        assert_eq!(updated["result"]["result"]["updated"], false);
        assert_eq!(
            updated["result"]["result"]["error"],
            "subscription has no url"
        );

        let provider = run_task_request(
            app.clone(),
            token.as_ref(),
            "/v1/providers/update-all",
            None,
        )
        .await;
        assert_eq!(provider["status"], "succeeded");
        assert_eq!(
            provider["result"]["results"].as_array().map(Vec::len),
            Some(2)
        );

        let geo = run_task_request(app.clone(), token.as_ref(), "/v1/geo/update", None).await;
        assert_eq!(geo["status"], "succeeded");
        assert_eq!(geo["result"]["summaries"].as_array().map(Vec::len), Some(0));

        let doctor = run_task_request(app.clone(), token.as_ref(), "/v1/doctor/run", None).await;
        assert_eq!(doctor["status"], "succeeded");
        assert_eq!(doctor["result"]["report"]["schema_version"], 1);

        let diagnostics =
            run_task_request(app, token.as_ref(), "/v1/diagnostics/export", None).await;
        assert_eq!(diagnostics["status"], "succeeded");
        assert_eq!(diagnostics["result"]["export"]["redacted"], true);
        let diagnostic_path =
            PathBuf::from(diagnostics["result"]["export"]["path"].as_str().unwrap());
        assert!(diagnostic_path.starts_with(&root));
        let diagnostic = std::fs::read_to_string(&diagnostic_path).unwrap();
        assert!(!diagnostic.contains("api-secret"));
        assert!(!diagnostic.contains("test-password"));
        assert!(!diagnostic.contains("Private-Node"));
        assert!(!diagnostic.contains("imported-password"));
        assert!(!diagnostic.contains("Imported-Node"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&diagnostic_path)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }

        std::fs::remove_dir_all(root).ok();
    }

    async fn run_task_request(
        app: Router,
        token: &str,
        path: &str,
        body: Option<&str>,
    ) -> serde_json::Value {
        let accepted = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(path)
                    .header(AUTHORIZATION, format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(body.unwrap_or_default().to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(accepted.status(), StatusCode::ACCEPTED);
        let accepted = to_bytes(accepted.into_body(), 64 * 1024).await.unwrap();
        let accepted: serde_json::Value = serde_json::from_slice(&accepted).unwrap();
        let task_id = accepted["task_id"].as_str().unwrap();

        for _ in 0..100 {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(format!("/v1/tasks/{task_id}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let body = to_bytes(response.into_body(), 8 * 1024 * 1024)
                .await
                .unwrap();
            let snapshot: serde_json::Value = serde_json::from_slice(&body).unwrap();
            if matches!(
                snapshot["status"].as_str(),
                Some("succeeded" | "failed" | "cancelled")
            ) {
                return snapshot;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("task {task_id} did not finish");
    }

    #[test]
    fn test_collect_group_probe_members_flattens_nested_groups() {
        let mut config = SuperConfig::default();
        config.outbounds = vec![
            OutboundConfig::Direct {
                name: "direct".to_string(),
            },
            OutboundConfig::Reject {
                name: "reject".to_string(),
            },
            OutboundConfig::Group {
                name: "node-group".to_string(),
                kind: "url-test".to_string(),
                members: vec![
                    "direct".to_string(),
                    "reject".to_string(),
                    "proxy-a".to_string(),
                    "child-group".to_string(),
                ],
            },
            OutboundConfig::Shadowsocks {
                name: "proxy-a".to_string(),
                server: "proxy.example".to_string(),
                port: 443,
                method: "chacha20-ietf-poly1305".to_string(),
                password: "password".to_string(),
                plugin: None,
                udp_over_tcp: false,
                udp_over_tcp_version: 1,
            },
            OutboundConfig::Group {
                name: "child-group".to_string(),
                kind: "url-test".to_string(),
                members: vec!["proxy-b".to_string(), "direct".to_string()],
            },
            OutboundConfig::Ssr {
                name: "proxy-b".to_string(),
                server: "proxy2.example".to_string(),
                port: 443,
                method: "aes-128-cfb".to_string(),
                password: "password".to_string(),
                protocol: "origin".to_string(),
                obfs: "plain".to_string(),
                protocol_param: None,
                obfs_param: None,
            },
        ];

        let members = collect_group_probe_members(&config, "node-group");
        assert_eq!(members, vec!["proxy-a".to_string(), "proxy-b".to_string()]);
    }

    #[test]
    fn test_collect_group_probe_members_skips_cycles_and_unknown_members() {
        let mut config = SuperConfig::default();
        config.outbounds = vec![
            OutboundConfig::Group {
                name: "cyclic-group-a".to_string(),
                kind: "url-test".to_string(),
                members: vec![
                    "cyclic-group-b".to_string(),
                    "missing".to_string(),
                    " ".to_string(),
                ],
            },
            OutboundConfig::Group {
                name: "cyclic-group-b".to_string(),
                kind: "url-test".to_string(),
                members: vec!["cyclic-group-a".to_string(), "direct".to_string()],
            },
        ];

        let members = collect_group_probe_members(&config, "cyclic-group-a");
        assert_eq!(members, vec!["missing".to_string()]);
    }

    #[test]
    fn test_collect_group_probe_members_handles_slash_in_group_name() {
        let mut config = SuperConfig::default();
        config.outbounds = vec![
            OutboundConfig::Group {
                name: "group/a".to_string(),
                kind: "select".to_string(),
                members: vec!["proxy-a".to_string(), "direct".to_string()],
            },
            OutboundConfig::Shadowsocks {
                name: "proxy-a".to_string(),
                server: "example.com".to_string(),
                port: 443,
                method: "chacha20-ietf-poly1305".to_string(),
                password: "password".to_string(),
                plugin: None,
                udp_over_tcp: false,
                udp_over_tcp_version: 1,
            },
        ];

        let members = collect_group_probe_members(&config, "group/a");
        assert_eq!(members, vec!["proxy-a".to_string()]);
    }

    #[test]
    fn test_collect_group_probe_members_handles_unicode_group_name() {
        let mut config = SuperConfig::default();
        config.outbounds = vec![
            OutboundConfig::Group {
                name: "香港节点".to_string(),
                kind: "select".to_string(),
                members: vec!["proxy-b".to_string(), "reject".to_string()],
            },
            OutboundConfig::Shadowsocks {
                name: "proxy-b".to_string(),
                server: "example.com".to_string(),
                port: 443,
                method: "chacha20-ietf-poly1305".to_string(),
                password: "password".to_string(),
                plugin: None,
                udp_over_tcp: false,
                udp_over_tcp_version: 1,
            },
        ];

        let members = collect_group_probe_members(&config, "香港节点");
        assert_eq!(members, vec!["proxy-b".to_string()]);
    }

    #[test]
    fn test_collect_group_probe_members_handles_emoji_group_name() {
        let mut config = SuperConfig::default();
        config.outbounds = vec![
            OutboundConfig::Group {
                name: "🚀-group".to_string(),
                kind: "select".to_string(),
                members: vec!["proxy-c".to_string()],
            },
            OutboundConfig::Shadowsocks {
                name: "proxy-c".to_string(),
                server: "example.com".to_string(),
                port: 443,
                method: "chacha20-ietf-poly1305".to_string(),
                password: "password".to_string(),
                plugin: None,
                udp_over_tcp: false,
                udp_over_tcp_version: 1,
            },
        ];

        let members = collect_group_probe_members(&config, "🚀-group");
        assert_eq!(members, vec!["proxy-c".to_string()]);
    }
}
