mod auth;
mod diagnostics;
mod error;
mod events;
mod routes;
mod schema;
mod tasks;

use std::{collections::HashSet, sync::Arc};

use anyhow::{anyhow, Context};
use axum::{
    extract::{FromRef, Path as AxumPath, State},
    http::StatusCode,
    middleware,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use tokio::{sync::Semaphore, task::JoinSet};
use tower_http::trace::TraceLayer;

use crate::{
    config::SuperConfig,
    core::Runtime,
    geo::{self, GeoUpdateProgress},
    outbound::error::{classify_message, OutboundErrorKind},
    routing::Destination,
    subscription_store::{SubscriptionMeta, SubscriptionStore, SubscriptionUpdateProgress},
};

use auth::*;
use diagnostics::{build_doctor_report, export_diagnostic_report};
use error::*;
use events::*;
use routes::build_router_with_tasks;
#[cfg(test)]
use routes::collect_group_probe_members;
use schema::*;
use tasks::TaskManager;

const MAX_SUBSCRIPTION_BODY_BYTES: usize = 32 * 1024 * 1024;

#[derive(Clone)]
struct ApiState {
    runtime: Arc<Runtime>,
    tasks: TaskManager,
}

impl FromRef<ApiState> for Arc<Runtime> {
    fn from_ref(state: &ApiState) -> Self {
        state.runtime.clone()
    }
}

impl FromRef<ApiState> for TaskManager {
    fn from_ref(state: &ApiState) -> Self {
        state.tasks.clone()
    }
}

pub async fn serve(runtime: Arc<Runtime>) -> anyhow::Result<()> {
    let control_listen = runtime.config().core.control_listen;
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
    let result = axum::serve(listener, app).await;
    tasks.cancel_all("control server stopped").await;
    result?;
    Ok(())
}

#[cfg(test)]
fn build_router(runtime: Arc<Runtime>, auth: ControlAuthState) -> Router {
    build_router_with_tasks(runtime, auth, TaskManager::default())
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "ok": true }))
}

async fn task_list(State(tasks): State<TaskManager>) -> Json<serde_json::Value> {
    Json(serde_json::json!({ "tasks": tasks.list().await }))
}

async fn task_status(State(tasks): State<TaskManager>, AxumPath(id): AxumPath<String>) -> Response {
    match tasks.get(&id).await {
        Some(task) => Json(task).into_response(),
        None => api_error_response(
            StatusCode::NOT_FOUND,
            "task_not_found",
            OutboundErrorKind::Internal,
            format!("task {id} does not exist"),
            serde_json::json!({ "task_id": id }),
        ),
    }
}

async fn cancel_task(State(tasks): State<TaskManager>, AxumPath(id): AxumPath<String>) -> Response {
    match tasks.cancel(&id).await {
        Some(task) => json_response(serde_json::json!({
            "ok": true,
            "task": task,
        })),
        None => api_error_response(
            StatusCode::NOT_FOUND,
            "task_not_found",
            OutboundErrorKind::Internal,
            format!("task {id} does not exist"),
            serde_json::json!({ "task_id": id }),
        ),
    }
}

async fn version() -> Json<VersionResponse> {
    Json(VersionResponse {
        name: "Supercore",
        version: env!("CARGO_PKG_VERSION"),
        engine: "rust-native",
    })
}

async fn status(State(runtime): State<Arc<Runtime>>) -> Json<StatusResponse> {
    Json(StatusResponse {
        mixed_listen: runtime.config().core.mixed_listen.to_string(),
        control_listen: runtime.config().core.control_listen.to_string(),
        outbounds: runtime.config().outbounds.len(),
        rules: runtime.config().rules.len(),
        smart_rules_enabled: runtime.config().smart_rules.enabled,
        traffic: runtime.telemetry().traffic(),
    })
}

async fn tun_status(State(runtime): State<Arc<Runtime>>) -> Json<serde_json::Value> {
    let config = runtime.config();
    Json(serde_json::json!({
        "tun": config.tun,
        "dns": config.dns,
    }))
}

async fn doctor(State(runtime): State<Arc<Runtime>>) -> Json<serde_json::Value> {
    let config = runtime.config();
    Json(serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "summary": config.summary(),
        "capabilities": runtime.outbound_capabilities(),
        "outbound_health": runtime.telemetry().outbound_health().await,
        "tun": config.tun,
        "dns": config.dns,
    }))
}

async fn run_doctor(State(state): State<ApiState>) -> Response {
    let (record, cancellation) = state.tasks.create("doctor_run", Some(3)).await;
    let task_id = record.id.clone();
    let runtime = state.runtime.clone();
    let tasks = state.tasks.clone();
    tokio::spawn(async move {
        tasks
            .mark_running(&task_id, "collecting runtime diagnostics")
            .await;
        tasks
            .progress(&task_id, 1, Some(3), "inspecting profiles and caches")
            .await;
        let operation = build_doctor_report(&runtime, false);
        tokio::select! {
            biased;
            _ = cancellation.cancelled() => {
                tasks.mark_cancelled(&task_id).await;
            }
            report = operation => {
                tasks
                    .progress(&task_id, 2, Some(3), "evaluating health checks")
                    .await;
                runtime.telemetry().publish_event(
                    "doctor_completed",
                    serde_json::json!({ "task_id": task_id }),
                );
                tasks
                    .progress(&task_id, 3, Some(3), "finalizing doctor report")
                    .await;
                tasks.succeed(
                    &task_id,
                    serde_json::json!({
                        "ok": true,
                        "report": report,
                    }),
                ).await;
            }
        }
    });
    task_accepted(&record)
}

async fn export_diagnostics(State(state): State<ApiState>) -> Response {
    let (record, cancellation) = state.tasks.create("diagnostic_export", Some(3)).await;
    let task_id = record.id.clone();
    let runtime = state.runtime.clone();
    let tasks = state.tasks.clone();
    tokio::spawn(async move {
        tasks
            .mark_running(&task_id, "building redacted diagnostic report")
            .await;
        tasks
            .progress(&task_id, 1, Some(3), "collecting redacted diagnostics")
            .await;
        let operation = export_diagnostic_report(&runtime, &task_id, &cancellation);
        tokio::select! {
            biased;
            _ = cancellation.cancelled() => {
                tasks.mark_cancelled(&task_id).await;
            }
            result = operation => {
                match result {
                    Ok(export) => {
                        tasks
                            .progress(&task_id, 2, Some(3), "securing diagnostic artifact")
                            .await;
                        runtime.telemetry().publish_event(
                            "diagnostic_exported",
                            serde_json::json!({
                                "task_id": task_id,
                                "bytes": export.bytes,
                                "redacted": export.redacted,
                            }),
                        );
                        tasks
                            .progress(&task_id, 3, Some(3), "diagnostic export ready")
                            .await;
                        tasks.succeed(
                            &task_id,
                            serde_json::json!({
                                "ok": true,
                                "export": export,
                            }),
                        ).await;
                    }
                    Err(_error) if cancellation.is_cancelled() => {
                        tasks.mark_cancelled(&task_id).await;
                    }
                    Err(error) => {
                        tasks.fail(
                            &task_id,
                            task_failure("diagnostic_export_failed", error),
                        ).await;
                    }
                }
            }
        }
    });
    task_accepted(&record)
}

async fn update_geo(State(state): State<ApiState>) -> Response {
    let geo_config = state.runtime.base_config().geo;
    let total = [
        geo_config.geoip_url.as_deref(),
        geo_config.geosite_url.as_deref(),
    ]
    .into_iter()
    .flatten()
    .filter(|url| !url.trim().is_empty())
    .count() as u64;
    let (record, cancellation) = state.tasks.create("geo_update", Some(total)).await;
    let task_id = record.id.clone();
    let runtime = state.runtime.clone();
    let tasks = state.tasks.clone();
    tokio::spawn(async move {
        tasks
            .mark_running(&task_id, format!("updating {total} geo assets"))
            .await;
        let (progress_tx, mut progress_rx) =
            tokio::sync::mpsc::unbounded_channel::<GeoUpdateProgress>();
        let progress_tasks = tasks.clone();
        let progress_runtime = runtime.clone();
        let progress_task_id = task_id.clone();
        let progress_handle = tokio::spawn(async move {
            while let Some(progress) = progress_rx.recv().await {
                progress_runtime.telemetry().publish_event(
                    "geo_update_progress",
                    serde_json::json!({
                        "task_id": progress_task_id,
                        "completed": progress.completed,
                        "total": progress.total,
                        "kind": progress.kind,
                    }),
                );
                progress_tasks
                    .progress(
                        &progress_task_id,
                        progress.completed,
                        Some(progress.total),
                        format!("updated {} geo asset", progress.kind),
                    )
                    .await;
            }
        });
        let operation = geo::update_geo_assets_with_progress(
            &geo_config,
            true,
            cancellation.clone(),
            Some(progress_tx),
        );
        tokio::select! {
            biased;
            _ = cancellation.cancelled() => {
                let _ = progress_handle.await;
                tasks.mark_cancelled(&task_id).await;
            }
            result = operation => {
                match result {
                    Ok(summaries) => {
                        let mut runtime_reloaded = false;
                        if summaries.iter().any(|summary| {
                            summary.kind == "geoip" && summary.error.is_none()
                        }) {
                            let mut base_config = runtime.base_config();
                            base_config.geoip_database =
                                Some(geo::geoip_cache_path(&base_config.geo));
                            match runtime.set_base_config(base_config) {
                                Ok(()) => match reload_active_subscription_config(&runtime) {
                                    Ok(_) => runtime_reloaded = true,
                                    Err(error) => {
                                        let _ = progress_handle.await;
                                        tasks.fail(
                                            &task_id,
                                            task_failure("geo_runtime_reload_failed", error),
                                        ).await;
                                        return;
                                    }
                                },
                                Err(error) => {
                                    let _ = progress_handle.await;
                                    tasks.fail(
                                        &task_id,
                                        task_failure("geo_base_config_update_failed", error),
                                    ).await;
                                    return;
                                }
                            }
                        }
                        let _ = progress_handle.await;
                        runtime.telemetry().publish_event(
                            "geo_updated",
                            serde_json::json!({
                                "task_id": task_id,
                                "count": summaries.len(),
                                "runtime_reloaded": runtime_reloaded,
                            }),
                        );
                        tasks.succeed(
                            &task_id,
                            serde_json::json!({
                                "ok": true,
                                "summaries": summaries,
                                "runtime": {
                                    "reloaded": runtime_reloaded,
                                },
                            }),
                        ).await;
                    }
                    Err(_error) if cancellation.is_cancelled() => {
                        let _ = progress_handle.await;
                        tasks.mark_cancelled(&task_id).await;
                    }
                    Err(error) => {
                        let _ = progress_handle.await;
                        tasks.fail(
                            &task_id,
                            task_failure("geo_update_failed", error),
                        ).await;
                    }
                }
            }
        }
    });
    task_accepted(&record)
}

async fn connections(State(runtime): State<Arc<Runtime>>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "traffic": runtime.telemetry().traffic(),
        "connections": runtime.telemetry().connections().await,
    }))
}

async fn traffic(State(runtime): State<Arc<Runtime>>) -> Json<crate::telemetry::TrafficSnapshot> {
    Json(runtime.telemetry().traffic())
}

async fn subscription_traffic(State(runtime): State<Arc<Runtime>>) -> Response {
    match subscription_store(&runtime).index() {
        Ok(index) => json_response(serde_json::json!({
            "ok": true,
            "active_id": index.active_id,
            "subscriptions": index.subscriptions.into_iter().map(|item| {
                serde_json::json!({
                    "id": item.id,
                    "name": item.name,
                    "upload_total": item.traffic_upload_total,
                    "download_total": item.traffic_download_total,
                    "total": item.traffic_upload_total.saturating_add(item.traffic_download_total),
                })
            }).collect::<Vec<_>>(),
        })),
        Err(error) => classified_api_error("subscription_traffic_read_failed", error),
    }
}

async fn outbounds(State(runtime): State<Arc<Runtime>>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "outbounds": runtime.telemetry().outbound_health().await,
        "groups": runtime.proxy_groups().await,
        "capabilities": runtime.outbound_capabilities(),
    }))
}

async fn rules_snapshot(State(runtime): State<Arc<Runtime>>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "rules": runtime.config().rules,
        "smart": runtime.smart_snapshot(),
    }))
}

async fn proxy_providers(State(runtime): State<Arc<Runtime>>) -> Json<serde_json::Value> {
    let subscriptions = subscription_store(&runtime)
        .index()
        .map(|index| index.subscriptions)
        .unwrap_or_default();
    Json(serde_json::json!({
        "providers": {
            "subscriptions": {
                "name": "subscriptions",
                "type": "Subscription",
                "subscriptions": subscriptions,
                "vehicleType": "HTTP",
            }
        }
    }))
}

async fn rule_providers(State(runtime): State<Arc<Runtime>>) -> Json<serde_json::Value> {
    let providers = runtime
        .config()
        .rule_sets
        .into_iter()
        .map(|provider| {
            (
                provider.name.clone(),
                serde_json::json!({
                    "name": provider.name,
                    "behavior": provider.behavior,
                    "ruleCount": provider.rules.len(),
                    "rules": provider.rules,
                    "vehicleType": "Inline",
                }),
            )
        })
        .collect::<serde_json::Map<_, _>>();
    Json(serde_json::json!({
        "providers": providers,
    }))
}

async fn update_providers(
    State(state): State<ApiState>,
    request: Option<Json<ProviderUpdateRequest>>,
) -> Response {
    let store = subscription_store(&state.runtime);
    let index = match store.index() {
        Ok(index) => index,
        Err(error) => return classified_api_error("subscription_index_read_failed", error),
    };
    let requested_id = request
        .and_then(|Json(request)| request.subscription_id)
        .filter(|id| !id.trim().is_empty());
    let target_id = requested_id.or(index.active_id.clone());
    let Some(target_id) = target_id else {
        return invalid_request(
            "provider_subscription_missing",
            "provide subscription_id or select an active subscription",
        );
    };
    let Some(target) = index
        .subscriptions
        .into_iter()
        .find(|item| item.id == target_id)
    else {
        return invalid_request(
            "provider_subscription_not_found",
            format!("subscription {target_id} does not exist"),
        );
    };
    queue_provider_updates(state, vec![target]).await
}

async fn update_all_providers(State(state): State<ApiState>) -> Response {
    let targets = match subscription_store(&state.runtime).index() {
        Ok(index) => index.subscriptions,
        Err(error) => return classified_api_error("subscription_index_read_failed", error),
    };
    queue_provider_updates(state, targets).await
}

async fn queue_provider_updates(state: ApiState, targets: Vec<SubscriptionMeta>) -> Response {
    let total = targets.len() as u64;
    let (record, cancellation) = state.tasks.create("provider_update", Some(total)).await;
    let task_id = record.id.clone();
    let runtime = state.runtime.clone();
    let tasks = state.tasks.clone();
    tokio::spawn(async move {
        tasks
            .mark_running(
                &task_id,
                format!("updating providers for {total} subscriptions"),
            )
            .await;
        let config = runtime.base_config();
        let timeout_secs = config.subscriptions.update_timeout_secs;
        let concurrency = config.subscriptions.update_concurrency.max(1);
        let store = SubscriptionStore::new(config.subscriptions.store_path);
        let active_id = store.index().ok().and_then(|index| index.active_id);
        let semaphore = Arc::new(Semaphore::new(concurrency));
        let mut jobs = JoinSet::new();

        for target in targets {
            let store = store.clone();
            let semaphore = semaphore.clone();
            let cancellation = cancellation.clone();
            jobs.spawn(async move {
                let permit = tokio::select! {
                    _ = cancellation.cancelled() => {
                        return (
                            target,
                            Err(anyhow!("provider refresh cancelled")),
                        );
                    }
                    permit = semaphore.acquire_owned() => permit,
                };
                let _permit = match permit {
                    Ok(permit) => permit,
                    Err(error) => {
                        return (
                            target,
                            Err(anyhow!("provider update scheduler closed: {error}")),
                        );
                    }
                };
                let result = store
                    .refresh_providers(&target.id, timeout_secs, &cancellation)
                    .await;
                (target, result)
            });
        }

        let mut completed = 0_u64;
        let mut summaries = Vec::new();
        let mut committed_ids = HashSet::new();
        loop {
            tokio::select! {
                biased;
                _ = cancellation.cancelled() => {
                    jobs.abort_all();
                    while jobs.join_next().await.is_some() {}
                    tasks.mark_cancelled(&task_id).await;
                    return;
                }
                joined = jobs.join_next() => {
                    let Some(joined) = joined else {
                        break;
                    };
                    completed = completed.saturating_add(1);
                    let (id, name, summary) = match joined {
                        Ok((_target, Ok(summary))) => {
                            if summary.committed {
                                committed_ids.insert(summary.id.clone());
                            }
                            (
                                summary.id.clone(),
                                summary.name.clone(),
                                serde_json::json!(summary),
                            )
                        }
                        Ok((target, Err(error))) => (
                            target.id,
                            target.name,
                            serde_json::json!({
                                "committed": false,
                                "updated": false,
                                "fatal_error": error.to_string(),
                            }),
                        ),
                        Err(error) => (
                            "unknown".to_string(),
                            "unknown".to_string(),
                            serde_json::json!({
                                "committed": false,
                                "updated": false,
                                "fatal_error": format!("provider update task failed: {error}"),
                            }),
                        ),
                    };
                    runtime.telemetry().publish_event(
                        "provider_update_progress",
                        serde_json::json!({
                            "task_id": task_id,
                            "completed": completed,
                            "total": total,
                            "subscription_id": id,
                            "subscription_name": name,
                            "result": summary,
                        }),
                    );
                    tasks
                        .progress(
                            &task_id,
                            completed,
                            Some(total),
                            format!("updated providers for {name}"),
                        )
                        .await;
                    summaries.push(serde_json::json!({
                        "id": id,
                        "name": name,
                        "result": summary,
                    }));
                }
            }
        }

        summaries.sort_by(|left, right| {
            left["name"]
                .as_str()
                .cmp(&right["name"].as_str())
                .then_with(|| left["id"].as_str().cmp(&right["id"].as_str()))
        });
        let reload = if active_id
            .as_ref()
            .is_some_and(|active_id| committed_ids.contains(active_id))
        {
            match reload_active_subscription_config(&runtime) {
                Ok(config) => serde_json::json!({
                    "reloaded": true,
                    "summary": config.summary(),
                }),
                Err(error) => {
                    tasks
                        .fail(
                            &task_id,
                            task_failure("provider_runtime_reload_failed", error),
                        )
                        .await;
                    return;
                }
            }
        } else {
            serde_json::json!({ "reloaded": false })
        };
        let failed = summaries
            .iter()
            .filter(|summary| summary["result"]["fatal_error"].is_string())
            .count();
        publish_subscription_event(
            &runtime,
            "provider_update",
            serde_json::json!({
                "count": total,
                "failed": failed,
                "reloaded": reload["reloaded"],
            }),
        );
        tasks
            .succeed(
                &task_id,
                serde_json::json!({
                    "ok": true,
                    "partial_failure": failed > 0,
                    "results": summaries,
                    "runtime": reload,
                }),
            )
            .await;
    });
    task_accepted(&record)
}

async fn groups(State(runtime): State<Arc<Runtime>>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "groups": runtime.proxy_groups().await,
    }))
}

async fn countries(State(runtime): State<Arc<Runtime>>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "countries": runtime.country_groups().await,
    }))
}

async fn use_country(
    State(runtime): State<Arc<Runtime>>,
    Json(request): Json<CountryUseRequest>,
) -> Response {
    match runtime.use_country_group(&request.code).await {
        Ok(config) => json_response(serde_json::json!({
            "ok": true,
            "runtime": {
                "reloaded": true,
                "summary": config.summary(),
                "default_outbound": config.core.default_outbound,
            },
        })),
        Err(error) => classified_api_error("country_selection_failed", error),
    }
}

async fn route_decision(
    State(runtime): State<Arc<Runtime>>,
    Json(destination): Json<Destination>,
) -> Response {
    json_response(serde_json::json!({
        "destination": destination,
        "decision": runtime.decide(&destination),
    }))
}

async fn smart_rules(State(runtime): State<Arc<Runtime>>) -> Json<serde_json::Value> {
    Json(serde_json::json!(runtime.smart_snapshot()))
}

async fn subscriptions(State(runtime): State<Arc<Runtime>>) -> Response {
    match subscription_store(&runtime).index() {
        Ok(index) => json_response(serde_json::json!({
            "ok": true,
            "index": index,
        })),
        Err(error) => classified_api_error("subscription_index_read_failed", error),
    }
}

async fn import_subscription(
    State(state): State<ApiState>,
    Json(request): Json<SubscriptionImportRequest>,
) -> Response {
    let (record, cancellation) = state.tasks.create("subscription_import", Some(1)).await;
    let task_id = record.id.clone();
    let runtime = state.runtime.clone();
    let tasks = state.tasks.clone();
    tokio::spawn(async move {
        tasks
            .mark_running(&task_id, "downloading subscription")
            .await;
        let operation_cancellation = cancellation.clone();
        let operation = async {
            let url = request.url.clone();
            let update_timeout_secs = runtime.config().subscriptions.update_timeout_secs;
            let text = subscription_source_text(
                request.text,
                request.url,
                update_timeout_secs,
                &operation_cancellation,
            )
            .await?;
            let result = subscription_store(&runtime)
                .import_text_with_id_async(
                    request.id,
                    request.name,
                    url,
                    &text,
                    request.switch,
                    update_timeout_secs,
                    &operation_cancellation,
                )
                .await?;
            let reload = if result.active_changed {
                let config = reload_active_subscription_config(&runtime)?;
                serde_json::json!({ "reloaded": true, "summary": config.summary() })
            } else {
                serde_json::json!({ "reloaded": false })
            };
            Ok::<serde_json::Value, anyhow::Error>(serde_json::json!({
                "ok": true,
                "result": result,
                "runtime": reload,
            }))
        };
        tokio::select! {
            _ = cancellation.cancelled() => {
                tasks.mark_cancelled(&task_id).await;
            }
            result = operation => {
                match result {
                    Ok(result) => {
                        publish_subscription_event(
                            &runtime,
                            "import",
                            serde_json::json!({
                                "active_changed": result["result"]["active_changed"],
                            }),
                        );
                        tasks.progress(&task_id, 1, Some(1), "saving subscription").await;
                        tasks.succeed(&task_id, result).await;
                    }
                    Err(_error) if cancellation.is_cancelled() => {
                        tasks.mark_cancelled(&task_id).await;
                    }
                    Err(error) => tasks.fail(
                        &task_id,
                        task_failure("subscription_import_failed", error),
                    ).await,
                }
            }
        }
    });
    task_accepted(&record)
}

async fn use_outbound(
    State(runtime): State<Arc<Runtime>>,
    Json(request): Json<OutboundUseRequest>,
) -> Response {
    match runtime.use_outbound(&request.name) {
        Ok(config) => json_response(serde_json::json!({
            "ok": true,
            "runtime": {
                "reloaded": true,
                "summary": config.summary(),
                "default_outbound": config.core.default_outbound,
            },
        })),
        Err(error) => classified_api_error("outbound_selection_failed", error),
    }
}

async fn use_subscription(
    State(runtime): State<Arc<Runtime>>,
    Json(request): Json<SubscriptionUseRequest>,
) -> Response {
    match subscription_store(&runtime).set_active(&request.id) {
        Ok(meta) => match reload_active_subscription_config(&runtime) {
            Ok(config) => json_response(serde_json::json!({
                "ok": true,
                "subscription": meta,
                "runtime": {
                    "reloaded": true,
                    "summary": config.summary(),
                },
            })),
            Err(error) => api_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "subscription_reload_failed",
                classify_message(&error.to_string()),
                error.to_string(),
                serde_json::json!({ "subscription": meta }),
            ),
        },
        Err(error) => classified_api_error("subscription_selection_failed", error),
    }
}

async fn update_subscription(
    State(state): State<ApiState>,
    Json(request): Json<SubscriptionUpdateRequest>,
) -> Response {
    if request.id.trim().is_empty() {
        return invalid_request("subscription_id_missing", "subscription id cannot be empty");
    }
    let store = subscription_store(&state.runtime);
    let active_id = match store.index() {
        Ok(index) => index.active_id,
        Err(error) => return classified_api_error("subscription_index_read_failed", error),
    };
    let options = (&state.runtime.config().subscriptions).into();
    let (record, cancellation) = state.tasks.create("subscription_update", Some(1)).await;
    let task_id = record.id.clone();
    let runtime = state.runtime.clone();
    let tasks = state.tasks.clone();
    tokio::spawn(async move {
        tasks.mark_running(&task_id, "updating subscription").await;
        let operation = store.update_from_url_with(&request.id, options, &cancellation);
        tokio::select! {
            biased;
            _ = cancellation.cancelled() => {
                tasks.mark_cancelled(&task_id).await;
            }
            result = operation => {
                match result {
                    Ok(summary) => {
                        let reload = if summary.updated
                            && active_id.as_deref() == Some(summary.id.as_str())
                        {
                            match reload_active_subscription_config(&runtime) {
                                Ok(config) => serde_json::json!({
                                    "reloaded": true,
                                    "summary": config.summary(),
                                }),
                                Err(error) => {
                                    tasks.fail(
                                        &task_id,
                                        task_failure("subscription_runtime_reload_failed", error),
                                    ).await;
                                    return;
                                }
                            }
                        } else {
                            serde_json::json!({ "reloaded": false })
                        };
                        publish_subscription_event(
                            &runtime,
                            "update",
                            serde_json::json!({
                                "subscription_id": summary.id,
                                "updated": summary.updated,
                                "reloaded": reload["reloaded"],
                            }),
                        );
                        tasks.progress(
                            &task_id,
                            1,
                            Some(1),
                            format!("updated subscription {}", summary.name),
                        ).await;
                        tasks.succeed(
                            &task_id,
                            serde_json::json!({
                                "ok": true,
                                "result": summary,
                                "runtime": reload,
                            }),
                        ).await;
                    }
                    Err(_error) if cancellation.is_cancelled() => {
                        tasks.mark_cancelled(&task_id).await;
                    }
                    Err(error) => {
                        tasks.fail(
                            &task_id,
                            task_failure("subscription_update_failed", error),
                        ).await;
                    }
                }
            }
        }
    });
    task_accepted(&record)
}

async fn update_all_subscriptions(State(state): State<ApiState>) -> Response {
    let store = subscription_store(&state.runtime);
    let total = match store.index() {
        Ok(index) => index.subscriptions.len() as u64,
        Err(error) => return classified_api_error("subscription_index_read_failed", error),
    };
    let options = (&state.runtime.config().subscriptions).into();
    let (record, cancellation) = state
        .tasks
        .create("subscription_update_all", Some(total))
        .await;
    let task_id = record.id.clone();
    let runtime = state.runtime.clone();
    let tasks = state.tasks.clone();
    tokio::spawn(async move {
        tasks
            .mark_running(&task_id, format!("updating {total} subscriptions"))
            .await;
        let (progress_tx, mut progress_rx) =
            tokio::sync::mpsc::unbounded_channel::<SubscriptionUpdateProgress>();
        let progress_tasks = tasks.clone();
        let progress_runtime = runtime.clone();
        let progress_task_id = task_id.clone();
        let progress_handle = tokio::spawn(async move {
            while let Some(progress) = progress_rx.recv().await {
                progress_runtime.telemetry().publish_event(
                    "subscription_update_progress",
                    serde_json::json!({
                        "task_id": progress_task_id,
                        "completed": progress.completed,
                        "total": progress.total,
                        "subscription_id": progress.id,
                        "subscription_name": progress.name,
                        "updated": progress.updated,
                    }),
                );
                progress_tasks
                    .progress(
                        &progress_task_id,
                        progress.completed,
                        Some(progress.total),
                        format!("updated subscription {}", progress.name),
                    )
                    .await;
            }
        });
        let operation = async {
            let active_id = store.index()?.active_id;
            let results = store
                .update_all_from_urls_with_progress(
                    options,
                    cancellation.clone(),
                    Some(progress_tx),
                )
                .await?;
            let active_updated = active_id.as_ref().is_some_and(|active_id| {
                results
                    .iter()
                    .any(|item| item.updated && item.id == *active_id)
            });
            let reload = if active_updated {
                let config = reload_active_subscription_config(&runtime)?;
                serde_json::json!({ "reloaded": true, "summary": config.summary() })
            } else {
                serde_json::json!({ "reloaded": false })
            };
            Ok::<serde_json::Value, anyhow::Error>(serde_json::json!({
                "ok": true,
                "results": results,
                "runtime": reload,
            }))
        };
        tokio::select! {
            biased;
            _ = cancellation.cancelled() => {
                let _ = progress_handle.await;
                tasks.mark_cancelled(&task_id).await;
            }
            result = operation => {
                match result {
                    Ok(result) => {
                        let _ = progress_handle.await;
                        publish_subscription_event(
                            &runtime,
                            "update_all",
                            serde_json::json!({
                                "count": total,
                                "reloaded": result["runtime"]["reloaded"],
                            }),
                        );
                        tasks.progress(
                            &task_id,
                            total,
                            Some(total),
                            "finalizing subscription updates",
                        ).await;
                        tasks.succeed(&task_id, result).await;
                    }
                    Err(_error) if cancellation.is_cancelled() => {
                        let _ = progress_handle.await;
                        tasks.mark_cancelled(&task_id).await;
                    }
                    Err(error) => {
                        let _ = progress_handle.await;
                        tasks.fail(
                            &task_id,
                            task_failure("subscription_update_failed", error),
                        ).await;
                    }
                }
            }
        }
    });
    task_accepted(&record)
}

async fn reload_active_subscription(State(runtime): State<Arc<Runtime>>) -> Response {
    match reload_active_subscription_config(&runtime) {
        Ok(config) => json_response(serde_json::json!({
            "ok": true,
            "runtime": {
                "reloaded": true,
                "summary": config.summary(),
            },
        })),
        Err(error) => classified_api_error("subscription_reload_failed", error),
    }
}

async fn active_subscription_config(
    State(runtime): State<Arc<Runtime>>,
    request: Option<Json<ActiveSubscriptionConfigRequest>>,
) -> Response {
    let base_config = runtime.base_config();
    let use_first_node = request
        .and_then(|Json(request)| request.use_first_node)
        .unwrap_or(base_config.subscriptions.use_first_node_as_default);
    match SubscriptionStore::new(base_config.subscriptions.store_path.clone())
        .active_runtime_config(base_config, use_first_node)
    {
        Ok(config) => json_response(serde_json::json!({
            "ok": true,
            "config": config,
        })),
        Err(error) => classified_api_error("subscription_config_failed", error),
    }
}

async fn upsert_smart_rule(
    State(runtime): State<Arc<Runtime>>,
    Json(request): Json<SmartRuleRequest>,
) -> Response {
    let result = runtime.upsert_smart_rule(smart_route_rule(request));
    match result {
        Ok(rules) => json_response(serde_json::json!({
            "ok": true,
            "rules": rules,
        })),
        Err(error) => classified_api_error("smart_rule_upsert_failed", error),
    }
}

async fn set_smart_rule_enabled(
    State(runtime): State<Arc<Runtime>>,
    Json(request): Json<SmartRuleEnabledRequest>,
) -> Response {
    match runtime.set_smart_rule_enabled(request.target, &request.value, request.enabled) {
        Ok(rules) => json_response(serde_json::json!({
            "ok": true,
            "rules": rules,
        })),
        Err(error) => classified_api_error("smart_rule_update_failed", error),
    }
}

async fn delete_smart_rule(
    State(runtime): State<Arc<Runtime>>,
    Json(request): Json<SmartRuleDeleteRequest>,
) -> Response {
    match runtime.delete_smart_rule(request.target, &request.value) {
        Ok(rules) => json_response(serde_json::json!({
            "ok": true,
            "rules": rules,
        })),
        Err(error) => classified_api_error("smart_rule_delete_failed", error),
    }
}

async fn apply_smart_recommendations(
    State(runtime): State<Arc<Runtime>>,
    request: Option<Json<ApplySmartRecommendationsRequest>>,
) -> Response {
    let action = request.and_then(|Json(request)| request.action);
    let rules = runtime.apply_smart_recommendations(action);
    json_response(serde_json::json!({
        "ok": true,
        "rules": rules,
    }))
}

async fn apply_smart_recommendation(
    State(runtime): State<Arc<Runtime>>,
    Json(request): Json<ApplySmartRecommendationRequest>,
) -> Response {
    match runtime.apply_smart_recommendation(request.target, &request.value) {
        Ok(rules) => json_response(serde_json::json!({
            "ok": true,
            "rules": rules,
        })),
        Err(error) => classified_api_error("smart_recommendation_apply_failed", error),
    }
}

async fn logs(State(runtime): State<Arc<Runtime>>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "logs": runtime.telemetry().logs().await,
    }))
}

async fn config(State(runtime): State<Arc<Runtime>>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "core": runtime.config().core,
        "tun": runtime.config().tun,
        "dns": runtime.config().dns,
        "smart_rules": runtime.config().smart_rules,
        "subscriptions": runtime.config().subscriptions,
        "outbounds": runtime.config().outbounds.iter().map(|item| item.name().to_string()).collect::<Vec<_>>(),
        "rule_sets": runtime.config().rule_sets,
        "rules": runtime.config().rules,
    }))
}

async fn reload_config(
    State(runtime): State<Arc<Runtime>>,
    Json(request): Json<ConfigReloadRequest>,
) -> Response {
    let base_config = match (request.path, request.yaml) {
        (Some(path), None) => SuperConfig::load(&path),
        (None, Some(yaml)) => serde_yaml::from_str(&yaml).map_err(Into::into),
        (Some(_), Some(_)) => Err(anyhow::anyhow!("provide path or yaml, not both")),
        (None, None) => Err(anyhow::anyhow!("provide path or yaml")),
    };
    let base_config = match base_config {
        Ok(config) => config,
        Err(error) => {
            return invalid_request("config_load_failed", error.to_string());
        }
    };
    if let Err(error) = runtime.set_base_config(base_config) {
        return invalid_request("config_validation_failed", error.to_string());
    }
    match reload_active_subscription_config(&runtime) {
        Ok(config) => json_response(serde_json::json!({
            "ok": true,
            "runtime": {
                "reloaded": true,
                "summary": config.summary(),
                "default_outbound": config.core.default_outbound,
            },
        })),
        Err(error) => classified_api_error("config_reload_failed", error),
    }
}

fn subscription_store(runtime: &Runtime) -> SubscriptionStore {
    SubscriptionStore::new(runtime.config().subscriptions.store_path.clone())
}

fn reload_active_subscription_config(
    runtime: &Runtime,
) -> anyhow::Result<crate::config::SuperConfig> {
    let base_config = runtime.base_config();
    let store = SubscriptionStore::new(base_config.subscriptions.store_path.clone());
    let config = store.active_runtime_config(
        base_config,
        runtime.config().subscriptions.use_first_node_as_default,
    )?;
    runtime.reload_config(config)
}

async fn subscription_source_text(
    text: Option<String>,
    url: Option<String>,
    timeout_secs: u64,
    cancellation: &tokio_util::sync::CancellationToken,
) -> anyhow::Result<String> {
    if let Some(text) = text.filter(|item| !item.trim().is_empty()) {
        return Ok(text);
    }
    let Some(url) = url else {
        return Err(anyhow::anyhow!("provide text or url"));
    };
    fetch_subscription_url(url, timeout_secs, cancellation).await
}

async fn fetch_subscription_url(
    url: String,
    timeout_secs: u64,
    cancellation: &tokio_util::sync::CancellationToken,
) -> anyhow::Result<String> {
    let parsed = url::Url::parse(&url).context("subscription url is invalid")?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(anyhow!("subscription url must use http or https"));
    }
    let source = parsed
        .host_str()
        .map(|host| format!("{}://{host}", parsed.scheme()))
        .unwrap_or_else(|| "<redacted-subscription-source>".to_string());
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(timeout_secs.max(1)))
        .no_proxy()
        .build()?;
    let response = tokio::select! {
        _ = cancellation.cancelled() => return Err(anyhow!("subscription import cancelled")),
        response = client
            .get(url)
            .header(
                "User-Agent",
                concat!("Supercore/", env!("CARGO_PKG_VERSION")),
            )
            .send() => {
                response.with_context(|| {
                    format!("failed to download subscription from {source}")
                })?
            }
    };
    let mut response = response
        .error_for_status()
        .with_context(|| format!("subscription endpoint returned an error from {source}"))?;
    if response
        .content_length()
        .is_some_and(|size| size > MAX_SUBSCRIPTION_BODY_BYTES as u64)
    {
        return Err(anyhow!(
            "subscription body exceeds {} bytes",
            MAX_SUBSCRIPTION_BODY_BYTES
        ));
    }
    let mut body = Vec::new();
    loop {
        let chunk = tokio::select! {
            _ = cancellation.cancelled() => {
                return Err(anyhow!("subscription import cancelled"));
            }
            chunk = response.chunk() => {
                chunk.with_context(|| {
                    format!("failed to read subscription body from {source}")
                })?
            }
        };
        let Some(chunk) = chunk else {
            break;
        };
        if body.len().saturating_add(chunk.len()) > MAX_SUBSCRIPTION_BODY_BYTES {
            return Err(anyhow!(
                "subscription body exceeds {} bytes",
                MAX_SUBSCRIPTION_BODY_BYTES
            ));
        }
        body.extend_from_slice(&chunk);
    }
    String::from_utf8(body).with_context(|| format!("subscription body from {source} is not UTF-8"))
}

#[cfg(test)]
mod tests {
    use std::{path::PathBuf, time::Duration};

    use super::*;
    use axum::{
        body::{to_bytes, Body},
        http::{header::AUTHORIZATION, HeaderMap, HeaderValue, Method, Request},
    };
    use tokio_stream::StreamExt;
    use tower::ServiceExt;

    use crate::config::OutboundConfig;

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
            },
        ];

        let members = collect_group_probe_members(&config, "🚀-group");
        assert_eq!(members, vec!["proxy-c".to_string()]);
    }
}
