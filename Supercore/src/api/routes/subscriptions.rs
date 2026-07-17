use std::{sync::Arc, time::Duration};

use anyhow::{anyhow, Context};
use axum::{extract::State, http::StatusCode, response::Response, Json};
use tokio_util::sync::CancellationToken;

use crate::{
    core::Runtime, outbound::error::classify_message,
    subscription_store::SubscriptionUpdateProgress,
};

use super::super::{
    api_error_response, classified_api_error, invalid_request, json_response, paginate_values,
    publish_subscription_event, task_accepted, task_failure, ActiveSubscriptionConfigRequest,
    ApiState, ListQuery, SortOrder, SubscriptionImportRequest, SubscriptionUpdateRequest,
    SubscriptionUseRequest,
};

const MAX_SUBSCRIPTION_BODY_BYTES: usize = 32 * 1024 * 1024;

pub(super) async fn subscriptions(
    State(runtime): State<Arc<Runtime>>,
    query: ListQuery,
) -> Response {
    match runtime.subscription_store().index() {
        Ok(index) => {
            let items = index
                .subscriptions
                .into_iter()
                .map(|item| serde_json::to_value(item).unwrap_or(serde_json::Value::Null))
                .collect();
            let page = match paginate_values(
                "subscriptions",
                items,
                query,
                "name",
                SortOrder::Asc,
                &[
                    "id",
                    "name",
                    "source_format",
                    "node_count",
                    "supported_outbound_count",
                    "unsupported_count",
                    "created_at",
                    "updated_at",
                ],
                "id",
            ) {
                Ok(page) => page,
                Err(error) => return invalid_request("invalid_pagination", error.to_string()),
            };
            json_response(serde_json::json!({
                "ok": true,
                "index": {
                    "version": index.version,
                    "active_id": index.active_id,
                    "subscriptions": page.items,
                },
                "pagination": page.pagination,
            }))
        }
        Err(error) => classified_api_error("subscription_index_read_failed", error),
    }
}

pub(super) async fn subscription_traffic(
    State(runtime): State<Arc<Runtime>>,
    query: ListQuery,
) -> Response {
    match runtime.subscription_store().index() {
        Ok(index) => {
            let items = index.subscriptions.into_iter().map(|item| {
                serde_json::json!({
                    "id": item.id,
                    "name": item.name,
                    "upload_total": item.traffic_upload_total,
                    "download_total": item.traffic_download_total,
                    "total": item.traffic_upload_total.saturating_add(item.traffic_download_total),
                })
            }).collect::<Vec<_>>();
            let page = match paginate_values(
                "subscription-traffic",
                items,
                query,
                "name",
                SortOrder::Asc,
                &["id", "name", "upload_total", "download_total", "total"],
                "id",
            ) {
                Ok(page) => page,
                Err(error) => return invalid_request("invalid_pagination", error.to_string()),
            };
            let mut extras = serde_json::Map::new();
            extras.insert("ok".to_string(), serde_json::Value::Bool(true));
            extras.insert(
                "active_id".to_string(),
                index
                    .active_id
                    .map_or(serde_json::Value::Null, serde_json::Value::String),
            );
            json_response(page.envelope("subscriptions", extras))
        }
        Err(error) => classified_api_error("subscription_traffic_read_failed", error),
    }
}

pub(super) async fn import_subscription(
    State(state): State<ApiState>,
    Json(request): Json<SubscriptionImportRequest>,
) -> Response {
    let (record, cancellation) = state.tasks().create("subscription_import", Some(1)).await;
    let task_id = record.id.clone();
    let runtime = state.runtime_handle();
    let tasks = state.task_manager();
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
            let result = runtime
                .subscription_store()
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
                let config = runtime.reload_active_subscription()?;
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

pub(super) async fn use_subscription(
    State(runtime): State<Arc<Runtime>>,
    Json(request): Json<SubscriptionUseRequest>,
) -> Response {
    match runtime.subscription_store().set_active(&request.id) {
        Ok(meta) => match runtime.reload_active_subscription() {
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

pub(super) async fn update_subscription(
    State(state): State<ApiState>,
    Json(request): Json<SubscriptionUpdateRequest>,
) -> Response {
    if request.id.trim().is_empty() {
        return invalid_request("subscription_id_missing", "subscription id cannot be empty");
    }
    let store = state.runtime().subscription_store();
    let active_id = match store.index() {
        Ok(index) => index.active_id,
        Err(error) => return classified_api_error("subscription_index_read_failed", error),
    };
    let options = (&state.runtime().config().subscriptions).into();
    let (record, cancellation) = state.tasks().create("subscription_update", Some(1)).await;
    let task_id = record.id.clone();
    let runtime = state.runtime_handle();
    let tasks = state.task_manager();
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
                            match runtime.reload_active_subscription() {
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

pub(super) async fn update_all_subscriptions(State(state): State<ApiState>) -> Response {
    let store = state.runtime().subscription_store();
    let total = match store.index() {
        Ok(index) => index.subscriptions.len() as u64,
        Err(error) => return classified_api_error("subscription_index_read_failed", error),
    };
    let options = (&state.runtime().config().subscriptions).into();
    let (record, cancellation) = state
        .tasks
        .create("subscription_update_all", Some(total))
        .await;
    let task_id = record.id.clone();
    let runtime = state.runtime_handle();
    let tasks = state.task_manager();
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
                let config = runtime.reload_active_subscription()?;
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

pub(super) async fn reload_active_subscription(State(runtime): State<Arc<Runtime>>) -> Response {
    match runtime.reload_active_subscription() {
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

pub(super) async fn active_subscription_config(
    State(runtime): State<Arc<Runtime>>,
    request: Option<Json<ActiveSubscriptionConfigRequest>>,
) -> Response {
    let use_first_node = request.and_then(|Json(request)| request.use_first_node);
    match runtime.active_subscription_config(use_first_node) {
        Ok(config) => json_response(serde_json::json!({
            "ok": true,
            "config": config,
        })),
        Err(error) => classified_api_error("subscription_config_failed", error),
    }
}

async fn subscription_source_text(
    text: Option<String>,
    url: Option<String>,
    timeout_secs: u64,
    cancellation: &CancellationToken,
) -> anyhow::Result<String> {
    if let Some(text) = text.filter(|item| !item.trim().is_empty()) {
        return Ok(text);
    }
    let Some(url) = url else {
        return Err(anyhow!("provide text or url"));
    };
    fetch_subscription_url(url, timeout_secs, cancellation).await
}

async fn fetch_subscription_url(
    url: String,
    timeout_secs: u64,
    cancellation: &CancellationToken,
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
        .timeout(Duration::from_secs(timeout_secs.max(1)))
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
