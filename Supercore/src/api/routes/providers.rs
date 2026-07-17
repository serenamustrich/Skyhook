use std::{collections::HashSet, sync::Arc};

use anyhow::anyhow;
use axum::{extract::State, response::Response, Json};
use tokio::{sync::Semaphore, task::JoinSet};

use crate::{
    core::Runtime,
    subscription_store::{SubscriptionMeta, SubscriptionStore},
};

use super::super::{
    classified_api_error, invalid_request, json_response, paginate_values,
    publish_subscription_event, task_accepted, task_failure, ApiState, ListQuery,
    ProviderUpdateRequest, SortOrder,
};

pub(super) async fn proxy_providers(
    State(runtime): State<Arc<Runtime>>,
    query: ListQuery,
) -> Response {
    let items = runtime
        .subscription_store()
        .index()
        .map(|index| index.subscriptions)
        .unwrap_or_default()
        .into_iter()
        .map(|item| serde_json::to_value(item).unwrap_or(serde_json::Value::Null))
        .collect();
    let page = match paginate_values(
        "proxy-providers",
        items,
        query,
        "name",
        SortOrder::Asc,
        &["id", "name", "node_count", "updated_at"],
        "id",
    ) {
        Ok(page) => page,
        Err(error) => return invalid_request("invalid_pagination", error.to_string()),
    };
    json_response(serde_json::json!({
        "providers": {
            "subscriptions": {
                "name": "subscriptions",
                "type": "Subscription",
                "subscriptions": page.items,
                "vehicleType": "HTTP",
            }
        },
        "pagination": page.pagination,
    }))
}

pub(super) async fn rule_providers(
    State(runtime): State<Arc<Runtime>>,
    query: ListQuery,
) -> Response {
    let items = runtime
        .config()
        .rule_sets
        .into_iter()
        .map(|provider| {
            serde_json::json!({
                "name": provider.name,
                "behavior": provider.behavior,
                "ruleCount": provider.rules.len(),
                "vehicleType": "Inline",
            })
        })
        .collect();
    let page = match paginate_values(
        "rule-providers",
        items,
        query,
        "name",
        SortOrder::Asc,
        &["name", "behavior", "ruleCount"],
        "name",
    ) {
        Ok(page) => page,
        Err(error) => return invalid_request("invalid_pagination", error.to_string()),
    };
    json_response(page.envelope("providers", serde_json::Map::new()))
}

pub(super) async fn update_providers(
    State(state): State<ApiState>,
    request: Option<Json<ProviderUpdateRequest>>,
) -> Response {
    let store = state.runtime().subscription_store();
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

pub(super) async fn update_all_providers(State(state): State<ApiState>) -> Response {
    let targets = match state.runtime().subscription_store().index() {
        Ok(index) => index.subscriptions,
        Err(error) => return classified_api_error("subscription_index_read_failed", error),
    };
    queue_provider_updates(state, targets).await
}

async fn queue_provider_updates(state: ApiState, targets: Vec<SubscriptionMeta>) -> Response {
    let total = targets.len() as u64;
    let (record, cancellation) = state.tasks().create("provider_update", Some(total)).await;
    let task_id = record.id.clone();
    let runtime = state.runtime_handle();
    let tasks = state.task_manager();
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
            match runtime.reload_active_subscription() {
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
