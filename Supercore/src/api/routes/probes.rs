use std::collections::{HashMap, HashSet};

use axum::{extract::State, response::Response, Json};

use crate::{
    config::{OutboundConfig, SuperConfig},
    core::{ProbeOptions, ProbeProgress},
};

use super::super::{
    invalid_request, publish_probe_progress_event, task_accepted, ApiState, ProbeGroupRequest,
    ProbeRequest,
};

pub(super) async fn probe_outbounds(
    State(state): State<ApiState>,
    request: Option<Json<ProbeRequest>>,
) -> Response {
    let options = request
        .map(|Json(request)| ProbeOptions {
            url: request.url,
            timeout_ms: request.timeout_ms,
            concurrency: request.concurrency,
            names: request.names,
        })
        .unwrap_or_default();
    let total = state.runtime.probe_target_count(&options);
    let (record, cancellation) = state.tasks.create("probe_outbounds", Some(total)).await;
    let task_id = record.id.clone();
    let runtime = state.runtime.clone();
    let tasks = state.tasks.clone();
    tokio::spawn(async move {
        tasks
            .mark_running(&task_id, format!("probing {total} outbounds"))
            .await;
        let (progress_tx, mut progress_rx) =
            tokio::sync::mpsc::unbounded_channel::<ProbeProgress>();
        let progress_tasks = tasks.clone();
        let progress_task_id = task_id.clone();
        let progress_runtime = runtime.clone();
        let progress_handle = tokio::spawn(async move {
            while let Some(progress) = progress_rx.recv().await {
                publish_probe_progress_event(&progress_runtime, &progress_task_id, &progress);
                progress_tasks
                    .progress(
                        &progress_task_id,
                        progress.completed,
                        Some(progress.total),
                        format!("tested {}", progress.name),
                    )
                    .await;
            }
        });
        tokio::select! {
            _ = cancellation.cancelled() => {
                tasks.mark_cancelled(&task_id).await;
            }
            results = runtime.probe_all_outbounds_with_progress(options, Some(progress_tx)) => {
                let failure_summary = build_probe_failure_summary(&results);
                tasks.progress(
                    &task_id,
                    results.len() as u64,
                    Some(total),
                    "finalizing probe results",
                ).await;
                tasks.succeed(&task_id, serde_json::json!({
                    "results": results,
                    "failure_summary": failure_summary,
                })).await;
            }
        }
        let _ = progress_handle.await;
    });
    task_accepted(&record)
}

pub(super) async fn probe_group_body(
    State(state): State<ApiState>,
    Json(request): Json<ProbeGroupRequest>,
) -> Response {
    let config = state.runtime.config();
    let member_names = collect_group_probe_members(&config, &request.group);
    if member_names.is_empty() {
        return invalid_request(
            "probe_group_empty",
            format!("group '{}' has no probeable members", request.group),
        );
    }
    let total = member_names.len() as u64;
    let group = request.group;
    let options = ProbeOptions {
        url: request.url,
        timeout_ms: request.timeout_ms,
        concurrency: request.concurrency,
        names: Some(member_names),
    };
    let (record, cancellation) = state.tasks.create("probe_group", Some(total)).await;
    let task_id = record.id.clone();
    let runtime = state.runtime.clone();
    let tasks = state.tasks.clone();
    tokio::spawn(async move {
        tasks
            .mark_running(&task_id, format!("probing group {group}"))
            .await;
        let (progress_tx, mut progress_rx) =
            tokio::sync::mpsc::unbounded_channel::<ProbeProgress>();
        let progress_tasks = tasks.clone();
        let progress_task_id = task_id.clone();
        let progress_runtime = runtime.clone();
        let progress_handle = tokio::spawn(async move {
            while let Some(progress) = progress_rx.recv().await {
                publish_probe_progress_event(&progress_runtime, &progress_task_id, &progress);
                progress_tasks
                    .progress(
                        &progress_task_id,
                        progress.completed,
                        Some(progress.total),
                        format!("tested {}", progress.name),
                    )
                    .await;
            }
        });
        tokio::select! {
            _ = cancellation.cancelled() => {
                tasks.mark_cancelled(&task_id).await;
            }
            results = runtime.probe_all_outbounds_with_progress(options, Some(progress_tx)) => {
                let failure_summary = build_probe_failure_summary(&results);
                tasks.progress(
                    &task_id,
                    results.len() as u64,
                    Some(total),
                    "finalizing group probe results",
                ).await;
                tasks.succeed(&task_id, serde_json::json!({
                    "ok": true,
                    "group": group,
                    "results": results,
                    "failure_summary": failure_summary,
                })).await;
            }
        }
        let _ = progress_handle.await;
    });
    task_accepted(&record)
}

fn build_probe_failure_summary(results: &[crate::core::ProbeResult]) -> HashMap<String, usize> {
    let mut summary = HashMap::new();
    for result in results.iter().filter(|result| !result.success) {
        let kind = result
            .failure_kind
            .clone()
            .unwrap_or_else(|| "unknown".to_string());
        *summary.entry(kind).or_insert(0) += 1;
    }
    summary
}

pub(in crate::api) fn collect_group_probe_members(
    config: &SuperConfig,
    group_name: &str,
) -> Vec<String> {
    let outbound_map: HashMap<&str, &OutboundConfig> = config
        .outbounds
        .iter()
        .map(|outbound| (outbound.name(), outbound))
        .collect();
    let Some(OutboundConfig::Group {
        members: root_members,
        ..
    }) = outbound_map.get(group_name)
    else {
        return Vec::new();
    };

    let mut visited = HashSet::new();
    let mut members = Vec::new();
    collect_group_members(
        root_members.as_slice(),
        &outbound_map,
        &mut visited,
        &mut members,
    );
    members
}

fn collect_group_members(
    members: &[String],
    outbound_map: &HashMap<&str, &OutboundConfig>,
    visited: &mut HashSet<String>,
    output: &mut Vec<String>,
) {
    for name in members {
        let trimmed = name.trim();
        if trimmed.is_empty() || !visited.insert(trimmed.to_string()) {
            continue;
        }
        if trimmed.eq_ignore_ascii_case("direct") || trimmed.eq_ignore_ascii_case("reject") {
            continue;
        }

        let Some(outbound) = outbound_map.get(trimmed) else {
            output.push(trimmed.to_string());
            continue;
        };
        if let OutboundConfig::Group { members, .. } = outbound {
            collect_group_members(members, outbound_map, visited, output);
        } else {
            output.push(trimmed.to_string());
        }
    }
}
