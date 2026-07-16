use std::sync::Arc;

use axum::{extract::State, response::Response, Json};

use crate::{
    config::SuperConfig,
    core::Runtime,
    geo::{self, GeoUpdateProgress},
};

use super::super::{
    build_doctor_report, classified_api_error, export_diagnostic_report, invalid_request,
    openapi_document, task_accepted, task_failure, ApiState, ConfigReloadRequest, StatusResponse,
    VersionResponse,
};

pub(super) async fn api_schema() -> Json<serde_json::Value> {
    Json(openapi_document())
}

pub(super) async fn version() -> Json<VersionResponse> {
    Json(VersionResponse {
        name: "Supercore",
        version: env!("CARGO_PKG_VERSION"),
        engine: "rust-native",
    })
}

pub(super) async fn status(State(runtime): State<Arc<Runtime>>) -> Json<StatusResponse> {
    Json(StatusResponse {
        mixed_listen: runtime.config().core.mixed_listen.to_string(),
        control_listen: runtime.config().core.control_listen.to_string(),
        outbounds: runtime.config().outbounds.len(),
        rules: runtime.config().rules.len(),
        smart_rules_enabled: runtime.config().smart_rules.enabled,
        traffic: runtime.telemetry().traffic(),
    })
}

pub(super) async fn tun_status(State(runtime): State<Arc<Runtime>>) -> Json<serde_json::Value> {
    let config = runtime.config();
    Json(serde_json::json!({
        "tun": config.tun,
        "dns": config.dns,
    }))
}

pub(super) async fn doctor(State(runtime): State<Arc<Runtime>>) -> Json<serde_json::Value> {
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

pub(super) async fn run_doctor(State(state): State<ApiState>) -> Response {
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

pub(super) async fn export_diagnostics(State(state): State<ApiState>) -> Response {
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

pub(super) async fn update_geo(State(state): State<ApiState>) -> Response {
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
                                Ok(()) => match runtime.reload_active_subscription() {
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

pub(super) async fn connections(State(runtime): State<Arc<Runtime>>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "traffic": runtime.telemetry().traffic(),
        "connections": runtime.telemetry().connections().await,
    }))
}

pub(super) async fn traffic(
    State(runtime): State<Arc<Runtime>>,
) -> Json<crate::telemetry::TrafficSnapshot> {
    Json(runtime.telemetry().traffic())
}

pub(super) async fn logs(State(runtime): State<Arc<Runtime>>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "logs": runtime.telemetry().logs().await,
    }))
}

pub(super) async fn config(State(runtime): State<Arc<Runtime>>) -> Json<serde_json::Value> {
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

pub(super) async fn reload_config(
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
    match runtime.reload_active_subscription() {
        Ok(config) => super::super::json_response(serde_json::json!({
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
