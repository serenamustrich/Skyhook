use std::{convert::Infallible, time::Duration};

use axum::{
    extract::State,
    response::{
        sse::{Event, KeepAlive},
        Sse,
    },
};
use tokio_stream::{wrappers::BroadcastStream, StreamExt};

use crate::core::{ProbeProgress, Runtime};

use super::ApiState;

pub(super) async fn task_events(
    State(state): State<ApiState>,
) -> Sse<impl tokio_stream::Stream<Item = Result<Event, Infallible>>> {
    let task_stream = BroadcastStream::new(state.tasks().subscribe()).map(|item| match item {
        Ok(event) => {
            let id = event.id.clone();
            let name = event.event;
            serde_json::to_string(&event)
                .ok()
                .map(|data| Event::default().id(id).event(name).data(data))
                .map(Ok)
                .unwrap_or_else(|| serialization_error_event("task_updated"))
        }
        Err(error) => lagged_event("tasks", error),
    });
    let telemetry_stream = BroadcastStream::new(state.runtime().telemetry().subscribe_events())
        .map(|item| match item {
            Ok(event) => {
                let id = event.id.clone();
                let name = event.event.clone();
                serde_json::to_string(&event)
                    .ok()
                    .map(|data| Event::default().id(id).event(name).data(data))
                    .map(Ok)
                    .unwrap_or_else(|| serialization_error_event("telemetry"))
            }
            Err(error) => lagged_event("telemetry", error),
        });
    let stream = task_stream.merge(telemetry_stream);
    Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keepalive"),
    )
}

fn lagged_event(source: &str, error: impl std::fmt::Display) -> Result<Event, Infallible> {
    let id = uuid::Uuid::new_v4().to_string();
    Ok(Event::default().id(id).event("lagged").data(
        serde_json::json!({
            "schema_version": 1,
            "timestamp": chrono::Utc::now(),
            "source": source,
            "message": error.to_string(),
        })
        .to_string(),
    ))
}

fn serialization_error_event(source: &str) -> Result<Event, Infallible> {
    let id = uuid::Uuid::new_v4().to_string();
    Ok(Event::default().id(id).event("serialization_error").data(
        serde_json::json!({
            "schema_version": 1,
            "timestamp": chrono::Utc::now(),
            "source": source,
        })
        .to_string(),
    ))
}

pub(super) fn publish_probe_progress_event(
    runtime: &Runtime,
    task_id: &str,
    progress: &ProbeProgress,
) {
    runtime.telemetry().publish_event(
        "probe_progress",
        serde_json::json!({
            "task_id": task_id,
            "completed": progress.completed,
            "total": progress.total,
            "node": progress.name,
        }),
    );
}

pub(super) fn publish_subscription_event(runtime: &Runtime, kind: &str, data: serde_json::Value) {
    runtime.telemetry().publish_event(
        "subscription_updated",
        serde_json::json!({
            "kind": kind,
            "data": data,
        }),
    );
}
