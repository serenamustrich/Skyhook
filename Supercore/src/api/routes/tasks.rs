use axum::{
    extract::{Path as AxumPath, State},
    response::{IntoResponse, Response},
    Json,
};

use crate::outbound::error::OutboundErrorKind;

use super::super::{api_error_response, json_response, TaskManager};

pub(super) async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "ok": true }))
}

pub(super) async fn task_list(State(tasks): State<TaskManager>) -> Json<serde_json::Value> {
    Json(serde_json::json!({ "tasks": tasks.list().await }))
}

pub(super) async fn task_status(
    State(tasks): State<TaskManager>,
    AxumPath(id): AxumPath<String>,
) -> Response {
    match tasks.get(&id).await {
        Some(task) => Json(task).into_response(),
        None => api_error_response(
            axum::http::StatusCode::NOT_FOUND,
            "task_not_found",
            OutboundErrorKind::Internal,
            format!("task {id} does not exist"),
            serde_json::json!({ "task_id": id }),
        ),
    }
}

pub(super) async fn cancel_task(
    State(tasks): State<TaskManager>,
    AxumPath(id): AxumPath<String>,
) -> Response {
    match tasks.cancel(&id).await {
        Some(task) => json_response(serde_json::json!({
            "ok": true,
            "task": task,
        })),
        None => api_error_response(
            axum::http::StatusCode::NOT_FOUND,
            "task_not_found",
            OutboundErrorKind::Internal,
            format!("task {id} does not exist"),
            serde_json::json!({ "task_id": id }),
        ),
    }
}
