use axum::{
    extract::{Path as AxumPath, State},
    response::{IntoResponse, Response},
    Json,
};

use crate::outbound::error::OutboundErrorKind;

use super::super::{
    api_error_response, invalid_request, json_response, paginate_values, ListQuery, SortOrder,
    TaskManager,
};

pub(super) async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "ok": true }))
}

pub(super) async fn task_list(State(tasks): State<TaskManager>, query: ListQuery) -> Response {
    let items = tasks
        .list()
        .await
        .into_iter()
        .map(|task| serde_json::to_value(task).unwrap_or(serde_json::Value::Null))
        .collect();
    let page = match paginate_values(
        "tasks",
        items,
        query,
        "created_at",
        SortOrder::Desc,
        &["id", "kind", "status", "created_at", "finished_at"],
        "id",
    ) {
        Ok(page) => page,
        Err(error) => return invalid_request("invalid_pagination", error.to_string()),
    };
    json_response(page.envelope("tasks", serde_json::Map::new()))
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
