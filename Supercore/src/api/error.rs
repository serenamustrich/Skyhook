use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};

use crate::outbound::error::{classify_message, OutboundErrorKind};

use super::{
    schema::ApiErrorResponse,
    tasks::{TaskFailure, TaskRecord},
};

pub(super) fn json_response(value: serde_json::Value) -> Response {
    Json(value).into_response()
}

pub(super) fn api_error_response(
    status: StatusCode,
    code: &'static str,
    kind: OutboundErrorKind,
    message: impl Into<String>,
    details: serde_json::Value,
) -> Response {
    let body = ApiErrorResponse {
        code,
        kind: kind.as_str(),
        message: message.into(),
        retryable: kind.retryable(),
        trace_id: uuid::Uuid::new_v4().to_string(),
        details,
    };
    (status, Json(body)).into_response()
}

pub(super) fn classified_api_error(code: &'static str, error: impl std::fmt::Display) -> Response {
    let message = error.to_string();
    let kind = classify_message(&message);
    let status = match kind {
        OutboundErrorKind::Authentication => StatusCode::UNAUTHORIZED,
        OutboundErrorKind::Timeout => StatusCode::GATEWAY_TIMEOUT,
        OutboundErrorKind::Dns
        | OutboundErrorKind::Tcp
        | OutboundErrorKind::Tls
        | OutboundErrorKind::HttpStatus
        | OutboundErrorKind::EmptyResponse => StatusCode::BAD_GATEWAY,
        OutboundErrorKind::Cancelled => StatusCode::CONFLICT,
        OutboundErrorKind::Protocol | OutboundErrorKind::Unsupported => {
            StatusCode::UNPROCESSABLE_ENTITY
        }
        OutboundErrorKind::Internal => StatusCode::INTERNAL_SERVER_ERROR,
    };
    api_error_response(status, code, kind, message, serde_json::json!({}))
}

pub(super) fn invalid_request(code: &'static str, message: impl Into<String>) -> Response {
    api_error_response(
        StatusCode::BAD_REQUEST,
        code,
        OutboundErrorKind::Protocol,
        message,
        serde_json::json!({}),
    )
}

pub(super) fn task_accepted(record: &TaskRecord) -> Response {
    (
        StatusCode::ACCEPTED,
        Json(serde_json::json!({
            "task_id": record.id,
            "trace_id": record.trace_id,
            "kind": record.kind,
            "status": record.status,
        })),
    )
        .into_response()
}

pub(super) fn task_failure(code: &'static str, error: impl std::fmt::Display) -> TaskFailure {
    let message = error.to_string();
    let kind = classify_message(&message);
    TaskFailure {
        code: code.to_string(),
        kind: kind.as_str().to_string(),
        message,
        retryable: kind.retryable(),
        trace_id: uuid::Uuid::new_v4().to_string(),
    }
}
