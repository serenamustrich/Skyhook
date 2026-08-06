use std::{path::PathBuf, sync::Arc};

use anyhow::anyhow;
use axum::{
    extract::{Request, State},
    http::{header::AUTHORIZATION, HeaderMap, Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};

use super::schema::ApiErrorResponse;

const CONTROL_TOKEN_ENV: &str = "SKYHOOK_CONTROL_TOKEN";
const CONTROL_TOKEN_FILE_ENV: &str = "SKYHOOK_CONTROL_TOKEN_FILE";
pub(super) const MIN_CONTROL_TOKEN_BYTES: usize = 32;

#[derive(Clone)]
pub(super) struct ControlAuthState {
    pub token: Option<Arc<str>>,
}

pub(super) fn validate_control_listen(control_listen: std::net::SocketAddr) -> anyhow::Result<()> {
    if control_listen.ip().is_loopback() {
        Ok(())
    } else {
        Err(anyhow!(
            "control API must listen on loopback; configured address is {control_listen}"
        ))
    }
}

pub(super) fn load_control_token() -> anyhow::Result<Option<Arc<str>>> {
    if let Some(token) = normalized_control_token(std::env::var(CONTROL_TOKEN_ENV).ok())? {
        return Ok(Some(token));
    }
    let Some(path) = std::env::var_os(CONTROL_TOKEN_FILE_ENV) else {
        return Ok(None);
    };
    let path = PathBuf::from(path);
    let token = std::fs::read_to_string(&path).map_err(|error| {
        anyhow!(
            "failed to read control token file '{}': {error}",
            path.display()
        )
    })?;
    normalized_control_token(Some(token))
}

pub(super) fn normalized_control_token(token: Option<String>) -> anyhow::Result<Option<Arc<str>>> {
    let Some(token) = token else {
        return Ok(None);
    };
    let token = token.trim();
    if token.is_empty() {
        return Ok(None);
    }
    if token.len() < MIN_CONTROL_TOKEN_BYTES {
        return Err(anyhow!(
            "control token must contain at least {MIN_CONTROL_TOKEN_BYTES} bytes"
        ));
    }
    Ok(Some(Arc::from(token)))
}

pub(super) async fn authorize_writes(
    State(auth): State<ControlAuthState>,
    request: Request,
    next: Next,
) -> Response {
    if !is_write_method(request.method()) {
        return next.run(request).await;
    }
    if request_has_valid_token(request.headers(), auth.token.as_deref()) {
        return next.run(request).await;
    }

    let trace_id = request
        .headers()
        .get("x-skyhook-trace-id")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.trim().is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let (code, message) = if auth.token.is_some() {
        (
            "control_auth_invalid",
            "a valid bearer token is required for this control operation",
        )
    } else {
        (
            "control_auth_unconfigured",
            "control API write operations are disabled until a control token is configured",
        )
    };
    let body = ApiErrorResponse {
        code,
        kind: "authentication",
        message: message.to_string(),
        retryable: false,
        trace_id,
        details: serde_json::json!({}),
    };
    (StatusCode::UNAUTHORIZED, Json(body)).into_response()
}

fn is_write_method(method: &Method) -> bool {
    method != Method::GET && method != Method::HEAD && method != Method::OPTIONS
}

pub(super) fn request_has_valid_token(headers: &HeaderMap, expected: Option<&str>) -> bool {
    let Some(expected) = expected else {
        return false;
    };
    let Some(provided) = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
    else {
        return false;
    };
    constant_time_eq(provided.as_bytes(), expected.as_bytes())
}

pub(super) fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right.iter())
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}
