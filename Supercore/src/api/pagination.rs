use std::cmp::Ordering;

use anyhow::anyhow;
use axum::{
    extract::{FromRequestParts, Query},
    http::request::Parts,
    response::Response,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::invalid_request;

const DEFAULT_PAGE_LIMIT: usize = 200;
const MAX_PAGE_LIMIT: usize = 500;
const CURSOR_VERSION: u8 = 1;

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(super) enum SortOrder {
    #[default]
    Asc,
    Desc,
}

impl SortOrder {
    fn as_str(self) -> &'static str {
        match self {
            Self::Asc => "asc",
            Self::Desc => "desc",
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
pub(super) struct ListQuery {
    #[serde(default)]
    pub cursor: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub filter: Option<String>,
    #[serde(default)]
    pub sort: Option<String>,
    #[serde(default)]
    pub order: Option<SortOrder>,
}

#[async_trait::async_trait]
impl<S> FromRequestParts<S> for ListQuery
where
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        Query::<ListQuery>::from_request_parts(parts, state)
            .await
            .map(|Query(query)| query)
            .map_err(|error| invalid_request("invalid_pagination", error.to_string()))
    }
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct PaginationMeta {
    pub limit: usize,
    pub returned: usize,
    pub total: usize,
    pub next_cursor: Option<String>,
    pub sort: String,
    pub order: SortOrder,
    pub filter: Option<String>,
}

#[derive(Debug)]
pub(super) struct ValuePage {
    pub items: Vec<Value>,
    pub pagination: PaginationMeta,
}

impl ValuePage {
    pub(super) fn envelope(self, key: &str, extras: Map<String, Value>) -> Value {
        let mut body = extras;
        body.insert(key.to_string(), Value::Array(self.items));
        body.insert(
            "pagination".to_string(),
            serde_json::to_value(self.pagination).unwrap_or(Value::Null),
        );
        Value::Object(body)
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct CursorPayload {
    version: u8,
    fingerprint: String,
    sort_value: Value,
    identity_value: Value,
}

pub(super) fn paginate_values(
    scope: &str,
    mut items: Vec<Value>,
    query: ListQuery,
    default_sort: &str,
    default_order: SortOrder,
    allowed_sorts: &[&str],
    identity_path: &str,
) -> anyhow::Result<ValuePage> {
    let limit = query.limit.unwrap_or(DEFAULT_PAGE_LIMIT);
    if limit == 0 || limit > MAX_PAGE_LIMIT {
        return Err(anyhow!(
            "limit must be between 1 and {MAX_PAGE_LIMIT}, got {limit}"
        ));
    }

    let sort = query
        .sort
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(default_sort)
        .to_string();
    if !allowed_sorts.iter().any(|allowed| *allowed == sort) {
        return Err(anyhow!(
            "unsupported sort field '{sort}'; allowed fields: {}",
            allowed_sorts.join(", ")
        ));
    }

    let filter = query
        .filter
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_lowercase);
    if let Some(filter) = filter.as_deref() {
        items.retain(|item| value_matches_filter(item, filter));
    }

    let order = query.order.unwrap_or(default_order);
    items.sort_by(|left, right| {
        let primary = compare_values(value_at_path(left, &sort), value_at_path(right, &sort));
        let stable = primary.then_with(|| {
            compare_values(
                value_at_path(left, identity_path),
                value_at_path(right, identity_path),
            )
        });
        match order {
            SortOrder::Asc => stable,
            SortOrder::Desc => stable.reverse(),
        }
    });

    let fingerprint = query_fingerprint(scope, &sort, order, filter.as_deref());
    let offset = match query.cursor.as_deref() {
        Some(cursor) => {
            let cursor = decode_cursor(cursor)?;
            if cursor.version != CURSOR_VERSION {
                return Err(anyhow!("unsupported pagination cursor version"));
            }
            if cursor.fingerprint != fingerprint {
                return Err(anyhow!(
                    "pagination cursor is stale or belongs to another query"
                ));
            }
            items
                .iter()
                .position(|item| {
                    value_at_path(item, &sort).unwrap_or(&Value::Null) == &cursor.sort_value
                        && value_at_path(item, identity_path).unwrap_or(&Value::Null)
                            == &cursor.identity_value
                })
                .map(|index| index + 1)
                .ok_or_else(|| anyhow!("pagination cursor anchor is stale"))?
        }
        None => 0,
    };

    let end = offset.saturating_add(limit).min(items.len());
    let page_items = items[offset..end].to_vec();
    let next_cursor = if end < items.len() {
        let last = page_items
            .last()
            .ok_or_else(|| anyhow!("pagination page ended without a cursor anchor"))?;
        Some(encode_cursor(
            fingerprint,
            value_at_path(last, &sort).cloned().unwrap_or(Value::Null),
            value_at_path(last, identity_path)
                .cloned()
                .unwrap_or(Value::Null),
        )?)
    } else {
        None
    };

    Ok(ValuePage {
        items: page_items,
        pagination: PaginationMeta {
            limit,
            returned: end.saturating_sub(offset),
            total: items.len(),
            next_cursor,
            sort,
            order,
            filter,
        },
    })
}

pub(super) fn stable_value_id(scope: &str, value: &Value) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(scope.as_bytes());
    hasher.update(&[0]);
    hasher.update(&serde_json::to_vec(value).unwrap_or_default());
    hasher.finalize().to_hex().to_string()
}

fn query_fingerprint(scope: &str, sort: &str, order: SortOrder, filter: Option<&str>) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(scope.as_bytes());
    hasher.update(&[0]);
    hasher.update(sort.as_bytes());
    hasher.update(&[0]);
    hasher.update(order.as_str().as_bytes());
    hasher.update(&[0]);
    hasher.update(filter.unwrap_or_default().as_bytes());
    hasher.finalize().to_hex().to_string()
}

fn encode_cursor(
    fingerprint: String,
    sort_value: Value,
    identity_value: Value,
) -> anyhow::Result<String> {
    let payload = CursorPayload {
        version: CURSOR_VERSION,
        fingerprint,
        sort_value,
        identity_value,
    };
    Ok(URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload)?))
}

fn decode_cursor(cursor: &str) -> anyhow::Result<CursorPayload> {
    let bytes = URL_SAFE_NO_PAD
        .decode(cursor)
        .map_err(|_| anyhow!("pagination cursor is not valid base64url"))?;
    serde_json::from_slice(&bytes).map_err(|_| anyhow!("pagination cursor payload is invalid"))
}

fn value_at_path<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    path.split('.').try_fold(value, |current, segment| {
        current.as_object().and_then(|object| object.get(segment))
    })
}

fn compare_values(left: Option<&Value>, right: Option<&Value>) -> Ordering {
    match (left, right) {
        (None | Some(Value::Null), None | Some(Value::Null)) => Ordering::Equal,
        (None | Some(Value::Null), _) => Ordering::Greater,
        (_, None | Some(Value::Null)) => Ordering::Less,
        (Some(Value::Number(left)), Some(Value::Number(right))) => left
            .as_f64()
            .partial_cmp(&right.as_f64())
            .unwrap_or(Ordering::Equal),
        (Some(Value::Bool(left)), Some(Value::Bool(right))) => left.cmp(right),
        (Some(Value::String(left)), Some(Value::String(right))) => {
            left.to_lowercase().cmp(&right.to_lowercase())
        }
        (Some(left), Some(right)) => type_rank(left)
            .cmp(&type_rank(right))
            .then_with(|| left.to_string().cmp(&right.to_string())),
    }
}

fn type_rank(value: &Value) -> u8 {
    match value {
        Value::Null => 0,
        Value::Bool(_) => 1,
        Value::Number(_) => 2,
        Value::String(_) => 3,
        Value::Array(_) => 4,
        Value::Object(_) => 5,
    }
}

fn value_matches_filter(value: &Value, needle: &str) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => value.to_string().contains(needle),
        Value::Number(value) => value.to_string().contains(needle),
        Value::String(value) => value.to_lowercase().contains(needle),
        Value::Array(values) => values
            .iter()
            .any(|value| value_matches_filter(value, needle)),
        Value::Object(values) => values
            .values()
            .any(|value| value_matches_filter(value, needle)),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{paginate_values, ListQuery, SortOrder};

    #[test]
    fn paginates_with_stable_sort_filter_and_cursor() {
        let items = vec![
            json!({"id":"b","name":"Tokyo","latency":30}),
            json!({"id":"a","name":"Tokyo","latency":20}),
            json!({"id":"c","name":"Singapore","latency":40}),
        ];
        let first = paginate_values(
            "nodes",
            items.clone(),
            ListQuery {
                limit: Some(1),
                filter: Some("tokyo".into()),
                sort: Some("name".into()),
                ..ListQuery::default()
            },
            "name",
            SortOrder::Asc,
            &["name", "latency"],
            "id",
        )
        .unwrap();
        assert_eq!(first.items[0]["id"], "a");
        assert_eq!(first.pagination.total, 2);
        let cursor = first.pagination.next_cursor.unwrap();

        let mut items = items;
        items.push(json!({"id":"0","name":"Tokyo","latency":10}));
        let second = paginate_values(
            "nodes",
            items,
            ListQuery {
                cursor: Some(cursor),
                limit: Some(1),
                filter: Some("tokyo".into()),
                sort: Some("name".into()),
                ..ListQuery::default()
            },
            "name",
            SortOrder::Asc,
            &["name", "latency"],
            "id",
        )
        .unwrap();
        assert_eq!(second.items[0]["id"], "b");
        assert!(second.pagination.next_cursor.is_none());
    }

    #[test]
    fn rejects_stale_cursor_and_invalid_limits_or_sort_fields() {
        let items = vec![json!({"id":"a","name":"A"}), json!({"id":"b","name":"B"})];
        let first = paginate_values(
            "nodes",
            items.clone(),
            ListQuery {
                limit: Some(1),
                ..ListQuery::default()
            },
            "name",
            SortOrder::Asc,
            &["name"],
            "id",
        )
        .unwrap();
        let changed = vec![items[1].clone()];
        let error = paginate_values(
            "nodes",
            changed,
            ListQuery {
                cursor: first.pagination.next_cursor,
                limit: Some(1),
                ..ListQuery::default()
            },
            "name",
            SortOrder::Asc,
            &["name"],
            "id",
        )
        .unwrap_err();
        assert!(error.to_string().contains("stale"));

        assert!(paginate_values(
            "nodes",
            Vec::new(),
            ListQuery {
                limit: Some(0),
                ..ListQuery::default()
            },
            "name",
            SortOrder::Asc,
            &["name"],
            "id",
        )
        .is_err());
        assert!(paginate_values(
            "nodes",
            Vec::new(),
            ListQuery {
                sort: Some("unknown".into()),
                order: Some(SortOrder::Desc),
                ..ListQuery::default()
            },
            "name",
            SortOrder::Asc,
            &["name"],
            "id",
        )
        .is_err());
    }
}
