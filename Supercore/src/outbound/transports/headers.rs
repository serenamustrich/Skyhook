use std::collections::BTreeMap;

use anyhow::anyhow;

pub(crate) fn render_transport_headers(
    headers: &BTreeMap<String, String>,
    reserved: &[&str],
) -> anyhow::Result<String> {
    let mut rendered = String::new();
    for (name, value) in headers {
        if reserved
            .iter()
            .any(|reserved_name| name.eq_ignore_ascii_case(reserved_name))
        {
            continue;
        }
        let header_name = http::header::HeaderName::from_bytes(name.as_bytes())
            .map_err(|error| anyhow!("invalid transport header name {name:?}: {error}"))?;
        let header_value = http::header::HeaderValue::from_str(value)
            .map_err(|error| anyhow!("invalid transport header value for {name:?}: {error}"))?;
        let header_value = header_value
            .to_str()
            .map_err(|error| anyhow!("transport header {name:?} is not visible ASCII: {error}"))?;
        rendered.push_str(header_name.as_str());
        rendered.push_str(": ");
        rendered.push_str(header_value);
        rendered.push_str("\r\n");
    }
    Ok(rendered)
}

pub(crate) fn normalize_http_path(path: &str) -> String {
    let path = path.trim();
    if path.is_empty() {
        "/".to_string()
    } else if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    }
}
