use std::{net::SocketAddr, time::Duration};

use uuid::Uuid;

use crate::routing::Destination;

#[derive(Debug, Clone)]
pub struct DialContext {
    pub destination: Destination,
    pub timeout: Duration,
    pub source: Option<SocketAddr>,
    pub app_id: Option<String>,
    pub matched_rule: Option<String>,
    pub trace_id: String,
}

impl DialContext {
    pub fn new(destination: Destination, timeout_ms: u64) -> Self {
        Self {
            destination,
            timeout: Duration::from_millis(timeout_ms),
            source: None,
            app_id: None,
            matched_rule: None,
            trace_id: Uuid::new_v4().to_string(),
        }
    }

    pub fn timeout_ms(&self) -> u64 {
        self.timeout.as_millis().min(u128::from(u64::MAX)) as u64
    }
}

#[cfg(test)]
mod tests {
    use crate::routing::Destination;

    use super::DialContext;

    #[test]
    fn creates_traceable_dial_context() {
        let context = DialContext::new(Destination::new("example.com", 443), 500);
        assert_eq!(context.destination.authority(), "example.com:443");
        assert_eq!(context.timeout_ms(), 500);
        assert!(!context.trace_id.is_empty());
    }
}
