use std::{net::SocketAddr, time::Duration};

use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::routing::Destination;

#[derive(Debug, Clone)]
pub struct DialContext {
    pub destination: Destination,
    pub timeout: Duration,
    pub source: Option<SocketAddr>,
    pub app_id: Option<String>,
    pub matched_rule: Option<String>,
    pub subscription_id: Option<String>,
    pub selected_group: Option<String>,
    pub selected_node: Option<String>,
    pub trace_id: String,
    pub cancellation: CancellationToken,
}

impl DialContext {
    pub fn new(destination: Destination, timeout_ms: u64) -> Self {
        Self {
            destination,
            timeout: Duration::from_millis(timeout_ms),
            source: None,
            app_id: None,
            matched_rule: None,
            subscription_id: None,
            selected_group: None,
            selected_node: None,
            trace_id: Uuid::new_v4().to_string(),
            cancellation: CancellationToken::new(),
        }
    }

    pub fn timeout_ms(&self) -> u64 {
        self.timeout.as_millis().min(u128::from(u64::MAX)) as u64
    }

    pub fn cancel(&self) {
        self.cancellation.cancel();
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
        assert!(!context.cancellation.is_cancelled());
        context.cancel();
        assert!(context.cancellation.is_cancelled());
    }
}
