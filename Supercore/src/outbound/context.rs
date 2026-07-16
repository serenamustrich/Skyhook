use std::{
    net::SocketAddr,
    time::{Duration, Instant},
};

use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::routing::{AppIdentity, Destination};

#[derive(Debug, Clone)]
pub struct DialContext {
    pub destination: Destination,
    pub timeout: Duration,
    pub deadline: Instant,
    pub source: Option<SocketAddr>,
    pub inbound_name: Option<String>,
    pub inbound_type: Option<String>,
    pub app_identity: Option<AppIdentity>,
    pub app_id: Option<String>,
    pub matched_rule: Option<String>,
    pub subscription_id: Option<String>,
    pub selected_group: Option<String>,
    pub selected_node: Option<String>,
    pub network_preference: Option<String>,
    pub interface_name: Option<String>,
    pub dns_policy: Option<String>,
    pub trace_id: String,
    pub cancellation: CancellationToken,
}

impl DialContext {
    pub fn new(destination: Destination, timeout_ms: u64) -> Self {
        let timeout = Duration::from_millis(timeout_ms);
        let app_identity = destination.app.clone();
        let app_id = app_identity.as_ref().and_then(|app| {
            app.bundle_id
                .clone()
                .or_else(|| app.name.clone())
                .or_else(|| app.path.clone())
        });
        Self {
            destination,
            timeout,
            deadline: Instant::now() + timeout,
            source: None,
            inbound_name: None,
            inbound_type: None,
            app_identity,
            app_id,
            matched_rule: None,
            subscription_id: None,
            selected_group: None,
            selected_node: None,
            network_preference: None,
            interface_name: None,
            dns_policy: None,
            trace_id: Uuid::new_v4().to_string(),
            cancellation: CancellationToken::new(),
        }
    }

    pub fn timeout_ms(&self) -> u64 {
        self.timeout.as_millis().min(u128::from(u64::MAX)) as u64
    }

    pub fn remaining_timeout(&self) -> Duration {
        self.deadline.saturating_duration_since(Instant::now())
    }

    pub fn cancel(&self) {
        self.cancellation.cancel();
    }
}

#[cfg(test)]
mod tests {
    use crate::routing::{AppIdentity, Destination};

    use super::DialContext;

    #[test]
    fn creates_traceable_dial_context() {
        let context = DialContext::new(Destination::new("example.com", 443), 500);
        assert_eq!(context.destination.authority(), "example.com:443");
        assert_eq!(context.timeout_ms(), 500);
        assert!(context.remaining_timeout() <= context.timeout);
        assert!(!context.trace_id.is_empty());
        assert!(!context.cancellation.is_cancelled());
        context.cancel();
        assert!(context.cancellation.is_cancelled());
    }

    #[test]
    fn carries_inbound_app_network_and_dns_metadata() {
        let destination = Destination::new("example.com", 443).with_app(AppIdentity {
            name: Some("Browser".to_string()),
            path: Some("/Applications/Browser.app".to_string()),
            bundle_id: Some("example.browser".to_string()),
        });
        let mut context = DialContext::new(destination, 500);
        context.inbound_name = Some("mixed".to_string());
        context.inbound_type = Some("http-connect".to_string());
        context.network_preference = Some("prefer-ipv6".to_string());
        context.interface_name = Some("en0".to_string());
        context.dns_policy = Some("proxy-server".to_string());

        assert_eq!(context.app_id.as_deref(), Some("example.browser"));
        assert_eq!(context.inbound_name.as_deref(), Some("mixed"));
        assert_eq!(context.inbound_type.as_deref(), Some("http-connect"));
        assert_eq!(context.network_preference.as_deref(), Some("prefer-ipv6"));
        assert_eq!(context.interface_name.as_deref(), Some("en0"));
        assert_eq!(context.dns_policy.as_deref(), Some("proxy-server"));
    }
}
