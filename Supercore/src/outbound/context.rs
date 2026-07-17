use std::{
    future::Future,
    net::SocketAddr,
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::routing::{AppIdentity, Destination};

tokio::task_local! {
    static ACTIVE_DIAL_CONTEXT: DialContext;
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IpVersionStrategy {
    #[default]
    Dual,
    Ipv4,
    Ipv6,
    PreferIpv4,
    PreferIpv6,
}

#[derive(Debug, Clone)]
pub struct DialContext {
    pub destination: Destination,
    pub timeout: Duration,
    pub deadline: Instant,
    pub source: Option<SocketAddr>,
    pub bind_address: Option<SocketAddr>,
    pub inbound_name: Option<String>,
    pub inbound_type: Option<String>,
    pub app_identity: Option<AppIdentity>,
    pub app_id: Option<String>,
    pub matched_rule: Option<String>,
    pub subscription_id: Option<String>,
    pub selected_group: Option<String>,
    pub selected_node: Option<String>,
    pub ip_version: IpVersionStrategy,
    pub interface_name: Option<String>,
    pub tcp_fast_open: bool,
    pub multipath_tcp: bool,
    pub keepalive: Option<Duration>,
    pub quic_mtu: Option<u16>,
    pub quic_zero_rtt: bool,
    pub certificate_fingerprint: Option<String>,
    pub websocket_early_data_header: Option<String>,
    pub websocket_max_early_data: usize,
    pub dialer_chain: Vec<String>,
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
            bind_address: None,
            inbound_name: None,
            inbound_type: None,
            app_identity,
            app_id,
            matched_rule: None,
            subscription_id: None,
            selected_group: None,
            selected_node: None,
            ip_version: IpVersionStrategy::Dual,
            interface_name: None,
            tcp_fast_open: false,
            multipath_tcp: false,
            keepalive: Some(Duration::from_secs(30)),
            quic_mtu: None,
            quic_zero_rtt: false,
            certificate_fingerprint: None,
            websocket_early_data_header: None,
            websocket_max_early_data: 0,
            dialer_chain: Vec::new(),
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

pub(crate) async fn scope_dial_context<F>(context: &DialContext, future: F) -> F::Output
where
    F: Future,
{
    ACTIVE_DIAL_CONTEXT.scope(context.clone(), future).await
}

pub(crate) fn active_dial_context() -> Option<DialContext> {
    ACTIVE_DIAL_CONTEXT.try_with(Clone::clone).ok()
}

#[cfg(test)]
mod tests {
    use crate::routing::{AppIdentity, Destination};

    use super::{DialContext, IpVersionStrategy};

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
        context.ip_version = IpVersionStrategy::PreferIpv6;
        context.interface_name = Some("en0".to_string());
        context.dns_policy = Some("proxy-server".to_string());

        assert_eq!(context.app_id.as_deref(), Some("example.browser"));
        assert_eq!(context.inbound_name.as_deref(), Some("mixed"));
        assert_eq!(context.inbound_type.as_deref(), Some("http-connect"));
        assert_eq!(context.ip_version, IpVersionStrategy::PreferIpv6);
        assert_eq!(context.interface_name.as_deref(), Some("en0"));
        assert_eq!(context.dns_policy.as_deref(), Some("proxy-server"));
    }
}
