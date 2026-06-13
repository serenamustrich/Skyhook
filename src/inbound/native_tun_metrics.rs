use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use serde::Serialize;

#[derive(Debug)]
pub struct NativeTunMetricsInner {
    pub enabled: bool,
    pub running: AtomicBool,
    pub backend: String,
    pub interface_name: RwLock<Option<String>>,
    pub l3_profile: RwLock<Option<String>>,
    pub mtu: AtomicU16,
    pub setup_enabled: bool,
    pub auto_route: bool,
    pub routes_installed: RwLock<Vec<String>>,
    pub bypass_routes_installed: RwLock<Vec<String>>,
    pub skipped_bypass_routes: RwLock<Vec<String>>,
    pub setup_warnings: RwLock<Vec<String>>,
    pub endpoint_bypass_installed: RwLock<Vec<String>>,
    pub endpoint_bypass_skipped: RwLock<Vec<String>>,
    pub l4_targets_unsupported: AtomicU64,
    pub last_unsupported_route_target: RwLock<Option<String>>,
    pub read_packets: AtomicU64,
    pub read_bytes: AtomicU64,
    pub write_packets: AtomicU64,
    pub write_bytes: AtomicU64,
    pub decode_errors: AtomicU64,
    pub encode_errors: AtomicU64,
    pub rejected_packets: AtomicU64,
    pub dropped_packets: AtomicU64,
    pub lagged_events: AtomicU64,
    pub last_error: RwLock<Option<String>>,
    pub last_drop_reason: RwLock<Option<String>>,
    // Session tracking
    pub tcp_active_sessions: AtomicU64,
    pub udp_active_sessions: AtomicU64,
    pub direct_sessions: AtomicU64,
    pub proxy_sessions: AtomicU64,
    pub group_resolved_sessions: AtomicU64,
    pub country_resolved_sessions: AtomicU64,
    // DNS hijack
    pub dns_queries: AtomicU64,
    pub dns_successes: AtomicU64,
    pub dns_failures: AtomicU64,
    pub dns_unsupported_ipv6: AtomicU64,
}

#[derive(Debug, Clone, Serialize)]
pub struct NativeTunMetricsSnapshot {
    pub enabled: bool,
    pub running: bool,
    pub backend: String,
    pub interface_name: Option<String>,
    pub l3_profile: Option<String>,
    pub mtu: u16,
    pub setup_enabled: bool,
    pub auto_route: bool,
    pub routes_installed: Vec<String>,
    pub bypass_routes_installed: Vec<String>,
    pub skipped_bypass_routes: Vec<String>,
    pub setup_warnings: Vec<String>,
    pub endpoint_bypass_installed: Vec<String>,
    pub endpoint_bypass_skipped: Vec<String>,
    pub l4_targets_unsupported: u64,
    pub last_unsupported_route_target: Option<String>,
    pub read_packets: u64,
    pub read_bytes: u64,
    pub write_packets: u64,
    pub write_bytes: u64,
    pub decode_errors: u64,
    pub encode_errors: u64,
    pub rejected_packets: u64,
    pub dropped_packets: u64,
    pub lagged_events: u64,
    pub last_error: Option<String>,
    pub last_drop_reason: Option<String>,
    // Session tracking
    pub tcp_active_sessions: u64,
    pub udp_active_sessions: u64,
    pub direct_sessions: u64,
    pub proxy_sessions: u64,
    pub group_resolved_sessions: u64,
    pub country_resolved_sessions: u64,
    // DNS hijack
    pub dns_queries: u64,
    pub dns_successes: u64,
    pub dns_failures: u64,
    pub dns_unsupported_ipv6: u64,
}

#[derive(Debug, Clone)]
pub struct NativeTunMetrics {
    inner: Arc<NativeTunMetricsInner>,
}

impl NativeTunMetrics {
    pub fn new(enabled: bool, backend: String, setup_enabled: bool, auto_route: bool) -> Self {
        Self {
            inner: Arc::new(NativeTunMetricsInner {
                enabled,
                running: AtomicBool::new(false),
                backend,
                interface_name: RwLock::new(None),
                l3_profile: RwLock::new(None),
                mtu: AtomicU16::new(1500),
                setup_enabled,
                auto_route,
                routes_installed: RwLock::new(Vec::new()),
                bypass_routes_installed: RwLock::new(Vec::new()),
                skipped_bypass_routes: RwLock::new(Vec::new()),
                setup_warnings: RwLock::new(Vec::new()),
                endpoint_bypass_installed: RwLock::new(Vec::new()),
                endpoint_bypass_skipped: RwLock::new(Vec::new()),
                l4_targets_unsupported: AtomicU64::new(0),
                last_unsupported_route_target: RwLock::new(None),
                read_packets: AtomicU64::new(0),
                read_bytes: AtomicU64::new(0),
                write_packets: AtomicU64::new(0),
                write_bytes: AtomicU64::new(0),
                decode_errors: AtomicU64::new(0),
                encode_errors: AtomicU64::new(0),
                rejected_packets: AtomicU64::new(0),
                dropped_packets: AtomicU64::new(0),
                lagged_events: AtomicU64::new(0),
                last_error: RwLock::new(None),
                last_drop_reason: RwLock::new(None),
                tcp_active_sessions: AtomicU64::new(0),
                udp_active_sessions: AtomicU64::new(0),
                direct_sessions: AtomicU64::new(0),
                proxy_sessions: AtomicU64::new(0),
                group_resolved_sessions: AtomicU64::new(0),
                country_resolved_sessions: AtomicU64::new(0),
                dns_queries: AtomicU64::new(0),
                dns_successes: AtomicU64::new(0),
                dns_failures: AtomicU64::new(0),
                dns_unsupported_ipv6: AtomicU64::new(0),
            }),
        }
    }

    pub fn set_running(&self, running: bool) {
        self.inner.running.store(running, Ordering::Relaxed);
    }

    pub fn set_interface_name(&self, name: Option<String>) {
        if let Ok(mut lock) = self.inner.interface_name.write() {
            *lock = name;
        }
    }

    pub fn set_l3_profile(&self, profile: Option<String>) {
        if let Ok(mut lock) = self.inner.l3_profile.write() {
            *lock = profile;
        }
    }

    pub fn set_mtu(&self, mtu: u16) {
        self.inner.mtu.store(mtu, Ordering::Relaxed);
    }

    pub fn set_routes(&self, routes: Vec<String>) {
        if let Ok(mut lock) = self.inner.routes_installed.write() {
            *lock = routes;
        }
    }

    pub fn set_bypass_routes(&self, routes: Vec<String>) {
        if let Ok(mut lock) = self.inner.bypass_routes_installed.write() {
            *lock = routes;
        }
    }

    pub fn set_skipped_bypass_routes(&self, routes: Vec<String>) {
        if let Ok(mut lock) = self.inner.skipped_bypass_routes.write() {
            *lock = routes;
        }
    }

    pub fn set_setup_warnings(&self, warnings: Vec<String>) {
        if let Ok(mut lock) = self.inner.setup_warnings.write() {
            *lock = warnings;
        }
    }

    pub fn set_endpoint_bypass_installed(&self, routes: Vec<String>) {
        if let Ok(mut lock) = self.inner.endpoint_bypass_installed.write() {
            *lock = routes;
        }
    }

    pub fn set_endpoint_bypass_skipped(&self, routes: Vec<String>) {
        if let Ok(mut lock) = self.inner.endpoint_bypass_skipped.write() {
            *lock = routes;
        }
    }

    pub fn record_l4_unsupported(&self, target: String) {
        self.inner
            .l4_targets_unsupported
            .fetch_add(1, Ordering::Relaxed);
        if let Ok(mut lock) = self.inner.last_unsupported_route_target.write() {
            *lock = Some(target);
        }
    }

    pub fn record_read(&self, bytes: u64) {
        self.inner.read_packets.fetch_add(1, Ordering::Relaxed);
        self.inner.read_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn record_write(&self, bytes: u64) {
        self.inner.write_packets.fetch_add(1, Ordering::Relaxed);
        self.inner.write_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn record_decode_error(&self) {
        self.inner.decode_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_encode_error(&self) {
        self.inner.encode_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_rejected(&self) {
        self.inner.rejected_packets.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_dropped(&self, reason: String) {
        self.inner.dropped_packets.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut lock) = self.inner.last_drop_reason.write() {
            *lock = Some(reason);
        }
    }

    pub fn record_lagged(&self) {
        self.inner.lagged_events.fetch_add(1, Ordering::Relaxed);
    }

    pub fn set_last_error(&self, error: Option<String>) {
        if let Ok(mut lock) = self.inner.last_error.write() {
            *lock = error;
        }
    }

    // Session tracking
    pub fn record_tcp_session_opened(&self) {
        self.inner
            .tcp_active_sessions
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_tcp_session_closed(&self) {
        self.inner
            .tcp_active_sessions
            .fetch_sub(1, Ordering::Relaxed);
    }

    pub fn record_udp_session_opened(&self) {
        self.inner
            .udp_active_sessions
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_udp_session_closed(&self) {
        self.inner
            .udp_active_sessions
            .fetch_sub(1, Ordering::Relaxed);
    }

    pub fn record_direct_session(&self) {
        self.inner.direct_sessions.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_proxy_session(&self) {
        self.inner.proxy_sessions.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_group_resolved_session(&self) {
        self.inner
            .group_resolved_sessions
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_country_resolved_session(&self) {
        self.inner
            .country_resolved_sessions
            .fetch_add(1, Ordering::Relaxed);
    }

    // DNS hijack
    pub fn record_dns_query(&self) {
        self.inner.dns_queries.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_dns_success(&self) {
        self.inner.dns_successes.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_dns_failure(&self) {
        self.inner.dns_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_dns_unsupported_ipv6(&self) {
        self.inner
            .dns_unsupported_ipv6
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> NativeTunMetricsSnapshot {
        NativeTunMetricsSnapshot {
            enabled: self.inner.enabled,
            running: self.inner.running.load(Ordering::Relaxed),
            backend: self.inner.backend.clone(),
            interface_name: self
                .inner
                .interface_name
                .read()
                .ok()
                .and_then(|v| v.clone()),
            l3_profile: self.inner.l3_profile.read().ok().and_then(|v| v.clone()),
            mtu: self.inner.mtu.load(Ordering::Relaxed),
            setup_enabled: self.inner.setup_enabled,
            auto_route: self.inner.auto_route,
            routes_installed: self
                .inner
                .routes_installed
                .read()
                .ok()
                .map(|v| v.clone())
                .unwrap_or_default(),
            bypass_routes_installed: self
                .inner
                .bypass_routes_installed
                .read()
                .ok()
                .map(|v| v.clone())
                .unwrap_or_default(),
            skipped_bypass_routes: self
                .inner
                .skipped_bypass_routes
                .read()
                .ok()
                .map(|v| v.clone())
                .unwrap_or_default(),
            setup_warnings: self
                .inner
                .setup_warnings
                .read()
                .ok()
                .map(|v| v.clone())
                .unwrap_or_default(),
            endpoint_bypass_installed: self
                .inner
                .endpoint_bypass_installed
                .read()
                .ok()
                .map(|v| v.clone())
                .unwrap_or_default(),
            endpoint_bypass_skipped: self
                .inner
                .endpoint_bypass_skipped
                .read()
                .ok()
                .map(|v| v.clone())
                .unwrap_or_default(),
            l4_targets_unsupported: self.inner.l4_targets_unsupported.load(Ordering::Relaxed),
            last_unsupported_route_target: self
                .inner
                .last_unsupported_route_target
                .read()
                .ok()
                .and_then(|v| v.clone()),
            read_packets: self.inner.read_packets.load(Ordering::Relaxed),
            read_bytes: self.inner.read_bytes.load(Ordering::Relaxed),
            write_packets: self.inner.write_packets.load(Ordering::Relaxed),
            write_bytes: self.inner.write_bytes.load(Ordering::Relaxed),
            decode_errors: self.inner.decode_errors.load(Ordering::Relaxed),
            encode_errors: self.inner.encode_errors.load(Ordering::Relaxed),
            rejected_packets: self.inner.rejected_packets.load(Ordering::Relaxed),
            dropped_packets: self.inner.dropped_packets.load(Ordering::Relaxed),
            lagged_events: self.inner.lagged_events.load(Ordering::Relaxed),
            last_error: self.inner.last_error.read().ok().and_then(|v| v.clone()),
            last_drop_reason: self
                .inner
                .last_drop_reason
                .read()
                .ok()
                .and_then(|v| v.clone()),
            // Session tracking
            tcp_active_sessions: self.inner.tcp_active_sessions.load(Ordering::Relaxed),
            udp_active_sessions: self.inner.udp_active_sessions.load(Ordering::Relaxed),
            direct_sessions: self.inner.direct_sessions.load(Ordering::Relaxed),
            proxy_sessions: self.inner.proxy_sessions.load(Ordering::Relaxed),
            group_resolved_sessions: self.inner.group_resolved_sessions.load(Ordering::Relaxed),
            country_resolved_sessions: self.inner.country_resolved_sessions.load(Ordering::Relaxed),
            // DNS hijack
            dns_queries: self.inner.dns_queries.load(Ordering::Relaxed),
            dns_successes: self.inner.dns_successes.load(Ordering::Relaxed),
            dns_failures: self.inner.dns_failures.load(Ordering::Relaxed),
            dns_unsupported_ipv6: self.inner.dns_unsupported_ipv6.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct NativeTunStatusResponse {
    pub ok: bool,
    pub status: NativeTunStatus,
}

#[derive(Debug, Clone, Serialize)]
pub struct NativeTunStatus {
    pub backend: String,
    pub running: bool,
    pub interface_name: Option<String>,
    pub l3_profile: Option<String>,
    pub mtu: u16,
    pub setup: NativeTunSetupStatus,
    pub metrics: NativeTunMetricsSnapshot,
}

#[derive(Debug, Clone, Serialize)]
pub struct NativeTunSetupStatus {
    pub enabled: bool,
    pub auto_route: bool,
    pub routes: Vec<String>,
    pub bypass: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_new_has_correct_defaults() {
        let metrics = NativeTunMetrics::new(true, "native-l3".to_string(), true, true);
        let snapshot = metrics.snapshot();
        assert!(snapshot.enabled);
        assert!(!snapshot.running);
        assert_eq!(snapshot.backend, "native-l3");
        assert!(snapshot.interface_name.is_none());
        assert_eq!(snapshot.read_packets, 0);
        assert_eq!(snapshot.write_packets, 0);
    }

    #[test]
    fn metrics_record_read_increments() {
        let metrics = NativeTunMetrics::new(true, "native-l3".to_string(), false, false);
        metrics.record_read(100);
        metrics.record_read(200);
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.read_packets, 2);
        assert_eq!(snapshot.read_bytes, 300);
    }

    #[test]
    fn metrics_record_write_increments() {
        let metrics = NativeTunMetrics::new(true, "native-l3".to_string(), false, false);
        metrics.record_write(150);
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.write_packets, 1);
        assert_eq!(snapshot.write_bytes, 150);
    }

    #[test]
    fn metrics_record_errors() {
        let metrics = NativeTunMetrics::new(true, "native-l3".to_string(), false, false);
        metrics.record_decode_error();
        metrics.record_encode_error();
        metrics.record_rejected();
        metrics.record_dropped("no_receiver".to_string());
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.decode_errors, 1);
        assert_eq!(snapshot.encode_errors, 1);
        assert_eq!(snapshot.rejected_packets, 1);
        assert_eq!(snapshot.dropped_packets, 1);
        assert_eq!(snapshot.last_drop_reason.as_deref(), Some("no_receiver"));
    }
}
