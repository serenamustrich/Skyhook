use std::{
    collections::HashMap,
    sync::{Arc, RwLock, Weak},
    time::Duration,
};

use anyhow::anyhow;
use async_trait::async_trait;

use crate::{config::OutboundCommonConfig, routing::Destination};

use super::{
    context::DialContext,
    mux::MuxPool,
    transports::{mptcp_runtime_available, scope_tcp_dialer},
    udp::UdpRuntime,
    BoxedStream, Outbound, OutboundCapability,
};

pub(super) type OutboundRegistry = Arc<RwLock<HashMap<String, Weak<dyn Outbound>>>>;

pub(super) fn outbound_registry() -> OutboundRegistry {
    Arc::new(RwLock::new(HashMap::new()))
}

pub(super) struct ConfiguredOutbound {
    inner: Arc<dyn Outbound>,
    options: OutboundCommonConfig,
    registry: OutboundRegistry,
    mux: Option<Arc<MuxPool>>,
    udp_runtime: Arc<UdpRuntime>,
}

impl ConfiguredOutbound {
    pub(super) fn new(
        inner: Arc<dyn Outbound>,
        options: OutboundCommonConfig,
        registry: OutboundRegistry,
    ) -> Self {
        let mux = options
            .smux
            .as_ref()
            .filter(|config| config.enabled)
            .cloned()
            .map(|config| Arc::new(MuxPool::new(Arc::clone(&inner), config)));
        let udp_runtime = Arc::new(UdpRuntime::new(
            inner.kind(),
            inner.name(),
            inner.udp_nat_mode(),
        ));
        Self {
            inner,
            options,
            registry,
            mux,
            udp_runtime,
        }
    }

    fn configured_context(&self, context: &DialContext) -> anyhow::Result<DialContext> {
        if self.options.routing_mark.is_some() {
            return Err(anyhow!(
                "routing-mark is not supported by the macOS Skyhook runtime"
            ));
        }
        if context.dialer_chain.iter().any(|name| name == self.name()) {
            return Err(anyhow!(
                "dialer-proxy cycle detected: {} -> {}",
                context.dialer_chain.join(" -> "),
                self.name()
            ));
        }

        let mut configured = context.clone();
        configured.ip_version = self.options.ip_version;
        configured.interface_name = self.options.interface_name.clone();
        configured.tcp_fast_open = self.options.tfo;
        configured.multipath_tcp = self.options.mptcp;
        configured.certificate_fingerprint = self.options.certificate_fingerprint.clone();
        configured.quic_mtu = self.options.quic_mtu;
        configured.quic_zero_rtt = self.options.quic_zero_rtt;
        configured.websocket_early_data_header = self.options.websocket_early_data_header.clone();
        configured.websocket_max_early_data = self.options.websocket_max_early_data;
        if let Some(keepalive_secs) = self.options.keepalive_secs {
            configured.keepalive = Some(Duration::from_secs(keepalive_secs.max(1)));
        }
        configured.dialer_chain.push(self.name().to_string());
        Ok(configured)
    }

    fn dialer(&self) -> anyhow::Result<Option<Arc<dyn Outbound>>> {
        let Some(name) = self
            .options
            .dialer_proxy
            .as_deref()
            .map(str::trim)
            .filter(|name| !name.is_empty())
        else {
            return Ok(None);
        };
        if name == self.name() {
            return Err(anyhow!("outbound {name} cannot use itself as dialer-proxy"));
        }
        self.registry
            .read()
            .map_err(|_| anyhow!("outbound registry lock poisoned"))?
            .get(name)
            .and_then(Weak::upgrade)
            .map(Some)
            .ok_or_else(|| anyhow!("dialer-proxy {name} does not exist"))
    }
}

#[async_trait]
impl Outbound for ConfiguredOutbound {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn kind(&self) -> &'static str {
        self.inner.kind()
    }

    fn capability(&self) -> OutboundCapability {
        let mut capability = self.inner.capability();
        let udp_uses_mux = self
            .options
            .smux
            .as_ref()
            .is_some_and(|smux| smux.enabled && !smux.only_tcp);
        if !self.options.udp {
            capability.udp_supported = false;
            capability.udp_mode = None;
            capability
                .limitations
                .push("UDP is disabled by outbound common options".to_string());
        } else if self.options.dialer_proxy.is_some()
            && capability.udp_supported
            && !udp_uses_mux
            && !self.inner.supports_udp_dialer_proxy()
        {
            capability.udp_supported = false;
            capability.udp_mode = None;
            capability.limitations.push(
                "native UDP/QUIC cannot apply dialer-proxy without a UDP packet tunnel".to_string(),
            );
        }
        if self.options.routing_mark.is_some() {
            capability
                .limitations
                .push("routing-mark is unavailable on macOS".to_string());
        }
        #[cfg(not(target_os = "macos"))]
        if self.options.mptcp {
            capability
                .limitations
                .push("MPTCP is only available through the native macOS dial backend".to_string());
        }
        #[cfg(target_os = "macos")]
        if self.options.mptcp && !mptcp_runtime_available() {
            capability.limitations.push(
                "MPTCP requires a signed supercore executable with the multipath entitlement"
                    .to_string(),
            );
        }
        if let Some(smux) = self.options.smux.as_ref().filter(|smux| smux.enabled) {
            if !smux.only_tcp && self.options.udp {
                capability.udp_supported = true;
                capability.udp_mode = Some("sing-mux fixed-destination stream".to_string());
            }
        }
        capability
    }

    fn udp_nat_mode(&self) -> super::UdpNatMode {
        self.inner.udp_nat_mode()
    }

    fn supports_udp_dialer_proxy(&self) -> bool {
        self.inner.supports_udp_dialer_proxy()
    }

    fn runtime_stats(&self) -> Option<serde_json::Value> {
        let udp = serde_json::to_value(self.udp_runtime.snapshot())
            .unwrap_or_else(|_| serde_json::json!({"error": "UDP stats unavailable"}));
        match (&self.mux, self.inner.runtime_stats()) {
            (Some(mux), Some(inner)) => Some(serde_json::json!({
                "mux": mux.snapshot(),
                "inner": inner,
                "udp": udp,
            })),
            (Some(mux), None) => Some(serde_json::json!({
                "mux": mux.snapshot(),
                "udp": udp,
            })),
            (None, Some(inner)) => Some(serde_json::json!({
                "inner": inner,
                "udp": udp,
            })),
            (None, None) => Some(serde_json::json!({
                "udp": udp,
            })),
        }
    }

    fn rematch_target(&self) -> Option<super::RematchTarget> {
        self.inner.rematch_target()
    }

    async fn connect(
        &self,
        destination: &Destination,
        timeout_ms: u64,
    ) -> anyhow::Result<BoxedStream> {
        let context = DialContext::new(destination.clone(), timeout_ms);
        self.connect_context(&context).await
    }

    async fn connect_context(&self, context: &DialContext) -> anyhow::Result<BoxedStream> {
        let context = self.configured_context(context)?;
        let dialer = self.dialer()?;
        if let Some(mux) = &self.mux {
            mux.connect(&context, dialer).await
        } else {
            scope_tcp_dialer(dialer, self.inner.connect_context(&context)).await
        }
    }

    async fn udp_exchange(
        &self,
        destination: &Destination,
        payload: &[u8],
        timeout_ms: u64,
    ) -> anyhow::Result<Vec<u8>> {
        let context = DialContext::new(destination.clone(), timeout_ms);
        self.udp_exchange_context(&context, payload).await
    }

    async fn udp_exchange_context(
        &self,
        context: &DialContext,
        payload: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        if !self.options.udp {
            return Err(anyhow!("UDP is disabled for outbound {}", self.name()));
        }
        let context = self.configured_context(context)?;
        let dialer = self.dialer()?;
        if let Some(mux) = &self.mux {
            if !self.options.smux.as_ref().is_some_and(|smux| smux.only_tcp) {
                return self
                    .udp_runtime
                    .exchange(&context, payload, || {
                        mux.udp_exchange(&context, payload, dialer)
                    })
                    .await;
            }
        }
        if dialer.is_some() && !self.inner.supports_udp_dialer_proxy() {
            return Err(anyhow!(
                "outbound {} uses native UDP/QUIC and cannot safely apply dialer-proxy without a UDP packet tunnel",
                self.name()
            ));
        }
        self.udp_runtime
            .exchange(&context, payload, || {
                scope_tcp_dialer(dialer, self.inner.udp_exchange_context(&context, payload))
            })
            .await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    use async_trait::async_trait;

    use crate::{
        config::{OutboundCommonConfig, SmuxConfig, SmuxProtocol},
        outbound::{BoxedStream, Outbound, OutboundCapability},
        routing::Destination,
    };

    use super::{outbound_registry, ConfiguredOutbound};

    struct NativeUdpOutbound {
        name: &'static str,
        tcp_calls: Arc<AtomicUsize>,
        udp_calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl Outbound for NativeUdpOutbound {
        fn name(&self) -> &str {
            self.name
        }

        fn kind(&self) -> &'static str {
            "mock"
        }

        fn capability(&self) -> OutboundCapability {
            OutboundCapability::tcp_udp("native test UDP")
        }

        async fn connect(
            &self,
            _destination: &Destination,
            _timeout_ms: u64,
        ) -> anyhow::Result<BoxedStream> {
            self.tcp_calls.fetch_add(1, Ordering::Relaxed);
            Err(anyhow::anyhow!("TCP must not be used by only-tcp UDP"))
        }

        async fn udp_exchange(
            &self,
            _destination: &Destination,
            payload: &[u8],
            _timeout_ms: u64,
        ) -> anyhow::Result<Vec<u8>> {
            self.udp_calls.fetch_add(1, Ordering::Relaxed);
            Ok(payload.to_vec())
        }
    }

    #[tokio::test]
    async fn smux_only_tcp_bypasses_mux_for_udp() {
        let tcp_calls = Arc::new(AtomicUsize::new(0));
        let udp_calls = Arc::new(AtomicUsize::new(0));
        let inner: Arc<dyn Outbound> = Arc::new(NativeUdpOutbound {
            name: "native-udp",
            tcp_calls: Arc::clone(&tcp_calls),
            udp_calls: Arc::clone(&udp_calls),
        });
        let configured = ConfiguredOutbound::new(
            inner,
            OutboundCommonConfig {
                smux: Some(SmuxConfig {
                    enabled: true,
                    protocol: SmuxProtocol::H2Mux,
                    only_tcp: true,
                    statistic: true,
                    ..SmuxConfig::default()
                }),
                ..OutboundCommonConfig::default()
            },
            outbound_registry(),
        );

        let response = configured
            .udp_exchange(&Destination::new("dns.example", 53), b"native", 500)
            .await
            .unwrap();
        assert_eq!(response, b"native");
        assert_eq!(udp_calls.load(Ordering::Relaxed), 1);
        assert_eq!(tcp_calls.load(Ordering::Relaxed), 0);
        let stats = configured.runtime_stats().unwrap();
        assert_eq!(stats["mux"]["underlay_visible"], true);
        assert_eq!(stats["mux"]["physical_active"], 0);
        assert_eq!(stats["udp"]["completed"], 1);
        assert_eq!(stats["udp"]["uploaded_bytes"], 6);
        assert_eq!(stats["udp"]["downloaded_bytes"], 6);
    }

    #[tokio::test]
    async fn native_udp_dialer_proxy_is_rejected_instead_of_leaking_direct() {
        let registry = outbound_registry();
        let dialer: Arc<dyn Outbound> = Arc::new(NativeUdpOutbound {
            name: "dialer",
            tcp_calls: Arc::new(AtomicUsize::new(0)),
            udp_calls: Arc::new(AtomicUsize::new(0)),
        });
        registry
            .write()
            .expect("registry write")
            .insert("dialer".to_string(), Arc::downgrade(&dialer));

        let udp_calls = Arc::new(AtomicUsize::new(0));
        let inner: Arc<dyn Outbound> = Arc::new(NativeUdpOutbound {
            name: "native-udp",
            tcp_calls: Arc::new(AtomicUsize::new(0)),
            udp_calls: Arc::clone(&udp_calls),
        });
        let configured = ConfiguredOutbound::new(
            inner,
            OutboundCommonConfig {
                dialer_proxy: Some("dialer".to_string()),
                ..OutboundCommonConfig::default()
            },
            registry,
        );

        let capability = configured.capability();
        assert!(!capability.udp_supported);
        assert!(capability
            .limitations
            .iter()
            .any(|item| item.contains("cannot apply dialer-proxy")));

        let error = configured
            .udp_exchange(&Destination::new("dns.example", 53), b"query", 500)
            .await
            .expect_err("native UDP dialer must not be silently bypassed");
        assert!(error
            .to_string()
            .contains("cannot safely apply dialer-proxy"));
        assert_eq!(udp_calls.load(Ordering::Relaxed), 0);
    }
}
