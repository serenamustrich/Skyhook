use std::{
    collections::HashMap,
    sync::{Arc, RwLock, Weak},
    time::Duration,
};

use anyhow::anyhow;
use async_trait::async_trait;

use crate::{config::OutboundCommonConfig, routing::Destination};

use super::{
    context::DialContext, transports::scope_tcp_dialer, BoxedStream, Outbound, OutboundCapability,
};

pub(super) type OutboundRegistry = Arc<RwLock<HashMap<String, Weak<dyn Outbound>>>>;

pub(super) fn outbound_registry() -> OutboundRegistry {
    Arc::new(RwLock::new(HashMap::new()))
}

pub(super) struct ConfiguredOutbound {
    inner: Arc<dyn Outbound>,
    options: OutboundCommonConfig,
    registry: OutboundRegistry,
}

impl ConfiguredOutbound {
    pub(super) fn new(
        inner: Arc<dyn Outbound>,
        options: OutboundCommonConfig,
        registry: OutboundRegistry,
    ) -> Self {
        Self {
            inner,
            options,
            registry,
        }
    }

    fn configured_context(&self, context: &DialContext) -> anyhow::Result<DialContext> {
        if self.options.routing_mark.is_some() {
            return Err(anyhow!(
                "routing-mark is not supported by the macOS Skyhook runtime"
            ));
        }
        if self.options.smux.as_ref().is_some_and(|smux| smux.enabled) {
            return Err(anyhow!(
                "smux is configured for {} but its selected mux backend is not active",
                self.name()
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
        if !self.options.udp {
            capability.udp_supported = false;
            capability.udp_mode = None;
            capability
                .limitations
                .push("UDP is disabled by outbound common options".to_string());
        }
        if self.options.routing_mark.is_some() {
            capability
                .limitations
                .push("routing-mark is unavailable on macOS".to_string());
        }
        if self.options.mptcp {
            capability
                .limitations
                .push("MPTCP requires the native macOS dial backend".to_string());
        }
        capability
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
        scope_tcp_dialer(dialer, self.inner.connect_context(&context)).await
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
        scope_tcp_dialer(dialer, self.inner.udp_exchange_context(&context, payload)).await
    }
}
