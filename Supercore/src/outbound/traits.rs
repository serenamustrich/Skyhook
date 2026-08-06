use std::{collections::HashMap, sync::Arc, time::Duration};

use async_trait::async_trait;
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::routing::Destination;

use super::{
    context::{scope_dial_context, DialContext},
    error::{contextualize_error, OutboundError, OutboundErrorKind},
};

pub trait ProxyStream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T> ProxyStream for T where T: AsyncRead + AsyncWrite + Send + Unpin {}

pub type BoxedStream = Box<dyn ProxyStream>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum UdpNatMode {
    EndpointDependent,
    EndpointIndependent,
}

#[derive(Debug, Clone, Serialize)]
pub struct OutboundCapability {
    pub tcp_supported: bool,
    pub udp_supported: bool,
    pub udp_mode: Option<String>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RematchTarget {
    pub rematch_name: Option<String>,
}

impl OutboundCapability {
    pub fn tcp_only(limitation: impl Into<String>) -> Self {
        Self {
            tcp_supported: true,
            udp_supported: false,
            udp_mode: None,
            limitations: vec![limitation.into()],
        }
    }

    pub fn tcp_udp(mode: impl Into<String>) -> Self {
        Self {
            tcp_supported: true,
            udp_supported: true,
            udp_mode: Some(mode.into()),
            limitations: Vec::new(),
        }
    }

    pub fn udp_only(mode: impl Into<String>, limitation: impl Into<String>) -> Self {
        Self {
            tcp_supported: false,
            udp_supported: true,
            udp_mode: Some(mode.into()),
            limitations: vec![limitation.into()],
        }
    }

    pub fn unsupported(limitation: impl Into<String>) -> Self {
        Self {
            tcp_supported: false,
            udp_supported: false,
            udp_mode: None,
            limitations: vec![limitation.into()],
        }
    }
}

#[async_trait]
pub trait Outbound: Send + Sync {
    fn name(&self) -> &str;
    fn kind(&self) -> &'static str;
    fn capability(&self) -> OutboundCapability;

    fn udp_nat_mode(&self) -> UdpNatMode {
        UdpNatMode::EndpointDependent
    }

    fn supports_udp_dialer_proxy(&self) -> bool {
        false
    }

    fn runtime_stats(&self) -> Option<serde_json::Value> {
        None
    }

    fn rematch_target(&self) -> Option<RematchTarget> {
        None
    }

    async fn connect(
        &self,
        destination: &Destination,
        timeout_ms: u64,
    ) -> anyhow::Result<BoxedStream>;

    async fn connect_context(&self, context: &DialContext) -> anyhow::Result<BoxedStream> {
        let remaining = context.remaining_timeout();
        if remaining.is_zero() {
            return Err(OutboundError::new(
                OutboundErrorKind::Timeout,
                "connect",
                format!(
                    "dial {} exceeded its deadline",
                    context.destination.authority()
                ),
            )
            .for_protocol(self.kind())
            .for_node(self.name())
            .for_destination(context.destination.authority())
            .with_trace_id(context.trace_id.clone())
            .into());
        }

        tokio::select! {
            biased;
            _ = context.cancellation.cancelled() => {
                Err(OutboundError::new(
                    OutboundErrorKind::Cancelled,
                    "connect",
                    format!("dial {} was cancelled", context.destination.authority()),
                )
                .for_protocol(self.kind())
                .for_node(self.name())
                .for_destination(context.destination.authority())
                .with_trace_id(context.trace_id.clone())
                .into())
            }
            result = scope_dial_context(
                context,
                self.connect(&context.destination, duration_millis(remaining)),
            ) => {
                result.map_err(|error| {
                    contextualize_error(
                        error,
                        "connect",
                        self.kind(),
                        self.name(),
                        &context.destination.authority(),
                        &context.trace_id,
                    )
                })
            }
            _ = tokio::time::sleep_until(context.deadline.into()) => {
                Err(OutboundError::new(
                    OutboundErrorKind::Timeout,
                    "connect",
                    format!("dial {} exceeded its deadline", context.destination.authority()),
                )
                .for_protocol(self.kind())
                .for_node(self.name())
                .for_destination(context.destination.authority())
                .with_trace_id(context.trace_id.clone())
                .into())
            },
        }
    }

    async fn udp_exchange(
        &self,
        _destination: &Destination,
        _payload: &[u8],
        _timeout_ms: u64,
    ) -> anyhow::Result<Vec<u8>> {
        Err(OutboundError::new(
            OutboundErrorKind::Unsupported,
            "udp_exchange",
            format!("outbound {} does not support udp", self.name()),
        )
        .for_protocol(self.kind())
        .for_node(self.name())
        .into())
    }

    async fn udp_exchange_context(
        &self,
        context: &DialContext,
        payload: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        let remaining = context.remaining_timeout();
        if remaining.is_zero() {
            return Err(OutboundError::new(
                OutboundErrorKind::Timeout,
                "udp_exchange",
                format!(
                    "UDP exchange with {} exceeded its deadline",
                    context.destination.authority()
                ),
            )
            .for_protocol(self.kind())
            .for_node(self.name())
            .for_destination(context.destination.authority())
            .with_trace_id(context.trace_id.clone())
            .into());
        }

        tokio::select! {
            biased;
            _ = context.cancellation.cancelled() => {
                Err(OutboundError::new(
                    OutboundErrorKind::Cancelled,
                    "udp_exchange",
                    format!("UDP exchange with {} was cancelled", context.destination.authority()),
                )
                .for_protocol(self.kind())
                .for_node(self.name())
                .for_destination(context.destination.authority())
                .with_trace_id(context.trace_id.clone())
                .into())
            }
            result = scope_dial_context(
                context,
                self.udp_exchange(&context.destination, payload, duration_millis(remaining)),
            ) => {
                result.map_err(|error| {
                    contextualize_error(
                        error,
                        "udp_exchange",
                        self.kind(),
                        self.name(),
                        &context.destination.authority(),
                        &context.trace_id,
                    )
                })
            }
            _ = tokio::time::sleep_until(context.deadline.into()) => {
                Err(OutboundError::new(
                    OutboundErrorKind::Timeout,
                    "udp_exchange",
                    format!("UDP exchange with {} exceeded its deadline", context.destination.authority()),
                )
                .for_protocol(self.kind())
                .for_node(self.name())
                .for_destination(context.destination.authority())
                .with_trace_id(context.trace_id.clone())
                .into())
            },
        }
    }
}

fn duration_millis(duration: Duration) -> u64 {
    duration.as_millis().clamp(1, u128::from(u64::MAX)) as u64
}

pub type OutboundMap = HashMap<String, Arc<dyn Outbound>>;
