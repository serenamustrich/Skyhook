use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::routing::Destination;

use super::{
    context::DialContext,
    error::{contextualize_error, OutboundError, OutboundErrorKind},
};

pub trait ProxyStream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T> ProxyStream for T where T: AsyncRead + AsyncWrite + Send + Unpin {}

pub type BoxedStream = Box<dyn ProxyStream>;

#[derive(Debug, Clone, Serialize)]
pub struct OutboundCapability {
    pub tcp_supported: bool,
    pub udp_supported: bool,
    pub udp_mode: Option<String>,
    pub limitations: Vec<String>,
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

    async fn connect(
        &self,
        destination: &Destination,
        timeout_ms: u64,
    ) -> anyhow::Result<BoxedStream>;

    async fn connect_context(&self, context: &DialContext) -> anyhow::Result<BoxedStream> {
        tokio::select! {
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
            result = self.connect(&context.destination, context.timeout_ms()) => {
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
        tokio::select! {
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
            result = self.udp_exchange(&context.destination, payload, context.timeout_ms()) => {
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
            },
        }
    }
}

pub type OutboundMap = HashMap<String, Arc<dyn Outbound>>;
