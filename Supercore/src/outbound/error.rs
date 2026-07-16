use std::{error::Error, fmt};

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutboundErrorKind {
    Dns,
    Tcp,
    TcpConnect,
    Tls,
    Authentication,
    Protocol,
    HttpStatus,
    RemoteRejected,
    Timeout,
    Cancelled,
    Unsupported,
    EmptyResponse,
    Io,
    Configuration,
    Internal,
}

impl OutboundErrorKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Dns => "dns",
            Self::Tcp => "tcp",
            Self::TcpConnect => "tcp_connect",
            Self::Tls => "tls",
            Self::Authentication => "authentication",
            Self::Protocol => "protocol",
            Self::HttpStatus => "http_status",
            Self::RemoteRejected => "remote_rejected",
            Self::Timeout => "timeout",
            Self::Cancelled => "cancelled",
            Self::Unsupported => "unsupported",
            Self::EmptyResponse => "empty_response",
            Self::Io => "io",
            Self::Configuration => "configuration",
            Self::Internal => "internal",
        }
    }

    pub fn probe_failure_kind(self) -> &'static str {
        match self {
            Self::Dns => "dns_error",
            Self::Tcp | Self::TcpConnect | Self::Io | Self::Internal => "dial_error",
            Self::Tls => "tls_error",
            Self::Authentication => "authentication_error",
            Self::Protocol | Self::Unsupported => "protocol_unsupported",
            Self::HttpStatus | Self::RemoteRejected => "http_status",
            Self::Timeout => "timeout",
            Self::Cancelled => "cancelled",
            Self::EmptyResponse => "empty_response",
            Self::Configuration => "configuration_error",
        }
    }

    pub fn retryable(self) -> bool {
        matches!(
            self,
            Self::Dns
                | Self::Tcp
                | Self::TcpConnect
                | Self::Timeout
                | Self::Cancelled
                | Self::Io
                | Self::Internal
        )
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct OutboundError {
    pub kind: OutboundErrorKind,
    pub protocol: Option<String>,
    pub node: Option<String>,
    pub destination: Option<String>,
    pub trace_id: Option<String>,
    pub operation: String,
    pub message: String,
    pub retryable: bool,
    pub source_chain: Vec<String>,
}

impl OutboundError {
    pub fn new(
        kind: OutboundErrorKind,
        operation: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            protocol: None,
            node: None,
            destination: None,
            trace_id: None,
            operation: operation.into(),
            message: message.into(),
            retryable: kind.retryable(),
            source_chain: Vec::new(),
        }
    }

    pub fn for_protocol(mut self, protocol: impl Into<String>) -> Self {
        self.protocol = Some(protocol.into());
        self
    }

    pub fn for_node(mut self, node: impl Into<String>) -> Self {
        self.node = Some(node.into());
        self
    }

    pub fn for_destination(mut self, destination: impl Into<String>) -> Self {
        self.destination = Some(destination.into());
        self
    }

    pub fn with_trace_id(mut self, trace_id: impl Into<String>) -> Self {
        self.trace_id = Some(trace_id.into());
        self
    }

    pub fn with_source(mut self, source: impl Into<String>) -> Self {
        self.source_chain.push(source.into());
        self
    }
}

impl fmt::Display for OutboundError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(protocol) = self.protocol.as_deref() {
            write!(
                formatter,
                "{protocol} {} failed: {}",
                self.operation, self.message
            )
        } else {
            write!(formatter, "{} failed: {}", self.operation, self.message)
        }
    }
}

impl Error for OutboundError {}

pub fn contextualize_error(
    error: anyhow::Error,
    operation: &str,
    protocol: &str,
    node: &str,
    destination: &str,
    trace_id: &str,
) -> anyhow::Error {
    if let Some(existing) = error.downcast_ref::<OutboundError>() {
        let mut contextualized = existing.clone();
        contextualized.operation = operation.to_string();
        contextualized.protocol = Some(protocol.to_string());
        contextualized.node = Some(node.to_string());
        contextualized.destination = Some(destination.to_string());
        contextualized.trace_id = Some(trace_id.to_string());
        if contextualized.source_chain.is_empty() {
            contextualized.source_chain.push(error.to_string());
        }
        return anyhow::Error::new(contextualized);
    }

    let message = error.to_string();
    anyhow::Error::new(
        OutboundError::new(classify_message(&message), operation, message.clone())
            .for_protocol(protocol)
            .for_node(node)
            .for_destination(destination)
            .with_trace_id(trace_id)
            .with_source(message),
    )
}

pub fn classify_message(message: &str) -> OutboundErrorKind {
    let lower = message.to_ascii_lowercase();
    if lower.contains("timed out") || lower.contains("timeout") {
        OutboundErrorKind::Timeout
    } else if lower.contains("cancelled") || lower.contains("canceled") {
        OutboundErrorKind::Cancelled
    } else if lower.contains("connection refused")
        || lower.contains("connect failed")
        || lower.contains("failed to connect")
    {
        OutboundErrorKind::TcpConnect
    } else if lower.contains("not implemented") {
        OutboundErrorKind::Unsupported
    } else if lower.contains("tls") || lower.contains("ssl") || lower.contains("certificate") {
        OutboundErrorKind::Tls
    } else if lower.contains("authentication")
        || lower.contains("auth failed")
        || lower.contains("invalid password")
    {
        OutboundErrorKind::Authentication
    } else if lower.contains("dns") || lower.contains("resolve") || lower.contains("lookup") {
        OutboundErrorKind::Dns
    } else if lower.contains("empty response") || lower.contains("no data") {
        OutboundErrorKind::EmptyResponse
    } else if lower.contains("unhealthy") || lower.contains("status") {
        OutboundErrorKind::RemoteRejected
    } else if lower.contains("unsupported") || lower.contains("not supported") {
        OutboundErrorKind::Unsupported
    } else if lower.contains("protocol") || lower.contains("invalid frame") {
        OutboundErrorKind::Protocol
    } else {
        OutboundErrorKind::Internal
    }
}

#[cfg(test)]
mod tests {
    use super::{classify_message, contextualize_error, OutboundError, OutboundErrorKind};

    #[test]
    fn classifies_stable_failure_categories() {
        assert_eq!(
            classify_message("lookup example.com failed"),
            OutboundErrorKind::Dns
        );
        assert_eq!(
            classify_message("TLS certificate rejected"),
            OutboundErrorKind::Tls
        );
        assert_eq!(
            classify_message("protocol is not implemented"),
            OutboundErrorKind::Unsupported
        );
        assert_eq!(
            classify_message("request timed out"),
            OutboundErrorKind::Timeout
        );
    }

    #[test]
    fn enriches_untyped_errors_with_dial_context() {
        let error = contextualize_error(
            anyhow::anyhow!("connection refused"),
            "connect",
            "test",
            "node-a",
            "example.com:443",
            "trace-a",
        );
        let error = error.downcast_ref::<OutboundError>().unwrap();
        assert_eq!(error.kind, OutboundErrorKind::TcpConnect);
        assert_eq!(error.protocol.as_deref(), Some("test"));
        assert_eq!(error.node.as_deref(), Some("node-a"));
        assert_eq!(error.destination.as_deref(), Some("example.com:443"));
        assert_eq!(error.trace_id.as_deref(), Some("trace-a"));
        assert!(!error.source_chain.is_empty());
    }
}
