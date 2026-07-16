use std::{error::Error, fmt};

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutboundErrorKind {
    Dns,
    Tcp,
    Tls,
    Authentication,
    Protocol,
    HttpStatus,
    Timeout,
    Cancelled,
    Unsupported,
    EmptyResponse,
    Internal,
}

impl OutboundErrorKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Dns => "dns",
            Self::Tcp => "tcp",
            Self::Tls => "tls",
            Self::Authentication => "authentication",
            Self::Protocol => "protocol",
            Self::HttpStatus => "http_status",
            Self::Timeout => "timeout",
            Self::Cancelled => "cancelled",
            Self::Unsupported => "unsupported",
            Self::EmptyResponse => "empty_response",
            Self::Internal => "internal",
        }
    }

    pub fn probe_failure_kind(self) -> &'static str {
        match self {
            Self::Dns => "dns_error",
            Self::Tcp | Self::Internal => "dial_error",
            Self::Tls => "tls_error",
            Self::Authentication => "authentication_error",
            Self::Protocol | Self::Unsupported => "protocol_unsupported",
            Self::HttpStatus => "http_status",
            Self::Timeout => "timeout",
            Self::Cancelled => "cancelled",
            Self::EmptyResponse => "empty_response",
        }
    }

    pub fn retryable(self) -> bool {
        matches!(
            self,
            Self::Dns | Self::Tcp | Self::Timeout | Self::Cancelled | Self::Internal
        )
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct OutboundError {
    pub kind: OutboundErrorKind,
    pub protocol: Option<String>,
    pub operation: String,
    pub message: String,
    pub retryable: bool,
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
            operation: operation.into(),
            message: message.into(),
            retryable: kind.retryable(),
        }
    }

    pub fn for_protocol(mut self, protocol: impl Into<String>) -> Self {
        self.protocol = Some(protocol.into());
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
        OutboundErrorKind::Tcp
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
        OutboundErrorKind::HttpStatus
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
    use super::{classify_message, OutboundErrorKind};

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
}
