use std::sync::Arc;

use anyhow::anyhow;
use async_trait::async_trait;
use rustls_pki_types::ServerName;
use tokio_rustls::TlsConnector;

use crate::routing::Destination;

use super::{
    target::destination_socket_addr,
    transports::{connect_tcp, establish_http_connect, run_dial_phase, tls_client_config},
    BoxedStream, Outbound, OutboundCapability,
};

pub(crate) struct HttpOutbound {
    name: String,
    server: String,
    port: u16,
    username: Option<String>,
    password: Option<String>,
    tls: bool,
    sni: Option<String>,
    skip_cert_verify: bool,
}

impl HttpOutbound {
    pub(crate) fn new(name: String, server: String, port: u16) -> Self {
        Self {
            name,
            server,
            port,
            username: None,
            password: None,
            tls: false,
            sni: None,
            skip_cert_verify: false,
        }
    }

    pub(crate) fn with_auth(mut self, username: Option<String>, password: Option<String>) -> Self {
        self.username = username;
        self.password = password;
        self
    }

    pub(crate) fn with_tls(
        mut self,
        tls: bool,
        sni: Option<String>,
        skip_cert_verify: bool,
    ) -> Self {
        self.tls = tls;
        self.sni = sni;
        self.skip_cert_verify = skip_cert_verify;
        self
    }

    fn validate_configuration(&self) -> anyhow::Result<()> {
        if self.server.trim().is_empty() || self.port == 0 {
            return Err(anyhow!("HTTP proxy server and port are required"));
        }
        match (&self.username, &self.password) {
            (Some(_), None) => {
                return Err(anyhow!("HTTP proxy password is required with username"))
            }
            (None, Some(_)) => {
                return Err(anyhow!("HTTP proxy username is required with password"))
            }
            _ => {}
        }
        if self
            .sni
            .as_deref()
            .is_some_and(|server_name| server_name.trim().is_empty())
        {
            return Err(anyhow!("HTTP proxy SNI must not be empty"));
        }
        Ok(())
    }
}

#[async_trait]
impl Outbound for HttpOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "http"
    }

    fn capability(&self) -> OutboundCapability {
        if let Err(error) = self.validate_configuration() {
            return OutboundCapability::unsupported(error.to_string());
        }
        OutboundCapability::tcp_only("HTTP CONNECT does not provide UDP relay")
    }

    async fn connect(
        &self,
        destination: &Destination,
        timeout_ms: u64,
    ) -> anyhow::Result<BoxedStream> {
        self.validate_configuration()?;
        let proxy = destination_socket_addr(&Destination::new(&self.server, self.port));
        let stream = connect_tcp(&proxy, timeout_ms).await?;
        if self.tls {
            let mut tls_config = tls_client_config(self.skip_cert_verify)?;
            tls_config.alpn_protocols = vec![b"http/1.1".to_vec()];
            let server_name = self.sni.as_deref().unwrap_or(&self.server).to_string();
            let server_name = ServerName::try_from(server_name)
                .map_err(|error| anyhow!("invalid HTTP proxy server name: {error}"))?;
            let stream = run_dial_phase(
                timeout_ms,
                "HTTPS proxy TLS handshake",
                TlsConnector::from(Arc::new(tls_config)).connect(server_name, stream),
            )
            .await??;
            let stream = run_dial_phase(
                timeout_ms,
                "HTTPS proxy CONNECT",
                establish_http_connect(
                    stream,
                    destination,
                    self.username.as_deref(),
                    self.password.as_deref(),
                    false,
                ),
            )
            .await??;
            Ok(Box::new(stream))
        } else {
            let stream = run_dial_phase(
                timeout_ms,
                "HTTP proxy CONNECT",
                establish_http_connect(
                    stream,
                    destination,
                    self.username.as_deref(),
                    self.password.as_deref(),
                    false,
                ),
            )
            .await??;
            Ok(Box::new(stream))
        }
    }
}
