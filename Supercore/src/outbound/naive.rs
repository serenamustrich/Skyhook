use std::{sync::Arc, time::Duration};

use anyhow::{anyhow, Context};
use async_trait::async_trait;
use rustls_pki_types::ServerName;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

use crate::routing::Destination;

use super::{
    transports::{connect_tcp, establish_http_connect, tls_client_config},
    BoxedStream, Outbound, OutboundCapability,
};

pub(crate) struct NaiveOutbound {
    name: String,
    server: String,
    port: u16,
    username: Option<String>,
    password: Option<String>,
    sni: Option<String>,
    skip_cert_verify: bool,
    alpn: Vec<String>,
}

impl NaiveOutbound {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        name: String,
        server: String,
        port: u16,
        username: Option<String>,
        password: Option<String>,
        sni: Option<String>,
        skip_cert_verify: bool,
        alpn: Vec<String>,
    ) -> Self {
        Self {
            name,
            server,
            port,
            username,
            password,
            sni,
            skip_cert_verify,
            alpn,
        }
    }
}

#[async_trait]
impl Outbound for NaiveOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "naive"
    }

    fn capability(&self) -> OutboundCapability {
        OutboundCapability {
            tcp_supported: true,
            udp_supported: false,
            udp_mode: Some("tls-http-connect".to_string()),
            limitations: vec!["naive udp is not supported".to_string()],
        }
    }

    async fn connect(
        &self,
        destination: &Destination,
        timeout_ms: u64,
    ) -> anyhow::Result<BoxedStream> {
        let tcp = connect_tcp(&format!("{}:{}", self.server, self.port), timeout_ms).await?;
        let server_name = self.sni.as_deref().unwrap_or(&self.server).to_string();
        let mut tls_config = tls_client_config(self.skip_cert_verify)?;
        tls_config.alpn_protocols = if self.alpn.is_empty() {
            vec![b"http/1.1".to_vec()]
        } else {
            self.alpn
                .iter()
                .map(|value| value.as_bytes().to_vec())
                .collect()
        };
        let connector = TlsConnector::from(Arc::new(tls_config));
        let tls_server_name = ServerName::try_from(server_name)
            .map_err(|error| anyhow!("invalid naive server name: {error}"))?;
        let mut stream = timeout(
            Duration::from_millis(timeout_ms),
            connector.connect(tls_server_name, tcp),
        )
        .await
        .context("naive tls handshake timed out")?
        .context("naive tls handshake failed")?;
        establish_http_connect(
            &mut stream,
            destination,
            self.username.as_deref(),
            self.password.as_deref(),
            true,
        )
        .await?;
        Ok(Box::new(stream))
    }
}
