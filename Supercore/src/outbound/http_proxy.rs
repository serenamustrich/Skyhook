use async_trait::async_trait;

use crate::routing::Destination;

use super::{
    transports::{connect_tcp, establish_http_connect},
    BoxedStream, Outbound,
};

pub(crate) struct HttpOutbound {
    name: String,
    server: String,
    port: u16,
    username: Option<String>,
    password: Option<String>,
}

impl HttpOutbound {
    pub(crate) fn new(
        name: String,
        server: String,
        port: u16,
        username: Option<String>,
        password: Option<String>,
    ) -> Self {
        Self {
            name,
            server,
            port,
            username,
            password,
        }
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

    async fn connect(
        &self,
        destination: &Destination,
        timeout_ms: u64,
    ) -> anyhow::Result<BoxedStream> {
        let proxy = format!("{}:{}", self.server, self.port);
        let mut stream = connect_tcp(&proxy, timeout_ms).await?;
        establish_http_connect(
            &mut stream,
            destination,
            self.username.as_deref(),
            self.password.as_deref(),
            false,
        )
        .await?;
        Ok(Box::new(stream))
    }
}
