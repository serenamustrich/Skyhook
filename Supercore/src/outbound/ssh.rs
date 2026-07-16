use std::{sync::Arc, time::Duration};

use anyhow::{anyhow, Context};
use async_trait::async_trait;
use russh::{client as ssh_client, ChannelMsg, Disconnect};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, DuplexStream},
    time::timeout,
};

use crate::routing::Destination;

use super::{BoxedStream, Outbound, OutboundCapability};

pub(super) struct SshOutbound {
    name: String,
    server: String,
    port: u16,
    username: String,
    password: Option<String>,
    private_key: Option<String>,
    private_key_passphrase: Option<String>,
}

impl SshOutbound {
    pub(super) fn new(
        name: String,
        server: String,
        port: u16,
        username: String,
        password: Option<String>,
        private_key: Option<String>,
        private_key_passphrase: Option<String>,
    ) -> Self {
        Self {
            name,
            server,
            port,
            username,
            password,
            private_key,
            private_key_passphrase,
        }
    }
}

struct AcceptAnySshServerKey;

impl ssh_client::Handler for AcceptAnySshServerKey {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

#[async_trait]
impl Outbound for SshOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "ssh"
    }

    fn capability(&self) -> OutboundCapability {
        OutboundCapability::tcp_only("SSH direct-tcpip has no standard UDP relay")
    }

    async fn connect(
        &self,
        destination: &Destination,
        timeout_ms: u64,
    ) -> anyhow::Result<BoxedStream> {
        let config = Arc::new(ssh_client::Config {
            nodelay: true,
            ..Default::default()
        });
        let mut session = timeout(
            Duration::from_millis(timeout_ms),
            ssh_client::connect(
                config,
                (self.server.as_str(), self.port),
                AcceptAnySshServerKey,
            ),
        )
        .await
        .context("ssh connect timed out")?
        .context("ssh connect failed")?;

        if let Some(private_key) = &self.private_key {
            let key =
                russh::keys::load_secret_key(private_key, self.private_key_passphrase.as_deref())
                    .with_context(|| format!("failed to load ssh private key {private_key}"))?;
            let hash = session
                .best_supported_rsa_hash()
                .await
                .context("failed to query ssh rsa hash support")?
                .flatten();
            let auth = session
                .authenticate_publickey(
                    self.username.clone(),
                    russh::keys::key::PrivateKeyWithHashAlg::new(Arc::new(key), hash),
                )
                .await
                .context("ssh publickey authentication failed")?;
            if !auth.success() {
                return Err(anyhow!("ssh publickey authentication was rejected"));
            }
        } else {
            let password = self.password.as_deref().ok_or_else(|| {
                anyhow!(
                    "ssh outbound {} is missing password or private_key",
                    self.name
                )
            })?;
            let auth = session
                .authenticate_password(self.username.clone(), password.to_string())
                .await
                .context("ssh password authentication failed")?;
            if !auth.success() {
                return Err(anyhow!("ssh password authentication was rejected"));
            }
        }

        let channel = timeout(
            Duration::from_millis(timeout_ms),
            session.channel_open_direct_tcpip(
                destination.host.clone(),
                u32::from(destination.port),
                "127.0.0.1".to_string(),
                0u32,
            ),
        )
        .await
        .context("ssh direct-tcpip open timed out")?
        .with_context(|| {
            format!(
                "ssh direct-tcpip open failed for {}",
                destination.authority()
            )
        })?;

        Ok(Box::new(spawn_ssh_channel_stream(session, channel)))
    }
}

fn spawn_ssh_channel_stream(
    session: ssh_client::Handle<AcceptAnySshServerKey>,
    mut channel: russh::Channel<ssh_client::Msg>,
) -> DuplexStream {
    let (app_side, relay_side) = tokio::io::duplex(64 * 1024);
    let (mut local_read, mut local_write) = tokio::io::split(relay_side);
    tokio::spawn(async move {
        let mut local_closed = false;
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            tokio::select! {
                read = local_read.read(&mut buf), if !local_closed => {
                    match read {
                        Ok(0) => {
                            local_closed = true;
                            let _ = channel.eof().await;
                        }
                        Ok(n) => {
                            if channel.data(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                message = channel.wait() => {
                    match message {
                        Some(ChannelMsg::Data { ref data }) => {
                            if local_write.write_all(data).await.is_err() {
                                break;
                            }
                        }
                        Some(ChannelMsg::Eof) | None => {
                            let _ = local_write.shutdown().await;
                            break;
                        }
                        Some(ChannelMsg::WindowAdjusted { .. }) => {}
                        Some(ChannelMsg::ExitStatus { .. }) | Some(ChannelMsg::ExitSignal { .. }) => {
                            break;
                        }
                        Some(_) => {}
                    }
                }
            }
        }
        let _ = channel.close().await;
        let _ = session
            .disconnect(Disconnect::ByApplication, "", "English")
            .await;
    });
    app_side
}
