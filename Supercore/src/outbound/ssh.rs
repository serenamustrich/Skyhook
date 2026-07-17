use std::{borrow::Cow, sync::Arc, time::Duration};

use anyhow::{anyhow, Context};
use async_trait::async_trait;
use russh::{client as ssh_client, ChannelMsg};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, DuplexStream},
    sync::Mutex,
};

use crate::routing::Destination;

use super::{
    target::destination_socket_addr,
    transports::{connect_tcp, run_dial_phase},
    BoxedStream, Outbound, OutboundCapability,
};

pub(super) struct SshOutbound {
    name: String,
    server: String,
    port: u16,
    username: String,
    password: Option<String>,
    private_key: Option<String>,
    private_key_passphrase: Option<String>,
    host_key: Vec<String>,
    host_key_algorithms: Vec<String>,
    skip_host_key_verify: bool,
    keepalive_interval_ms: u64,
    keepalive_max: usize,
    session: Mutex<Option<Arc<SshSession>>>,
}

impl SshOutbound {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        name: String,
        server: String,
        port: u16,
        username: String,
        password: Option<String>,
        private_key: Option<String>,
        private_key_passphrase: Option<String>,
        host_key: Vec<String>,
        host_key_algorithms: Vec<String>,
        skip_host_key_verify: bool,
        keepalive_interval_ms: u64,
        keepalive_max: usize,
    ) -> Self {
        Self {
            name,
            server,
            port,
            username,
            password,
            private_key,
            private_key_passphrase,
            host_key,
            host_key_algorithms,
            skip_host_key_verify,
            keepalive_interval_ms,
            keepalive_max,
            session: Mutex::new(None),
        }
    }

    fn validate_configuration(&self) -> anyhow::Result<()> {
        if self.server.trim().is_empty() || self.port == 0 {
            return Err(anyhow!("ssh server and port are required"));
        }
        if self.username.trim().is_empty() {
            return Err(anyhow!("ssh username is required"));
        }
        if self.password.as_deref().is_some_and(str::is_empty) {
            return Err(anyhow!("ssh password must not be empty"));
        }
        if self.private_key.as_deref().is_some_and(str::is_empty) {
            return Err(anyhow!("ssh private_key must not be empty"));
        }
        if self.password.as_deref().is_none_or(str::is_empty)
            && self.private_key.as_deref().is_none_or(str::is_empty)
        {
            return Err(anyhow!("ssh password or private_key is required"));
        }
        if !self.skip_host_key_verify && self.host_key.is_empty() {
            return Err(anyhow!(
                "ssh host key policy requires host_key or skip_host_key_verify=true"
            ));
        }
        parse_pinned_host_keys(&self.host_key)?;
        parse_host_key_algorithms(&self.host_key_algorithms)?;
        Ok(())
    }

    async fn session(&self, timeout_ms: u64) -> anyhow::Result<Arc<SshSession>> {
        let mut stored = self.session.lock().await;
        if let Some(session) = stored.as_ref().filter(|session| !session.is_closed()) {
            return Ok(Arc::clone(session));
        }
        let session = Arc::new(self.connect_session(timeout_ms).await?);
        *stored = Some(Arc::clone(&session));
        Ok(session)
    }

    async fn invalidate_session(&self, session: &Arc<SshSession>) {
        let mut stored = self.session.lock().await;
        if stored
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, session))
        {
            stored.take();
        }
    }

    async fn connect_session(&self, timeout_ms: u64) -> anyhow::Result<SshSession> {
        self.validate_configuration()?;
        let host_keys = parse_pinned_host_keys(&self.host_key)?;
        let host_key_algorithms = parse_host_key_algorithms(&self.host_key_algorithms)?;
        let mut config = ssh_client::Config {
            nodelay: true,
            keepalive_interval: (self.keepalive_interval_ms > 0)
                .then(|| Duration::from_millis(self.keepalive_interval_ms)),
            keepalive_max: self.keepalive_max,
            ..Default::default()
        };
        if !host_key_algorithms.is_empty() {
            config.preferred.key = Cow::Owned(host_key_algorithms.clone());
        }
        let policy = SshServerKeyPolicy {
            pinned: host_keys,
            algorithms: host_key_algorithms,
            skip_verify: self.skip_host_key_verify,
        };
        let endpoint = destination_socket_addr(&Destination::new(&self.server, self.port));
        let stream = connect_tcp(&endpoint, timeout_ms).await?;
        let mut handle = run_dial_phase(
            timeout_ms,
            "ssh transport handshake",
            ssh_client::connect_stream(Arc::new(config), stream, policy),
        )
        .await??;

        if let Some(private_key) = &self.private_key {
            let value = private_key.clone();
            let passphrase = self.private_key_passphrase.clone();
            let key = run_dial_phase(
                timeout_ms,
                "ssh private key load",
                tokio::task::spawn_blocking(move || {
                    load_private_key(&value, passphrase.as_deref())
                }),
            )
            .await??
            .context("failed to load ssh private key")?;
            let hash = run_dial_phase(
                timeout_ms,
                "ssh RSA algorithm negotiation",
                handle.best_supported_rsa_hash(),
            )
            .await??
            .flatten();
            let auth = run_dial_phase(
                timeout_ms,
                "ssh publickey authentication",
                handle.authenticate_publickey(
                    self.username.clone(),
                    russh::keys::key::PrivateKeyWithHashAlg::new(Arc::new(key), hash),
                ),
            )
            .await??;
            if !auth.success() {
                return Err(anyhow!("ssh publickey authentication was rejected"));
            }
        } else {
            let password = self
                .password
                .as_ref()
                .ok_or_else(|| anyhow!("ssh password is required"))?;
            let auth = run_dial_phase(
                timeout_ms,
                "ssh password authentication",
                handle.authenticate_password(self.username.clone(), password.clone()),
            )
            .await??;
            if !auth.success() {
                return Err(anyhow!("ssh password authentication was rejected"));
            }
        }

        Ok(SshSession { handle })
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
        if let Err(error) = self.validate_configuration() {
            return OutboundCapability::unsupported(error.to_string());
        }
        OutboundCapability::tcp_only("SSH direct-tcpip has no standard UDP relay")
    }

    async fn connect(
        &self,
        destination: &Destination,
        timeout_ms: u64,
    ) -> anyhow::Result<BoxedStream> {
        self.validate_configuration()?;
        for attempt in 0..2 {
            let session = self.session(timeout_ms).await?;
            let channel = run_dial_phase(
                timeout_ms,
                "ssh direct-tcpip channel open",
                session.handle.channel_open_direct_tcpip(
                    destination.host.clone(),
                    u32::from(destination.port),
                    "127.0.0.1".to_string(),
                    0u32,
                ),
            )
            .await?;
            match channel {
                Ok(channel) => {
                    return Ok(Box::new(spawn_ssh_channel_stream(session, channel)));
                }
                Err(error) if attempt == 0 => {
                    self.invalidate_session(&session).await;
                    tracing::debug!(error = %error, "rebuilding stale SSH session");
                }
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!(
                            "ssh direct-tcpip open failed for {}",
                            destination_socket_addr(destination)
                        )
                    });
                }
            }
        }
        Err(anyhow!("ssh session retry exhausted"))
    }
}

struct SshSession {
    handle: ssh_client::Handle<SshServerKeyPolicy>,
}

impl SshSession {
    fn is_closed(&self) -> bool {
        self.handle.is_closed()
    }
}

#[derive(Clone)]
struct SshServerKeyPolicy {
    pinned: Vec<PinnedSshHostKey>,
    algorithms: Vec<russh::keys::ssh_key::Algorithm>,
    skip_verify: bool,
}

impl ssh_client::Handler for SshServerKeyPolicy {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        if !self.algorithms.is_empty()
            && !self
                .algorithms
                .iter()
                .any(|algorithm| ssh_algorithms_match(algorithm, &server_public_key.algorithm()))
        {
            return Ok(false);
        }
        if self.skip_verify {
            return Ok(true);
        }
        let fingerprint = server_public_key
            .fingerprint(russh::keys::ssh_key::HashAlg::Sha256)
            .to_string();
        Ok(self.pinned.iter().any(|pinned| match pinned {
            PinnedSshHostKey::Fingerprint(expected) => expected == &fingerprint,
            PinnedSshHostKey::PublicKey(expected) => expected == server_public_key,
        }))
    }
}

#[derive(Clone)]
enum PinnedSshHostKey {
    Fingerprint(String),
    PublicKey(russh::keys::ssh_key::PublicKey),
}

fn parse_pinned_host_keys(values: &[String]) -> anyhow::Result<Vec<PinnedSshHostKey>> {
    values
        .iter()
        .map(|value| {
            let value = value.trim();
            if value.starts_with("SHA256:") {
                if value.len() <= "SHA256:".len() {
                    return Err(anyhow!("ssh host key fingerprint is empty"));
                }
                return Ok(PinnedSshHostKey::Fingerprint(value.to_string()));
            }
            let public_key = if value.split_ascii_whitespace().count() >= 2 {
                russh::keys::ssh_key::PublicKey::from_openssh(value)
                    .context("invalid OpenSSH host key")?
            } else {
                russh::keys::parse_public_key_base64(value)
                    .context("invalid base64 SSH host key")?
            };
            Ok(PinnedSshHostKey::PublicKey(public_key))
        })
        .collect()
}

fn parse_host_key_algorithms(
    values: &[String],
) -> anyhow::Result<Vec<russh::keys::ssh_key::Algorithm>> {
    values
        .iter()
        .map(|value| {
            let value = value.trim();
            if value.is_empty() {
                return Err(anyhow!("ssh host key algorithm must not be empty"));
            }
            russh::keys::ssh_key::Algorithm::new(value)
                .with_context(|| format!("unsupported SSH host key algorithm {value}"))
        })
        .collect()
}

fn ssh_algorithms_match(
    expected: &russh::keys::ssh_key::Algorithm,
    actual: &russh::keys::ssh_key::Algorithm,
) -> bool {
    (expected.clone().is_rsa() && actual.clone().is_rsa()) || expected == actual
}

fn load_private_key(
    value: &str,
    passphrase: Option<&str>,
) -> anyhow::Result<russh::keys::PrivateKey> {
    if value.contains("-----BEGIN OPENSSH PRIVATE KEY-----") {
        let key = russh::keys::PrivateKey::from_openssh(value)
            .context("invalid inline OpenSSH private key")?;
        if key.is_encrypted() {
            let passphrase = passphrase
                .ok_or_else(|| anyhow!("encrypted SSH private key requires a passphrase"))?;
            return key
                .decrypt(passphrase)
                .context("failed to decrypt inline SSH private key");
        }
        Ok(key)
    } else {
        russh::keys::load_secret_key(value, passphrase)
            .context("failed to load SSH private key file")
    }
}

fn spawn_ssh_channel_stream(
    session: Arc<SshSession>,
    mut channel: russh::Channel<ssh_client::Msg>,
) -> DuplexStream {
    let (app_side, relay_side) = tokio::io::duplex(256 * 1024);
    let (mut local_read, mut local_write) = tokio::io::split(relay_side);
    tokio::spawn(async move {
        let _session = session;
        let mut local_closed = false;
        let mut buffer = vec![0u8; 64 * 1024];
        loop {
            tokio::select! {
                read = local_read.read(&mut buffer), if !local_closed => {
                    match read {
                        Ok(0) => {
                            local_closed = true;
                            let _ = channel.eof().await;
                        }
                        Ok(length) => {
                            if channel.data(&buffer[..length]).await.is_err() {
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
                            let _ = local_write.shutdown().await;
                            break;
                        }
                        Some(_) => {}
                    }
                }
            }
        }
        let _ = channel.close().await;
    });
    app_side
}

#[cfg(test)]
mod tests {
    use super::{parse_host_key_algorithms, parse_pinned_host_keys, PinnedSshHostKey, SshOutbound};

    #[test]
    fn validates_host_key_fingerprints_and_algorithms() {
        let keys = parse_pinned_host_keys(&["SHA256:ZmFrZS1maW5nZXJwcmludA".to_string()])
            .expect("fingerprint");
        assert!(matches!(keys[0], PinnedSshHostKey::Fingerprint(_)));
        let algorithms =
            parse_host_key_algorithms(&["ssh-ed25519".to_string(), "rsa-sha2-256".to_string()])
                .expect("algorithms");
        assert_eq!(algorithms.len(), 2);
        assert!(parse_host_key_algorithms(&[String::new()]).is_err());
    }

    #[test]
    fn rejects_empty_private_key_instead_of_masking_password_authentication() {
        let outbound = SshOutbound::new(
            "ssh".to_string(),
            "127.0.0.1".to_string(),
            22,
            "user".to_string(),
            Some("password".to_string()),
            Some(String::new()),
            None,
            Vec::new(),
            Vec::new(),
            true,
            15_000,
            3,
        );
        assert!(outbound.validate_configuration().is_err());
    }
}
