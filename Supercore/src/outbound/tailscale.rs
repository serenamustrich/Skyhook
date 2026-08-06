use std::{
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use ::tailscale::{Config, Device};
use anyhow::{anyhow, Context};
use async_trait::async_trait;
use tokio::{
    net::lookup_host,
    sync::OnceCell,
    time::{timeout, timeout_at, Instant},
};

use crate::routing::Destination;

use super::traits::{BoxedStream, Outbound, OutboundCapability, UdpNatMode};

const DEFAULT_TIMEOUT_MS: u64 = 15_000;

/// A native userspace Tailscale device used as a Skyhook outbound.
///
/// The device owns its identity and control-plane state in the configured state file. It never
/// shells out to the system Tailscale client and never changes the host routing table.
pub(crate) struct TailscaleOutbound {
    name: String,
    auth_key: Option<String>,
    state_file: PathBuf,
    control_server_url: Option<String>,
    hostname: Option<String>,
    tags: Vec<String>,
    device: OnceCell<Arc<Device>>,
}

impl TailscaleOutbound {
    pub(crate) fn new(
        name: String,
        auth_key: Option<String>,
        state_file: Option<PathBuf>,
        control_server_url: Option<String>,
        hostname: Option<String>,
        tags: Vec<String>,
    ) -> anyhow::Result<Self> {
        if let Some(value) = control_server_url.as_deref() {
            value
                .parse::<url::Url>()
                .with_context(|| format!("invalid Tailscale control URL '{value}'"))?;
        }
        Ok(Self {
            state_file: state_file.unwrap_or_else(|| default_state_file(&name)),
            name,
            auth_key,
            control_server_url,
            hostname,
            tags,
            device: OnceCell::new(),
        })
    }

    async fn device(&self, timeout_ms: u64) -> anyhow::Result<Arc<Device>> {
        let timeout_ms = if timeout_ms == 0 {
            DEFAULT_TIMEOUT_MS
        } else {
            timeout_ms
        };
        let deadline = Instant::now() + Duration::from_millis(timeout_ms);
        let device = timeout_at(deadline, self.device.get_or_try_init(|| async {
            // tailscale-rs intentionally requires this opt-in marker until its security audit is
            // complete. Skyhook owns the userspace integration, so set it for this process only.
            std::env::set_var("TS_RS_EXPERIMENT", "this_is_unstable_software");

            let mut config = Config::default_with_key_file(&self.state_file)
                .await
                .map_err(|error| anyhow!("load Tailscale state failed: {error}"))?;
            if let Some(value) = self.control_server_url.as_deref() {
                config.control_server_url = value
                    .parse()
                    .with_context(|| format!("invalid Tailscale control URL '{value}'"))?;
            }
            config.client_name = Some("Skyhook".to_string());
            config.requested_hostname = self.hostname.clone();
            config.requested_tags = self.tags.clone();

            Device::new(&config, self.auth_key.clone())
                .await
                .map(Arc::new)
                .map_err(|error| anyhow!("initialize Tailscale userspace device failed: {error}"))
        }))
        .await
        .map_err(|_| anyhow!("Tailscale device initialization timed out"))??;
        Ok(Arc::clone(device))
    }

    async fn resolve_target(
        &self,
        destination: &Destination,
        timeout_ms: u64,
    ) -> anyhow::Result<SocketAddr> {
        if let Ok(ip) = destination.host.parse::<IpAddr>() {
            return Ok(SocketAddr::new(ip, destination.port));
        }
        let timeout_ms = if timeout_ms == 0 {
            DEFAULT_TIMEOUT_MS
        } else {
            timeout_ms
        };
        let mut addresses = timeout(
            Duration::from_millis(timeout_ms),
            lookup_host((destination.host.as_str(), destination.port)),
        )
        .await
        .context("Tailscale destination DNS resolve timed out")??;
        addresses
            .next()
            .ok_or_else(|| anyhow!("Tailscale destination {} resolved to no addresses", destination.host))
    }

    async fn local_ip_for(device: &Device, target: SocketAddr) -> anyhow::Result<IpAddr> {
        if target.is_ipv4() {
            Ok(device
                .ipv4_addr()
                .await
                .map_err(|error| anyhow!("Tailscale IPv4 address unavailable: {error}"))?
                .into())
        } else {
            Ok(device
                .ipv6_addr()
                .await
                .map_err(|error| anyhow!("Tailscale IPv6 address unavailable: {error}"))?
                .into())
        }
    }
}

#[async_trait]
impl Outbound for TailscaleOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "tailscale"
    }

    fn capability(&self) -> OutboundCapability {
        OutboundCapability::tcp_udp("tailscale-userspace")
    }

    fn udp_nat_mode(&self) -> UdpNatMode {
        UdpNatMode::EndpointIndependent
    }

    async fn connect(
        &self,
        destination: &Destination,
        timeout_ms: u64,
    ) -> anyhow::Result<BoxedStream> {
        let timeout_ms = if timeout_ms == 0 {
            DEFAULT_TIMEOUT_MS
        } else {
            timeout_ms
        };
        let deadline = Instant::now() + Duration::from_millis(timeout_ms);
        let device = self.device(timeout_ms).await?;
        let target = self.resolve_target(destination, timeout_ms).await?;
        let stream = timeout_at(deadline, device.tcp_connect(target))
            .await
            .context("Tailscale TCP connect timed out")?
            .map_err(|error| anyhow!("Tailscale TCP connect to {target} failed: {error}"))?;
        Ok(Box::new(stream))
    }

    async fn udp_exchange(
        &self,
        destination: &Destination,
        payload: &[u8],
        timeout_ms: u64,
    ) -> anyhow::Result<Vec<u8>> {
        let timeout_ms = if timeout_ms == 0 {
            DEFAULT_TIMEOUT_MS
        } else {
            timeout_ms
        };
        let deadline = Instant::now() + Duration::from_millis(timeout_ms);
        let device = self.device(timeout_ms).await?;
        let target = self.resolve_target(destination, timeout_ms).await?;
        let local_ip = Self::local_ip_for(&device, target).await?;
        let socket = timeout_at(deadline, device.udp_bind((local_ip, 0).into()))
            .await
            .context("Tailscale UDP bind timed out")?
            .map_err(|error| anyhow!("Tailscale UDP bind failed: {error}"))?;
        timeout_at(deadline, socket.send_to(target, payload))
            .await
            .context("Tailscale UDP send timed out")?
            .map_err(|error| anyhow!("Tailscale UDP send to {target} failed: {error}"))?;
        let (source, response) = timeout_at(deadline, socket.recv_from_bytes())
            .await
            .context("Tailscale UDP receive timed out")?
            .map_err(|error| anyhow!("Tailscale UDP receive from {target} failed: {error}"))?;
        if source != target {
            return Err(anyhow!(
                "Tailscale UDP response came from unexpected endpoint {source}, expected {target}"
            ));
        }
        Ok(response.to_vec())
    }
}

fn default_state_file(name: &str) -> PathBuf {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    home.join(".config")
        .join("skyhook")
        .join("tailscale")
        .join(format!("{}.json", sanitize_name(name)))
}

fn sanitize_name(value: &str) -> String {
    let mut output = value
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_') { ch } else { '_' })
        .collect::<String>();
    if output.is_empty() {
        output.push_str("default");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_state_path_is_scoped_to_skyhook() {
        let path = default_state_file("skyhook/ts node");
        assert!(path.ends_with("skyhook/tailscale/skyhook_ts_node.json"));
    }

    #[test]
    fn validates_control_server_url_before_runtime_creation() {
        let error = match TailscaleOutbound::new(
            "tailscale".to_string(),
            None,
            None,
            Some("not a url".to_string()),
            None,
            Vec::new(),
        ) {
            Ok(_) => panic!("invalid URL must fail during construction"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("invalid Tailscale control URL"));
    }
}
