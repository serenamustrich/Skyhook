use std::{
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicBool, AtomicU16, Ordering},
        Arc,
    },
    time::Duration,
};

use anyhow::{anyhow, Context};
use hickory_proto::{
    op::{Message, MessageType, OpCode, Query, ResponseCode},
    rr::{Name, RData, RecordType},
};
use ipnet::IpNet;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    task::JoinHandle,
    time::timeout,
};
use ts_netstack_smoltcp::{
    netcore::{smoltcp::phy::Medium, Config as NetstackConfig, HasChannel, NetstackControl},
    netsock::{TcpStream as NetstackTcpStream, UdpSocket as NetstackUdpSocket},
    CreateSocket, Netstack, WakingPipe, WakingPipeDev, WakingPipeReceiver, WakingPipeSender,
};

use crate::routing::Destination;

use super::transports::random_u16;

const PIPE_CAPACITY: usize = 256;

pub(super) struct IpPacketIo {
    pub(super) outgoing: WakingPipeReceiver,
    pub(super) incoming: WakingPipeSender,
}

pub(super) struct IpStackRuntime {
    channel: ts_netstack_smoltcp::netcore::Channel,
    local_ips: Vec<IpAddr>,
    dns: Vec<SocketAddr>,
    remote_dns_resolve: bool,
    next_port: AtomicU16,
    healthy: AtomicBool,
    runner: JoinHandle<()>,
}

impl IpStackRuntime {
    pub(super) async fn start(
        local_networks: &[IpNet],
        dns: Vec<SocketAddr>,
        remote_dns_resolve: bool,
        mtu: usize,
    ) -> anyhow::Result<(Arc<Self>, IpPacketIo)> {
        if local_networks.is_empty() {
            return Err(anyhow!("IP tunnel requires at least one local address"));
        }
        let local_ips = local_networks.iter().map(IpNet::addr).collect::<Vec<_>>();
        let stack_config = NetstackConfig {
            mtu,
            command_channel_capacity: Some(256),
            udp_buffer_size: mtu.saturating_mul(16),
            tcp_buffer_size: mtu.saturating_mul(64),
            ..NetstackConfig::default()
        };
        let (stack_pipe, pipe) = WakingPipe::bounded(PIPE_CAPACITY);
        let stack = Netstack::new(
            WakingPipeDev {
                pipe: stack_pipe,
                medium: Medium::Ip,
                mtu,
            },
            stack_config,
        );
        let channel = stack.command_channel();
        let runner = stack.spawn_tokio();
        if let Err(error) = channel.set_ips(local_ips.iter().copied()).await {
            runner.abort();
            return Err(anyhow!("IP tunnel netstack address setup failed: {error}"));
        }
        let WakingPipe { rx, tx } = pipe;
        Ok((
            Arc::new(Self {
                channel,
                local_ips,
                dns,
                remote_dns_resolve,
                next_port: AtomicU16::new(random_ephemeral_port()?),
                healthy: AtomicBool::new(true),
                runner,
            }),
            IpPacketIo {
                outgoing: rx,
                incoming: tx,
            },
        ))
    }

    pub(super) fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::Acquire) && !self.runner.is_finished()
    }

    pub(super) fn mark_unhealthy(&self) {
        self.healthy.store(false, Ordering::Release);
    }

    pub(super) async fn connect_tcp(
        &self,
        destination: &Destination,
        timeout_ms: u64,
    ) -> anyhow::Result<NetstackTcpStream> {
        let candidates = self.resolve_destination(destination, timeout_ms).await?;
        let deadline = tokio::time::Instant::now() + Duration::from_millis(timeout_ms);
        let mut errors = Vec::new();
        for remote in candidates {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            let local = self.next_local_endpoint(remote.ip())?;
            match timeout(remaining, self.channel.tcp_connect(local, remote)).await {
                Ok(Ok(stream)) => return Ok(stream),
                Ok(Err(error)) => errors.push(format!("{remote}: {error}")),
                Err(_) => errors.push(format!("{remote}: timed out")),
            }
        }
        Err(anyhow!(
            "IP tunnel TCP connect to {} failed: {}",
            destination.authority(),
            errors.join("; ")
        ))
    }

    pub(super) async fn udp_socket(
        &self,
        destination: &Destination,
        timeout_ms: u64,
    ) -> anyhow::Result<(NetstackUdpSocket, SocketAddr)> {
        let remote = self
            .resolve_destination(destination, timeout_ms)
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("IP tunnel UDP destination did not resolve"))?;
        let local = self.next_local_endpoint(remote.ip())?;
        let socket = self
            .channel
            .udp_bind(local)
            .await
            .map_err(|error| anyhow!("IP tunnel netstack UDP bind failed: {error}"))?;
        Ok((socket, remote))
    }

    #[cfg(test)]
    pub(super) async fn tcp_listener(
        &self,
        local: SocketAddr,
    ) -> anyhow::Result<ts_netstack_smoltcp::netsock::TcpListener> {
        self.channel
            .tcp_listen(local)
            .await
            .map_err(|error| anyhow!("IP tunnel test TCP listen failed: {error}"))
    }

    #[cfg(test)]
    pub(super) async fn bound_udp(&self, local: SocketAddr) -> anyhow::Result<NetstackUdpSocket> {
        self.channel
            .udp_bind(local)
            .await
            .map_err(|error| anyhow!("IP tunnel test UDP bind failed: {error}"))
    }

    async fn resolve_destination(
        &self,
        destination: &Destination,
        timeout_ms: u64,
    ) -> anyhow::Result<Vec<SocketAddr>> {
        if let Ok(address) = destination.host.parse::<IpAddr>() {
            self.local_ip_for(address)?;
            return Ok(vec![SocketAddr::new(address, destination.port)]);
        }
        let addresses = if self.remote_dns_resolve {
            if self.dns.is_empty() {
                return Err(anyhow!(
                    "remote DNS resolution is enabled but no MASQUE DNS server is configured"
                ));
            }
            self.resolve_domain(&destination.host, timeout_ms).await?
        } else {
            timeout(
                Duration::from_millis(timeout_ms),
                tokio::net::lookup_host((destination.host.as_str(), destination.port)),
            )
            .await
            .context("IP tunnel destination resolve timed out")?
            .with_context(|| format!("failed to resolve {}", destination.host))?
            .map(|address| address.ip())
            .collect()
        };
        let mut candidates = Vec::new();
        for address in addresses {
            if self.local_ip_for(address).is_ok() {
                let remote = SocketAddr::new(address, destination.port);
                if !candidates.contains(&remote) {
                    candidates.push(remote);
                }
            }
        }
        if candidates.is_empty() {
            return Err(anyhow!(
                "IP tunnel destination {} resolved to no address matching its local IP families",
                destination.host
            ));
        }
        Ok(candidates)
    }

    fn local_ip_for(&self, remote: IpAddr) -> anyhow::Result<IpAddr> {
        self.local_ips
            .iter()
            .copied()
            .find(|local| local.is_ipv4() == remote.is_ipv4())
            .ok_or_else(|| {
                anyhow!(
                    "IP tunnel has no local {} address",
                    if remote.is_ipv4() { "IPv4" } else { "IPv6" }
                )
            })
    }

    fn next_local_endpoint(&self, remote: IpAddr) -> anyhow::Result<SocketAddr> {
        let local = self.local_ip_for(remote)?;
        const EPHEMERAL_START: u16 = 49_152;
        const EPHEMERAL_COUNT: u16 = u16::MAX - EPHEMERAL_START + 1;
        let sequence = self.next_port.fetch_add(1, Ordering::Relaxed);
        let port = EPHEMERAL_START + sequence.wrapping_sub(EPHEMERAL_START) % EPHEMERAL_COUNT;
        Ok(SocketAddr::new(local, port))
    }

    async fn resolve_domain(&self, host: &str, timeout_ms: u64) -> anyhow::Result<Vec<IpAddr>> {
        let mut addresses = Vec::new();
        let mut errors = Vec::new();
        for record_type in [RecordType::A, RecordType::AAAA] {
            if (record_type == RecordType::A && !self.local_ips.iter().any(IpAddr::is_ipv4))
                || (record_type == RecordType::AAAA && !self.local_ips.iter().any(IpAddr::is_ipv6))
            {
                continue;
            }
            for server in &self.dns {
                match self.dns_query(*server, host, record_type, timeout_ms).await {
                    Ok(found) => {
                        addresses.extend(found);
                        break;
                    }
                    Err(error) => errors.push(format!("{server}: {error}")),
                }
            }
        }
        addresses.sort_unstable();
        addresses.dedup();
        if addresses.is_empty() {
            return Err(anyhow!(
                "IP tunnel remote DNS failed for {host}: {}",
                errors.join("; ")
            ));
        }
        Ok(addresses)
    }

    async fn dns_query(
        &self,
        server: SocketAddr,
        host: &str,
        record_type: RecordType,
        timeout_ms: u64,
    ) -> anyhow::Result<Vec<IpAddr>> {
        self.local_ip_for(server.ip())?;
        let deadline = tokio::time::Instant::now() + Duration::from_millis(timeout_ms);
        let socket = self
            .channel
            .udp_bind(self.next_local_endpoint(server.ip())?)
            .await
            .map_err(|error| anyhow!("IP tunnel DNS socket bind failed: {error}"))?;
        let id = random_u16()?;
        let mut message = Message::new();
        message
            .set_id(id)
            .set_message_type(MessageType::Query)
            .set_op_code(OpCode::Query)
            .set_recursion_desired(true)
            .add_query(Query::query(Name::from_ascii(host)?, record_type));
        let request = message.to_vec()?;
        let response = timeout(
            deadline.saturating_duration_since(tokio::time::Instant::now()),
            async {
                socket
                    .send_to(server, &request)
                    .await
                    .map_err(|error| anyhow!("IP tunnel DNS send failed: {error}"))?;
                loop {
                    let (source, response) = socket
                        .recv_from_bytes()
                        .await
                        .map_err(|error| anyhow!("IP tunnel DNS receive failed: {error}"))?;
                    if source == server {
                        return Ok::<_, anyhow::Error>(response);
                    }
                }
            },
        )
        .await
        .context("IP tunnel remote DNS query timed out")??;
        let mut response = validate_dns_response(&response, id)?;
        if response.truncated() {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(anyhow!("IP tunnel DNS TCP fallback timed out"));
            }
            let mut stream = timeout(
                remaining,
                self.channel
                    .tcp_connect(self.next_local_endpoint(server.ip())?, server),
            )
            .await
            .context("IP tunnel DNS TCP connect timed out")?
            .map_err(|error| anyhow!("IP tunnel DNS TCP connect failed: {error}"))?;
            let request_length = u16::try_from(request.len())
                .map_err(|_| anyhow!("IP tunnel DNS request is too large"))?;
            let tcp_response = timeout(
                deadline.saturating_duration_since(tokio::time::Instant::now()),
                async {
                    stream.write_all(&request_length.to_be_bytes()).await?;
                    stream.write_all(&request).await?;
                    stream.flush().await?;
                    let mut length = [0u8; 2];
                    stream.read_exact(&mut length).await?;
                    let mut response = vec![0; usize::from(u16::from_be_bytes(length))];
                    stream.read_exact(&mut response).await?;
                    Ok::<_, std::io::Error>(response)
                },
            )
            .await
            .context("IP tunnel DNS TCP fallback timed out")??;
            response = validate_dns_response(&tcp_response, id)?;
        }
        Ok(response
            .answers()
            .iter()
            .chain(response.additionals().iter())
            .filter_map(|record| match record.data() {
                RData::A(address) => Some(IpAddr::V4(address.0)),
                RData::AAAA(address) => Some(IpAddr::V6(address.0)),
                _ => None,
            })
            .collect())
    }
}

impl Drop for IpStackRuntime {
    fn drop(&mut self) {
        self.healthy.store(false, Ordering::Release);
        self.runner.abort();
    }
}

pub(super) fn parse_local_network(value: &str, ipv6: bool) -> anyhow::Result<IpNet> {
    let value = value.trim();
    let normalized = if value.contains('/') {
        value.to_string()
    } else if ipv6 {
        format!("{value}/128")
    } else {
        format!("{value}/32")
    };
    let network = normalized
        .parse::<IpNet>()
        .with_context(|| format!("invalid IP tunnel local address {value}"))?;
    if network.addr().is_ipv6() != ipv6 {
        return Err(anyhow!(
            "IP tunnel {} field contains the wrong address family",
            if ipv6 { "ipv6" } else { "ip" }
        ));
    }
    Ok(network)
}

pub(super) fn parse_dns_server(value: &str) -> anyhow::Result<SocketAddr> {
    let value = value.trim();
    if let Ok(address) = value.parse::<SocketAddr>() {
        return Ok(address);
    }
    let address = value
        .trim_matches(|character| character == '[' || character == ']')
        .parse::<IpAddr>()
        .with_context(|| format!("MASQUE DNS server {value} must be an IP address"))?;
    Ok(SocketAddr::new(address, 53))
}

fn random_ephemeral_port() -> anyhow::Result<u16> {
    Ok(49_152 + random_u16()? % (u16::MAX - 49_152 + 1))
}

fn validate_dns_response(response: &[u8], id: u16) -> anyhow::Result<Message> {
    let response = Message::from_vec(response)?;
    if response.id() != id || response.message_type() != MessageType::Response {
        return Err(anyhow!("IP tunnel DNS response header mismatch"));
    }
    if response.response_code() != ResponseCode::NoError {
        return Err(anyhow!(
            "IP tunnel DNS server returned {}",
            response.response_code()
        ));
    }
    Ok(response)
}
