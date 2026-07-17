use std::{
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicU16, Ordering},
        Arc,
    },
    task::{Context as TaskContext, Poll},
    time::Duration,
};

use anyhow::{anyhow, Context};
use async_trait::async_trait;
use base64::Engine;
use boringtun::noise::{Tunn, TunnResult};
use hickory_proto::{
    op::{Message, MessageType, OpCode, Query, ResponseCode},
    rr::{Name, RData, RecordType},
};
use ipnet::IpNet;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::UdpSocket,
    sync::Mutex,
    task::JoinHandle,
    time::timeout,
};
use ts_netstack_smoltcp::{
    netcore::{smoltcp::phy::Medium, Config as NetstackConfig, HasChannel, NetstackControl},
    netsock::{TcpStream as NetstackTcpStream, UdpSocket as NetstackUdpSocket},
    CreateSocket, Netstack, WakingPipe, WakingPipeDev, WakingPipeReceiver, WakingPipeSender,
};

use crate::{config::WireGuardPeerConfig, routing::Destination};

use super::{
    transports::random_u16,
    udp::{
        create_bound_udp, resolve_udp_socket_addr, KeyedRoundRobinSessionPool,
        UDP_SESSION_POOL_SIZE,
    },
    BoxedStream, Outbound, OutboundCapability, UdpNatMode,
};

const WIREGUARD_MIN_IPV4_MTU: usize = 576;
const WIREGUARD_MIN_IPV6_MTU: usize = 1_280;
const WIREGUARD_MAX_MTU: usize = 65_535;
const WIREGUARD_PACKET_OVERHEAD: usize = 256;
const WIREGUARD_PIPE_CAPACITY: usize = 256;
const WIREGUARD_MAX_PEERS: usize = 32;
const WIREGUARD_MAX_LOCAL_ADDRESSES: usize = 4;
const WIREGUARD_UDP_MAX_PAYLOAD: usize = 65_507;

pub(super) struct WireGuardOutbound {
    name: String,
    server: String,
    port: u16,
    private_key: String,
    public_key: String,
    preshared_key: Option<String>,
    ip: Vec<String>,
    ipv6: Vec<String>,
    allowed_ips: Vec<String>,
    reserved: Vec<u8>,
    mtu: u16,
    persistent_keepalive: Option<u16>,
    remote_dns_resolve: bool,
    dns: Vec<String>,
    peers: Vec<WireGuardPeerConfig>,
    runtime: Mutex<Option<Arc<WireGuardRuntime>>>,
    udp_sessions: Mutex<WireGuardUdpPool>,
}

type WireGuardUdpPool = KeyedRoundRobinSessionPool<WireGuardUdpSession>;

struct WireGuardUdpSession {
    _runtime: Arc<WireGuardRuntime>,
    socket: NetstackUdpSocket,
    remote: SocketAddr,
}

#[derive(Clone)]
struct ValidatedWireGuardConfig {
    private_key: [u8; 32],
    local_ips: Vec<IpAddr>,
    peers: Vec<ValidatedWireGuardPeer>,
    mtu: usize,
    remote_dns_resolve: bool,
    dns: Vec<SocketAddr>,
}

#[derive(Clone)]
struct ValidatedWireGuardPeer {
    server: String,
    port: u16,
    public_key: [u8; 32],
    preshared_key: Option<[u8; 32]>,
    allowed_ips: Vec<IpNet>,
    reserved: [u8; 3],
    persistent_keepalive: Option<u16>,
}

struct WireGuardRuntime {
    channel: ts_netstack_smoltcp::netcore::Channel,
    peers: Vec<Arc<WireGuardPeer>>,
    local_ips: Vec<IpAddr>,
    dns: Vec<SocketAddr>,
    remote_dns_resolve: bool,
    next_port: AtomicU16,
    healthy: Arc<AtomicBool>,
    tasks: Vec<JoinHandle<()>>,
}

struct WireGuardPeer {
    tunnel: Mutex<Tunn>,
    socket: Arc<UdpSocket>,
    allowed_ips: Vec<IpNet>,
    reserved: [u8; 3],
    packet_capacity: usize,
}

enum WireGuardAction {
    Done,
    Network(Vec<u8>),
    Tunnel { packet: Vec<u8>, source: IpAddr },
}

impl WireGuardOutbound {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        name: String,
        server: String,
        port: u16,
        private_key: String,
        public_key: String,
        preshared_key: Option<String>,
        ip: Vec<String>,
        ipv6: Vec<String>,
        allowed_ips: Vec<String>,
        reserved: Vec<u8>,
        mtu: u16,
        persistent_keepalive: Option<u16>,
        remote_dns_resolve: bool,
        dns: Vec<String>,
        peers: Vec<WireGuardPeerConfig>,
    ) -> Self {
        Self {
            name,
            server,
            port,
            private_key,
            public_key,
            preshared_key,
            ip,
            ipv6,
            allowed_ips,
            reserved,
            mtu,
            persistent_keepalive,
            remote_dns_resolve,
            dns,
            peers,
            runtime: Mutex::new(None),
            udp_sessions: Mutex::new(WireGuardUdpPool::default()),
        }
    }

    fn validated_configuration(&self) -> anyhow::Result<ValidatedWireGuardConfig> {
        let private_key = parse_wireguard_key(&self.private_key, "private_key")?;
        if private_key.iter().all(|byte| *byte == 0) {
            return Err(anyhow!("wireguard private_key must not be all zero"));
        }

        let mut local_ips = Vec::new();
        for value in &self.ip {
            let address = parse_wireguard_local_ip(value, false)?;
            local_ips.push(address);
        }
        for value in &self.ipv6 {
            let address = parse_wireguard_local_ip(value, true)?;
            local_ips.push(address);
        }
        local_ips.sort_unstable();
        local_ips.dedup();
        if local_ips.is_empty() {
            return Err(anyhow!("wireguard ip/ipv6 address is required"));
        }
        if local_ips.len() > WIREGUARD_MAX_LOCAL_ADDRESSES {
            return Err(anyhow!(
                "wireguard supports at most {WIREGUARD_MAX_LOCAL_ADDRESSES} local addresses"
            ));
        }

        let mtu = usize::from(self.mtu);
        let minimum_mtu = if local_ips.iter().any(IpAddr::is_ipv6) {
            WIREGUARD_MIN_IPV6_MTU
        } else {
            WIREGUARD_MIN_IPV4_MTU
        };
        if !(minimum_mtu..=WIREGUARD_MAX_MTU).contains(&mtu) {
            return Err(anyhow!(
                "wireguard mtu must be between {minimum_mtu} and {WIREGUARD_MAX_MTU}"
            ));
        }

        let mut peers = Vec::with_capacity(1 + self.peers.len());
        peers.push(validate_wireguard_peer(
            &self.server,
            self.port,
            &self.public_key,
            self.preshared_key.as_deref(),
            &self.allowed_ips,
            &self.reserved,
            self.persistent_keepalive,
            &local_ips,
            self.peers.is_empty(),
        )?);
        if self.peers.len() + 1 > WIREGUARD_MAX_PEERS {
            return Err(anyhow!(
                "wireguard supports at most {WIREGUARD_MAX_PEERS} peers"
            ));
        }
        for peer in &self.peers {
            peers.push(validate_wireguard_peer(
                &peer.server,
                peer.port,
                &peer.public_key,
                peer.preshared_key.as_deref(),
                &peer.allowed_ips,
                &peer.reserved,
                peer.persistent_keepalive,
                &local_ips,
                false,
            )?);
        }

        let dns = self
            .dns
            .iter()
            .map(|value| parse_wireguard_dns_server(value))
            .collect::<anyhow::Result<Vec<_>>>()?;
        if self.remote_dns_resolve && dns.is_empty() {
            return Err(anyhow!(
                "wireguard dns is required when remote_dns_resolve is enabled"
            ));
        }
        if self.remote_dns_resolve {
            for server in &dns {
                if !peers.iter().any(|peer| {
                    peer.allowed_ips
                        .iter()
                        .any(|net| net.contains(&server.ip()))
                }) {
                    return Err(anyhow!(
                        "wireguard DNS server {} is not covered by any allowed_ips route",
                        server.ip()
                    ));
                }
            }
        }

        Ok(ValidatedWireGuardConfig {
            private_key,
            local_ips,
            peers,
            mtu,
            remote_dns_resolve: self.remote_dns_resolve,
            dns,
        })
    }

    async fn runtime(
        &self,
        config: &ValidatedWireGuardConfig,
        timeout_ms: u64,
    ) -> anyhow::Result<Arc<WireGuardRuntime>> {
        let mut runtime = self.runtime.lock().await;
        if let Some(existing) = runtime.as_ref().filter(|existing| existing.is_healthy()) {
            return Ok(Arc::clone(existing));
        }
        runtime.take();
        let created = WireGuardRuntime::start(config, timeout_ms).await?;
        *runtime = Some(Arc::clone(&created));
        Ok(created)
    }

    async fn resolve_destination(
        &self,
        runtime: &Arc<WireGuardRuntime>,
        destination: &Destination,
        timeout_ms: u64,
    ) -> anyhow::Result<Vec<SocketAddr>> {
        if let Ok(address) = destination.host.parse::<IpAddr>() {
            let remote = SocketAddr::new(address, destination.port);
            runtime.validate_route(remote.ip())?;
            runtime.local_ip_for(remote.ip())?;
            return Ok(vec![remote]);
        }

        let addresses = if runtime.remote_dns_resolve {
            runtime
                .resolve_domain(&destination.host, timeout_ms)
                .await?
        } else {
            timeout(
                Duration::from_millis(timeout_ms),
                tokio::net::lookup_host((destination.host.as_str(), destination.port)),
            )
            .await
            .context("wireguard direct DNS resolve timed out")?
            .with_context(|| {
                format!(
                    "wireguard failed to resolve destination {}",
                    destination.host
                )
            })?
            .map(|address| address.ip())
            .collect()
        };

        let mut candidates = Vec::new();
        for address in addresses {
            if runtime.local_ip_for(address).is_ok() && runtime.validate_route(address).is_ok() {
                let remote = SocketAddr::new(address, destination.port);
                if !candidates.contains(&remote) {
                    candidates.push(remote);
                }
            }
        }
        if candidates.is_empty() {
            return Err(anyhow!(
                "wireguard destination {} did not resolve to a routed address",
                destination.host
            ));
        }
        Ok(candidates)
    }

    async fn udp_session(
        &self,
        runtime: Arc<WireGuardRuntime>,
        remote: SocketAddr,
    ) -> anyhow::Result<Arc<Mutex<WireGuardUdpSession>>> {
        let key = remote.to_string();
        {
            let mut pool = self.udp_sessions.lock().await;
            let count = pool.len(&key);
            if let Some(session) = pool.next(&key) {
                if session.try_lock().is_ok() || count >= UDP_SESSION_POOL_SIZE {
                    return Ok(session);
                }
            }
        }

        let local = runtime.next_local_endpoint(remote.ip())?;
        let socket = runtime
            .channel
            .udp_bind(local)
            .await
            .map_err(|error| anyhow!("wireguard netstack UDP bind failed: {error}"))?;
        let session = Arc::new(Mutex::new(WireGuardUdpSession {
            _runtime: runtime,
            socket,
            remote,
        }));
        let mut pool = self.udp_sessions.lock().await;
        if pool.len(&key) < UDP_SESSION_POOL_SIZE {
            pool.push(key, Arc::clone(&session));
            return Ok(session);
        }
        pool.next(&remote.to_string())
            .ok_or_else(|| anyhow!("wireguard UDP session pool is unexpectedly empty"))
    }

    async fn remove_udp_session(
        &self,
        remote: SocketAddr,
        target: &Arc<Mutex<WireGuardUdpSession>>,
    ) {
        self.udp_sessions
            .lock()
            .await
            .remove(&remote.to_string(), target);
    }
}

#[async_trait]
impl Outbound for WireGuardOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "wireguard"
    }

    fn capability(&self) -> OutboundCapability {
        match self.validated_configuration() {
            Ok(_) => OutboundCapability::tcp_udp("wireguard-userspace-netstack"),
            Err(error) => OutboundCapability::unsupported(error.to_string()),
        }
    }

    fn udp_nat_mode(&self) -> UdpNatMode {
        UdpNatMode::EndpointDependent
    }

    fn runtime_stats(&self) -> Option<serde_json::Value> {
        self.runtime.try_lock().ok().and_then(|runtime| {
            runtime.as_ref().map(|runtime| {
                serde_json::json!({
                    "healthy": runtime.is_healthy(),
                    "peers": runtime.peers.len(),
                    "remote_dns_resolve": runtime.remote_dns_resolve,
                })
            })
        })
    }

    async fn connect(
        &self,
        destination: &Destination,
        timeout_ms: u64,
    ) -> anyhow::Result<BoxedStream> {
        let config = self.validated_configuration()?;
        let runtime = self.runtime(&config, timeout_ms).await?;
        let candidates = self
            .resolve_destination(&runtime, destination, timeout_ms)
            .await?;
        let deadline = tokio::time::Instant::now() + Duration::from_millis(timeout_ms);
        let mut errors = Vec::new();
        for remote in candidates {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            let local = runtime.next_local_endpoint(remote.ip())?;
            match timeout(remaining, runtime.channel.tcp_connect(local, remote)).await {
                Ok(Ok(stream)) => {
                    return Ok(Box::new(WireGuardTcpStream {
                        inner: stream,
                        _runtime: runtime,
                    }));
                }
                Ok(Err(error)) => errors.push(format!("{remote}: {error}")),
                Err(_) => errors.push(format!("{remote}: timed out")),
            }
        }
        Err(anyhow!(
            "wireguard TCP connect to {} failed: {}",
            destination.authority(),
            errors.join("; ")
        ))
    }

    async fn udp_exchange(
        &self,
        destination: &Destination,
        payload: &[u8],
        timeout_ms: u64,
    ) -> anyhow::Result<Vec<u8>> {
        if payload.len() > WIREGUARD_UDP_MAX_PAYLOAD {
            return Err(anyhow!("wireguard UDP payload exceeds 65507 bytes"));
        }
        let config = self.validated_configuration()?;
        let runtime = self.runtime(&config, timeout_ms).await?;
        let remote = self
            .resolve_destination(&runtime, destination, timeout_ms)
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("wireguard UDP destination did not resolve"))?;
        let session = self.udp_session(runtime, remote).await?;
        let exchange = timeout(Duration::from_millis(timeout_ms), async {
            let session = session.lock().await;
            session
                .socket
                .send_to(session.remote, payload)
                .await
                .map_err(|error| anyhow!("wireguard netstack UDP send failed: {error}"))?;
            loop {
                let (source, response) =
                    session.socket.recv_from_bytes().await.map_err(|error| {
                        anyhow!("wireguard netstack UDP receive failed: {error}")
                    })?;
                if source == session.remote {
                    return Ok::<Vec<u8>, anyhow::Error>(response.to_vec());
                }
            }
        })
        .await
        .context("wireguard UDP exchange timed out")?;
        if exchange.is_err() {
            self.remove_udp_session(remote, &session).await;
        }
        exchange
    }
}

struct WireGuardTcpStream {
    inner: NetstackTcpStream,
    _runtime: Arc<WireGuardRuntime>,
}

impl AsyncRead for WireGuardTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for WireGuardTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl WireGuardRuntime {
    async fn start(
        config: &ValidatedWireGuardConfig,
        timeout_ms: u64,
    ) -> anyhow::Result<Arc<Self>> {
        let initial_port = random_ephemeral_port()?;
        let mut peers = Vec::with_capacity(config.peers.len());
        for (index, peer) in config.peers.iter().enumerate() {
            peers.push(Arc::new(
                WireGuardPeer::connect(
                    config.private_key,
                    peer,
                    index as u32 + 1,
                    config.mtu,
                    timeout_ms,
                )
                .await?,
            ));
        }

        let stack_config = NetstackConfig {
            mtu: config.mtu,
            command_channel_capacity: Some(256),
            udp_buffer_size: config.mtu.saturating_mul(16),
            tcp_buffer_size: config.mtu.saturating_mul(64),
            ..NetstackConfig::default()
        };
        let (stack_pipe, pipe) = WakingPipe::bounded(WIREGUARD_PIPE_CAPACITY);
        let stack = Netstack::new(
            WakingPipeDev {
                pipe: stack_pipe,
                medium: Medium::Ip,
                mtu: config.mtu,
            },
            stack_config,
        );
        let channel = stack.command_channel();
        let runner = stack.spawn_tokio();
        if let Err(error) = channel.set_ips(config.local_ips.iter().copied()).await {
            runner.abort();
            return Err(anyhow!("wireguard netstack address setup failed: {error}"));
        }

        for peer in &peers {
            if let Err(error) = initiate_wireguard_handshake(peer).await {
                runner.abort();
                return Err(error);
            }
        }

        let healthy = Arc::new(AtomicBool::new(true));
        let WakingPipe { rx, tx } = pipe;
        let mut tasks = vec![runner];
        for peer in &peers {
            tasks.push(spawn_wireguard_receiver(
                Arc::clone(peer),
                tx.clone(),
                Arc::clone(&healthy),
            ));
            tasks.push(spawn_wireguard_timer(
                Arc::clone(peer),
                Arc::clone(&healthy),
            ));
        }
        tasks.push(spawn_wireguard_router(
            peers.clone(),
            rx,
            Arc::clone(&healthy),
        ));
        Ok(Arc::new(Self {
            channel,
            peers,
            local_ips: config.local_ips.clone(),
            dns: config.dns.clone(),
            remote_dns_resolve: config.remote_dns_resolve,
            next_port: AtomicU16::new(initial_port),
            healthy,
            tasks,
        }))
    }

    fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::Acquire) && self.tasks.iter().all(|task| !task.is_finished())
    }

    fn validate_route(&self, address: IpAddr) -> anyhow::Result<()> {
        select_wireguard_peer(&self.peers, address)
            .map(|_| ())
            .ok_or_else(|| anyhow!("wireguard destination {address} is not covered by allowed_ips"))
    }

    fn local_ip_for(&self, remote: IpAddr) -> anyhow::Result<IpAddr> {
        self.local_ips
            .iter()
            .copied()
            .find(|local| local.is_ipv4() == remote.is_ipv4())
            .ok_or_else(|| {
                anyhow!(
                    "wireguard has no local {} address",
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
                "wireguard remote DNS failed for {host}: {}",
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
        self.validate_route(server.ip())?;
        let deadline = tokio::time::Instant::now() + Duration::from_millis(timeout_ms);
        let local = self.next_local_endpoint(server.ip())?;
        let socket = self
            .channel
            .udp_bind(local)
            .await
            .map_err(|error| anyhow!("wireguard DNS socket bind failed: {error}"))?;
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
                    .map_err(|error| anyhow!("wireguard DNS send failed: {error}"))?;
                loop {
                    let (source, response) = socket
                        .recv_from_bytes()
                        .await
                        .map_err(|error| anyhow!("wireguard DNS receive failed: {error}"))?;
                    if source == server {
                        return Ok::<_, anyhow::Error>(response);
                    }
                }
            },
        )
        .await
        .context("wireguard remote DNS query timed out")??;
        let mut response = validate_wireguard_dns_response(&response, id)?;
        if response.truncated() {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(anyhow!("wireguard DNS TCP fallback timed out"));
            }
            let local = self.next_local_endpoint(server.ip())?;
            let mut stream = timeout(remaining, self.channel.tcp_connect(local, server))
                .await
                .context("wireguard DNS TCP connect timed out")?
                .map_err(|error| anyhow!("wireguard DNS TCP connect failed: {error}"))?;
            let request_length = u16::try_from(request.len())
                .map_err(|_| anyhow!("wireguard DNS request is too large for TCP framing"))?;
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
            .context("wireguard DNS TCP fallback timed out")?
            .context("wireguard DNS TCP fallback failed")?;
            response = validate_wireguard_dns_response(&tcp_response, id)?;
            if response.truncated() {
                return Err(anyhow!("wireguard DNS TCP response is still truncated"));
            }
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

fn validate_wireguard_dns_response(response: &[u8], id: u16) -> anyhow::Result<Message> {
    let response = Message::from_vec(response)?;
    if response.id() != id || response.message_type() != MessageType::Response {
        return Err(anyhow!("wireguard DNS response header mismatch"));
    }
    if response.response_code() != ResponseCode::NoError {
        return Err(anyhow!(
            "wireguard DNS server returned {}",
            response.response_code()
        ));
    }
    Ok(response)
}

impl Drop for WireGuardRuntime {
    fn drop(&mut self) {
        self.healthy.store(false, Ordering::Release);
        for task in &self.tasks {
            task.abort();
        }
    }
}

impl WireGuardPeer {
    async fn connect(
        private_key: [u8; 32],
        config: &ValidatedWireGuardPeer,
        index: u32,
        mtu: usize,
        timeout_ms: u64,
    ) -> anyhow::Result<Self> {
        let remote = resolve_udp_socket_addr(&config.server, config.port, timeout_ms).await?;
        let socket = Arc::new(
            create_bound_udp(remote)
                .map_err(|error| anyhow!("wireguard UDP bind failed: {error}"))?,
        );
        socket
            .connect(remote)
            .await
            .map_err(|error| anyhow!("wireguard UDP connect failed: {error}"))?;
        let tunnel = Tunn::new(
            boringtun::x25519::StaticSecret::from(private_key),
            boringtun::x25519::PublicKey::from(config.public_key),
            config.preshared_key,
            config.persistent_keepalive.filter(|value| *value > 0),
            index,
            None,
        );
        Ok(Self {
            tunnel: Mutex::new(tunnel),
            socket,
            allowed_ips: config.allowed_ips.clone(),
            reserved: config.reserved,
            packet_capacity: mtu.saturating_add(WIREGUARD_PACKET_OVERHEAD),
        })
    }

    fn accepts_source(&self, source: IpAddr) -> bool {
        self.allowed_ips.iter().any(|net| net.contains(&source))
    }

    async fn send_network(&self, mut packet: Vec<u8>) -> anyhow::Result<()> {
        apply_wireguard_reserved(&mut packet, self.reserved)?;
        self.socket
            .send(&packet)
            .await
            .map_err(|error| anyhow!("wireguard UDP send failed: {error}"))?;
        Ok(())
    }
}

fn spawn_wireguard_router(
    peers: Vec<Arc<WireGuardPeer>>,
    mut packets: WakingPipeReceiver,
    healthy: Arc<AtomicBool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(packet) = packets.recv_async().await {
            let Some(destination) = Tunn::dst_address(&packet) else {
                continue;
            };
            let Some(peer) = select_wireguard_peer(&peers, destination) else {
                continue;
            };
            let mut output = vec![0u8; peer.packet_capacity.max(packet.len() + 32)];
            let action = {
                let mut tunnel = peer.tunnel.lock().await;
                own_wireguard_result(tunnel.encapsulate(&packet, &mut output))
            };
            match action {
                Ok(WireGuardAction::Network(packet)) => {
                    if peer.send_network(packet).await.is_err() {
                        healthy.store(false, Ordering::Release);
                        break;
                    }
                }
                Ok(WireGuardAction::Done) => {}
                Ok(WireGuardAction::Tunnel { .. }) => {
                    healthy.store(false, Ordering::Release);
                    break;
                }
                Err(_) => {
                    healthy.store(false, Ordering::Release);
                    break;
                }
            }
        }
    })
}

fn spawn_wireguard_receiver(
    peer: Arc<WireGuardPeer>,
    packets: WakingPipeSender,
    healthy: Arc<AtomicBool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut network = vec![0u8; peer.packet_capacity];
        loop {
            let len = match peer.socket.recv(&mut network).await {
                Ok(len) => len,
                Err(_) => {
                    healthy.store(false, Ordering::Release);
                    break;
                }
            };
            let mut incoming = network[..len].to_vec();
            clear_wireguard_reserved(&mut incoming);
            let mut first = Some(incoming);
            loop {
                let mut output = vec![0u8; peer.packet_capacity];
                let action = {
                    let mut tunnel = peer.tunnel.lock().await;
                    let input = first.take().unwrap_or_default();
                    own_wireguard_result(tunnel.decapsulate(None, &input, &mut output))
                };
                match action {
                    Ok(WireGuardAction::Network(packet)) => {
                        if peer.send_network(packet).await.is_err() {
                            healthy.store(false, Ordering::Release);
                            return;
                        }
                    }
                    Ok(WireGuardAction::Tunnel { packet, source }) => {
                        if peer.accepts_source(source) {
                            packets.send_async(&packet).await;
                        }
                    }
                    Ok(WireGuardAction::Done) => break,
                    Err(_) => break,
                }
            }
        }
    })
}

fn spawn_wireguard_timer(peer: Arc<WireGuardPeer>, healthy: Arc<AtomicBool>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(1));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            let mut output = vec![0u8; peer.packet_capacity];
            let action = {
                let mut tunnel = peer.tunnel.lock().await;
                own_wireguard_result(tunnel.update_timers(&mut output))
            };
            match action {
                Ok(WireGuardAction::Network(packet)) => {
                    if peer.send_network(packet).await.is_err() {
                        healthy.store(false, Ordering::Release);
                        break;
                    }
                }
                Ok(WireGuardAction::Done) => {}
                Ok(WireGuardAction::Tunnel { .. }) | Err(_) => {
                    healthy.store(false, Ordering::Release);
                    break;
                }
            }
        }
    })
}

async fn initiate_wireguard_handshake(peer: &Arc<WireGuardPeer>) -> anyhow::Result<()> {
    let mut output = vec![0u8; peer.packet_capacity];
    let action = {
        let mut tunnel = peer.tunnel.lock().await;
        own_wireguard_result(tunnel.encapsulate(&[], &mut output))
    }?;
    if let WireGuardAction::Network(packet) = action {
        peer.send_network(packet).await?;
    }
    Ok(())
}

fn own_wireguard_result(result: TunnResult<'_>) -> anyhow::Result<WireGuardAction> {
    match result {
        TunnResult::Done => Ok(WireGuardAction::Done),
        TunnResult::Err(error) => Err(anyhow!("wireguard tunnel error: {error:?}")),
        TunnResult::WriteToNetwork(packet) => Ok(WireGuardAction::Network(packet.to_vec())),
        TunnResult::WriteToTunnelV4(packet, source) => Ok(WireGuardAction::Tunnel {
            packet: packet.to_vec(),
            source: IpAddr::V4(source),
        }),
        TunnResult::WriteToTunnelV6(packet, source) => Ok(WireGuardAction::Tunnel {
            packet: packet.to_vec(),
            source: IpAddr::V6(source),
        }),
    }
}

fn select_wireguard_peer(
    peers: &[Arc<WireGuardPeer>],
    destination: IpAddr,
) -> Option<Arc<WireGuardPeer>> {
    peers
        .iter()
        .flat_map(|peer| {
            peer.allowed_ips
                .iter()
                .filter(move |net| net.contains(&destination))
                .map(move |net| (net.prefix_len(), peer))
        })
        .max_by_key(|(prefix, _)| *prefix)
        .map(|(_, peer)| Arc::clone(peer))
}

#[allow(clippy::too_many_arguments)]
fn validate_wireguard_peer(
    server: &str,
    port: u16,
    public_key: &str,
    preshared_key: Option<&str>,
    allowed_ips: &[String],
    reserved: &[u8],
    persistent_keepalive: Option<u16>,
    local_ips: &[IpAddr],
    allow_default_routes: bool,
) -> anyhow::Result<ValidatedWireGuardPeer> {
    if server.trim().is_empty() || port == 0 {
        return Err(anyhow!("wireguard peer server and port are required"));
    }
    let public_key = parse_wireguard_key(public_key, "public_key")?;
    if public_key.iter().all(|byte| *byte == 0) {
        return Err(anyhow!("wireguard public_key must not be all zero"));
    }
    let preshared_key = preshared_key
        .map(|value| parse_wireguard_key(value, "preshared_key"))
        .transpose()?;
    let reserved = parse_wireguard_reserved(reserved)?;
    let mut routes = allowed_ips
        .iter()
        .map(|value| {
            value
                .parse::<IpNet>()
                .with_context(|| format!("wireguard allowed_ips value '{value}' is invalid"))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    if routes.is_empty() {
        if !allow_default_routes {
            return Err(anyhow!(
                "wireguard additional peers must declare allowed_ips"
            ));
        }
        if local_ips.iter().any(IpAddr::is_ipv4) {
            routes.push("0.0.0.0/0".parse().expect("constant IPv4 route"));
        }
        if local_ips.iter().any(IpAddr::is_ipv6) {
            routes.push("::/0".parse().expect("constant IPv6 route"));
        }
    }
    Ok(ValidatedWireGuardPeer {
        server: server.trim().to_string(),
        port,
        public_key,
        preshared_key,
        allowed_ips: routes,
        reserved,
        persistent_keepalive,
    })
}

fn parse_wireguard_key(value: &str, label: &str) -> anyhow::Result<[u8; 32]> {
    let value = value.trim();
    if value.is_empty() {
        return Err(anyhow!("wireguard {label} is empty"));
    }
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(value)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(value))
        .map_err(|error| anyhow!("wireguard {label} is not valid base64: {error}"))?;
    decoded
        .try_into()
        .map_err(|_| anyhow!("wireguard {label} must be 32 bytes"))
}

fn parse_wireguard_local_ip(value: &str, expect_ipv6: bool) -> anyhow::Result<IpAddr> {
    let address = value
        .trim()
        .parse::<IpAddr>()
        .or_else(|_| value.trim().parse::<IpNet>().map(|network| network.addr()))
        .with_context(|| format!("wireguard tunnel address '{value}' is invalid"))?;
    if address.is_ipv6() != expect_ipv6 {
        return Err(anyhow!(
            "wireguard {} field contains wrong address family: {value}",
            if expect_ipv6 { "ipv6" } else { "ip" }
        ));
    }
    if address.is_unspecified() || address.is_multicast() {
        return Err(anyhow!("wireguard tunnel address '{value}' is not usable"));
    }
    Ok(address)
}

fn parse_wireguard_dns_server(value: &str) -> anyhow::Result<SocketAddr> {
    let value = value.trim();
    if let Ok(address) = value.parse::<SocketAddr>() {
        return Ok(address);
    }
    value
        .parse::<IpAddr>()
        .map(|address| SocketAddr::new(address, 53))
        .with_context(|| format!("wireguard DNS server '{value}' is invalid"))
}

fn parse_wireguard_reserved(value: &[u8]) -> anyhow::Result<[u8; 3]> {
    if value.is_empty() {
        return Ok([0; 3]);
    }
    value
        .try_into()
        .map_err(|_| anyhow!("wireguard reserved must be exactly 3 bytes"))
}

fn apply_wireguard_reserved(packet: &mut [u8], reserved: [u8; 3]) -> anyhow::Result<()> {
    if packet.len() < 4 {
        return Err(anyhow!("wireguard network packet is too short"));
    }
    packet[1..4].copy_from_slice(&reserved);
    Ok(())
}

fn clear_wireguard_reserved(packet: &mut [u8]) {
    if packet.len() >= 4 {
        packet[1..4].fill(0);
    }
}

fn random_ephemeral_port() -> anyhow::Result<u16> {
    Ok(49_152 + random_u16()? % (65_535 - 49_152))
}

#[cfg(test)]
mod tests {
    use std::{
        net::{Ipv4Addr, Ipv6Addr},
        sync::atomic::{AtomicUsize, Ordering},
    };

    use hickory_proto::rr::{rdata::A, Record};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    const CLIENT_IP: Ipv4Addr = Ipv4Addr::new(10, 77, 0, 2);
    const SERVER_IP: Ipv4Addr = Ipv4Addr::new(10, 77, 0, 1);
    const SERVER_TCP_PORT: u16 = 443;
    const SERVER_UDP_PORT: u16 = 5_353;
    const RESERVED: [u8; 3] = [7, 23, 91];

    fn test_dns_response(
        request: &[u8],
        server_ip: IpAddr,
        truncate_tcp_only: bool,
    ) -> Option<Vec<u8>> {
        let request = Message::from_vec(request).ok()?;
        let should_truncate = truncate_tcp_only
            && request
                .queries()
                .iter()
                .any(|query| query.name().to_ascii().trim_end_matches('.') == "tcp-only.test");
        let mut response = Message::new();
        response
            .set_id(request.id())
            .set_message_type(MessageType::Response)
            .set_op_code(request.op_code())
            .set_recursion_desired(request.recursion_desired())
            .set_recursion_available(true)
            .set_truncated(should_truncate)
            .set_response_code(ResponseCode::NoError);
        for query in request.queries() {
            response.add_query(query.clone());
            let name = query.name().to_ascii();
            if !should_truncate
                && matches!(name.trim_end_matches('.'), "service.test" | "tcp-only.test")
                && query.query_type() == RecordType::A
            {
                if let IpAddr::V4(server_ip) = server_ip {
                    response.add_answer(Record::from_rdata(
                        query.name().clone(),
                        60,
                        RData::A(A(server_ip)),
                    ));
                }
            }
        }
        response.to_vec().ok()
    }

    struct TestWireGuardServer {
        endpoint: SocketAddr,
        server_ip: IpAddr,
        client_ip: IpAddr,
        client_private_key: [u8; 32],
        server_public_key: [u8; 32],
        preshared_key: [u8; 32],
        encrypted_data_packets: Arc<AtomicUsize>,
        replay_rejections: Arc<AtomicUsize>,
        tasks: Vec<JoinHandle<()>>,
    }

    impl TestWireGuardServer {
        async fn start() -> anyhow::Result<Self> {
            Self::start_for(SERVER_IP.into(), CLIENT_IP.into(), 29).await
        }

        async fn start_for(
            server_ip: IpAddr,
            client_ip: IpAddr,
            server_key_byte: u8,
        ) -> anyhow::Result<Self> {
            let client_private_key = [11; 32];
            let server_private_key = [server_key_byte; 32];
            let preshared_key = [47; 32];
            let client_secret = boringtun::x25519::StaticSecret::from(client_private_key);
            let server_secret = boringtun::x25519::StaticSecret::from(server_private_key);
            let client_public_key = boringtun::x25519::PublicKey::from(&client_secret).to_bytes();
            let server_public_key = boringtun::x25519::PublicKey::from(&server_secret).to_bytes();

            let transport = Arc::new(UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?);
            let endpoint = transport.local_addr()?;
            let tunnel = Arc::new(Mutex::new(Tunn::new(
                server_secret,
                boringtun::x25519::PublicKey::from(client_public_key),
                Some(preshared_key),
                Some(1),
                10_001,
                None,
            )));
            let client_endpoint = Arc::new(Mutex::new(None::<SocketAddr>));
            let encrypted_data_packets = Arc::new(AtomicUsize::new(0));
            let replay_rejections = Arc::new(AtomicUsize::new(0));

            let stack_config = NetstackConfig {
                mtu: 1_280,
                command_channel_capacity: Some(64),
                udp_buffer_size: 32 * 1_280,
                tcp_buffer_size: 128 * 1_280,
                ..NetstackConfig::default()
            };
            let (stack_pipe, pipe) = WakingPipe::bounded(128);
            let stack = Netstack::new(
                WakingPipeDev {
                    pipe: stack_pipe,
                    medium: Medium::Ip,
                    mtu: 1_280,
                },
                stack_config,
            );
            let channel = stack.command_channel();
            let runner = stack.spawn_tokio();
            channel.set_ips([server_ip]).await?;

            let tcp_listener = channel
                .tcp_listen(SocketAddr::new(server_ip, SERVER_TCP_PORT))
                .await?;
            let udp_socket = channel
                .udp_bind(SocketAddr::new(server_ip, SERVER_UDP_PORT))
                .await?;
            let dns_socket = channel.udp_bind(SocketAddr::new(server_ip, 53)).await?;
            let dns_tcp_listener = channel.tcp_listen(SocketAddr::new(server_ip, 53)).await?;

            let WakingPipe { mut rx, tx } = pipe;
            let mut tasks = vec![runner];

            tasks.push(tokio::spawn(async move {
                while let Ok(mut stream) = tcp_listener.accept().await {
                    tokio::spawn(async move {
                        let mut length = [0u8; 4];
                        if stream.read_exact(&mut length).await.is_err() {
                            return;
                        }
                        let mut payload = vec![0; u32::from_be_bytes(length) as usize];
                        if stream.read_exact(&mut payload).await.is_err() {
                            return;
                        }
                        let _ = stream.write_all(&length).await;
                        let _ = stream.write_all(&payload).await;
                        let _ = stream.flush().await;
                    });
                }
            }));

            tasks.push(tokio::spawn(async move {
                while let Ok((source, payload)) = udp_socket.recv_from_bytes().await {
                    let _ = udp_socket.send_to(source, &payload).await;
                }
            }));

            tasks.push(tokio::spawn(async move {
                while let Ok((source, request)) = dns_socket.recv_from_bytes().await {
                    if let Some(response) = test_dns_response(&request, server_ip, true) {
                        let _ = dns_socket.send_to(source, &response).await;
                    }
                }
            }));

            tasks.push(tokio::spawn(async move {
                while let Ok(mut stream) = dns_tcp_listener.accept().await {
                    tokio::spawn(async move {
                        let mut length = [0u8; 2];
                        if stream.read_exact(&mut length).await.is_err() {
                            return;
                        }
                        let mut request = vec![0; usize::from(u16::from_be_bytes(length))];
                        if stream.read_exact(&mut request).await.is_err() {
                            return;
                        }
                        let Some(response) = test_dns_response(&request, server_ip, false) else {
                            return;
                        };
                        let Ok(length) = u16::try_from(response.len()) else {
                            return;
                        };
                        let _ = stream.write_all(&length.to_be_bytes()).await;
                        let _ = stream.write_all(&response).await;
                        let _ = stream.flush().await;
                    });
                }
            }));

            let receiver_transport = Arc::clone(&transport);
            let receiver_tunnel = Arc::clone(&tunnel);
            let receiver_client_endpoint = Arc::clone(&client_endpoint);
            let receiver_data_packets = Arc::clone(&encrypted_data_packets);
            let receiver_replay_rejections = Arc::clone(&replay_rejections);
            tasks.push(tokio::spawn(async move {
                let mut network = vec![0u8; 2_048];
                let mut replay_checked = false;
                loop {
                    let Ok((length, source)) = receiver_transport.recv_from(&mut network).await
                    else {
                        return;
                    };
                    *receiver_client_endpoint.lock().await = Some(source);
                    let mut incoming = network[..length].to_vec();
                    clear_wireguard_reserved(&mut incoming);
                    let is_data = incoming.first() == Some(&4);
                    if is_data {
                        receiver_data_packets.fetch_add(1, Ordering::Relaxed);
                    }

                    let mut first = Some(incoming.clone());
                    loop {
                        let mut output = vec![0u8; 2_048];
                        let action = {
                            let mut tunnel = receiver_tunnel.lock().await;
                            own_wireguard_result(tunnel.decapsulate(
                                Some(source.ip()),
                                &first.take().unwrap_or_default(),
                                &mut output,
                            ))
                        };
                        match action {
                            Ok(WireGuardAction::Network(mut packet)) => {
                                if apply_wireguard_reserved(&mut packet, RESERVED).is_err()
                                    || receiver_transport.send_to(&packet, source).await.is_err()
                                {
                                    return;
                                }
                            }
                            Ok(WireGuardAction::Tunnel { packet, .. }) => {
                                tx.send_async(&packet).await;
                            }
                            Ok(WireGuardAction::Done) => break,
                            Err(_) => break,
                        }
                    }

                    if is_data && !replay_checked {
                        replay_checked = true;
                        let mut output = vec![0u8; 2_048];
                        let duplicate = {
                            let mut tunnel = receiver_tunnel.lock().await;
                            own_wireguard_result(tunnel.decapsulate(
                                Some(source.ip()),
                                &incoming,
                                &mut output,
                            ))
                        };
                        if !matches!(duplicate, Ok(WireGuardAction::Tunnel { .. })) {
                            receiver_replay_rejections.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            }));

            let router_transport = Arc::clone(&transport);
            let router_tunnel = Arc::clone(&tunnel);
            let router_client_endpoint = Arc::clone(&client_endpoint);
            tasks.push(tokio::spawn(async move {
                while let Some(packet) = rx.recv_async().await {
                    let mut output = vec![0u8; 2_048];
                    let action = {
                        let mut tunnel = router_tunnel.lock().await;
                        own_wireguard_result(tunnel.encapsulate(&packet, &mut output))
                    };
                    if let Ok(WireGuardAction::Network(mut packet)) = action {
                        let Some(target) = *router_client_endpoint.lock().await else {
                            continue;
                        };
                        if apply_wireguard_reserved(&mut packet, RESERVED).is_err()
                            || router_transport.send_to(&packet, target).await.is_err()
                        {
                            return;
                        }
                    }
                }
            }));

            let timer_transport = Arc::clone(&transport);
            let timer_tunnel = Arc::clone(&tunnel);
            let timer_client_endpoint = Arc::clone(&client_endpoint);
            tasks.push(tokio::spawn(async move {
                let mut ticker = tokio::time::interval(Duration::from_secs(1));
                loop {
                    ticker.tick().await;
                    let mut output = vec![0u8; 2_048];
                    let action = {
                        let mut tunnel = timer_tunnel.lock().await;
                        own_wireguard_result(tunnel.update_timers(&mut output))
                    };
                    if let Ok(WireGuardAction::Network(mut packet)) = action {
                        let Some(target) = *timer_client_endpoint.lock().await else {
                            continue;
                        };
                        if apply_wireguard_reserved(&mut packet, RESERVED).is_err()
                            || timer_transport.send_to(&packet, target).await.is_err()
                        {
                            return;
                        }
                    }
                }
            }));

            Ok(Self {
                endpoint,
                server_ip,
                client_ip,
                client_private_key,
                server_public_key,
                preshared_key,
                encrypted_data_packets,
                replay_rejections,
                tasks,
            })
        }

        fn outbound(&self) -> WireGuardOutbound {
            WireGuardOutbound::new(
                "wg-test".to_string(),
                self.endpoint.ip().to_string(),
                self.endpoint.port(),
                base64::engine::general_purpose::STANDARD.encode(self.client_private_key),
                base64::engine::general_purpose::STANDARD.encode(self.server_public_key),
                Some(base64::engine::general_purpose::STANDARD.encode(self.preshared_key)),
                self.client_ip
                    .is_ipv4()
                    .then(|| self.client_ip.to_string())
                    .into_iter()
                    .collect(),
                self.client_ip
                    .is_ipv6()
                    .then(|| self.client_ip.to_string())
                    .into_iter()
                    .collect(),
                vec![self.route()],
                RESERVED.to_vec(),
                1_280,
                Some(1),
                true,
                vec![self.server_ip.to_string()],
                Vec::new(),
            )
        }

        fn route(&self) -> String {
            match self.server_ip {
                IpAddr::V4(address) => {
                    let [a, b, c, _] = address.octets();
                    format!("{a}.{b}.{c}.0/24")
                }
                IpAddr::V6(address) => {
                    let segments = address.segments();
                    format!(
                        "{:x}:{:x}:{:x}:{:x}::/64",
                        segments[0], segments[1], segments[2], segments[3]
                    )
                }
            }
        }

        fn peer_config(&self) -> WireGuardPeerConfig {
            WireGuardPeerConfig {
                server: self.endpoint.ip().to_string(),
                port: self.endpoint.port(),
                public_key: base64::engine::general_purpose::STANDARD
                    .encode(self.server_public_key),
                preshared_key: Some(
                    base64::engine::general_purpose::STANDARD.encode(self.preshared_key),
                ),
                allowed_ips: vec![self.route()],
                reserved: RESERVED.to_vec(),
                persistent_keepalive: Some(1),
            }
        }
    }

    impl Drop for TestWireGuardServer {
        fn drop(&mut self) {
            for task in &self.tasks {
                task.abort();
            }
        }
    }

    #[tokio::test]
    async fn real_wireguard_tcp_udp_dns_keepalive_and_replay_protection() -> anyhow::Result<()> {
        let server = TestWireGuardServer::start().await?;
        let outbound = server.outbound();
        assert!(outbound.capability().tcp_supported);
        assert!(outbound.capability().udp_supported);

        let payload = (0..96 * 1_024)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        let mut stream = timeout(
            Duration::from_secs(5),
            outbound.connect(
                &Destination::new(SERVER_IP.to_string(), SERVER_TCP_PORT),
                5_000,
            ),
        )
        .await??;
        stream
            .write_all(&(payload.len() as u32).to_be_bytes())
            .await?;
        stream.write_all(&payload).await?;
        stream.flush().await?;
        let mut response_length = [0u8; 4];
        stream.read_exact(&mut response_length).await?;
        let mut response = vec![0; u32::from_be_bytes(response_length) as usize];
        stream.read_exact(&mut response).await?;
        assert_eq!(response, payload);

        let udp_one = outbound
            .udp_exchange(
                &Destination::new(SERVER_IP.to_string(), SERVER_UDP_PORT),
                b"first datagram",
                5_000,
            )
            .await?;
        let udp_two = outbound
            .udp_exchange(
                &Destination::new(SERVER_IP.to_string(), SERVER_UDP_PORT),
                b"second datagram",
                5_000,
            )
            .await?;
        assert_eq!(udp_one, b"first datagram");
        assert_eq!(udp_two, b"second datagram");

        let mut domain_stream = outbound
            .connect(&Destination::new("service.test", SERVER_TCP_PORT), 5_000)
            .await?;
        domain_stream.write_all(&4u32.to_be_bytes()).await?;
        domain_stream.write_all(b"dns!").await?;
        domain_stream.flush().await?;
        let mut domain_response = [0u8; 8];
        domain_stream.read_exact(&mut domain_response).await?;
        assert_eq!(&domain_response[..4], &4u32.to_be_bytes());
        assert_eq!(&domain_response[4..], b"dns!");

        let mut tcp_dns_stream = outbound
            .connect(&Destination::new("tcp-only.test", SERVER_TCP_PORT), 5_000)
            .await?;
        tcp_dns_stream.write_all(&5u32.to_be_bytes()).await?;
        tcp_dns_stream.write_all(b"dns-t").await?;
        tcp_dns_stream.flush().await?;
        let mut tcp_dns_response = [0u8; 9];
        tcp_dns_stream.read_exact(&mut tcp_dns_response).await?;
        assert_eq!(&tcp_dns_response[..4], &5u32.to_be_bytes());
        assert_eq!(&tcp_dns_response[4..], b"dns-t");

        assert!(server.replay_rejections.load(Ordering::Relaxed) >= 1);
        let packets_before_keepalive = server.encrypted_data_packets.load(Ordering::Relaxed);
        tokio::time::sleep(Duration::from_millis(2_200)).await;
        assert!(
            server.encrypted_data_packets.load(Ordering::Relaxed) > packets_before_keepalive,
            "persistent keepalive did not emit another encrypted transport packet"
        );
        assert_eq!(
            outbound
                .runtime_stats()
                .and_then(|stats| stats["healthy"].as_bool()),
            Some(true)
        );
        Ok(())
    }

    #[tokio::test]
    async fn real_wireguard_multi_peer_uses_longest_allowed_ip_prefix() -> anyhow::Result<()> {
        let primary =
            TestWireGuardServer::start_for(SERVER_IP.into(), CLIENT_IP.into(), 29).await?;
        let secondary_ip = Ipv4Addr::new(10, 88, 0, 1);
        let secondary =
            TestWireGuardServer::start_for(secondary_ip.into(), CLIENT_IP.into(), 31).await?;
        let outbound = WireGuardOutbound::new(
            "wg-multi-peer".to_string(),
            primary.endpoint.ip().to_string(),
            primary.endpoint.port(),
            base64::engine::general_purpose::STANDARD.encode(primary.client_private_key),
            base64::engine::general_purpose::STANDARD.encode(primary.server_public_key),
            Some(base64::engine::general_purpose::STANDARD.encode(primary.preshared_key)),
            vec![CLIENT_IP.to_string()],
            Vec::new(),
            vec!["10.0.0.0/8".to_string()],
            RESERVED.to_vec(),
            1_280,
            Some(1),
            false,
            Vec::new(),
            vec![secondary.peer_config()],
        );

        let primary_response = outbound
            .udp_exchange(
                &Destination::new(SERVER_IP.to_string(), SERVER_UDP_PORT),
                b"primary peer",
                5_000,
            )
            .await?;
        let secondary_response = outbound
            .udp_exchange(
                &Destination::new(secondary_ip.to_string(), SERVER_UDP_PORT),
                b"longest prefix peer",
                5_000,
            )
            .await?;

        assert_eq!(primary_response, b"primary peer");
        assert_eq!(secondary_response, b"longest prefix peer");
        assert!(primary.encrypted_data_packets.load(Ordering::Relaxed) > 0);
        assert!(secondary.encrypted_data_packets.load(Ordering::Relaxed) > 0);
        assert_eq!(
            outbound
                .runtime_stats()
                .and_then(|stats| stats["peers"].as_u64()),
            Some(2)
        );
        Ok(())
    }

    #[tokio::test]
    async fn real_wireguard_ipv6_tcp_uses_the_ipv6_tunnel_address() -> anyhow::Result<()> {
        let server_ip = Ipv6Addr::new(0xfd42, 0x77, 0, 0, 0, 0, 0, 1);
        let client_ip = Ipv6Addr::new(0xfd42, 0x77, 0, 0, 0, 0, 0, 2);
        let server = TestWireGuardServer::start_for(server_ip.into(), client_ip.into(), 37).await?;
        let outbound = server.outbound();
        let mut stream = outbound
            .connect(
                &Destination::new(server_ip.to_string(), SERVER_TCP_PORT),
                5_000,
            )
            .await?;
        stream.write_all(&6u32.to_be_bytes()).await?;
        stream.write_all(b"ipv6!!").await?;
        stream.flush().await?;
        let mut response = [0u8; 10];
        stream.read_exact(&mut response).await?;
        assert_eq!(&response[..4], &6u32.to_be_bytes());
        assert_eq!(&response[4..], b"ipv6!!");
        Ok(())
    }

    #[test]
    fn local_endpoint_ports_remain_in_the_ephemeral_range_after_wrap() {
        let runtime = WireGuardRuntime {
            channel: panic_channel(),
            peers: Vec::new(),
            local_ips: vec![IpAddr::V4(CLIENT_IP)],
            dns: Vec::new(),
            remote_dns_resolve: false,
            next_port: AtomicU16::new(u16::MAX),
            healthy: Arc::new(AtomicBool::new(true)),
            tasks: Vec::new(),
        };
        assert_eq!(
            runtime
                .next_local_endpoint(IpAddr::V4(SERVER_IP))
                .unwrap()
                .port(),
            u16::MAX
        );
        assert_eq!(
            runtime
                .next_local_endpoint(IpAddr::V4(SERVER_IP))
                .unwrap()
                .port(),
            49_152
        );
    }

    fn panic_channel() -> ts_netstack_smoltcp::netcore::Channel {
        let stack = Netstack::new(
            WakingPipeDev {
                pipe: WakingPipe::bounded(1).0,
                medium: Medium::Ip,
                mtu: 1_280,
            },
            NetstackConfig::default(),
        );
        stack.command_channel()
    }
}
