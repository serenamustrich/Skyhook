mod config;
mod control;
mod data;
mod key_method;
mod link;
mod packet;
mod push;
mod wrap;

use std::{
    net::SocketAddr,
    path::PathBuf,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, OnceLock,
    },
    task::{Context as TaskContext, Poll},
    time::{Duration, Instant},
};

use anyhow::{anyhow, Context};
use async_trait::async_trait;
use serde_json::json;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::Mutex,
    task::JoinHandle,
    time::{interval, timeout, MissedTickBehavior},
};
use ts_netstack_smoltcp::netsock::{
    TcpStream as NetstackTcpStream, UdpSocket as NetstackUdpSocket,
};

use crate::{config::OpenVpnOptions, routing::Destination};

use self::{
    config::OpenVpnProfile,
    control::{negotiate, process_tls_control, send_pending_tls, NegotiatedConnection},
    data::OPENVPN_PING,
    packet::OpCode,
};
use super::{
    ip_stack::{IpPacketIo, IpStackRuntime},
    udp::{KeyedRoundRobinSessionPool, UDP_SESSION_POOL_SIZE},
    BoxedStream, Outbound, OutboundCapability, UdpNatMode,
};

const DEFAULT_CONNECT_TIMEOUT_MS: u64 = 20_000;
const ACTOR_TICK: Duration = Duration::from_millis(200);

pub(super) struct OpenVpnOutbound {
    name: String,
    profile_path: Option<PathBuf>,
    inline_profile: Option<String>,
    options: OpenVpnOptions,
    profile: OnceLock<Result<Arc<OpenVpnProfile>, String>>,
    runtime: Mutex<Option<Arc<OpenVpnRuntime>>>,
    udp_sessions: Mutex<KeyedRoundRobinSessionPool<OpenVpnUdpSession>>,
}

struct OpenVpnRuntime {
    stack: Arc<IpStackRuntime>,
    healthy: Arc<AtomicBool>,
    task: JoinHandle<()>,
    remote: String,
    cipher: &'static str,
    routes: Vec<String>,
    dns: Vec<String>,
}

struct OpenVpnTcpStream {
    inner: NetstackTcpStream,
    _runtime: Arc<OpenVpnRuntime>,
}

struct OpenVpnUdpSession {
    _runtime: Arc<OpenVpnRuntime>,
    socket: NetstackUdpSocket,
    remote: SocketAddr,
}

impl OpenVpnOutbound {
    pub(super) fn new(
        name: String,
        profile_path: Option<PathBuf>,
        inline_profile: Option<String>,
        options: OpenVpnOptions,
    ) -> Self {
        Self {
            name,
            profile_path,
            inline_profile,
            options,
            profile: OnceLock::new(),
            runtime: Mutex::new(None),
            udp_sessions: Mutex::new(KeyedRoundRobinSessionPool::default()),
        }
    }

    fn profile(&self) -> anyhow::Result<Arc<OpenVpnProfile>> {
        self.profile
            .get_or_init(|| {
                OpenVpnProfile::load(
                    self.profile_path.as_deref(),
                    self.inline_profile.as_deref(),
                    &self.options,
                )
                .map(Arc::new)
                .map_err(|error| error.to_string())
            })
            .clone()
            .map_err(anyhow::Error::msg)
    }

    async fn runtime(&self, timeout_ms: u64) -> anyhow::Result<Arc<OpenVpnRuntime>> {
        let mut slot = self.runtime.lock().await;
        if let Some(runtime) = slot.as_ref() {
            if runtime.is_healthy() {
                return Ok(Arc::clone(runtime));
            }
        }
        *slot = None;
        *self.udp_sessions.lock().await = KeyedRoundRobinSessionPool::default();
        let profile = self.profile()?;
        let runtime = Arc::new(
            OpenVpnRuntime::connect(
                profile,
                timeout_ms.clamp(1, DEFAULT_CONNECT_TIMEOUT_MS),
            )
            .await?,
        );
        *slot = Some(Arc::clone(&runtime));
        Ok(runtime)
    }

    async fn udp_session(
        &self,
        runtime: Arc<OpenVpnRuntime>,
        destination: &Destination,
        timeout_ms: u64,
    ) -> anyhow::Result<Arc<Mutex<OpenVpnUdpSession>>> {
        let key = destination.authority();
        {
            let mut pool = self.udp_sessions.lock().await;
            let count = pool.len(&key);
            if let Some(session) = pool.next(&key) {
                if session.try_lock().is_ok() || count >= UDP_SESSION_POOL_SIZE {
                    return Ok(session);
                }
            }
        }
        let (socket, remote) = runtime.stack.udp_socket(destination, timeout_ms).await?;
        let session = Arc::new(Mutex::new(OpenVpnUdpSession {
            _runtime: runtime,
            socket,
            remote,
        }));
        let mut pool = self.udp_sessions.lock().await;
        if pool.len(&key) < UDP_SESSION_POOL_SIZE {
            pool.push(key, Arc::clone(&session));
            return Ok(session);
        }
        pool
            .next(&destination.authority())
            .ok_or_else(|| anyhow!("OpenVPN UDP session pool is unexpectedly empty"))
    }

    async fn remove_udp_session(
        &self,
        destination: &Destination,
        target: &Arc<Mutex<OpenVpnUdpSession>>,
    ) {
        self.udp_sessions
            .lock()
            .await
            .remove(&destination.authority(), target);
    }
}

#[async_trait]
impl Outbound for OpenVpnOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "openvpn"
    }

    fn capability(&self) -> OutboundCapability {
        match self.profile() {
            Ok(_) => OutboundCapability::tcp_udp("openvpn-layer3"),
            Err(error) => OutboundCapability::unsupported(error.to_string()),
        }
    }

    fn udp_nat_mode(&self) -> UdpNatMode {
        UdpNatMode::EndpointDependent
    }

    fn runtime_stats(&self) -> Option<serde_json::Value> {
        let runtime = self.runtime.try_lock().ok()?.as_ref().cloned()?;
        Some(json!({
            "healthy": runtime.is_healthy(),
            "remote": runtime.remote,
            "cipher": runtime.cipher,
            "routes": runtime.routes,
            "dns": runtime.dns,
        }))
    }

    async fn connect(
        &self,
        destination: &Destination,
        timeout_ms: u64,
    ) -> anyhow::Result<BoxedStream> {
        let runtime = self.runtime(timeout_ms).await?;
        let inner = runtime.stack.connect_tcp(destination, timeout_ms).await?;
        Ok(Box::new(OpenVpnTcpStream {
            inner,
            _runtime: runtime,
        }))
    }

    async fn udp_exchange(
        &self,
        destination: &Destination,
        payload: &[u8],
        timeout_ms: u64,
    ) -> anyhow::Result<Vec<u8>> {
        if payload.len() > 65_507 {
            return Err(anyhow!("OpenVPN UDP payload exceeds 65507 bytes"));
        }
        let runtime = self.runtime(timeout_ms).await?;
        let session = self
            .udp_session(Arc::clone(&runtime), destination, timeout_ms)
            .await?;
        let exchange = timeout(Duration::from_millis(timeout_ms), async {
            let session = session.lock().await;
            session
                .socket
                .send_to(session.remote, payload)
                .await
                .map_err(|error| anyhow!("OpenVPN netstack UDP send failed: {error}"))?;
            loop {
                let (source, response) = session
                    .socket
                    .recv_from_bytes()
                    .await
                    .map_err(|error| anyhow!("OpenVPN netstack UDP receive failed: {error}"))?;
                if source == session.remote {
                    return Ok::<_, anyhow::Error>(response.to_vec());
                }
            }
        })
        .await
        .context("OpenVPN UDP exchange timed out")?;
        if exchange.is_err() {
            self.remove_udp_session(destination, &session).await;
        }
        exchange
    }
}

impl OpenVpnRuntime {
    async fn connect(profile: Arc<OpenVpnProfile>, timeout_ms: u64) -> anyhow::Result<Self> {
        let deadline = tokio::time::Instant::now() + Duration::from_millis(timeout_ms);
        let mut errors = Vec::new();
        for remote_index in 0..profile.remotes.len() {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            match negotiate(&profile, remote_index, remaining.as_millis().max(1) as u64).await {
                Ok(connection) => return Self::start(profile, remote_index, connection).await,
                Err(error) => errors.push(format!(
                    "{}:{}: {error}",
                    profile.remotes[remote_index].host, profile.remotes[remote_index].port
                )),
            }
        }
        Err(anyhow!(
            "OpenVPN could not establish any configured remote: {}",
            errors.join("; ")
        ))
    }

    async fn start(
        profile: Arc<OpenVpnProfile>,
        remote_index: usize,
        connection: NegotiatedConnection,
    ) -> anyhow::Result<Self> {
        let mut dns = connection.push.dns.clone();
        for address in &profile.static_dns {
            if !dns.contains(address) {
                dns.push(*address);
            }
        }
        let dns_sockets = dns
            .iter()
            .map(|address| SocketAddr::new(*address, 53))
            .collect::<Vec<_>>();
        let (stack, packet_io) = IpStackRuntime::start(
            &connection.push.local_networks,
            dns_sockets,
            profile.remote_dns_resolve || !dns.is_empty(),
            usize::from(profile.mtu),
        )
        .await?;
        let cipher = connection.cipher.name();
        let routes = connection.push.routes.clone();
        let healthy = Arc::new(AtomicBool::new(true));
        let task = spawn_actor(
            connection,
            packet_io,
            Arc::clone(&stack),
            Arc::clone(&healthy),
            Arc::clone(&profile),
        );
        Ok(Self {
            stack,
            healthy,
            task,
            remote: format!(
                "{}:{}",
                profile.remotes[remote_index].host, profile.remotes[remote_index].port
            ),
            cipher,
            routes,
            dns: dns.iter().map(ToString::to_string).collect(),
        })
    }

    fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::Acquire)
            && self.stack.is_healthy()
            && !self.task.is_finished()
    }
}

fn spawn_actor(
    connection: NegotiatedConnection,
    packet_io: IpPacketIo,
    stack: Arc<IpStackRuntime>,
    healthy: Arc<AtomicBool>,
    profile: Arc<OpenVpnProfile>,
) -> JoinHandle<()> {
    let NegotiatedConnection {
        mut link,
        mut control,
        mut tls,
        mut data,
        push,
        ..
    } = connection;
    let IpPacketIo {
        mut outgoing,
        incoming,
    } = packet_io;
    tokio::spawn(async move {
        let ping_interval = push
            .ping_interval
            .unwrap_or(profile.ping_interval)
            .max(Duration::from_secs(1));
        let ping_restart = push
            .ping_restart
            .unwrap_or(profile.ping_restart)
            .max(ping_interval);
        let mut ping_tick = interval(ping_interval);
        ping_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut maintenance = interval(ACTOR_TICK);
        maintenance.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let started = Instant::now();
        let mut last_received = Instant::now();
        let mut tls_plaintext = Vec::new();
        let mut keep_running = true;

        while keep_running {
            tokio::select! {
                packet = outgoing.recv_async() => {
                    let Some(packet) = packet else { break };
                    if packet.len() > usize::from(profile.mtu) {
                        continue;
                    }
                    match data.encrypt(&packet) {
                        Ok(packet) if link.send(&packet).await.is_ok() => {}
                        _ => break,
                    }
                }
                received = link.receive() => {
                    let packet = match received {
                        Ok(packet) => packet,
                        Err(_) => break,
                    };
                    last_received = Instant::now();
                    let opcode = match packet.first().copied().map(OpCode::decode) {
                        Some(Ok(opcode)) => opcode,
                        _ => continue,
                    };
                    if opcode.is_data() {
                        match data.decrypt(&packet) {
                            Ok(plain) if plain == OPENVPN_PING => {}
                            Ok(plain) if valid_ip_packet(&plain, usize::from(profile.mtu)) => {
                                incoming.send_async(&plain).await;
                            }
                            Ok(_) => {}
                            Err(_) => continue,
                        }
                    } else {
                        let events = match control.receive(&mut link, &packet).await {
                            Ok(events) => events,
                            Err(_) => break,
                        };
                        if events.soft_reset {
                            break;
                        }
                        let messages = match process_tls_control(
                            &mut tls,
                            events.payloads,
                            &mut tls_plaintext,
                        ) {
                            Ok(messages) => messages,
                            Err(_) => break,
                        };
                        if messages.iter().any(|message| message.starts_with("AUTH_FAILED") || message.starts_with("RESTART")) {
                            break;
                        }
                        if send_pending_tls(&mut control, &mut link, &mut tls).await.is_err() {
                            break;
                        }
                    }
                }
                _ = ping_tick.tick() => {
                    match data.encrypt(&OPENVPN_PING) {
                        Ok(packet) if link.send(&packet).await.is_ok() => {}
                        _ => break,
                    }
                }
                _ = maintenance.tick() => {
                    if last_received.elapsed() >= ping_restart
                        || started.elapsed() >= profile.renegotiate_after
                        || control.retransmit_due(&mut link).await.is_err()
                    {
                        keep_running = false;
                    }
                }
            }
        }
        healthy.store(false, Ordering::Release);
        stack.mark_unhealthy();
    })
}

fn valid_ip_packet(packet: &[u8], mtu: usize) -> bool {
    !packet.is_empty()
        && packet.len() <= mtu
        && match packet[0] >> 4 {
            4 => packet.len() >= 20,
            6 => packet.len() >= 40,
            _ => false,
        }
}

impl Drop for OpenVpnRuntime {
    fn drop(&mut self) {
        self.healthy.store(false, Ordering::Release);
        self.stack.mark_unhealthy();
        self.task.abort();
    }
}

impl AsyncRead for OpenVpnTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut TaskContext<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}

impl AsyncWrite for OpenVpnTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut TaskContext<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.inner).poll_write(context, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut TaskContext<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut TaskContext<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncReadExt;

    use super::*;

    #[tokio::test]
    #[ignore = "requires an official OpenVPN server and SKYHOOK_OPENVPN_PROFILE"]
    async fn official_openvpn_server_tcp_interop() {
        let profile = std::env::var("SKYHOOK_OPENVPN_PROFILE")
            .expect("SKYHOOK_OPENVPN_PROFILE must point to the test client profile");
        let outbound = OpenVpnOutbound::new(
            "openvpn-interop".to_string(),
            Some(profile.into()),
            None,
            OpenVpnOptions::default(),
        );
        let mut stream = outbound
            .connect(&Destination::new("10.8.0.1", 7_000), 15_000)
            .await
            .expect("OpenVPN TCP interop connect failed");
        let mut response = [0u8; 18];
        timeout(Duration::from_secs(5), stream.read_exact(&mut response))
            .await
            .expect("OpenVPN TCP interop response timed out")
            .expect("OpenVPN TCP interop read failed");
        assert_eq!(&response, b"skyhook-openvpn-ok");
    }

    #[tokio::test]
    #[ignore = "requires an official OpenVPN UDP server and SKYHOOK_OPENVPN_UDP_PROFILE"]
    async fn official_openvpn_server_udp_interop() {
        let profile = std::env::var("SKYHOOK_OPENVPN_UDP_PROFILE")
            .expect("SKYHOOK_OPENVPN_UDP_PROFILE must point to the test client profile");
        let outbound = OpenVpnOutbound::new(
            "openvpn-interop-udp".to_string(),
            Some(profile.into()),
            None,
            OpenVpnOptions::default(),
        );
        let response = outbound
            .udp_exchange(
                &Destination::new("10.8.0.1", 7_001),
                b"skyhook-openvpn-udp-request",
                15_000,
            )
            .await
            .expect("OpenVPN UDP interop exchange failed");
        assert_eq!(response, b"skyhook-openvpn-udp");
    }
}
