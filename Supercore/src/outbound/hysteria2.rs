use std::{
    any::Any,
    collections::HashMap,
    io::{Error, ErrorKind, IoSliceMut},
    net::SocketAddr,
    pin::Pin,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex as StdMutex,
    },
    task::{Context as TaskContext, Poll},
    time::{Duration, Instant},
};

use anyhow::{anyhow, Context};
use async_trait::async_trait;
use blake2::{digest::VariableOutput, Blake2bVar};
use bytes::Bytes;
use quinn_proto::RttEstimator;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    sync::{mpsc, Mutex as TokioMutex},
    task::JoinHandle,
};

use crate::routing::Destination;

use super::{
    target::destination_socket_addr,
    transports::{
        connect_quic_endpoint, create_quic_endpoint, encode_quic_varint,
        quic_client_config_with_controller, random_u16, random_u32, read_quic_varint,
        read_quic_varint_from_slice, resolve_quic_remote, run_dial_phase, SharedConnectionPool,
    },
    udp::{
        create_bound_std_udp, udp_session_key, FragmentReassembler, KeyedRoundRobinSessionPool,
        UDP_SESSION_POOL_SIZE,
    },
    BoxedStream, Outbound, OutboundCapability, UdpNatMode,
};

const HYSTERIA2_MAX_UDP_PACKET_SIZE: usize = 65_535;
const HYSTERIA2_UDP_ROUTE_CAPACITY: usize = 64;

pub(super) struct Hysteria2Outbound {
    name: String,
    server: String,
    port: u16,
    password: String,
    sni: Option<String>,
    skip_cert_verify: bool,
    obfs: Option<String>,
    obfs_password: Option<String>,
    alpn: Option<String>,
    up: Option<String>,
    down: Option<String>,
    congestion_control: Option<String>,
    connection: SharedConnectionPool<Hysteria2Connection>,
    udp_sessions: TokioMutex<Hysteria2UdpPool>,
}

type Hysteria2UdpPool = KeyedRoundRobinSessionPool<Hysteria2UdpSession>;

struct Hysteria2UdpSession {
    shared: Arc<Hysteria2Connection>,
    session_id: u32,
    next_packet_id: u16,
    incoming: mpsc::Receiver<Vec<u8>>,
}

impl Drop for Hysteria2UdpSession {
    fn drop(&mut self) {
        self.shared.unregister_udp_session(self.session_id);
    }
}

struct ValidatedHysteria2Config {
    obfs: Option<Hysteria2ObfsConfig>,
    upload_bytes_per_second: Option<u64>,
    download_bytes_per_second: Option<u64>,
    congestion_control: Option<String>,
}

struct Hysteria2RateControllerFactory {
    rate: Arc<AtomicU64>,
    fallback: Arc<dyn quinn::congestion::ControllerFactory + Send + Sync>,
}

impl quinn::congestion::ControllerFactory for Hysteria2RateControllerFactory {
    fn build(
        self: Arc<Self>,
        now: Instant,
        current_mtu: u16,
    ) -> Box<dyn quinn::congestion::Controller> {
        Box::new(Hysteria2RateController {
            fallback: Arc::clone(&self.fallback).build(now, current_mtu),
            rate: Arc::clone(&self.rate),
            current_mtu,
            rtt: Duration::from_millis(100),
        })
    }
}

struct Hysteria2RateController {
    fallback: Box<dyn quinn::congestion::Controller>,
    rate: Arc<AtomicU64>,
    current_mtu: u16,
    rtt: Duration,
}

impl Hysteria2RateController {
    fn rate_window(&self) -> Option<u64> {
        let rate = self.rate.load(Ordering::Relaxed);
        if rate == 0 {
            return None;
        }
        let rtt_nanos = self.rtt.as_nanos().clamp(5_000_000, 10_000_000_000);
        let bandwidth_delay_product = u128::from(rate)
            .saturating_mul(rtt_nanos)
            .saturating_div(1_000_000_000)
            .saturating_mul(4)
            .saturating_div(5);
        Some(
            bandwidth_delay_product
                .max(u128::from(self.current_mtu) * 10)
                .min(u128::from(u32::MAX)) as u64,
        )
    }
}

impl quinn::congestion::Controller for Hysteria2RateController {
    fn on_sent(&mut self, now: Instant, bytes: u64, last_packet_number: u64) {
        self.fallback.on_sent(now, bytes, last_packet_number);
    }

    fn on_ack(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        app_limited: bool,
        rtt: &RttEstimator,
    ) {
        self.rtt = rtt.get();
        self.fallback.on_ack(now, sent, bytes, app_limited, rtt);
    }

    fn on_end_acks(
        &mut self,
        now: Instant,
        in_flight: u64,
        app_limited: bool,
        largest_packet_num_acked: Option<u64>,
    ) {
        self.fallback
            .on_end_acks(now, in_flight, app_limited, largest_packet_num_acked);
    }

    fn on_congestion_event(
        &mut self,
        now: Instant,
        sent: Instant,
        is_persistent_congestion: bool,
        lost_bytes: u64,
    ) {
        self.fallback
            .on_congestion_event(now, sent, is_persistent_congestion, lost_bytes);
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.current_mtu = new_mtu;
        self.fallback.on_mtu_update(new_mtu);
    }

    fn window(&self) -> u64 {
        self.rate_window().unwrap_or_else(|| self.fallback.window())
    }

    fn metrics(&self) -> quinn::congestion::ControllerMetrics {
        let mut metrics = self.fallback.metrics();
        if let Some(window) = self.rate_window() {
            metrics.congestion_window = window;
            metrics.pacing_rate = Some(self.rate.load(Ordering::Relaxed).saturating_mul(8));
        }
        metrics
    }

    fn clone_box(&self) -> Box<dyn quinn::congestion::Controller> {
        Box::new(Self {
            fallback: self.fallback.clone_box(),
            rate: Arc::clone(&self.rate),
            current_mtu: self.current_mtu,
            rtt: self.rtt,
        })
    }

    fn initial_window(&self) -> u64 {
        self.rate_window()
            .unwrap_or_else(|| self.fallback.initial_window())
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Hysteria2ObfsKind {
    Salamander,
    Gecko,
}

#[derive(Debug, Clone)]
struct Hysteria2ObfsConfig {
    kind: Hysteria2ObfsKind,
    key: Vec<u8>,
}

#[async_trait]
impl Outbound for Hysteria2Outbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "hysteria2"
    }

    fn capability(&self) -> OutboundCapability {
        match self.validated_configuration() {
            Ok(config) => OutboundCapability::tcp_udp(match config.obfs.map(|item| item.kind) {
                Some(Hysteria2ObfsKind::Salamander) => "quic-datagram-salamander-session-pool",
                Some(Hysteria2ObfsKind::Gecko) => "quic-datagram-gecko-session-pool",
                None => "quic-datagram-session-pool",
            }),
            Err(error) => OutboundCapability::unsupported(error.to_string()),
        }
    }

    fn udp_nat_mode(&self) -> UdpNatMode {
        UdpNatMode::EndpointIndependent
    }

    async fn connect(
        &self,
        destination: &Destination,
        timeout_ms: u64,
    ) -> anyhow::Result<BoxedStream> {
        let config = self.validated_configuration()?;
        let connection = self.hysteria2_connection(&config, timeout_ms).await?;
        let (mut send, mut recv) = run_dial_phase(timeout_ms, "hysteria2 open stream", async {
            connection.connection.open_bi().await
        })
        .await?
        .context("hysteria2 failed to open bidirectional stream")?;
        let request = build_hysteria2_tcp_request(destination)?;
        run_dial_phase(timeout_ms, "hysteria2 tcp request write", async {
            send.write_all(&request).await?;
            send.flush().await
        })
        .await??;
        run_dial_phase(
            timeout_ms,
            "hysteria2 tcp response read",
            read_hysteria2_tcp_response(&mut recv),
        )
        .await??;
        Ok(Box::new(Hysteria2TcpStream {
            _shared: connection,
            recv,
            send,
        }))
    }

    async fn udp_exchange(
        &self,
        destination: &Destination,
        payload: &[u8],
        timeout_ms: u64,
    ) -> anyhow::Result<Vec<u8>> {
        if payload.len() > HYSTERIA2_MAX_UDP_PACKET_SIZE {
            return Err(anyhow!("hysteria2 udp payload exceeds 65535 bytes"));
        }
        let config = self.validated_configuration()?;
        let key = udp_session_key(
            self.kind(),
            self.name(),
            self.udp_nat_mode(),
            Some(destination),
        );
        let session_handle = self
            .hysteria2_udp_session(&key, &config, timeout_ms)
            .await?;

        let exchange = {
            let mut session = session_handle.lock().await;
            async {
                let packet_id = session.next_packet_id;
                session.next_packet_id = session.next_packet_id.wrapping_add(1);
                let messages = build_hysteria2_udp_messages(
                    session.session_id,
                    packet_id,
                    destination,
                    payload,
                    session.shared.connection.max_datagram_size(),
                )?;
                for message in messages {
                    run_dial_phase(timeout_ms, "hysteria2 udp send", async {
                        session
                            .shared
                            .connection
                            .send_datagram_wait(Bytes::from(message))
                            .await
                    })
                    .await?
                    .map_err(|error| anyhow!("hysteria2 udp send failed: {error}"))?;
                }
                run_dial_phase(timeout_ms, "hysteria2 udp receive", async {
                    let mut reassembly = Hysteria2UdpReassembly::default();
                    loop {
                        let datagram = session
                            .incoming
                            .recv()
                            .await
                            .ok_or_else(|| anyhow!("hysteria2 udp dispatcher stopped"))?;
                        if let Some(payload) = parse_hysteria2_udp_message(
                            &datagram,
                            session.session_id,
                            &mut reassembly,
                        )? {
                            return Ok::<Vec<u8>, anyhow::Error>(payload);
                        }
                    }
                })
                .await?
            }
            .await
        };
        if exchange.is_err() {
            self.remove_hysteria2_udp_session(&key, &session_handle)
                .await;
        }
        exchange
    }
}

impl Hysteria2Outbound {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        name: String,
        server: String,
        port: u16,
        password: String,
        sni: Option<String>,
        skip_cert_verify: bool,
        obfs: Option<String>,
        obfs_password: Option<String>,
        alpn: Option<String>,
        up: Option<String>,
        down: Option<String>,
        congestion_control: Option<String>,
    ) -> Self {
        Self {
            name,
            server,
            port,
            password,
            sni,
            skip_cert_verify,
            obfs,
            obfs_password,
            alpn,
            up,
            down,
            congestion_control,
            connection: SharedConnectionPool::default(),
            udp_sessions: TokioMutex::new(Hysteria2UdpPool::default()),
        }
    }

    async fn hysteria2_connection(
        &self,
        config: &ValidatedHysteria2Config,
        timeout_ms: u64,
    ) -> anyhow::Result<Arc<Hysteria2Connection>> {
        self.connection
            .get_or_connect(
                |connection| connection.connection.close_reason().is_none(),
                || {
                    open_hysteria2_connection(
                        &self.server,
                        self.port,
                        self.sni.as_deref(),
                        self.skip_cert_verify,
                        &self.password,
                        self.alpn.as_deref(),
                        config.obfs.as_ref(),
                        config.upload_bytes_per_second,
                        config.download_bytes_per_second,
                        config.congestion_control.as_deref(),
                        timeout_ms,
                    )
                },
            )
            .await
    }

    async fn hysteria2_udp_session(
        &self,
        key: &str,
        config: &ValidatedHysteria2Config,
        timeout_ms: u64,
    ) -> anyhow::Result<Arc<TokioMutex<Hysteria2UdpSession>>> {
        {
            let mut pool = self.udp_sessions.lock().await;
            let session_count = pool.len(key);
            if let Some(session) = pool.next(key) {
                let available = session.try_lock().is_ok();
                if available || session_count >= UDP_SESSION_POOL_SIZE {
                    return Ok(session);
                }
            }
        }

        let connection = self.hysteria2_connection(config, timeout_ms).await?;
        if !connection.udp_supported {
            return Err(anyhow!("hysteria2 server does not support udp relay"));
        }
        let (session_id, incoming) = connection.register_udp_session()?;
        let session = Arc::new(TokioMutex::new(Hysteria2UdpSession {
            shared: connection,
            session_id,
            next_packet_id: random_u16()?,
            incoming,
        }));
        let mut pool = self.udp_sessions.lock().await;
        if pool.len(key) < UDP_SESSION_POOL_SIZE {
            pool.push(key.to_string(), Arc::clone(&session));
            return Ok(session);
        }
        pool.next(key)
            .ok_or_else(|| anyhow!("hysteria2 UDP session pool is unexpectedly empty"))
    }

    fn validated_configuration(&self) -> anyhow::Result<ValidatedHysteria2Config> {
        if self.server.trim().is_empty() || self.port == 0 {
            return Err(anyhow!("hysteria2 server and port must be configured"));
        }
        if self.password.is_empty() {
            return Err(anyhow!("hysteria2 password is empty"));
        }
        validate_hysteria2_text_list("hysteria2 alpn", self.alpn.as_deref())?;
        let congestion_control = validate_hysteria2_congestion(self.congestion_control.as_deref())?;
        Ok(ValidatedHysteria2Config {
            obfs: hysteria2_obfs_config(self.obfs.as_deref(), self.obfs_password.as_deref())?,
            upload_bytes_per_second: parse_hysteria2_bandwidth(self.up.as_deref(), "upload")?,
            download_bytes_per_second: parse_hysteria2_bandwidth(self.down.as_deref(), "download")?,
            congestion_control,
        })
    }

    async fn remove_hysteria2_udp_session(
        &self,
        key: &str,
        target: &Arc<TokioMutex<Hysteria2UdpSession>>,
    ) {
        let mut pool = self.udp_sessions.lock().await;
        pool.remove(key, target);
    }
}

struct Hysteria2Connection {
    _endpoint: quinn::Endpoint,
    connection: quinn::Connection,
    _h3_sender: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    h3_driver: JoinHandle<()>,
    udp_driver: JoinHandle<()>,
    udp_routes: Arc<StdMutex<HashMap<u32, mpsc::Sender<Vec<u8>>>>>,
    udp_supported: bool,
    _server_receive_rate: Option<u64>,
}

impl Hysteria2Connection {
    fn register_udp_session(&self) -> anyhow::Result<(u32, mpsc::Receiver<Vec<u8>>)> {
        for _ in 0..64 {
            let session_id = random_u32()?;
            let mut routes = self
                .udp_routes
                .lock()
                .map_err(|_| anyhow!("hysteria2 udp route lock poisoned"))?;
            if routes.contains_key(&session_id) {
                continue;
            }
            let (sender, receiver) = mpsc::channel(HYSTERIA2_UDP_ROUTE_CAPACITY);
            routes.insert(session_id, sender);
            return Ok((session_id, receiver));
        }
        Err(anyhow!(
            "hysteria2 could not allocate a unique UDP session id"
        ))
    }

    fn unregister_udp_session(&self, session_id: u32) {
        if let Ok(mut routes) = self.udp_routes.lock() {
            routes.remove(&session_id);
        }
    }
}

impl Drop for Hysteria2Connection {
    fn drop(&mut self) {
        self.connection
            .close(quinn::VarInt::from_u32(0), b"supercore close");
        self.h3_driver.abort();
        self.udp_driver.abort();
    }
}

#[derive(Debug)]
struct SalamanderUdpSocket {
    inner: Arc<dyn quinn::AsyncUdpSocket>,
    key: Arc<[u8]>,
    kind: Hysteria2ObfsKind,
    gecko: StdMutex<GeckoState>,
}

impl SalamanderUdpSocket {
    fn new(inner: Arc<dyn quinn::AsyncUdpSocket>, key: &[u8], kind: Hysteria2ObfsKind) -> Self {
        Self {
            inner,
            key: Arc::from(key.to_vec().into_boxed_slice()),
            kind,
            gecko: StdMutex::new(GeckoState::default()),
        }
    }

    fn encode_salamander_packet(&self, payload: &[u8]) -> std::io::Result<Vec<u8>> {
        let mut salt = [0u8; 8];
        getrandom::fill(&mut salt)
            .map_err(|error| Error::other(format!("salt failed: {error}")))?;
        let mask = salamander_mask(&self.key, &salt)?;
        let mut packet = Vec::with_capacity(8 + payload.len());
        packet.extend_from_slice(&salt);
        for (index, byte) in payload.iter().enumerate() {
            packet.push(byte ^ mask[index % mask.len()]);
        }
        Ok(packet)
    }

    fn decode_salamander_packet(&self, packet: &mut [u8], len: usize) -> std::io::Result<usize> {
        if len < 8 {
            return Ok(0);
        }
        let mut salt = [0u8; 8];
        salt.copy_from_slice(&packet[..8]);
        let mask = salamander_mask(&self.key, &salt)?;
        let payload_len = len - 8;
        for payload_index in 0..payload_len {
            packet[payload_index] = packet[payload_index + 8] ^ mask[payload_index % mask.len()];
        }
        Ok(payload_len)
    }
}

#[cfg(test)]
pub(super) fn wrap_hysteria2_obfs_socket_for_test(
    inner: Arc<dyn quinn::AsyncUdpSocket>,
    mode: &str,
    password: &str,
) -> anyhow::Result<Arc<dyn quinn::AsyncUdpSocket>> {
    let config = hysteria2_obfs_config(Some(mode), Some(password))?
        .ok_or_else(|| anyhow!("hysteria2 test obfs config is missing"))?;
    Ok(Arc::new(SalamanderUdpSocket::new(
        inner,
        &config.key,
        config.kind,
    )))
}

impl quinn::AsyncUdpSocket for SalamanderUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn quinn::UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &quinn::udp::Transmit) -> std::io::Result<()> {
        if transmit.segment_size.is_some() {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "hysteria2 obfs does not support segmented udp transmits",
            ));
        }
        let packets = if self.kind == Hysteria2ObfsKind::Gecko
            && transmit
                .contents
                .first()
                .map(|byte| byte & 0x80 != 0)
                .unwrap_or(false)
        {
            let mut state = self
                .gecko
                .lock()
                .map_err(|_| Error::other("gecko state lock poisoned"))?;
            build_gecko_fragments(&mut state, transmit.contents)?
        } else {
            vec![transmit.contents.to_vec()]
        };
        for payload in packets {
            let packet = self.encode_salamander_packet(&payload)?;
            let transmit = quinn::udp::Transmit {
                destination: transmit.destination,
                ecn: transmit.ecn,
                contents: &packet,
                segment_size: None,
                src_ip: transmit.src_ip,
            };
            self.inner.try_send(&transmit)?;
        }
        Ok(())
    }

    fn poll_recv(
        &self,
        cx: &mut TaskContext<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> Poll<std::io::Result<usize>> {
        match self.inner.poll_recv(cx, bufs, meta) {
            Poll::Ready(Ok(count)) => {
                for index in 0..count {
                    if meta[index].len < 8 {
                        meta[index].len = 0;
                        meta[index].stride = 0;
                        continue;
                    }
                    let len = meta[index].len;
                    let packet = &mut bufs[index][..len];
                    let payload_len = match self.decode_salamander_packet(packet, len) {
                        Ok(payload_len) => payload_len,
                        Err(error) => return Poll::Ready(Err(error)),
                    };
                    if payload_len == 0 {
                        meta[index].len = 0;
                        meta[index].stride = 0;
                        continue;
                    }
                    if self.kind == Hysteria2ObfsKind::Gecko && packet[0] & 0x80 != 0 {
                        let reassembled = {
                            let mut state = match self.gecko.lock() {
                                Ok(state) => state,
                                Err(_) => {
                                    return Poll::Ready(Err(Error::other(
                                        "gecko state lock poisoned",
                                    )));
                                }
                            };
                            match parse_gecko_fragment(
                                &mut state,
                                meta[index].addr,
                                &packet[..payload_len],
                            ) {
                                Ok(reassembled) => reassembled,
                                Err(error) => return Poll::Ready(Err(error)),
                            }
                        };
                        let Some(reassembled) = reassembled else {
                            meta[index].len = 0;
                            meta[index].stride = 0;
                            continue;
                        };
                        if reassembled.len() > bufs[index].len() {
                            return Poll::Ready(Err(Error::new(
                                ErrorKind::InvalidData,
                                "gecko reassembled packet exceeds receive buffer",
                            )));
                        }
                        bufs[index][..reassembled.len()].copy_from_slice(&reassembled);
                        meta[index].len = reassembled.len();
                        meta[index].stride = reassembled.len();
                    } else {
                        meta[index].len = payload_len;
                        meta[index].stride = payload_len;
                    }
                }
                Poll::Ready(Ok(count))
            }
            other => other,
        }
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        1
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

#[derive(Default, Debug)]
struct GeckoState {
    next_msg_id: u8,
    reassembly: HashMap<(SocketAddr, u8), GeckoFragmentSet>,
}

#[derive(Debug)]
struct GeckoFragmentSet {
    total: u8,
    chunks: Vec<Option<Vec<u8>>>,
}

fn build_gecko_fragments(state: &mut GeckoState, payload: &[u8]) -> std::io::Result<Vec<Vec<u8>>> {
    if payload.len() < 2 {
        return Ok(vec![payload.to_vec()]);
    }
    let max_fragments = payload.len().clamp(2, 8);
    let mut random = [0u8; 1];
    getrandom::fill(&mut random)
        .map_err(|error| Error::other(format!("gecko random failed: {error}")))?;
    let total = 2 + (random[0] as usize % (max_fragments - 1));
    let msg_id = state.next_msg_id;
    state.next_msg_id = state.next_msg_id.wrapping_add(1);

    let mut offset = 0usize;
    let mut frames = Vec::with_capacity(total);
    for index in 0..total {
        let remaining = payload.len() - offset;
        let remaining_fragments = total - index;
        let chunk_len = if remaining_fragments == 1 {
            remaining
        } else {
            let max_len = remaining - (remaining_fragments - 1);
            let mut random = [0u8; 2];
            getrandom::fill(&mut random)
                .map_err(|error| Error::other(format!("gecko chunk random failed: {error}")))?;
            1 + (u16::from_be_bytes(random) as usize % max_len)
        };
        let chunk = &payload[offset..offset + chunk_len];
        offset += chunk_len;

        let mut random = [0u8; 1];
        getrandom::fill(&mut random)
            .map_err(|error| Error::other(format!("gecko padding random failed: {error}")))?;
        let pad_len = random[0] as usize % 64;
        let mut frame = Vec::with_capacity(5 + pad_len + chunk.len());
        frame.push(0x80);
        frame.push(msg_id);
        frame.push(((index as u8) << 4) | total as u8);
        frame.extend_from_slice(&(pad_len as u16).to_be_bytes());
        if pad_len > 0 {
            let mut padding = vec![0u8; pad_len];
            getrandom::fill(&mut padding)
                .map_err(|error| Error::other(format!("gecko padding failed: {error}")))?;
            frame.extend_from_slice(&padding);
        }
        frame.extend_from_slice(chunk);
        frames.push(frame);
    }
    Ok(frames)
}

fn parse_gecko_fragment(
    state: &mut GeckoState,
    source: SocketAddr,
    frame: &[u8],
) -> std::io::Result<Option<Vec<u8>>> {
    if frame.len() < 5 || frame[0] != 0x80 {
        return Ok(None);
    }
    let msg_id = frame[1];
    let chunk_idx = frame[2] >> 4;
    let total = frame[2] & 0x0f;
    if !(2..=8).contains(&total) || chunk_idx >= total {
        return Ok(None);
    }
    let pad_len = u16::from_be_bytes([frame[3], frame[4]]) as usize;
    if 5 + pad_len > frame.len() {
        return Ok(None);
    }
    let chunk = frame[5 + pad_len..].to_vec();
    if state.reassembly.len() > 256 {
        state.reassembly.clear();
    }
    let key = (source, msg_id);
    let entry = state
        .reassembly
        .entry(key)
        .or_insert_with(|| GeckoFragmentSet {
            total,
            chunks: vec![None; total as usize],
        });
    if entry.total != total {
        state.reassembly.remove(&key);
        return Ok(None);
    }
    entry.chunks[chunk_idx as usize] = Some(chunk);
    if !entry.chunks.iter().all(Option::is_some) {
        return Ok(None);
    }
    let entry = state
        .reassembly
        .remove(&key)
        .ok_or_else(|| Error::other("gecko reassembly entry missing"))?;
    let mut output = Vec::new();
    for chunk in entry.chunks {
        output.extend_from_slice(&chunk.ok_or_else(|| Error::other("gecko fragment missing"))?);
    }
    Ok(Some(output))
}

fn salamander_mask(key: &[u8], salt: &[u8; 8]) -> std::io::Result<[u8; 32]> {
    let mut hasher = Blake2bVar::new(32)
        .map_err(|error| Error::other(format!("blake2b init failed: {error}")))?;
    blake2::digest::Update::update(&mut hasher, key);
    blake2::digest::Update::update(&mut hasher, salt);
    let mut output = [0u8; 32];
    hasher
        .finalize_variable(&mut output)
        .map_err(|error| Error::other(format!("blake2b failed: {error}")))?;
    Ok(output)
}

fn hysteria2_obfs_config(
    obfs: Option<&str>,
    obfs_password: Option<&str>,
) -> anyhow::Result<Option<Hysteria2ObfsConfig>> {
    let Some(obfs) = obfs.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    match obfs.to_ascii_lowercase().as_str() {
        "salamander" | "gecko" => {
            let password = obfs_password
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| anyhow!("hysteria2 {obfs} obfs password is required"))?;
            let kind = if obfs.eq_ignore_ascii_case("gecko") {
                Hysteria2ObfsKind::Gecko
            } else {
                Hysteria2ObfsKind::Salamander
            };
            Ok(Some(Hysteria2ObfsConfig {
                kind,
                key: password.as_bytes().to_vec(),
            }))
        }
        other => Err(anyhow!("unsupported hysteria2 obfs mode {other}")),
    }
}

fn validate_hysteria2_text_list(label: &str, value: Option<&str>) -> anyhow::Result<()> {
    let Some(value) = value else {
        return Ok(());
    };
    let mut count = 0usize;
    for item in value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
    {
        count += 1;
        if item.len() > u8::MAX as usize || !item.is_ascii() {
            return Err(anyhow!(
                "{label} entries must be non-empty ASCII strings up to 255 bytes"
            ));
        }
    }
    if count == 0 {
        return Err(anyhow!("{label} must contain at least one protocol"));
    }
    Ok(())
}

fn validate_hysteria2_congestion(value: Option<&str>) -> anyhow::Result<Option<String>> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    let normalized = value.to_ascii_lowercase();
    if matches!(
        normalized.as_str(),
        "default" | "cubic" | "bbr" | "brutal" | "new-reno" | "new_reno" | "newreno"
    ) {
        Ok(Some(normalized))
    } else {
        Err(anyhow!(
            "unsupported hysteria2 congestion controller {normalized}"
        ))
    }
}

fn hysteria2_fallback_controller(
    value: Option<&str>,
) -> Arc<dyn quinn::congestion::ControllerFactory + Send + Sync> {
    match value.unwrap_or("cubic") {
        "bbr" | "brutal" => Arc::new(quinn::congestion::BbrConfig::default()),
        "new-reno" | "new_reno" | "newreno" => {
            Arc::new(quinn::congestion::NewRenoConfig::default())
        }
        _ => Arc::new(quinn::congestion::CubicConfig::default()),
    }
}

fn parse_hysteria2_bandwidth(value: Option<&str>, label: &str) -> anyhow::Result<Option<u64>> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    let normalized = value.to_ascii_lowercase().replace(' ', "");
    if normalized == "auto" || normalized == "0" {
        return Ok(None);
    }
    let (number, bits_multiplier) = [
        ("gbps", 1_000_000_000f64),
        ("mbps", 1_000_000f64),
        ("kbps", 1_000f64),
        ("bps", 1f64),
        ("g", 1_000_000_000f64),
        ("m", 1_000_000f64),
        ("k", 1_000f64),
    ]
    .into_iter()
    .find_map(|(suffix, multiplier)| {
        normalized
            .strip_suffix(suffix)
            .map(|number| (number, multiplier))
    })
    .unwrap_or((normalized.as_str(), 1_000_000f64));
    let amount = number
        .parse::<f64>()
        .with_context(|| format!("invalid hysteria2 {label} bandwidth {value}"))?;
    if !amount.is_finite() || amount <= 0.0 {
        return Err(anyhow!(
            "hysteria2 {label} bandwidth must be a positive finite value"
        ));
    }
    let bytes_per_second = (amount * bits_multiplier / 8.0).round();
    if bytes_per_second < 1.0 || bytes_per_second > u64::MAX as f64 {
        return Err(anyhow!("hysteria2 {label} bandwidth is out of range"));
    }
    Ok(Some(bytes_per_second as u64))
}

fn random_hysteria2_padding() -> anyhow::Result<String> {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut random = [0u8; 256];
    getrandom::fill(&mut random).context("failed to generate hysteria2 auth padding")?;
    let len = 64 + usize::from(random[0] % 192);
    Ok(random[1..=len]
        .iter()
        .map(|byte| ALPHABET[*byte as usize % ALPHABET.len()] as char)
        .collect())
}

fn parse_hysteria2_server_receive_rate(value: &str) -> anyhow::Result<Option<u64>> {
    let value = value.trim();
    if value.eq_ignore_ascii_case("auto") {
        return Ok(None);
    }
    value
        .parse::<u64>()
        .map(Some)
        .with_context(|| format!("invalid Hysteria-CC-RX response value {value}"))
}

struct Hysteria2TcpStream {
    _shared: Arc<Hysteria2Connection>,
    recv: quinn::RecvStream,
    send: quinn::SendStream,
}

impl AsyncRead for Hysteria2TcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), Error>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for Hysteria2TcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        AsyncWrite::poll_write(Pin::new(&mut self.send), cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Result<(), Error>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.send), cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Result<(), Error>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.send), cx)
    }
}

#[allow(clippy::too_many_arguments)]
async fn open_hysteria2_connection(
    server: &str,
    port: u16,
    sni: Option<&str>,
    skip_cert_verify: bool,
    password: &str,
    alpn: Option<&str>,
    obfs_config: Option<&Hysteria2ObfsConfig>,
    upload_bytes_per_second: Option<u64>,
    download_bytes_per_second: Option<u64>,
    congestion_control: Option<&str>,
    timeout_ms: u64,
) -> anyhow::Result<Hysteria2Connection> {
    if password.is_empty() {
        return Err(anyhow!("hysteria2 password is empty"));
    }
    let remote = resolve_quic_remote("hysteria2", server, port).await?;
    let endpoint = if let Some(obfs_config) = obfs_config {
        let socket =
            create_bound_std_udp(remote).context("failed to bind hysteria2 obfs udp socket")?;
        let runtime: Arc<dyn quinn::Runtime> = Arc::new(quinn::TokioRuntime);
        let inner = runtime
            .wrap_udp_socket(socket)
            .context("failed to wrap hysteria2 obfs udp socket")?;
        let socket = Arc::new(SalamanderUdpSocket::new(
            inner,
            &obfs_config.key,
            obfs_config.kind,
        ));
        quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            None,
            socket,
            runtime,
        )
        .context("failed to create hysteria2 obfs quic endpoint")?
    } else {
        create_quic_endpoint(remote)?
    };
    let server_name = sni.unwrap_or(server).to_string();
    let negotiated_upload_rate =
        Arc::new(AtomicU64::new(upload_bytes_per_second.unwrap_or_default()));
    let rate_controller = Arc::new(Hysteria2RateControllerFactory {
        rate: Arc::clone(&negotiated_upload_rate),
        fallback: hysteria2_fallback_controller(congestion_control),
    });
    let (endpoint, connection) = connect_quic_endpoint(
        endpoint,
        remote,
        &server_name,
        quic_client_config_with_controller(
            skip_cert_verify,
            alpn,
            congestion_control,
            rate_controller,
        )?,
        timeout_ms,
        "hysteria2",
    )
    .await?;

    let h3_connection = h3_quinn::Connection::new(connection.clone());
    let (mut h3_connection, mut send_request) = run_dial_phase(
        timeout_ms,
        "hysteria2 http/3 client init",
        h3::client::new(h3_connection),
    )
    .await??;
    let h3_driver = tokio::spawn(async move {
        let _ = h3_connection.wait_idle().await;
    });

    let auth_padding = random_hysteria2_padding()?;
    let request = http::Request::builder()
        .method(http::Method::POST)
        .uri("https://hysteria/auth")
        .header("hysteria-auth", password)
        .header(
            "hysteria-cc-rx",
            download_bytes_per_second.unwrap_or(0).to_string(),
        )
        .header("hysteria-padding", auth_padding)
        .body(())
        .context("failed to build hysteria2 auth request")?;
    let mut stream = match run_dial_phase(
        timeout_ms,
        "hysteria2 auth request",
        send_request.send_request(request),
    )
    .await?
    {
        Ok(stream) => stream,
        Err(error) => {
            h3_driver.abort();
            return Err(anyhow!("hysteria2 auth request failed: {error}"));
        }
    };
    if let Err(error) = run_dial_phase(timeout_ms, "hysteria2 auth finish", stream.finish()).await?
    {
        h3_driver.abort();
        return Err(anyhow!("hysteria2 auth finish failed: {error}"));
    }
    let response = match run_dial_phase(
        timeout_ms,
        "hysteria2 auth response",
        stream.recv_response(),
    )
    .await?
    {
        Ok(response) => response,
        Err(error) => {
            h3_driver.abort();
            return Err(anyhow!("hysteria2 auth response failed: {error}"));
        }
    };
    if response.status().as_u16() != 233 {
        h3_driver.abort();
        return Err(anyhow!(
            "hysteria2 authentication failed with status {}",
            response.status()
        ));
    }

    let udp_supported = match response
        .headers()
        .get("hysteria-udp")
        .ok_or_else(|| anyhow!("hysteria2 auth response is missing Hysteria-UDP"))?
        .to_str()
        .context("hysteria2 Hysteria-UDP header is not valid ASCII")?
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "true" => true,
        "false" => false,
        _ => {
            return Err(anyhow!(
                "hysteria2 Hysteria-UDP header must be true or false"
            ))
        }
    };
    let advertised_server_receive_rate = parse_hysteria2_server_receive_rate(
        response
            .headers()
            .get("hysteria-cc-rx")
            .ok_or_else(|| anyhow!("hysteria2 auth response is missing Hysteria-CC-RX"))?
            .to_str()
            .context("hysteria2 Hysteria-CC-RX header is not valid ASCII")?,
    )?;
    let server_receive_rate = match (upload_bytes_per_second, advertised_server_receive_rate) {
        (Some(configured), Some(advertised)) if advertised > 0 => Some(configured.min(advertised)),
        (Some(configured), _) => Some(configured),
        (None, advertised) => advertised.filter(|rate| *rate > 0),
    };
    negotiated_upload_rate.store(server_receive_rate.unwrap_or_default(), Ordering::Relaxed);

    let udp_routes = Arc::new(StdMutex::new(HashMap::<u32, mpsc::Sender<Vec<u8>>>::new()));
    let udp_connection = connection.clone();
    let driver_routes = Arc::clone(&udp_routes);
    let udp_driver = tokio::spawn(async move {
        while let Ok(datagram) = udp_connection.read_datagram().await {
            if datagram.len() < 4 {
                continue;
            }
            let session_id =
                u32::from_be_bytes([datagram[0], datagram[1], datagram[2], datagram[3]]);
            let sender = driver_routes
                .lock()
                .ok()
                .and_then(|routes| routes.get(&session_id).cloned());
            if let Some(sender) = sender {
                let _ = sender.try_send(datagram.to_vec());
            }
        }
    });

    Ok(Hysteria2Connection {
        _endpoint: endpoint,
        connection,
        _h3_sender: send_request,
        h3_driver,
        udp_driver,
        udp_routes,
        udp_supported,
        _server_receive_rate: server_receive_rate,
    })
}

pub(super) fn build_hysteria2_tcp_request(destination: &Destination) -> anyhow::Result<Vec<u8>> {
    let address = destination_socket_addr(destination);
    let mut random = [0u8; 65];
    getrandom::fill(&mut random).context("failed to generate hysteria2 TCP padding")?;
    let padding_len = usize::from(random[0] % 65);
    let padding = &random[1..1 + padding_len];
    let mut output = Vec::with_capacity(address.len() + padding.len() + 16);
    encode_quic_varint(0x401, &mut output)?;
    encode_quic_varint(address.len() as u64, &mut output)?;
    output.extend_from_slice(address.as_bytes());
    encode_quic_varint(padding.len() as u64, &mut output)?;
    output.extend_from_slice(padding);
    Ok(output)
}

async fn read_hysteria2_tcp_response<R>(reader: &mut R) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut status = [0u8; 1];
    reader.read_exact(&mut status).await?;
    let message_len = read_quic_varint(reader).await?;
    if message_len > 4096 {
        return Err(anyhow!("hysteria2 tcp response message is too large"));
    }
    let mut message = vec![0u8; message_len as usize];
    reader.read_exact(&mut message).await?;
    let padding_len = read_quic_varint(reader).await?;
    if padding_len > 16 * 1024 {
        return Err(anyhow!("hysteria2 tcp response padding is too large"));
    }
    let mut padding = vec![0u8; padding_len as usize];
    reader.read_exact(&mut padding).await?;
    if status[0] != 0x00 {
        let message = String::from_utf8_lossy(&message);
        return Err(anyhow!("hysteria2 tcp request failed: {message}"));
    }
    Ok(())
}

pub(super) type Hysteria2UdpReassembly = FragmentReassembler<u16>;

pub(super) fn build_hysteria2_udp_messages(
    session_id: u32,
    packet_id: u16,
    destination: &Destination,
    payload: &[u8],
    max_datagram_size: Option<usize>,
) -> anyhow::Result<Vec<Vec<u8>>> {
    let address = destination_socket_addr(destination);
    let single =
        build_hysteria2_udp_message_fragment(session_id, packet_id, 0, 1, &address, payload)?;
    let Some(max_size) = max_datagram_size else {
        return Ok(vec![single]);
    };
    if single.len() <= max_size {
        return Ok(vec![single]);
    }

    let header_len =
        build_hysteria2_udp_message_fragment(session_id, packet_id, 0, 1, &address, &[])?.len();
    if header_len >= max_size {
        return Err(anyhow!(
            "hysteria2 udp header is too large for quic datagram: {} >= {}",
            header_len,
            max_size
        ));
    }
    let max_payload_len = max_size - header_len;
    let fragment_count = payload.len().div_ceil(max_payload_len);
    if fragment_count > u8::MAX as usize {
        return Err(anyhow!(
            "hysteria2 udp payload needs too many fragments: {fragment_count}"
        ));
    }
    let mut messages = Vec::with_capacity(fragment_count);
    for (index, chunk) in payload.chunks(max_payload_len).enumerate() {
        messages.push(build_hysteria2_udp_message_fragment(
            session_id,
            packet_id,
            index as u8,
            fragment_count as u8,
            &address,
            chunk,
        )?);
    }
    Ok(messages)
}

fn build_hysteria2_udp_message_fragment(
    session_id: u32,
    packet_id: u16,
    fragment_id: u8,
    fragment_count: u8,
    address: &str,
    payload: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let mut output = Vec::with_capacity(12 + address.len() + payload.len());
    output.extend_from_slice(&session_id.to_be_bytes());
    output.extend_from_slice(&packet_id.to_be_bytes());
    output.push(fragment_id);
    output.push(fragment_count);
    encode_quic_varint(address.len() as u64, &mut output)?;
    output.extend_from_slice(address.as_bytes());
    output.extend_from_slice(payload);
    Ok(output)
}

pub(super) fn parse_hysteria2_udp_message(
    datagram: &[u8],
    expected_session_id: u32,
    reassembly: &mut Hysteria2UdpReassembly,
) -> anyhow::Result<Option<Vec<u8>>> {
    if datagram.len() < 8 {
        return Ok(None);
    }
    let session_id = u32::from_be_bytes([datagram[0], datagram[1], datagram[2], datagram[3]]);
    if session_id != expected_session_id {
        return Ok(None);
    }
    let packet_id = u16::from_be_bytes([datagram[4], datagram[5]]);
    let fragment_id = datagram[6];
    let fragment_count = datagram[7];
    if fragment_count == 0 || fragment_id >= fragment_count {
        return Err(anyhow!(
            "invalid hysteria2 udp fragment id/count: {fragment_id}/{fragment_count}"
        ));
    }
    let mut cursor = 8;
    let address_len = read_quic_varint_from_slice(datagram, &mut cursor)? as usize;
    if cursor + address_len > datagram.len() {
        return Err(anyhow!("hysteria2 udp address length exceeds datagram"));
    }
    cursor += address_len;
    let payload = datagram[cursor..].to_vec();
    reassembly
        .push(packet_id, fragment_id, fragment_count, payload)
        .context("hysteria2 udp reassembly failed")
}
