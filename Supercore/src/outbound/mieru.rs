use std::{
    collections::{BTreeMap, HashMap},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex as StdMutex,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{anyhow, Context};
use async_trait::async_trait;
use bytes::BytesMut;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use pbkdf2::pbkdf2_hmac;
use sha2::{Digest, Sha256};
use tokio::{
    io::{split, AsyncRead, AsyncReadExt, AsyncWriteExt, DuplexStream, WriteHalf},
    net::UdpSocket,
    sync::{mpsc, Mutex, Notify, OnceCell},
    task::JoinHandle,
    time::{sleep, timeout},
};
use tokio_util::sync::CancellationToken;

use crate::routing::Destination;

use super::{
    target::encode_socks5_destination,
    transports::{connect_tcp, run_dial_phase},
    udp::{create_bound_udp, resolve_udp_socket_addr, udp_session_key, KeyedRoundRobinSessionPool},
    BoxedStream, Outbound, OutboundCapability, UdpNatMode,
};

const MIERU_METADATA_LENGTH: usize = 32;
const MIERU_NONCE_LENGTH: usize = 24;
const MIERU_TAG_LENGTH: usize = 16;
const MIERU_MAX_SESSION_OPEN_PAYLOAD: usize = 1_024;
const MIERU_MAX_STREAM_PAYLOAD: usize = 32 * 1_024;
const MIERU_STREAM_BUFFER_SIZE: usize = 256 * 1_024;
const MIERU_SESSION_CHANNEL_SIZE: usize = 256;
const MIERU_KEY_ITERATIONS: u32 = 64;
const MIERU_KEY_REFRESH_SECONDS: u64 = 120;
const MIERU_DEFAULT_MTU: u16 = 1_400;
const MIERU_MIN_MTU: u16 = 1_280;
const MIERU_MAX_MTU: u16 = 1_500;
const MIERU_MAX_RANDOM_PADDING: usize = 31;
const MIERU_PACKET_OVERHEAD: usize =
    MIERU_NONCE_LENGTH + MIERU_METADATA_LENGTH + MIERU_TAG_LENGTH * 2;
const MIERU_PACKET_INITIAL_WINDOW: u32 = 16;
const MIERU_PACKET_MAX_WINDOW: u32 = 4_096;
const MIERU_PACKET_MAX_TRANSMISSIONS: u8 = 20;
const MIERU_PACKET_HEARTBEAT: Duration = Duration::from_secs(5);
const MIERU_PACKET_TICK: Duration = Duration::from_millis(5);
const MIERU_PACKET_MAX_RTO: Duration = Duration::from_secs(10);

const PROTOCOL_OPEN_SESSION_REQUEST: u8 = 2;
const PROTOCOL_OPEN_SESSION_RESPONSE: u8 = 3;
const PROTOCOL_CLOSE_SESSION_REQUEST: u8 = 4;
const PROTOCOL_CLOSE_SESSION_RESPONSE: u8 = 5;
const PROTOCOL_DATA_CLIENT_TO_SERVER: u8 = 6;
const PROTOCOL_DATA_SERVER_TO_CLIENT: u8 = 7;
const PROTOCOL_ACK_CLIENT_TO_SERVER: u8 = 8;
const PROTOCOL_ACK_SERVER_TO_CLIENT: u8 = 9;

const SOCKS5_CONNECT: u8 = 1;
const SOCKS5_UDP_ASSOCIATE: u8 = 3;

pub(super) struct MieruOutbound {
    name: String,
    server: String,
    port: u16,
    port_range: Option<String>,
    username: String,
    password: String,
    transport: Option<String>,
    mtu: Option<u16>,
    multiplexing: Option<String>,
    handshake_mode: Option<String>,
    client: OnceCell<Arc<MieruClient>>,
    udp_sessions: Mutex<MieruUdpPool>,
}

type MieruUdpPool = KeyedRoundRobinSessionPool<MieruUdpSession>;

struct MieruUdpSession {
    stream: BoxedStream,
}

struct MieruClient {
    server: String,
    ports: Vec<u16>,
    username: String,
    password: String,
    transport: MieruTransport,
    mtu: u16,
    multiplexing: MieruMultiplexing,
    handshake_mode: MieruHandshakeMode,
    connections: Mutex<Vec<Arc<MieruConnection>>>,
    packet_connections: Mutex<Vec<Arc<MieruPacketConnection>>>,
}

struct MieruConnection {
    writer: Mutex<MieruConnectionWriter>,
    sessions: Arc<StdMutex<HashMap<u32, mpsc::Sender<MieruInboundEvent>>>>,
    healthy: Arc<AtomicBool>,
    active_sessions: AtomicUsize,
    reader_task: StdMutex<Option<JoinHandle<()>>>,
}

struct MieruConnectionWriter {
    writer: WriteHalf<BoxedStream>,
    cipher: MieruStatefulCipher,
}

struct MieruStreamSessionSender {
    connection: Arc<MieruConnection>,
    session_id: u32,
    next_sequence: u32,
}

enum MieruSessionSender {
    Stream(MieruStreamSessionSender),
    Packet(MieruPacketSessionSender),
}

struct MieruSessionReader {
    incoming: mpsc::Receiver<MieruInboundEvent>,
    buffered: BytesMut,
    next_sequence: u32,
    opened: bool,
}

struct MieruStreamSessionLease {
    connection: Arc<MieruConnection>,
    session_id: u32,
}

enum MieruSessionLease {
    Stream(MieruStreamSessionLease),
    Packet(MieruPacketSessionLease),
}

impl Drop for MieruSessionLease {
    fn drop(&mut self) {
        match self {
            Self::Stream(lease) => {
                let _ = lease.session_id;
            }
            Self::Packet(lease) => {
                let _ = lease.session_id;
            }
        }
    }
}

struct MieruPacketConnection {
    socket: Arc<UdpSocket>,
    key: [u8; 32],
    username: String,
    mtu: u16,
    sessions: Arc<StdMutex<HashMap<u32, Arc<MieruPacketSessionEntry>>>>,
    healthy: Arc<AtomicBool>,
    active_sessions: AtomicUsize,
    reader_task: StdMutex<Option<JoinHandle<()>>>,
    timer_task: StdMutex<Option<JoinHandle<()>>>,
}

struct MieruPacketSessionEntry {
    session_id: u32,
    incoming: mpsc::Sender<MieruInboundEvent>,
    state: Arc<Mutex<MieruPacketSessionState>>,
    wake_sender: Arc<Notify>,
}

struct MieruPacketSessionSender {
    connection: Arc<MieruPacketConnection>,
    session_id: u32,
    state: Arc<Mutex<MieruPacketSessionState>>,
    wake_sender: Arc<Notify>,
}

struct MieruPacketSessionLease {
    connection: Arc<MieruPacketConnection>,
    session_id: u32,
}

struct MieruPacketSessionState {
    next_send: u32,
    next_receive: u32,
    receive_buffer: BTreeMap<u32, MieruInboundSegment>,
    unacknowledged: BTreeMap<u32, MieruPendingPacket>,
    remote_window: u32,
    congestion: MieruCubicWindow,
    rtt: MieruRttEstimator,
    last_send: Instant,
    last_receive: Instant,
    closed: bool,
}

#[derive(Clone)]
struct MieruPendingPacket {
    metadata: MieruOutboundMetadata,
    payload: Vec<u8>,
    sent_at: Instant,
    timeout: Duration,
    transmissions: u8,
    duplicate_acks: u8,
}

#[derive(Clone)]
struct MieruRttEstimator {
    smoothed: Option<Duration>,
    deviation: Duration,
}

struct MieruCubicWindow {
    window: u32,
    previous_maximum: u32,
    reduction_time: Option<Instant>,
    accumulated_acks: u32,
    slow_start: bool,
}

struct MieruInboundSegment {
    protocol: u8,
    session_id: u32,
    sequence: u32,
    status: u8,
    unacknowledged_sequence: u32,
    window_size: u16,
    fragment: u8,
    payload: Vec<u8>,
}

enum MieruInboundEvent {
    Segment(MieruInboundSegment),
    Error(String),
}

#[derive(Clone)]
enum MieruOutboundMetadata {
    Session {
        protocol: u8,
        session_id: u32,
        sequence: u32,
        status: u8,
        payload_len: u16,
        suffix_len: u8,
    },
    Data {
        protocol: u8,
        session_id: u32,
        sequence: u32,
        unacknowledged_sequence: u32,
        window_size: u16,
        fragment: u8,
        prefix_len: u8,
        payload_len: u16,
        suffix_len: u8,
    },
}

struct MieruInboundMetadata {
    protocol: u8,
    session_id: u32,
    sequence: u32,
    status: u8,
    unacknowledged_sequence: u32,
    window_size: u16,
    fragment: u8,
    prefix_len: usize,
    payload_len: usize,
    suffix_len: usize,
}

struct MieruStatefulCipher {
    cipher: XChaCha20Poly1305,
    nonce: Option<[u8; MIERU_NONCE_LENGTH]>,
    username: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MieruTransport {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MieruMultiplexing {
    Off,
    Low,
    Middle,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MieruHandshakeMode {
    Standard,
    NoWait,
}

#[async_trait]
impl Outbound for MieruOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "mieru"
    }

    fn capability(&self) -> OutboundCapability {
        match self.validated_config() {
            Ok(config) => OutboundCapability::tcp_udp(match config.transport {
                MieruTransport::Tcp => "mieru-v3-tcp-underlay-socks5-udp-associate",
                MieruTransport::Udp => "mieru-v3-reliable-udp-underlay-socks5-udp-associate",
            }),
            Err(error) => OutboundCapability::unsupported(error.to_string()),
        }
    }

    fn udp_nat_mode(&self) -> UdpNatMode {
        UdpNatMode::EndpointIndependent
    }

    fn supports_udp_dialer_proxy(&self) -> bool {
        normalized_mieru_transport(self.transport.as_deref()).is_ok()
    }

    async fn connect(
        &self,
        destination: &Destination,
        timeout_ms: u64,
    ) -> anyhow::Result<BoxedStream> {
        let config = self.validated_config()?;
        let client = self.client(config).await;
        let stream = run_dial_phase(
            timeout_ms,
            "mieru SOCKS5 CONNECT handshake",
            client.open_socks_stream(SOCKS5_CONNECT, destination, false),
        )
        .await??;
        Ok(Box::new(stream))
    }

    async fn udp_exchange(
        &self,
        destination: &Destination,
        payload: &[u8],
        timeout_ms: u64,
    ) -> anyhow::Result<Vec<u8>> {
        let config = self.validated_config()?;
        let key = udp_session_key(
            self.kind(),
            self.name(),
            self.udp_nat_mode(),
            Some(destination),
        );
        let session_handle = self.udp_session(&key, config, timeout_ms).await?;
        let mut session = session_handle.lock().await;
        let packet = encode_mieru_udp_tunnel_packet(destination, payload)?;
        let exchange = run_dial_phase(timeout_ms, "mieru UDP ASSOCIATE exchange", async {
            session.stream.write_all(&packet).await?;
            session.stream.flush().await?;
            read_mieru_udp_tunnel_packet(&mut session.stream).await
        })
        .await;
        let failed = !matches!(&exchange, Ok(Ok(_)));
        if failed {
            drop(session);
            self.udp_sessions.lock().await.remove(&key, &session_handle);
        }
        exchange?
    }
}

struct ValidatedMieruConfig {
    ports: Vec<u16>,
    transport: MieruTransport,
    mtu: u16,
    multiplexing: MieruMultiplexing,
    handshake_mode: MieruHandshakeMode,
}

impl MieruOutbound {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        name: String,
        server: String,
        port: u16,
        port_range: Option<String>,
        username: String,
        password: String,
        transport: Option<String>,
        mtu: Option<u16>,
        multiplexing: Option<String>,
        handshake_mode: Option<String>,
    ) -> Self {
        Self {
            name,
            server,
            port,
            port_range,
            username,
            password,
            transport,
            mtu,
            multiplexing,
            handshake_mode,
            client: OnceCell::new(),
            udp_sessions: Mutex::new(MieruUdpPool::default()),
        }
    }

    fn validated_config(&self) -> anyhow::Result<ValidatedMieruConfig> {
        if self.server.trim().is_empty() {
            return Err(anyhow!("mieru server must not be empty"));
        }
        if self.username.is_empty() {
            return Err(anyhow!("mieru username must not be empty"));
        }
        if self.password.is_empty() {
            return Err(anyhow!("mieru password must not be empty"));
        }
        let mtu = self.mtu.unwrap_or(MIERU_DEFAULT_MTU);
        if !(MIERU_MIN_MTU..=MIERU_MAX_MTU).contains(&mtu) {
            return Err(anyhow!(
                "mieru MTU {mtu} is outside the official range {MIERU_MIN_MTU}..={MIERU_MAX_MTU}"
            ));
        }
        Ok(ValidatedMieruConfig {
            ports: parse_mieru_server_ports(self.port, self.port_range.as_deref())?,
            transport: normalized_mieru_transport(self.transport.as_deref())?,
            mtu,
            multiplexing: normalized_mieru_multiplexing(self.multiplexing.as_deref())?,
            handshake_mode: normalized_mieru_handshake_mode(self.handshake_mode.as_deref())?,
        })
    }

    async fn client(&self, config: ValidatedMieruConfig) -> Arc<MieruClient> {
        Arc::clone(
            self.client
                .get_or_init(|| async {
                    Arc::new(MieruClient {
                        server: self.server.clone(),
                        ports: config.ports,
                        username: self.username.clone(),
                        password: self.password.clone(),
                        transport: config.transport,
                        mtu: config.mtu,
                        multiplexing: config.multiplexing,
                        handshake_mode: config.handshake_mode,
                        connections: Mutex::new(Vec::new()),
                        packet_connections: Mutex::new(Vec::new()),
                    })
                })
                .await,
        )
    }

    async fn udp_session(
        &self,
        key: &str,
        config: ValidatedMieruConfig,
        timeout_ms: u64,
    ) -> anyhow::Result<Arc<Mutex<MieruUdpSession>>> {
        let mut pool = self.udp_sessions.lock().await;
        if let Some(session) = pool.next(key) {
            return Ok(session);
        }
        drop(pool);

        let client = self.client(config).await;
        let destination = Destination::new("0.0.0.0", 0);
        let stream = run_dial_phase(
            timeout_ms,
            "mieru SOCKS5 UDP ASSOCIATE handshake",
            client.open_socks_stream(SOCKS5_UDP_ASSOCIATE, &destination, true),
        )
        .await??;
        let session = Arc::new(Mutex::new(MieruUdpSession {
            stream: Box::new(stream),
        }));
        let mut pool = self.udp_sessions.lock().await;
        pool.push(key.to_string(), Arc::clone(&session));
        Ok(session)
    }
}

impl MieruClient {
    async fn open_socks_stream(
        &self,
        command: u8,
        destination: &Destination,
        require_standard_handshake: bool,
    ) -> anyhow::Result<DuplexStream> {
        let (sender, mut reader, lease) = match self.transport {
            MieruTransport::Tcp => self
                .acquire_connection()
                .await?
                .open_session(self.max_sessions())?,
            MieruTransport::Udp => self
                .acquire_packet_connection()
                .await?
                .open_session(self.max_sessions())?,
        };
        let sender = Arc::new(Mutex::new(sender));

        let request = build_socks5_request(command, destination)?;
        sender.lock().await.send_open_session(&request).await?;
        let no_wait =
            self.handshake_mode == MieruHandshakeMode::NoWait && !require_standard_handshake;
        if !no_wait {
            read_socks5_command_response(&mut reader).await?;
        }

        Ok(spawn_mieru_session_bridge(sender, reader, lease, no_wait))
    }

    async fn acquire_connection(&self) -> anyhow::Result<Arc<MieruConnection>> {
        let max_sessions = self.max_sessions();
        let mut connections = self.connections.lock().await;
        connections.retain(|connection| connection.healthy.load(Ordering::Acquire));
        if self.multiplexing != MieruMultiplexing::Off {
            if let Some(connection) = connections.iter().find(|connection| {
                connection.active_sessions.load(Ordering::Acquire) < max_sessions
            }) {
                return Ok(Arc::clone(connection));
            }
        }

        let port = random_mieru_port(&self.ports)?;
        let connection =
            MieruConnection::connect(&self.server, port, &self.username, &self.password).await?;
        if self.multiplexing != MieruMultiplexing::Off {
            connections.push(Arc::clone(&connection));
        }
        Ok(connection)
    }

    async fn acquire_packet_connection(&self) -> anyhow::Result<Arc<MieruPacketConnection>> {
        let max_sessions = self.max_sessions();
        let mut connections = self.packet_connections.lock().await;
        connections.retain(|connection| connection.healthy.load(Ordering::Acquire));
        if self.multiplexing != MieruMultiplexing::Off {
            if let Some(connection) = connections.iter().find(|connection| {
                connection.active_sessions.load(Ordering::Acquire) < max_sessions
            }) {
                return Ok(Arc::clone(connection));
            }
        }

        let port = random_mieru_port(&self.ports)?;
        let connection = MieruPacketConnection::connect(
            &self.server,
            port,
            &self.username,
            &self.password,
            self.mtu,
        )
        .await?;
        if self.multiplexing != MieruMultiplexing::Off {
            connections.push(Arc::clone(&connection));
        }
        Ok(connection)
    }

    fn max_sessions(&self) -> usize {
        match self.multiplexing {
            MieruMultiplexing::Off => 1,
            MieruMultiplexing::Low => 16,
            MieruMultiplexing::Middle => 64,
            MieruMultiplexing::High => 128,
        }
    }
}

impl MieruConnection {
    async fn connect(
        server: &str,
        port: u16,
        username: &str,
        password: &str,
    ) -> anyhow::Result<Arc<Self>> {
        let stream = connect_tcp(&server_address(server, port), 10_000)
            .await
            .with_context(|| format!("failed to connect mieru server {server}:{port}"))?;
        let key = derive_mieru_key(username, password, unix_seconds())?;
        let (reader, writer) = split(stream);
        let sessions = Arc::new(StdMutex::new(HashMap::new()));
        let healthy = Arc::new(AtomicBool::new(true));
        let connection = Arc::new(Self {
            writer: Mutex::new(MieruConnectionWriter {
                writer,
                cipher: MieruStatefulCipher::new(key, username.to_string()),
            }),
            sessions: Arc::clone(&sessions),
            healthy: Arc::clone(&healthy),
            active_sessions: AtomicUsize::new(0),
            reader_task: StdMutex::new(None),
        });
        let task = tokio::spawn(run_mieru_connection_reader(
            reader,
            key,
            username.to_string(),
            sessions,
            healthy,
        ));
        *connection
            .reader_task
            .lock()
            .expect("mieru reader task lock poisoned") = Some(task);
        Ok(connection)
    }

    fn open_session(
        self: &Arc<Self>,
        max_sessions: usize,
    ) -> anyhow::Result<(
        MieruSessionSender,
        MieruSessionReader,
        Arc<MieruSessionLease>,
    )> {
        if !self.healthy.load(Ordering::Acquire) {
            return Err(anyhow!("mieru underlay connection is closed"));
        }
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| anyhow!("mieru session map lock poisoned"))?;
        if sessions.len() >= max_sessions {
            return Err(anyhow!("mieru underlay reached its session limit"));
        }
        let session_id = (0..32)
            .find_map(|_| {
                let id = random_u32().ok()?.max(1);
                (!sessions.contains_key(&id)).then_some(id)
            })
            .ok_or_else(|| anyhow!("failed to allocate unique mieru session ID"))?;
        let (tx, rx) = mpsc::channel(MIERU_SESSION_CHANNEL_SIZE);
        sessions.insert(session_id, tx);
        drop(sessions);
        self.active_sessions.fetch_add(1, Ordering::AcqRel);
        Ok((
            MieruSessionSender::Stream(MieruStreamSessionSender {
                connection: Arc::clone(self),
                session_id,
                next_sequence: 0,
            }),
            MieruSessionReader {
                incoming: rx,
                buffered: BytesMut::new(),
                next_sequence: 0,
                opened: false,
            },
            Arc::new(MieruSessionLease::Stream(MieruStreamSessionLease {
                connection: Arc::clone(self),
                session_id,
            })),
        ))
    }

    async fn write_segment(
        &self,
        metadata: MieruOutboundMetadata,
        payload: &[u8],
    ) -> anyhow::Result<()> {
        if !self.healthy.load(Ordering::Acquire) {
            return Err(anyhow!("mieru underlay connection is closed"));
        }
        let mut writer = self.writer.lock().await;
        writer
            .write_segment(metadata, payload)
            .await
            .inspect_err(|_| {
                self.healthy.store(false, Ordering::Release);
            })
    }
}

impl Drop for MieruConnection {
    fn drop(&mut self) {
        if let Some(task) = self
            .reader_task
            .lock()
            .expect("mieru reader task lock poisoned")
            .take()
        {
            task.abort();
        }
    }
}

impl MieruSessionSender {
    async fn send_open_session(&mut self, payload: &[u8]) -> anyhow::Result<()> {
        match self {
            Self::Stream(sender) => sender.send_open_session(payload).await,
            Self::Packet(sender) => sender.send_open_session(payload).await,
        }
    }

    async fn send_data(&mut self, payload: &[u8]) -> anyhow::Result<()> {
        match self {
            Self::Stream(sender) => sender.send_data(payload).await,
            Self::Packet(sender) => sender.send_data(payload).await,
        }
    }

    async fn send_close(&mut self, response: bool) -> anyhow::Result<()> {
        match self {
            Self::Stream(sender) => sender.send_close(response).await,
            Self::Packet(sender) => sender.send_close(response).await,
        }
    }
}

impl MieruPacketSessionState {
    fn new() -> Self {
        let now = Instant::now();
        Self {
            next_send: 0,
            next_receive: 0,
            receive_buffer: BTreeMap::new(),
            unacknowledged: BTreeMap::new(),
            remote_window: MIERU_PACKET_INITIAL_WINDOW,
            congestion: MieruCubicWindow::new(),
            rtt: MieruRttEstimator::new(),
            last_send: now,
            last_receive: now,
            closed: false,
        }
    }

    fn receive_window(&self) -> u16 {
        MIERU_PACKET_MAX_WINDOW
            .saturating_sub(self.receive_buffer.len() as u32)
            .min(u16::MAX as u32) as u16
    }

    fn send_window(&self) -> usize {
        self.remote_window.min(self.congestion.window()).max(1) as usize
    }
}

impl MieruRttEstimator {
    fn new() -> Self {
        Self {
            smoothed: None,
            deviation: Duration::ZERO,
        }
    }

    fn update(&mut self, sample: Duration) {
        if sample.is_zero() {
            return;
        }
        match self.smoothed {
            None => {
                self.smoothed = Some(sample);
                self.deviation = sample / 2;
            }
            Some(smoothed) => {
                let difference = smoothed.abs_diff(sample);
                self.deviation = duration_weighted(self.deviation, difference, 3, 1, 4);
                self.smoothed = Some(duration_weighted(smoothed, sample, 7, 1, 8));
            }
        }
    }

    fn retransmission_timeout(&self, transmission: u8) -> Duration {
        let base = self
            .smoothed
            .map(|smoothed| {
                smoothed + (self.deviation * 4).max(Duration::from_millis(10)) + MIERU_PACKET_TICK
            })
            .unwrap_or(Duration::from_secs(2));
        let multiplier = 1.5_f64.powi(i32::from(transmission.max(1)));
        base.mul_f64(multiplier).min(MIERU_PACKET_MAX_RTO)
    }
}

impl MieruCubicWindow {
    fn new() -> Self {
        Self {
            window: MIERU_PACKET_INITIAL_WINDOW,
            previous_maximum: 0,
            reduction_time: None,
            accumulated_acks: 0,
            slow_start: true,
        }
    }

    fn window(&self) -> u32 {
        self.window
            .clamp(MIERU_PACKET_INITIAL_WINDOW, MIERU_PACKET_MAX_WINDOW)
    }

    fn on_ack(&mut self) {
        if self.slow_start {
            self.window = (self.window + 1).min(MIERU_PACKET_MAX_WINDOW);
            return;
        }
        self.accumulated_acks = self.accumulated_acks.saturating_add(1);
        let elapsed = self
            .reduction_time
            .map(|time| time.elapsed().as_secs_f64())
            .unwrap_or_default();
        let k = (f64::from(self.previous_maximum) * 0.3 / 0.4).cbrt();
        let cubic = 0.4 * (elapsed - k).powi(3) + f64::from(self.previous_maximum);
        self.window = (cubic.max(0.0) as u32)
            .saturating_add(self.accumulated_acks / 16)
            .clamp(MIERU_PACKET_INITIAL_WINDOW, MIERU_PACKET_MAX_WINDOW);
    }

    fn on_loss(&mut self) {
        self.slow_start = false;
        self.previous_maximum = self.window;
        self.reduction_time = Some(Instant::now());
        self.accumulated_acks = 0;
        self.window = ((f64::from(self.window) * 0.7) as u32).max(MIERU_PACKET_INITIAL_WINDOW);
    }

    fn on_timeout(&mut self) {
        self.slow_start = true;
        self.window = MIERU_PACKET_INITIAL_WINDOW;
        self.previous_maximum = 0;
        self.reduction_time = None;
        self.accumulated_acks = 0;
    }
}

fn duration_weighted(
    first: Duration,
    second: Duration,
    first_weight: u32,
    second_weight: u32,
    divisor: u32,
) -> Duration {
    let nanos = first.as_nanos().saturating_mul(u128::from(first_weight))
        + second.as_nanos().saturating_mul(u128::from(second_weight));
    Duration::from_nanos((nanos / u128::from(divisor)).min(u128::from(u64::MAX)) as u64)
}

impl MieruPacketConnection {
    async fn connect(
        server: &str,
        port: u16,
        username: &str,
        password: &str,
        mtu: u16,
    ) -> anyhow::Result<Arc<Self>> {
        let remote = resolve_udp_socket_addr(server, port, 10_000)
            .await
            .with_context(|| format!("failed to resolve mieru UDP server {server}:{port}"))?;
        let socket = create_bound_udp(remote)
            .with_context(|| format!("failed to create mieru UDP socket for {remote}"))?;
        socket
            .connect(remote)
            .await
            .with_context(|| format!("failed to connect mieru UDP server {remote}"))?;
        let socket = Arc::new(socket);
        let key = derive_mieru_key(username, password, unix_seconds())?;
        let sessions = Arc::new(StdMutex::new(HashMap::new()));
        let healthy = Arc::new(AtomicBool::new(true));
        let connection = Arc::new(Self {
            socket: Arc::clone(&socket),
            key,
            username: username.to_string(),
            mtu,
            sessions: Arc::clone(&sessions),
            healthy: Arc::clone(&healthy),
            active_sessions: AtomicUsize::new(0),
            reader_task: StdMutex::new(None),
            timer_task: StdMutex::new(None),
        });
        let reader = tokio::spawn(run_mieru_packet_reader(
            Arc::clone(&socket),
            key,
            username.to_string(),
            Arc::clone(&sessions),
            Arc::clone(&healthy),
            mtu,
        ));
        let timer = tokio::spawn(run_mieru_packet_timer(
            socket,
            key,
            username.to_string(),
            sessions,
            Arc::clone(&healthy),
            mtu,
        ));
        *connection
            .reader_task
            .lock()
            .expect("mieru UDP reader task lock poisoned") = Some(reader);
        *connection
            .timer_task
            .lock()
            .expect("mieru UDP timer task lock poisoned") = Some(timer);
        Ok(connection)
    }

    fn open_session(
        self: &Arc<Self>,
        max_sessions: usize,
    ) -> anyhow::Result<(
        MieruSessionSender,
        MieruSessionReader,
        Arc<MieruSessionLease>,
    )> {
        if !self.healthy.load(Ordering::Acquire) {
            return Err(anyhow!("mieru UDP underlay is closed"));
        }
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| anyhow!("mieru UDP session map lock poisoned"))?;
        if sessions.len() >= max_sessions {
            return Err(anyhow!("mieru UDP underlay reached its session limit"));
        }
        let session_id = (0..32)
            .find_map(|_| {
                let id = random_u32().ok()?.max(1);
                (!sessions.contains_key(&id)).then_some(id)
            })
            .ok_or_else(|| anyhow!("failed to allocate unique mieru UDP session ID"))?;
        let (tx, rx) = mpsc::channel(MIERU_SESSION_CHANNEL_SIZE);
        let state = Arc::new(Mutex::new(MieruPacketSessionState::new()));
        let wake_sender = Arc::new(Notify::new());
        sessions.insert(
            session_id,
            Arc::new(MieruPacketSessionEntry {
                session_id,
                incoming: tx,
                state: Arc::clone(&state),
                wake_sender: Arc::clone(&wake_sender),
            }),
        );
        drop(sessions);
        self.active_sessions.fetch_add(1, Ordering::AcqRel);
        Ok((
            MieruSessionSender::Packet(MieruPacketSessionSender {
                connection: Arc::clone(self),
                session_id,
                state,
                wake_sender,
            }),
            MieruSessionReader {
                incoming: rx,
                buffered: BytesMut::new(),
                next_sequence: 0,
                opened: false,
            },
            Arc::new(MieruSessionLease::Packet(MieruPacketSessionLease {
                connection: Arc::clone(self),
                session_id,
            })),
        ))
    }

    async fn write_packet(
        &self,
        metadata: &MieruOutboundMetadata,
        payload: &[u8],
    ) -> anyhow::Result<()> {
        if !self.healthy.load(Ordering::Acquire) {
            return Err(anyhow!("mieru UDP underlay is closed"));
        }
        let packet = encode_mieru_packet(self.key, &self.username, self.mtu, metadata, payload)?;
        self.socket
            .send(&packet)
            .await
            .context("failed to send mieru UDP packet")?;
        Ok(())
    }
}

impl Drop for MieruPacketConnection {
    fn drop(&mut self) {
        if let Some(task) = self
            .reader_task
            .lock()
            .expect("mieru UDP reader task lock poisoned")
            .take()
        {
            task.abort();
        }
        if let Some(task) = self
            .timer_task
            .lock()
            .expect("mieru UDP timer task lock poisoned")
            .take()
        {
            task.abort();
        }
    }
}

impl MieruPacketSessionSender {
    async fn send_open_session(&mut self, payload: &[u8]) -> anyhow::Result<()> {
        if payload.len() > MIERU_MAX_SESSION_OPEN_PAYLOAD {
            return Err(anyhow!("mieru open-session payload is too large"));
        }
        let sequence = self.take_sequence().await?;
        self.queue_reliable(
            MieruOutboundMetadata::Session {
                protocol: PROTOCOL_OPEN_SESSION_REQUEST,
                session_id: self.session_id,
                sequence,
                status: 0,
                payload_len: payload.len() as u16,
                suffix_len: 0,
            },
            payload,
        )
        .await
    }

    async fn send_data(&mut self, payload: &[u8]) -> anyhow::Result<()> {
        let max_fragment = usize::from(self.connection.mtu)
            .checked_sub(MIERU_PACKET_OVERHEAD)
            .ok_or_else(|| anyhow!("mieru MTU is too small for packet metadata"))?;
        let chunks = payload.chunks(max_fragment).collect::<Vec<_>>();
        for (index, chunk) in chunks.iter().enumerate() {
            let sequence = self.take_sequence().await?;
            let (unacknowledged_sequence, window_size) = {
                let state = self.state.lock().await;
                (state.next_receive, state.receive_window())
            };
            let fragment = u8::try_from(chunks.len().saturating_sub(index + 1))
                .context("mieru payload requires too many UDP fragments")?;
            self.queue_reliable(
                MieruOutboundMetadata::Data {
                    protocol: PROTOCOL_DATA_CLIENT_TO_SERVER,
                    session_id: self.session_id,
                    sequence,
                    unacknowledged_sequence,
                    window_size,
                    fragment,
                    prefix_len: 0,
                    payload_len: chunk.len() as u16,
                    suffix_len: 0,
                },
                chunk,
            )
            .await?;
        }
        Ok(())
    }

    async fn send_close(&mut self, response: bool) -> anyhow::Result<()> {
        let sequence = self.take_sequence().await?;
        let metadata = MieruOutboundMetadata::Session {
            protocol: if response {
                PROTOCOL_CLOSE_SESSION_RESPONSE
            } else {
                PROTOCOL_CLOSE_SESSION_REQUEST
            },
            session_id: self.session_id,
            sequence,
            status: 0,
            payload_len: 0,
            suffix_len: 0,
        };
        if response {
            self.connection.write_packet(&metadata, &[]).await
        } else {
            self.queue_reliable(metadata, &[]).await
        }
    }

    async fn take_sequence(&self) -> anyhow::Result<u32> {
        let mut state = self.state.lock().await;
        if state.closed {
            return Err(anyhow!("mieru UDP logical session is closed"));
        }
        let sequence = state.next_send;
        state.next_send = state.next_send.wrapping_add(1);
        Ok(sequence)
    }

    async fn queue_reliable(
        &self,
        metadata: MieruOutboundMetadata,
        payload: &[u8],
    ) -> anyhow::Result<()> {
        self.wait_for_send_window().await?;
        let sequence = metadata.sequence();
        {
            let mut state = self.state.lock().await;
            if state.closed {
                return Err(anyhow!("mieru UDP logical session is closed"));
            }
            let retransmission_timeout = state.rtt.retransmission_timeout(1);
            state.unacknowledged.insert(
                sequence,
                MieruPendingPacket {
                    metadata: metadata.clone(),
                    payload: payload.to_vec(),
                    sent_at: Instant::now(),
                    timeout: retransmission_timeout,
                    transmissions: 1,
                    duplicate_acks: 0,
                },
            );
            state.last_send = Instant::now();
        }
        if let Err(error) = self.connection.write_packet(&metadata, payload).await {
            self.state.lock().await.unacknowledged.remove(&sequence);
            self.wake_sender.notify_waiters();
            return Err(error);
        }
        Ok(())
    }

    async fn wait_for_send_window(&self) -> anyhow::Result<()> {
        loop {
            let notified = self.wake_sender.notified();
            {
                let state = self.state.lock().await;
                if state.closed {
                    return Err(anyhow!("mieru UDP logical session is closed"));
                }
                if state.unacknowledged.len() < state.send_window() {
                    return Ok(());
                }
            }
            timeout(MIERU_PACKET_MAX_RTO, notified)
                .await
                .context("mieru UDP send window remained blocked")?;
        }
    }
}

impl Drop for MieruPacketSessionLease {
    fn drop(&mut self) {
        if let Ok(mut sessions) = self.connection.sessions.lock() {
            if let Some(entry) = sessions.remove(&self.session_id) {
                if let Ok(mut state) = entry.state.try_lock() {
                    state.closed = true;
                }
                entry.wake_sender.notify_waiters();
                self.connection
                    .active_sessions
                    .fetch_sub(1, Ordering::AcqRel);
            }
        }
    }
}

impl MieruConnectionWriter {
    async fn write_segment(
        &mut self,
        metadata: MieruOutboundMetadata,
        payload: &[u8],
    ) -> anyhow::Result<()> {
        let (prefix, suffix, metadata) = match metadata {
            MieruOutboundMetadata::Session {
                protocol,
                session_id,
                sequence,
                status,
                payload_len,
                ..
            } => {
                let suffix = random_padding()?;
                let metadata = MieruOutboundMetadata::Session {
                    protocol,
                    session_id,
                    sequence,
                    status,
                    payload_len,
                    suffix_len: suffix.len() as u8,
                };
                (Vec::new(), suffix, metadata)
            }
            MieruOutboundMetadata::Data {
                protocol,
                session_id,
                sequence,
                unacknowledged_sequence,
                window_size,
                fragment,
                payload_len,
                ..
            } => {
                let prefix = random_padding()?;
                let suffix = random_padding()?;
                let metadata = MieruOutboundMetadata::Data {
                    protocol,
                    session_id,
                    sequence,
                    unacknowledged_sequence,
                    window_size,
                    fragment,
                    prefix_len: prefix.len() as u8,
                    payload_len,
                    suffix_len: suffix.len() as u8,
                };
                (prefix, suffix, metadata)
            }
        };
        let encrypted_metadata = self.cipher.encrypt(&metadata.marshal())?;
        self.writer.write_all(&encrypted_metadata).await?;
        self.writer.write_all(&prefix).await?;
        if !payload.is_empty() {
            let encrypted_payload = self.cipher.encrypt(payload)?;
            self.writer.write_all(&encrypted_payload).await?;
        }
        self.writer.write_all(&suffix).await?;
        self.writer.flush().await?;
        Ok(())
    }
}

impl MieruStreamSessionSender {
    async fn send_open_session(&mut self, payload: &[u8]) -> anyhow::Result<()> {
        if payload.len() > MIERU_MAX_SESSION_OPEN_PAYLOAD {
            return Err(anyhow!("mieru open-session payload is too large"));
        }
        let sequence = self.take_sequence();
        self.connection
            .write_segment(
                MieruOutboundMetadata::Session {
                    protocol: PROTOCOL_OPEN_SESSION_REQUEST,
                    session_id: self.session_id,
                    sequence,
                    status: 0,
                    payload_len: payload.len() as u16,
                    suffix_len: 0,
                },
                payload,
            )
            .await
    }

    async fn send_data(&mut self, payload: &[u8]) -> anyhow::Result<()> {
        for chunk in payload.chunks(MIERU_MAX_STREAM_PAYLOAD) {
            let sequence = self.take_sequence();
            self.connection
                .write_segment(
                    MieruOutboundMetadata::Data {
                        protocol: PROTOCOL_DATA_CLIENT_TO_SERVER,
                        session_id: self.session_id,
                        sequence,
                        unacknowledged_sequence: 0,
                        window_size: 4_096,
                        fragment: 0,
                        prefix_len: 0,
                        payload_len: chunk.len() as u16,
                        suffix_len: 0,
                    },
                    chunk,
                )
                .await?;
        }
        Ok(())
    }

    async fn send_close(&mut self, response: bool) -> anyhow::Result<()> {
        let sequence = self.take_sequence();
        self.connection
            .write_segment(
                MieruOutboundMetadata::Session {
                    protocol: if response {
                        PROTOCOL_CLOSE_SESSION_RESPONSE
                    } else {
                        PROTOCOL_CLOSE_SESSION_REQUEST
                    },
                    session_id: self.session_id,
                    sequence,
                    status: 0,
                    payload_len: 0,
                    suffix_len: 0,
                },
                &[],
            )
            .await
    }

    fn take_sequence(&mut self) -> u32 {
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.wrapping_add(1);
        sequence
    }
}

impl MieruSessionReader {
    async fn read_exact(&mut self, length: usize) -> anyhow::Result<Vec<u8>> {
        while self.buffered.len() < length {
            self.read_next_payload().await?;
        }
        Ok(self.buffered.split_to(length).to_vec())
    }

    async fn read_next_payload(&mut self) -> anyhow::Result<()> {
        loop {
            let segment = self
                .incoming
                .recv()
                .await
                .ok_or_else(|| anyhow!("mieru underlay closed the logical session"))?;
            let segment = match segment {
                MieruInboundEvent::Segment(segment) => segment,
                MieruInboundEvent::Error(error) => return Err(anyhow!(error)),
            };
            if segment.sequence != self.next_sequence
                && segment.protocol != PROTOCOL_ACK_SERVER_TO_CLIENT
            {
                return Err(anyhow!(
                    "mieru session {} received sequence {}, expected {}",
                    segment.session_id,
                    segment.sequence,
                    self.next_sequence
                ));
            }
            match segment.protocol {
                PROTOCOL_OPEN_SESSION_RESPONSE => {
                    self.next_sequence = self.next_sequence.wrapping_add(1);
                    if segment.status != 0 {
                        return Err(anyhow!(
                            "mieru server rejected session {} with status {}",
                            segment.session_id,
                            segment.status
                        ));
                    }
                    self.opened = true;
                    if !segment.payload.is_empty() {
                        self.buffered.extend_from_slice(&segment.payload);
                        return Ok(());
                    }
                }
                PROTOCOL_DATA_SERVER_TO_CLIENT => {
                    if !self.opened {
                        return Err(anyhow!("mieru server sent data before opening the session"));
                    }
                    self.next_sequence = self.next_sequence.wrapping_add(1);
                    if !segment.payload.is_empty() {
                        self.buffered.extend_from_slice(&segment.payload);
                        return Ok(());
                    }
                }
                PROTOCOL_ACK_SERVER_TO_CLIENT => {}
                PROTOCOL_CLOSE_SESSION_REQUEST | PROTOCOL_CLOSE_SESSION_RESPONSE => {
                    return Err(anyhow!("mieru server closed the logical session"));
                }
                protocol => {
                    return Err(anyhow!("unexpected mieru server protocol {protocol}"));
                }
            }
        }
    }

    fn take_buffered(&mut self) -> Vec<u8> {
        self.buffered.split().to_vec()
    }
}

impl Drop for MieruStreamSessionLease {
    fn drop(&mut self) {
        if let Ok(mut sessions) = self.connection.sessions.lock() {
            if sessions.remove(&self.session_id).is_some() {
                self.connection
                    .active_sessions
                    .fetch_sub(1, Ordering::AcqRel);
            }
        }
    }
}

impl MieruOutboundMetadata {
    fn marshal(&self) -> [u8; MIERU_METADATA_LENGTH] {
        let mut output = [0u8; MIERU_METADATA_LENGTH];
        output[0] = self.protocol();
        output[2..6].copy_from_slice(&(unix_seconds() as u32 / 60).to_be_bytes());
        match self {
            Self::Session {
                session_id,
                sequence,
                status,
                payload_len,
                suffix_len,
                ..
            } => {
                output[6..10].copy_from_slice(&session_id.to_be_bytes());
                output[10..14].copy_from_slice(&sequence.to_be_bytes());
                output[14] = *status;
                output[15..17].copy_from_slice(&payload_len.to_be_bytes());
                output[17] = *suffix_len;
            }
            Self::Data {
                session_id,
                sequence,
                unacknowledged_sequence,
                window_size,
                fragment,
                prefix_len,
                payload_len,
                suffix_len,
                ..
            } => {
                output[6..10].copy_from_slice(&session_id.to_be_bytes());
                output[10..14].copy_from_slice(&sequence.to_be_bytes());
                output[14..18].copy_from_slice(&unacknowledged_sequence.to_be_bytes());
                output[18..20].copy_from_slice(&window_size.to_be_bytes());
                output[20] = *fragment;
                output[21] = *prefix_len;
                output[22..24].copy_from_slice(&payload_len.to_be_bytes());
                output[24] = *suffix_len;
            }
        }
        output
    }

    fn protocol(&self) -> u8 {
        match self {
            Self::Session { protocol, .. } | Self::Data { protocol, .. } => *protocol,
        }
    }

    fn sequence(&self) -> u32 {
        match self {
            Self::Session { sequence, .. } | Self::Data { sequence, .. } => *sequence,
        }
    }

    fn refresh_flow_control(&mut self, unacknowledged_sequence: u32, window_size: u16) {
        if let Self::Data {
            unacknowledged_sequence: current_unacknowledged,
            window_size: current_window,
            ..
        } = self
        {
            *current_unacknowledged = unacknowledged_sequence;
            *current_window = window_size;
        }
    }
}

impl MieruInboundMetadata {
    fn parse(input: &[u8]) -> anyhow::Result<Self> {
        if input.len() != MIERU_METADATA_LENGTH {
            return Err(anyhow!("invalid mieru metadata length {}", input.len()));
        }
        let protocol = input[0];
        let timestamp = u32::from_be_bytes(input[2..6].try_into().expect("fixed timestamp"));
        let current = unix_seconds() as u32 / 60;
        if current.abs_diff(timestamp) > 1 {
            return Err(anyhow!(
                "mieru metadata timestamp is outside the accepted window"
            ));
        }
        let session_id = u32::from_be_bytes(input[6..10].try_into().expect("fixed session ID"));
        let sequence = u32::from_be_bytes(input[10..14].try_into().expect("fixed sequence"));
        match protocol {
            PROTOCOL_OPEN_SESSION_REQUEST
            | PROTOCOL_OPEN_SESSION_RESPONSE
            | PROTOCOL_CLOSE_SESSION_REQUEST
            | PROTOCOL_CLOSE_SESSION_RESPONSE => {
                let payload_len = u16::from_be_bytes(
                    input[15..17]
                        .try_into()
                        .expect("fixed session payload length"),
                ) as usize;
                if payload_len > MIERU_MAX_SESSION_OPEN_PAYLOAD {
                    return Err(anyhow!("mieru session payload exceeds protocol limit"));
                }
                Ok(Self {
                    protocol,
                    session_id,
                    sequence,
                    status: input[14],
                    unacknowledged_sequence: 0,
                    window_size: 0,
                    fragment: 0,
                    prefix_len: 0,
                    payload_len,
                    suffix_len: input[17] as usize,
                })
            }
            PROTOCOL_DATA_CLIENT_TO_SERVER
            | PROTOCOL_DATA_SERVER_TO_CLIENT
            | PROTOCOL_ACK_CLIENT_TO_SERVER
            | PROTOCOL_ACK_SERVER_TO_CLIENT => Ok(Self {
                protocol,
                session_id,
                sequence,
                status: 0,
                unacknowledged_sequence: u32::from_be_bytes(
                    input[14..18]
                        .try_into()
                        .expect("fixed unacknowledged sequence"),
                ),
                window_size: u16::from_be_bytes(
                    input[18..20].try_into().expect("fixed receive window"),
                ),
                fragment: input[20],
                prefix_len: input[21] as usize,
                payload_len: u16::from_be_bytes(
                    input[22..24].try_into().expect("fixed data payload length"),
                ) as usize,
                suffix_len: input[24] as usize,
            }),
            _ => Err(anyhow!("unsupported mieru server protocol {protocol}")),
        }
    }
}

impl MieruStatefulCipher {
    fn new(key: [u8; 32], username: String) -> Self {
        Self {
            cipher: XChaCha20Poly1305::new((&key).into()),
            nonce: None,
            username,
        }
    }

    fn encrypt(&mut self, plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
        let first = self.nonce.is_none();
        let nonce = if let Some(mut nonce) = self.nonce {
            increment_nonce(&mut nonce);
            self.nonce = Some(nonce);
            nonce
        } else {
            let mut nonce = [0u8; MIERU_NONCE_LENGTH];
            getrandom::fill(&mut nonce).context("failed to generate mieru nonce")?;
            apply_user_hint(&self.username, &mut nonce);
            self.nonce = Some(nonce);
            nonce
        };
        let encrypted = self
            .cipher
            .encrypt(XNonce::from_slice(&nonce), plaintext)
            .map_err(|_| anyhow!("failed to encrypt mieru segment"))?;
        if first {
            let mut output = Vec::with_capacity(MIERU_NONCE_LENGTH + encrypted.len());
            output.extend_from_slice(&nonce);
            output.extend_from_slice(&encrypted);
            Ok(output)
        } else {
            Ok(encrypted)
        }
    }

    fn decrypt(&mut self, ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
        let body = if let Some(nonce) = self.nonce.as_mut() {
            increment_nonce(nonce);
            ciphertext
        } else {
            if ciphertext.len() < MIERU_NONCE_LENGTH + MIERU_TAG_LENGTH {
                return Err(anyhow!("mieru first encrypted segment is too short"));
            }
            let mut nonce = [0u8; MIERU_NONCE_LENGTH];
            nonce.copy_from_slice(&ciphertext[..MIERU_NONCE_LENGTH]);
            self.nonce = Some(nonce);
            &ciphertext[MIERU_NONCE_LENGTH..]
        };
        let nonce = self
            .nonce
            .as_ref()
            .ok_or_else(|| anyhow!("mieru nonce is not initialized"))?;
        self.cipher
            .decrypt(XNonce::from_slice(nonce), body)
            .map_err(|_| anyhow!("failed to authenticate mieru segment"))
    }
}

async fn run_mieru_connection_reader<R>(
    mut reader: R,
    key: [u8; 32],
    username: String,
    sessions: Arc<StdMutex<HashMap<u32, mpsc::Sender<MieruInboundEvent>>>>,
    healthy: Arc<AtomicBool>,
) where
    R: AsyncRead + Unpin,
{
    let mut cipher = MieruStatefulCipher::new(key, username);
    let terminal_error = loop {
        let segment = match read_mieru_segment(&mut reader, &mut cipher).await {
            Ok(segment) => segment,
            Err(error) => break error.to_string(),
        };
        let sender = sessions
            .lock()
            .ok()
            .and_then(|sessions| sessions.get(&segment.session_id).cloned());
        if let Some(sender) = sender {
            if sender
                .send(MieruInboundEvent::Segment(segment))
                .await
                .is_err()
            {
                continue;
            }
        }
    };
    healthy.store(false, Ordering::Release);
    let senders = sessions
        .lock()
        .map(|sessions| sessions.values().cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    for sender in senders {
        let _ = sender
            .send(MieruInboundEvent::Error(terminal_error.clone()))
            .await;
    }
    if let Ok(mut sessions) = sessions.lock() {
        sessions.clear();
    }
}

async fn read_mieru_segment<R>(
    reader: &mut R,
    cipher: &mut MieruStatefulCipher,
) -> anyhow::Result<MieruInboundSegment>
where
    R: AsyncRead + Unpin,
{
    let encrypted_metadata_len = MIERU_METADATA_LENGTH
        + MIERU_TAG_LENGTH
        + usize::from(cipher.nonce.is_none()) * MIERU_NONCE_LENGTH;
    let mut encrypted_metadata = vec![0u8; encrypted_metadata_len];
    reader.read_exact(&mut encrypted_metadata).await?;
    let plaintext_metadata = cipher.decrypt(&encrypted_metadata)?;
    let metadata = MieruInboundMetadata::parse(&plaintext_metadata)?;
    if metadata.prefix_len > 0 {
        let mut prefix = vec![0u8; metadata.prefix_len];
        reader.read_exact(&mut prefix).await?;
    }
    let payload = if metadata.payload_len > 0 {
        let mut encrypted_payload = vec![0u8; metadata.payload_len + MIERU_TAG_LENGTH];
        reader.read_exact(&mut encrypted_payload).await?;
        cipher.decrypt(&encrypted_payload)?
    } else {
        Vec::new()
    };
    if metadata.suffix_len > 0 {
        let mut suffix = vec![0u8; metadata.suffix_len];
        reader.read_exact(&mut suffix).await?;
    }
    Ok(MieruInboundSegment {
        protocol: metadata.protocol,
        session_id: metadata.session_id,
        sequence: metadata.sequence,
        status: metadata.status,
        unacknowledged_sequence: metadata.unacknowledged_sequence,
        window_size: metadata.window_size,
        fragment: metadata.fragment,
        payload,
    })
}

fn encode_mieru_packet(
    key: [u8; 32],
    username: &str,
    mtu: u16,
    metadata: &MieruOutboundMetadata,
    payload: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let payload_overhead = usize::from(!payload.is_empty()) * MIERU_TAG_LENGTH;
    let fixed_size = MIERU_NONCE_LENGTH
        + MIERU_METADATA_LENGTH
        + MIERU_TAG_LENGTH
        + payload.len()
        + payload_overhead;
    if fixed_size > usize::from(mtu) {
        return Err(anyhow!(
            "mieru UDP packet size {fixed_size} exceeds configured MTU {mtu}"
        ));
    }
    let padding_limit = (usize::from(mtu) - fixed_size).min(MIERU_MAX_RANDOM_PADDING);
    let suffix = random_padding_with_limit(padding_limit)?;
    let mut metadata = metadata.clone();
    match &mut metadata {
        MieruOutboundMetadata::Session { suffix_len, .. }
        | MieruOutboundMetadata::Data { suffix_len, .. } => {
            *suffix_len = suffix.len() as u8;
        }
    }

    let mut nonce = [0u8; MIERU_NONCE_LENGTH];
    getrandom::fill(&mut nonce).context("failed to generate mieru UDP nonce")?;
    apply_user_hint(username, &mut nonce);
    let cipher = XChaCha20Poly1305::new((&key).into());
    let encrypted_metadata = cipher
        .encrypt(XNonce::from_slice(&nonce), metadata.marshal().as_slice())
        .map_err(|_| anyhow!("failed to encrypt mieru UDP metadata"))?;
    let mut output = Vec::with_capacity(fixed_size + suffix.len());
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&encrypted_metadata);
    if !payload.is_empty() {
        let encrypted_payload = cipher
            .encrypt(XNonce::from_slice(&nonce), payload)
            .map_err(|_| anyhow!("failed to encrypt mieru UDP payload"))?;
        output.extend_from_slice(&encrypted_payload);
    }
    output.extend_from_slice(&suffix);
    Ok(output)
}

fn decode_mieru_packet(key: [u8; 32], packet: &[u8]) -> anyhow::Result<MieruInboundSegment> {
    let metadata_end = MIERU_NONCE_LENGTH + MIERU_METADATA_LENGTH + MIERU_TAG_LENGTH;
    if packet.len() < metadata_end {
        return Err(anyhow!(
            "mieru UDP packet is shorter than encrypted metadata"
        ));
    }
    let nonce: &[u8; MIERU_NONCE_LENGTH] = packet[..MIERU_NONCE_LENGTH]
        .try_into()
        .expect("fixed mieru nonce");
    let cipher = XChaCha20Poly1305::new((&key).into());
    let plaintext_metadata = cipher
        .decrypt(
            XNonce::from_slice(nonce),
            &packet[MIERU_NONCE_LENGTH..metadata_end],
        )
        .map_err(|_| anyhow!("failed to authenticate mieru UDP metadata"))?;
    let metadata = MieruInboundMetadata::parse(&plaintext_metadata)?;
    let payload_start = metadata_end
        .checked_add(metadata.prefix_len)
        .ok_or_else(|| anyhow!("mieru UDP prefix length overflow"))?;
    let payload_ciphertext_len =
        metadata.payload_len + usize::from(metadata.payload_len > 0) * MIERU_TAG_LENGTH;
    let payload_end = payload_start
        .checked_add(payload_ciphertext_len)
        .ok_or_else(|| anyhow!("mieru UDP payload length overflow"))?;
    let expected = payload_end
        .checked_add(metadata.suffix_len)
        .ok_or_else(|| anyhow!("mieru UDP suffix length overflow"))?;
    if expected != packet.len() {
        return Err(anyhow!(
            "mieru UDP packet length {} does not match metadata {expected}",
            packet.len()
        ));
    }
    let payload = if metadata.payload_len == 0 {
        Vec::new()
    } else {
        cipher
            .decrypt(
                XNonce::from_slice(nonce),
                &packet[payload_start..payload_end],
            )
            .map_err(|_| anyhow!("failed to authenticate mieru UDP payload"))?
    };
    Ok(MieruInboundSegment {
        protocol: metadata.protocol,
        session_id: metadata.session_id,
        sequence: metadata.sequence,
        status: metadata.status,
        unacknowledged_sequence: metadata.unacknowledged_sequence,
        window_size: metadata.window_size,
        fragment: metadata.fragment,
        payload,
    })
}

async fn run_mieru_packet_reader(
    socket: Arc<UdpSocket>,
    key: [u8; 32],
    username: String,
    sessions: Arc<StdMutex<HashMap<u32, Arc<MieruPacketSessionEntry>>>>,
    healthy: Arc<AtomicBool>,
    mtu: u16,
) {
    let terminal_error = loop {
        let mut packet = [0u8; MIERU_MAX_MTU as usize];
        let size = match socket.recv(&mut packet).await {
            Ok(size) => size,
            Err(error) => break format!("mieru UDP receive failed: {error}"),
        };
        let segment = match decode_mieru_packet(key, &packet[..size]) {
            Ok(segment) => segment,
            Err(_) => continue,
        };
        let entry = sessions
            .lock()
            .ok()
            .and_then(|sessions| sessions.get(&segment.session_id).cloned());
        let Some(entry) = entry else {
            continue;
        };
        if let Err(error) =
            process_mieru_packet_segment(&socket, key, &username, mtu, entry, segment).await
        {
            break error.to_string();
        }
    };
    healthy.store(false, Ordering::Release);
    fail_mieru_packet_sessions(&sessions, &terminal_error).await;
}

async fn process_mieru_packet_segment(
    socket: &Arc<UdpSocket>,
    key: [u8; 32],
    username: &str,
    mtu: u16,
    entry: Arc<MieruPacketSessionEntry>,
    segment: MieruInboundSegment,
) -> anyhow::Result<()> {
    if matches!(
        segment.protocol,
        PROTOCOL_DATA_SERVER_TO_CLIENT | PROTOCOL_ACK_SERVER_TO_CLIENT
    ) {
        acknowledge_mieru_packets(&entry, &segment).await;
    }

    match segment.protocol {
        PROTOCOL_OPEN_SESSION_RESPONSE | PROTOCOL_DATA_SERVER_TO_CLIENT => {
            let (deliver, ack) = {
                let mut state = entry.state.lock().await;
                state.last_receive = Instant::now();
                if segment.sequence >= state.next_receive
                    && state.receive_buffer.len() < MIERU_PACKET_MAX_WINDOW as usize
                {
                    state
                        .receive_buffer
                        .entry(segment.sequence)
                        .or_insert(segment);
                }
                let mut deliver = Vec::new();
                loop {
                    let sequence = state.next_receive;
                    let Some(next) = state.receive_buffer.remove(&sequence) else {
                        break;
                    };
                    state.next_receive = state.next_receive.wrapping_add(1);
                    deliver.push(next);
                }
                let ack = packet_ack_metadata(entry.session_id, &state);
                (deliver, ack)
            };
            for segment in deliver {
                let _ = segment.fragment;
                if entry
                    .incoming
                    .send(MieruInboundEvent::Segment(segment))
                    .await
                    .is_err()
                {
                    return Ok(());
                }
            }
            send_mieru_packet(socket, key, username, mtu, &ack, &[]).await?;
        }
        PROTOCOL_ACK_SERVER_TO_CLIENT => {}
        PROTOCOL_CLOSE_SESSION_REQUEST | PROTOCOL_CLOSE_SESSION_RESPONSE => {
            if segment.protocol == PROTOCOL_CLOSE_SESSION_REQUEST {
                let response = {
                    let mut state = entry.state.lock().await;
                    let sequence = state.next_send;
                    state.next_send = state.next_send.wrapping_add(1);
                    MieruOutboundMetadata::Session {
                        protocol: PROTOCOL_CLOSE_SESSION_RESPONSE,
                        session_id: segment.session_id,
                        sequence,
                        status: 0,
                        payload_len: 0,
                        suffix_len: 0,
                    }
                };
                send_mieru_packet(socket, key, username, mtu, &response, &[]).await?;
            }
            entry
                .incoming
                .send(MieruInboundEvent::Segment(segment))
                .await
                .ok();
            let mut state = entry.state.lock().await;
            state.closed = true;
            entry.wake_sender.notify_waiters();
        }
        protocol => {
            return Err(anyhow!("unexpected mieru UDP server protocol {protocol}"));
        }
    }
    Ok(())
}

async fn acknowledge_mieru_packets(entry: &MieruPacketSessionEntry, segment: &MieruInboundSegment) {
    let mut state = entry.state.lock().await;
    state.remote_window = u32::from(segment.window_size);
    let acknowledged = state
        .unacknowledged
        .range(..segment.unacknowledged_sequence)
        .map(|(sequence, _)| *sequence)
        .collect::<Vec<_>>();
    for sequence in &acknowledged {
        if let Some(packet) = state.unacknowledged.remove(sequence) {
            state.rtt.update(packet.sent_at.elapsed());
            state.congestion.on_ack();
        }
    }
    if acknowledged.is_empty() {
        let mut fast_retransmit = false;
        if let Some(packet) = state
            .unacknowledged
            .get_mut(&segment.unacknowledged_sequence)
        {
            packet.duplicate_acks = packet.duplicate_acks.saturating_add(1);
            if packet.duplicate_acks >= 3 && packet.transmissions <= 1 {
                packet.sent_at = Instant::now()
                    .checked_sub(packet.timeout)
                    .unwrap_or_else(Instant::now);
                fast_retransmit = true;
            }
        }
        if fast_retransmit {
            state.congestion.on_loss();
        }
    }
    drop(state);
    if !acknowledged.is_empty() {
        entry.wake_sender.notify_waiters();
    }
}

fn packet_ack_metadata(session_id: u32, state: &MieruPacketSessionState) -> MieruOutboundMetadata {
    MieruOutboundMetadata::Data {
        protocol: PROTOCOL_ACK_CLIENT_TO_SERVER,
        session_id,
        sequence: state.next_send.saturating_sub(1),
        unacknowledged_sequence: state.next_receive,
        window_size: state.receive_window(),
        fragment: 0,
        prefix_len: 0,
        payload_len: 0,
        suffix_len: 0,
    }
}

async fn run_mieru_packet_timer(
    socket: Arc<UdpSocket>,
    key: [u8; 32],
    username: String,
    sessions: Arc<StdMutex<HashMap<u32, Arc<MieruPacketSessionEntry>>>>,
    healthy: Arc<AtomicBool>,
    mtu: u16,
) {
    while healthy.load(Ordering::Acquire) {
        sleep(MIERU_PACKET_TICK).await;
        let entries = sessions
            .lock()
            .map(|sessions| sessions.values().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        for entry in entries {
            let (packets, heartbeat, terminal_error) = {
                let mut state = entry.state.lock().await;
                if state.closed {
                    continue;
                }
                let rtt = state.rtt.clone();
                let next_receive = state.next_receive;
                let receive_window = state.receive_window();
                let now = Instant::now();
                let mut packets = Vec::new();
                let mut terminal_error = None;
                let mut timed_out = false;
                for pending in state.unacknowledged.values_mut() {
                    if now.duration_since(pending.sent_at) < pending.timeout {
                        continue;
                    }
                    if pending.transmissions >= MIERU_PACKET_MAX_TRANSMISSIONS {
                        terminal_error = Some(format!(
                            "mieru UDP session exceeded {} transmissions for sequence {}",
                            MIERU_PACKET_MAX_TRANSMISSIONS,
                            pending.metadata.sequence()
                        ));
                        break;
                    }
                    pending.transmissions = pending.transmissions.saturating_add(1);
                    pending.sent_at = now;
                    pending.timeout = rtt.retransmission_timeout(pending.transmissions);
                    pending.duplicate_acks = 0;
                    pending
                        .metadata
                        .refresh_flow_control(next_receive, receive_window);
                    packets.push((pending.metadata.clone(), pending.payload.clone()));
                    timed_out = true;
                }
                if timed_out {
                    state.congestion.on_timeout();
                    state.last_send = now;
                }
                let heartbeat = if terminal_error.is_none()
                    && state.last_send.elapsed() >= MIERU_PACKET_HEARTBEAT
                {
                    state.last_send = now;
                    Some(packet_ack_metadata(entry.session_id, &state))
                } else {
                    None
                };
                if terminal_error.is_some() {
                    state.closed = true;
                }
                (packets, heartbeat, terminal_error)
            };
            if let Some(error) = terminal_error {
                entry.wake_sender.notify_waiters();
                entry
                    .incoming
                    .send(MieruInboundEvent::Error(error))
                    .await
                    .ok();
                continue;
            }
            for (metadata, payload) in packets {
                if let Err(error) =
                    send_mieru_packet(&socket, key, &username, mtu, &metadata, &payload).await
                {
                    healthy.store(false, Ordering::Release);
                    fail_mieru_packet_sessions(&sessions, &error.to_string()).await;
                    return;
                }
            }
            if let Some(metadata) = heartbeat {
                if let Err(error) =
                    send_mieru_packet(&socket, key, &username, mtu, &metadata, &[]).await
                {
                    healthy.store(false, Ordering::Release);
                    fail_mieru_packet_sessions(&sessions, &error.to_string()).await;
                    return;
                }
            }
        }
    }
}

async fn send_mieru_packet(
    socket: &UdpSocket,
    key: [u8; 32],
    username: &str,
    mtu: u16,
    metadata: &MieruOutboundMetadata,
    payload: &[u8],
) -> anyhow::Result<()> {
    let packet = encode_mieru_packet(key, username, mtu, metadata, payload)?;
    socket
        .send(&packet)
        .await
        .context("failed to send mieru UDP packet")?;
    Ok(())
}

async fn fail_mieru_packet_sessions(
    sessions: &StdMutex<HashMap<u32, Arc<MieruPacketSessionEntry>>>,
    error: &str,
) {
    let entries = sessions
        .lock()
        .map(|sessions| sessions.values().cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    for entry in entries {
        {
            let mut state = entry.state.lock().await;
            state.closed = true;
        }
        entry.wake_sender.notify_waiters();
        entry
            .incoming
            .send(MieruInboundEvent::Error(error.to_string()))
            .await
            .ok();
    }
}

fn spawn_mieru_session_bridge(
    sender: Arc<Mutex<MieruSessionSender>>,
    mut receiver: MieruSessionReader,
    lease: Arc<MieruSessionLease>,
    pending_socks_handshake: bool,
) -> DuplexStream {
    let (client, bridge) = tokio::io::duplex(MIERU_STREAM_BUFFER_SIZE);
    let (mut bridge_read, mut bridge_write) = split(bridge);
    let cancellation = CancellationToken::new();

    let upload_cancellation = cancellation.clone();
    let upload_sender = Arc::clone(&sender);
    let upload_lease = Arc::clone(&lease);
    tokio::spawn(async move {
        let _lease = upload_lease;
        let mut buffer = vec![0u8; MIERU_MAX_STREAM_PAYLOAD];
        loop {
            let read = tokio::select! {
                _ = upload_cancellation.cancelled() => break,
                result = bridge_read.read(&mut buffer) => result,
            };
            match read {
                Ok(0) => {
                    let _ = upload_sender.lock().await.send_close(false).await;
                    break;
                }
                Ok(size) => {
                    if upload_sender
                        .lock()
                        .await
                        .send_data(&buffer[..size])
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        upload_cancellation.cancel();
    });

    let download_cancellation = cancellation.clone();
    tokio::spawn(async move {
        let _lease = lease;
        if pending_socks_handshake && read_socks5_command_response(&mut receiver).await.is_err() {
            download_cancellation.cancel();
            return;
        }
        let buffered = receiver.take_buffered();
        if !buffered.is_empty() && bridge_write.write_all(&buffered).await.is_err() {
            download_cancellation.cancel();
            return;
        }
        loop {
            let next = tokio::select! {
                _ = download_cancellation.cancelled() => break,
                result = receiver.read_next_payload() => result,
            };
            match next {
                Ok(()) => {
                    let buffered = receiver.take_buffered();
                    if !buffered.is_empty() && bridge_write.write_all(&buffered).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = bridge_write.shutdown().await;
        download_cancellation.cancel();
    });

    client
}

async fn read_socks5_command_response(reader: &mut MieruSessionReader) -> anyhow::Result<()> {
    let header = reader.read_exact(4).await?;
    if header[0] != 5 {
        return Err(anyhow!("invalid SOCKS5 response version {}", header[0]));
    }
    if header[1] != 0 {
        return Err(anyhow!(
            "mieru server rejected SOCKS5 command with status {}",
            header[1]
        ));
    }
    match header[3] {
        1 => {
            reader.read_exact(6).await?;
        }
        3 => {
            let length = reader.read_exact(1).await?[0] as usize;
            reader.read_exact(length + 2).await?;
        }
        4 => {
            reader.read_exact(18).await?;
        }
        address_type => return Err(anyhow!("invalid SOCKS5 address type {address_type}")),
    }
    Ok(())
}

fn build_socks5_request(command: u8, destination: &Destination) -> anyhow::Result<Vec<u8>> {
    let mut request = vec![5, command, 0];
    encode_socks5_destination(destination, &mut request)?;
    Ok(request)
}

fn encode_mieru_udp_tunnel_packet(
    destination: &Destination,
    payload: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let mut datagram = vec![0, 0, 0];
    encode_socks5_destination(destination, &mut datagram)?;
    datagram.extend_from_slice(payload);
    let length = u16::try_from(datagram.len()).context("mieru UDP datagram exceeds 65535 bytes")?;
    let mut packet = Vec::with_capacity(datagram.len() + 4);
    packet.push(0);
    packet.extend_from_slice(&length.to_be_bytes());
    packet.extend_from_slice(&datagram);
    packet.push(0xff);
    Ok(packet)
}

async fn read_mieru_udp_tunnel_packet<R>(reader: &mut R) -> anyhow::Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let marker = reader.read_u8().await?;
    if marker != 0 {
        return Err(anyhow!("invalid mieru UDP tunnel start marker {marker}"));
    }
    let length = reader.read_u16().await? as usize;
    let mut datagram = vec![0u8; length];
    reader.read_exact(&mut datagram).await?;
    if reader.read_u8().await? != 0xff {
        return Err(anyhow!("invalid mieru UDP tunnel end marker"));
    }
    if datagram.len() < 4 || datagram[0..3] != [0, 0, 0] {
        return Err(anyhow!("invalid SOCKS5 UDP datagram from mieru server"));
    }
    let address_length = socks5_address_length(&datagram[3..])?;
    let payload_offset = 3 + address_length;
    if payload_offset > datagram.len() {
        return Err(anyhow!("truncated SOCKS5 UDP datagram from mieru server"));
    }
    Ok(datagram[payload_offset..].to_vec())
}

fn socks5_address_length(input: &[u8]) -> anyhow::Result<usize> {
    let Some(address_type) = input.first().copied() else {
        return Err(anyhow!("missing SOCKS5 UDP address"));
    };
    match address_type {
        1 => Ok(1 + 4 + 2),
        3 => {
            let length = input
                .get(1)
                .copied()
                .ok_or_else(|| anyhow!("missing SOCKS5 UDP domain length"))?
                as usize;
            Ok(1 + 1 + length + 2)
        }
        4 => Ok(1 + 16 + 2),
        _ => Err(anyhow!(
            "unsupported SOCKS5 UDP address type {address_type}"
        )),
    }
}

fn derive_mieru_key(username: &str, password: &str, now_seconds: u64) -> anyhow::Result<[u8; 32]> {
    if username.is_empty() || password.is_empty() {
        return Err(anyhow!("mieru username and password must not be empty"));
    }
    let mut password_input = Vec::with_capacity(password.len() + username.len() + 1);
    password_input.extend_from_slice(password.as_bytes());
    password_input.push(0);
    password_input.extend_from_slice(username.as_bytes());
    let hashed_password = Sha256::digest(&password_input);
    let rounded = ((now_seconds + MIERU_KEY_REFRESH_SECONDS / 2) / MIERU_KEY_REFRESH_SECONDS)
        * MIERU_KEY_REFRESH_SECONDS;
    let salt = Sha256::digest(rounded.to_be_bytes());
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(&hashed_password, &salt, MIERU_KEY_ITERATIONS, &mut key);
    Ok(key)
}

fn apply_user_hint(username: &str, nonce: &mut [u8; MIERU_NONCE_LENGTH]) {
    let mut input = Vec::with_capacity(username.len() + 16);
    input.extend_from_slice(username.as_bytes());
    input.extend_from_slice(&nonce[..16]);
    let hint = Sha256::digest(&input);
    nonce[20..24].copy_from_slice(&hint[..4]);
}

fn increment_nonce(nonce: &mut [u8; MIERU_NONCE_LENGTH]) {
    for byte in nonce.iter_mut().rev() {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            break;
        }
    }
}

fn random_padding() -> anyhow::Result<Vec<u8>> {
    random_padding_with_limit(MIERU_MAX_RANDOM_PADDING)
}

fn random_padding_with_limit(maximum: usize) -> anyhow::Result<Vec<u8>> {
    if maximum == 0 {
        return Ok(Vec::new());
    }
    let mut selector = [0u8; 1];
    getrandom::fill(&mut selector).context("failed to select mieru padding length")?;
    let length = selector[0] as usize % (maximum + 1);
    let mut padding = vec![0u8; length];
    if !padding.is_empty() {
        getrandom::fill(&mut padding).context("failed to generate mieru padding")?;
    }
    Ok(padding)
}

fn random_u32() -> anyhow::Result<u32> {
    let mut bytes = [0u8; 4];
    getrandom::fill(&mut bytes).context("failed to generate mieru session ID")?;
    Ok(u32::from_be_bytes(bytes))
}

fn parse_mieru_server_ports(port: u16, port_range: Option<&str>) -> anyhow::Result<Vec<u16>> {
    let Some(port_range) = port_range.map(str::trim).filter(|value| !value.is_empty()) else {
        if port == 0 {
            return Err(anyhow!("mieru port or port-range must be configured"));
        }
        return Ok(vec![port]);
    };

    let (start, end) = match port_range.split_once('-') {
        Some((start, end)) => (
            start
                .trim()
                .parse::<u16>()
                .with_context(|| format!("invalid mieru port-range start {start}"))?,
            end.trim()
                .parse::<u16>()
                .with_context(|| format!("invalid mieru port-range end {end}"))?,
        ),
        None => {
            let fixed = port_range
                .parse::<u16>()
                .with_context(|| format!("invalid mieru port-range {port_range}"))?;
            (fixed, fixed)
        }
    };
    if start == 0 || start > end || usize::from(end - start) > 4_096 {
        return Err(anyhow!(
            "invalid or oversized mieru port-range {port_range}"
        ));
    }
    Ok((start..=end).collect())
}

fn random_mieru_port(ports: &[u16]) -> anyhow::Result<u16> {
    match ports {
        [] => Err(anyhow!("mieru server has no usable port")),
        [port] => Ok(*port),
        ports => Ok(ports[random_u32()? as usize % ports.len()]),
    }
}

fn normalized_mieru_transport(value: Option<&str>) -> anyhow::Result<MieruTransport> {
    match value.unwrap_or("tcp").trim().to_ascii_lowercase().as_str() {
        "" | "tcp" | "stream" => Ok(MieruTransport::Tcp),
        "udp" | "packet" => Ok(MieruTransport::Udp),
        value => Err(anyhow!("unsupported mieru transport {value}")),
    }
}

fn normalized_mieru_multiplexing(value: Option<&str>) -> anyhow::Result<MieruMultiplexing> {
    match value
        .unwrap_or("middle")
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "" | "default" | "multiplexing_default" | "middle" | "medium" | "multiplexing_middle" => {
            Ok(MieruMultiplexing::Middle)
        }
        "off" | "disabled" | "multiplexing_off" => Ok(MieruMultiplexing::Off),
        "low" | "multiplexing_low" => Ok(MieruMultiplexing::Low),
        "high" | "multiplexing_high" => Ok(MieruMultiplexing::High),
        value => Err(anyhow!("unsupported mieru multiplexing level {value}")),
    }
}

fn normalized_mieru_handshake_mode(value: Option<&str>) -> anyhow::Result<MieruHandshakeMode> {
    match value
        .unwrap_or("standard")
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "" | "default" | "standard" | "handshake_default" | "handshake_standard" | "1-rtt"
        | "1rtt" => Ok(MieruHandshakeMode::Standard),
        "no-wait" | "no_wait" | "nowait" | "handshake_no_wait" | "0-rtt" | "0rtt" => {
            Ok(MieruHandshakeMode::NoWait)
        }
        value => Err(anyhow!("unsupported mieru handshake mode {value}")),
    }
}

fn server_address(server: &str, port: u16) -> String {
    if server.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{server}]:{port}")
    } else {
        format!("{server}:{port}")
    }
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_and_data_metadata_match_official_layout() {
        let session = MieruOutboundMetadata::Session {
            protocol: PROTOCOL_OPEN_SESSION_REQUEST,
            session_id: 0x0102_0304,
            sequence: 0x0506_0708,
            status: 9,
            payload_len: 0x0a0b,
            suffix_len: 12,
        }
        .marshal();
        assert_eq!(session[0], PROTOCOL_OPEN_SESSION_REQUEST);
        assert_eq!(&session[6..10], &0x0102_0304u32.to_be_bytes());
        assert_eq!(&session[10..14], &0x0506_0708u32.to_be_bytes());
        assert_eq!(session[14], 9);
        assert_eq!(&session[15..17], &0x0a0bu16.to_be_bytes());
        assert_eq!(session[17], 12);

        let data = MieruOutboundMetadata::Data {
            protocol: PROTOCOL_DATA_CLIENT_TO_SERVER,
            session_id: 1,
            sequence: 2,
            unacknowledged_sequence: 3,
            window_size: 4,
            fragment: 5,
            prefix_len: 6,
            payload_len: 7,
            suffix_len: 8,
        }
        .marshal();
        assert_eq!(&data[14..18], &3u32.to_be_bytes());
        assert_eq!(&data[18..20], &4u16.to_be_bytes());
        assert_eq!(data[20], 5);
        assert_eq!(data[21], 6);
        assert_eq!(&data[22..24], &7u16.to_be_bytes());
        assert_eq!(data[24], 8);
    }

    #[test]
    fn stateful_cipher_sends_nonce_once_and_increments_big_endian() {
        let key = [7u8; 32];
        let mut sender = MieruStatefulCipher::new(key, "user".to_string());
        let mut receiver = MieruStatefulCipher::new(key, "user".to_string());
        let first = sender.encrypt(b"first").unwrap();
        let second = sender.encrypt(b"second").unwrap();
        assert_eq!(first.len(), MIERU_NONCE_LENGTH + 5 + MIERU_TAG_LENGTH);
        assert_eq!(second.len(), 6 + MIERU_TAG_LENGTH);
        assert_eq!(receiver.decrypt(&first).unwrap(), b"first");
        assert_eq!(receiver.decrypt(&second).unwrap(), b"second");
    }

    #[test]
    fn udp_tunnel_packet_preserves_socks5_destination_and_payload() {
        let packet =
            encode_mieru_udp_tunnel_packet(&Destination::new("dns.example", 53), b"question")
                .unwrap();
        assert_eq!(packet[0], 0);
        assert_eq!(*packet.last().unwrap(), 0xff);
        let length = u16::from_be_bytes([packet[1], packet[2]]) as usize;
        assert_eq!(length + 4, packet.len());
        assert_eq!(&packet[3..6], &[0, 0, 0]);
        assert!(packet.ends_with(b"question\xff"));
    }

    #[test]
    fn stateless_udp_packet_round_trip_preserves_flow_control() {
        let key = [9u8; 32];
        let metadata = MieruOutboundMetadata::Data {
            protocol: PROTOCOL_DATA_SERVER_TO_CLIENT,
            session_id: 77,
            sequence: 12,
            unacknowledged_sequence: 8,
            window_size: 321,
            fragment: 2,
            prefix_len: 0,
            payload_len: 7,
            suffix_len: 0,
        };
        let packet = encode_mieru_packet(key, "user", 1_280, &metadata, b"payload").unwrap();
        assert!(packet.len() <= 1_280);
        let decoded = decode_mieru_packet(key, &packet).unwrap();
        assert_eq!(decoded.protocol, PROTOCOL_DATA_SERVER_TO_CLIENT);
        assert_eq!(decoded.session_id, 77);
        assert_eq!(decoded.sequence, 12);
        assert_eq!(decoded.unacknowledged_sequence, 8);
        assert_eq!(decoded.window_size, 321);
        assert_eq!(decoded.fragment, 2);
        assert_eq!(decoded.payload, b"payload");
    }

    #[test]
    fn stateless_udp_ack_has_no_payload_tag() {
        let key = [3u8; 32];
        let metadata = MieruOutboundMetadata::Data {
            protocol: PROTOCOL_ACK_SERVER_TO_CLIENT,
            session_id: 9,
            sequence: 4,
            unacknowledged_sequence: 5,
            window_size: 16,
            fragment: 0,
            prefix_len: 0,
            payload_len: 0,
            suffix_len: 0,
        };
        let packet = encode_mieru_packet(key, "user", 1_400, &metadata, &[]).unwrap();
        assert!(packet.len() >= MIERU_NONCE_LENGTH + MIERU_METADATA_LENGTH + MIERU_TAG_LENGTH);
        let decoded = decode_mieru_packet(key, &packet).unwrap();
        assert_eq!(decoded.protocol, PROTOCOL_ACK_SERVER_TO_CLIENT);
        assert!(decoded.payload.is_empty());
    }

    #[test]
    fn official_config_names_normalize() {
        assert_eq!(
            normalized_mieru_multiplexing(Some("MULTIPLEXING_HIGH")).unwrap(),
            MieruMultiplexing::High
        );
        assert_eq!(
            normalized_mieru_handshake_mode(Some("HANDSHAKE_NO_WAIT")).unwrap(),
            MieruHandshakeMode::NoWait
        );
        assert_eq!(
            normalized_mieru_transport(Some("TCP")).unwrap(),
            MieruTransport::Tcp
        );
    }

    #[test]
    fn official_port_range_takes_precedence_over_fixed_port() {
        assert_eq!(
            parse_mieru_server_ports(39090, Some("39091-39093")).unwrap(),
            vec![39091, 39092, 39093]
        );
        assert_eq!(
            parse_mieru_server_ports(0, Some("39094")).unwrap(),
            vec![39094]
        );
        assert!(parse_mieru_server_ports(0, None).is_err());
        assert!(parse_mieru_server_ports(0, Some("39095-39094")).is_err());
    }

    #[tokio::test]
    async fn native_tcp_underlay_real_dial_echoes_application_data() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let key = derive_mieru_key("user", "secret", unix_seconds()).unwrap();
            let mut reader_cipher = MieruStatefulCipher::new(key, "user".to_string());
            let mut writer_cipher = MieruStatefulCipher::new(key, "user".to_string());
            let open = read_mieru_segment(&mut stream, &mut reader_cipher)
                .await
                .unwrap();
            assert_eq!(open.protocol, PROTOCOL_OPEN_SESSION_REQUEST);
            assert_eq!(&open.payload[..3], &[5, SOCKS5_CONNECT, 0]);
            write_test_stream_segment(
                &mut stream,
                &mut writer_cipher,
                MieruOutboundMetadata::Session {
                    protocol: PROTOCOL_OPEN_SESSION_RESPONSE,
                    session_id: open.session_id,
                    sequence: 0,
                    status: 0,
                    payload_len: 10,
                    suffix_len: 0,
                },
                &[5, 0, 0, 1, 0, 0, 0, 0, 0, 0],
            )
            .await;
            let data = read_mieru_segment(&mut stream, &mut reader_cipher)
                .await
                .unwrap();
            assert_eq!(data.protocol, PROTOCOL_DATA_CLIENT_TO_SERVER);
            let payload_len = data.payload.len() as u16;
            write_test_stream_segment(
                &mut stream,
                &mut writer_cipher,
                MieruOutboundMetadata::Data {
                    protocol: PROTOCOL_DATA_SERVER_TO_CLIENT,
                    session_id: data.session_id,
                    sequence: 1,
                    unacknowledged_sequence: 0,
                    window_size: 4_096,
                    fragment: 0,
                    prefix_len: 0,
                    payload_len,
                    suffix_len: 0,
                },
                &data.payload,
            )
            .await;
        });
        let outbound = MieruOutbound::new(
            "tcp".to_string(),
            address.ip().to_string(),
            address.port(),
            None,
            "user".to_string(),
            "secret".to_string(),
            Some("tcp".to_string()),
            Some(1_400),
            Some("off".to_string()),
            Some("standard".to_string()),
        );
        let mut stream = timeout(
            Duration::from_secs(3),
            outbound.connect(&Destination::new("target.example", 443), 3_000),
        )
        .await
        .unwrap()
        .unwrap();
        stream.write_all(b"tcp-echo").await.unwrap();
        let mut reply = [0u8; 8];
        stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"tcp-echo");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn native_udp_underlay_real_dial_echoes_application_data() {
        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let address = socket.local_addr().unwrap();
        let server_socket = Arc::clone(&socket);
        let server = tokio::spawn(async move {
            let key = derive_mieru_key("user", "secret", unix_seconds()).unwrap();
            let mut buffer = [0u8; MIERU_MAX_MTU as usize];
            loop {
                let (size, peer) = server_socket.recv_from(&mut buffer).await.unwrap();
                let segment = match decode_mieru_packet(key, &buffer[..size]) {
                    Ok(segment) => segment,
                    Err(_) => continue,
                };
                match segment.protocol {
                    PROTOCOL_OPEN_SESSION_REQUEST => {
                        let metadata = MieruOutboundMetadata::Session {
                            protocol: PROTOCOL_OPEN_SESSION_RESPONSE,
                            session_id: segment.session_id,
                            sequence: 0,
                            status: 0,
                            payload_len: 10,
                            suffix_len: 0,
                        };
                        let packet = encode_mieru_packet(
                            key,
                            "user",
                            1_400,
                            &metadata,
                            &[5, 0, 0, 1, 0, 0, 0, 0, 0, 0],
                        )
                        .unwrap();
                        server_socket.send_to(&packet, peer).await.unwrap();
                    }
                    PROTOCOL_DATA_CLIENT_TO_SERVER => {
                        let metadata = MieruOutboundMetadata::Data {
                            protocol: PROTOCOL_DATA_SERVER_TO_CLIENT,
                            session_id: segment.session_id,
                            sequence: 1,
                            unacknowledged_sequence: segment.sequence.wrapping_add(1),
                            window_size: 4_096,
                            fragment: 0,
                            prefix_len: 0,
                            payload_len: segment.payload.len() as u16,
                            suffix_len: 0,
                        };
                        let packet =
                            encode_mieru_packet(key, "user", 1_400, &metadata, &segment.payload)
                                .unwrap();
                        server_socket.send_to(&packet, peer).await.unwrap();
                        break;
                    }
                    PROTOCOL_ACK_CLIENT_TO_SERVER => {}
                    protocol => panic!("unexpected client protocol {protocol}"),
                }
            }
        });
        let outbound = MieruOutbound::new(
            "udp".to_string(),
            address.ip().to_string(),
            address.port(),
            None,
            "user".to_string(),
            "secret".to_string(),
            Some("udp".to_string()),
            Some(1_400),
            Some("off".to_string()),
            Some("standard".to_string()),
        );
        let mut stream = timeout(
            Duration::from_secs(5),
            outbound.connect(&Destination::new("target.example", 443), 5_000),
        )
        .await
        .unwrap()
        .unwrap();
        stream.write_all(b"udp-echo").await.unwrap();
        let mut reply = [0u8; 8];
        stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"udp-echo");
        server.await.unwrap();
    }

    async fn write_test_stream_segment<W>(
        writer: &mut W,
        cipher: &mut MieruStatefulCipher,
        metadata: MieruOutboundMetadata,
        payload: &[u8],
    ) where
        W: tokio::io::AsyncWrite + Unpin,
    {
        writer
            .write_all(&cipher.encrypt(&metadata.marshal()).unwrap())
            .await
            .unwrap();
        if !payload.is_empty() {
            writer
                .write_all(&cipher.encrypt(payload).unwrap())
                .await
                .unwrap();
        }
        writer.flush().await.unwrap();
    }
}
