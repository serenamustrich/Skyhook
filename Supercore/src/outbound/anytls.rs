use std::{
    collections::{BTreeMap, HashMap},
    sync::{
        atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, AtomicUsize, Ordering},
        Arc, Mutex as StdMutex, RwLock as StdRwLock,
    },
    time::{Duration, Instant},
};

use anyhow::{anyhow, Context};
use async_trait::async_trait;
use md5::Md5;
use rustls_pki_types::ServerName;
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream},
    sync::{mpsc, oneshot, Mutex, OnceCell},
    task::JoinHandle,
    time::timeout,
};
use tokio_rustls::TlsConnector;

use crate::routing::Destination;

use super::{
    io::read_exact_or_eof,
    target::encode_socks5_destination,
    transports::{connect_tcp, random_u32, run_dial_phase, tls_client_config},
    udp::{udp_session_key, KeyedRoundRobinSessionPool, UDP_SESSION_POOL_SIZE},
    util::hex_lower,
    BoxedStream, Outbound, OutboundCapability, UdpNatMode,
};

const ANYTLS_PROTOCOL_VERSION: u8 = 2;
const ANYTLS_MAX_SESSIONS: usize = 16;
const ANYTLS_MAX_STREAMS_PER_SESSION: usize = 128;
const ANYTLS_STREAM_EVENT_CAPACITY: usize = 64;
const ANYTLS_WRITE_QUEUE_CAPACITY: usize = 256;
const ANYTLS_MAX_PADDING_SCHEME_SIZE: usize = 4_096;
const ANYTLS_MAX_PADDING_PACKET_SIZE: usize = u16::MAX as usize;
const ANYTLS_STREAM_BUFFER_SIZE: usize = 64 * 1024;
const ANYTLS_STREAM_WRITE_SIZE: usize = 48 * 1024;
const ANYTLS_DEFAULT_IDLE_CHECK_SECONDS: u64 = 30;
const ANYTLS_DEFAULT_IDLE_TIMEOUT_SECONDS: u64 = 30;
const ANYTLS_UOT_MAGIC_HOST: &str = "sp.v2.udp-over-tcp.arpa";

const CMD_WASTE: u8 = 0;
const CMD_SYN: u8 = 1;
const CMD_PSH: u8 = 2;
const CMD_FIN: u8 = 3;
const CMD_SETTINGS: u8 = 4;
const CMD_ALERT: u8 = 5;
const CMD_UPDATE_PADDING_SCHEME: u8 = 6;
const CMD_SYNACK: u8 = 7;
const CMD_HEART_REQUEST: u8 = 8;
const CMD_HEART_RESPONSE: u8 = 9;
const CMD_SERVER_SETTINGS: u8 = 10;

pub(super) struct AnyTlsOutbound {
    name: String,
    server: String,
    port: u16,
    password: String,
    sni: Option<String>,
    skip_cert_verify: bool,
    alpn: Vec<String>,
    idle_session_check_interval: Duration,
    idle_session_timeout: Duration,
    min_idle_session: usize,
    client: OnceCell<Arc<AnyTlsClient>>,
    udp_sessions: Mutex<AnyTlsUdpPool>,
}

type AnyTlsUdpPool = KeyedRoundRobinSessionPool<AnyTlsUdpSession>;

struct AnyTlsUdpSession {
    stream: BoxedStream,
}

struct AnyTlsClient {
    server: String,
    port: u16,
    password: String,
    server_name: String,
    tls_config: Arc<rustls::ClientConfig>,
    padding: Arc<StdRwLock<AnyTlsPaddingScheme>>,
    sessions: Mutex<Vec<Arc<AnyTlsSession>>>,
    next_session_sequence: AtomicU64,
    idle_session_check_interval: Duration,
    idle_session_timeout: Duration,
    min_idle_session: usize,
    cleanup_task: StdMutex<Option<JoinHandle<()>>>,
}

struct AnyTlsSession {
    sequence: u64,
    write_tx: mpsc::Sender<AnyTlsWriteRequest>,
    streams: Arc<Mutex<HashMap<u32, AnyTlsStreamMailbox>>>,
    healthy: Arc<AtomicBool>,
    peer_version: Arc<AtomicU8>,
    next_stream_id: AtomicU32,
    active_streams: AtomicUsize,
    idle_since: StdMutex<Instant>,
    first_open: Mutex<bool>,
    padding_md5: String,
    tasks: StdMutex<Vec<JoinHandle<()>>>,
}

struct AnyTlsStreamMailbox {
    events: mpsc::Sender<AnyTlsStreamEvent>,
    synack: StdMutex<Option<oneshot::Sender<Result<(), String>>>>,
}

struct AnyTlsWriteRequest {
    payload: Vec<u8>,
    completion: Option<oneshot::Sender<Result<(), String>>>,
}

enum AnyTlsStreamEvent {
    Data(Vec<u8>),
    Fin,
    Error(String),
}

struct AnyTlsStreamLease {
    session: Arc<AnyTlsSession>,
    sid: Option<u32>,
    send_fin: bool,
}

#[derive(Clone)]
struct AnyTlsPaddingScheme {
    md5: String,
    stop: u32,
    packets: BTreeMap<u32, Vec<AnyTlsPaddingInstruction>>,
}

#[derive(Clone, Copy)]
enum AnyTlsPaddingInstruction {
    Range { minimum: usize, maximum: usize },
    Check,
}

struct AnyTlsPaddingWriter<W> {
    writer: W,
    scheme: AnyTlsPaddingScheme,
    packet_counter: u32,
}

struct AnyTlsFrame {
    command: u8,
    sid: u32,
    data: Vec<u8>,
}

impl AnyTlsOutbound {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        name: String,
        server: String,
        port: u16,
        password: String,
        sni: Option<String>,
        skip_cert_verify: bool,
        alpn: Vec<String>,
        idle_session_check_interval: Option<u64>,
        idle_session_timeout: Option<u64>,
        min_idle_session: Option<usize>,
    ) -> Self {
        Self {
            name,
            server,
            port,
            password,
            sni,
            skip_cert_verify,
            alpn,
            idle_session_check_interval: Duration::from_secs(
                idle_session_check_interval.unwrap_or(ANYTLS_DEFAULT_IDLE_CHECK_SECONDS),
            ),
            idle_session_timeout: Duration::from_secs(
                idle_session_timeout.unwrap_or(ANYTLS_DEFAULT_IDLE_TIMEOUT_SECONDS),
            ),
            min_idle_session: min_idle_session.unwrap_or(0),
            client: OnceCell::new(),
            udp_sessions: Mutex::new(AnyTlsUdpPool::default()),
        }
    }

    fn validate_configuration(&self) -> anyhow::Result<()> {
        if self.server.trim().is_empty() || self.port == 0 {
            return Err(anyhow!("anytls server and port are required"));
        }
        if self.password.is_empty() {
            return Err(anyhow!("anytls password is empty"));
        }
        if self.idle_session_check_interval.is_zero() {
            return Err(anyhow!(
                "anytls idle-session-check-interval must be greater than zero"
            ));
        }
        if self.idle_session_timeout.is_zero() {
            return Err(anyhow!(
                "anytls idle-session-timeout must be greater than zero"
            ));
        }
        if self.min_idle_session > ANYTLS_MAX_SESSIONS {
            return Err(anyhow!(
                "anytls min-idle-session must not exceed {ANYTLS_MAX_SESSIONS}"
            ));
        }
        for protocol in &self.alpn {
            if protocol.is_empty() || protocol.len() > u8::MAX as usize {
                return Err(anyhow!("anytls ALPN value is invalid"));
            }
        }
        Ok(())
    }

    async fn client(&self) -> anyhow::Result<Arc<AnyTlsClient>> {
        self.validate_configuration()?;
        self.client
            .get_or_try_init(|| async {
                AnyTlsClient::new(
                    self.server.clone(),
                    self.port,
                    self.password.clone(),
                    self.sni.clone().unwrap_or_else(|| self.server.clone()),
                    self.skip_cert_verify,
                    self.alpn.clone(),
                    self.idle_session_check_interval,
                    self.idle_session_timeout,
                    self.min_idle_session,
                )
            })
            .await
            .cloned()
    }

    async fn udp_session(
        &self,
        destination: &Destination,
        timeout_ms: u64,
    ) -> anyhow::Result<Arc<Mutex<AnyTlsUdpSession>>> {
        let key = udp_session_key(
            self.kind(),
            self.name(),
            self.udp_nat_mode(),
            Some(destination),
        );
        let mut pool = self.udp_sessions.lock().await;
        if pool.len(&key) < UDP_SESSION_POOL_SIZE {
            let mut stream = self
                .connect(&Destination::new(ANYTLS_UOT_MAGIC_HOST, 0), timeout_ms)
                .await?;
            let mut request = vec![0u8];
            encode_socks5_destination(destination, &mut request)?;
            stream.write_all(&request).await?;
            stream.flush().await?;
            let session = Arc::new(Mutex::new(AnyTlsUdpSession { stream }));
            pool.push(key, Arc::clone(&session));
            return Ok(session);
        }
        pool.next(&key)
            .ok_or_else(|| anyhow!("anytls UoT session pool is unexpectedly empty"))
    }

    async fn remove_udp_session(
        &self,
        destination: &Destination,
        session: &Arc<Mutex<AnyTlsUdpSession>>,
    ) {
        let key = udp_session_key(
            self.kind(),
            self.name(),
            self.udp_nat_mode(),
            Some(destination),
        );
        self.udp_sessions.lock().await.remove(&key, session);
    }
}

#[async_trait]
impl Outbound for AnyTlsOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "anytls"
    }

    fn capability(&self) -> OutboundCapability {
        match self.validate_configuration() {
            Ok(()) => OutboundCapability::tcp_udp("anytls-uot-v2"),
            Err(error) => OutboundCapability::unsupported(error.to_string()),
        }
    }

    fn udp_nat_mode(&self) -> UdpNatMode {
        UdpNatMode::EndpointDependent
    }

    fn runtime_stats(&self) -> Option<serde_json::Value> {
        let client = self.client.get()?;
        let sessions = client.sessions.try_lock().ok()?;
        Some(serde_json::json!({
            "sessions": sessions.len(),
            "healthy_sessions": sessions.iter().filter(|session| session.is_healthy()).count(),
            "active_streams": sessions.iter().map(|session| session.active_streams.load(Ordering::Relaxed)).sum::<usize>(),
            "protocol_version": ANYTLS_PROTOCOL_VERSION,
        }))
    }

    async fn connect(
        &self,
        destination: &Destination,
        timeout_ms: u64,
    ) -> anyhow::Result<BoxedStream> {
        self.client()
            .await?
            .open_stream(destination, timeout_ms)
            .await
    }

    async fn udp_exchange(
        &self,
        destination: &Destination,
        payload: &[u8],
        timeout_ms: u64,
    ) -> anyhow::Result<Vec<u8>> {
        if payload.len() > u16::MAX as usize {
            return Err(anyhow!("anytls UoT payload is too large"));
        }
        let session_handle = self.udp_session(destination, timeout_ms).await?;
        let exchange = timeout(Duration::from_millis(timeout_ms), async {
            let mut session = session_handle.lock().await;
            let mut frame = Vec::with_capacity(1 + 255 + 2 + 2 + payload.len());
            encode_uot_destination(destination, &mut frame)?;
            frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
            frame.extend_from_slice(payload);
            session.stream.write_all(&frame).await?;
            session.stream.flush().await?;

            let _response_destination = read_uot_destination(&mut session.stream).await?;
            let response_len = session.stream.read_u16().await? as usize;
            let mut response = vec![0u8; response_len];
            session.stream.read_exact(&mut response).await?;
            Ok::<_, anyhow::Error>(response)
        })
        .await
        .context("anytls UoT exchange timed out")?;
        if exchange.is_err() {
            self.remove_udp_session(destination, &session_handle).await;
        }
        exchange
    }
}

impl AnyTlsClient {
    #[allow(clippy::too_many_arguments)]
    fn new(
        server: String,
        port: u16,
        password: String,
        server_name: String,
        skip_cert_verify: bool,
        alpn: Vec<String>,
        idle_session_check_interval: Duration,
        idle_session_timeout: Duration,
        min_idle_session: usize,
    ) -> anyhow::Result<Arc<Self>> {
        let mut tls_config = tls_client_config(skip_cert_verify)?;
        tls_config.alpn_protocols = alpn.iter().map(|value| value.as_bytes().to_vec()).collect();
        let client = Arc::new(Self {
            server,
            port,
            password,
            server_name,
            tls_config: Arc::new(tls_config),
            padding: Arc::new(StdRwLock::new(AnyTlsPaddingScheme::default_scheme())),
            sessions: Mutex::new(Vec::new()),
            next_session_sequence: AtomicU64::new(1),
            idle_session_check_interval,
            idle_session_timeout,
            min_idle_session,
            cleanup_task: StdMutex::new(None),
        });
        client.start_cleanup_task();
        Ok(client)
    }

    fn start_cleanup_task(self: &Arc<Self>) {
        let weak = Arc::downgrade(self);
        let interval = self.idle_session_check_interval;
        let task = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            ticker.tick().await;
            loop {
                ticker.tick().await;
                let Some(client) = weak.upgrade() else {
                    return;
                };
                client.cleanup_idle_sessions().await;
            }
        });
        *self.cleanup_task.lock().expect("anytls cleanup lock") = Some(task);
    }

    async fn cleanup_idle_sessions(&self) {
        let now = Instant::now();
        let mut sessions = self.sessions.lock().await;
        sessions.retain(|session| session.is_healthy());
        let mut idle = sessions
            .iter()
            .filter(|session| session.active_streams.load(Ordering::Acquire) == 0)
            .cloned()
            .collect::<Vec<_>>();
        idle.sort_by_key(|session| std::cmp::Reverse(session.sequence));
        for session in idle.into_iter().skip(self.min_idle_session) {
            let idle_since = *session.idle_since.lock().expect("anytls idle lock");
            if now.saturating_duration_since(idle_since) >= self.idle_session_timeout {
                session.close();
            }
        }
        sessions.retain(|session| session.is_healthy());
    }

    async fn open_stream(
        self: &Arc<Self>,
        destination: &Destination,
        timeout_ms: u64,
    ) -> anyhow::Result<BoxedStream> {
        let session = self.acquire_session(timeout_ms).await?;
        let lease = AnyTlsStreamLease {
            session: Arc::clone(&session),
            sid: None,
            send_fin: true,
        };
        session.open_stream(destination, timeout_ms, lease).await
    }

    async fn acquire_session(&self, timeout_ms: u64) -> anyhow::Result<Arc<AnyTlsSession>> {
        let mut sessions = self.sessions.lock().await;
        sessions.retain(|session| session.is_healthy());
        for session in sessions.iter().rev() {
            if session.try_acquire() {
                return Ok(Arc::clone(session));
            }
        }
        if sessions.len() >= ANYTLS_MAX_SESSIONS {
            return Err(anyhow!(
                "anytls reached the maximum of {ANYTLS_MAX_SESSIONS} sessions"
            ));
        }
        let sequence = self.next_session_sequence.fetch_add(1, Ordering::Relaxed);
        let session = self.create_session(sequence, timeout_ms).await?;
        if !session.try_acquire() {
            return Err(anyhow!("new anytls session has no stream capacity"));
        }
        sessions.push(Arc::clone(&session));
        Ok(session)
    }

    async fn create_session(
        &self,
        sequence: u64,
        timeout_ms: u64,
    ) -> anyhow::Result<Arc<AnyTlsSession>> {
        let tcp = connect_tcp(&format!("{}:{}", self.server, self.port), timeout_ms).await?;
        let server_name = ServerName::try_from(self.server_name.clone())
            .map_err(|error| anyhow!("invalid anytls server name: {error}"))?;
        let connector = TlsConnector::from(Arc::clone(&self.tls_config));
        let mut stream = run_dial_phase(
            timeout_ms,
            "anytls tls handshake",
            connector.connect(server_name, tcp),
        )
        .await?
        .context("anytls tls handshake failed")?;

        let scheme = self
            .padding
            .read()
            .map_err(|_| anyhow!("anytls padding scheme lock is poisoned"))?
            .clone();
        let auth_padding = scheme.auth_padding_length()?;
        let password_hash: [u8; 32] = Sha256::digest(self.password.as_bytes()).into();
        let mut auth = Vec::with_capacity(34 + auth_padding);
        auth.extend_from_slice(&password_hash);
        auth.extend_from_slice(&(auth_padding as u16).to_be_bytes());
        auth.resize(auth.len() + auth_padding, 0);
        run_dial_phase(timeout_ms, "anytls authentication", async {
            stream.write_all(&auth).await?;
            stream.flush().await
        })
        .await?
        .context("anytls authentication write failed")?;

        Ok(AnyTlsSession::new(
            sequence,
            stream,
            scheme,
            Arc::clone(&self.padding),
        ))
    }
}

impl Drop for AnyTlsClient {
    fn drop(&mut self) {
        if let Some(task) = self
            .cleanup_task
            .lock()
            .expect("anytls cleanup lock")
            .take()
        {
            task.abort();
        }
    }
}

impl AnyTlsSession {
    fn new<S>(
        sequence: u64,
        stream: S,
        scheme: AnyTlsPaddingScheme,
        shared_padding: Arc<StdRwLock<AnyTlsPaddingScheme>>,
    ) -> Arc<Self>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (read_half, write_half) = tokio::io::split(stream);
        let (write_tx, write_rx) = mpsc::channel(ANYTLS_WRITE_QUEUE_CAPACITY);
        let streams = Arc::new(Mutex::new(HashMap::new()));
        let healthy = Arc::new(AtomicBool::new(true));
        let peer_version = Arc::new(AtomicU8::new(1));
        let session = Arc::new(Self {
            sequence,
            write_tx: write_tx.clone(),
            streams: Arc::clone(&streams),
            healthy: Arc::clone(&healthy),
            peer_version: Arc::clone(&peer_version),
            next_stream_id: AtomicU32::new(1),
            active_streams: AtomicUsize::new(0),
            idle_since: StdMutex::new(Instant::now()),
            first_open: Mutex::new(true),
            padding_md5: scheme.md5.clone(),
            tasks: StdMutex::new(Vec::new()),
        });

        let writer_task = tokio::spawn(run_anytls_writer(
            write_half,
            write_rx,
            scheme,
            Arc::clone(&healthy),
            Arc::clone(&streams),
        ));
        let reader_task = tokio::spawn(run_anytls_reader(
            read_half,
            write_tx,
            Arc::clone(&streams),
            Arc::clone(&healthy),
            peer_version,
            shared_padding,
        ));
        session
            .tasks
            .lock()
            .expect("anytls task lock")
            .extend([writer_task, reader_task]);
        session
    }

    fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::Acquire)
            && self
                .tasks
                .lock()
                .expect("anytls task lock")
                .iter()
                .all(|task| !task.is_finished())
    }

    fn try_acquire(&self) -> bool {
        if !self.is_healthy() {
            return false;
        }
        self.active_streams
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                (active < ANYTLS_MAX_STREAMS_PER_SESSION).then_some(active + 1)
            })
            .is_ok()
    }

    fn release(&self) {
        if self.active_streams.fetch_sub(1, Ordering::AcqRel) == 1 {
            *self.idle_since.lock().expect("anytls idle lock") = Instant::now();
        }
    }

    fn close(&self) {
        if self.healthy.swap(false, Ordering::AcqRel) {
            for task in self.tasks.lock().expect("anytls task lock").iter() {
                task.abort();
            }
        }
    }

    async fn open_stream(
        self: &Arc<Self>,
        destination: &Destination,
        timeout_ms: u64,
        mut lease: AnyTlsStreamLease,
    ) -> anyhow::Result<BoxedStream> {
        let deadline = tokio::time::Instant::now() + Duration::from_millis(timeout_ms);
        let sid = self.next_stream_id.fetch_add(1, Ordering::Relaxed);
        if sid == 0 || sid == u32::MAX {
            self.close();
            return Err(anyhow!("anytls stream id space is exhausted"));
        }
        lease.sid = Some(sid);

        let (event_tx, event_rx) = mpsc::channel(ANYTLS_STREAM_EVENT_CAPACITY);
        let expect_synack = sid >= 2 && self.peer_version.load(Ordering::Acquire) >= 2;
        let (synack_tx, synack_rx) = oneshot::channel();
        self.streams.lock().await.insert(
            sid,
            AnyTlsStreamMailbox {
                events: event_tx,
                synack: StdMutex::new(expect_synack.then_some(synack_tx)),
            },
        );

        let mut first_open = self.first_open.lock().await;
        let mut payload = Vec::new();
        if *first_open {
            append_frame(
                &mut payload,
                CMD_SETTINGS,
                0,
                build_settings(&self.padding_md5).as_bytes(),
            )?;
        }
        append_frame(&mut payload, CMD_SYN, sid, &[])?;
        let mut target = Vec::new();
        encode_socks5_destination(destination, &mut target)?;
        append_frame(&mut payload, CMD_PSH, sid, &target)?;
        self.send_payload(payload, deadline).await?;
        *first_open = false;
        drop(first_open);

        if expect_synack {
            timeout(
                deadline.saturating_duration_since(tokio::time::Instant::now()),
                synack_rx,
            )
            .await
            .context("anytls stream open timed out")?
            .context("anytls stream-open waiter closed")?
            .map_err(|error| anyhow!("anytls server rejected stream: {error}"))?;
        }

        let (app_side, relay_side) = tokio::io::duplex(ANYTLS_STREAM_BUFFER_SIZE);
        tokio::spawn(run_anytls_stream(relay_side, event_rx, lease));
        Ok(Box::new(app_side))
    }

    async fn send_payload(
        &self,
        payload: Vec<u8>,
        deadline: tokio::time::Instant,
    ) -> anyhow::Result<()> {
        let (completion_tx, completion_rx) = oneshot::channel();
        timeout(
            deadline.saturating_duration_since(tokio::time::Instant::now()),
            self.write_tx.send(AnyTlsWriteRequest {
                payload,
                completion: Some(completion_tx),
            }),
        )
        .await
        .context("anytls write queue timed out")?
        .map_err(|_| anyhow!("anytls session writer is closed"))?;
        timeout(
            deadline.saturating_duration_since(tokio::time::Instant::now()),
            completion_rx,
        )
        .await
        .context("anytls session write timed out")?
        .context("anytls session writer dropped completion")?
        .map_err(|error| anyhow!(error))
    }
}

impl Drop for AnyTlsSession {
    fn drop(&mut self) {
        self.healthy.store(false, Ordering::Release);
        for task in self.tasks.lock().expect("anytls task lock").iter() {
            task.abort();
        }
    }
}

impl Drop for AnyTlsStreamLease {
    fn drop(&mut self) {
        self.session.release();
        let Some(sid) = self.sid else {
            return;
        };
        if self.send_fin && self.session.is_healthy() {
            let mut payload = Vec::with_capacity(7);
            if append_frame(&mut payload, CMD_FIN, sid, &[]).is_ok() {
                let _ = self.session.write_tx.try_send(AnyTlsWriteRequest {
                    payload,
                    completion: None,
                });
            }
        }
        let removed = match self.session.streams.try_lock() {
            Ok(mut streams) => {
                streams.remove(&sid);
                true
            }
            Err(_) => false,
        };
        if !removed {
            if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                let streams = Arc::clone(&self.session.streams);
                runtime.spawn(async move {
                    streams.lock().await.remove(&sid);
                });
            }
        }
    }
}

async fn run_anytls_writer<W>(
    writer: W,
    mut requests: mpsc::Receiver<AnyTlsWriteRequest>,
    scheme: AnyTlsPaddingScheme,
    healthy: Arc<AtomicBool>,
    streams: Arc<Mutex<HashMap<u32, AnyTlsStreamMailbox>>>,
) where
    W: AsyncWrite + Unpin,
{
    let mut writer = AnyTlsPaddingWriter {
        writer,
        scheme,
        packet_counter: 1,
    };
    while let Some(request) = requests.recv().await {
        let result = writer
            .write(&request.payload)
            .await
            .map_err(|error| error.to_string());
        if let Some(completion) = request.completion {
            let _ = completion.send(result.clone());
        }
        if let Err(error) = result {
            fail_anytls_session(&healthy, &streams, error).await;
            return;
        }
    }
}

async fn run_anytls_reader<R>(
    mut reader: R,
    write_tx: mpsc::Sender<AnyTlsWriteRequest>,
    streams: Arc<Mutex<HashMap<u32, AnyTlsStreamMailbox>>>,
    healthy: Arc<AtomicBool>,
    peer_version: Arc<AtomicU8>,
    shared_padding: Arc<StdRwLock<AnyTlsPaddingScheme>>,
) where
    R: AsyncRead + Unpin,
{
    loop {
        let frame = match read_frame(&mut reader).await {
            Ok(Some(frame)) => frame,
            Ok(None) => {
                fail_anytls_session(&healthy, &streams, "anytls server closed session").await;
                return;
            }
            Err(error) => {
                fail_anytls_session(&healthy, &streams, error.to_string()).await;
                return;
            }
        };
        match frame.command {
            CMD_WASTE | CMD_SETTINGS | CMD_HEART_RESPONSE => {}
            CMD_PSH => {
                if !send_stream_event(&streams, frame.sid, AnyTlsStreamEvent::Data(frame.data))
                    .await
                {
                    continue;
                }
            }
            CMD_FIN => {
                let _ = send_stream_event(&streams, frame.sid, AnyTlsStreamEvent::Fin).await;
            }
            CMD_SYNACK => {
                let streams = streams.lock().await;
                if let Some(mailbox) = streams.get(&frame.sid) {
                    let result = if frame.data.is_empty() {
                        Ok(())
                    } else {
                        Err(String::from_utf8_lossy(&frame.data).into_owned())
                    };
                    if let Some(waiter) = mailbox.synack.lock().expect("anytls synack lock").take()
                    {
                        let _ = waiter.send(result);
                    } else if let Err(error) = result {
                        let _ = mailbox.events.try_send(AnyTlsStreamEvent::Error(error));
                    }
                }
            }
            CMD_HEART_REQUEST => {
                let mut payload = Vec::with_capacity(7);
                if append_frame(&mut payload, CMD_HEART_RESPONSE, frame.sid, &[]).is_err()
                    || write_tx
                        .send(AnyTlsWriteRequest {
                            payload,
                            completion: None,
                        })
                        .await
                        .is_err()
                {
                    fail_anytls_session(&healthy, &streams, "anytls heartbeat response failed")
                        .await;
                    return;
                }
            }
            CMD_SERVER_SETTINGS => {
                if let Some(version) = parse_settings(&frame.data)
                    .get("v")
                    .and_then(|value| value.parse::<u8>().ok())
                {
                    peer_version.store(version.min(ANYTLS_PROTOCOL_VERSION), Ordering::Release);
                }
            }
            CMD_UPDATE_PADDING_SCHEME => {
                if frame.data.len() > ANYTLS_MAX_PADDING_SCHEME_SIZE {
                    fail_anytls_session(&healthy, &streams, "anytls padding scheme is too large")
                        .await;
                    return;
                }
                let update = AnyTlsPaddingScheme::parse(&frame.data).and_then(|scheme| {
                    shared_padding
                        .write()
                        .map(|mut current| *current = scheme)
                        .map_err(|_| anyhow!("anytls padding scheme lock is poisoned"))
                });
                if let Err(error) = update {
                    fail_anytls_session(&healthy, &streams, error.to_string()).await;
                    return;
                }
            }
            CMD_ALERT => {
                fail_anytls_session(
                    &healthy,
                    &streams,
                    format!("anytls alert: {}", String::from_utf8_lossy(&frame.data)),
                )
                .await;
                return;
            }
            CMD_SYN => {
                fail_anytls_session(
                    &healthy,
                    &streams,
                    "anytls server sent an invalid SYN command",
                )
                .await;
                return;
            }
            _ => {}
        }
    }
}

async fn send_stream_event(
    streams: &Mutex<HashMap<u32, AnyTlsStreamMailbox>>,
    sid: u32,
    event: AnyTlsStreamEvent,
) -> bool {
    let mut streams = streams.lock().await;
    let Some(mailbox) = streams.get(&sid) else {
        return false;
    };
    if mailbox.events.try_send(event).is_err() {
        streams.remove(&sid);
        return false;
    }
    true
}

async fn fail_anytls_session(
    healthy: &AtomicBool,
    streams: &Mutex<HashMap<u32, AnyTlsStreamMailbox>>,
    message: impl Into<String>,
) {
    if !healthy.swap(false, Ordering::AcqRel) {
        return;
    }
    let message = message.into();
    let mut streams = streams.lock().await;
    for mailbox in streams.values() {
        let _ = mailbox
            .events
            .try_send(AnyTlsStreamEvent::Error(message.clone()));
    }
    streams.clear();
}

async fn run_anytls_stream(
    stream: DuplexStream,
    mut events: mpsc::Receiver<AnyTlsStreamEvent>,
    mut lease: AnyTlsStreamLease,
) {
    let sid = lease.sid.expect("anytls stream lease sid");
    let (mut app_read, mut app_write) = tokio::io::split(stream);
    let mut upload = vec![0u8; ANYTLS_STREAM_WRITE_SIZE];
    let mut remote_closed = false;
    loop {
        tokio::select! {
            read = app_read.read(&mut upload) => {
                match read {
                    Ok(0) => break,
                    Ok(length) => {
                        let mut payload = Vec::with_capacity(7 + length);
                        if append_frame(&mut payload, CMD_PSH, sid, &upload[..length]).is_err()
                            || lease.session.write_tx.send(AnyTlsWriteRequest {
                                payload,
                                completion: None,
                            }).await.is_err()
                        {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            event = events.recv(), if !remote_closed => {
                match event {
                    Some(AnyTlsStreamEvent::Data(data)) => {
                        if app_write.write_all(&data).await.is_err() {
                            break;
                        }
                    }
                    Some(AnyTlsStreamEvent::Fin) => {
                        lease.send_fin = false;
                        let _ = app_write.shutdown().await;
                        remote_closed = true;
                    }
                    Some(AnyTlsStreamEvent::Error(message)) => {
                        tracing::debug!(error = %message, "anytls stream closed with session error");
                        lease.send_fin = false;
                        let _ = app_write.shutdown().await;
                        break;
                    }
                    None => {
                        lease.send_fin = false;
                        let _ = app_write.shutdown().await;
                        break;
                    }
                }
            }
        }
    }
    if remote_closed {
        lease.send_fin = false;
    }
}

impl AnyTlsPaddingScheme {
    fn default_scheme() -> Self {
        Self::parse(default_padding_scheme().as_bytes()).expect("valid default anytls padding")
    }

    fn parse(raw: &[u8]) -> anyhow::Result<Self> {
        if raw.is_empty() || raw.len() > ANYTLS_MAX_PADDING_SCHEME_SIZE {
            return Err(anyhow!("anytls padding scheme size is invalid"));
        }
        let text = std::str::from_utf8(raw).context("anytls padding scheme is not UTF-8")?;
        let mut stop = None;
        let mut packets = BTreeMap::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let (key, value) = line
                .split_once('=')
                .ok_or_else(|| anyhow!("invalid anytls padding scheme line '{line}'"))?;
            if key == "stop" {
                let parsed = value
                    .parse::<u32>()
                    .context("invalid anytls padding stop value")?;
                if parsed > 64 {
                    return Err(anyhow!("anytls padding stop must not exceed 64"));
                }
                stop = Some(parsed);
                continue;
            }
            let packet = key
                .parse::<u32>()
                .with_context(|| format!("invalid anytls padding packet '{key}'"))?;
            let mut instructions = Vec::new();
            for item in value.split(',') {
                let item = item.trim();
                if item == "c" {
                    instructions.push(AnyTlsPaddingInstruction::Check);
                    continue;
                }
                let (minimum, maximum) = item
                    .split_once('-')
                    .ok_or_else(|| anyhow!("invalid anytls padding range '{item}'"))?;
                let minimum = minimum
                    .parse::<usize>()
                    .with_context(|| format!("invalid anytls padding minimum '{minimum}'"))?;
                let maximum = maximum
                    .parse::<usize>()
                    .with_context(|| format!("invalid anytls padding maximum '{maximum}'"))?;
                let (minimum, maximum) = (minimum.min(maximum), minimum.max(maximum));
                if minimum == 0 || maximum > ANYTLS_MAX_PADDING_PACKET_SIZE {
                    return Err(anyhow!(
                        "anytls padding range must be between 1 and {ANYTLS_MAX_PADDING_PACKET_SIZE}"
                    ));
                }
                instructions.push(AnyTlsPaddingInstruction::Range { minimum, maximum });
                if instructions.len() > 32 {
                    return Err(anyhow!("anytls padding packet has too many instructions"));
                }
            }
            packets.insert(packet, instructions);
        }
        let stop = stop.ok_or_else(|| anyhow!("anytls padding scheme has no stop value"))?;
        Ok(Self {
            md5: hex_lower(&Md5::digest(raw)),
            stop,
            packets,
        })
    }

    fn auth_padding_length(&self) -> anyhow::Result<usize> {
        let Some(instructions) = self.packets.get(&0) else {
            return Ok(0);
        };
        for instruction in instructions {
            if let AnyTlsPaddingInstruction::Range { minimum, maximum } = *instruction {
                return random_padding_size(minimum, maximum);
            }
        }
        Ok(0)
    }

    fn packet_sizes(&self, packet: u32) -> anyhow::Result<Vec<Option<usize>>> {
        if packet >= self.stop {
            return Ok(Vec::new());
        }
        self.packets
            .get(&packet)
            .map(|instructions| {
                instructions
                    .iter()
                    .map(|instruction| match *instruction {
                        AnyTlsPaddingInstruction::Check => Ok(None),
                        AnyTlsPaddingInstruction::Range { minimum, maximum } => {
                            random_padding_size(minimum, maximum).map(Some)
                        }
                    })
                    .collect()
            })
            .unwrap_or_else(|| Ok(Vec::new()))
    }
}

impl<W> AnyTlsPaddingWriter<W>
where
    W: AsyncWrite + Unpin,
{
    async fn write(&mut self, payload: &[u8]) -> anyhow::Result<()> {
        let packet = self.packet_counter;
        self.packet_counter = self.packet_counter.saturating_add(1);
        let instructions = self.scheme.packet_sizes(packet)?;
        if instructions.is_empty() {
            self.writer.write_all(payload).await?;
            self.writer.flush().await?;
            return Ok(());
        }

        let mut remaining = payload;
        for instruction in instructions {
            let Some(size) = instruction else {
                if remaining.is_empty() {
                    break;
                }
                continue;
            };
            if remaining.len() > size {
                self.writer.write_all(&remaining[..size]).await?;
                remaining = &remaining[size..];
                continue;
            }
            if !remaining.is_empty() {
                let padding_len = size.saturating_sub(remaining.len() + 7);
                let mut packet = Vec::with_capacity(remaining.len() + 7 + padding_len);
                packet.extend_from_slice(remaining);
                if padding_len > 0 {
                    append_frame(&mut packet, CMD_WASTE, 0, &vec![0; padding_len])?;
                }
                self.writer.write_all(&packet).await?;
                remaining = &[];
            } else {
                let mut packet = Vec::with_capacity(7 + size);
                append_frame(&mut packet, CMD_WASTE, 0, &vec![0; size])?;
                self.writer.write_all(&packet).await?;
            }
        }
        if !remaining.is_empty() {
            self.writer.write_all(remaining).await?;
        }
        self.writer.flush().await?;
        Ok(())
    }
}

fn random_padding_size(minimum: usize, maximum: usize) -> anyhow::Result<usize> {
    if minimum == maximum {
        return Ok(minimum);
    }
    let width = maximum - minimum + 1;
    Ok(minimum + random_u32()? as usize % width)
}

fn build_settings(padding_md5: &str) -> String {
    format!(
        "v={ANYTLS_PROTOCOL_VERSION}\nclient=supercore/{}\npadding-md5={}",
        env!("CARGO_PKG_VERSION"),
        padding_md5
    )
}

fn parse_settings(data: &[u8]) -> HashMap<String, String> {
    String::from_utf8_lossy(data)
        .lines()
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect()
}

fn default_padding_scheme() -> &'static str {
    "stop=8\n0=30-30\n1=100-400\n2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000\n3=9-9,500-1000\n4=500-1000\n5=500-1000\n6=500-1000\n7=500-1000"
}

fn append_frame(output: &mut Vec<u8>, command: u8, sid: u32, data: &[u8]) -> anyhow::Result<()> {
    let length =
        u16::try_from(data.len()).map_err(|_| anyhow!("anytls frame data is too large"))?;
    output.push(command);
    output.extend_from_slice(&sid.to_be_bytes());
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(data);
    Ok(())
}

async fn read_frame<R>(reader: &mut R) -> anyhow::Result<Option<AnyTlsFrame>>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; 7];
    if !read_exact_or_eof(reader, &mut header).await? {
        return Ok(None);
    }
    let command = header[0];
    let sid = u32::from_be_bytes([header[1], header[2], header[3], header[4]]);
    let length = u16::from_be_bytes([header[5], header[6]]) as usize;
    let mut data = vec![0u8; length];
    reader.read_exact(&mut data).await?;
    Ok(Some(AnyTlsFrame { command, sid, data }))
}

fn encode_uot_destination(destination: &Destination, output: &mut Vec<u8>) -> anyhow::Result<()> {
    match destination.host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(address)) => {
            output.push(0x00);
            output.extend_from_slice(&address.octets());
        }
        Ok(std::net::IpAddr::V6(address)) => {
            output.push(0x01);
            output.extend_from_slice(&address.octets());
        }
        Err(_) => {
            let domain = destination.host.as_bytes();
            if domain.is_empty() || domain.len() > u8::MAX as usize {
                return Err(anyhow!("invalid anytls UoT destination host"));
            }
            output.push(0x02);
            output.push(domain.len() as u8);
            output.extend_from_slice(domain);
        }
    }
    output.extend_from_slice(&destination.port.to_be_bytes());
    Ok(())
}

async fn read_uot_destination<R>(reader: &mut R) -> anyhow::Result<Destination>
where
    R: AsyncRead + Unpin,
{
    let family = reader.read_u8().await?;
    let host = match family {
        0x00 => {
            let mut address = [0u8; 4];
            reader.read_exact(&mut address).await?;
            std::net::Ipv4Addr::from(address).to_string()
        }
        0x01 => {
            let mut address = [0u8; 16];
            reader.read_exact(&mut address).await?;
            std::net::Ipv6Addr::from(address).to_string()
        }
        0x02 => {
            let length = reader.read_u8().await? as usize;
            if length == 0 {
                return Err(anyhow!("empty anytls UoT domain"));
            }
            let mut domain = vec![0u8; length];
            reader.read_exact(&mut domain).await?;
            String::from_utf8(domain).context("invalid anytls UoT domain encoding")?
        }
        _ => return Err(anyhow!("invalid anytls UoT address family {family}")),
    };
    let port = reader.read_u16().await?;
    Ok(Destination::new(host, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_padding_scheme_has_official_auth_padding_and_stable_md5() {
        let scheme = AnyTlsPaddingScheme::default_scheme();
        assert_eq!(scheme.auth_padding_length().unwrap(), 30);
        assert_eq!(
            scheme.md5,
            hex_lower(&Md5::digest(default_padding_scheme()))
        );
    }

    #[tokio::test]
    async fn reader_applies_valid_server_padding_update() {
        let (mut server, client) = tokio::io::duplex(4_096);
        let streams = Arc::new(Mutex::new(HashMap::new()));
        let healthy = Arc::new(AtomicBool::new(true));
        let peer_version = Arc::new(AtomicU8::new(1));
        let shared_padding = Arc::new(StdRwLock::new(AnyTlsPaddingScheme::default_scheme()));
        let (write_tx, _write_rx) = mpsc::channel(1);
        let reader = tokio::spawn(run_anytls_reader(
            client,
            write_tx,
            Arc::clone(&streams),
            Arc::clone(&healthy),
            peer_version,
            Arc::clone(&shared_padding),
        ));

        let update = b"stop=2\n0=41-41\n1=52-52";
        let mut frame = Vec::new();
        append_frame(&mut frame, CMD_UPDATE_PADDING_SCHEME, 0, update).unwrap();
        server.write_all(&frame).await.unwrap();
        server.shutdown().await.unwrap();
        reader.await.unwrap();

        let padding = shared_padding.read().unwrap();
        assert_eq!(padding.md5, hex_lower(&Md5::digest(update)));
        assert_eq!(padding.auth_padding_length().unwrap(), 41);
    }

    #[tokio::test]
    async fn reader_rejects_invalid_server_padding_update() {
        let (mut server, client) = tokio::io::duplex(4_096);
        let streams = Arc::new(Mutex::new(HashMap::new()));
        let healthy = Arc::new(AtomicBool::new(true));
        let peer_version = Arc::new(AtomicU8::new(1));
        let shared_padding = Arc::new(StdRwLock::new(AnyTlsPaddingScheme::default_scheme()));
        let original_md5 = shared_padding.read().unwrap().md5.clone();
        let (write_tx, _write_rx) = mpsc::channel(1);
        let reader = tokio::spawn(run_anytls_reader(
            client,
            write_tx,
            Arc::clone(&streams),
            Arc::clone(&healthy),
            peer_version,
            Arc::clone(&shared_padding),
        ));

        let mut frame = Vec::new();
        append_frame(
            &mut frame,
            CMD_UPDATE_PADDING_SCHEME,
            0,
            b"stop=2\n0=0-999999",
        )
        .unwrap();
        server.write_all(&frame).await.unwrap();
        reader.await.unwrap();

        assert!(!healthy.load(Ordering::Acquire));
        assert_eq!(shared_padding.read().unwrap().md5, original_md5);
    }
}
