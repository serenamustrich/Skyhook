use std::{
    collections::HashMap,
    io::Error,
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex as StdMutex},
    task::{Context as TaskContext, Poll},
    time::Duration,
};

use anyhow::{anyhow, Context};
use async_trait::async_trait;
use bytes::Bytes;
use rustls::client::{ClientSessionMemoryCache, ClientSessionStore};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf},
    sync::{mpsc, Mutex as TokioMutex},
    task::JoinHandle,
};
use uuid::Uuid;

use crate::routing::Destination;

use super::{
    context::active_dial_context,
    transports::{
        connect_quic_endpoint_resumable, create_quic_endpoint, quic_client_config_with_resumption,
        random_u16, resolve_quic_remote, run_dial_phase, SharedConnectionPool,
    },
    udp::{
        udp_session_key, FragmentReassembler, KeyedRoundRobinSessionPool, UDP_SESSION_POOL_SIZE,
    },
    BoxedStream, Outbound, OutboundCapability, UdpNatMode,
};

const TUIC_DEFAULT_MAX_UDP_PACKET_SIZE: usize = 65_535;
const TUIC_UDP_ROUTE_CAPACITY: usize = 64;
const TUIC_DEFAULT_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);

pub(super) struct TuicOutbound {
    name: String,
    server: String,
    port: u16,
    uuid: String,
    password: String,
    sni: Option<String>,
    skip_cert_verify: bool,
    congestion_control: Option<String>,
    udp_relay_mode: Option<String>,
    alpn: Option<String>,
    max_udp_relay_packet_size: Option<usize>,
    heartbeat_interval_ms: Option<u64>,
    reduce_rtt: bool,
    tls_sessions: Arc<dyn ClientSessionStore>,
    quic_config: TokioMutex<Option<quinn::ClientConfig>>,
    connection: SharedConnectionPool<TuicConnection>,
    udp_sessions: TokioMutex<TuicUdpPool>,
}

type TuicUdpPool = KeyedRoundRobinSessionPool<TuicUdpSession>;

struct TuicUdpSession {
    shared: Arc<TuicConnection>,
    mode: String,
    associate_id: u16,
    next_packet_id: u16,
    incoming: mpsc::Receiver<Vec<u8>>,
}

impl Drop for TuicUdpSession {
    fn drop(&mut self) {
        self.shared.unregister_udp_session(self.associate_id);
        self.shared.send_dissociate(self.associate_id);
    }
}

struct ValidatedTuicConfig {
    user_id: Uuid,
    mode: String,
    max_udp_relay_packet_size: usize,
    heartbeat_interval: Duration,
}

#[async_trait]
impl Outbound for TuicOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "tuic"
    }

    fn capability(&self) -> OutboundCapability {
        match self.validated_configuration() {
            Ok(config) => {
                OutboundCapability::tcp_udp(format!("{}-session-pool-heartbeat", config.mode))
            }
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
        let connection = self.tuic_connection(&config, timeout_ms).await?;
        let (mut send, recv) = run_dial_phase(timeout_ms, "tuic open stream", async {
            connection.connection.open_bi().await
        })
        .await?
        .context("tuic failed to open bidirectional stream")?;
        let request = build_tuic_connect_request(destination)?;
        run_dial_phase(timeout_ms, "tuic connect request write", async {
            send.write_all(&request).await?;
            send.flush().await
        })
        .await??;
        Ok(Box::new(TuicTcpStream {
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
        if payload.len() > TUIC_DEFAULT_MAX_UDP_PACKET_SIZE {
            return Err(anyhow!("tuic udp payload exceeds 65535 bytes"));
        }
        let config = self.validated_configuration()?;
        let key = udp_session_key(
            self.kind(),
            self.name(),
            self.udp_nat_mode(),
            Some(destination),
        );
        let session_handle = self.tuic_udp_session(&key, &config, timeout_ms).await?;

        let exchange =
            {
                let mut session = session_handle.lock().await;
                async {
                    let packet_id = session.next_packet_id;
                    session.next_packet_id = session.next_packet_id.wrapping_add(1);
                    let messages = build_tuic_packet_messages(
                        session.associate_id,
                        packet_id,
                        destination,
                        payload,
                        if session.mode == "quic" {
                            Some(config.max_udp_relay_packet_size)
                        } else {
                            session
                                .shared
                                .connection
                                .max_datagram_size()
                                .map(|size| size.min(config.max_udp_relay_packet_size))
                        },
                    )?;
                    if session.mode == "quic" {
                        for message in messages {
                            let mut stream =
                                run_dial_phase(timeout_ms, "tuic udp stream open", async {
                                    session.shared.connection.open_uni().await
                                })
                                .await?
                                .context("tuic failed to open udp stream")?;
                            run_dial_phase(timeout_ms, "tuic udp stream write", async {
                                stream.write_all(&message).await.map_err(|error| {
                                    anyhow!("tuic udp stream write failed: {error}")
                                })?;
                                stream.finish().map_err(|error| {
                                    anyhow!("tuic udp stream finish failed: {error}")
                                })
                            })
                            .await??;
                        }
                        run_dial_phase(timeout_ms, "tuic udp stream receive", async {
                            let mut reassembly = TuicUdpReassembly::default();
                            loop {
                                let data =
                                    session.incoming.recv().await.ok_or_else(|| {
                                        anyhow!("tuic udp stream dispatcher stopped")
                                    })?;
                                if let Some(payload) = parse_tuic_packet_message(
                                    &data,
                                    session.associate_id,
                                    &mut reassembly,
                                )? {
                                    return Ok::<Vec<u8>, anyhow::Error>(payload);
                                }
                            }
                        })
                        .await?
                    } else {
                        for message in messages {
                            run_dial_phase(timeout_ms, "tuic udp datagram send", async {
                                session
                                    .shared
                                    .connection
                                    .send_datagram_wait(Bytes::from(message))
                                    .await
                            })
                            .await?
                            .map_err(|error| anyhow!("tuic udp send failed: {error}"))?;
                        }
                        run_dial_phase(timeout_ms, "tuic udp datagram receive", async {
                            let mut reassembly = TuicUdpReassembly::default();
                            loop {
                                let datagram = session.incoming.recv().await.ok_or_else(|| {
                                    anyhow!("tuic udp datagram dispatcher stopped")
                                })?;
                                if let Some(payload) = parse_tuic_packet_message(
                                    &datagram,
                                    session.associate_id,
                                    &mut reassembly,
                                )? {
                                    return Ok::<Vec<u8>, anyhow::Error>(payload);
                                }
                            }
                        })
                        .await?
                    }
                }
                .await
            };
        if exchange.is_err() {
            self.remove_tuic_udp_session(&key, &session_handle).await;
        }
        exchange
    }
}

impl TuicOutbound {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        name: String,
        server: String,
        port: u16,
        uuid: String,
        password: String,
        sni: Option<String>,
        skip_cert_verify: bool,
        congestion_control: Option<String>,
        udp_relay_mode: Option<String>,
        alpn: Option<String>,
        max_udp_relay_packet_size: Option<usize>,
        heartbeat_interval_ms: Option<u64>,
        reduce_rtt: bool,
    ) -> Self {
        Self {
            name,
            server,
            port,
            uuid,
            password,
            sni,
            skip_cert_verify,
            congestion_control,
            udp_relay_mode,
            alpn,
            max_udp_relay_packet_size,
            heartbeat_interval_ms,
            reduce_rtt,
            tls_sessions: Arc::new(ClientSessionMemoryCache::new(64)),
            quic_config: TokioMutex::new(None),
            connection: SharedConnectionPool::default(),
            udp_sessions: TokioMutex::new(TuicUdpPool::default()),
        }
    }

    async fn tuic_connection(
        &self,
        config: &ValidatedTuicConfig,
        timeout_ms: u64,
    ) -> anyhow::Result<Arc<TuicConnection>> {
        let client_config = self.quic_client_config().await?;
        self.connection
            .get_or_connect(
                |connection| connection.connection.close_reason().is_none(),
                || {
                    open_tuic_connection(
                        &self.server,
                        self.port,
                        self.sni.as_deref(),
                        &config.user_id,
                        &self.password,
                        config.heartbeat_interval,
                        self.reduce_rtt,
                        client_config,
                        timeout_ms,
                    )
                },
            )
            .await
    }

    async fn quic_client_config(&self) -> anyhow::Result<quinn::ClientConfig> {
        let mut cached = self.quic_config.lock().await;
        if let Some(config) = cached.as_ref() {
            return Ok(config.clone());
        }
        // Reuse one rustls config per outbound. Rustls deliberately rejects a
        // cached session when a later config uses different verifier/resolver
        // Arc instances, even if both configs have equivalent settings.
        let config = quic_client_config_with_resumption(
            self.skip_cert_verify,
            self.alpn.as_deref().or(Some("h3")),
            self.congestion_control.as_deref(),
            Some(Arc::clone(&self.tls_sessions)),
            true,
        )?;
        *cached = Some(config.clone());
        Ok(config)
    }

    async fn tuic_udp_session(
        &self,
        key: &str,
        config: &ValidatedTuicConfig,
        timeout_ms: u64,
    ) -> anyhow::Result<Arc<TokioMutex<TuicUdpSession>>> {
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

        let connection = self.tuic_connection(config, timeout_ms).await?;
        let (associate_id, incoming) = connection.register_udp_session()?;
        let session = Arc::new(TokioMutex::new(TuicUdpSession {
            shared: connection,
            mode: config.mode.clone(),
            associate_id,
            next_packet_id: random_u16()?,
            incoming,
        }));
        let mut pool = self.udp_sessions.lock().await;
        if pool.len(key) < UDP_SESSION_POOL_SIZE {
            pool.push(key.to_string(), Arc::clone(&session));
            return Ok(session);
        }
        pool.next(key)
            .ok_or_else(|| anyhow!("tuic UDP session pool is unexpectedly empty"))
    }

    fn validated_configuration(&self) -> anyhow::Result<ValidatedTuicConfig> {
        if self.server.trim().is_empty() || self.port == 0 {
            return Err(anyhow!("tuic server and port must be configured"));
        }
        if self.password.is_empty() {
            return Err(anyhow!("tuic password is empty"));
        }
        let user_id = Uuid::parse_str(self.uuid.trim())
            .map_err(|error| anyhow!("invalid tuic uuid for {}: {error}", self.name))?;
        let mode = self
            .udp_relay_mode
            .as_deref()
            .unwrap_or("native")
            .trim()
            .to_ascii_lowercase();
        if !matches!(mode.as_str(), "native" | "quic") {
            return Err(anyhow!("unsupported tuic udp relay mode {mode}"));
        }
        validate_quic_text_list("tuic alpn", self.alpn.as_deref())?;
        validate_tuic_congestion_control(self.congestion_control.as_deref())?;
        let max_udp_relay_packet_size = self
            .max_udp_relay_packet_size
            .unwrap_or(TUIC_DEFAULT_MAX_UDP_PACKET_SIZE);
        if !(512..=TUIC_DEFAULT_MAX_UDP_PACKET_SIZE).contains(&max_udp_relay_packet_size) {
            return Err(anyhow!(
                "tuic max udp relay packet size must be between 512 and 65535 bytes"
            ));
        }
        let heartbeat_interval = self
            .heartbeat_interval_ms
            .map(Duration::from_millis)
            .unwrap_or(TUIC_DEFAULT_HEARTBEAT_INTERVAL);
        if !(Duration::from_millis(500)..=Duration::from_secs(600)).contains(&heartbeat_interval) {
            return Err(anyhow!(
                "tuic heartbeat interval must be between 500ms and 600000ms"
            ));
        }
        Ok(ValidatedTuicConfig {
            user_id,
            mode,
            max_udp_relay_packet_size,
            heartbeat_interval,
        })
    }

    async fn remove_tuic_udp_session(&self, key: &str, target: &Arc<TokioMutex<TuicUdpSession>>) {
        let mut pool = self.udp_sessions.lock().await;
        pool.remove(key, target);
    }

    #[cfg(test)]
    pub(super) async fn take_connection_for_test(&self) -> Option<bool> {
        self.connection
            .take_for_test()
            .await
            .map(|connection| connection._zero_rtt_used)
    }

    #[cfg(test)]
    pub(super) async fn clear_udp_sessions_for_test(&self) {
        *self.udp_sessions.lock().await = TuicUdpPool::default();
    }
}

struct TuicConnection {
    _endpoint: quinn::Endpoint,
    connection: quinn::Connection,
    udp_routes: Arc<StdMutex<HashMap<u16, mpsc::Sender<Vec<u8>>>>>,
    datagram_driver: JoinHandle<()>,
    stream_driver: JoinHandle<()>,
    heartbeat_driver: JoinHandle<()>,
    _zero_rtt_used: bool,
}

impl TuicConnection {
    fn register_udp_session(&self) -> anyhow::Result<(u16, mpsc::Receiver<Vec<u8>>)> {
        for _ in 0..64 {
            let associate_id = random_u16()?;
            let mut routes = self
                .udp_routes
                .lock()
                .map_err(|_| anyhow!("tuic udp route lock poisoned"))?;
            if routes.contains_key(&associate_id) {
                continue;
            }
            let (sender, receiver) = mpsc::channel(TUIC_UDP_ROUTE_CAPACITY);
            routes.insert(associate_id, sender);
            return Ok((associate_id, receiver));
        }
        Err(anyhow!("tuic could not allocate a unique UDP associate id"))
    }

    fn unregister_udp_session(&self, associate_id: u16) {
        if let Ok(mut routes) = self.udp_routes.lock() {
            routes.remove(&associate_id);
        }
    }

    fn send_dissociate(&self, associate_id: u16) {
        let connection = self.connection.clone();
        let command = build_tuic_dissociate(associate_id);
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                let Ok(mut stream) = connection.open_uni().await else {
                    return;
                };
                if stream.write_all(&command).await.is_ok() {
                    let _ = stream.finish();
                }
            });
        }
    }
}

impl Drop for TuicConnection {
    fn drop(&mut self) {
        self.connection
            .close(quinn::VarInt::from_u32(0), b"supercore close");
        self.datagram_driver.abort();
        self.stream_driver.abort();
        self.heartbeat_driver.abort();
    }
}

struct TuicTcpStream {
    _shared: Arc<TuicConnection>,
    recv: quinn::RecvStream,
    send: quinn::SendStream,
}

impl AsyncRead for TuicTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), Error>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for TuicTcpStream {
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
async fn open_tuic_connection(
    server: &str,
    port: u16,
    sni: Option<&str>,
    user_id: &Uuid,
    password: &str,
    heartbeat_interval: Duration,
    reduce_rtt: bool,
    client_config: quinn::ClientConfig,
    timeout_ms: u64,
) -> anyhow::Result<TuicConnection> {
    if password.is_empty() {
        return Err(anyhow!("tuic password is empty"));
    }
    let remote = resolve_quic_remote("tuic", server, port).await?;
    let endpoint = create_quic_endpoint(remote)?;
    let server_name = sni.unwrap_or(server).to_string();
    let zero_rtt = reduce_rtt
        || active_dial_context()
            .as_ref()
            .is_some_and(|context| context.quic_zero_rtt);
    let resumable = connect_quic_endpoint_resumable(
        endpoint,
        remote,
        &server_name,
        client_config,
        zero_rtt,
        timeout_ms,
        "tuic",
    )
    .await?;
    let endpoint = resumable.endpoint;
    let connection = resumable.connection;

    let mut zero_rtt_used = false;
    if let Some(zero_rtt_accepted) = resumable.zero_rtt_accepted {
        let accepted =
            run_dial_phase(timeout_ms, "tuic zero-rtt acceptance", zero_rtt_accepted).await?;
        zero_rtt_used = accepted;
    }
    // TUIC derives its token from the exporter of the current TLS session.
    // Rustls cannot export that keying material until the resumed handshake is
    // confirmed, so authentication and user traffic deliberately stay out of
    // replayable early data.
    send_tuic_auth(&connection, user_id, password, timeout_ms).await?;

    let udp_routes = Arc::new(StdMutex::new(HashMap::new()));
    let datagram_connection = connection.clone();
    let datagram_routes = Arc::clone(&udp_routes);
    let datagram_driver = tokio::spawn(async move {
        while let Ok(datagram) = datagram_connection.read_datagram().await {
            dispatch_tuic_udp_packet(&datagram_routes, datagram.to_vec());
        }
    });
    let stream_connection = connection.clone();
    let stream_routes = Arc::clone(&udp_routes);
    let stream_driver = tokio::spawn(async move {
        while let Ok(mut stream) = stream_connection.accept_uni().await {
            let Ok(packet) = stream
                .read_to_end(TUIC_DEFAULT_MAX_UDP_PACKET_SIZE + 512)
                .await
            else {
                continue;
            };
            dispatch_tuic_udp_packet(&stream_routes, packet);
        }
    });
    let heartbeat_connection = connection.clone();
    let heartbeat_driver = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(heartbeat_interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        ticker.tick().await;
        loop {
            ticker.tick().await;
            if heartbeat_connection.close_reason().is_some() {
                break;
            }
            let _ = heartbeat_connection.send_datagram(Bytes::from_static(&[0x05, 0x04]));
        }
    });

    Ok(TuicConnection {
        _endpoint: endpoint,
        connection,
        udp_routes,
        datagram_driver,
        stream_driver,
        heartbeat_driver,
        _zero_rtt_used: zero_rtt_used,
    })
}

async fn send_tuic_auth(
    connection: &quinn::Connection,
    user_id: &Uuid,
    password: &str,
    timeout_ms: u64,
) -> anyhow::Result<()> {
    let mut token = [0u8; 32];
    connection
        .export_keying_material(&mut token, user_id.as_bytes(), password.as_bytes())
        .map_err(|_| anyhow!("tuic token export failed"))?;
    let mut auth = Vec::with_capacity(2 + 16 + 32);
    auth.extend_from_slice(&[0x05, 0x00]);
    auth.extend_from_slice(user_id.as_bytes());
    auth.extend_from_slice(&token);
    let mut stream = run_dial_phase(timeout_ms, "tuic auth stream open", async {
        connection.open_uni().await
    })
    .await?
    .context("tuic failed to open auth stream")?;
    run_dial_phase(timeout_ms, "tuic auth write", async {
        stream
            .write_all(&auth)
            .await
            .map_err(|error| anyhow!("tuic auth write failed: {error}"))?;
        stream
            .finish()
            .map_err(|error| anyhow!("tuic auth finish failed: {error}"))
    })
    .await??;
    Ok(())
}

fn dispatch_tuic_udp_packet(
    routes: &StdMutex<HashMap<u16, mpsc::Sender<Vec<u8>>>>,
    packet: Vec<u8>,
) {
    if packet.len() < 4 || packet[0] != 0x05 || packet[1] != 0x02 {
        return;
    }
    let associate_id = u16::from_be_bytes([packet[2], packet[3]]);
    let sender = routes
        .lock()
        .ok()
        .and_then(|routes| routes.get(&associate_id).cloned());
    if let Some(sender) = sender {
        let _ = sender.try_send(packet);
    }
}

fn build_tuic_dissociate(associate_id: u16) -> [u8; 4] {
    let id = associate_id.to_be_bytes();
    [0x05, 0x03, id[0], id[1]]
}

pub(super) fn build_tuic_connect_request(destination: &Destination) -> anyhow::Result<Vec<u8>> {
    let mut output = Vec::with_capacity(32 + destination.host.len());
    output.extend_from_slice(&[0x05, 0x01]);
    encode_tuic_address(destination, &mut output)?;
    Ok(output)
}

pub(super) type TuicUdpReassembly = FragmentReassembler<u16>;

pub(super) fn build_tuic_packet_messages(
    associate_id: u16,
    packet_id: u16,
    destination: &Destination,
    payload: &[u8],
    max_datagram_size: Option<usize>,
) -> anyhow::Result<Vec<Vec<u8>>> {
    let single = build_tuic_packet_fragment(associate_id, packet_id, 1, 0, destination, payload)?;
    let header_len =
        build_tuic_packet_fragment(associate_id, packet_id, 1, 0, destination, &[])?.len();
    let max_payload_len = match max_datagram_size {
        Some(max_size) => {
            if single.len() <= max_size {
                return Ok(vec![single]);
            }
            if header_len >= max_size {
                return Err(anyhow!(
                    "tuic udp header is too large for quic datagram: {} >= {}",
                    header_len,
                    max_size
                ));
            }
            (max_size - header_len).min(u16::MAX as usize)
        }
        None => {
            if payload.len() <= u16::MAX as usize {
                return Ok(vec![single]);
            }
            u16::MAX as usize
        }
    };
    let fragment_total = payload.len().div_ceil(max_payload_len);
    if fragment_total > u8::MAX as usize {
        return Err(anyhow!(
            "tuic udp payload needs too many fragments: {fragment_total}"
        ));
    }
    let mut messages = Vec::with_capacity(fragment_total);
    for (index, chunk) in payload.chunks(max_payload_len).enumerate() {
        messages.push(build_tuic_packet_fragment(
            associate_id,
            packet_id,
            fragment_total as u8,
            index as u8,
            destination,
            chunk,
        )?);
    }
    Ok(messages)
}

fn build_tuic_packet_fragment(
    associate_id: u16,
    packet_id: u16,
    fragment_total: u8,
    fragment_id: u8,
    destination: &Destination,
    payload: &[u8],
) -> anyhow::Result<Vec<u8>> {
    if payload.len() > u16::MAX as usize {
        return Err(anyhow!("tuic udp fragment payload is too large"));
    }
    let mut output = Vec::with_capacity(48 + destination.host.len() + payload.len());
    output.extend_from_slice(&[0x05, 0x02]);
    output.extend_from_slice(&associate_id.to_be_bytes());
    output.extend_from_slice(&packet_id.to_be_bytes());
    output.push(fragment_total);
    output.push(fragment_id);
    output.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    if fragment_id == 0 {
        encode_tuic_address(destination, &mut output)?;
    } else {
        output.push(0xff);
    }
    output.extend_from_slice(payload);
    Ok(output)
}

pub(super) fn parse_tuic_packet_message(
    data: &[u8],
    expected_associate_id: u16,
    reassembly: &mut TuicUdpReassembly,
) -> anyhow::Result<Option<Vec<u8>>> {
    if data.len() < 10 || data[0] != 0x05 || data[1] != 0x02 {
        return Ok(None);
    }
    let associate_id = u16::from_be_bytes([data[2], data[3]]);
    if associate_id != expected_associate_id {
        return Ok(None);
    }
    let packet_id = u16::from_be_bytes([data[4], data[5]]);
    let fragment_total = data[6];
    let fragment_id = data[7];
    if fragment_total == 0 || fragment_id >= fragment_total {
        return Err(anyhow!(
            "invalid tuic udp fragment id/count: {fragment_id}/{fragment_total}"
        ));
    }
    let payload_len = u16::from_be_bytes([data[8], data[9]]) as usize;
    let mut cursor = 10;
    let address_type = skip_tuic_address(data, &mut cursor)?;
    if fragment_id == 0 && address_type == 0xff {
        return Err(anyhow!("tuic first UDP fragment is missing its address"));
    }
    if fragment_id > 0 && address_type != 0xff {
        return Err(anyhow!(
            "tuic non-first UDP fragment must use the none address type"
        ));
    }
    if cursor + payload_len > data.len() {
        return Err(anyhow!("tuic udp payload length exceeds packet"));
    }
    let payload = data[cursor..cursor + payload_len].to_vec();
    reassembly
        .push(packet_id, fragment_id, fragment_total, payload)
        .context("tuic udp reassembly failed")
}

fn encode_tuic_address(destination: &Destination, output: &mut Vec<u8>) -> anyhow::Result<()> {
    if let Ok(addr) = destination.host.parse::<SocketAddr>() {
        match addr {
            SocketAddr::V4(addr) => {
                output.push(0x01);
                output.extend_from_slice(&addr.ip().octets());
                output.extend_from_slice(&addr.port().to_be_bytes());
            }
            SocketAddr::V6(addr) => {
                output.push(0x02);
                output.extend_from_slice(&addr.ip().octets());
                output.extend_from_slice(&addr.port().to_be_bytes());
            }
        }
    } else if let Ok(ip) = destination.host.parse::<std::net::IpAddr>() {
        match ip {
            std::net::IpAddr::V4(ip) => {
                output.push(0x01);
                output.extend_from_slice(&ip.octets());
            }
            std::net::IpAddr::V6(ip) => {
                output.push(0x02);
                output.extend_from_slice(&ip.octets());
            }
        }
        output.extend_from_slice(&destination.port.to_be_bytes());
    } else {
        if destination.host.len() > 255 {
            return Err(anyhow!("domain name too long"));
        }
        output.push(0x00);
        output.push(destination.host.len() as u8);
        output.extend_from_slice(destination.host.as_bytes());
        output.extend_from_slice(&destination.port.to_be_bytes());
    }
    Ok(())
}

fn skip_tuic_address(input: &[u8], cursor: &mut usize) -> anyhow::Result<u8> {
    if *cursor >= input.len() {
        return Err(anyhow!("tuic address is missing"));
    }
    let address_type = input[*cursor];
    *cursor += 1;
    match address_type {
        0xff => Ok(address_type),
        0x00 => {
            if *cursor >= input.len() {
                return Err(anyhow!("tuic domain length is missing"));
            }
            let len = input[*cursor] as usize;
            *cursor += 1;
            if *cursor + len + 2 > input.len() {
                return Err(anyhow!("tuic domain address is truncated"));
            }
            *cursor += len + 2;
            Ok(address_type)
        }
        0x01 => {
            if *cursor + 4 + 2 > input.len() {
                return Err(anyhow!("tuic ipv4 address is truncated"));
            }
            *cursor += 4 + 2;
            Ok(address_type)
        }
        0x02 => {
            if *cursor + 16 + 2 > input.len() {
                return Err(anyhow!("tuic ipv6 address is truncated"));
            }
            *cursor += 16 + 2;
            Ok(address_type)
        }
        other => Err(anyhow!("unsupported tuic address type {other}")),
    }
}

fn validate_tuic_congestion_control(value: Option<&str>) -> anyhow::Result<()> {
    let value = value.unwrap_or("cubic").trim().to_ascii_lowercase();
    if matches!(
        value.as_str(),
        "" | "default" | "cubic" | "bbr" | "new-reno" | "new_reno" | "newreno"
    ) {
        Ok(())
    } else {
        Err(anyhow!("unsupported TUIC congestion controller {value}"))
    }
}

fn validate_quic_text_list(label: &str, value: Option<&str>) -> anyhow::Result<()> {
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
