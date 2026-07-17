use std::{
    any::Any,
    collections::HashMap,
    future::Future,
    io::{Error, ErrorKind, IoSliceMut},
    net::SocketAddr,
    pin::Pin,
    sync::{
        atomic::{AtomicU32, AtomicU64, Ordering},
        Arc, Mutex as StdMutex,
    },
    task::{Context as TaskContext, Poll},
    time::{Duration, Instant},
};

use anyhow::{anyhow, Context};
use async_trait::async_trait;
use bytes::Bytes;
use quinn_proto::RttEstimator;
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    sync::{mpsc, Mutex as TokioMutex},
    task::JoinHandle,
};

use crate::routing::Destination;

use super::{
    transports::{
        connect_quic_endpoint, quic_client_config_with_controller_and_tuning, random_u16,
        resolve_quic_remote, run_dial_phase, QuicTransportTuning, SharedConnectionPool,
    },
    udp::{
        create_bound_std_udp, udp_session_key, FragmentReassembler, KeyedRoundRobinSessionPool,
        UDP_SESSION_POOL_SIZE,
    },
    BoxedStream, Outbound, OutboundCapability, UdpNatMode,
};

const HYSTERIA_PROTOCOL_VERSION: u8 = 3;
const HYSTERIA_DEFAULT_ALPN: &str = "hysteria";
const HYSTERIA_DEFAULT_STREAM_WINDOW: u64 = 16 * 1024 * 1024;
const HYSTERIA_DEFAULT_CONNECTION_WINDOW: u64 = 40 * 1024 * 1024;
const HYSTERIA_DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(20);
const HYSTERIA_DEFAULT_KEEPALIVE: Duration = Duration::from_secs(8);
const HYSTERIA_MIN_RATE_BYTES_PER_SECOND: u64 = 16_384;
const HYSTERIA_MAX_UDP_PACKET_SIZE: usize = 65_535;
const HYSTERIA_UDP_ROUTE_CAPACITY: usize = 64;
const XPLUS_SALT_LEN: usize = 16;
const WECHAT_VIDEO_HEADER_LEN: usize = 13;

pub(super) struct HysteriaOutbound {
    name: String,
    server: String,
    port: u16,
    auth: Option<String>,
    auth_str: Option<String>,
    protocol: Option<String>,
    up: Option<String>,
    down: Option<String>,
    sni: Option<String>,
    skip_cert_verify: bool,
    obfs: Option<String>,
    alpn: Option<String>,
    receive_window_conn: Option<u64>,
    receive_window: Option<u64>,
    disable_mtu_discovery: bool,
    fast_open: bool,
    connection: SharedConnectionPool<HysteriaConnection>,
    udp_sessions: TokioMutex<HysteriaUdpPool>,
}

type HysteriaUdpPool = KeyedRoundRobinSessionPool<HysteriaUdpSession>;

struct ValidatedHysteriaConfig {
    auth: Vec<u8>,
    protocol: HysteriaPacketProtocol,
    upload_bytes_per_second: u64,
    download_bytes_per_second: u64,
    obfs_key: Option<Vec<u8>>,
    alpn: String,
    receive_window_conn: u64,
    receive_window: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HysteriaPacketProtocol {
    Udp,
    WechatVideo,
    FakeTcp,
}

impl HysteriaPacketProtocol {
    fn parse(value: Option<&str>) -> anyhow::Result<Self> {
        match value
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("udp")
            .to_ascii_lowercase()
            .as_str()
        {
            "udp" => Ok(Self::Udp),
            "wechat" | "wechat-video" | "wechat_video" => Ok(Self::WechatVideo),
            "faketcp" | "fake-tcp" | "fake_tcp" => Ok(Self::FakeTcp),
            value => Err(anyhow!("unsupported hysteria v1 packet protocol {value}")),
        }
    }

    fn packet_overhead(self) -> usize {
        match self {
            Self::Udp => 0,
            Self::WechatVideo => WECHAT_VIDEO_HEADER_LEN,
            Self::FakeTcp => 0,
        }
    }
}

struct HysteriaUdpSession {
    shared: Arc<HysteriaConnection>,
    session_id: u32,
    next_message_id: u16,
    incoming: mpsc::Receiver<Vec<u8>>,
    _send: quinn::SendStream,
    _recv: quinn::RecvStream,
}

impl Drop for HysteriaUdpSession {
    fn drop(&mut self) {
        self.shared.unregister_udp_session(self.session_id);
    }
}

#[async_trait]
impl Outbound for HysteriaOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "hysteria"
    }

    fn capability(&self) -> OutboundCapability {
        match self.validated_configuration() {
            Ok(config) => OutboundCapability::tcp_udp(match (config.protocol, config.obfs_key) {
                (HysteriaPacketProtocol::Udp, Some(_)) => "quic-datagram-xplus-session-pool",
                (HysteriaPacketProtocol::Udp, None) => "quic-datagram-session-pool",
                (HysteriaPacketProtocol::WechatVideo, Some(_)) => {
                    "quic-datagram-wechat-video-xplus-session-pool"
                }
                (HysteriaPacketProtocol::WechatVideo, None) => {
                    "quic-datagram-wechat-video-session-pool"
                }
                (HysteriaPacketProtocol::FakeTcp, _) => "quic-faketcp-session-pool",
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
        let connection = self.hysteria_connection(&config, timeout_ms).await?;
        let (mut send, mut recv) = run_dial_phase(timeout_ms, "hysteria v1 open stream", async {
            connection.connection.open_bi().await
        })
        .await?
        .context("hysteria v1 failed to open bidirectional stream")?;
        let request = build_hysteria_client_request(false, destination)?;
        run_dial_phase(timeout_ms, "hysteria v1 tcp request write", async {
            send.write_all(&request).await?;
            send.flush().await
        })
        .await??;

        if self.fast_open {
            let establish = Box::pin(async move {
                read_hysteria_server_response(&mut recv)
                    .await
                    .map_err(|error| Error::new(ErrorKind::ConnectionRefused, error))?;
                Ok(recv)
            });
            return Ok(Box::new(HysteriaTcpStream {
                _shared: connection,
                recv: None,
                establish: Some(establish),
                send,
            }));
        }

        run_dial_phase(
            timeout_ms,
            "hysteria v1 tcp response read",
            read_hysteria_server_response(&mut recv),
        )
        .await??;
        Ok(Box::new(HysteriaTcpStream {
            _shared: connection,
            recv: Some(recv),
            establish: None,
            send,
        }))
    }

    async fn udp_exchange(
        &self,
        destination: &Destination,
        payload: &[u8],
        timeout_ms: u64,
    ) -> anyhow::Result<Vec<u8>> {
        if payload.len() > HYSTERIA_MAX_UDP_PACKET_SIZE {
            return Err(anyhow!("hysteria v1 udp payload exceeds 65535 bytes"));
        }
        let config = self.validated_configuration()?;
        let key = udp_session_key(
            self.kind(),
            self.name(),
            self.udp_nat_mode(),
            Some(destination),
        );
        let session_handle = self.hysteria_udp_session(&key, &config, timeout_ms).await?;

        let exchange = {
            let mut session = session_handle.lock().await;
            async {
                let message_id = session.next_message_id.max(1);
                session.next_message_id = message_id.wrapping_add(1).max(1);
                let max_datagram_size = session
                    .shared
                    .connection
                    .max_datagram_size()
                    .ok_or_else(|| anyhow!("hysteria v1 server did not enable QUIC datagrams"))?
                    .saturating_sub(session.shared.packet_overhead);
                let messages = build_hysteria_udp_messages(
                    session.session_id,
                    message_id,
                    destination,
                    payload,
                    max_datagram_size,
                )?;
                for message in messages {
                    run_dial_phase(timeout_ms, "hysteria v1 udp send", async {
                        session
                            .shared
                            .connection
                            .send_datagram_wait(Bytes::from(message))
                            .await
                    })
                    .await?
                    .map_err(|error| anyhow!("hysteria v1 udp send failed: {error}"))?;
                }
                run_dial_phase(timeout_ms, "hysteria v1 udp receive", async {
                    let mut reassembly = FragmentReassembler::default();
                    loop {
                        let datagram = session
                            .incoming
                            .recv()
                            .await
                            .ok_or_else(|| anyhow!("hysteria v1 udp dispatcher stopped"))?;
                        if let Some(payload) = parse_hysteria_udp_message(
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
            self.remove_hysteria_udp_session(&key, &session_handle)
                .await;
        }
        exchange
    }
}

impl HysteriaOutbound {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        name: String,
        server: String,
        port: u16,
        auth: Option<String>,
        auth_str: Option<String>,
        protocol: Option<String>,
        up: Option<String>,
        down: Option<String>,
        sni: Option<String>,
        skip_cert_verify: bool,
        obfs: Option<String>,
        alpn: Option<String>,
        receive_window_conn: Option<u64>,
        receive_window: Option<u64>,
        disable_mtu_discovery: bool,
        fast_open: bool,
    ) -> Self {
        Self {
            name,
            server,
            port,
            auth,
            auth_str,
            protocol,
            up,
            down,
            sni,
            skip_cert_verify,
            obfs,
            alpn,
            receive_window_conn,
            receive_window,
            disable_mtu_discovery,
            fast_open,
            connection: SharedConnectionPool::default(),
            udp_sessions: TokioMutex::new(HysteriaUdpPool::default()),
        }
    }

    fn validated_configuration(&self) -> anyhow::Result<ValidatedHysteriaConfig> {
        if self.server.trim().is_empty() || self.port == 0 {
            return Err(anyhow!("hysteria v1 server and port must be configured"));
        }
        let auth = self
            .auth
            .as_deref()
            .filter(|value| !value.is_empty())
            .or_else(|| self.auth_str.as_deref().filter(|value| !value.is_empty()))
            .ok_or_else(|| anyhow!("hysteria v1 auth is empty"))?
            .as_bytes()
            .to_vec();
        if auth.len() > u16::MAX as usize {
            return Err(anyhow!("hysteria v1 auth exceeds 65535 bytes"));
        }
        let upload_bytes_per_second = parse_hysteria_bandwidth(self.up.as_deref(), "upload")?;
        let download_bytes_per_second = parse_hysteria_bandwidth(self.down.as_deref(), "download")?;
        let protocol = HysteriaPacketProtocol::parse(self.protocol.as_deref())?;
        if protocol == HysteriaPacketProtocol::FakeTcp {
            return Err(anyhow!(
                "hysteria v1 faketcp transport is only available on supported Linux packet backends"
            ));
        }
        let obfs_key = self
            .obfs
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| value.as_bytes().to_vec());
        let alpn = self
            .alpn
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or(HYSTERIA_DEFAULT_ALPN)
            .to_string();
        validate_alpn(&alpn)?;
        let receive_window_conn = self
            .receive_window_conn
            .unwrap_or(HYSTERIA_DEFAULT_STREAM_WINDOW);
        let receive_window = self
            .receive_window
            .unwrap_or(HYSTERIA_DEFAULT_CONNECTION_WINDOW);
        if receive_window_conn < 65_536 || receive_window < 65_536 {
            return Err(anyhow!(
                "hysteria v1 receive windows must be at least 65536 bytes"
            ));
        }
        Ok(ValidatedHysteriaConfig {
            auth,
            protocol,
            upload_bytes_per_second,
            download_bytes_per_second,
            obfs_key,
            alpn,
            receive_window_conn,
            receive_window,
        })
    }

    async fn hysteria_connection(
        &self,
        config: &ValidatedHysteriaConfig,
        timeout_ms: u64,
    ) -> anyhow::Result<Arc<HysteriaConnection>> {
        self.connection
            .get_or_connect(
                |connection| connection.connection.close_reason().is_none(),
                || {
                    open_hysteria_connection(
                        &self.server,
                        self.port,
                        self.sni.as_deref(),
                        self.skip_cert_verify,
                        config,
                        self.disable_mtu_discovery,
                        timeout_ms,
                    )
                },
            )
            .await
    }

    async fn hysteria_udp_session(
        &self,
        key: &str,
        config: &ValidatedHysteriaConfig,
        timeout_ms: u64,
    ) -> anyhow::Result<Arc<TokioMutex<HysteriaUdpSession>>> {
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

        let connection = self.hysteria_connection(config, timeout_ms).await?;
        let (mut send, mut recv) =
            run_dial_phase(timeout_ms, "hysteria v1 udp open stream", async {
                connection.connection.open_bi().await
            })
            .await?
            .context("hysteria v1 failed to open UDP control stream")?;
        let request = build_hysteria_client_request(true, &Destination::new("", 0))?;
        run_dial_phase(timeout_ms, "hysteria v1 udp request write", async {
            send.write_all(&request).await?;
            send.flush().await
        })
        .await??;
        let response = run_dial_phase(
            timeout_ms,
            "hysteria v1 udp response read",
            read_hysteria_server_response(&mut recv),
        )
        .await??;
        let session_id = response.udp_session_id;
        let incoming = connection.register_udp_session(session_id)?;
        let session = Arc::new(TokioMutex::new(HysteriaUdpSession {
            shared: connection,
            session_id,
            next_message_id: random_u16()?.max(1),
            incoming,
            _send: send,
            _recv: recv,
        }));
        let mut pool = self.udp_sessions.lock().await;
        if pool.len(key) < UDP_SESSION_POOL_SIZE {
            pool.push(key.to_string(), Arc::clone(&session));
            return Ok(session);
        }
        pool.next(key)
            .ok_or_else(|| anyhow!("hysteria v1 UDP session pool is unexpectedly empty"))
    }

    async fn remove_hysteria_udp_session(
        &self,
        key: &str,
        target: &Arc<TokioMutex<HysteriaUdpSession>>,
    ) {
        self.udp_sessions.lock().await.remove(key, target);
    }
}

struct HysteriaConnection {
    _endpoint: quinn::Endpoint,
    connection: quinn::Connection,
    udp_driver: JoinHandle<()>,
    udp_routes: Arc<StdMutex<HashMap<u32, mpsc::Sender<Vec<u8>>>>>,
    packet_overhead: usize,
    _server_receive_rate: u64,
    _server_send_rate: u64,
}

impl HysteriaConnection {
    fn register_udp_session(&self, session_id: u32) -> anyhow::Result<mpsc::Receiver<Vec<u8>>> {
        let mut routes = self
            .udp_routes
            .lock()
            .map_err(|_| anyhow!("hysteria v1 udp route lock poisoned"))?;
        if routes.contains_key(&session_id) {
            return Err(anyhow!(
                "hysteria v1 server reused active UDP session id {session_id}"
            ));
        }
        let (sender, receiver) = mpsc::channel(HYSTERIA_UDP_ROUTE_CAPACITY);
        routes.insert(session_id, sender);
        Ok(receiver)
    }

    fn unregister_udp_session(&self, session_id: u32) {
        if let Ok(mut routes) = self.udp_routes.lock() {
            routes.remove(&session_id);
        }
    }
}

impl Drop for HysteriaConnection {
    fn drop(&mut self) {
        self.connection
            .close(quinn::VarInt::from_u32(0), b"supercore close");
        self.udp_driver.abort();
    }
}

type EstablishFuture = Pin<Box<dyn Future<Output = std::io::Result<quinn::RecvStream>> + Send>>;

struct HysteriaTcpStream {
    _shared: Arc<HysteriaConnection>,
    recv: Option<quinn::RecvStream>,
    establish: Option<EstablishFuture>,
    send: quinn::SendStream,
}

impl AsyncRead for HysteriaTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), Error>> {
        if self.recv.is_none() {
            let establish = self
                .establish
                .as_mut()
                .expect("hysteria v1 stream must have a receive stream or establish future");
            match establish.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(recv)) => {
                    self.recv = Some(recv);
                    self.establish = None;
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            }
        }
        Pin::new(
            self.recv
                .as_mut()
                .expect("hysteria v1 receive stream established"),
        )
        .poll_read(cx, buf)
    }
}

impl AsyncWrite for HysteriaTcpStream {
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

#[derive(Debug)]
struct HysteriaServerHello {
    server_send_rate: u64,
    server_receive_rate: u64,
}

#[derive(Debug)]
struct HysteriaServerResponse {
    udp_session_id: u32,
}

#[allow(clippy::too_many_arguments)]
async fn open_hysteria_connection(
    server: &str,
    port: u16,
    sni: Option<&str>,
    skip_cert_verify: bool,
    config: &ValidatedHysteriaConfig,
    disable_mtu_discovery: bool,
    timeout_ms: u64,
) -> anyhow::Result<HysteriaConnection> {
    let remote = resolve_quic_remote("hysteria v1", server, port).await?;
    let packet_overhead =
        config.protocol.packet_overhead() + config.obfs_key.as_ref().map_or(0, |_| XPLUS_SALT_LEN);
    let endpoint = create_hysteria_endpoint(remote, config.protocol, config.obfs_key.as_deref())?;
    let server_name = sni.unwrap_or(server).to_string();
    let negotiated_upload_rate = Arc::new(AtomicU64::new(config.upload_bytes_per_second));
    let controller = Arc::new(HysteriaRateControllerFactory {
        rate: Arc::clone(&negotiated_upload_rate),
        fallback: Arc::new(quinn::congestion::CubicConfig::default()),
    });
    let tuning = QuicTransportTuning {
        stream_receive_window: Some(config.receive_window_conn),
        receive_window: Some(config.receive_window),
        max_idle_timeout: Some(HYSTERIA_DEFAULT_IDLE_TIMEOUT),
        keep_alive_interval: Some(HYSTERIA_DEFAULT_KEEPALIVE),
        initial_mtu: None,
        disable_mtu_discovery,
    };
    let (endpoint, connection) = connect_quic_endpoint(
        endpoint,
        remote,
        &server_name,
        quic_client_config_with_controller_and_tuning(
            skip_cert_verify,
            Some(&config.alpn),
            None,
            controller,
            tuning,
        )?,
        timeout_ms,
        "hysteria v1",
    )
    .await?;

    let (mut send, mut recv) = run_dial_phase(timeout_ms, "hysteria v1 control stream", async {
        connection.open_bi().await
    })
    .await?
    .context("hysteria v1 failed to open control stream")?;
    let hello = build_hysteria_client_hello(
        &config.auth,
        config.upload_bytes_per_second,
        config.download_bytes_per_second,
    )?;
    run_dial_phase(timeout_ms, "hysteria v1 auth write", async {
        send.write_all(&hello).await?;
        send.flush().await
    })
    .await??;
    let hello = run_dial_phase(
        timeout_ms,
        "hysteria v1 auth response",
        read_hysteria_server_hello(&mut recv),
    )
    .await??;
    negotiated_upload_rate.store(hello.server_receive_rate, Ordering::Relaxed);

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

    Ok(HysteriaConnection {
        _endpoint: endpoint,
        connection,
        udp_driver,
        udp_routes,
        packet_overhead,
        _server_receive_rate: hello.server_receive_rate,
        _server_send_rate: hello.server_send_rate,
    })
}

fn create_hysteria_endpoint(
    remote: SocketAddr,
    protocol: HysteriaPacketProtocol,
    obfs_key: Option<&[u8]>,
) -> anyhow::Result<quinn::Endpoint> {
    if protocol == HysteriaPacketProtocol::Udp && obfs_key.is_none() {
        return super::transports::create_quic_endpoint(remote);
    }
    let socket = create_bound_std_udp(remote).context("failed to bind hysteria v1 UDP socket")?;
    let runtime: Arc<dyn quinn::Runtime> = Arc::new(quinn::TokioRuntime);
    let inner = runtime
        .wrap_udp_socket(socket)
        .context("failed to wrap hysteria v1 UDP socket")?;
    let socket = Arc::new(HysteriaPacketSocket::new(inner, protocol, obfs_key));
    quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        None,
        socket,
        runtime,
    )
    .context("failed to create hysteria v1 QUIC endpoint")
}

fn build_hysteria_client_hello(auth: &[u8], upload: u64, download: u64) -> anyhow::Result<Vec<u8>> {
    if auth.len() > u16::MAX as usize {
        return Err(anyhow!("hysteria v1 auth exceeds 65535 bytes"));
    }
    let mut output = Vec::with_capacity(19 + auth.len());
    output.push(HYSTERIA_PROTOCOL_VERSION);
    output.extend_from_slice(&upload.to_be_bytes());
    output.extend_from_slice(&download.to_be_bytes());
    output.extend_from_slice(&(auth.len() as u16).to_be_bytes());
    output.extend_from_slice(auth);
    Ok(output)
}

async fn read_hysteria_server_hello<R>(reader: &mut R) -> anyhow::Result<HysteriaServerHello>
where
    R: AsyncRead + Unpin,
{
    let ok = read_hysteria_bool(reader).await?;
    let server_send_rate = read_u64(reader).await?;
    let server_receive_rate = read_u64(reader).await?;
    let message = read_hysteria_string(reader).await?;
    if !ok {
        return Err(anyhow!("hysteria v1 authentication failed: {message}"));
    }
    if server_send_rate == 0 || server_receive_rate == 0 {
        return Err(anyhow!(
            "hysteria v1 server negotiated an invalid zero bandwidth"
        ));
    }
    Ok(HysteriaServerHello {
        server_send_rate,
        server_receive_rate,
    })
}

fn build_hysteria_client_request(udp: bool, destination: &Destination) -> anyhow::Result<Vec<u8>> {
    let host = if udp { "" } else { destination.host.as_str() };
    if host.len() > u16::MAX as usize {
        return Err(anyhow!("hysteria v1 destination host exceeds 65535 bytes"));
    }
    let mut output = Vec::with_capacity(5 + host.len());
    output.push(u8::from(udp));
    output.extend_from_slice(&(host.len() as u16).to_be_bytes());
    output.extend_from_slice(host.as_bytes());
    output.extend_from_slice(&(if udp { 0 } else { destination.port }).to_be_bytes());
    Ok(output)
}

async fn read_hysteria_server_response<R>(reader: &mut R) -> anyhow::Result<HysteriaServerResponse>
where
    R: AsyncRead + Unpin,
{
    let ok = read_hysteria_bool(reader).await?;
    let udp_session_id = read_u32(reader).await?;
    let message = read_hysteria_string(reader).await?;
    if !ok {
        return Err(anyhow!("hysteria v1 connection rejected: {message}"));
    }
    Ok(HysteriaServerResponse { udp_session_id })
}

async fn read_hysteria_bool<R>(reader: &mut R) -> anyhow::Result<bool>
where
    R: AsyncRead + Unpin,
{
    let mut value = [0u8; 1];
    reader.read_exact(&mut value).await?;
    match value[0] {
        0 => Ok(false),
        1 => Ok(true),
        value => Err(anyhow!("invalid hysteria v1 boolean value {value}")),
    }
}

async fn read_u32<R>(reader: &mut R) -> anyhow::Result<u32>
where
    R: AsyncRead + Unpin,
{
    let mut value = [0u8; 4];
    reader.read_exact(&mut value).await?;
    Ok(u32::from_be_bytes(value))
}

async fn read_u64<R>(reader: &mut R) -> anyhow::Result<u64>
where
    R: AsyncRead + Unpin,
{
    let mut value = [0u8; 8];
    reader.read_exact(&mut value).await?;
    Ok(u64::from_be_bytes(value))
}

async fn read_hysteria_string<R>(reader: &mut R) -> anyhow::Result<String>
where
    R: AsyncRead + Unpin,
{
    let mut length = [0u8; 2];
    reader.read_exact(&mut length).await?;
    let mut value = vec![0u8; u16::from_be_bytes(length) as usize];
    reader.read_exact(&mut value).await?;
    String::from_utf8(value).context("hysteria v1 response is not valid UTF-8")
}

fn build_hysteria_udp_messages(
    session_id: u32,
    message_id: u16,
    destination: &Destination,
    payload: &[u8],
    max_datagram_size: usize,
) -> anyhow::Result<Vec<Vec<u8>>> {
    if destination.host.len() > u16::MAX as usize {
        return Err(anyhow!(
            "hysteria v1 UDP destination host exceeds 65535 bytes"
        ));
    }
    if payload.len() > HYSTERIA_MAX_UDP_PACKET_SIZE {
        return Err(anyhow!("hysteria v1 UDP payload exceeds 65535 bytes"));
    }
    let header_size = 14usize
        .checked_add(destination.host.len())
        .ok_or_else(|| anyhow!("hysteria v1 UDP header size overflow"))?;
    if max_datagram_size <= header_size {
        return Err(anyhow!(
            "hysteria v1 QUIC datagram size {max_datagram_size} cannot fit UDP header {header_size}"
        ));
    }
    let max_payload = max_datagram_size - header_size;
    let fragment_count = payload.len().max(1).div_ceil(max_payload);
    if fragment_count > u8::MAX as usize {
        return Err(anyhow!("hysteria v1 UDP payload needs too many fragments"));
    }
    let mut messages = Vec::with_capacity(fragment_count);
    if payload.is_empty() {
        messages.push(encode_hysteria_udp_message(
            session_id,
            destination,
            0,
            0,
            1,
            payload,
        )?);
        return Ok(messages);
    }
    for (fragment_id, chunk) in payload.chunks(max_payload).enumerate() {
        messages.push(encode_hysteria_udp_message(
            session_id,
            destination,
            if fragment_count > 1 {
                message_id.max(1)
            } else {
                0
            },
            fragment_id as u8,
            fragment_count as u8,
            chunk,
        )?);
    }
    Ok(messages)
}

fn encode_hysteria_udp_message(
    session_id: u32,
    destination: &Destination,
    message_id: u16,
    fragment_id: u8,
    fragment_count: u8,
    payload: &[u8],
) -> anyhow::Result<Vec<u8>> {
    if payload.len() > u16::MAX as usize {
        return Err(anyhow!("hysteria v1 UDP fragment exceeds 65535 bytes"));
    }
    let host = destination.host.as_bytes();
    let mut output = Vec::with_capacity(14 + host.len() + payload.len());
    output.extend_from_slice(&session_id.to_be_bytes());
    output.extend_from_slice(&(host.len() as u16).to_be_bytes());
    output.extend_from_slice(host);
    output.extend_from_slice(&destination.port.to_be_bytes());
    output.extend_from_slice(&message_id.to_be_bytes());
    output.push(fragment_id);
    output.push(fragment_count);
    output.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    output.extend_from_slice(payload);
    Ok(output)
}

fn parse_hysteria_udp_message(
    packet: &[u8],
    expected_session_id: u32,
    reassembly: &mut FragmentReassembler<u16>,
) -> anyhow::Result<Option<Vec<u8>>> {
    if packet.len() < 14 {
        return Err(anyhow!("short hysteria v1 UDP message"));
    }
    let session_id = u32::from_be_bytes([packet[0], packet[1], packet[2], packet[3]]);
    if session_id != expected_session_id {
        return Err(anyhow!(
            "hysteria v1 UDP session mismatch: expected {expected_session_id}, got {session_id}"
        ));
    }
    let host_len = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let header_size = 14usize
        .checked_add(host_len)
        .ok_or_else(|| anyhow!("hysteria v1 UDP header size overflow"))?;
    if packet.len() < header_size {
        return Err(anyhow!("truncated hysteria v1 UDP destination"));
    }
    let _host = std::str::from_utf8(&packet[6..6 + host_len])
        .context("hysteria v1 UDP destination is not valid UTF-8")?;
    let cursor = 6 + host_len;
    let _port = u16::from_be_bytes([packet[cursor], packet[cursor + 1]]);
    let message_id = u16::from_be_bytes([packet[cursor + 2], packet[cursor + 3]]);
    let fragment_id = packet[cursor + 4];
    let fragment_count = packet[cursor + 5];
    let payload_len = u16::from_be_bytes([packet[cursor + 6], packet[cursor + 7]]) as usize;
    if packet.len() != header_size + payload_len {
        return Err(anyhow!("invalid hysteria v1 UDP payload length"));
    }
    if fragment_count > 1 && message_id == 0 {
        return Err(anyhow!(
            "fragmented hysteria v1 UDP message has zero message id"
        ));
    }
    reassembly.push(
        message_id,
        fragment_id,
        fragment_count,
        packet[header_size..].to_vec(),
    )
}

fn parse_hysteria_bandwidth(value: Option<&str>, label: &str) -> anyhow::Result<u64> {
    let value = value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("hysteria v1 {label} bandwidth is required"))?;
    let compact = value
        .chars()
        .filter(|char| !char.is_whitespace())
        .collect::<String>();
    let (number, multiplier, is_bits) = bandwidth_parts(&compact)
        .ok_or_else(|| anyhow!("invalid hysteria v1 {label} bandwidth {value}"))?;
    let amount = number
        .parse::<f64>()
        .with_context(|| format!("invalid hysteria v1 {label} bandwidth {value}"))?;
    if !amount.is_finite() || amount <= 0.0 {
        return Err(anyhow!(
            "hysteria v1 {label} bandwidth must be a positive finite value"
        ));
    }
    let bytes_per_second = amount * multiplier / if is_bits { 8.0 } else { 1.0 };
    if bytes_per_second < HYSTERIA_MIN_RATE_BYTES_PER_SECOND as f64
        || bytes_per_second > u64::MAX as f64
    {
        return Err(anyhow!(
            "hysteria v1 {label} bandwidth must be at least 131.072 Kbps"
        ));
    }
    Ok(bytes_per_second.round() as u64)
}

fn bandwidth_parts(value: &str) -> Option<(&str, f64, bool)> {
    for (suffix, multiplier, is_bits) in [
        ("TBps", 1_000_000_000_000f64, false),
        ("GBps", 1_000_000_000f64, false),
        ("MBps", 1_000_000f64, false),
        ("KBps", 1_000f64, false),
        ("Bps", 1f64, false),
        ("Tbps", 1_000_000_000_000f64, true),
        ("Gbps", 1_000_000_000f64, true),
        ("Mbps", 1_000_000f64, true),
        ("Kbps", 1_000f64, true),
        ("bps", 1f64, true),
    ] {
        if let Some(number) = value.strip_suffix(suffix) {
            return Some((number, multiplier, is_bits));
        }
    }
    if value.parse::<f64>().is_ok() {
        Some((value, 1_000_000f64, true))
    } else {
        None
    }
}

fn validate_alpn(value: &str) -> anyhow::Result<()> {
    let mut count = 0usize;
    for item in value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
    {
        count += 1;
        if item.len() > u8::MAX as usize || !item.is_ascii() {
            return Err(anyhow!(
                "hysteria v1 ALPN entries must be ASCII strings up to 255 bytes"
            ));
        }
    }
    if count == 0 {
        return Err(anyhow!("hysteria v1 ALPN must not be empty"));
    }
    Ok(())
}

struct HysteriaRateControllerFactory {
    rate: Arc<AtomicU64>,
    fallback: Arc<dyn quinn::congestion::ControllerFactory + Send + Sync>,
}

impl quinn::congestion::ControllerFactory for HysteriaRateControllerFactory {
    fn build(
        self: Arc<Self>,
        now: Instant,
        current_mtu: u16,
    ) -> Box<dyn quinn::congestion::Controller> {
        Box::new(HysteriaRateController {
            rate: Arc::clone(&self.rate),
            fallback: Arc::clone(&self.fallback).build(now, current_mtu),
            current_mtu,
            rtt: Duration::from_millis(100),
        })
    }
}

struct HysteriaRateController {
    rate: Arc<AtomicU64>,
    fallback: Box<dyn quinn::congestion::Controller>,
    current_mtu: u16,
    rtt: Duration,
}

impl HysteriaRateController {
    fn rate_window(&self) -> u64 {
        let rate = self.rate.load(Ordering::Relaxed);
        let rtt_nanos = self.rtt.as_nanos().clamp(5_000_000, 10_000_000_000);
        u128::from(rate)
            .saturating_mul(rtt_nanos)
            .saturating_div(1_000_000_000)
            .saturating_mul(4)
            .saturating_div(5)
            .max(u128::from(self.current_mtu) * 10)
            .min(u128::from(u32::MAX)) as u64
    }
}

impl quinn::congestion::Controller for HysteriaRateController {
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
        self.rate_window()
    }

    fn metrics(&self) -> quinn::congestion::ControllerMetrics {
        let mut metrics = self.fallback.metrics();
        metrics.congestion_window = self.rate_window();
        metrics.pacing_rate = Some(self.rate.load(Ordering::Relaxed).saturating_mul(8));
        metrics
    }

    fn clone_box(&self) -> Box<dyn quinn::congestion::Controller> {
        Box::new(Self {
            rate: Arc::clone(&self.rate),
            fallback: self.fallback.clone_box(),
            current_mtu: self.current_mtu,
            rtt: self.rtt,
        })
    }

    fn initial_window(&self) -> u64 {
        self.rate_window()
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

#[derive(Debug)]
struct HysteriaPacketSocket {
    inner: Arc<dyn quinn::AsyncUdpSocket>,
    protocol: HysteriaPacketProtocol,
    obfs_key: Option<Arc<[u8]>>,
    sequence: AtomicU32,
}

impl HysteriaPacketSocket {
    fn new(
        inner: Arc<dyn quinn::AsyncUdpSocket>,
        protocol: HysteriaPacketProtocol,
        obfs_key: Option<&[u8]>,
    ) -> Self {
        Self {
            inner,
            protocol,
            obfs_key: obfs_key.map(|key| Arc::from(key.to_vec().into_boxed_slice())),
            sequence: AtomicU32::new(0),
        }
    }

    fn encode_packet(&self, payload: &[u8]) -> std::io::Result<Vec<u8>> {
        let mut encoded = if let Some(key) = self.obfs_key.as_deref() {
            encode_xplus_packet(key, payload)?
        } else {
            payload.to_vec()
        };
        if self.protocol == HysteriaPacketProtocol::WechatVideo {
            let sequence = self.sequence.fetch_add(1, Ordering::Relaxed);
            let mut packet = Vec::with_capacity(WECHAT_VIDEO_HEADER_LEN + encoded.len());
            packet.extend_from_slice(&[0xa1, 0x08]);
            packet.extend_from_slice(&sequence.to_be_bytes());
            packet.extend_from_slice(&[0x00, 0x10, 0x11, 0x18, 0x30, 0x22, 0x30]);
            packet.append(&mut encoded);
            Ok(packet)
        } else {
            Ok(encoded)
        }
    }

    fn decode_packet(&self, packet: &mut [u8], len: usize) -> std::io::Result<usize> {
        let offset = if self.protocol == HysteriaPacketProtocol::WechatVideo {
            if len <= WECHAT_VIDEO_HEADER_LEN {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "hysteria v1 wechat-video packet is too short",
                ));
            }
            WECHAT_VIDEO_HEADER_LEN
        } else {
            0
        };
        if let Some(key) = self.obfs_key.as_deref() {
            decode_xplus_packet(key, packet, offset, len)
        } else {
            let payload_len = len - offset;
            packet.copy_within(offset..len, 0);
            Ok(payload_len)
        }
    }
}

impl quinn::AsyncUdpSocket for HysteriaPacketSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn quinn::UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &quinn::udp::Transmit) -> std::io::Result<()> {
        if transmit.segment_size.is_some() {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "hysteria v1 packet wrapper does not support segmented UDP transmits",
            ));
        }
        let packet = self.encode_packet(transmit.contents)?;
        self.inner.try_send(&quinn::udp::Transmit {
            destination: transmit.destination,
            ecn: transmit.ecn,
            contents: &packet,
            segment_size: None,
            src_ip: transmit.src_ip,
        })
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
                    let len = meta[index].len;
                    match self.decode_packet(&mut bufs[index][..len], len) {
                        Ok(payload_len) => {
                            meta[index].len = payload_len;
                            meta[index].stride = payload_len;
                        }
                        Err(error) => return Poll::Ready(Err(error)),
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

fn encode_xplus_packet(key: &[u8], payload: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut salt = [0u8; XPLUS_SALT_LEN];
    getrandom::fill(&mut salt)
        .map_err(|error| Error::other(format!("hysteria v1 xplus salt failed: {error}")))?;
    let mask = xplus_mask(key, &salt);
    let mut packet = Vec::with_capacity(XPLUS_SALT_LEN + payload.len());
    packet.extend_from_slice(&salt);
    packet.extend(
        payload
            .iter()
            .enumerate()
            .map(|(index, byte)| byte ^ mask[index % mask.len()]),
    );
    Ok(packet)
}

fn decode_xplus_packet(
    key: &[u8],
    packet: &mut [u8],
    offset: usize,
    len: usize,
) -> std::io::Result<usize> {
    if len < offset + XPLUS_SALT_LEN + 1 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "hysteria v1 xplus packet is too short",
        ));
    }
    let salt_start = offset;
    let payload_start = salt_start + XPLUS_SALT_LEN;
    let mut salt = [0u8; XPLUS_SALT_LEN];
    salt.copy_from_slice(&packet[salt_start..payload_start]);
    let mask = xplus_mask(key, &salt);
    let payload_len = len - payload_start;
    for index in 0..payload_len {
        packet[index] = packet[payload_start + index] ^ mask[index % mask.len()];
    }
    Ok(payload_len)
}

fn xplus_mask(key: &[u8], salt: &[u8; XPLUS_SALT_LEN]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(key);
    hasher.update(salt);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::{
        crypto::aws_lc_rs,
        pki_types::{CertificateDer, PrivatePkcs8KeyDer},
        ServerConfig,
    };

    #[test]
    fn client_hello_matches_hysteria_v1_protocol_v3_layout() {
        let hello = build_hysteria_client_hello(b"secret", 12_500_000, 25_000_000).unwrap();
        assert_eq!(hello[0], 3);
        assert_eq!(&hello[1..9], &12_500_000u64.to_be_bytes());
        assert_eq!(&hello[9..17], &25_000_000u64.to_be_bytes());
        assert_eq!(&hello[17..19], &6u16.to_be_bytes());
        assert_eq!(&hello[19..], b"secret");
    }

    #[test]
    fn tcp_and_udp_requests_use_big_endian_struc_layout() {
        let tcp =
            build_hysteria_client_request(false, &Destination::new("example.com", 443)).unwrap();
        assert_eq!(tcp[0], 0);
        assert_eq!(&tcp[1..3], &11u16.to_be_bytes());
        assert_eq!(&tcp[3..14], b"example.com");
        assert_eq!(&tcp[14..], &443u16.to_be_bytes());

        let udp = build_hysteria_client_request(true, &Destination::new("ignored", 53)).unwrap();
        assert_eq!(udp, vec![1, 0, 0, 0, 0]);
    }

    #[test]
    fn udp_messages_fragment_and_reassemble() {
        let destination = Destination::new("dns.example", 53);
        let payload = vec![0x5a; 256];
        let messages = build_hysteria_udp_messages(7, 9, &destination, &payload, 80).unwrap();
        assert!(messages.len() > 1);
        let mut reassembly = FragmentReassembler::default();
        let mut output = None;
        for message in messages {
            output = parse_hysteria_udp_message(&message, 7, &mut reassembly).unwrap();
        }
        assert_eq!(output.as_deref(), Some(payload.as_slice()));
    }

    #[test]
    fn xplus_matches_official_key_salt_sha256_xor() {
        let key = b"password";
        let salt = [0x11u8; XPLUS_SALT_LEN];
        let payload = b"hysteria-v1";
        let mask = xplus_mask(key, &salt);
        let mut packet = Vec::from(salt);
        packet.extend(
            payload
                .iter()
                .enumerate()
                .map(|(index, byte)| byte ^ mask[index % mask.len()]),
        );
        let len = packet.len();
        let decoded = decode_xplus_packet(key, &mut packet, 0, len).unwrap();
        assert_eq!(decoded, payload.len());
        assert_eq!(&packet[..decoded], payload);
    }

    #[test]
    fn bandwidth_plain_numbers_are_mbps_and_units_preserve_bits_or_bytes() {
        assert_eq!(
            parse_hysteria_bandwidth(Some("100"), "up").unwrap(),
            12_500_000
        );
        assert_eq!(
            parse_hysteria_bandwidth(Some("8 Mbps"), "up").unwrap(),
            1_000_000
        );
        assert_eq!(
            parse_hysteria_bandwidth(Some("1 MBps"), "up").unwrap(),
            1_000_000
        );
        assert!(parse_hysteria_bandwidth(Some("1 Kbps"), "up").is_err());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn xplus_wechat_video_socket_interoperates_over_real_quic() {
        const AUTH: &str = "hy1-obfs-auth";
        const OBFS: &str = "hy1-obfs-password";
        let certificate =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let certificate_der = CertificateDer::from(certificate.cert.der().to_vec());
        let private_key = PrivatePkcs8KeyDer::from(certificate.key_pair.serialize_der());
        let provider = aws_lc_rs::default_provider();
        let mut server_crypto = ServerConfig::builder_with_provider(provider.into())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![certificate_der], private_key.into())
            .unwrap();
        server_crypto.alpn_protocols = vec![b"hysteria".to_vec()];
        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto).unwrap(),
        ));
        let mut transport = quinn::TransportConfig::default();
        transport.datagram_receive_buffer_size(Some(1024 * 1024));
        transport.datagram_send_buffer_size(1024 * 1024);
        server_config.transport_config(Arc::new(transport));

        let socket = std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        socket.set_nonblocking(true).unwrap();
        let runtime: Arc<dyn quinn::Runtime> = Arc::new(quinn::TokioRuntime);
        let inner = runtime.wrap_udp_socket(socket).unwrap();
        let socket = Arc::new(HysteriaPacketSocket::new(
            inner,
            HysteriaPacketProtocol::WechatVideo,
            Some(OBFS.as_bytes()),
        ));
        let endpoint = quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            Some(server_config),
            socket,
            runtime,
        )
        .unwrap();
        let address = endpoint.local_addr().unwrap();
        let (client_done_tx, client_done_rx) = tokio::sync::oneshot::channel();

        let server = tokio::spawn(async move {
            let connection = endpoint.accept().await.unwrap().await.unwrap();
            let (mut control_send, mut control_recv) = connection.accept_bi().await.unwrap();
            let mut header = [0u8; 19];
            control_recv.read_exact(&mut header).await.unwrap();
            assert_eq!(header[0], HYSTERIA_PROTOCOL_VERSION);
            assert_eq!(
                u64::from_be_bytes(header[1..9].try_into().unwrap()),
                12_500_000
            );
            assert_eq!(
                u64::from_be_bytes(header[9..17].try_into().unwrap()),
                25_000_000
            );
            let auth_len = u16::from_be_bytes([header[17], header[18]]) as usize;
            let mut auth = vec![0u8; auth_len];
            control_recv.read_exact(&mut auth).await.unwrap();
            assert_eq!(auth, AUTH.as_bytes());
            let mut hello = vec![1];
            hello.extend_from_slice(&25_000_000u64.to_be_bytes());
            hello.extend_from_slice(&12_500_000u64.to_be_bytes());
            hello.extend_from_slice(&0u16.to_be_bytes());
            control_send.write_all(&hello).await.unwrap();
            control_send.flush().await.unwrap();

            let (mut send, mut recv) = connection.accept_bi().await.unwrap();
            let mut request_header = [0u8; 3];
            recv.read_exact(&mut request_header).await.unwrap();
            assert_eq!(request_header[0], 0);
            let host_len = u16::from_be_bytes([request_header[1], request_header[2]]) as usize;
            let mut target = vec![0u8; host_len + 2];
            recv.read_exact(&mut target).await.unwrap();
            assert_eq!(&target[..host_len], b"obfs.example");
            assert_eq!(
                u16::from_be_bytes([target[host_len], target[host_len + 1]]),
                443
            );
            send.write_all(&[1, 0, 0, 0, 0, 0, 0]).await.unwrap();
            let mut payload = [0u8; 4];
            recv.read_exact(&mut payload).await.unwrap();
            assert_eq!(&payload, b"ping");
            send.write_all(b"pong").await.unwrap();
            send.finish().unwrap();
            let _ = client_done_rx.await;
            endpoint.close(quinn::VarInt::from_u32(0), b"test complete");
        });

        let outbound = HysteriaOutbound::new(
            "hy1-obfs".to_string(),
            address.ip().to_string(),
            address.port(),
            Some(AUTH.to_string()),
            None,
            Some("wechat-video".to_string()),
            Some("100 Mbps".to_string()),
            Some("200 Mbps".to_string()),
            Some("localhost".to_string()),
            true,
            Some(OBFS.to_string()),
            Some("hysteria".to_string()),
            None,
            None,
            true,
            false,
        );
        let mut stream = tokio::time::timeout(
            Duration::from_secs(5),
            outbound.connect(&Destination::new("obfs.example", 443), 2_000),
        )
        .await
        .expect("hysteria v1 obfs connect hung")
        .unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut response = [0u8; 4];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"pong");
        let _ = client_done_tx.send(());
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap();
    }
}
