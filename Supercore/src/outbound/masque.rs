use std::{
    net::SocketAddr,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, OnceLock,
    },
    task::{Context as TaskContext, Poll},
    time::Duration,
};

use anyhow::{anyhow, Context};
use async_trait::async_trait;
use base64::{engine::general_purpose, Engine};
use bytes::{Buf, Bytes, BytesMut};
use futures::future::pending;
use ipnet::IpNet;
use rcgen::{
    CertificateParams, KeyPair, SerialNumber, PKCS_ECDSA_P256_SHA256, PKCS_ECDSA_P384_SHA384,
    PKCS_ECDSA_P521_SHA512,
};
use rustls::{
    client::{
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        Resumption, WebPkiServerVerifier,
    },
    crypto::aws_lc_rs,
    ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme,
};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivateSec1KeyDer, ServerName, UnixTime};
use time::OffsetDateTime;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf},
    sync::Mutex,
    task::JoinHandle,
    time::timeout,
};
use tokio_rustls::TlsConnector;
use ts_netstack_smoltcp::netsock::{
    TcpStream as NetstackTcpStream, UdpSocket as NetstackUdpSocket,
};
use url::Url;
use x509_parser::prelude::{FromDer, SubjectPublicKeyInfo, X509Certificate};

use crate::routing::Destination;

use super::{
    ip_stack::{parse_dns_server, parse_local_network, IpPacketIo, IpStackRuntime},
    transports::{
        connect_quic_endpoint, connect_tcp, create_quic_endpoint, encode_quic_varint,
        quic_client_config_from_rustls, read_quic_varint_from_slice, resolve_quic_remote,
        run_dial_phase, NoCertificateVerification, QuicTransportTuning,
    },
    udp::{KeyedRoundRobinSessionPool, UDP_SESSION_POOL_SIZE},
    BoxedStream, Outbound, OutboundCapability, UdpNatMode,
};

const DEFAULT_CONNECT_URI: &str = "https://cloudflareaccess.com";
const DEFAULT_CONNECT_SNI: &str = "consumer-masque.cloudflareclient.com";
const DEFAULT_L4_SNI: &str = "consumer-masque-proxy.cloudflareclient.com";
const DEFAULT_MTU: u16 = 1_280;
const DEFAULT_HANDSHAKE_TIMEOUT_MS: u64 = 10_000;
const QUIC_KEEPALIVE: Duration = Duration::from_secs(30);
const RELAY_BUFFER_SIZE: usize = 32 * 1024;
const DUPLEX_CAPACITY: usize = 256 * 1024;
const DATAGRAM_CAPSULE_TYPE: u64 = 0;
const ROUTE_ADVERTISEMENT_CAPSULE_TYPE: u64 = 3;

pub(super) struct MasqueOutbound {
    name: String,
    server: String,
    port: u16,
    private_key: String,
    public_key: String,
    ip: Option<String>,
    ipv6: Option<String>,
    uri: Option<String>,
    sni: Option<String>,
    mtu: Option<u16>,
    udp: bool,
    handshake_timeout_ms: Option<u64>,
    skip_cert_verify: bool,
    network: Option<String>,
    congestion_control: Option<String>,
    cwnd: Option<u64>,
    bbr_profile: Option<String>,
    remote_dns_resolve: bool,
    dns: Vec<String>,
    validated: OnceLock<Result<ValidatedMasqueConfig, String>>,
    ip_runtime: Mutex<Option<Arc<MasqueIpRuntime>>>,
    l4_runtime: Mutex<Option<Arc<MasqueH3Session>>>,
    udp_sessions: Mutex<MasqueUdpPool>,
    connect_udp_sessions: Mutex<MasqueConnectUdpPool>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MasqueMode {
    QuicConnectIp,
    H2ConnectIp,
    H3L4Proxy,
    H3ConnectUdp,
}

#[derive(Clone)]
struct ValidatedMasqueConfig {
    server: String,
    port: u16,
    connect_uri: Option<http::Uri>,
    connect_udp_uri_template: Option<String>,
    server_name: String,
    mode: MasqueMode,
    local_networks: Vec<IpNet>,
    dns: Vec<SocketAddr>,
    remote_dns_resolve: bool,
    mtu: u16,
    udp: bool,
    handshake_timeout_ms: u64,
    congestion_control: Option<String>,
    cwnd: Option<u64>,
    bbr_profile: Option<String>,
    tls_config: ClientConfig,
}

struct MasqueIpRuntime {
    stack: Arc<IpStackRuntime>,
    healthy: Arc<AtomicBool>,
    _endpoint: Option<quinn::Endpoint>,
    quic_connection: Option<quinn::Connection>,
    tasks: Vec<JoinHandle<()>>,
}

struct MasqueH3Session {
    _endpoint: quinn::Endpoint,
    connection: quinn::Connection,
    sender: Mutex<h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>>,
    closed: Arc<AtomicBool>,
}

struct MasqueTcpStream {
    inner: NetstackTcpStream,
    _runtime: Arc<MasqueIpRuntime>,
}

type MasqueUdpPool = KeyedRoundRobinSessionPool<MasqueUdpSession>;
type MasqueConnectUdpPool = KeyedRoundRobinSessionPool<MasqueConnectUdpSession>;

struct MasqueUdpSession {
    _runtime: Arc<MasqueIpRuntime>,
    socket: NetstackUdpSocket,
    remote: SocketAddr,
}

struct MasqueConnectUdpSession {
    _endpoint: quinn::Endpoint,
    connection: quinn::Connection,
    flow_id: u64,
    closed: Arc<AtomicBool>,
    tasks: Vec<JoinHandle<()>>,
}

impl MasqueOutbound {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        name: String,
        server: String,
        port: u16,
        private_key: String,
        public_key: String,
        ip: Option<String>,
        ipv6: Option<String>,
        uri: Option<String>,
        sni: Option<String>,
        mtu: Option<u16>,
        udp: bool,
        handshake_timeout_ms: Option<u64>,
        skip_cert_verify: bool,
        network: Option<String>,
        congestion_control: Option<String>,
        cwnd: Option<u64>,
        bbr_profile: Option<String>,
        remote_dns_resolve: bool,
        dns: Vec<String>,
    ) -> Self {
        Self {
            name,
            server,
            port,
            private_key,
            public_key,
            ip,
            ipv6,
            uri,
            sni,
            mtu,
            udp,
            handshake_timeout_ms,
            skip_cert_verify,
            network,
            congestion_control,
            cwnd,
            bbr_profile,
            remote_dns_resolve,
            dns,
            validated: OnceLock::new(),
            ip_runtime: Mutex::new(None),
            l4_runtime: Mutex::new(None),
            udp_sessions: Mutex::new(MasqueUdpPool::default()),
            connect_udp_sessions: Mutex::new(MasqueConnectUdpPool::default()),
        }
    }

    fn validated_configuration(&self) -> anyhow::Result<ValidatedMasqueConfig> {
        self.validated
            .get_or_init(|| {
                self.build_validated_configuration()
                    .map_err(|error| format!("{error:#}"))
            })
            .clone()
            .map_err(anyhow::Error::msg)
    }

    fn build_validated_configuration(&self) -> anyhow::Result<ValidatedMasqueConfig> {
        if self.server.trim().is_empty() || self.port == 0 {
            return Err(anyhow!("MASQUE server and port are required"));
        }
        let mode = match self
            .network
            .as_deref()
            .unwrap_or("quic")
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "" | "quic" | "h3" => MasqueMode::QuicConnectIp,
            "h2" => MasqueMode::H2ConnectIp,
            "h3-l4proxy" | "h3_l4proxy" => MasqueMode::H3L4Proxy,
            "connect-udp" | "h3-connect-udp" | "h3_connect_udp" => MasqueMode::H3ConnectUdp,
            value => return Err(anyhow!("unsupported MASQUE network mode {value}")),
        };
        let (connect_uri, connect_udp_uri_template) = if mode == MasqueMode::H3ConnectUdp {
            let template = self.uri.clone().unwrap_or_else(|| {
                format!(
                    "https://{}/.well-known/masque/udp/{{target_host}}/{{target_port}}/",
                    uri_authority_host(&self.server)
                )
            });
            validate_connect_udp_uri_template(&template)?;
            (None, Some(template))
        } else {
            let uri_text = self.uri.as_deref().unwrap_or(DEFAULT_CONNECT_URI);
            let parsed_uri = Url::parse(uri_text).context("invalid MASQUE CONNECT URI")?;
            if parsed_uri.scheme() != "https" || parsed_uri.host_str().is_none() {
                return Err(anyhow!("MASQUE CONNECT URI must be an absolute https URL"));
            }
            if parsed_uri.query().is_some_and(|query| query.contains('{'))
                || parsed_uri.path().contains('{')
            {
                return Err(anyhow!("MASQUE CONNECT URI templates are not supported"));
            }
            let uri = uri_text
                .parse::<http::Uri>()
                .context("MASQUE CONNECT URI cannot be represented as HTTP URI")?;
            (Some(uri), None)
        };
        let server_name = self.sni.clone().unwrap_or_else(|| {
            if mode == MasqueMode::H3L4Proxy {
                DEFAULT_L4_SNI.to_string()
            } else {
                DEFAULT_CONNECT_SNI.to_string()
            }
        });
        ServerName::try_from(server_name.clone())
            .map_err(|_| anyhow!("invalid MASQUE SNI {server_name}"))?;

        let mut local_networks = Vec::new();
        if let Some(ip) = self.ip.as_deref() {
            local_networks.push(parse_local_network(ip, false)?);
        }
        if let Some(ipv6) = self.ipv6.as_deref() {
            local_networks.push(parse_local_network(ipv6, true)?);
        }
        if matches!(mode, MasqueMode::QuicConnectIp | MasqueMode::H2ConnectIp)
            && local_networks.is_empty()
        {
            return Err(anyhow!("MASQUE CONNECT-IP requires ip and/or ipv6"));
        }
        let mtu = self.mtu.unwrap_or(DEFAULT_MTU);
        if mtu < 576 {
            return Err(anyhow!("MASQUE MTU must be at least 576"));
        }
        if local_networks
            .iter()
            .any(|network| network.addr().is_ipv6())
            && mtu < 1_280
        {
            return Err(anyhow!("MASQUE IPv6 requires an MTU of at least 1280"));
        }
        let dns = self
            .dns
            .iter()
            .map(|value| parse_dns_server(value))
            .collect::<anyhow::Result<Vec<_>>>()?;
        if self.remote_dns_resolve && dns.is_empty() {
            return Err(anyhow!(
                "MASQUE remote-dns-resolve requires at least one DNS server"
            ));
        }
        let handshake_timeout_ms = self
            .handshake_timeout_ms
            .unwrap_or(DEFAULT_HANDSHAKE_TIMEOUT_MS);
        if handshake_timeout_ms == 0 {
            return Err(anyhow!(
                "MASQUE handshake timeout must be greater than zero"
            ));
        }
        if mode == MasqueMode::H3L4Proxy && self.udp {
            return Err(anyhow!("MASQUE h3-l4proxy does not support UDP"));
        }
        if mode == MasqueMode::H3ConnectUdp && !self.udp {
            return Err(anyhow!("MASQUE h3-connect-udp requires udp: true"));
        }
        if let Some(profile) = self
            .bbr_profile
            .as_deref()
            .filter(|value| !value.is_empty())
        {
            match profile.trim().to_ascii_lowercase().as_str() {
                "conservative" | "standard" | "aggressive" => {}
                value => return Err(anyhow!("unsupported MASQUE BBR profile {value}")),
            }
        }
        if self.cwnd == Some(0) {
            return Err(anyhow!("MASQUE cwnd must be greater than zero"));
        }
        let alpn = if mode == MasqueMode::H2ConnectIp {
            b"h2".as_slice()
        } else {
            b"h3".as_slice()
        };
        let tls_config = build_masque_tls_config(
            &self.private_key,
            &self.public_key,
            self.skip_cert_verify,
            alpn,
        )?;
        Ok(ValidatedMasqueConfig {
            server: self.server.clone(),
            port: self.port,
            connect_uri,
            connect_udp_uri_template,
            server_name,
            mode,
            local_networks,
            dns,
            remote_dns_resolve: self.remote_dns_resolve,
            mtu,
            udp: self.udp,
            handshake_timeout_ms,
            congestion_control: self.congestion_control.clone(),
            cwnd: self.cwnd,
            bbr_profile: self
                .bbr_profile
                .as_ref()
                .map(|value| value.trim().to_ascii_lowercase()),
            tls_config,
        })
    }

    async fn ip_runtime(
        &self,
        config: &ValidatedMasqueConfig,
        timeout_ms: u64,
    ) -> anyhow::Result<Arc<MasqueIpRuntime>> {
        let mut runtime = self.ip_runtime.lock().await;
        if let Some(existing) = runtime.as_ref().filter(|item| item.is_healthy()) {
            return Ok(Arc::clone(existing));
        }
        let timeout_ms = timeout_ms.min(config.handshake_timeout_ms);
        let created = Arc::new(MasqueIpRuntime::connect(config, timeout_ms).await?);
        *self.udp_sessions.lock().await = MasqueUdpPool::default();
        *runtime = Some(Arc::clone(&created));
        Ok(created)
    }

    async fn l4_runtime(
        &self,
        config: &ValidatedMasqueConfig,
        timeout_ms: u64,
    ) -> anyhow::Result<Arc<MasqueH3Session>> {
        let mut runtime = self.l4_runtime.lock().await;
        if let Some(existing) = runtime.as_ref().filter(|item| !item.is_closed()) {
            return Ok(Arc::clone(existing));
        }
        let created = Arc::new(
            MasqueH3Session::connect(config, timeout_ms.min(config.handshake_timeout_ms)).await?,
        );
        *runtime = Some(Arc::clone(&created));
        Ok(created)
    }

    async fn udp_session(
        &self,
        runtime: Arc<MasqueIpRuntime>,
        destination: &Destination,
        timeout_ms: u64,
    ) -> anyhow::Result<Arc<Mutex<MasqueUdpSession>>> {
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
        let session = Arc::new(Mutex::new(MasqueUdpSession {
            _runtime: runtime,
            socket,
            remote,
        }));
        let mut pool = self.udp_sessions.lock().await;
        if pool.len(&key) < UDP_SESSION_POOL_SIZE {
            pool.push(key, Arc::clone(&session));
            return Ok(session);
        }
        pool.next(&destination.authority())
            .ok_or_else(|| anyhow!("MASQUE UDP session pool is unexpectedly empty"))
    }

    async fn remove_udp_session(
        &self,
        destination: &Destination,
        target: &Arc<Mutex<MasqueUdpSession>>,
    ) {
        self.udp_sessions
            .lock()
            .await
            .remove(&destination.authority(), target);
    }

    async fn connect_udp_session(
        &self,
        config: &ValidatedMasqueConfig,
        destination: &Destination,
        timeout_ms: u64,
    ) -> anyhow::Result<Arc<Mutex<MasqueConnectUdpSession>>> {
        let key = destination.authority();
        {
            let mut pool = self.connect_udp_sessions.lock().await;
            let count = pool.len(&key);
            if let Some(session) = pool.next(&key) {
                if session.try_lock().is_ok() || count >= UDP_SESSION_POOL_SIZE {
                    return Ok(session);
                }
            }
        }
        let session = Arc::new(Mutex::new(
            MasqueConnectUdpSession::connect(
                config,
                destination,
                timeout_ms.min(config.handshake_timeout_ms),
            )
            .await?,
        ));
        let mut pool = self.connect_udp_sessions.lock().await;
        if pool.len(&key) < UDP_SESSION_POOL_SIZE {
            pool.push(key, Arc::clone(&session));
            return Ok(session);
        }
        pool.next(&destination.authority())
            .ok_or_else(|| anyhow!("MASQUE CONNECT-UDP session pool is unexpectedly empty"))
    }

    async fn remove_connect_udp_session(
        &self,
        destination: &Destination,
        target: &Arc<Mutex<MasqueConnectUdpSession>>,
    ) {
        self.connect_udp_sessions
            .lock()
            .await
            .remove(&destination.authority(), target);
    }
}

#[async_trait]
impl Outbound for MasqueOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "masque"
    }

    fn capability(&self) -> OutboundCapability {
        match self.validated_configuration() {
            Ok(config) if config.mode == MasqueMode::H3ConnectUdp => OutboundCapability::udp_only(
                "masque-h3-connect-udp",
                "CONNECT-UDP is a UDP-only MASQUE mode",
            ),
            Ok(config) if config.mode == MasqueMode::H3L4Proxy || !config.udp => {
                OutboundCapability::tcp_only("masque-http-connect")
            }
            Ok(_) => OutboundCapability::tcp_udp("masque-connect-ip"),
            Err(error) => OutboundCapability::unsupported(error.to_string()),
        }
    }

    fn udp_nat_mode(&self) -> UdpNatMode {
        UdpNatMode::EndpointDependent
    }

    fn runtime_stats(&self) -> Option<serde_json::Value> {
        let config = self.validated_configuration().ok()?;
        Some(serde_json::json!({
            "mode": match config.mode {
                MasqueMode::QuicConnectIp => "quic-connect-ip",
                MasqueMode::H2ConnectIp => "h2-connect-ip",
                MasqueMode::H3L4Proxy => "h3-l4proxy",
                MasqueMode::H3ConnectUdp => "h3-connect-udp",
            },
            "mtu": config.mtu,
            "udp": config.udp,
            "cwnd": config.cwnd,
            "bbr_profile": config.bbr_profile,
        }))
    }

    async fn connect(
        &self,
        destination: &Destination,
        timeout_ms: u64,
    ) -> anyhow::Result<BoxedStream> {
        let config = self.validated_configuration()?;
        if config.mode == MasqueMode::H3ConnectUdp {
            return Err(anyhow!("MASQUE h3-connect-udp does not support TCP"));
        }
        if config.mode == MasqueMode::H3L4Proxy {
            let session = self.l4_runtime(&config, timeout_ms).await?;
            return session.open(destination, timeout_ms).await;
        }
        let runtime = self.ip_runtime(&config, timeout_ms).await?;
        let inner = runtime.stack.connect_tcp(destination, timeout_ms).await?;
        Ok(Box::new(MasqueTcpStream {
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
            return Err(anyhow!("MASQUE UDP payload exceeds 65507 bytes"));
        }
        let config = self.validated_configuration()?;
        if !config.udp || config.mode == MasqueMode::H3L4Proxy {
            return Err(anyhow!("MASQUE UDP is disabled for this outbound"));
        }
        if config.mode == MasqueMode::H3ConnectUdp {
            let session = self
                .connect_udp_session(&config, destination, timeout_ms)
                .await?;
            let exchange = timeout(Duration::from_millis(timeout_ms), async {
                session.lock().await.exchange(payload).await
            })
            .await
            .context("MASQUE CONNECT-UDP exchange timed out")?;
            if exchange.is_err() {
                self.remove_connect_udp_session(destination, &session).await;
            }
            return exchange;
        }
        let runtime = self.ip_runtime(&config, timeout_ms).await?;
        let session = self
            .udp_session(Arc::clone(&runtime), destination, timeout_ms)
            .await?;
        let exchange = timeout(Duration::from_millis(timeout_ms), async {
            let session = session.lock().await;
            session
                .socket
                .send_to(session.remote, payload)
                .await
                .map_err(|error| anyhow!("MASQUE netstack UDP send failed: {error}"))?;
            loop {
                let (source, response) = session
                    .socket
                    .recv_from_bytes()
                    .await
                    .map_err(|error| anyhow!("MASQUE netstack UDP receive failed: {error}"))?;
                if source == session.remote {
                    return Ok::<_, anyhow::Error>(response.to_vec());
                }
            }
        })
        .await
        .context("MASQUE UDP exchange timed out")?;
        if exchange.is_err() {
            self.remove_udp_session(destination, &session).await;
        }
        exchange
    }
}

impl MasqueIpRuntime {
    async fn connect(config: &ValidatedMasqueConfig, timeout_ms: u64) -> anyhow::Result<Self> {
        match config.mode {
            MasqueMode::QuicConnectIp => Self::connect_h3(config, timeout_ms).await,
            MasqueMode::H2ConnectIp => Self::connect_h2(config, timeout_ms).await,
            MasqueMode::H3L4Proxy | MasqueMode::H3ConnectUdp => {
                Err(anyhow!("this MASQUE mode does not use an IP runtime"))
            }
        }
    }

    async fn connect_h3(config: &ValidatedMasqueConfig, timeout_ms: u64) -> anyhow::Result<Self> {
        let remote = resolve_quic_remote("MASQUE", &config.server, config.port).await?;
        let endpoint = create_quic_endpoint(remote)?;
        let tuning = QuicTransportTuning {
            keep_alive_interval: Some(QUIC_KEEPALIVE),
            initial_mtu: Some(1_242),
            ..QuicTransportTuning::default()
        };
        let quic_config = quic_client_config_from_rustls(
            config.tls_config.clone(),
            config.congestion_control.as_deref(),
            tuning,
            masque_initial_window(config)?,
        )?;
        let (endpoint, connection) = connect_quic_endpoint(
            endpoint,
            remote,
            &config.server_name,
            quic_config,
            timeout_ms,
            "MASQUE",
        )
        .await?;
        let mut builder = h3::client::builder();
        builder
            .enable_datagram(true)
            .enable_datagram_00(true)
            .enable_extended_connect(true);
        let (mut driver, mut sender) = run_dial_phase(
            timeout_ms,
            "MASQUE HTTP/3 initialization",
            builder.build::<_, _, Bytes>(h3_quinn::Connection::new(connection.clone())),
        )
        .await??;
        let mut request = http::Request::builder()
            .method(http::Method::CONNECT)
            .version(http::Version::HTTP_3)
            .uri(
                config
                    .connect_uri
                    .clone()
                    .context("MASQUE CONNECT-IP URI is unavailable")?,
            )
            .header("capsule-protocol", "?1")
            .header("cf-connect-proto", "cf-connect-ip")
            .header(http::header::USER_AGENT, "")
            .body(())?;
        request
            .extensions_mut()
            .insert(h3::ext::Protocol::CF_CONNECT_IP);
        let mut stream = run_dial_phase(
            timeout_ms,
            "MASQUE CONNECT-IP request",
            sender.send_request(request),
        )
        .await??;
        let flow_id = stream.id().index();
        let response = run_dial_phase(
            timeout_ms,
            "MASQUE CONNECT-IP response",
            stream.recv_response(),
        )
        .await??;
        validate_masque_status(response.status())?;
        stream
            .send_data(Bytes::from(route_advertisement_capsule()?))
            .await
            .context("failed to advertise MASQUE routes")?;
        let (send_half, recv_half) = stream.split();

        let (stack, packet_io) = IpStackRuntime::start(
            &config.local_networks,
            config.dns.clone(),
            config.remote_dns_resolve,
            usize::from(config.mtu),
        )
        .await?;
        let healthy = Arc::new(AtomicBool::new(true));
        let driver_healthy = Arc::clone(&healthy);
        let driver_task = tokio::spawn(async move {
            let _ = driver.wait_idle().await;
            driver_healthy.store(false, Ordering::Release);
        });
        let hold_healthy = Arc::clone(&healthy);
        let hold_task = tokio::spawn(async move {
            let _sender = sender;
            let _send_half = send_half;
            let _recv_half = recv_half;
            pending::<()>().await;
            hold_healthy.store(false, Ordering::Release);
        });
        let (send_task, receive_task) = spawn_h3_packet_relay(
            connection.clone(),
            flow_id,
            packet_io,
            Arc::clone(&stack),
            Arc::clone(&healthy),
            usize::from(config.mtu),
        );
        Ok(Self {
            stack,
            healthy,
            _endpoint: Some(endpoint),
            quic_connection: Some(connection),
            tasks: vec![driver_task, hold_task, send_task, receive_task],
        })
    }

    async fn connect_h2(config: &ValidatedMasqueConfig, timeout_ms: u64) -> anyhow::Result<Self> {
        let tcp = connect_tcp(&format!("{}:{}", config.server, config.port), timeout_ms).await?;
        let server_name = ServerName::try_from(config.server_name.clone())
            .map_err(|_| anyhow!("invalid MASQUE SNI"))?;
        let tls = run_dial_phase(
            timeout_ms,
            "MASQUE HTTP/2 TLS handshake",
            TlsConnector::from(Arc::new(config.tls_config.clone())).connect(server_name, tcp),
        )
        .await??;
        let (mut sender, connection) = run_dial_phase(
            timeout_ms,
            "MASQUE HTTP/2 initialization",
            h2::client::handshake(tls),
        )
        .await??;
        let healthy = Arc::new(AtomicBool::new(true));
        let connection_healthy = Arc::clone(&healthy);
        let connection_task = tokio::spawn(async move {
            let _ = connection.await;
            connection_healthy.store(false, Ordering::Release);
        });
        sender = run_dial_phase(timeout_ms, "MASQUE HTTP/2 readiness", sender.ready()).await??;
        let request = http::Request::builder()
            .method(http::Method::CONNECT)
            .version(http::Version::HTTP_2)
            .uri(
                config
                    .connect_uri
                    .clone()
                    .context("MASQUE CONNECT-IP URI is unavailable")?,
            )
            .header("cf-connect-proto", "cf-connect-ip")
            .header("pq-enabled", "false")
            .header(http::header::USER_AGENT, "")
            .body(())?;
        let (response, send_stream) = sender
            .send_request(request, false)
            .context("failed to open MASQUE HTTP/2 CONNECT-IP stream")?;
        let response = run_dial_phase(timeout_ms, "MASQUE HTTP/2 response", response).await??;
        validate_masque_status(response.status())?;
        let recv_stream = response.into_body();
        let (stack, packet_io) = IpStackRuntime::start(
            &config.local_networks,
            config.dns.clone(),
            config.remote_dns_resolve,
            usize::from(config.mtu),
        )
        .await?;
        let (send_task, receive_task) = spawn_h2_packet_relay(
            send_stream,
            recv_stream,
            packet_io,
            Arc::clone(&stack),
            Arc::clone(&healthy),
            usize::from(config.mtu),
        );
        Ok(Self {
            stack,
            healthy,
            _endpoint: None,
            quic_connection: None,
            tasks: vec![connection_task, send_task, receive_task],
        })
    }

    fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::Acquire)
            && self.stack.is_healthy()
            && self.tasks.iter().all(|task| !task.is_finished())
            && self
                .quic_connection
                .as_ref()
                .is_none_or(|connection| connection.close_reason().is_none())
    }
}

impl Drop for MasqueIpRuntime {
    fn drop(&mut self) {
        self.healthy.store(false, Ordering::Release);
        self.stack.mark_unhealthy();
        if let Some(connection) = &self.quic_connection {
            connection.close(0u32.into(), b"MASQUE runtime closed");
        }
        for task in &self.tasks {
            task.abort();
        }
    }
}

impl MasqueH3Session {
    async fn connect(config: &ValidatedMasqueConfig, timeout_ms: u64) -> anyhow::Result<Self> {
        let remote = resolve_quic_remote("MASQUE L4", &config.server, config.port).await?;
        let endpoint = create_quic_endpoint(remote)?;
        let quic_config = quic_client_config_from_rustls(
            config.tls_config.clone(),
            config.congestion_control.as_deref(),
            QuicTransportTuning {
                keep_alive_interval: Some(QUIC_KEEPALIVE),
                initial_mtu: Some(1_242),
                ..QuicTransportTuning::default()
            },
            masque_initial_window(config)?,
        )?;
        let (endpoint, connection) = connect_quic_endpoint(
            endpoint,
            remote,
            &config.server_name,
            quic_config,
            timeout_ms,
            "MASQUE L4",
        )
        .await?;
        let (mut driver, sender) = run_dial_phase(
            timeout_ms,
            "MASQUE L4 HTTP/3 initialization",
            h3::client::new(h3_quinn::Connection::new(connection.clone())),
        )
        .await??;
        let closed = Arc::new(AtomicBool::new(false));
        let driver_closed = Arc::clone(&closed);
        tokio::spawn(async move {
            let _ = driver.wait_idle().await;
            driver_closed.store(true, Ordering::Release);
        });
        Ok(Self {
            _endpoint: endpoint,
            connection,
            sender: Mutex::new(sender),
            closed,
        })
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire) || self.connection.close_reason().is_some()
    }

    async fn open(
        &self,
        destination: &Destination,
        timeout_ms: u64,
    ) -> anyhow::Result<BoxedStream> {
        if self.is_closed() {
            return Err(anyhow!("MASQUE L4 session is closed"));
        }
        let authority = destination.authority();
        let request = http::Request::builder()
            .method(http::Method::CONNECT)
            .version(http::Version::HTTP_3)
            .uri(format!("https://{authority}"))
            .body(())?;
        let mut sender = self.sender.lock().await;
        let mut stream = run_dial_phase(
            timeout_ms,
            "MASQUE L4 CONNECT request",
            sender.send_request(request),
        )
        .await??;
        drop(sender);
        let response = run_dial_phase(
            timeout_ms,
            "MASQUE L4 CONNECT response",
            stream.recv_response(),
        )
        .await??;
        validate_masque_status(response.status())?;
        Ok(Box::new(spawn_h3_l4_stream(stream)))
    }
}

impl MasqueConnectUdpSession {
    async fn connect(
        config: &ValidatedMasqueConfig,
        destination: &Destination,
        timeout_ms: u64,
    ) -> anyhow::Result<Self> {
        let remote = resolve_quic_remote("MASQUE CONNECT-UDP", &config.server, config.port).await?;
        let endpoint = create_quic_endpoint(remote)?;
        let quic_config = quic_client_config_from_rustls(
            config.tls_config.clone(),
            config.congestion_control.as_deref(),
            QuicTransportTuning {
                keep_alive_interval: Some(QUIC_KEEPALIVE),
                initial_mtu: Some(1_242),
                ..QuicTransportTuning::default()
            },
            masque_initial_window(config)?,
        )?;
        let (endpoint, connection) = connect_quic_endpoint(
            endpoint,
            remote,
            &config.server_name,
            quic_config,
            timeout_ms,
            "MASQUE CONNECT-UDP",
        )
        .await?;
        let mut builder = h3::client::builder();
        builder.enable_datagram(true).enable_extended_connect(true);
        let (mut driver, mut sender) = run_dial_phase(
            timeout_ms,
            "MASQUE CONNECT-UDP HTTP/3 initialization",
            builder.build::<_, _, Bytes>(h3_quinn::Connection::new(connection.clone())),
        )
        .await??;
        let template = config
            .connect_udp_uri_template
            .as_deref()
            .context("MASQUE CONNECT-UDP URI template is unavailable")?;
        let mut request = http::Request::builder()
            .method(http::Method::CONNECT)
            .version(http::Version::HTTP_3)
            .uri(expand_connect_udp_uri_template(template, destination)?)
            .header("capsule-protocol", "?1")
            .body(())?;
        request
            .extensions_mut()
            .insert(h3::ext::Protocol::CONNECT_UDP);
        let mut stream = run_dial_phase(
            timeout_ms,
            "MASQUE CONNECT-UDP request",
            sender.send_request(request),
        )
        .await??;
        let flow_id = stream.id().index();
        let response = run_dial_phase(
            timeout_ms,
            "MASQUE CONNECT-UDP response",
            stream.recv_response(),
        )
        .await??;
        validate_masque_status(response.status())?;
        let (send_half, recv_half) = stream.split();
        let closed = Arc::new(AtomicBool::new(false));
        let driver_closed = Arc::clone(&closed);
        let driver_task = tokio::spawn(async move {
            let _ = driver.wait_idle().await;
            driver_closed.store(true, Ordering::Release);
        });
        let hold_closed = Arc::clone(&closed);
        let hold_task = tokio::spawn(async move {
            let _sender = sender;
            let _send_half = send_half;
            let _recv_half = recv_half;
            pending::<()>().await;
            hold_closed.store(true, Ordering::Release);
        });
        Ok(Self {
            _endpoint: endpoint,
            connection,
            flow_id,
            closed,
            tasks: vec![driver_task, hold_task],
        })
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
            || self.connection.close_reason().is_some()
            || self.tasks.iter().any(JoinHandle::is_finished)
    }

    async fn exchange(&self, payload: &[u8]) -> anyhow::Result<Vec<u8>> {
        if self.is_closed() {
            return Err(anyhow!("MASQUE CONNECT-UDP session is closed"));
        }
        let mut datagram = Vec::with_capacity(payload.len() + 16);
        encode_quic_varint(self.flow_id, &mut datagram)?;
        encode_quic_varint(0, &mut datagram)?;
        datagram.extend_from_slice(payload);
        self.connection
            .send_datagram_wait(Bytes::from(datagram))
            .await
            .context("failed to send MASQUE CONNECT-UDP datagram")?;
        loop {
            let datagram = self
                .connection
                .read_datagram()
                .await
                .context("failed to receive MASQUE CONNECT-UDP datagram")?;
            let mut cursor = 0;
            let received_flow = read_quic_varint_from_slice(&datagram, &mut cursor)?;
            let context_id = read_quic_varint_from_slice(&datagram, &mut cursor)?;
            if received_flow == self.flow_id && context_id == 0 {
                return Ok(datagram[cursor..].to_vec());
            }
        }
    }
}

impl Drop for MasqueConnectUdpSession {
    fn drop(&mut self) {
        self.closed.store(true, Ordering::Release);
        self.connection
            .close(0u32.into(), b"MASQUE CONNECT-UDP session closed");
        for task in &self.tasks {
            task.abort();
        }
    }
}

impl Drop for MasqueH3Session {
    fn drop(&mut self) {
        self.closed.store(true, Ordering::Release);
        self.connection
            .close(0u32.into(), b"MASQUE L4 session closed");
    }
}

impl AsyncRead for MasqueTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buffer)
    }
}

impl AsyncWrite for MasqueTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buffer)
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

#[derive(Debug)]
struct MasqueServerKeyVerifier {
    expected_spki: Vec<u8>,
    signature_verifier: Arc<dyn ServerCertVerifier>,
}

impl ServerCertVerifier for MasqueServerKeyVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        for certificate in std::iter::once(end_entity).chain(intermediates.iter()) {
            let (_, parsed) = X509Certificate::from_der(certificate.as_ref()).map_err(|_| {
                rustls::Error::General("MASQUE server certificate is malformed".to_string())
            })?;
            if parsed.public_key().raw != self.expected_spki.as_slice() {
                return Err(rustls::Error::General(
                    "MASQUE server public key pin mismatch".to_string(),
                ));
            }
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.signature_verifier
            .verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.signature_verifier
            .verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.signature_verifier.supported_verify_schemes()
    }
}

fn build_masque_tls_config(
    private_key: &str,
    public_key: &str,
    skip_cert_verify: bool,
    alpn: &[u8],
) -> anyhow::Result<ClientConfig> {
    let private_key = decode_standard_base64(private_key, "MASQUE private-key")?;
    let public_key = decode_standard_base64(public_key, "MASQUE public-key")?;
    let (remaining, server_spki) = SubjectPublicKeyInfo::from_der(&public_key)
        .map_err(|_| anyhow!("MASQUE public-key is not DER SubjectPublicKeyInfo"))?;
    if !remaining.is_empty() {
        return Err(anyhow!("MASQUE public-key contains trailing DER data"));
    }
    if server_spki.algorithm.algorithm.to_id_string() != "1.2.840.10045.2.1" {
        return Err(anyhow!(
            "MASQUE public-key must contain an ECDSA public key"
        ));
    }
    let (certificate, private_key) = build_masque_client_identity(private_key)?;
    let provider = Arc::new(aws_lc_rs::default_provider());
    let builder = ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&rustls::version::TLS13])?;
    let verifier: Arc<dyn ServerCertVerifier> = if skip_cert_verify {
        Arc::new(NoCertificateVerification)
    } else {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let signature_verifier =
            WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider).build()?;
        Arc::new(MasqueServerKeyVerifier {
            expected_spki: public_key,
            signature_verifier,
        })
    };
    let mut config = builder
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(vec![certificate], private_key)?;
    config.alpn_protocols = vec![alpn.to_vec()];
    config.resumption = Resumption::in_memory_sessions(64);
    Ok(config)
}

fn build_masque_client_identity(
    private_key: Vec<u8>,
) -> anyhow::Result<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
    let rustls_private_key = PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(private_key.clone()));
    let sec1 = PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(private_key));
    let key_pair =
        KeyPair::try_from(&sec1).context("MASQUE private-key is not a SEC1 ECDSA key")?;
    if ![
        &PKCS_ECDSA_P256_SHA256,
        &PKCS_ECDSA_P384_SHA384,
        &PKCS_ECDSA_P521_SHA512,
    ]
    .contains(&key_pair.algorithm())
    {
        return Err(anyhow!("MASQUE private-key must contain an ECDSA key"));
    }
    let now = OffsetDateTime::now_utc();
    let mut params = CertificateParams::default();
    params.not_before = now;
    params.not_after = now + time::Duration::days(1);
    params.serial_number = Some(SerialNumber::from(0u64));
    let certificate = params
        .self_signed(&key_pair)
        .context("failed to generate MASQUE client certificate")?;
    let certificate = CertificateDer::from(certificate.der().to_vec());
    Ok((certificate, rustls_private_key))
}

fn decode_standard_base64(value: &str, label: &str) -> anyhow::Result<Vec<u8>> {
    general_purpose::STANDARD
        .decode(value.trim())
        .with_context(|| format!("{label} is not valid standard base64"))
}

fn uri_authority_host(host: &str) -> String {
    if host.starts_with('[') || host.parse::<std::net::Ipv6Addr>().is_err() {
        host.to_string()
    } else {
        format!("[{host}]")
    }
}

fn validate_connect_udp_uri_template(template: &str) -> anyhow::Result<()> {
    if !template.contains("{target_host}") || !template.contains("{target_port}") {
        return Err(anyhow!(
            "MASQUE CONNECT-UDP URI template must contain {{target_host}} and {{target_port}}"
        ));
    }
    expand_connect_udp_uri_template(template, &Destination::new("example.com", 443))?;
    Ok(())
}

fn expand_connect_udp_uri_template(
    template: &str,
    destination: &Destination,
) -> anyhow::Result<http::Uri> {
    let escaped_host =
        url::form_urlencoded::byte_serialize(destination.host.as_bytes()).collect::<String>();
    let expanded = template
        .replace("{target_host}", &escaped_host)
        .replace("{target_port}", &destination.port.to_string());
    if expanded.contains('{') || expanded.contains('}') {
        return Err(anyhow!(
            "MASQUE CONNECT-UDP URI template contains unsupported variables"
        ));
    }
    let parsed = Url::parse(&expanded).context("invalid expanded MASQUE CONNECT-UDP URI")?;
    if parsed.scheme() != "https" || parsed.host_str().is_none() {
        return Err(anyhow!(
            "MASQUE CONNECT-UDP URI template must produce an absolute https URL"
        ));
    }
    expanded
        .parse::<http::Uri>()
        .context("expanded MASQUE CONNECT-UDP URI cannot be represented as HTTP URI")
}

fn masque_initial_window(config: &ValidatedMasqueConfig) -> anyhow::Result<Option<u64>> {
    let packets = config.cwnd.or_else(|| {
        config.bbr_profile.as_deref().map(|profile| match profile {
            "conservative" => 24,
            "aggressive" => 48,
            _ => 32,
        })
    });
    packets
        .map(|packets| {
            packets
                .checked_mul(1_200)
                .ok_or_else(|| anyhow!("MASQUE cwnd is too large"))
        })
        .transpose()
}

fn spawn_h3_packet_relay(
    connection: quinn::Connection,
    flow_id: u64,
    packet_io: IpPacketIo,
    stack: Arc<IpStackRuntime>,
    healthy: Arc<AtomicBool>,
    mtu: usize,
) -> (JoinHandle<()>, JoinHandle<()>) {
    let IpPacketIo {
        mut outgoing,
        incoming,
    } = packet_io;
    let send_connection = connection.clone();
    let send_stack = Arc::clone(&stack);
    let send_healthy = Arc::clone(&healthy);
    let send_task = tokio::spawn(async move {
        while let Some(packet) = outgoing.recv_async().await {
            let Ok(packet) = prepare_outgoing_ip_packet(packet.to_vec(), mtu) else {
                continue;
            };
            let mut datagram = Vec::with_capacity(packet.len() + 16);
            if encode_quic_varint(flow_id, &mut datagram).is_err()
                || encode_quic_varint(0, &mut datagram).is_err()
            {
                break;
            }
            datagram.extend_from_slice(&packet);
            if send_connection
                .send_datagram_wait(Bytes::from(datagram))
                .await
                .is_err()
            {
                break;
            }
        }
        send_healthy.store(false, Ordering::Release);
        send_stack.mark_unhealthy();
    });
    let receive_stack = stack;
    let receive_task = tokio::spawn(async move {
        loop {
            let datagram = match connection.read_datagram().await {
                Ok(datagram) => datagram,
                Err(_) => break,
            };
            let mut cursor = 0;
            let Ok(received_flow) = read_quic_varint_from_slice(&datagram, &mut cursor) else {
                continue;
            };
            let Ok(context_id) = read_quic_varint_from_slice(&datagram, &mut cursor) else {
                continue;
            };
            if received_flow != flow_id || context_id != 0 {
                continue;
            }
            let packet = &datagram[cursor..];
            if validate_incoming_ip_packet(packet, mtu).is_ok() {
                incoming.send_async(packet).await;
            }
        }
        healthy.store(false, Ordering::Release);
        receive_stack.mark_unhealthy();
    });
    (send_task, receive_task)
}

fn spawn_h2_packet_relay(
    mut send_stream: h2::SendStream<Bytes>,
    mut recv_stream: h2::RecvStream,
    packet_io: IpPacketIo,
    stack: Arc<IpStackRuntime>,
    healthy: Arc<AtomicBool>,
    mtu: usize,
) -> (JoinHandle<()>, JoinHandle<()>) {
    let IpPacketIo {
        mut outgoing,
        incoming,
    } = packet_io;
    let send_stack = Arc::clone(&stack);
    let send_healthy = Arc::clone(&healthy);
    let send_task = tokio::spawn(async move {
        while let Some(packet) = outgoing.recv_async().await {
            let Ok(packet) = prepare_outgoing_ip_packet(packet.to_vec(), mtu) else {
                continue;
            };
            let mut capsule = Vec::with_capacity(packet.len() + 16);
            if encode_quic_varint(DATAGRAM_CAPSULE_TYPE, &mut capsule).is_err()
                || encode_quic_varint(packet.len() as u64, &mut capsule).is_err()
            {
                break;
            }
            capsule.extend_from_slice(&packet);
            if send_h2_bytes(&mut send_stream, capsule).await.is_err() {
                break;
            }
        }
        send_healthy.store(false, Ordering::Release);
        send_stack.mark_unhealthy();
    });
    let receive_stack = stack;
    let receive_task = tokio::spawn(async move {
        let mut decoder = CapsuleDecoder::default();
        while let Some(chunk) = recv_stream.data().await {
            let chunk = match chunk {
                Ok(chunk) => chunk,
                Err(_) => break,
            };
            let length = chunk.len();
            decoder.buffer.extend_from_slice(&chunk);
            let _ = recv_stream.flow_control().release_capacity(length);
            loop {
                match decoder.next_datagram() {
                    Ok(Some(packet)) if validate_incoming_ip_packet(&packet, mtu).is_ok() => {
                        incoming.send_async(&packet).await;
                    }
                    Ok(Some(_)) => {}
                    Ok(None) => break,
                    Err(_) => {
                        healthy.store(false, Ordering::Release);
                        receive_stack.mark_unhealthy();
                        return;
                    }
                }
            }
        }
        healthy.store(false, Ordering::Release);
        receive_stack.mark_unhealthy();
    });
    (send_task, receive_task)
}

async fn send_h2_bytes(
    stream: &mut h2::SendStream<Bytes>,
    mut payload: Vec<u8>,
) -> anyhow::Result<()> {
    use futures::future::poll_fn;

    while !payload.is_empty() {
        stream.reserve_capacity(payload.len());
        let capacity = poll_fn(|cx| stream.poll_capacity(cx))
            .await
            .ok_or_else(|| anyhow!("MASQUE HTTP/2 send stream closed"))??;
        if capacity == 0 {
            continue;
        }
        let length = capacity.min(payload.len());
        let remainder = payload.split_off(length);
        stream.send_data(Bytes::from(payload), false)?;
        payload = remainder;
    }
    Ok(())
}

#[derive(Default)]
struct CapsuleDecoder {
    buffer: BytesMut,
}

impl CapsuleDecoder {
    fn next_datagram(&mut self) -> anyhow::Result<Option<Vec<u8>>> {
        let mut cursor = 0;
        let capsule_type = match read_quic_varint_from_slice(&self.buffer, &mut cursor) {
            Ok(value) => value,
            Err(error) if error.to_string().contains("truncated") || self.buffer.len() < 8 => {
                return Ok(None)
            }
            Err(error) => return Err(error),
        };
        let length = match read_quic_varint_from_slice(&self.buffer, &mut cursor) {
            Ok(value) => usize::try_from(value).context("MASQUE capsule length exceeds usize")?,
            Err(_) => return Ok(None),
        };
        if length > 65_535 || self.buffer.len() < cursor + length {
            if length > 65_535 {
                return Err(anyhow!("MASQUE capsule exceeds 65535 bytes"));
            }
            return Ok(None);
        }
        let mut frame = self.buffer.split_to(cursor + length);
        frame.advance(cursor);
        if capsule_type == DATAGRAM_CAPSULE_TYPE {
            Ok(Some(frame.to_vec()))
        } else {
            Ok(Some(Vec::new()))
        }
    }
}

fn route_advertisement_capsule() -> anyhow::Result<Vec<u8>> {
    let mut payload = Vec::with_capacity(44);
    payload.push(4);
    payload.extend_from_slice(&[0, 0, 0, 0]);
    payload.extend_from_slice(&[255, 255, 255, 255]);
    payload.push(0);
    payload.push(6);
    payload.extend_from_slice(&[0; 16]);
    payload.extend_from_slice(&[255; 16]);
    payload.push(0);
    let mut capsule = Vec::with_capacity(payload.len() + 16);
    encode_quic_varint(ROUTE_ADVERTISEMENT_CAPSULE_TYPE, &mut capsule)?;
    encode_quic_varint(payload.len() as u64, &mut capsule)?;
    capsule.extend_from_slice(&payload);
    Ok(capsule)
}

fn prepare_outgoing_ip_packet(mut packet: Vec<u8>, mtu: usize) -> anyhow::Result<Vec<u8>> {
    validate_incoming_ip_packet(&packet, mtu)?;
    match packet[0] >> 4 {
        4 => {
            if packet[8] <= 1 {
                return Err(anyhow!("MASQUE IPv4 packet TTL is too small"));
            }
            packet[8] -= 1;
            packet[10] = 0;
            packet[11] = 0;
            let header_length = usize::from(packet[0] & 0x0f) * 4;
            let checksum = ipv4_checksum(&packet[..header_length]);
            packet[10..12].copy_from_slice(&checksum.to_be_bytes());
        }
        6 => {
            if packet[7] <= 1 {
                return Err(anyhow!("MASQUE IPv6 packet hop limit is too small"));
            }
            packet[7] -= 1;
        }
        _ => unreachable!(),
    }
    Ok(packet)
}

fn validate_incoming_ip_packet(packet: &[u8], mtu: usize) -> anyhow::Result<()> {
    if packet.is_empty() || packet.len() > mtu {
        return Err(anyhow!("MASQUE IP packet has an invalid length"));
    }
    match packet[0] >> 4 {
        4 => {
            if packet.len() < 20 {
                return Err(anyhow!("MASQUE IPv4 packet is too short"));
            }
            let header_length = usize::from(packet[0] & 0x0f) * 4;
            if header_length < 20 || header_length > packet.len() {
                return Err(anyhow!("MASQUE IPv4 header length is invalid"));
            }
        }
        6 if packet.len() < 40 => return Err(anyhow!("MASQUE IPv6 packet is too short")),
        6 => {}
        version => return Err(anyhow!("MASQUE IP packet has unknown version {version}")),
    }
    Ok(())
}

fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in header.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]])
        } else {
            u16::from(chunk[0]) << 8
        };
        sum += u32::from(word);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn validate_masque_status(status: http::StatusCode) -> anyhow::Result<()> {
    if status.is_success() {
        Ok(())
    } else if status == http::StatusCode::UNAUTHORIZED
        || status == http::StatusCode::FORBIDDEN
        || status == http::StatusCode::PROXY_AUTHENTICATION_REQUIRED
    {
        Err(anyhow!("MASQUE authentication failed with status {status}"))
    } else {
        Err(anyhow!("MASQUE CONNECT failed with status {status}"))
    }
}

fn spawn_h3_l4_stream(
    stream: h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
) -> DuplexStream {
    let (app_side, relay_side) = tokio::io::duplex(DUPLEX_CAPACITY);
    let (mut local_read, mut local_write) = tokio::io::split(relay_side);
    let (mut send, mut recv) = stream.split();
    tokio::spawn(async move {
        let mut buffer = vec![0u8; RELAY_BUFFER_SIZE];
        loop {
            match local_read.read(&mut buffer).await {
                Ok(0) => {
                    let _ = send.finish().await;
                    return;
                }
                Ok(length)
                    if send
                        .send_data(Bytes::copy_from_slice(&buffer[..length]))
                        .await
                        .is_ok() => {}
                Ok(_) | Err(_) => return,
            }
        }
    });
    tokio::spawn(async move {
        loop {
            match recv.recv_data().await {
                Ok(Some(mut chunk)) => {
                    let bytes = chunk.copy_to_bytes(chunk.remaining());
                    if local_write.write_all(&bytes).await.is_err() {
                        return;
                    }
                }
                Ok(None) => {
                    let _ = local_write.shutdown().await;
                    return;
                }
                Err(_) => return,
            }
        }
    });
    app_side
}

#[cfg(test)]
mod tests {
    use std::{net::IpAddr, sync::Arc, time::Duration};

    use bytes::{Buf, Bytes};
    use rustls::{crypto::aws_lc_rs, server::WebPkiClientVerifier, RootCertStore, ServerConfig};
    use rustls_pki_types::{CertificateDer, PrivatePkcs8KeyDer};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use crate::{outbound::Outbound, routing::Destination};

    use super::*;

    const CLIENT_PRIVATE_KEY: &str = "MHcCAQEEIA1SUanhFrOFhmn22I0kWyaCACpbGxAAnAUiRAGfFC/VoAoGCCqGSM49AwEHoUQDQgAEI8HULAWSoCJNxmkV+MJMzOspO3c9UsL96KOuPZ+3VY47qxa/B7JG4xyFe/t1mW9xGc+UlSXInqYq9d9Tv6V2Ew==";

    #[test]
    fn decrements_ipv4_ttl_and_repairs_checksum() {
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&20u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 6;
        packet[12..16].copy_from_slice(&[10, 0, 0, 1]);
        packet[16..20].copy_from_slice(&[10, 0, 0, 2]);
        let packet = prepare_outgoing_ip_packet(packet, 1280).unwrap();
        assert_eq!(packet[8], 63);
        assert_eq!(ipv4_checksum(&packet), 0);
    }

    #[test]
    fn capsule_decoder_handles_fragmentation_and_unknown_capsules() {
        let mut decoder = CapsuleDecoder::default();
        decoder.buffer.extend_from_slice(&[0, 4, 1]);
        assert!(decoder.next_datagram().unwrap().is_none());
        decoder.buffer.extend_from_slice(&[2, 3, 4]);
        assert_eq!(decoder.next_datagram().unwrap().unwrap(), vec![1, 2, 3, 4]);
        decoder.buffer.extend_from_slice(&[7, 1, 9]);
        assert!(decoder.next_datagram().unwrap().unwrap().is_empty());
    }

    #[test]
    fn route_advertisement_covers_ipv4_and_ipv6() {
        let capsule = route_advertisement_capsule().unwrap();
        assert_eq!(capsule[0], 3);
        assert!(capsule.contains(&4));
        assert!(capsule.contains(&6));
    }

    #[tokio::test]
    async fn local_h3_l4_server_verifies_identity_pin_and_relays_tcp() {
        let (server_endpoint, server_address, public_key) = local_masque_quic_server();
        let server = tokio::spawn(async move {
            let connection = server_endpoint.accept().await.unwrap().await.unwrap();
            assert!(connection.peer_identity().is_some());
            let mut h3_connection: h3::server::Connection<h3_quinn::Connection, Bytes> =
                h3::server::builder()
                    .build(h3_quinn::Connection::new(connection))
                    .await
                    .unwrap();
            let resolver = h3_connection.accept().await.unwrap().unwrap();
            let (request, mut stream) = resolver.resolve_request().await.unwrap();
            assert_eq!(request.method(), http::Method::CONNECT);
            assert_eq!(
                request.uri().authority().unwrap().as_str(),
                "target.example:443"
            );
            stream
                .send_response(http::Response::builder().status(200).body(()).unwrap())
                .await
                .unwrap();
            let mut payload = Vec::new();
            while let Some(mut chunk) = timeout(Duration::from_secs(2), stream.recv_data())
                .await
                .expect("MASQUE L4 server did not receive DATA")
                .unwrap()
            {
                payload.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
                if payload.len() >= 4 {
                    break;
                }
            }
            assert_eq!(&payload, b"ping");
            stream.send_data(Bytes::from_static(b"pong")).await.unwrap();
            stream.finish().await.unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;
        });
        let outbound = test_masque_outbound(server_address, public_key, "h3-l4proxy", None, false);
        let mut stream = outbound
            .connect(&Destination::new("target.example", 443), 2_000)
            .await
            .unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut response = [0u8; 4];
        timeout(Duration::from_secs(2), stream.read_exact(&mut response))
            .await
            .expect("MASQUE L4 client did not receive DATA")
            .unwrap();
        assert_eq!(&response, b"pong");
        timeout(Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn rejects_server_with_a_different_pinned_public_key() {
        let (server_endpoint, server_address, _) = local_masque_quic_server();
        let server = tokio::spawn(async move {
            if let Some(incoming) = server_endpoint.accept().await {
                let _ = incoming.await;
            }
        });
        let wrong_key = KeyPair::generate().unwrap();
        let wrong_public_key = general_purpose::STANDARD.encode(wrong_key.public_key_der());
        let outbound =
            test_masque_outbound(server_address, wrong_public_key, "h3-l4proxy", None, false);
        let error = match outbound
            .connect(&Destination::new("target.example", 443), 2_000)
            .await
        {
            Ok(_) => panic!("a mismatched MASQUE public-key pin must fail the TLS handshake"),
            Err(error) => error,
        };
        assert!(
            format!("{error:#}").contains("public key pin mismatch"),
            "unexpected MASQUE pin error: {error:#}"
        );
        timeout(Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn local_h2_connect_ip_relays_tcp_and_udp_through_netstack() {
        let client_certificate = test_client_certificate();
        let (server_crypto, public_key) = local_masque_server_crypto(b"h2", client_certificate);
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let server_address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let local_networks = vec!["10.77.0.1/24".parse::<IpNet>().unwrap()];
            let (stack, packet_io) =
                IpStackRuntime::start(&local_networks, Vec::new(), false, 1_280)
                    .await
                    .unwrap();
            let tcp_listener = stack
                .tcp_listener("10.77.0.1:7000".parse().unwrap())
                .await
                .unwrap();
            let udp_socket = stack
                .bound_udp("10.77.0.1:7001".parse().unwrap())
                .await
                .unwrap();
            let tcp_echo = tokio::spawn(async move {
                let mut stream = tcp_listener.accept().await.unwrap();
                let mut request = [0u8; 4];
                stream.read_exact(&mut request).await.unwrap();
                assert_eq!(&request, b"ping");
                stream.write_all(b"pong").await.unwrap();
            });
            let udp_echo = tokio::spawn(async move {
                let (source, payload) =
                    timeout(Duration::from_secs(2), udp_socket.recv_from_bytes())
                        .await
                        .expect("MASQUE H2 server netstack did not receive UDP")
                        .unwrap();
                assert_eq!(payload.as_ref(), b"dns");
                udp_socket.send_to(source, &payload).await.unwrap();
                tokio::time::sleep(Duration::from_millis(100)).await;
            });

            let (socket, _) = listener.accept().await.unwrap();
            let tls = tokio_rustls::TlsAcceptor::from(Arc::new(server_crypto))
                .accept(socket)
                .await
                .unwrap();
            let mut h2 = h2::server::handshake(tls).await.unwrap();
            let (request, mut respond) = h2.accept().await.unwrap().unwrap();
            assert_eq!(request.method(), http::Method::CONNECT);
            assert_eq!(request.headers()["cf-connect-proto"], "cf-connect-ip");
            let recv_stream = request.into_body();
            let send_stream = respond
                .send_response(
                    http::Response::builder().status(200).body(()).unwrap(),
                    false,
                )
                .unwrap();
            let h2_driver = tokio::spawn(async move {
                while let Some(request) = h2.accept().await {
                    if request.is_err() {
                        break;
                    }
                }
            });
            let healthy = Arc::new(AtomicBool::new(true));
            let (send_task, receive_task) = spawn_h2_packet_relay(
                send_stream,
                recv_stream,
                packet_io,
                Arc::clone(&stack),
                healthy,
                1_280,
            );
            tcp_echo.await.unwrap();
            udp_echo.await.unwrap();
            send_task.abort();
            receive_task.abort();
            h2_driver.abort();
        });

        let outbound =
            test_masque_outbound(server_address, public_key, "h2", Some("10.77.0.2/24"), true);
        let mut stream = outbound
            .connect(&Destination::new("10.77.0.1", 7000), 3_000)
            .await
            .unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut response = [0u8; 4];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"pong");
        assert_eq!(
            outbound
                .udp_exchange(&Destination::new("10.77.0.1", 7001), b"dns", 3_000)
                .await
                .unwrap(),
            b"dns"
        );
        timeout(Duration::from_secs(3), server)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn local_h3_connect_ip_relays_tcp_and_udp_datagrams() {
        let (server_endpoint, server_address, public_key) = local_masque_quic_server();
        let server = tokio::spawn(async move {
            let local_networks = vec!["10.88.0.1/24".parse::<IpNet>().unwrap()];
            let (stack, packet_io) =
                IpStackRuntime::start(&local_networks, Vec::new(), false, 1_280)
                    .await
                    .unwrap();
            let tcp_listener = stack
                .tcp_listener("10.88.0.1:7100".parse().unwrap())
                .await
                .unwrap();
            let udp_socket = stack
                .bound_udp("10.88.0.1:7101".parse().unwrap())
                .await
                .unwrap();
            let tcp_echo = tokio::spawn(async move {
                let mut stream = tcp_listener.accept().await.unwrap();
                let mut request = [0u8; 4];
                stream.read_exact(&mut request).await.unwrap();
                assert_eq!(&request, b"ping");
                stream.write_all(b"pong").await.unwrap();
            });
            let udp_echo = tokio::spawn(async move {
                let (source, payload) =
                    timeout(Duration::from_secs(2), udp_socket.recv_from_bytes())
                        .await
                        .expect("MASQUE H3 server netstack did not receive UDP")
                        .unwrap();
                assert_eq!(payload.as_ref(), b"dns");
                udp_socket.send_to(source, &payload).await.unwrap();
                tokio::time::sleep(Duration::from_millis(100)).await;
            });

            let connection = server_endpoint.accept().await.unwrap().await.unwrap();
            assert!(connection.peer_identity().is_some());
            let mut builder = h3::server::builder();
            builder.enable_datagram(true).enable_extended_connect(true);
            let mut h3_connection: h3::server::Connection<h3_quinn::Connection, Bytes> = builder
                .build(h3_quinn::Connection::new(connection.clone()))
                .await
                .unwrap();
            let resolver = h3_connection.accept().await.unwrap().unwrap();
            let (request, mut stream) = resolver.resolve_request().await.unwrap();
            assert_eq!(request.method(), http::Method::CONNECT);
            assert_eq!(
                request.extensions().get::<h3::ext::Protocol>(),
                Some(&h3::ext::Protocol::CF_CONNECT_IP)
            );
            assert_eq!(request.headers()["capsule-protocol"], "?1");
            let flow_id = stream.id().index();
            stream
                .send_response(http::Response::builder().status(200).body(()).unwrap())
                .await
                .unwrap();
            let (send_half, recv_half) = stream.split();
            let hold_stream = tokio::spawn(async move {
                let _send_half = send_half;
                let _recv_half = recv_half;
                pending::<()>().await;
            });
            let h3_driver = tokio::spawn(async move {
                while let Ok(Some(resolver)) = h3_connection.accept().await {
                    if resolver.resolve_request().await.is_err() {
                        break;
                    }
                }
            });
            let healthy = Arc::new(AtomicBool::new(true));
            let (send_task, receive_task) = spawn_h3_packet_relay(
                connection,
                flow_id,
                packet_io,
                Arc::clone(&stack),
                healthy,
                1_280,
            );
            tcp_echo.await.unwrap();
            udp_echo.await.unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;
            send_task.abort();
            receive_task.abort();
            hold_stream.abort();
            h3_driver.abort();
        });

        let outbound = test_masque_outbound(
            server_address,
            public_key,
            "quic",
            Some("10.88.0.2/24"),
            true,
        );
        let mut stream = outbound
            .connect(&Destination::new("10.88.0.1", 7100), 3_000)
            .await
            .unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut response = [0u8; 4];
        timeout(Duration::from_secs(2), stream.read_exact(&mut response))
            .await
            .expect("MASQUE H3 client did not receive TCP response")
            .unwrap();
        assert_eq!(&response, b"pong");
        assert_eq!(
            outbound
                .udp_exchange(&Destination::new("10.88.0.1", 7101), b"dns", 3_000)
                .await
                .unwrap(),
            b"dns"
        );
        timeout(Duration::from_secs(3), server)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn local_h3_connect_udp_uses_rfc_uri_template_and_datagram_context() {
        let (server_endpoint, server_address, public_key) = local_masque_quic_server();
        let server = tokio::spawn(async move {
            let connection = server_endpoint.accept().await.unwrap().await.unwrap();
            assert!(connection.peer_identity().is_some());
            let mut builder = h3::server::builder();
            builder.enable_datagram(true).enable_extended_connect(true);
            let mut h3_connection: h3::server::Connection<h3_quinn::Connection, Bytes> = builder
                .build(h3_quinn::Connection::new(connection.clone()))
                .await
                .unwrap();
            let resolver = h3_connection.accept().await.unwrap().unwrap();
            let (request, mut stream) = resolver.resolve_request().await.unwrap();
            assert_eq!(request.method(), http::Method::CONNECT);
            assert_eq!(
                request.extensions().get::<h3::ext::Protocol>(),
                Some(&h3::ext::Protocol::CONNECT_UDP)
            );
            assert_eq!(
                request.uri().path(),
                "/.well-known/masque/udp/target.example/5353/"
            );
            assert_eq!(request.headers()["capsule-protocol"], "?1");
            let flow_id = stream.id().index();
            stream
                .send_response(http::Response::builder().status(200).body(()).unwrap())
                .await
                .unwrap();
            let (send_half, recv_half) = stream.split();
            let hold_stream = tokio::spawn(async move {
                let _send_half = send_half;
                let _recv_half = recv_half;
                pending::<()>().await;
            });
            let h3_driver = tokio::spawn(async move {
                while let Ok(Some(resolver)) = h3_connection.accept().await {
                    if resolver.resolve_request().await.is_err() {
                        break;
                    }
                }
            });
            let datagram = timeout(Duration::from_secs(2), connection.read_datagram())
                .await
                .expect("MASQUE CONNECT-UDP server did not receive a datagram")
                .unwrap();
            let mut cursor = 0;
            assert_eq!(
                read_quic_varint_from_slice(&datagram, &mut cursor).unwrap(),
                flow_id
            );
            assert_eq!(
                read_quic_varint_from_slice(&datagram, &mut cursor).unwrap(),
                0
            );
            assert_eq!(&datagram[cursor..], b"dns");
            connection.send_datagram_wait(datagram).await.unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;
            hold_stream.abort();
            h3_driver.abort();
        });

        let outbound =
            test_masque_outbound(server_address, public_key, "h3-connect-udp", None, true);
        let capability = outbound.capability();
        assert!(!capability.tcp_supported);
        assert!(capability.udp_supported);
        assert_eq!(
            capability.udp_mode.as_deref(),
            Some("masque-h3-connect-udp")
        );
        assert_eq!(
            outbound
                .udp_exchange(&Destination::new("target.example", 5353), b"dns", 3_000)
                .await
                .unwrap(),
            b"dns"
        );
        timeout(Duration::from_secs(3), server)
            .await
            .unwrap()
            .unwrap();
    }

    fn test_masque_outbound(
        address: SocketAddr,
        public_key: String,
        network: &str,
        ip: Option<&str>,
        udp: bool,
    ) -> MasqueOutbound {
        MasqueOutbound::new(
            "masque-local".to_string(),
            address.ip().to_string(),
            address.port(),
            CLIENT_PRIVATE_KEY.to_string(),
            public_key,
            ip.map(ToString::to_string),
            None,
            None,
            Some("localhost".to_string()),
            Some(1_280),
            udp,
            Some(3_000),
            false,
            Some(network.to_string()),
            Some("bbr".to_string()),
            Some(16),
            Some("standard".to_string()),
            false,
            Vec::new(),
        )
    }

    fn test_client_certificate() -> CertificateDer<'static> {
        let private_key = general_purpose::STANDARD
            .decode(CLIENT_PRIVATE_KEY)
            .unwrap();
        build_masque_client_identity(private_key).unwrap().0
    }

    fn local_masque_server_crypto(
        alpn: &[u8],
        client_certificate: CertificateDer<'static>,
    ) -> (ServerConfig, String) {
        let _ = aws_lc_rs::default_provider().install_default();
        let key_pair = KeyPair::generate().unwrap();
        let public_key = general_purpose::STANDARD.encode(key_pair.public_key_der());
        let certificate = CertificateParams::new(vec!["localhost".to_string()])
            .unwrap()
            .self_signed(&key_pair)
            .unwrap();
        let certificate = CertificateDer::from(certificate.der().to_vec());
        let private_key = PrivatePkcs8KeyDer::from(key_pair.serialize_der());
        let mut client_roots = RootCertStore::empty();
        client_roots.add(client_certificate).unwrap();
        let client_verifier = WebPkiClientVerifier::builder(Arc::new(client_roots))
            .build()
            .unwrap();
        let provider = aws_lc_rs::default_provider();
        let mut server_crypto = ServerConfig::builder_with_provider(provider.into())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(vec![certificate], private_key.into())
            .unwrap();
        server_crypto.alpn_protocols = vec![alpn.to_vec()];
        (server_crypto, public_key)
    }

    fn local_masque_quic_server() -> (quinn::Endpoint, SocketAddr, String) {
        let (server_crypto, public_key) =
            local_masque_server_crypto(b"h3", test_client_certificate());
        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto).unwrap(),
        ));
        let mut transport = quinn::TransportConfig::default();
        transport.datagram_receive_buffer_size(Some(1024 * 1024));
        transport.datagram_send_buffer_size(1024 * 1024);
        server_config.transport_config(Arc::new(transport));
        let endpoint = quinn::Endpoint::server(
            server_config,
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 0),
        )
        .unwrap();
        let address = endpoint.local_addr().unwrap();
        (endpoint, address, public_key)
    }
}
