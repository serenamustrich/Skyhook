use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm,
};
use anyhow::{anyhow, Context};
use async_trait::async_trait;
use hkdf::Hkdf;
use rustls::{
    client::{DangerousClientHelloSessionIdProvider, Resumption},
    crypto::{aws_lc_rs, ActiveKeyExchange, SharedSecret, SupportedKxGroup},
    ffdhe_groups::FfdheGroup,
    ClientConfig, Error as RustlsError, NamedGroup, ProtocolVersion, RootCertStore,
};
use rustls_pki_types::ServerName;
use sha2::Sha256;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    sync::Mutex as TokioMutex,
    time::timeout,
};
use tokio_rustls::TlsConnector;
use uuid::Uuid;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

use crate::routing::Destination;

use super::{
    transports::{
        connect_tcp, open_grpc_tunnel, open_h2_tunnel, open_websocket_transport_without_headers,
        run_dial_phase, tls_client_config, NoCertificateVerification,
    },
    udp::{udp_session_key, KeyedRoundRobinSessionPool, UDP_SESSION_POOL_SIZE},
    BoxedStream, Outbound, OutboundCapability,
};

pub(super) struct VlessOutbound {
    name: String,
    server: String,
    port: u16,
    uuid: String,
    flow: Option<String>,
    security: Option<String>,
    tls: bool,
    sni: Option<String>,
    skip_cert_verify: bool,
    network: Option<String>,
    ws_path: Option<String>,
    ws_host: Option<String>,
    grpc_service_name: Option<String>,
    reality_public_key: Option<String>,
    reality_short_id: Option<String>,
    reality_fingerprint: Option<String>,
    reality_spider_x: Option<String>,
    udp_sessions: TokioMutex<KeyedRoundRobinSessionPool<VlessUdpSession>>,
}

struct VlessUdpSession {
    stream: BoxedStream,
    response_header_read: bool,
}

#[async_trait]
impl Outbound for VlessOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "vless"
    }

    fn capability(&self) -> OutboundCapability {
        if self
            .security
            .as_deref()
            .is_some_and(|value| value.eq_ignore_ascii_case("reality"))
            && self
                .reality_public_key
                .as_deref()
                .unwrap_or_default()
                .trim()
                .is_empty()
        {
            OutboundCapability::unsupported("VLESS Reality public key is required")
        } else {
            OutboundCapability::tcp_udp("vless-command-udp-session-pool")
        }
    }

    fn supports_udp_dialer_proxy(&self) -> bool {
        true
    }

    async fn connect(
        &self,
        destination: &Destination,
        timeout_ms: u64,
    ) -> anyhow::Result<BoxedStream> {
        let user_id = Uuid::parse_str(&self.uuid)
            .map_err(|error| anyhow!("invalid vless uuid for {}: {error}", self.name))?;
        let network = self
            .network
            .as_deref()
            .unwrap_or("tcp")
            .to_ascii_lowercase();
        if !matches!(
            network.as_str(),
            "tcp" | "ws" | "websocket" | "grpc" | "h2" | "http"
        ) {
            return Err(anyhow!("unsupported vless network {network}"));
        }
        let security = self
            .security
            .as_deref()
            .unwrap_or(if self.tls { "tls" } else { "none" })
            .to_ascii_lowercase();
        if !matches!(security.as_str(), "tls" | "none" | "" | "reality") {
            return Err(anyhow!("unsupported vless security {security}"));
        }
        let flow = self
            .flow
            .as_deref()
            .map(str::trim)
            .filter(|flow| !flow.is_empty());
        if let Some(flow) = flow {
            if flow != "xtls-rprx-vision" {
                return Err(anyhow!("unsupported vless flow {flow}"));
            }
            if (!self.tls && security != "reality") || network != "tcp" {
                return Err(anyhow!(
                    "vless flow {flow} requires tls/reality over tcp transport"
                ));
            }
        }
        let request = build_vless_request_with_flow(&user_id, destination, flow)?;
        let mut stream = self.open_transport(&network, timeout_ms).await?;
        stream.write_all(&request).await?;
        read_vless_response_header(&mut stream).await?;
        Ok(stream)
    }

    async fn udp_exchange(
        &self,
        destination: &Destination,
        payload: &[u8],
        timeout_ms: u64,
    ) -> anyhow::Result<Vec<u8>> {
        let user_id = Uuid::parse_str(&self.uuid)
            .map_err(|error| anyhow!("invalid vless uuid for {}: {error}", self.name))?;
        let network = self.network_name()?;
        let security = self.security_name();
        if !matches!(security.as_str(), "tls" | "none" | "" | "reality") {
            return Err(anyhow!("unsupported vless security {security}"));
        }
        if self
            .flow
            .as_deref()
            .map(str::trim)
            .filter(|flow| !flow.is_empty())
            .is_some()
        {
            return Err(anyhow!("vless udp does not support xtls flow addons"));
        }

        let packet = encode_length_prefixed_packet(payload, "vless udp")?;
        let session_handle = self
            .vless_udp_session(&user_id, destination, &network, timeout_ms)
            .await?;
        let exchange = {
            let mut session = session_handle.lock().await;
            timeout(Duration::from_millis(timeout_ms), async {
                session.stream.write_all(&packet).await?;
                session.stream.flush().await?;
                if !session.response_header_read {
                    read_vless_response_header(&mut session.stream).await?;
                    session.response_header_read = true;
                }
                read_length_prefixed_packet(&mut session.stream, "vless udp").await
            })
            .await
            .context("vless udp exchange timed out")?
        };
        if exchange.is_err() {
            self.remove_vless_udp_session(destination, &session_handle)
                .await;
        }
        exchange
    }
}

impl VlessOutbound {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        name: String,
        server: String,
        port: u16,
        uuid: String,
        flow: Option<String>,
        security: Option<String>,
        tls: bool,
        sni: Option<String>,
        skip_cert_verify: bool,
        network: Option<String>,
        ws_path: Option<String>,
        ws_host: Option<String>,
        grpc_service_name: Option<String>,
        reality_public_key: Option<String>,
        reality_short_id: Option<String>,
        reality_fingerprint: Option<String>,
        reality_spider_x: Option<String>,
    ) -> Self {
        Self {
            name,
            server,
            port,
            uuid,
            flow,
            security,
            tls,
            sni,
            skip_cert_verify,
            network,
            ws_path,
            ws_host,
            grpc_service_name,
            reality_public_key,
            reality_short_id,
            reality_fingerprint,
            reality_spider_x,
            udp_sessions: TokioMutex::new(KeyedRoundRobinSessionPool::default()),
        }
    }

    fn network_name(&self) -> anyhow::Result<String> {
        let network = self
            .network
            .as_deref()
            .unwrap_or("tcp")
            .to_ascii_lowercase();
        if !matches!(
            network.as_str(),
            "tcp" | "ws" | "websocket" | "grpc" | "h2" | "http"
        ) {
            return Err(anyhow!("unsupported vless network {network}"));
        }
        Ok(network)
    }

    fn security_name(&self) -> String {
        self.security
            .as_deref()
            .unwrap_or(if self.tls { "tls" } else { "none" })
            .to_ascii_lowercase()
    }

    async fn open_transport(&self, network: &str, timeout_ms: u64) -> anyhow::Result<BoxedStream> {
        let tcp = connect_tcp(&format!("{}:{}", self.server, self.port), timeout_ms).await?;
        let security = self.security_name();
        let tls_enabled = self.tls || security == "reality";
        if security == "reality" && matches!(network, "ws" | "websocket") {
            return Err(anyhow!(
                "vless reality does not support websocket transport"
            ));
        }
        if tls_enabled {
            let server_name = self.sni.as_deref().unwrap_or(&self.server).to_string();
            let mut tls_config = if security == "reality" {
                reality_tls_client_config(
                    self.skip_cert_verify,
                    self.reality_public_key.as_deref(),
                    self.reality_short_id.as_deref(),
                    self.reality_fingerprint.as_deref(),
                    self.reality_spider_x.as_deref(),
                )?
            } else {
                tls_client_config(self.skip_cert_verify)?
            };
            if matches!(network, "grpc" | "h2" | "http") {
                tls_config.alpn_protocols = vec![b"h2".to_vec()];
            }
            let connector = TlsConnector::from(Arc::new(tls_config));
            let tls_server_name = ServerName::try_from(server_name.clone())
                .map_err(|error| anyhow!("invalid vless server name: {error}"))?;
            let stream = run_dial_phase(
                timeout_ms,
                "vless tls handshake",
                connector.connect(tls_server_name, tcp),
            )
            .await?
            .context("vless tls handshake failed")?;
            if network == "ws" || network == "websocket" {
                return open_websocket_transport_without_headers(
                    stream,
                    self.ws_host.as_deref().unwrap_or(&server_name),
                    self.ws_path.as_deref().unwrap_or("/"),
                    timeout_ms,
                )
                .await;
            }
            if network == "grpc" {
                return open_grpc_tunnel(
                    stream,
                    self.ws_host.as_deref().unwrap_or(&server_name),
                    self.grpc_service_name.as_deref(),
                    timeout_ms,
                )
                .await
                .map(|stream| Box::new(stream) as BoxedStream);
            }
            if matches!(network, "h2" | "http") {
                return open_h2_tunnel(
                    stream,
                    self.ws_host.as_deref().unwrap_or(&server_name),
                    self.ws_path.as_deref().unwrap_or("/"),
                    timeout_ms,
                )
                .await
                .map(|stream| Box::new(stream) as BoxedStream);
            }
            Ok(Box::new(stream))
        } else {
            let stream = tcp;
            if network == "ws" || network == "websocket" {
                return open_websocket_transport_without_headers(
                    stream,
                    self.ws_host.as_deref().unwrap_or(&self.server),
                    self.ws_path.as_deref().unwrap_or("/"),
                    timeout_ms,
                )
                .await;
            }
            if network == "grpc" {
                return open_grpc_tunnel(
                    stream,
                    self.ws_host.as_deref().unwrap_or(&self.server),
                    self.grpc_service_name.as_deref(),
                    timeout_ms,
                )
                .await
                .map(|stream| Box::new(stream) as BoxedStream);
            }
            if matches!(network, "h2" | "http") {
                return open_h2_tunnel(
                    stream,
                    self.ws_host.as_deref().unwrap_or(&self.server),
                    self.ws_path.as_deref().unwrap_or("/"),
                    timeout_ms,
                )
                .await
                .map(|stream| Box::new(stream) as BoxedStream);
            }
            Ok(Box::new(stream))
        }
    }

    async fn vless_udp_session(
        &self,
        user_id: &Uuid,
        destination: &Destination,
        network: &str,
        timeout_ms: u64,
    ) -> anyhow::Result<Arc<TokioMutex<VlessUdpSession>>> {
        let key = udp_session_key(
            self.kind(),
            self.name(),
            self.udp_nat_mode(),
            Some(destination),
        );
        let mut pool = self.udp_sessions.lock().await;
        if pool.len(&key) < UDP_SESSION_POOL_SIZE {
            let session = Arc::new(TokioMutex::new(
                self.open_vless_udp_session(user_id, destination, network, timeout_ms)
                    .await?,
            ));
            pool.push(key, Arc::clone(&session));
            return Ok(session);
        }
        pool.next(&key)
            .ok_or_else(|| anyhow!("vless UDP session pool is unexpectedly empty"))
    }

    async fn open_vless_udp_session(
        &self,
        user_id: &Uuid,
        destination: &Destination,
        network: &str,
        timeout_ms: u64,
    ) -> anyhow::Result<VlessUdpSession> {
        let mut stream = self.open_transport(network, timeout_ms).await?;
        let request =
            build_vless_request_with_command_and_flow(user_id, destination, None, VLESS_CMD_UDP)?;
        timeout(Duration::from_millis(timeout_ms), async {
            stream.write_all(&request).await?;
            stream.flush().await
        })
        .await
        .context("vless udp session setup timed out")??;
        Ok(VlessUdpSession {
            stream,
            response_header_read: false,
        })
    }

    async fn remove_vless_udp_session(
        &self,
        destination: &Destination,
        target: &Arc<TokioMutex<VlessUdpSession>>,
    ) {
        let mut pool = self.udp_sessions.lock().await;
        let key = udp_session_key(
            self.kind(),
            self.name(),
            self.udp_nat_mode(),
            Some(destination),
        );
        pool.remove(&key, target);
    }
}

fn reality_tls_client_config(
    skip_cert_verify: bool,
    public_key: Option<&str>,
    short_id: Option<&str>,
    fingerprint: Option<&str>,
    spider_x: Option<&str>,
) -> anyhow::Result<ClientConfig> {
    let public_key = public_key.ok_or_else(|| anyhow!("vless reality public key is required"))?;
    validate_reality_fingerprint(fingerprint)?;
    validate_reality_spider_x(spider_x)?;
    let mut provider = aws_lc_rs::default_provider();
    provider.kx_groups = vec![&REALITY_X25519_KX_GROUP];
    let builder = ClientConfig::builder_with_provider(provider.into())
        .with_protocol_versions(&[&rustls::version::TLS13])?;
    let mut config = if skip_cert_verify {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
            .with_no_client_auth()
    } else {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        builder.with_root_certificates(roots).with_no_client_auth()
    };
    config.alpn_protocols.clear();
    config.resumption = Resumption::disabled();
    config
        .dangerous()
        .set_client_hello_session_id_provider(Arc::new(RealitySessionIdProvider {
            public_key: decode_reality_public_key(public_key)?.to_bytes(),
            short_id: decode_reality_short_id(short_id)?,
        }));
    Ok(config)
}

const VLESS_CMD_TCP: u8 = 0x01;
const VLESS_CMD_UDP: u8 = 0x02;

#[cfg(test)]
pub(super) fn build_vless_request(
    user_id: &Uuid,
    destination: &Destination,
) -> anyhow::Result<Vec<u8>> {
    build_vless_request_with_flow(user_id, destination, None)
}

pub(super) fn build_vless_request_with_flow(
    user_id: &Uuid,
    destination: &Destination,
    flow: Option<&str>,
) -> anyhow::Result<Vec<u8>> {
    build_vless_request_with_command_and_flow(user_id, destination, flow, VLESS_CMD_TCP)
}

fn build_vless_request_with_command_and_flow(
    user_id: &Uuid,
    destination: &Destination,
    flow: Option<&str>,
    command: u8,
) -> anyhow::Result<Vec<u8>> {
    let mut request = Vec::with_capacity(32 + destination.host.len());
    request.push(0x00);
    request.extend_from_slice(user_id.as_bytes());
    let addons = encode_vless_addons(flow)?;
    if addons.len() > u8::MAX as usize {
        return Err(anyhow!("vless addons are too large"));
    }
    request.push(addons.len() as u8);
    request.extend_from_slice(&addons);
    request.push(command);
    encode_vless_destination(destination, &mut request)?;
    Ok(request)
}

fn encode_length_prefixed_packet(payload: &[u8], context: &str) -> anyhow::Result<Vec<u8>> {
    if payload.len() > u16::MAX as usize {
        return Err(anyhow!("{context} payload is too large"));
    }
    let mut packet = Vec::with_capacity(2 + payload.len());
    packet.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    packet.extend_from_slice(payload);
    Ok(packet)
}

async fn read_length_prefixed_packet<R>(reader: &mut R, context: &str) -> anyhow::Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut length = [0u8; 2];
    reader
        .read_exact(&mut length)
        .await
        .with_context(|| format!("failed to read {context} packet length"))?;
    let payload_len = u16::from_be_bytes(length) as usize;
    let mut payload = vec![0u8; payload_len];
    reader
        .read_exact(&mut payload)
        .await
        .with_context(|| format!("failed to read {context} packet payload"))?;
    Ok(payload)
}

fn encode_vless_addons(flow: Option<&str>) -> anyhow::Result<Vec<u8>> {
    let Some(flow) = flow.map(str::trim).filter(|flow| !flow.is_empty()) else {
        return Ok(Vec::new());
    };
    if flow != "xtls-rprx-vision" {
        return Err(anyhow!("unsupported vless flow {flow}"));
    }
    let mut output = Vec::with_capacity(flow.len() + 2);
    output.push(0x0a);
    encode_protobuf_varint(flow.len() as u64, &mut output);
    output.extend_from_slice(flow.as_bytes());
    Ok(output)
}

fn encode_protobuf_varint(mut value: u64, output: &mut Vec<u8>) {
    while value >= 0x80 {
        output.push((value as u8) | 0x80);
        value >>= 7;
    }
    output.push(value as u8);
}

fn encode_vless_destination(destination: &Destination, output: &mut Vec<u8>) -> anyhow::Result<()> {
    output.extend_from_slice(&destination.port.to_be_bytes());
    if let Ok(addr) = destination.host.parse::<SocketAddr>() {
        match addr {
            SocketAddr::V4(v4) => {
                output.push(0x01);
                output.extend_from_slice(&v4.ip().octets());
            }
            SocketAddr::V6(v6) => {
                output.push(0x03);
                output.extend_from_slice(&v6.ip().octets());
            }
        }
    } else if let Ok(ip) = destination.host.parse::<std::net::IpAddr>() {
        match ip {
            std::net::IpAddr::V4(ip) => {
                output.push(0x01);
                output.extend_from_slice(&ip.octets());
            }
            std::net::IpAddr::V6(ip) => {
                output.push(0x03);
                output.extend_from_slice(&ip.octets());
            }
        }
    } else {
        if destination.host.len() > 255 {
            return Err(anyhow!("domain name too long"));
        }
        output.push(0x02);
        output.push(destination.host.len() as u8);
        output.extend_from_slice(destination.host.as_bytes());
    }
    Ok(())
}

pub(super) const REALITY_CLIENT_VERSION: [u8; 3] = [1, 8, 24];
static REALITY_X25519_KX_GROUP: RealityX25519KxGroup = RealityX25519KxGroup;

#[derive(Debug)]
struct RealityX25519KxGroup;

impl SupportedKxGroup for RealityX25519KxGroup {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, RustlsError> {
        let secret = X25519StaticSecret::random();
        let public = X25519PublicKey::from(&secret).to_bytes();
        Ok(Box::new(RealityX25519KeyExchange { secret, public }))
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::X25519
    }

    fn usable_for_version(&self, version: ProtocolVersion) -> bool {
        version == ProtocolVersion::TLSv1_3
    }
}

struct RealityX25519KeyExchange {
    secret: X25519StaticSecret,
    public: [u8; 32],
}

impl ActiveKeyExchange for RealityX25519KeyExchange {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, RustlsError> {
        reality_x25519_shared_secret(&self.secret, peer_pub_key)
    }

    fn dangerous_shared_secret_for_client_hello(
        &self,
        peer_pub_key: &[u8],
    ) -> Option<Result<SharedSecret, RustlsError>> {
        Some(reality_x25519_shared_secret(&self.secret, peer_pub_key))
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519
    }

    fn pub_key(&self) -> &[u8] {
        &self.public
    }
}

fn reality_x25519_shared_secret(
    secret: &X25519StaticSecret,
    peer_pub_key: &[u8],
) -> Result<SharedSecret, RustlsError> {
    let peer_pub_key: [u8; 32] = peer_pub_key
        .try_into()
        .map_err(|_| RustlsError::General("invalid X25519 peer key share".into()))?;
    let peer = X25519PublicKey::from(peer_pub_key);
    Ok(SharedSecret::from(
        secret.diffie_hellman(&peer).as_bytes().as_slice(),
    ))
}

#[derive(Debug)]
struct RealitySessionIdProvider {
    public_key: [u8; 32],
    short_id: Vec<u8>,
}

impl DangerousClientHelloSessionIdProvider for RealitySessionIdProvider {
    fn plaintext_session_id(&self) -> [u8; 32] {
        let unix_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs().min(u32::MAX as u64) as u32)
            .unwrap_or(0);
        let mut session_id = [0u8; 32];
        session_id[..3].copy_from_slice(&REALITY_CLIENT_VERSION);
        session_id[3] = 0;
        session_id[4..8].copy_from_slice(&unix_time.to_be_bytes());
        session_id[8..8 + self.short_id.len()].copy_from_slice(&self.short_id);
        session_id
    }

    fn seal_session_id(
        &self,
        client_hello_random: &[u8; 32],
        client_hello_raw: &[u8],
        key_exchange: &dyn ActiveKeyExchange,
    ) -> Result<[u8; 32], RustlsError> {
        let shared_secret = key_exchange
            .dangerous_shared_secret_for_client_hello(&self.public_key)
            .ok_or_else(|| {
                RustlsError::General("Reality X25519 shared secret is not available".into())
            })??;
        seal_reality_session_id_from_client_hello(
            shared_secret.secret_bytes(),
            client_hello_random,
            client_hello_raw,
        )
        .map_err(|error| RustlsError::General(format!("Reality session id failed: {error}")))
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct RealityClientHelloMaterial {
    session_id: [u8; 32],
    auth_key: [u8; 32],
    client_public_key: [u8; 32],
    unix_time: u32,
}

#[allow(dead_code)]
fn build_reality_client_hello_material(
    public_key: &str,
    short_id: Option<&str>,
    hello_random: &[u8; 32],
    hello_raw: &[u8],
) -> anyhow::Result<RealityClientHelloMaterial> {
    let server_public_key = decode_reality_public_key(public_key)?;
    let short_id = decode_reality_short_id(short_id)?;
    let client_secret = X25519StaticSecret::random();
    let client_public_key = X25519PublicKey::from(&client_secret).to_bytes();
    let shared_secret = client_secret.diffie_hellman(&server_public_key);
    let unix_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before unix epoch")?
        .as_secs()
        .min(u32::MAX as u64) as u32;
    let (session_id, auth_key) = seal_reality_session_id(
        shared_secret.as_bytes(),
        &short_id,
        hello_random,
        hello_raw,
        unix_time,
    )?;
    Ok(RealityClientHelloMaterial {
        session_id,
        auth_key,
        client_public_key,
        unix_time,
    })
}

fn seal_reality_session_id_from_client_hello(
    shared_secret: &[u8],
    hello_random: &[u8; 32],
    hello_raw: &[u8],
) -> anyhow::Result<[u8; 32]> {
    if shared_secret.len() != 32 {
        return Err(anyhow!("vless reality shared secret must be 32 bytes"));
    }
    if hello_raw.len() < 55 {
        return Err(anyhow!("vless reality ClientHello is too short"));
    }
    let mut shared = [0u8; 32];
    shared.copy_from_slice(shared_secret);
    let mut auth_key = [0u8; 32];
    Hkdf::<Sha256>::new(Some(&hello_random[..20]), &shared)
        .expand(b"REALITY", &mut auth_key)
        .map_err(|_| anyhow!("failed to derive vless reality auth key"))?;

    let cipher = Aes256Gcm::new_from_slice(&auth_key)
        .map_err(|_| anyhow!("failed to initialize vless reality aead"))?;
    let encrypted = cipher
        .encrypt(
            aes_gcm::Nonce::from_slice(&hello_random[20..]),
            aes_gcm::aead::Payload {
                msg: &hello_raw[39..55],
                aad: hello_raw,
            },
        )
        .map_err(|_| anyhow!("failed to seal vless reality session id"))?;
    encrypted
        .try_into()
        .map_err(|_| anyhow!("vless reality sealed session id has invalid length"))
}

pub(super) fn decode_reality_public_key(value: &str) -> anyhow::Result<X25519PublicKey> {
    let value = value.trim();
    if value.is_empty() {
        return Err(anyhow!("vless reality public key is empty"));
    }
    let bytes = base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, value)
        .or_else(|_| base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE, value))
        .or_else(|_| base64::Engine::decode(&base64::engine::general_purpose::STANDARD, value))
        .map_err(|error| anyhow!("invalid vless reality public key: {error}"))?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow!("vless reality public key must decode to 32 bytes"))?;
    Ok(X25519PublicKey::from(bytes))
}

pub(super) fn decode_reality_short_id(value: Option<&str>) -> anyhow::Result<Vec<u8>> {
    let value = value.map(str::trim).unwrap_or("");
    if value.is_empty() {
        return Ok(Vec::new());
    }
    if value.len() > 16 {
        return Err(anyhow!("vless reality short_id cannot exceed 8 bytes"));
    }
    if value.len() % 2 != 0 {
        return Err(anyhow!(
            "vless reality short_id must be hex with even length"
        ));
    }
    let mut output = Vec::with_capacity(value.len() / 2);
    let bytes = value.as_bytes();
    for index in (0..bytes.len()).step_by(2) {
        let high = decode_hex_nibble(bytes[index])
            .ok_or_else(|| anyhow!("vless reality short_id contains non-hex character"))?;
        let low = decode_hex_nibble(bytes[index + 1])
            .ok_or_else(|| anyhow!("vless reality short_id contains non-hex character"))?;
        output.push((high << 4) | low);
    }
    Ok(output)
}

fn validate_reality_fingerprint(value: Option<&str>) -> anyhow::Result<()> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(());
    };
    let supported = matches!(
        value.to_ascii_lowercase().as_str(),
        "chrome"
            | "firefox"
            | "safari"
            | "ios"
            | "android"
            | "edge"
            | "qq"
            | "random"
            | "randomized"
    );
    if supported {
        Ok(())
    } else {
        Err(anyhow!("unsupported vless reality fingerprint {value}"))
    }
}

fn validate_reality_spider_x(value: Option<&str>) -> anyhow::Result<()> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(());
    };
    if value.starts_with('/') {
        Ok(())
    } else {
        Err(anyhow!("vless reality spider_x must start with /"))
    }
}

fn decode_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[allow(dead_code)]
pub(super) fn seal_reality_session_id(
    shared_secret: &[u8; 32],
    short_id: &[u8],
    hello_random: &[u8; 32],
    hello_raw: &[u8],
    unix_time: u32,
) -> anyhow::Result<([u8; 32], [u8; 32])> {
    if short_id.len() > 8 {
        return Err(anyhow!("vless reality short_id cannot exceed 8 bytes"));
    }
    let mut auth_key = [0u8; 32];
    Hkdf::<Sha256>::new(Some(&hello_random[..20]), shared_secret)
        .expand(b"REALITY", &mut auth_key)
        .map_err(|_| anyhow!("failed to derive vless reality auth key"))?;

    let mut plaintext = [0u8; 16];
    plaintext[..3].copy_from_slice(&REALITY_CLIENT_VERSION);
    plaintext[3] = 0;
    plaintext[4..8].copy_from_slice(&unix_time.to_be_bytes());
    plaintext[8..8 + short_id.len()].copy_from_slice(short_id);

    let cipher = Aes256Gcm::new_from_slice(&auth_key)
        .map_err(|_| anyhow!("failed to initialize vless reality aead"))?;
    let encrypted = cipher
        .encrypt(
            aes_gcm::Nonce::from_slice(&hello_random[20..]),
            aes_gcm::aead::Payload {
                msg: &plaintext,
                aad: hello_raw,
            },
        )
        .map_err(|_| anyhow!("failed to seal vless reality session id"))?;
    let session_id: [u8; 32] = encrypted
        .try_into()
        .map_err(|_| anyhow!("vless reality sealed session id has invalid length"))?;
    Ok((session_id, auth_key))
}

async fn read_vless_response_header<R>(reader: &mut R) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; 2];
    reader.read_exact(&mut header).await?;
    if header[0] != 0x00 {
        return Err(anyhow!("unsupported vless response version {}", header[0]));
    }
    if header[1] > 0 {
        let mut addon = vec![0u8; header[1] as usize];
        reader.read_exact(&mut addon).await?;
    }
    Ok(())
}
