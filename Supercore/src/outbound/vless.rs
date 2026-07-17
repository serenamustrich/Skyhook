use std::{
    collections::BTreeMap,
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex as StdMutex,
    },
    time::{SystemTime, UNIX_EPOCH},
};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm,
};
use anyhow::{anyhow, Context};
use async_trait::async_trait;
use hkdf::Hkdf;
use rustls::{
    client::{
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        DangerousClientHelloSessionIdProvider, Resumption, WebPkiServerVerifier,
    },
    crypto::{aws_lc_rs, ActiveKeyExchange, SharedSecret, SupportedKxGroup},
    ffdhe_groups::FfdheGroup,
    CipherSuite, ClientConfig, DigitallySignedStruct, Error as RustlsError, NamedGroup,
    ProtocolVersion, RootCertStore, SignatureScheme,
};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use sha2::{Digest, Sha256, Sha512};
use subtle::ConstantTimeEq;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    sync::Mutex as TokioMutex,
};
use tokio_rustls::TlsConnector;
use uuid::Uuid;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::routing::Destination;

use super::{
    transports::{
        connect_tcp, open_grpc_tunnel, open_h2_tunnel, open_http_camouflage_transport,
        open_http_upgrade_tunnel, open_websocket_transport, run_dial_phase, tls_client_config,
    },
    udp::{udp_session_key, KeyedRoundRobinSessionPool, UDP_SESSION_POOL_SIZE},
    vless_vision::VlessVisionTransport,
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
    transport_headers: BTreeMap<String, String>,
    alpn: Vec<String>,
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

struct VlessTlsConfiguration {
    config: ClientConfig,
    reality_verified: Option<Arc<AtomicBool>>,
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
        match self.validated_configuration() {
            Ok(_) => OutboundCapability::tcp_udp("vless-command-udp-session-pool"),
            Err(error) => OutboundCapability::unsupported(error.to_string()),
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
        let (user_id, network, security, flow) = self.validated_configuration()?;
        let request = build_vless_request_with_flow(&user_id, destination, flow.as_deref())?;
        if flow.as_deref() == Some("xtls-rprx-vision") {
            return self
                .connect_vision(user_id, &security, &request, timeout_ms)
                .await;
        }
        let stream = self.open_transport(&network, &security, timeout_ms).await?;
        let mut stream = self
            .establish_vless_request(stream, &network, &request, timeout_ms)
            .await?;
        run_dial_phase(
            timeout_ms,
            "vless response header",
            read_vless_response_header(&mut stream),
        )
        .await??;
        Ok(stream)
    }

    async fn udp_exchange(
        &self,
        destination: &Destination,
        payload: &[u8],
        timeout_ms: u64,
    ) -> anyhow::Result<Vec<u8>> {
        if payload.len() > VLESS_MAX_UDP_PAYLOAD {
            return Err(anyhow!(
                "vless udp payload is too large: {} bytes exceeds {}",
                payload.len(),
                VLESS_MAX_UDP_PAYLOAD
            ));
        }
        let (user_id, network, security, flow) = self.validated_configuration()?;
        if flow.is_some() {
            return Err(anyhow!("vless udp does not support xtls flow addons"));
        }

        let packet = encode_length_prefixed_packet(payload, "vless udp")?;
        let session_handle = self
            .vless_udp_session(&user_id, destination, &network, &security, timeout_ms)
            .await?;
        let mut session = session_handle.lock().await;
        let exchange = {
            run_dial_phase(timeout_ms, "vless udp exchange", async {
                session.stream.write_all(&packet).await?;
                session.stream.flush().await?;
                if !session.response_header_read {
                    read_vless_response_header(&mut session.stream).await?;
                    session.response_header_read = true;
                }
                read_length_prefixed_packet(&mut session.stream, "vless udp").await
            })
            .await
        };
        let failed = !matches!(&exchange, Ok(Ok(_)));
        if failed {
            drop(session);
            self.remove_vless_udp_session(destination, &session_handle)
                .await;
        }
        exchange?
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
        transport_headers: BTreeMap<String, String>,
        alpn: Vec<String>,
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
            transport_headers,
            alpn,
            reality_public_key,
            reality_short_id,
            reality_fingerprint,
            reality_spider_x,
            udp_sessions: TokioMutex::new(KeyedRoundRobinSessionPool::default()),
        }
    }

    fn validated_configuration(&self) -> anyhow::Result<(Uuid, String, String, Option<String>)> {
        let user_id = Uuid::parse_str(self.uuid.trim())
            .map_err(|error| anyhow!("invalid vless uuid: {error}"))?;
        let network = normalized_vless_network(self.network.as_deref());
        if network == "xhttp" {
            return Err(anyhow!(
                "vless xhttp transport is not implemented; use tcp, ws, grpc, h2, http, or httpupgrade"
            ));
        }
        if !matches!(
            network.as_str(),
            "tcp" | "ws" | "grpc" | "h2" | "http" | "httpupgrade"
        ) {
            return Err(anyhow!("unsupported vless network {network}"));
        }
        let security = normalized_vless_security(self.security.as_deref(), self.tls);
        if !matches!(security.as_str(), "tls" | "none" | "reality") {
            return Err(anyhow!("unsupported vless security {security}"));
        }
        let flow = self
            .flow
            .as_deref()
            .map(str::trim)
            .filter(|flow| !flow.is_empty())
            .map(str::to_ascii_lowercase);
        if let Some(flow) = flow.as_deref() {
            if flow != "xtls-rprx-vision" {
                return Err(anyhow!("unsupported vless flow {flow}"));
            }
            if security == "none" || network != "tcp" {
                return Err(anyhow!(
                    "vless flow {flow} requires tls/reality over tcp transport"
                ));
            }
        }
        if security == "reality" {
            let public_key = self
                .reality_public_key
                .as_deref()
                .ok_or_else(|| anyhow!("vless reality public key is required"))?;
            decode_reality_public_key(public_key)?;
            decode_reality_short_id(self.reality_short_id.as_deref())?;
            validate_reality_fingerprint(self.reality_fingerprint.as_deref())?;
            validate_reality_spider_x(self.reality_spider_x.as_deref())?;
            if network == "ws" {
                return Err(anyhow!(
                    "vless reality does not support websocket transport"
                ));
            }
        }
        vless_alpn_protocols(&network, &self.alpn)?;
        Ok((user_id, network, security, flow))
    }

    async fn open_transport(
        &self,
        network: &str,
        security: &str,
        timeout_ms: u64,
    ) -> anyhow::Result<BoxedStream> {
        let tcp = connect_tcp(&format!("{}:{}", self.server, self.port), timeout_ms).await?;
        let tls_enabled = security != "none";
        if tls_enabled {
            let server_name = nonempty_or(self.sni.as_deref(), &self.server).to_string();
            let tls_config = self.tls_configuration(network, security)?;
            let reality_verified = tls_config.reality_verified;
            let connector = TlsConnector::from(Arc::new(tls_config.config));
            let tls_server_name = ServerName::try_from(server_name.clone())
                .map_err(|error| anyhow!("invalid vless server name: {error}"))?;
            let stream = run_dial_phase(
                timeout_ms,
                "vless tls handshake",
                connector.connect(tls_server_name, tcp),
            )
            .await?
            .context("vless tls handshake failed")?;
            ensure_reality_authenticated(reality_verified.as_ref())?;
            if network == "ws" {
                return open_websocket_transport(
                    stream,
                    nonempty_or(self.ws_host.as_deref(), &server_name),
                    self.ws_path.as_deref().unwrap_or("/"),
                    &self.transport_headers,
                    timeout_ms,
                )
                .await;
            }
            if network == "grpc" {
                return open_grpc_tunnel(
                    stream,
                    nonempty_or(self.ws_host.as_deref(), &server_name),
                    self.grpc_service_name.as_deref(),
                    timeout_ms,
                )
                .await
                .map(|stream| Box::new(stream) as BoxedStream);
            }
            if network == "h2" {
                return open_h2_tunnel(
                    stream,
                    nonempty_or(self.ws_host.as_deref(), &server_name),
                    self.ws_path.as_deref().unwrap_or("/"),
                    timeout_ms,
                )
                .await
                .map(|stream| Box::new(stream) as BoxedStream);
            }
            if network == "httpupgrade" {
                return open_http_upgrade_tunnel(
                    stream,
                    nonempty_or(self.ws_host.as_deref(), &server_name),
                    self.ws_path.as_deref().unwrap_or("/"),
                    &self.transport_headers,
                    timeout_ms,
                )
                .await
                .map(|stream| Box::new(stream) as BoxedStream);
            }
            Ok(Box::new(stream))
        } else {
            let stream = tcp;
            if network == "ws" {
                return open_websocket_transport(
                    stream,
                    nonempty_or(self.ws_host.as_deref(), &self.server),
                    self.ws_path.as_deref().unwrap_or("/"),
                    &self.transport_headers,
                    timeout_ms,
                )
                .await;
            }
            if network == "grpc" {
                return open_grpc_tunnel(
                    stream,
                    nonempty_or(self.ws_host.as_deref(), &self.server),
                    self.grpc_service_name.as_deref(),
                    timeout_ms,
                )
                .await
                .map(|stream| Box::new(stream) as BoxedStream);
            }
            if network == "h2" {
                return open_h2_tunnel(
                    stream,
                    nonempty_or(self.ws_host.as_deref(), &self.server),
                    self.ws_path.as_deref().unwrap_or("/"),
                    timeout_ms,
                )
                .await
                .map(|stream| Box::new(stream) as BoxedStream);
            }
            if network == "httpupgrade" {
                return open_http_upgrade_tunnel(
                    stream,
                    nonempty_or(self.ws_host.as_deref(), &self.server),
                    self.ws_path.as_deref().unwrap_or("/"),
                    &self.transport_headers,
                    timeout_ms,
                )
                .await
                .map(|stream| Box::new(stream) as BoxedStream);
            }
            Ok(Box::new(stream))
        }
    }

    fn tls_configuration(
        &self,
        network: &str,
        security: &str,
    ) -> anyhow::Result<VlessTlsConfiguration> {
        let (mut config, reality_verified) = if security == "reality" {
            let (config, verified) = reality_tls_client_config(
                self.skip_cert_verify,
                self.reality_public_key.as_deref(),
                self.reality_short_id.as_deref(),
                self.reality_fingerprint.as_deref(),
                self.reality_spider_x.as_deref(),
            )?;
            (config, Some(verified))
        } else {
            (tls_client_config(self.skip_cert_verify)?, None)
        };
        config.alpn_protocols = if security == "reality"
            && network == "tcp"
            && self.alpn.iter().all(|value| value.trim().is_empty())
        {
            reality_fingerprint_alpn(self.reality_fingerprint.as_deref())?
        } else {
            vless_alpn_protocols(network, &self.alpn)?
        };
        Ok(VlessTlsConfiguration {
            config,
            reality_verified,
        })
    }

    async fn connect_vision(
        &self,
        user_id: Uuid,
        security: &str,
        request: &[u8],
        timeout_ms: u64,
    ) -> anyhow::Result<BoxedStream> {
        let tcp = connect_tcp(&format!("{}:{}", self.server, self.port), timeout_ms).await?;
        let server_name = nonempty_or(self.sni.as_deref(), &self.server).to_string();
        let tls_server_name = ServerName::try_from(server_name)
            .map_err(|error| anyhow!("invalid vless server name: {error}"))?;
        let tls_config = self.tls_configuration("tcp", security)?;
        let reality_verified = tls_config.reality_verified;
        let mut transport =
            VlessVisionTransport::open(tcp, tls_config.config, tls_server_name, timeout_ms).await?;
        ensure_reality_authenticated(reality_verified.as_ref())?;
        run_dial_phase(timeout_ms, "vless vision request write", async {
            transport.tls_mut().write_all(request).await?;
            transport.tls_mut().flush().await
        })
        .await??;
        run_dial_phase(
            timeout_ms,
            "vless vision response header",
            read_vless_response_header(transport.tls_mut()),
        )
        .await??;
        Ok(Box::new(transport.into_stream(user_id)))
    }

    async fn establish_vless_request(
        &self,
        mut stream: BoxedStream,
        network: &str,
        request: &[u8],
        timeout_ms: u64,
    ) -> anyhow::Result<BoxedStream> {
        if network == "http" {
            let stream = open_http_camouflage_transport(
                stream,
                nonempty_or(self.ws_host.as_deref(), &self.server),
                self.ws_path.as_deref().unwrap_or("/"),
                &self.transport_headers,
                request,
                timeout_ms,
            )
            .await?;
            return Ok(Box::new(stream));
        }
        run_dial_phase(timeout_ms, "vless request write", async {
            stream.write_all(request).await?;
            stream.flush().await
        })
        .await??;
        Ok(stream)
    }

    async fn vless_udp_session(
        &self,
        user_id: &Uuid,
        destination: &Destination,
        network: &str,
        security: &str,
        timeout_ms: u64,
    ) -> anyhow::Result<Arc<TokioMutex<VlessUdpSession>>> {
        let key = udp_session_key(
            self.kind(),
            self.name(),
            self.udp_nat_mode(),
            Some(destination),
        );
        {
            let mut pool = self.udp_sessions.lock().await;
            let session_count = pool.len(&key);
            if let Some(session) = pool.next(&key) {
                let available = session.try_lock().is_ok();
                if available || session_count >= UDP_SESSION_POOL_SIZE {
                    return Ok(session);
                }
            }
        }

        let session = Arc::new(TokioMutex::new(
            self.open_vless_udp_session(user_id, destination, network, security, timeout_ms)
                .await?,
        ));
        let mut pool = self.udp_sessions.lock().await;
        if pool.len(&key) < UDP_SESSION_POOL_SIZE {
            pool.push(key.clone(), Arc::clone(&session));
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
        security: &str,
        timeout_ms: u64,
    ) -> anyhow::Result<VlessUdpSession> {
        let stream = self.open_transport(network, security, timeout_ms).await?;
        let request =
            build_vless_request_with_command_and_flow(user_id, destination, None, VLESS_CMD_UDP)?;
        let stream = self
            .establish_vless_request(stream, network, &request, timeout_ms)
            .await?;
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

fn nonempty_or<'a>(value: Option<&'a str>, fallback: &'a str) -> &'a str {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(fallback)
}

fn normalized_vless_network(network: Option<&str>) -> String {
    match network
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("tcp")
        .to_ascii_lowercase()
        .as_str()
    {
        "websocket" => "ws".to_string(),
        "http-upgrade" => "httpupgrade".to_string(),
        network => network.to_string(),
    }
}

fn normalized_vless_security(security: Option<&str>, tls: bool) -> String {
    security
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(if tls { "tls" } else { "none" })
        .to_ascii_lowercase()
}

fn vless_alpn_protocols(network: &str, configured: &[String]) -> anyhow::Result<Vec<Vec<u8>>> {
    let mut protocols = Vec::new();
    for value in configured {
        for protocol in value
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            if !protocol.is_ascii() || protocol.len() > u8::MAX as usize {
                return Err(anyhow!("invalid vless ALPN value {protocol:?}"));
            }
            if !protocols
                .iter()
                .any(|existing: &Vec<u8>| existing.as_slice() == protocol.as_bytes())
            {
                protocols.push(protocol.as_bytes().to_vec());
            }
        }
    }
    if protocols.is_empty() {
        return Ok(match network {
            "grpc" | "h2" => vec![b"h2".to_vec()],
            "ws" | "http" | "httpupgrade" => vec![b"http/1.1".to_vec()],
            _ => Vec::new(),
        });
    }
    if matches!(network, "grpc" | "h2") && !protocols.iter().any(|value| value.as_slice() == b"h2")
    {
        return Err(anyhow!("vless {network} transport requires h2 in ALPN"));
    }
    if matches!(network, "ws" | "http" | "httpupgrade")
        && !protocols
            .iter()
            .any(|value| value.as_slice() == b"http/1.1")
    {
        return Err(anyhow!(
            "vless {network} transport requires http/1.1 in ALPN"
        ));
    }
    Ok(protocols)
}

fn reality_tls_client_config(
    skip_cert_verify: bool,
    public_key: Option<&str>,
    short_id: Option<&str>,
    fingerprint: Option<&str>,
    spider_x: Option<&str>,
) -> anyhow::Result<(ClientConfig, Arc<AtomicBool>)> {
    let public_key = public_key.ok_or_else(|| anyhow!("vless reality public key is required"))?;
    validate_reality_fingerprint(fingerprint)?;
    validate_reality_spider_x(spider_x)?;
    let mut provider = aws_lc_rs::default_provider();
    apply_reality_fingerprint(&mut provider.cipher_suites, fingerprint)?;
    provider.kx_groups = vec![&REALITY_X25519_KX_GROUP];
    let provider = Arc::new(provider);
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let fallback =
        WebPkiServerVerifier::builder_with_provider(Arc::new(roots), Arc::clone(&provider))
            .build()
            .context("failed to build vless reality certificate verifier")?;
    let auth_key = Arc::new(StdMutex::new(None));
    let verified = Arc::new(AtomicBool::new(false));
    let verifier = Arc::new(RealityServerVerifier {
        auth_key: Arc::clone(&auth_key),
        verified: Arc::clone(&verified),
        fallback,
        accept_invalid_fallback: skip_cert_verify,
    });
    let builder = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?;
    let mut config = builder
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    config.alpn_protocols.clear();
    config.resumption = Resumption::disabled();
    config
        .dangerous()
        .set_client_hello_session_id_provider(Arc::new(RealitySessionIdProvider {
            public_key: decode_reality_public_key(public_key)?.to_bytes(),
            short_id: decode_reality_short_id(short_id)?,
            auth_key,
        }));
    Ok((config, verified))
}

fn ensure_reality_authenticated(verified: Option<&Arc<AtomicBool>>) -> anyhow::Result<()> {
    if verified.is_some_and(|verified| !verified.load(Ordering::Acquire)) {
        return Err(anyhow!(
            "vless reality authentication failed: server certificate was not authenticated"
        ));
    }
    Ok(())
}

#[derive(Debug)]
struct RealityServerVerifier {
    auth_key: Arc<StdMutex<Option<[u8; 32]>>>,
    verified: Arc<AtomicBool>,
    fallback: Arc<WebPkiServerVerifier>,
    accept_invalid_fallback: bool,
}

impl RealityServerVerifier {
    fn verify_reality_certificate(&self, end_entity: &CertificateDer<'_>) -> bool {
        let Ok(auth_key) = self.auth_key.lock() else {
            return false;
        };
        let Some(auth_key) = auth_key.as_ref() else {
            return false;
        };
        let Ok((remaining, certificate)) = X509Certificate::from_der(end_entity.as_ref()) else {
            return false;
        };
        if !remaining.is_empty() {
            return false;
        }
        let public_key = certificate.public_key().subject_public_key.data.as_ref();
        let signature = certificate.signature_value.data.as_ref();
        if public_key.len() != 32 || signature.len() != 64 {
            return false;
        }
        let expected = reality_hmac_sha512(auth_key, public_key);
        bool::from(expected.as_slice().ct_eq(signature))
    }
}

impl ServerCertVerifier for RealityServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        if self.verify_reality_certificate(end_entity) {
            self.verified.store(true, Ordering::Release);
            return Ok(ServerCertVerified::assertion());
        }
        if self.accept_invalid_fallback {
            return Ok(ServerCertVerified::assertion());
        }
        self.fallback
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        self.fallback.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        self.fallback.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.fallback.supported_verify_schemes()
    }
}

#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn reality_hmac_sha512(key: &[u8], input: &[u8]) -> [u8; 64] {
    const BLOCK_SIZE: usize = 128;
    let mut normalized = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        normalized[..64].copy_from_slice(&Sha512::digest(key));
    } else {
        normalized[..key.len()].copy_from_slice(key);
    }
    let mut inner_pad = [0x36u8; BLOCK_SIZE];
    let mut outer_pad = [0x5cu8; BLOCK_SIZE];
    for index in 0..BLOCK_SIZE {
        inner_pad[index] ^= normalized[index];
        outer_pad[index] ^= normalized[index];
    }
    let mut inner = Sha512::new();
    inner.update(inner_pad);
    inner.update(input);
    let inner_hash = inner.finalize();
    let mut outer = Sha512::new();
    outer.update(outer_pad);
    outer.update(inner_hash);
    outer.finalize().into()
}

const VLESS_CMD_TCP: u8 = 0x01;
const VLESS_CMD_UDP: u8 = 0x02;
const VLESS_MAX_UDP_PAYLOAD: usize = 8192;

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

pub(super) const REALITY_CLIENT_VERSION: [u8; 3] = [1, 8, 2];
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
    auth_key: Arc<StdMutex<Option<[u8; 32]>>>,
}

impl DangerousClientHelloSessionIdProvider for RealitySessionIdProvider {
    fn plaintext_session_id(&self) -> [u8; 32] {
        [0u8; 32]
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
        let unix_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| RustlsError::General("system clock is before unix epoch".into()))?
            .as_secs()
            .min(u32::MAX as u64) as u32;
        let shared_secret: [u8; 32] = shared_secret
            .secret_bytes()
            .try_into()
            .map_err(|_| RustlsError::General("Reality shared secret has invalid length".into()))?;
        let (session_id, auth_key) = seal_reality_session_id(
            &shared_secret,
            &self.short_id,
            client_hello_random,
            client_hello_raw,
            unix_time,
        )
        .map_err(|error| RustlsError::General(format!("Reality session id failed: {error}")))?;
        *self
            .auth_key
            .lock()
            .map_err(|_| RustlsError::General("Reality auth key lock is poisoned".into()))? =
            Some(auth_key);
        Ok(session_id)
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

#[derive(Clone, Copy)]
enum RealityFingerprintProfile {
    Native,
    Chrome,
    Firefox,
    Safari,
    Android,
    Edge,
    Qq,
    Random,
    Randomized,
}

fn reality_fingerprint_profile(value: Option<&str>) -> anyhow::Result<RealityFingerprintProfile> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(RealityFingerprintProfile::Native);
    };
    match value.to_ascii_lowercase().as_str() {
        "chrome" => Ok(RealityFingerprintProfile::Chrome),
        "firefox" => Ok(RealityFingerprintProfile::Firefox),
        "safari" | "ios" => Ok(RealityFingerprintProfile::Safari),
        "android" => Ok(RealityFingerprintProfile::Android),
        "edge" => Ok(RealityFingerprintProfile::Edge),
        "qq" => Ok(RealityFingerprintProfile::Qq),
        "random" => Ok(RealityFingerprintProfile::Random),
        "randomized" => Ok(RealityFingerprintProfile::Randomized),
        _ => Err(anyhow!("unsupported vless reality fingerprint {value}")),
    }
}

fn validate_reality_fingerprint(value: Option<&str>) -> anyhow::Result<()> {
    reality_fingerprint_profile(value).map(|_| ())
}

fn resolve_random_reality_profile() -> anyhow::Result<RealityFingerprintProfile> {
    let mut random = [0u8; 1];
    getrandom::fill(&mut random)
        .map_err(|error| anyhow!("Reality fingerprint randomness failed: {error}"))?;
    Ok(match random[0] % 4 {
        0 => RealityFingerprintProfile::Chrome,
        1 => RealityFingerprintProfile::Firefox,
        2 => RealityFingerprintProfile::Safari,
        _ => RealityFingerprintProfile::Android,
    })
}

fn apply_reality_fingerprint(
    cipher_suites: &mut [rustls::SupportedCipherSuite],
    value: Option<&str>,
) -> anyhow::Result<()> {
    let mut profile = reality_fingerprint_profile(value)?;
    if matches!(profile, RealityFingerprintProfile::Random) {
        profile = resolve_random_reality_profile()?;
    }
    if matches!(profile, RealityFingerprintProfile::Randomized) {
        for upper in (1..cipher_suites.len()).rev() {
            let mut random = [0u8; 8];
            getrandom::fill(&mut random)
                .map_err(|error| anyhow!("Reality fingerprint randomness failed: {error}"))?;
            let index = (u64::from_be_bytes(random) as usize) % (upper + 1);
            cipher_suites.swap(upper, index);
        }
        return Ok(());
    }
    cipher_suites.sort_by_key(|suite| {
        let suite = suite.suite();
        match profile {
            RealityFingerprintProfile::Firefox | RealityFingerprintProfile::Android => {
                match suite {
                    CipherSuite::TLS13_AES_128_GCM_SHA256 => 0,
                    CipherSuite::TLS13_CHACHA20_POLY1305_SHA256 => 1,
                    CipherSuite::TLS13_AES_256_GCM_SHA384 => 2,
                    _ => 100,
                }
            }
            RealityFingerprintProfile::Native => 0,
            _ => match suite {
                CipherSuite::TLS13_AES_128_GCM_SHA256 => 0,
                CipherSuite::TLS13_AES_256_GCM_SHA384 => 1,
                CipherSuite::TLS13_CHACHA20_POLY1305_SHA256 => 2,
                _ => 100,
            },
        }
    });
    Ok(())
}

fn reality_fingerprint_alpn(value: Option<&str>) -> anyhow::Result<Vec<Vec<u8>>> {
    let profile = reality_fingerprint_profile(value)?;
    if matches!(profile, RealityFingerprintProfile::Native) {
        Ok(Vec::new())
    } else {
        Ok(vec![b"h2".to_vec(), b"http/1.1".to_vec()])
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
