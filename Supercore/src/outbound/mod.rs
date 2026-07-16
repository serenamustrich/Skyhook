use std::{
    collections::{BTreeMap, HashMap},
    io::{Error, ErrorKind, IoSliceMut},
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex as StdMutex},
    task::{Context as TaskContext, Poll},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use aes::cipher::{BlockEncrypt, KeyInit as BlockKeyInit};
use aes::Aes128;
use aes_gcm::{aead::Aead, Aes128Gcm, Aes256Gcm};
use anyhow::{anyhow, Context};
use async_trait::async_trait;
use blake2::{digest::VariableOutput, Blake2bVar};
use bytes::Bytes;
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use ipnet::IpNet;
use md5::{Digest, Md5};
use russh::{client as ssh_client, ChannelMsg, Disconnect};
use rustls::{
    client::{DangerousClientHelloSessionIdProvider, Resumption},
    crypto::{aws_lc_rs, ActiveKeyExchange, SharedSecret, SupportedKxGroup},
    ffdhe_groups::FfdheGroup,
    ClientConfig, Error as RustlsError, NamedGroup, ProtocolVersion, RootCertStore,
};
use rustls_pki_types::ServerName;
use sha2::{Sha224, Sha256};
use sha3::{
    digest::{ExtendableOutput, XofReader},
    Shake128,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf},
    net::lookup_host,
    sync::Mutex as TokioMutex,
    task::JoinHandle,
    time::timeout,
};
use tokio_rustls::TlsConnector;
use uuid::Uuid;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

use crate::{config::OutboundConfig, routing::Destination, telemetry::Telemetry};

mod anytls;
pub mod context;
mod direct;
pub mod error;
mod factory;
mod group;
mod http_proxy;
mod io;
mod naive;
mod pool;
mod registry;
mod reject;
mod shadowsocks;
mod shadowtls;
mod snell;
mod socks5;
mod ssh;
mod ssr;
mod target;
mod traits;
mod transports;
mod udp;
mod unsupported;
mod wireguard;

use anytls::AnyTlsOutbound;
use direct::DirectOutbound;
use http_proxy::HttpOutbound;
use io::read_exact_or_eof;
use naive::NaiveOutbound;
use pool::IdlePool;
use registry::{attach_groups, insert_leaf};
use reject::RejectOutbound;
use shadowsocks::ShadowsocksOutbound;
use shadowtls::ShadowTlsOutbound;
use snell::SnellOutbound;
use socks5::Socks5Outbound;
use ssh::SshOutbound;
use ssr::SsrOutbound;
use target::{parse_socks5_destination_prefix, read_socks5_destination_after_atyp};
use transports::{
    connect_tcp, open_grpc_tunnel, open_h2_tunnel, open_http_upgrade_tunnel,
    perform_websocket_handshake, perform_websocket_handshake_with_headers, quic_client_config,
    spawn_websocket_stream, tls_client_config, NoCertificateVerification,
};
use udp::{resolve_udp_socket_addr, RoundRobinSessionPool};
use unsupported::UnsupportedProtocolOutbound;
use wireguard::WireGuardOutbound;

pub use factory::build_outbounds;
pub use target::encode_socks5_destination;
pub use traits::{BoxedStream, Outbound, OutboundCapability, OutboundMap, ProxyStream};

#[cfg(test)]
use self::{
    context::DialContext,
    error::{OutboundError, OutboundErrorKind},
};

#[cfg(test)]
use std::io::Cursor;

#[cfg(test)]
use bytes::BytesMut;

#[cfg(test)]
use crate::config::ShadowsocksPluginConfig;

#[cfg(test)]
use group::GroupOutbound;

#[cfg(test)]
use shadowsocks::{
    encode_ss_chunk, evp_bytes_to_key, find_header_end, read_simple_obfs_tls_record, read_ss_chunk,
    write_ss_chunk, Ss2022ReplayWindow, SsCipher, SIMPLE_OBFS_TLS_FIXED_CLIENT_HELLO_LEN,
    SIMPLE_OBFS_TLS_SESSION_TICKET_HEADER_LEN, SS_NONCE_LEN,
};

#[cfg(test)]
use transports::{
    read_websocket_frame, render_transport_headers, websocket_accept_key,
    write_websocket_binary_frame, write_websocket_frame,
};

const UDP_SESSION_POOL_SIZE: usize = 4;

struct TrojanOutbound {
    name: String,
    server: String,
    port: u16,
    password: String,
    sni: Option<String>,
    skip_cert_verify: bool,
    network: Option<String>,
    ws_path: Option<String>,
    ws_host: Option<String>,
    grpc_service_name: Option<String>,
    transport_headers: BTreeMap<String, String>,
    alpn: Vec<String>,
    udp_sessions: TokioMutex<TrojanUdpPool>,
}

type TrojanUdpPool = RoundRobinSessionPool<TrojanUdpSession>;

struct TrojanUdpSession {
    stream: BoxedStream,
}

struct VmessOutbound {
    name: String,
    server: String,
    port: u16,
    uuid: String,
    cipher: String,
    tls: bool,
    sni: Option<String>,
    skip_cert_verify: bool,
    network: Option<String>,
    ws_path: Option<String>,
    ws_host: Option<String>,
    grpc_service_name: Option<String>,
    udp_sessions: TokioMutex<VmessUdpPool>,
}

struct VlessOutbound {
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
    udp_sessions: TokioMutex<VlessUdpPool>,
}

#[derive(Default)]
struct VmessUdpPool {
    buckets: HashMap<String, UdpSessionBucket<VmessUdpSession>>,
}

#[derive(Default)]
struct VlessUdpPool {
    buckets: HashMap<String, UdpSessionBucket<VlessUdpSession>>,
}

struct UdpSessionBucket<T> {
    sessions: Vec<Arc<TokioMutex<T>>>,
    next_index: usize,
}

impl<T> Default for UdpSessionBucket<T> {
    fn default() -> Self {
        Self {
            sessions: Vec::new(),
            next_index: 0,
        }
    }
}

struct VmessUdpSession {
    stream: BoxedStream,
    upload: VmessUploadState,
    download: VmessDownloadState,
    response_header_read: bool,
}

struct VlessUdpSession {
    stream: BoxedStream,
    response_header_read: bool,
}

struct Hysteria2Outbound {
    name: String,
    server: String,
    port: u16,
    password: String,
    sni: Option<String>,
    skip_cert_verify: bool,
    obfs: Option<String>,
    obfs_password: Option<String>,
    alpn: Option<String>,
    udp_sessions: TokioMutex<Hysteria2UdpPool>,
}

type Hysteria2UdpPool = RoundRobinSessionPool<Hysteria2UdpSession>;

struct Hysteria2UdpSession {
    _endpoint: quinn::Endpoint,
    connection: quinn::Connection,
    h3_driver: JoinHandle<()>,
    session_id: u32,
    next_packet_id: u16,
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

impl Drop for Hysteria2UdpSession {
    fn drop(&mut self) {
        self.connection
            .close(quinn::VarInt::from_u32(0), b"supercore close");
        self.h3_driver.abort();
    }
}

struct TuicOutbound {
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
    udp_sessions: TokioMutex<TuicUdpPool>,
}

#[derive(Default)]
struct TuicUdpPool {
    mode: Option<String>,
    sessions: RoundRobinSessionPool<TuicUdpSession>,
}

struct TuicUdpSession {
    _endpoint: quinn::Endpoint,
    connection: quinn::Connection,
    mode: String,
    associate_id: u16,
    next_packet_id: u16,
}

impl Drop for TuicUdpSession {
    fn drop(&mut self) {
        self.connection
            .close(quinn::VarInt::from_u32(0), b"supercore close");
    }
}

#[async_trait]
impl Outbound for VmessOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "vmess"
    }

    fn capability(&self) -> OutboundCapability {
        OutboundCapability::tcp_udp("vmess-command-udp-session-pool")
    }

    async fn connect(
        &self,
        destination: &Destination,
        timeout_ms: u64,
    ) -> anyhow::Result<BoxedStream> {
        let user_id = Uuid::parse_str(&self.uuid)
            .map_err(|error| anyhow!("invalid vmess uuid for {}: {error}", self.name))?;
        let cipher = VmessCipher::from_name(&self.cipher)?;
        let stream = self.open_transport(timeout_ms).await?;
        setup_vmess_stream(stream, &user_id, cipher, destination).await
    }

    async fn udp_exchange(
        &self,
        destination: &Destination,
        payload: &[u8],
        timeout_ms: u64,
    ) -> anyhow::Result<Vec<u8>> {
        let session_handle = self.vmess_udp_session(destination, timeout_ms).await?;
        let exchange = {
            let mut session = session_handle.lock().await;
            let VmessUdpSession {
                stream,
                upload,
                download,
                response_header_read,
            } = &mut *session;
            timeout(Duration::from_millis(timeout_ms), async {
                write_vmess_chunk(stream, upload, payload).await?;
                if !*response_header_read {
                    read_vmess_response_header(stream, download).await?;
                    *response_header_read = true;
                }
                read_vmess_chunk(stream, download)
                    .await?
                    .ok_or_else(|| anyhow!("vmess udp response ended before payload"))
            })
            .await
            .context("vmess udp exchange timed out")?
        };
        if exchange.is_err() {
            self.remove_vmess_udp_session(destination, &session_handle)
                .await;
        }
        exchange
    }
}

impl VmessOutbound {
    async fn open_transport(&self, timeout_ms: u64) -> anyhow::Result<BoxedStream> {
        let network = self
            .network
            .as_deref()
            .unwrap_or("tcp")
            .to_ascii_lowercase();
        if !matches!(
            network.as_str(),
            "tcp" | "ws" | "websocket" | "grpc" | "h2" | "http"
        ) {
            return Err(anyhow!("unsupported vmess network {network}"));
        }
        let tcp = connect_tcp(&format!("{}:{}", self.server, self.port), timeout_ms).await?;

        if self.tls {
            let server_name = self.sni.as_deref().unwrap_or(&self.server).to_string();
            let mut tls_config = tls_client_config(self.skip_cert_verify)?;
            if matches!(network.as_str(), "grpc" | "h2" | "http") {
                tls_config.alpn_protocols = vec![b"h2".to_vec()];
            }
            let connector = TlsConnector::from(Arc::new(tls_config));
            let tls_server_name = ServerName::try_from(server_name.clone())
                .map_err(|error| anyhow!("invalid vmess server name: {error}"))?;
            let mut stream = timeout(
                Duration::from_millis(timeout_ms),
                connector.connect(tls_server_name, tcp),
            )
            .await
            .context("vmess tls handshake timed out")?
            .context("vmess tls handshake failed")?;
            if network == "ws" || network == "websocket" {
                perform_websocket_handshake(
                    &mut stream,
                    self.ws_host.as_deref().unwrap_or(&server_name),
                    self.ws_path.as_deref().unwrap_or("/"),
                )
                .await?;
                return Ok(Box::new(spawn_websocket_stream(stream)));
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
            if matches!(network.as_str(), "h2" | "http") {
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
            let mut stream = tcp;
            if network == "ws" || network == "websocket" {
                perform_websocket_handshake(
                    &mut stream,
                    self.ws_host.as_deref().unwrap_or(&self.server),
                    self.ws_path.as_deref().unwrap_or("/"),
                )
                .await?;
                return Ok(Box::new(spawn_websocket_stream(stream)));
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
            if matches!(network.as_str(), "h2" | "http") {
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

    async fn vmess_udp_session(
        &self,
        destination: &Destination,
        timeout_ms: u64,
    ) -> anyhow::Result<Arc<TokioMutex<VmessUdpSession>>> {
        let key = destination.authority();
        let mut pool = self.udp_sessions.lock().await;
        let bucket = pool.buckets.entry(key.clone()).or_default();
        if bucket.sessions.len() < UDP_SESSION_POOL_SIZE {
            let session = Arc::new(TokioMutex::new(
                self.open_vmess_udp_session(destination, timeout_ms).await?,
            ));
            bucket.sessions.push(session.clone());
            bucket.next_index = bucket.sessions.len() % UDP_SESSION_POOL_SIZE;
            return Ok(session);
        }
        let index = bucket.next_index % bucket.sessions.len();
        bucket.next_index = (bucket.next_index + 1) % bucket.sessions.len();
        Ok(bucket.sessions[index].clone())
    }

    async fn open_vmess_udp_session(
        &self,
        destination: &Destination,
        timeout_ms: u64,
    ) -> anyhow::Result<VmessUdpSession> {
        let user_id = Uuid::parse_str(&self.uuid)
            .map_err(|error| anyhow!("invalid vmess uuid for {}: {error}", self.name))?;
        let cipher = VmessCipher::from_name(&self.cipher)?;
        let mut stream = self.open_transport(timeout_ms).await?;
        let setup = build_vmess_setup_with_command(&user_id, cipher, destination, VMESS_CMD_UDP)?;
        timeout(Duration::from_millis(timeout_ms), async {
            stream.write_all(&setup.request).await?;
            stream.flush().await
        })
        .await
        .context("vmess udp session setup timed out")??;
        Ok(VmessUdpSession {
            stream,
            upload: setup.upload,
            download: setup.download,
            response_header_read: false,
        })
    }

    async fn remove_vmess_udp_session(
        &self,
        destination: &Destination,
        target: &Arc<TokioMutex<VmessUdpSession>>,
    ) {
        let mut pool = self.udp_sessions.lock().await;
        let key = destination.authority();
        let Some(bucket) = pool.buckets.get_mut(&key) else {
            return;
        };
        bucket
            .sessions
            .retain(|session| !Arc::ptr_eq(session, target));
        if !bucket.sessions.is_empty() {
            bucket.next_index %= bucket.sessions.len();
        } else {
            pool.buckets.remove(&key);
        }
    }
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
            let mut stream = timeout(
                Duration::from_millis(timeout_ms),
                connector.connect(tls_server_name, tcp),
            )
            .await
            .context("vless tls handshake timed out")?
            .context("vless tls handshake failed")?;
            if network == "ws" || network == "websocket" {
                perform_websocket_handshake(
                    &mut stream,
                    self.ws_host.as_deref().unwrap_or(&server_name),
                    self.ws_path.as_deref().unwrap_or("/"),
                )
                .await?;
                return Ok(Box::new(spawn_websocket_stream(stream)));
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
            let mut stream = tcp;
            if network == "ws" || network == "websocket" {
                perform_websocket_handshake(
                    &mut stream,
                    self.ws_host.as_deref().unwrap_or(&self.server),
                    self.ws_path.as_deref().unwrap_or("/"),
                )
                .await?;
                return Ok(Box::new(spawn_websocket_stream(stream)));
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
        let key = destination.authority();
        let mut pool = self.udp_sessions.lock().await;
        let bucket = pool.buckets.entry(key.clone()).or_default();
        if bucket.sessions.len() < UDP_SESSION_POOL_SIZE {
            let session = Arc::new(TokioMutex::new(
                self.open_vless_udp_session(user_id, destination, network, timeout_ms)
                    .await?,
            ));
            bucket.sessions.push(session.clone());
            bucket.next_index = bucket.sessions.len() % UDP_SESSION_POOL_SIZE;
            return Ok(session);
        }
        let index = bucket.next_index % bucket.sessions.len();
        bucket.next_index = (bucket.next_index + 1) % bucket.sessions.len();
        Ok(bucket.sessions[index].clone())
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
        let key = destination.authority();
        let Some(bucket) = pool.buckets.get_mut(&key) else {
            return;
        };
        bucket
            .sessions
            .retain(|session| !Arc::ptr_eq(session, target));
        if !bucket.sessions.is_empty() {
            bucket.next_index %= bucket.sessions.len();
        } else {
            pool.buckets.remove(&key);
        }
    }
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
        match hysteria2_obfs_config(self.obfs.as_deref(), self.obfs_password.as_deref()) {
            Ok(config) => OutboundCapability::tcp_udp(match config.map(|item| item.kind) {
                Some(Hysteria2ObfsKind::Salamander) => "quic-datagram-salamander-session-pool",
                Some(Hysteria2ObfsKind::Gecko) => "quic-datagram-gecko-session-pool",
                None => "quic-datagram-session-pool",
            }),
            Err(error) => OutboundCapability::unsupported(error.to_string()),
        }
    }

    async fn connect(
        &self,
        destination: &Destination,
        timeout_ms: u64,
    ) -> anyhow::Result<BoxedStream> {
        let obfs_config =
            hysteria2_obfs_config(self.obfs.as_deref(), self.obfs_password.as_deref())?;
        let connection = open_hysteria2_connection(
            &self.server,
            self.port,
            self.sni.as_deref(),
            self.skip_cert_verify,
            &self.password,
            self.alpn.as_deref(),
            obfs_config.as_ref(),
            timeout_ms,
        )
        .await?;
        let (mut send, mut recv) = timeout(
            Duration::from_millis(timeout_ms),
            connection.connection.open_bi(),
        )
        .await
        .context("hysteria2 open stream timed out")?
        .context("hysteria2 failed to open bidirectional stream")?;
        let request = build_hysteria2_tcp_request(destination)?;
        send.write_all(&request).await?;
        send.flush().await?;
        read_hysteria2_tcp_response(&mut recv).await?;
        Ok(Box::new(Hysteria2TcpStream {
            _endpoint: connection.endpoint,
            connection: connection.connection,
            h3_driver: connection.h3_driver,
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
        let obfs_config =
            hysteria2_obfs_config(self.obfs.as_deref(), self.obfs_password.as_deref())?;
        let session_handle = self
            .hysteria2_udp_session(obfs_config.as_ref(), timeout_ms)
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
                    session.connection.max_datagram_size(),
                )?;
                for message in messages {
                    timeout(
                        Duration::from_millis(timeout_ms),
                        session.connection.send_datagram_wait(Bytes::from(message)),
                    )
                    .await
                    .context("hysteria2 udp send timed out")?
                    .map_err(|error| anyhow!("hysteria2 udp send failed: {error}"))?;
                }
                timeout(Duration::from_millis(timeout_ms), async {
                    let mut reassembly = Hysteria2UdpReassembly::default();
                    loop {
                        let datagram = session.connection.read_datagram().await?;
                        if let Some(payload) = parse_hysteria2_udp_message(
                            &datagram,
                            session.session_id,
                            &mut reassembly,
                        )? {
                            return Ok::<Vec<u8>, anyhow::Error>(payload);
                        }
                    }
                })
                .await
                .context("hysteria2 udp receive timed out")?
            }
            .await
        };
        if exchange.is_err() {
            self.remove_hysteria2_udp_session(&session_handle).await;
        }
        exchange
    }
}

impl Hysteria2Outbound {
    async fn hysteria2_udp_session(
        &self,
        obfs_config: Option<&Hysteria2ObfsConfig>,
        timeout_ms: u64,
    ) -> anyhow::Result<Arc<TokioMutex<Hysteria2UdpSession>>> {
        let mut pool = self.udp_sessions.lock().await;
        if pool.len() < UDP_SESSION_POOL_SIZE {
            let connection = open_hysteria2_connection(
                &self.server,
                self.port,
                self.sni.as_deref(),
                self.skip_cert_verify,
                &self.password,
                self.alpn.as_deref(),
                obfs_config,
                timeout_ms,
            )
            .await?;
            if !connection.udp_supported {
                connection
                    .connection
                    .close(quinn::VarInt::from_u32(0), b"supercore close");
                connection.h3_driver.abort();
                return Err(anyhow!("hysteria2 server does not support udp relay"));
            }
            let session = Arc::new(TokioMutex::new(Hysteria2UdpSession {
                _endpoint: connection.endpoint,
                connection: connection.connection,
                h3_driver: connection.h3_driver,
                session_id: random_u32()?,
                next_packet_id: random_u16()?,
            }));
            pool.push(session.clone());
            return Ok(session);
        }
        pool.next()
            .ok_or_else(|| anyhow!("hysteria2 UDP session pool is unexpectedly empty"))
    }

    async fn remove_hysteria2_udp_session(&self, target: &Arc<TokioMutex<Hysteria2UdpSession>>) {
        let mut pool = self.udp_sessions.lock().await;
        pool.remove(target);
    }
}

struct Hysteria2Connection {
    endpoint: quinn::Endpoint,
    connection: quinn::Connection,
    h3_driver: JoinHandle<()>,
    udp_supported: bool,
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
            .map_err(|error| Error::new(ErrorKind::Other, format!("salt failed: {error}")))?;
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
                .map_err(|_| Error::new(ErrorKind::Other, "gecko state lock poisoned"))?;
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
                                    return Poll::Ready(Err(Error::new(
                                        ErrorKind::Other,
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
    let max_fragments = payload.len().min(8).max(2);
    let mut random = [0u8; 1];
    getrandom::fill(&mut random)
        .map_err(|error| Error::new(ErrorKind::Other, format!("gecko random failed: {error}")))?;
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
            getrandom::fill(&mut random).map_err(|error| {
                Error::new(
                    ErrorKind::Other,
                    format!("gecko chunk random failed: {error}"),
                )
            })?;
            1 + (u16::from_be_bytes(random) as usize % max_len)
        };
        let chunk = &payload[offset..offset + chunk_len];
        offset += chunk_len;

        let mut random = [0u8; 1];
        getrandom::fill(&mut random).map_err(|error| {
            Error::new(
                ErrorKind::Other,
                format!("gecko padding random failed: {error}"),
            )
        })?;
        let pad_len = random[0] as usize % 64;
        let mut frame = Vec::with_capacity(5 + pad_len + chunk.len());
        frame.push(0x80);
        frame.push(msg_id);
        frame.push(((index as u8) << 4) | total as u8);
        frame.extend_from_slice(&(pad_len as u16).to_be_bytes());
        if pad_len > 0 {
            let mut padding = vec![0u8; pad_len];
            getrandom::fill(&mut padding).map_err(|error| {
                Error::new(ErrorKind::Other, format!("gecko padding failed: {error}"))
            })?;
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
        .ok_or_else(|| Error::new(ErrorKind::Other, "gecko reassembly entry missing"))?;
    let mut output = Vec::new();
    for chunk in entry.chunks {
        output.extend_from_slice(
            &chunk.ok_or_else(|| Error::new(ErrorKind::Other, "gecko fragment missing"))?,
        );
    }
    Ok(Some(output))
}

fn salamander_mask(key: &[u8], salt: &[u8; 8]) -> std::io::Result<[u8; 32]> {
    let mut hasher = Blake2bVar::new(32)
        .map_err(|error| Error::new(ErrorKind::Other, format!("blake2b init failed: {error}")))?;
    blake2::digest::Update::update(&mut hasher, key);
    blake2::digest::Update::update(&mut hasher, salt);
    let mut output = [0u8; 32];
    hasher
        .finalize_variable(&mut output)
        .map_err(|error| Error::new(ErrorKind::Other, format!("blake2b failed: {error}")))?;
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

struct Hysteria2TcpStream {
    _endpoint: quinn::Endpoint,
    connection: quinn::Connection,
    h3_driver: JoinHandle<()>,
    recv: quinn::RecvStream,
    send: quinn::SendStream,
}

impl Drop for Hysteria2TcpStream {
    fn drop(&mut self) {
        self.connection
            .close(quinn::VarInt::from_u32(0), b"supercore close");
        self.h3_driver.abort();
    }
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

async fn open_hysteria2_connection(
    server: &str,
    port: u16,
    sni: Option<&str>,
    skip_cert_verify: bool,
    password: &str,
    alpn: Option<&str>,
    obfs_config: Option<&Hysteria2ObfsConfig>,
    timeout_ms: u64,
) -> anyhow::Result<Hysteria2Connection> {
    if password.is_empty() {
        return Err(anyhow!("hysteria2 password is empty"));
    }
    let remote = lookup_host((server, port))
        .await
        .with_context(|| format!("failed to resolve hysteria2 server {server}:{port}"))?
        .next()
        .ok_or_else(|| anyhow!("hysteria2 server {server}:{port} did not resolve"))?;
    let bind = if remote.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    }
    .parse::<SocketAddr>()
    .expect("valid quic bind address");
    let mut endpoint = if let Some(obfs_config) = obfs_config {
        let socket =
            std::net::UdpSocket::bind(bind).context("failed to bind hysteria2 obfs udp socket")?;
        socket
            .set_nonblocking(true)
            .context("failed to set hysteria2 obfs udp socket nonblocking")?;
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
        quinn::Endpoint::client(bind).context("failed to create quic endpoint")?
    };
    endpoint.set_default_client_config(quic_client_config(skip_cert_verify, alpn)?);
    let server_name = sni.unwrap_or(server).to_string();
    let connection = timeout(
        Duration::from_millis(timeout_ms),
        endpoint.connect(remote, &server_name)?,
    )
    .await
    .context("hysteria2 quic connect timed out")?
    .context("hysteria2 quic connect failed")?;

    let h3_connection = h3_quinn::Connection::new(connection.clone());
    let (mut h3_connection, mut send_request) = h3::client::new(h3_connection)
        .await
        .context("hysteria2 http/3 client init failed")?;
    let h3_driver = tokio::spawn(async move {
        let _ = h3_connection.wait_idle().await;
    });

    let request = http::Request::builder()
        .method(http::Method::POST)
        .uri("https://hysteria/auth")
        .header("hysteria-auth", password)
        .header("hysteria-cc-rx", "0")
        .header("hysteria-padding", "supercore")
        .body(())
        .context("failed to build hysteria2 auth request")?;
    let mut stream = match timeout(
        Duration::from_millis(timeout_ms),
        send_request.send_request(request),
    )
    .await
    .context("hysteria2 auth request timed out")?
    {
        Ok(stream) => stream,
        Err(error) => {
            h3_driver.abort();
            return Err(anyhow!("hysteria2 auth request failed: {error}"));
        }
    };
    if let Err(error) = stream.finish().await {
        h3_driver.abort();
        return Err(anyhow!("hysteria2 auth finish failed: {error}"));
    }
    let response = match timeout(Duration::from_millis(timeout_ms), stream.recv_response()).await {
        Ok(Ok(response)) => response,
        Ok(Err(error)) => {
            h3_driver.abort();
            return Err(anyhow!("hysteria2 auth response failed: {error}"));
        }
        Err(_) => {
            h3_driver.abort();
            return Err(anyhow!("hysteria2 auth response timed out"));
        }
    };
    if response.status().as_u16() != 233 {
        h3_driver.abort();
        return Err(anyhow!(
            "hysteria2 authentication failed with status {}",
            response.status()
        ));
    }

    let udp_supported = response
        .headers()
        .get("hysteria-udp")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.eq_ignore_ascii_case("true"))
        .unwrap_or(true);

    Ok(Hysteria2Connection {
        endpoint,
        connection,
        h3_driver,
        udp_supported,
    })
}

fn build_hysteria2_tcp_request(destination: &Destination) -> anyhow::Result<Vec<u8>> {
    let address = destination_socket_addr(destination);
    let mut output = Vec::with_capacity(address.len() + 16);
    encode_quic_varint(0x401, &mut output)?;
    encode_quic_varint(address.len() as u64, &mut output)?;
    output.extend_from_slice(address.as_bytes());
    encode_quic_varint(0, &mut output)?;
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

#[derive(Default)]
struct Hysteria2UdpReassembly {
    packets: HashMap<u16, Hysteria2UdpFragmentSet>,
}

struct Hysteria2UdpFragmentSet {
    total: u8,
    fragments: Vec<Option<Vec<u8>>>,
}

fn build_hysteria2_udp_messages(
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

fn parse_hysteria2_udp_message(
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
    if fragment_count == 1 {
        return Ok(Some(payload));
    }
    push_hysteria2_udp_fragment(reassembly, packet_id, fragment_id, fragment_count, payload)
}

fn push_hysteria2_udp_fragment(
    reassembly: &mut Hysteria2UdpReassembly,
    packet_id: u16,
    fragment_id: u8,
    fragment_count: u8,
    payload: Vec<u8>,
) -> anyhow::Result<Option<Vec<u8>>> {
    if reassembly.packets.len() > 64 {
        reassembly.packets.clear();
    }
    let entry = reassembly
        .packets
        .entry(packet_id)
        .or_insert_with(|| Hysteria2UdpFragmentSet {
            total: fragment_count,
            fragments: vec![None; fragment_count as usize],
        });
    if entry.total != fragment_count {
        reassembly.packets.remove(&packet_id);
        return Err(anyhow!("inconsistent hysteria2 udp fragment count"));
    }
    entry.fragments[fragment_id as usize] = Some(payload);
    if !entry.fragments.iter().all(Option::is_some) {
        return Ok(None);
    }
    let entry = reassembly
        .packets
        .remove(&packet_id)
        .ok_or_else(|| anyhow!("missing hysteria2 udp reassembly entry"))?;
    let mut output = Vec::new();
    for fragment in entry.fragments {
        output
            .extend_from_slice(&fragment.ok_or_else(|| anyhow!("missing hysteria2 udp fragment"))?);
    }
    Ok(Some(output))
}

fn encode_quic_varint(value: u64, output: &mut Vec<u8>) -> anyhow::Result<()> {
    match value {
        0..=0x3f => output.push(value as u8),
        0x40..=0x3fff => output.extend_from_slice(&((value as u16) | 0x4000).to_be_bytes()),
        0x4000..=0x3fff_ffff => {
            output.extend_from_slice(&((value as u32) | 0x8000_0000).to_be_bytes())
        }
        0x4000_0000..=0x3fff_ffff_ffff_ffff => {
            output.extend_from_slice(&(value | 0xc000_0000_0000_0000).to_be_bytes())
        }
        _ => return Err(anyhow!("quic varint value is too large")),
    }
    Ok(())
}

async fn read_quic_varint<R>(reader: &mut R) -> anyhow::Result<u64>
where
    R: AsyncRead + Unpin,
{
    let mut first = [0u8; 1];
    reader.read_exact(&mut first).await?;
    let tag = first[0] >> 6;
    let len = 1usize << tag;
    let mut value = (first[0] & 0x3f) as u64;
    for _ in 1..len {
        let mut byte = [0u8; 1];
        reader.read_exact(&mut byte).await?;
        value = (value << 8) | byte[0] as u64;
    }
    Ok(value)
}

fn read_quic_varint_from_slice(input: &[u8], cursor: &mut usize) -> anyhow::Result<u64> {
    if *cursor >= input.len() {
        return Err(anyhow!("quic varint is missing"));
    }
    let first = input[*cursor];
    let tag = first >> 6;
    let len = 1usize << tag;
    if *cursor + len > input.len() {
        return Err(anyhow!("quic varint is truncated"));
    }
    *cursor += 1;
    let mut value = (first & 0x3f) as u64;
    for _ in 1..len {
        value = (value << 8) | input[*cursor] as u64;
        *cursor += 1;
    }
    Ok(value)
}

fn random_u16() -> anyhow::Result<u16> {
    let mut bytes = [0u8; 2];
    getrandom::fill(&mut bytes).context("failed to generate random u16")?;
    Ok(u16::from_be_bytes(bytes))
}

fn random_u32() -> anyhow::Result<u32> {
    let mut bytes = [0u8; 4];
    getrandom::fill(&mut bytes).context("failed to generate random u32")?;
    Ok(u32::from_be_bytes(bytes))
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
        OutboundCapability::tcp_udp(format!(
            "{}-session-pool",
            self.udp_relay_mode.as_deref().unwrap_or("native")
        ))
    }

    async fn connect(
        &self,
        destination: &Destination,
        timeout_ms: u64,
    ) -> anyhow::Result<BoxedStream> {
        let _udp_mode = self.udp_relay_mode.as_deref().unwrap_or("native");
        let _congestion_control = self.congestion_control.as_deref().unwrap_or("default");
        let user_id = Uuid::parse_str(&self.uuid)
            .map_err(|error| anyhow!("invalid tuic uuid for {}: {error}", self.name))?;
        let connection = open_tuic_connection(
            &self.server,
            self.port,
            self.sni.as_deref(),
            self.skip_cert_verify,
            self.alpn.as_deref(),
            &user_id,
            &self.password,
            timeout_ms,
        )
        .await?;
        let (mut send, recv) = timeout(
            Duration::from_millis(timeout_ms),
            connection.connection.open_bi(),
        )
        .await
        .context("tuic open stream timed out")?
        .context("tuic failed to open bidirectional stream")?;
        let request = build_tuic_connect_request(destination)?;
        send.write_all(&request).await?;
        send.flush().await?;
        Ok(Box::new(TuicTcpStream {
            _endpoint: connection.endpoint,
            connection: connection.connection,
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
        let mode = self
            .udp_relay_mode
            .as_deref()
            .unwrap_or("native")
            .to_ascii_lowercase();
        if !matches!(mode.as_str(), "native" | "quic") {
            return Err(anyhow!("unsupported tuic udp relay mode {mode}"));
        }
        let session_handle = self.tuic_udp_session(&mode, timeout_ms).await?;

        let exchange = {
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
                        None
                    } else {
                        session.connection.max_datagram_size()
                    },
                )?;
                if session.mode == "quic" {
                    for message in messages {
                        let mut stream = timeout(
                            Duration::from_millis(timeout_ms),
                            session.connection.open_uni(),
                        )
                        .await
                        .context("tuic udp stream open timed out")?
                        .context("tuic failed to open udp stream")?;
                        stream.write_all(&message).await?;
                        stream.finish()?;
                    }
                    timeout(Duration::from_millis(timeout_ms), async {
                        let mut reassembly = TuicUdpReassembly::default();
                        loop {
                            let mut incoming = session.connection.accept_uni().await?;
                            let data = incoming
                                .read_to_end(65_535 + 512)
                                .await
                                .map_err(|error| anyhow!("tuic udp stream read failed: {error}"))?;
                            if let Some(payload) = parse_tuic_packet_message(
                                &data,
                                session.associate_id,
                                &mut reassembly,
                            )? {
                                return Ok::<Vec<u8>, anyhow::Error>(payload);
                            }
                        }
                    })
                    .await
                    .context("tuic udp stream receive timed out")?
                } else {
                    for message in messages {
                        timeout(
                            Duration::from_millis(timeout_ms),
                            session.connection.send_datagram_wait(Bytes::from(message)),
                        )
                        .await
                        .context("tuic udp send timed out")?
                        .map_err(|error| anyhow!("tuic udp send failed: {error}"))?;
                    }
                    timeout(Duration::from_millis(timeout_ms), async {
                        let mut reassembly = TuicUdpReassembly::default();
                        loop {
                            let datagram = session.connection.read_datagram().await?;
                            if let Some(payload) = parse_tuic_packet_message(
                                &datagram,
                                session.associate_id,
                                &mut reassembly,
                            )? {
                                return Ok::<Vec<u8>, anyhow::Error>(payload);
                            }
                        }
                    })
                    .await
                    .context("tuic udp datagram receive timed out")?
                }
            }
            .await
        };
        if exchange.is_err() {
            self.remove_tuic_udp_session(&session_handle).await;
        }
        exchange
    }
}

impl TuicOutbound {
    async fn tuic_udp_session(
        &self,
        mode: &str,
        timeout_ms: u64,
    ) -> anyhow::Result<Arc<TokioMutex<TuicUdpSession>>> {
        let mut pool = self.udp_sessions.lock().await;
        if pool.mode.as_deref() != Some(mode) {
            pool.sessions.clear();
            pool.mode = Some(mode.to_string());
        }
        if pool.sessions.len() < UDP_SESSION_POOL_SIZE {
            let user_id = Uuid::parse_str(&self.uuid)
                .map_err(|error| anyhow!("invalid tuic uuid for {}: {error}", self.name))?;
            let connection = open_tuic_connection(
                &self.server,
                self.port,
                self.sni.as_deref(),
                self.skip_cert_verify,
                self.alpn.as_deref(),
                &user_id,
                &self.password,
                timeout_ms,
            )
            .await?;
            let session = Arc::new(TokioMutex::new(TuicUdpSession {
                _endpoint: connection.endpoint,
                connection: connection.connection,
                mode: mode.to_string(),
                associate_id: random_u16()?,
                next_packet_id: random_u16()?,
            }));
            pool.sessions.push(session.clone());
            return Ok(session);
        }
        pool.sessions
            .next()
            .ok_or_else(|| anyhow!("tuic UDP session pool is unexpectedly empty"))
    }

    async fn remove_tuic_udp_session(&self, target: &Arc<TokioMutex<TuicUdpSession>>) {
        let mut pool = self.udp_sessions.lock().await;
        pool.sessions.remove(target);
    }
}

struct TuicConnection {
    endpoint: quinn::Endpoint,
    connection: quinn::Connection,
}

struct TuicTcpStream {
    _endpoint: quinn::Endpoint,
    connection: quinn::Connection,
    recv: quinn::RecvStream,
    send: quinn::SendStream,
}

impl Drop for TuicTcpStream {
    fn drop(&mut self) {
        self.connection
            .close(quinn::VarInt::from_u32(0), b"supercore close");
    }
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

async fn open_tuic_connection(
    server: &str,
    port: u16,
    sni: Option<&str>,
    skip_cert_verify: bool,
    alpn: Option<&str>,
    user_id: &Uuid,
    password: &str,
    timeout_ms: u64,
) -> anyhow::Result<TuicConnection> {
    if password.is_empty() {
        return Err(anyhow!("tuic password is empty"));
    }
    let remote = lookup_host((server, port))
        .await
        .with_context(|| format!("failed to resolve tuic server {server}:{port}"))?
        .next()
        .ok_or_else(|| anyhow!("tuic server {server}:{port} did not resolve"))?;
    let bind = if remote.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    }
    .parse::<SocketAddr>()
    .expect("valid quic bind address");
    let mut endpoint = quinn::Endpoint::client(bind).context("failed to create quic endpoint")?;
    endpoint.set_default_client_config(quic_client_config(skip_cert_verify, alpn.or(Some("h3")))?);
    let server_name = sni.unwrap_or(server).to_string();
    let connection = timeout(
        Duration::from_millis(timeout_ms),
        endpoint.connect(remote, &server_name)?,
    )
    .await
    .context("tuic quic connect timed out")?
    .context("tuic quic connect failed")?;

    let mut token = [0u8; 32];
    connection
        .export_keying_material(&mut token, user_id.as_bytes(), password.as_bytes())
        .map_err(|_| anyhow!("tuic token export failed"))?;
    let mut auth = Vec::with_capacity(2 + 16 + 32);
    auth.extend_from_slice(&[0x05, 0x00]);
    auth.extend_from_slice(user_id.as_bytes());
    auth.extend_from_slice(&token);
    let mut stream = timeout(Duration::from_millis(timeout_ms), connection.open_uni())
        .await
        .context("tuic auth stream timed out")?
        .context("tuic failed to open auth stream")?;
    stream.write_all(&auth).await?;
    stream.finish()?;

    Ok(TuicConnection {
        endpoint,
        connection,
    })
}

fn build_tuic_connect_request(destination: &Destination) -> anyhow::Result<Vec<u8>> {
    let mut output = Vec::with_capacity(32 + destination.host.len());
    output.extend_from_slice(&[0x05, 0x01]);
    encode_tuic_address(destination, &mut output)?;
    Ok(output)
}

#[derive(Default)]
struct TuicUdpReassembly {
    packets: HashMap<u16, TuicUdpFragmentSet>,
}

struct TuicUdpFragmentSet {
    total: u8,
    fragments: Vec<Option<Vec<u8>>>,
}

fn build_tuic_packet_messages(
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
    encode_tuic_address(destination, &mut output)?;
    output.extend_from_slice(payload);
    Ok(output)
}

fn parse_tuic_packet_message(
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
    skip_tuic_address(data, &mut cursor)?;
    if cursor + payload_len > data.len() {
        return Err(anyhow!("tuic udp payload length exceeds packet"));
    }
    let payload = data[cursor..cursor + payload_len].to_vec();
    if fragment_total == 1 {
        return Ok(Some(payload));
    }
    push_tuic_udp_fragment(reassembly, packet_id, fragment_id, fragment_total, payload)
}

fn push_tuic_udp_fragment(
    reassembly: &mut TuicUdpReassembly,
    packet_id: u16,
    fragment_id: u8,
    fragment_total: u8,
    payload: Vec<u8>,
) -> anyhow::Result<Option<Vec<u8>>> {
    if reassembly.packets.len() > 64 {
        reassembly.packets.clear();
    }
    let entry = reassembly
        .packets
        .entry(packet_id)
        .or_insert_with(|| TuicUdpFragmentSet {
            total: fragment_total,
            fragments: vec![None; fragment_total as usize],
        });
    if entry.total != fragment_total {
        reassembly.packets.remove(&packet_id);
        return Err(anyhow!("inconsistent tuic udp fragment count"));
    }
    entry.fragments[fragment_id as usize] = Some(payload);
    if !entry.fragments.iter().all(Option::is_some) {
        return Ok(None);
    }
    let entry = reassembly
        .packets
        .remove(&packet_id)
        .ok_or_else(|| anyhow!("missing tuic udp reassembly entry"))?;
    let mut output = Vec::new();
    for fragment in entry.fragments {
        output.extend_from_slice(&fragment.ok_or_else(|| anyhow!("missing tuic udp fragment"))?);
    }
    Ok(Some(output))
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

fn skip_tuic_address(input: &[u8], cursor: &mut usize) -> anyhow::Result<()> {
    if *cursor >= input.len() {
        return Err(anyhow!("tuic address is missing"));
    }
    let address_type = input[*cursor];
    *cursor += 1;
    match address_type {
        0xff => Ok(()),
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
            Ok(())
        }
        0x01 => {
            if *cursor + 4 + 2 > input.len() {
                return Err(anyhow!("tuic ipv4 address is truncated"));
            }
            *cursor += 4 + 2;
            Ok(())
        }
        0x02 => {
            if *cursor + 16 + 2 > input.len() {
                return Err(anyhow!("tuic ipv6 address is truncated"));
            }
            *cursor += 16 + 2;
            Ok(())
        }
        other => Err(anyhow!("unsupported tuic address type {other}")),
    }
}

#[async_trait]
impl Outbound for TrojanOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "trojan"
    }

    fn capability(&self) -> OutboundCapability {
        let network = self
            .network
            .as_deref()
            .unwrap_or("tcp")
            .trim()
            .to_ascii_lowercase();
        match trojan_alpn_protocols(&network, &self.alpn) {
            Ok(_) => OutboundCapability::tcp_udp("trojan-udp-associate-stream-pool"),
            Err(error) => OutboundCapability::unsupported(error.to_string()),
        }
    }

    async fn connect(
        &self,
        destination: &Destination,
        timeout_ms: u64,
    ) -> anyhow::Result<BoxedStream> {
        let mut stream = self.open_transport(timeout_ms).await?;
        let request = build_trojan_request(&self.password, destination)?;
        stream.write_all(&request).await?;
        stream.flush().await?;
        Ok(stream)
    }

    async fn udp_exchange(
        &self,
        destination: &Destination,
        payload: &[u8],
        timeout_ms: u64,
    ) -> anyhow::Result<Vec<u8>> {
        let session_handle = self.trojan_udp_session(timeout_ms).await?;
        let mut session = session_handle.lock().await;
        let packet = encode_trojan_udp_packet(destination, payload)?;
        let exchange = timeout(Duration::from_millis(timeout_ms), async {
            session.stream.write_all(&packet).await?;
            session.stream.flush().await?;
            let (_response_destination, response) =
                read_trojan_udp_packet(&mut session.stream).await?;
            anyhow::Ok(response)
        })
        .await
        .context("trojan udp exchange timed out")?;
        if exchange.is_err() {
            drop(session);
            self.remove_trojan_udp_session(&session_handle).await;
        }
        exchange
    }
}

impl TrojanOutbound {
    async fn open_transport(&self, timeout_ms: u64) -> anyhow::Result<BoxedStream> {
        let network = self
            .network
            .as_deref()
            .unwrap_or("tcp")
            .trim()
            .to_ascii_lowercase();
        if !matches!(
            network.as_str(),
            "tcp" | "ws" | "websocket" | "grpc" | "h2" | "http" | "httpupgrade" | "http-upgrade"
        ) {
            return Err(anyhow!("unsupported trojan network {network}"));
        }

        let tcp = connect_tcp(&format!("{}:{}", self.server, self.port), timeout_ms).await?;
        let server_name = self.sni.as_deref().unwrap_or(&self.server).to_string();
        let mut tls_config = tls_client_config(self.skip_cert_verify)?;
        tls_config.alpn_protocols = trojan_alpn_protocols(&network, &self.alpn)?;
        let connector = TlsConnector::from(Arc::new(tls_config));
        let tls_server_name = ServerName::try_from(server_name.clone())
            .map_err(|error| anyhow!("invalid trojan server name: {error}"))?;
        let mut stream = timeout(
            Duration::from_millis(timeout_ms),
            connector.connect(tls_server_name, tcp),
        )
        .await
        .context("trojan tls handshake timed out")?
        .context("trojan tls handshake failed")?;

        match network.as_str() {
            "tcp" => Ok(Box::new(stream)),
            "ws" | "websocket" => {
                perform_websocket_handshake_with_headers(
                    &mut stream,
                    self.ws_host.as_deref().unwrap_or(&server_name),
                    self.ws_path.as_deref().unwrap_or("/"),
                    &self.transport_headers,
                )
                .await?;
                Ok(Box::new(spawn_websocket_stream(stream)))
            }
            "grpc" => open_grpc_tunnel(
                stream,
                self.ws_host.as_deref().unwrap_or(&server_name),
                self.grpc_service_name.as_deref(),
                timeout_ms,
            )
            .await
            .map(|stream| Box::new(stream) as BoxedStream),
            "h2" | "http" => open_h2_tunnel(
                stream,
                self.ws_host.as_deref().unwrap_or(&server_name),
                self.ws_path.as_deref().unwrap_or("/"),
                timeout_ms,
            )
            .await
            .map(|stream| Box::new(stream) as BoxedStream),
            "httpupgrade" | "http-upgrade" => open_http_upgrade_tunnel(
                stream,
                self.ws_host.as_deref().unwrap_or(&server_name),
                self.ws_path.as_deref().unwrap_or("/"),
                &self.transport_headers,
            )
            .await
            .map(|stream| Box::new(stream) as BoxedStream),
            _ => unreachable!("trojan network was validated"),
        }
    }

    async fn trojan_udp_session(
        &self,
        timeout_ms: u64,
    ) -> anyhow::Result<Arc<TokioMutex<TrojanUdpSession>>> {
        let mut pool = self.udp_sessions.lock().await;
        if pool.len() < UDP_SESSION_POOL_SIZE {
            let session = Arc::new(TokioMutex::new(
                self.open_trojan_udp_session(timeout_ms).await?,
            ));
            pool.push(session.clone());
            return Ok(session);
        }
        pool.next()
            .ok_or_else(|| anyhow!("trojan UDP session pool is unexpectedly empty"))
    }

    async fn open_trojan_udp_session(&self, timeout_ms: u64) -> anyhow::Result<TrojanUdpSession> {
        let mut stream = self.open_transport(timeout_ms).await?;
        let request = build_trojan_request_with_command(
            &self.password,
            &Destination::new("0.0.0.0", 0),
            TROJAN_CMD_UDP_ASSOCIATE,
        )?;
        stream.write_all(&request).await?;
        stream.flush().await?;
        Ok(TrojanUdpSession { stream })
    }

    async fn remove_trojan_udp_session(&self, target: &Arc<TokioMutex<TrojanUdpSession>>) {
        let mut pool = self.udp_sessions.lock().await;
        pool.remove(target);
    }
}

fn trojan_alpn_protocols(network: &str, configured: &[String]) -> anyhow::Result<Vec<Vec<u8>>> {
    let mut protocols = Vec::new();
    for value in configured {
        for protocol in value
            .split(',')
            .map(str::trim)
            .filter(|item| !item.is_empty())
        {
            if !protocol.is_ascii() || protocol.len() > u8::MAX as usize {
                return Err(anyhow!("invalid trojan ALPN value {protocol:?}"));
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
            "grpc" | "h2" | "http" => vec![b"h2".to_vec()],
            "ws" | "websocket" | "httpupgrade" | "http-upgrade" => {
                vec![b"http/1.1".to_vec()]
            }
            _ => Vec::new(),
        });
    }
    if matches!(network, "grpc" | "h2" | "http")
        && !protocols.iter().any(|item| item.as_slice() == b"h2")
    {
        return Err(anyhow!("trojan {network} transport requires h2 in ALPN"));
    }
    if matches!(network, "ws" | "websocket" | "httpupgrade" | "http-upgrade")
        && !protocols.iter().any(|item| item.as_slice() == b"http/1.1")
    {
        return Err(anyhow!(
            "trojan {network} transport requires http/1.1 in ALPN"
        ));
    }
    Ok(protocols)
}

fn destination_socket_addr(destination: &Destination) -> String {
    if destination.host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{}]:{}", destination.host, destination.port)
    } else {
        destination.authority()
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

const VMESS_TAG_LEN: usize = 16;
const VMESS_MAX_CHUNK_PLAINTEXT: usize = 8192;
const VMESS_CMD_TCP: u8 = 0x01;
const VMESS_CMD_UDP: u8 = 0x02;
type VmessMaskReader = digest::core_api::XofReaderCoreWrapper<sha3::Shake128ReaderCore>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VmessCipher {
    Aes128Gcm,
    Chacha20Poly1305,
    None,
}

struct VmessSetup {
    request: Vec<u8>,
    upload: VmessUploadState,
    download: VmessDownloadState,
}

struct VmessUploadState {
    cipher: Option<VmessAeadState>,
    length_mask: VmessLengthMask,
}

struct VmessDownloadState {
    response_header_key: [u8; 16],
    response_header_iv: [u8; 16],
    response_authentication: u8,
    cipher: Option<VmessAeadState>,
    length_mask: VmessLengthMask,
}

struct VmessLengthMask {
    reader: VmessMaskReader,
}

struct VmessAeadState {
    cipher: VmessCipher,
    key: Vec<u8>,
    nonce: [u8; 12],
    counter: u16,
}

impl VmessCipher {
    fn from_name(name: &str) -> anyhow::Result<Self> {
        match name.to_ascii_lowercase().as_str() {
            "auto" | "chacha20-poly1305" | "chacha20-ietf-poly1305" => Ok(Self::Chacha20Poly1305),
            "aes-128-gcm" => Ok(Self::Aes128Gcm),
            "none" => Ok(Self::None),
            _ => Err(anyhow!("unsupported vmess cipher {name}")),
        }
    }

    fn method_byte(self) -> u8 {
        match self {
            Self::Aes128Gcm => 3,
            Self::Chacha20Poly1305 => 4,
            Self::None => 5,
        }
    }

    fn tag_len(self) -> usize {
        match self {
            Self::None => 0,
            Self::Aes128Gcm | Self::Chacha20Poly1305 => VMESS_TAG_LEN,
        }
    }
}

impl VmessLengthMask {
    fn new(seed: &[u8]) -> Self {
        let mut shake = Shake128::default();
        sha3::digest::Update::update(&mut shake, seed);
        Self {
            reader: shake.finalize_xof(),
        }
    }

    fn next(&mut self) -> u16 {
        let mut mask = [0u8; 2];
        self.reader.read(&mut mask);
        u16::from_be_bytes(mask)
    }
}

impl VmessAeadState {
    fn new(cipher: VmessCipher, key: &[u8], iv: &[u8]) -> anyhow::Result<Option<Self>> {
        if cipher == VmessCipher::None {
            return Ok(None);
        }
        if iv.len() < 12 {
            return Err(anyhow!("vmess iv is too short"));
        }
        let mut nonce = [0u8; 12];
        nonce[2..].copy_from_slice(&iv[2..12]);
        let key = match cipher {
            VmessCipher::Aes128Gcm => key.to_vec(),
            VmessCipher::Chacha20Poly1305 => vmess_chacha_key(key).to_vec(),
            VmessCipher::None => unreachable!(),
        };
        Ok(Some(Self {
            cipher,
            key,
            nonce,
            counter: 0,
        }))
    }

    fn next_nonce(&mut self) -> [u8; 12] {
        let mut nonce = self.nonce;
        nonce[0..2].copy_from_slice(&self.counter.to_be_bytes());
        self.counter = self.counter.wrapping_add(1);
        nonce
    }

    fn encrypt(&mut self, plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
        let nonce = self.next_nonce();
        match self.cipher {
            VmessCipher::Aes128Gcm => Aes128Gcm::new_from_slice(&self.key)
                .map_err(|_| anyhow!("invalid vmess aes-128-gcm key"))?
                .encrypt(aes_gcm::Nonce::from_slice(&nonce), plaintext)
                .map_err(|_| anyhow!("vmess encrypt failed")),
            VmessCipher::Chacha20Poly1305 => ChaCha20Poly1305::new_from_slice(&self.key)
                .map_err(|_| anyhow!("invalid vmess chacha20-poly1305 key"))?
                .encrypt(chacha20poly1305::Nonce::from_slice(&nonce), plaintext)
                .map_err(|_| anyhow!("vmess encrypt failed")),
            VmessCipher::None => Ok(plaintext.to_vec()),
        }
    }

    fn decrypt(&mut self, ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
        let nonce = self.next_nonce();
        match self.cipher {
            VmessCipher::Aes128Gcm => Aes128Gcm::new_from_slice(&self.key)
                .map_err(|_| anyhow!("invalid vmess aes-128-gcm key"))?
                .decrypt(aes_gcm::Nonce::from_slice(&nonce), ciphertext)
                .map_err(|_| anyhow!("vmess decrypt failed")),
            VmessCipher::Chacha20Poly1305 => ChaCha20Poly1305::new_from_slice(&self.key)
                .map_err(|_| anyhow!("invalid vmess chacha20-poly1305 key"))?
                .decrypt(chacha20poly1305::Nonce::from_slice(&nonce), ciphertext)
                .map_err(|_| anyhow!("vmess decrypt failed")),
            VmessCipher::None => Ok(ciphertext.to_vec()),
        }
    }
}

async fn setup_vmess_stream<S>(
    mut stream: S,
    user_id: &Uuid,
    cipher: VmessCipher,
    destination: &Destination,
) -> anyhow::Result<BoxedStream>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let setup = build_vmess_setup(user_id, cipher, destination)?;
    stream.write_all(&setup.request).await?;
    stream.flush().await?;
    Ok(Box::new(spawn_vmess_stream(
        stream,
        setup.upload,
        setup.download,
    )))
}

fn spawn_vmess_stream<S>(
    stream: S,
    mut upload_state: VmessUploadState,
    mut download_state: VmessDownloadState,
) -> DuplexStream
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (app_side, relay_side) = tokio::io::duplex(64 * 1024);
    let (mut local_read, mut local_write) = tokio::io::split(relay_side);
    let (mut remote_read, mut remote_write) = tokio::io::split(stream);

    tokio::spawn(async move {
        let mut buf = [0u8; 16 * 1024];
        loop {
            match local_read.read(&mut buf).await {
                Ok(0) => {
                    let _ = write_vmess_chunk(&mut remote_write, &mut upload_state, &[]).await;
                    let _ = remote_write.shutdown().await;
                    break;
                }
                Ok(n) => {
                    for chunk in buf[..n].chunks(VMESS_MAX_CHUNK_PLAINTEXT) {
                        if write_vmess_chunk(&mut remote_write, &mut upload_state, chunk)
                            .await
                            .is_err()
                        {
                            return;
                        }
                    }
                }
                Err(_) => break,
            }
        }
    });

    tokio::spawn(async move {
        if read_vmess_response_header(&mut remote_read, &download_state)
            .await
            .is_err()
        {
            let _ = local_write.shutdown().await;
            return;
        }
        loop {
            match read_vmess_chunk(&mut remote_read, &mut download_state).await {
                Ok(Some(chunk)) => {
                    if local_write.write_all(&chunk).await.is_err() {
                        break;
                    }
                }
                Ok(None) => {
                    let _ = local_write.shutdown().await;
                    break;
                }
                Err(_) => {
                    let _ = local_write.shutdown().await;
                    break;
                }
            }
        }
    });

    app_side
}

async fn write_vmess_chunk<W>(
    writer: &mut W,
    state: &mut VmessUploadState,
    payload: &[u8],
) -> anyhow::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let body = match &mut state.cipher {
        Some(cipher) => cipher.encrypt(payload)?,
        None => payload.to_vec(),
    };
    if body.len() > u16::MAX as usize {
        return Err(anyhow!("vmess chunk is too large"));
    }
    let masked_len = (body.len() as u16) ^ state.length_mask.next();
    writer.write_all(&masked_len.to_be_bytes()).await?;
    writer.write_all(&body).await?;
    writer.flush().await?;
    Ok(())
}

async fn read_vmess_chunk<R>(
    reader: &mut R,
    state: &mut VmessDownloadState,
) -> anyhow::Result<Option<Vec<u8>>>
where
    R: AsyncRead + Unpin,
{
    let mut length = [0u8; 2];
    if !read_exact_or_eof(reader, &mut length).await? {
        return Ok(None);
    }
    let body_len = (u16::from_be_bytes(length) ^ state.length_mask.next()) as usize;
    let tag_len = state
        .cipher
        .as_ref()
        .map(|cipher| cipher.cipher.tag_len())
        .unwrap_or(0);
    if body_len == tag_len {
        let mut eof = vec![0u8; body_len];
        if body_len > 0 {
            reader.read_exact(&mut eof).await?;
        }
        return Ok(None);
    }
    if body_len > u16::MAX as usize {
        return Err(anyhow!("vmess response chunk is too large"));
    }
    if body_len < tag_len {
        return Err(anyhow!("vmess response chunk is shorter than tag"));
    }
    let mut body = vec![0u8; body_len];
    reader.read_exact(&mut body).await?;
    match &mut state.cipher {
        Some(cipher) => cipher.decrypt(&body).map(Some),
        None => Ok(Some(body)),
    }
}

async fn read_vmess_response_header<R>(
    reader: &mut R,
    state: &VmessDownloadState,
) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin,
{
    let len_key = vmess_kdf(&state.response_header_key, &[b"AEAD Resp Header Len Key"]);
    let len_nonce = vmess_kdf(&state.response_header_iv, &[b"AEAD Resp Header Len IV"]);
    let mut encrypted_len = [0u8; 2 + VMESS_TAG_LEN];
    reader.read_exact(&mut encrypted_len).await?;
    let len = vmess_aes128gcm_decrypt(&len_key[..16], &len_nonce[..12], &[], &encrypted_len)?;
    if len.len() != 2 {
        return Err(anyhow!("invalid vmess response header length"));
    }
    let header_len = u16::from_be_bytes([len[0], len[1]]) as usize;

    let header_key = vmess_kdf(&state.response_header_key, &[b"AEAD Resp Header Key"]);
    let header_nonce = vmess_kdf(&state.response_header_iv, &[b"AEAD Resp Header IV"]);
    let mut encrypted_header = vec![0u8; header_len + VMESS_TAG_LEN];
    reader.read_exact(&mut encrypted_header).await?;
    let header = vmess_aes128gcm_decrypt(
        &header_key[..16],
        &header_nonce[..12],
        &[],
        &encrypted_header,
    )?;
    if header.len() < 4 {
        return Err(anyhow!("vmess response header is too short"));
    }
    if header[0] != state.response_authentication {
        return Err(anyhow!(
            "invalid vmess response auth value: expected {}, got {}",
            state.response_authentication,
            header[0]
        ));
    }
    Ok(())
}

fn build_vmess_setup(
    user_id: &Uuid,
    cipher: VmessCipher,
    destination: &Destination,
) -> anyhow::Result<VmessSetup> {
    build_vmess_setup_with_command(user_id, cipher, destination, VMESS_CMD_TCP)
}

fn build_vmess_setup_with_command(
    user_id: &Uuid,
    cipher: VmessCipher,
    destination: &Destination,
    command: u8,
) -> anyhow::Result<VmessSetup> {
    let instruction_key = vmess_instruction_key(user_id);
    let auth_id = vmess_auth_id(&instruction_key)?;

    let mut data_iv = [0u8; 16];
    let mut data_key = [0u8; 16];
    getrandom::fill(&mut data_iv)
        .map_err(|error| anyhow!("failed to generate vmess iv: {error}"))?;
    getrandom::fill(&mut data_key)
        .map_err(|error| anyhow!("failed to generate vmess key: {error}"))?;
    let mut response_auth = [0u8; 1];
    getrandom::fill(&mut response_auth)
        .map_err(|error| anyhow!("failed to generate vmess response auth: {error}"))?;

    let response_header_iv = vmess_sha256_16(&data_iv);
    let response_header_key = vmess_sha256_16(&data_key);

    let mut header = Vec::with_capacity(316);
    header.push(0x01);
    header.extend_from_slice(&data_iv);
    header.extend_from_slice(&data_key);
    header.push(response_auth[0]);
    header.push(0x01 | 0x04);
    header.push(cipher.method_byte());
    header.push(0x00);
    header.push(command);
    encode_vmess_destination(destination, &mut header)?;
    let checksum = vmess_fnv1a(&header).to_be_bytes();
    header.extend_from_slice(&checksum);

    let mut nonce = [0u8; 8];
    getrandom::fill(&mut nonce)
        .map_err(|error| anyhow!("failed to generate vmess header nonce: {error}"))?;

    let len_key = vmess_kdf(
        &instruction_key,
        &[b"VMess Header AEAD Key_Length", &auth_id, &nonce],
    );
    let len_nonce = vmess_kdf(
        &instruction_key,
        &[b"VMess Header AEAD Nonce_Length", &auth_id, &nonce],
    );
    let encrypted_len = vmess_aes128gcm_encrypt(
        &len_key[..16],
        &len_nonce[..12],
        &auth_id,
        &(header.len() as u16).to_be_bytes(),
    )?;

    let header_key = vmess_kdf(
        &instruction_key,
        &[b"VMess Header AEAD Key", &auth_id, &nonce],
    );
    let header_nonce = vmess_kdf(
        &instruction_key,
        &[b"VMess Header AEAD Nonce", &auth_id, &nonce],
    );
    let encrypted_header =
        vmess_aes128gcm_encrypt(&header_key[..16], &header_nonce[..12], &auth_id, &header)?;

    let mut request =
        Vec::with_capacity(16 + encrypted_len.len() + nonce.len() + encrypted_header.len());
    request.extend_from_slice(&auth_id);
    request.extend_from_slice(&encrypted_len);
    request.extend_from_slice(&nonce);
    request.extend_from_slice(&encrypted_header);

    Ok(VmessSetup {
        request,
        upload: VmessUploadState {
            cipher: VmessAeadState::new(cipher, &data_key, &data_iv)?,
            length_mask: VmessLengthMask::new(&data_iv),
        },
        download: VmessDownloadState {
            response_header_key,
            response_header_iv,
            response_authentication: response_auth[0],
            cipher: VmessAeadState::new(cipher, &response_header_key, &response_header_iv)?,
            length_mask: VmessLengthMask::new(&response_header_iv),
        },
    })
}

fn encode_vmess_destination(destination: &Destination, output: &mut Vec<u8>) -> anyhow::Result<()> {
    output.extend_from_slice(&destination.port.to_be_bytes());
    if let Ok(ip) = destination.host.parse::<std::net::IpAddr>() {
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
        return Ok(());
    }
    let host = destination.host.as_bytes();
    if host.len() > u8::MAX as usize {
        return Err(anyhow!("vmess destination host is too long"));
    }
    output.push(0x02);
    output.push(host.len() as u8);
    output.extend_from_slice(host);
    Ok(())
}

fn vmess_instruction_key(user_id: &Uuid) -> [u8; 16] {
    let mut data = user_id.as_bytes().to_vec();
    data.extend_from_slice(b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
    Md5::digest(&data).into()
}

fn vmess_auth_id(instruction_key: &[u8; 16]) -> anyhow::Result<[u8; 16]> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| anyhow!("system time before unix epoch: {error}"))?
        .as_secs();
    let mut auth = [0u8; 16];
    auth[0..8].copy_from_slice(&now.to_be_bytes());
    getrandom::fill(&mut auth[8..12])
        .map_err(|error| anyhow!("failed to generate vmess auth random: {error}"))?;
    let checksum = crc32c::crc32c(&auth[0..12]).to_be_bytes();
    auth[12..16].copy_from_slice(&checksum);

    let key = vmess_kdf(instruction_key, &[b"AES Auth ID Encryption"]);
    let cipher =
        Aes128::new_from_slice(&key[..16]).map_err(|_| anyhow!("invalid vmess auth key"))?;
    cipher.encrypt_block((&mut auth).into());
    Ok(auth)
}

fn vmess_aes128gcm_encrypt(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> anyhow::Result<Vec<u8>> {
    Aes128Gcm::new_from_slice(key)
        .map_err(|_| anyhow!("invalid vmess aes-gcm key"))?
        .encrypt(
            aes_gcm::Nonce::from_slice(nonce),
            aes_gcm::aead::Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| anyhow!("vmess aes-gcm encrypt failed"))
}

fn vmess_aes128gcm_decrypt(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> anyhow::Result<Vec<u8>> {
    Aes128Gcm::new_from_slice(key)
        .map_err(|_| anyhow!("invalid vmess aes-gcm key"))?
        .decrypt(
            aes_gcm::Nonce::from_slice(nonce),
            aes_gcm::aead::Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| anyhow!("vmess aes-gcm decrypt failed"))
}

fn vmess_kdf(key: &[u8], path: &[&[u8]]) -> [u8; 32] {
    let mut keys = Vec::with_capacity(path.len() + 1);
    keys.push(b"VMess AEAD KDF".as_slice());
    keys.extend_from_slice(path);
    vmess_recursive_hash(&keys, keys.len(), key)
}

fn vmess_recursive_hash(keys: &[&[u8]], level: usize, data: &[u8]) -> [u8; 32] {
    if level == 0 {
        return Sha256::digest(data).into();
    }
    let (inner_pad, outer_pad) = vmess_hmac_pads(keys[level - 1]);
    let mut inner_input = Vec::with_capacity(inner_pad.len() + data.len());
    inner_input.extend_from_slice(&inner_pad);
    inner_input.extend_from_slice(data);
    let inner_digest = vmess_recursive_hash(keys, level - 1, &inner_input);

    let mut outer_input = Vec::with_capacity(outer_pad.len() + inner_digest.len());
    outer_input.extend_from_slice(&outer_pad);
    outer_input.extend_from_slice(&inner_digest);
    vmess_recursive_hash(keys, level - 1, &outer_input)
}

fn vmess_hmac_pads(key: &[u8]) -> ([u8; 64], [u8; 64]) {
    let key_material = if key.len() > 64 {
        Sha256::digest(key).to_vec()
    } else {
        key.to_vec()
    };
    let mut inner = [0x36u8; 64];
    let mut outer = [0x5cu8; 64];
    for (index, byte) in key_material.iter().enumerate() {
        inner[index] ^= byte;
        outer[index] ^= byte;
    }
    (inner, outer)
}

fn vmess_sha256_16(data: &[u8]) -> [u8; 16] {
    let digest = Sha256::digest(data);
    let mut output = [0u8; 16];
    output.copy_from_slice(&digest[..16]);
    output
}

fn vmess_chacha_key(data: &[u8]) -> [u8; 32] {
    let first: [u8; 16] = Md5::digest(data).into();
    let second: [u8; 16] = Md5::digest(first).into();
    let mut output = [0u8; 32];
    output[..16].copy_from_slice(&first);
    output[16..].copy_from_slice(&second);
    output
}

fn vmess_fnv1a(data: &[u8]) -> u32 {
    let mut hash = 0x811c9dc5u32;
    for byte in data {
        hash ^= *byte as u32;
        hash = hash.wrapping_mul(16_777_619);
    }
    hash
}

const TROJAN_CMD_CONNECT: u8 = 0x01;
const TROJAN_CMD_UDP_ASSOCIATE: u8 = 0x03;

fn build_trojan_request(password: &str, destination: &Destination) -> anyhow::Result<Vec<u8>> {
    build_trojan_request_with_command(password, destination, TROJAN_CMD_CONNECT)
}

fn build_trojan_request_with_command(
    password: &str,
    destination: &Destination,
    command: u8,
) -> anyhow::Result<Vec<u8>> {
    let mut hasher = Sha224::new();
    hasher.update(password.as_bytes());
    let password_hash = hasher.finalize();
    let mut request = hex_lower(&password_hash).into_bytes();
    request.extend_from_slice(b"\r\n");
    request.push(command);
    encode_socks5_destination(destination, &mut request)?;
    request.extend_from_slice(b"\r\n");
    Ok(request)
}

fn encode_trojan_udp_packet(destination: &Destination, payload: &[u8]) -> anyhow::Result<Vec<u8>> {
    if payload.len() > u16::MAX as usize {
        return Err(anyhow!("trojan udp payload is too large"));
    }
    let mut packet = Vec::with_capacity(1 + 255 + 2 + 2 + 2 + payload.len());
    encode_socks5_destination(destination, &mut packet)?;
    packet.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    packet.extend_from_slice(b"\r\n");
    packet.extend_from_slice(payload);
    Ok(packet)
}

async fn read_trojan_udp_packet<R>(reader: &mut R) -> anyhow::Result<(Destination, Vec<u8>)>
where
    R: AsyncRead + Unpin,
{
    let mut atyp = [0u8; 1];
    reader.read_exact(&mut atyp).await?;
    let destination = read_socks5_destination_after_atyp(reader, atyp[0]).await?;
    let mut length = [0u8; 2];
    reader.read_exact(&mut length).await?;
    let payload_len = u16::from_be_bytes(length) as usize;
    let mut crlf = [0u8; 2];
    reader.read_exact(&mut crlf).await?;
    if crlf != *b"\r\n" {
        return Err(anyhow!("invalid trojan udp packet separator"));
    }
    let mut payload = vec![0u8; payload_len];
    reader.read_exact(&mut payload).await?;
    Ok((destination, payload))
}

const VLESS_CMD_TCP: u8 = 0x01;
const VLESS_CMD_UDP: u8 = 0x02;

#[cfg(test)]
fn build_vless_request(user_id: &Uuid, destination: &Destination) -> anyhow::Result<Vec<u8>> {
    build_vless_request_with_flow(user_id, destination, None)
}

fn build_vless_request_with_flow(
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

const REALITY_CLIENT_VERSION: [u8; 3] = [1, 8, 24];
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

fn decode_reality_public_key(value: &str) -> anyhow::Result<X25519PublicKey> {
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

fn decode_reality_short_id(value: Option<&str>) -> anyhow::Result<Vec<u8>> {
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
fn seal_reality_session_id(
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

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::ServerConfig;
    use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    struct ContextRecordingOutbound {
        trace_id: Arc<StdMutex<Option<String>>>,
    }

    struct PendingOutbound;

    #[async_trait]
    impl Outbound for PendingOutbound {
        fn name(&self) -> &str {
            "pending"
        }

        fn kind(&self) -> &'static str {
            "test"
        }

        fn capability(&self) -> OutboundCapability {
            OutboundCapability::tcp_only("test outbound")
        }

        async fn connect(
            &self,
            _destination: &Destination,
            _timeout_ms: u64,
        ) -> anyhow::Result<BoxedStream> {
            std::future::pending().await
        }
    }

    #[async_trait]
    impl Outbound for ContextRecordingOutbound {
        fn name(&self) -> &str {
            "context-recorder"
        }

        fn kind(&self) -> &'static str {
            "test"
        }

        fn capability(&self) -> OutboundCapability {
            OutboundCapability::tcp_only("test outbound")
        }

        async fn connect(
            &self,
            _destination: &Destination,
            _timeout_ms: u64,
        ) -> anyhow::Result<BoxedStream> {
            let (stream, peer) = tokio::io::duplex(64);
            drop(peer);
            Ok(Box::new(stream))
        }

        async fn connect_context(&self, context: &DialContext) -> anyhow::Result<BoxedStream> {
            *self.trace_id.lock().expect("trace lock") = Some(context.trace_id.clone());
            self.connect(&context.destination, context.timeout_ms())
                .await
        }
    }

    #[tokio::test]
    async fn group_propagates_dial_context_to_selected_member() {
        let recorded = Arc::new(StdMutex::new(None));
        let member: Arc<dyn Outbound> = Arc::new(ContextRecordingOutbound {
            trace_id: Arc::clone(&recorded),
        });
        let group = GroupOutbound::new(
            "group".to_string(),
            "select".to_string(),
            vec![member],
            None,
        );
        let context = DialContext::new(Destination::new("example.com", 443), 500);
        let expected = context.trace_id.clone();
        group
            .connect_context(&context)
            .await
            .expect("group connect");
        assert_eq!(
            recorded.lock().expect("trace lock").as_deref(),
            Some(expected.as_str())
        );
    }

    #[tokio::test]
    async fn dial_context_cancellation_stops_pending_outbound() {
        let outbound = PendingOutbound;
        let context = DialContext::new(Destination::new("example.com", 443), 30_000);
        context.cancel();
        let error = match outbound.connect_context(&context).await {
            Ok(_) => panic!("cancelled dial should fail"),
            Err(error) => error,
        };
        assert_eq!(
            error
                .downcast_ref::<OutboundError>()
                .map(|error| error.kind),
            Some(OutboundErrorKind::Cancelled)
        );
    }

    #[tokio::test]
    async fn shadowsocks_outbound_encrypts_tcp_stream() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let password = "correct horse battery staple".to_string();
        let destination = Destination::new("target.example", 443);
        let mut expected_destination = Vec::new();
        encode_socks5_destination(&destination, &mut expected_destination).unwrap();
        let server_password = password.clone();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let cipher = SsCipher::Aes128Gcm;
            let master_key = evp_bytes_to_key(server_password.as_bytes(), cipher.key_len());
            let mut salt = vec![0u8; cipher.salt_len()];
            stream.read_exact(&mut salt).await.unwrap();
            let subkey = cipher.derive_subkey(&master_key, &salt).unwrap();

            let mut inbound_nonce = [0u8; SS_NONCE_LEN];
            let destination_payload =
                read_ss_chunk(cipher, &subkey, &mut inbound_nonce, &mut stream)
                    .await
                    .unwrap()
                    .unwrap();
            assert_eq!(destination_payload, expected_destination);

            let payload = read_ss_chunk(cipher, &subkey, &mut inbound_nonce, &mut stream)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(payload, b"ping");

            let response_salt = vec![0x42; cipher.salt_len()];
            let response_key = cipher.derive_subkey(&master_key, &response_salt).unwrap();
            stream.write_all(&response_salt).await.unwrap();
            let mut outbound_nonce = [0u8; SS_NONCE_LEN];
            write_ss_chunk(
                cipher,
                &response_key,
                &mut outbound_nonce,
                &mut stream,
                b"pong",
            )
            .await
            .unwrap();
        });

        let outbound = ShadowsocksOutbound::new(
            "ss-test".to_string(),
            "127.0.0.1".to_string(),
            listen_addr.port(),
            "aes-128-gcm".to_string(),
            password,
            None,
        );
        let mut stream = outbound.connect(&destination, 1000).await.unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut response = [0u8; 4];
        stream.read_exact(&mut response).await.unwrap();

        assert_eq!(&response, b"pong");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn shadowsocks_simple_obfs_http_wraps_first_packet() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let password = "secret".to_string();
        let destination = Destination::new("target.example", 443);
        let mut expected_destination = Vec::new();
        encode_socks5_destination(&destination, &mut expected_destination).unwrap();
        let server_password = password.clone();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut first_packet = Vec::new();
            let mut buf = [0u8; 512];
            loop {
                let n = stream.read(&mut buf).await.unwrap();
                assert!(n > 0);
                first_packet.extend_from_slice(&buf[..n]);
                if let Some(index) = find_header_end(&first_packet) {
                    let header_bytes = first_packet[..index].to_vec();
                    let mut body = first_packet[index..].to_vec();
                    let header = String::from_utf8(header_bytes).unwrap();
                    assert!(header.starts_with("GET / HTTP/1.1"));
                    assert!(header.contains("Host: edge.example.com"));
                    assert!(header.contains("Upgrade: websocket"));
                    let content_length = header
                        .lines()
                        .find_map(|line| {
                            line.split_once(':').and_then(|(name, value)| {
                                name.eq_ignore_ascii_case("content-length")
                                    .then(|| value.trim().parse::<usize>().ok())
                                    .flatten()
                            })
                        })
                        .unwrap();
                    while body.len() < content_length {
                        let n = stream.read(&mut buf).await.unwrap();
                        assert!(n > 0);
                        body.extend_from_slice(&buf[..n]);
                    }

                    let cipher = SsCipher::Aes128Gcm;
                    let master_key = evp_bytes_to_key(server_password.as_bytes(), cipher.key_len());
                    let salt = body[..cipher.salt_len()].to_vec();
                    let subkey = cipher.derive_subkey(&master_key, &salt).unwrap();
                    let mut inbound_nonce = [0u8; SS_NONCE_LEN];
                    let mut body_reader = Cursor::new(body.split_off(cipher.salt_len()));
                    let destination_payload =
                        read_ss_chunk(cipher, &subkey, &mut inbound_nonce, &mut body_reader)
                            .await
                            .unwrap()
                            .unwrap();
                    assert_eq!(destination_payload, expected_destination);

                    stream
                        .write_all(
                            b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\n\r\n",
                        )
                        .await
                        .unwrap();
                    let response_salt = vec![0x42; cipher.salt_len()];
                    let response_key = cipher.derive_subkey(&master_key, &response_salt).unwrap();
                    stream.write_all(&response_salt).await.unwrap();
                    let mut outbound_nonce = [0u8; SS_NONCE_LEN];
                    write_ss_chunk(
                        cipher,
                        &response_key,
                        &mut outbound_nonce,
                        &mut stream,
                        b"pong",
                    )
                    .await
                    .unwrap();
                    break;
                }
            }
        });

        let outbound = ShadowsocksOutbound::new(
            "ss-obfs-test".to_string(),
            "127.0.0.1".to_string(),
            listen_addr.port(),
            "aes-128-gcm".to_string(),
            password,
            Some(ShadowsocksPluginConfig {
                mode: "http_simple".to_string(),
                host: Some("edge.example.com".to_string()),
                path: None,
                tls: false,
                skip_cert_verify: false,
            }),
        );
        let mut stream = outbound.connect(&destination, 1000).await.unwrap();
        let mut response = [0u8; 4];
        stream.read_exact(&mut response).await.unwrap();

        assert_eq!(&response, b"pong");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn shadowsocks_simple_obfs_tls_wraps_stream() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let password = "secret".to_string();
        let destination = Destination::new("target.example", 443);
        let mut expected_destination = Vec::new();
        encode_socks5_destination(&destination, &mut expected_destination).unwrap();
        let server_password = password.clone();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (record_type, _version, client_hello) = read_simple_obfs_tls_record(&mut stream)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(record_type, 0x16);
            assert_eq!(client_hello[0], 0x01);
            assert_eq!(&client_hello[4..6], &[0x03, 0x03]);
            assert!(client_hello
                .windows("edge.example.com".len())
                .any(|window| window == b"edge.example.com"));
            let ticket_offset = SIMPLE_OBFS_TLS_FIXED_CLIENT_HELLO_LEN - 5;
            assert_eq!(
                &client_hello[ticket_offset..ticket_offset + 2],
                &[0x00, 0x23]
            );
            let ticket_len = u16::from_be_bytes([
                client_hello[ticket_offset + 2],
                client_hello[ticket_offset + 3],
            ]) as usize;
            let body_start = ticket_offset + SIMPLE_OBFS_TLS_SESSION_TICKET_HEADER_LEN;
            let body_end = body_start + ticket_len;
            let body = client_hello[body_start..body_end].to_vec();

            let cipher = SsCipher::Aes128Gcm;
            let master_key = evp_bytes_to_key(server_password.as_bytes(), cipher.key_len());
            let salt = body[..cipher.salt_len()].to_vec();
            let subkey = cipher.derive_subkey(&master_key, &salt).unwrap();
            let mut inbound_nonce = [0u8; SS_NONCE_LEN];
            let mut body_reader = Cursor::new(body[cipher.salt_len()..].to_vec());
            let destination_payload =
                read_ss_chunk(cipher, &subkey, &mut inbound_nonce, &mut body_reader)
                    .await
                    .unwrap()
                    .unwrap();
            assert_eq!(destination_payload, expected_destination);

            let (record_type, _version, upload) = read_simple_obfs_tls_record(&mut stream)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(record_type, 0x17);
            let mut upload_reader = Cursor::new(upload);
            let payload = read_ss_chunk(cipher, &subkey, &mut inbound_nonce, &mut upload_reader)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(payload, b"ping");

            let response_salt = vec![0x42; cipher.salt_len()];
            let response_key = cipher.derive_subkey(&master_key, &response_salt).unwrap();
            let mut outbound_nonce = [0u8; SS_NONCE_LEN];
            let response_chunk =
                encode_ss_chunk(cipher, &response_key, &mut outbound_nonce, b"pong").unwrap();
            let mut response_payload = response_salt;
            response_payload.extend_from_slice(&response_chunk);
            let mut response = vec![
                0x16, 0x03, 0x01, 0x00, 0x00, 0x14, 0x03, 0x03, 0x00, 0x01, 0x01,
            ];
            response.extend_from_slice(&[0x16, 0x03, 0x03]);
            response.extend_from_slice(&(response_payload.len() as u16).to_be_bytes());
            response.extend_from_slice(&response_payload);
            stream.write_all(&response).await.unwrap();
        });

        let outbound = ShadowsocksOutbound::new(
            "ss-obfs-tls-test".to_string(),
            "127.0.0.1".to_string(),
            listen_addr.port(),
            "aes-128-gcm".to_string(),
            password,
            Some(ShadowsocksPluginConfig {
                mode: "tls".to_string(),
                host: Some("edge.example.com".to_string()),
                path: None,
                tls: false,
                skip_cert_verify: false,
            }),
        );
        let mut stream = outbound.connect(&destination, 1000).await.unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut response = [0u8; 4];
        stream.read_exact(&mut response).await.unwrap();

        assert_eq!(&response, b"pong");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn shadowsocks_v2ray_plugin_websocket_real_dial() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let password = "secret".to_string();
        let server_password = password.clone();
        let destination = Destination::new("target.example", 443);
        let mut expected_destination = Vec::new();
        encode_socks5_destination(&destination, &mut expected_destination).unwrap();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buffer = [0u8; 512];
            let header_end = loop {
                let count = stream.read(&mut buffer).await.unwrap();
                assert!(count > 0);
                request.extend_from_slice(&buffer[..count]);
                if let Some(index) = find_header_end(&request) {
                    break index;
                }
            };
            let header = String::from_utf8(request[..header_end].to_vec()).unwrap();
            assert!(header.starts_with("GET /ss HTTP/1.1"));
            assert!(header.contains("Host: cdn.example.com"));
            let key = header
                .lines()
                .find_map(|line| {
                    line.split_once(':').and_then(|(name, value)| {
                        name.eq_ignore_ascii_case("sec-websocket-key")
                            .then(|| value.trim().to_string())
                    })
                })
                .unwrap();
            let response = format!(
                "HTTP/1.1 101 Switching Protocols\r\n\
                 Upgrade: websocket\r\n\
                 Connection: Upgrade\r\n\
                 Sec-WebSocket-Accept: {}\r\n\
                 \r\n",
                websocket_accept_key(&key)
            );
            stream.write_all(response.as_bytes()).await.unwrap();

            let request = read_websocket_frame(&mut stream).await.unwrap().unwrap();
            let cipher = SsCipher::Aes128Gcm;
            let master_key = cipher.master_key(server_password.as_bytes()).unwrap();
            let request_salt = &request[..cipher.salt_len()];
            let request_key = cipher.derive_subkey(&master_key, request_salt).unwrap();
            let mut request_nonce = vec![0u8; cipher.nonce_len()];
            let mut request_reader = Cursor::new(&request[cipher.salt_len()..]);
            let target = read_ss_chunk(
                cipher,
                &request_key,
                &mut request_nonce,
                &mut request_reader,
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(target, expected_destination);

            let payload = read_websocket_frame(&mut stream).await.unwrap().unwrap();
            let mut payload_reader = Cursor::new(payload);
            let payload = read_ss_chunk(
                cipher,
                &request_key,
                &mut request_nonce,
                &mut payload_reader,
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(payload, b"ping");

            let response_salt = vec![0x42; cipher.salt_len()];
            let response_key = cipher.derive_subkey(&master_key, &response_salt).unwrap();
            let mut response_nonce = vec![0u8; cipher.nonce_len()];
            let response_chunk =
                encode_ss_chunk(cipher, &response_key, &mut response_nonce, b"pong").unwrap();
            let mut response = response_salt;
            response.extend_from_slice(&response_chunk);
            write_websocket_frame(&mut stream, 0x2, &response)
                .await
                .unwrap();
        });

        let outbound = ShadowsocksOutbound::new(
            "ss-v2ray-plugin-test".to_string(),
            "127.0.0.1".to_string(),
            listen_addr.port(),
            "aes-128-gcm".to_string(),
            password,
            Some(ShadowsocksPluginConfig {
                mode: "v2ray-plugin".to_string(),
                host: Some("cdn.example.com".to_string()),
                path: Some("/ss".to_string()),
                tls: false,
                skip_cert_verify: false,
            }),
        );
        let mut stream = outbound.connect(&destination, 1000).await.unwrap();
        stream.write_all(b"ping").await.unwrap();
        stream.flush().await.unwrap();
        let mut response = [0u8; 4];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"pong");
        server.await.unwrap();
    }

    #[test]
    fn shadowsocks_rejects_unsupported_method() {
        let error = SsCipher::from_method("rc4-md5").unwrap_err();
        assert!(error.to_string().contains("unsupported shadowsocks method"));
    }

    #[tokio::test]
    async fn trojan_outbound_sends_valid_connect_request_over_tls() {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_der = CertificateDer::from(cert.cert.der().to_vec());
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()));
        let provider = aws_lc_rs::default_provider();
        let server_config = ServerConfig::builder_with_provider(provider.into())
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let destination = Destination::new("target.example", 443);
        let mut expected_destination = Vec::new();
        encode_socks5_destination(&destination, &mut expected_destination).unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = acceptor.accept(stream).await.unwrap();
            let mut request = Vec::new();
            let mut buf = [0u8; 512];
            loop {
                let n = stream.read(&mut buf).await.unwrap();
                assert!(n > 0);
                request.extend_from_slice(&buf[..n]);
                if request.ends_with(b"\r\n")
                    && request.len() >= 56 + 2 + 1 + expected_destination.len() + 2
                {
                    break;
                }
            }

            let expected_hash = hex_lower(&Sha224::digest(b"secret"));
            assert_eq!(&request[..56], expected_hash.as_bytes());
            assert_eq!(&request[56..58], b"\r\n");
            assert_eq!(request[58], 0x01);
            assert_eq!(
                &request[59..59 + expected_destination.len()],
                expected_destination.as_slice()
            );
            assert_eq!(
                &request[59 + expected_destination.len()..61 + expected_destination.len()],
                b"\r\n"
            );
            stream.write_all(b"pong").await.unwrap();
        });

        let outbound = TrojanOutbound {
            name: "trojan-test".to_string(),
            server: "127.0.0.1".to_string(),
            port: listen_addr.port(),
            password: "secret".to_string(),
            sni: Some("localhost".to_string()),
            skip_cert_verify: true,
            network: None,
            ws_path: None,
            ws_host: None,
            grpc_service_name: None,
            transport_headers: BTreeMap::new(),
            alpn: Vec::new(),
            udp_sessions: TokioMutex::new(TrojanUdpPool::default()),
        };
        let mut stream = outbound.connect(&destination, 1000).await.unwrap();
        let mut response = [0u8; 4];
        stream.read_exact(&mut response).await.unwrap();

        assert_eq!(&response, b"pong");
        server.await.unwrap();
    }

    #[test]
    fn trojan_request_uses_sha224_password_hash() {
        let request =
            build_trojan_request("secret", &Destination::new("example.com", 443)).unwrap();

        assert_eq!(
            &request[..56],
            hex_lower(&Sha224::digest(b"secret")).as_bytes()
        );
        assert_eq!(&request[56..58], b"\r\n");
        assert_eq!(request[58], 0x01);
    }

    #[test]
    fn trojan_transport_alpn_rejects_incompatible_protocols() {
        let grpc_error = trojan_alpn_protocols("grpc", &["http/1.1".to_string()])
            .expect_err("gRPC without h2 must fail");
        assert!(grpc_error.to_string().contains("requires h2"));

        let ws_error = trojan_alpn_protocols("ws", &["h2".to_string()])
            .expect_err("WebSocket without http/1.1 must fail");
        assert!(ws_error.to_string().contains("requires http/1.1"));
    }

    #[test]
    fn transport_headers_reject_line_injection() {
        let headers =
            BTreeMap::from([("X-Test".to_string(), "safe\r\nInjected: true".to_string())]);
        let error = render_transport_headers(&headers, &[])
            .expect_err("header line injection must be rejected");
        assert!(error.to_string().contains("invalid transport header value"));
    }

    #[test]
    fn shadowsocks_2022_udp_replay_window_rejects_duplicates_and_old_packets() {
        let mut window = Ss2022ReplayWindow::default();
        assert!(window.accept(100));
        assert!(!window.accept(100));
        assert!(window.accept(99));
        assert!(window.accept(164));
        assert!(!window.accept(99));
        assert!(!window.accept(90));
    }

    #[tokio::test]
    async fn vless_outbound_sends_valid_tcp_request_over_tls_and_strips_response_header() {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_der = CertificateDer::from(cert.cert.der().to_vec());
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()));
        let provider = aws_lc_rs::default_provider();
        let server_config = ServerConfig::builder_with_provider(provider.into())
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let destination = Destination::new("target.example", 443);
        let user_id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = acceptor.accept(stream).await.unwrap();
            let mut fixed = [0u8; 1 + 16 + 1 + 1 + 2 + 1];
            stream.read_exact(&mut fixed).await.unwrap();
            assert_eq!(fixed[0], 0x00);
            assert_eq!(&fixed[1..17], user_id.as_bytes());
            assert_eq!(fixed[17], 0x00);
            assert_eq!(fixed[18], 0x01);
            assert_eq!(u16::from_be_bytes([fixed[19], fixed[20]]), 443);
            assert_eq!(fixed[21], 0x02);

            let mut domain_len = [0u8; 1];
            stream.read_exact(&mut domain_len).await.unwrap();
            let mut domain = vec![0u8; domain_len[0] as usize];
            stream.read_exact(&mut domain).await.unwrap();
            assert_eq!(domain, b"target.example");

            stream.write_all(&[0x00, 0x00]).await.unwrap();
            let mut payload = [0u8; 4];
            stream.read_exact(&mut payload).await.unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong").await.unwrap();
        });

        let outbound = VlessOutbound {
            name: "vless-test".to_string(),
            server: "127.0.0.1".to_string(),
            port: listen_addr.port(),
            uuid: "11111111-1111-1111-1111-111111111111".to_string(),
            flow: None,
            security: None,
            tls: true,
            sni: Some("localhost".to_string()),
            skip_cert_verify: true,
            network: None,
            ws_path: None,
            ws_host: None,
            grpc_service_name: None,
            reality_public_key: None,
            reality_short_id: None,
            reality_fingerprint: None,
            reality_spider_x: None,
            udp_sessions: TokioMutex::new(VlessUdpPool::default()),
        };
        let mut stream = outbound.connect(&destination, 1000).await.unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut response = [0u8; 4];
        stream.read_exact(&mut response).await.unwrap();

        assert_eq!(&response, b"pong");
        server.await.unwrap();
    }

    #[test]
    fn websocket_accept_key_matches_rfc_example() {
        assert_eq!(
            websocket_accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[tokio::test]
    async fn websocket_client_frames_are_masked_and_decodable() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let writer = tokio::spawn(async move {
            write_websocket_binary_frame(&mut client, b"hello")
                .await
                .unwrap();
        });

        let mut header = [0u8; 2];
        server.read_exact(&mut header).await.unwrap();
        assert_eq!(header[0], 0x82);
        assert_eq!(header[1] & 0x80, 0x80);
        assert_eq!(header[1] & 0x7f, 5);
        let mut mask = [0u8; 4];
        server.read_exact(&mut mask).await.unwrap();
        let mut payload = [0u8; 5];
        server.read_exact(&mut payload).await.unwrap();
        for (index, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask[index % 4];
        }
        assert_eq!(&payload, b"hello");
        writer.await.unwrap();
    }

    #[tokio::test]
    async fn vless_outbound_supports_websocket_transport() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let destination = Destination::new("target.example", 443);
        let user_id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buf = [0u8; 512];
            let header_end = loop {
                let n = stream.read(&mut buf).await.unwrap();
                assert!(n > 0);
                request.extend_from_slice(&buf[..n]);
                if let Some(index) = find_header_end(&request) {
                    break index;
                }
            };
            let header = String::from_utf8(request[..header_end].to_vec()).unwrap();
            assert!(header.starts_with("GET /ray HTTP/1.1"));
            assert!(header.contains("Host: cdn.example.com"));
            let key = header
                .lines()
                .find_map(|line| {
                    line.split_once(':').and_then(|(name, value)| {
                        name.eq_ignore_ascii_case("sec-websocket-key")
                            .then(|| value.trim().to_string())
                    })
                })
                .unwrap();
            let response = format!(
                "HTTP/1.1 101 Switching Protocols\r\n\
                 Upgrade: websocket\r\n\
                 Connection: Upgrade\r\n\
                 Sec-WebSocket-Accept: {}\r\n\
                 \r\n",
                websocket_accept_key(&key)
            );
            stream.write_all(response.as_bytes()).await.unwrap();

            let request_payload = read_websocket_frame(&mut stream).await.unwrap().unwrap();
            assert_eq!(request_payload[0], 0x00);
            assert_eq!(&request_payload[1..17], user_id.as_bytes());
            assert_eq!(request_payload[17], 0x00);
            assert_eq!(request_payload[18], 0x01);
            assert_eq!(
                u16::from_be_bytes([request_payload[19], request_payload[20]]),
                443
            );
            assert_eq!(request_payload[21], 0x02);
            assert_eq!(request_payload[22], "target.example".len() as u8);
            assert_eq!(&request_payload[23..], b"target.example");

            write_websocket_frame(&mut stream, 0x2, &[0x00, 0x00])
                .await
                .unwrap();
            let payload = read_websocket_frame(&mut stream).await.unwrap().unwrap();
            assert_eq!(payload, b"ping");
            write_websocket_frame(&mut stream, 0x2, b"pong")
                .await
                .unwrap();
        });

        let outbound = VlessOutbound {
            name: "vless-ws-test".to_string(),
            server: "127.0.0.1".to_string(),
            port: listen_addr.port(),
            uuid: "11111111-1111-1111-1111-111111111111".to_string(),
            flow: None,
            security: None,
            tls: false,
            sni: None,
            skip_cert_verify: false,
            network: Some("ws".to_string()),
            ws_path: Some("/ray".to_string()),
            ws_host: Some("cdn.example.com".to_string()),
            grpc_service_name: None,
            reality_public_key: None,
            reality_short_id: None,
            reality_fingerprint: None,
            reality_spider_x: None,
            udp_sessions: TokioMutex::new(VlessUdpPool::default()),
        };
        let mut stream = outbound.connect(&destination, 1000).await.unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut response = [0u8; 4];
        stream.read_exact(&mut response).await.unwrap();

        assert_eq!(&response, b"pong");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn vless_outbound_supports_grpc_transport() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let destination = Destination::new("target.example", 443);
        let user_id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut h2 = h2::server::handshake(stream).await.unwrap();
            let (request, mut respond) = h2.accept().await.unwrap().unwrap();
            let handler = tokio::spawn(async move {
                assert_eq!(request.uri().path(), "/ray/Tun");
                assert_eq!(
                    request
                        .headers()
                        .get(http::header::CONTENT_TYPE)
                        .and_then(|value| value.to_str().ok()),
                    Some("application/grpc")
                );
                let mut body = request.into_body();
                let request_payload = read_grpc_message_for_test(&mut body).await;
                assert_eq!(request_payload[0], 0x00);
                assert_eq!(&request_payload[1..17], user_id.as_bytes());
                assert_eq!(request_payload[17], 0x00);
                assert_eq!(request_payload[18], 0x01);
                assert_eq!(
                    u16::from_be_bytes([request_payload[19], request_payload[20]]),
                    443
                );
                assert_eq!(request_payload[21], 0x02);
                assert_eq!(request_payload[22], "target.example".len() as u8);
                assert_eq!(&request_payload[23..], b"target.example");

                let response = http::Response::builder()
                    .status(200)
                    .header(http::header::CONTENT_TYPE, "application/grpc")
                    .body(())
                    .unwrap();
                let mut send = respond.send_response(response, false).unwrap();
                send.send_data(grpc_frame_for_test(&[0x00, 0x00]), false)
                    .unwrap();

                let payload = read_grpc_message_for_test(&mut body).await;
                assert_eq!(payload, b"ping");
                send.send_data(grpc_frame_for_test(b"pong"), false).unwrap();
            });
            let driver = tokio::spawn(async move { while h2.accept().await.is_some() {} });
            handler.await.unwrap();
            driver.abort();
        });

        let outbound = VlessOutbound {
            name: "vless-grpc-test".to_string(),
            server: "127.0.0.1".to_string(),
            port: listen_addr.port(),
            uuid: "11111111-1111-1111-1111-111111111111".to_string(),
            flow: None,
            security: None,
            tls: false,
            sni: None,
            skip_cert_verify: false,
            network: Some("grpc".to_string()),
            ws_path: None,
            ws_host: Some("cdn.example.com".to_string()),
            grpc_service_name: Some("ray".to_string()),
            reality_public_key: None,
            reality_short_id: None,
            reality_fingerprint: None,
            reality_spider_x: None,
            udp_sessions: TokioMutex::new(VlessUdpPool::default()),
        };
        let mut stream =
            tokio::time::timeout(Duration::from_secs(2), outbound.connect(&destination, 1000))
                .await
                .expect("vless grpc connect timed out")
                .unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut response = [0u8; 4];
        tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut response))
            .await
            .expect("vless grpc read timed out")
            .unwrap();

        assert_eq!(&response, b"pong");
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("vless grpc server timed out")
            .unwrap();
    }

    #[tokio::test]
    async fn vless_outbound_supports_h2_transport() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let destination = Destination::new("target.example", 443);
        let user_id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut h2 = h2::server::handshake(stream).await.unwrap();
            let (request, mut respond) = h2.accept().await.unwrap().unwrap();
            let handler = tokio::spawn(async move {
                assert_eq!(request.method(), http::Method::PUT);
                assert_eq!(request.uri().path(), "/h2");
                let mut body = H2BodyReaderForTest::new(request.into_body());
                let mut fixed = [0u8; 23];
                body.read_exact(&mut fixed).await.unwrap();
                assert_eq!(fixed[0], 0x00);
                assert_eq!(&fixed[1..17], user_id.as_bytes());
                assert_eq!(fixed[17], 0x00);
                assert_eq!(fixed[18], 0x01);
                assert_eq!(u16::from_be_bytes([fixed[19], fixed[20]]), 443);
                assert_eq!(fixed[21], 0x02);
                assert_eq!(fixed[22], "target.example".len() as u8);
                let mut domain = vec![0u8; "target.example".len()];
                body.read_exact(&mut domain).await.unwrap();
                assert_eq!(domain, b"target.example");

                let response = http::Response::builder().status(200).body(()).unwrap();
                let mut send = respond.send_response(response, false).unwrap();
                send.send_data(Bytes::from_static(&[0x00, 0x00]), false)
                    .unwrap();

                let mut payload = [0u8; 4];
                body.read_exact(&mut payload).await.unwrap();
                assert_eq!(&payload, b"ping");
                send.send_data(Bytes::from_static(b"pong"), false).unwrap();
            });
            let driver = tokio::spawn(async move { while h2.accept().await.is_some() {} });
            handler.await.unwrap();
            driver.abort();
        });

        let outbound = VlessOutbound {
            name: "vless-h2-test".to_string(),
            server: "127.0.0.1".to_string(),
            port: listen_addr.port(),
            uuid: "11111111-1111-1111-1111-111111111111".to_string(),
            flow: None,
            security: None,
            tls: false,
            sni: None,
            skip_cert_verify: false,
            network: Some("h2".to_string()),
            ws_path: Some("/h2".to_string()),
            ws_host: Some("cdn.example.com".to_string()),
            grpc_service_name: None,
            reality_public_key: None,
            reality_short_id: None,
            reality_fingerprint: None,
            reality_spider_x: None,
            udp_sessions: TokioMutex::new(VlessUdpPool::default()),
        };
        let mut stream =
            tokio::time::timeout(Duration::from_secs(2), outbound.connect(&destination, 1000))
                .await
                .expect("vless h2 connect timed out")
                .unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut response = [0u8; 4];
        tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut response))
            .await
            .expect("vless h2 read timed out")
            .unwrap();

        assert_eq!(&response, b"pong");
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("vless h2 server timed out")
            .unwrap();
    }

    #[tokio::test]
    async fn vmess_outbound_supports_tcp_aead_stream() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let destination = Destination::new("target.example", 443);
        let expected_destination = destination.clone();
        let user_id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let setup = read_vmess_client_setup_for_test(&mut stream, &user_id).await;
            assert_eq!(setup.destination, expected_destination);
            assert_eq!(setup.cipher, VmessCipher::Chacha20Poly1305);

            let mut client_reader = VmessDownloadState {
                response_header_key: [0u8; 16],
                response_header_iv: [0u8; 16],
                response_authentication: setup.response_authentication,
                cipher: VmessAeadState::new(setup.cipher, &setup.data_key, &setup.data_iv).unwrap(),
                length_mask: VmessLengthMask::new(&setup.data_iv),
            };
            let payload = read_vmess_chunk(&mut stream, &mut client_reader)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(payload, b"ping");

            write_vmess_response_header_for_test(
                &mut stream,
                &setup.response_header_key,
                &setup.response_header_iv,
                setup.response_authentication,
            )
            .await;
            let mut server_writer = VmessUploadState {
                cipher: VmessAeadState::new(
                    setup.cipher,
                    &setup.response_header_key,
                    &setup.response_header_iv,
                )
                .unwrap(),
                length_mask: VmessLengthMask::new(&setup.response_header_iv),
            };
            write_vmess_chunk(&mut stream, &mut server_writer, b"pong")
                .await
                .unwrap();
        });

        let outbound = VmessOutbound {
            name: "vmess-test".to_string(),
            server: "127.0.0.1".to_string(),
            port: listen_addr.port(),
            uuid: "11111111-1111-1111-1111-111111111111".to_string(),
            cipher: "auto".to_string(),
            tls: false,
            sni: None,
            skip_cert_verify: false,
            network: None,
            ws_path: None,
            ws_host: None,
            grpc_service_name: None,
            udp_sessions: TokioMutex::new(VmessUdpPool::default()),
        };
        let mut stream = outbound.connect(&destination, 1000).await.unwrap();
        stream.write_all(b"ping").await.unwrap();
        stream.flush().await.unwrap();
        let mut response = [0u8; 4];
        stream.read_exact(&mut response).await.unwrap();

        assert_eq!(&response, b"pong");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn vmess_outbound_supports_grpc_transport() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let destination = Destination::new("target.example", 443);
        let expected_destination = destination.clone();
        let user_id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut h2 = h2::server::handshake(stream).await.unwrap();
            let (request, mut respond) = h2.accept().await.unwrap().unwrap();
            let handler = tokio::spawn(async move {
                assert_eq!(request.uri().path(), "/vmess/Tun");
                let mut body = GrpcBodyReaderForTest::new(request.into_body());
                let setup = read_vmess_client_setup_for_test(&mut body, &user_id).await;
                assert_eq!(setup.destination, expected_destination);
                assert_eq!(setup.cipher, VmessCipher::Chacha20Poly1305);

                let response = http::Response::builder()
                    .status(200)
                    .header(http::header::CONTENT_TYPE, "application/grpc")
                    .body(())
                    .unwrap();
                let mut send = respond.send_response(response, false).unwrap();
                let mut response_header = Vec::new();
                write_vmess_response_header_for_test(
                    &mut response_header,
                    &setup.response_header_key,
                    &setup.response_header_iv,
                    setup.response_authentication,
                )
                .await;
                send.send_data(grpc_frame_for_test(&response_header), false)
                    .unwrap();

                let mut client_reader = VmessDownloadState {
                    response_header_key: [0u8; 16],
                    response_header_iv: [0u8; 16],
                    response_authentication: setup.response_authentication,
                    cipher: VmessAeadState::new(setup.cipher, &setup.data_key, &setup.data_iv)
                        .unwrap(),
                    length_mask: VmessLengthMask::new(&setup.data_iv),
                };
                let payload = read_vmess_chunk(&mut body, &mut client_reader)
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(payload, b"ping");

                let mut server_writer = VmessUploadState {
                    cipher: VmessAeadState::new(
                        setup.cipher,
                        &setup.response_header_key,
                        &setup.response_header_iv,
                    )
                    .unwrap(),
                    length_mask: VmessLengthMask::new(&setup.response_header_iv),
                };
                let mut response_payload = Vec::new();
                write_vmess_chunk(&mut response_payload, &mut server_writer, b"pong")
                    .await
                    .unwrap();
                send.send_data(grpc_frame_for_test(&response_payload), false)
                    .unwrap();
            });
            let driver = tokio::spawn(async move { while h2.accept().await.is_some() {} });
            handler.await.unwrap();
            driver.abort();
        });

        let outbound = VmessOutbound {
            name: "vmess-grpc-test".to_string(),
            server: "127.0.0.1".to_string(),
            port: listen_addr.port(),
            uuid: "11111111-1111-1111-1111-111111111111".to_string(),
            cipher: "auto".to_string(),
            tls: false,
            sni: None,
            skip_cert_verify: false,
            network: Some("grpc".to_string()),
            ws_path: None,
            ws_host: Some("cdn.example.com".to_string()),
            grpc_service_name: Some("vmess".to_string()),
            udp_sessions: TokioMutex::new(VmessUdpPool::default()),
        };
        let mut stream =
            tokio::time::timeout(Duration::from_secs(2), outbound.connect(&destination, 1000))
                .await
                .expect("vmess grpc connect timed out")
                .unwrap();
        stream.write_all(b"ping").await.unwrap();
        stream.flush().await.unwrap();
        let mut response = [0u8; 4];
        tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut response))
            .await
            .expect("vmess grpc read timed out")
            .unwrap();

        assert_eq!(&response, b"pong");
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("vmess grpc server timed out")
            .unwrap();
    }

    #[tokio::test]
    async fn vmess_outbound_supports_h2_transport() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let destination = Destination::new("target.example", 443);
        let expected_destination = destination.clone();
        let user_id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut h2 = h2::server::handshake(stream).await.unwrap();
            let (request, mut respond) = h2.accept().await.unwrap().unwrap();
            let handler = tokio::spawn(async move {
                assert_eq!(request.method(), http::Method::PUT);
                assert_eq!(request.uri().path(), "/vmess-h2");
                let mut body = H2BodyReaderForTest::new(request.into_body());
                let setup = read_vmess_client_setup_for_test(&mut body, &user_id).await;
                assert_eq!(setup.destination, expected_destination);
                assert_eq!(setup.cipher, VmessCipher::Chacha20Poly1305);

                let response = http::Response::builder().status(200).body(()).unwrap();
                let mut send = respond.send_response(response, false).unwrap();
                let mut response_header = Vec::new();
                write_vmess_response_header_for_test(
                    &mut response_header,
                    &setup.response_header_key,
                    &setup.response_header_iv,
                    setup.response_authentication,
                )
                .await;
                send.send_data(Bytes::from(response_header), false).unwrap();

                let mut client_reader = VmessDownloadState {
                    response_header_key: [0u8; 16],
                    response_header_iv: [0u8; 16],
                    response_authentication: setup.response_authentication,
                    cipher: VmessAeadState::new(setup.cipher, &setup.data_key, &setup.data_iv)
                        .unwrap(),
                    length_mask: VmessLengthMask::new(&setup.data_iv),
                };
                let payload = read_vmess_chunk(&mut body, &mut client_reader)
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(payload, b"ping");

                let mut server_writer = VmessUploadState {
                    cipher: VmessAeadState::new(
                        setup.cipher,
                        &setup.response_header_key,
                        &setup.response_header_iv,
                    )
                    .unwrap(),
                    length_mask: VmessLengthMask::new(&setup.response_header_iv),
                };
                let mut response_payload = Vec::new();
                write_vmess_chunk(&mut response_payload, &mut server_writer, b"pong")
                    .await
                    .unwrap();
                send.send_data(Bytes::from(response_payload), false)
                    .unwrap();
            });
            let driver = tokio::spawn(async move { while h2.accept().await.is_some() {} });
            handler.await.unwrap();
            driver.abort();
        });

        let outbound = VmessOutbound {
            name: "vmess-h2-test".to_string(),
            server: "127.0.0.1".to_string(),
            port: listen_addr.port(),
            uuid: "11111111-1111-1111-1111-111111111111".to_string(),
            cipher: "auto".to_string(),
            tls: false,
            sni: None,
            skip_cert_verify: false,
            network: Some("h2".to_string()),
            ws_path: Some("/vmess-h2".to_string()),
            ws_host: Some("cdn.example.com".to_string()),
            grpc_service_name: None,
            udp_sessions: TokioMutex::new(VmessUdpPool::default()),
        };
        let mut stream =
            tokio::time::timeout(Duration::from_secs(2), outbound.connect(&destination, 1000))
                .await
                .expect("vmess h2 connect timed out")
                .unwrap();
        stream.write_all(b"ping").await.unwrap();
        stream.flush().await.unwrap();
        let mut response = [0u8; 4];
        tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut response))
            .await
            .expect("vmess h2 read timed out")
            .unwrap();

        assert_eq!(&response, b"pong");
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("vmess h2 server timed out")
            .unwrap();
    }

    async fn read_grpc_message_for_test(body: &mut h2::RecvStream) -> Vec<u8> {
        let mut data = BytesMut::new();
        loop {
            let chunk = body.data().await.unwrap().unwrap();
            let len = chunk.len();
            data.extend_from_slice(&chunk);
            body.flow_control().release_capacity(len).unwrap();
            if data.len() < 5 {
                continue;
            }
            let payload_len = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;
            if data.len() < 5 + payload_len {
                continue;
            }
            assert_eq!(data[0], 0);
            bytes::Buf::advance(&mut data, 5);
            return data.split_to(payload_len).to_vec();
        }
    }

    fn grpc_frame_for_test(payload: &[u8]) -> Bytes {
        let mut frame = Vec::with_capacity(5 + payload.len());
        frame.push(0);
        frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        frame.extend_from_slice(payload);
        Bytes::from(frame)
    }

    struct H2BodyReaderForTest {
        body: h2::RecvStream,
        read_buffer: BytesMut,
    }

    impl H2BodyReaderForTest {
        fn new(body: h2::RecvStream) -> Self {
            Self {
                body,
                read_buffer: BytesMut::new(),
            }
        }
    }

    impl AsyncRead for H2BodyReaderForTest {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut TaskContext<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<Result<(), Error>> {
            if buf.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }
            loop {
                if !self.read_buffer.is_empty() {
                    let len = self.read_buffer.len().min(buf.remaining());
                    let chunk = self.read_buffer.split_to(len);
                    buf.put_slice(&chunk);
                    return Poll::Ready(Ok(()));
                }
                match self.body.poll_data(cx) {
                    Poll::Ready(Some(Ok(chunk))) => {
                        let len = chunk.len();
                        self.read_buffer.extend_from_slice(&chunk);
                        let _ = self.body.flow_control().release_capacity(len);
                    }
                    Poll::Ready(Some(Err(error))) => {
                        return Poll::Ready(Err(Error::new(
                            ErrorKind::ConnectionAborted,
                            format!("h2 body failed: {error}"),
                        )));
                    }
                    Poll::Ready(None) => return Poll::Ready(Ok(())),
                    Poll::Pending => return Poll::Pending,
                }
            }
        }
    }

    struct GrpcBodyReaderForTest {
        body: h2::RecvStream,
        incoming: BytesMut,
        read_buffer: BytesMut,
    }

    impl GrpcBodyReaderForTest {
        fn new(body: h2::RecvStream) -> Self {
            Self {
                body,
                incoming: BytesMut::new(),
                read_buffer: BytesMut::new(),
            }
        }

        fn decode_next_message(&mut self) -> bool {
            if self.incoming.len() < 5 {
                return false;
            }
            let payload_len = u32::from_be_bytes([
                self.incoming[1],
                self.incoming[2],
                self.incoming[3],
                self.incoming[4],
            ]) as usize;
            if self.incoming.len() < 5 + payload_len {
                return false;
            }
            assert_eq!(self.incoming[0], 0);
            bytes::Buf::advance(&mut self.incoming, 5);
            let payload = self.incoming.split_to(payload_len);
            self.read_buffer.extend_from_slice(&payload);
            true
        }
    }

    impl AsyncRead for GrpcBodyReaderForTest {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut TaskContext<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<Result<(), Error>> {
            if buf.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }
            loop {
                if !self.read_buffer.is_empty() {
                    let len = self.read_buffer.len().min(buf.remaining());
                    let chunk = self.read_buffer.split_to(len);
                    buf.put_slice(&chunk);
                    return Poll::Ready(Ok(()));
                }
                if self.decode_next_message() {
                    continue;
                }
                match self.body.poll_data(cx) {
                    Poll::Ready(Some(Ok(chunk))) => {
                        let len = chunk.len();
                        self.incoming.extend_from_slice(&chunk);
                        let _ = self.body.flow_control().release_capacity(len);
                    }
                    Poll::Ready(Some(Err(error))) => {
                        return Poll::Ready(Err(Error::new(
                            ErrorKind::ConnectionAborted,
                            format!("grpc body failed: {error}"),
                        )));
                    }
                    Poll::Ready(None) => return Poll::Ready(Ok(())),
                    Poll::Pending => return Poll::Pending,
                }
            }
        }
    }

    struct VmessClientSetupForTest {
        destination: Destination,
        cipher: VmessCipher,
        data_iv: [u8; 16],
        data_key: [u8; 16],
        response_header_iv: [u8; 16],
        response_header_key: [u8; 16],
        response_authentication: u8,
    }

    async fn read_vmess_client_setup_for_test<S>(
        stream: &mut S,
        user_id: &Uuid,
    ) -> VmessClientSetupForTest
    where
        S: AsyncRead + Unpin,
    {
        let instruction_key = vmess_instruction_key(user_id);
        let mut auth_id = [0u8; 16];
        stream.read_exact(&mut auth_id).await.unwrap();
        let mut encrypted_len = [0u8; 18];
        stream.read_exact(&mut encrypted_len).await.unwrap();
        let mut nonce = [0u8; 8];
        stream.read_exact(&mut nonce).await.unwrap();

        let len_key = vmess_kdf(
            &instruction_key,
            &[b"VMess Header AEAD Key_Length", &auth_id, &nonce],
        );
        let len_nonce = vmess_kdf(
            &instruction_key,
            &[b"VMess Header AEAD Nonce_Length", &auth_id, &nonce],
        );
        let len =
            vmess_aes128gcm_decrypt(&len_key[..16], &len_nonce[..12], &auth_id, &encrypted_len)
                .unwrap();
        let header_len = u16::from_be_bytes([len[0], len[1]]) as usize;
        let mut encrypted_header = vec![0u8; header_len + VMESS_TAG_LEN];
        stream.read_exact(&mut encrypted_header).await.unwrap();
        let header_key = vmess_kdf(
            &instruction_key,
            &[b"VMess Header AEAD Key", &auth_id, &nonce],
        );
        let header_nonce = vmess_kdf(
            &instruction_key,
            &[b"VMess Header AEAD Nonce", &auth_id, &nonce],
        );
        let header = vmess_aes128gcm_decrypt(
            &header_key[..16],
            &header_nonce[..12],
            &auth_id,
            &encrypted_header,
        )
        .unwrap();

        assert_eq!(header[0], 0x01);
        assert_eq!(header[34] & 0x01, 0x01);
        assert_eq!(header[34] & 0x04, 0x04);
        assert_eq!(header[37], 0x01);
        let mut data_iv = [0u8; 16];
        data_iv.copy_from_slice(&header[1..17]);
        let mut data_key = [0u8; 16];
        data_key.copy_from_slice(&header[17..33]);
        let response_authentication = header[33];
        let cipher = match header[35] & 0x0f {
            3 => VmessCipher::Aes128Gcm,
            4 => VmessCipher::Chacha20Poly1305,
            5 => VmessCipher::None,
            other => panic!("unexpected vmess cipher {other}"),
        };

        let mut cursor = 38;
        let port = u16::from_be_bytes([header[cursor], header[cursor + 1]]);
        cursor += 2;
        let host = match header[cursor] {
            0x01 => {
                cursor += 1;
                let host = std::net::Ipv4Addr::new(
                    header[cursor],
                    header[cursor + 1],
                    header[cursor + 2],
                    header[cursor + 3],
                )
                .to_string();
                cursor += 4;
                host
            }
            0x02 => {
                cursor += 1;
                let len = header[cursor] as usize;
                cursor += 1;
                let host = std::str::from_utf8(&header[cursor..cursor + len])
                    .unwrap()
                    .to_string();
                cursor += len;
                host
            }
            0x03 => {
                cursor += 1;
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&header[cursor..cursor + 16]);
                cursor += 16;
                std::net::Ipv6Addr::from(octets).to_string()
            }
            other => panic!("unexpected vmess address type {other}"),
        };
        let margin_len = (header[35] >> 4) as usize;
        cursor += margin_len;
        let expected_checksum = u32::from_be_bytes([
            header[cursor],
            header[cursor + 1],
            header[cursor + 2],
            header[cursor + 3],
        ]);
        assert_eq!(expected_checksum, vmess_fnv1a(&header[..cursor]));

        VmessClientSetupForTest {
            destination: Destination::new(host, port),
            cipher,
            data_iv,
            data_key,
            response_header_iv: vmess_sha256_16(&data_iv),
            response_header_key: vmess_sha256_16(&data_key),
            response_authentication,
        }
    }

    async fn write_vmess_response_header_for_test<S>(
        stream: &mut S,
        response_header_key: &[u8; 16],
        response_header_iv: &[u8; 16],
        response_authentication: u8,
    ) where
        S: AsyncWrite + Unpin,
    {
        let response_header = [response_authentication, 0x00, 0x00, 0x00];
        let len_key = vmess_kdf(response_header_key, &[b"AEAD Resp Header Len Key"]);
        let len_nonce = vmess_kdf(response_header_iv, &[b"AEAD Resp Header Len IV"]);
        let encrypted_len = vmess_aes128gcm_encrypt(
            &len_key[..16],
            &len_nonce[..12],
            &[],
            &(response_header.len() as u16).to_be_bytes(),
        )
        .unwrap();
        let header_key = vmess_kdf(response_header_key, &[b"AEAD Resp Header Key"]);
        let header_nonce = vmess_kdf(response_header_iv, &[b"AEAD Resp Header IV"]);
        let encrypted_header = vmess_aes128gcm_encrypt(
            &header_key[..16],
            &header_nonce[..12],
            &[],
            &response_header,
        )
        .unwrap();
        stream.write_all(&encrypted_len).await.unwrap();
        stream.write_all(&encrypted_header).await.unwrap();
        stream.flush().await.unwrap();
    }

    #[test]
    fn vless_request_uses_port_then_vless_address_type() {
        let user_id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        let request =
            build_vless_request(&user_id, &Destination::new("example.com", 8443)).unwrap();

        assert_eq!(request[0], 0x00);
        assert_eq!(&request[1..17], user_id.as_bytes());
        assert_eq!(request[17], 0x00);
        assert_eq!(request[18], 0x01);
        assert_eq!(u16::from_be_bytes([request[19], request[20]]), 8443);
        assert_eq!(request[21], 0x02);
        assert_eq!(request[22], "example.com".len() as u8);
    }

    #[test]
    fn vless_request_encodes_vision_flow_addon() {
        let user_id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        let request = build_vless_request_with_flow(
            &user_id,
            &Destination::new("example.com", 8443),
            Some("xtls-rprx-vision"),
        )
        .unwrap();

        assert_eq!(request[0], 0x00);
        assert_eq!(&request[1..17], user_id.as_bytes());
        assert_eq!(request[17], 18);
        assert_eq!(&request[18..36], b"\x0a\x10xtls-rprx-vision");
        assert_eq!(request[36], 0x01);
        assert_eq!(u16::from_be_bytes([request[37], request[38]]), 8443);
        assert_eq!(request[39], 0x02);
    }

    #[test]
    fn hysteria2_tcp_request_encodes_command_address_and_padding() {
        let request = build_hysteria2_tcp_request(&Destination::new("example.com", 443)).unwrap();

        assert_eq!(&request[0..2], &[0x44, 0x01]);
        assert_eq!(request[2], b"example.com:443".len() as u8);
        assert_eq!(&request[3..18], b"example.com:443");
        assert_eq!(request[18], 0x00);
    }

    #[test]
    fn hysteria2_udp_message_round_trips_payload() {
        let request = build_hysteria2_udp_messages(
            0x0102_0304,
            0x0506,
            &Destination::new("example.com", 53),
            b"dns",
            None,
        )
        .unwrap()
        .remove(0);

        assert_eq!(&request[0..4], &[1, 2, 3, 4]);
        assert_eq!(&request[4..8], &[5, 6, 0, 1]);
        assert_eq!(request[8], b"example.com:53".len() as u8);
        assert_eq!(&request[9..23], b"example.com:53");
        assert_eq!(&request[23..], b"dns");
        let mut reassembly = Hysteria2UdpReassembly::default();
        assert_eq!(
            parse_hysteria2_udp_message(&request, 0x0102_0304, &mut reassembly)
                .unwrap()
                .unwrap(),
            b"dns"
        );
        assert!(parse_hysteria2_udp_message(
            &request,
            0x9999_0000,
            &mut Hysteria2UdpReassembly::default()
        )
        .unwrap()
        .is_none());
    }

    #[test]
    fn tuic_connect_request_encodes_domain_target() {
        let request = build_tuic_connect_request(&Destination::new("example.com", 443)).unwrap();

        assert_eq!(&request[0..3], &[0x05, 0x01, 0x00]);
        assert_eq!(request[3], b"example.com".len() as u8);
        assert_eq!(&request[4..15], b"example.com");
        assert_eq!(u16::from_be_bytes([request[15], request[16]]), 443);
    }

    #[test]
    fn tuic_connect_request_encodes_ip_target() {
        let request = build_tuic_connect_request(&Destination::new("1.2.3.4", 53)).unwrap();

        assert_eq!(&request, &[0x05, 0x01, 0x01, 1, 2, 3, 4, 0, 53]);
    }

    #[test]
    fn tuic_packet_request_round_trips_payload() {
        let request = build_tuic_packet_messages(
            0x0102,
            0x0304,
            &Destination::new("example.com", 53),
            b"dns",
            None,
        )
        .unwrap()
        .remove(0);

        assert_eq!(&request[0..10], &[0x05, 0x02, 1, 2, 3, 4, 1, 0, 0, 3]);
        assert_eq!(request[10], 0x00);
        assert_eq!(request[11], b"example.com".len() as u8);
        assert_eq!(&request[12..23], b"example.com");
        assert_eq!(u16::from_be_bytes([request[23], request[24]]), 53);
        assert_eq!(&request[25..], b"dns");
        let mut reassembly = TuicUdpReassembly::default();
        assert_eq!(
            parse_tuic_packet_message(&request, 0x0102, &mut reassembly)
                .unwrap()
                .unwrap(),
            b"dns"
        );
        assert!(
            parse_tuic_packet_message(&request, 0x9999, &mut TuicUdpReassembly::default())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn reality_decodes_public_key_and_short_id() {
        let server_secret = X25519StaticSecret::from([9u8; 32]);
        let server_public = X25519PublicKey::from(&server_secret).to_bytes();
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            server_public,
        );

        assert_eq!(
            decode_reality_public_key(&encoded).unwrap().to_bytes(),
            server_public
        );
        assert_eq!(
            decode_reality_short_id(Some("01aB")).unwrap(),
            vec![0x01, 0xab]
        );
        assert!(decode_reality_short_id(Some("abc")).is_err());
        assert!(decode_reality_short_id(Some("001122334455667788")).is_err());
    }

    #[test]
    fn reality_session_id_seals_version_time_and_short_id() {
        let server_secret = X25519StaticSecret::from([9u8; 32]);
        let server_public = X25519PublicKey::from(&server_secret);
        let client_secret = X25519StaticSecret::from([7u8; 32]);
        let shared_secret = client_secret.diffie_hellman(&server_public);
        let mut hello_random = [0u8; 32];
        hello_random
            .iter_mut()
            .enumerate()
            .for_each(|(index, byte)| *byte = index as u8);
        let hello_raw = b"synthetic client hello";
        let (session_id, auth_key) = seal_reality_session_id(
            shared_secret.as_bytes(),
            &[0x01, 0xab],
            &hello_random,
            hello_raw,
            0x0102_0304,
        )
        .unwrap();

        let cipher = Aes256Gcm::new_from_slice(&auth_key).unwrap();
        let plaintext = cipher
            .decrypt(
                aes_gcm::Nonce::from_slice(&hello_random[20..]),
                aes_gcm::aead::Payload {
                    msg: &session_id,
                    aad: hello_raw,
                },
            )
            .unwrap();
        assert_eq!(&plaintext[..3], &REALITY_CLIENT_VERSION);
        assert_eq!(plaintext[3], 0);
        assert_eq!(&plaintext[4..8], &[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(&plaintext[8..10], &[0x01, 0xab]);
        assert_eq!(&plaintext[10..], &[0u8; 6]);
    }
}
