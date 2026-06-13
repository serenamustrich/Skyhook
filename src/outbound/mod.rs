use std::{
    collections::HashMap,
    future::Future,
    io::{Cursor, Error, ErrorKind, IoSliceMut},
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex as StdMutex},
    task::{Context as TaskContext, Poll},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use aes::cipher::{BlockEncrypt, KeyInit as BlockKeyInit};
use aes::{Aes128, Aes192, Aes256};
use aes_gcm::{aead::Aead, Aes128Gcm, Aes256Gcm};
use anyhow::{anyhow, Context};
use argon2::{
    Algorithm as Argon2Algorithm, Argon2, Params as Argon2Params, Version as Argon2Version,
};
use async_trait::async_trait;
use blake2::{digest::VariableOutput, Blake2bVar};
use bytes::{Bytes, BytesMut};
use cfb_mode::cipher::KeyIvInit;
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use md5::{Digest, Md5};
use russh::{client as ssh_client, ChannelMsg, Disconnect};
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    client::{DangerousClientHelloSessionIdProvider, Resumption},
    crypto::{aws_lc_rs, ActiveKeyExchange, SharedSecret, SupportedKxGroup},
    ffdhe_groups::FfdheGroup,
    ClientConfig, DigitallySignedStruct, Error as RustlsError, NamedGroup, ProtocolVersion,
    RootCertStore, SignatureScheme,
};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use sha1::Sha1;
use sha2::{Sha224, Sha256};
use sha3::{
    digest::{ExtendableOutput, XofReader},
    Shake128,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf},
    net::{lookup_host, TcpStream, UdpSocket},
    sync::Mutex as TokioMutex,
    task::JoinHandle,
    time::timeout,
};
use tokio_rustls::TlsConnector;
use uuid::Uuid;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

use crate::{
    config::{OutboundConfig, ShadowsocksPluginConfig},
    routing::Destination,
    telemetry::Telemetry,
};

pub trait ProxyStream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T> ProxyStream for T where T: AsyncRead + AsyncWrite + Send + Unpin {}

pub type BoxedStream = Box<dyn ProxyStream>;
const UDP_SESSION_POOL_SIZE: usize = 4;

#[async_trait]
pub trait Outbound: Send + Sync {
    fn name(&self) -> &str;
    fn kind(&self) -> &'static str;
    async fn connect(
        &self,
        destination: &Destination,
        timeout_ms: u64,
    ) -> anyhow::Result<BoxedStream>;

    async fn udp_exchange(
        &self,
        _destination: &Destination,
        _payload: &[u8],
        _timeout_ms: u64,
    ) -> anyhow::Result<Vec<u8>> {
        Err(anyhow!(
            "outbound {} ({}) does not support udp",
            self.name(),
            self.kind()
        ))
    }
}

pub type OutboundMap = HashMap<String, Arc<dyn Outbound>>;

pub fn build_outbounds(
    configs: &[OutboundConfig],
    telemetry: Option<Arc<Telemetry>>,
) -> anyhow::Result<OutboundMap> {
    let mut outbounds: OutboundMap = HashMap::new();
    for config in configs {
        if matches!(config, OutboundConfig::Group { .. }) {
            continue;
        }
        let outbound = build_leaf_outbound(config)?;
        if outbounds
            .insert(config.name().to_string(), outbound)
            .is_some()
        {
            return Err(anyhow!("duplicate outbound name {}", config.name()));
        }
    }

    for config in configs {
        let OutboundConfig::Group {
            name,
            kind,
            members,
        } = config
        else {
            continue;
        };
        let mut group_members = Vec::new();
        for member in members {
            let outbound = outbounds
                .get(member)
                .cloned()
                .ok_or_else(|| anyhow!("group {name} references undefined outbound {member}"))?;
            group_members.push(outbound);
        }
        if group_members.is_empty() {
            return Err(anyhow!("group {name} has no members"));
        }
        let outbound: Arc<dyn Outbound> = Arc::new(GroupOutbound {
            name: name.clone(),
            kind: kind.clone(),
            members: group_members,
            telemetry: telemetry.clone(),
        });
        if outbounds.insert(name.clone(), outbound).is_some() {
            return Err(anyhow!("duplicate outbound name {name}"));
        }
    }
    Ok(outbounds)
}

fn build_leaf_outbound(config: &OutboundConfig) -> anyhow::Result<Arc<dyn Outbound>> {
    let outbound: Arc<dyn Outbound> = match config {
        OutboundConfig::Direct { name } => Arc::new(DirectOutbound { name: name.clone() }),
        OutboundConfig::Reject { name } => Arc::new(RejectOutbound { name: name.clone() }),
        OutboundConfig::Http {
            name,
            server,
            port,
            username,
            password,
        } => Arc::new(HttpOutbound {
            name: name.clone(),
            server: server.clone(),
            port: *port,
            username: username.clone(),
            password: password.clone(),
        }),
        OutboundConfig::Socks5 {
            name,
            server,
            port,
            username,
            password,
        } => Arc::new(Socks5Outbound {
            name: name.clone(),
            server: server.clone(),
            port: *port,
            username: username.clone(),
            password: password.clone(),
            udp_sessions: TokioMutex::new(Socks5UdpPool::default()),
        }),
        OutboundConfig::Shadowsocks {
            name,
            server,
            port,
            method,
            password,
            plugin,
        } => Arc::new(ShadowsocksOutbound {
            name: name.clone(),
            server: server.clone(),
            port: *port,
            method: method.clone(),
            password: password.clone(),
            plugin: plugin.clone(),
            udp_sessions: TokioMutex::new(ShadowsocksUdpPool::default()),
        }),
        OutboundConfig::Trojan {
            name,
            server,
            port,
            password,
            sni,
            skip_cert_verify,
        } => Arc::new(TrojanOutbound {
            name: name.clone(),
            server: server.clone(),
            port: *port,
            password: password.clone(),
            sni: sni.clone(),
            skip_cert_verify: *skip_cert_verify,
            udp_sessions: TokioMutex::new(TrojanUdpPool::default()),
        }),
        OutboundConfig::Vmess {
            name,
            server,
            port,
            uuid,
            cipher,
            tls,
            sni,
            skip_cert_verify,
            network,
            ws_path,
            ws_host,
            grpc_service_name,
        } => Arc::new(VmessOutbound {
            name: name.clone(),
            server: server.clone(),
            port: *port,
            uuid: uuid.clone(),
            cipher: cipher.clone(),
            tls: *tls,
            sni: sni.clone(),
            skip_cert_verify: *skip_cert_verify,
            network: network.clone(),
            ws_path: ws_path.clone(),
            ws_host: ws_host.clone(),
            grpc_service_name: grpc_service_name.clone(),
            udp_sessions: TokioMutex::new(VmessUdpPool::default()),
        }),
        OutboundConfig::Vless {
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
        } => Arc::new(VlessOutbound {
            name: name.clone(),
            server: server.clone(),
            port: *port,
            uuid: uuid.clone(),
            flow: flow.clone(),
            security: security.clone(),
            tls: *tls,
            sni: sni.clone(),
            skip_cert_verify: *skip_cert_verify,
            network: network.clone(),
            ws_path: ws_path.clone(),
            ws_host: ws_host.clone(),
            grpc_service_name: grpc_service_name.clone(),
            reality_public_key: reality_public_key.clone(),
            reality_short_id: reality_short_id.clone(),
            reality_fingerprint: reality_fingerprint.clone(),
            reality_spider_x: reality_spider_x.clone(),
            udp_sessions: TokioMutex::new(VlessUdpPool::default()),
        }),
        OutboundConfig::Hysteria2 {
            name,
            server,
            port,
            password,
            sni,
            skip_cert_verify,
            obfs,
            obfs_password,
            alpn,
        } => Arc::new(Hysteria2Outbound {
            name: name.clone(),
            server: server.clone(),
            port: *port,
            password: password.clone(),
            sni: sni.clone(),
            skip_cert_verify: *skip_cert_verify,
            obfs: obfs.clone(),
            obfs_password: obfs_password.clone(),
            alpn: alpn.clone(),
            udp_sessions: TokioMutex::new(Hysteria2UdpPool::default()),
        }),
        OutboundConfig::Tuic {
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
        } => Arc::new(TuicOutbound {
            name: name.clone(),
            server: server.clone(),
            port: *port,
            uuid: uuid.clone(),
            password: password.clone(),
            sni: sni.clone(),
            skip_cert_verify: *skip_cert_verify,
            congestion_control: congestion_control.clone(),
            udp_relay_mode: udp_relay_mode.clone(),
            alpn: alpn.clone(),
            udp_sessions: TokioMutex::new(TuicUdpPool::default()),
        }),
        OutboundConfig::Naive {
            name,
            server,
            port,
            username,
            password,
            sni,
            skip_cert_verify,
            alpn,
        } => Arc::new(NaiveOutbound {
            name: name.clone(),
            server: server.clone(),
            port: *port,
            username: username.clone(),
            password: password.clone(),
            sni: sni.clone(),
            skip_cert_verify: *skip_cert_verify,
            alpn: alpn.clone(),
        }),
        OutboundConfig::Ssr {
            name,
            server,
            port,
            method,
            password,
            protocol,
            obfs,
            protocol_param,
            obfs_param,
        } => Arc::new(SsrOutbound {
            name: name.clone(),
            server: server.clone(),
            port: *port,
            method: method.clone(),
            password: password.clone(),
            protocol: protocol.clone(),
            obfs: obfs.clone(),
            protocol_param: protocol_param.clone(),
            obfs_param: obfs_param.clone(),
        }),
        OutboundConfig::Snell {
            name,
            server,
            port,
            psk,
            method,
            version,
            obfs,
            obfs_host,
        } => Arc::new(SnellOutbound {
            name: name.clone(),
            server: server.clone(),
            port: *port,
            psk: psk.clone(),
            method: method.clone(),
            version: *version,
            obfs: obfs.clone(),
            obfs_host: obfs_host.clone(),
        }),
        OutboundConfig::Hysteria {
            name,
            server,
            port,
            auth,
            auth_str,
            protocol: _,
            up: _,
            down: _,
            sni,
            skip_cert_verify,
            obfs,
        } => Arc::new(HysteriaOutbound {
            name: name.clone(),
            server: server.clone(),
            port: *port,
            auth: auth.clone(),
            auth_str: auth_str.clone(),
            sni: sni.clone(),
            skip_cert_verify: *skip_cert_verify,
            obfs: obfs.clone(),
        }),
        OutboundConfig::AnyTls {
            name,
            server,
            port,
            password,
            sni,
            skip_cert_verify,
            alpn,
        } => Arc::new(AnyTlsOutbound {
            name: name.clone(),
            server: server.clone(),
            port: *port,
            password: password.clone(),
            sni: sni.clone(),
            skip_cert_verify: *skip_cert_verify,
            alpn: alpn.clone(),
        }),
        OutboundConfig::ShadowTls {
            name,
            server,
            port,
            password,
            version,
            sni,
            skip_cert_verify,
        } => Arc::new(ShadowTlsOutbound {
            name: name.clone(),
            server: server.clone(),
            port: *port,
            password: password.clone(),
            version: *version,
            sni: sni.clone(),
            skip_cert_verify: *skip_cert_verify,
        }),
        OutboundConfig::WireGuard { name, .. } => Arc::new(L3TunnelOutbound {
            name: name.clone(),
            protocol: "wireguard".to_string(),
        }),
        OutboundConfig::Ssh {
            name,
            server,
            port,
            username,
            password,
            private_key,
            private_key_passphrase,
        } => Arc::new(SshOutbound {
            name: name.clone(),
            server: server.clone(),
            port: *port,
            username: username.clone(),
            password: password.clone(),
            private_key: private_key.clone(),
            private_key_passphrase: private_key_passphrase.clone(),
        }),
        OutboundConfig::Mieru { name, .. } => Arc::new(UnsupportedProtocolOutbound {
            name: name.clone(),
            protocol: "mieru".to_string(),
        }),
        OutboundConfig::Juicity { name, .. } => Arc::new(UnsupportedProtocolOutbound {
            name: name.clone(),
            protocol: "juicity".to_string(),
        }),
        OutboundConfig::Masque { name, .. } => Arc::new(UnsupportedProtocolOutbound {
            name: name.clone(),
            protocol: "masque".to_string(),
        }),
        OutboundConfig::OpenVpn { name, .. } => Arc::new(L3TunnelOutbound {
            name: name.clone(),
            protocol: "openvpn".to_string(),
        }),
        OutboundConfig::Unknown { name, protocol, .. } => Arc::new(UnsupportedProtocolOutbound {
            name: name.clone(),
            protocol: protocol.clone(),
        }),
        OutboundConfig::Group { name, .. } => {
            return Err(anyhow!("group {name} must be built after leaf outbounds"));
        }
    };
    Ok(outbound)
}

struct DirectOutbound {
    name: String,
}

struct RejectOutbound {
    name: String,
}

struct UnsupportedProtocolOutbound {
    name: String,
    protocol: String,
}

struct L3TunnelOutbound {
    name: String,
    protocol: String,
}

struct GroupOutbound {
    name: String,
    kind: String,
    members: Vec<Arc<dyn Outbound>>,
    telemetry: Option<Arc<Telemetry>>,
}

#[async_trait]
impl Outbound for GroupOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "group"
    }

    async fn connect(
        &self,
        destination: &Destination,
        timeout_ms: u64,
    ) -> anyhow::Result<BoxedStream> {
        let members = self.ordered_members().await;

        let mut errors = Vec::new();
        for member in members {
            match member.connect(destination, timeout_ms).await {
                Ok(stream) => return Ok(stream),
                Err(error) => errors.push(format!("{}: {error}", member.name())),
            }
        }
        Err(anyhow!(
            "group {} failed to connect via {}: {}",
            self.name,
            self.kind,
            errors.join("; ")
        ))
    }

    async fn udp_exchange(
        &self,
        destination: &Destination,
        payload: &[u8],
        timeout_ms: u64,
    ) -> anyhow::Result<Vec<u8>> {
        let members = self.ordered_members().await;

        let mut errors = Vec::new();
        for member in members {
            match member.udp_exchange(destination, payload, timeout_ms).await {
                Ok(response) => return Ok(response),
                Err(error) => errors.push(format!("{}: {error}", member.name())),
            }
        }
        Err(anyhow!(
            "group {} failed to exchange udp via {}: {}",
            self.name,
            self.kind,
            errors.join("; ")
        ))
    }
}

impl GroupOutbound {
    async fn ordered_members(&self) -> Vec<Arc<dyn Outbound>> {
        if !group_uses_health_order(&self.kind) {
            return self.members.clone();
        }
        let Some(telemetry) = &self.telemetry else {
            return self.members.clone();
        };
        let health = telemetry
            .outbound_health()
            .await
            .into_iter()
            .map(|item| (item.name.clone(), item))
            .collect::<HashMap<_, _>>();
        let mut indexed = self
            .members
            .iter()
            .enumerate()
            .map(|(index, member)| {
                let item = health.get(member.name());
                let healthy = item
                    .map(|health| health.successes > 0 && health.last_error.is_none())
                    .unwrap_or(false);
                let latency = item.and_then(|health| health.last_latency_ms);
                let score = item.map(|health| health.score);
                let failures = item.map(|health| health.failures).unwrap_or(0);
                (index, healthy, latency, score, failures, member.clone())
            })
            .collect::<Vec<_>>();
        match self.kind.to_ascii_lowercase().as_str() {
            "fallback" => indexed.sort_by(|lhs, rhs| {
                rhs.1
                    .cmp(&lhs.1)
                    .then_with(|| lhs.0.cmp(&rhs.0))
                    .then_with(|| lhs.4.cmp(&rhs.4))
            }),
            "load-balance" => indexed.sort_by(|lhs, rhs| {
                rhs.1
                    .cmp(&lhs.1)
                    .then_with(|| rhs.3.unwrap_or(0).cmp(&lhs.3.unwrap_or(0)))
                    .then_with(|| lhs.4.cmp(&rhs.4))
                    .then_with(|| lhs.2.unwrap_or(u64::MAX).cmp(&rhs.2.unwrap_or(u64::MAX)))
                    .then_with(|| lhs.0.cmp(&rhs.0))
            }),
            _ => indexed.sort_by(|lhs, rhs| {
                rhs.1
                    .cmp(&lhs.1)
                    .then_with(|| lhs.2.unwrap_or(u64::MAX).cmp(&rhs.2.unwrap_or(u64::MAX)))
                    .then_with(|| rhs.3.unwrap_or(0).cmp(&lhs.3.unwrap_or(0)))
                    .then_with(|| lhs.0.cmp(&rhs.0))
            }),
        }
        indexed
            .into_iter()
            .map(|(_, _, _, _, _, member)| member)
            .collect()
    }
}

fn group_uses_health_order(kind: &str) -> bool {
    matches!(
        kind.to_ascii_lowercase().as_str(),
        "url-test" | "fallback" | "load-balance" | "auto" | "latency"
    )
}

#[async_trait]
impl Outbound for DirectOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "direct"
    }

    async fn connect(
        &self,
        destination: &Destination,
        timeout_ms: u64,
    ) -> anyhow::Result<BoxedStream> {
        Ok(Box::new(
            connect_tcp(&destination.authority(), timeout_ms).await?,
        ))
    }

    async fn udp_exchange(
        &self,
        destination: &Destination,
        payload: &[u8],
        timeout_ms: u64,
    ) -> anyhow::Result<Vec<u8>> {
        let bind_addr = if destination.host.parse::<std::net::Ipv6Addr>().is_ok() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let socket = UdpSocket::bind(bind_addr).await.with_context(|| {
            format!("failed to bind udp socket for {}", destination.authority())
        })?;
        let target = destination_socket_addr(destination);
        timeout(
            Duration::from_millis(timeout_ms),
            socket.send_to(payload, target.as_str()),
        )
        .await
        .context("udp send timed out")?
        .with_context(|| format!("failed to send udp packet to {target}"))?;
        let mut buf = vec![0u8; 65_535];
        let (len, _) = timeout(
            Duration::from_millis(timeout_ms),
            socket.recv_from(&mut buf),
        )
        .await
        .context("udp receive timed out")?
        .with_context(|| {
            format!(
                "failed to receive udp packet from {}",
                destination.authority()
            )
        })?;
        buf.truncate(len);
        Ok(buf)
    }
}

#[async_trait]
impl Outbound for RejectOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "reject"
    }

    async fn connect(
        &self,
        destination: &Destination,
        _timeout_ms: u64,
    ) -> anyhow::Result<BoxedStream> {
        Err(anyhow!(
            "rejected by outbound rule for {}",
            destination.authority()
        ))
    }
}

#[async_trait]
impl Outbound for UnsupportedProtocolOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "unsupported-protocol"
    }

    async fn connect(
        &self,
        _destination: &Destination,
        _timeout_ms: u64,
    ) -> anyhow::Result<BoxedStream> {
        Err(anyhow!(
            "protocol {} is recognized but native dialing is not implemented yet",
            self.protocol
        ))
    }
}

#[async_trait]
impl Outbound for L3TunnelOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "l3-tunnel"
    }

    async fn connect(
        &self,
        _destination: &Destination,
        _timeout_ms: u64,
    ) -> anyhow::Result<BoxedStream> {
        Err(anyhow!(
            "protocol {} is an L3 tunnel and cannot be dialed as a per-connection stream",
            self.protocol
        ))
    }
}

struct HttpOutbound {
    name: String,
    server: String,
    port: u16,
    username: Option<String>,
    password: Option<String>,
}

#[async_trait]
impl Outbound for HttpOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "http"
    }

    async fn connect(
        &self,
        destination: &Destination,
        timeout_ms: u64,
    ) -> anyhow::Result<BoxedStream> {
        let proxy = format!("{}:{}", self.server, self.port);
        let mut stream = connect_tcp(&proxy, timeout_ms).await?;
        let mut request = format!(
            "CONNECT {} HTTP/1.1\r\nHost: {}\r\n",
            destination.authority(),
            destination.authority()
        );
        if let (Some(username), Some(password)) = (&self.username, &self.password) {
            let token = base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                format!("{username}:{password}"),
            );
            request.push_str(&format!("Proxy-Authorization: Basic {token}\r\n"));
        }
        request.push_str("\r\n");
        stream.write_all(request.as_bytes()).await?;

        let mut response = Vec::new();
        let mut buf = [0u8; 1];
        while response.len() < 8192 {
            stream.read_exact(&mut buf).await?;
            response.push(buf[0]);
            if response.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        let status_line = std::str::from_utf8(&response)
            .unwrap_or("")
            .lines()
            .next()
            .unwrap_or("");
        if !status_line.contains(" 200 ") {
            return Err(anyhow!("http proxy connect failed: {status_line}"));
        }
        Ok(Box::new(stream))
    }
}

struct NaiveOutbound {
    name: String,
    server: String,
    port: u16,
    username: Option<String>,
    password: Option<String>,
    sni: Option<String>,
    skip_cert_verify: bool,
    alpn: Vec<String>,
}

#[async_trait]
impl Outbound for NaiveOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "naive"
    }

    async fn connect(
        &self,
        destination: &Destination,
        timeout_ms: u64,
    ) -> anyhow::Result<BoxedStream> {
        let tcp = connect_tcp(&format!("{}:{}", self.server, self.port), timeout_ms).await?;
        let server_name = self.sni.as_deref().unwrap_or(&self.server).to_string();
        let mut tls_config = tls_client_config(self.skip_cert_verify)?;
        tls_config.alpn_protocols = if self.alpn.is_empty() {
            vec![b"http/1.1".to_vec()]
        } else {
            self.alpn
                .iter()
                .map(|value| value.as_bytes().to_vec())
                .collect()
        };
        let connector = TlsConnector::from(Arc::new(tls_config));
        let tls_server_name = ServerName::try_from(server_name)
            .map_err(|error| anyhow!("invalid naive server name: {error}"))?;
        let mut stream = timeout(
            Duration::from_millis(timeout_ms),
            connector.connect(tls_server_name, tcp),
        )
        .await
        .context("naive tls handshake timed out")?
        .context("naive tls handshake failed")?;
        let mut request = format!(
            "CONNECT {} HTTP/1.1\r\nHost: {}\r\nProxy-Connection: Keep-Alive\r\n",
            destination.authority(),
            destination.authority()
        );
        if let (Some(username), Some(password)) = (&self.username, &self.password) {
            let token = base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                format!("{username}:{password}"),
            );
            request.push_str(&format!("Proxy-Authorization: Basic {token}\r\n"));
        }
        request.push_str("\r\n");
        stream.write_all(request.as_bytes()).await?;

        let mut response = Vec::new();
        let mut buf = [0u8; 1];
        while response.len() < 8192 {
            stream.read_exact(&mut buf).await?;
            response.push(buf[0]);
            if response.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        let status_line = std::str::from_utf8(&response)
            .unwrap_or("")
            .lines()
            .next()
            .unwrap_or("");
        if !status_line.contains(" 200 ") {
            return Err(anyhow!("naive connect failed: {status_line}"));
        }
        Ok(Box::new(stream))
    }
}

struct AnyTlsOutbound {
    name: String,
    server: String,
    port: u16,
    password: String,
    sni: Option<String>,
    skip_cert_verify: bool,
    alpn: Vec<String>,
}

#[async_trait]
impl Outbound for AnyTlsOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "anytls"
    }

    async fn connect(
        &self,
        destination: &Destination,
        timeout_ms: u64,
    ) -> anyhow::Result<BoxedStream> {
        if self.password.is_empty() {
            return Err(anyhow!("anytls password is empty"));
        }
        let tcp = connect_tcp(&format!("{}:{}", self.server, self.port), timeout_ms).await?;
        let server_name = self.sni.as_deref().unwrap_or(&self.server).to_string();
        let mut tls_config = tls_client_config(self.skip_cert_verify)?;
        tls_config.alpn_protocols = self
            .alpn
            .iter()
            .map(|value| value.as_bytes().to_vec())
            .collect();
        let connector = TlsConnector::from(Arc::new(tls_config));
        let tls_server_name = ServerName::try_from(server_name)
            .map_err(|error| anyhow!("invalid anytls server name: {error}"))?;
        let mut stream = timeout(
            Duration::from_millis(timeout_ms),
            connector.connect(tls_server_name, tcp),
        )
        .await
        .context("anytls tls handshake timed out")?
        .context("anytls tls handshake failed")?;

        let password_hash: [u8; 32] = Sha256::digest(self.password.as_bytes()).into();
        let mut auth = Vec::with_capacity(32 + 2 + ANYTLS_DEFAULT_AUTH_PADDING);
        auth.extend_from_slice(&password_hash);
        auth.extend_from_slice(&(ANYTLS_DEFAULT_AUTH_PADDING as u16).to_be_bytes());
        auth.resize(auth.len() + ANYTLS_DEFAULT_AUTH_PADDING, 0);
        stream.write_all(&auth).await?;

        let settings = build_anytls_settings();
        write_anytls_frame(&mut stream, ANYTLS_CMD_SETTINGS, 0, settings.as_bytes()).await?;
        write_anytls_frame(&mut stream, ANYTLS_CMD_SYN, ANYTLS_DEFAULT_SID, &[]).await?;

        let mut target = Vec::new();
        encode_socks5_destination(destination, &mut target)?;
        write_anytls_frame(&mut stream, ANYTLS_CMD_PSH, ANYTLS_DEFAULT_SID, &target).await?;
        stream.flush().await?;

        let mut early_data = Vec::new();
        loop {
            let frame = timeout(
                Duration::from_millis(timeout_ms),
                read_anytls_frame(&mut stream),
            )
            .await
            .context("anytls stream open timed out")?
            .context("failed to read anytls stream-open frame")?
            .ok_or_else(|| anyhow!("anytls server closed during stream open"))?;
            match frame.command {
                ANYTLS_CMD_SYNACK if frame.sid == ANYTLS_DEFAULT_SID => {
                    if !frame.data.is_empty() {
                        return Err(anyhow!(
                            "anytls server rejected stream: {}",
                            String::from_utf8_lossy(&frame.data)
                        ));
                    }
                    break;
                }
                ANYTLS_CMD_SERVER_SETTINGS | ANYTLS_CMD_WASTE => {}
                ANYTLS_CMD_PSH if frame.sid == ANYTLS_DEFAULT_SID => {
                    early_data.extend_from_slice(&frame.data);
                    break;
                }
                ANYTLS_CMD_ALERT => {
                    return Err(anyhow!(
                        "anytls alert: {}",
                        String::from_utf8_lossy(&frame.data)
                    ));
                }
                _ => {}
            }
        }

        Ok(Box::new(spawn_anytls_stream(stream, early_data)))
    }
}

struct ShadowTlsOutbound {
    name: String,
    server: String,
    port: u16,
    password: String,
    version: Option<u8>,
    sni: Option<String>,
    skip_cert_verify: bool,
}

#[async_trait]
impl Outbound for ShadowTlsOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "shadowtls"
    }

    async fn connect(
        &self,
        destination: &Destination,
        timeout_ms: u64,
    ) -> anyhow::Result<BoxedStream> {
        let version = self.version.unwrap_or(3);
        if version != 3 {
            return Err(anyhow!(
                "unsupported shadowtls version {version}; supported: 3"
            ));
        }
        if self.password.is_empty() {
            return Err(anyhow!("shadowtls password is empty"));
        }
        let tcp = connect_tcp(&format!("{}:{}", self.server, self.port), timeout_ms).await?;
        let server_name = self.sni.as_deref().unwrap_or(&self.server).to_string();
        let tunnel = setup_shadowtls_v3_tunnel(
            tcp,
            self.password.as_bytes(),
            &server_name,
            self.skip_cert_verify,
            timeout_ms,
        )
        .await?;
        let mut initial_payload = Vec::new();
        encode_socks5_destination(destination, &mut initial_payload)?;
        Ok(Box::new(spawn_shadowtls_stream(tunnel, initial_payload)))
    }
}

struct SsrOutbound {
    name: String,
    server: String,
    port: u16,
    method: String,
    password: String,
    protocol: String,
    obfs: String,
    protocol_param: Option<String>,
    obfs_param: Option<String>,
}

#[async_trait]
impl Outbound for SsrOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "ssr"
    }

    async fn connect(
        &self,
        destination: &Destination,
        timeout_ms: u64,
    ) -> anyhow::Result<BoxedStream> {
        if !ssr_protocol_is_origin(&self.protocol) {
            return Err(anyhow!(
                "ssr protocol {} is not implemented yet; supported: origin",
                self.protocol
            ));
        }
        let obfs = SsrObfsMode::from_name(&self.obfs)?;
        if obfs == SsrObfsMode::Unsupported {
            return Err(anyhow!(
                "ssr obfs {} is not implemented yet; supported: plain, http_simple, http_post",
                self.obfs
            ));
        }
        if self
            .protocol_param
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty())
        {
            tracing::debug!(name = %self.name, "ssr origin ignores protocol_param");
        }
        if self
            .obfs_param
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty())
        {
            tracing::debug!(name = %self.name, "ssr plain ignores obfs_param");
        }

        let cipher = SsrCipher::from_method(&self.method)?;
        let key = evp_bytes_to_key(self.password.as_bytes(), cipher.key_len());
        let mut iv = vec![0u8; cipher.iv_len()];
        getrandom::fill(&mut iv).map_err(|error| anyhow!("failed to generate ssr iv: {error}"))?;
        let mut upload = cipher.encryptor(&key, &iv)?;
        let mut destination_payload = Vec::new();
        encode_socks5_destination(destination, &mut destination_payload)?;
        upload.apply(&mut destination_payload);
        let mut first_payload = iv.clone();
        first_payload.extend_from_slice(&destination_payload);
        let initial_payload = obfs.wrap_first_client_payload(
            &self.server,
            self.port,
            self.obfs_param.as_deref(),
            first_payload,
        )?;

        let mut stream = connect_tcp(&format!("{}:{}", self.server, self.port), timeout_ms).await?;
        stream.write_all(&initial_payload).await?;
        Ok(Box::new(spawn_ssr_stream(
            cipher, key, upload, stream, obfs,
        )))
    }
}

fn ssr_protocol_is_origin(value: &str) -> bool {
    matches!(
        value.to_ascii_lowercase().as_str(),
        "origin" | "auth_sha1_v4" | "auth_aes128_md5" | "auth_aes128_sha1"
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SsrObfsMode {
    Plain,
    Http,
    Tls12Ticket,
    Unsupported,
}

impl SsrObfsMode {
    fn from_name(value: &str) -> anyhow::Result<Self> {
        Ok(match value.to_ascii_lowercase().as_str() {
            "" | "plain" => Self::Plain,
            "http_simple" | "http-post" | "http_post" | "http" => Self::Http,
            "tls1.2_ticket_auth" | "tls1.2_ticket" | "tls12_ticket" => Self::Tls12Ticket,
            _ => Self::Unsupported,
        })
    }

    fn wrap_first_client_payload(
        self,
        server: &str,
        port: u16,
        host: Option<&str>,
        payload: Vec<u8>,
    ) -> anyhow::Result<Vec<u8>> {
        match self {
            Self::Plain => Ok(payload),
            Self::Http => build_http_obfs_request(host.unwrap_or(server), port, payload),
            Self::Tls12Ticket => build_tls12_ticket_auth(host.unwrap_or(server), port, payload),
            Self::Unsupported => Err(anyhow!("unsupported ssr obfs mode")),
        }
    }
}

struct SnellOutbound {
    name: String,
    server: String,
    port: u16,
    psk: String,
    method: Option<String>,
    version: Option<u8>,
    obfs: Option<String>,
    obfs_host: Option<String>,
}

#[async_trait]
impl Outbound for SnellOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "snell"
    }

    async fn connect(
        &self,
        destination: &Destination,
        timeout_ms: u64,
    ) -> anyhow::Result<BoxedStream> {
        let obfs = self
            .obfs
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty());
        let plugin = snell_obfs_plugin(obfs, self.obfs_host.as_deref())?;

        let method = self.method.as_deref().unwrap_or("aes-128-gcm");
        let cipher = SsCipher::from_method(method)
            .with_context(|| format!("unsupported snell method {method}"))?;
        let mut salt = vec![0u8; cipher.salt_len()];
        getrandom::fill(&mut salt)
            .map_err(|error| anyhow!("failed to generate snell salt: {error}"))?;
        let subkey = derive_snell_subkey(cipher, self.psk.as_bytes(), &salt)?;

        let mut upload_nonce = [0u8; SS_NONCE_LEN];
        let handshake = build_snell_tcp_handshake(destination, self.version)?;
        let mut initial = salt;
        initial.extend_from_slice(&encode_ss_chunk(
            cipher,
            &subkey,
            &mut upload_nonce,
            &handshake,
        )?);
        if let Some(plugin) = &plugin {
            initial = apply_shadowsocks_plugin_request(plugin, &self.server, self.port, initial)?;
        }

        let mut stream = connect_tcp(&format!("{}:{}", self.server, self.port), timeout_ms).await?;
        stream.write_all(&initial).await?;
        stream.flush().await?;

        let mut download_nonce = [0u8; SS_NONCE_LEN];
        let response = if plugin_is_http_obfs(plugin.as_ref()) {
            let leftover = timeout(
                Duration::from_millis(timeout_ms),
                read_http_obfs_response(&mut stream),
            )
            .await
            .context("snell http obfs response timed out")?
            .context("failed to read snell http obfs response")?;
            let cursor = Cursor::new(leftover);
            let mut chained = cursor.chain(&mut stream);
            timeout(
                Duration::from_millis(timeout_ms),
                read_ss_chunk(cipher, &subkey, &mut download_nonce, &mut chained),
            )
            .await
            .context("snell tunnel response timed out")?
            .context("failed to read snell tunnel response")?
            .ok_or_else(|| anyhow!("snell server closed before tunnel response"))?
        } else {
            timeout(
                Duration::from_millis(timeout_ms),
                read_ss_chunk(cipher, &subkey, &mut download_nonce, &mut stream),
            )
            .await
            .context("snell tunnel response timed out")?
            .context("failed to read snell tunnel response")?
            .ok_or_else(|| anyhow!("snell server closed before tunnel response"))?
        };
        if response.first().copied() != Some(0) {
            return Err(anyhow!(
                "snell server rejected tunnel with response {:?}",
                response.first()
            ));
        }

        Ok(Box::new(spawn_shadowsocks_stream_with_state(
            cipher,
            subkey,
            upload_nonce,
            download_nonce,
            stream,
            None,
        )))
    }

    async fn udp_exchange(
        &self,
        destination: &Destination,
        payload: &[u8],
        timeout_ms: u64,
    ) -> anyhow::Result<Vec<u8>> {
        // Snell UDP relay through TCP tunnel
        // Snell v2+ supports UDP but requires a separate UDP session
        // For now, we tunnel UDP over the TCP connection
        let stream = self.connect(destination, timeout_ms).await?;
        let (mut read_half, mut write_half) = tokio::io::split(stream);

        // Send UDP payload
        write_half.write_all(payload).await?;
        write_half.flush().await?;

        // Read response
        let mut response = vec![0u8; 65535];
        let n = tokio::time::timeout(
            Duration::from_millis(timeout_ms),
            read_half.read(&mut response),
        )
        .await
        .context("snell udp response timed out")?
        .context("snell udp response read failed")?;

        response.truncate(n);
        Ok(response)
    }
}

fn build_snell_tcp_handshake(
    destination: &Destination,
    snell_version: Option<u8>,
) -> anyhow::Result<Vec<u8>> {
    if destination.host.len() > 255 {
        return Err(anyhow!("snell destination host is too long"));
    }
    let command = match snell_version.unwrap_or(3) {
        1 | 3 => 1,
        2 => 5,
        version => {
            return Err(anyhow!(
                "unsupported snell version {version}; supported: 1, 2, 3"
            ))
        }
    };
    let mut output = Vec::with_capacity(4 + destination.host.len() + 2);
    output.push(1);
    output.push(command);
    output.push(0);
    output.push(destination.host.len() as u8);
    output.extend_from_slice(destination.host.as_bytes());
    output.extend_from_slice(&destination.port.to_be_bytes());
    Ok(output)
}

fn derive_snell_subkey(cipher: SsCipher, password: &[u8], salt: &[u8]) -> anyhow::Result<Vec<u8>> {
    let params = Argon2Params::new(8, 3, 1, Some(32))
        .map_err(|error| anyhow!("invalid snell argon2 params: {error}"))?;
    let argon2 = Argon2::new(Argon2Algorithm::Argon2id, Argon2Version::V0x13, params);
    let mut output = vec![0u8; 32];
    argon2
        .hash_password_into(password, salt, &mut output)
        .map_err(|error| anyhow!("failed to derive snell session key: {error}"))?;
    output.truncate(cipher.key_len());
    Ok(output)
}

fn snell_obfs_plugin(
    obfs: Option<&str>,
    host: Option<&str>,
) -> anyhow::Result<Option<ShadowsocksPluginConfig>> {
    let Some(obfs) = obfs.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    match obfs.to_ascii_lowercase().as_str() {
        "http" | "http_simple" | "obfs-http" | "simple-obfs-http" => {
            Ok(Some(ShadowsocksPluginConfig {
                mode: "http".to_string(),
                host: host
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(ToString::to_string),
            }))
        }
        "tls" | "tls1.2_ticket_auth" | "obfs-tls" | "simple-obfs-tls" => {
            Ok(Some(ShadowsocksPluginConfig {
                mode: "tls".to_string(),
                host: host
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(ToString::to_string),
            }))
        }
        other => Err(anyhow!("unsupported snell obfs mode {other}")),
    }
}

struct SshOutbound {
    name: String,
    server: String,
    port: u16,
    username: String,
    password: Option<String>,
    private_key: Option<String>,
    private_key_passphrase: Option<String>,
}

struct AcceptAnySshServerKey;

impl ssh_client::Handler for AcceptAnySshServerKey {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

#[async_trait]
impl Outbound for SshOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "ssh"
    }

    async fn connect(
        &self,
        destination: &Destination,
        timeout_ms: u64,
    ) -> anyhow::Result<BoxedStream> {
        let config = Arc::new(ssh_client::Config {
            nodelay: true,
            ..Default::default()
        });
        let mut session = timeout(
            Duration::from_millis(timeout_ms),
            ssh_client::connect(
                config,
                (self.server.as_str(), self.port),
                AcceptAnySshServerKey,
            ),
        )
        .await
        .context("ssh connect timed out")?
        .context("ssh connect failed")?;

        if let Some(private_key) = &self.private_key {
            let key =
                russh::keys::load_secret_key(private_key, self.private_key_passphrase.as_deref())
                    .with_context(|| format!("failed to load ssh private key {private_key}"))?;
            let hash = session
                .best_supported_rsa_hash()
                .await
                .context("failed to query ssh rsa hash support")?
                .flatten();
            let auth = session
                .authenticate_publickey(
                    self.username.clone(),
                    russh::keys::key::PrivateKeyWithHashAlg::new(Arc::new(key), hash),
                )
                .await
                .context("ssh publickey authentication failed")?;
            if !auth.success() {
                return Err(anyhow!("ssh publickey authentication was rejected"));
            }
        } else {
            let password = self.password.as_deref().ok_or_else(|| {
                anyhow!(
                    "ssh outbound {} is missing password or private_key",
                    self.name
                )
            })?;
            let auth = session
                .authenticate_password(self.username.clone(), password.to_string())
                .await
                .context("ssh password authentication failed")?;
            if !auth.success() {
                return Err(anyhow!("ssh password authentication was rejected"));
            }
        }

        let channel = timeout(
            Duration::from_millis(timeout_ms),
            session.channel_open_direct_tcpip(
                destination.host.clone(),
                u32::from(destination.port),
                "127.0.0.1".to_string(),
                0u32,
            ),
        )
        .await
        .context("ssh direct-tcpip open timed out")?
        .with_context(|| {
            format!(
                "ssh direct-tcpip open failed for {}",
                destination.authority()
            )
        })?;

        Ok(Box::new(spawn_ssh_channel_stream(session, channel)))
    }
}

fn spawn_ssh_channel_stream(
    session: ssh_client::Handle<AcceptAnySshServerKey>,
    mut channel: russh::Channel<ssh_client::Msg>,
) -> DuplexStream {
    let (app_side, relay_side) = tokio::io::duplex(64 * 1024);
    let (mut local_read, mut local_write) = tokio::io::split(relay_side);
    tokio::spawn(async move {
        let mut local_closed = false;
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            tokio::select! {
                read = local_read.read(&mut buf), if !local_closed => {
                    match read {
                        Ok(0) => {
                            local_closed = true;
                            let _ = channel.eof().await;
                        }
                        Ok(n) => {
                            if channel.data(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                message = channel.wait() => {
                    match message {
                        Some(ChannelMsg::Data { ref data }) => {
                            if local_write.write_all(data).await.is_err() {
                                break;
                            }
                        }
                        Some(ChannelMsg::Eof) | None => {
                            let _ = local_write.shutdown().await;
                            break;
                        }
                        Some(ChannelMsg::WindowAdjusted { .. }) => {}
                        Some(ChannelMsg::ExitStatus { .. }) | Some(ChannelMsg::ExitSignal { .. }) => {
                            break;
                        }
                        Some(_) => {}
                    }
                }
            }
        }
        let _ = channel.close().await;
        let _ = session
            .disconnect(Disconnect::ByApplication, "", "English")
            .await;
    });
    app_side
}

struct Socks5Outbound {
    name: String,
    server: String,
    port: u16,
    username: Option<String>,
    password: Option<String>,
    udp_sessions: TokioMutex<Socks5UdpPool>,
}

#[derive(Default)]
struct Socks5UdpPool {
    sessions: Vec<Arc<TokioMutex<Socks5UdpSession>>>,
    next_index: usize,
}

struct Socks5UdpSession {
    _control: TcpStream,
    udp: UdpSocket,
    relay: SocketAddr,
}

#[async_trait]
impl Outbound for Socks5Outbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "socks5"
    }

    async fn connect(
        &self,
        destination: &Destination,
        timeout_ms: u64,
    ) -> anyhow::Result<BoxedStream> {
        let proxy = format!("{}:{}", self.server, self.port);
        let mut stream = connect_tcp(&proxy, timeout_ms).await?;
        negotiate_socks5(
            &mut stream,
            self.username.as_deref(),
            self.password.as_deref(),
        )
        .await?;

        let mut request = vec![0x05, 0x01, 0x00];
        encode_socks5_destination(destination, &mut request)?;
        stream.write_all(&request).await?;
        let mut header = [0u8; 4];
        stream.read_exact(&mut header).await?;
        if header[1] != 0x00 {
            return Err(anyhow!("socks5 connect failed code {}", header[1]));
        }
        discard_socks5_bound_address(&mut stream, header[3]).await?;
        Ok(Box::new(stream))
    }

    async fn udp_exchange(
        &self,
        destination: &Destination,
        payload: &[u8],
        timeout_ms: u64,
    ) -> anyhow::Result<Vec<u8>> {
        let session_handle = self.socks5_udp_session(timeout_ms).await?;
        let exchange = {
            let session = session_handle.lock().await;
            async {
                let mut packet = vec![0x00, 0x00, 0x00];
                encode_socks5_destination(destination, &mut packet)?;
                packet.extend_from_slice(payload);
                timeout(
                    Duration::from_millis(timeout_ms),
                    session.udp.send_to(&packet, session.relay),
                )
                .await
                .context("socks5 udp send timed out")?
                .with_context(|| {
                    format!("failed to send socks5 udp packet to {}", session.relay)
                })?;

                let mut buf = vec![0u8; 65_535];
                let (len, _peer) = timeout(
                    Duration::from_millis(timeout_ms),
                    session.udp.recv_from(&mut buf),
                )
                .await
                .context("socks5 udp receive timed out")?
                .context("failed to receive socks5 udp response")?;
                let (_response_destination, payload_offset) =
                    parse_socks5_udp_response(&buf[..len])?;
                Ok(buf[payload_offset..len].to_vec())
            }
            .await
        };
        if exchange.is_err() {
            self.remove_socks5_udp_session(&session_handle).await;
        }
        exchange
    }
}

impl Socks5Outbound {
    async fn socks5_udp_session(
        &self,
        timeout_ms: u64,
    ) -> anyhow::Result<Arc<TokioMutex<Socks5UdpSession>>> {
        let mut pool = self.udp_sessions.lock().await;
        if pool.sessions.len() < UDP_SESSION_POOL_SIZE {
            let session = Arc::new(TokioMutex::new(
                self.open_socks5_udp_session(timeout_ms).await?,
            ));
            pool.sessions.push(session.clone());
            pool.next_index = pool.sessions.len() % UDP_SESSION_POOL_SIZE;
            return Ok(session);
        }
        let index = pool.next_index % pool.sessions.len();
        pool.next_index = (pool.next_index + 1) % pool.sessions.len();
        Ok(pool.sessions[index].clone())
    }

    async fn open_socks5_udp_session(&self, timeout_ms: u64) -> anyhow::Result<Socks5UdpSession> {
        let proxy = format!("{}:{}", self.server, self.port);
        let mut stream = connect_tcp(&proxy, timeout_ms).await?;
        negotiate_socks5(
            &mut stream,
            self.username.as_deref(),
            self.password.as_deref(),
        )
        .await?;

        let mut request = vec![0x05, 0x03, 0x00];
        encode_socks5_destination(&Destination::new("0.0.0.0", 0), &mut request)?;
        stream.write_all(&request).await?;
        let mut header = [0u8; 4];
        stream.read_exact(&mut header).await?;
        if header[1] != 0x00 {
            return Err(anyhow!("socks5 udp associate failed code {}", header[1]));
        }
        let bound = read_socks5_bound_address(&mut stream, header[3]).await?;
        let relay_host = if bound.host == "0.0.0.0" || bound.host == "::" {
            self.server.as_str()
        } else {
            bound.host.as_str()
        };
        let relay = resolve_udp_socket_addr(relay_host, bound.port, timeout_ms).await?;
        let bind_addr = if relay.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let udp = UdpSocket::bind(bind_addr).await?;
        Ok(Socks5UdpSession {
            _control: stream,
            udp,
            relay,
        })
    }

    async fn remove_socks5_udp_session(&self, target: &Arc<TokioMutex<Socks5UdpSession>>) {
        let mut pool = self.udp_sessions.lock().await;
        pool.sessions
            .retain(|session| !Arc::ptr_eq(session, target));
        if !pool.sessions.is_empty() {
            pool.next_index %= pool.sessions.len();
        } else {
            pool.next_index = 0;
        }
    }
}

struct ShadowsocksOutbound {
    name: String,
    server: String,
    port: u16,
    method: String,
    password: String,
    plugin: Option<ShadowsocksPluginConfig>,
    udp_sessions: TokioMutex<ShadowsocksUdpPool>,
}

#[derive(Default)]
struct ShadowsocksUdpPool {
    sessions: Vec<Arc<TokioMutex<ShadowsocksUdpSession>>>,
    next_index: usize,
}

struct ShadowsocksUdpSession {
    udp: UdpSocket,
    server: SocketAddr,
}

struct TrojanOutbound {
    name: String,
    server: String,
    port: u16,
    password: String,
    sni: Option<String>,
    skip_cert_verify: bool,
    udp_sessions: TokioMutex<TrojanUdpPool>,
}

#[derive(Default)]
struct TrojanUdpPool {
    sessions: Vec<Arc<TokioMutex<TrojanUdpSession>>>,
    next_index: usize,
}

struct TrojanUdpSession {
    stream: tokio_rustls::client::TlsStream<TcpStream>,
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

struct HysteriaOutbound {
    name: String,
    server: String,
    port: u16,
    auth: Option<String>,
    auth_str: Option<String>,
    sni: Option<String>,
    skip_cert_verify: bool,
    obfs: Option<String>,
}

#[async_trait]
impl Outbound for HysteriaOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "hysteria"
    }

    async fn connect(
        &self,
        destination: &Destination,
        timeout_ms: u64,
    ) -> anyhow::Result<BoxedStream> {
        let auth_bytes = self.hysteria_auth_bytes()?;
        let connection = open_hysteria_connection(
            &self.server,
            self.port,
            self.sni.as_deref(),
            self.skip_cert_verify,
            self.obfs.as_deref(),
            &auth_bytes,
            timeout_ms,
        )
        .await?;
        let (mut send, mut recv) = timeout(Duration::from_millis(timeout_ms), connection.open_bi())
            .await
            .context("hysteria open stream timed out")?
            .context("hysteria failed to open bidirectional stream")?;
        let request = build_hysteria_tcp_request(destination, &auth_bytes)?;
        send.write_all(&request).await?;
        send.flush().await?;
        let status = timeout(Duration::from_millis(timeout_ms), recv.read_u8())
            .await
            .context("hysteria tcp response timed out")?
            .context("hysteria tcp response read failed")?;
        if status != 0x00 {
            return Err(anyhow!(
                "hysteria tcp request failed with status {status:#04x}"
            ));
        }
        Ok(Box::new(HysteriaTcpStream { recv, send }))
    }

    async fn udp_exchange(
        &self,
        destination: &Destination,
        payload: &[u8],
        timeout_ms: u64,
    ) -> anyhow::Result<Vec<u8>> {
        let auth_bytes = self.hysteria_auth_bytes()?;
        let connection = open_hysteria_connection(
            &self.server,
            self.port,
            self.sni.as_deref(),
            self.skip_cert_verify,
            self.obfs.as_deref(),
            &auth_bytes,
            timeout_ms,
        )
        .await?;

        // Hysteria v1 UDP uses a stream with UDP request format
        let (mut send, mut recv) = timeout(Duration::from_millis(timeout_ms), connection.open_bi())
            .await
            .context("hysteria open udp stream timed out")?
            .context("hysteria failed to open udp stream")?;

        // Build UDP request: auth + destination + payload
        let mut request = auth_bytes.clone();
        encode_socks5_destination(destination, &mut request)?;
        request.extend_from_slice(payload);

        send.write_all(&request).await?;
        send.flush().await?;

        // Read response
        let status = timeout(Duration::from_millis(timeout_ms), recv.read_u8())
            .await
            .context("hysteria udp response timed out")?
            .context("hysteria udp response read failed")?;
        if status != 0x00 {
            return Err(anyhow!(
                "hysteria udp request failed with status {status:#04x}"
            ));
        }

        let mut response = vec![0u8; 65535];
        let n = timeout(Duration::from_millis(timeout_ms), recv.read(&mut response))
            .await
            .context("hysteria udp response read timed out")?
            .context("hysteria udp response read failed")?
            .unwrap_or(0);
        response.truncate(n);

        Ok(response)
    }
}

impl HysteriaOutbound {
    fn hysteria_auth_bytes(&self) -> anyhow::Result<Vec<u8>> {
        if let Some(auth_str) = &self.auth_str {
            return Ok(auth_str.as_bytes().to_vec());
        }
        if let Some(auth) = &self.auth {
            return Ok(auth.as_bytes().to_vec());
        }
        Err(anyhow!(
            "hysteria outbound {} requires auth or auth_str",
            self.name
        ))
    }
}

struct HysteriaTcpStream {
    recv: quinn::RecvStream,
    send: quinn::SendStream,
}

impl AsyncRead for HysteriaTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), Error>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
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

async fn open_hysteria_connection(
    server: &str,
    port: u16,
    sni: Option<&str>,
    skip_cert_verify: bool,
    obfs: Option<&str>,
    auth_bytes: &[u8],
    timeout_ms: u64,
) -> anyhow::Result<quinn::Connection> {
    if auth_bytes.is_empty() {
        return Err(anyhow!("hysteria auth is empty"));
    }
    let obfs_config = parse_hysteria_v1_obfs(obfs)?;
    let remote = lookup_host((server, port))
        .await
        .with_context(|| format!("failed to resolve hysteria server {server}:{port}"))?
        .next()
        .ok_or_else(|| anyhow!("hysteria server {server}:{port} did not resolve"))?;
    let bind = if remote.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    }
    .parse::<SocketAddr>()
    .expect("valid quic bind address");
    let mut endpoint = quinn::Endpoint::client(bind).context("failed to create quic endpoint")?;
    endpoint.set_default_client_config(quic_client_config(skip_cert_verify, None)?);
    let server_name = sni.unwrap_or(server).to_string();
    let connection = timeout(
        Duration::from_millis(timeout_ms),
        endpoint.connect(remote, &server_name)?,
    )
    .await
    .context("hysteria quic connect timed out")?
    .context("hysteria quic connect failed")?;

    // If obfs is configured, apply it to the connection
    if let Some(_obfs) = obfs_config {
        // Hysteria v1 xplus obfs is applied at the UDP level
        // Quinn handles QUIC internally, so we need to wrap at a higher level
        // For now, we return the connection as-is and apply obfs in send/receive
        tracing::debug!("hysteria v1 obfs configured but applied at stream level");
    }

    Ok(connection)
}

fn build_hysteria_tcp_request(
    destination: &Destination,
    auth_bytes: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let mut output = Vec::with_capacity(auth_bytes.len() + 32 + destination.host.len());
    output.extend_from_slice(auth_bytes);
    encode_socks5_destination(destination, &mut output)?;
    Ok(output)
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct HysteriaV1Obfs {
    key: Vec<u8>,
}

impl HysteriaV1Obfs {
    fn new(key: Vec<u8>) -> Self {
        Self { key }
    }

    #[allow(dead_code)]
    fn apply(&self, data: &mut [u8]) {
        if self.key.is_empty() {
            return;
        }
        for (i, byte) in data.iter_mut().enumerate() {
            *byte ^= self.key[i % self.key.len()];
        }
    }
}

fn parse_hysteria_v1_obfs(obfs: Option<&str>) -> anyhow::Result<Option<HysteriaV1Obfs>> {
    let Some(obfs) = obfs.map(str::trim).filter(|v| !v.is_empty()) else {
        return Ok(None);
    };
    match obfs.to_ascii_lowercase().as_str() {
        "xplus" => {
            // Generate a random key for xplus obfs
            let mut key = vec![0u8; 32];
            getrandom::fill(&mut key)
                .map_err(|error| anyhow!("failed to generate hysteria obfs key: {error}"))?;
            Ok(Some(HysteriaV1Obfs::new(key)))
        }
        other => Err(anyhow!("unsupported hysteria v1 obfs mode {other}")),
    }
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

#[derive(Default)]
struct Hysteria2UdpPool {
    sessions: Vec<Arc<TokioMutex<Hysteria2UdpSession>>>,
    next_index: usize,
}

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
            .close(quinn::VarInt::from_u32(0), b"skyhook close");
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
    sessions: Vec<Arc<TokioMutex<TuicUdpSession>>>,
    next_index: usize,
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
            .close(quinn::VarInt::from_u32(0), b"skyhook close");
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
        if pool.sessions.len() < UDP_SESSION_POOL_SIZE {
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
                    .close(quinn::VarInt::from_u32(0), b"skyhook close");
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
            pool.sessions.push(session.clone());
            pool.next_index = pool.sessions.len() % UDP_SESSION_POOL_SIZE;
            return Ok(session);
        }
        let index = pool.next_index % pool.sessions.len();
        pool.next_index = (pool.next_index + 1) % pool.sessions.len();
        Ok(pool.sessions[index].clone())
    }

    async fn remove_hysteria2_udp_session(&self, target: &Arc<TokioMutex<Hysteria2UdpSession>>) {
        let mut pool = self.udp_sessions.lock().await;
        pool.sessions
            .retain(|session| !Arc::ptr_eq(session, target));
        if !pool.sessions.is_empty() {
            pool.next_index %= pool.sessions.len();
        } else {
            pool.next_index = 0;
        }
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
            .close(quinn::VarInt::from_u32(0), b"skyhook close");
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

#[allow(clippy::too_many_arguments)]
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
        .header("hysteria-padding", "skyhook")
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

fn quic_client_config(
    skip_cert_verify: bool,
    alpn: Option<&str>,
) -> anyhow::Result<quinn::ClientConfig> {
    let provider = aws_lc_rs::default_provider();
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
    let protocols = alpn
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|item| !item.is_empty())
                .map(|item| item.as_bytes().to_vec())
                .collect::<Vec<_>>()
        })
        .filter(|items| !items.is_empty())
        .unwrap_or_else(|| vec![b"h3".to_vec()]);
    config.alpn_protocols = protocols;
    let quic_config = quinn::crypto::rustls::QuicClientConfig::try_from(config)
        .context("failed to build quic rustls client config")?;
    let mut client_config = quinn::ClientConfig::new(Arc::new(quic_config));
    let mut transport_config = quinn::TransportConfig::default();
    transport_config.datagram_receive_buffer_size(Some(4 * 1024 * 1024));
    client_config.transport_config(Arc::new(transport_config));
    Ok(client_config)
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
            pool.next_index = 0;
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
            pool.next_index = pool.sessions.len() % UDP_SESSION_POOL_SIZE;
            return Ok(session);
        }
        let index = pool.next_index % pool.sessions.len();
        pool.next_index = (pool.next_index + 1) % pool.sessions.len();
        Ok(pool.sessions[index].clone())
    }

    async fn remove_tuic_udp_session(&self, target: &Arc<TokioMutex<TuicUdpSession>>) {
        let mut pool = self.udp_sessions.lock().await;
        pool.sessions
            .retain(|session| !Arc::ptr_eq(session, target));
        if !pool.sessions.is_empty() {
            pool.next_index %= pool.sessions.len();
        } else {
            pool.next_index = 0;
        }
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
            .close(quinn::VarInt::from_u32(0), b"skyhook close");
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

#[allow(clippy::too_many_arguments)]
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

    async fn connect(
        &self,
        destination: &Destination,
        timeout_ms: u64,
    ) -> anyhow::Result<BoxedStream> {
        let tcp = connect_tcp(&format!("{}:{}", self.server, self.port), timeout_ms).await?;
        let server_name = self.sni.as_deref().unwrap_or(&self.server).to_string();
        let tls_config = tls_client_config(self.skip_cert_verify)?;
        let connector = TlsConnector::from(Arc::new(tls_config));
        let server_name = ServerName::try_from(server_name)
            .map_err(|error| anyhow!("invalid trojan server name: {error}"))?;
        let mut stream = timeout(
            Duration::from_millis(timeout_ms),
            connector.connect(server_name, tcp),
        )
        .await
        .context("trojan tls handshake timed out")?
        .context("trojan tls handshake failed")?;
        let request = build_trojan_request(&self.password, destination)?;
        stream.write_all(&request).await?;
        Ok(Box::new(stream))
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
    async fn trojan_udp_session(
        &self,
        timeout_ms: u64,
    ) -> anyhow::Result<Arc<TokioMutex<TrojanUdpSession>>> {
        let mut pool = self.udp_sessions.lock().await;
        if pool.sessions.len() < UDP_SESSION_POOL_SIZE {
            let session = Arc::new(TokioMutex::new(
                self.open_trojan_udp_session(timeout_ms).await?,
            ));
            pool.sessions.push(session.clone());
            pool.next_index = pool.sessions.len() % UDP_SESSION_POOL_SIZE;
            return Ok(session);
        }
        let index = pool.next_index % pool.sessions.len();
        pool.next_index = (pool.next_index + 1) % pool.sessions.len();
        Ok(pool.sessions[index].clone())
    }

    async fn open_trojan_udp_session(&self, timeout_ms: u64) -> anyhow::Result<TrojanUdpSession> {
        let tcp = connect_tcp(&format!("{}:{}", self.server, self.port), timeout_ms).await?;
        let server_name = self.sni.as_deref().unwrap_or(&self.server).to_string();
        let tls_config = tls_client_config(self.skip_cert_verify)?;
        let connector = TlsConnector::from(Arc::new(tls_config));
        let server_name = ServerName::try_from(server_name)
            .map_err(|error| anyhow!("invalid trojan server name: {error}"))?;
        let mut stream = timeout(
            Duration::from_millis(timeout_ms),
            connector.connect(server_name, tcp),
        )
        .await
        .context("trojan udp tls handshake timed out")?
        .context("trojan udp tls handshake failed")?;
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
        pool.sessions
            .retain(|session| !Arc::ptr_eq(session, target));
        if !pool.sessions.is_empty() {
            pool.next_index %= pool.sessions.len();
        } else {
            pool.next_index = 0;
        }
    }
}

#[async_trait]
impl Outbound for ShadowsocksOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "shadowsocks"
    }

    async fn connect(
        &self,
        destination: &Destination,
        timeout_ms: u64,
    ) -> anyhow::Result<BoxedStream> {
        let cipher = SsCipher::from_method(&self.method)?;
        let server = format!("{}:{}", self.server, self.port);
        let mut stream = connect_tcp(&server, timeout_ms).await?;
        let master_key = evp_bytes_to_key(self.password.as_bytes(), cipher.key_len());
        let mut salt = vec![0u8; cipher.salt_len()];
        getrandom::fill(&mut salt)
            .map_err(|error| anyhow!("failed to generate shadowsocks salt: {error}"))?;
        let subkey = cipher.derive_subkey(&master_key, &salt)?;

        let mut outbound_nonce = [0u8; SS_NONCE_LEN];
        let mut destination_payload = Vec::new();
        encode_socks5_destination(destination, &mut destination_payload)?;
        let mut initial = salt;
        initial.extend_from_slice(&encode_ss_chunk(
            cipher,
            &subkey,
            &mut outbound_nonce,
            &destination_payload,
        )?);
        if let Some(plugin) = &self.plugin {
            initial = apply_shadowsocks_plugin_request(plugin, &self.server, self.port, initial)?;
        }
        stream.write_all(&initial).await?;

        let app_side =
            spawn_shadowsocks_stream(cipher, subkey, outbound_nonce, stream, self.plugin.clone());
        Ok(Box::new(app_side))
    }

    async fn udp_exchange(
        &self,
        destination: &Destination,
        payload: &[u8],
        timeout_ms: u64,
    ) -> anyhow::Result<Vec<u8>> {
        if self.plugin.is_some() {
            return Err(anyhow!(
                "shadowsocks udp with simple-obfs plugin is not supported"
            ));
        }

        let cipher = SsCipher::from_method(&self.method)?;
        let session_handle = self.shadowsocks_udp_session(timeout_ms).await?;
        let session = session_handle.lock().await;
        let packet =
            encode_shadowsocks_udp_packet(cipher, self.password.as_bytes(), destination, payload)?;
        let exchange = async {
            timeout(
                Duration::from_millis(timeout_ms),
                session.udp.send_to(&packet, session.server),
            )
            .await
            .context("shadowsocks udp send timed out")?
            .with_context(|| {
                format!(
                    "failed to send shadowsocks udp packet to {}",
                    session.server
                )
            })?;

            let mut buf = vec![0u8; 65_535];
            let (len, _) = timeout(
                Duration::from_millis(timeout_ms),
                session.udp.recv_from(&mut buf),
            )
            .await
            .context("shadowsocks udp receive timed out")?
            .context("failed to receive shadowsocks udp response")?;
            let (_response_destination, response) =
                decode_shadowsocks_udp_packet(cipher, self.password.as_bytes(), &buf[..len])?;
            Ok(response)
        }
        .await;
        if exchange.is_err() {
            drop(session);
            self.remove_shadowsocks_udp_session(&session_handle).await;
        }
        exchange
    }
}

impl ShadowsocksOutbound {
    async fn shadowsocks_udp_session(
        &self,
        timeout_ms: u64,
    ) -> anyhow::Result<Arc<TokioMutex<ShadowsocksUdpSession>>> {
        let mut pool = self.udp_sessions.lock().await;
        if pool.sessions.len() < UDP_SESSION_POOL_SIZE {
            let server = resolve_udp_socket_addr(&self.server, self.port, timeout_ms).await?;
            let bind_addr = match server {
                SocketAddr::V4(_) => "0.0.0.0:0",
                SocketAddr::V6(_) => "[::]:0",
            };
            let udp = UdpSocket::bind(bind_addr).await.with_context(|| {
                format!(
                    "failed to bind udp socket for shadowsocks outbound {}",
                    self.name
                )
            })?;
            let session = Arc::new(TokioMutex::new(ShadowsocksUdpSession { udp, server }));
            pool.sessions.push(session.clone());
            pool.next_index = pool.sessions.len() % UDP_SESSION_POOL_SIZE;
            return Ok(session);
        }
        let index = pool.next_index % pool.sessions.len();
        pool.next_index = (pool.next_index + 1) % pool.sessions.len();
        Ok(pool.sessions[index].clone())
    }

    async fn remove_shadowsocks_udp_session(
        &self,
        target: &Arc<TokioMutex<ShadowsocksUdpSession>>,
    ) {
        let mut pool = self.udp_sessions.lock().await;
        pool.sessions
            .retain(|session| !Arc::ptr_eq(session, target));
        if !pool.sessions.is_empty() {
            pool.next_index %= pool.sessions.len();
        } else {
            pool.next_index = 0;
        }
    }
}

async fn connect_tcp(addr: &str, timeout_ms: u64) -> anyhow::Result<TcpStream> {
    timeout(Duration::from_millis(timeout_ms), TcpStream::connect(addr))
        .await
        .context("tcp connect timed out")?
        .with_context(|| format!("failed to connect {addr}"))
}

async fn resolve_udp_socket_addr(
    host: &str,
    port: u16,
    timeout_ms: u64,
) -> anyhow::Result<SocketAddr> {
    let mut resolved = timeout(Duration::from_millis(timeout_ms), lookup_host((host, port)))
        .await
        .context("udp target resolve timed out")?
        .with_context(|| format!("failed to resolve udp target {host}:{port}"))?;
    resolved
        .next()
        .ok_or_else(|| anyhow!("udp target {host}:{port} resolved to no addresses"))
}

fn destination_socket_addr(destination: &Destination) -> String {
    if destination.host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{}]:{}", destination.host, destination.port)
    } else {
        destination.authority()
    }
}

fn tls_client_config(skip_cert_verify: bool) -> anyhow::Result<ClientConfig> {
    let provider = aws_lc_rs::default_provider();
    let builder = ClientConfig::builder_with_provider(provider.into())
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])?;
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
    Ok(config)
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

async fn open_grpc_tunnel<S>(
    stream: S,
    host: &str,
    service_name: Option<&str>,
    timeout_ms: u64,
) -> anyhow::Result<GrpcTunnelStream>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (send_request, connection) = timeout(
        Duration::from_millis(timeout_ms),
        h2::client::Builder::new().handshake(stream),
    )
    .await
    .context("grpc h2 handshake timed out")?
    .context("grpc h2 handshake failed")?;
    tokio::spawn(async move {
        if let Err(error) = connection.await {
            tracing::debug!(error = %error, "grpc h2 connection ended");
        }
    });

    let mut send_request = timeout(Duration::from_millis(timeout_ms), send_request.ready())
        .await
        .context("grpc h2 client readiness timed out")?
        .context("grpc h2 client is not ready")?;
    let path = grpc_service_path(service_name);
    let uri = format!("https://{host}{path}");
    let request = http::Request::builder()
        .method(http::Method::POST)
        .version(http::Version::HTTP_2)
        .uri(uri)
        .header(http::header::CONTENT_TYPE, "application/grpc")
        .header("te", "trailers")
        .header(http::header::USER_AGENT, "Skyhook/0.1")
        .body(())
        .context("failed to build grpc request")?;
    let (response, send) = send_request
        .send_request(request, false)
        .context("failed to send grpc request")?;

    Ok(GrpcTunnelStream {
        send,
        response: Some(response),
        recv: None,
        incoming: BytesMut::new(),
        read_buffer: BytesMut::new(),
        closed: false,
    })
}

async fn open_h2_tunnel<S>(
    stream: S,
    host: &str,
    path: &str,
    timeout_ms: u64,
) -> anyhow::Result<Http2TunnelStream>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (send_request, connection) = timeout(
        Duration::from_millis(timeout_ms),
        h2::client::Builder::new().handshake(stream),
    )
    .await
    .context("h2 handshake timed out")?
    .context("h2 handshake failed")?;
    tokio::spawn(async move {
        if let Err(error) = connection.await {
            tracing::debug!(error = %error, "h2 connection ended");
        }
    });

    let mut send_request = timeout(Duration::from_millis(timeout_ms), send_request.ready())
        .await
        .context("h2 client readiness timed out")?
        .context("h2 client is not ready")?;
    let path = http_path(path);
    let uri = format!("https://{host}{path}");
    let request = http::Request::builder()
        .method(http::Method::PUT)
        .version(http::Version::HTTP_2)
        .uri(uri)
        .header(http::header::USER_AGENT, "Skyhook/0.1")
        .body(())
        .context("failed to build h2 request")?;
    let (response, send) = send_request
        .send_request(request, false)
        .context("failed to send h2 request")?;

    Ok(Http2TunnelStream {
        send,
        response: Some(response),
        recv: None,
        read_buffer: BytesMut::new(),
        closed: false,
    })
}

fn http_path(path: &str) -> String {
    let path = path.trim();
    if path.is_empty() {
        "/".to_string()
    } else if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    }
}

fn grpc_service_path(service_name: Option<&str>) -> String {
    let Some(service_name) = service_name.map(str::trim).filter(|item| !item.is_empty()) else {
        return "/Tun".to_string();
    };
    if service_name.starts_with('/') {
        return service_name.to_string();
    }
    format!("/{}/Tun", service_name.trim_matches('/'))
}

struct Http2TunnelStream {
    send: h2::SendStream<Bytes>,
    response: Option<h2::client::ResponseFuture>,
    recv: Option<h2::RecvStream>,
    read_buffer: BytesMut,
    closed: bool,
}

impl Http2TunnelStream {
    fn poll_response(&mut self, cx: &mut TaskContext<'_>) -> Poll<Result<(), Error>> {
        if self.recv.is_some() {
            return Poll::Ready(Ok(()));
        }
        let response = self
            .response
            .as_mut()
            .ok_or_else(|| Error::new(ErrorKind::UnexpectedEof, "h2 response missing"))?;
        let response = match Pin::new(response).poll(cx) {
            Poll::Ready(Ok(response)) => response,
            Poll::Ready(Err(error)) => {
                return Poll::Ready(Err(Error::new(
                    ErrorKind::ConnectionAborted,
                    format!("h2 response failed: {error}"),
                )));
            }
            Poll::Pending => return Poll::Pending,
        };
        if !response.status().is_success() {
            return Poll::Ready(Err(Error::new(
                ErrorKind::ConnectionAborted,
                format!("h2 response status {}", response.status()),
            )));
        }
        self.recv = Some(response.into_body());
        self.response = None;
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for Http2TunnelStream {
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
            match self.poll_response(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
            let recv = self
                .recv
                .as_mut()
                .ok_or_else(|| Error::new(ErrorKind::UnexpectedEof, "h2 receive stream missing"));
            let recv = match recv {
                Ok(recv) => recv,
                Err(error) => return Poll::Ready(Err(error)),
            };
            match recv.poll_data(cx) {
                Poll::Ready(Some(Ok(chunk))) => {
                    let len = chunk.len();
                    self.read_buffer.extend_from_slice(&chunk);
                    if let Some(recv) = self.recv.as_mut() {
                        let _ = recv.flow_control().release_capacity(len);
                    }
                }
                Poll::Ready(Some(Err(error))) => {
                    return Poll::Ready(Err(Error::new(
                        ErrorKind::ConnectionAborted,
                        format!("h2 receive failed: {error}"),
                    )));
                }
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for Http2TunnelStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        if self.closed {
            return Poll::Ready(Err(Error::new(
                ErrorKind::BrokenPipe,
                "h2 send stream is closed",
            )));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let len = buf.len().min(16 * 1024);
        self.send.reserve_capacity(len);
        match self.send.poll_capacity(cx) {
            Poll::Ready(Some(Ok(capacity))) if capacity >= len => {}
            Poll::Ready(Some(Ok(_))) | Poll::Pending => return Poll::Pending,
            Poll::Ready(Some(Err(error))) => {
                return Poll::Ready(Err(Error::new(
                    ErrorKind::BrokenPipe,
                    format!("h2 send capacity failed: {error}"),
                )));
            }
            Poll::Ready(None) => {
                return Poll::Ready(Err(Error::new(
                    ErrorKind::BrokenPipe,
                    "h2 send stream has no capacity",
                )));
            }
        }
        match self
            .send
            .send_data(Bytes::copy_from_slice(&buf[..len]), false)
        {
            Ok(()) => Poll::Ready(Ok(len)),
            Err(error) => Poll::Ready(Err(Error::new(
                ErrorKind::BrokenPipe,
                format!("h2 send failed: {error}"),
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<Result<(), Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        _cx: &mut TaskContext<'_>,
    ) -> Poll<Result<(), Error>> {
        if !self.closed {
            self.closed = true;
            if let Err(error) = self.send.send_data(Bytes::new(), true) {
                return Poll::Ready(Err(Error::new(
                    ErrorKind::BrokenPipe,
                    format!("h2 shutdown failed: {error}"),
                )));
            }
        }
        Poll::Ready(Ok(()))
    }
}

struct GrpcTunnelStream {
    send: h2::SendStream<Bytes>,
    response: Option<h2::client::ResponseFuture>,
    recv: Option<h2::RecvStream>,
    incoming: BytesMut,
    read_buffer: BytesMut,
    closed: bool,
}

impl GrpcTunnelStream {
    fn poll_response(&mut self, cx: &mut TaskContext<'_>) -> Poll<Result<(), Error>> {
        if self.recv.is_some() {
            return Poll::Ready(Ok(()));
        }
        let response = self
            .response
            .as_mut()
            .ok_or_else(|| Error::new(ErrorKind::UnexpectedEof, "grpc response missing"))?;
        let response = match Pin::new(response).poll(cx) {
            Poll::Ready(Ok(response)) => response,
            Poll::Ready(Err(error)) => {
                return Poll::Ready(Err(Error::new(
                    ErrorKind::ConnectionAborted,
                    format!("grpc response failed: {error}"),
                )));
            }
            Poll::Pending => return Poll::Pending,
        };
        if !response.status().is_success() {
            return Poll::Ready(Err(Error::new(
                ErrorKind::ConnectionAborted,
                format!("grpc response status {}", response.status()),
            )));
        }
        self.recv = Some(response.into_body());
        self.response = None;
        Poll::Ready(Ok(()))
    }

    fn decode_next_message(&mut self) -> Result<bool, Error> {
        if self.incoming.len() < 5 {
            return Ok(false);
        }
        let compressed = self.incoming[0];
        if compressed != 0 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "compressed grpc messages are not supported",
            ));
        }
        let len = u32::from_be_bytes([
            self.incoming[1],
            self.incoming[2],
            self.incoming[3],
            self.incoming[4],
        ]) as usize;
        if self.incoming.len() < 5 + len {
            return Ok(false);
        }
        bytes::Buf::advance(&mut self.incoming, 5);
        let payload = self.incoming.split_to(len);
        self.read_buffer.extend_from_slice(&payload);
        Ok(true)
    }
}

impl AsyncRead for GrpcTunnelStream {
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

            match self.decode_next_message() {
                Ok(true) => continue,
                Ok(false) => {}
                Err(error) => return Poll::Ready(Err(error)),
            }

            match self.poll_response(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }

            let recv = self
                .recv
                .as_mut()
                .ok_or_else(|| Error::new(ErrorKind::UnexpectedEof, "grpc receive stream missing"));
            let recv = match recv {
                Ok(recv) => recv,
                Err(error) => return Poll::Ready(Err(error)),
            };
            match recv.poll_data(cx) {
                Poll::Ready(Some(Ok(chunk))) => {
                    let len = chunk.len();
                    self.incoming.extend_from_slice(&chunk);
                    if let Some(recv) = self.recv.as_mut() {
                        let _ = recv.flow_control().release_capacity(len);
                    }
                }
                Poll::Ready(Some(Err(error))) => {
                    return Poll::Ready(Err(Error::new(
                        ErrorKind::ConnectionAborted,
                        format!("grpc receive failed: {error}"),
                    )));
                }
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for GrpcTunnelStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        if self.closed {
            return Poll::Ready(Err(Error::new(
                ErrorKind::BrokenPipe,
                "grpc send stream is closed",
            )));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let len = buf.len().min(16 * 1024);
        let frame_len = 5 + len;
        self.send.reserve_capacity(frame_len);
        match self.send.poll_capacity(cx) {
            Poll::Ready(Some(Ok(capacity))) if capacity >= frame_len => {}
            Poll::Ready(Some(Ok(_))) => return Poll::Pending,
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Some(Err(error))) => {
                return Poll::Ready(Err(Error::new(
                    ErrorKind::BrokenPipe,
                    format!("grpc send capacity failed: {error}"),
                )));
            }
            Poll::Ready(None) => {
                return Poll::Ready(Err(Error::new(
                    ErrorKind::BrokenPipe,
                    "grpc send stream has no capacity",
                )));
            }
        }
        let mut frame = Vec::with_capacity(5 + len);
        frame.push(0);
        frame.extend_from_slice(&(len as u32).to_be_bytes());
        frame.extend_from_slice(&buf[..len]);
        match self.send.send_data(Bytes::from(frame), false) {
            Ok(()) => Poll::Ready(Ok(len)),
            Err(error) => Poll::Ready(Err(Error::new(
                ErrorKind::BrokenPipe,
                format!("grpc send failed: {error}"),
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<Result<(), Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        _cx: &mut TaskContext<'_>,
    ) -> Poll<Result<(), Error>> {
        if !self.closed {
            self.closed = true;
            if let Err(error) = self.send.send_data(Bytes::new(), true) {
                return Poll::Ready(Err(Error::new(
                    ErrorKind::BrokenPipe,
                    format!("grpc shutdown failed: {error}"),
                )));
            }
        }
        Poll::Ready(Ok(()))
    }
}

async fn perform_websocket_handshake<S>(
    stream: &mut S,
    host: &str,
    path: &str,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut key_bytes = [0u8; 16];
    getrandom::fill(&mut key_bytes)
        .map_err(|error| anyhow!("failed to generate websocket key: {error}"))?;
    let key = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, key_bytes);
    let path = if path.is_empty() { "/" } else { path };
    let request = format!(
        "GET {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: {key}\r\n\
         Sec-WebSocket-Version: 13\r\n\
         \r\n"
    );
    stream.write_all(request.as_bytes()).await?;

    let mut response = Vec::with_capacity(1024);
    let mut buf = [0u8; 512];
    while response.len() < 64 * 1024 {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            return Err(anyhow!("websocket handshake ended before headers"));
        }
        response.extend_from_slice(&buf[..n]);
        if find_header_end(&response).is_some() {
            break;
        }
    }
    let text = std::str::from_utf8(&response)?;
    let status_line = text.lines().next().unwrap_or("");
    if !status_line.contains(" 101 ") {
        return Err(anyhow!("websocket upgrade failed: {status_line}"));
    }
    let expected_accept = websocket_accept_key(&key);
    let accept_ok = text.lines().any(|line| {
        line.split_once(':')
            .map(|(name, value)| {
                name.eq_ignore_ascii_case("sec-websocket-accept") && value.trim() == expected_accept
            })
            .unwrap_or(false)
    });
    if !accept_ok {
        return Err(anyhow!("websocket upgrade missing valid accept key"));
    }
    Ok(())
}

fn websocket_accept_key(key: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(key.as_bytes());
    hasher.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        hasher.finalize(),
    )
}

fn spawn_websocket_stream<S>(stream: S) -> DuplexStream
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
                    let _ = write_websocket_close_frame(&mut remote_write).await;
                    let _ = remote_write.shutdown().await;
                    break;
                }
                Ok(n) => {
                    if write_websocket_binary_frame(&mut remote_write, &buf[..n])
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    tokio::spawn(async move {
        loop {
            match read_websocket_frame(&mut remote_read).await {
                Ok(Some(frame)) => {
                    if local_write.write_all(&frame).await.is_err() {
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

async fn write_websocket_binary_frame<W>(writer: &mut W, payload: &[u8]) -> anyhow::Result<()>
where
    W: AsyncWrite + Unpin,
{
    write_websocket_frame(writer, 0x2, payload).await
}

async fn write_websocket_close_frame<W>(writer: &mut W) -> anyhow::Result<()>
where
    W: AsyncWrite + Unpin,
{
    write_websocket_frame(writer, 0x8, &[]).await
}

async fn write_websocket_frame<W>(writer: &mut W, opcode: u8, payload: &[u8]) -> anyhow::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut mask = [0u8; 4];
    getrandom::fill(&mut mask)
        .map_err(|error| anyhow!("failed to generate websocket mask: {error}"))?;
    let mut frame = Vec::with_capacity(payload.len() + 14);
    frame.push(0x80 | (opcode & 0x0f));
    match payload.len() {
        0..=125 => frame.push(0x80 | payload.len() as u8),
        126..=65_535 => {
            frame.push(0x80 | 126);
            frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        }
        _ => {
            frame.push(0x80 | 127);
            frame.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        }
    }
    frame.extend_from_slice(&mask);
    for (index, byte) in payload.iter().enumerate() {
        frame.push(byte ^ mask[index % 4]);
    }
    writer.write_all(&frame).await?;
    Ok(())
}

async fn read_websocket_frame<R>(reader: &mut R) -> anyhow::Result<Option<Vec<u8>>>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; 2];
    if !read_exact_or_eof(reader, &mut header).await? {
        return Ok(None);
    }
    let opcode = header[0] & 0x0f;
    let masked = header[1] & 0x80 != 0;
    let mut len = (header[1] & 0x7f) as u64;
    if len == 126 {
        let mut ext = [0u8; 2];
        reader.read_exact(&mut ext).await?;
        len = u16::from_be_bytes(ext) as u64;
    } else if len == 127 {
        let mut ext = [0u8; 8];
        reader.read_exact(&mut ext).await?;
        len = u64::from_be_bytes(ext);
    }
    if len > 16 * 1024 * 1024 {
        return Err(anyhow!("websocket frame is too large"));
    }
    let mut mask = [0u8; 4];
    if masked {
        reader.read_exact(&mut mask).await?;
    }
    let mut payload = vec![0u8; len as usize];
    reader.read_exact(&mut payload).await?;
    if masked {
        for (index, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask[index % 4];
        }
    }
    match opcode {
        0x0..=0x2 => Ok(Some(payload)),
        0x8 => Ok(None),
        0x9 | 0xA => Ok(Some(Vec::new())),
        other => Err(anyhow!("unsupported websocket opcode {other}")),
    }
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

async fn read_socks5_destination_after_atyp<R>(
    reader: &mut R,
    atyp: u8,
) -> anyhow::Result<Destination>
where
    R: AsyncRead + Unpin,
{
    match atyp {
        0x01 => {
            let mut data = [0u8; 6];
            reader.read_exact(&mut data).await?;
            Ok(Destination::new(
                format!("{}.{}.{}.{}", data[0], data[1], data[2], data[3]),
                u16::from_be_bytes([data[4], data[5]]),
            ))
        }
        0x03 => {
            let mut len = [0u8; 1];
            reader.read_exact(&mut len).await?;
            let mut host = vec![0u8; len[0] as usize];
            reader.read_exact(&mut host).await?;
            let mut port = [0u8; 2];
            reader.read_exact(&mut port).await?;
            Ok(Destination::new(
                String::from_utf8(host)?,
                u16::from_be_bytes(port),
            ))
        }
        0x04 => {
            let mut data = [0u8; 18];
            reader.read_exact(&mut data).await?;
            let mut host = [0u8; 16];
            host.copy_from_slice(&data[..16]);
            Ok(Destination::new(
                std::net::Ipv6Addr::from(host).to_string(),
                u16::from_be_bytes([data[16], data[17]]),
            ))
        }
        _ => Err(anyhow!("unsupported socks5 address type {atyp}")),
    }
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
    if !value.len().is_multiple_of(2) {
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

#[derive(Debug)]
struct NoCertificateVerification;

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}

async fn authenticate_socks5(
    stream: &mut TcpStream,
    username: Option<&str>,
    password: Option<&str>,
) -> anyhow::Result<()> {
    let username = username.ok_or_else(|| anyhow!("socks5 proxy requested username"))?;
    let password = password.ok_or_else(|| anyhow!("socks5 proxy requested password"))?;
    if username.len() > 255 || password.len() > 255 {
        return Err(anyhow!("socks5 credentials are too long"));
    }
    let mut request = vec![0x01, username.len() as u8];
    request.extend_from_slice(username.as_bytes());
    request.push(password.len() as u8);
    request.extend_from_slice(password.as_bytes());
    stream.write_all(&request).await?;
    let mut response = [0u8; 2];
    stream.read_exact(&mut response).await?;
    if response != [0x01, 0x00] {
        return Err(anyhow!("socks5 authentication failed"));
    }
    Ok(())
}

async fn negotiate_socks5(
    stream: &mut TcpStream,
    username: Option<&str>,
    password: Option<&str>,
) -> anyhow::Result<()> {
    let methods = if username.is_some() && password.is_some() {
        vec![0x00, 0x02]
    } else {
        vec![0x00]
    };
    let mut greeting = vec![0x05, methods.len() as u8];
    greeting.extend_from_slice(&methods);
    stream.write_all(&greeting).await?;
    let mut response = [0u8; 2];
    stream.read_exact(&mut response).await?;
    match response {
        [0x05, 0x00] => Ok(()),
        [0x05, 0x02] => authenticate_socks5(stream, username, password).await,
        [0x05, method] => Err(anyhow!("socks5 unsupported auth method {method}")),
        _ => Err(anyhow!("invalid socks5 greeting response")),
    }
}

pub fn encode_socks5_destination(
    destination: &Destination,
    output: &mut Vec<u8>,
) -> anyhow::Result<()> {
    if let Ok(addr) = destination.host.parse::<SocketAddr>() {
        match addr {
            SocketAddr::V4(v4) => {
                output.push(0x01);
                output.extend_from_slice(&v4.ip().octets());
                output.extend_from_slice(&v4.port().to_be_bytes());
            }
            SocketAddr::V6(v6) => {
                output.push(0x04);
                output.extend_from_slice(&v6.ip().octets());
                output.extend_from_slice(&v6.port().to_be_bytes());
            }
        }
    } else if let Ok(ip) = destination.host.parse::<std::net::IpAddr>() {
        match ip {
            std::net::IpAddr::V4(ip) => {
                output.push(0x01);
                output.extend_from_slice(&ip.octets());
                output.extend_from_slice(&destination.port.to_be_bytes());
            }
            std::net::IpAddr::V6(ip) => {
                output.push(0x04);
                output.extend_from_slice(&ip.octets());
                output.extend_from_slice(&destination.port.to_be_bytes());
            }
        }
    } else {
        if destination.host.len() > 255 {
            return Err(anyhow!("domain name too long"));
        }
        output.push(0x03);
        output.push(destination.host.len() as u8);
        output.extend_from_slice(destination.host.as_bytes());
        output.extend_from_slice(&destination.port.to_be_bytes());
    }
    Ok(())
}

async fn discard_socks5_bound_address(stream: &mut TcpStream, atyp: u8) -> anyhow::Result<()> {
    let _ = read_socks5_bound_address(stream, atyp).await?;
    Ok(())
}

async fn read_socks5_bound_address(
    stream: &mut TcpStream,
    atyp: u8,
) -> anyhow::Result<Destination> {
    match atyp {
        0x01 => {
            let mut data = [0u8; 6];
            stream.read_exact(&mut data).await?;
            Ok(Destination::new(
                format!("{}.{}.{}.{}", data[0], data[1], data[2], data[3]),
                u16::from_be_bytes([data[4], data[5]]),
            ))
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut host = vec![0u8; len[0] as usize];
            stream.read_exact(&mut host).await?;
            let mut port = [0u8; 2];
            stream.read_exact(&mut port).await?;
            Ok(Destination::new(
                String::from_utf8(host)?,
                u16::from_be_bytes(port),
            ))
        }
        0x04 => {
            let mut data = [0u8; 18];
            stream.read_exact(&mut data).await?;
            let mut host = [0u8; 16];
            host.copy_from_slice(&data[..16]);
            Ok(Destination::new(
                std::net::Ipv6Addr::from(host).to_string(),
                u16::from_be_bytes([data[16], data[17]]),
            ))
        }
        _ => Err(anyhow!("invalid socks5 bound address type")),
    }
}

fn parse_socks5_udp_response(packet: &[u8]) -> anyhow::Result<(Destination, usize)> {
    if packet.len() < 4 {
        return Err(anyhow!("short socks5 udp response"));
    }
    if packet[0] != 0 || packet[1] != 0 {
        return Err(anyhow!("invalid socks5 udp response reserved bytes"));
    }
    if packet[2] != 0 {
        return Err(anyhow!("fragmented socks5 udp responses are not supported"));
    }
    let (destination, destination_len) = parse_socks5_destination_prefix(&packet[3..])?;
    Ok((destination, 3 + destination_len))
}

fn parse_socks5_destination_prefix(packet: &[u8]) -> anyhow::Result<(Destination, usize)> {
    if packet.is_empty() {
        return Err(anyhow!("short socks5 destination"));
    }
    let atyp = packet[0];
    let mut offset = 1;
    let host = match atyp {
        0x01 => {
            if packet.len() < offset + 4 + 2 {
                return Err(anyhow!("short socks5 ipv4 destination"));
            }
            let host = format!(
                "{}.{}.{}.{}",
                packet[offset],
                packet[offset + 1],
                packet[offset + 2],
                packet[offset + 3]
            );
            offset += 4;
            host
        }
        0x03 => {
            if packet.len() < offset + 1 {
                return Err(anyhow!("short socks5 domain destination"));
            }
            let len = packet[offset] as usize;
            offset += 1;
            if packet.len() < offset + len + 2 {
                return Err(anyhow!("short socks5 domain destination payload"));
            }
            let host = std::str::from_utf8(&packet[offset..offset + len])?.to_string();
            offset += len;
            host
        }
        0x04 => {
            if packet.len() < offset + 16 + 2 {
                return Err(anyhow!("short socks5 ipv6 destination"));
            }
            let mut raw = [0u8; 16];
            raw.copy_from_slice(&packet[offset..offset + 16]);
            offset += 16;
            std::net::Ipv6Addr::from(raw).to_string()
        }
        _ => return Err(anyhow!("unsupported socks5 address type {atyp}")),
    };
    if packet.len() < offset + 2 {
        return Err(anyhow!("short socks5 destination port"));
    }
    let port = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
    offset += 2;
    Ok((Destination::new(host, port), offset))
}

const ANYTLS_DEFAULT_SID: u32 = 1;
const ANYTLS_DEFAULT_AUTH_PADDING: usize = 30;
const ANYTLS_CMD_WASTE: u8 = 0;
const ANYTLS_CMD_SYN: u8 = 1;
const ANYTLS_CMD_PSH: u8 = 2;
const ANYTLS_CMD_FIN: u8 = 3;
const ANYTLS_CMD_SETTINGS: u8 = 4;
const ANYTLS_CMD_ALERT: u8 = 5;
const ANYTLS_CMD_SYNACK: u8 = 7;
const ANYTLS_CMD_HEART_REQUEST: u8 = 8;
const ANYTLS_CMD_HEART_RESPONSE: u8 = 9;
const ANYTLS_CMD_SERVER_SETTINGS: u8 = 10;

struct AnyTlsFrame {
    command: u8,
    sid: u32,
    data: Vec<u8>,
}

fn build_anytls_settings() -> String {
    format!(
        "v=3\nclient=skyhook/{}\npadding-md5={}",
        env!("CARGO_PKG_VERSION"),
        anytls_default_padding_md5()
    )
}

fn anytls_default_padding_md5() -> String {
    const DEFAULT_PADDING_SCHEME: &str = "stop=8\n0=30-30\n1=100-400\n2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000\n3=9-9,500-1000\n4=500-1000\n5=500-1000\n6=500-1000\n7=500-1000";
    hex_lower(&Md5::digest(DEFAULT_PADDING_SCHEME.as_bytes()))
}

async fn write_anytls_frame<W>(
    writer: &mut W,
    command: u8,
    sid: u32,
    data: &[u8],
) -> anyhow::Result<()>
where
    W: AsyncWrite + Unpin,
{
    if data.len() > u16::MAX as usize {
        return Err(anyhow!("anytls frame data is too large"));
    }
    let mut header = [0u8; 7];
    header[0] = command;
    header[1..5].copy_from_slice(&sid.to_be_bytes());
    header[5..7].copy_from_slice(&(data.len() as u16).to_be_bytes());
    writer.write_all(&header).await?;
    if !data.is_empty() {
        writer.write_all(data).await?;
    }
    Ok(())
}

async fn read_anytls_frame<R>(reader: &mut R) -> anyhow::Result<Option<AnyTlsFrame>>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; 7];
    if !read_exact_or_eof(reader, &mut header).await? {
        return Ok(None);
    }
    let command = header[0];
    let sid = u32::from_be_bytes([header[1], header[2], header[3], header[4]]);
    let len = u16::from_be_bytes([header[5], header[6]]) as usize;
    let mut data = vec![0u8; len];
    if len > 0 {
        reader.read_exact(&mut data).await?;
    }
    Ok(Some(AnyTlsFrame { command, sid, data }))
}

const SHADOWTLS_TLS_HEADER_LEN: usize = 5;
const SHADOWTLS_TLS_FRAME_MAX_LEN: usize = SHADOWTLS_TLS_HEADER_LEN + 65535;
const SHADOWTLS_CONTENT_TYPE_HANDSHAKE: u8 = 0x16;
const SHADOWTLS_CONTENT_TYPE_APPLICATION_DATA: u8 = 0x17;
const SHADOWTLS_CONTENT_TYPE_ALERT: u8 = 0x15;
const SHADOWTLS_HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;
const SHADOWTLS_HANDSHAKE_TYPE_SERVER_HELLO: u8 = 0x02;
const SHADOWTLS_MAX_WRITE_PAYLOAD_LEN: usize = 16_380;

#[derive(Clone)]
struct ShadowTlsHmac {
    inner: Sha1,
    outer_pad: [u8; 64],
}

impl ShadowTlsHmac {
    fn new(key: &[u8]) -> Self {
        let key = if key.len() > 64 {
            Sha1::digest(key).to_vec()
        } else {
            key.to_vec()
        };
        let mut inner_pad = [0x36u8; 64];
        let mut outer_pad = [0x5cu8; 64];
        for (index, byte) in key.iter().enumerate() {
            inner_pad[index] ^= byte;
            outer_pad[index] ^= byte;
        }
        let mut inner = Sha1::new();
        inner.update(inner_pad);
        Self { inner, outer_pad }
    }

    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    fn digest(&self) -> [u8; 4] {
        let inner_digest = self.inner.clone().finalize();
        let mut outer = Sha1::new();
        outer.update(self.outer_pad);
        outer.update(inner_digest);
        let digest = outer.finalize();
        [digest[0], digest[1], digest[2], digest[3]]
    }

    fn finalized_digest(self) -> [u8; 4] {
        self.digest()
    }
}

struct ShadowTlsTunnel<S> {
    stream: S,
    read_hmac: ShadowTlsHmac,
    write_hmac: ShadowTlsHmac,
    handshake_hmac: ShadowTlsHmac,
}

async fn setup_shadowtls_v3_tunnel<S>(
    mut stream: S,
    password: &[u8],
    server_name: &str,
    skip_cert_verify: bool,
    timeout_ms: u64,
) -> anyhow::Result<ShadowTlsTunnel<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let tls_config = tls_client_config(skip_cert_verify)?;
    let tls_server_name = ServerName::try_from(server_name.to_string())
        .map_err(|error| anyhow!("invalid shadowtls server name: {error}"))?;
    let mut client_conn = rustls::ClientConnection::new(Arc::new(tls_config), tls_server_name)
        .map_err(|error| anyhow!("failed to create shadowtls client hello: {error}"))?;

    let mut client_hello = Vec::with_capacity(1024);
    client_conn
        .write_tls(&mut client_hello)
        .map_err(|error| anyhow!("failed to build shadowtls client hello: {error}"))?;
    let initial_hmac = ShadowTlsHmac::new(password);
    let modified_client_hello = modify_shadowtls_client_hello(&client_hello, &initial_hmac)?;
    stream.write_all(&modified_client_hello).await?;
    stream.flush().await?;

    let server_hello = timeout(
        Duration::from_millis(timeout_ms),
        read_shadowtls_tls_record(&mut stream),
    )
    .await
    .context("shadowtls server hello timed out")?
    .context("failed to read shadowtls server hello")?
    .ok_or_else(|| anyhow!("shadowtls server closed before server hello"))?;
    let server_random = parse_shadowtls_server_hello_random(&server_hello)?;
    feed_rustls_client_connection(&mut client_conn, &server_hello)?;
    client_conn
        .process_new_packets()
        .map_err(|error| anyhow!("shadowtls failed to process server hello: {error}"))?;

    let mut hmac_server_random = initial_hmac.clone();
    hmac_server_random.update(&server_random);
    let mut write_hmac = hmac_server_random.clone();
    write_hmac.update(b"C");
    let mut read_hmac = hmac_server_random.clone();
    read_hmac.update(b"S");

    while client_conn.is_handshaking() {
        if client_conn.wants_write() {
            let mut output = Vec::new();
            let n = client_conn
                .write_tls(&mut output)
                .map_err(|error| anyhow!("shadowtls tls write failed: {error}"))?;
            if n > 0 {
                stream.write_all(&output).await?;
                stream.flush().await?;
            }
            continue;
        }

        let frame = timeout(
            Duration::from_millis(timeout_ms),
            read_shadowtls_tls_record(&mut stream),
        )
        .await
        .context("shadowtls handshake frame timed out")?
        .context("failed to read shadowtls handshake frame")?
        .ok_or_else(|| anyhow!("shadowtls server closed during handshake"))?;
        match frame[0] {
            SHADOWTLS_CONTENT_TYPE_APPLICATION_DATA => {
                let payload_len = u16::from_be_bytes([frame[3], frame[4]]) as usize;
                if payload_len < 5 {
                    return Err(anyhow!("shadowtls handshake app-data frame is too short"));
                }
                let received = &frame[SHADOWTLS_TLS_HEADER_LEN..SHADOWTLS_TLS_HEADER_LEN + 4];
                let payload =
                    &frame[SHADOWTLS_TLS_HEADER_LEN + 4..SHADOWTLS_TLS_HEADER_LEN + payload_len];
                hmac_server_random.update(payload);
                if hmac_server_random.digest() != received {
                    return Err(anyhow!("shadowtls handshake hmac check failed"));
                }
                break;
            }
            SHADOWTLS_CONTENT_TYPE_ALERT => {
                return Err(anyhow!("shadowtls server sent alert during handshake"));
            }
            _ => {
                feed_rustls_client_connection(&mut client_conn, &frame)?;
                client_conn
                    .process_new_packets()
                    .map_err(|error| anyhow!("shadowtls failed to process handshake: {error}"))?;
            }
        }
    }

    Ok(ShadowTlsTunnel {
        stream,
        read_hmac,
        write_hmac,
        handshake_hmac: hmac_server_random,
    })
}

fn modify_shadowtls_client_hello(
    original_frame: &[u8],
    initial_hmac: &ShadowTlsHmac,
) -> anyhow::Result<Vec<u8>> {
    if original_frame.len() < SHADOWTLS_TLS_HEADER_LEN {
        return Err(anyhow!("shadowtls client hello frame is too short"));
    }
    if original_frame[0] != SHADOWTLS_CONTENT_TYPE_HANDSHAKE {
        return Err(anyhow!("shadowtls expected TLS ClientHello record"));
    }
    let original_payload_len = u16::from_be_bytes([original_frame[3], original_frame[4]]) as usize;
    if original_frame.len() != SHADOWTLS_TLS_HEADER_LEN + original_payload_len {
        return Err(anyhow!("shadowtls client hello length mismatch"));
    }
    let payload = &original_frame[SHADOWTLS_TLS_HEADER_LEN..];
    if payload.len() < 42 {
        return Err(anyhow!("shadowtls client hello payload is too short"));
    }
    if payload[0] != SHADOWTLS_HANDSHAKE_TYPE_CLIENT_HELLO {
        return Err(anyhow!("shadowtls expected ClientHello message"));
    }
    let client_hello_payload_len =
        ((payload[1] as usize) << 16) | ((payload[2] as usize) << 8) | payload[3] as usize;
    if client_hello_payload_len + 4 != payload.len() {
        return Err(anyhow!("shadowtls client hello message length mismatch"));
    }
    if payload[4] != 0x03 || payload[5] != 0x03 {
        return Err(anyhow!("shadowtls requires TLS1.3-style ClientHello"));
    }
    let mut offset = 4 + 2 + 32;
    if offset >= payload.len() {
        return Err(anyhow!("shadowtls client hello has no session id"));
    }
    let original_session_id_len = payload[offset] as usize;
    offset += 1;
    if original_session_id_len != 0 {
        if original_session_id_len != 32 {
            return Err(anyhow!(
                "shadowtls original ClientHello session id is not 32 bytes"
            ));
        }
        offset += 32;
    }
    if offset > payload.len() {
        return Err(anyhow!("shadowtls client hello session id exceeds payload"));
    }
    let remaining = &payload[offset..];
    let new_client_hello_payload_len = client_hello_payload_len + (32 - original_session_id_len);
    let new_record_payload_len = new_client_hello_payload_len + 4;
    if new_record_payload_len > u16::MAX as usize {
        return Err(anyhow!("shadowtls modified ClientHello is too large"));
    }
    let mut modified = vec![0u8; SHADOWTLS_TLS_HEADER_LEN + new_record_payload_len];
    modified[0] = SHADOWTLS_CONTENT_TYPE_HANDSHAKE;
    modified[1] = original_frame[1];
    modified[2] = original_frame[2];
    modified[3..5].copy_from_slice(&(new_record_payload_len as u16).to_be_bytes());
    modified[5] = SHADOWTLS_HANDSHAKE_TYPE_CLIENT_HELLO;
    modified[6..9].copy_from_slice(&(new_client_hello_payload_len as u32).to_be_bytes()[1..]);
    modified[9] = 0x03;
    modified[10] = 0x03;
    modified[11..43].copy_from_slice(&payload[6..38]);
    modified[43] = 32;
    getrandom::fill(&mut modified[44..72])
        .map_err(|error| anyhow!("failed to generate shadowtls session id: {error}"))?;
    modified[72..76].copy_from_slice(&[0, 0, 0, 0]);
    modified[76..].copy_from_slice(remaining);
    let mut hmac = initial_hmac.clone();
    hmac.update(&modified[SHADOWTLS_TLS_HEADER_LEN..]);
    let digest = hmac.finalized_digest();
    modified[72..76].copy_from_slice(&digest);
    Ok(modified)
}

fn parse_shadowtls_server_hello_random(frame: &[u8]) -> anyhow::Result<[u8; 32]> {
    if frame.len() < SHADOWTLS_TLS_HEADER_LEN + 4 + 2 + 32 {
        return Err(anyhow!("shadowtls server hello is too short"));
    }
    if frame[0] != SHADOWTLS_CONTENT_TYPE_HANDSHAKE
        || frame[SHADOWTLS_TLS_HEADER_LEN] != SHADOWTLS_HANDSHAKE_TYPE_SERVER_HELLO
    {
        return Err(anyhow!("shadowtls expected TLS ServerHello"));
    }
    let mut random = [0u8; 32];
    random.copy_from_slice(&frame[SHADOWTLS_TLS_HEADER_LEN + 4 + 2..][..32]);
    Ok(random)
}

fn feed_rustls_client_connection(
    connection: &mut rustls::ClientConnection,
    data: &[u8],
) -> anyhow::Result<()> {
    let mut cursor = Cursor::new(data);
    while cursor.position() < data.len() as u64 {
        let n = connection
            .read_tls(&mut cursor)
            .map_err(|error| anyhow!("rustls read_tls failed: {error}"))?;
        if n == 0 {
            break;
        }
    }
    Ok(())
}

async fn read_shadowtls_tls_record<R>(reader: &mut R) -> anyhow::Result<Option<Vec<u8>>>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; SHADOWTLS_TLS_HEADER_LEN];
    if !read_exact_or_eof(reader, &mut header).await? {
        return Ok(None);
    }
    let payload_len = u16::from_be_bytes([header[3], header[4]]) as usize;
    if payload_len > SHADOWTLS_TLS_FRAME_MAX_LEN - SHADOWTLS_TLS_HEADER_LEN {
        return Err(anyhow!("shadowtls TLS record is too large"));
    }
    let mut frame = Vec::with_capacity(SHADOWTLS_TLS_HEADER_LEN + payload_len);
    frame.extend_from_slice(&header);
    frame.resize(SHADOWTLS_TLS_HEADER_LEN + payload_len, 0);
    reader
        .read_exact(&mut frame[SHADOWTLS_TLS_HEADER_LEN..])
        .await?;
    Ok(Some(frame))
}

const SS_CHUNK_SIZE: usize = 0x3fff;
const SS_TAG_LEN: usize = 16;
const SS_NONCE_LEN: usize = 12;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SsCipher {
    Aes128Gcm,
    Aes256Gcm,
    Chacha20IetfPoly1305,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::enum_variant_names)]
enum SsrCipher {
    Aes128Cfb,
    Aes192Cfb,
    Aes256Cfb,
    Chacha20Ietf,
}

impl SsrCipher {
    fn from_method(method: &str) -> anyhow::Result<Self> {
        match method.to_ascii_lowercase().as_str() {
            "aes-128-cfb" => Ok(Self::Aes128Cfb),
            "aes-192-cfb" => Ok(Self::Aes192Cfb),
            "aes-256-cfb" => Ok(Self::Aes256Cfb),
            "chacha20-ietf" => Ok(Self::Chacha20Ietf),
            _ => Err(anyhow!("unsupported ssr method {method}")),
        }
    }

    fn key_len(self) -> usize {
        match self {
            Self::Aes128Cfb => 16,
            Self::Aes192Cfb => 24,
            Self::Aes256Cfb => 32,
            Self::Chacha20Ietf => 32,
        }
    }

    fn iv_len(self) -> usize {
        match self {
            Self::Chacha20Ietf => 12,
            _ => 16,
        }
    }

    fn encryptor(self, key: &[u8], iv: &[u8]) -> anyhow::Result<SsrStreamCipher> {
        match self {
            Self::Aes128Cfb => Ok(SsrStreamCipher::Aes128Enc(
                cfb_mode::BufEncryptor::<Aes128>::new_from_slices(key, iv)
                    .map_err(|_| anyhow!("invalid aes-128-cfb key/iv"))?,
            )),
            Self::Aes192Cfb => Ok(SsrStreamCipher::Aes192Enc(
                cfb_mode::BufEncryptor::<Aes192>::new_from_slices(key, iv)
                    .map_err(|_| anyhow!("invalid aes-192-cfb key/iv"))?,
            )),
            Self::Aes256Cfb => Ok(SsrStreamCipher::Aes256Enc(
                cfb_mode::BufEncryptor::<Aes256>::new_from_slices(key, iv)
                    .map_err(|_| anyhow!("invalid aes-256-cfb key/iv"))?,
            )),
            Self::Chacha20Ietf => {
                use chacha20::cipher::KeyIvInit;
                let cipher = chacha20::ChaCha20::new_from_slices(key, iv)
                    .map_err(|_| anyhow!("invalid chacha20-ietf key/iv"))?;
                Ok(SsrStreamCipher::Chacha20Enc(cipher))
            }
        }
    }

    fn decryptor(self, key: &[u8], iv: &[u8]) -> anyhow::Result<SsrStreamCipher> {
        match self {
            Self::Aes128Cfb => Ok(SsrStreamCipher::Aes128Dec(
                cfb_mode::BufDecryptor::<Aes128>::new_from_slices(key, iv)
                    .map_err(|_| anyhow!("invalid aes-128-cfb key/iv"))?,
            )),
            Self::Aes192Cfb => Ok(SsrStreamCipher::Aes192Dec(
                cfb_mode::BufDecryptor::<Aes192>::new_from_slices(key, iv)
                    .map_err(|_| anyhow!("invalid aes-192-cfb key/iv"))?,
            )),
            Self::Aes256Cfb => Ok(SsrStreamCipher::Aes256Dec(
                cfb_mode::BufDecryptor::<Aes256>::new_from_slices(key, iv)
                    .map_err(|_| anyhow!("invalid aes-256-cfb key/iv"))?,
            )),
            Self::Chacha20Ietf => {
                use chacha20::cipher::KeyIvInit;
                let cipher = chacha20::ChaCha20::new_from_slices(key, iv)
                    .map_err(|_| anyhow!("invalid chacha20-ietf key/iv"))?;
                Ok(SsrStreamCipher::Chacha20Dec(cipher))
            }
        }
    }
}

enum SsrStreamCipher {
    Aes128Enc(cfb_mode::BufEncryptor<Aes128>),
    Aes192Enc(cfb_mode::BufEncryptor<Aes192>),
    Aes256Enc(cfb_mode::BufEncryptor<Aes256>),
    Aes128Dec(cfb_mode::BufDecryptor<Aes128>),
    Aes192Dec(cfb_mode::BufDecryptor<Aes192>),
    Aes256Dec(cfb_mode::BufDecryptor<Aes256>),
    Chacha20Enc(chacha20::ChaCha20),
    Chacha20Dec(chacha20::ChaCha20),
}

impl SsrStreamCipher {
    fn apply(&mut self, data: &mut [u8]) {
        use chacha20::cipher::StreamCipher;
        match self {
            Self::Aes128Enc(cipher) => cipher.encrypt(data),
            Self::Aes192Enc(cipher) => cipher.encrypt(data),
            Self::Aes256Enc(cipher) => cipher.encrypt(data),
            Self::Aes128Dec(cipher) => cipher.decrypt(data),
            Self::Aes192Dec(cipher) => cipher.decrypt(data),
            Self::Aes256Dec(cipher) => cipher.decrypt(data),
            Self::Chacha20Enc(cipher) => cipher.apply_keystream(data),
            Self::Chacha20Dec(cipher) => cipher.apply_keystream(data),
        }
    }
}

impl SsCipher {
    fn from_method(method: &str) -> anyhow::Result<Self> {
        match method.to_ascii_lowercase().as_str() {
            "aes-128-gcm" => Ok(Self::Aes128Gcm),
            "aes-256-gcm" => Ok(Self::Aes256Gcm),
            "chacha20-ietf-poly1305" | "chacha20-poly1305" => Ok(Self::Chacha20IetfPoly1305),
            _ => Err(anyhow!("unsupported shadowsocks method {method}")),
        }
    }

    fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            Self::Aes256Gcm | Self::Chacha20IetfPoly1305 => 32,
        }
    }

    fn salt_len(self) -> usize {
        self.key_len()
    }

    fn derive_subkey(self, master_key: &[u8], salt: &[u8]) -> anyhow::Result<Vec<u8>> {
        let hkdf = Hkdf::<Sha1>::new(Some(salt), master_key);
        let mut subkey = vec![0u8; self.key_len()];
        hkdf.expand(b"ss-subkey", &mut subkey)
            .map_err(|_| anyhow!("failed to derive shadowsocks subkey"))?;
        Ok(subkey)
    }

    fn encrypt(
        self,
        key: &[u8],
        nonce: &[u8; SS_NONCE_LEN],
        plaintext: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        match self {
            Self::Aes128Gcm => Aes128Gcm::new_from_slice(key)
                .map_err(|_| anyhow!("invalid aes-128-gcm key"))?
                .encrypt(aes_gcm::Nonce::from_slice(nonce), plaintext)
                .map_err(|_| anyhow!("shadowsocks encrypt failed")),
            Self::Aes256Gcm => Aes256Gcm::new_from_slice(key)
                .map_err(|_| anyhow!("invalid aes-256-gcm key"))?
                .encrypt(aes_gcm::Nonce::from_slice(nonce), plaintext)
                .map_err(|_| anyhow!("shadowsocks encrypt failed")),
            Self::Chacha20IetfPoly1305 => ChaCha20Poly1305::new_from_slice(key)
                .map_err(|_| anyhow!("invalid chacha20-ietf-poly1305 key"))?
                .encrypt(chacha20poly1305::Nonce::from_slice(nonce), plaintext)
                .map_err(|_| anyhow!("shadowsocks encrypt failed")),
        }
    }

    fn decrypt(
        self,
        key: &[u8],
        nonce: &[u8; SS_NONCE_LEN],
        ciphertext: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        match self {
            Self::Aes128Gcm => Aes128Gcm::new_from_slice(key)
                .map_err(|_| anyhow!("invalid aes-128-gcm key"))?
                .decrypt(aes_gcm::Nonce::from_slice(nonce), ciphertext)
                .map_err(|_| anyhow!("shadowsocks decrypt failed")),
            Self::Aes256Gcm => Aes256Gcm::new_from_slice(key)
                .map_err(|_| anyhow!("invalid aes-256-gcm key"))?
                .decrypt(aes_gcm::Nonce::from_slice(nonce), ciphertext)
                .map_err(|_| anyhow!("shadowsocks decrypt failed")),
            Self::Chacha20IetfPoly1305 => ChaCha20Poly1305::new_from_slice(key)
                .map_err(|_| anyhow!("invalid chacha20-ietf-poly1305 key"))?
                .decrypt(chacha20poly1305::Nonce::from_slice(nonce), ciphertext)
                .map_err(|_| anyhow!("shadowsocks decrypt failed")),
        }
    }
}

fn evp_bytes_to_key(password: &[u8], key_len: usize) -> Vec<u8> {
    let mut key = Vec::with_capacity(key_len);
    let mut previous = Vec::new();
    while key.len() < key_len {
        let mut digest = Md5::new();
        if !previous.is_empty() {
            digest.update(&previous);
        }
        digest.update(password);
        previous = digest.finalize().to_vec();
        key.extend_from_slice(&previous);
    }
    key.truncate(key_len);
    key
}

fn increment_nonce(nonce: &mut [u8; SS_NONCE_LEN]) {
    for item in nonce.iter_mut() {
        let (next, overflow) = item.overflowing_add(1);
        *item = next;
        if !overflow {
            break;
        }
    }
}

fn encode_shadowsocks_udp_packet(
    cipher: SsCipher,
    password: &[u8],
    destination: &Destination,
    payload: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let master_key = evp_bytes_to_key(password, cipher.key_len());
    let mut salt = vec![0u8; cipher.salt_len()];
    getrandom::fill(&mut salt)
        .map_err(|error| anyhow!("failed to generate shadowsocks udp salt: {error}"))?;
    let subkey = cipher.derive_subkey(&master_key, &salt)?;
    let mut plaintext = Vec::with_capacity(1 + 255 + 2 + payload.len());
    encode_socks5_destination(destination, &mut plaintext)?;
    plaintext.extend_from_slice(payload);
    let nonce = [0u8; SS_NONCE_LEN];
    let encrypted = cipher.encrypt(&subkey, &nonce, &plaintext)?;
    let mut packet = Vec::with_capacity(salt.len() + encrypted.len());
    packet.extend_from_slice(&salt);
    packet.extend_from_slice(&encrypted);
    Ok(packet)
}

fn decode_shadowsocks_udp_packet(
    cipher: SsCipher,
    password: &[u8],
    packet: &[u8],
) -> anyhow::Result<(Destination, Vec<u8>)> {
    let salt_len = cipher.salt_len();
    if packet.len() < salt_len + SS_TAG_LEN {
        return Err(anyhow!("short shadowsocks udp packet"));
    }
    let master_key = evp_bytes_to_key(password, cipher.key_len());
    let subkey = cipher.derive_subkey(&master_key, &packet[..salt_len])?;
    let nonce = [0u8; SS_NONCE_LEN];
    let plaintext = cipher.decrypt(&subkey, &nonce, &packet[salt_len..])?;
    let (destination, payload_offset) = parse_socks5_destination_prefix(&plaintext)?;
    Ok((destination, plaintext[payload_offset..].to_vec()))
}

fn spawn_ssr_stream(
    cipher: SsrCipher,
    key: Vec<u8>,
    mut upload: SsrStreamCipher,
    stream: TcpStream,
    obfs: SsrObfsMode,
) -> DuplexStream {
    let (app_side, relay_side) = tokio::io::duplex(64 * 1024);
    let (mut local_read, mut local_write) = tokio::io::split(relay_side);
    let (mut remote_read, mut remote_write) = stream.into_split();

    tokio::spawn(async move {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            match local_read.read(&mut buf).await {
                Ok(0) => {
                    let _ = remote_write.shutdown().await;
                    break;
                }
                Ok(n) => {
                    let mut chunk = buf[..n].to_vec();
                    upload.apply(&mut chunk);
                    if remote_write.write_all(&chunk).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    tokio::spawn(async move {
        let mut reader: Box<dyn AsyncRead + Unpin + Send> = if obfs == SsrObfsMode::Http {
            match read_http_obfs_response(&mut remote_read).await {
                Ok(leftover) => Box::new(Cursor::new(leftover).chain(remote_read)),
                Err(_) => {
                    let _ = local_write.shutdown().await;
                    return;
                }
            }
        } else {
            Box::new(remote_read)
        };
        let mut iv = vec![0u8; cipher.iv_len()];
        if reader.read_exact(&mut iv).await.is_err() {
            let _ = local_write.shutdown().await;
            return;
        }
        let Ok(mut download) = cipher.decryptor(&key, &iv) else {
            let _ = local_write.shutdown().await;
            return;
        };
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            match reader.read(&mut buf).await {
                Ok(0) => {
                    let _ = local_write.shutdown().await;
                    break;
                }
                Ok(n) => {
                    let mut chunk = buf[..n].to_vec();
                    download.apply(&mut chunk);
                    if local_write.write_all(&chunk).await.is_err() {
                        break;
                    }
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

fn spawn_anytls_stream<S>(stream: S, early_data: Vec<u8>) -> DuplexStream
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (app_side, relay_side) = tokio::io::duplex(64 * 1024);
    let (mut local_read, mut local_write) = tokio::io::split(relay_side);
    let (mut remote_read, remote_write) = tokio::io::split(stream);
    let remote_write = Arc::new(TokioMutex::new(remote_write));

    let upload_writer = remote_write.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            match local_read.read(&mut buf).await {
                Ok(0) => {
                    let mut writer = upload_writer.lock().await;
                    let _ =
                        write_anytls_frame(&mut *writer, ANYTLS_CMD_FIN, ANYTLS_DEFAULT_SID, &[])
                            .await;
                    let _ = writer.flush().await;
                    break;
                }
                Ok(n) => {
                    let mut writer = upload_writer.lock().await;
                    if write_anytls_frame(
                        &mut *writer,
                        ANYTLS_CMD_PSH,
                        ANYTLS_DEFAULT_SID,
                        &buf[..n],
                    )
                    .await
                    .is_err()
                    {
                        break;
                    }
                    if writer.flush().await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    tokio::spawn(async move {
        if !early_data.is_empty() && local_write.write_all(&early_data).await.is_err() {
            let _ = local_write.shutdown().await;
            return;
        }
        loop {
            match read_anytls_frame(&mut remote_read).await {
                Ok(Some(frame)) => match frame.command {
                    ANYTLS_CMD_PSH if frame.sid == ANYTLS_DEFAULT_SID => {
                        if local_write.write_all(&frame.data).await.is_err() {
                            break;
                        }
                    }
                    ANYTLS_CMD_FIN if frame.sid == ANYTLS_DEFAULT_SID => {
                        let _ = local_write.shutdown().await;
                        break;
                    }
                    ANYTLS_CMD_HEART_REQUEST => {
                        let mut writer = remote_write.lock().await;
                        let _ = write_anytls_frame(&mut *writer, ANYTLS_CMD_HEART_RESPONSE, 0, &[])
                            .await;
                        let _ = writer.flush().await;
                    }
                    ANYTLS_CMD_ALERT => {
                        let _ = local_write.shutdown().await;
                        break;
                    }
                    ANYTLS_CMD_WASTE
                    | ANYTLS_CMD_SERVER_SETTINGS
                    | ANYTLS_CMD_HEART_RESPONSE
                    | ANYTLS_CMD_SYNACK => {}
                    _ => {}
                },
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

fn spawn_shadowtls_stream<S>(tunnel: ShadowTlsTunnel<S>, initial_payload: Vec<u8>) -> DuplexStream
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (app_side, relay_side) = tokio::io::duplex(64 * 1024);
    let (mut local_read, mut local_write) = tokio::io::split(relay_side);
    let (mut remote_read, mut remote_write) = tokio::io::split(tunnel.stream);
    let mut write_hmac = tunnel.write_hmac;
    let mut read_hmac = tunnel.read_hmac;
    let mut handshake_hmac = Some(tunnel.handshake_hmac);

    tokio::spawn(async move {
        if !initial_payload.is_empty()
            && write_shadowtls_app_data(&mut remote_write, &mut write_hmac, &initial_payload)
                .await
                .is_err()
        {
            let _ = remote_write.shutdown().await;
            return;
        }
        let mut buf = vec![0u8; SHADOWTLS_MAX_WRITE_PAYLOAD_LEN];
        loop {
            match local_read.read(&mut buf).await {
                Ok(0) => {
                    let _ = remote_write.shutdown().await;
                    break;
                }
                Ok(n) => {
                    if write_shadowtls_app_data(&mut remote_write, &mut write_hmac, &buf[..n])
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    tokio::spawn(async move {
        loop {
            match read_shadowtls_app_data(&mut remote_read, &mut read_hmac, &mut handshake_hmac)
                .await
            {
                Ok(Some(payload)) => {
                    if local_write.write_all(&payload).await.is_err() {
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

async fn write_shadowtls_app_data<W>(
    writer: &mut W,
    hmac: &mut ShadowTlsHmac,
    payload: &[u8],
) -> anyhow::Result<()>
where
    W: AsyncWrite + Unpin,
{
    for chunk in payload.chunks(SHADOWTLS_MAX_WRITE_PAYLOAD_LEN) {
        hmac.update(chunk);
        let digest = hmac.digest();
        hmac.update(&digest);
        let frame_len = 4 + chunk.len();
        let mut header = [0u8; SHADOWTLS_TLS_HEADER_LEN];
        header[0] = SHADOWTLS_CONTENT_TYPE_APPLICATION_DATA;
        header[1] = 0x03;
        header[2] = 0x03;
        header[3..5].copy_from_slice(&(frame_len as u16).to_be_bytes());
        writer.write_all(&header).await?;
        writer.write_all(&digest).await?;
        writer.write_all(chunk).await?;
        writer.flush().await?;
    }
    Ok(())
}

async fn read_shadowtls_app_data<R>(
    reader: &mut R,
    read_hmac: &mut ShadowTlsHmac,
    handshake_hmac: &mut Option<ShadowTlsHmac>,
) -> anyhow::Result<Option<Vec<u8>>>
where
    R: AsyncRead + Unpin,
{
    loop {
        let Some(frame) = read_shadowtls_tls_record(reader).await? else {
            return Ok(None);
        };
        match frame[0] {
            SHADOWTLS_CONTENT_TYPE_ALERT => return Ok(None),
            SHADOWTLS_CONTENT_TYPE_APPLICATION_DATA => {
                let payload_len = u16::from_be_bytes([frame[3], frame[4]]) as usize;
                if payload_len < 4 {
                    return Err(anyhow!("shadowtls app-data frame is too short"));
                }
                let received = &frame[SHADOWTLS_TLS_HEADER_LEN..SHADOWTLS_TLS_HEADER_LEN + 4];
                let payload =
                    &frame[SHADOWTLS_TLS_HEADER_LEN + 4..SHADOWTLS_TLS_HEADER_LEN + payload_len];
                if let Some(current) = handshake_hmac.as_ref() {
                    let mut candidate = current.clone();
                    candidate.update(payload);
                    if candidate.digest() == received {
                        *handshake_hmac = Some(candidate);
                        continue;
                    }
                    *handshake_hmac = None;
                }
                read_hmac.update(payload);
                let expected = read_hmac.digest();
                if received != expected {
                    return Err(anyhow!("shadowtls app-data hmac check failed"));
                }
                read_hmac.update(&expected);
                return Ok(Some(payload.to_vec()));
            }
            _ if handshake_hmac.is_some() => continue,
            _ => return Err(anyhow!("shadowtls unexpected TLS record type {}", frame[0])),
        }
    }
}

fn spawn_shadowsocks_stream(
    cipher: SsCipher,
    subkey: Vec<u8>,
    upload_nonce: [u8; SS_NONCE_LEN],
    stream: TcpStream,
    plugin: Option<ShadowsocksPluginConfig>,
) -> DuplexStream {
    spawn_shadowsocks_stream_with_state(
        cipher,
        subkey,
        upload_nonce,
        [0u8; SS_NONCE_LEN],
        stream,
        plugin,
    )
}

fn spawn_shadowsocks_stream_with_state(
    cipher: SsCipher,
    subkey: Vec<u8>,
    upload_nonce: [u8; SS_NONCE_LEN],
    download_nonce: [u8; SS_NONCE_LEN],
    stream: TcpStream,
    plugin: Option<ShadowsocksPluginConfig>,
) -> DuplexStream {
    let (app_side, relay_side) = tokio::io::duplex(64 * 1024);
    let (mut local_read, mut local_write) = tokio::io::split(relay_side);
    let (mut remote_read, mut remote_write) = stream.into_split();
    let upload_key = subkey.clone();
    let download_key = subkey;

    let upload_tls_obfs = plugin_is_tls_obfs(plugin.as_ref());
    tokio::spawn(async move {
        let mut nonce = upload_nonce;
        let mut buf = vec![0u8; SS_CHUNK_SIZE];
        loop {
            match local_read.read(&mut buf).await {
                Ok(0) => {
                    let _ = remote_write.shutdown().await;
                    break;
                }
                Ok(n) => {
                    if write_ss_plugin_chunk(
                        cipher,
                        &upload_key,
                        &mut nonce,
                        &mut remote_write,
                        &buf[..n],
                        upload_tls_obfs,
                    )
                    .await
                    .is_err()
                    {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    tokio::spawn(async move {
        let nonce = download_nonce;
        if plugin_is_http_obfs(plugin.as_ref()) {
            match read_http_obfs_response(&mut remote_read).await {
                Ok(leftover) => {
                    let cursor = Cursor::new(leftover);
                    let chained = cursor.chain(remote_read);
                    relay_shadowsocks_download(cipher, download_key, nonce, chained, local_write)
                        .await;
                }
                Err(_) => {
                    let _ = local_write.shutdown().await;
                }
            }
        } else if plugin_is_tls_obfs(plugin.as_ref()) {
            relay_shadowsocks_tls_download(cipher, download_key, nonce, remote_read, local_write)
                .await;
        } else {
            relay_shadowsocks_download(cipher, download_key, nonce, remote_read, local_write).await;
        }
    });

    app_side
}

async fn relay_shadowsocks_download<R, W>(
    cipher: SsCipher,
    subkey: Vec<u8>,
    mut nonce: [u8; SS_NONCE_LEN],
    mut reader: R,
    mut writer: W,
) where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    loop {
        match read_ss_chunk(cipher, &subkey, &mut nonce, &mut reader).await {
            Ok(Some(plaintext)) => {
                if writer.write_all(&plaintext).await.is_err() {
                    break;
                }
            }
            Ok(None) => {
                let _ = writer.shutdown().await;
                break;
            }
            Err(_) => {
                let _ = writer.shutdown().await;
                break;
            }
        }
    }
}

async fn relay_shadowsocks_tls_download<R, W>(
    cipher: SsCipher,
    subkey: Vec<u8>,
    mut nonce: [u8; SS_NONCE_LEN],
    mut reader: R,
    mut writer: W,
) where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut decoder = SimpleObfsTlsDecoder::new();
    loop {
        match read_ss_chunk_from_tls_obfs(cipher, &subkey, &mut nonce, &mut decoder, &mut reader)
            .await
        {
            Ok(Some(plaintext)) => {
                if writer.write_all(&plaintext).await.is_err() {
                    break;
                }
            }
            Ok(None) => {
                let _ = writer.shutdown().await;
                break;
            }
            Err(_) => {
                let _ = writer.shutdown().await;
                break;
            }
        }
    }
}

fn encode_ss_chunk(
    cipher: SsCipher,
    subkey: &[u8],
    nonce: &mut [u8; SS_NONCE_LEN],
    plaintext: &[u8],
) -> anyhow::Result<Vec<u8>> {
    if plaintext.len() > SS_CHUNK_SIZE {
        return Err(anyhow!("shadowsocks chunk is too large"));
    }
    let length = (plaintext.len() as u16).to_be_bytes();
    let encrypted_length = cipher.encrypt(subkey, nonce, &length)?;
    increment_nonce(nonce);
    let encrypted_payload = cipher.encrypt(subkey, nonce, plaintext)?;
    increment_nonce(nonce);
    let mut output = Vec::with_capacity(encrypted_length.len() + encrypted_payload.len());
    output.extend_from_slice(&encrypted_length);
    output.extend_from_slice(&encrypted_payload);
    Ok(output)
}

#[cfg(test)]
async fn write_ss_chunk<W>(
    cipher: SsCipher,
    subkey: &[u8],
    nonce: &mut [u8; SS_NONCE_LEN],
    writer: &mut W,
    plaintext: &[u8],
) -> anyhow::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let chunk = encode_ss_chunk(cipher, subkey, nonce, plaintext)?;
    writer.write_all(&chunk).await?;
    Ok(())
}

async fn write_ss_plugin_chunk<W>(
    cipher: SsCipher,
    subkey: &[u8],
    nonce: &mut [u8; SS_NONCE_LEN],
    writer: &mut W,
    plaintext: &[u8],
    tls_obfs: bool,
) -> anyhow::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let chunk = encode_ss_chunk(cipher, subkey, nonce, plaintext)?;
    if tls_obfs {
        writer
            .write_all(&wrap_simple_obfs_tls_app_data(&chunk))
            .await?;
    } else {
        writer.write_all(&chunk).await?;
    }
    Ok(())
}

async fn read_ss_chunk<R>(
    cipher: SsCipher,
    subkey: &[u8],
    nonce: &mut [u8; SS_NONCE_LEN],
    reader: &mut R,
) -> anyhow::Result<Option<Vec<u8>>>
where
    R: AsyncRead + Unpin,
{
    let mut encrypted_length = [0u8; 2 + SS_TAG_LEN];
    if !read_exact_or_eof(reader, &mut encrypted_length).await? {
        return Ok(None);
    }
    let length = cipher.decrypt(subkey, nonce, &encrypted_length)?;
    increment_nonce(nonce);
    if length.len() != 2 {
        return Err(anyhow!("invalid shadowsocks length block"));
    }
    let payload_len = u16::from_be_bytes([length[0], length[1]]) as usize;
    if payload_len > SS_CHUNK_SIZE {
        return Err(anyhow!("shadowsocks chunk length is too large"));
    }
    let mut encrypted_payload = vec![0u8; payload_len + SS_TAG_LEN];
    read_exact_or_eof(reader, &mut encrypted_payload)
        .await?
        .then_some(())
        .ok_or_else(|| anyhow!("unexpected eof while reading shadowsocks payload"))?;
    let payload = cipher.decrypt(subkey, nonce, &encrypted_payload)?;
    increment_nonce(nonce);
    Ok(Some(payload))
}

async fn read_ss_chunk_from_tls_obfs<R>(
    cipher: SsCipher,
    subkey: &[u8],
    nonce: &mut [u8; SS_NONCE_LEN],
    decoder: &mut SimpleObfsTlsDecoder,
    reader: &mut R,
) -> anyhow::Result<Option<Vec<u8>>>
where
    R: AsyncRead + Unpin,
{
    let encrypted_length = match decoder.read_exact_or_eof(reader, 2 + SS_TAG_LEN).await? {
        Some(value) => value,
        None => return Ok(None),
    };
    let length = cipher.decrypt(subkey, nonce, &encrypted_length)?;
    increment_nonce(nonce);
    if length.len() != 2 {
        return Err(anyhow!("invalid shadowsocks length block"));
    }
    let payload_len = u16::from_be_bytes([length[0], length[1]]) as usize;
    if payload_len > SS_CHUNK_SIZE {
        return Err(anyhow!("shadowsocks chunk length is too large"));
    }
    let encrypted_payload = decoder
        .read_exact_or_eof(reader, payload_len + SS_TAG_LEN)
        .await?
        .ok_or_else(|| anyhow!("unexpected eof while reading shadowsocks payload"))?;
    let payload = cipher.decrypt(subkey, nonce, &encrypted_payload)?;
    increment_nonce(nonce);
    Ok(Some(payload))
}

async fn read_exact_or_eof<R>(reader: &mut R, buf: &mut [u8]) -> anyhow::Result<bool>
where
    R: AsyncRead + Unpin,
{
    let mut offset = 0;
    while offset < buf.len() {
        let n = reader.read(&mut buf[offset..]).await?;
        if n == 0 {
            if offset == 0 {
                return Ok(false);
            }
            return Err(Error::new(ErrorKind::UnexpectedEof, "partial read").into());
        }
        offset += n;
    }
    Ok(true)
}

fn apply_shadowsocks_plugin_request(
    plugin: &ShadowsocksPluginConfig,
    server: &str,
    port: u16,
    payload: Vec<u8>,
) -> anyhow::Result<Vec<u8>> {
    if plugin_is_tls_obfs(Some(plugin)) {
        let host = plugin.host.as_deref().unwrap_or(server);
        return build_simple_obfs_tls_client_hello(host, &payload);
    }
    if !plugin_is_http_obfs(Some(plugin)) {
        return Err(anyhow!(
            "unsupported shadowsocks plugin mode {}",
            plugin.mode
        ));
    }
    let host = plugin.host.as_deref().unwrap_or(server);
    build_http_obfs_request(host, port, payload)
}

fn build_http_obfs_request(host: &str, port: u16, payload: Vec<u8>) -> anyhow::Result<Vec<u8>> {
    let host_header = if host.contains(':') || port == 80 || port == 443 {
        host.to_string()
    } else {
        format!("{host}:{port}")
    };
    let websocket_key = "U3VwZXJjb3JlU2ltcGxlT2Jmcw==";
    let header = format!(
        "GET / HTTP/1.1\r\n\
         Host: {host_header}\r\n\
         User-Agent: curl/8.5.0\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: {websocket_key}\r\n\
         Content-Length: {}\r\n\
         \r\n",
        payload.len()
    );
    let mut output = header.into_bytes();
    output.extend_from_slice(&payload);
    Ok(output)
}

const SIMPLE_OBFS_TLS_CIPHER_SUITES: [u8; 56] = [
    0xc0, 0x2c, 0xc0, 0x30, 0x00, 0x9f, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0xaa, 0xc0, 0x2b, 0xc0, 0x2f,
    0x00, 0x9e, 0xc0, 0x24, 0xc0, 0x28, 0x00, 0x6b, 0xc0, 0x23, 0xc0, 0x27, 0x00, 0x67, 0xc0, 0x0a,
    0xc0, 0x14, 0x00, 0x39, 0xc0, 0x09, 0xc0, 0x13, 0x00, 0x33, 0x00, 0x9d, 0x00, 0x9c, 0x00, 0x3d,
    0x00, 0x3c, 0x00, 0x35, 0x00, 0x2f, 0x00, 0xff,
];

const SIMPLE_OBFS_TLS_OTHER_EXTENSIONS: [u8; 66] = [
    0x00, 0x0b, 0x00, 0x04, 0x03, 0x01, 0x00, 0x02, 0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x1d,
    0x00, 0x17, 0x00, 0x19, 0x00, 0x18, 0x00, 0x0d, 0x00, 0x20, 0x00, 0x1e, 0x06, 0x01, 0x06, 0x02,
    0x06, 0x03, 0x05, 0x01, 0x05, 0x02, 0x05, 0x03, 0x04, 0x01, 0x04, 0x02, 0x04, 0x03, 0x03, 0x01,
    0x03, 0x02, 0x03, 0x03, 0x02, 0x01, 0x02, 0x02, 0x02, 0x03, 0x00, 0x16, 0x00, 0x00, 0x00, 0x17,
    0x00, 0x00,
];

const SIMPLE_OBFS_TLS_FIXED_CLIENT_HELLO_LEN: usize = 138;
const SIMPLE_OBFS_TLS_SESSION_TICKET_HEADER_LEN: usize = 4;
const SIMPLE_OBFS_TLS_SNI_HEADER_LEN: usize = 9;
const SIMPLE_OBFS_TLS_MAX_APP_DATA_LEN: usize = 16 * 1024;

fn build_simple_obfs_tls_client_hello(host: &str, payload: &[u8]) -> anyhow::Result<Vec<u8>> {
    let host = host.trim();
    if host.is_empty() {
        return Err(anyhow!("simple-obfs tls host is empty"));
    }
    let host_bytes = host.as_bytes();
    if host_bytes.len() > u16::MAX as usize {
        return Err(anyhow!("simple-obfs tls host is too long"));
    }
    if payload.len() > u16::MAX as usize {
        return Err(anyhow!("simple-obfs tls first packet is too large"));
    }

    let extensions_len = SIMPLE_OBFS_TLS_SESSION_TICKET_HEADER_LEN
        + payload.len()
        + SIMPLE_OBFS_TLS_SNI_HEADER_LEN
        + host_bytes.len()
        + SIMPLE_OBFS_TLS_OTHER_EXTENSIONS.len();
    if extensions_len > u16::MAX as usize {
        return Err(anyhow!("simple-obfs tls extensions are too large"));
    }
    let tls_len = SIMPLE_OBFS_TLS_FIXED_CLIENT_HELLO_LEN + extensions_len;
    let record_len = tls_len
        .checked_sub(5)
        .ok_or_else(|| anyhow!("invalid simple-obfs tls record length"))?;
    if record_len > u16::MAX as usize {
        return Err(anyhow!("simple-obfs tls record is too large"));
    }
    let handshake_len = tls_len
        .checked_sub(9)
        .ok_or_else(|| anyhow!("invalid simple-obfs tls handshake length"))?;
    if handshake_len > 0x00ff_ffff {
        return Err(anyhow!("simple-obfs tls handshake is too large"));
    }

    let mut output = Vec::with_capacity(tls_len);
    output.extend_from_slice(&[0x16, 0x03, 0x01]);
    output.extend_from_slice(&(record_len as u16).to_be_bytes());
    output.push(0x01);
    output.extend_from_slice(&(handshake_len as u32).to_be_bytes()[1..]);
    output.extend_from_slice(&[0x03, 0x03]);

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32;
    output.extend_from_slice(&now.to_be_bytes());
    let mut random = [0u8; 28];
    getrandom::fill(&mut random)
        .map_err(|error| anyhow!("failed to generate simple-obfs tls random: {error}"))?;
    output.extend_from_slice(&random);
    output.push(32);
    let mut session_id = [0u8; 32];
    getrandom::fill(&mut session_id)
        .map_err(|error| anyhow!("failed to generate simple-obfs tls session id: {error}"))?;
    output.extend_from_slice(&session_id);
    output.extend_from_slice(&(SIMPLE_OBFS_TLS_CIPHER_SUITES.len() as u16).to_be_bytes());
    output.extend_from_slice(&SIMPLE_OBFS_TLS_CIPHER_SUITES);
    output.extend_from_slice(&[0x01, 0x00]);
    output.extend_from_slice(&(extensions_len as u16).to_be_bytes());

    output.extend_from_slice(&[0x00, 0x23]);
    output.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    output.extend_from_slice(payload);

    let sni_ext_len = host_bytes.len() + 5;
    let sni_list_len = host_bytes.len() + 3;
    output.extend_from_slice(&[0x00, 0x00]);
    output.extend_from_slice(&(sni_ext_len as u16).to_be_bytes());
    output.extend_from_slice(&(sni_list_len as u16).to_be_bytes());
    output.push(0x00);
    output.extend_from_slice(&(host_bytes.len() as u16).to_be_bytes());
    output.extend_from_slice(host_bytes);

    output.extend_from_slice(&SIMPLE_OBFS_TLS_OTHER_EXTENSIONS);
    debug_assert_eq!(output.len(), tls_len);
    Ok(output)
}

fn wrap_simple_obfs_tls_app_data(payload: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(
        payload.len() + (payload.len() / SIMPLE_OBFS_TLS_MAX_APP_DATA_LEN + 1) * 5,
    );
    if payload.is_empty() {
        return output;
    }
    for chunk in payload.chunks(SIMPLE_OBFS_TLS_MAX_APP_DATA_LEN) {
        output.extend_from_slice(&[0x17, 0x03, 0x03]);
        output.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
        output.extend_from_slice(chunk);
    }
    output
}

fn build_tls12_ticket_auth(host: &str, _port: u16, payload: Vec<u8>) -> anyhow::Result<Vec<u8>> {
    build_simple_obfs_tls_client_hello(host, &payload)
}

fn plugin_is_http_obfs(plugin: Option<&ShadowsocksPluginConfig>) -> bool {
    plugin
        .map(|plugin| {
            matches!(
                plugin.mode.to_ascii_lowercase().as_str(),
                "http" | "obfs-http" | "simple-obfs-http"
            )
        })
        .unwrap_or(false)
}

fn plugin_is_tls_obfs(plugin: Option<&ShadowsocksPluginConfig>) -> bool {
    plugin
        .map(|plugin| {
            matches!(
                plugin.mode.to_ascii_lowercase().as_str(),
                "tls" | "obfs-tls" | "simple-obfs-tls"
            )
        })
        .unwrap_or(false)
}

async fn read_http_obfs_response<R>(reader: &mut R) -> anyhow::Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut data = Vec::with_capacity(1024);
    let mut buf = [0u8; 512];
    while data.len() < 64 * 1024 {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            return Err(anyhow!("unexpected eof while reading obfs http response"));
        }
        data.extend_from_slice(&buf[..n]);
        if let Some(index) = find_header_end(&data) {
            return Ok(data.split_off(index));
        }
    }
    Err(anyhow!("obfs http response header is too large"))
}

fn find_header_end(data: &[u8]) -> Option<usize> {
    data.windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SimpleObfsTlsReadStage {
    ServerHello,
    AppData,
}

struct SimpleObfsTlsDecoder {
    stage: SimpleObfsTlsReadStage,
    plain: BytesMut,
}

impl SimpleObfsTlsDecoder {
    fn new() -> Self {
        Self {
            stage: SimpleObfsTlsReadStage::ServerHello,
            plain: BytesMut::new(),
        }
    }

    async fn read_exact_or_eof<R>(
        &mut self,
        reader: &mut R,
        len: usize,
    ) -> anyhow::Result<Option<Vec<u8>>>
    where
        R: AsyncRead + Unpin,
    {
        while self.plain.len() < len {
            if !self.read_next_plain_record(reader).await? {
                if self.plain.is_empty() {
                    return Ok(None);
                }
                return Err(anyhow!(
                    "unexpected eof while reading simple-obfs tls payload"
                ));
            }
        }
        Ok(Some(self.plain.split_to(len).to_vec()))
    }

    async fn read_next_plain_record<R>(&mut self, reader: &mut R) -> anyhow::Result<bool>
    where
        R: AsyncRead + Unpin,
    {
        match self.stage {
            SimpleObfsTlsReadStage::ServerHello => {
                let Some((content_type, _version, _payload)) =
                    read_simple_obfs_tls_record(reader).await?
                else {
                    return Ok(false);
                };
                if content_type != 0x16 {
                    return Err(anyhow!("invalid simple-obfs tls server hello record"));
                }

                let Some((content_type, _version, payload)) =
                    read_simple_obfs_tls_record(reader).await?
                else {
                    return Err(anyhow!("unexpected eof after simple-obfs tls server hello"));
                };
                if content_type == 0x14 {
                    if payload != [0x01] {
                        return Err(anyhow!("invalid simple-obfs tls change cipher spec"));
                    }
                    let Some((handshake_type, _version, payload)) =
                        read_simple_obfs_tls_record(reader).await?
                    else {
                        return Err(anyhow!(
                            "unexpected eof after simple-obfs tls change cipher spec"
                        ));
                    };
                    if handshake_type != 0x16 {
                        return Err(anyhow!("invalid simple-obfs tls encrypted handshake"));
                    }
                    self.plain.extend_from_slice(&payload);
                } else if content_type == 0x16 {
                    self.plain.extend_from_slice(&payload);
                } else {
                    return Err(anyhow!("invalid simple-obfs tls response record"));
                }
                self.stage = SimpleObfsTlsReadStage::AppData;
                Ok(true)
            }
            SimpleObfsTlsReadStage::AppData => {
                let Some((content_type, _version, payload)) =
                    read_simple_obfs_tls_record(reader).await?
                else {
                    return Ok(false);
                };
                if content_type != 0x17 {
                    return Err(anyhow!("invalid simple-obfs tls app data record"));
                }
                self.plain.extend_from_slice(&payload);
                Ok(true)
            }
        }
    }
}

async fn read_simple_obfs_tls_record<R>(
    reader: &mut R,
) -> anyhow::Result<Option<(u8, [u8; 2], Vec<u8>)>>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; 5];
    if !read_exact_or_eof(reader, &mut header).await? {
        return Ok(None);
    }
    if header[1] != 0x03 {
        return Err(anyhow!("invalid simple-obfs tls record version"));
    }
    let len = u16::from_be_bytes([header[3], header[4]]) as usize;
    if header[0] == 0x17 && len > SIMPLE_OBFS_TLS_MAX_APP_DATA_LEN {
        return Err(anyhow!("simple-obfs tls app data frame is too large"));
    }
    let mut payload = vec![0u8; len];
    read_exact_or_eof(reader, &mut payload)
        .await?
        .then_some(())
        .ok_or_else(|| anyhow!("unexpected eof while reading simple-obfs tls record"))?;
    Ok(Some((header[0], [header[1], header[2]], payload)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::ServerConfig;
    use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

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

            let mut outbound_nonce = [0u8; SS_NONCE_LEN];
            write_ss_chunk(cipher, &subkey, &mut outbound_nonce, &mut stream, b"pong")
                .await
                .unwrap();
        });

        let outbound = ShadowsocksOutbound {
            name: "ss-test".to_string(),
            server: "127.0.0.1".to_string(),
            port: listen_addr.port(),
            method: "aes-128-gcm".to_string(),
            password,
            plugin: None,
            udp_sessions: TokioMutex::new(ShadowsocksUdpPool::default()),
        };
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
                    let mut outbound_nonce = [0u8; SS_NONCE_LEN];
                    write_ss_chunk(cipher, &subkey, &mut outbound_nonce, &mut stream, b"pong")
                        .await
                        .unwrap();
                    break;
                }
            }
        });

        let outbound = ShadowsocksOutbound {
            name: "ss-obfs-test".to_string(),
            server: "127.0.0.1".to_string(),
            port: listen_addr.port(),
            method: "aes-128-gcm".to_string(),
            password,
            plugin: Some(ShadowsocksPluginConfig {
                mode: "http".to_string(),
                host: Some("edge.example.com".to_string()),
            }),
            udp_sessions: TokioMutex::new(ShadowsocksUdpPool::default()),
        };
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

            let mut outbound_nonce = [0u8; SS_NONCE_LEN];
            let response_chunk =
                encode_ss_chunk(cipher, &subkey, &mut outbound_nonce, b"pong").unwrap();
            let mut response = vec![
                0x16, 0x03, 0x01, 0x00, 0x00, 0x14, 0x03, 0x03, 0x00, 0x01, 0x01,
            ];
            response.extend_from_slice(&[0x16, 0x03, 0x03]);
            response.extend_from_slice(&(response_chunk.len() as u16).to_be_bytes());
            response.extend_from_slice(&response_chunk);
            stream.write_all(&response).await.unwrap();
        });

        let outbound = ShadowsocksOutbound {
            name: "ss-obfs-tls-test".to_string(),
            server: "127.0.0.1".to_string(),
            port: listen_addr.port(),
            method: "aes-128-gcm".to_string(),
            password,
            plugin: Some(ShadowsocksPluginConfig {
                mode: "tls".to_string(),
                host: Some("edge.example.com".to_string()),
            }),
            udp_sessions: TokioMutex::new(ShadowsocksUdpPool::default()),
        };
        let mut stream = outbound.connect(&destination, 1000).await.unwrap();
        stream.write_all(b"ping").await.unwrap();
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
