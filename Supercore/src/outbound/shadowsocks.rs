use std::{
    collections::HashMap,
    io::Cursor,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use aes::cipher::{
    consts::{U1, U24, U32},
    inout::InOut,
    Block, BlockBackend, BlockCipher, BlockClosure, BlockDecrypt, BlockEncrypt, BlockSizeUser, Key,
    KeyInit as BlockKeyInit, KeySizeUser, ParBlocksSizeUser,
};
use aes::{Aes128, Aes192, Aes256};
use aes_gcm::{
    aead::{consts::U12, Aead},
    Aes128Gcm, Aes256Gcm, AesGcm,
};
use anyhow::{anyhow, Context};
use async_trait::async_trait;
use bytes::BytesMut;
use ccm::{aead::consts::U16, Ccm};
use chacha20poly1305::{ChaCha20Poly1305, ChaCha8Poly1305, XChaCha20Poly1305, XChaCha8Poly1305};
use hkdf::Hkdf;
use md5::{Digest, Md5};
use rustls_pki_types::ServerName;
use sha1::Sha1;
use shadowsocks::{
    config::{ServerConfig, ServerType},
    context::{Context as ShadowsocksContext, SharedContext as ShadowsocksContextHandle},
    crypto::{CipherCategory, CipherKind},
    relay::{
        socks5::Address as ShadowsocksAddress,
        udprelay::{
            crypto_io::{decrypt_server_payload, encrypt_client_payload},
            options::UdpSocketControlData,
        },
    },
    ProxyClientStream, ServerAddr,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream},
    net::UdpSocket,
    sync::Mutex,
    time::timeout,
};
use tokio_rustls::TlsConnector;

use crate::{config::ShadowsocksPluginConfig, routing::Destination};

use super::io::read_exact_or_eof;
use super::{
    shadowtls::open_v3_transport,
    target::{encode_socks5_destination, parse_socks5_destination_prefix},
    transports::{
        connect_tcp, open_websocket_transport_without_headers, run_dial_phase, tls_client_config,
    },
    udp::{
        create_bound_udp, resolve_udp_socket_addr, udp_session_key, KeyedRoundRobinSessionPool,
        ReplayWindow64, UDP_SESSION_POOL_SIZE,
    },
    BoxedStream, Outbound, OutboundCapability, UdpNatMode,
};

pub(super) struct ShadowsocksOutbound {
    name: String,
    server: String,
    port: u16,
    method: String,
    password: String,
    plugin: Option<ShadowsocksPluginConfig>,
    udp_over_tcp: bool,
    udp_over_tcp_version: u8,
    context: ShadowsocksContextHandle,
    udp_sessions: Mutex<ShadowsocksUdpPool>,
    uot_sessions: Mutex<ShadowsocksUotPool>,
}

impl ShadowsocksOutbound {
    pub(super) fn new(
        name: String,
        server: String,
        port: u16,
        method: String,
        password: String,
        plugin: Option<ShadowsocksPluginConfig>,
        udp_over_tcp: bool,
        udp_over_tcp_version: u8,
    ) -> Self {
        Self {
            name,
            server,
            port,
            method,
            password,
            plugin,
            udp_over_tcp,
            udp_over_tcp_version,
            context: ShadowsocksContext::new_shared(ServerType::Local),
            udp_sessions: Mutex::new(ShadowsocksUdpPool::default()),
            uot_sessions: Mutex::new(ShadowsocksUotPool::default()),
        }
    }

    fn method(&self) -> anyhow::Result<CipherKind> {
        self.method
            .to_ascii_lowercase()
            .parse::<CipherKind>()
            .map_err(|_| anyhow!("unsupported shadowsocks method {}", self.method))
    }

    fn server_config(&self) -> anyhow::Result<ServerConfig> {
        ServerConfig::new(
            shadowsocks_server_address(&self.server, self.port),
            self.password.clone(),
            self.method()?,
        )
        .map_err(|error| anyhow!("invalid shadowsocks server configuration: {error}"))
    }

    fn validate_udp_over_tcp(&self) -> anyhow::Result<()> {
        if self.udp_over_tcp && !matches!(self.udp_over_tcp_version, 1 | 2) {
            return Err(anyhow!(
                "shadowsocks udp-over-tcp-version must be 1 or 2, got {}",
                self.udp_over_tcp_version
            ));
        }
        Ok(())
    }

    async fn connect_managed_crypto(
        &self,
        destination: &Destination,
        timeout_ms: u64,
    ) -> anyhow::Result<BoxedStream> {
        let server = format!("{}:{}", self.server, self.port);
        let tcp = connect_tcp(&server, timeout_ms).await?;
        let mut transport: BoxedStream = if self
            .plugin
            .as_ref()
            .map(|plugin| plugin_is_v2ray_ws(Some(plugin)) && plugin.tls)
            .unwrap_or(false)
        {
            let plugin = self.plugin.as_ref().expect("plugin checked");
            let server_name = plugin.host.as_deref().unwrap_or(&self.server).to_string();
            let tls_config = tls_client_config(plugin.skip_cert_verify)?;
            let connector = TlsConnector::from(Arc::new(tls_config));
            let tls_server_name = ServerName::try_from(server_name)
                .map_err(|error| anyhow!("invalid shadowsocks plugin server name: {error}"))?;
            let tls = run_dial_phase(
                timeout_ms,
                "shadowsocks plugin tls handshake",
                connector.connect(tls_server_name, tcp),
            )
            .await?
            .context("shadowsocks plugin tls handshake failed")?;
            Box::new(tls)
        } else {
            Box::new(tcp)
        };

        if let Some(plugin) = &self.plugin {
            if plugin_is_shadowtls(Some(plugin)) {
                transport =
                    open_shadowtls_plugin_transport(transport, plugin, &self.server, timeout_ms)
                        .await?;
            } else if plugin_is_v2ray_ws(Some(plugin)) {
                transport = open_websocket_transport_without_headers(
                    transport,
                    plugin.host.as_deref().unwrap_or(&self.server),
                    plugin.path.as_deref().unwrap_or("/"),
                    timeout_ms,
                )
                .await?;
            } else if plugin_is_http_obfs(Some(plugin)) || plugin_is_tls_obfs(Some(plugin)) {
                transport = Box::new(spawn_simple_obfs_transport(
                    transport,
                    plugin.clone(),
                    self.server.clone(),
                    self.port,
                ));
            } else {
                return Err(anyhow!(
                    "unsupported shadowsocks plugin mode {}",
                    plugin.mode
                ));
            }
        }

        let server_config = self.server_config()?;
        let target = shadowsocks_target_address(destination)?;
        let stream =
            ProxyClientStream::from_stream(self.context.clone(), transport, &server_config, target);
        Ok(Box::new(stream))
    }

    async fn connect_legacy_stream_crypto(
        &self,
        method: LegacySsStreamMethod,
        destination: &Destination,
        timeout_ms: u64,
    ) -> anyhow::Result<BoxedStream> {
        let server = format!("{}:{}", self.server, self.port);
        let tcp = connect_tcp(&server, timeout_ms).await?;
        let mut transport: BoxedStream = if self
            .plugin
            .as_ref()
            .map(|plugin| plugin_is_v2ray_ws(Some(plugin)) && plugin.tls)
            .unwrap_or(false)
        {
            let plugin = self.plugin.as_ref().expect("plugin checked");
            let server_name = plugin.host.as_deref().unwrap_or(&self.server).to_string();
            let tls_config = tls_client_config(plugin.skip_cert_verify)?;
            let connector = TlsConnector::from(Arc::new(tls_config));
            let tls_server_name = ServerName::try_from(server_name)
                .map_err(|error| anyhow!("invalid shadowsocks plugin server name: {error}"))?;
            let tls = run_dial_phase(
                timeout_ms,
                "shadowsocks plugin tls handshake",
                connector.connect(tls_server_name, tcp),
            )
            .await?
            .context("shadowsocks plugin tls handshake failed")?;
            Box::new(tls)
        } else {
            Box::new(tcp)
        };

        if let Some(plugin) = &self.plugin {
            if plugin_is_shadowtls(Some(plugin)) {
                transport =
                    open_shadowtls_plugin_transport(transport, plugin, &self.server, timeout_ms)
                        .await?;
            } else if plugin_is_v2ray_ws(Some(plugin)) {
                transport = open_websocket_transport_without_headers(
                    transport,
                    plugin.host.as_deref().unwrap_or(&self.server),
                    plugin.path.as_deref().unwrap_or("/"),
                    timeout_ms,
                )
                .await?;
            } else if plugin_is_http_obfs(Some(plugin)) || plugin_is_tls_obfs(Some(plugin)) {
                transport = Box::new(spawn_simple_obfs_transport(
                    transport,
                    plugin.clone(),
                    self.server.clone(),
                    self.port,
                ));
            } else {
                return Err(anyhow!(
                    "unsupported shadowsocks plugin mode {}",
                    plugin.mode
                ));
            }
        }

        let key = evp_bytes_to_key(self.password.as_bytes(), method.key_len());
        let mut request_iv = vec![0u8; method.iv_len()];
        getrandom::fill(&mut request_iv)
            .map_err(|error| anyhow!("failed to generate shadowsocks IV: {error}"))?;
        let mut encryptor = method.new_cipher(&key, &request_iv)?;
        let mut request = Vec::new();
        encode_socks5_destination(destination, &mut request)?;
        encryptor.apply_keystream(&mut request);
        transport.write_all(&request_iv).await?;
        transport.write_all(&request).await?;
        transport.flush().await?;
        Ok(Box::new(spawn_legacy_ss_stream(
            method, key, encryptor, transport,
        )))
    }

    async fn shadowsocks_udp_session(
        &self,
        key: &str,
        timeout_ms: u64,
    ) -> anyhow::Result<Arc<Mutex<ShadowsocksUdpSession>>> {
        let mut pool = self.udp_sessions.lock().await;
        if pool.len(key) < UDP_SESSION_POOL_SIZE {
            let server = resolve_udp_socket_addr(&self.server, self.port, timeout_ms).await?;
            let udp = create_bound_udp(server).with_context(|| {
                format!(
                    "failed to bind udp socket for shadowsocks outbound {}",
                    self.name
                )
            })?;
            let cipher = SsCipher::from_method(&self.method).ok();
            let ss2022 = cipher
                .filter(|cipher| cipher.is_blake3())
                .map(|_| Ss2022UdpState::new())
                .transpose()?;
            let session = Arc::new(Mutex::new(ShadowsocksUdpSession {
                udp,
                server,
                ss2022,
            }));
            pool.push(key.to_string(), session.clone());
            return Ok(session);
        }
        pool.next(key)
            .ok_or_else(|| anyhow!("shadowsocks UDP session pool is unexpectedly empty"))
    }

    async fn remove_shadowsocks_udp_session(
        &self,
        key: &str,
        target: &Arc<Mutex<ShadowsocksUdpSession>>,
    ) {
        self.udp_sessions.lock().await.remove(key, target);
    }

    async fn shadowsocks_uot_session(
        &self,
        key: &str,
        destination: &Destination,
        timeout_ms: u64,
    ) -> anyhow::Result<Arc<Mutex<ShadowsocksUotSession>>> {
        let mut pool = self.uot_sessions.lock().await;
        if pool.len(key) < UDP_SESSION_POOL_SIZE {
            let magic_host = match self.udp_over_tcp_version {
                1 => "sp.udp-over-tcp.arpa",
                2 => "sp.v2.udp-over-tcp.arpa",
                version => {
                    return Err(anyhow!(
                        "shadowsocks udp-over-tcp-version must be 1 or 2, got {version}"
                    ))
                }
            };
            let mut stream = self
                .connect(&Destination::new(magic_host, 0), timeout_ms)
                .await?;
            if self.udp_over_tcp_version == 2 {
                let mut request = vec![0u8];
                encode_socks5_destination(destination, &mut request)?;
                stream.write_all(&request).await?;
                stream.flush().await?;
            }
            let session = Arc::new(Mutex::new(ShadowsocksUotSession { stream }));
            pool.push(key.to_string(), session.clone());
            return Ok(session);
        }
        pool.next(key)
            .ok_or_else(|| anyhow!("shadowsocks UoT session pool is unexpectedly empty"))
    }

    async fn remove_shadowsocks_uot_session(
        &self,
        key: &str,
        target: &Arc<Mutex<ShadowsocksUotSession>>,
    ) {
        self.uot_sessions.lock().await.remove(key, target);
    }

    async fn udp_over_tcp_exchange(
        &self,
        destination: &Destination,
        payload: &[u8],
        timeout_ms: u64,
    ) -> anyhow::Result<Vec<u8>> {
        self.validate_udp_over_tcp()?;
        if payload.len() > u16::MAX as usize {
            return Err(anyhow!("shadowsocks UoT payload is too large"));
        }
        let key = udp_session_key(
            self.kind(),
            self.name(),
            self.udp_nat_mode(),
            Some(destination),
        );
        let session_handle = self
            .shadowsocks_uot_session(&key, destination, timeout_ms)
            .await?;
        let mut session = session_handle.lock().await;
        let exchange = timeout(Duration::from_millis(timeout_ms), async {
            let mut frame = Vec::with_capacity(1 + 255 + 2 + 2 + payload.len());
            encode_uot_destination(destination, &mut frame)?;
            frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
            frame.extend_from_slice(payload);
            session.stream.write_all(&frame).await?;
            session.stream.flush().await?;

            let _response_destination = read_uot_destination(&mut session.stream).await?;
            let mut length = [0u8; 2];
            session.stream.read_exact(&mut length).await?;
            let response_len = u16::from_be_bytes(length) as usize;
            let mut response = vec![0u8; response_len];
            session.stream.read_exact(&mut response).await?;
            anyhow::Ok(response)
        })
        .await
        .context("shadowsocks UoT exchange timed out")?;
        if exchange.is_err() {
            drop(session);
            self.remove_shadowsocks_uot_session(&key, &session_handle)
                .await;
        }
        exchange
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

    fn capability(&self) -> OutboundCapability {
        let native_method = SsCipher::from_method(&self.method).ok();
        let legacy_stream_method = LegacySsStreamMethod::from_method(&self.method);
        let managed_method = self.method().ok();
        if native_method.is_none() && legacy_stream_method.is_none() && managed_method.is_none() {
            return OutboundCapability::unsupported(format!(
                "unsupported shadowsocks method {}",
                self.method
            ));
        }
        if let Err(error) = self.validate_udp_over_tcp() {
            return OutboundCapability::unsupported(error.to_string());
        }
        if let Some(plugin) = &self.plugin {
            if !plugin_is_v2ray_ws(Some(plugin))
                && !plugin_is_http_obfs(Some(plugin))
                && !plugin_is_tls_obfs(Some(plugin))
                && !plugin_is_shadowtls(Some(plugin))
            {
                return OutboundCapability::unsupported(format!(
                    "unsupported shadowsocks plugin mode {}",
                    plugin.mode
                ));
            }
            if plugin_is_shadowtls(Some(plugin)) {
                if let Err(error) = validate_shadowtls_plugin(plugin) {
                    return OutboundCapability::unsupported(error.to_string());
                }
            }
            if self.udp_over_tcp {
                OutboundCapability::tcp_udp(match self.udp_over_tcp_version {
                    1 => "shadowsocks-uot-v1-over-plugin",
                    2 => "shadowsocks-uot-v2-over-plugin",
                    _ => unreachable!("validated above"),
                })
            } else {
                OutboundCapability::tcp_only(
                    "Shadowsocks plugin transports require udp-over-tcp for UDP relay",
                )
            }
        } else if self.udp_over_tcp {
            OutboundCapability::tcp_udp(match self.udp_over_tcp_version {
                1 => "shadowsocks-uot-v1",
                2 => "shadowsocks-uot-v2",
                _ => unreachable!("validated above"),
            })
        } else {
            let category = if native_method.map(SsCipher::is_blake3).unwrap_or(false) {
                CipherCategory::Aead2022
            } else if native_method.is_some() {
                CipherCategory::Aead
            } else if legacy_stream_method.is_some() {
                CipherCategory::Stream
            } else {
                managed_method.expect("validated above").category()
            };
            OutboundCapability::tcp_udp(match category {
                CipherCategory::None => "shadowsocks-none-udp-session-pool",
                CipherCategory::Stream => "shadowsocks-stream-udp-session-pool",
                CipherCategory::Aead => "shadowsocks-aead-udp-session-pool",
                CipherCategory::Aead2022 => "shadowsocks-2022-udp-session-pool",
            })
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
        if let Some(method) = LegacySsStreamMethod::from_method(&self.method) {
            return self
                .connect_legacy_stream_crypto(method, destination, timeout_ms)
                .await;
        }
        if SsCipher::from_method(&self.method).is_err() {
            return self.connect_managed_crypto(destination, timeout_ms).await;
        }

        let cipher = SsCipher::from_method(&self.method)?;
        let server = format!("{}:{}", self.server, self.port);
        let tcp = connect_tcp(&server, timeout_ms).await?;
        let psk_chain = cipher.psk_chain(self.password.as_bytes())?;
        let master_key = psk_chain
            .last()
            .cloned()
            .ok_or_else(|| anyhow!("shadowsocks key chain is empty"))?;
        let mut salt = vec![0u8; cipher.salt_len()];
        getrandom::fill(&mut salt)
            .map_err(|error| anyhow!("failed to generate shadowsocks salt: {error}"))?;
        let subkey = cipher.derive_subkey(&master_key, &salt)?;

        let mut outbound_nonce = vec![0u8; cipher.nonce_len()];
        let request_salt = salt.clone();
        let mut initial = salt;
        if cipher.is_blake3() {
            initial.extend_from_slice(&build_ss2022_tcp_identity_headers(
                cipher,
                &psk_chain,
                &request_salt,
            )?);
            initial.extend_from_slice(&build_ss2022_request_header(
                cipher,
                &subkey,
                &mut outbound_nonce,
                destination,
            )?);
        } else {
            let mut destination_payload = Vec::new();
            encode_socks5_destination(destination, &mut destination_payload)?;
            initial.extend_from_slice(&encode_ss_chunk(
                cipher,
                &subkey,
                &mut outbound_nonce,
                &destination_payload,
            )?);
        }

        let mut transport: BoxedStream = if self
            .plugin
            .as_ref()
            .map(|plugin| plugin_is_v2ray_ws(Some(plugin)) && plugin.tls)
            .unwrap_or(false)
        {
            let plugin = self.plugin.as_ref().expect("plugin checked");
            let server_name = plugin.host.as_deref().unwrap_or(&self.server).to_string();
            let tls_config = tls_client_config(plugin.skip_cert_verify)?;
            let connector = TlsConnector::from(Arc::new(tls_config));
            let tls_server_name = ServerName::try_from(server_name)
                .map_err(|error| anyhow!("invalid shadowsocks plugin server name: {error}"))?;
            let tls = run_dial_phase(
                timeout_ms,
                "shadowsocks plugin tls handshake",
                connector.connect(tls_server_name, tcp),
            )
            .await?
            .context("shadowsocks plugin tls handshake failed")?;
            Box::new(tls)
        } else {
            Box::new(tcp)
        };

        if let Some(plugin) = &self.plugin {
            if plugin_is_v2ray_ws(Some(plugin)) {
                transport = open_websocket_transport_without_headers(
                    transport,
                    plugin.host.as_deref().unwrap_or(&self.server),
                    plugin.path.as_deref().unwrap_or("/"),
                    timeout_ms,
                )
                .await?;
            } else if plugin_is_shadowtls(Some(plugin)) {
                transport =
                    open_shadowtls_plugin_transport(transport, plugin, &self.server, timeout_ms)
                        .await?;
            } else {
                initial =
                    apply_shadowsocks_plugin_request(plugin, &self.server, self.port, initial)?;
            }
        }
        transport.write_all(&initial).await?;
        transport.flush().await?;

        let app_side = spawn_shadowsocks_stream(
            cipher,
            master_key,
            request_salt,
            subkey,
            outbound_nonce,
            transport,
            self.plugin.clone(),
        );
        Ok(Box::new(app_side))
    }

    async fn udp_exchange(
        &self,
        destination: &Destination,
        payload: &[u8],
        timeout_ms: u64,
    ) -> anyhow::Result<Vec<u8>> {
        if self.udp_over_tcp {
            return self
                .udp_over_tcp_exchange(destination, payload, timeout_ms)
                .await;
        }
        if self.plugin.is_some() {
            return Err(anyhow!(
                "shadowsocks udp with simple-obfs plugin is not supported"
            ));
        }

        let native_cipher = SsCipher::from_method(&self.method).ok();
        let legacy_stream_method = LegacySsStreamMethod::from_method(&self.method);
        let managed_method = if native_cipher.is_none() && legacy_stream_method.is_none() {
            Some(self.method()?)
        } else {
            None
        };
        let key = udp_session_key(
            self.kind(),
            self.name(),
            self.udp_nat_mode(),
            Some(destination),
        );
        let session_handle = self.shadowsocks_udp_session(&key, timeout_ms).await?;
        let mut session = session_handle.lock().await;
        let packet = if let Some(cipher) = native_cipher {
            encode_shadowsocks_udp_packet(
                cipher,
                self.password.as_bytes(),
                destination,
                payload,
                session.ss2022.as_mut(),
            )?
        } else if let Some(method) = legacy_stream_method {
            encode_legacy_ss_stream_udp_packet(
                method,
                self.password.as_bytes(),
                destination,
                payload,
            )?
        } else {
            let server_config = self.server_config()?;
            let target = shadowsocks_target_address(destination)?;
            let control = UdpSocketControlData::default();
            let mut packet = BytesMut::new();
            encrypt_client_payload(
                &self.context,
                managed_method.expect("managed Shadowsocks method validated above"),
                server_config.key(),
                &target,
                &control,
                server_config.identity_keys(),
                payload,
                &mut packet,
            );
            packet.to_vec()
        };
        let server = session.server;
        let exchange = async {
            timeout(
                Duration::from_millis(timeout_ms),
                session.udp.send_to(&packet, server),
            )
            .await
            .context("shadowsocks udp send timed out")?
            .with_context(|| format!("failed to send shadowsocks udp packet to {}", server))?;

            let mut buf = vec![0u8; 65_535];
            let (len, _) = timeout(
                Duration::from_millis(timeout_ms),
                session.udp.recv_from(&mut buf),
            )
            .await
            .context("shadowsocks udp receive timed out")?
            .context("failed to receive shadowsocks udp response")?;
            let response = if let Some(cipher) = native_cipher {
                let (_response_destination, response) = decode_shadowsocks_udp_packet(
                    cipher,
                    self.password.as_bytes(),
                    &buf[..len],
                    session.ss2022.as_mut(),
                )?;
                response
            } else if let Some(method) = legacy_stream_method {
                let (_response_destination, response) = decode_legacy_ss_stream_udp_packet(
                    method,
                    self.password.as_bytes(),
                    &buf[..len],
                )?;
                response
            } else {
                let server_config = self.server_config()?;
                let mut packet = buf[..len].to_vec();
                let (payload_len, _response_destination, _) = decrypt_server_payload(
                    &self.context,
                    managed_method.expect("managed Shadowsocks method validated above"),
                    server_config.key(),
                    &mut packet,
                )
                .map_err(|error| anyhow!("shadowsocks UDP decryption failed: {error}"))?;
                packet.truncate(payload_len);
                packet
            };
            Ok(response)
        }
        .await;
        if exchange.is_err() {
            drop(session);
            self.remove_shadowsocks_udp_session(&key, &session_handle)
                .await;
        }
        exchange
    }
}

fn shadowsocks_server_address(server: &str, port: u16) -> ServerAddr {
    server
        .parse()
        .map(|ip| ServerAddr::SocketAddr(SocketAddr::new(ip, port)))
        .unwrap_or_else(|_| ServerAddr::DomainName(server.to_string(), port))
}

fn shadowsocks_target_address(destination: &Destination) -> anyhow::Result<ShadowsocksAddress> {
    if let Ok(ip) = destination.host.parse() {
        return Ok(ShadowsocksAddress::SocketAddress(SocketAddr::new(
            ip,
            destination.port,
        )));
    }
    if destination.host.is_empty() || destination.host.len() > u8::MAX as usize {
        return Err(anyhow!("invalid shadowsocks destination host"));
    }
    Ok(ShadowsocksAddress::DomainNameAddress(
        destination.host.clone(),
        destination.port,
    ))
}

fn encode_uot_destination(destination: &Destination, output: &mut Vec<u8>) -> anyhow::Result<()> {
    match destination.host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(ip)) => {
            output.push(0x00);
            output.extend_from_slice(&ip.octets());
        }
        Ok(std::net::IpAddr::V6(ip)) => {
            output.push(0x01);
            output.extend_from_slice(&ip.octets());
        }
        Err(_) => {
            let host = destination.host.as_bytes();
            if host.is_empty() || host.len() > u8::MAX as usize {
                return Err(anyhow!("invalid Shadowsocks UoT destination host"));
            }
            output.push(0x02);
            output.push(host.len() as u8);
            output.extend_from_slice(host);
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
                return Err(anyhow!("empty Shadowsocks UoT domain"));
            }
            let mut domain = vec![0u8; length];
            reader.read_exact(&mut domain).await?;
            String::from_utf8(domain).context("invalid Shadowsocks UoT domain encoding")?
        }
        _ => return Err(anyhow!("invalid Shadowsocks UoT address family {family}")),
    };
    let port = reader.read_u16().await?;
    Ok(Destination::new(host, port))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LegacySsStreamMethod {
    ChaCha20,
    XChaCha20,
}

impl LegacySsStreamMethod {
    fn from_method(method: &str) -> Option<Self> {
        match method.to_ascii_lowercase().as_str() {
            "chacha20" => Some(Self::ChaCha20),
            "xchacha20" => Some(Self::XChaCha20),
            _ => None,
        }
    }

    fn key_len(self) -> usize {
        32
    }

    fn iv_len(self) -> usize {
        match self {
            Self::ChaCha20 => 8,
            Self::XChaCha20 => 24,
        }
    }

    fn new_cipher(self, key: &[u8], iv: &[u8]) -> anyhow::Result<LegacySsStreamCipher> {
        use chacha20::cipher::KeyIvInit;

        match self {
            Self::ChaCha20 => Ok(LegacySsStreamCipher::ChaCha20(
                chacha20::ChaCha20Legacy::new_from_slices(key, iv)
                    .map_err(|_| anyhow!("invalid chacha20 key or IV"))?,
            )),
            Self::XChaCha20 => Ok(LegacySsStreamCipher::XChaCha20(
                chacha20::XChaCha20::new_from_slices(key, iv)
                    .map_err(|_| anyhow!("invalid xchacha20 key or IV"))?,
            )),
        }
    }
}

enum LegacySsStreamCipher {
    ChaCha20(chacha20::ChaCha20Legacy),
    XChaCha20(chacha20::XChaCha20),
}

impl LegacySsStreamCipher {
    fn apply_keystream(&mut self, data: &mut [u8]) {
        use chacha20::cipher::StreamCipher;

        match self {
            Self::ChaCha20(cipher) => cipher.apply_keystream(data),
            Self::XChaCha20(cipher) => cipher.apply_keystream(data),
        }
    }
}

type ShadowsocksUdpPool = KeyedRoundRobinSessionPool<ShadowsocksUdpSession>;

type ShadowsocksUotPool = KeyedRoundRobinSessionPool<ShadowsocksUotSession>;

struct ShadowsocksUotSession {
    stream: BoxedStream,
}

struct ShadowsocksUdpSession {
    udp: UdpSocket,
    server: SocketAddr,
    ss2022: Option<Ss2022UdpState>,
}

struct Ss2022UdpState {
    client_session_id: [u8; 8],
    next_packet_id: u64,
    server_sessions: HashMap<[u8; 8], Ss2022ServerSession>,
}

struct Ss2022ServerSession {
    replay: Ss2022ReplayWindow,
    last_seen: Instant,
}

pub(super) type Ss2022ReplayWindow = ReplayWindow64;

impl Ss2022UdpState {
    fn new() -> anyhow::Result<Self> {
        let mut client_session_id = [0u8; 8];
        getrandom::fill(&mut client_session_id).map_err(|error| {
            anyhow!("failed to generate shadowsocks 2022 UDP session ID: {error}")
        })?;
        Ok(Self {
            client_session_id,
            next_packet_id: 0,
            server_sessions: HashMap::new(),
        })
    }

    fn next_client_packet(&mut self) -> anyhow::Result<([u8; 8], u64)> {
        let packet_id = self.next_packet_id;
        self.next_packet_id = self
            .next_packet_id
            .checked_add(1)
            .ok_or_else(|| anyhow!("shadowsocks 2022 UDP packet ID exhausted"))?;
        Ok((self.client_session_id, packet_id))
    }

    fn accept_server_packet(
        &mut self,
        server_session_id: [u8; 8],
        packet_id: u64,
    ) -> anyhow::Result<()> {
        let now = Instant::now();
        self.server_sessions
            .retain(|_, session| now.duration_since(session.last_seen) < Duration::from_secs(60));
        if self.server_sessions.len() >= 64
            && !self.server_sessions.contains_key(&server_session_id)
        {
            return Err(anyhow!(
                "too many active shadowsocks 2022 UDP server sessions"
            ));
        }
        let session = self
            .server_sessions
            .entry(server_session_id)
            .or_insert_with(|| Ss2022ServerSession {
                replay: Ss2022ReplayWindow::default(),
                last_seen: now,
            });
        if !session.replay.accept(packet_id) {
            return Err(anyhow!(
                "shadowsocks 2022 UDP replayed or out-of-window packet"
            ));
        }
        session.last_seen = now;
        Ok(())
    }
}

pub(super) const SS_CHUNK_SIZE: usize = 0x3fff;
pub(super) const SS_TAG_LEN: usize = 16;
pub(super) const SS_NONCE_LEN: usize = 12;

macro_rules! define_lea_adapter {
    ($adapter:ident, $backend:ident, $lea:ty, $key_size:ty) => {
        struct $adapter($lea);

        impl KeySizeUser for $adapter {
            type KeySize = $key_size;
        }

        impl BlockSizeUser for $adapter {
            type BlockSize = U16;
        }

        impl BlockCipher for $adapter {}

        impl BlockKeyInit for $adapter {
            fn new(key: &Key<Self>) -> Self {
                let legacy_key = lea::cipher::generic_array::GenericArray::clone_from_slice(key);
                Self(<$lea as lea::cipher::NewBlockCipher>::new(&legacy_key))
            }
        }

        struct $backend<'a>(&'a $adapter);

        impl BlockSizeUser for $backend<'_> {
            type BlockSize = U16;
        }

        impl ParBlocksSizeUser for $backend<'_> {
            type ParBlocksSize = U1;
        }

        impl BlockBackend for $backend<'_> {
            fn proc_block(&mut self, mut block: InOut<'_, '_, Block<Self>>) {
                let mut legacy_block =
                    lea::cipher::generic_array::GenericArray::clone_from_slice(block.get_in());
                lea::cipher::BlockEncrypt::encrypt_block(&self.0 .0, &mut legacy_block);
                block.get_out().copy_from_slice(&legacy_block);
            }
        }

        impl BlockEncrypt for $adapter {
            fn encrypt_with_backend(&self, f: impl BlockClosure<BlockSize = U16>) {
                f.call(&mut $backend(self));
            }
        }
    };
}

define_lea_adapter!(Lea128Adapter, Lea128EncryptBackend, lea::Lea128, U16);
define_lea_adapter!(Lea192Adapter, Lea192EncryptBackend, lea::Lea192, U24);
define_lea_adapter!(Lea256Adapter, Lea256EncryptBackend, lea::Lea256, U32);

type Lea128Gcm = AesGcm<Lea128Adapter, U12>;
type Lea192Gcm = AesGcm<Lea192Adapter, U12>;
type Lea256Gcm = AesGcm<Lea256Adapter, U12>;

fn encrypt_aegis128l(key: &[u8], nonce: &[u8], plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
    let key: [u8; 16] = key
        .try_into()
        .map_err(|_| anyhow!("invalid aegis-128l key"))?;
    let nonce: [u8; 16] = nonce
        .try_into()
        .map_err(|_| anyhow!("invalid aegis-128l nonce"))?;
    let (mut ciphertext, tag) =
        aegis::aegis128l::Aegis128L::<SS_TAG_LEN>::new(&key, &nonce).encrypt(plaintext, &[]);
    ciphertext.extend_from_slice(&tag);
    Ok(ciphertext)
}

fn decrypt_aegis128l(key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
    let key: [u8; 16] = key
        .try_into()
        .map_err(|_| anyhow!("invalid aegis-128l key"))?;
    let nonce: [u8; 16] = nonce
        .try_into()
        .map_err(|_| anyhow!("invalid aegis-128l nonce"))?;
    let split = ciphertext
        .len()
        .checked_sub(SS_TAG_LEN)
        .ok_or_else(|| anyhow!("short aegis-128l ciphertext"))?;
    let tag: [u8; SS_TAG_LEN] = ciphertext[split..].try_into()?;
    aegis::aegis128l::Aegis128L::<SS_TAG_LEN>::new(&key, &nonce)
        .decrypt(&ciphertext[..split], &tag, &[])
        .map_err(|_| anyhow!("shadowsocks decrypt failed"))
}

fn encrypt_aegis256(key: &[u8], nonce: &[u8], plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
    let key: [u8; 32] = key
        .try_into()
        .map_err(|_| anyhow!("invalid aegis-256 key"))?;
    let nonce: [u8; 32] = nonce
        .try_into()
        .map_err(|_| anyhow!("invalid aegis-256 nonce"))?;
    let (mut ciphertext, tag) =
        aegis::aegis256::Aegis256::<SS_TAG_LEN>::new(&key, &nonce).encrypt(plaintext, &[]);
    ciphertext.extend_from_slice(&tag);
    Ok(ciphertext)
}

fn decrypt_aegis256(key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
    let key: [u8; 32] = key
        .try_into()
        .map_err(|_| anyhow!("invalid aegis-256 key"))?;
    let nonce: [u8; 32] = nonce
        .try_into()
        .map_err(|_| anyhow!("invalid aegis-256 nonce"))?;
    let split = ciphertext
        .len()
        .checked_sub(SS_TAG_LEN)
        .ok_or_else(|| anyhow!("short aegis-256 ciphertext"))?;
    let tag: [u8; SS_TAG_LEN] = ciphertext[split..].try_into()?;
    aegis::aegis256::Aegis256::<SS_TAG_LEN>::new(&key, &nonce)
        .decrypt(&ciphertext[..split], &tag, &[])
        .map_err(|_| anyhow!("shadowsocks decrypt failed"))
}

fn encrypt_deoxys(key: &[u8], nonce: &[u8], plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
    use deoxys::aead::{Aead, KeyInit};

    let cipher = deoxys::DeoxysII256::new_from_slice(key)
        .map_err(|_| anyhow!("invalid deoxys-ii-256-128 key"))?;
    let nonce: &deoxys::Nonce<deoxys::consts::U15> = nonce
        .try_into()
        .map_err(|_| anyhow!("invalid deoxys-ii-256-128 nonce"))?;
    cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| anyhow!("shadowsocks encrypt failed"))
}

fn decrypt_deoxys(key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
    use deoxys::aead::{Aead, KeyInit};

    let cipher = deoxys::DeoxysII256::new_from_slice(key)
        .map_err(|_| anyhow!("invalid deoxys-ii-256-128 key"))?;
    let nonce: &deoxys::Nonce<deoxys::consts::U15> = nonce
        .try_into()
        .map_err(|_| anyhow!("invalid deoxys-ii-256-128 nonce"))?;
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| anyhow!("shadowsocks decrypt failed"))
}

fn encrypt_ascon128(key: &[u8], nonce: &[u8], plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
    use ascon_aead::aead::{Aead, KeyInit};

    let cipher =
        ascon_aead::Ascon128::new_from_slice(key).map_err(|_| anyhow!("invalid ascon128 key"))?;
    cipher
        .encrypt(
            ascon_aead::Nonce::<ascon_aead::Ascon128>::from_slice(nonce),
            plaintext,
        )
        .map_err(|_| anyhow!("shadowsocks encrypt failed"))
}

fn decrypt_ascon128(key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
    use ascon_aead::aead::{Aead, KeyInit};

    let cipher =
        ascon_aead::Ascon128::new_from_slice(key).map_err(|_| anyhow!("invalid ascon128 key"))?;
    cipher
        .decrypt(
            ascon_aead::Nonce::<ascon_aead::Ascon128>::from_slice(nonce),
            ciphertext,
        )
        .map_err(|_| anyhow!("shadowsocks decrypt failed"))
}

fn encrypt_ascon128a(key: &[u8], nonce: &[u8], plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
    use ascon_aead::aead::{Aead, KeyInit};

    let cipher =
        ascon_aead::Ascon128a::new_from_slice(key).map_err(|_| anyhow!("invalid ascon128a key"))?;
    cipher
        .encrypt(
            ascon_aead::Nonce::<ascon_aead::Ascon128a>::from_slice(nonce),
            plaintext,
        )
        .map_err(|_| anyhow!("shadowsocks encrypt failed"))
}

fn decrypt_ascon128a(key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
    use ascon_aead::aead::{Aead, KeyInit};

    let cipher =
        ascon_aead::Ascon128a::new_from_slice(key).map_err(|_| anyhow!("invalid ascon128a key"))?;
    cipher
        .decrypt(
            ascon_aead::Nonce::<ascon_aead::Ascon128a>::from_slice(nonce),
            ciphertext,
        )
        .map_err(|_| anyhow!("shadowsocks decrypt failed"))
}

fn rabbit_poly1305_tag(
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    associated_data: &[u8],
) -> anyhow::Result<[u8; SS_TAG_LEN]> {
    use poly1305::universal_hash::{KeyInit, UniversalHash};

    let mut one_time_key = [0u8; poly1305::KEY_SIZE];
    let mut rabbit = super::rabbit_compat::RabbitCompat::new(key, nonce)?;
    rabbit.apply_keystream(&mut one_time_key);

    let mut authenticator = poly1305::Poly1305::new((&one_time_key).into());
    authenticator.update_padded(associated_data);
    authenticator.update_padded(ciphertext);
    let mut lengths = poly1305::Block::default();
    lengths[..8].copy_from_slice(&(associated_data.len() as u64).to_le_bytes());
    lengths[8..].copy_from_slice(&(ciphertext.len() as u64).to_le_bytes());
    authenticator.update(&[lengths]);
    Ok(authenticator.finalize().into())
}

fn encrypt_rabbit_poly1305(key: &[u8], nonce: &[u8], plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
    encrypt_rabbit_poly1305_with_aad(key, nonce, plaintext, &[])
}

pub(super) fn encrypt_rabbit_poly1305_with_aad(
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    associated_data: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let mut ciphertext = plaintext.to_vec();
    let mut rabbit = super::rabbit_compat::RabbitCompat::new(key, nonce)?;
    rabbit.apply_keystream(&mut ciphertext);
    let tag = rabbit_poly1305_tag(key, nonce, &ciphertext, associated_data)?;
    ciphertext.extend_from_slice(&tag);
    Ok(ciphertext)
}

fn decrypt_rabbit_poly1305(key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
    use subtle::ConstantTimeEq;

    let split = ciphertext
        .len()
        .checked_sub(SS_TAG_LEN)
        .ok_or_else(|| anyhow!("short rabbit128-poly1305 ciphertext"))?;
    let expected_tag = rabbit_poly1305_tag(key, nonce, &ciphertext[..split], &[])?;
    if !bool::from(expected_tag.ct_eq(&ciphertext[split..])) {
        return Err(anyhow!("shadowsocks decrypt failed"));
    }
    let mut plaintext = ciphertext[..split].to_vec();
    let mut rabbit = super::rabbit_compat::RabbitCompat::new(key, nonce)?;
    rabbit.apply_keystream(&mut plaintext);
    Ok(plaintext)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SsCipher {
    Aes128Gcm,
    Aes192Gcm,
    Aes256Gcm,
    Aes192Ccm,
    Lea128Gcm,
    Lea192Gcm,
    Lea256Gcm,
    Aegis128L,
    Aegis256,
    Aez384,
    DeoxysIi256128,
    Ascon128,
    Ascon128a,
    Rabbit128Poly1305,
    Chacha20IetfPoly1305,
    Chacha8IetfPoly1305,
    XChacha8IetfPoly1305,
    Blake3Aes128Gcm,
    Blake3Aes256Gcm,
    Blake3Chacha20IetfPoly1305,
    Blake3Chacha8Poly1305,
}

impl SsCipher {
    pub(super) fn from_method(method: &str) -> anyhow::Result<Self> {
        match method.to_ascii_lowercase().as_str() {
            "aes-128-gcm" => Ok(Self::Aes128Gcm),
            "aes-192-gcm" => Ok(Self::Aes192Gcm),
            "aes-256-gcm" => Ok(Self::Aes256Gcm),
            "aes-192-ccm" => Ok(Self::Aes192Ccm),
            "lea-128-gcm" => Ok(Self::Lea128Gcm),
            "lea-192-gcm" => Ok(Self::Lea192Gcm),
            "lea-256-gcm" => Ok(Self::Lea256Gcm),
            "aegis-128l" => Ok(Self::Aegis128L),
            "aegis-256" => Ok(Self::Aegis256),
            "aez-384" => Ok(Self::Aez384),
            "deoxys-ii-256-128" => Ok(Self::DeoxysIi256128),
            "ascon128" => Ok(Self::Ascon128),
            "ascon128a" => Ok(Self::Ascon128a),
            "rabbit128-poly1305" => Ok(Self::Rabbit128Poly1305),
            "chacha20-ietf-poly1305" | "chacha20-poly1305" => Ok(Self::Chacha20IetfPoly1305),
            "chacha8-ietf-poly1305" => Ok(Self::Chacha8IetfPoly1305),
            "xchacha8-ietf-poly1305" => Ok(Self::XChacha8IetfPoly1305),
            "2022-blake3-aes-128-gcm" => Ok(Self::Blake3Aes128Gcm),
            "2022-blake3-aes-256-gcm" => Ok(Self::Blake3Aes256Gcm),
            "2022-blake3-chacha20-poly1305" => Ok(Self::Blake3Chacha20IetfPoly1305),
            "2022-blake3-chacha8-poly1305" => Ok(Self::Blake3Chacha8Poly1305),
            _ => Err(anyhow!("unsupported shadowsocks method {method}")),
        }
    }

    pub(super) fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm
            | Self::Lea128Gcm
            | Self::Aegis128L
            | Self::Ascon128
            | Self::Ascon128a
            | Self::Rabbit128Poly1305
            | Self::Blake3Aes128Gcm => 16,
            Self::Aes192Gcm | Self::Aes192Ccm | Self::Lea192Gcm => 24,
            Self::Aes256Gcm
            | Self::Lea256Gcm
            | Self::Aegis256
            | Self::DeoxysIi256128
            | Self::Chacha20IetfPoly1305
            | Self::Chacha8IetfPoly1305
            | Self::XChacha8IetfPoly1305
            | Self::Blake3Aes256Gcm
            | Self::Blake3Chacha20IetfPoly1305
            | Self::Blake3Chacha8Poly1305 => 32,
            Self::Aez384 => 48,
        }
    }

    pub(super) fn salt_len(self) -> usize {
        match self {
            Self::Blake3Aes128Gcm
            | Self::Blake3Aes256Gcm
            | Self::Blake3Chacha20IetfPoly1305
            | Self::Blake3Chacha8Poly1305 => self.key_len(),
            _ => self.key_len(),
        }
    }

    pub(super) fn nonce_len(self) -> usize {
        match self {
            Self::XChacha8IetfPoly1305 => 24,
            Self::Aegis128L | Self::Aez384 | Self::Ascon128 | Self::Ascon128a => 16,
            Self::Rabbit128Poly1305 => 8,
            Self::Aegis256 => 32,
            Self::DeoxysIi256128 => 15,
            _ => SS_NONCE_LEN,
        }
    }

    pub(super) fn is_blake3(self) -> bool {
        matches!(
            self,
            Self::Blake3Aes128Gcm
                | Self::Blake3Aes256Gcm
                | Self::Blake3Chacha20IetfPoly1305
                | Self::Blake3Chacha8Poly1305
        )
    }

    fn is_blake3_chacha(self) -> bool {
        matches!(
            self,
            Self::Blake3Chacha20IetfPoly1305 | Self::Blake3Chacha8Poly1305
        )
    }

    pub(super) fn master_key(self, password: &[u8]) -> anyhow::Result<Vec<u8>> {
        if !self.is_blake3() {
            return Ok(evp_bytes_to_key(password, self.key_len()));
        }
        self.psk_chain(password)?
            .into_iter()
            .last()
            .ok_or_else(|| anyhow!("shadowsocks 2022 PSK is empty"))
    }

    fn psk_chain(self, password: &[u8]) -> anyhow::Result<Vec<Vec<u8>>> {
        if !self.is_blake3() {
            return Ok(vec![evp_bytes_to_key(password, self.key_len())]);
        }
        let password = std::str::from_utf8(password)
            .map_err(|_| anyhow!("shadowsocks 2022 PSK must be base64 text"))?;
        let mut keys = Vec::new();
        for encoded in password.split(':').map(str::trim) {
            if encoded.is_empty() {
                return Err(anyhow!("shadowsocks 2022 PSK chain contains an empty key"));
            }
            let decoded = [
                &base64::engine::general_purpose::STANDARD,
                &base64::engine::general_purpose::STANDARD_NO_PAD,
                &base64::engine::general_purpose::URL_SAFE,
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            ]
            .into_iter()
            .find_map(|engine| base64::Engine::decode(engine, encoded).ok())
            .ok_or_else(|| anyhow!("shadowsocks 2022 PSK is not valid base64"))?;
            if decoded.len() != self.key_len() {
                return Err(anyhow!(
                    "shadowsocks 2022 PSK has {} bytes, expected {}",
                    decoded.len(),
                    self.key_len()
                ));
            }
            keys.push(decoded);
        }
        if keys.is_empty() {
            return Err(anyhow!("shadowsocks 2022 PSK is empty"));
        }
        Ok(keys)
    }

    pub(super) fn derive_subkey(self, master_key: &[u8], salt: &[u8]) -> anyhow::Result<Vec<u8>> {
        if self.is_blake3() {
            let mut key_material = Vec::with_capacity(master_key.len() + salt.len());
            key_material.extend_from_slice(master_key);
            key_material.extend_from_slice(salt);
            let derived = blake3::derive_key("shadowsocks 2022 session subkey", &key_material);
            Ok(derived[..self.key_len()].to_vec())
        } else {
            let hkdf = Hkdf::<Sha1>::new(Some(salt), master_key);
            let mut subkey = vec![0u8; self.key_len()];
            hkdf.expand(b"ss-subkey", &mut subkey)
                .map_err(|_| anyhow!("failed to derive shadowsocks subkey"))?;
            Ok(subkey)
        }
    }

    pub(super) fn encrypt(
        self,
        key: &[u8],
        nonce: &[u8],
        plaintext: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        match self {
            Self::Aes128Gcm | Self::Blake3Aes128Gcm => Aes128Gcm::new_from_slice(key)
                .map_err(|_| anyhow!("invalid aes-128-gcm key"))?
                .encrypt(aes_gcm::Nonce::from_slice(nonce), plaintext)
                .map_err(|_| anyhow!("shadowsocks encrypt failed")),
            Self::Aes192Gcm => AesGcm::<Aes192, U12>::new_from_slice(key)
                .map_err(|_| anyhow!("invalid aes-192-gcm key"))?
                .encrypt(aes_gcm::Nonce::from_slice(nonce), plaintext)
                .map_err(|_| anyhow!("shadowsocks encrypt failed")),
            Self::Aes256Gcm | Self::Blake3Aes256Gcm => Aes256Gcm::new_from_slice(key)
                .map_err(|_| anyhow!("invalid aes-256-gcm key"))?
                .encrypt(aes_gcm::Nonce::from_slice(nonce), plaintext)
                .map_err(|_| anyhow!("shadowsocks encrypt failed")),
            Self::Aes192Ccm => Ccm::<Aes192, U16, U12>::new_from_slice(key)
                .map_err(|_| anyhow!("invalid aes-192-ccm key"))?
                .encrypt(ccm::Nonce::<U12>::from_slice(nonce), plaintext)
                .map_err(|_| anyhow!("shadowsocks encrypt failed")),
            Self::Lea128Gcm => Lea128Gcm::new_from_slice(key)
                .map_err(|_| anyhow!("invalid lea-128-gcm key"))?
                .encrypt(aes_gcm::Nonce::from_slice(nonce), plaintext)
                .map_err(|_| anyhow!("shadowsocks encrypt failed")),
            Self::Lea192Gcm => Lea192Gcm::new_from_slice(key)
                .map_err(|_| anyhow!("invalid lea-192-gcm key"))?
                .encrypt(aes_gcm::Nonce::from_slice(nonce), plaintext)
                .map_err(|_| anyhow!("shadowsocks encrypt failed")),
            Self::Lea256Gcm => Lea256Gcm::new_from_slice(key)
                .map_err(|_| anyhow!("invalid lea-256-gcm key"))?
                .encrypt(aes_gcm::Nonce::from_slice(nonce), plaintext)
                .map_err(|_| anyhow!("shadowsocks encrypt failed")),
            Self::Aegis128L => encrypt_aegis128l(key, nonce, plaintext),
            Self::Aegis256 => encrypt_aegis256(key, nonce, plaintext),
            Self::Aez384 => {
                Ok(zears::Aez::new(key).encrypt(nonce, &[], SS_TAG_LEN as u32, plaintext))
            }
            Self::DeoxysIi256128 => encrypt_deoxys(key, nonce, plaintext),
            Self::Ascon128 => encrypt_ascon128(key, nonce, plaintext),
            Self::Ascon128a => encrypt_ascon128a(key, nonce, plaintext),
            Self::Rabbit128Poly1305 => encrypt_rabbit_poly1305(key, nonce, plaintext),
            Self::Chacha20IetfPoly1305 | Self::Blake3Chacha20IetfPoly1305 => {
                ChaCha20Poly1305::new_from_slice(key)
                    .map_err(|_| anyhow!("invalid chacha20-ietf-poly1305 key"))?
                    .encrypt(chacha20poly1305::Nonce::from_slice(nonce), plaintext)
                    .map_err(|_| anyhow!("shadowsocks encrypt failed"))
            }
            Self::Chacha8IetfPoly1305 | Self::Blake3Chacha8Poly1305 => {
                ChaCha8Poly1305::new_from_slice(key)
                    .map_err(|_| anyhow!("invalid chacha8-ietf-poly1305 key"))?
                    .encrypt(chacha20poly1305::Nonce::from_slice(nonce), plaintext)
                    .map_err(|_| anyhow!("shadowsocks encrypt failed"))
            }
            Self::XChacha8IetfPoly1305 => XChaCha8Poly1305::new_from_slice(key)
                .map_err(|_| anyhow!("invalid xchacha8-ietf-poly1305 key"))?
                .encrypt(chacha20poly1305::XNonce::from_slice(nonce), plaintext)
                .map_err(|_| anyhow!("shadowsocks encrypt failed")),
        }
    }

    pub(super) fn decrypt(
        self,
        key: &[u8],
        nonce: &[u8],
        ciphertext: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        match self {
            Self::Aes128Gcm | Self::Blake3Aes128Gcm => Aes128Gcm::new_from_slice(key)
                .map_err(|_| anyhow!("invalid aes-128-gcm key"))?
                .decrypt(aes_gcm::Nonce::from_slice(nonce), ciphertext)
                .map_err(|_| anyhow!("shadowsocks decrypt failed")),
            Self::Aes192Gcm => AesGcm::<Aes192, U12>::new_from_slice(key)
                .map_err(|_| anyhow!("invalid aes-192-gcm key"))?
                .decrypt(aes_gcm::Nonce::from_slice(nonce), ciphertext)
                .map_err(|_| anyhow!("shadowsocks decrypt failed")),
            Self::Aes256Gcm | Self::Blake3Aes256Gcm => Aes256Gcm::new_from_slice(key)
                .map_err(|_| anyhow!("invalid aes-256-gcm key"))?
                .decrypt(aes_gcm::Nonce::from_slice(nonce), ciphertext)
                .map_err(|_| anyhow!("shadowsocks decrypt failed")),
            Self::Aes192Ccm => Ccm::<Aes192, U16, U12>::new_from_slice(key)
                .map_err(|_| anyhow!("invalid aes-192-ccm key"))?
                .decrypt(ccm::Nonce::<U12>::from_slice(nonce), ciphertext)
                .map_err(|_| anyhow!("shadowsocks decrypt failed")),
            Self::Lea128Gcm => Lea128Gcm::new_from_slice(key)
                .map_err(|_| anyhow!("invalid lea-128-gcm key"))?
                .decrypt(aes_gcm::Nonce::from_slice(nonce), ciphertext)
                .map_err(|_| anyhow!("shadowsocks decrypt failed")),
            Self::Lea192Gcm => Lea192Gcm::new_from_slice(key)
                .map_err(|_| anyhow!("invalid lea-192-gcm key"))?
                .decrypt(aes_gcm::Nonce::from_slice(nonce), ciphertext)
                .map_err(|_| anyhow!("shadowsocks decrypt failed")),
            Self::Lea256Gcm => Lea256Gcm::new_from_slice(key)
                .map_err(|_| anyhow!("invalid lea-256-gcm key"))?
                .decrypt(aes_gcm::Nonce::from_slice(nonce), ciphertext)
                .map_err(|_| anyhow!("shadowsocks decrypt failed")),
            Self::Aegis128L => decrypt_aegis128l(key, nonce, ciphertext),
            Self::Aegis256 => decrypt_aegis256(key, nonce, ciphertext),
            Self::Aez384 => zears::Aez::new(key)
                .decrypt(nonce, &[], SS_TAG_LEN as u32, ciphertext)
                .ok_or_else(|| anyhow!("shadowsocks decrypt failed")),
            Self::DeoxysIi256128 => decrypt_deoxys(key, nonce, ciphertext),
            Self::Ascon128 => decrypt_ascon128(key, nonce, ciphertext),
            Self::Ascon128a => decrypt_ascon128a(key, nonce, ciphertext),
            Self::Rabbit128Poly1305 => decrypt_rabbit_poly1305(key, nonce, ciphertext),
            Self::Chacha20IetfPoly1305 | Self::Blake3Chacha20IetfPoly1305 => {
                ChaCha20Poly1305::new_from_slice(key)
                    .map_err(|_| anyhow!("invalid chacha20-ietf-poly1305 key"))?
                    .decrypt(chacha20poly1305::Nonce::from_slice(nonce), ciphertext)
                    .map_err(|_| anyhow!("shadowsocks decrypt failed"))
            }
            Self::Chacha8IetfPoly1305 | Self::Blake3Chacha8Poly1305 => {
                ChaCha8Poly1305::new_from_slice(key)
                    .map_err(|_| anyhow!("invalid chacha8-ietf-poly1305 key"))?
                    .decrypt(chacha20poly1305::Nonce::from_slice(nonce), ciphertext)
                    .map_err(|_| anyhow!("shadowsocks decrypt failed"))
            }
            Self::XChacha8IetfPoly1305 => XChaCha8Poly1305::new_from_slice(key)
                .map_err(|_| anyhow!("invalid xchacha8-ietf-poly1305 key"))?
                .decrypt(chacha20poly1305::XNonce::from_slice(nonce), ciphertext)
                .map_err(|_| anyhow!("shadowsocks decrypt failed")),
        }
    }

    pub(super) fn max_chunk_size(self) -> usize {
        if self.is_blake3() {
            u16::MAX as usize
        } else {
            SS_CHUNK_SIZE
        }
    }
}

pub(super) fn evp_bytes_to_key(password: &[u8], key_len: usize) -> Vec<u8> {
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

pub(super) fn increment_nonce(nonce: &mut [u8]) {
    for item in nonce.iter_mut() {
        let (next, overflow) = item.overflowing_add(1);
        *item = next;
        if !overflow {
            break;
        }
    }
}

const SS2022_CLIENT_STREAM_TYPE: u8 = 0;
const SS2022_SERVER_STREAM_TYPE: u8 = 1;
const SS2022_MAX_CLOCK_SKEW_SECS: u64 = 30;

fn current_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn validate_ss2022_timestamp(timestamp: u64) -> anyhow::Result<()> {
    let now = current_unix_timestamp();
    if now.abs_diff(timestamp) > SS2022_MAX_CLOCK_SKEW_SECS {
        return Err(anyhow!(
            "shadowsocks 2022 timestamp is outside the allowed clock skew"
        ));
    }
    Ok(())
}

fn build_ss2022_request_header(
    cipher: SsCipher,
    subkey: &[u8],
    nonce: &mut [u8],
    destination: &Destination,
) -> anyhow::Result<Vec<u8>> {
    let mut variable_header = Vec::new();
    encode_socks5_destination(destination, &mut variable_header)?;

    let mut random = [0u8; 1];
    getrandom::fill(&mut random)
        .map_err(|error| anyhow!("failed to generate shadowsocks 2022 padding: {error}"))?;
    let padding_length = 1 + (random[0] as usize % 32);
    variable_header.extend_from_slice(&(padding_length as u16).to_be_bytes());
    let padding_start = variable_header.len();
    variable_header.resize(padding_start + padding_length, 0);
    getrandom::fill(&mut variable_header[padding_start..])
        .map_err(|error| anyhow!("failed to generate shadowsocks 2022 padding: {error}"))?;
    if variable_header.len() > u16::MAX as usize {
        return Err(anyhow!("shadowsocks 2022 request header is too large"));
    }

    let mut fixed_header = Vec::with_capacity(11);
    fixed_header.push(SS2022_CLIENT_STREAM_TYPE);
    fixed_header.extend_from_slice(&current_unix_timestamp().to_be_bytes());
    fixed_header.extend_from_slice(&(variable_header.len() as u16).to_be_bytes());

    let mut output = cipher.encrypt(subkey, nonce, &fixed_header)?;
    increment_nonce(nonce);
    output.extend_from_slice(&cipher.encrypt(subkey, nonce, &variable_header)?);
    increment_nonce(nonce);
    Ok(output)
}

fn build_ss2022_tcp_identity_headers(
    cipher: SsCipher,
    psk_chain: &[Vec<u8>],
    salt: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let mut output = Vec::with_capacity(psk_chain.len().saturating_sub(1) * 16);
    for pair in psk_chain.windows(2) {
        let mut key_material = Vec::with_capacity(pair[0].len() + salt.len());
        key_material.extend_from_slice(&pair[0]);
        key_material.extend_from_slice(salt);
        let identity_subkey = blake3::derive_key("shadowsocks 2022 identity subkey", &key_material);
        let next_hash = blake3::hash(&pair[1]);
        let plaintext: [u8; 16] = next_hash.as_bytes()[..16].try_into()?;
        let encrypted =
            ss2022_identity_aes_block(&identity_subkey[..cipher.key_len()], &plaintext, true)?;
        output.extend_from_slice(&encrypted);
    }
    Ok(output)
}

async fn read_ss2022_response_header<R>(
    cipher: SsCipher,
    subkey: &[u8],
    nonce: &mut [u8],
    request_salt: &[u8],
    reader: &mut R,
) -> anyhow::Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let fixed_header_length = 1 + 8 + request_salt.len() + 2;
    let mut encrypted_fixed_header = vec![0u8; fixed_header_length + SS_TAG_LEN];
    reader.read_exact(&mut encrypted_fixed_header).await?;
    let fixed_header = cipher.decrypt(subkey, nonce, &encrypted_fixed_header)?;
    increment_nonce(nonce);
    if fixed_header.len() != fixed_header_length {
        return Err(anyhow!(
            "invalid shadowsocks 2022 response fixed header length"
        ));
    }
    if fixed_header[0] != SS2022_SERVER_STREAM_TYPE {
        return Err(anyhow!(
            "invalid shadowsocks 2022 response stream type {}",
            fixed_header[0]
        ));
    }
    let timestamp = u64::from_be_bytes(fixed_header[1..9].try_into()?);
    validate_ss2022_timestamp(timestamp)?;
    let salt_end = 9 + request_salt.len();
    if &fixed_header[9..salt_end] != request_salt {
        return Err(anyhow!(
            "shadowsocks 2022 response does not match request salt"
        ));
    }
    let payload_length =
        u16::from_be_bytes(fixed_header[salt_end..salt_end + 2].try_into()?) as usize;
    let mut encrypted_payload = vec![0u8; payload_length + SS_TAG_LEN];
    reader.read_exact(&mut encrypted_payload).await?;
    let payload = cipher.decrypt(subkey, nonce, &encrypted_payload)?;
    increment_nonce(nonce);
    Ok(payload)
}

fn encode_legacy_ss_stream_udp_packet(
    method: LegacySsStreamMethod,
    password: &[u8],
    destination: &Destination,
    payload: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let key = evp_bytes_to_key(password, method.key_len());
    let mut iv = vec![0u8; method.iv_len()];
    getrandom::fill(&mut iv)
        .map_err(|error| anyhow!("failed to generate shadowsocks UDP IV: {error}"))?;
    let mut plaintext = Vec::with_capacity(1 + 255 + 2 + payload.len());
    encode_socks5_destination(destination, &mut plaintext)?;
    plaintext.extend_from_slice(payload);
    method
        .new_cipher(&key, &iv)?
        .apply_keystream(&mut plaintext);
    let mut packet = iv;
    packet.extend_from_slice(&plaintext);
    Ok(packet)
}

fn decode_legacy_ss_stream_udp_packet(
    method: LegacySsStreamMethod,
    password: &[u8],
    packet: &[u8],
) -> anyhow::Result<(Destination, Vec<u8>)> {
    if packet.len() <= method.iv_len() {
        return Err(anyhow!("short shadowsocks stream UDP packet"));
    }
    let key = evp_bytes_to_key(password, method.key_len());
    let mut plaintext = packet[method.iv_len()..].to_vec();
    method
        .new_cipher(&key, &packet[..method.iv_len()])?
        .apply_keystream(&mut plaintext);
    let (destination, offset) = parse_socks5_destination_prefix(&plaintext)?;
    Ok((destination, plaintext[offset..].to_vec()))
}

fn encode_shadowsocks_udp_packet(
    cipher: SsCipher,
    password: &[u8],
    destination: &Destination,
    payload: &[u8],
    ss2022_state: Option<&mut Ss2022UdpState>,
) -> anyhow::Result<Vec<u8>> {
    if cipher.is_blake3() {
        return encode_ss2022_udp_packet(
            cipher,
            password,
            destination,
            payload,
            ss2022_state.ok_or_else(|| anyhow!("missing shadowsocks 2022 UDP session state"))?,
        );
    }
    let master_key = cipher.master_key(password)?;
    let mut salt = vec![0u8; cipher.salt_len()];
    getrandom::fill(&mut salt)
        .map_err(|error| anyhow!("failed to generate shadowsocks udp salt: {error}"))?;
    let subkey = cipher.derive_subkey(&master_key, &salt)?;
    let mut plaintext = Vec::with_capacity(1 + 255 + 2 + payload.len());
    encode_socks5_destination(destination, &mut plaintext)?;
    plaintext.extend_from_slice(payload);
    let nonce = vec![0u8; cipher.nonce_len()];
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
    ss2022_state: Option<&mut Ss2022UdpState>,
) -> anyhow::Result<(Destination, Vec<u8>)> {
    if cipher.is_blake3() {
        return decode_ss2022_udp_packet(
            cipher,
            password,
            packet,
            ss2022_state.ok_or_else(|| anyhow!("missing shadowsocks 2022 UDP session state"))?,
        );
    }
    let salt_len = cipher.salt_len();
    if packet.len() < salt_len + SS_TAG_LEN {
        return Err(anyhow!("short shadowsocks udp packet"));
    }
    let master_key = cipher.master_key(password)?;
    let subkey = cipher.derive_subkey(&master_key, &packet[..salt_len])?;
    let nonce = vec![0u8; cipher.nonce_len()];
    let plaintext = cipher.decrypt(&subkey, &nonce, &packet[salt_len..])?;
    let (destination, payload_offset) = parse_socks5_destination_prefix(&plaintext)?;
    Ok((destination, plaintext[payload_offset..].to_vec()))
}

fn encode_ss2022_udp_packet(
    cipher: SsCipher,
    password: &[u8],
    destination: &Destination,
    payload: &[u8],
    state: &mut Ss2022UdpState,
) -> anyhow::Result<Vec<u8>> {
    let psk_chain = cipher.psk_chain(password)?;
    let psk = psk_chain
        .last()
        .ok_or_else(|| anyhow!("shadowsocks 2022 PSK chain is empty"))?;
    let (client_session_id, packet_id) = state.next_client_packet()?;
    if cipher.is_blake3_chacha() {
        if psk_chain.len() > 1 {
            return Err(anyhow!(
                "SIP023 identity headers are not defined for Shadowsocks 2022 chacha UDP"
            ));
        }
        let mut nonce = [0u8; 24];
        getrandom::fill(&mut nonce)
            .map_err(|error| anyhow!("failed to generate shadowsocks 2022 UDP nonce: {error}"))?;
        let mut body = Vec::new();
        body.extend_from_slice(&client_session_id);
        body.extend_from_slice(&packet_id.to_be_bytes());
        body.push(0);
        body.extend_from_slice(&current_unix_timestamp().to_be_bytes());
        body.extend_from_slice(&0u16.to_be_bytes());
        encode_socks5_destination(destination, &mut body)?;
        body.extend_from_slice(payload);
        let encrypted = match cipher {
            SsCipher::Blake3Chacha20IetfPoly1305 => XChaCha20Poly1305::new_from_slice(psk)
                .map_err(|_| anyhow!("invalid shadowsocks 2022 chacha PSK"))?
                .encrypt(chacha20poly1305::XNonce::from_slice(&nonce), body.as_ref())
                .map_err(|_| anyhow!("shadowsocks 2022 UDP encryption failed"))?,
            SsCipher::Blake3Chacha8Poly1305 => XChaCha8Poly1305::new_from_slice(psk)
                .map_err(|_| anyhow!("invalid shadowsocks 2022 chacha8 PSK"))?
                .encrypt(chacha20poly1305::XNonce::from_slice(&nonce), body.as_ref())
                .map_err(|_| anyhow!("shadowsocks 2022 UDP encryption failed"))?,
            _ => unreachable!("checked as Shadowsocks 2022 chacha"),
        };
        let mut packet = nonce.to_vec();
        packet.extend_from_slice(&encrypted);
        return Ok(packet);
    }

    let mut separate_header = [0u8; 16];
    separate_header[..8].copy_from_slice(&client_session_id);
    separate_header[8..].copy_from_slice(&packet_id.to_be_bytes());
    let encrypted_header = ss2022_aes_block(cipher, &psk_chain[0], &separate_header, true)?;
    let subkey = cipher.derive_subkey(psk, &client_session_id)?;
    let nonce = &separate_header[4..16];
    let mut body = Vec::new();
    body.push(0);
    body.extend_from_slice(&current_unix_timestamp().to_be_bytes());
    body.extend_from_slice(&0u16.to_be_bytes());
    encode_socks5_destination(destination, &mut body)?;
    body.extend_from_slice(payload);
    let encrypted_body = cipher.encrypt(&subkey, nonce, &body)?;
    let mut packet = encrypted_header.to_vec();
    for pair in psk_chain.windows(2) {
        let next_hash = blake3::hash(&pair[1]);
        let mut plaintext: [u8; 16] = next_hash.as_bytes()[..16].try_into()?;
        for (byte, header_byte) in plaintext.iter_mut().zip(separate_header) {
            *byte ^= header_byte;
        }
        packet.extend_from_slice(&ss2022_identity_aes_block(&pair[0], &plaintext, true)?);
    }
    packet.extend_from_slice(&encrypted_body);
    Ok(packet)
}

fn decode_ss2022_udp_packet(
    cipher: SsCipher,
    password: &[u8],
    packet: &[u8],
    state: &mut Ss2022UdpState,
) -> anyhow::Result<(Destination, Vec<u8>)> {
    let psk = cipher.master_key(password)?;
    let (server_session_id, packet_id, body) = if cipher.is_blake3_chacha() {
        if packet.len() < 24 + SS_TAG_LEN {
            return Err(anyhow!("short shadowsocks 2022 chacha UDP packet"));
        }
        let nonce = &packet[..24];
        let body = match cipher {
            SsCipher::Blake3Chacha20IetfPoly1305 => XChaCha20Poly1305::new_from_slice(&psk)
                .map_err(|_| anyhow!("invalid shadowsocks 2022 chacha PSK"))?
                .decrypt(chacha20poly1305::XNonce::from_slice(nonce), &packet[24..])
                .map_err(|_| anyhow!("shadowsocks 2022 UDP decryption failed"))?,
            SsCipher::Blake3Chacha8Poly1305 => XChaCha8Poly1305::new_from_slice(&psk)
                .map_err(|_| anyhow!("invalid shadowsocks 2022 chacha8 PSK"))?
                .decrypt(chacha20poly1305::XNonce::from_slice(nonce), &packet[24..])
                .map_err(|_| anyhow!("shadowsocks 2022 UDP decryption failed"))?,
            _ => unreachable!("checked as Shadowsocks 2022 chacha"),
        };
        if body.len() < 16 {
            return Err(anyhow!("short shadowsocks 2022 chacha UDP message header"));
        }
        let server_session_id: [u8; 8] = body[..8].try_into()?;
        let packet_id = u64::from_be_bytes(body[8..16].try_into()?);
        (server_session_id, packet_id, body[16..].to_vec())
    } else {
        if packet.len() < 16 + SS_TAG_LEN {
            return Err(anyhow!("short shadowsocks 2022 AES UDP packet"));
        }
        let encrypted_header: [u8; 16] = packet[..16].try_into()?;
        let separate_header = ss2022_aes_block(cipher, &psk, &encrypted_header, false)?;
        let server_session_id: [u8; 8] = separate_header[..8].try_into()?;
        let packet_id = u64::from_be_bytes(separate_header[8..].try_into()?);
        let subkey = cipher.derive_subkey(&psk, &server_session_id)?;
        let body = cipher.decrypt(&subkey, &separate_header[4..16], &packet[16..])?;
        (server_session_id, packet_id, body)
    };

    if body.len() < 1 + 8 + 8 + 2 {
        return Err(anyhow!("short shadowsocks 2022 UDP response header"));
    }
    if body[0] != 1 {
        return Err(anyhow!(
            "invalid shadowsocks 2022 UDP response type {}",
            body[0]
        ));
    }
    let timestamp = u64::from_be_bytes(body[1..9].try_into()?);
    validate_ss2022_timestamp(timestamp)?;
    if body[9..17] != state.client_session_id {
        return Err(anyhow!(
            "shadowsocks 2022 UDP response has the wrong client session ID"
        ));
    }
    let padding_length = u16::from_be_bytes(body[17..19].try_into()?) as usize;
    let destination_offset = 19usize
        .checked_add(padding_length)
        .ok_or_else(|| anyhow!("shadowsocks 2022 UDP padding length overflow"))?;
    if destination_offset > body.len() {
        return Err(anyhow!("shadowsocks 2022 UDP padding is truncated"));
    }
    let (destination, destination_length) =
        parse_socks5_destination_prefix(&body[destination_offset..])?;
    let payload_offset = destination_offset + destination_length;
    state.accept_server_packet(server_session_id, packet_id)?;
    Ok((destination, body[payload_offset..].to_vec()))
}

fn ss2022_aes_block(
    cipher: SsCipher,
    psk: &[u8],
    input: &[u8; 16],
    encrypt: bool,
) -> anyhow::Result<[u8; 16]> {
    if !matches!(
        cipher,
        SsCipher::Blake3Aes128Gcm | SsCipher::Blake3Aes256Gcm
    ) {
        return Err(anyhow!("shadowsocks 2022 UDP AES block method required"));
    }
    ss2022_identity_aes_block(psk, input, encrypt)
}

fn ss2022_identity_aes_block(
    key: &[u8],
    input: &[u8; 16],
    encrypt: bool,
) -> anyhow::Result<[u8; 16]> {
    let mut output = [0u8; 16];
    match key.len() {
        16 => {
            let cipher = Aes128::new_from_slice(key)
                .map_err(|_| anyhow!("invalid shadowsocks 2022 AES-128 PSK"))?;
            let mut block = Block::<Aes128>::default();
            block.copy_from_slice(input);
            if encrypt {
                cipher.encrypt_block(&mut block);
            } else {
                cipher.decrypt_block(&mut block);
            }
            output.copy_from_slice(&block);
        }
        32 => {
            let cipher = Aes256::new_from_slice(key)
                .map_err(|_| anyhow!("invalid shadowsocks 2022 AES-256 PSK"))?;
            let mut block = Block::<Aes256>::default();
            block.copy_from_slice(input);
            if encrypt {
                cipher.encrypt_block(&mut block);
            } else {
                cipher.decrypt_block(&mut block);
            }
            output.copy_from_slice(&block);
        }
        length => {
            return Err(anyhow!(
                "shadowsocks 2022 identity key has invalid length {length}"
            ))
        }
    }
    Ok(output)
}

fn spawn_legacy_ss_stream(
    method: LegacySsStreamMethod,
    key: Vec<u8>,
    mut encryptor: LegacySsStreamCipher,
    stream: BoxedStream,
) -> DuplexStream {
    let (app_side, relay_side) = tokio::io::duplex(64 * 1024);
    let (mut local_read, mut local_write) = tokio::io::split(relay_side);
    let (mut remote_read, mut remote_write) = tokio::io::split(stream);

    tokio::spawn(async move {
        let mut buffer = vec![0u8; 16 * 1024];
        loop {
            match local_read.read(&mut buffer).await {
                Ok(0) => {
                    let _ = remote_write.shutdown().await;
                    break;
                }
                Ok(read) => {
                    encryptor.apply_keystream(&mut buffer[..read]);
                    if remote_write.write_all(&buffer[..read]).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    tokio::spawn(async move {
        let mut response_iv = vec![0u8; method.iv_len()];
        if remote_read.read_exact(&mut response_iv).await.is_err() {
            let _ = local_write.shutdown().await;
            return;
        }
        let Ok(mut decryptor) = method.new_cipher(&key, &response_iv) else {
            let _ = local_write.shutdown().await;
            return;
        };
        let mut buffer = vec![0u8; 16 * 1024];
        loop {
            match remote_read.read(&mut buffer).await {
                Ok(0) => break,
                Ok(read) => {
                    decryptor.apply_keystream(&mut buffer[..read]);
                    if local_write.write_all(&buffer[..read]).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = local_write.shutdown().await;
    });

    app_side
}

fn spawn_shadowsocks_stream(
    cipher: SsCipher,
    master_key: Vec<u8>,
    request_salt: Vec<u8>,
    upload_key: Vec<u8>,
    upload_nonce: Vec<u8>,
    stream: BoxedStream,
    plugin: Option<ShadowsocksPluginConfig>,
) -> DuplexStream {
    let (app_side, relay_side) = tokio::io::duplex(64 * 1024);
    let (mut local_read, mut local_write) = tokio::io::split(relay_side);
    let (mut remote_read, mut remote_write) = tokio::io::split(stream);

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
        if plugin_is_http_obfs(plugin.as_ref()) {
            match read_http_obfs_response(&mut remote_read).await {
                Ok(leftover) => {
                    let cursor = Cursor::new(leftover);
                    let mut chained = cursor.chain(remote_read);
                    relay_shadowsocks_download_with_response_salt(
                        cipher,
                        &master_key,
                        &request_salt,
                        &mut chained,
                        &mut local_write,
                    )
                    .await;
                }
                Err(_) => {
                    let _ = local_write.shutdown().await;
                }
            }
        } else if plugin_is_tls_obfs(plugin.as_ref()) {
            relay_shadowsocks_tls_download_with_response_salt(
                cipher,
                &master_key,
                &request_salt,
                remote_read,
                local_write,
            )
            .await;
        } else {
            relay_shadowsocks_download_with_response_salt(
                cipher,
                &master_key,
                &request_salt,
                &mut remote_read,
                &mut local_write,
            )
            .await;
        }
    });

    app_side
}

pub(super) fn spawn_simple_obfs_transport(
    stream: BoxedStream,
    plugin: ShadowsocksPluginConfig,
    server: String,
    port: u16,
) -> DuplexStream {
    let (app_side, relay_side) = tokio::io::duplex(64 * 1024);
    let (mut local_read, mut local_write) = tokio::io::split(relay_side);
    let (mut remote_read, mut remote_write) = tokio::io::split(stream);
    let upload_plugin = plugin.clone();
    let upload_tls = plugin_is_tls_obfs(Some(&plugin));

    tokio::spawn(async move {
        let mut first_write = true;
        let mut buffer = vec![0u8; SIMPLE_OBFS_TLS_MAX_APP_DATA_LEN];
        loop {
            let read = match local_read.read(&mut buffer).await {
                Ok(0) => {
                    let _ = remote_write.shutdown().await;
                    break;
                }
                Ok(read) => read,
                Err(_) => break,
            };
            let payload = if first_write {
                first_write = false;
                match apply_shadowsocks_plugin_request(
                    &upload_plugin,
                    &server,
                    port,
                    buffer[..read].to_vec(),
                ) {
                    Ok(payload) => payload,
                    Err(_) => break,
                }
            } else if upload_tls {
                wrap_simple_obfs_tls_app_data(&buffer[..read])
            } else {
                buffer[..read].to_vec()
            };
            if remote_write.write_all(&payload).await.is_err() {
                break;
            }
            if remote_write.flush().await.is_err() {
                break;
            }
        }
    });

    tokio::spawn(async move {
        if plugin_is_http_obfs(Some(&plugin)) {
            match read_http_obfs_response(&mut remote_read).await {
                Ok(leftover) => {
                    if !leftover.is_empty() && local_write.write_all(&leftover).await.is_err() {
                        return;
                    }
                    let _ = tokio::io::copy(&mut remote_read, &mut local_write).await;
                }
                Err(_) => {}
            }
        } else if plugin_is_tls_obfs(Some(&plugin)) {
            let mut decoder = SimpleObfsTlsDecoder::new();
            loop {
                match decoder
                    .read_some_or_eof(&mut remote_read, SIMPLE_OBFS_TLS_MAX_APP_DATA_LEN)
                    .await
                {
                    Ok(Some(payload)) => {
                        if local_write.write_all(&payload).await.is_err() {
                            break;
                        }
                    }
                    Ok(None) | Err(_) => break,
                }
            }
        }
        let _ = local_write.shutdown().await;
    });

    app_side
}

async fn relay_shadowsocks_download_with_response_salt<R, W>(
    cipher: SsCipher,
    master_key: &[u8],
    request_salt: &[u8],
    reader: &mut R,
    writer: &mut W,
) where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut response_salt = vec![0u8; cipher.salt_len()];
    if reader.read_exact(&mut response_salt).await.is_err() {
        let _ = writer.shutdown().await;
        return;
    }
    let Ok(response_key) = cipher.derive_subkey(master_key, &response_salt) else {
        let _ = writer.shutdown().await;
        return;
    };
    let mut nonce = vec![0u8; cipher.nonce_len()];
    if cipher.is_blake3() {
        match read_ss2022_response_header(cipher, &response_key, &mut nonce, request_salt, reader)
            .await
        {
            Ok(initial_payload) => {
                if !initial_payload.is_empty() && writer.write_all(&initial_payload).await.is_err()
                {
                    return;
                }
            }
            Err(_) => {
                let _ = writer.shutdown().await;
                return;
            }
        }
    }
    relay_shadowsocks_download(cipher, response_key, nonce, reader, writer).await;
}

async fn relay_shadowsocks_tls_download_with_response_salt<R, W>(
    cipher: SsCipher,
    master_key: &[u8],
    request_salt: &[u8],
    mut reader: R,
    mut writer: W,
) where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut decoder = SimpleObfsTlsDecoder::new();
    let response_salt = match decoder
        .read_exact_or_eof(&mut reader, cipher.salt_len())
        .await
    {
        Ok(Some(value)) => value,
        _ => {
            let _ = writer.shutdown().await;
            return;
        }
    };
    let Ok(response_key) = cipher.derive_subkey(master_key, &response_salt) else {
        let _ = writer.shutdown().await;
        return;
    };
    let mut nonce = vec![0u8; cipher.nonce_len()];
    if cipher.is_blake3() {
        match read_ss2022_response_header_from_tls_obfs(
            cipher,
            &response_key,
            &mut nonce,
            request_salt,
            &mut decoder,
            &mut reader,
        )
        .await
        {
            Ok(initial_payload) => {
                if !initial_payload.is_empty() && writer.write_all(&initial_payload).await.is_err()
                {
                    return;
                }
            }
            Err(_) => {
                let _ = writer.shutdown().await;
                return;
            }
        }
    }
    loop {
        match read_ss_chunk_from_tls_obfs(
            cipher,
            &response_key,
            &mut nonce,
            &mut decoder,
            &mut reader,
        )
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

async fn read_ss2022_response_header_from_tls_obfs<R>(
    cipher: SsCipher,
    subkey: &[u8],
    nonce: &mut [u8],
    request_salt: &[u8],
    decoder: &mut SimpleObfsTlsDecoder,
    reader: &mut R,
) -> anyhow::Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let fixed_header_length = 1 + 8 + request_salt.len() + 2;
    let encrypted_fixed_header = decoder
        .read_exact_or_eof(reader, fixed_header_length + SS_TAG_LEN)
        .await?
        .ok_or_else(|| anyhow!("missing shadowsocks 2022 response fixed header"))?;
    let fixed_header = cipher.decrypt(subkey, nonce, &encrypted_fixed_header)?;
    increment_nonce(nonce);
    if fixed_header.len() != fixed_header_length
        || fixed_header.first().copied() != Some(SS2022_SERVER_STREAM_TYPE)
    {
        return Err(anyhow!("invalid shadowsocks 2022 response fixed header"));
    }
    let timestamp = u64::from_be_bytes(fixed_header[1..9].try_into()?);
    validate_ss2022_timestamp(timestamp)?;
    let salt_end = 9 + request_salt.len();
    if &fixed_header[9..salt_end] != request_salt {
        return Err(anyhow!(
            "shadowsocks 2022 response does not match request salt"
        ));
    }
    let payload_length =
        u16::from_be_bytes(fixed_header[salt_end..salt_end + 2].try_into()?) as usize;
    let encrypted_payload = decoder
        .read_exact_or_eof(reader, payload_length + SS_TAG_LEN)
        .await?
        .ok_or_else(|| anyhow!("missing shadowsocks 2022 response payload"))?;
    let payload = cipher.decrypt(subkey, nonce, &encrypted_payload)?;
    increment_nonce(nonce);
    Ok(payload)
}

pub(super) async fn relay_shadowsocks_download<R, W>(
    cipher: SsCipher,
    subkey: Vec<u8>,
    mut nonce: Vec<u8>,
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

pub(super) fn encode_ss_chunk(
    cipher: SsCipher,
    subkey: &[u8],
    nonce: &mut [u8],
    plaintext: &[u8],
) -> anyhow::Result<Vec<u8>> {
    if plaintext.len() > cipher.max_chunk_size() {
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
pub(super) async fn write_ss_chunk<W>(
    cipher: SsCipher,
    subkey: &[u8],
    nonce: &mut [u8],
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

pub(super) async fn write_ss_plugin_chunk<W>(
    cipher: SsCipher,
    subkey: &[u8],
    nonce: &mut [u8],
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

pub(super) async fn read_ss_chunk<R>(
    cipher: SsCipher,
    subkey: &[u8],
    nonce: &mut [u8],
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
    if payload_len > cipher.max_chunk_size() {
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

pub(super) async fn read_ss_chunk_from_tls_obfs<R>(
    cipher: SsCipher,
    subkey: &[u8],
    nonce: &mut [u8],
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
    if payload_len > cipher.max_chunk_size() {
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

pub(super) fn apply_shadowsocks_plugin_request(
    plugin: &ShadowsocksPluginConfig,
    server: &str,
    port: u16,
    payload: Vec<u8>,
) -> anyhow::Result<Vec<u8>> {
    if plugin_is_tls_obfs(Some(plugin)) {
        let host = plugin.host.as_deref().unwrap_or(server);
        return build_simple_obfs_tls_client_hello(host, &payload);
    }
    if plugin_is_v2ray_ws(Some(plugin)) {
        let host = plugin.host.as_deref().unwrap_or(server);
        let ws_path = plugin.path.as_deref().unwrap_or("/");
        let host_header = if host.contains(':') || port == 80 || port == 443 {
            host.to_string()
        } else {
            format!("{host}:{port}")
        };
        let ws_key = "dGhlIHNhbXBsZSBub25jZQ==";
        let header = format!(
            "GET {ws_path} HTTP/1.1\r\n\
             Host: {host_header}\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: {ws_key}\r\n\
             Sec-WebSocket-Version: 13\r\n\
             \r\n"
        );
        let mut output = header.into_bytes();
        output.extend_from_slice(&payload);
        return Ok(output);
    }
    if !plugin_is_http_obfs(Some(plugin)) {
        return Err(anyhow!(
            "unsupported shadowsocks plugin mode {}",
            plugin.mode
        ));
    }
    let host = plugin.host.as_deref().unwrap_or(server);
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

pub(super) const SIMPLE_OBFS_TLS_FIXED_CLIENT_HELLO_LEN: usize = 138;
pub(super) const SIMPLE_OBFS_TLS_SESSION_TICKET_HEADER_LEN: usize = 4;
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

pub(super) fn wrap_simple_obfs_tls_app_data(payload: &[u8]) -> Vec<u8> {
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

pub(super) fn plugin_is_http_obfs(plugin: Option<&ShadowsocksPluginConfig>) -> bool {
    plugin.map_or(false, |p| {
        let mode = p.mode.to_ascii_lowercase();
        mode == "http_simple" || mode == "http_post"
    })
}

fn plugin_is_v2ray_ws(plugin: Option<&ShadowsocksPluginConfig>) -> bool {
    plugin.map_or(false, |p| {
        let mode = p.mode.to_ascii_lowercase();
        mode == "v2ray-plugin" || mode == "websocket"
    })
}

fn plugin_is_shadowtls(plugin: Option<&ShadowsocksPluginConfig>) -> bool {
    plugin.is_some_and(|plugin| {
        matches!(
            plugin.mode.to_ascii_lowercase().as_str(),
            "shadow-tls" | "shadowtls"
        )
    })
}

fn validate_shadowtls_plugin(plugin: &ShadowsocksPluginConfig) -> anyhow::Result<()> {
    if plugin.version.unwrap_or(3) != 3 {
        return Err(anyhow!("only shadow-tls plugin version 3 is supported"));
    }
    if plugin
        .host
        .as_deref()
        .is_none_or(|host| host.trim().is_empty())
    {
        return Err(anyhow!("shadow-tls plugin host is required"));
    }
    if plugin
        .password
        .as_deref()
        .is_none_or(|password| password.is_empty())
    {
        return Err(anyhow!("shadow-tls plugin password is required"));
    }
    Ok(())
}

async fn open_shadowtls_plugin_transport(
    stream: BoxedStream,
    plugin: &ShadowsocksPluginConfig,
    fallback_server: &str,
    timeout_ms: u64,
) -> anyhow::Result<BoxedStream> {
    validate_shadowtls_plugin(plugin)?;
    open_v3_transport(
        stream,
        plugin
            .password
            .as_deref()
            .expect("validated password")
            .as_bytes(),
        plugin.host.as_deref().unwrap_or(fallback_server),
        plugin.skip_cert_verify,
        timeout_ms,
    )
    .await
}

pub(super) fn plugin_is_tls_obfs(plugin: Option<&ShadowsocksPluginConfig>) -> bool {
    plugin
        .map(|plugin| {
            matches!(
                plugin.mode.to_ascii_lowercase().as_str(),
                "tls" | "obfs-tls" | "simple-obfs-tls"
            )
        })
        .unwrap_or(false)
}

pub(super) async fn read_http_obfs_response<R>(reader: &mut R) -> anyhow::Result<Vec<u8>>
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

pub(super) fn find_header_end(data: &[u8]) -> Option<usize> {
    data.windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SimpleObfsTlsReadStage {
    ServerHello,
    AppData,
}

pub(super) struct SimpleObfsTlsDecoder {
    stage: SimpleObfsTlsReadStage,
    plain: BytesMut,
}

impl SimpleObfsTlsDecoder {
    pub(super) fn new() -> Self {
        Self {
            stage: SimpleObfsTlsReadStage::ServerHello,
            plain: BytesMut::new(),
        }
    }

    pub(super) async fn read_exact_or_eof<R>(
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

    async fn read_some_or_eof<R>(
        &mut self,
        reader: &mut R,
        max_len: usize,
    ) -> anyhow::Result<Option<Vec<u8>>>
    where
        R: AsyncRead + Unpin,
    {
        if self.plain.is_empty() && !self.read_next_plain_record(reader).await? {
            return Ok(None);
        }
        let len = self.plain.len().min(max_len.max(1));
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

pub(super) async fn read_simple_obfs_tls_record<R>(
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
