use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::{anyhow, Context};
use async_trait::async_trait;
use rustls_pki_types::ServerName;
use tokio::{io::AsyncWriteExt, net::UdpSocket, sync::Mutex, time::timeout};
use tokio_rustls::TlsConnector;

use crate::{config::ShadowsocksPluginConfig, routing::Destination};

use super::{
    apply_shadowsocks_plugin_request, build_ss2022_request_header,
    build_ss2022_tcp_identity_headers, connect_tcp, decode_shadowsocks_udp_packet,
    encode_shadowsocks_udp_packet, encode_socks5_destination, encode_ss_chunk,
    perform_websocket_handshake, plugin_is_v2ray_ws, resolve_udp_socket_addr,
    spawn_shadowsocks_stream, spawn_websocket_stream, tls_client_config, BoxedStream, Outbound,
    OutboundCapability, ShadowsocksUdpPool, ShadowsocksUdpSession, Ss2022UdpState, SsCipher,
    UDP_SESSION_POOL_SIZE,
};

pub(super) struct ShadowsocksOutbound {
    name: String,
    server: String,
    port: u16,
    method: String,
    password: String,
    plugin: Option<ShadowsocksPluginConfig>,
    udp_sessions: Mutex<ShadowsocksUdpPool>,
}

impl ShadowsocksOutbound {
    pub(super) fn new(
        name: String,
        server: String,
        port: u16,
        method: String,
        password: String,
        plugin: Option<ShadowsocksPluginConfig>,
    ) -> Self {
        Self {
            name,
            server,
            port,
            method,
            password,
            plugin,
            udp_sessions: Mutex::new(ShadowsocksUdpPool::default()),
        }
    }

    async fn shadowsocks_udp_session(
        &self,
        timeout_ms: u64,
    ) -> anyhow::Result<Arc<Mutex<ShadowsocksUdpSession>>> {
        let mut pool = self.udp_sessions.lock().await;
        if pool.len() < UDP_SESSION_POOL_SIZE {
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
            let cipher = SsCipher::from_method(&self.method)?;
            let ss2022 = cipher.is_blake3().then(Ss2022UdpState::new).transpose()?;
            let session = Arc::new(Mutex::new(ShadowsocksUdpSession {
                udp,
                server,
                ss2022,
            }));
            pool.push(session.clone());
            return Ok(session);
        }
        pool.next()
            .ok_or_else(|| anyhow!("shadowsocks UDP session pool is unexpectedly empty"))
    }

    async fn remove_shadowsocks_udp_session(&self, target: &Arc<Mutex<ShadowsocksUdpSession>>) {
        self.udp_sessions.lock().await.remove(target);
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
        if let Err(error) = SsCipher::from_method(&self.method) {
            return OutboundCapability::unsupported(error.to_string());
        }
        if self.plugin.is_some() {
            OutboundCapability::tcp_only("Shadowsocks plugin transports do not provide UDP relay")
        } else {
            OutboundCapability::tcp_udp("shadowsocks-aead-udp-session-pool")
        }
    }

    async fn connect(
        &self,
        destination: &Destination,
        timeout_ms: u64,
    ) -> anyhow::Result<BoxedStream> {
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
            let tls = timeout(
                Duration::from_millis(timeout_ms),
                connector.connect(tls_server_name, tcp),
            )
            .await
            .context("shadowsocks plugin tls handshake timed out")?
            .context("shadowsocks plugin tls handshake failed")?;
            Box::new(tls)
        } else {
            Box::new(tcp)
        };

        if let Some(plugin) = &self.plugin {
            if plugin_is_v2ray_ws(Some(plugin)) {
                perform_websocket_handshake(
                    &mut transport,
                    plugin.host.as_deref().unwrap_or(&self.server),
                    plugin.path.as_deref().unwrap_or("/"),
                )
                .await?;
                transport = Box::new(spawn_websocket_stream(transport));
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
        if self.plugin.is_some() {
            return Err(anyhow!(
                "shadowsocks udp with simple-obfs plugin is not supported"
            ));
        }

        let cipher = SsCipher::from_method(&self.method)?;
        let session_handle = self.shadowsocks_udp_session(timeout_ms).await?;
        let mut session = session_handle.lock().await;
        let packet = encode_shadowsocks_udp_packet(
            cipher,
            self.password.as_bytes(),
            destination,
            payload,
            session.ss2022.as_mut(),
        )?;
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
            let (_response_destination, response) = decode_shadowsocks_udp_packet(
                cipher,
                self.password.as_bytes(),
                &buf[..len],
                session.ss2022.as_mut(),
            )?;
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
