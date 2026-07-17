use std::{collections::BTreeMap, sync::Arc, time::Duration};

use anyhow::{anyhow, Context};
use async_trait::async_trait;
use rustls_pki_types::ServerName;
use sha2::{Digest, Sha224};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    sync::Mutex as TokioMutex,
    time::timeout,
};
use tokio_rustls::TlsConnector;

use crate::routing::Destination;

use super::{
    target::{encode_socks5_destination, read_socks5_destination_after_atyp},
    transports::{
        connect_tcp, open_grpc_tunnel, open_h2_tunnel, open_http_upgrade_tunnel,
        open_websocket_transport, run_dial_phase, tls_client_config,
    },
    udp::{udp_session_key, KeyedRoundRobinSessionPool, UDP_SESSION_POOL_SIZE},
    util::hex_lower,
    BoxedStream, Outbound, OutboundCapability, UdpNatMode,
};

pub(super) struct TrojanOutbound {
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

type TrojanUdpPool = KeyedRoundRobinSessionPool<TrojanUdpSession>;

struct TrojanUdpSession {
    stream: BoxedStream,
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

    fn udp_nat_mode(&self) -> UdpNatMode {
        UdpNatMode::EndpointIndependent
    }

    fn supports_udp_dialer_proxy(&self) -> bool {
        true
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
        let key = udp_session_key(
            self.kind(),
            self.name(),
            self.udp_nat_mode(),
            Some(destination),
        );
        let session_handle = self.trojan_udp_session(&key, timeout_ms).await?;
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
            self.remove_trojan_udp_session(&key, &session_handle).await;
        }
        exchange
    }
}

impl TrojanOutbound {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
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
    ) -> Self {
        Self {
            name,
            server,
            port,
            password,
            sni,
            skip_cert_verify,
            network,
            ws_path,
            ws_host,
            grpc_service_name,
            transport_headers,
            alpn,
            udp_sessions: TokioMutex::new(TrojanUdpPool::default()),
        }
    }

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
        let stream = run_dial_phase(
            timeout_ms,
            "trojan tls handshake",
            connector.connect(tls_server_name, tcp),
        )
        .await?
        .context("trojan tls handshake failed")?;

        match network.as_str() {
            "tcp" => Ok(Box::new(stream)),
            "ws" | "websocket" => {
                open_websocket_transport(
                    stream,
                    self.ws_host.as_deref().unwrap_or(&server_name),
                    self.ws_path.as_deref().unwrap_or("/"),
                    &self.transport_headers,
                    timeout_ms,
                )
                .await
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
                timeout_ms,
            )
            .await
            .map(|stream| Box::new(stream) as BoxedStream),
            _ => unreachable!("trojan network was validated"),
        }
    }

    async fn trojan_udp_session(
        &self,
        key: &str,
        timeout_ms: u64,
    ) -> anyhow::Result<Arc<TokioMutex<TrojanUdpSession>>> {
        let mut pool = self.udp_sessions.lock().await;
        if pool.len(key) < UDP_SESSION_POOL_SIZE {
            let session = Arc::new(TokioMutex::new(
                self.open_trojan_udp_session(timeout_ms).await?,
            ));
            pool.push(key.to_string(), session.clone());
            return Ok(session);
        }
        pool.next(key)
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

    async fn remove_trojan_udp_session(
        &self,
        key: &str,
        target: &Arc<TokioMutex<TrojanUdpSession>>,
    ) {
        let mut pool = self.udp_sessions.lock().await;
        pool.remove(key, target);
    }
}

pub(super) fn trojan_alpn_protocols(
    network: &str,
    configured: &[String],
) -> anyhow::Result<Vec<Vec<u8>>> {
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

const TROJAN_CMD_CONNECT: u8 = 0x01;
const TROJAN_CMD_UDP_ASSOCIATE: u8 = 0x03;

pub(super) fn build_trojan_request(
    password: &str,
    destination: &Destination,
) -> anyhow::Result<Vec<u8>> {
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
