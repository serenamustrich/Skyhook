use std::{
    io::Error,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    pin::Pin,
    sync::Arc,
    task::{Context as TaskContext, Poll},
    time::Duration,
};

use anyhow::{anyhow, Context};
use async_trait::async_trait;
use base64::{engine::general_purpose, Engine as _};
use rustls::client::{ClientSessionMemoryCache, ClientSessionStore};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    sync::Mutex,
};
use uuid::Uuid;

use crate::routing::Destination;

use super::{
    transports::{
        connect_quic_endpoint_resumable, create_quic_endpoint,
        quic_client_config_with_resumption_tuning_and_chain_pin, resolve_quic_remote,
        run_dial_phase, QuicTransportTuning, SharedConnectionPool,
    },
    udp::{udp_session_key, KeyedRoundRobinSessionPool},
    BoxedStream, Outbound, OutboundCapability, UdpNatMode,
};

const JUICITY_DEFAULT_KEEPALIVE: Duration = Duration::from_secs(5);
const JUICITY_MIN_KEEPALIVE: Duration = Duration::from_millis(500);
const JUICITY_MAX_KEEPALIVE: Duration = Duration::from_secs(600);
const JUICITY_MAX_UDP_PAYLOAD: usize = u16::MAX as usize;

pub(super) struct JuicityOutbound {
    name: String,
    server: String,
    port: u16,
    uuid: String,
    password: String,
    sni: Option<String>,
    skip_cert_verify: bool,
    congestion_control: Option<String>,
    keepalive_interval_ms: Option<u64>,
    pinned_certchain_sha256: Option<String>,
    tls_sessions: Arc<dyn ClientSessionStore>,
    quic_config: Mutex<Option<quinn::ClientConfig>>,
    connection: SharedConnectionPool<JuicityConnection>,
    udp_sessions: Mutex<JuicityUdpPool>,
}

type JuicityUdpPool = KeyedRoundRobinSessionPool<JuicityUdpSession>;

struct JuicityConnection {
    _endpoint: quinn::Endpoint,
    connection: quinn::Connection,
}

struct JuicityUdpSession {
    _shared: Arc<JuicityConnection>,
    recv: quinn::RecvStream,
    send: quinn::SendStream,
}

struct ValidatedJuicityConfig {
    user_id: Uuid,
    keepalive_interval: Duration,
    pinned_certchain_sha256: Option<[u8; 32]>,
}

#[async_trait]
impl Outbound for JuicityOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "juicity"
    }

    fn capability(&self) -> OutboundCapability {
        match self.validated_configuration() {
            Ok(_) => OutboundCapability::tcp_udp(
                "juicity-v0-quic-stream-tcp-udp-session-pool".to_string(),
            ),
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
        let connection = self.juicity_connection(&config, timeout_ms).await?;
        let (mut send, recv) = run_dial_phase(timeout_ms, "juicity open TCP stream", async {
            connection.connection.open_bi().await
        })
        .await?
        .context("juicity failed to open TCP stream")?;
        let request = build_juicity_proxy_header(1, destination)?;
        run_dial_phase(timeout_ms, "juicity TCP request write", async {
            send.write_all(&request).await?;
            send.flush().await
        })
        .await??;
        Ok(Box::new(JuicityStream {
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
        if payload.len() > JUICITY_MAX_UDP_PAYLOAD {
            return Err(anyhow!("juicity UDP payload exceeds 65535 bytes"));
        }
        let config = self.validated_configuration()?;
        let key = udp_session_key(
            self.kind(),
            self.name(),
            self.udp_nat_mode(),
            Some(destination),
        );
        let session_handle = self
            .juicity_udp_session(&key, destination, &config, timeout_ms)
            .await?;
        let mut session = session_handle.lock().await;
        let packet = build_juicity_udp_packet(destination, payload)?;
        let exchange = run_dial_phase(timeout_ms, "juicity UDP stream exchange", async {
            session.send.write_all(&packet).await?;
            session.send.flush().await?;
            read_juicity_udp_packet(&mut session.recv)
                .await
                .map(|(_, payload)| payload)
        })
        .await;
        if !matches!(&exchange, Ok(Ok(_))) {
            drop(session);
            self.udp_sessions.lock().await.remove(&key, &session_handle);
        }
        exchange?
    }
}

impl JuicityOutbound {
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
        keepalive_interval_ms: Option<u64>,
        pinned_certchain_sha256: Option<String>,
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
            keepalive_interval_ms,
            pinned_certchain_sha256,
            tls_sessions: Arc::new(ClientSessionMemoryCache::new(64)),
            quic_config: Mutex::new(None),
            connection: SharedConnectionPool::default(),
            udp_sessions: Mutex::new(JuicityUdpPool::default()),
        }
    }

    fn validated_configuration(&self) -> anyhow::Result<ValidatedJuicityConfig> {
        if self.server.trim().is_empty() || self.port == 0 {
            return Err(anyhow!("juicity server and port must be configured"));
        }
        if self.password.is_empty() {
            return Err(anyhow!("juicity password must not be empty"));
        }
        let user_id = Uuid::parse_str(self.uuid.trim())
            .map_err(|error| anyhow!("invalid juicity uuid for {}: {error}", self.name))?;
        validate_juicity_congestion_control(self.congestion_control.as_deref())?;
        let keepalive_interval = self
            .keepalive_interval_ms
            .map(Duration::from_millis)
            .unwrap_or(JUICITY_DEFAULT_KEEPALIVE);
        if !(JUICITY_MIN_KEEPALIVE..=JUICITY_MAX_KEEPALIVE).contains(&keepalive_interval) {
            return Err(anyhow!(
                "juicity keepalive interval must be between 500ms and 600000ms"
            ));
        }
        let pinned_certchain_sha256 = self
            .pinned_certchain_sha256
            .as_deref()
            .map(parse_juicity_certificate_chain_pin)
            .transpose()?;
        Ok(ValidatedJuicityConfig {
            user_id,
            keepalive_interval,
            pinned_certchain_sha256,
        })
    }

    async fn quic_client_config(
        &self,
        config: &ValidatedJuicityConfig,
    ) -> anyhow::Result<quinn::ClientConfig> {
        let mut cached = self.quic_config.lock().await;
        if let Some(config) = cached.as_ref() {
            return Ok(config.clone());
        }
        let quic_config = quic_client_config_with_resumption_tuning_and_chain_pin(
            self.skip_cert_verify,
            Some("h3"),
            self.congestion_control.as_deref().or(Some("bbr")),
            Some(Arc::clone(&self.tls_sessions)),
            false,
            QuicTransportTuning {
                stream_receive_window: Some(32 * 1024 * 1024),
                receive_window: Some(64 * 1024 * 1024),
                max_idle_timeout: Some(config.keepalive_interval.saturating_mul(6)),
                keep_alive_interval: Some(config.keepalive_interval),
                ..QuicTransportTuning::default()
            },
            config.pinned_certchain_sha256,
        )?;
        *cached = Some(quic_config.clone());
        Ok(quic_config)
    }

    async fn juicity_connection(
        &self,
        config: &ValidatedJuicityConfig,
        timeout_ms: u64,
    ) -> anyhow::Result<Arc<JuicityConnection>> {
        let client_config = self.quic_client_config(config).await?;
        self.connection
            .get_or_connect(
                |connection| connection.connection.close_reason().is_none(),
                || {
                    open_juicity_connection(
                        &self.server,
                        self.port,
                        self.sni.as_deref(),
                        &config.user_id,
                        &self.password,
                        client_config,
                        timeout_ms,
                    )
                },
            )
            .await
    }

    async fn juicity_udp_session(
        &self,
        key: &str,
        destination: &Destination,
        config: &ValidatedJuicityConfig,
        timeout_ms: u64,
    ) -> anyhow::Result<Arc<Mutex<JuicityUdpSession>>> {
        let mut pool = self.udp_sessions.lock().await;
        if let Some(session) = pool.next(key) {
            return Ok(session);
        }
        drop(pool);

        let connection = self.juicity_connection(config, timeout_ms).await?;
        let (mut send, recv) = run_dial_phase(timeout_ms, "juicity open UDP stream", async {
            connection.connection.open_bi().await
        })
        .await?
        .context("juicity failed to open UDP stream")?;
        let request = build_juicity_proxy_header(3, destination)?;
        run_dial_phase(timeout_ms, "juicity UDP session header", async {
            send.write_all(&request).await?;
            send.flush().await
        })
        .await??;
        let session = Arc::new(Mutex::new(JuicityUdpSession {
            _shared: connection,
            recv,
            send,
        }));
        let mut pool = self.udp_sessions.lock().await;
        pool.push(key.to_string(), Arc::clone(&session));
        Ok(session)
    }
}

impl Drop for JuicityConnection {
    fn drop(&mut self) {
        self.connection
            .close(quinn::VarInt::from_u32(0), b"skyhook juicity close");
    }
}

struct JuicityStream {
    _shared: Arc<JuicityConnection>,
    recv: quinn::RecvStream,
    send: quinn::SendStream,
}

impl AsyncRead for JuicityStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), Error>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for JuicityStream {
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
async fn open_juicity_connection(
    server: &str,
    port: u16,
    sni: Option<&str>,
    user_id: &Uuid,
    password: &str,
    client_config: quinn::ClientConfig,
    timeout_ms: u64,
) -> anyhow::Result<JuicityConnection> {
    let remote = resolve_quic_remote("juicity", server, port).await?;
    let endpoint = create_quic_endpoint(remote)?;
    let server_name = sni.unwrap_or(server);
    let resumable = connect_quic_endpoint_resumable(
        endpoint,
        remote,
        server_name,
        client_config,
        false,
        timeout_ms,
        "juicity",
    )
    .await?;
    send_juicity_auth(&resumable.connection, user_id, password, timeout_ms).await?;
    Ok(JuicityConnection {
        _endpoint: resumable.endpoint,
        connection: resumable.connection,
    })
}

async fn send_juicity_auth(
    connection: &quinn::Connection,
    user_id: &Uuid,
    password: &str,
    timeout_ms: u64,
) -> anyhow::Result<()> {
    let mut token = [0u8; 32];
    connection
        .export_keying_material(&mut token, user_id.as_bytes(), password.as_bytes())
        .map_err(|_| anyhow!("juicity TLS exporter token failed"))?;
    let mut auth = Vec::with_capacity(50);
    auth.extend_from_slice(&[0, 0]);
    auth.extend_from_slice(user_id.as_bytes());
    auth.extend_from_slice(&token);
    let mut stream = run_dial_phase(timeout_ms, "juicity auth stream open", async {
        connection.open_uni().await
    })
    .await?
    .context("juicity failed to open auth stream")?;
    run_dial_phase(timeout_ms, "juicity auth write", async {
        stream.write_all(&auth).await?;
        stream
            .finish()
            .map_err(|error| anyhow!("juicity auth finish failed: {error}"))
    })
    .await??;
    Ok(())
}

fn validate_juicity_congestion_control(value: Option<&str>) -> anyhow::Result<()> {
    match value.unwrap_or("bbr").trim().to_ascii_lowercase().as_str() {
        "" | "bbr" | "cubic" | "new-reno" | "new_reno" | "newreno" => Ok(()),
        value => Err(anyhow!("unsupported juicity congestion controller {value}")),
    }
}

fn parse_juicity_certificate_chain_pin(value: &str) -> anyhow::Result<[u8; 32]> {
    let value = value.trim();
    let normalized_hex = value
        .chars()
        .filter(|character| !matches!(character, ':' | '-' | ' '))
        .collect::<String>();
    if normalized_hex.len() == 64 && normalized_hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        let mut pin = [0u8; 32];
        for (index, byte) in pin.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&normalized_hex[index * 2..index * 2 + 2], 16)
                .map_err(|error| anyhow!("invalid juicity certificate chain pin: {error}"))?;
        }
        return Ok(pin);
    }

    for engine in [
        &general_purpose::URL_SAFE_NO_PAD,
        &general_purpose::URL_SAFE,
        &general_purpose::STANDARD_NO_PAD,
        &general_purpose::STANDARD,
    ] {
        if let Ok(decoded) = engine.decode(value) {
            if let Ok(pin) = <[u8; 32]>::try_from(decoded) {
                return Ok(pin);
            }
        }
    }
    Err(anyhow!(
        "juicity pinned-certchain-sha256 must be a 32-byte base64 or SHA-256 hex value"
    ))
}

fn build_juicity_proxy_header(network: u8, destination: &Destination) -> anyhow::Result<Vec<u8>> {
    if !matches!(network, 1 | 3) {
        return Err(anyhow!("invalid juicity network {network}"));
    }
    let mut output = Vec::with_capacity(24 + destination.host.len());
    output.push(network);
    encode_juicity_address(destination, &mut output)?;
    Ok(output)
}

fn build_juicity_udp_packet(destination: &Destination, payload: &[u8]) -> anyhow::Result<Vec<u8>> {
    if payload.len() > JUICITY_MAX_UDP_PAYLOAD {
        return Err(anyhow!("juicity UDP payload exceeds 65535 bytes"));
    }
    let mut output = Vec::with_capacity(24 + destination.host.len() + payload.len());
    encode_juicity_address(destination, &mut output)?;
    output.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    output.extend_from_slice(payload);
    Ok(output)
}

fn encode_juicity_address(destination: &Destination, output: &mut Vec<u8>) -> anyhow::Result<()> {
    match destination.host.parse::<IpAddr>() {
        Ok(IpAddr::V4(address)) => {
            output.push(1);
            output.extend_from_slice(&address.octets());
        }
        Ok(IpAddr::V6(address)) => {
            output.push(4);
            output.extend_from_slice(&address.octets());
        }
        Err(_) => {
            let host = destination.host.as_bytes();
            if host.is_empty() || host.len() > u8::MAX as usize {
                return Err(anyhow!("juicity domain length must be between 1 and 255"));
            }
            output.push(3);
            output.push(host.len() as u8);
            output.extend_from_slice(host);
        }
    }
    output.extend_from_slice(&destination.port.to_be_bytes());
    Ok(())
}

async fn read_juicity_address<R>(reader: &mut R) -> anyhow::Result<Destination>
where
    R: AsyncRead + Unpin,
{
    let address_type = reader.read_u8().await?;
    let host = match address_type {
        1 => {
            let mut address = [0u8; 4];
            reader.read_exact(&mut address).await?;
            Ipv4Addr::from(address).to_string()
        }
        4 => {
            let mut address = [0u8; 16];
            reader.read_exact(&mut address).await?;
            Ipv6Addr::from(address).to_string()
        }
        3 => {
            let length = reader.read_u8().await? as usize;
            if length == 0 {
                return Err(anyhow!("juicity domain is empty"));
            }
            let mut host = vec![0u8; length];
            reader.read_exact(&mut host).await?;
            String::from_utf8(host).context("juicity domain is not UTF-8")?
        }
        value => return Err(anyhow!("unsupported juicity address type {value}")),
    };
    let port = reader.read_u16().await?;
    Ok(Destination::new(host, port))
}

async fn read_juicity_udp_packet<R>(reader: &mut R) -> anyhow::Result<(Destination, Vec<u8>)>
where
    R: AsyncRead + Unpin,
{
    let destination = read_juicity_address(reader).await?;
    let length = reader.read_u16().await? as usize;
    let mut payload = vec![0u8; length];
    reader.read_exact(&mut payload).await?;
    Ok((destination, payload))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use rustls::{crypto::aws_lc_rs, pki_types::PrivatePkcs8KeyDer, ServerConfig};
    use rustls_pki_types::CertificateDer;
    use sha2::{Digest, Sha256};

    #[test]
    fn official_proxy_and_udp_headers_cover_all_address_types() {
        assert_eq!(
            build_juicity_proxy_header(1, &Destination::new("1.2.3.4", 443)).unwrap(),
            vec![1, 1, 1, 2, 3, 4, 1, 187]
        );
        let ipv6 = build_juicity_proxy_header(1, &Destination::new("::1", 443)).unwrap();
        assert_eq!(&ipv6[..2], &[1, 4]);
        let domain =
            build_juicity_udp_packet(&Destination::new("dns.example", 53), b"query").unwrap();
        assert_eq!(&domain[..2], &[3, 11]);
        assert!(domain.ends_with(b"\0\x05query"));
    }

    #[test]
    fn configuration_rejects_invalid_identity_congestion_and_keepalive() {
        let outbound = JuicityOutbound::new(
            "invalid".to_string(),
            "example.com".to_string(),
            443,
            "not-a-uuid".to_string(),
            "password".to_string(),
            None,
            false,
            Some("invalid".to_string()),
            Some(10),
            None,
        );
        assert!(outbound.validated_configuration().is_err());
        assert!(!outbound.capability().tcp_supported);
    }

    #[tokio::test]
    async fn local_quic_server_verifies_auth_tcp_and_udp_streams() {
        const PASSWORD: &str = "juicity-local-password";
        let user_id = Uuid::parse_str("11111111-2222-3333-4444-555555555555").unwrap();
        let (server_endpoint, server_address, certificate_pin) = local_quic_server();
        let server = tokio::spawn(async move {
            let connection = server_endpoint.accept().await.unwrap().await.unwrap();
            let mut auth_stream = connection.accept_uni().await.unwrap();
            let auth = auth_stream.read_to_end(64).await.unwrap();
            assert_eq!(&auth[..18], &[&[0, 0][..], user_id.as_bytes()].concat());
            let mut expected_token = [0u8; 32];
            connection
                .export_keying_material(
                    &mut expected_token,
                    user_id.as_bytes(),
                    PASSWORD.as_bytes(),
                )
                .unwrap();
            assert_eq!(&auth[18..], &expected_token);

            let (mut tcp_send, mut tcp_recv) = connection.accept_bi().await.unwrap();
            assert_eq!(tcp_recv.read_u8().await.unwrap(), 1);
            assert_eq!(
                read_juicity_address(&mut tcp_recv).await.unwrap(),
                Destination::new("target.example", 443)
            );
            let mut tcp_payload = [0u8; 4];
            tcp_recv.read_exact(&mut tcp_payload).await.unwrap();
            assert_eq!(&tcp_payload, b"ping");
            tcp_send.write_all(b"pong").await.unwrap();
            tcp_send.flush().await.unwrap();

            let (mut udp_send, mut udp_recv) = connection.accept_bi().await.unwrap();
            assert_eq!(udp_recv.read_u8().await.unwrap(), 3);
            assert_eq!(
                read_juicity_address(&mut udp_recv).await.unwrap(),
                Destination::new("dns.example", 53)
            );
            let (destination, payload) = read_juicity_udp_packet(&mut udp_recv).await.unwrap();
            assert_eq!(destination, Destination::new("dns.example", 53));
            assert_eq!(payload, b"question");
            let response = build_juicity_udp_packet(&destination, b"answer").unwrap();
            udp_send.write_all(&response).await.unwrap();
            udp_send.flush().await.unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;
        });

        let outbound = JuicityOutbound::new(
            "juicity-local".to_string(),
            server_address.ip().to_string(),
            server_address.port(),
            user_id.to_string(),
            PASSWORD.to_string(),
            Some("localhost".to_string()),
            false,
            Some("bbr".to_string()),
            Some(500),
            Some(general_purpose::URL_SAFE_NO_PAD.encode(certificate_pin)),
        );
        let mut stream = outbound
            .connect(&Destination::new("target.example", 443), 3_000)
            .await
            .unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut response = [0u8; 4];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"pong");
        let response = outbound
            .udp_exchange(&Destination::new("dns.example", 53), b"question", 3_000)
            .await
            .unwrap();
        assert_eq!(response, b"answer");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn wrong_password_is_rejected_by_authenticated_server() {
        const PASSWORD: &str = "juicity-correct-password";
        let user_id = Uuid::parse_str("11111111-2222-3333-4444-555555555555").unwrap();
        let (server_endpoint, server_address, certificate_pin) = local_quic_server();
        let server = tokio::spawn(async move {
            let connection = server_endpoint.accept().await.unwrap().await.unwrap();
            let mut auth_stream = connection.accept_uni().await.unwrap();
            let auth = auth_stream.read_to_end(64).await.unwrap();
            let mut expected_token = [0u8; 32];
            connection
                .export_keying_material(
                    &mut expected_token,
                    user_id.as_bytes(),
                    PASSWORD.as_bytes(),
                )
                .unwrap();
            assert_ne!(&auth[18..], &expected_token);
            connection.close(quinn::VarInt::from_u32(1), b"authentication rejected");
        });

        let outbound = JuicityOutbound::new(
            "juicity-wrong-auth".to_string(),
            server_address.ip().to_string(),
            server_address.port(),
            user_id.to_string(),
            "wrong-password".to_string(),
            Some("localhost".to_string()),
            false,
            Some("bbr".to_string()),
            Some(500),
            Some(general_purpose::URL_SAFE_NO_PAD.encode(certificate_pin)),
        );
        let rejected = tokio::time::timeout(Duration::from_secs(2), async {
            match outbound
                .connect(&Destination::new("target.example", 443), 2_000)
                .await
            {
                Err(_) => true,
                Ok(mut stream) => {
                    if stream.write_all(b"must-not-pass").await.is_err() {
                        return true;
                    }
                    let mut response = [0u8; 1];
                    stream.read_exact(&mut response).await.is_err()
                }
            }
        })
        .await
        .unwrap_or(false);
        assert!(rejected, "wrong juicity password was not rejected");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn closed_quic_session_is_replaced_on_the_next_dial() {
        const PASSWORD: &str = "juicity-recovery-password";
        let user_id = Uuid::parse_str("11111111-2222-3333-4444-555555555555").unwrap();
        let (server_endpoint, server_address, certificate_pin) = local_quic_server();
        let server = tokio::spawn(async move {
            for attempt in 0..2u8 {
                let connection = server_endpoint.accept().await.unwrap().await.unwrap();
                let mut auth_stream = connection.accept_uni().await.unwrap();
                let auth = auth_stream.read_to_end(64).await.unwrap();
                let mut expected_token = [0u8; 32];
                connection
                    .export_keying_material(
                        &mut expected_token,
                        user_id.as_bytes(),
                        PASSWORD.as_bytes(),
                    )
                    .unwrap();
                assert_eq!(&auth[18..], &expected_token);
                let (mut send, mut recv) = connection.accept_bi().await.unwrap();
                assert_eq!(recv.read_u8().await.unwrap(), 1);
                read_juicity_address(&mut recv).await.unwrap();
                let mut payload = [0u8; 4];
                recv.read_exact(&mut payload).await.unwrap();
                assert_eq!(&payload, b"ping");
                send.write_all(&[b'0' + attempt]).await.unwrap();
                send.finish().unwrap();
                tokio::time::sleep(Duration::from_millis(30)).await;
                connection.close(quinn::VarInt::from_u32(2), b"rotate session");
            }
        });

        let outbound = JuicityOutbound::new(
            "juicity-recovery".to_string(),
            server_address.ip().to_string(),
            server_address.port(),
            user_id.to_string(),
            PASSWORD.to_string(),
            Some("localhost".to_string()),
            false,
            Some("bbr".to_string()),
            Some(500),
            Some(general_purpose::URL_SAFE_NO_PAD.encode(certificate_pin)),
        );
        for expected in [b'0', b'1'] {
            let mut stream = outbound
                .connect(&Destination::new("target.example", 443), 3_000)
                .await
                .unwrap();
            stream.write_all(b"ping").await.unwrap();
            assert_eq!(stream.read_u8().await.unwrap(), expected);
            drop(stream);
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        server.await.unwrap();
    }

    fn local_quic_server() -> (quinn::Endpoint, SocketAddr, [u8; 32]) {
        let certificate =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let certificate_der = CertificateDer::from(certificate.cert.der().to_vec());
        let certificate_pin = Sha256::digest(certificate_der.as_ref()).into();
        let private_key = PrivatePkcs8KeyDer::from(certificate.key_pair.serialize_der());
        let provider = aws_lc_rs::default_provider();
        let mut server_crypto = ServerConfig::builder_with_provider(provider.into())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![certificate_der], private_key.into())
            .unwrap();
        server_crypto.alpn_protocols = vec![b"h3".to_vec()];
        let server_config = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto).unwrap(),
        ));
        let endpoint = quinn::Endpoint::server(
            server_config,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        )
        .unwrap();
        let address = endpoint.local_addr().unwrap();
        (endpoint, address, certificate_pin)
    }
}
