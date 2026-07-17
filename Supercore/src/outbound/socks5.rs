use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::{anyhow, Context};
use async_trait::async_trait;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UdpSocket,
    sync::Mutex,
    time::timeout,
};

use crate::routing::Destination;

use super::{
    target::{encode_socks5_destination, parse_socks5_destination_prefix},
    transports::connect_tcp,
    udp::{
        create_bound_udp, resolve_udp_socket_addr, RoundRobinSessionPool, UDP_SESSION_POOL_SIZE,
    },
    BoxedStream, Outbound, OutboundCapability,
};

pub(super) struct Socks5Outbound {
    name: String,
    server: String,
    port: u16,
    username: Option<String>,
    password: Option<String>,
    udp_sessions: Mutex<Socks5UdpPool>,
}

type Socks5UdpPool = RoundRobinSessionPool<Socks5UdpSession>;

struct Socks5UdpSession {
    _control: Arc<Mutex<BoxedStream>>,
    udp: UdpSocket,
    relay: SocketAddr,
}

impl Socks5Outbound {
    pub(super) fn new(
        name: String,
        server: String,
        port: u16,
        username: Option<String>,
        password: Option<String>,
    ) -> Self {
        Self {
            name,
            server,
            port,
            username,
            password,
            udp_sessions: Mutex::new(Socks5UdpPool::default()),
        }
    }

    async fn socks5_udp_session(
        &self,
        timeout_ms: u64,
    ) -> anyhow::Result<Arc<Mutex<Socks5UdpSession>>> {
        let mut pool = self.udp_sessions.lock().await;
        if pool.len() < UDP_SESSION_POOL_SIZE {
            let session = Arc::new(Mutex::new(self.open_socks5_udp_session(timeout_ms).await?));
            pool.push(session.clone());
            return Ok(session);
        }
        pool.next()
            .ok_or_else(|| anyhow!("socks5 UDP session pool is unexpectedly empty"))
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
        validate_socks5_response_header(header, "udp associate")?;
        let bound = read_socks5_bound_address(&mut stream, header[3]).await?;
        let relay_host = if bound.host == "0.0.0.0" || bound.host == "::" {
            self.server.as_str()
        } else {
            bound.host.as_str()
        };
        let relay = resolve_udp_socket_addr(relay_host, bound.port, timeout_ms).await?;
        let udp = create_bound_udp(relay)?;
        Ok(Socks5UdpSession {
            _control: Arc::new(Mutex::new(stream)),
            udp,
            relay,
        })
    }

    async fn remove_socks5_udp_session(&self, target: &Arc<Mutex<Socks5UdpSession>>) {
        self.udp_sessions.lock().await.remove(target);
    }
}

#[async_trait]
impl Outbound for Socks5Outbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "socks5"
    }

    fn capability(&self) -> OutboundCapability {
        OutboundCapability::tcp_udp("socks5-udp-associate-session-pool")
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
        validate_socks5_response_header(header, "connect")?;
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

fn validate_socks5_response_header(header: [u8; 4], operation: &str) -> anyhow::Result<()> {
    if header[0] != 0x05 {
        return Err(anyhow!("invalid socks5 {operation} response version"));
    }
    if header[2] != 0x00 {
        return Err(anyhow!("invalid socks5 {operation} reserved byte"));
    }
    if header[1] != 0x00 {
        return Err(anyhow!("socks5 {operation} failed code {}", header[1]));
    }
    Ok(())
}

async fn authenticate_socks5<S>(
    stream: &mut S,
    username: Option<&str>,
    password: Option<&str>,
) -> anyhow::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let username = username.ok_or_else(|| anyhow!("socks5 proxy requested username"))?;
    let password = password.ok_or_else(|| anyhow!("socks5 proxy requested password"))?;
    if username.len() > u8::MAX as usize || password.len() > u8::MAX as usize {
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

async fn negotiate_socks5<S>(
    stream: &mut S,
    username: Option<&str>,
    password: Option<&str>,
) -> anyhow::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
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

async fn discard_socks5_bound_address<S>(stream: &mut S, atyp: u8) -> anyhow::Result<()>
where
    S: tokio::io::AsyncRead + Unpin,
{
    read_socks5_bound_address(stream, atyp).await.map(|_| ())
}

async fn read_socks5_bound_address<S>(stream: &mut S, atyp: u8) -> anyhow::Result<Destination>
where
    S: tokio::io::AsyncRead + Unpin,
{
    super::target::read_socks5_destination_after_atyp(stream, atyp)
        .await
        .context("invalid socks5 bound address")
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_response_header_before_using_address_type() {
        assert!(validate_socks5_response_header([0x04, 0, 0, 1], "connect").is_err());
        assert!(validate_socks5_response_header([0x05, 0, 1, 1], "connect").is_err());
        assert!(validate_socks5_response_header([0x05, 5, 0, 1], "connect").is_err());
        assert!(validate_socks5_response_header([0x05, 0, 0, 1], "connect").is_ok());
    }

    #[test]
    fn udp_response_rejects_fragmentation_and_preserves_payload_offset() {
        let destination = Destination::new("example.com", 53);
        let mut packet = vec![0, 0, 0];
        encode_socks5_destination(&destination, &mut packet).unwrap();
        let payload_offset = packet.len();
        packet.extend_from_slice(b"dns");
        let (decoded, actual_offset) = parse_socks5_udp_response(&packet).unwrap();
        assert_eq!(decoded, destination);
        assert_eq!(actual_offset, payload_offset);
        packet[2] = 1;
        assert!(parse_socks5_udp_response(&packet).is_err());
    }
}
