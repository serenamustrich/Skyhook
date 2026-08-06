use std::{io, net::SocketAddr, time::Duration};

use anyhow::{anyhow, Context};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UdpSocket,
    time::timeout,
};

use super::config::{OpenVpnRemote, OpenVpnTransport};
use crate::outbound::{transports::connect_tcp, BoxedStream};

const MAX_OPENVPN_PACKET: usize = u16::MAX as usize;

pub(super) enum OpenVpnLink {
    Tcp(BoxedStream),
    Udp(UdpSocket),
}

impl OpenVpnLink {
    pub(super) async fn connect(remote: &OpenVpnRemote, timeout_ms: u64) -> anyhow::Result<Self> {
        match remote.transport {
            OpenVpnTransport::Tcp => {
                let stream = connect_tcp(&format!("{}:{}", remote.host, remote.port), timeout_ms)
                    .await
                    .with_context(|| format!("OpenVPN TCP connect to {}:{} failed", remote.host, remote.port))?;
                Ok(Self::Tcp(stream))
            }
            OpenVpnTransport::Udp => connect_udp(remote, timeout_ms).await.map(Self::Udp),
        }
    }

    pub(super) async fn send(&mut self, packet: &[u8]) -> anyhow::Result<()> {
        if packet.is_empty() || packet.len() > MAX_OPENVPN_PACKET {
            return Err(anyhow!("invalid OpenVPN packet length {}", packet.len()));
        }
        match self {
            Self::Tcp(stream) => {
                stream.write_all(&(packet.len() as u16).to_be_bytes()).await?;
                stream.write_all(packet).await?;
                stream.flush().await?;
            }
            Self::Udp(socket) => {
                let sent = socket.send(packet).await?;
                if sent != packet.len() {
                    return Err(anyhow!("OpenVPN UDP datagram was only partially sent"));
                }
            }
        }
        Ok(())
    }

    pub(super) async fn receive(&mut self) -> anyhow::Result<Vec<u8>> {
        match self {
            Self::Tcp(stream) => {
                let length = stream.read_u16().await? as usize;
                if length == 0 {
                    return Err(anyhow!("OpenVPN TCP peer sent an empty frame"));
                }
                let mut packet = vec![0; length];
                stream.read_exact(&mut packet).await?;
                Ok(packet)
            }
            Self::Udp(socket) => {
                let mut packet = vec![0; MAX_OPENVPN_PACKET];
                let length = socket.recv(&mut packet).await?;
                if length == 0 {
                    return Err(anyhow!("OpenVPN UDP peer sent an empty datagram"));
                }
                packet.truncate(length);
                Ok(packet)
            }
        }
    }
}

async fn connect_udp(remote: &OpenVpnRemote, timeout_ms: u64) -> anyhow::Result<UdpSocket> {
    let addresses = timeout(
        Duration::from_millis(timeout_ms),
        tokio::net::lookup_host((remote.host.as_str(), remote.port)),
    )
    .await
    .context("OpenVPN UDP resolve timed out")?
    .with_context(|| format!("failed to resolve OpenVPN remote {}", remote.host))?
    .collect::<Vec<_>>();
    let deadline = tokio::time::Instant::now() + Duration::from_millis(timeout_ms);
    let mut errors = Vec::new();
    for address in addresses {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        let bind = if address.is_ipv4() {
            "0.0.0.0:0".parse::<SocketAddr>().expect("valid IPv4 bind")
        } else {
            "[::]:0".parse::<SocketAddr>().expect("valid IPv6 bind")
        };
        let result = timeout(remaining, async {
            let socket = UdpSocket::bind(bind).await?;
            socket.connect(address).await?;
            Ok::<_, io::Error>(socket)
        })
        .await;
        match result {
            Ok(Ok(socket)) => return Ok(socket),
            Ok(Err(error)) => errors.push(format!("{address}: {error}")),
            Err(_) => errors.push(format!("{address}: timed out")),
        }
    }
    Err(anyhow!(
        "OpenVPN UDP connect to {}:{} failed: {}",
        remote.host,
        remote.port,
        errors.join("; ")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::timeout;

    #[tokio::test]
    async fn udp_link_round_trips_a_connected_datagram() {
        let server = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind UDP test server");
        let port = server.local_addr().expect("read UDP test address").port();
        let task = tokio::spawn(async move {
            let mut packet = [0u8; 64];
            let (length, peer) = server
                .recv_from(&mut packet)
                .await
                .expect("receive UDP test packet");
            assert_eq!(&packet[..length], b"skyhook-link-test");
            server
                .send_to(b"skyhook-link-ok", peer)
                .await
                .expect("send UDP test response");
        });

        let remote = OpenVpnRemote {
            host: "127.0.0.1".to_string(),
            port,
            transport: OpenVpnTransport::Udp,
        };
        let mut link = OpenVpnLink::connect(&remote, 1_000)
            .await
            .expect("connect UDP test link");
        link.send(b"skyhook-link-test")
            .await
            .expect("send UDP test packet");
        let response = timeout(Duration::from_secs(1), link.receive())
            .await
            .expect("receive UDP test response timed out")
            .expect("receive UDP test response");
        assert_eq!(response, b"skyhook-link-ok");
        task.await.expect("UDP test server task");
    }
}
