use std::{sync::Arc, time::Duration};

use anyhow::anyhow;
use async_trait::async_trait;
use ipnet::IpNet;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::routing::Destination;

use super::{
    udp::{create_bound_udp, resolve_udp_socket_addr},
    BoxedStream, Outbound, OutboundCapability,
};

pub(super) struct WireGuardOutbound {
    name: String,
    server: String,
    port: u16,
    private_key: String,
    public_key: String,
    preshared_key: Option<String>,
    ip: Vec<String>,
    ipv6: Vec<String>,
    allowed_ips: Vec<String>,
    reserved: Vec<u8>,
    mtu: u16,
}

impl WireGuardOutbound {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        name: String,
        server: String,
        port: u16,
        private_key: String,
        public_key: String,
        preshared_key: Option<String>,
        ip: Vec<String>,
        ipv6: Vec<String>,
        allowed_ips: Vec<String>,
        reserved: Vec<u8>,
        mtu: u16,
    ) -> Self {
        Self {
            name,
            server,
            port,
            private_key,
            public_key,
            preshared_key,
            ip,
            ipv6,
            allowed_ips,
            reserved,
            mtu,
        }
    }
}

#[async_trait]
impl Outbound for WireGuardOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "wireguard"
    }

    fn capability(&self) -> OutboundCapability {
        if self.private_key.trim().is_empty()
            || self.public_key.trim().is_empty()
            || self.ip.is_empty()
        {
            OutboundCapability::unsupported(
                "WireGuard private key, public key, and tunnel address are required",
            )
        } else {
            OutboundCapability::tcp_udp("wireguard-userspace-tunnel")
        }
    }

    async fn connect(
        &self,
        destination: &Destination,
        timeout_ms: u64,
    ) -> anyhow::Result<BoxedStream> {
        if self.private_key.is_empty() {
            return Err(anyhow!("wireguard private_key is empty"));
        }
        if self.public_key.is_empty() {
            return Err(anyhow!("wireguard public_key is empty"));
        }
        if self.ip.is_empty() && self.ipv6.is_empty() {
            return Err(anyhow!("wireguard ip/ipv6 address is required"));
        }
        if !self.reserved.is_empty() && self.reserved.len() != 3 {
            return Err(anyhow!("wireguard reserved must be exactly 3 bytes"));
        }
        let mtu = self.mtu as usize;
        if mtu == 0 {
            return Err(anyhow!("wireguard mtu must be greater than zero"));
        }
        let mtu = mtu.min(65_535);
        let allowed_nets = self
            .allowed_ips
            .iter()
            .map(|item| {
                item.parse::<IpNet>()
                    .map_err(|_| anyhow!("wireguard allowed_ips value '{item}' is invalid"))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        if let Ok(destination_ip) = destination.host.parse::<std::net::IpAddr>() {
            if !allowed_nets.is_empty()
                && !allowed_nets
                    .iter()
                    .any(|item| item.contains(&destination_ip))
            {
                return Err(anyhow!(
                    "wireguard destination {destination_ip} is not covered by allowed_ips"
                ));
            }
        }
        let source_ipv4 = self
            .ip
            .iter()
            .find_map(|item| {
                item.parse::<std::net::Ipv4Addr>().ok().or_else(|| {
                    item.parse::<IpNet>().ok().and_then(|net| match net.addr() {
                        std::net::IpAddr::V4(addr) => Some(addr),
                        _ => None,
                    })
                })
            })
            .unwrap_or(std::net::Ipv4Addr::new(198, 18, 0, 1));
        let destination_ipv4 = destination
            .host
            .parse::<std::net::Ipv4Addr>()
            .ok()
            .map(|address| address.octets())
            .unwrap_or([0; 4]);

        let private_key_bytes = base64_decode_key(&self.private_key)
            .map_err(|_| anyhow!("invalid wireguard private_key"))?;
        let public_key_bytes = base64_decode_key(&self.public_key)
            .map_err(|_| anyhow!("invalid wireguard public_key"))?;
        if private_key_bytes.len() != 32 {
            return Err(anyhow!("wireguard private_key must be 32 bytes"));
        }
        if public_key_bytes.len() != 32 {
            return Err(anyhow!("wireguard public_key must be 32 bytes"));
        }

        let mut private_key_arr = [0u8; 32];
        private_key_arr.copy_from_slice(&private_key_bytes);
        let static_private = boringtun::x25519::StaticSecret::from(private_key_arr);
        let mut public_key_arr = [0u8; 32];
        public_key_arr.copy_from_slice(&public_key_bytes);
        let peer_public = boringtun::x25519::PublicKey::from(public_key_arr);
        let psk = self.preshared_key.as_ref().and_then(|psk| {
            base64_decode_key(psk).ok().and_then(|bytes| {
                if bytes.len() == 32 {
                    let mut value = [0u8; 32];
                    value.copy_from_slice(&bytes);
                    Some(value)
                } else {
                    None
                }
            })
        });

        let mut tunnel =
            boringtun::noise::Tunn::new(static_private, peer_public, psk, None, 0, None);
        let addr = resolve_udp_socket_addr(&self.server, self.port, timeout_ms).await?;
        let udp = Arc::new(
            create_bound_udp(addr)
                .map_err(|error| anyhow!("wireguard UDP bind failed: {error}"))?,
        );
        udp.connect(addr)
            .await
            .map_err(|error| anyhow!("wireguard UDP connect failed: {error}"))?;

        let mut init_buf = vec![0u8; 2048];
        if let boringtun::noise::TunnResult::WriteToNetwork(data) =
            tunnel.encapsulate(&[], &mut init_buf)
        {
            udp.send(data)
                .await
                .map_err(|error| anyhow!("wireguard init send failed: {error}"))?;
        }

        let mut response = vec![0u8; 2048];
        let mut decapsulated = vec![0u8; 2048];
        match tokio::time::timeout(Duration::from_millis(timeout_ms), udp.recv(&mut response)).await
        {
            Ok(Ok(len)) => {
                if let boringtun::noise::TunnResult::WriteToNetwork(data) =
                    tunnel.decapsulate(None, &response[..len], &mut decapsulated)
                {
                    udp.send(data)
                        .await
                        .map_err(|error| anyhow!("wireguard response send failed: {error}"))?;
                }
            }
            Ok(Err(error)) => return Err(anyhow!("wireguard recv failed: {error}")),
            Err(_) => {
                return Err(anyhow!(
                    "wireguard handshake timed out after {timeout_ms}ms"
                ));
            }
        }

        let tunnel = Arc::new(tokio::sync::Mutex::new(tunnel));
        let (tunnel_side, app_side) = tokio::io::duplex(64 * 1024);
        let (mut app_read, mut app_write) = tokio::io::split(tunnel_side);
        let mtu_payload = mtu.saturating_sub(40).max(1);
        let mtu_capacity = mtu.saturating_add(64);

        let udp_recv = udp.clone();
        let tunnel_recv = tunnel.clone();
        tokio::spawn(async move {
            let mut recv_buf = vec![0u8; 2048];
            let mut decap_buf = vec![0u8; mtu_capacity];
            loop {
                match tokio::time::timeout(Duration::from_secs(2), udp_recv.recv(&mut recv_buf))
                    .await
                {
                    Ok(Ok(len)) => {
                        let mut tunnel = tunnel_recv.lock().await;
                        match tunnel.decapsulate(None, &recv_buf[..len], &mut decap_buf) {
                            boringtun::noise::TunnResult::WriteToTunnelV4(data, _) => {
                                if data.len() >= 20 {
                                    let _ = app_write.write_all(&data[20..]).await;
                                }
                            }
                            boringtun::noise::TunnResult::WriteToTunnelV6(data, _) => {
                                if data.len() >= 40 {
                                    let _ = app_write.write_all(&data[40..]).await;
                                }
                            }
                            boringtun::noise::TunnResult::WriteToNetwork(data) => {
                                let _ = udp_recv.send(data).await;
                            }
                            _ => {}
                        }
                    }
                    Ok(Err(_)) => break,
                    Err(_) => {
                        let mut empty = Vec::new();
                        let mut tunnel = tunnel_recv.lock().await;
                        if let boringtun::noise::TunnResult::WriteToNetwork(data) =
                            tunnel.decapsulate(None, &[], &mut empty)
                        {
                            let _ = udp_recv.send(data).await;
                        }
                    }
                }
            }
        });

        let udp_send = udp.clone();
        let tunnel_send = tunnel.clone();
        let source_ipv4 = source_ipv4.octets();
        tokio::spawn(async move {
            let mut buf = vec![0u8; mtu_payload.max(1)];
            loop {
                match app_read.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        let mut offset = 0usize;
                        while offset < n {
                            let chunk_len = (n - offset).min(mtu_payload);
                            let mut packet = vec![0u8; 20 + chunk_len];
                            packet[0] = 0x45;
                            let total_len = (20 + chunk_len) as u16;
                            packet[2..4].copy_from_slice(&total_len.to_be_bytes());
                            packet[8] = 64;
                            packet[9] = 6;
                            packet[12..16].copy_from_slice(&source_ipv4);
                            packet[16..20].copy_from_slice(&destination_ipv4);
                            packet[20..20 + chunk_len]
                                .copy_from_slice(&buf[offset..offset + chunk_len]);
                            let mut encap_buf = vec![0u8; mtu_capacity];
                            let mut tunnel = tunnel_send.lock().await;
                            if let boringtun::noise::TunnResult::WriteToNetwork(data) =
                                tunnel.encapsulate(&packet, &mut encap_buf)
                            {
                                let _ = udp_send.send(data).await;
                            }
                            offset += chunk_len;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        Ok(Box::new(app_side))
    }
}

fn base64_decode_key(value: &str) -> anyhow::Result<Vec<u8>> {
    use base64::Engine;
    let trimmed = value.trim();
    if trimmed.len() == 44 || trimmed.len() == 43 {
        base64::engine::general_purpose::STANDARD
            .decode(trimmed)
            .map_err(|error| anyhow!("base64 decode failed: {error}"))
    } else {
        Err(anyhow!("invalid key length {}", trimmed.len()))
    }
}
