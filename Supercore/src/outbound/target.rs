use std::net::SocketAddr;

use anyhow::{anyhow, Context};
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::routing::Destination;

pub fn encode_socks5_destination(
    destination: &Destination,
    output: &mut Vec<u8>,
) -> anyhow::Result<()> {
    if let Ok(addr) = destination.host.parse::<SocketAddr>() {
        match addr {
            SocketAddr::V4(addr) => {
                output.push(0x01);
                output.extend_from_slice(&addr.ip().octets());
                output.extend_from_slice(&addr.port().to_be_bytes());
            }
            SocketAddr::V6(addr) => {
                output.push(0x04);
                output.extend_from_slice(&addr.ip().octets());
                output.extend_from_slice(&addr.port().to_be_bytes());
            }
        }
        return Ok(());
    }
    if let Ok(ip) = destination.host.parse::<std::net::IpAddr>() {
        match ip {
            std::net::IpAddr::V4(ip) => {
                output.push(0x01);
                output.extend_from_slice(&ip.octets());
            }
            std::net::IpAddr::V6(ip) => {
                output.push(0x04);
                output.extend_from_slice(&ip.octets());
            }
        }
    } else {
        let host = destination.host.as_bytes();
        if host.len() > u8::MAX as usize {
            return Err(anyhow!("domain name too long"));
        }
        output.push(0x03);
        output.push(host.len() as u8);
        output.extend_from_slice(host);
    }
    output.extend_from_slice(&destination.port.to_be_bytes());
    Ok(())
}

pub(super) async fn read_socks5_destination_after_atyp<R>(
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
                std::net::Ipv4Addr::new(data[0], data[1], data[2], data[3]).to_string(),
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
                String::from_utf8(host).context("socks5 destination is not valid UTF-8")?,
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

pub(super) fn parse_socks5_destination_prefix(
    packet: &[u8],
) -> anyhow::Result<(Destination, usize)> {
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
            let host = std::net::Ipv4Addr::new(
                packet[offset],
                packet[offset + 1],
                packet[offset + 2],
                packet[offset + 3],
            )
            .to_string();
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
            let host = std::str::from_utf8(&packet[offset..offset + len])
                .context("socks5 destination is not valid UTF-8")?
                .to_string();
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn destination_round_trips_for_domain_ipv4_and_ipv6() {
        for destination in [
            Destination::new("example.com", 443),
            Destination::new("127.0.0.1", 8080),
            Destination::new("2001:db8::1", 53),
        ] {
            let mut encoded = Vec::new();
            encode_socks5_destination(&destination, &mut encoded).unwrap();
            let (decoded, consumed) = parse_socks5_destination_prefix(&encoded).unwrap();
            assert_eq!(decoded, destination);
            assert_eq!(consumed, encoded.len());
        }
    }

    #[test]
    fn destination_rejects_oversized_domains() {
        let mut encoded = Vec::new();
        assert!(
            encode_socks5_destination(&Destination::new("a".repeat(256), 443), &mut encoded)
                .is_err()
        );
    }

    #[test]
    fn destination_parser_rejects_truncated_and_unknown_addresses() {
        assert!(parse_socks5_destination_prefix(&[]).is_err());
        assert!(parse_socks5_destination_prefix(&[0x01, 127]).is_err());
        assert!(parse_socks5_destination_prefix(&[0x03, 0x01]).is_err());
        assert!(parse_socks5_destination_prefix(&[0x04, 0]).is_err());
        assert!(parse_socks5_destination_prefix(&[0x7f, 0x00, 0x00]).is_err());
    }
}
