use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use anyhow::anyhow;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub enum TunIpPacket {
    Ipv4(Ipv4Packet),
    Ipv6(Ipv6Packet),
}

#[derive(Debug, Clone, Serialize)]
pub struct Ipv4Packet {
    pub version: u8,
    pub ihl: u8,
    pub dscp: u8,
    pub ecn: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags: u8,
    pub fragment_offset: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub checksum: u16,
    pub source: Ipv4Addr,
    pub destination: Ipv4Addr,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Ipv6Packet {
    pub version: u8,
    pub traffic_class: u8,
    pub flow_label: u32,
    pub payload_length: u16,
    pub next_header: u8,
    pub hop_limit: u8,
    pub source: Ipv6Addr,
    pub destination: Ipv6Addr,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Serialize)]
pub struct UdpDatagram {
    pub source_port: u16,
    pub dest_port: u16,
    pub length: u16,
    pub checksum: u16,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub enum IpVersion {
    V4,
    V6,
}

pub fn parse_ip_packet(data: &[u8]) -> anyhow::Result<TunIpPacket> {
    if data.is_empty() {
        return Err(anyhow!("empty packet"));
    }

    let version = data[0] >> 4;
    match version {
        4 => parse_ipv4_packet(data).map(TunIpPacket::Ipv4),
        6 => parse_ipv6_packet(data).map(TunIpPacket::Ipv6),
        _ => Err(anyhow!("unknown IP version: {version}")),
    }
}

pub fn validate_ip_packet(data: &[u8]) -> anyhow::Result<IpVersion> {
    if data.is_empty() {
        return Err(anyhow!("empty packet"));
    }

    let version = data[0] >> 4;
    match version {
        4 => Ok(IpVersion::V4),
        6 => Ok(IpVersion::V6),
        _ => Err(anyhow!("unknown IP version: {version}")),
    }
}

fn parse_ipv4_packet(data: &[u8]) -> anyhow::Result<Ipv4Packet> {
    if data.len() < 20 {
        return Err(anyhow!("IPv4 packet too short: {} bytes", data.len()));
    }

    let version = data[0] >> 4;
    let ihl = data[0] & 0x0F;
    let header_len = (ihl as usize) * 4;

    if data.len() < header_len {
        return Err(anyhow!("IPv4 header too short for IHL: {ihl}"));
    }

    let total_length = u16::from_be_bytes([data[2], data[3]]) as usize;
    if data.len() < total_length {
        return Err(anyhow!(
            "IPv4 packet truncated: expected {total_length}, got {}",
            data.len()
        ));
    }

    let dscp = (data[1] >> 2) & 0x3F;
    let ecn = data[1] & 0x03;
    let identification = u16::from_be_bytes([data[4], data[5]]);
    let flags = data[6] >> 5;
    let fragment_offset = u16::from_be_bytes([data[6] & 0x1F, data[7]]);
    let ttl = data[8];
    let protocol = data[9];
    let checksum = u16::from_be_bytes([data[10], data[11]]);
    let source = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
    let destination = Ipv4Addr::new(data[16], data[17], data[18], data[19]);

    let payload = if total_length > header_len {
        data[header_len..total_length].to_vec()
    } else {
        Vec::new()
    };

    Ok(Ipv4Packet {
        version,
        ihl,
        dscp,
        ecn,
        total_length: total_length as u16,
        identification,
        flags,
        fragment_offset,
        ttl,
        protocol,
        checksum,
        source,
        destination,
        payload,
    })
}

fn parse_ipv6_packet(data: &[u8]) -> anyhow::Result<Ipv6Packet> {
    if data.len() < 40 {
        return Err(anyhow!("IPv6 packet too short: {} bytes", data.len()));
    }

    let version = data[0] >> 4;
    let traffic_class = ((data[0] & 0x0F) << 4) | (data[1] >> 4);
    let flow_label = u32::from_be_bytes([0, data[1] & 0x0F, data[2], data[3]]);
    let payload_length = u16::from_be_bytes([data[4], data[5]]);
    let next_header = data[6];
    let hop_limit = data[7];

    let source = Ipv6Addr::from([
        data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15], data[16],
        data[17], data[18], data[19], data[20], data[21], data[22], data[23],
    ]);
    let destination = Ipv6Addr::from([
        data[24], data[25], data[26], data[27], data[28], data[29], data[30], data[31], data[32],
        data[33], data[34], data[35], data[36], data[37], data[38], data[39],
    ]);

    let payload_end = 40 + payload_length as usize;
    if data.len() < payload_end {
        return Err(anyhow!(
            "IPv6 packet truncated: expected {payload_end}, got {}",
            data.len()
        ));
    }

    let payload = data[40..payload_end].to_vec();

    Ok(Ipv6Packet {
        version,
        traffic_class,
        flow_label,
        payload_length,
        next_header,
        hop_limit,
        source,
        destination,
        payload,
    })
}

pub fn parse_udp_datagram(data: &[u8]) -> anyhow::Result<UdpDatagram> {
    if data.len() < 8 {
        return Err(anyhow!("UDP datagram too short: {} bytes", data.len()));
    }

    let source_port = u16::from_be_bytes([data[0], data[1]]);
    let dest_port = u16::from_be_bytes([data[2], data[3]]);
    let length = u16::from_be_bytes([data[4], data[5]]);
    let checksum = u16::from_be_bytes([data[6], data[7]]);

    if length < 8 {
        return Err(anyhow!("UDP length field too small: {length} bytes"));
    }

    let payload_len = length.saturating_sub(8) as usize;
    if data.len() < 8 + payload_len {
        return Err(anyhow!(
            "UDP datagram truncated: expected {} bytes, got {}",
            8 + payload_len,
            data.len()
        ));
    }

    let payload = data[8..8 + payload_len].to_vec();

    Ok(UdpDatagram {
        source_port,
        dest_port,
        length,
        checksum,
        payload,
    })
}

pub fn extract_transport_ports(ip_packet: &TunIpPacket) -> (u16, u16) {
    match ip_packet {
        TunIpPacket::Ipv4(ipv4) => extract_ports_from_payload(ipv4.protocol, &ipv4.payload),
        TunIpPacket::Ipv6(ipv6) => extract_ports_from_payload(ipv6.next_header, &ipv6.payload),
    }
}

fn extract_ports_from_payload(protocol: u8, payload: &[u8]) -> (u16, u16) {
    match protocol {
        6 if payload.len() >= 4 => {
            let src = u16::from_be_bytes([payload[0], payload[1]]);
            let dst = u16::from_be_bytes([payload[2], payload[3]]);
            (src, dst)
        }
        17 if payload.len() >= 4 => {
            let src = u16::from_be_bytes([payload[0], payload[1]]);
            let dst = u16::from_be_bytes([payload[2], payload[3]]);
            (src, dst)
        }
        _ => (0, 0),
    }
}

pub fn is_dns_packet(ip_packet: &TunIpPacket) -> bool {
    match ip_packet {
        TunIpPacket::Ipv4(ipv4) => {
            if ipv4.protocol != 17 {
                return false;
            }
            match parse_udp_datagram(&ipv4.payload) {
                Ok(udp) => udp.source_port == 53 || udp.dest_port == 53,
                Err(_) => false,
            }
        }
        TunIpPacket::Ipv6(ipv6) => {
            if ipv6.next_header != 17 {
                return false;
            }
            match parse_udp_datagram(&ipv6.payload) {
                Ok(udp) => udp.source_port == 53 || udp.dest_port == 53,
                Err(_) => false,
            }
        }
    }
}

pub fn extract_dns_query(
    ip_packet: &TunIpPacket,
) -> anyhow::Result<(SocketAddr, SocketAddr, Vec<u8>)> {
    match ip_packet {
        TunIpPacket::Ipv4(ipv4) => {
            if ipv4.protocol != 17 {
                return Err(anyhow!("not a UDP packet"));
            }
            let udp = parse_udp_datagram(&ipv4.payload)?;
            let src = SocketAddr::new(IpAddr::V4(ipv4.source), udp.source_port);
            let dst = SocketAddr::new(IpAddr::V4(ipv4.destination), udp.dest_port);
            Ok((src, dst, udp.payload))
        }
        TunIpPacket::Ipv6(ipv6) => {
            if ipv6.next_header != 17 {
                return Err(anyhow!("not a UDP packet"));
            }
            let udp = parse_udp_datagram(&ipv6.payload)?;
            let src = SocketAddr::new(IpAddr::V6(ipv6.source), udp.source_port);
            let dst = SocketAddr::new(IpAddr::V6(ipv6.destination), udp.dest_port);
            Ok((src, dst, udp.payload))
        }
    }
}

pub fn build_ipv4_udp_response(
    source: Ipv4Addr,
    dest: Ipv4Addr,
    source_port: u16,
    dest_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_length = 8 + payload.len();
    let total_length = 20 + udp_length;

    let mut packet = Vec::with_capacity(total_length);

    packet.push(0x45);
    packet.push(0x00);
    packet.extend_from_slice(&(total_length as u16).to_be_bytes());
    packet.extend_from_slice(&[0x00, 0x00]);
    packet.extend_from_slice(&[0x40, 0x00]);
    packet.push(64);
    packet.push(17);
    packet.extend_from_slice(&[0x00, 0x00]);
    packet.extend_from_slice(&source.octets());
    packet.extend_from_slice(&dest.octets());

    let checksum = calculate_ipv4_checksum(&packet);
    packet[10] = (checksum >> 8) as u8;
    packet[11] = (checksum & 0xFF) as u8;

    packet.extend_from_slice(&source_port.to_be_bytes());
    packet.extend_from_slice(&dest_port.to_be_bytes());
    packet.extend_from_slice(&(udp_length as u16).to_be_bytes());
    packet.extend_from_slice(&[0x00, 0x00]);
    packet.extend_from_slice(payload);

    let udp_checksum = calculate_udp_checksum_ipv4(source, dest, source_port, dest_port, payload);
    let udp_checksum_offset = 20 + 6;
    packet[udp_checksum_offset] = (udp_checksum >> 8) as u8;
    packet[udp_checksum_offset + 1] = (udp_checksum & 0xFF) as u8;

    packet
}

pub fn calculate_ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let len = header.len();

    for i in (0..len).step_by(2) {
        if i + 1 < len {
            sum += u32::from(u16::from_be_bytes([header[i], header[i + 1]]));
        } else {
            sum += u32::from(header[i]) << 8;
        }
    }

    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !sum as u16
}

fn calculate_udp_checksum_ipv4(
    source: Ipv4Addr,
    dest: Ipv4Addr,
    source_port: u16,
    dest_port: u16,
    payload: &[u8],
) -> u16 {
    let udp_length = 8 + payload.len();
    let mut sum: u32 = 0;

    let source_octets = source.octets();
    let dest_octets = dest.octets();

    sum += u32::from(u16::from_be_bytes([source_octets[0], source_octets[1]]));
    sum += u32::from(u16::from_be_bytes([source_octets[2], source_octets[3]]));
    sum += u32::from(u16::from_be_bytes([dest_octets[0], dest_octets[1]]));
    sum += u32::from(u16::from_be_bytes([dest_octets[2], dest_octets[3]]));
    sum += 17;
    sum += udp_length as u32;

    sum += u32::from(source_port);
    sum += u32::from(dest_port);
    sum += udp_length as u32;

    for i in (0..payload.len()).step_by(2) {
        if i + 1 < payload.len() {
            sum += u32::from(u16::from_be_bytes([payload[i], payload[i + 1]]));
        } else {
            sum += u32::from(payload[i]) << 8;
        }
    }

    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    let checksum = !sum as u16;
    if checksum == 0 {
        0xFFFF
    } else {
        checksum
    }
}

pub fn extract_tls_sni(ip_packet: &TunIpPacket) -> Option<String> {
    let payload = match ip_packet {
        TunIpPacket::Ipv4(ipv4) if ipv4.protocol == 6 => &ipv4.payload,
        TunIpPacket::Ipv6(ipv6) if ipv6.next_header == 6 => &ipv6.payload,
        _ => return None,
    };

    if payload.len() < 6 {
        return None;
    }

    let tcp_data_offset = ((payload[12] >> 4) as usize) * 4;
    if payload.len() <= tcp_data_offset {
        return None;
    }
    let tls_data = &payload[tcp_data_offset..];

    if tls_data.len() < 5 || tls_data[0] != 0x16 || tls_data[1] != 0x03 {
        return None;
    }

    let record_len = u16::from_be_bytes([tls_data[3], tls_data[4]]) as usize;
    if tls_data.len() < 5 + record_len {
        return None;
    }
    let handshake = &tls_data[5..5 + record_len];

    if handshake.len() < 4 || handshake[0] != 0x01 {
        return None;
    }

    let mut offset = 4;
    if handshake.len() < offset + 2 {
        return None;
    }
    offset += 2;

    if handshake.len() < offset + 32 {
        return None;
    }
    offset += 32;

    if handshake.len() < offset + 1 {
        return None;
    }
    let session_id_len = handshake[offset] as usize;
    offset += 1 + session_id_len;

    if handshake.len() < offset + 2 {
        return None;
    }
    let cipher_suites_len = u16::from_be_bytes([handshake[offset], handshake[offset + 1]]) as usize;
    offset += 2 + cipher_suites_len;

    if handshake.len() < offset + 1 {
        return None;
    }
    let compression_len = handshake[offset] as usize;
    offset += 1 + compression_len;

    if handshake.len() < offset + 2 {
        return None;
    }
    let extensions_len = u16::from_be_bytes([handshake[offset], handshake[offset + 1]]) as usize;
    offset += 2;

    let extensions_end = offset + extensions_len;
    if handshake.len() < extensions_end {
        return None;
    }

    while offset + 4 <= extensions_end {
        let ext_type = u16::from_be_bytes([handshake[offset], handshake[offset + 1]]);
        let ext_len = u16::from_be_bytes([handshake[offset + 2], handshake[offset + 3]]) as usize;
        offset += 4;

        if offset + ext_len > extensions_end {
            break;
        }

        if ext_type == 0x0000 && ext_len >= 5 {
            let sni_list_len =
                u16::from_be_bytes([handshake[offset], handshake[offset + 1]]) as usize;
            let mut sni_offset = offset + 2;
            if sni_list_len > 0 && sni_offset + 3 <= offset + ext_len {
                let name_type = handshake[sni_offset];
                sni_offset += 1;
                if name_type == 0 {
                    let name_len =
                        u16::from_be_bytes([handshake[sni_offset], handshake[sni_offset + 1]])
                            as usize;
                    sni_offset += 2;
                    if sni_offset + name_len <= offset + ext_len {
                        if let Ok(sni) =
                            std::str::from_utf8(&handshake[sni_offset..sni_offset + name_len])
                        {
                            return Some(sni.to_string());
                        }
                    }
                }
            }
        }

        offset += ext_len;
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ipv4_udp_dns_query() {
        let mut packet = vec![0x45, 0x00, 0x00, 0x1C];
        packet.extend_from_slice(&[0x00, 0x01, 0x40, 0x00]);
        packet.extend_from_slice(&[0x40, 0x11, 0x00, 0x00]);
        packet.extend_from_slice(&[0x0A, 0x00, 0x00, 0x01]);
        packet.extend_from_slice(&[0x08, 0x08, 0x08, 0x08]);

        packet.extend_from_slice(&[0xC0, 0x00, 0x00, 0x35]);
        packet.extend_from_slice(&[0x00, 0x08, 0x00, 0x00]);

        let result = parse_ip_packet(&packet).unwrap();
        match result {
            TunIpPacket::Ipv4(ipv4) => {
                assert_eq!(ipv4.protocol, 17);
                assert_eq!(ipv4.source, Ipv4Addr::new(10, 0, 0, 1));
                assert_eq!(ipv4.destination, Ipv4Addr::new(8, 8, 8, 8));
                assert_eq!(ipv4.total_length, 28);
            }
            _ => panic!("expected IPv4"),
        }
    }

    #[test]
    fn reject_truncated_ipv4_header() {
        let packet = [0x45, 0x00, 0x00];
        assert!(parse_ip_packet(&packet).is_err());
    }

    #[test]
    fn reject_invalid_udp_length() {
        let udp_data = [0xC0, 0x00, 0x00, 0x35, 0x00, 0x08, 0x00, 0x00];
        let result = parse_udp_datagram(&udp_data);
        assert!(result.is_ok());

        let udp_data2 = [0xC0, 0x00, 0x00, 0x35, 0x00, 0x03, 0x00, 0x00];
        let result2 = parse_udp_datagram(&udp_data2);
        assert!(result2.is_err());
    }

    #[test]
    fn validate_ip_packet_works() {
        let mut packet = vec![0x45, 0x00, 0x00, 0x20];
        packet.extend_from_slice(&[0x00, 0x01, 0x40, 0x00]);
        packet.extend_from_slice(&[0x40, 0x11, 0x00, 0x00]);
        packet.extend_from_slice(&[0x0A, 0x00, 0x00, 0x01]);
        packet.extend_from_slice(&[0x08, 0x08, 0x08, 0x08]);
        packet.extend_from_slice(&[0xC0, 0x00, 0x00, 0x35]);
        packet.extend_from_slice(&[0x00, 0x0C, 0x00, 0x00]);

        assert_eq!(validate_ip_packet(&packet).unwrap(), IpVersion::V4);
    }

    #[test]
    fn validate_ip_packet_rejects_empty() {
        assert!(validate_ip_packet(&[]).is_err());
    }

    #[test]
    fn validate_ip_packet_rejects_unknown_version() {
        assert!(validate_ip_packet(&[0x00]).is_err());
    }

    #[test]
    fn build_ipv4_udp_response_checksum_changes() {
        let source = Ipv4Addr::new(8, 8, 8, 8);
        let dest = Ipv4Addr::new(10, 0, 0, 1);
        let payload = b"test dns response";

        let response = build_ipv4_udp_response(source, dest, 53, 12345, payload);

        assert_eq!(response[0] >> 4, 4);
        assert_eq!(response[9], 17);

        let checksum = u16::from_be_bytes([response[10], response[11]]);
        assert_ne!(checksum, 0);
    }

    #[test]
    fn is_dns_packet_detects_port_53() {
        let mut packet = vec![0x45, 0x00, 0x00, 0x1C];
        packet.extend_from_slice(&[0x00, 0x01, 0x40, 0x00]);
        packet.extend_from_slice(&[0x40, 0x11, 0x00, 0x00]);
        packet.extend_from_slice(&[0x0A, 0x00, 0x00, 0x01]);
        packet.extend_from_slice(&[0x08, 0x08, 0x08, 0x08]);
        packet.extend_from_slice(&[0xC0, 0x00, 0x00, 0x35]);
        packet.extend_from_slice(&[0x00, 0x08, 0x00, 0x00]);

        let ip_packet = parse_ip_packet(&packet).unwrap();
        assert!(is_dns_packet(&ip_packet));
    }

    #[test]
    fn extract_dns_query_works() {
        let mut packet = vec![0x45, 0x00, 0x00, 0x1C];
        packet.extend_from_slice(&[0x00, 0x01, 0x40, 0x00]);
        packet.extend_from_slice(&[0x40, 0x11, 0x00, 0x00]);
        packet.extend_from_slice(&[0x0A, 0x00, 0x00, 0x01]);
        packet.extend_from_slice(&[0x08, 0x08, 0x08, 0x08]);
        packet.extend_from_slice(&[0xC0, 0x00, 0x00, 0x35]);
        packet.extend_from_slice(&[0x00, 0x08, 0x00, 0x00]);

        let ip_packet = parse_ip_packet(&packet).unwrap();
        let (src, dst, _payload) = extract_dns_query(&ip_packet).unwrap();

        assert_eq!(src.port(), 49152);
        assert_eq!(dst.port(), 53);
    }
}
