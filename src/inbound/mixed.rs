use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

use anyhow::{anyhow, Context};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::Semaphore,
    time,
};
use url::Url;

use crate::{core::Runtime, routing::Destination};

const UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const UDP_WORKER_LIMIT: usize = 1024;

#[derive(Debug, Default)]
pub struct UdpMetrics {
    pub packets_rx: AtomicU64,
    pub packets_tx: AtomicU64,
    pub bytes_rx: AtomicU64,
    pub bytes_tx: AtomicU64,
    pub errors: AtomicU64,
    pub fragments_rejected: AtomicU64,
}

pub async fn serve(runtime: Arc<Runtime>) -> anyhow::Result<()> {
    let listener = TcpListener::bind(runtime.config().core.mixed_listen)
        .await
        .with_context(|| {
            format!(
                "failed to bind mixed listener {}",
                runtime.config().core.mixed_listen
            )
        })?;
    runtime
        .telemetry()
        .log(
            "info",
            format!("mixed listener on {}", runtime.config().core.mixed_listen),
        )
        .await;

    loop {
        let (stream, peer) = listener.accept().await?;
        let runtime = runtime.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_client(runtime.clone(), stream, peer).await {
                runtime
                    .telemetry()
                    .log("warn", format!("mixed client {peer} failed: {error:#}"))
                    .await;
            }
        });
    }
}

async fn handle_client(
    runtime: Arc<Runtime>,
    stream: TcpStream,
    peer: SocketAddr,
) -> anyhow::Result<()> {
    let mut first = [0u8; 1];
    let n = stream.peek(&mut first).await?;
    if n == 0 {
        return Ok(());
    }
    match first[0] {
        0x05 => handle_socks5(runtime, stream, peer).await,
        _ => handle_http(runtime, stream).await,
    }
}

async fn handle_socks5(
    runtime: Arc<Runtime>,
    mut stream: TcpStream,
    peer: SocketAddr,
) -> anyhow::Result<()> {
    let mut header = [0u8; 2];
    stream.read_exact(&mut header).await?;
    if header[0] != 0x05 {
        return Err(anyhow!("invalid socks version"));
    }
    let mut methods = vec![0u8; header[1] as usize];
    stream.read_exact(&mut methods).await?;
    if !methods.contains(&0x00) {
        stream.write_all(&[0x05, 0xff]).await?;
        return Err(anyhow!("socks5 client does not support no-auth"));
    }
    stream.write_all(&[0x05, 0x00]).await?;

    let mut request = [0u8; 4];
    stream.read_exact(&mut request).await?;
    if request[0] != 0x05 {
        return Err(anyhow!("invalid socks request version"));
    }
    if request[1] == 0x03 {
        let _destination = read_socks5_destination(&mut stream, request[3]).await?;
        return handle_socks5_udp_associate(runtime, stream, peer).await;
    }
    if request[1] != 0x01 {
        return Err(anyhow!(
            "only socks5 CONNECT and UDP ASSOCIATE are supported"
        ));
    }
    let destination = read_socks5_destination(&mut stream, request[3]).await?;
    stream
        .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;
    runtime.tunnel("socks5", destination, stream).await
}

async fn handle_socks5_udp_associate(
    runtime: Arc<Runtime>,
    mut stream: TcpStream,
    peer: SocketAddr,
) -> anyhow::Result<()> {
    let bind_addr = if peer.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let udp = Arc::new(UdpSocket::bind(bind_addr).await?);
    let local = udp.local_addr()?;

    let reply = build_udp_associate_reply(local);
    stream.write_all(&reply).await?;

    runtime
        .telemetry()
        .log(
            "info",
            format!("socks5 udp associate on {local} (client {peer})"),
        )
        .await;

    let metrics = Arc::new(UdpMetrics::default());
    let mut client_addr: Option<SocketAddr> = None;
    let mut udp_buf = vec![0u8; 65_535];
    let mut tcp_probe = [0u8; 1];
    let udp_workers = Arc::new(Semaphore::new(UDP_WORKER_LIMIT));

    let result = run_udp_associate_loop(
        &runtime,
        &mut stream,
        &udp,
        &mut client_addr,
        &mut udp_buf,
        &mut tcp_probe,
        &udp_workers,
        &metrics,
    )
    .await;

    let m = &metrics;
    runtime
        .telemetry()
        .log(
            "info",
            format!(
                "socks5 udp associate closed: rx={} tx={} bytes_rx={} bytes_tx={} errors={}",
                m.packets_rx.load(Ordering::Relaxed),
                m.packets_tx.load(Ordering::Relaxed),
                m.bytes_rx.load(Ordering::Relaxed),
                m.bytes_tx.load(Ordering::Relaxed),
                m.errors.load(Ordering::Relaxed),
            ),
        )
        .await;

    result
}

fn build_udp_associate_reply(local: std::net::SocketAddr) -> Vec<u8> {
    let mut reply = vec![0x05u8, 0x00, 0x00];
    match local {
        std::net::SocketAddr::V4(addr) => {
            reply.push(0x01);
            reply.extend_from_slice(&addr.ip().octets());
            reply.extend_from_slice(&addr.port().to_be_bytes());
        }
        std::net::SocketAddr::V6(addr) => {
            reply.push(0x04);
            reply.extend_from_slice(&addr.ip().octets());
            reply.extend_from_slice(&addr.port().to_be_bytes());
        }
    }
    reply
}

#[allow(clippy::too_many_arguments)]
async fn run_udp_associate_loop(
    runtime: &Arc<Runtime>,
    stream: &mut TcpStream,
    udp: &Arc<UdpSocket>,
    client_addr: &mut Option<SocketAddr>,
    udp_buf: &mut [u8],
    tcp_probe: &mut [u8; 1],
    udp_workers: &Arc<Semaphore>,
    metrics: &Arc<UdpMetrics>,
) -> anyhow::Result<()> {
    loop {
        let idle = tokio::select! {
            tcp = stream.read(tcp_probe) => {
                if tcp.unwrap_or(0) == 0 {
                    return Ok(());
                }
                continue;
            }
            received = time::timeout(UDP_IDLE_TIMEOUT, udp.recv_from(udp_buf)) => {
                match received {
                    Ok(result) => result?,
                    Err(_) => {
                        runtime
                            .telemetry()
                            .log("info", "socks5 udp associate idle timeout".to_string())
                            .await;
                        return Ok(());
                    }
                }
            }
        };
        let (len, peer_addr) = idle;
        metrics.packets_rx.fetch_add(1, Ordering::Relaxed);
        metrics.bytes_rx.fetch_add(len as u64, Ordering::Relaxed);

        if client_addr.is_none() {
            *client_addr = Some(peer_addr);
        }
        if Some(peer_addr) != *client_addr {
            continue;
        }

        let Ok(permit) = udp_workers.clone().try_acquire_owned() else {
            runtime
                .telemetry()
                .log(
                    "warn",
                    "socks5 udp worker limit reached; dropping datagram".to_string(),
                )
                .await;
            metrics.errors.fetch_add(1, Ordering::Relaxed);
            continue;
        };
        let packet = udp_buf[..len].to_vec();
        let runtime = runtime.clone();
        let udp = udp.clone();
        let metrics = metrics.clone();
        tokio::spawn(async move {
            let _permit = permit;
            match handle_socks5_udp_datagram(runtime.clone(), &packet).await {
                Ok(Some(response)) => {
                    if udp.send_to(&response, peer_addr).await.is_ok() {
                        metrics.packets_tx.fetch_add(1, Ordering::Relaxed);
                        metrics
                            .bytes_tx
                            .fetch_add(response.len() as u64, Ordering::Relaxed);
                    }
                }
                Ok(None) => {}
                Err(error) => {
                    metrics.errors.fetch_add(1, Ordering::Relaxed);
                    runtime
                        .telemetry()
                        .log("warn", format!("socks5 udp datagram failed: {error:#}"))
                        .await;
                }
            }
        });
    }
}

async fn handle_socks5_udp_datagram(
    runtime: Arc<Runtime>,
    packet: &[u8],
) -> anyhow::Result<Option<Vec<u8>>> {
    let (destination, payload_offset) = parse_socks5_udp_packet(packet)?;
    let config = runtime.config();
    if destination.port == 53 && config.dns.enabled && config.dns.hijack_udp_53 {
        let response = runtime
            .exchange_dns_over_tcp(&packet[payload_offset..])
            .await?;
        return Ok(Some(build_socks5_udp_packet(&destination, &response)?));
    }
    if config.dns.block_non_dns_udp {
        return Ok(None);
    }
    let response = runtime
        .exchange_udp("socks5-udp", destination.clone(), &packet[payload_offset..])
        .await?;
    Ok(Some(build_socks5_udp_packet(&destination, &response)?))
}

async fn read_socks5_destination(stream: &mut TcpStream, atyp: u8) -> anyhow::Result<Destination> {
    match atyp {
        0x01 => {
            let mut data = [0u8; 6];
            stream.read_exact(&mut data).await?;
            let host = format!("{}.{}.{}.{}", data[0], data[1], data[2], data[3]);
            let port = u16::from_be_bytes([data[4], data[5]]);
            Ok(Destination::new(host, port))
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
            let mut host = [0u8; 16];
            let mut port = [0u8; 2];
            stream.read_exact(&mut host).await?;
            stream.read_exact(&mut port).await?;
            Ok(Destination::new(
                std::net::Ipv6Addr::from(host).to_string(),
                u16::from_be_bytes(port),
            ))
        }
        _ => Err(anyhow!("unsupported socks5 address type {atyp}")),
    }
}

fn parse_socks5_udp_packet(packet: &[u8]) -> anyhow::Result<(Destination, usize)> {
    if packet.len() < 4 {
        return Err(anyhow!("short socks5 udp packet"));
    }
    if packet[0] != 0 || packet[1] != 0 {
        return Err(anyhow!("invalid socks5 udp reserved bytes"));
    }
    if packet[2] != 0 {
        return Err(anyhow!("fragmented socks5 udp packets are not supported"));
    }
    let atyp = packet[3];
    let mut offset = 4;
    let host = match atyp {
        0x01 => {
            if packet.len() < offset + 4 + 2 {
                return Err(anyhow!("short socks5 udp ipv4 packet"));
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
                return Err(anyhow!("short socks5 udp domain packet"));
            }
            let len = packet[offset] as usize;
            offset += 1;
            if packet.len() < offset + len + 2 {
                return Err(anyhow!("short socks5 udp domain payload"));
            }
            let host = std::str::from_utf8(&packet[offset..offset + len])?.to_string();
            offset += len;
            host
        }
        0x04 => {
            if packet.len() < offset + 16 + 2 {
                return Err(anyhow!("short socks5 udp ipv6 packet"));
            }
            let mut raw = [0u8; 16];
            raw.copy_from_slice(&packet[offset..offset + 16]);
            offset += 16;
            std::net::Ipv6Addr::from(raw).to_string()
        }
        _ => return Err(anyhow!("unsupported socks5 udp address type {atyp}")),
    };
    let port = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
    offset += 2;
    Ok((Destination::new(host, port), offset))
}

fn build_socks5_udp_packet(destination: &Destination, payload: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut packet = vec![0x00, 0x00, 0x00];
    encode_socks5_udp_destination(destination, &mut packet)?;
    packet.extend_from_slice(payload);
    Ok(packet)
}

fn encode_socks5_udp_destination(
    destination: &Destination,
    output: &mut Vec<u8>,
) -> anyhow::Result<()> {
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
        if destination.host.len() > 255 {
            return Err(anyhow!("domain name too long"));
        }
        output.push(0x03);
        output.push(destination.host.len() as u8);
        output.extend_from_slice(destination.host.as_bytes());
    }
    output.extend_from_slice(&destination.port.to_be_bytes());
    Ok(())
}

async fn handle_http(runtime: Arc<Runtime>, mut stream: TcpStream) -> anyhow::Result<()> {
    let head = read_http_head(&mut stream).await?;
    let text = std::str::from_utf8(&head)?;
    let mut lines = text.split("\r\n");
    let first_line = lines.next().ok_or_else(|| anyhow!("empty http request"))?;
    let parts = first_line.split_whitespace().collect::<Vec<_>>();
    if parts.len() < 3 {
        return Err(anyhow!("invalid http request line"));
    }
    if parts[0].eq_ignore_ascii_case("CONNECT") {
        let destination = parse_authority(parts[1], 443)?;
        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        return runtime.tunnel("http-connect", destination, stream).await;
    }

    let url =
        Url::parse(parts[1]).context("only absolute-form HTTP proxy requests are supported")?;
    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("absolute-form request is missing host"))?
        .to_string();
    let port = url.port_or_known_default().unwrap_or(80);
    let destination = Destination::new(host, port);
    let rewritten = rewrite_absolute_form_request(&head, &url)?;
    let (_client_read, mut client_write) = stream.into_split();
    let (mut remote_stream, decision, outbound_name) =
        runtime.connect_outbound(&destination).await?;
    let id = runtime
        .open_connection_record(
            "http",
            destination,
            outbound_name.clone(),
            decision.matched_rule,
            crate::telemetry::Protocol::Tcp,
        )
        .await;
    remote_stream.write_all(&rewritten).await?;
    runtime
        .telemetry()
        .add_transfer(
            id,
            rewritten.len() as u64,
            0,
            crate::telemetry::Protocol::Tcp,
            &outbound_name,
        )
        .await;
    let copied = tokio::io::copy(&mut remote_stream, &mut client_write).await?;
    runtime
        .telemetry()
        .add_transfer(
            id,
            0,
            copied,
            crate::telemetry::Protocol::Tcp,
            &outbound_name,
        )
        .await;
    runtime.close_connection_record(id).await;
    Ok(())
}

async fn read_http_head(stream: &mut TcpStream) -> anyhow::Result<Vec<u8>> {
    let mut data = Vec::with_capacity(1024);
    let mut buf = [0u8; 1];
    while data.len() < 64 * 1024 {
        stream.read_exact(&mut buf).await?;
        data.push(buf[0]);
        if data.ends_with(b"\r\n\r\n") {
            return Ok(data);
        }
    }
    Err(anyhow!("http header is too large"))
}

fn parse_authority(value: &str, default_port: u16) -> anyhow::Result<Destination> {
    if let Some((host, port)) = value.rsplit_once(':') {
        Ok(Destination::new(host.to_string(), port.parse()?))
    } else {
        Ok(Destination::new(value.to_string(), default_port))
    }
}

fn rewrite_absolute_form_request(head: &[u8], url: &Url) -> anyhow::Result<Vec<u8>> {
    let text = std::str::from_utf8(head)?;
    let mut lines = text.split("\r\n");
    let first = lines.next().ok_or_else(|| anyhow!("empty request"))?;
    let parts = first.split_whitespace().collect::<Vec<_>>();
    let path = match (url.path(), url.query()) {
        ("", None) => "/".to_string(),
        (path, None) => path.to_string(),
        (path, Some(query)) => format!("{path}?{query}"),
    };
    let mut output = format!("{} {} {}\r\n", parts[0], path, parts[2]).into_bytes();
    let mut inserted_connection_close = false;
    for line in lines {
        if line.is_empty() {
            if !inserted_connection_close {
                output.extend_from_slice(b"Connection: close\r\n");
            }
            output.extend_from_slice(b"\r\n");
            break;
        }
        if line
            .split_once(':')
            .map(|(name, _)| {
                name.eq_ignore_ascii_case("connection")
                    || name.eq_ignore_ascii_case("proxy-connection")
            })
            .unwrap_or(false)
        {
            if !inserted_connection_close {
                output.extend_from_slice(b"Connection: close\r\n");
                inserted_connection_close = true;
            }
            continue;
        }
        output.extend_from_slice(line.as_bytes());
        output.extend_from_slice(b"\r\n");
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_builds_socks5_udp_ipv4_packet() {
        let payload = b"hello";
        let mut packet = vec![0x00, 0x00, 0x00, 0x01, 192, 168, 1, 1, 0x00, 0x50];
        packet.extend_from_slice(payload);

        let (destination, offset) = parse_socks5_udp_packet(&packet).expect("parse");
        assert_eq!(destination.host, "192.168.1.1");
        assert_eq!(destination.port, 80);
        assert_eq!(&packet[offset..], payload);

        let response = build_socks5_udp_packet(&destination, b"world").expect("build");
        assert_eq!(&response[..offset], &packet[..offset]);
        assert_eq!(&response[offset..], b"world");
    }

    #[test]
    fn parses_and_builds_socks5_udp_ipv6_packet() {
        let payload = b"test";
        let mut packet = vec![0x00, 0x00, 0x00, 0x04];
        packet.extend_from_slice(&std::net::Ipv6Addr::LOCALHOST.octets());
        packet.extend_from_slice(&0x01BBu16.to_be_bytes());
        packet.extend_from_slice(payload);

        let (destination, offset) = parse_socks5_udp_packet(&packet).expect("parse");
        assert_eq!(destination.host, "::1");
        assert_eq!(destination.port, 443);
        assert_eq!(&packet[offset..], payload);

        let response = build_socks5_udp_packet(&destination, b"reply").expect("build");
        assert_eq!(&response[..offset], &packet[..offset]);
        assert_eq!(&response[offset..], b"reply");
    }

    #[test]
    fn parses_and_builds_socks5_udp_domain_packet() {
        let packet = [
            0x00, 0x00, 0x00, 0x03, 11, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o',
            b'm', 0x00, 0x35, b'q',
        ];

        let (destination, offset) = parse_socks5_udp_packet(&packet).expect("parse");
        let response = build_socks5_udp_packet(&destination, b"r").expect("build");

        assert_eq!(destination.host, "example.com");
        assert_eq!(destination.port, 53);
        assert_eq!(&packet[offset..], b"q");
        assert_eq!(&response[..offset], &packet[..offset]);
        assert_eq!(&response[offset..], b"r");
    }

    #[test]
    fn rejects_short_socks5_udp_packet() {
        assert!(parse_socks5_udp_packet(&[0x00, 0x00]).is_err());
        assert!(parse_socks5_udp_packet(&[]).is_err());
    }

    #[test]
    fn rejects_invalid_reserved_bytes() {
        assert!(parse_socks5_udp_packet(&[0x01, 0x00, 0x00, 0x01, 1, 2, 3, 4, 0, 80]).is_err());
        assert!(parse_socks5_udp_packet(&[0x00, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0, 80]).is_err());
    }

    #[test]
    fn rejects_fragmented_packet() {
        let packet = [0x00, 0x00, 0x01, 0x01, 1, 2, 3, 4, 0, 80];
        assert!(parse_socks5_udp_packet(&packet).is_err());
    }

    #[test]
    fn rejects_unsupported_address_type() {
        let packet = [0x00, 0x00, 0x00, 0x02, 1, 2, 3, 4, 0, 80];
        assert!(parse_socks5_udp_packet(&packet).is_err());
    }

    #[test]
    fn rejects_short_ipv4_packet() {
        let packet = [0x00, 0x00, 0x00, 0x01, 192, 168];
        assert!(parse_socks5_udp_packet(&packet).is_err());
    }

    #[test]
    fn rejects_short_ipv6_packet() {
        let packet = [
            0x00, 0x00, 0x00, 0x04, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        assert!(parse_socks5_udp_packet(&packet).is_err());
    }

    #[test]
    fn rejects_short_domain_packet() {
        let packet = [0x00, 0x00, 0x00, 0x03, 5, b'h', b'e'];
        assert!(parse_socks5_udp_packet(&packet).is_err());
    }

    #[test]
    fn rejects_invalid_domain_utf8() {
        let packet = [0x00, 0x00, 0x00, 0x03, 3, 0xFF, 0xFE, 0xFD, 0x00, 0x50];
        assert!(parse_socks5_udp_packet(&packet).is_err());
    }

    #[test]
    fn rejects_domain_name_too_long() {
        let long_domain = "a".repeat(256);
        let dest = Destination::new(long_domain, 80);
        assert!(build_socks5_udp_packet(&dest, b"x").is_err());
    }

    #[test]
    fn build_udp_associate_reply_ipv4() {
        let addr: std::net::SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let reply = build_udp_associate_reply(addr);
        assert_eq!(reply[0], 0x05);
        assert_eq!(reply[1], 0x00);
        assert_eq!(reply[2], 0x00);
        assert_eq!(reply[3], 0x01);
        assert_eq!(&reply[4..8], &[127, 0, 0, 1]);
        assert_eq!(u16::from_be_bytes([reply[8], reply[9]]), 12345);
    }

    #[test]
    fn build_udp_associate_reply_ipv6() {
        let addr: std::net::SocketAddr = "[::1]:54321".parse().unwrap();
        let reply = build_udp_associate_reply(addr);
        assert_eq!(reply[0], 0x05);
        assert_eq!(reply[1], 0x00);
        assert_eq!(reply[2], 0x00);
        assert_eq!(reply[3], 0x04);
        assert_eq!(&reply[4..20], &std::net::Ipv6Addr::LOCALHOST.octets());
        assert_eq!(u16::from_be_bytes([reply[20], reply[21]]), 54321);
    }

    #[test]
    fn roundtrip_all_address_types() {
        let ipv4 = Destination::new("10.0.0.1", 443);
        let built = build_socks5_udp_packet(&ipv4, b"data").unwrap();
        let (parsed, _) = parse_socks5_udp_packet(&built).unwrap();
        assert_eq!(parsed, ipv4);

        let ipv6 = Destination::new("fe80::1", 8080);
        let built = build_socks5_udp_packet(&ipv6, b"data").unwrap();
        let (parsed, _) = parse_socks5_udp_packet(&built).unwrap();
        assert_eq!(parsed, ipv6);

        let domain = Destination::new("test.example.org", 53);
        let built = build_socks5_udp_packet(&domain, b"data").unwrap();
        let (parsed, _) = parse_socks5_udp_packet(&built).unwrap();
        assert_eq!(parsed, domain);
    }
}
