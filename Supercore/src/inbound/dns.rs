use std::{
    collections::HashSet,
    fs,
    net::{IpAddr, SocketAddr},
    process::Command,
    sync::Arc,
};

use anyhow::{anyhow, Context};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    task::JoinSet,
    time::{timeout_at, Duration, Instant},
};
use tokio_util::sync::CancellationToken;

use crate::core::Runtime;
use crate::inbound::fakeip::{build_fake_ip_dns_response, extract_domain_from_dns_query};

pub async fn serve(runtime: Arc<Runtime>) -> anyhow::Result<()> {
    let config = runtime.config().dns;
    if !config.enabled {
        return Ok(());
    }
    let Some(listen) = config.listen else {
        return Ok(());
    };

    let udp = Arc::new(
        UdpSocket::bind(listen)
            .await
            .with_context(|| format!("failed to bind dns udp listener {listen}"))?,
    );
    let tcp = TcpListener::bind(listen)
        .await
        .with_context(|| format!("failed to bind dns tcp listener {listen}"))?;

    let enhanced_mode = config.enhanced_mode;
    runtime
        .telemetry()
        .log(
            "info",
            format!(
                "dns listener on {listen}, enhanced_mode={:?}, cache={:?}, respect_rules={}",
                config.enhanced_mode, config.cache_algorithm, config.respect_rules
            ),
        )
        .await;

    tokio::try_join!(
        serve_udp(runtime.clone(), udp, enhanced_mode),
        serve_tcp(runtime, tcp, enhanced_mode)
    )?;
    Ok(())
}

async fn serve_udp(
    runtime: Arc<Runtime>,
    udp: Arc<UdpSocket>,
    enhanced_mode: crate::config::DnsEnhancedMode,
) -> anyhow::Result<()> {
    let mut buf = vec![0u8; 65_535];
    let shutdown = runtime.cancellation_token();
    let mut queries = JoinSet::new();
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            Some(result) = queries.join_next(), if !queries.is_empty() => {
                if let Err(error) = result {
                    runtime
                        .telemetry()
                        .log("warn", format!("dns udp task failed: {error}"))
                        .await;
                }
            }
            received = udp.recv_from(&mut buf) => {
                let (len, peer) = received?;
                let query = buf[..len].to_vec();
                let runtime = runtime.clone();
                let udp = udp.clone();
                queries.spawn(async move {
                    if let crate::config::DnsEnhancedMode::FakeIp = enhanced_mode {
                        if let Some(domain) = extract_domain_from_dns_query(&query) {
                            if let Some(fake_ip) = runtime.fakeip_store().lookup_or_create(&domain).await {
                                let response = build_fake_ip_dns_response(&query, &domain, fake_ip);
                                if !response.is_empty() {
                                    let _ = udp.send_to(&response, peer).await;
                                    return;
                                }
                            }
                        }
                    }

                    match runtime.exchange_dns_over_tcp(&query).await {
                        Ok(response) => {
                            let _ = udp.send_to(&response, peer).await;
                        }
                        Err(_) if runtime.is_shutting_down() => {}
                        Err(error) => {
                            runtime
                                .telemetry()
                                .log(
                                    "warn",
                                    format!("dns udp query from {peer} failed, trying system DNS fallback: {error:#}"),
                                )
                                .await;
                            if let Ok(system_response) = fallback_system_dns(runtime.as_ref(), &query).await {
                                let _ = udp.send_to(&system_response, peer).await;
                            }
                        }
                    }
                });
            }
        }
    }
    queries.abort_all();
    while queries.join_next().await.is_some() {}
    Ok(())
}

async fn fallback_system_dns(runtime: &Runtime, query: &[u8]) -> anyhow::Result<Vec<u8>> {
    let config = runtime.config();
    let cancellation = runtime.cancellation_token();
    let mut servers = discover_system_dns_servers();
    servers.extend(
        config
            .dns
            .direct_nameserver
            .iter()
            .chain(config.dns.default_nameserver.iter())
            .chain(config.dns.nameserver.iter())
            .filter_map(|item| parse_plain_dns_server(item)),
    );
    servers.push(config.dns.server);

    let mut seen = HashSet::new();
    servers.retain(|server| {
        let is_core_listener = config.dns.listen.is_some_and(|listen| listen == *server);
        !is_core_listener && seen.insert(*server)
    });

    let timeout_ms = config.dns.timeout_ms.clamp(100, 10_000);
    let mut errors = Vec::new();
    for server in servers {
        match exchange_system_dns_server(
            server,
            query,
            Duration::from_millis(timeout_ms),
            &cancellation,
        )
        .await
        {
            Ok(response) => {
                runtime
                    .telemetry()
                    .log("debug", format!("system DNS fallback succeeded via {server}"))
                    .await;
                return Ok(response);
            }
            Err(error) => errors.push(format!("{server}: {error}")),
        }
    }
    Err(anyhow!(
        "all system DNS fallbacks failed: {}",
        errors.join("; ")
    ))
}

pub(crate) async fn exchange_system_dns_server(
    server: SocketAddr,
    query: &[u8],
    timeout_budget: Duration,
    cancellation: &CancellationToken,
) -> anyhow::Result<Vec<u8>> {
    if query.len() > u16::MAX as usize {
        anyhow::bail!("dns query is too large");
    }
    let deadline = Instant::now() + timeout_budget;
    // Reserve half of the resolver budget for TCP. A silent UDP resolver must
    // not consume the entire budget and prevent the reliable fallback path.
    let udp_deadline = Instant::now() + timeout_budget / 2;
    let bind_addr = match server.ip() {
        IpAddr::V4(_) => "0.0.0.0:0",
        IpAddr::V6(_) => "[::]:0",
    };
    let socket = UdpSocket::bind(bind_addr).await?;
    let udp_result = tokio::select! {
        _ = cancellation.cancelled() => return Err(anyhow!("dns fallback cancelled")),
        result = timeout_at(udp_deadline, exchange_system_dns_udp(&socket, server, query)) => {
            match result {
                Ok(result) => result,
                Err(_) => Err(anyhow!("udp timed out")),
            }
        }
    };
    match udp_result {
        Ok(response) => Ok(response),
        Err(udp_error) => {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(udp_error.context("udp failed and no time remained for tcp"));
            }
            let tcp_result = tokio::select! {
                _ = cancellation.cancelled() => return Err(anyhow!("dns fallback cancelled")),
                result = timeout_at(deadline, exchange_system_dns_tcp(server, query)) => {
                    match result {
                        Ok(result) => result,
                        Err(_) => Err(anyhow!("tcp timed out")),
                    }
                }
            };
            tcp_result.map_err(|tcp_error| {
                anyhow!("udp: {udp_error}; tcp: {tcp_error}")
            })
        }
    }
}

async fn exchange_system_dns_udp(
    socket: &UdpSocket,
    server: SocketAddr,
    query: &[u8],
) -> anyhow::Result<Vec<u8>> {
    socket.send_to(query, server).await?;
    let mut buf = vec![0u8; 65_535];
    loop {
        let (len, source) = socket.recv_from(&mut buf).await?;
        if source != server {
            continue;
        }
        let response = &buf[..len];
        validate_dns_response(query, response)?;
        if response[2] & 0x02 != 0 {
            anyhow::bail!("udp response is truncated");
        }
        return Ok(response.to_vec());
    }
}

async fn exchange_system_dns_tcp(
    server: SocketAddr,
    query: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let mut stream = TcpStream::connect(server).await?;
    stream.set_nodelay(true)?;
    stream.write_all(&(query.len() as u16).to_be_bytes()).await?;
    stream.write_all(query).await?;
    let mut len = [0u8; 2];
    stream.read_exact(&mut len).await?;
    let response_len = u16::from_be_bytes(len) as usize;
    if response_len < 12 {
        anyhow::bail!("tcp DNS response is too short");
    }
    let mut response = vec![0u8; response_len];
    stream.read_exact(&mut response).await?;
    validate_dns_response(query, &response)?;
    Ok(response)
}

fn validate_dns_response(query: &[u8], response: &[u8]) -> anyhow::Result<()> {
    if query.len() < 2 || response.len() < 12 {
        anyhow::bail!("invalid DNS response");
    }
    if response[0..2] != query[0..2] {
        anyhow::bail!("DNS transaction id mismatch");
    }
    if response[2] & 0x80 == 0 {
        anyhow::bail!("DNS response is not a response packet");
    }
    Ok(())
}

pub(crate) fn discover_system_dns_servers() -> Vec<SocketAddr> {
    let mut servers = Vec::new();
    #[cfg(target_os = "macos")]
    {
        if let Ok(output) = Command::new("/usr/sbin/scutil").arg("--dns").output() {
            if output.status.success() {
                servers.extend(parse_scutil_dns_servers(&String::from_utf8_lossy(
                    &output.stdout,
                )));
            }
        }
    }
    if let Ok(contents) = fs::read_to_string("/etc/resolv.conf") {
        servers.extend(parse_resolv_conf_servers(&contents));
    }
    servers
}

fn parse_scutil_dns_servers(output: &str) -> Vec<SocketAddr> {
    output
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if !line.starts_with("nameserver[") {
                return None;
            }
            line.split_once(':')
                .and_then(|(_, value)| parse_dns_ip(value.trim()))
                .map(|ip| SocketAddr::new(ip, 53))
        })
        .collect()
}

fn parse_resolv_conf_servers(contents: &str) -> Vec<SocketAddr> {
    contents
        .lines()
        .filter_map(|line| {
            let line = line.split('#').next()?.trim();
            let value = line.strip_prefix("nameserver")?.trim();
            parse_dns_ip(value).map(|ip| SocketAddr::new(ip, 53))
        })
        .collect()
}

fn parse_dns_ip(value: &str) -> Option<IpAddr> {
    value
        .split('%')
        .next()
        .and_then(|value| value.trim().parse().ok())
}

pub(crate) fn parse_plain_dns_server(value: &str) -> Option<SocketAddr> {
    let value = value.trim();
    if let Ok(server) = value.parse() {
        return Some(server);
    }
    if let Some(ip) = parse_dns_ip(value) {
        return Some(SocketAddr::new(ip, 53));
    }
    let value = value
        .strip_prefix("udp://")
        .or_else(|| value.strip_prefix("tcp://"))
        .or_else(|| value.strip_prefix("dns://"))?;
    value
        .parse()
        .ok()
        .or_else(|| parse_dns_ip(value).map(|ip| SocketAddr::new(ip, 53)))
}

async fn serve_tcp(
    runtime: Arc<Runtime>,
    tcp: TcpListener,
    enhanced_mode: crate::config::DnsEnhancedMode,
) -> anyhow::Result<()> {
    let shutdown = runtime.cancellation_token();
    let mut clients = JoinSet::new();
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            Some(result) = clients.join_next(), if !clients.is_empty() => {
                if let Err(error) = result {
                    runtime
                        .telemetry()
                        .log("warn", format!("dns tcp task failed: {error}"))
                        .await;
                }
            }
            accepted = tcp.accept() => {
                let (stream, peer) = accepted?;
                let runtime = runtime.clone();
                clients.spawn(async move {
                    if let Err(error) = handle_tcp_client(runtime.clone(), stream, enhanced_mode).await {
                        runtime
                            .telemetry()
                            .log("warn", format!("dns tcp client {peer} failed: {error:#}"))
                            .await;
                    }
                });
            }
        }
    }
    clients.abort_all();
    while clients.join_next().await.is_some() {}
    Ok(())
}

async fn handle_tcp_client(
    runtime: Arc<Runtime>,
    mut stream: TcpStream,
    enhanced_mode: crate::config::DnsEnhancedMode,
) -> anyhow::Result<()> {
    let shutdown = runtime.cancellation_token();
    loop {
        let mut len = [0u8; 2];
        let read = tokio::select! {
            _ = shutdown.cancelled() => return Ok(()),
            result = stream.read_exact(&mut len) => result,
        };
        match read {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(error) => return Err(error.into()),
        }
        let query_len = u16::from_be_bytes(len) as usize;
        let mut query = vec![0u8; query_len];
        stream.read_exact(&mut query).await?;

        let response = if let crate::config::DnsEnhancedMode::FakeIp = enhanced_mode {
            if let Some(domain) = extract_domain_from_dns_query(&query) {
                if let Some(fake_ip) = runtime.fakeip_store().lookup_or_create(&domain).await {
                    let resp = build_fake_ip_dns_response(&query, &domain, fake_ip);
                    if !resp.is_empty() {
                        resp
                    } else {
                        runtime.exchange_dns_over_tcp(&query).await?
                    }
                } else {
                    runtime.exchange_dns_over_tcp(&query).await?
                }
            } else {
                runtime.exchange_dns_over_tcp(&query).await?
            }
        } else {
            runtime.exchange_dns_over_tcp(&query).await?
        };

        if response.len() > u16::MAX as usize {
            anyhow::bail!("dns response is too large");
        }
        stream
            .write_all(&(response.len() as u16).to_be_bytes())
            .await?;
        stream.write_all(&response).await?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_macos_scutil_dns_servers() {
        let output = r#"
        resolver #1
          nameserver[0] : 192.168.1.1
          nameserver[1] : 2001:db8::53
        "#;
        assert_eq!(
            parse_scutil_dns_servers(output),
            vec![
                "192.168.1.1:53".parse().unwrap(),
                "[2001:db8::53]:53".parse().unwrap(),
            ]
        );
    }

    #[test]
    fn parses_resolv_conf_dns_servers() {
        let contents = r#"
        # generated
        nameserver 10.0.0.1
        nameserver 2001:4860:4860::8888
        "#;
        assert_eq!(
            parse_resolv_conf_servers(contents),
            vec![
                "10.0.0.1:53".parse().unwrap(),
                "[2001:4860:4860::8888]:53".parse().unwrap(),
            ]
        );
    }

    #[tokio::test]
    async fn falls_back_to_tcp_when_udp_has_no_responder() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server = listener.local_addr().unwrap();
        let query = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm',
            0x00, 0x00, 0x01, 0x00, 0x01,
        ];
        let response = {
            let mut response = query.clone();
            response[2] = 0x81;
            response[3] = 0x80;
            response
        };
        let response_for_server = response.clone();
        let server_task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut len = [0u8; 2];
            stream.read_exact(&mut len).await.unwrap();
            let mut incoming = vec![0u8; u16::from_be_bytes(len) as usize];
            stream.read_exact(&mut incoming).await.unwrap();
            stream
                .write_all(&(response_for_server.len() as u16).to_be_bytes())
                .await
                .unwrap();
            stream.write_all(&response_for_server).await.unwrap();
        });

        let cancellation = CancellationToken::new();
        let result = exchange_system_dns_server(
            server,
            &query,
            Duration::from_secs(1),
            &cancellation,
        )
        .await
        .unwrap();
        assert_eq!(result, response);
        server_task.await.unwrap();
    }

    #[test]
    fn rejects_dns_response_with_wrong_transaction_id() {
        let query = [0x12, 0x34];
        let mut response = vec![0u8; 12];
        response[2] = 0x80;
        assert!(validate_dns_response(&query, &response).is_err());
    }
}
