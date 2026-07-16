use std::{collections::HashSet, io, net::SocketAddr, time::Duration};

use anyhow::{anyhow, Context};
use socket2::{Domain, Protocol, Socket, TcpKeepalive, Type};
use tokio::{net::TcpStream, task::JoinSet, time::timeout};
use tokio_util::sync::CancellationToken;

use crate::outbound::context::{active_dial_context, IpVersionStrategy};

use super::socket_options::{bind_interface, enable_tcp_fast_open};

const HAPPY_EYEBALLS_DELAY: Duration = Duration::from_millis(250);

#[derive(Clone)]
struct TcpDialOptions {
    source: Option<SocketAddr>,
    interface_name: Option<String>,
    keepalive: Option<Duration>,
    tcp_fast_open: bool,
    multipath_tcp: bool,
    cancellation: CancellationToken,
}

pub(crate) async fn connect_tcp(addr: &str, timeout_ms: u64) -> anyhow::Result<TcpStream> {
    let active = active_dial_context();
    let timeout_budget = active
        .as_ref()
        .map(|context| Duration::from_millis(timeout_ms).min(context.remaining_timeout()))
        .unwrap_or_else(|| Duration::from_millis(timeout_ms));
    if timeout_budget.is_zero() {
        return Err(anyhow!("tcp connect deadline expired for {addr}"));
    }

    let strategy = active
        .as_ref()
        .map(|context| context.ip_version)
        .unwrap_or_default();
    let cancellation = active
        .as_ref()
        .map(|context| context.cancellation.clone())
        .unwrap_or_default();
    let options = TcpDialOptions {
        source: active.as_ref().and_then(|context| context.bind_address),
        interface_name: active
            .as_ref()
            .and_then(|context| context.interface_name.clone()),
        keepalive: active.as_ref().and_then(|context| context.keepalive),
        tcp_fast_open: active.as_ref().is_some_and(|context| context.tcp_fast_open),
        multipath_tcp: active.as_ref().is_some_and(|context| context.multipath_tcp),
        cancellation: cancellation.clone(),
    };

    let resolved = tokio::select! {
        _ = cancellation.cancelled() => return Err(anyhow!("tcp resolve cancelled for {addr}")),
        result = timeout(timeout_budget, tokio::net::lookup_host(addr)) => {
            result
                .context("tcp resolve timed out")?
                .with_context(|| format!("failed to resolve {addr}"))?
                .collect::<Vec<_>>()
        }
    };
    let addresses = order_addresses(resolved, strategy);
    if addresses.is_empty() {
        return Err(anyhow!(
            "{addr} resolved to no addresses matching {strategy:?}"
        ));
    }

    tokio::select! {
        _ = cancellation.cancelled() => Err(anyhow!("tcp connect cancelled for {addr}")),
        result = timeout(timeout_budget, race_addresses(addresses, options)) => {
            result
                .context("tcp connect timed out")?
                .with_context(|| format!("failed to connect {addr}"))
        }
    }
}

async fn race_addresses(
    addresses: Vec<SocketAddr>,
    options: TcpDialOptions,
) -> anyhow::Result<TcpStream> {
    let mut attempts = JoinSet::new();
    for (index, address) in addresses.into_iter().enumerate() {
        let options = options.clone();
        attempts.spawn(async move {
            let delay = HAPPY_EYEBALLS_DELAY.saturating_mul(index as u32);
            if !delay.is_zero() {
                tokio::select! {
                    _ = options.cancellation.cancelled() => {
                        return Err(anyhow!("connect to {address} cancelled"));
                    }
                    _ = tokio::time::sleep(delay) => {}
                }
            }
            connect_socket(address, &options)
                .await
                .with_context(|| format!("connect to {address}"))
        });
    }

    let mut errors = Vec::new();
    while let Some(result) = attempts.join_next().await {
        match result {
            Ok(Ok(stream)) => {
                attempts.abort_all();
                return Ok(stream);
            }
            Ok(Err(error)) => errors.push(error.to_string()),
            Err(error) if error.is_cancelled() => {}
            Err(error) => errors.push(format!("dial task failed: {error}")),
        }
    }

    Err(anyhow!("all addresses failed: {}", errors.join("; ")))
}

async fn connect_socket(
    address: SocketAddr,
    options: &TcpDialOptions,
) -> anyhow::Result<TcpStream> {
    if options.multipath_tcp {
        return Err(anyhow!(
            "MPTCP requires the macOS Network.framework dial backend"
        ));
    }

    let socket = Socket::new(
        Domain::for_address(address),
        Type::STREAM,
        Some(Protocol::TCP),
    )?;
    socket.set_nonblocking(true)?;
    socket.set_tcp_nodelay(true)?;
    if let Some(keepalive) = options.keepalive {
        socket.set_keepalive(true)?;
        socket.set_tcp_keepalive(&TcpKeepalive::new().with_time(keepalive))?;
    }
    if let Some(interface_name) = options.interface_name.as_deref() {
        bind_interface(&socket, address, interface_name)?;
    }
    if let Some(source) = options.source {
        if source.is_ipv4() != address.is_ipv4() {
            return Err(anyhow!(
                "source address {source} does not match destination family {address}"
            ));
        }
        socket.bind(&source.into())?;
    }
    if options.tcp_fast_open {
        enable_tcp_fast_open(&socket)?;
    }

    match socket.connect(&address.into()) {
        Ok(()) => {}
        Err(error) if connect_is_in_progress(&error) => {}
        Err(error) => return Err(error.into()),
    }
    let stream = TcpStream::from_std(socket.into())?;
    tokio::select! {
        _ = options.cancellation.cancelled() => {
            return Err(anyhow!("connect to {address} cancelled"));
        }
        result = stream.writable() => result?,
    }
    if let Some(error) = stream.take_error()? {
        return Err(error.into());
    }
    Ok(stream)
}

fn connect_is_in_progress(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::WouldBlock
        || matches!(
            error.raw_os_error(),
            Some(libc::EINPROGRESS) | Some(libc::EALREADY)
        )
}

pub(crate) fn order_addresses(
    addresses: impl IntoIterator<Item = SocketAddr>,
    strategy: IpVersionStrategy,
) -> Vec<SocketAddr> {
    let mut seen = HashSet::new();
    let addresses = addresses
        .into_iter()
        .filter(|address| seen.insert(*address))
        .collect::<Vec<_>>();
    let mut ipv4 = addresses
        .iter()
        .copied()
        .filter(SocketAddr::is_ipv4)
        .collect::<Vec<_>>();
    let mut ipv6 = addresses
        .iter()
        .copied()
        .filter(SocketAddr::is_ipv6)
        .collect::<Vec<_>>();

    match strategy {
        IpVersionStrategy::Ipv4 => ipv4,
        IpVersionStrategy::Ipv6 => ipv6,
        IpVersionStrategy::PreferIpv4 => interleave(&mut ipv4, &mut ipv6),
        IpVersionStrategy::PreferIpv6 => interleave(&mut ipv6, &mut ipv4),
        IpVersionStrategy::Dual => {
            if addresses.first().is_some_and(SocketAddr::is_ipv6) {
                interleave(&mut ipv6, &mut ipv4)
            } else {
                interleave(&mut ipv4, &mut ipv6)
            }
        }
    }
}

fn interleave(preferred: &mut Vec<SocketAddr>, alternate: &mut Vec<SocketAddr>) -> Vec<SocketAddr> {
    let mut ordered = Vec::with_capacity(preferred.len() + alternate.len());
    let mut preferred = preferred.drain(..);
    let mut alternate = alternate.drain(..);
    loop {
        match (preferred.next(), alternate.next()) {
            (None, None) => break,
            (preferred, alternate) => {
                ordered.extend(preferred);
                ordered.extend(alternate);
            }
        }
    }
    ordered
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    use super::{order_addresses, IpVersionStrategy};

    fn v4(last: u8) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, last)), 443)
    }

    fn v6(last: u16) -> SocketAddr {
        SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, last)),
            443,
        )
    }

    #[test]
    fn filters_single_family_strategies() {
        let addresses = vec![v6(1), v4(1), v6(2), v4(2)];
        assert_eq!(
            order_addresses(addresses.clone(), IpVersionStrategy::Ipv4),
            vec![v4(1), v4(2)]
        );
        assert_eq!(
            order_addresses(addresses, IpVersionStrategy::Ipv6),
            vec![v6(1), v6(2)]
        );
    }

    #[test]
    fn interleaves_preferred_and_alternate_families() {
        let addresses = vec![v4(1), v4(2), v6(1), v6(2)];
        assert_eq!(
            order_addresses(addresses, IpVersionStrategy::PreferIpv6),
            vec![v6(1), v4(1), v6(2), v4(2)]
        );
    }
}
