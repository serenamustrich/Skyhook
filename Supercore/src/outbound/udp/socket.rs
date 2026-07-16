use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use anyhow::{anyhow, Context};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;

use crate::outbound::{context::active_dial_context, transports::bind_interface};

pub(crate) fn create_bound_std_udp(remote: SocketAddr) -> anyhow::Result<std::net::UdpSocket> {
    let socket = Socket::new(
        Domain::for_address(remote),
        Type::DGRAM,
        Some(Protocol::UDP),
    )?;
    socket.set_nonblocking(true)?;

    let active = active_dial_context();
    if let Some(interface_name) = active
        .as_ref()
        .and_then(|context| context.interface_name.as_deref())
    {
        bind_interface(&socket, remote, interface_name)
            .with_context(|| format!("failed to bind UDP socket to interface {interface_name}"))?;
    }
    let bind_address = match active.as_ref().and_then(|context| context.bind_address) {
        Some(source) if source.is_ipv4() == remote.is_ipv4() => source,
        Some(source) => {
            return Err(anyhow!(
                "UDP source address {source} does not match destination family {remote}"
            ));
        }
        None if remote.is_ipv6() => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        None => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
    };
    socket.bind(&bind_address.into())?;
    Ok(socket.into())
}

pub(crate) fn create_bound_udp(remote: SocketAddr) -> anyhow::Result<UdpSocket> {
    UdpSocket::from_std(create_bound_std_udp(remote)?).context("failed to create Tokio UDP socket")
}
