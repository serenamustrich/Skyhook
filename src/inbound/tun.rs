use std::{net::IpAddr, sync::Arc};

use anyhow::Context;
use tproxy_config::IpCidr;
use tun2proxy::{ArgDns, ArgProxy, ArgVerbosity, Args, CancellationToken, ProxyType, DEFAULT_MTU};

use crate::{config::TunDnsStrategy, core::Runtime};

pub async fn serve(runtime: Arc<Runtime>) -> anyhow::Result<()> {
    let runtime_config = runtime.config();
    let config = runtime_config.tun.clone();
    if !config.enabled {
        return Ok(());
    }

    let mut args = Args::default();
    args.proxy = ArgProxy {
        proxy_type: ProxyType::Socks5,
        addr: runtime_config.core.mixed_listen,
        credentials: None,
    };
    args.setup = config.setup;
    args.mtu = config.mtu;
    args.dns = dns_strategy(config.dns_strategy);
    args.dns_addr = config.dns_addr;
    if let Ok(pool) = runtime_config.dns.fake_ip_range.parse::<IpCidr>() {
        args.virtual_dns_pool = pool;
    }
    args.ipv6_enabled = config.ipv6;
    args.tcp_timeout = config.tcp_timeout_secs;
    args.udp_timeout = config.udp_timeout_secs;
    args.max_sessions = config.max_sessions;
    args.verbosity = ArgVerbosity::Info;
    if let Some(name) = config.name.clone() {
        args.tun = Some(name);
    }
    for bypass in config
        .bypass
        .iter()
        .chain(config.route_exclude_address.iter())
    {
        args.bypass
            .push(parse_bypass(bypass).with_context(|| format!("invalid tun bypass {bypass}"))?);
    }
    if let Some(server) = config.udpgw_server {
        args.udpgw_server = Some(server);
    }

    runtime
        .telemetry()
        .log(
            "info",
            format!(
                "tun inbound starting: proxy=socks5://{}, stack={:?}, setup={}, auto_route={}, auto_detect_interface={}, strict_route={}, auto_redirect={}, endpoint_independent_nat={}, dns={:?}, dns_hijack={:?}, mtu={}",
                runtime_config.core.mixed_listen,
                config.stack,
                config.setup,
                config.auto_route,
                config.auto_detect_interface,
                config.strict_route,
                config.auto_redirect,
                config.endpoint_independent_nat,
                config.dns_strategy,
                config.dns_hijack,
                config.mtu
            ),
        )
        .await;

    let shutdown = CancellationToken::new();
    let mtu = if config.mtu == 0 {
        DEFAULT_MTU
    } else {
        config.mtu
    };
    let packet_information = cfg!(target_os = "macos");
    tun2proxy::general_run_async(args, mtu, packet_information, shutdown)
        .await
        .map(|_| ())
        .map_err(anyhow::Error::from)
}

fn dns_strategy(strategy: TunDnsStrategy) -> ArgDns {
    match strategy {
        TunDnsStrategy::Direct => ArgDns::Direct,
        TunDnsStrategy::OverTcp => ArgDns::OverTcp,
        TunDnsStrategy::Virtual => ArgDns::Virtual,
    }
}

fn parse_bypass(value: &str) -> anyhow::Result<IpCidr> {
    if let Ok(cidr) = value.parse::<IpCidr>() {
        return Ok(cidr);
    }
    let ip = value.parse::<IpAddr>()?;
    let with_prefix = match ip {
        IpAddr::V4(ip) => format!("{ip}/32"),
        IpAddr::V6(ip) => format!("{ip}/128"),
    };
    Ok(with_prefix.parse()?)
}
