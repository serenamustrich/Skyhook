use std::{collections::BTreeSet, net::IpAddr, sync::Arc};

use anyhow::Context;
use serde::Serialize;
use tproxy_config::IpCidr;
use tun2proxy::{ArgDns, ArgProxy, ArgVerbosity, Args, CancellationToken, ProxyType, DEFAULT_MTU};

use crate::{
    config::{OutboundConfig, SuperConfig, TunBackend, TunDnsStrategy},
    core::Runtime,
};

#[derive(Debug, Clone, Serialize)]
pub struct TunProfile {
    pub enabled: bool,
    pub backend: &'static str,
    pub l3_profile: Option<String>,
    pub proxy: String,
    pub setup: bool,
    pub route_mode: String,
    pub dns_strategy: TunDnsStrategy,
    pub dns_addr: IpAddr,
    pub virtual_dns_pool: String,
    pub ipv6: bool,
    pub mtu: u16,
    pub tcp_timeout_secs: u64,
    pub udp_timeout_secs: u64,
    pub max_sessions: usize,
    pub bypass: Vec<String>,
    pub warnings: Vec<String>,
}

pub async fn serve(runtime: Arc<Runtime>) -> anyhow::Result<()> {
    let runtime_config = runtime.config();
    let config = runtime_config.tun.clone();
    if !config.enabled {
        return Ok(());
    }

    if config.backend != TunBackend::Tun2Proxy {
        return Ok(());
    }

    let mut args = Args::default();
    args.proxy = ArgProxy {
        proxy_type: ProxyType::Socks5,
        addr: runtime_config.core.mixed_listen,
        credentials: None,
    };
    args.setup = effective_setup(&runtime_config);
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
    for bypass in effective_bypass(&runtime_config) {
        args.bypass
            .push(parse_bypass(&bypass).with_context(|| format!("invalid tun bypass {bypass}"))?);
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
                args.setup,
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

pub fn profile(config: &SuperConfig) -> TunProfile {
    let mut warnings = Vec::new();

    if config.tun.backend == TunBackend::Tun2Proxy {
        if config.tun.enabled && !effective_setup(config) {
            warnings.push(
                "tun is enabled without setup/auto_route; only an already-routed tun device will work"
                    .to_string(),
            );
        }
        if config.tun.auto_detect_interface {
            warnings.push(
                "auto_detect_interface is advisory in the current backend; routing setup protects known proxy server IPs"
                    .to_string(),
            );
        }
        if !config.tun.inet4_address.is_empty() || !config.tun.inet6_address.is_empty() {
            warnings.push(
                "tun2proxy backend owns interface addressing; inet*_address is preserved for clients but not applied directly"
                    .to_string(),
            );
        }
    }

    TunProfile {
        enabled: config.tun.enabled && config.tun.backend == TunBackend::Tun2Proxy,
        backend: "tun2proxy",
        l3_profile: None,
        proxy: format!("socks5://{}", config.core.mixed_listen),
        setup: effective_setup(config),
        route_mode: route_mode(config),
        dns_strategy: config.tun.dns_strategy,
        dns_addr: config.tun.dns_addr,
        virtual_dns_pool: config.dns.fake_ip_range.clone(),
        ipv6: config.tun.ipv6,
        mtu: if config.tun.mtu == 0 {
            DEFAULT_MTU
        } else {
            config.tun.mtu
        },
        tcp_timeout_secs: config.tun.tcp_timeout_secs,
        udp_timeout_secs: config.tun.udp_timeout_secs,
        max_sessions: config.tun.max_sessions,
        bypass: effective_bypass(config),
        warnings,
    }
}

fn effective_setup(config: &SuperConfig) -> bool {
    config.tun.setup || config.tun.auto_route || config.tun.strict_route || config.tun.auto_redirect
}

fn route_mode(config: &SuperConfig) -> String {
    if config.tun.strict_route {
        "strict-route".to_string()
    } else if config.tun.auto_redirect {
        "auto-redirect".to_string()
    } else if config.tun.auto_route {
        "auto-route".to_string()
    } else if config.tun.setup {
        "setup".to_string()
    } else {
        "manual".to_string()
    }
}

fn effective_bypass(config: &SuperConfig) -> Vec<String> {
    let mut items = BTreeSet::new();
    for value in config
        .tun
        .bypass
        .iter()
        .chain(config.tun.route_exclude_address.iter())
    {
        let value = value.trim();
        if !value.is_empty() {
            items.insert(value.to_string());
        }
    }
    if config.tun.auto_bypass_private {
        for cidr in [
            "0.0.0.0/8",
            "10.0.0.0/8",
            "100.64.0.0/10",
            "127.0.0.0/8",
            "169.254.0.0/16",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "224.0.0.0/4",
            "240.0.0.0/4",
            "::1/128",
            "fc00::/7",
            "fe80::/10",
        ] {
            items.insert(cidr.to_string());
        }
    }
    if config.tun.auto_bypass_proxy_servers {
        for outbound in &config.outbounds {
            if let Some(server) = outbound_server_ip(outbound) {
                items.insert(server);
            }
        }
    }
    items.into_iter().collect()
}

fn outbound_server_ip(outbound: &OutboundConfig) -> Option<String> {
    let server = match outbound {
        OutboundConfig::Http { server, .. }
        | OutboundConfig::Socks5 { server, .. }
        | OutboundConfig::Shadowsocks { server, .. }
        | OutboundConfig::Trojan { server, .. }
        | OutboundConfig::Vmess { server, .. }
        | OutboundConfig::Vless { server, .. }
        | OutboundConfig::Hysteria2 { server, .. }
        | OutboundConfig::Tuic { server, .. }
        | OutboundConfig::Naive { server, .. }
        | OutboundConfig::Ssr { server, .. }
        | OutboundConfig::Snell { server, .. }
        | OutboundConfig::Hysteria { server, .. }
        | OutboundConfig::AnyTls { server, .. }
        | OutboundConfig::ShadowTls { server, .. }
        | OutboundConfig::WireGuard { server, .. }
        | OutboundConfig::Ssh { server, .. }
        | OutboundConfig::Mieru { server, .. }
        | OutboundConfig::Juicity { server, .. }
        | OutboundConfig::Masque { server, .. } => server.as_str(),
        OutboundConfig::Unknown { server, .. } => server.as_deref()?,
        OutboundConfig::Direct { .. }
        | OutboundConfig::Reject { .. }
        | OutboundConfig::OpenVpn { .. }
        | OutboundConfig::Group { .. } => return None,
    };
    server.parse::<IpAddr>().ok().map(|ip| match ip {
        IpAddr::V4(ip) => format!("{ip}/32"),
        IpAddr::V6(ip) => format!("{ip}/128"),
    })
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
