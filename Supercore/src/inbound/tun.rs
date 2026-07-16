use std::{net::IpAddr, sync::Arc};

use anyhow::Context;
use tproxy_config::IpCidr;
use tun2proxy::{ArgDns, ArgProxy, ArgVerbosity, Args, ProxyType, DEFAULT_MTU};

use crate::{
    config::{TunConfig, TunDnsStrategy, TunStack},
    core::Runtime,
};

pub async fn serve(runtime: Arc<Runtime>) -> anyhow::Result<()> {
    let runtime_config = runtime.config();
    let config = runtime_config.tun.clone();
    if !config.enabled {
        return Ok(());
    }
    validate_supported_config(&config)?;

    let mut args = Args::default();
    args.proxy = ArgProxy {
        proxy_type: ProxyType::Socks5,
        addr: runtime_config.core.mixed_listen,
        credentials: None,
    };
    args.setup = config.setup || config.auto_route;
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
                "tun inbound starting: proxy=socks5://{}, stack={:?}, setup={}, dns={:?}, dns_hijack={:?}, mtu={}",
                runtime_config.core.mixed_listen,
                config.stack,
                args.setup,
                config.dns_strategy,
                config.dns_hijack,
                config.mtu
            ),
        )
        .await;

    let shutdown = runtime.cancellation_token();
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

fn validate_supported_config(config: &TunConfig) -> anyhow::Result<()> {
    let mut unsupported = Vec::new();
    if config.stack != TunStack::System {
        unsupported.push("stack (only system is supported)");
    }
    if config.auto_detect_interface {
        unsupported.push("auto_detect_interface");
    }
    if config.strict_route {
        unsupported.push("strict_route");
    }
    if config.auto_redirect {
        unsupported.push("auto_redirect");
    }
    if config.gso {
        unsupported.push("gso");
    }
    if !config.inet4_address.is_empty()
        || !config.inet6_address.is_empty()
        || !config.inet4_route_address.is_empty()
        || !config.inet6_route_address.is_empty()
    {
        unsupported.push("custom TUN addresses/routes");
    }
    if !config.include_uid.is_empty()
        || !config.include_uid_range.is_empty()
        || !config.exclude_uid.is_empty()
        || !config.exclude_uid_range.is_empty()
        || !config.include_package.is_empty()
        || !config.exclude_package.is_empty()
        || !config.include_process.is_empty()
        || !config.exclude_process.is_empty()
    {
        unsupported.push("UID/package/process filters");
    }
    if unsupported.is_empty() {
        Ok(())
    } else {
        anyhow::bail!(
            "unsupported TUN options for the current tun2proxy backend: {}",
            unsupported.join(", ")
        )
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_tun_config_is_supported() {
        assert!(validate_supported_config(&TunConfig::default()).is_ok());
    }

    #[test]
    fn unsupported_tun_options_fail_explicitly() {
        let mut config = TunConfig::default();
        config.strict_route = true;
        let error = validate_supported_config(&config).unwrap_err().to_string();
        assert!(error.contains("strict_route"));
    }
}
