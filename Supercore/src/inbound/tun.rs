use std::{collections::HashSet, net::IpAddr, process::Command, sync::Arc};

use anyhow::Context;
use tokio::{
    task::JoinHandle,
    time::{sleep, Duration, Instant},
};
use tokio_util::sync::CancellationToken;
use tproxy_config::IpCidr;
use tun2proxy::{ArgDns, ArgProxy, ArgVerbosity, Args, ProxyType, DEFAULT_MTU};

use crate::{
    config::{TunConfig, TunDnsStrategy, TunStack},
    core::{Runtime, TunRuntimeStatus},
};

#[allow(clippy::field_reassign_with_default)]
pub async fn serve(runtime: Arc<Runtime>) -> anyhow::Result<()> {
    let shutdown = runtime.cancellation_token();
    serve_with_shutdown(runtime, shutdown).await
}

/// Run one TUN instance with a caller-owned cancellation token.
///
/// The main process uses this entry point from its config supervisor so a
/// LaunchDaemon can turn TUN on or off through `/v1/config/reload` without
/// restarting the privileged process.
#[allow(clippy::field_reassign_with_default)]
pub async fn serve_with_shutdown(
    runtime: Arc<Runtime>,
    shutdown: CancellationToken,
) -> anyhow::Result<()> {
    let runtime_config = runtime.config();
    let config = runtime_config.tun.clone();
    if !config.enabled {
        runtime.set_tun_runtime_status(TunRuntimeStatus::Disabled);
        return Ok(());
    }
    if let Err(error) = validate_supported_config(&config) {
        runtime.set_tun_runtime_status(TunRuntimeStatus::Failed(error.to_string()));
        return Err(error);
    }

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

    let mtu = if config.mtu == 0 {
        DEFAULT_MTU
    } else {
        config.mtu
    };
    let packet_information = cfg!(target_os = "macos");
    let existing_interfaces = network_interfaces()?;
    runtime.set_tun_runtime_status(TunRuntimeStatus::Starting);
    let tun_shutdown = shutdown.clone();
    let monitor_shutdown = shutdown.child_token();
    let monitor = tokio::spawn(wait_for_tun_device(
        config.name.clone(),
        existing_interfaces,
        monitor_shutdown.clone(),
    ));
    let tun_task = tokio::spawn(async move {
        tun2proxy::general_run_async(args, mtu, packet_information, shutdown).await
    });
    await_tun_start(runtime, tun_shutdown, monitor_shutdown, monitor, tun_task).await
}

async fn await_tun_start(
    runtime: Arc<Runtime>,
    tun_shutdown: CancellationToken,
    monitor_shutdown: CancellationToken,
    mut monitor: JoinHandle<anyhow::Result<String>>,
    mut tun_task: JoinHandle<std::io::Result<usize>>,
) -> anyhow::Result<()> {
    tokio::select! {
        result = &mut tun_task => {
            monitor_shutdown.cancel();
            let _ = monitor.await;
            finish_tun_task(&runtime, &tun_shutdown, result).await
        }
        ready = &mut monitor => {
            let device = match ready {
                Ok(Ok(device)) => device,
                Ok(Err(error)) => {
                    tun_shutdown.cancel();
                    monitor_shutdown.cancel();
                    let _ = tun_task.await;
                    runtime.set_tun_runtime_status(TunRuntimeStatus::Failed(error.to_string()));
                    return Err(error);
                }
                Err(error) => {
                    tun_shutdown.cancel();
                    monitor_shutdown.cancel();
                    let _ = tun_task.await;
                    let error = anyhow::anyhow!("TUN readiness monitor failed: {error}");
                    runtime.set_tun_runtime_status(TunRuntimeStatus::Failed(error.to_string()));
                    return Err(error);
                }
            };
            runtime.set_tun_runtime_status(TunRuntimeStatus::Running);
            runtime
                .telemetry()
                .log("info", format!("TUN device ready: {device}"))
                .await;
            finish_tun_task(&runtime, &tun_shutdown, tun_task.await).await
        }
    }
}

async fn finish_tun_task(
    runtime: &Runtime,
    shutdown: &CancellationToken,
    result: Result<std::io::Result<usize>, tokio::task::JoinError>,
) -> anyhow::Result<()> {
    match result {
        Ok(Ok(_)) => {
            runtime.set_tun_runtime_status(TunRuntimeStatus::Disabled);
            Ok(())
        }
        Ok(Err(_error)) if shutdown.is_cancelled() => {
            runtime.set_tun_runtime_status(TunRuntimeStatus::Disabled);
            Ok(())
        }
        Ok(Err(error)) => {
            runtime.set_tun_runtime_status(TunRuntimeStatus::Failed(error.to_string()));
            Err(error.into())
        }
        Err(_error) if shutdown.is_cancelled() => {
            runtime.set_tun_runtime_status(TunRuntimeStatus::Disabled);
            Ok(())
        }
        Err(error) => {
            let error = anyhow::anyhow!("TUN task join failed: {error}");
            runtime.set_tun_runtime_status(TunRuntimeStatus::Failed(error.to_string()));
            Err(error)
        }
    }
}

async fn wait_for_tun_device(
    expected_name: Option<String>,
    before: HashSet<String>,
    shutdown: CancellationToken,
) -> anyhow::Result<String> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if shutdown.is_cancelled() {
            return Err(anyhow::anyhow!("TUN startup cancelled"));
        }
        let current = network_interfaces()?;
        if let Some(name) = expected_name.as_deref() {
            if current.contains(name) && interface_is_up(name)? {
                return Ok(name.to_string());
            }
        } else if let Some(name) = current
            .difference(&before)
            .filter(|name| is_tun_interface(name))
            .find(|name| interface_is_up(name).unwrap_or(false))
        {
            return Ok(name.clone());
        }
        if Instant::now() >= deadline {
            return Err(anyhow::anyhow!(
                "TUN device did not appear within 10 seconds"
            ));
        }
        tokio::select! {
            _ = shutdown.cancelled() => return Err(anyhow::anyhow!("TUN startup cancelled")),
            _ = sleep(Duration::from_millis(100)) => {}
        }
    }
}

fn network_interfaces() -> anyhow::Result<HashSet<String>> {
    if !cfg!(target_os = "macos") {
        return Ok(HashSet::from(["tun-runtime".to_string()]));
    }
    let output = Command::new("/sbin/ifconfig")
        .arg("-l")
        .output()
        .context("failed to list macOS network interfaces")?;
    if !output.status.success() {
        return Err(anyhow::anyhow!(
            "ifconfig -l failed with status {}",
            output.status
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .map(str::to_string)
        .collect())
}

fn is_tun_interface(name: &str) -> bool {
    name.starts_with("utun") || name.starts_with("tun")
}

fn interface_is_up(name: &str) -> anyhow::Result<bool> {
    if !cfg!(target_os = "macos") {
        return Ok(true);
    }
    let output = Command::new("/sbin/ifconfig")
        .arg(name)
        .output()
        .with_context(|| format!("failed to inspect TUN interface {name}"))?;
    if !output.status.success() {
        return Ok(false);
    }
    let first_line = String::from_utf8_lossy(&output.stdout)
        .lines()
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();
    Ok(first_line.contains("<UP") || first_line.contains(",UP") || first_line.contains(" UP"))
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
    #[allow(clippy::field_reassign_with_default)]
    fn unsupported_tun_options_fail_explicitly() {
        let mut config = TunConfig::default();
        config.strict_route = true;
        let error = validate_supported_config(&config).unwrap_err().to_string();
        assert!(error.contains("strict_route"));
    }

    #[test]
    fn tun_interface_names_are_classified_without_matching_regular_adapters() {
        assert!(is_tun_interface("utun7"));
        assert!(is_tun_interface("tun0"));
        assert!(!is_tun_interface("en0"));
    }
}
