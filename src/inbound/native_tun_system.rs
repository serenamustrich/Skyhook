use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

use anyhow::{anyhow, Context};
use ipnet::IpNet;
use serde::Serialize;

use crate::config::TunConfig;

pub fn normalize_endpoint_to_cidr(endpoint: &str) -> Vec<String> {
    if let Ok(net) = endpoint.parse::<IpNet>() {
        return vec![net.to_string()];
    }

    if let Ok(ip) = endpoint.parse::<IpAddr>() {
        let cidr = match ip {
            IpAddr::V4(_) => format!("{}/32", ip),
            IpAddr::V6(_) => format!("{}/128", ip),
        };
        return vec![cidr];
    }

    if let Ok(addr) = endpoint.parse::<SocketAddr>() {
        let cidr = match addr.ip() {
            IpAddr::V4(_) => format!("{}/32", addr.ip()),
            IpAddr::V6(_) => format!("{}/128", addr.ip()),
        };
        return vec![cidr];
    }

    if let Some((host, _port)) = endpoint.rsplit_once(':') {
        let host = host.trim_matches(|c| c == '[' || c == ']');
        if let Ok(ip) = host.parse::<IpAddr>() {
            let cidr = match ip {
                IpAddr::V4(_) => format!("{}/32", ip),
                IpAddr::V6(_) => format!("{}/128", ip),
            };
            return vec![cidr];
        }

        if let Ok(addrs) = (host, 0u16).to_socket_addrs() {
            let mut cidrs: Vec<String> = addrs
                .map(|addr| match addr.ip() {
                    IpAddr::V4(_) => format!("{}/32", addr.ip()),
                    IpAddr::V6(_) => format!("{}/128", addr.ip()),
                })
                .collect();
            cidrs.sort();
            cidrs.dedup();
            return cidrs;
        }
    }

    Vec::new()
}

#[derive(Debug)]
pub struct NativeTunDevice {
    pub file: tokio::fs::File,
    pub interface_name: String,
    pub mtu: u16,
}

#[derive(Debug, Clone, Serialize)]
pub struct NativeTunSetupPlan {
    pub interface_name: String,
    pub mtu: u16,
    pub inet4_address: Vec<String>,
    pub inet6_address: Vec<String>,
    pub route_add: Vec<String>,
    pub bypass: Vec<String>,
    pub endpoint_bypass: Vec<String>,
}

#[derive(Debug)]
pub struct NativeTunSetupGuard {
    cleanup_commands: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct NativeTunSetupResult {
    pub installed_routes: Vec<String>,
    pub installed_bypass_routes: Vec<String>,
    pub installed_endpoint_bypass: Vec<String>,
    pub skipped_bypass_routes: Vec<String>,
    pub skipped_endpoint_bypass: Vec<String>,
    pub warnings: Vec<String>,
}

pub struct NativeTunSetupResultWithGuard {
    pub result: NativeTunSetupResult,
    pub guard: NativeTunSetupGuard,
}

#[derive(Debug, Clone, Serialize)]
pub struct DefaultGateway {
    pub gateway: IpAddr,
    pub interface: String,
}

impl NativeTunSetupPlan {
    pub fn from_config(config: &TunConfig, interface_name: String) -> Self {
        let mtu = if config.mtu == 0 { 1500 } else { config.mtu };

        let mut inet4_address = config.inet4_address.clone();
        let inet6_address = config.inet6_address.clone();
        let mut route_add = Vec::new();
        let mut bypass = config.bypass.clone();

        if inet4_address.is_empty() && inet6_address.is_empty() {
            inet4_address.push("198.18.0.1/30".to_string());
        }

        if !config.inet4_route_address.is_empty() || !config.inet6_route_address.is_empty() {
            route_add.extend(config.inet4_route_address.clone());
            route_add.extend(config.inet6_route_address.clone());
        } else if config.auto_route {
            route_add.push("0.0.0.0/1".to_string());
            route_add.push("128.0.0.0/1".to_string());
        }

        bypass.extend(config.route_exclude_address.clone());

        if config.auto_bypass_private {
            bypass.extend([
                "127.0.0.0/8".to_string(),
                "10.0.0.0/8".to_string(),
                "172.16.0.0/12".to_string(),
                "192.168.0.0/16".to_string(),
                "::1/128".to_string(),
                "fc00::/7".to_string(),
                "fe80::/10".to_string(),
            ]);
        }

        NativeTunSetupPlan {
            interface_name,
            mtu,
            inet4_address,
            inet6_address,
            route_add,
            bypass,
            endpoint_bypass: Vec::new(),
        }
    }

    pub fn add_endpoint_bypass(&mut self, endpoints: Vec<String>) {
        for endpoint in &endpoints {
            let cidrs = normalize_endpoint_to_cidr(endpoint);
            if cidrs.is_empty() {
                tracing::warn!(
                    endpoint = endpoint,
                    "native_tun: could not normalize endpoint to CIDR"
                );
            }
            self.endpoint_bypass.extend(cidrs);
        }
    }

    pub fn build_macos_commands(&self, gateway: &Option<DefaultGateway>) -> Vec<SetupCommand> {
        let mut commands = Vec::new();

        for addr in self.inet4_address.iter().chain(self.inet6_address.iter()) {
            if let Ok(net) = addr.parse::<IpNet>() {
                let ip = net.addr();
                let prefix_len = net.prefix_len();
                if net.addr().is_ipv4() {
                    let peer = calculate_peer_address(ip, prefix_len);
                    commands.push(SetupCommand::Ifconfig {
                        interface: self.interface_name.clone(),
                        args: format!(
                            "inet {ip} {peer} netmask {} mtu {} up",
                            prefix_to_mask(prefix_len),
                            self.mtu
                        ),
                    });
                } else {
                    commands.push(SetupCommand::Ifconfig {
                        interface: self.interface_name.clone(),
                        args: format!("inet6 {ip}/{prefix_len} mtu {} up", self.mtu),
                    });
                }
            }
        }

        for cidr in &self.endpoint_bypass {
            if cidr.parse::<IpNet>().is_ok() {
                if let Some(gw) = gateway {
                    commands.push(SetupCommand::RouteAddGateway {
                        cidr: cidr.clone(),
                        gateway: gw.gateway,
                    });
                }
            }
        }

        for cidr in &self.bypass {
            if cidr.parse::<IpNet>().is_ok() {
                if let Some(gw) = gateway {
                    commands.push(SetupCommand::RouteAddGateway {
                        cidr: cidr.clone(),
                        gateway: gw.gateway,
                    });
                }
            }
        }

        for route in &self.route_add {
            if let Ok(net) = route.parse::<IpNet>() {
                if net.addr().is_ipv4() {
                    commands.push(SetupCommand::RouteAddTun {
                        cidr: route.clone(),
                        interface: self.interface_name.clone(),
                    });
                }
            }
        }

        commands
    }

    pub fn build_linux_commands(&self, gateway: &Option<DefaultGateway>) -> Vec<SetupCommand> {
        let mut commands = Vec::new();

        for addr in self.inet4_address.iter().chain(self.inet6_address.iter()) {
            if addr.parse::<IpNet>().is_ok() {
                commands.push(SetupCommand::IpAddrAdd {
                    addr: addr.clone(),
                    interface: self.interface_name.clone(),
                });
            }
        }

        commands.push(SetupCommand::IpLinkSet {
            interface: self.interface_name.clone(),
            mtu: self.mtu,
        });

        for cidr in &self.endpoint_bypass {
            if cidr.parse::<IpNet>().is_ok() {
                if let Some(gw) = gateway {
                    commands.push(SetupCommand::IpRouteAddGateway {
                        cidr: cidr.clone(),
                        gateway: gw.gateway,
                    });
                }
            }
        }

        for cidr in &self.bypass {
            if cidr.parse::<IpNet>().is_ok() {
                if let Some(gw) = gateway {
                    commands.push(SetupCommand::IpRouteAddGateway {
                        cidr: cidr.clone(),
                        gateway: gw.gateway,
                    });
                }
            }
        }

        for route in &self.route_add {
            if route.parse::<IpNet>().is_ok() {
                commands.push(SetupCommand::IpRouteAddTun {
                    cidr: route.clone(),
                    interface: self.interface_name.clone(),
                });
            }
        }

        commands
    }
}

#[derive(Debug, Clone)]
pub enum SetupCommand {
    Ifconfig { interface: String, args: String },
    RouteAddTun { cidr: String, interface: String },
    RouteAddGateway { cidr: String, gateway: IpAddr },
    IpAddrAdd { addr: String, interface: String },
    IpLinkSet { interface: String, mtu: u16 },
    IpRouteAddTun { cidr: String, interface: String },
    IpRouteAddGateway { cidr: String, gateway: IpAddr },
}

impl SetupCommand {
    pub fn is_fatal(&self) -> bool {
        matches!(
            self,
            Self::Ifconfig { .. }
                | Self::IpAddrAdd { .. }
                | Self::IpLinkSet { .. }
                | Self::RouteAddTun { .. }
                | Self::IpRouteAddTun { .. }
        )
    }

    pub fn is_bypass(&self) -> bool {
        matches!(
            self,
            Self::RouteAddGateway { .. } | Self::IpRouteAddGateway { .. }
        )
    }

    pub fn to_shell_command(&self) -> String {
        match self {
            Self::Ifconfig { interface, args } => {
                format!("ifconfig {interface} {args}")
            }
            Self::RouteAddTun { cidr, interface } => {
                format!("route -n add -net {cidr} -interface {interface}")
            }
            Self::RouteAddGateway { cidr, gateway } => {
                format!("route -n add -net {cidr} {gateway}")
            }
            Self::IpAddrAdd { addr, interface } => {
                format!("ip addr add {addr} dev {interface}")
            }
            Self::IpLinkSet { interface, mtu } => {
                format!("ip link set {interface} mtu {mtu} up")
            }
            Self::IpRouteAddTun { cidr, interface } => {
                format!("ip route add {cidr} dev {interface}")
            }
            Self::IpRouteAddGateway { cidr, gateway } => {
                format!("ip route add {cidr} via {gateway}")
            }
        }
    }

    pub fn to_cleanup_command(&self) -> Option<String> {
        match self {
            Self::RouteAddTun { cidr, interface } => Some(format!(
                "route -n delete -net {cidr} -interface {interface}"
            )),
            Self::RouteAddGateway { cidr, gateway } => {
                Some(format!("route -n delete -net {cidr} {gateway}"))
            }
            Self::IpRouteAddTun { cidr, interface } => {
                Some(format!("ip route del {cidr} dev {interface}"))
            }
            Self::IpRouteAddGateway { cidr, gateway } => {
                Some(format!("ip route del {cidr} via {gateway}"))
            }
            _ => None,
        }
    }
}

impl NativeTunSetupGuard {
    pub fn new() -> Self {
        Self {
            cleanup_commands: Vec::new(),
        }
    }

    pub fn record_cleanup_command(&mut self, command: String) {
        self.cleanup_commands.push(command);
    }

    pub async fn cleanup(&self) {
        for cmd in self.cleanup_commands.iter().rev() {
            if let Err(e) = run_system_command(cmd).await {
                tracing::warn!(command = cmd, error = %e, "native_tun: cleanup failed");
            } else {
                tracing::info!(command = cmd, "native_tun: cleanup succeeded");
            }
        }
    }
}

pub async fn resolve_default_gateway() -> Option<DefaultGateway> {
    #[cfg(target_os = "macos")]
    {
        let output = tokio::process::Command::new("route")
            .args(["-n", "get", "default"])
            .output()
            .await
            .ok()?;
        if !output.status.success() {
            return None;
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut gateway = None;
        let mut interface = None;
        for line in stdout.lines() {
            let line = line.trim();
            if let Some(val) = line.strip_prefix("gateway:") {
                if let Ok(ip) = val.trim().parse::<IpAddr>() {
                    gateway = Some(ip);
                }
            } else if let Some(val) = line.strip_prefix("interface:") {
                interface = Some(val.trim().to_string());
            }
        }
        match (gateway, interface) {
            (Some(gw), Some(iface)) => Some(DefaultGateway {
                gateway: gw,
                interface: iface,
            }),
            _ => None,
        }
    }
    #[cfg(target_os = "linux")]
    {
        let output = tokio::process::Command::new("ip")
            .args(["route", "show", "default"])
            .output()
            .await
            .ok()?;
        if !output.status.success() {
            return None;
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut gateway = None;
        let mut interface = None;
        for part in stdout.split_whitespace() {
            if let Ok(ip) = part.parse::<IpAddr>() {
                if gateway.is_none() {
                    gateway = Some(ip);
                }
            }
        }
        if let Some(pos) = stdout.find("dev ") {
            let rest = &stdout[pos + 4..];
            if let Some(iface) = rest.split_whitespace().next() {
                interface = Some(iface.to_string());
            }
        }
        match (gateway, interface) {
            (Some(gw), Some(iface)) => Some(DefaultGateway {
                gateway: gw,
                interface: iface,
            }),
            _ => None,
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        None
    }
}

pub async fn execute_setup_plan(
    plan: &NativeTunSetupPlan,
) -> anyhow::Result<NativeTunSetupResultWithGuard> {
    let mut guard = NativeTunSetupGuard::new();
    let mut installed_routes = Vec::new();
    let mut installed_bypass_routes = Vec::new();
    let mut installed_endpoint_bypass = Vec::new();
    let mut skipped_bypass_routes = Vec::new();
    let mut skipped_endpoint_bypass = Vec::new();
    let mut warnings = Vec::new();

    let gateway = resolve_default_gateway().await;
    if gateway.is_none() && (!plan.bypass.is_empty() || !plan.endpoint_bypass.is_empty()) {
        warnings.push("Could not resolve default gateway; bypass routes not installed".to_string());
        skipped_bypass_routes.extend(plan.bypass.clone());
        skipped_endpoint_bypass.extend(plan.endpoint_bypass.clone());
    }

    let endpoint_set: std::collections::HashSet<String> =
        plan.endpoint_bypass.iter().cloned().collect();

    #[cfg(target_os = "macos")]
    let commands = plan.build_macos_commands(&gateway);
    #[cfg(target_os = "linux")]
    let commands = plan.build_linux_commands(&gateway);
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let commands = Vec::new();

    for cmd in &commands {
        let shell = cmd.to_shell_command();
        tracing::info!(command = shell, "native_tun: executing setup command");
        match run_system_command(&shell).await {
            Ok(()) => {
                if let Some(cleanup) = cmd.to_cleanup_command() {
                    guard.record_cleanup_command(cleanup);
                }
                if let Some(route) = extract_route_from_command(cmd) {
                    if is_bypass_command(cmd) {
                        if endpoint_set.contains(&route) {
                            installed_endpoint_bypass.push(route);
                        } else {
                            installed_bypass_routes.push(route);
                        }
                    } else {
                        installed_routes.push(route);
                    }
                }
            }
            Err(e) => {
                if cmd.is_fatal() {
                    warnings.push(format!("Fatal failure: {shell}: {e}"));
                    tracing::error!(
                        command = shell,
                        error = %e,
                        "native_tun: fatal setup failure, rolling back"
                    );
                    guard.cleanup().await;
                    return Err(anyhow!("fatal setup command failed: {shell}: {e}"));
                } else {
                    warnings.push(format!("Non-fatal failure: {shell}: {e}"));
                    if let Some(cidr) = extract_bypass_cidr_from_command(cmd) {
                        if endpoint_set.contains(&cidr) {
                            skipped_endpoint_bypass.push(cidr);
                        } else {
                            skipped_bypass_routes.push(cidr);
                        }
                    }
                }
            }
        }
    }

    Ok(NativeTunSetupResultWithGuard {
        result: NativeTunSetupResult {
            installed_routes,
            installed_bypass_routes,
            installed_endpoint_bypass,
            skipped_bypass_routes,
            skipped_endpoint_bypass,
            warnings,
        },
        guard,
    })
}

async fn run_system_command(cmd: &str) -> anyhow::Result<()> {
    let output = tokio::process::Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .output()
        .await
        .with_context(|| format!("failed to run command: {cmd}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!("command failed: {cmd}: {}", stderr.trim()));
    }
    Ok(())
}

fn extract_route_from_command(cmd: &SetupCommand) -> Option<String> {
    match cmd {
        SetupCommand::RouteAddTun { cidr, .. }
        | SetupCommand::RouteAddGateway { cidr, .. }
        | SetupCommand::IpRouteAddTun { cidr, .. }
        | SetupCommand::IpRouteAddGateway { cidr, .. } => Some(cidr.clone()),
        _ => None,
    }
}

fn is_bypass_command(cmd: &SetupCommand) -> bool {
    matches!(
        cmd,
        SetupCommand::RouteAddGateway { .. } | SetupCommand::IpRouteAddGateway { .. }
    )
}

fn extract_bypass_cidr_from_command(cmd: &SetupCommand) -> Option<String> {
    match cmd {
        SetupCommand::RouteAddGateway { cidr, .. }
        | SetupCommand::IpRouteAddGateway { cidr, .. } => Some(cidr.clone()),
        _ => None,
    }
}

fn calculate_peer_address(ip: IpAddr, prefix_len: u8) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            let mask = !((1u32 << (32 - prefix_len)) - 1);
            let network = u32::from_be_bytes(octets) & mask;
            IpAddr::V4(std::net::Ipv4Addr::from((network | 1).to_be_bytes()))
        }
        IpAddr::V6(v6) => {
            let segments = v6.segments();
            let mut new_segments = segments;
            new_segments[7] |= 1;
            IpAddr::V6(std::net::Ipv6Addr::from(new_segments))
        }
    }
}

fn prefix_to_mask(prefix_len: u8) -> String {
    let mask = if prefix_len == 0 {
        0u32
    } else {
        !((1u32 << (32 - prefix_len)) - 1)
    };
    let octets = mask.to_be_bytes();
    format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setup_plan_builds_full_route_macos_commands() {
        let config = TunConfig {
            enabled: true,
            name: Some("utun7".to_string()),
            mtu: 1420,
            auto_route: true,
            auto_bypass_private: true,
            inet4_address: vec!["198.18.0.1/30".to_string()],
            inet4_route_address: vec![],
            ..Default::default()
        };
        let plan = NativeTunSetupPlan::from_config(&config, "utun7".to_string());

        assert_eq!(plan.interface_name, "utun7");
        assert_eq!(plan.mtu, 1420);
        assert!(plan.route_add.contains(&"0.0.0.0/1".to_string()));
        assert!(plan.route_add.contains(&"128.0.0.0/1".to_string()));
        assert!(plan.bypass.contains(&"127.0.0.0/8".to_string()));
        assert!(plan.bypass.contains(&"10.0.0.0/8".to_string()));

        let commands = plan.build_macos_commands(&None);
        assert!(commands
            .iter()
            .any(|c| matches!(c, SetupCommand::Ifconfig { .. })));
        assert!(commands
            .iter()
            .any(|c| matches!(c, SetupCommand::RouteAddTun { .. })));
    }

    #[test]
    fn setup_plan_honors_auto_route_false() {
        let config = TunConfig {
            enabled: true,
            auto_route: false,
            inet4_address: vec!["198.18.0.1/30".to_string()],
            ..Default::default()
        };
        let plan = NativeTunSetupPlan::from_config(&config, "utun0".to_string());
        assert!(plan.route_add.is_empty());
    }

    #[test]
    fn setup_plan_adds_private_bypass_ranges() {
        let config = TunConfig {
            enabled: true,
            auto_bypass_private: true,
            ..Default::default()
        };
        let plan = NativeTunSetupPlan::from_config(&config, "utun0".to_string());
        assert!(plan.bypass.contains(&"127.0.0.0/8".to_string()));
        assert!(plan.bypass.contains(&"10.0.0.0/8".to_string()));
        assert!(plan.bypass.contains(&"172.16.0.0/12".to_string()));
        assert!(plan.bypass.contains(&"192.168.0.0/16".to_string()));
    }

    #[test]
    fn setup_plan_custom_route_addresses() {
        let config = TunConfig {
            enabled: true,
            inet4_route_address: vec!["10.0.0.0/8".to_string(), "172.16.0.0/12".to_string()],
            ..Default::default()
        };
        let plan = NativeTunSetupPlan::from_config(&config, "utun0".to_string());
        assert_eq!(plan.route_add.len(), 2);
        assert!(plan.route_add.contains(&"10.0.0.0/8".to_string()));
    }

    #[test]
    fn setup_guard_stores_cleanup_commands() {
        let mut guard = NativeTunSetupGuard::new();
        guard.record_cleanup_command("route -n delete -net 0.0.0.0/1 -interface utun0".to_string());
        guard.record_cleanup_command(
            "route -n delete -net 128.0.0.0/1 -interface utun0".to_string(),
        );

        assert_eq!(guard.cleanup_commands.len(), 2);
        assert_eq!(
            guard.cleanup_commands[0],
            "route -n delete -net 0.0.0.0/1 -interface utun0"
        );
        assert_eq!(
            guard.cleanup_commands[1],
            "route -n delete -net 128.0.0.0/1 -interface utun0"
        );
    }

    #[test]
    fn route_exclude_goes_to_bypass_not_route_add() {
        let config = TunConfig {
            enabled: true,
            auto_route: true,
            route_exclude_address: vec!["10.0.0.0/8".to_string(), "172.16.0.0/12".to_string()],
            ..Default::default()
        };
        let plan = NativeTunSetupPlan::from_config(&config, "utun0".to_string());
        assert!(!plan.route_add.contains(&"10.0.0.0/8".to_string()));
        assert!(!plan.route_add.contains(&"172.16.0.0/12".to_string()));
        assert!(plan.bypass.contains(&"10.0.0.0/8".to_string()));
        assert!(plan.bypass.contains(&"172.16.0.0/12".to_string()));
    }

    #[test]
    fn macos_command_format() {
        let cmd = SetupCommand::Ifconfig {
            interface: "utun7".to_string(),
            args: "inet 198.18.0.1 198.18.0.1 netmask 255.255.255.252 mtu 1420 up".to_string(),
        };
        assert_eq!(
            cmd.to_shell_command(),
            "ifconfig utun7 inet 198.18.0.1 198.18.0.1 netmask 255.255.255.252 mtu 1420 up"
        );
    }

    #[test]
    fn route_command_format() {
        let cmd = SetupCommand::RouteAddTun {
            cidr: "0.0.0.0/1".to_string(),
            interface: "utun7".to_string(),
        };
        assert_eq!(
            cmd.to_shell_command(),
            "route -n add -net 0.0.0.0/1 -interface utun7"
        );
        assert_eq!(
            cmd.to_cleanup_command().unwrap(),
            "route -n delete -net 0.0.0.0/1 -interface utun7"
        );
    }

    #[test]
    fn bypass_route_uses_gateway() {
        let cmd = SetupCommand::RouteAddGateway {
            cidr: "192.168.0.0/16".to_string(),
            gateway: "192.168.1.1".parse().unwrap(),
        };
        assert_eq!(
            cmd.to_shell_command(),
            "route -n add -net 192.168.0.0/16 192.168.1.1"
        );
        assert_eq!(
            cmd.to_cleanup_command().unwrap(),
            "route -n delete -net 192.168.0.0/16 192.168.1.1"
        );
    }

    #[test]
    fn prefix_to_mask_works() {
        assert_eq!(prefix_to_mask(30), "255.255.255.252");
        assert_eq!(prefix_to_mask(24), "255.255.255.0");
        assert_eq!(prefix_to_mask(16), "255.255.0.0");
        assert_eq!(prefix_to_mask(0), "0.0.0.0");
    }

    #[test]
    fn calculate_peer_address_works() {
        let ip: IpAddr = "198.18.0.1".parse().unwrap();
        let peer = calculate_peer_address(ip, 30);
        assert_eq!(peer.to_string(), "198.18.0.1");
    }

    #[test]
    fn endpoint_ip_port_becomes_32_cidr() {
        let cidrs = normalize_endpoint_to_cidr("1.2.3.4:51820");
        assert_eq!(cidrs, vec!["1.2.3.4/32"]);
    }

    #[test]
    fn endpoint_ipv6_port_becomes_128_cidr() {
        let cidrs = normalize_endpoint_to_cidr("[2606:4700::1111]:51820");
        assert_eq!(cidrs, vec!["2606:4700::1111/128"]);
    }

    #[test]
    fn endpoint_pure_ip_becomes_cidr() {
        let cidrs = normalize_endpoint_to_cidr("10.0.0.1");
        assert_eq!(cidrs, vec!["10.0.0.1/32"]);
    }

    #[test]
    fn endpoint_cidr_passthrough() {
        let cidrs = normalize_endpoint_to_cidr("192.168.0.0/16");
        assert_eq!(cidrs, vec!["192.168.0.0/16"]);
    }
}
