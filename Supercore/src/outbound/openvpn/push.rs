use std::{net::IpAddr, time::Duration};

use anyhow::{anyhow, bail, Context};
use ipnet::IpNet;

#[derive(Clone, Debug)]
pub(super) struct PushReply {
    pub(super) local_networks: Vec<IpNet>,
    pub(super) dns: Vec<IpAddr>,
    pub(super) routes: Vec<String>,
    pub(super) peer_id: Option<u32>,
    pub(super) cipher: Option<String>,
    pub(super) tls_exporter: bool,
    pub(super) ping_interval: Option<Duration>,
    pub(super) ping_restart: Option<Duration>,
    pub(super) raw_options: Vec<String>,
}

impl PushReply {
    pub(super) fn parse(message: &str) -> anyhow::Result<Self> {
        let message = message.trim_matches('\0').trim();
        if message.starts_with("AUTH_FAILED") {
            bail!("OpenVPN authentication failed: {message}");
        }
        if message.starts_with("AUTH_PENDING") {
            bail!("OpenVPN server requires interactive authentication, which is not available");
        }
        let options = message
            .strip_prefix("PUSH_REPLY,")
            .ok_or_else(|| anyhow!("expected OpenVPN PUSH_REPLY, got {message}"))?;
        let mut reply = Self {
            local_networks: Vec::new(),
            dns: Vec::new(),
            routes: Vec::new(),
            peer_id: None,
            cipher: None,
            tls_exporter: false,
            ping_interval: None,
            ping_restart: None,
            raw_options: Vec::new(),
        };
        for option in split_options(options) {
            let tokens = option.split_whitespace().collect::<Vec<_>>();
            let Some(name) = tokens.first().map(|value| value.to_ascii_lowercase()) else {
                continue;
            };
            match name.as_str() {
                "ifconfig" => {
                    let address = required(&tokens, 1, "ifconfig")?
                        .parse::<IpAddr>()
                        .context("invalid OpenVPN pushed IPv4 address")?;
                    if !address.is_ipv4() {
                        bail!("OpenVPN ifconfig pushed a non-IPv4 address");
                    }
                    reply.local_networks.push(format!("{address}/32").parse()?);
                }
                "ifconfig-ipv6" => {
                    let value = required(&tokens, 1, "ifconfig-ipv6")?;
                    let network = if value.contains('/') {
                        value.parse::<IpNet>()?
                    } else {
                        format!("{value}/128").parse::<IpNet>()?
                    };
                    if !network.addr().is_ipv6() {
                        bail!("OpenVPN ifconfig-ipv6 pushed a non-IPv6 address");
                    }
                    reply.local_networks.push(network);
                }
                "dhcp-option" if tokens.get(1).is_some_and(|value| value.eq_ignore_ascii_case("DNS")) => {
                    let address = required(&tokens, 2, "dhcp-option DNS")?
                        .parse::<IpAddr>()
                        .context("invalid OpenVPN pushed DNS address")?;
                    if !reply.dns.contains(&address) {
                        reply.dns.push(address);
                    }
                }
                "dns" if tokens.get(2).is_some_and(|value| value.eq_ignore_ascii_case("address")) => {
                    let address = required(&tokens, 3, "dns address")?
                        .parse::<IpAddr>()
                        .context("invalid OpenVPN 2.6 pushed DNS address")?;
                    if !reply.dns.contains(&address) {
                        reply.dns.push(address);
                    }
                }
                "route" | "route-ipv6" | "redirect-gateway" | "redirect-private" => {
                    reply.routes.push(option.clone())
                }
                "peer-id" => {
                    let value = required(&tokens, 1, "peer-id")?.parse::<u32>()?;
                    if value > 0x00ff_ffff {
                        bail!("OpenVPN peer-id exceeds 24 bits");
                    }
                    reply.peer_id = Some(value);
                }
                "cipher" => reply.cipher = Some(required(&tokens, 1, "cipher")?.to_string()),
                "key-derivation" if tokens.get(1).is_some_and(|value| value.eq_ignore_ascii_case("tls-ekm")) => {
                    reply.tls_exporter = true;
                }
                "ping" => reply.ping_interval = Some(parse_seconds(&tokens, 1, "ping")?),
                "ping-restart" => reply.ping_restart = Some(parse_seconds(&tokens, 1, "ping-restart")?),
                _ => reply.raw_options.push(option),
            }
        }
        if reply.local_networks.is_empty() {
            bail!("OpenVPN PUSH_REPLY did not assign a tunnel address");
        }
        Ok(reply)
    }
}

fn split_options(value: &str) -> Vec<String> {
    let mut options = Vec::new();
    let mut current = String::new();
    let mut escaped = false;
    for character in value.chars() {
        if escaped {
            current.push(character);
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if character == ',' {
            if !current.trim().is_empty() {
                options.push(current.trim().to_string());
            }
            current.clear();
        } else {
            current.push(character);
        }
    }
    if !current.trim().is_empty() {
        options.push(current.trim().to_string());
    }
    options
}

fn required<'a>(tokens: &'a [&str], index: usize, name: &str) -> anyhow::Result<&'a str> {
    tokens
        .get(index)
        .copied()
        .ok_or_else(|| anyhow!("OpenVPN pushed option {name} is incomplete"))
}

fn parse_seconds(tokens: &[&str], index: usize, name: &str) -> anyhow::Result<Duration> {
    Ok(Duration::from_secs(
        required(tokens, index, name)?
            .parse::<u64>()
            .with_context(|| format!("invalid OpenVPN pushed {name}"))?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_outbound_relevant_push_options() {
        let reply = PushReply::parse(
            "PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0,ifconfig-ipv6 fd00::2/64,dhcp-option DNS 10.8.0.1,route 0.0.0.0 0.0.0.0,peer-id 17,cipher AES-256-GCM,ping 5,ping-restart 30",
        )
        .unwrap();
        assert_eq!(reply.local_networks.len(), 2);
        assert_eq!(reply.dns, vec!["10.8.0.1".parse::<IpAddr>().unwrap()]);
        assert_eq!(reply.peer_id, Some(17));
        assert_eq!(reply.cipher.as_deref(), Some("AES-256-GCM"));
    }
}
