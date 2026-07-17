use std::collections::BTreeMap;

use anyhow::{anyhow, Context};
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_yaml::Value;
use url::Url;

use crate::{
    config::{
        OutboundCommonConfig, OutboundConfig, ShadowsocksPluginConfig, SmuxBrutalConfig,
        SmuxConfig, SmuxProtocol, WireGuardPeerConfig,
    },
    outbound::context::IpVersionStrategy,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubscriptionDocument {
    pub source_format: String,
    pub nodes: Vec<SubscriptionNode>,
    pub groups: Vec<SubscriptionGroup>,
    #[serde(default)]
    pub proxy_providers: Vec<SubscriptionProxyProvider>,
    #[serde(default)]
    pub rule_providers: Vec<SubscriptionRuleProvider>,
    pub rules: Vec<String>,
    pub unsupported: Vec<UnsupportedItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubscriptionNode {
    pub name: String,
    pub protocol: NodeProtocol,
    pub server: String,
    pub port: u16,
    #[serde(default)]
    pub params: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubscriptionGroup {
    pub name: String,
    pub kind: String,
    pub members: Vec<String>,
    #[serde(default)]
    pub providers: Vec<String>,
    #[serde(default)]
    pub include_all: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubscriptionProxyProvider {
    pub name: String,
    #[serde(default)]
    pub provider_type: String,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub cache_path: Option<String>,
    #[serde(default)]
    pub interval: Option<u64>,
    #[serde(default)]
    pub nodes: Vec<SubscriptionNode>,
    #[serde(default)]
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubscriptionRuleProvider {
    pub name: String,
    #[serde(default)]
    pub behavior: String,
    #[serde(default)]
    pub format: String,
    #[serde(default)]
    pub provider_type: String,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub cache_path: Option<String>,
    #[serde(default)]
    pub interval: Option<u64>,
    #[serde(default)]
    pub rules: Vec<String>,
    #[serde(default)]
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UnsupportedItem {
    pub item: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum NodeProtocol {
    Http,
    Socks5,
    Shadowsocks,
    ShadowsocksR,
    Trojan,
    Vmess,
    Vless,
    Snell,
    Hysteria,
    Hysteria2,
    Tuic,
    WireGuard,
    AnyTls,
    ShadowTls,
    Naive,
    Ssh,
    Mieru,
    Juicity,
    Masque,
    OpenVpn,
    Unknown(String),
}

impl SubscriptionDocument {
    pub fn supported_outbounds(&self) -> Vec<OutboundConfig> {
        self.nodes
            .iter()
            .filter_map(|node| node.to_outbound_config().ok())
            .collect()
    }
}

impl SubscriptionNode {
    pub fn common_options(&self) -> anyhow::Result<Option<OutboundCommonConfig>> {
        let mut options = OutboundCommonConfig::default();
        options.ip_version = match first_param(&self.params, &["ip-version", "ip_version"])
            .as_deref()
            .unwrap_or("dual")
            .to_ascii_lowercase()
            .as_str()
        {
            "dual" => IpVersionStrategy::Dual,
            "ipv4" | "v4" => IpVersionStrategy::Ipv4,
            "ipv6" | "v6" => IpVersionStrategy::Ipv6,
            "prefer-ipv4" | "prefer_ipv4" => IpVersionStrategy::PreferIpv4,
            "prefer-ipv6" | "prefer_ipv6" => IpVersionStrategy::PreferIpv6,
            value => return Err(anyhow!("unsupported ip-version {value}")),
        };
        options.interface_name = first_param(&self.params, &["interface-name", "interface"]);
        options.routing_mark = first_param(&self.params, &["routing-mark", "routing_mark"])
            .map(|value| parse_u32_text(&value, "routing-mark"))
            .transpose()?;
        options.tfo = bool_param_any(&self.params, &["tfo", "tcp-fast-open"]);
        options.mptcp = bool_param_any(&self.params, &["mptcp", "multipath-tcp"]);
        options.dialer_proxy = first_param(&self.params, &["dialer-proxy", "dialer_proxy"]);
        if self.params.contains_key("udp") {
            options.udp = bool_param(&self.params, "udp");
        }
        options.certificate_fingerprint = first_param(
            &self.params,
            &["certificate-fingerprint", "cert-fingerprint", "fingerprint"],
        );
        options.keepalive_secs = first_param(&self.params, &["keepalive", "keepalive-secs"])
            .map(|value| parse_u64_text(&value, "keepalive"))
            .transpose()?;
        options.quic_mtu = first_param(&self.params, &["quic-mtu", "mtu"])
            .map(|value| parse_u16_text(&value, "quic-mtu"))
            .transpose()?;
        options.quic_zero_rtt = bool_param_any(
            &self.params,
            &["quic-zero-rtt", "zero-rtt", "reduce-rtt", "reduce_rtt"],
        );
        options.websocket_early_data_header = first_param(
            &self.params,
            &["early-data-header-name", "ws-early-data-header"],
        );
        options.websocket_max_early_data =
            first_param(&self.params, &["max-early-data", "ws-max-early-data"])
                .map(|value| parse_u64_text(&value, "max-early-data").map(|value| value as usize))
                .transpose()?
                .unwrap_or(0);
        if bool_param(&self.params, "smux-enabled") {
            let brutal = if self.params.contains_key("smux-brutal-enabled") {
                Some(SmuxBrutalConfig {
                    enabled: bool_param(&self.params, "smux-brutal-enabled"),
                    up_mbps: first_param(&self.params, &["smux-brutal-up"])
                        .map(|value| parse_bandwidth_mbps(&value, "smux brutal up"))
                        .transpose()?
                        .unwrap_or(100),
                    down_mbps: first_param(&self.params, &["smux-brutal-down"])
                        .map(|value| parse_bandwidth_mbps(&value, "smux brutal down"))
                        .transpose()?
                        .unwrap_or(100),
                })
            } else {
                None
            };
            options.smux = Some(SmuxConfig {
                enabled: true,
                protocol: match first_param(&self.params, &["smux-protocol"])
                    .as_deref()
                    .unwrap_or("h2mux")
                    .to_ascii_lowercase()
                    .as_str()
                {
                    "smux" => SmuxProtocol::Smux,
                    "yamux" => SmuxProtocol::Yamux,
                    "h2mux" | "h2-mux" => SmuxProtocol::H2Mux,
                    value => return Err(anyhow!("unsupported smux protocol {value}")),
                },
                max_connections: first_param(&self.params, &["smux-max-connections"])
                    .map(|value| parse_u64_text(&value, "smux-max-connections"))
                    .transpose()?
                    .unwrap_or(4) as usize,
                min_streams: first_param(&self.params, &["smux-min-streams"])
                    .map(|value| parse_u64_text(&value, "smux-min-streams"))
                    .transpose()?
                    .unwrap_or(4) as usize,
                max_streams: first_param(&self.params, &["smux-max-streams"])
                    .map(|value| parse_u64_text(&value, "smux-max-streams"))
                    .transpose()?
                    .unwrap_or(0) as usize,
                statistic: bool_param(&self.params, "smux-statistic"),
                padding: bool_param(&self.params, "smux-padding"),
                only_tcp: bool_param(&self.params, "smux-only-tcp"),
                brutal,
            });
        }

        options.validate()?;

        Ok((options != OutboundCommonConfig::default()).then_some(options))
    }

    pub fn to_outbound_config(&self) -> anyhow::Result<OutboundConfig> {
        match &self.protocol {
            NodeProtocol::Http => Ok(OutboundConfig::Http {
                name: self.name.clone(),
                server: self.server.clone(),
                port: self.port,
                username: self.params.get("username").cloned(),
                password: self.params.get("password").cloned(),
            }),
            NodeProtocol::Socks5 => Ok(OutboundConfig::Socks5 {
                name: self.name.clone(),
                server: self.server.clone(),
                port: self.port,
                username: self.params.get("username").cloned(),
                password: self.params.get("password").cloned(),
            }),
            NodeProtocol::Shadowsocks => {
                let method = self
                    .params
                    .get("method")
                    .or_else(|| self.params.get("cipher"))
                    .ok_or_else(|| anyhow!("shadowsocks node {} is missing method", self.name))?
                    .clone();
                let password = self
                    .params
                    .get("password")
                    .ok_or_else(|| anyhow!("shadowsocks node {} is missing password", self.name))?
                    .clone();
                Ok(OutboundConfig::Shadowsocks {
                    name: self.name.clone(),
                    server: self.server.clone(),
                    port: self.port,
                    method,
                    password,
                    plugin: shadowsocks_plugin_config(&self.params)?,
                    udp_over_tcp: self
                        .params
                        .get("udp-over-tcp")
                        .map(|value| bool_text(value))
                        .unwrap_or(false),
                    udp_over_tcp_version: self
                        .params
                        .get("udp-over-tcp-version")
                        .map(|value| parse_u16_text(value, "shadowsocks udp-over-tcp-version"))
                        .transpose()?
                        .unwrap_or(1)
                        .try_into()
                        .map_err(|_| anyhow!("shadowsocks udp-over-tcp-version is too large"))?,
                })
            }
            NodeProtocol::ShadowsocksR => {
                let method = required_param(&self.params, &["method", "cipher"], "ssr method")?;
                let password = required_param(&self.params, &["password"], "ssr password")?;
                let protocol = required_param(&self.params, &["protocol"], "ssr protocol")
                    .unwrap_or_else(|_| "origin".to_string());
                let obfs = required_param(&self.params, &["obfs"], "ssr obfs")
                    .unwrap_or_else(|_| "plain".to_string());
                Ok(OutboundConfig::Ssr {
                    name: self.name.clone(),
                    server: self.server.clone(),
                    port: self.port,
                    method,
                    password,
                    protocol,
                    obfs,
                    protocol_param: first_param(&self.params, &["protocol-param", "protoparam"]),
                    obfs_param: first_param(&self.params, &["obfs-param", "obfsparam"]),
                })
            }
            NodeProtocol::Snell => Ok(OutboundConfig::Snell {
                name: self.name.clone(),
                server: self.server.clone(),
                port: self.port,
                psk: required_param(&self.params, &["psk", "password"], "snell psk")?,
                method: first_param(&self.params, &["method", "cipher"]),
                version: first_param(&self.params, &["version", "v"])
                    .and_then(|value| value.parse().ok()),
                obfs: first_param(&self.params, &["obfs"]),
                obfs_host: first_param(&self.params, &["obfs-host", "obfs_host", "host"]),
                reuse: bool_param(&self.params, "reuse"),
            }),
            NodeProtocol::Trojan => {
                let password = self
                    .params
                    .get("password")
                    .or_else(|| self.params.get("username"))
                    .ok_or_else(|| anyhow!("trojan node {} is missing password", self.name))?
                    .clone();
                Ok(OutboundConfig::Trojan {
                    name: self.name.clone(),
                    server: self.server.clone(),
                    port: self.port,
                    password,
                    sni: self
                        .params
                        .get("sni")
                        .or_else(|| self.params.get("servername"))
                        .cloned(),
                    skip_cert_verify: bool_param(&self.params, "skip-cert-verify")
                        || bool_param(&self.params, "allowInsecure"),
                    network: Some(normalize_trojan_network(
                        self.params
                            .get("network")
                            .or_else(|| self.params.get("type"))
                            .or_else(|| self.params.get("net"))
                            .map(String::as_str)
                            .unwrap_or("tcp"),
                        &self.name,
                    )?),
                    ws_path: self.params.get("path").cloned(),
                    ws_host: self
                        .params
                        .get("host")
                        .or_else(|| self.params.get("ws-host"))
                        .cloned(),
                    grpc_service_name: grpc_service_name(&self.params),
                    transport_headers: transport_headers(&self.params),
                    alpn: string_list_param(&self.params, &["alpn"]),
                })
            }
            NodeProtocol::Hysteria2 => {
                let password = self
                    .params
                    .get("password")
                    .or_else(|| self.params.get("auth"))
                    .or_else(|| self.params.get("auth-str"))
                    .or_else(|| self.params.get("username"))
                    .ok_or_else(|| anyhow!("hysteria2 node {} is missing password", self.name))?
                    .clone();
                Ok(OutboundConfig::Hysteria2 {
                    name: self.name.clone(),
                    server: self.server.clone(),
                    port: self.port,
                    password,
                    sni: self
                        .params
                        .get("sni")
                        .or_else(|| self.params.get("servername"))
                        .cloned(),
                    skip_cert_verify: bool_param(&self.params, "skip-cert-verify")
                        || bool_param(&self.params, "allowInsecure")
                        || bool_param(&self.params, "insecure"),
                    obfs: self.params.get("obfs").cloned(),
                    obfs_password: self
                        .params
                        .get("obfs-password")
                        .or_else(|| self.params.get("obfs_password"))
                        .cloned(),
                    alpn: self.params.get("alpn").cloned(),
                    up: first_param(&self.params, &["up", "upmbps", "up-mbps"]),
                    down: first_param(&self.params, &["down", "downmbps", "down-mbps"]),
                    congestion_control: first_param(
                        &self.params,
                        &[
                            "congestion-control",
                            "congestion-controller",
                            "congestion_control",
                        ],
                    ),
                })
            }
            NodeProtocol::Hysteria => Ok(OutboundConfig::Hysteria {
                name: self.name.clone(),
                server: self.server.clone(),
                port: self.port,
                auth: first_param(&self.params, &["auth"]),
                auth_str: first_param(&self.params, &["auth-str", "auth_str", "password"]),
                protocol: first_param(&self.params, &["protocol"]),
                up: first_param(&self.params, &["up", "upmbps"]),
                down: first_param(&self.params, &["down", "downmbps"]),
                sni: first_param(&self.params, &["sni", "servername"]),
                skip_cert_verify: bool_param_any(
                    &self.params,
                    &["skip-cert-verify", "allowInsecure", "insecure"],
                ),
                obfs: first_param(&self.params, &["obfs"]),
            }),
            NodeProtocol::Tuic => {
                let uuid = self
                    .params
                    .get("uuid")
                    .or_else(|| self.params.get("id"))
                    .or_else(|| self.params.get("username"))
                    .ok_or_else(|| anyhow!("tuic node {} is missing uuid", self.name))?
                    .clone();
                let password = self
                    .params
                    .get("password")
                    .ok_or_else(|| anyhow!("tuic node {} is missing password", self.name))?
                    .clone();
                Ok(OutboundConfig::Tuic {
                    name: self.name.clone(),
                    server: self.server.clone(),
                    port: self.port,
                    uuid,
                    password,
                    sni: self
                        .params
                        .get("sni")
                        .or_else(|| self.params.get("servername"))
                        .cloned(),
                    skip_cert_verify: bool_param(&self.params, "skip-cert-verify")
                        || bool_param(&self.params, "allowInsecure")
                        || bool_param(&self.params, "insecure"),
                    congestion_control: self
                        .params
                        .get("congestion-control")
                        .or_else(|| self.params.get("congestion-controller"))
                        .or_else(|| self.params.get("congestion_control"))
                        .cloned(),
                    udp_relay_mode: self
                        .params
                        .get("udp-relay-mode")
                        .or_else(|| self.params.get("udp_relay_mode"))
                        .cloned(),
                    alpn: self.params.get("alpn").cloned(),
                    max_udp_relay_packet_size: first_param(
                        &self.params,
                        &["max-udp-relay-packet-size", "max_udp_relay_packet_size"],
                    )
                    .map(|value| parse_u64_text(&value, "tuic max udp relay packet size"))
                    .transpose()?
                    .map(|value| {
                        usize::try_from(value)
                            .context("tuic max udp relay packet size exceeds platform limits")
                    })
                    .transpose()?,
                    heartbeat_interval_ms: first_param(
                        &self.params,
                        &["heartbeat-interval", "heartbeat_interval"],
                    )
                    .map(|value| parse_u64_text(&value, "tuic heartbeat interval"))
                    .transpose()?,
                    reduce_rtt: bool_param_any(
                        &self.params,
                        &["reduce-rtt", "reduce_rtt", "quic-zero-rtt", "zero-rtt"],
                    ),
                })
            }
            NodeProtocol::WireGuard => Ok(OutboundConfig::WireGuard {
                name: self.name.clone(),
                server: self.server.clone(),
                port: self.port,
                private_key: required_param(
                    &self.params,
                    &["private-key", "private_key", "privateKey", "username"],
                    "wireguard private key",
                )?,
                public_key: required_param(
                    &self.params,
                    &["public-key", "public_key", "publicKey", "password"],
                    "wireguard public key",
                )?,
                preshared_key: first_param(
                    &self.params,
                    &[
                        "pre-shared-key",
                        "preshared-key",
                        "preshared_key",
                        "presharedKey",
                    ],
                ),
                ip: string_list_param(&self.params, &["ip", "address"]),
                ipv6: string_list_param(&self.params, &["ipv6"]),
                allowed_ips: string_list_param(
                    &self.params,
                    &["allowed-ips", "allowed_ips", "allowedIPs"],
                ),
                reserved: first_param(&self.params, &["reserved"])
                    .map(|value| parse_wireguard_reserved_param(&value))
                    .transpose()?
                    .unwrap_or_default(),
                mtu: first_param(&self.params, &["mtu"])
                    .map(|value| parse_u16_text(&value, "wireguard mtu"))
                    .transpose()?,
                persistent_keepalive: first_param(
                    &self.params,
                    &["persistent-keepalive", "persistent_keepalive"],
                )
                .map(|value| parse_u16_text(&value, "wireguard persistent keepalive"))
                .transpose()?,
                remote_dns_resolve: bool_param_any(
                    &self.params,
                    &["remote-dns-resolve", "remote_dns_resolve"],
                ),
                dns: string_list_param(&self.params, &["dns"]),
                peers: self
                    .params
                    .get("peers")
                    .map(|value| serde_yaml::from_str::<Vec<WireGuardPeerConfig>>(value))
                    .transpose()
                    .context("invalid wireguard peers configuration")?
                    .unwrap_or_default(),
            }),
            NodeProtocol::AnyTls => Ok(OutboundConfig::AnyTls {
                name: self.name.clone(),
                server: self.server.clone(),
                port: self.port,
                password: required_param(
                    &self.params,
                    &["password", "auth", "username"],
                    "anytls password",
                )?,
                sni: first_param(&self.params, &["sni", "servername"]),
                skip_cert_verify: bool_param_any(
                    &self.params,
                    &["skip-cert-verify", "allowInsecure", "insecure"],
                ),
                alpn: string_list_param(&self.params, &["alpn"]),
                idle_session_check_interval: first_param(
                    &self.params,
                    &["idle-session-check-interval", "idle_session_check_interval"],
                )
                .map(|value| parse_u64_text(&value, "anytls idle session check interval"))
                .transpose()?,
                idle_session_timeout: first_param(
                    &self.params,
                    &["idle-session-timeout", "idle_session_timeout"],
                )
                .map(|value| parse_u64_text(&value, "anytls idle session timeout"))
                .transpose()?,
                min_idle_session: first_param(
                    &self.params,
                    &["min-idle-session", "min_idle_session"],
                )
                .map(|value| parse_u64_text(&value, "anytls minimum idle sessions"))
                .transpose()?
                .map(|value| {
                    usize::try_from(value)
                        .context("anytls minimum idle sessions exceeds platform limits")
                })
                .transpose()?,
            }),
            NodeProtocol::ShadowTls => Ok(OutboundConfig::ShadowTls {
                name: self.name.clone(),
                server: self.server.clone(),
                port: self.port,
                password: required_param(&self.params, &["password"], "shadowtls password")?,
                version: first_param(&self.params, &["version", "v"])
                    .and_then(|value| value.parse().ok()),
                sni: first_param(&self.params, &["sni", "servername", "host"]),
                skip_cert_verify: bool_param_any(
                    &self.params,
                    &["skip-cert-verify", "allowInsecure", "insecure"],
                ),
            }),
            NodeProtocol::Naive => Ok(OutboundConfig::Naive {
                name: self.name.clone(),
                server: self.server.clone(),
                port: self.port,
                username: first_param(&self.params, &["username"]),
                password: first_param(&self.params, &["password"]),
                sni: first_param(&self.params, &["sni", "servername", "host"]),
                skip_cert_verify: bool_param_any(
                    &self.params,
                    &["skip-cert-verify", "allowInsecure", "insecure"],
                ),
                alpn: string_list_param(&self.params, &["alpn"]),
            }),
            NodeProtocol::Ssh => Ok(OutboundConfig::Ssh {
                name: self.name.clone(),
                server: self.server.clone(),
                port: self.port,
                username: required_param(&self.params, &["username"], "ssh username")?,
                password: first_param(&self.params, &["password"]),
                private_key: first_param(&self.params, &["private-key", "private_key"]),
                private_key_passphrase: first_param(
                    &self.params,
                    &["private-key-passphrase", "private_key_passphrase"],
                ),
            }),
            NodeProtocol::Mieru => Ok(OutboundConfig::Mieru {
                name: self.name.clone(),
                server: self.server.clone(),
                port: self.port,
                username: required_param(&self.params, &["username"], "mieru username")?,
                password: required_param(&self.params, &["password"], "mieru password")?,
                transport: first_param(&self.params, &["transport", "protocol"]),
            }),
            NodeProtocol::Juicity => Ok(OutboundConfig::Juicity {
                name: self.name.clone(),
                server: self.server.clone(),
                port: self.port,
                uuid: required_param(&self.params, &["uuid", "id", "username"], "juicity uuid")?,
                password: required_param(&self.params, &["password"], "juicity password")?,
                sni: first_param(&self.params, &["sni", "servername"]),
                skip_cert_verify: bool_param_any(
                    &self.params,
                    &["skip-cert-verify", "allowInsecure", "insecure"],
                ),
            }),
            NodeProtocol::Masque => Ok(OutboundConfig::Masque {
                name: self.name.clone(),
                server: self.server.clone(),
                port: self.port,
                username: first_param(&self.params, &["username"]),
                password: first_param(&self.params, &["password"]),
                sni: first_param(&self.params, &["sni", "servername"]),
                skip_cert_verify: bool_param_any(
                    &self.params,
                    &["skip-cert-verify", "allowInsecure", "insecure"],
                ),
            }),
            NodeProtocol::OpenVpn => Ok(OutboundConfig::OpenVpn {
                name: self.name.clone(),
                profile: first_param(&self.params, &["profile", "path"]).map(Into::into),
                inline_profile: first_param(&self.params, &["inline-profile", "inline_profile"]),
            }),
            NodeProtocol::Vmess => {
                let uuid = self
                    .params
                    .get("uuid")
                    .or_else(|| self.params.get("id"))
                    .or_else(|| self.params.get("username"))
                    .ok_or_else(|| anyhow!("vmess node {} is missing uuid", self.name))?
                    .clone();
                let alter_id = self
                    .params
                    .get("alterId")
                    .or_else(|| self.params.get("aid"))
                    .map(|item| item.parse::<u16>())
                    .transpose()
                    .map_err(|_| anyhow!("vmess node {} has invalid alterId", self.name))?
                    .unwrap_or(0);
                let mut network = self
                    .params
                    .get("network")
                    .or_else(|| self.params.get("net"))
                    .or_else(|| self.params.get("type"))
                    .map(|item| item.to_ascii_lowercase())
                    .unwrap_or_else(|| "tcp".to_string());
                let header_type = self
                    .params
                    .get("headerType")
                    .or_else(|| self.params.get("type"))
                    .map(|item| item.trim().to_ascii_lowercase());
                if network == "tcp" && header_type.as_deref() == Some("http") {
                    network = "http".to_string();
                }
                if network != "tcp"
                    && network != "ws"
                    && network != "websocket"
                    && network != "grpc"
                    && network != "h2"
                    && network != "http"
                    && network != "httpupgrade"
                    && network != "http-upgrade"
                    && network != "httpupgrade"
                    && network != "http-upgrade"
                {
                    return Err(anyhow!(
                        "vmess node {} uses unsupported network {}",
                        self.name,
                        network
                    ));
                }
                let cipher = self
                    .params
                    .get("cipher")
                    .or_else(|| self.params.get("security"))
                    .or_else(|| self.params.get("scy"))
                    .cloned()
                    .unwrap_or_else(|| "auto".to_string());
                if !matches!(
                    cipher.to_ascii_lowercase().as_str(),
                    "auto"
                        | "aes-128-gcm"
                        | "chacha20-poly1305"
                        | "chacha20-ietf-poly1305"
                        | "none"
                ) {
                    return Err(anyhow!(
                        "vmess node {} uses unsupported cipher {}",
                        self.name,
                        cipher
                    ));
                }
                let tls = self
                    .params
                    .get("tls")
                    .map(|value| bool_text(value) || value.eq_ignore_ascii_case("tls"))
                    .unwrap_or(false);
                Ok(OutboundConfig::Vmess {
                    name: self.name.clone(),
                    server: self.server.clone(),
                    port: self.port,
                    uuid,
                    alter_id,
                    cipher,
                    tls,
                    sni: self
                        .params
                        .get("sni")
                        .or_else(|| self.params.get("servername"))
                        .cloned(),
                    skip_cert_verify: bool_param(&self.params, "skip-cert-verify")
                        || bool_param(&self.params, "allowInsecure"),
                    network: Some(match network.as_str() {
                        "websocket" => "ws".to_string(),
                        "http-upgrade" => "httpupgrade".to_string(),
                        _ => network,
                    }),
                    ws_path: self.params.get("path").cloned(),
                    ws_host: self
                        .params
                        .get("host")
                        .or_else(|| self.params.get("ws-host"))
                        .cloned(),
                    grpc_service_name: grpc_service_name(&self.params),
                    transport_headers: transport_headers(&self.params),
                    alpn: string_list_param(&self.params, &["alpn"]),
                })
            }
            NodeProtocol::Vless => {
                let network = self
                    .params
                    .get("network")
                    .or_else(|| self.params.get("type"))
                    .or_else(|| self.params.get("net"))
                    .map(|item| item.to_ascii_lowercase())
                    .unwrap_or_else(|| "tcp".to_string());
                if network != "tcp"
                    && network != "ws"
                    && network != "websocket"
                    && network != "grpc"
                    && network != "h2"
                    && network != "http"
                    && network != "httpupgrade"
                    && network != "http-upgrade"
                {
                    return Err(anyhow!(
                        "vless node {} uses unsupported network {}",
                        self.name,
                        network
                    ));
                }
                let flow = self
                    .params
                    .get("flow")
                    .map(|flow| flow.trim().to_ascii_lowercase())
                    .filter(|flow| !flow.is_empty());
                if let Some(flow) = flow.as_deref() {
                    if flow != "xtls-rprx-vision" {
                        return Err(anyhow!(
                            "vless node {} uses unsupported flow {}",
                            self.name,
                            flow
                        ));
                    }
                }
                let security = self
                    .params
                    .get("security")
                    .map(|item| item.to_ascii_lowercase())
                    .unwrap_or_else(|| {
                        self.params
                            .get("tls")
                            .map(|value| if bool_text(value) { "tls" } else { "none" })
                            .unwrap_or("tls")
                            .to_string()
                    });
                if !matches!(security.as_str(), "tls" | "none" | "" | "reality") {
                    return Err(anyhow!(
                        "vless node {} uses unsupported security {}",
                        self.name,
                        security
                    ));
                }
                let uuid = self
                    .params
                    .get("uuid")
                    .or_else(|| self.params.get("id"))
                    .or_else(|| self.params.get("username"))
                    .ok_or_else(|| anyhow!("vless node {} is missing uuid", self.name))?
                    .clone();
                Ok(OutboundConfig::Vless {
                    name: self.name.clone(),
                    server: self.server.clone(),
                    port: self.port,
                    uuid,
                    flow,
                    security: Some(security.clone()),
                    tls: security != "none",
                    sni: self
                        .params
                        .get("sni")
                        .or_else(|| self.params.get("servername"))
                        .cloned(),
                    skip_cert_verify: bool_param(&self.params, "skip-cert-verify")
                        || bool_param(&self.params, "allowInsecure"),
                    network: Some(match network.as_str() {
                        "websocket" => "ws".to_string(),
                        "http-upgrade" => "httpupgrade".to_string(),
                        _ => network,
                    }),
                    ws_path: self.params.get("path").cloned(),
                    ws_host: self
                        .params
                        .get("host")
                        .or_else(|| self.params.get("ws-host"))
                        .cloned(),
                    grpc_service_name: grpc_service_name(&self.params),
                    transport_headers: transport_headers(&self.params),
                    alpn: string_list_param(&self.params, &["alpn"]),
                    reality_public_key: self
                        .params
                        .get("pbk")
                        .or_else(|| self.params.get("public-key"))
                        .or_else(|| self.params.get("publicKey"))
                        .cloned(),
                    reality_short_id: self
                        .params
                        .get("sid")
                        .or_else(|| self.params.get("short-id"))
                        .or_else(|| self.params.get("shortId"))
                        .cloned(),
                    reality_fingerprint: self.params.get("fp").cloned(),
                    reality_spider_x: self
                        .params
                        .get("spx")
                        .or_else(|| self.params.get("spider-x"))
                        .or_else(|| self.params.get("spiderX"))
                        .cloned(),
                })
            }
            NodeProtocol::Unknown(protocol) => Ok(OutboundConfig::Unknown {
                name: self.name.clone(),
                protocol: protocol.clone(),
                server: (!self.server.is_empty()).then(|| self.server.clone()),
                port: (self.port != 0).then_some(self.port),
                params: self.params.clone(),
            }),
        }
    }
}

pub fn parse_subscription(text: &str) -> anyhow::Result<SubscriptionDocument> {
    if let Ok(value) = serde_yaml::from_str::<Value>(text) {
        if looks_like_clash_yaml(&value) {
            return parse_clash_yaml(value);
        }
    }

    parse_uri_subscription(text)
}

fn looks_like_clash_yaml(value: &Value) -> bool {
    value
        .as_mapping()
        .map(|mapping| {
            mapping.contains_key(Value::String("proxies".to_string()))
                || mapping.contains_key(Value::String("proxy-providers".to_string()))
                || mapping.contains_key(Value::String("proxy-groups".to_string()))
                || mapping.contains_key(Value::String("rule-providers".to_string()))
                || mapping.contains_key(Value::String("rules".to_string()))
        })
        .unwrap_or(false)
}

fn parse_clash_yaml(value: Value) -> anyhow::Result<SubscriptionDocument> {
    let mapping = value
        .as_mapping()
        .ok_or_else(|| anyhow!("subscription yaml root must be a mapping"))?;
    let mut nodes = Vec::new();
    let mut groups = Vec::new();
    let mut proxy_providers = Vec::new();
    let mut rule_providers = Vec::new();
    let mut rules = Vec::new();
    let mut unsupported = Vec::new();

    if let Some(proxies) = mapping
        .get(Value::String("proxies".to_string()))
        .and_then(Value::as_sequence)
    {
        for proxy in proxies {
            match parse_clash_proxy(proxy) {
                Ok(node) => nodes.push(node),
                Err(error) => unsupported.push(UnsupportedItem {
                    item: serde_yaml::to_string(proxy).unwrap_or_else(|_| "<proxy>".to_string()),
                    reason: error.to_string(),
                }),
            }
        }
    }

    if let Some(proxy_groups) = mapping
        .get(Value::String("proxy-groups".to_string()))
        .and_then(Value::as_sequence)
    {
        for group in proxy_groups {
            match parse_clash_group(group) {
                Ok(group) => groups.push(group),
                Err(error) => unsupported.push(UnsupportedItem {
                    item: serde_yaml::to_string(group).unwrap_or_else(|_| "<group>".to_string()),
                    reason: error.to_string(),
                }),
            }
        }
    }

    if let Some(providers) = mapping
        .get(Value::String("proxy-providers".to_string()))
        .and_then(Value::as_mapping)
    {
        for (name, provider) in providers {
            let Some(name) = name.as_str() else {
                continue;
            };
            match parse_clash_proxy_provider(name, provider) {
                Ok(provider) => proxy_providers.push(provider),
                Err(error) => unsupported.push(UnsupportedItem {
                    item: name.to_string(),
                    reason: error.to_string(),
                }),
            }
        }
    }

    if let Some(items) = mapping
        .get(Value::String("rules".to_string()))
        .and_then(Value::as_sequence)
    {
        rules.extend(
            items
                .iter()
                .filter_map(Value::as_str)
                .map(ToString::to_string),
        );
    }

    if let Some(providers) = mapping
        .get(Value::String("rule-providers".to_string()))
        .and_then(Value::as_mapping)
    {
        for (name, provider) in providers {
            let Some(name) = name.as_str() else {
                continue;
            };
            match parse_clash_rule_provider(name, provider) {
                Ok(provider) => rule_providers.push(provider),
                Err(error) => unsupported.push(UnsupportedItem {
                    item: name.to_string(),
                    reason: error.to_string(),
                }),
            }
        }
    }

    Ok(SubscriptionDocument {
        source_format: "clash-yaml".to_string(),
        nodes,
        groups,
        proxy_providers,
        rule_providers,
        rules,
        unsupported,
    })
}

fn parse_clash_proxy(value: &Value) -> anyhow::Result<SubscriptionNode> {
    let mapping = value
        .as_mapping()
        .ok_or_else(|| anyhow!("proxy item must be a mapping"))?;
    let name = yaml_string(mapping, "name").ok_or_else(|| anyhow!("proxy is missing name"))?;
    let protocol = yaml_string(mapping, "type")
        .map(|item| protocol_from_str(&item))
        .unwrap_or_else(|| NodeProtocol::Unknown("missing".to_string()));
    let server =
        yaml_string(mapping, "server").ok_or_else(|| anyhow!("{name} is missing server"))?;
    let port = yaml_u16(mapping, "port").ok_or_else(|| anyhow!("{name} is missing port"))?;
    let mut params = BTreeMap::new();
    for (key, value) in mapping {
        let Some(key) = key.as_str() else {
            continue;
        };
        if matches!(key, "name" | "type" | "server" | "port") {
            continue;
        }
        if key == "plugin-opts" {
            parse_clash_plugin_opts(value, &mut params);
            continue;
        }
        if key == "ws-opts" {
            parse_clash_ws_opts(value, &mut params);
            continue;
        }
        if key == "smux" {
            parse_clash_smux_opts(value, &mut params);
            continue;
        }
        if key == "grpc-opts" {
            parse_clash_grpc_opts(value, &mut params);
            continue;
        }
        if key == "h2-opts" {
            parse_clash_h2_opts(value, &mut params);
            continue;
        }
        if key == "http-upgrade-opts" || key == "httpupgrade-opts" {
            parse_clash_http_upgrade_opts(value, &mut params);
            continue;
        }
        if key == "peers" && matches!(&protocol, NodeProtocol::WireGuard) {
            params.insert(
                key.to_string(),
                serde_yaml::to_string(value).context("failed to preserve wireguard peers")?,
            );
            continue;
        }
        if let Some(value) = yaml_scalar_to_string(value) {
            params.insert(key.to_string(), value);
        } else if let Some(values) = yaml_string_list(value) {
            params.insert(key.to_string(), values.join(","));
        }
    }
    let node = SubscriptionNode {
        name,
        protocol,
        server,
        port,
        params,
    };
    node.common_options()?;
    Ok(node)
}

fn parse_clash_group(value: &Value) -> anyhow::Result<SubscriptionGroup> {
    let mapping = value
        .as_mapping()
        .ok_or_else(|| anyhow!("proxy group item must be a mapping"))?;
    let name = yaml_string(mapping, "name").ok_or_else(|| anyhow!("group is missing name"))?;
    let kind = yaml_string(mapping, "type").unwrap_or_else(|| "select".to_string());
    let members = mapping
        .get(Value::String("proxies".to_string()))
        .and_then(Value::as_sequence)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(ToString::to_string)
                .collect()
        })
        .unwrap_or_default();
    let providers = mapping
        .get(Value::String("use".to_string()))
        .and_then(Value::as_sequence)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(ToString::to_string)
                .collect()
        })
        .unwrap_or_default();
    Ok(SubscriptionGroup {
        name,
        kind,
        members,
        providers,
        include_all: yaml_bool(mapping, "include-all").unwrap_or(false),
    })
}

fn parse_clash_proxy_provider(
    name: &str,
    value: &Value,
) -> anyhow::Result<SubscriptionProxyProvider> {
    let mapping = value
        .as_mapping()
        .ok_or_else(|| anyhow!("proxy provider {name} must be a mapping"))?;
    let nodes = mapping
        .get(Value::String("proxies".to_string()))
        .and_then(Value::as_sequence)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| parse_clash_proxy(item).ok())
                .collect()
        })
        .unwrap_or_default();
    Ok(SubscriptionProxyProvider {
        name: name.to_string(),
        provider_type: yaml_string(mapping, "type").unwrap_or_else(|| "http".to_string()),
        url: yaml_string(mapping, "url"),
        path: yaml_string(mapping, "path"),
        cache_path: None,
        interval: yaml_u64(mapping, "interval"),
        nodes,
        last_error: None,
    })
}

fn parse_clash_rule_provider(
    name: &str,
    value: &Value,
) -> anyhow::Result<SubscriptionRuleProvider> {
    let mapping = value
        .as_mapping()
        .ok_or_else(|| anyhow!("rule provider {name} must be a mapping"))?;
    let rules = mapping
        .get(Value::String("payload".to_string()))
        .map(rule_provider_payload)
        .unwrap_or_default();
    Ok(SubscriptionRuleProvider {
        name: name.to_string(),
        behavior: yaml_string(mapping, "behavior").unwrap_or_else(|| "classical".to_string()),
        format: yaml_string(mapping, "format").unwrap_or_else(|| "yaml".to_string()),
        provider_type: yaml_string(mapping, "type").unwrap_or_else(|| "inline".to_string()),
        url: yaml_string(mapping, "url"),
        path: yaml_string(mapping, "path"),
        cache_path: None,
        interval: yaml_u64(mapping, "interval"),
        rules,
        last_error: None,
    })
}

pub fn parse_rule_provider_rules(text: &str) -> Vec<String> {
    if let Ok(value) = serde_yaml::from_str::<Value>(text) {
        if let Some(mapping) = value.as_mapping() {
            if let Some(payload) = mapping.get(Value::String("payload".to_string())) {
                return rule_provider_payload(payload);
            }
        }
        if let Some(sequence) = value.as_sequence() {
            return sequence
                .iter()
                .filter_map(Value::as_str)
                .map(ToString::to_string)
                .collect();
        }
    }
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(ToString::to_string)
        .collect()
}

fn rule_provider_payload(value: &Value) -> Vec<String> {
    value
        .as_sequence()
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(ToString::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn parse_uri_subscription(text: &str) -> anyhow::Result<SubscriptionDocument> {
    let decoded = decode_base64_text(text).unwrap_or_else(|| text.to_string());
    let mut nodes = Vec::new();
    let mut unsupported = Vec::new();

    for line in decoded
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        match parse_node_uri(line).and_then(|node| {
            node.common_options()?;
            Ok(node)
        }) {
            Ok(node) => nodes.push(node),
            Err(error) => unsupported.push(UnsupportedItem {
                item: line.to_string(),
                reason: error.to_string(),
            }),
        }
    }

    Ok(SubscriptionDocument {
        source_format: "uri-list".to_string(),
        nodes,
        groups: Vec::new(),
        proxy_providers: Vec::new(),
        rule_providers: Vec::new(),
        rules: Vec::new(),
        unsupported,
    })
}

fn parse_node_uri(value: &str) -> anyhow::Result<SubscriptionNode> {
    let scheme = value
        .split_once("://")
        .map(|(scheme, _)| scheme.to_ascii_lowercase())
        .ok_or_else(|| anyhow!("missing uri scheme"))?;
    match scheme.as_str() {
        "ss" => parse_ss_uri(value),
        "ssr" | "shadowsocksr" => parse_ssr_uri(value),
        "vmess" => parse_vmess_uri(value),
        "http" | "https" | "socks" | "socks5" | "trojan" | "vless" | "hysteria2" | "hy2"
        | "tuic" | "snell" | "hysteria" | "hy" | "wireguard" | "wg" | "anytls" | "shadowtls"
        | "shadow-tls" | "naive" | "ssh" | "mieru" | "juicity" | "masque" | "openvpn" => {
            parse_url_like_node(value)
        }
        _ => parse_url_like_node(value).or_else(|_| {
            Ok(SubscriptionNode {
                name: scheme.clone(),
                protocol: NodeProtocol::Unknown(scheme.clone()),
                server: String::new(),
                port: 0,
                params: BTreeMap::new(),
            })
        }),
    }
}

fn parse_ss_uri(value: &str) -> anyhow::Result<SubscriptionNode> {
    let body = value
        .strip_prefix("ss://")
        .ok_or_else(|| anyhow!("invalid ss uri"))?;
    let (body, fragment) = split_once_optional(body, '#');
    let (body, query) = split_once_optional(body, '?');
    let decoded_body = if body.contains('@') {
        body.to_string()
    } else {
        decode_base64_text(body).ok_or_else(|| anyhow!("invalid ss payload"))?
    };
    let (userinfo, host_port) = decoded_body
        .rsplit_once('@')
        .ok_or_else(|| anyhow!("ss payload is missing @"))?;
    let userinfo = decode_base64_text(userinfo).unwrap_or_else(|| userinfo.to_string());
    let (method, password) = userinfo
        .split_once(':')
        .ok_or_else(|| anyhow!("ss userinfo is missing method/password"))?;
    let (server, port) = parse_host_port(host_port.trim_end_matches('/'))?;
    let mut params = BTreeMap::new();
    params.insert("method".to_string(), method.to_string());
    params.insert("password".to_string(), password.to_string());
    if let Some(query) = query {
        for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
            let key = key.into_owned();
            let value = value.into_owned();
            if key == "plugin" {
                parse_simple_obfs_plugin(&value, &mut params);
                continue;
            }
            params.insert(key, value);
        }
    }
    Ok(SubscriptionNode {
        name: fragment
            .map(percent_decode_lossy)
            .filter(|item| !item.is_empty())
            .unwrap_or_else(|| server.clone()),
        protocol: NodeProtocol::Shadowsocks,
        server,
        port,
        params,
    })
}

fn parse_ssr_uri(value: &str) -> anyhow::Result<SubscriptionNode> {
    let body = value
        .split_once("://")
        .map(|(_, body)| body)
        .ok_or_else(|| anyhow!("invalid ssr uri"))?;
    let decoded = decode_base64_text(body).ok_or_else(|| anyhow!("invalid ssr payload"))?;
    let (main, query) = decoded
        .split_once("/?")
        .map(|(head, tail)| (head, Some(tail)))
        .unwrap_or_else(|| split_once_optional(&decoded, '?'));
    let parts = main.split(':').collect::<Vec<_>>();
    if parts.len() < 6 {
        return Err(anyhow!("ssr payload is incomplete"));
    }
    let password = parts.last().copied().unwrap_or_default();
    let obfs = parts[parts.len() - 2];
    let method = parts[parts.len() - 3];
    let protocol = parts[parts.len() - 4];
    let port = parts[parts.len() - 5].parse::<u16>()?;
    let server = parts[..parts.len() - 5].join(":");
    let mut params = BTreeMap::new();
    params.insert("protocol".to_string(), protocol.to_string());
    params.insert("method".to_string(), method.to_string());
    params.insert("obfs".to_string(), obfs.to_string());
    params.insert(
        "password".to_string(),
        decode_base64_text(password).unwrap_or_else(|| password.to_string()),
    );
    let mut name = server.clone();
    if let Some(query) = query {
        for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
            let key = key.into_owned();
            let decoded_value = decode_base64_text(&value).unwrap_or_else(|| value.into_owned());
            match key.as_str() {
                "remarks" if !decoded_value.trim().is_empty() => {
                    name = decoded_value.clone();
                }
                "obfsparam" => {
                    params.insert("obfs-param".to_string(), decoded_value.clone());
                }
                "protoparam" => {
                    params.insert("protocol-param".to_string(), decoded_value.clone());
                }
                _ => {}
            }
            params.insert(key, decoded_value);
        }
    }
    Ok(SubscriptionNode {
        name,
        protocol: NodeProtocol::ShadowsocksR,
        server,
        port,
        params,
    })
}

fn parse_vmess_uri(value: &str) -> anyhow::Result<SubscriptionNode> {
    let body = value
        .strip_prefix("vmess://")
        .ok_or_else(|| anyhow!("invalid vmess uri"))?;
    let decoded = decode_base64_text(body).ok_or_else(|| anyhow!("invalid vmess payload"))?;
    let json: serde_json::Value = serde_json::from_str(&decoded).context("invalid vmess json")?;
    let name = json
        .get("ps")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("vmess")
        .to_string();
    let server = json
        .get("add")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow!("vmess is missing add"))?
        .to_string();
    let port = json
        .get("port")
        .and_then(value_to_u16)
        .ok_or_else(|| anyhow!("vmess is missing port"))?;
    let mut params = BTreeMap::new();
    for key in [
        "id",
        "aid",
        "net",
        "type",
        "headerType",
        "host",
        "path",
        "tls",
        "sni",
        "alpn",
        "scy",
    ] {
        if let Some(value) = json.get(key).and_then(json_scalar_to_string) {
            params.insert(key.to_string(), value);
        }
    }
    Ok(SubscriptionNode {
        name,
        protocol: NodeProtocol::Vmess,
        server,
        port,
        params,
    })
}

fn parse_url_like_node(value: &str) -> anyhow::Result<SubscriptionNode> {
    let url = Url::parse(value)?;
    let protocol = protocol_from_str(url.scheme());
    let server = url
        .host_str()
        .ok_or_else(|| anyhow!("uri is missing host"))?
        .to_string();
    let port = url
        .port_or_known_default()
        .ok_or_else(|| anyhow!("uri is missing port"))?;
    let mut params = BTreeMap::new();
    if !url.username().is_empty() {
        params.insert("username".to_string(), percent_decode_lossy(url.username()));
    }
    if let Some(password) = url.password() {
        params.insert("password".to_string(), percent_decode_lossy(password));
    }
    if let Some(query) = url.query() {
        for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
            params.insert(key.into_owned(), value.into_owned());
        }
    }
    Ok(SubscriptionNode {
        name: url
            .fragment()
            .map(percent_decode_lossy)
            .filter(|item| !item.is_empty())
            .unwrap_or_else(|| server.clone()),
        protocol,
        server,
        port,
        params,
    })
}

fn bool_param(params: &BTreeMap<String, String>, key: &str) -> bool {
    params
        .get(key)
        .map(|value| bool_text(value))
        .unwrap_or(false)
}

fn bool_param_any(params: &BTreeMap<String, String>, keys: &[&str]) -> bool {
    keys.iter().any(|key| bool_param(params, key))
}

fn parse_u64_text(value: &str, label: &str) -> anyhow::Result<u64> {
    value
        .trim()
        .parse::<u64>()
        .map_err(|error| anyhow!("invalid {label} value {value}: {error}"))
}

fn parse_bandwidth_mbps(value: &str, label: &str) -> anyhow::Result<u64> {
    let normalized = value.trim().to_ascii_lowercase();
    let number = normalized
        .strip_suffix("mbps")
        .or_else(|| normalized.strip_suffix('m'))
        .unwrap_or(&normalized)
        .trim();
    parse_u64_text(number, label)
}

fn parse_u32_text(value: &str, label: &str) -> anyhow::Result<u32> {
    let value = value.trim();
    let result = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .map(|hex| u32::from_str_radix(hex, 16))
        .unwrap_or_else(|| value.parse::<u32>());
    result.map_err(|error| anyhow!("invalid {label} value {value}: {error}"))
}

fn parse_u16_text(value: &str, label: &str) -> anyhow::Result<u16> {
    value
        .trim()
        .parse::<u16>()
        .map_err(|error| anyhow!("invalid {label} value {value}: {error}"))
}

fn first_param(params: &BTreeMap<String, String>, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| params.get(*key))
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

fn required_param(
    params: &BTreeMap<String, String>,
    keys: &[&str],
    label: &str,
) -> anyhow::Result<String> {
    first_param(params, keys).ok_or_else(|| anyhow!("{label} is missing"))
}

fn string_list_param(params: &BTreeMap<String, String>, keys: &[&str]) -> Vec<String> {
    first_param(params, keys)
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|item| !item.is_empty())
                .map(ToString::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn parse_wireguard_reserved_param(value: &str) -> anyhow::Result<Vec<u8>> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(Vec::new());
    }
    if value.contains(',') {
        return value
            .split(',')
            .map(|part| {
                part.trim()
                    .parse::<u8>()
                    .with_context(|| format!("invalid wireguard reserved byte '{part}'"))
            })
            .collect();
    }
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .with_context(|| "wireguard reserved must be comma-separated bytes or base64")
}

fn grpc_service_name(params: &BTreeMap<String, String>) -> Option<String> {
    params
        .get("grpc-service-name")
        .or_else(|| params.get("serviceName"))
        .or_else(|| params.get("service-name"))
        .or_else(|| params.get("service_name"))
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

fn transport_headers(params: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    params
        .iter()
        .filter_map(|(key, value)| {
            key.strip_prefix("transport-header:")
                .map(|name| (name.to_string(), value.clone()))
        })
        .collect()
}

fn normalize_trojan_network(network: &str, node_name: &str) -> anyhow::Result<String> {
    let network = network.trim().to_ascii_lowercase();
    let normalized = match network.as_str() {
        "" | "tcp" => "tcp",
        "ws" | "websocket" => "ws",
        "grpc" => "grpc",
        "h2" | "http" => "h2",
        "httpupgrade" | "http-upgrade" => "httpupgrade",
        _ => {
            return Err(anyhow!(
                "trojan node {node_name} uses unsupported network {network}"
            ))
        }
    };
    Ok(normalized.to_string())
}

fn bool_text(value: &str) -> bool {
    matches!(
        value.to_ascii_lowercase().as_str(),
        "true" | "1" | "yes" | "y"
    )
}

fn shadowsocks_plugin_config(
    params: &BTreeMap<String, String>,
) -> anyhow::Result<Option<ShadowsocksPluginConfig>> {
    let Some(plugin) = params.get("plugin") else {
        return Ok(None);
    };
    let plugin = plugin
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    let mode = match plugin.as_str() {
        "obfs" | "obfs-local" | "simple-obfs" => params
            .get("plugin-mode")
            .or_else(|| params.get("obfs"))
            .cloned()
            .unwrap_or_else(|| "http".to_string()),
        "v2ray-plugin" => "v2ray-plugin".to_string(),
        "shadow-tls" | "shadowtls" => "shadow-tls".to_string(),
        _ => return Err(anyhow!("unsupported shadowsocks plugin {plugin}")),
    };
    Ok(Some(ShadowsocksPluginConfig {
        mode,
        host: params
            .get("plugin-host")
            .or_else(|| params.get("obfs-host"))
            .cloned(),
        path: params
            .get("plugin-opts-path")
            .or_else(|| params.get("ws-path"))
            .cloned(),
        tls: params
            .get("plugin-opts-tls")
            .or_else(|| params.get("tls"))
            .map(|value| bool_text(value))
            .unwrap_or(false),
        skip_cert_verify: params
            .get("plugin-opts-skip-cert-verify")
            .or_else(|| params.get("skip-cert-verify"))
            .map(|value| bool_text(value))
            .unwrap_or(false),
        password: params.get("plugin-opts-password").cloned(),
        version: params
            .get("plugin-opts-version")
            .map(|value| {
                value
                    .parse::<u8>()
                    .context("invalid shadow-tls plugin version")
            })
            .transpose()?,
    }))
}

fn parse_clash_plugin_opts(value: &Value, params: &mut BTreeMap<String, String>) {
    let Some(mapping) = value.as_mapping() else {
        return;
    };
    if let Some(mode) = yaml_string(mapping, "mode") {
        params.insert("plugin-mode".to_string(), mode);
    }
    if let Some(host) = yaml_string(mapping, "host") {
        params.insert("plugin-host".to_string(), host);
    }
    if let Some(path) = yaml_string(mapping, "path") {
        params.insert("plugin-opts-path".to_string(), path);
    }
    for key in ["tls", "skip-cert-verify", "password", "version"] {
        if let Some(value) = mapping
            .get(Value::String(key.to_string()))
            .and_then(yaml_scalar_to_string)
        {
            params.insert(format!("plugin-opts-{key}"), value);
        }
    }
}

fn parse_clash_ws_opts(value: &Value, params: &mut BTreeMap<String, String>) {
    let Some(mapping) = value.as_mapping() else {
        return;
    };
    if let Some(path) = yaml_string(mapping, "path") {
        params.insert("path".to_string(), path);
    }
    if let Some(host) = yaml_string(mapping, "host") {
        params.insert("host".to_string(), host);
    }
    if let Some(max_early_data) = yaml_u64(mapping, "max-early-data") {
        params.insert("max-early-data".to_string(), max_early_data.to_string());
    }
    if let Some(header) = yaml_string(mapping, "early-data-header-name") {
        params.insert("early-data-header-name".to_string(), header);
    }
    if let Some(headers) = mapping
        .get(Value::String("headers".to_string()))
        .and_then(Value::as_mapping)
    {
        for (name, value) in headers {
            let (Some(name), Some(value)) = (name.as_str(), yaml_scalar_to_string(value)) else {
                continue;
            };
            params.insert(format!("transport-header:{name}"), value);
        }
        if let Some(host) = yaml_string(headers, "Host").or_else(|| yaml_string(headers, "host")) {
            params.insert("host".to_string(), host);
        }
    }
}

fn parse_clash_smux_opts(value: &Value, params: &mut BTreeMap<String, String>) {
    let Some(mapping) = value.as_mapping() else {
        return;
    };
    for key in [
        "enabled",
        "protocol",
        "max-connections",
        "min-streams",
        "max-streams",
        "statistic",
        "padding",
        "only-tcp",
    ] {
        if let Some(value) = mapping
            .get(Value::String(key.to_string()))
            .and_then(yaml_scalar_to_string)
        {
            params.insert(format!("smux-{key}"), value);
        }
    }
    if let Some(brutal) = mapping
        .get(Value::String("brutal-opts".to_string()))
        .and_then(Value::as_mapping)
    {
        for key in ["enabled", "up", "down"] {
            if let Some(value) = brutal
                .get(Value::String(key.to_string()))
                .and_then(yaml_scalar_to_string)
            {
                params.insert(format!("smux-brutal-{key}"), value);
            }
        }
    }
}

fn parse_clash_grpc_opts(value: &Value, params: &mut BTreeMap<String, String>) {
    let Some(mapping) = value.as_mapping() else {
        return;
    };
    if let Some(service_name) = yaml_string(mapping, "grpc-service-name")
        .or_else(|| yaml_string(mapping, "serviceName"))
        .or_else(|| yaml_string(mapping, "service-name"))
    {
        params.insert("grpc-service-name".to_string(), service_name);
    }
}

fn parse_clash_h2_opts(value: &Value, params: &mut BTreeMap<String, String>) {
    let Some(mapping) = value.as_mapping() else {
        return;
    };
    if let Some(path) = yaml_string(mapping, "path").or_else(|| yaml_first_string(mapping, "path"))
    {
        params.insert("path".to_string(), path);
    }
    if let Some(host) = yaml_string(mapping, "host").or_else(|| yaml_first_string(mapping, "host"))
    {
        params.insert("host".to_string(), host);
    }
}

fn parse_clash_http_upgrade_opts(value: &Value, params: &mut BTreeMap<String, String>) {
    let Some(mapping) = value.as_mapping() else {
        return;
    };
    if let Some(path) = yaml_string(mapping, "path") {
        params.insert("path".to_string(), path);
    }
    if let Some(host) = yaml_string(mapping, "host") {
        params.insert("host".to_string(), host);
    }
    if let Some(headers) = mapping
        .get(Value::String("headers".to_string()))
        .and_then(Value::as_mapping)
    {
        for (name, value) in headers {
            let (Some(name), Some(value)) = (name.as_str(), yaml_scalar_to_string(value)) else {
                continue;
            };
            params.insert(format!("transport-header:{name}"), value);
        }
        if let Some(host) = yaml_string(headers, "Host").or_else(|| yaml_string(headers, "host")) {
            params.insert("host".to_string(), host);
        }
    }
}

fn parse_simple_obfs_plugin(value: &str, params: &mut BTreeMap<String, String>) {
    let parts = value.split(';').collect::<Vec<_>>();
    let plugin = parts.first().copied().unwrap_or_default();
    params.insert("plugin".to_string(), plugin.to_string());
    for part in parts.into_iter().skip(1) {
        let (key, value) = part.split_once('=').unwrap_or((part, "true"));
        match key.to_ascii_lowercase().as_str() {
            "obfs" | "mode" => {
                params.insert("plugin-mode".to_string(), value.to_string());
            }
            "obfs-host" | "host" => {
                params.insert("plugin-host".to_string(), value.to_string());
            }
            "path" => {
                params.insert("plugin-opts-path".to_string(), value.to_string());
            }
            "tls" => {
                params.insert("plugin-opts-tls".to_string(), value.to_string());
            }
            "skip-cert-verify" => {
                params.insert(
                    "plugin-opts-skip-cert-verify".to_string(),
                    value.to_string(),
                );
            }
            "password" => {
                params.insert("plugin-opts-password".to_string(), value.to_string());
            }
            "version" => {
                params.insert("plugin-opts-version".to_string(), value.to_string());
            }
            _ => {}
        }
    }
}

fn protocol_from_str(value: &str) -> NodeProtocol {
    match value.to_ascii_lowercase().as_str() {
        "http" | "https" => NodeProtocol::Http,
        "socks" | "socks5" => NodeProtocol::Socks5,
        "ss" | "shadowsocks" => NodeProtocol::Shadowsocks,
        "ssr" | "shadowsocksr" => NodeProtocol::ShadowsocksR,
        "trojan" => NodeProtocol::Trojan,
        "vmess" => NodeProtocol::Vmess,
        "vless" => NodeProtocol::Vless,
        "snell" => NodeProtocol::Snell,
        "hysteria" | "hy" => NodeProtocol::Hysteria,
        "hysteria2" | "hy2" => NodeProtocol::Hysteria2,
        "tuic" => NodeProtocol::Tuic,
        "wireguard" | "wg" => NodeProtocol::WireGuard,
        "anytls" | "any-tls" => NodeProtocol::AnyTls,
        "shadowtls" | "shadow-tls" => NodeProtocol::ShadowTls,
        "naive" => NodeProtocol::Naive,
        "ssh" => NodeProtocol::Ssh,
        "mieru" => NodeProtocol::Mieru,
        "juicity" => NodeProtocol::Juicity,
        "masque" => NodeProtocol::Masque,
        "openvpn" | "open-vpn" => NodeProtocol::OpenVpn,
        other => NodeProtocol::Unknown(other.to_string()),
    }
}

fn yaml_string(mapping: &serde_yaml::Mapping, key: &str) -> Option<String> {
    mapping
        .get(Value::String(key.to_string()))
        .and_then(Value::as_str)
        .map(ToString::to_string)
}

fn yaml_first_string(mapping: &serde_yaml::Mapping, key: &str) -> Option<String> {
    mapping
        .get(Value::String(key.to_string()))
        .and_then(Value::as_sequence)
        .and_then(|items| items.iter().find_map(yaml_scalar_to_string))
}

fn yaml_u16(mapping: &serde_yaml::Mapping, key: &str) -> Option<u16> {
    mapping
        .get(Value::String(key.to_string()))
        .and_then(|value| match value {
            Value::Number(number) => number.as_u64().and_then(|item| u16::try_from(item).ok()),
            Value::String(text) => text.parse().ok(),
            _ => None,
        })
}

fn yaml_u64(mapping: &serde_yaml::Mapping, key: &str) -> Option<u64> {
    mapping
        .get(Value::String(key.to_string()))
        .and_then(|value| match value {
            Value::Number(number) => number.as_u64(),
            Value::String(text) => text.parse().ok(),
            _ => None,
        })
}

fn yaml_bool(mapping: &serde_yaml::Mapping, key: &str) -> Option<bool> {
    mapping
        .get(Value::String(key.to_string()))
        .and_then(|value| match value {
            Value::Bool(value) => Some(*value),
            Value::String(text) => match text.to_ascii_lowercase().as_str() {
                "true" | "yes" | "on" | "1" => Some(true),
                "false" | "no" | "off" | "0" => Some(false),
                _ => None,
            },
            _ => None,
        })
}

fn yaml_scalar_to_string(value: &Value) -> Option<String> {
    match value {
        Value::Bool(value) => Some(value.to_string()),
        Value::Number(value) => Some(value.to_string()),
        Value::String(value) => Some(value.clone()),
        _ => None,
    }
}

fn yaml_string_list(value: &Value) -> Option<Vec<String>> {
    value.as_sequence().map(|items| {
        items
            .iter()
            .filter_map(yaml_scalar_to_string)
            .collect::<Vec<_>>()
    })
}

fn json_scalar_to_string(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::Bool(value) => Some(value.to_string()),
        serde_json::Value::Number(value) => Some(value.to_string()),
        serde_json::Value::String(value) => Some(value.clone()),
        _ => None,
    }
}

fn value_to_u16(value: &serde_json::Value) -> Option<u16> {
    match value {
        serde_json::Value::Number(number) => {
            number.as_u64().and_then(|item| u16::try_from(item).ok())
        }
        serde_json::Value::String(text) => text.parse().ok(),
        _ => None,
    }
}

fn decode_base64_text(value: &str) -> Option<String> {
    let compact = value.trim().replace(['\r', '\n', ' '], "");
    if compact.is_empty() {
        return None;
    }
    let mut padded = compact.clone();
    while padded.len() % 4 != 0 {
        padded.push('=');
    }
    for engine in [
        &base64::engine::general_purpose::STANDARD,
        &base64::engine::general_purpose::URL_SAFE,
        &base64::engine::general_purpose::STANDARD_NO_PAD,
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
    ] {
        if let Ok(bytes) = engine.decode(&padded) {
            if let Ok(text) = String::from_utf8(bytes) {
                return Some(text);
            }
        }
        if let Ok(bytes) = engine.decode(&compact) {
            if let Ok(text) = String::from_utf8(bytes) {
                return Some(text);
            }
        }
    }
    None
}

fn parse_host_port(value: &str) -> anyhow::Result<(String, u16)> {
    let (host, port) = value
        .rsplit_once(':')
        .ok_or_else(|| anyhow!("missing host port separator"))?;
    Ok((host.trim_matches(['[', ']']).to_string(), port.parse()?))
}

fn split_once_optional(value: &str, delimiter: char) -> (&str, Option<&str>) {
    value
        .split_once(delimiter)
        .map(|(head, tail)| (head, Some(tail)))
        .unwrap_or((value, None))
}

fn percent_decode_lossy(value: &str) -> String {
    let replaced = value.replace('+', "%2B");
    url::form_urlencoded::parse(replaced.as_bytes())
        .next()
        .map(|(key, _)| key.into_owned())
        .unwrap_or_else(|| value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_clash_yaml_nodes_groups_and_rules() {
        let text = r#"
proxies:
  - name: HK-01
    type: ss
    server: hk.example.com
    port: 8388
    cipher: chacha20-ietf-poly1305
    password: secret
proxy-groups:
  - name: Auto
    type: url-test
    proxies:
      - HK-01
rules:
  - DOMAIN-SUFFIX,example.com,Auto
"#;

        let doc = parse_subscription(text).unwrap();

        assert_eq!(doc.source_format, "clash-yaml");
        assert_eq!(doc.nodes.len(), 1);
        assert_eq!(doc.nodes[0].protocol, NodeProtocol::Shadowsocks);
        assert_eq!(doc.groups[0].members, vec!["HK-01"]);
        assert_eq!(doc.rules, vec!["DOMAIN-SUFFIX,example.com,Auto"]);
    }

    #[test]
    fn parses_base64_uri_list_with_shadowsocks() {
        let uri = "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwYXNzQGhrLmV4YW1wbGUuY29tOjgzODg#HK%2001";
        let encoded = base64::engine::general_purpose::STANDARD.encode(uri);

        let doc = parse_subscription(&encoded).unwrap();

        assert_eq!(doc.source_format, "uri-list");
        assert_eq!(doc.nodes.len(), 1);
        assert_eq!(doc.nodes[0].name, "HK 01");
        assert_eq!(doc.nodes[0].server, "hk.example.com");
        assert_eq!(doc.nodes[0].port, 8388);
        assert_eq!(doc.nodes[0].protocol, NodeProtocol::Shadowsocks);
    }

    #[test]
    fn converts_basic_shadowsocks_node_to_outbound_config() {
        let text = r#"
proxies:
  - name: HK-01
    type: ss
    server: hk.example.com
    port: 8388
    cipher: aes-128-gcm
    password: secret
"#;

        let doc = parse_subscription(text).unwrap();
        let outbounds = doc.supported_outbounds();

        assert_eq!(outbounds.len(), 1);
        match &outbounds[0] {
            OutboundConfig::Shadowsocks {
                name,
                server,
                port,
                method,
                password,
                plugin,
                ..
            } => {
                assert_eq!(name, "HK-01");
                assert_eq!(server, "hk.example.com");
                assert_eq!(*port, 8388);
                assert_eq!(method, "aes-128-gcm");
                assert_eq!(password, "secret");
                assert!(plugin.is_none());
            }
            other => panic!("unexpected outbound {other:?}"),
        }
    }

    #[test]
    fn converts_snell_reuse_yaml_to_outbound_config() {
        let text = r#"
proxies:
  - name: SNELL-REUSE
    type: snell
    server: snell.example.com
    port: 4406
    psk: test-psk
    version: 5
    reuse: true
"#;

        let doc = parse_subscription(text).unwrap();
        let outbound = doc.nodes[0].to_outbound_config().unwrap();
        match outbound {
            OutboundConfig::Snell {
                name,
                version,
                reuse,
                ..
            } => {
                assert_eq!(name, "SNELL-REUSE");
                assert_eq!(version, Some(5));
                assert!(reuse);
            }
            other => panic!("unexpected outbound {other:?}"),
        }
    }

    #[test]
    fn converts_complete_wireguard_yaml_without_losing_peer_options() {
        let private_key = base64::engine::general_purpose::STANDARD.encode([11u8; 32]);
        let primary_public_key = base64::engine::general_purpose::STANDARD.encode([29u8; 32]);
        let secondary_public_key = base64::engine::general_purpose::STANDARD.encode([31u8; 32]);
        let preshared_key = base64::engine::general_purpose::STANDARD.encode([47u8; 32]);
        let reserved = base64::engine::general_purpose::STANDARD.encode([7u8, 23, 91]);
        let text = format!(
            r#"
proxies:
  - name: WG-COMPLETE
    type: wireguard
    server: 127.0.0.1
    port: 51820
    private-key: "{private_key}"
    public-key: "{primary_public_key}"
    pre-shared-key: "{preshared_key}"
    ip: [10.77.0.2/32]
    ipv6: [fd42:77::2/128]
    allowed-ips: [10.77.0.0/24, "fd42:77::/64"]
    reserved: "{reserved}"
    mtu: 1280
    persistent-keepalive: 25
    remote-dns-resolve: true
    dns: [10.77.0.1, "[fd42:77::1]:53"]
    peers:
      - server: 127.0.0.2
        port: 51821
        public-key: "{secondary_public_key}"
        pre-shared-key: "{preshared_key}"
        allowed-ips: [10.88.0.0/24]
        reserved: [1, 2, 3]
        persistent-keepalive: 30
"#
        );

        let document = parse_subscription(&text).unwrap();
        assert!(document.unsupported.is_empty());
        let outbound = document.nodes[0].to_outbound_config().unwrap();
        match outbound {
            OutboundConfig::WireGuard {
                name,
                private_key: parsed_private_key,
                public_key,
                preshared_key: parsed_preshared_key,
                ip,
                ipv6,
                allowed_ips,
                reserved,
                mtu,
                persistent_keepalive,
                remote_dns_resolve,
                dns,
                peers,
                ..
            } => {
                assert_eq!(name, "WG-COMPLETE");
                assert_eq!(parsed_private_key, private_key);
                assert_eq!(public_key, primary_public_key);
                assert_eq!(
                    parsed_preshared_key.as_deref(),
                    Some(preshared_key.as_str())
                );
                assert_eq!(ip, vec!["10.77.0.2/32"]);
                assert_eq!(ipv6, vec!["fd42:77::2/128"]);
                assert_eq!(allowed_ips, vec!["10.77.0.0/24", "fd42:77::/64"]);
                assert_eq!(reserved, vec![7, 23, 91]);
                assert_eq!(mtu, Some(1_280));
                assert_eq!(persistent_keepalive, Some(25));
                assert!(remote_dns_resolve);
                assert_eq!(dns, vec!["10.77.0.1", "[fd42:77::1]:53"]);
                assert_eq!(peers.len(), 1);
                assert_eq!(peers[0].public_key, secondary_public_key);
                assert_eq!(peers[0].allowed_ips, vec!["10.88.0.0/24"]);
                assert_eq!(peers[0].reserved, vec![1, 2, 3]);
                assert_eq!(peers[0].persistent_keepalive, Some(30));
            }
            other => panic!("unexpected outbound {other:?}"),
        }
    }

    #[test]
    fn rejects_invalid_wireguard_reserved_instead_of_silently_dropping_it() {
        let private_key = base64::engine::general_purpose::STANDARD.encode([11u8; 32]);
        let public_key = base64::engine::general_purpose::STANDARD.encode([29u8; 32]);
        let text = format!(
            r#"
proxies:
  - name: WG-BAD-RESERVED
    type: wireguard
    server: 127.0.0.1
    port: 51820
    private-key: "{private_key}"
    public-key: "{public_key}"
    ip: [10.77.0.2/32]
    reserved: 1,not-a-byte,3
"#
        );

        let document = parse_subscription(&text).unwrap();
        let error = document.nodes[0].to_outbound_config().unwrap_err();
        assert!(error
            .to_string()
            .contains("invalid wireguard reserved byte 'not-a-byte'"));
    }

    #[test]
    fn converts_anytls_v2_session_options_without_losing_values() {
        let text = r#"
proxies:
  - name: ANYTLS-V2
    type: anytls
    server: anytls.example.com
    port: 443
    password: secret
    sni: edge.example.com
    alpn: [h2, http/1.1]
    idle-session-check-interval: 11
    idle-session-timeout: 22
    min-idle-session: 3
"#;

        let document = parse_subscription(text).unwrap();
        let outbound = document.nodes[0].to_outbound_config().unwrap();
        match outbound {
            OutboundConfig::AnyTls {
                idle_session_check_interval,
                idle_session_timeout,
                min_idle_session,
                alpn,
                ..
            } => {
                assert_eq!(idle_session_check_interval, Some(11));
                assert_eq!(idle_session_timeout, Some(22));
                assert_eq!(min_idle_session, Some(3));
                assert_eq!(alpn, vec!["h2", "http/1.1"]);
            }
            other => panic!("unexpected outbound {other:?}"),
        }
    }

    #[test]
    fn converts_shadowsocks_simple_obfs_plugin_options() {
        let text = r#"
proxies:
  - name: HK-OBFS
    type: ss
    server: hk.example.com
    port: 8388
    cipher: aes-128-gcm
    password: secret
    plugin: obfs
    plugin-opts:
      mode: http
      host: edge.example.com
"#;

        let doc = parse_subscription(text).unwrap();
        let outbound = doc.nodes[0].to_outbound_config().unwrap();

        match outbound {
            OutboundConfig::Shadowsocks { plugin, .. } => {
                let plugin = plugin.expect("plugin");
                assert_eq!(plugin.mode, "http");
                assert_eq!(plugin.host.as_deref(), Some("edge.example.com"));
            }
            other => panic!("unexpected outbound {other:?}"),
        }
    }

    #[test]
    fn converts_shadowsocks_shadowtls_v3_yaml_plugin_options() {
        let text = r#"
proxies:
  - name: HK-SHADOWTLS
    type: ss
    server: hk.example.com
    port: 443
    cipher: aes-128-gcm
    password: shadowsocks-secret
    plugin: shadow-tls
    plugin-opts:
      host: edge.example.com
      password: shadowtls-secret
      version: 3
      skip-cert-verify: true
"#;

        let document = parse_subscription(text).unwrap();
        let outbound = document.nodes[0].to_outbound_config().unwrap();
        match outbound {
            OutboundConfig::Shadowsocks { plugin, .. } => {
                let plugin = plugin.expect("plugin");
                assert_eq!(plugin.mode, "shadow-tls");
                assert_eq!(plugin.host.as_deref(), Some("edge.example.com"));
                assert_eq!(plugin.password.as_deref(), Some("shadowtls-secret"));
                assert_eq!(plugin.version, Some(3));
                assert!(plugin.skip_cert_verify);
            }
            other => panic!("unexpected outbound {other:?}"),
        }
    }

    #[test]
    fn parses_shadowsocks_shadowtls_v3_sip003_plugin_options() {
        let uri = "ss://YWVzLTEyOC1nY206c2hhZG93c29ja3Mtc2VjcmV0@hk.example.com:443/?plugin=shadow-tls%3Bhost%3Dedge.example.com%3Bpassword%3Dshadowtls-secret%3Bversion%3D3%3Bskip-cert-verify%3Dtrue#HK";

        let document = parse_subscription(uri).unwrap();
        let outbound = document.nodes[0].to_outbound_config().unwrap();
        match outbound {
            OutboundConfig::Shadowsocks { plugin, .. } => {
                let plugin = plugin.expect("plugin");
                assert_eq!(plugin.mode, "shadow-tls");
                assert_eq!(plugin.host.as_deref(), Some("edge.example.com"));
                assert_eq!(plugin.password.as_deref(), Some("shadowtls-secret"));
                assert_eq!(plugin.version, Some(3));
                assert!(plugin.skip_cert_verify);
            }
            other => panic!("unexpected outbound {other:?}"),
        }
    }

    #[test]
    fn parses_standard_ssr_uri_with_extended_cipher_and_user_param() {
        use base64::Engine as _;

        let engine = &base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let password = engine.encode("secret");
        let remarks = engine.encode("SSR-CTR");
        let user = engine.encode("1001:user-secret");
        let decoded = format!(
            "example.com:8388:auth_aes128_sha1:aes-256-ctr:random_head:{password}/?remarks={remarks}&protoparam={user}"
        );
        let uri = format!("ssr://{}", engine.encode(decoded));
        let document = parse_subscription(&uri).unwrap();
        let outbound = document.nodes[0].to_outbound_config().unwrap();
        match outbound {
            OutboundConfig::Ssr {
                name,
                method,
                password,
                protocol,
                obfs,
                protocol_param,
                ..
            } => {
                assert_eq!(name, "SSR-CTR");
                assert_eq!(method, "aes-256-ctr");
                assert_eq!(password, "secret");
                assert_eq!(protocol, "auth_aes128_sha1");
                assert_eq!(obfs, "random_head");
                assert_eq!(protocol_param.as_deref(), Some("1001:user-secret"));
            }
            other => panic!("unexpected outbound {other:?}"),
        }
    }

    #[test]
    fn converts_shadowsocks_udp_over_tcp_options() {
        let text = r#"
proxies:
  - name: HK-UOT
    type: ss
    server: hk.example.com
    port: 8388
    cipher: aes-128-gcm
    password: secret
    udp-over-tcp: true
    udp-over-tcp-version: 2
"#;

        let doc = parse_subscription(text).unwrap();
        let outbound = doc.nodes[0].to_outbound_config().unwrap();
        match outbound {
            OutboundConfig::Shadowsocks {
                udp_over_tcp,
                udp_over_tcp_version,
                ..
            } => {
                assert!(udp_over_tcp);
                assert_eq!(udp_over_tcp_version, 2);
            }
            other => panic!("unexpected outbound {other:?}"),
        }
    }

    #[test]
    fn rejects_shadowsocks_udp_over_tcp_version_over_u8() {
        let text = r#"
proxies:
  - name: HK-UOT
    type: ss
    server: hk.example.com
    port: 8388
    cipher: aes-128-gcm
    password: secret
    udp-over-tcp: true
    udp-over-tcp-version: 256
"#;

        let doc = parse_subscription(text).unwrap();
        let error = doc.nodes[0].to_outbound_config().unwrap_err();
        assert!(error
            .to_string()
            .contains("shadowsocks udp-over-tcp-version is too large"));
    }

    #[test]
    fn parses_shadowsocks_uri_simple_obfs_plugin_options() {
        let uri = "ss://YWVzLTEyOC1nY206cGFzcw@example.com:8388/?plugin=simple-obfs%3Bobfs%3Dhttp%3Bobfs-host%3Dedge.example.com#HK";

        let doc = parse_subscription(uri).unwrap();
        let outbound = doc.nodes[0].to_outbound_config().unwrap();

        match outbound {
            OutboundConfig::Shadowsocks { plugin, .. } => {
                let plugin = plugin.expect("plugin");
                assert_eq!(plugin.mode, "http");
                assert_eq!(plugin.host.as_deref(), Some("edge.example.com"));
            }
            other => panic!("unexpected outbound {other:?}"),
        }
    }

    #[test]
    fn parses_shadowsocks_uri_simple_obfs_tls_plugin_options() {
        let uri = "ss://YWVzLTEyOC1nY206cGFzcw@example.com:8388/?plugin=simple-obfs%3Bobfs%3Dtls%3Bobfs-host%3Dedge.example.com#HK";

        let doc = parse_subscription(uri).unwrap();
        let outbound = doc.nodes[0].to_outbound_config().unwrap();

        match outbound {
            OutboundConfig::Shadowsocks { plugin, .. } => {
                let plugin = plugin.expect("plugin");
                assert_eq!(plugin.mode, "tls");
                assert_eq!(plugin.host.as_deref(), Some("edge.example.com"));
            }
            other => panic!("unexpected outbound {other:?}"),
        }
    }

    #[test]
    fn converts_shadowsocks_v2ray_plugin_yaml_options() {
        let text = r#"
proxies:
  - name: HK-WS
    type: ss
    server: hk.example.com
    port: 443
    cipher: aes-192-ctr
    password: secret
    plugin: v2ray-plugin
    plugin-opts:
      mode: websocket
      host: edge.example.com
      path: /ss
      tls: true
      skip-cert-verify: true
"#;

        let doc = parse_subscription(text).unwrap();
        let outbound = doc.nodes[0].to_outbound_config().unwrap();
        match outbound {
            OutboundConfig::Shadowsocks { plugin, .. } => {
                let plugin = plugin.expect("plugin");
                assert_eq!(plugin.mode, "v2ray-plugin");
                assert_eq!(plugin.host.as_deref(), Some("edge.example.com"));
                assert_eq!(plugin.path.as_deref(), Some("/ss"));
                assert!(plugin.tls);
                assert!(plugin.skip_cert_verify);
            }
            other => panic!("unexpected outbound {other:?}"),
        }
    }

    #[test]
    fn parses_shadowsocks_v2ray_plugin_uri_options() {
        let uri = "ss://YWVzLTE5Mi1jdHI6cGFzcw@example.com:8388/?plugin=v2ray-plugin%3Bmode%3Dwebsocket%3Bhost%3Dedge.example.com%3Bpath%3D%2Fss%3Btls#HK";

        let doc = parse_subscription(uri).unwrap();
        let outbound = doc.nodes[0].to_outbound_config().unwrap();
        match outbound {
            OutboundConfig::Shadowsocks { plugin, .. } => {
                let plugin = plugin.expect("plugin");
                assert_eq!(plugin.mode, "v2ray-plugin");
                assert_eq!(plugin.host.as_deref(), Some("edge.example.com"));
                assert_eq!(plugin.path.as_deref(), Some("/ss"));
                assert!(plugin.tls);
            }
            other => panic!("unexpected outbound {other:?}"),
        }
    }

    #[test]
    fn converts_trojan_yaml_to_outbound_config() {
        let text = r#"
proxies:
  - name: TR-01
    type: trojan
    server: tr.example.com
    port: 443
    password: secret
    sni: cdn.example.com
    skip-cert-verify: true
"#;

        let doc = parse_subscription(text).unwrap();
        let outbound = doc.nodes[0].to_outbound_config().unwrap();

        match outbound {
            OutboundConfig::Trojan {
                name,
                server,
                port,
                password,
                sni,
                skip_cert_verify,
                network,
                ws_path,
                ws_host,
                grpc_service_name,
                transport_headers,
                alpn,
            } => {
                assert_eq!(name, "TR-01");
                assert_eq!(server, "tr.example.com");
                assert_eq!(port, 443);
                assert_eq!(password, "secret");
                assert_eq!(sni.as_deref(), Some("cdn.example.com"));
                assert!(skip_cert_verify);
                assert_eq!(network.as_deref(), Some("tcp"));
                assert!(ws_path.is_none());
                assert!(ws_host.is_none());
                assert!(grpc_service_name.is_none());
                assert!(transport_headers.is_empty());
                assert!(alpn.is_empty());
            }
            other => panic!("unexpected outbound {other:?}"),
        }
    }

    #[test]
    fn parses_trojan_uri_to_outbound_config() {
        let uri = "trojan://secret@tr.example.com:443?sni=cdn.example.com&allowInsecure=1#TR";

        let doc = parse_subscription(uri).unwrap();
        let outbound = doc.nodes[0].to_outbound_config().unwrap();

        match outbound {
            OutboundConfig::Trojan {
                name,
                server,
                port,
                password,
                sni,
                skip_cert_verify,
                network,
                ws_path,
                ws_host,
                grpc_service_name,
                transport_headers,
                alpn,
            } => {
                assert_eq!(name, "TR");
                assert_eq!(server, "tr.example.com");
                assert_eq!(port, 443);
                assert_eq!(password, "secret");
                assert_eq!(sni.as_deref(), Some("cdn.example.com"));
                assert!(skip_cert_verify);
                assert_eq!(network.as_deref(), Some("tcp"));
                assert!(ws_path.is_none());
                assert!(ws_host.is_none());
                assert!(grpc_service_name.is_none());
                assert!(transport_headers.is_empty());
                assert!(alpn.is_empty());
            }
            other => panic!("unexpected outbound {other:?}"),
        }
    }

    #[test]
    fn converts_trojan_http_upgrade_yaml_to_outbound_config() {
        let text = r#"
proxies:
  - name: TR-HTTP-UPGRADE
    type: trojan
    server: tr.example.com
    port: 443
    password: secret
    sni: cdn.example.com
    network: httpupgrade
    alpn:
      - http/1.1
    http-upgrade-opts:
      path: /trojan
      host: edge.example.com
      headers:
        X-Supercore-Test: enabled
"#;

        let doc = parse_subscription(text).unwrap();
        let outbound = doc.nodes[0].to_outbound_config().unwrap();

        match outbound {
            OutboundConfig::Trojan {
                network,
                ws_path,
                ws_host,
                grpc_service_name,
                transport_headers,
                alpn,
                ..
            } => {
                assert_eq!(network.as_deref(), Some("httpupgrade"));
                assert_eq!(ws_path.as_deref(), Some("/trojan"));
                assert_eq!(ws_host.as_deref(), Some("edge.example.com"));
                assert!(grpc_service_name.is_none());
                assert_eq!(
                    transport_headers
                        .get("X-Supercore-Test")
                        .map(String::as_str),
                    Some("enabled")
                );
                assert_eq!(alpn, vec!["http/1.1"]);
            }
            other => panic!("unexpected outbound {other:?}"),
        }
    }

    #[test]
    fn parses_trojan_grpc_uri_to_outbound_config() {
        let uri = "trojan://secret@tr.example.com:443?type=grpc&serviceName=trojan-grpc&host=cdn.example.com&sni=cdn.example.com#TR-GRPC";

        let doc = parse_subscription(uri).unwrap();
        let outbound = doc.nodes[0].to_outbound_config().unwrap();

        match outbound {
            OutboundConfig::Trojan {
                network,
                ws_host,
                grpc_service_name,
                ..
            } => {
                assert_eq!(network.as_deref(), Some("grpc"));
                assert_eq!(ws_host.as_deref(), Some("cdn.example.com"));
                assert_eq!(grpc_service_name.as_deref(), Some("trojan-grpc"));
            }
            other => panic!("unexpected outbound {other:?}"),
        }
    }

    #[test]
    fn converts_vmess_websocket_yaml_to_outbound_config() {
        let text = r#"
proxies:
  - name: VM-WS
    type: vmess
    server: vm.example.com
    port: 443
    uuid: 11111111-1111-1111-1111-111111111111
    alterId: 0
    cipher: auto
    tls: true
    servername: cdn.example.com
    network: ws
    ws-opts:
      path: /ray
      headers:
        Host: edge.example.com
"#;

        let doc = parse_subscription(text).unwrap();
        let outbound = doc.nodes[0].to_outbound_config().unwrap();

        match outbound {
            OutboundConfig::Vmess {
                name,
                server,
                port,
                uuid,
                cipher,
                tls,
                sni,
                network,
                ws_path,
                ws_host,
                ..
            } => {
                assert_eq!(name, "VM-WS");
                assert_eq!(server, "vm.example.com");
                assert_eq!(port, 443);
                assert_eq!(uuid, "11111111-1111-1111-1111-111111111111");
                assert_eq!(cipher, "auto");
                assert!(tls);
                assert_eq!(sni.as_deref(), Some("cdn.example.com"));
                assert_eq!(network.as_deref(), Some("ws"));
                assert_eq!(ws_path.as_deref(), Some("/ray"));
                assert_eq!(ws_host.as_deref(), Some("edge.example.com"));
            }
            other => panic!("unexpected outbound {other:?}"),
        }
    }

    #[test]
    fn converts_vmess_grpc_yaml_to_outbound_config() {
        let text = r#"
proxies:
  - name: VM-GRPC
    type: vmess
    server: vm.example.com
    port: 443
    uuid: 11111111-1111-1111-1111-111111111111
    alterId: 0
    cipher: auto
    tls: true
    servername: cdn.example.com
    network: grpc
    grpc-opts:
      grpc-service-name: ray
"#;

        let doc = parse_subscription(text).unwrap();
        let outbound = doc.nodes[0].to_outbound_config().unwrap();

        match outbound {
            OutboundConfig::Vmess {
                network,
                grpc_service_name,
                ..
            } => {
                assert_eq!(network.as_deref(), Some("grpc"));
                assert_eq!(grpc_service_name.as_deref(), Some("ray"));
            }
            other => panic!("unexpected outbound {other:?}"),
        }
    }

    #[test]
    fn converts_vmess_h2_yaml_to_outbound_config() {
        let text = r#"
proxies:
  - name: VM-H2
    type: vmess
    server: vm.example.com
    port: 443
    uuid: 11111111-1111-1111-1111-111111111111
    alterId: 0
    cipher: auto
    tls: true
    network: h2
    h2-opts:
      path: /ray
      host:
        - cdn.example.com
"#;

        let doc = parse_subscription(text).unwrap();
        let outbound = doc.nodes[0].to_outbound_config().unwrap();

        match outbound {
            OutboundConfig::Vmess {
                network,
                ws_path,
                ws_host,
                ..
            } => {
                assert_eq!(network.as_deref(), Some("h2"));
                assert_eq!(ws_path.as_deref(), Some("/ray"));
                assert_eq!(ws_host.as_deref(), Some("cdn.example.com"));
            }
            other => panic!("unexpected outbound {other:?}"),
        }
    }

    #[test]
    fn preserves_legacy_vmess_alter_id() {
        let text = r#"
proxies:
  - name: VM-OLD
    type: vmess
    server: vm.example.com
    port: 443
    uuid: 11111111-1111-1111-1111-111111111111
    alterId: 64
"#;

        let doc = parse_subscription(text).unwrap();
        let outbound = doc.nodes[0].to_outbound_config().unwrap();
        match outbound {
            OutboundConfig::Vmess { alter_id, .. } => assert_eq!(alter_id, 64),
            other => panic!("unexpected outbound {other:?}"),
        }
    }

    #[test]
    fn converts_standard_vmess_uri_without_confusing_header_type_for_network() {
        let json = r#"{"v":"2","ps":"VM-URI","add":"vm.example.com","port":"443","id":"11111111-1111-1111-1111-111111111111","aid":"64","scy":"aes-128-gcm","net":"ws","type":"none","host":"cdn.example.com","path":"/ray","tls":"tls","sni":"origin.example.com","alpn":"http/1.1"}"#;
        let encoded = base64::engine::general_purpose::STANDARD_NO_PAD.encode(json);
        let doc = parse_subscription(&format!("vmess://{encoded}")).unwrap();
        let outbound = doc.nodes[0].to_outbound_config().unwrap();

        match outbound {
            OutboundConfig::Vmess {
                name,
                server,
                port,
                alter_id,
                cipher,
                network,
                ws_path,
                ws_host,
                tls,
                sni,
                alpn,
                ..
            } => {
                assert_eq!(name, "VM-URI");
                assert_eq!(server, "vm.example.com");
                assert_eq!(port, 443);
                assert_eq!(alter_id, 64);
                assert_eq!(cipher, "aes-128-gcm");
                assert_eq!(network.as_deref(), Some("ws"));
                assert_eq!(ws_path.as_deref(), Some("/ray"));
                assert_eq!(ws_host.as_deref(), Some("cdn.example.com"));
                assert!(tls);
                assert_eq!(sni.as_deref(), Some("origin.example.com"));
                assert_eq!(alpn, vec!["http/1.1"]);
            }
            other => panic!("unexpected outbound {other:?}"),
        }
    }

    #[test]
    fn maps_standard_vmess_tcp_http_header_to_http_camouflage() {
        let json = r#"{"v":"2","ps":"VM-HTTP","add":"vm.example.com","port":80,"id":"11111111-1111-1111-1111-111111111111","aid":0,"net":"tcp","type":"http","host":"cdn.example.com","path":"/http"}"#;
        let encoded = base64::engine::general_purpose::STANDARD_NO_PAD.encode(json);
        let doc = parse_subscription(&format!("vmess://{encoded}")).unwrap();
        let outbound = doc.nodes[0].to_outbound_config().unwrap();

        match outbound {
            OutboundConfig::Vmess {
                network,
                ws_path,
                ws_host,
                ..
            } => {
                assert_eq!(network.as_deref(), Some("http"));
                assert_eq!(ws_path.as_deref(), Some("/http"));
                assert_eq!(ws_host.as_deref(), Some("cdn.example.com"));
            }
            other => panic!("unexpected outbound {other:?}"),
        }
    }

    #[test]
    fn converts_vless_uri_to_outbound_config() {
        let uri = "vless://11111111-1111-1111-1111-111111111111@vl.example.com:443?security=tls&type=tcp&sni=cdn.example.com&allowInsecure=1#VL";

        let doc = parse_subscription(uri).unwrap();
        let outbound = doc.nodes[0].to_outbound_config().unwrap();

        match outbound {
            OutboundConfig::Vless {
                name,
                server,
                port,
                uuid,
                tls,
                sni,
                skip_cert_verify,
                network,
                ws_path,
                ws_host,
                grpc_service_name,
                ..
            } => {
                assert_eq!(name, "VL");
                assert_eq!(server, "vl.example.com");
                assert_eq!(port, 443);
                assert_eq!(uuid, "11111111-1111-1111-1111-111111111111");
                assert!(tls);
                assert_eq!(sni.as_deref(), Some("cdn.example.com"));
                assert!(skip_cert_verify);
                assert_eq!(network.as_deref(), Some("tcp"));
                assert!(ws_path.is_none());
                assert!(ws_host.is_none());
                assert!(grpc_service_name.is_none());
            }
            other => panic!("unexpected outbound {other:?}"),
        }
    }

    #[test]
    fn converts_vless_yaml_to_outbound_config() {
        let text = r#"
proxies:
  - name: VL-01
    type: vless
    server: vl.example.com
    port: 443
    uuid: 11111111-1111-1111-1111-111111111111
    tls: true
    servername: cdn.example.com
"#;

        let doc = parse_subscription(text).unwrap();
        let outbound = doc.nodes[0].to_outbound_config().unwrap();

        match outbound {
            OutboundConfig::Vless {
                name,
                server,
                port,
                uuid,
                tls,
                sni,
                skip_cert_verify,
                network,
                ws_path,
                ws_host,
                grpc_service_name,
                ..
            } => {
                assert_eq!(name, "VL-01");
                assert_eq!(server, "vl.example.com");
                assert_eq!(port, 443);
                assert_eq!(uuid, "11111111-1111-1111-1111-111111111111");
                assert!(tls);
                assert_eq!(sni.as_deref(), Some("cdn.example.com"));
                assert!(!skip_cert_verify);
                assert_eq!(network.as_deref(), Some("tcp"));
                assert!(ws_path.is_none());
                assert!(ws_host.is_none());
                assert!(grpc_service_name.is_none());
            }
            other => panic!("unexpected outbound {other:?}"),
        }
    }

    #[test]
    fn converts_vless_websocket_yaml_to_outbound_config() {
        let text = r#"
proxies:
  - name: VL-WS
    type: vless
    server: vl.example.com
    port: 443
    uuid: 11111111-1111-1111-1111-111111111111
    tls: true
    network: ws
    ws-opts:
      path: /ray
      headers:
        Host: cdn.example.com
"#;

        let doc = parse_subscription(text).unwrap();
        let outbound = doc.nodes[0].to_outbound_config().unwrap();

        match outbound {
            OutboundConfig::Vless {
                network,
                ws_path,
                ws_host,
                ..
            } => {
                assert_eq!(network.as_deref(), Some("ws"));
                assert_eq!(ws_path.as_deref(), Some("/ray"));
                assert_eq!(ws_host.as_deref(), Some("cdn.example.com"));
            }
            other => panic!("unexpected outbound {other:?}"),
        }
    }

    #[test]
    fn converts_vless_http_upgrade_headers_and_alpn() {
        let text = r#"
proxies:
  - name: VL-UPGRADE
    type: vless
    server: vl.example.com
    port: 443
    uuid: 11111111-1111-1111-1111-111111111111
    security: tls
    network: httpupgrade
    alpn:
      - http/1.1
    http-upgrade-opts:
      path: /upgrade
      headers:
        Host: cdn.example.com
        X-VLESS-Test: enabled
"#;

        let doc = parse_subscription(text).unwrap();
        let outbound = doc.nodes[0].to_outbound_config().unwrap();
        match outbound {
            OutboundConfig::Vless {
                network,
                ws_path,
                ws_host,
                transport_headers,
                alpn,
                ..
            } => {
                assert_eq!(network.as_deref(), Some("httpupgrade"));
                assert_eq!(ws_path.as_deref(), Some("/upgrade"));
                assert_eq!(ws_host.as_deref(), Some("cdn.example.com"));
                assert_eq!(transport_headers["X-VLESS-Test"], "enabled");
                assert_eq!(alpn, vec!["http/1.1"]);
            }
            other => panic!("unexpected outbound {other:?}"),
        }
    }

    #[test]
    fn converts_vless_grpc_uri_to_outbound_config() {
        let uri = "vless://11111111-1111-1111-1111-111111111111@vl.example.com:443?security=tls&type=grpc&serviceName=ray&sni=cdn.example.com#VL-GRPC";

        let doc = parse_subscription(uri).unwrap();
        let outbound = doc.nodes[0].to_outbound_config().unwrap();

        match outbound {
            OutboundConfig::Vless {
                name,
                network,
                grpc_service_name,
                sni,
                ..
            } => {
                assert_eq!(name, "VL-GRPC");
                assert_eq!(network.as_deref(), Some("grpc"));
                assert_eq!(grpc_service_name.as_deref(), Some("ray"));
                assert_eq!(sni.as_deref(), Some("cdn.example.com"));
            }
            other => panic!("unexpected outbound {other:?}"),
        }
    }

    #[test]
    fn converts_vless_h2_uri_to_outbound_config() {
        let uri = "vless://11111111-1111-1111-1111-111111111111@vl.example.com:443?security=tls&type=h2&path=%2Fray&host=cdn.example.com&sni=cdn.example.com#VL-H2";

        let doc = parse_subscription(uri).unwrap();
        let outbound = doc.nodes[0].to_outbound_config().unwrap();

        match outbound {
            OutboundConfig::Vless {
                name,
                network,
                ws_path,
                ws_host,
                ..
            } => {
                assert_eq!(name, "VL-H2");
                assert_eq!(network.as_deref(), Some("h2"));
                assert_eq!(ws_path.as_deref(), Some("/ray"));
                assert_eq!(ws_host.as_deref(), Some("cdn.example.com"));
            }
            other => panic!("unexpected outbound {other:?}"),
        }
    }

    #[test]
    fn parses_vless_reality_and_vision_fields() {
        let reality = parse_subscription(
            "vless://11111111-1111-1111-1111-111111111111@vl.example.com:443?security=reality&type=tcp&pbk=AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE&sid=01&fp=chrome&spx=%2F#VL",
        )
        .unwrap();
        let vision = parse_subscription(
            "vless://11111111-1111-1111-1111-111111111111@vl.example.com:443?security=tls&type=tcp&flow=xtls-rprx-vision#VL",
        )
        .unwrap();

        match reality.nodes[0].to_outbound_config().unwrap() {
            OutboundConfig::Vless {
                security,
                reality_public_key,
                reality_short_id,
                reality_fingerprint,
                reality_spider_x,
                ..
            } => {
                assert_eq!(security.as_deref(), Some("reality"));
                assert_eq!(
                    reality_public_key.as_deref(),
                    Some("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE")
                );
                assert_eq!(reality_short_id.as_deref(), Some("01"));
                assert_eq!(reality_fingerprint.as_deref(), Some("chrome"));
                assert_eq!(reality_spider_x.as_deref(), Some("/"));
            }
            other => panic!("unexpected outbound {other:?}"),
        }
        match vision.nodes[0].to_outbound_config().unwrap() {
            OutboundConfig::Vless { flow, security, .. } => {
                assert_eq!(security.as_deref(), Some("tls"));
                assert_eq!(flow.as_deref(), Some("xtls-rprx-vision"));
            }
            other => panic!("unexpected outbound {other:?}"),
        }
    }

    #[test]
    fn parses_hysteria2_uri_to_outbound_config() {
        let uri = "hysteria2://secret@hy.example.com:443?sni=cdn.example.com&insecure=1&obfs=salamander&obfs-password=mask#HY2";

        let doc = parse_subscription(uri).unwrap();
        let outbound = doc.nodes[0].to_outbound_config().unwrap();

        match outbound {
            OutboundConfig::Hysteria2 {
                name,
                server,
                port,
                password,
                sni,
                skip_cert_verify,
                obfs,
                obfs_password,
                ..
            } => {
                assert_eq!(name, "HY2");
                assert_eq!(server, "hy.example.com");
                assert_eq!(port, 443);
                assert_eq!(password, "secret");
                assert_eq!(sni.as_deref(), Some("cdn.example.com"));
                assert!(skip_cert_verify);
                assert_eq!(obfs.as_deref(), Some("salamander"));
                assert_eq!(obfs_password.as_deref(), Some("mask"));
            }
            other => panic!("unexpected outbound {other:?}"),
        }
    }

    #[test]
    fn parses_tuic_uri_to_outbound_config() {
        let uri = "tuic://11111111-1111-1111-1111-111111111111:secret@tu.example.com:443?sni=cdn.example.com&congestion_control=bbr&udp_relay_mode=native#TUIC";

        let doc = parse_subscription(uri).unwrap();
        let outbound = doc.nodes[0].to_outbound_config().unwrap();

        match outbound {
            OutboundConfig::Tuic {
                name,
                server,
                port,
                uuid,
                password,
                sni,
                congestion_control,
                udp_relay_mode,
                ..
            } => {
                assert_eq!(name, "TUIC");
                assert_eq!(server, "tu.example.com");
                assert_eq!(port, 443);
                assert_eq!(uuid, "11111111-1111-1111-1111-111111111111");
                assert_eq!(password, "secret");
                assert_eq!(sni.as_deref(), Some("cdn.example.com"));
                assert_eq!(congestion_control.as_deref(), Some("bbr"));
                assert_eq!(udp_relay_mode.as_deref(), Some("native"));
            }
            other => panic!("unexpected outbound {other:?}"),
        }
    }
}
