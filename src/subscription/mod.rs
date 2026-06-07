use std::collections::BTreeMap;

use anyhow::{anyhow, Context};
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_yaml::Value;
use url::Url;

use crate::config::{OutboundConfig, ShadowsocksPluginConfig};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubscriptionDocument {
    pub source_format: String,
    pub nodes: Vec<SubscriptionNode>,
    pub groups: Vec<SubscriptionGroup>,
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
                        .or_else(|| self.params.get("congestion_control"))
                        .cloned(),
                    udp_relay_mode: self
                        .params
                        .get("udp-relay-mode")
                        .or_else(|| self.params.get("udp_relay_mode"))
                        .cloned(),
                    alpn: self.params.get("alpn").cloned(),
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
                    &["preshared-key", "preshared_key", "presharedKey"],
                ),
                ip: string_list_param(&self.params, &["ip", "address"]),
                ipv6: string_list_param(&self.params, &["ipv6"]),
                allowed_ips: string_list_param(
                    &self.params,
                    &["allowed-ips", "allowed_ips", "allowedIPs"],
                ),
                reserved: first_param(&self.params, &["reserved"])
                    .map(|value| {
                        value
                            .split(',')
                            .filter_map(|part| part.trim().parse::<u8>().ok())
                            .collect()
                    })
                    .unwrap_or_default(),
                mtu: first_param(&self.params, &["mtu"]).and_then(|value| value.parse().ok()),
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
                if alter_id != 0 {
                    return Err(anyhow!(
                        "vmess node {} uses legacy alterId {}; only AEAD alterId=0 is supported",
                        self.name,
                        alter_id
                    ));
                }
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
                    cipher,
                    tls,
                    sni: self
                        .params
                        .get("sni")
                        .or_else(|| self.params.get("servername"))
                        .cloned(),
                    skip_cert_verify: bool_param(&self.params, "skip-cert-verify")
                        || bool_param(&self.params, "allowInsecure"),
                    network: Some(if network == "websocket" {
                        "ws".to_string()
                    } else {
                        network
                    }),
                    ws_path: self.params.get("path").cloned(),
                    ws_host: self
                        .params
                        .get("host")
                        .or_else(|| self.params.get("ws-host"))
                        .cloned(),
                    grpc_service_name: grpc_service_name(&self.params),
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
                    network: Some(if network == "websocket" {
                        "ws".to_string()
                    } else {
                        network
                    }),
                    ws_path: self.params.get("path").cloned(),
                    ws_host: self
                        .params
                        .get("host")
                        .or_else(|| self.params.get("ws-host"))
                        .cloned(),
                    grpc_service_name: grpc_service_name(&self.params),
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
        if key == "grpc-opts" {
            parse_clash_grpc_opts(value, &mut params);
            continue;
        }
        if key == "h2-opts" {
            parse_clash_h2_opts(value, &mut params);
            continue;
        }
        if let Some(value) = yaml_scalar_to_string(value) {
            params.insert(key.to_string(), value);
        } else if let Some(values) = yaml_string_list(value) {
            params.insert(key.to_string(), values.join(","));
        }
    }
    Ok(SubscriptionNode {
        name,
        protocol,
        server,
        port,
        params,
    })
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
    Ok(SubscriptionGroup {
        name,
        kind,
        members,
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
        match parse_node_uri(line) {
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
        "id", "aid", "net", "type", "host", "path", "tls", "sni", "alpn", "scy",
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
    let plugin = plugin.to_ascii_lowercase();
    if plugin != "obfs" && !plugin.starts_with("simple-obfs") {
        return Err(anyhow!("unsupported shadowsocks plugin {plugin}"));
    }
    let mode = params
        .get("plugin-mode")
        .or_else(|| params.get("obfs"))
        .cloned()
        .unwrap_or_else(|| "http".to_string());
    Ok(Some(ShadowsocksPluginConfig {
        mode,
        host: params
            .get("plugin-host")
            .or_else(|| params.get("obfs-host"))
            .cloned(),
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
    if let Some(headers) = mapping
        .get(Value::String("headers".to_string()))
        .and_then(Value::as_mapping)
    {
        if let Some(host) = yaml_string(headers, "Host").or_else(|| yaml_string(headers, "host")) {
            params.insert("host".to_string(), host);
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

fn parse_simple_obfs_plugin(value: &str, params: &mut BTreeMap<String, String>) {
    let parts = value.split(';').collect::<Vec<_>>();
    if parts
        .first()
        .map(|item| item.eq_ignore_ascii_case("simple-obfs"))
        .unwrap_or(false)
    {
        for part in parts.into_iter().skip(1) {
            let Some((key, value)) = part.split_once('=') else {
                continue;
            };
            match key {
                "obfs" => {
                    params.insert("plugin-mode".to_string(), value.to_string());
                }
                "obfs-host" => {
                    params.insert("plugin-host".to_string(), value.to_string());
                }
                _ => {}
            }
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
            } => {
                assert_eq!(name, "TR-01");
                assert_eq!(server, "tr.example.com");
                assert_eq!(port, 443);
                assert_eq!(password, "secret");
                assert_eq!(sni.as_deref(), Some("cdn.example.com"));
                assert!(skip_cert_verify);
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
            } => {
                assert_eq!(name, "TR");
                assert_eq!(server, "tr.example.com");
                assert_eq!(port, 443);
                assert_eq!(password, "secret");
                assert_eq!(sni.as_deref(), Some("cdn.example.com"));
                assert!(skip_cert_verify);
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
    fn refuses_legacy_vmess_alter_id() {
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
        let error = doc.nodes[0].to_outbound_config().unwrap_err();
        assert!(error.to_string().contains("legacy alterId"));
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
            "vless://11111111-1111-1111-1111-111111111111@vl.example.com:443?security=reality&type=tcp&pbk=pub&sid=01&fp=chrome&spx=%2F#VL",
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
                assert_eq!(reality_public_key.as_deref(), Some("pub"));
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
