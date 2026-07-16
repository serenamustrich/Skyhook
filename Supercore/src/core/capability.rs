use crate::config::OutboundConfig;

use super::OutboundCapabilitySnapshot;

pub(super) fn outbound_config_kind(config: &OutboundConfig) -> String {
    match config {
        OutboundConfig::Direct { .. } => "direct".to_string(),
        OutboundConfig::Reject { .. } => "reject".to_string(),
        OutboundConfig::Http { .. } => "http".to_string(),
        OutboundConfig::Socks5 { .. } => "socks5".to_string(),
        OutboundConfig::Shadowsocks { .. } => "shadowsocks".to_string(),
        OutboundConfig::Trojan { .. } => "trojan".to_string(),
        OutboundConfig::Vmess { .. } => "vmess".to_string(),
        OutboundConfig::Vless { .. } => "vless".to_string(),
        OutboundConfig::Hysteria2 { .. } => "hysteria2".to_string(),
        OutboundConfig::Tuic { .. } => "tuic".to_string(),
        OutboundConfig::Naive { .. } => "naive".to_string(),
        OutboundConfig::Ssr { .. } => "ssr".to_string(),
        OutboundConfig::Snell { .. } => "snell".to_string(),
        OutboundConfig::Hysteria { .. } => "hysteria".to_string(),
        OutboundConfig::AnyTls { .. } => "anytls".to_string(),
        OutboundConfig::ShadowTls { .. } => "shadowtls".to_string(),
        OutboundConfig::WireGuard { .. } => "wireguard".to_string(),
        OutboundConfig::Ssh { .. } => "ssh".to_string(),
        OutboundConfig::Mieru { .. } => "mieru".to_string(),
        OutboundConfig::Juicity { .. } => "juicity".to_string(),
        OutboundConfig::Masque { .. } => "masque".to_string(),
        OutboundConfig::OpenVpn { .. } => "openvpn".to_string(),
        OutboundConfig::Unknown { protocol, .. } => format!("unknown:{protocol}"),
        OutboundConfig::Group { kind, .. } => format!("group:{kind}"),
    }
}

pub(super) fn outbound_capability_snapshot(config: &OutboundConfig) -> OutboundCapabilitySnapshot {
    let mut limitations = Vec::new();
    let (tcp_supported, udp_supported, udp_mode) = match config {
        OutboundConfig::Direct { .. } => (true, true, Some("native".to_string())),
        OutboundConfig::Reject { .. } => {
            limitations.push("reject outbound intentionally blocks traffic".to_string());
            (false, false, None)
        }
        OutboundConfig::Http { .. } => {
            limitations.push("http proxy udp is not supported".to_string());
            (true, false, None)
        }
        OutboundConfig::Socks5 { .. } => (
            true,
            true,
            Some("socks5-udp-associate-session-pool".to_string()),
        ),
        OutboundConfig::Shadowsocks { plugin, method, .. } => {
            let method = method.to_ascii_lowercase();
            let method_supported = matches!(
                method.as_str(),
                "aes-128-gcm"
                    | "aes-256-gcm"
                    | "chacha20-ietf-poly1305"
                    | "2022-blake3-aes-128-gcm"
                    | "2022-blake3-aes-256-gcm"
                    | "2022-blake3-chacha20-poly1305"
            );
            let udp_mode = if plugin.is_some() {
                limitations.push("shadowsocks with plugin does not support UDP relay".to_string());
                None
            } else {
                Some("shadowsocks-aead-udp-socket-pool".to_string())
            };
            if !method_supported {
                limitations.push(format!("unsupported shadowsocks method {method}"));
            }
            if let Some(plugin) = plugin {
                let mode = plugin.mode.to_ascii_lowercase();
                if mode != "http_simple"
                    && mode != "http_post"
                    && mode != "tls"
                    && mode != "v2ray-plugin"
                    && mode != "websocket"
                {
                    limitations.push(format!(
                        "unsupported shadowsocks plugin mode {}",
                        plugin.mode
                    ));
                }
            }
            (method_supported, plugin.is_none(), udp_mode)
        }
        OutboundConfig::Trojan { network, alpn, .. } => {
            let network = network
                .as_deref()
                .unwrap_or("tcp")
                .trim()
                .to_ascii_lowercase();
            let transport_supported = matches!(
                network.as_str(),
                "tcp"
                    | "ws"
                    | "websocket"
                    | "grpc"
                    | "h2"
                    | "http"
                    | "httpupgrade"
                    | "http-upgrade"
            );
            if !transport_supported {
                limitations.push(format!("unsupported trojan network {network}"));
            }
            let configured_alpn = alpn
                .iter()
                .flat_map(|value| value.split(','))
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .collect::<Vec<_>>();
            let alpn_supported = configured_alpn.is_empty()
                || if matches!(network.as_str(), "grpc" | "h2" | "http") {
                    configured_alpn.contains(&"h2")
                } else if matches!(
                    network.as_str(),
                    "ws" | "websocket" | "httpupgrade" | "http-upgrade"
                ) {
                    configured_alpn.contains(&"http/1.1")
                } else {
                    true
                };
            if !alpn_supported {
                limitations.push(format!(
                    "trojan network {network} has incompatible ALPN configuration"
                ));
            }
            let supported = transport_supported && alpn_supported;
            (
                supported,
                supported,
                supported.then(|| "trojan-udp-associate-stream-pool".to_string()),
            )
        }
        OutboundConfig::Vmess { .. } => (
            true,
            true,
            Some("vmess-command-udp-session-pool".to_string()),
        ),
        OutboundConfig::Vless {
            security,
            reality_public_key,
            ..
        } => {
            if security
                .as_deref()
                .map(|value| value.eq_ignore_ascii_case("reality"))
                .unwrap_or(false)
            {
                if reality_public_key
                    .as_deref()
                    .unwrap_or("")
                    .trim()
                    .is_empty()
                {
                    limitations.push("vless reality public key is missing".to_string());
                }
                (
                    true,
                    true,
                    Some("vless-reality-command-udp-session-pool".to_string()),
                )
            } else {
                (
                    true,
                    true,
                    Some("vless-command-udp-session-pool".to_string()),
                )
            }
        }
        OutboundConfig::Hysteria2 { obfs, .. } => {
            let obfs = obfs
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(|value| value.to_ascii_lowercase());
            if obfs.is_some() && !matches!(obfs.as_deref(), Some("salamander" | "gecko")) {
                limitations.push("unsupported hysteria2 obfuscation mode".to_string());
                (false, false, None)
            } else {
                let mode = match obfs.as_deref() {
                    Some("salamander") => "quic-datagram-salamander-session-pool",
                    Some("gecko") => "quic-datagram-gecko-session-pool",
                    _ => "quic-datagram-session-pool",
                };
                (true, true, Some(mode.to_string()))
            }
        }
        OutboundConfig::Tuic { udp_relay_mode, .. } => (
            true,
            true,
            Some(format!(
                "{}-session-pool",
                udp_relay_mode.as_deref().unwrap_or("native")
            )),
        ),
        OutboundConfig::Naive { .. } => {
            limitations.push("naive udp is not supported".to_string());
            (true, false, Some("tls-http-connect".to_string()))
        }
        OutboundConfig::Ssr {
            method,
            protocol,
            obfs,
            ..
        } => {
            let method_supported = matches!(
                method.to_ascii_lowercase().as_str(),
                "aes-128-cfb"
                    | "aes-192-cfb"
                    | "aes-256-cfb"
                    | "rc4-md5"
                    | "chacha20"
                    | "chacha20-ietf"
            );
            let protocol_supported = matches!(
                protocol.to_ascii_lowercase().as_str(),
                "origin"
                    | "verify_simple"
                    | "auth_simple"
                    | "auth_sha1"
                    | "auth_sha1_v2"
                    | "auth_sha1_v4"
                    | "auth_aes128_md5"
                    | "auth_aes128_sha1"
                    | "auth_chain_a"
                    | "auth_chain_b"
                    | "auth_chain_c"
                    | "auth_chain_d"
                    | "auth_chain_e"
                    | "auth_chain_f"
            );
            let obfs_supported = matches!(
                obfs.to_ascii_lowercase().as_str(),
                "plain"
                    | ""
                    | "http_simple"
                    | "http-simple"
                    | "http_post"
                    | "http-post"
                    | "tls1.2_ticket_auth"
                    | "tls1.2-ticket-auth"
            );
            if !method_supported {
                limitations.push(format!("unsupported ssr method {method}"));
            }
            if !protocol_supported {
                limitations.push(format!("unsupported ssr protocol {protocol}"));
            }
            if !obfs_supported {
                limitations.push(format!("unsupported ssr obfs {obfs}"));
            }
            let udp_supported = method_supported
                && matches!(
                    protocol.to_ascii_lowercase().as_str(),
                    "origin"
                        | "verify_simple"
                        | "auth_simple"
                        | "auth_sha1"
                        | "auth_sha1_v2"
                        | "auth_aes128_md5"
                        | "auth_aes128_sha1"
                        | "auth_chain_a"
                        | "auth_chain_b"
                        | "auth_chain_c"
                        | "auth_chain_d"
                        | "auth_chain_e"
                        | "auth_chain_f"
                )
                && obfs_supported;
            if protocol.eq_ignore_ascii_case("auth_sha1_v4") {
                limitations.push(format!("ssr {protocol} udp is not supported"));
            }
            (
                method_supported && protocol_supported && obfs_supported,
                udp_supported,
                Some(if udp_supported {
                    "ssr-datagram-stream-cipher".to_string()
                } else {
                    "ssr-authenticated-tcp".to_string()
                }),
            )
        }
        OutboundConfig::Snell {
            method,
            version,
            obfs,
            reuse,
            ..
        } => {
            let version = version.unwrap_or(3);
            let method = method.as_deref().unwrap_or(if version == 1 {
                "chacha20-ietf-poly1305"
            } else {
                "aes-128-gcm"
            });
            let method_supported = if version >= 4 {
                method.eq_ignore_ascii_case("aes-128-gcm")
            } else {
                matches!(
                    method.to_ascii_lowercase().as_str(),
                    "aes-128-gcm" | "aes-256-gcm" | "chacha20-ietf-poly1305" | "chacha20-poly1305"
                )
            };
            let version_supported = matches!(version, 1..=5);
            let obfs = obfs
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(|value| value.to_ascii_lowercase());
            let obfs_supported = obfs
                .as_deref()
                .map(|value| {
                    matches!(
                        value,
                        "none"
                            | "off"
                            | "http"
                            | "http_simple"
                            | "http-simple"
                            | "tls"
                            | "simple-obfs-tls"
                            | "obfs-tls"
                    )
                })
                .unwrap_or(true);
            if !method_supported {
                limitations.push(format!("unsupported snell method {method}"));
            }
            if !version_supported {
                limitations.push(format!("unsupported snell version {version}"));
            }
            if !obfs_supported {
                limitations.push(format!(
                    "unsupported snell obfs {}",
                    obfs.as_deref().unwrap_or_default()
                ));
            }
            let reuse_supported = !reuse || matches!(version, 4 | 5);
            if !reuse_supported {
                limitations.push("snell connection reuse requires version 4 or 5".to_string());
            }
            let udp_supported = version_supported
                && method_supported
                && matches!(version, 3..=5)
                && obfs
                    .as_deref()
                    .map(|value| matches!(value, "none" | "off"))
                    .unwrap_or(true);
            if version < 3 {
                limitations.push("snell udp requires version 3, 4, or 5".to_string());
            } else if !udp_supported {
                limitations.push("snell udp over simple-obfs is not supported".to_string());
            }
            (
                version_supported && method_supported && obfs_supported && reuse_supported,
                udp_supported,
                Some(if udp_supported {
                    if version >= 4 {
                        "snell-v4-framed-udp-over-tcp".to_string()
                    } else {
                        "snell-v3-udp-over-tcp".to_string()
                    }
                } else {
                    "snell-aead-tcp".to_string()
                }),
            )
        }
        OutboundConfig::Hysteria { .. } => {
            unsupported_protocol_capability("hysteria", &mut limitations)
        }
        OutboundConfig::AnyTls { .. } => {
            limitations.push("anytls udp is not supported".to_string());
            (true, false, Some("tls-anytls-session".to_string()))
        }
        OutboundConfig::ShadowTls { version, .. } => {
            let version_supported = version.unwrap_or(3) == 3;
            if !version_supported {
                limitations.push("only shadowtls v3 is supported".to_string());
            }
            limitations.push("shadowtls udp is not supported".to_string());
            limitations.push("standalone shadowtls uses socks-address target handoff".to_string());
            (
                version_supported,
                false,
                Some("shadowtls-v3-tcp-transport".to_string()),
            )
        }
        OutboundConfig::WireGuard {
            private_key,
            public_key,
            ip,
            ..
        } => {
            let mut limitations = Vec::new();
            let has_keys = !private_key.is_empty() && !public_key.is_empty();
            let has_ip = !ip.is_empty();
            if !has_keys {
                limitations.push("wireguard private_key and public_key are required".to_string());
            }
            if !has_ip {
                limitations.push("wireguard ip address is required".to_string());
            }
            (
                has_keys && has_ip,
                has_keys && has_ip,
                Some("wireguard-tunnel".to_string()),
            )
        }
        OutboundConfig::Ssh { .. } => {
            limitations.push("ssh udp is not supported".to_string());
            (true, false, Some("ssh-direct-tcpip".to_string()))
        }
        OutboundConfig::Mieru { .. } => unsupported_protocol_capability("mieru", &mut limitations),
        OutboundConfig::Juicity { .. } => {
            unsupported_protocol_capability("juicity", &mut limitations)
        }
        OutboundConfig::Masque { .. } => {
            unsupported_protocol_capability("masque", &mut limitations)
        }
        OutboundConfig::OpenVpn { .. } => {
            unsupported_protocol_capability("openvpn", &mut limitations)
        }
        OutboundConfig::Unknown { protocol, .. } => {
            unsupported_protocol_capability(protocol, &mut limitations)
        }
        OutboundConfig::Group { kind, .. } => (true, true, Some(format!("group-{kind}-delegated"))),
    };
    OutboundCapabilitySnapshot {
        name: config.name().to_string(),
        kind: outbound_config_kind(config),
        tcp_supported,
        udp_supported,
        udp_mode,
        limitations,
    }
}

fn unsupported_protocol_capability(
    protocol: &str,
    limitations: &mut Vec<String>,
) -> (bool, bool, Option<String>) {
    limitations.push(format!(
        "{protocol} is recognized in config/subscriptions but native dialing is not implemented yet"
    ));
    (false, false, None)
}
