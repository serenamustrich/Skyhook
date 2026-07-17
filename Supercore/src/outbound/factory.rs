use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};

use anyhow::anyhow;

use crate::{
    config::{OutboundCommonConfig, OutboundConfig},
    telemetry::Telemetry,
};

use super::{
    anytls::AnyTlsOutbound,
    configured::{outbound_registry, ConfiguredOutbound},
    direct::DirectOutbound,
    http_proxy::HttpOutbound,
    hysteria2::Hysteria2Outbound,
    naive::NaiveOutbound,
    registry::{attach_groups, insert_leaf},
    reject::RejectOutbound,
    shadowsocks::ShadowsocksOutbound,
    shadowtls::ShadowTlsOutbound,
    snell::SnellOutbound,
    socks5::Socks5Outbound,
    ssh::SshOutbound,
    ssr::SsrOutbound,
    traits::{Outbound, OutboundMap},
    trojan::TrojanOutbound,
    tuic::TuicOutbound,
    unsupported::UnsupportedProtocolOutbound,
    vless::VlessOutbound,
    vmess::VmessOutbound,
    wireguard::WireGuardOutbound,
};

pub fn build_outbounds(
    configs: &[OutboundConfig],
    telemetry: Option<Arc<Telemetry>>,
) -> anyhow::Result<OutboundMap> {
    build_outbounds_with_options(configs, &BTreeMap::new(), telemetry)
}

pub fn build_outbounds_with_options(
    configs: &[OutboundConfig],
    common_options: &BTreeMap<String, OutboundCommonConfig>,
    telemetry: Option<Arc<Telemetry>>,
) -> anyhow::Result<OutboundMap> {
    validate_common_options(configs, common_options)?;
    let mut outbounds: OutboundMap = HashMap::new();
    let registry = outbound_registry();
    for config in configs {
        if matches!(config, OutboundConfig::Group { .. }) {
            continue;
        }
        let outbound = build_leaf_outbound(config)?;
        let outbound = Arc::new(ConfiguredOutbound::new(
            outbound,
            common_options
                .get(config.name())
                .cloned()
                .unwrap_or_default(),
            Arc::clone(&registry),
        )) as Arc<dyn Outbound>;
        insert_leaf(&mut outbounds, config.name(), outbound)?;
    }

    attach_groups(configs, &mut outbounds, telemetry)?;
    let mut registered = registry
        .write()
        .map_err(|_| anyhow!("outbound registry lock poisoned"))?;
    registered.extend(
        outbounds
            .iter()
            .map(|(name, outbound)| (name.clone(), Arc::downgrade(outbound))),
    );
    drop(registered);
    Ok(outbounds)
}

fn validate_common_options(
    configs: &[OutboundConfig],
    common_options: &BTreeMap<String, OutboundCommonConfig>,
) -> anyhow::Result<()> {
    let configs_by_name = configs
        .iter()
        .map(|config| (config.name(), config))
        .collect::<HashMap<_, _>>();
    for (name, options) in common_options {
        let config = configs_by_name
            .get(name.as_str())
            .ok_or_else(|| anyhow!("outbound-options references unknown outbound {name}"))?;
        if matches!(config, OutboundConfig::Group { .. }) {
            return Err(anyhow!(
                "outbound-options cannot be applied to proxy group {name}"
            ));
        }
        options
            .validate()
            .map_err(|error| anyhow!("invalid outbound-options for {name}: {error}"))?;
        if let Some(dialer) = options.dialer_proxy.as_deref() {
            let dialer = dialer.trim();
            if !configs_by_name.contains_key(dialer) {
                return Err(anyhow!(
                    "dialer-proxy {dialer} referenced by {name} does not exist"
                ));
            }
        }
    }

    for start in common_options.keys() {
        let mut chain = Vec::new();
        let mut current = start.as_str();
        loop {
            if let Some(position) = chain.iter().position(|name| *name == current) {
                chain.push(current);
                return Err(anyhow!(
                    "dialer-proxy cycle detected: {}",
                    chain[position..].join(" -> ")
                ));
            }
            chain.push(current);
            let Some(next) = common_options
                .get(current)
                .and_then(|options| options.dialer_proxy.as_deref())
            else {
                break;
            };
            current = next.trim();
        }
    }
    Ok(())
}

fn build_leaf_outbound(config: &OutboundConfig) -> anyhow::Result<Arc<dyn Outbound>> {
    let outbound: Arc<dyn Outbound> = match config {
        OutboundConfig::Direct { name } => Arc::new(DirectOutbound::new(name.clone())),
        OutboundConfig::Reject { name } => Arc::new(RejectOutbound::new(name.clone())),
        OutboundConfig::Http {
            name,
            server,
            port,
            username,
            password,
        } => Arc::new(HttpOutbound::new(
            name.clone(),
            server.clone(),
            *port,
            username.clone(),
            password.clone(),
        )),
        OutboundConfig::Socks5 {
            name,
            server,
            port,
            username,
            password,
        } => Arc::new(Socks5Outbound::new(
            name.clone(),
            server.clone(),
            *port,
            username.clone(),
            password.clone(),
        )),
        OutboundConfig::Shadowsocks {
            name,
            server,
            port,
            method,
            password,
            plugin,
            udp_over_tcp,
            udp_over_tcp_version,
        } => Arc::new(ShadowsocksOutbound::new(
            name.clone(),
            server.clone(),
            *port,
            method.clone(),
            password.clone(),
            plugin.clone(),
            *udp_over_tcp,
            *udp_over_tcp_version,
        )),
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
        } => Arc::new(TrojanOutbound::new(
            name.clone(),
            server.clone(),
            *port,
            password.clone(),
            sni.clone(),
            *skip_cert_verify,
            network.clone(),
            ws_path.clone(),
            ws_host.clone(),
            grpc_service_name.clone(),
            transport_headers.clone(),
            alpn.clone(),
        )),
        OutboundConfig::Vmess {
            name,
            server,
            port,
            uuid,
            alter_id,
            cipher,
            tls,
            sni,
            skip_cert_verify,
            network,
            ws_path,
            ws_host,
            grpc_service_name,
            transport_headers,
            alpn,
        } => Arc::new(VmessOutbound::new(
            name.clone(),
            server.clone(),
            *port,
            uuid.clone(),
            *alter_id,
            cipher.clone(),
            *tls,
            sni.clone(),
            *skip_cert_verify,
            network.clone(),
            ws_path.clone(),
            ws_host.clone(),
            grpc_service_name.clone(),
            transport_headers.clone(),
            alpn.clone(),
        )),
        OutboundConfig::Vless {
            name,
            server,
            port,
            uuid,
            flow,
            security,
            tls,
            sni,
            skip_cert_verify,
            network,
            ws_path,
            ws_host,
            grpc_service_name,
            transport_headers,
            alpn,
            reality_public_key,
            reality_short_id,
            reality_fingerprint,
            reality_spider_x,
        } => Arc::new(VlessOutbound::new(
            name.clone(),
            server.clone(),
            *port,
            uuid.clone(),
            flow.clone(),
            security.clone(),
            *tls,
            sni.clone(),
            *skip_cert_verify,
            network.clone(),
            ws_path.clone(),
            ws_host.clone(),
            grpc_service_name.clone(),
            transport_headers.clone(),
            alpn.clone(),
            reality_public_key.clone(),
            reality_short_id.clone(),
            reality_fingerprint.clone(),
            reality_spider_x.clone(),
        )),
        OutboundConfig::Hysteria2 {
            name,
            server,
            port,
            password,
            sni,
            skip_cert_verify,
            obfs,
            obfs_password,
            alpn,
            up,
            down,
            congestion_control,
        } => Arc::new(Hysteria2Outbound::new(
            name.clone(),
            server.clone(),
            *port,
            password.clone(),
            sni.clone(),
            *skip_cert_verify,
            obfs.clone(),
            obfs_password.clone(),
            alpn.clone(),
            up.clone(),
            down.clone(),
            congestion_control.clone(),
        )),
        OutboundConfig::Tuic {
            name,
            server,
            port,
            uuid,
            password,
            sni,
            skip_cert_verify,
            congestion_control,
            udp_relay_mode,
            alpn,
            max_udp_relay_packet_size,
            heartbeat_interval_ms,
            reduce_rtt,
        } => Arc::new(TuicOutbound::new(
            name.clone(),
            server.clone(),
            *port,
            uuid.clone(),
            password.clone(),
            sni.clone(),
            *skip_cert_verify,
            congestion_control.clone(),
            udp_relay_mode.clone(),
            alpn.clone(),
            *max_udp_relay_packet_size,
            *heartbeat_interval_ms,
            *reduce_rtt,
        )),
        OutboundConfig::Naive {
            name,
            server,
            port,
            username,
            password,
            sni,
            skip_cert_verify,
            alpn,
        } => Arc::new(NaiveOutbound::new(
            name.clone(),
            server.clone(),
            *port,
            username.clone(),
            password.clone(),
            sni.clone(),
            *skip_cert_verify,
            alpn.clone(),
        )),
        OutboundConfig::Ssr {
            name,
            server,
            port,
            method,
            password,
            protocol,
            obfs,
            protocol_param,
            obfs_param,
        } => Arc::new(SsrOutbound::new(
            name.clone(),
            server.clone(),
            *port,
            method.clone(),
            password.clone(),
            protocol.clone(),
            obfs.clone(),
            protocol_param.clone(),
            obfs_param.clone(),
        )),
        OutboundConfig::Snell {
            name,
            server,
            port,
            psk,
            method,
            version,
            obfs,
            obfs_host,
            reuse,
        } => Arc::new(SnellOutbound::new(
            name.clone(),
            server.clone(),
            *port,
            psk.clone(),
            method.clone(),
            *version,
            obfs.clone(),
            obfs_host.clone(),
            *reuse,
        )),
        OutboundConfig::Hysteria { name, .. } => Arc::new(UnsupportedProtocolOutbound::new(
            name.clone(),
            "hysteria".to_string(),
        )),
        OutboundConfig::AnyTls {
            name,
            server,
            port,
            password,
            sni,
            skip_cert_verify,
            alpn,
        } => Arc::new(AnyTlsOutbound::new(
            name.clone(),
            server.clone(),
            *port,
            password.clone(),
            sni.clone(),
            *skip_cert_verify,
            alpn.clone(),
        )),
        OutboundConfig::ShadowTls {
            name,
            server,
            port,
            password,
            version,
            sni,
            skip_cert_verify,
        } => Arc::new(ShadowTlsOutbound::new(
            name.clone(),
            server.clone(),
            *port,
            password.clone(),
            *version,
            sni.clone(),
            *skip_cert_verify,
        )),
        OutboundConfig::WireGuard {
            name,
            server,
            port,
            private_key,
            public_key,
            preshared_key,
            ip,
            ipv6,
            allowed_ips,
            reserved,
            mtu,
            persistent_keepalive,
            remote_dns_resolve,
            dns,
            peers,
        } => Arc::new(WireGuardOutbound::new(
            name.clone(),
            server.clone(),
            *port,
            private_key.clone(),
            public_key.clone(),
            preshared_key.clone(),
            ip.clone(),
            ipv6.clone(),
            allowed_ips.clone(),
            reserved.clone(),
            mtu.unwrap_or(1420),
            *persistent_keepalive,
            *remote_dns_resolve,
            dns.clone(),
            peers.clone(),
        )),
        OutboundConfig::Ssh {
            name,
            server,
            port,
            username,
            password,
            private_key,
            private_key_passphrase,
        } => Arc::new(SshOutbound::new(
            name.clone(),
            server.clone(),
            *port,
            username.clone(),
            password.clone(),
            private_key.clone(),
            private_key_passphrase.clone(),
        )),
        OutboundConfig::Mieru { name, .. } => Arc::new(UnsupportedProtocolOutbound::new(
            name.clone(),
            "mieru".to_string(),
        )),
        OutboundConfig::Juicity { name, .. } => Arc::new(UnsupportedProtocolOutbound::new(
            name.clone(),
            "juicity".to_string(),
        )),
        OutboundConfig::Masque { name, .. } => Arc::new(UnsupportedProtocolOutbound::new(
            name.clone(),
            "masque".to_string(),
        )),
        OutboundConfig::OpenVpn { name, .. } => Arc::new(UnsupportedProtocolOutbound::new(
            name.clone(),
            "openvpn".to_string(),
        )),
        OutboundConfig::Unknown { name, protocol, .. } => Arc::new(
            UnsupportedProtocolOutbound::new(name.clone(), protocol.clone()),
        ),
        OutboundConfig::Group { name, .. } => {
            return Err(anyhow!("group {name} must be built after leaf outbounds"));
        }
    };
    Ok(outbound)
}
