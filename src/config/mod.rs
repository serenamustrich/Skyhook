use std::{
    collections::BTreeMap,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use anyhow::Context;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SuperConfig {
    #[serde(default)]
    pub core: CoreConfig,
    #[serde(default)]
    pub tun: TunConfig,
    #[serde(default)]
    pub dns: DnsConfig,
    #[serde(default)]
    pub smart_rules: SmartRulesConfig,
    #[serde(default)]
    pub subscriptions: SubscriptionConfig,
    #[serde(default)]
    pub geo: GeoConfig,
    #[serde(default = "default_outbounds")]
    pub outbounds: Vec<OutboundConfig>,
    #[serde(default)]
    pub rule_sets: Vec<RuleSetConfig>,
    #[serde(default)]
    pub geoip_database: Option<PathBuf>,
    #[serde(default)]
    pub geoip: Vec<GeoIpCountryConfig>,
    #[serde(default)]
    pub rules: Vec<RouteRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CoreConfig {
    #[serde(default = "default_mixed_listen")]
    pub mixed_listen: SocketAddr,
    #[serde(default = "default_control_listen")]
    pub control_listen: SocketAddr,
    #[serde(default = "default_outbound_name")]
    pub default_outbound: String,
    #[serde(default = "default_connect_timeout_ms")]
    pub connect_timeout_ms: u64,
    #[serde(default = "default_probe_url")]
    pub probe_url: String,
    #[serde(default = "default_probe_timeout_ms")]
    pub probe_timeout_ms: u64,
    #[serde(default = "default_probe_interval_secs")]
    pub probe_interval_secs: u64,
    #[serde(default = "default_probe_concurrency")]
    pub probe_concurrency: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TunConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default = "default_tun_stack")]
    pub stack: TunStack,
    #[serde(default = "default_tun_setup")]
    pub setup: bool,
    #[serde(default)]
    pub auto_route: bool,
    #[serde(default)]
    pub auto_detect_interface: bool,
    #[serde(default)]
    pub strict_route: bool,
    #[serde(default)]
    pub auto_redirect: bool,
    #[serde(default = "default_tun_endpoint_independent_nat")]
    pub endpoint_independent_nat: bool,
    #[serde(default)]
    pub gso: bool,
    #[serde(default = "default_tun_gso_max_size")]
    pub gso_max_size: u32,
    #[serde(default = "default_tun_mtu")]
    pub mtu: u16,
    #[serde(default = "default_tun_dns_strategy")]
    pub dns_strategy: TunDnsStrategy,
    #[serde(default = "default_tun_dns_addr")]
    pub dns_addr: std::net::IpAddr,
    #[serde(default = "default_tun_dns_hijack")]
    pub dns_hijack: Vec<String>,
    #[serde(default = "default_tun_ipv6")]
    pub ipv6: bool,
    #[serde(default)]
    pub inet4_address: Vec<String>,
    #[serde(default)]
    pub inet6_address: Vec<String>,
    #[serde(default)]
    pub inet4_route_address: Vec<String>,
    #[serde(default)]
    pub inet6_route_address: Vec<String>,
    #[serde(default = "default_tun_tcp_timeout_secs")]
    pub tcp_timeout_secs: u64,
    #[serde(default = "default_tun_udp_timeout_secs")]
    pub udp_timeout_secs: u64,
    #[serde(default = "default_tun_max_sessions")]
    pub max_sessions: usize,
    #[serde(default)]
    pub bypass: Vec<String>,
    #[serde(default)]
    pub route_exclude_address: Vec<String>,
    #[serde(default)]
    pub include_uid: Vec<u32>,
    #[serde(default)]
    pub include_uid_range: Vec<String>,
    #[serde(default)]
    pub exclude_uid: Vec<u32>,
    #[serde(default)]
    pub exclude_uid_range: Vec<String>,
    #[serde(default)]
    pub include_package: Vec<String>,
    #[serde(default)]
    pub exclude_package: Vec<String>,
    #[serde(default)]
    pub include_process: Vec<String>,
    #[serde(default)]
    pub exclude_process: Vec<String>,
    #[serde(default)]
    pub udpgw_server: Option<SocketAddr>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DnsConfig {
    #[serde(default = "default_dns_enabled")]
    pub enabled: bool,
    #[serde(default = "default_dns_server")]
    pub server: SocketAddr,
    #[serde(default)]
    pub listen: Option<SocketAddr>,
    #[serde(default = "default_dns_enhanced_mode")]
    pub enhanced_mode: DnsEnhancedMode,
    #[serde(default = "default_dns_cache_algorithm")]
    pub cache_algorithm: DnsCacheAlgorithm,
    #[serde(default)]
    pub prefer_h3: bool,
    #[serde(default = "default_dns_ipv6")]
    pub ipv6: bool,
    #[serde(default = "default_dns_fake_ip_range")]
    pub fake_ip_range: String,
    #[serde(default)]
    pub fake_ip_range6: Option<String>,
    #[serde(default)]
    pub fake_ip_filter: Vec<String>,
    #[serde(default = "default_dns_fake_ip_filter_mode")]
    pub fake_ip_filter_mode: FakeIpFilterMode,
    #[serde(default = "default_dns_fake_ip_ttl")]
    pub fake_ip_ttl: u32,
    #[serde(default = "default_dns_use_hosts")]
    pub use_hosts: bool,
    #[serde(default = "default_dns_use_system_hosts")]
    pub use_system_hosts: bool,
    #[serde(default)]
    pub respect_rules: bool,
    #[serde(default = "default_dns_default_nameserver")]
    pub default_nameserver: Vec<String>,
    #[serde(default = "default_dns_nameserver")]
    pub nameserver: Vec<String>,
    #[serde(default)]
    pub nameserver_policy: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    pub proxy_server_nameserver: Vec<String>,
    #[serde(default)]
    pub proxy_server_nameserver_policy: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    pub direct_nameserver: Vec<String>,
    #[serde(default)]
    pub direct_nameserver_follow_policy: bool,
    #[serde(default)]
    pub fallback: Vec<String>,
    #[serde(default)]
    pub fallback_filter: DnsFallbackFilter,
    #[serde(default = "default_dns_hijack_udp_53")]
    pub hijack_udp_53: bool,
    #[serde(default = "default_dns_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_dns_block_non_dns_udp")]
    pub block_non_dns_udp: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum TunStack {
    System,
    Gvisor,
    Mixed,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum TunDnsStrategy {
    Direct,
    OverTcp,
    Virtual,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum DnsEnhancedMode {
    RedirHost,
    FakeIp,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum DnsCacheAlgorithm {
    Lru,
    Arc,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum FakeIpFilterMode {
    Blacklist,
    Whitelist,
    Rule,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DnsFallbackFilter {
    #[serde(default = "default_dns_fallback_filter_geoip")]
    pub geoip: bool,
    #[serde(default = "default_dns_fallback_filter_geoip_code")]
    pub geoip_code: String,
    #[serde(default)]
    pub geosite: Vec<String>,
    #[serde(default)]
    pub ipcidr: Vec<String>,
    #[serde(default)]
    pub domain: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum OutboundConfig {
    Direct {
        name: String,
    },
    Reject {
        name: String,
    },
    Http {
        name: String,
        server: String,
        port: u16,
        #[serde(default)]
        username: Option<String>,
        #[serde(default)]
        password: Option<String>,
    },
    Socks5 {
        name: String,
        server: String,
        port: u16,
        #[serde(default)]
        username: Option<String>,
        #[serde(default)]
        password: Option<String>,
    },
    Shadowsocks {
        name: String,
        server: String,
        port: u16,
        method: String,
        password: String,
        #[serde(default)]
        plugin: Option<ShadowsocksPluginConfig>,
    },
    Trojan {
        name: String,
        server: String,
        port: u16,
        password: String,
        #[serde(default)]
        sni: Option<String>,
        #[serde(default)]
        skip_cert_verify: bool,
    },
    Vmess {
        name: String,
        server: String,
        port: u16,
        uuid: String,
        #[serde(default = "default_vmess_cipher")]
        cipher: String,
        #[serde(default)]
        tls: bool,
        #[serde(default)]
        sni: Option<String>,
        #[serde(default)]
        skip_cert_verify: bool,
        #[serde(default)]
        network: Option<String>,
        #[serde(default)]
        ws_path: Option<String>,
        #[serde(default)]
        ws_host: Option<String>,
        #[serde(default)]
        grpc_service_name: Option<String>,
    },
    Vless {
        name: String,
        server: String,
        port: u16,
        uuid: String,
        #[serde(default)]
        flow: Option<String>,
        #[serde(default)]
        security: Option<String>,
        #[serde(default = "default_vless_tls")]
        tls: bool,
        #[serde(default)]
        sni: Option<String>,
        #[serde(default)]
        skip_cert_verify: bool,
        #[serde(default)]
        network: Option<String>,
        #[serde(default)]
        ws_path: Option<String>,
        #[serde(default)]
        ws_host: Option<String>,
        #[serde(default)]
        grpc_service_name: Option<String>,
        #[serde(default)]
        reality_public_key: Option<String>,
        #[serde(default)]
        reality_short_id: Option<String>,
        #[serde(default)]
        reality_fingerprint: Option<String>,
        #[serde(default)]
        reality_spider_x: Option<String>,
    },
    Hysteria2 {
        name: String,
        server: String,
        port: u16,
        password: String,
        #[serde(default)]
        sni: Option<String>,
        #[serde(default)]
        skip_cert_verify: bool,
        #[serde(default)]
        obfs: Option<String>,
        #[serde(default)]
        obfs_password: Option<String>,
        #[serde(default)]
        alpn: Option<String>,
    },
    Tuic {
        name: String,
        server: String,
        port: u16,
        uuid: String,
        password: String,
        #[serde(default)]
        sni: Option<String>,
        #[serde(default)]
        skip_cert_verify: bool,
        #[serde(default)]
        congestion_control: Option<String>,
        #[serde(default)]
        udp_relay_mode: Option<String>,
        #[serde(default)]
        alpn: Option<String>,
    },
    Naive {
        name: String,
        server: String,
        port: u16,
        #[serde(default)]
        username: Option<String>,
        #[serde(default)]
        password: Option<String>,
        #[serde(default)]
        sni: Option<String>,
        #[serde(default)]
        skip_cert_verify: bool,
        #[serde(default)]
        alpn: Vec<String>,
    },
    Ssr {
        name: String,
        server: String,
        port: u16,
        method: String,
        password: String,
        protocol: String,
        obfs: String,
        #[serde(default)]
        protocol_param: Option<String>,
        #[serde(default)]
        obfs_param: Option<String>,
    },
    Snell {
        name: String,
        server: String,
        port: u16,
        psk: String,
        #[serde(default)]
        method: Option<String>,
        #[serde(default)]
        version: Option<u8>,
        #[serde(default)]
        obfs: Option<String>,
        #[serde(default)]
        obfs_host: Option<String>,
    },
    Hysteria {
        name: String,
        server: String,
        port: u16,
        #[serde(default)]
        auth: Option<String>,
        #[serde(default)]
        auth_str: Option<String>,
        #[serde(default)]
        protocol: Option<String>,
        #[serde(default)]
        up: Option<String>,
        #[serde(default)]
        down: Option<String>,
        #[serde(default)]
        sni: Option<String>,
        #[serde(default)]
        skip_cert_verify: bool,
        #[serde(default)]
        obfs: Option<String>,
    },
    AnyTls {
        name: String,
        server: String,
        port: u16,
        password: String,
        #[serde(default)]
        sni: Option<String>,
        #[serde(default)]
        skip_cert_verify: bool,
        #[serde(default)]
        alpn: Vec<String>,
    },
    ShadowTls {
        name: String,
        server: String,
        port: u16,
        password: String,
        #[serde(default)]
        version: Option<u8>,
        #[serde(default)]
        sni: Option<String>,
        #[serde(default)]
        skip_cert_verify: bool,
    },
    WireGuard {
        name: String,
        server: String,
        port: u16,
        private_key: String,
        public_key: String,
        #[serde(default)]
        preshared_key: Option<String>,
        #[serde(default)]
        ip: Vec<String>,
        #[serde(default)]
        ipv6: Vec<String>,
        #[serde(default)]
        allowed_ips: Vec<String>,
        #[serde(default)]
        reserved: Vec<u8>,
        #[serde(default)]
        mtu: Option<u16>,
    },
    Ssh {
        name: String,
        server: String,
        port: u16,
        username: String,
        #[serde(default)]
        password: Option<String>,
        #[serde(default)]
        private_key: Option<String>,
        #[serde(default)]
        private_key_passphrase: Option<String>,
    },
    Mieru {
        name: String,
        server: String,
        port: u16,
        username: String,
        password: String,
        #[serde(default)]
        transport: Option<String>,
    },
    Juicity {
        name: String,
        server: String,
        port: u16,
        uuid: String,
        password: String,
        #[serde(default)]
        sni: Option<String>,
        #[serde(default)]
        skip_cert_verify: bool,
    },
    Masque {
        name: String,
        server: String,
        port: u16,
        #[serde(default)]
        username: Option<String>,
        #[serde(default)]
        password: Option<String>,
        #[serde(default)]
        sni: Option<String>,
        #[serde(default)]
        skip_cert_verify: bool,
    },
    OpenVpn {
        name: String,
        #[serde(default)]
        profile: Option<PathBuf>,
        #[serde(default)]
        inline_profile: Option<String>,
    },
    Unknown {
        name: String,
        protocol: String,
        #[serde(default)]
        server: Option<String>,
        #[serde(default)]
        port: Option<u16>,
        #[serde(default)]
        params: BTreeMap<String, String>,
    },
    Group {
        name: String,
        kind: String,
        members: Vec<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShadowsocksPluginConfig {
    pub mode: String,
    #[serde(default)]
    pub host: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RouteRule {
    pub target: RuleTarget,
    pub value: String,
    pub outbound: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuleSetConfig {
    pub name: String,
    #[serde(default = "default_rule_set_behavior")]
    pub behavior: RuleSetBehavior,
    #[serde(default)]
    pub rules: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GeoIpCountryConfig {
    pub country: String,
    #[serde(default)]
    pub cidrs: Vec<ipnet::IpNet>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RuleSetBehavior {
    Domain,
    IpCidr,
    Classical,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SmartRulesConfig {
    #[serde(default = "default_smart_rules_enabled")]
    pub enabled: bool,
    #[serde(default = "default_smart_auto_probe")]
    pub auto_probe: bool,
    #[serde(default = "default_smart_auto_apply_recommendations")]
    pub auto_apply_recommendations: bool,
    #[serde(default = "default_smart_direct_outbound")]
    pub direct_outbound: String,
    #[serde(default)]
    pub proxy_outbound: Option<String>,
    #[serde(default = "default_smart_direct_probe_timeout_ms")]
    pub direct_probe_timeout_ms: u64,
    #[serde(default = "default_smart_probe_cooldown_secs")]
    pub probe_cooldown_secs: u64,
    #[serde(default = "default_smart_min_samples")]
    pub min_samples: u32,
    #[serde(default = "default_smart_state_path")]
    pub state_path: PathBuf,
    #[serde(default = "default_smart_persist_interval_secs")]
    pub persist_interval_secs: u64,
    #[serde(default = "default_smart_max_observations")]
    pub max_observations: usize,
    #[serde(default)]
    pub rules: Vec<SmartRouteRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubscriptionConfig {
    #[serde(default = "default_subscriptions_use_active")]
    pub use_active: bool,
    #[serde(default = "default_subscription_store_path")]
    pub store_path: PathBuf,
    #[serde(default = "default_subscription_use_first_node")]
    pub use_first_node_as_default: bool,
    #[serde(default = "default_subscription_update_on_start")]
    pub update_on_start: bool,
    #[serde(default = "default_subscription_auto_update")]
    pub auto_update: bool,
    #[serde(default = "default_subscription_update_interval_secs")]
    pub update_interval_secs: u64,
    #[serde(default = "default_subscription_update_timeout_secs")]
    pub update_timeout_secs: u64,
    #[serde(default = "default_subscription_update_retries")]
    pub update_retries: u8,
    #[serde(default = "default_subscription_update_concurrency")]
    pub update_concurrency: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GeoConfig {
    #[serde(default = "default_geo_auto_update")]
    pub auto_update: bool,
    #[serde(default = "default_geo_update_on_start")]
    pub update_on_start: bool,
    #[serde(default = "default_geo_cache_dir")]
    pub cache_dir: PathBuf,
    #[serde(default)]
    pub geoip_url: Option<String>,
    #[serde(default)]
    pub geosite_url: Option<String>,
    #[serde(default = "default_geo_update_timeout_secs")]
    pub update_timeout_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SmartRouteRule {
    pub target: RuleTarget,
    pub value: String,
    pub outbound: String,
    #[serde(default = "default_smart_rule_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RuleTarget {
    Domain,
    DomainSuffix,
    DomainKeyword,
    Ip,
    IpCidr,
    AppName,
    AppPath,
    AppBundle,
    RuleSet,
    GeoIp,
    Match,
}

impl Default for SuperConfig {
    fn default() -> Self {
        Self {
            core: CoreConfig::default(),
            tun: TunConfig::default(),
            dns: DnsConfig::default(),
            smart_rules: SmartRulesConfig::default(),
            subscriptions: SubscriptionConfig::default(),
            geo: GeoConfig::default(),
            outbounds: default_outbounds(),
            rule_sets: Vec::new(),
            geoip_database: None,
            geoip: Vec::new(),
            rules: vec![RouteRule {
                target: RuleTarget::Match,
                value: "*".to_string(),
                outbound: default_outbound_name(),
            }],
        }
    }
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            enabled: default_dns_enabled(),
            server: default_dns_server(),
            listen: None,
            enhanced_mode: default_dns_enhanced_mode(),
            cache_algorithm: default_dns_cache_algorithm(),
            prefer_h3: false,
            ipv6: default_dns_ipv6(),
            fake_ip_range: default_dns_fake_ip_range(),
            fake_ip_range6: None,
            fake_ip_filter: Vec::new(),
            fake_ip_filter_mode: default_dns_fake_ip_filter_mode(),
            fake_ip_ttl: default_dns_fake_ip_ttl(),
            use_hosts: default_dns_use_hosts(),
            use_system_hosts: default_dns_use_system_hosts(),
            respect_rules: false,
            default_nameserver: default_dns_default_nameserver(),
            nameserver: default_dns_nameserver(),
            nameserver_policy: BTreeMap::new(),
            proxy_server_nameserver: Vec::new(),
            proxy_server_nameserver_policy: BTreeMap::new(),
            direct_nameserver: Vec::new(),
            direct_nameserver_follow_policy: false,
            fallback: Vec::new(),
            fallback_filter: DnsFallbackFilter::default(),
            hijack_udp_53: default_dns_hijack_udp_53(),
            timeout_ms: default_dns_timeout_ms(),
            block_non_dns_udp: default_dns_block_non_dns_udp(),
        }
    }
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            name: None,
            stack: default_tun_stack(),
            setup: default_tun_setup(),
            auto_route: false,
            auto_detect_interface: false,
            strict_route: false,
            auto_redirect: false,
            endpoint_independent_nat: default_tun_endpoint_independent_nat(),
            gso: false,
            gso_max_size: default_tun_gso_max_size(),
            mtu: default_tun_mtu(),
            dns_strategy: default_tun_dns_strategy(),
            dns_addr: default_tun_dns_addr(),
            dns_hijack: default_tun_dns_hijack(),
            ipv6: default_tun_ipv6(),
            inet4_address: Vec::new(),
            inet6_address: Vec::new(),
            inet4_route_address: Vec::new(),
            inet6_route_address: Vec::new(),
            tcp_timeout_secs: default_tun_tcp_timeout_secs(),
            udp_timeout_secs: default_tun_udp_timeout_secs(),
            max_sessions: default_tun_max_sessions(),
            bypass: Vec::new(),
            route_exclude_address: Vec::new(),
            include_uid: Vec::new(),
            include_uid_range: Vec::new(),
            exclude_uid: Vec::new(),
            exclude_uid_range: Vec::new(),
            include_package: Vec::new(),
            exclude_package: Vec::new(),
            include_process: Vec::new(),
            exclude_process: Vec::new(),
            udpgw_server: None,
        }
    }
}

impl Default for DnsFallbackFilter {
    fn default() -> Self {
        Self {
            geoip: default_dns_fallback_filter_geoip(),
            geoip_code: default_dns_fallback_filter_geoip_code(),
            geosite: Vec::new(),
            ipcidr: Vec::new(),
            domain: Vec::new(),
        }
    }
}

impl Default for SmartRulesConfig {
    fn default() -> Self {
        Self {
            enabled: default_smart_rules_enabled(),
            auto_probe: default_smart_auto_probe(),
            auto_apply_recommendations: default_smart_auto_apply_recommendations(),
            direct_outbound: default_smart_direct_outbound(),
            proxy_outbound: None,
            direct_probe_timeout_ms: default_smart_direct_probe_timeout_ms(),
            probe_cooldown_secs: default_smart_probe_cooldown_secs(),
            min_samples: default_smart_min_samples(),
            state_path: default_smart_state_path(),
            persist_interval_secs: default_smart_persist_interval_secs(),
            max_observations: default_smart_max_observations(),
            rules: Vec::new(),
        }
    }
}

impl Default for SubscriptionConfig {
    fn default() -> Self {
        Self {
            use_active: default_subscriptions_use_active(),
            store_path: default_subscription_store_path(),
            use_first_node_as_default: default_subscription_use_first_node(),
            update_on_start: default_subscription_update_on_start(),
            auto_update: default_subscription_auto_update(),
            update_interval_secs: default_subscription_update_interval_secs(),
            update_timeout_secs: default_subscription_update_timeout_secs(),
            update_retries: default_subscription_update_retries(),
            update_concurrency: default_subscription_update_concurrency(),
        }
    }
}

impl Default for GeoConfig {
    fn default() -> Self {
        Self {
            auto_update: default_geo_auto_update(),
            update_on_start: default_geo_update_on_start(),
            cache_dir: default_geo_cache_dir(),
            geoip_url: None,
            geosite_url: None,
            update_timeout_secs: default_geo_update_timeout_secs(),
        }
    }
}

impl Default for CoreConfig {
    fn default() -> Self {
        Self {
            mixed_listen: default_mixed_listen(),
            control_listen: default_control_listen(),
            default_outbound: default_outbound_name(),
            connect_timeout_ms: default_connect_timeout_ms(),
            probe_url: default_probe_url(),
            probe_timeout_ms: default_probe_timeout_ms(),
            probe_interval_secs: default_probe_interval_secs(),
            probe_concurrency: default_probe_concurrency(),
        }
    }
}

impl SuperConfig {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read config {}", path.display()))?;
        serde_yaml::from_str(&text).with_context(|| format!("invalid config {}", path.display()))
    }

    pub fn example_yaml() -> anyhow::Result<String> {
        serde_yaml::to_string(&Self::default()).context("failed to encode example config")
    }

    pub fn summary(&self) -> String {
        format!(
            "mixed={}, control={}, outbounds={}, rules={}",
            self.core.mixed_listen,
            self.core.control_listen,
            self.outbounds.len(),
            self.rules.len()
        )
    }
}

impl OutboundConfig {
    pub fn name(&self) -> &str {
        match self {
            Self::Direct { name }
            | Self::Reject { name }
            | Self::Http { name, .. }
            | Self::Socks5 { name, .. }
            | Self::Shadowsocks { name, .. }
            | Self::Trojan { name, .. }
            | Self::Vmess { name, .. }
            | Self::Vless { name, .. }
            | Self::Hysteria2 { name, .. }
            | Self::Tuic { name, .. }
            | Self::Naive { name, .. }
            | Self::Ssr { name, .. }
            | Self::Snell { name, .. }
            | Self::Hysteria { name, .. }
            | Self::AnyTls { name, .. }
            | Self::ShadowTls { name, .. }
            | Self::WireGuard { name, .. }
            | Self::Ssh { name, .. }
            | Self::Mieru { name, .. }
            | Self::Juicity { name, .. }
            | Self::Masque { name, .. }
            | Self::OpenVpn { name, .. }
            | Self::Unknown { name, .. }
            | Self::Group { name, .. } => name,
        }
    }
}

fn default_outbounds() -> Vec<OutboundConfig> {
    vec![
        OutboundConfig::Direct {
            name: default_outbound_name(),
        },
        OutboundConfig::Reject {
            name: "reject".to_string(),
        },
    ]
}

fn default_tun_setup() -> bool {
    false
}

fn default_tun_stack() -> TunStack {
    TunStack::System
}

fn default_tun_endpoint_independent_nat() -> bool {
    true
}

fn default_tun_gso_max_size() -> u32 {
    65_536
}

fn default_tun_mtu() -> u16 {
    1500
}

fn default_tun_dns_strategy() -> TunDnsStrategy {
    TunDnsStrategy::Virtual
}

fn default_tun_dns_addr() -> std::net::IpAddr {
    "8.8.8.8".parse().expect("valid default DNS address")
}

fn default_tun_dns_hijack() -> Vec<String> {
    vec!["0.0.0.0:53".to_string()]
}

fn default_tun_ipv6() -> bool {
    false
}

fn default_tun_tcp_timeout_secs() -> u64 {
    600
}

fn default_tun_udp_timeout_secs() -> u64 {
    10
}

fn default_tun_max_sessions() -> usize {
    200
}

fn default_dns_enabled() -> bool {
    true
}

fn default_dns_server() -> SocketAddr {
    "8.8.8.8:53".parse().expect("valid default DNS server")
}

fn default_dns_enhanced_mode() -> DnsEnhancedMode {
    DnsEnhancedMode::RedirHost
}

fn default_dns_cache_algorithm() -> DnsCacheAlgorithm {
    DnsCacheAlgorithm::Lru
}

fn default_dns_ipv6() -> bool {
    false
}

fn default_dns_fake_ip_range() -> String {
    "198.18.0.1/16".to_string()
}

fn default_dns_fake_ip_filter_mode() -> FakeIpFilterMode {
    FakeIpFilterMode::Blacklist
}

fn default_dns_fake_ip_ttl() -> u32 {
    60
}

fn default_dns_use_hosts() -> bool {
    true
}

fn default_dns_use_system_hosts() -> bool {
    true
}

fn default_dns_default_nameserver() -> Vec<String> {
    vec![default_dns_server().to_string()]
}

fn default_dns_nameserver() -> Vec<String> {
    vec![default_dns_server().to_string()]
}

fn default_dns_fallback_filter_geoip() -> bool {
    true
}

fn default_dns_fallback_filter_geoip_code() -> String {
    "CN".to_string()
}

fn default_dns_hijack_udp_53() -> bool {
    true
}

fn default_dns_timeout_ms() -> u64 {
    2_000
}

fn default_dns_block_non_dns_udp() -> bool {
    false
}

fn default_subscriptions_use_active() -> bool {
    true
}

fn default_subscription_store_path() -> PathBuf {
    PathBuf::from("skyhook-subscriptions")
}

fn default_subscription_use_first_node() -> bool {
    true
}

fn default_subscription_update_on_start() -> bool {
    true
}

fn default_subscription_auto_update() -> bool {
    true
}

fn default_subscription_update_interval_secs() -> u64 {
    6 * 60 * 60
}

fn default_subscription_update_timeout_secs() -> u64 {
    10
}

fn default_subscription_update_retries() -> u8 {
    1
}

fn default_subscription_update_concurrency() -> usize {
    4
}

fn default_geo_auto_update() -> bool {
    true
}

fn default_geo_update_on_start() -> bool {
    true
}

fn default_geo_cache_dir() -> PathBuf {
    PathBuf::from("skyhook-geo")
}

fn default_geo_update_timeout_secs() -> u64 {
    20
}

fn default_rule_set_behavior() -> RuleSetBehavior {
    RuleSetBehavior::Classical
}

fn default_mixed_listen() -> SocketAddr {
    "127.0.0.1:7897"
        .parse()
        .expect("valid default mixed listen")
}

fn default_control_listen() -> SocketAddr {
    "127.0.0.1:9197"
        .parse()
        .expect("valid default control listen")
}

fn default_outbound_name() -> String {
    "direct".to_string()
}

fn default_connect_timeout_ms() -> u64 {
    5000
}

fn default_probe_url() -> String {
    "http://cp.cloudflare.com/generate_204".to_string()
}

fn default_probe_timeout_ms() -> u64 {
    500
}

fn default_probe_interval_secs() -> u64 {
    300
}

fn default_probe_concurrency() -> usize {
    256
}

fn default_smart_rules_enabled() -> bool {
    true
}

fn default_smart_auto_probe() -> bool {
    true
}

fn default_smart_auto_apply_recommendations() -> bool {
    true
}

fn default_smart_direct_outbound() -> String {
    "direct".to_string()
}

fn default_smart_direct_probe_timeout_ms() -> u64 {
    500
}

fn default_smart_probe_cooldown_secs() -> u64 {
    300
}

fn default_smart_min_samples() -> u32 {
    2
}

fn default_smart_state_path() -> PathBuf {
    PathBuf::from("skyhook-smart-rules.json")
}

fn default_smart_persist_interval_secs() -> u64 {
    30
}

fn default_smart_max_observations() -> usize {
    10_000
}

fn default_smart_rule_enabled() -> bool {
    true
}

fn default_vless_tls() -> bool {
    true
}

fn default_vmess_cipher() -> String {
    "auto".to_string()
}
