mod anytls;
mod configured;
pub mod context;
mod dns;
mod direct;
pub mod error;
mod factory;
mod group;
mod http_proxy;
mod hysteria;
mod hysteria2;
mod ip_stack;
mod io;
mod juicity;
mod masque;
mod mieru;
mod mux;
mod naive;
mod openvpn;
mod pool;
mod rabbit_compat;
mod registry;
mod reject;
mod rematch;
mod shadowsocks;
mod shadowtls;
mod snell;
mod socks5;
mod ssh;
mod ssr;
mod sudoku;
mod tailscale;
mod target;
mod traits;
mod transports;
mod trusttunnel;
mod trojan;
mod tuic;
mod udp;
mod unsupported;
mod util;
mod vless;
mod vless_vision;
mod vmess;
mod wireguard;

pub use factory::{
    build_outbounds, build_outbounds_with_options, build_outbounds_with_options_and_dns,
};
pub use target::encode_socks5_destination;
pub use traits::{
    BoxedStream, Outbound, OutboundCapability, OutboundMap, ProxyStream, RematchTarget,
    UdpNatMode,
};

#[cfg(test)]
mod tests;
