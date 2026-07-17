mod anytls;
mod configured;
pub mod context;
mod direct;
pub mod error;
mod factory;
mod group;
mod http_proxy;
mod hysteria2;
mod io;
mod mux;
mod naive;
mod pool;
mod registry;
mod reject;
mod shadowsocks;
mod shadowtls;
mod snell;
mod socks5;
mod ssh;
mod ssr;
mod target;
mod traits;
mod transports;
mod trojan;
mod tuic;
mod udp;
mod unsupported;
mod util;
mod vless;
mod vmess;
mod wireguard;

pub use factory::{build_outbounds, build_outbounds_with_options};
pub use target::encode_socks5_destination;
pub use traits::{BoxedStream, Outbound, OutboundCapability, OutboundMap, ProxyStream, UdpNatMode};

#[cfg(test)]
mod tests;
