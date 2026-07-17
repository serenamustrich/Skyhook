mod connection_pool;
mod deadline;
mod grpc;
mod headers;
mod http2;
mod http_camouflage;
mod http_connect;
mod http_upgrade;
mod mptcp;
mod quic;
mod socket_options;
mod tcp;
mod tls;
mod websocket;

pub(crate) use connection_pool::SharedConnectionPool;
pub(crate) use deadline::run_dial_phase;
pub(crate) use grpc::open_grpc_tunnel;
pub(crate) use http2::{open_h2_tunnel, Http2TunnelStream};
pub(crate) use http_camouflage::open_http_camouflage_transport;
pub(crate) use http_connect::establish_http_connect;
pub(crate) use http_upgrade::open_http_upgrade_tunnel;
pub(crate) use mptcp::runtime_available as mptcp_runtime_available;
pub(crate) use quic::{
    connect_quic_endpoint, create_quic_endpoint, encode_quic_varint, quic_client_config,
    random_u16, random_u32, read_quic_varint, read_quic_varint_from_slice, resolve_quic_remote,
};
pub(crate) use socket_options::bind_interface;
pub(crate) use tcp::{connect_tcp, order_addresses, scope_tcp_dialer};
pub(crate) use tls::tls_client_config;
pub(crate) use websocket::{open_websocket_transport, open_websocket_transport_without_headers};

#[cfg(test)]
pub(crate) use headers::render_transport_headers;

#[cfg(test)]
pub(crate) use websocket::{
    read_websocket_frame, websocket_accept_key, write_websocket_binary_frame, write_websocket_frame,
};
