mod reassembly;
mod replay;
mod resolver;
mod runtime;
mod session_pool;
mod socket;

pub(crate) use reassembly::FragmentReassembler;
pub(crate) use replay::ReplayWindow64;
pub(crate) use resolver::resolve_udp_socket_addr;
pub(crate) use runtime::{udp_session_key, UdpRuntime};
pub(crate) use session_pool::KeyedRoundRobinSessionPool;
pub(crate) use socket::{create_bound_std_udp, create_bound_udp};

pub(crate) const UDP_SESSION_POOL_SIZE: usize = 4;
