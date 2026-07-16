mod resolver;
mod session_pool;
mod socket;

pub(crate) use resolver::resolve_udp_socket_addr;
pub(crate) use session_pool::{KeyedRoundRobinSessionPool, RoundRobinSessionPool};
pub(crate) use socket::{create_bound_std_udp, create_bound_udp};

pub(crate) const UDP_SESSION_POOL_SIZE: usize = 4;
