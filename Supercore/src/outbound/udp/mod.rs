mod resolver;
mod session_pool;

pub(crate) use resolver::resolve_udp_socket_addr;
pub(crate) use session_pool::{KeyedRoundRobinSessionPool, RoundRobinSessionPool};

pub(crate) const UDP_SESSION_POOL_SIZE: usize = 4;
