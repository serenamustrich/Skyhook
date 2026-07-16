use std::{io, net::SocketAddr};

use socket2::Socket;

#[cfg(target_os = "macos")]
pub(crate) fn bind_interface(
    socket: &Socket,
    address: SocketAddr,
    interface_name: &str,
) -> io::Result<()> {
    use std::{ffi::CString, mem::size_of_val, os::fd::AsRawFd};

    let interface = CString::new(interface_name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "interface contains NUL"))?;
    let index = unsafe { libc::if_nametoindex(interface.as_ptr()) };
    if index == 0 {
        return Err(io::Error::last_os_error());
    }
    let (level, option) = if address.is_ipv4() {
        (libc::IPPROTO_IP, libc::IP_BOUND_IF)
    } else {
        (libc::IPPROTO_IPV6, libc::IPV6_BOUND_IF)
    };
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            level,
            option,
            std::ptr::addr_of!(index).cast(),
            size_of_val(&index) as libc::socklen_t,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn bind_interface(
    _socket: &Socket,
    _address: SocketAddr,
    interface_name: &str,
) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        format!("interface binding is unsupported on this platform: {interface_name}"),
    ))
}

#[cfg(target_os = "macos")]
pub(crate) fn enable_tcp_fast_open(socket: &Socket) -> io::Result<()> {
    use std::{mem::size_of_val, os::fd::AsRawFd};

    let enabled: libc::c_int = 1;
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_FASTOPEN,
            std::ptr::addr_of!(enabled).cast(),
            size_of_val(&enabled) as libc::socklen_t,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn enable_tcp_fast_open(_socket: &Socket) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "TCP Fast Open is unsupported on this platform",
    ))
}
