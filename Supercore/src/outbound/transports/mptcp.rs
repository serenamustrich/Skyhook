#[cfg(target_os = "macos")]
mod macos {
    use std::{
        ffi::{c_char, c_void, CStr, CString},
        io,
        os::fd::{FromRawFd, RawFd},
        pin::Pin,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
        task::{Context, Poll},
        time::Duration,
    };

    use anyhow::{anyhow, Context as _};
    use tokio::{
        io::{AsyncRead, AsyncWrite, ReadBuf},
        net::UnixStream,
    };

    use crate::outbound::{context::IpVersionStrategy, BoxedStream};

    type CancelledCallback = unsafe extern "C" fn(*mut c_void) -> bool;

    extern "C" {
        fn skyhook_mptcp_connect(
            host: *const c_char,
            service: *const c_char,
            source_host: *const c_char,
            source_service: *const c_char,
            ip_version: i32,
            keepalive_secs: u32,
            enable_multipath: bool,
            timeout_ms: u64,
            cancelled: CancelledCallback,
            cancel_context: *mut c_void,
            stream_fd: *mut RawFd,
            bridge_handle: *mut *mut c_void,
            error: *mut c_char,
            error_capacity: usize,
        ) -> i32;
        fn skyhook_mptcp_release(bridge_handle: *mut c_void);
        fn skyhook_mptcp_backend_probe() -> i32;
        fn skyhook_mptcp_entitlement_probe() -> i32;
    }

    pub(crate) struct MptcpOptions {
        pub source: Option<std::net::SocketAddr>,
        pub ip_version: IpVersionStrategy,
        pub keepalive: Option<Duration>,
        pub fast_open: bool,
    }

    pub(crate) async fn connect(
        host: String,
        port: u16,
        timeout: Duration,
        cancellation: tokio_util::sync::CancellationToken,
        options: MptcpOptions,
    ) -> anyhow::Result<BoxedStream> {
        if options.fast_open {
            return Err(anyhow!(
                "MPTCP cannot be combined with TFO because Network.framework requires replay-safe early data before the stream is ready"
            ));
        }
        if !backend_available() {
            return Err(anyhow!(
                "Network.framework did not accept the MPTCP interactive service"
            ));
        }
        if !entitlement_available() {
            return Err(anyhow!(
                "MPTCP requires the com.apple.developer.networking.multipath entitlement on the supercore executable"
            ));
        }
        connect_bridge(host, port, timeout, cancellation, options, true).await
    }

    async fn connect_bridge(
        host: String,
        port: u16,
        timeout: Duration,
        cancellation: tokio_util::sync::CancellationToken,
        options: MptcpOptions,
        enable_multipath: bool,
    ) -> anyhow::Result<BoxedStream> {
        if cancellation.is_cancelled() {
            return Err(anyhow!("MPTCP connection cancelled"));
        }
        let host = CString::new(host).context("MPTCP host contains a NUL byte")?;
        let service = CString::new(port.to_string()).expect("numeric port has no NUL");
        let source_host = options
            .source
            .map(|source| CString::new(source.ip().to_string()).expect("IP has no NUL"));
        let source_service = options
            .source
            .map(|source| CString::new(source.port().to_string()).expect("port has no NUL"));
        let timeout_ms = timeout.as_millis().clamp(1, u128::from(u64::MAX)) as u64;
        // Reserve a small part of the outbound-wide deadline for native cleanup
        // without collapsing short probe budgets (for example 500 ms) to 1 ms.
        let unwind_margin_ms = (timeout_ms / 10).clamp(1, 100);
        let backend_timeout_ms = timeout_ms.saturating_sub(unwind_margin_ms).max(1);
        let cancelled = Arc::new(AtomicBool::new(false));
        let blocking_cancelled = Arc::clone(&cancelled);
        let ip_version = match options.ip_version {
            IpVersionStrategy::Ipv4 => 4,
            IpVersionStrategy::Ipv6 => 6,
            IpVersionStrategy::Dual
            | IpVersionStrategy::PreferIpv4
            | IpVersionStrategy::PreferIpv6 => 0,
        };
        let keepalive_secs = options
            .keepalive
            .map(|duration| duration.as_secs().clamp(1, u64::from(u32::MAX)) as u32)
            .unwrap_or(0);
        let mut task = tokio::task::spawn_blocking(move || {
            let mut stream_fd = -1;
            let mut bridge_handle = std::ptr::null_mut();
            let mut error = [0 as c_char; 512];
            let status = unsafe {
                skyhook_mptcp_connect(
                    host.as_ptr(),
                    service.as_ptr(),
                    source_host
                        .as_ref()
                        .map_or(std::ptr::null(), |value| value.as_ptr()),
                    source_service
                        .as_ref()
                        .map_or(std::ptr::null(), |value| value.as_ptr()),
                    ip_version,
                    keepalive_secs,
                    enable_multipath,
                    backend_timeout_ms,
                    cancellation_requested,
                    Arc::as_ptr(&blocking_cancelled).cast_mut().cast(),
                    &mut stream_fd,
                    &mut bridge_handle,
                    error.as_mut_ptr(),
                    error.len(),
                )
            };
            if status != 0 {
                let message = unsafe { CStr::from_ptr(error.as_ptr()) }
                    .to_string_lossy()
                    .into_owned();
                return Err(anyhow!(message));
            }
            Ok((stream_fd, BridgeHandle(bridge_handle)))
        });

        let (stream_fd, bridge_handle) = tokio::select! {
            result = &mut task => result.context("MPTCP bridge task failed")??,
            _ = cancellation.cancelled() => {
                cancelled.store(true, Ordering::Release);
                let _ = task.await;
                return Err(anyhow!("MPTCP connection cancelled"));
            }
        };
        let stream = unsafe { std::os::unix::net::UnixStream::from_raw_fd(stream_fd) };
        stream.set_nonblocking(true)?;
        let stream = UnixStream::from_std(stream)?;
        Ok(Box::new(MptcpStream {
            stream,
            _bridge: bridge_handle,
        }))
    }

    fn backend_available() -> bool {
        unsafe { skyhook_mptcp_backend_probe() == 1 }
    }

    fn entitlement_available() -> bool {
        unsafe { skyhook_mptcp_entitlement_probe() == 1 }
    }

    pub(crate) fn runtime_available() -> bool {
        backend_available() && entitlement_available()
    }

    unsafe extern "C" fn cancellation_requested(context: *mut c_void) -> bool {
        let flag = unsafe { &*context.cast::<AtomicBool>() };
        flag.load(Ordering::Acquire)
    }

    struct BridgeHandle(*mut c_void);

    unsafe impl Send for BridgeHandle {}

    impl Drop for BridgeHandle {
        fn drop(&mut self) {
            unsafe { skyhook_mptcp_release(self.0) };
        }
    }

    struct MptcpStream {
        stream: UnixStream,
        _bridge: BridgeHandle,
    }

    impl AsyncRead for MptcpStream {
        fn poll_read(
            self: Pin<&mut Self>,
            context: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().stream).poll_read(context, buffer)
        }
    }

    impl AsyncWrite for MptcpStream {
        fn poll_write(
            self: Pin<&mut Self>,
            context: &mut Context<'_>,
            buffer: &[u8],
        ) -> Poll<Result<usize, io::Error>> {
            Pin::new(&mut self.get_mut().stream).poll_write(context, buffer)
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            context: &mut Context<'_>,
        ) -> Poll<Result<(), io::Error>> {
            Pin::new(&mut self.get_mut().stream).poll_flush(context)
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            context: &mut Context<'_>,
        ) -> Poll<Result<(), io::Error>> {
            Pin::new(&mut self.get_mut().stream).poll_shutdown(context)
        }
    }

    #[cfg(test)]
    mod tests {
        use std::{sync::Arc, time::Duration};

        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt},
            net::TcpListener,
        };
        use tokio_util::sync::CancellationToken;

        use super::{connect_bridge, IpVersionStrategy, MptcpOptions};

        fn test_options() -> MptcpOptions {
            MptcpOptions {
                source: None,
                ip_version: IpVersionStrategy::Ipv4,
                keepalive: Some(Duration::from_secs(5)),
                fast_open: false,
            }
        }

        #[tokio::test]
        async fn network_framework_bridge_relays_stream_without_multipath_entitlement() {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = [0u8; 4];
                stream.read_exact(&mut request).await.unwrap();
                assert_eq!(&request, b"ping");
                stream.write_all(b"pong").await.unwrap();
                stream.shutdown().await.unwrap();
            });

            let mut stream = connect_bridge(
                address.ip().to_string(),
                address.port(),
                Duration::from_secs(2),
                CancellationToken::new(),
                test_options(),
                false,
            )
            .await
            .unwrap();
            stream.write_all(b"ping").await.unwrap();
            let mut response = [0u8; 4];
            stream.read_exact(&mut response).await.unwrap();
            assert_eq!(&response, b"pong");
            stream.shutdown().await.unwrap();
            server.await.unwrap();
        }

        #[tokio::test]
        async fn network_framework_bridge_preserves_large_payload_and_half_close() {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let payload = Arc::new(
                (0..512 * 1024)
                    .map(|index| ((index * 31) % 251) as u8)
                    .collect::<Vec<_>>(),
            );
            let expected = Arc::clone(&payload);
            let (received_tx, received_rx) = tokio::sync::oneshot::channel();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                stream.read_to_end(&mut request).await.unwrap();
                assert_eq!(request.as_slice(), expected.as_slice());
                let _ = received_tx.send(request.len());
                stream.write_all(&request).await.unwrap();
                stream.shutdown().await.unwrap();
            });

            let mut stream = connect_bridge(
                address.ip().to_string(),
                address.port(),
                Duration::from_secs(3),
                CancellationToken::new(),
                test_options(),
                false,
            )
            .await
            .unwrap();
            stream.write_all(payload.as_slice()).await.unwrap();
            stream.shutdown().await.unwrap();
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(2), received_rx)
                    .await
                    .expect("server EOF deadline")
                    .expect("server EOF signal"),
                payload.len()
            );
            let mut response = vec![0; payload.len()];
            tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut response))
                .await
                .expect("bridge response deadline")
                .unwrap();
            assert_eq!(response.as_slice(), payload.as_slice());
            let mut eof = [0; 1];
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(2), stream.read(&mut eof))
                    .await
                    .expect("bridge EOF deadline")
                    .unwrap(),
                0
            );
            server.await.unwrap();
        }

        #[tokio::test]
        async fn network_framework_bridge_honors_pre_cancelled_dial() {
            let cancellation = CancellationToken::new();
            cancellation.cancel();
            let started = std::time::Instant::now();
            let error = connect_bridge(
                "127.0.0.1".to_string(),
                9,
                Duration::from_millis(500),
                cancellation,
                test_options(),
                false,
            )
            .await
            .err()
            .expect("cancelled connection must fail");
            assert!(started.elapsed() < Duration::from_millis(50));
            assert!(error.to_string().contains("cancelled"));
        }

        #[tokio::test]
        async fn dropping_network_framework_bridge_closes_the_remote_stream() {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let (received_tx, received_rx) = tokio::sync::oneshot::channel();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut byte = [0u8; 1];
                stream.read_exact(&mut byte).await.unwrap();
                assert_eq!(byte, [7]);
                let _ = received_tx.send(());
                let mut tail = [0u8; 1];
                let _ = stream.read(&mut tail).await;
            });

            let mut stream = connect_bridge(
                address.ip().to_string(),
                address.port(),
                Duration::from_secs(2),
                CancellationToken::new(),
                test_options(),
                false,
            )
            .await
            .unwrap();
            stream.write_all(&[7]).await.unwrap();
            tokio::time::timeout(Duration::from_secs(1), received_rx)
                .await
                .expect("server receive deadline")
                .expect("server receive signal");
            drop(stream);
            tokio::time::timeout(Duration::from_secs(1), server)
                .await
                .expect("remote close deadline")
                .unwrap();
        }
    }
}

#[cfg(target_os = "macos")]
pub(crate) use macos::{connect, runtime_available, MptcpOptions};

#[cfg(not(target_os = "macos"))]
mod unsupported {
    use std::{net::SocketAddr, time::Duration};

    use crate::outbound::{context::IpVersionStrategy, BoxedStream};

    pub(crate) struct MptcpOptions {
        pub source: Option<SocketAddr>,
        pub ip_version: IpVersionStrategy,
        pub keepalive: Option<Duration>,
        pub fast_open: bool,
    }

    pub(crate) async fn connect(
        _host: String,
        _port: u16,
        _timeout: Duration,
        _cancellation: tokio_util::sync::CancellationToken,
        _options: MptcpOptions,
    ) -> anyhow::Result<BoxedStream> {
        anyhow::bail!("MPTCP is only supported on macOS")
    }

    pub(crate) fn runtime_available() -> bool {
        false
    }
}

#[cfg(not(target_os = "macos"))]
pub(crate) use unsupported::{connect, runtime_available, MptcpOptions};
