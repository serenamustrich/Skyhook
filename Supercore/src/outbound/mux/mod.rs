mod backend;
mod wire;

use std::{
    future::Future,
    io,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
    task::{Context as TaskContext, Poll},
};

use anyhow::{anyhow, Context};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    sync::Mutex,
};
use tokio_util::sync::CancellationToken;

use crate::{config::SmuxConfig, routing::Destination};

use super::{
    context::DialContext, target::encode_socks5_destination, transports::scope_tcp_dialer,
    BoxedStream, Outbound,
};
use backend::MuxBackend;

const MUX_DESTINATION_HOST: &str = "sp.mux.sing-box.arpa";
const MUX_DESTINATION_PORT: u16 = 444;
const MAX_STREAMS_PER_CONNECTION: usize = 4096;
const MAX_UDP_PACKET_SIZE: usize = u16::MAX as usize;

pub(super) struct MuxPool {
    inner: Arc<dyn Outbound>,
    config: SmuxConfig,
    sessions: Mutex<Vec<Arc<PhysicalSession>>>,
    metrics: Arc<MuxMetrics>,
}

impl MuxPool {
    pub(super) fn new(inner: Arc<dyn Outbound>, config: SmuxConfig) -> Self {
        Self {
            inner,
            config,
            sessions: Mutex::new(Vec::new()),
            metrics: Arc::new(MuxMetrics::default()),
        }
    }

    pub(super) async fn connect(
        &self,
        context: &DialContext,
        dialer: Option<Arc<dyn Outbound>>,
    ) -> anyhow::Result<BoxedStream> {
        let raw = self.open_raw(context, dialer, 0).await?;
        let RawLogicalStream { stream, lease } = raw;
        Ok(Box::new(CountingMuxStream {
            inner: stream,
            _lease: lease,
            metrics: Arc::clone(&self.metrics),
        }))
    }

    pub(super) async fn udp_exchange(
        &self,
        context: &DialContext,
        payload: &[u8],
        dialer: Option<Arc<dyn Outbound>>,
    ) -> anyhow::Result<Vec<u8>> {
        if payload.len() > MAX_UDP_PACKET_SIZE {
            return Err(anyhow!(
                "sing-mux UDP payload is too large: {} bytes",
                payload.len()
            ));
        }
        let RawLogicalStream {
            mut stream,
            lease: _lease,
        } = self.open_raw(context, dialer, 1).await?;

        let response = within_context(context, "sing-mux UDP exchange", async {
            stream.write_u16(payload.len() as u16).await?;
            stream.write_all(payload).await?;
            stream.flush().await?;
            let response_len = stream.read_u16().await? as usize;
            let mut response = vec![0u8; response_len];
            stream.read_exact(&mut response).await?;
            Ok(response)
        })
        .await?;
        self.metrics
            .uploaded
            .fetch_add(payload.len() as u64, Ordering::Relaxed);
        self.metrics
            .downloaded
            .fetch_add(response.len() as u64, Ordering::Relaxed);
        Ok(response)
    }

    async fn open_raw(
        &self,
        context: &DialContext,
        dialer: Option<Arc<dyn Outbound>>,
        flags: u16,
    ) -> anyhow::Result<RawLogicalStream> {
        let mut last_error = None;
        for _ in 0..2 {
            let session = match self.offer(context, dialer.clone()).await {
                Ok(session) => session,
                Err(error) => {
                    self.metrics.open_failures.fetch_add(1, Ordering::Relaxed);
                    if context.cancellation.is_cancelled() || context.remaining_timeout().is_zero()
                    {
                        return Err(error);
                    }
                    last_error = Some(error);
                    continue;
                }
            };
            let result = async {
                let mut stream = session.backend.open(context).await?;
                let mut request = Vec::with_capacity(2 + context.destination.host.len() + 4);
                request.extend_from_slice(&flags.to_be_bytes());
                encode_socks5_destination(&context.destination, &mut request)?;
                within_context(context, "sing-mux logical stream handshake", async {
                    stream.write_all(&request).await?;
                    stream.flush().await?;
                    read_stream_status(&mut stream).await
                })
                .await?;
                Ok::<_, anyhow::Error>(stream)
            }
            .await;
            match result {
                Ok(stream) => {
                    self.metrics.logical_opened.fetch_add(1, Ordering::Relaxed);
                    return Ok(RawLogicalStream {
                        stream,
                        lease: ActiveLease {
                            session,
                            metrics: Arc::clone(&self.metrics),
                        },
                    });
                }
                Err(error) => {
                    session.active_streams.fetch_sub(1, Ordering::AcqRel);
                    self.metrics.open_failures.fetch_add(1, Ordering::Relaxed);
                    if context.cancellation.is_cancelled() || context.remaining_timeout().is_zero()
                    {
                        return Err(error);
                    }
                    session.mark_unhealthy();
                    last_error = Some(error);
                }
            }
        }
        Err(last_error.unwrap_or_else(|| anyhow!("sing-mux failed to open a logical stream")))
    }

    async fn offer(
        &self,
        context: &DialContext,
        dialer: Option<Arc<dyn Outbound>>,
    ) -> anyhow::Result<Arc<PhysicalSession>> {
        let mut sessions = self.sessions.lock().await;
        let mut retained = Vec::with_capacity(sessions.len());
        for session in sessions.drain(..) {
            if session.is_healthy() {
                retained.push(session);
            } else {
                session.mark_unhealthy();
                self.metrics.physical_active.fetch_sub(1, Ordering::AcqRel);
                self.metrics.evicted.fetch_add(1, Ordering::Relaxed);
            }
        }
        *sessions = retained;

        let best = sessions
            .iter()
            .filter(|session| self.can_take(session))
            .min_by_key(|session| session.active_streams.load(Ordering::Acquire))
            .cloned();
        if best.is_none()
            && self.config.max_connections > 0
            && sessions.len() >= self.config.max_connections
        {
            return Err(anyhow!(
                "sing-mux pool reached {} physical connections with {} streams per connection",
                self.config.max_connections,
                MAX_STREAMS_PER_CONNECTION
            ));
        }
        let use_existing = best.as_ref().is_some_and(|session| {
            let active = session.active_streams.load(Ordering::Acquire);
            if active == 0 {
                return true;
            }
            if self.config.max_connections > 0 {
                sessions.len() >= self.config.max_connections || active < self.config.min_streams
            } else if self.config.max_streams > 0 {
                active < self.config.max_streams
            } else {
                active < self.config.min_streams.max(8)
            }
        });

        let session = if use_existing {
            self.metrics.reused.fetch_add(1, Ordering::Relaxed);
            best.expect("checked above")
        } else {
            let session = Arc::new(self.create_session(context, dialer).await?);
            sessions.push(Arc::clone(&session));
            self.metrics
                .physical_created
                .fetch_add(1, Ordering::Relaxed);
            self.metrics.physical_active.fetch_add(1, Ordering::Relaxed);
            session
        };
        session.active_streams.fetch_add(1, Ordering::AcqRel);
        Ok(session)
    }

    fn can_take(&self, session: &PhysicalSession) -> bool {
        let active = session.active_streams.load(Ordering::Acquire);
        active < MAX_STREAMS_PER_CONNECTION
            && (self.config.max_streams == 0 || active < self.config.max_streams)
    }

    async fn create_session(
        &self,
        context: &DialContext,
        dialer: Option<Arc<dyn Outbound>>,
    ) -> anyhow::Result<PhysicalSession> {
        let mut underlay_context = context.clone();
        underlay_context.destination = Destination::new(MUX_DESTINATION_HOST, MUX_DESTINATION_PORT);
        let base = scope_tcp_dialer(dialer, self.inner.connect_context(&underlay_context))
            .await
            .context("failed to dial sing-mux underlay")?;
        let cancellation = CancellationToken::new();
        let wire = wire::spawn_protocol_stream(
            base,
            self.config.protocol,
            self.config.padding,
            cancellation.clone(),
        );
        let backend = match MuxBackend::connect(
            self.config.protocol,
            wire,
            cancellation.clone(),
            context,
            self.config.max_streams.min(MAX_STREAMS_PER_CONNECTION),
        )
        .await
        {
            Ok(backend) => backend,
            Err(error) => {
                cancellation.cancel();
                return Err(error);
            }
        };
        Ok(PhysicalSession {
            backend,
            active_streams: AtomicUsize::new(0),
            unhealthy: AtomicBool::new(false),
            cancellation,
        })
    }

    pub(super) fn snapshot(&self) -> MuxSnapshot {
        self.metrics.snapshot(self.config.statistic)
    }
}

struct PhysicalSession {
    backend: MuxBackend,
    active_streams: AtomicUsize,
    unhealthy: AtomicBool,
    cancellation: CancellationToken,
}

impl PhysicalSession {
    fn is_healthy(&self) -> bool {
        !self.unhealthy.load(Ordering::Acquire) && !self.backend.is_closed()
    }

    fn mark_unhealthy(&self) {
        self.unhealthy.store(true, Ordering::Release);
        self.cancellation.cancel();
    }
}

impl Drop for PhysicalSession {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

struct RawLogicalStream {
    stream: BoxedStream,
    lease: ActiveLease,
}

struct ActiveLease {
    session: Arc<PhysicalSession>,
    metrics: Arc<MuxMetrics>,
}

impl Drop for ActiveLease {
    fn drop(&mut self) {
        self.session.active_streams.fetch_sub(1, Ordering::AcqRel);
        self.metrics.logical_closed.fetch_add(1, Ordering::Relaxed);
    }
}

struct CountingMuxStream {
    inner: BoxedStream,
    _lease: ActiveLease,
    metrics: Arc<MuxMetrics>,
}

impl AsyncRead for CountingMuxStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &result {
            let read = buf.filled().len().saturating_sub(before);
            self.metrics
                .downloaded
                .fetch_add(read as u64, Ordering::Relaxed);
        }
        result
    }
}

impl AsyncWrite for CountingMuxStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(written)) = result {
            self.metrics
                .uploaded
                .fetch_add(written as u64, Ordering::Relaxed);
            Poll::Ready(Ok(written))
        } else {
            result
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[derive(Default)]
struct MuxMetrics {
    physical_created: AtomicU64,
    physical_active: AtomicUsize,
    logical_opened: AtomicU64,
    logical_closed: AtomicU64,
    open_failures: AtomicU64,
    reused: AtomicU64,
    evicted: AtomicU64,
    uploaded: AtomicU64,
    downloaded: AtomicU64,
}

#[derive(Debug, serde::Serialize, PartialEq, Eq)]
pub(super) struct MuxSnapshot {
    pub underlay_visible: bool,
    pub physical_created: u64,
    pub physical_active: usize,
    pub logical_opened: u64,
    pub logical_closed: u64,
    pub open_failures: u64,
    pub reused: u64,
    pub evicted: u64,
    pub uploaded: u64,
    pub downloaded: u64,
}

impl MuxMetrics {
    fn snapshot(&self, underlay_visible: bool) -> MuxSnapshot {
        MuxSnapshot {
            underlay_visible,
            physical_created: self.physical_created.load(Ordering::Relaxed),
            physical_active: self.physical_active.load(Ordering::Relaxed),
            logical_opened: self.logical_opened.load(Ordering::Relaxed),
            logical_closed: self.logical_closed.load(Ordering::Relaxed),
            open_failures: self.open_failures.load(Ordering::Relaxed),
            reused: self.reused.load(Ordering::Relaxed),
            evicted: self.evicted.load(Ordering::Relaxed),
            uploaded: self.uploaded.load(Ordering::Relaxed),
            downloaded: self.downloaded.load(Ordering::Relaxed),
        }
    }
}

async fn read_stream_status(stream: &mut BoxedStream) -> anyhow::Result<()> {
    match stream.read_u8().await? {
        0 => Ok(()),
        1 => Err(anyhow!("sing-mux server rejected the logical stream")),
        status => Err(anyhow!("unknown sing-mux stream status {status}")),
    }
}

pub(super) async fn within_context<T, F>(
    context: &DialContext,
    operation: &'static str,
    future: F,
) -> anyhow::Result<T>
where
    F: Future<Output = anyhow::Result<T>>,
{
    let remaining = context.remaining_timeout();
    if remaining.is_zero() {
        return Err(anyhow!("{operation} exceeded its deadline"));
    }
    tokio::select! {
        _ = context.cancellation.cancelled() => Err(anyhow!("{operation} was cancelled")),
        result = tokio::time::timeout(remaining, future) => {
            result
                .with_context(|| format!("{operation} timed out"))?
                .with_context(|| operation)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io,
        pin::Pin,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
        task::{Context as TaskContext, Poll},
    };

    use async_trait::async_trait;
    use bytes::{Bytes, BytesMut};
    use futures::future::poll_fn;
    use tokio::{
        io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
        sync::mpsc,
    };
    use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

    use crate::{
        config::{SmuxConfig, SmuxProtocol},
        outbound::{
            target::read_socks5_destination_after_atyp, BoxedStream, Outbound, OutboundCapability,
        },
        routing::Destination,
    };

    use super::{wire::accept_protocol_stream, DialContext, MuxPool};

    struct MockUnderlay {
        sender: mpsc::UnboundedSender<BoxedStream>,
        dials: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl Outbound for MockUnderlay {
        fn name(&self) -> &str {
            "mock-underlay"
        }

        fn kind(&self) -> &'static str {
            "mock"
        }

        fn capability(&self) -> OutboundCapability {
            OutboundCapability::tcp_only("test underlay")
        }

        async fn connect(
            &self,
            destination: &Destination,
            _timeout_ms: u64,
        ) -> anyhow::Result<BoxedStream> {
            assert_eq!(destination.host, super::MUX_DESTINATION_HOST);
            assert_eq!(destination.port, super::MUX_DESTINATION_PORT);
            self.dials.fetch_add(1, Ordering::Relaxed);
            let (client, server) = tokio::io::duplex(256 * 1024);
            self.sender
                .send(Box::new(server) as BoxedStream)
                .map_err(|_| anyhow::anyhow!("test sing-mux server stopped"))?;
            Ok(Box::new(client) as BoxedStream)
        }
    }

    struct TestHarness {
        pool: MuxPool,
        physical_dials: Arc<AtomicUsize>,
        logical_streams: Arc<AtomicUsize>,
        server: tokio::task::JoinHandle<()>,
    }

    impl Drop for TestHarness {
        fn drop(&mut self) {
            self.server.abort();
        }
    }

    fn harness(config: SmuxConfig) -> TestHarness {
        harness_with_first_failure(config, false)
    }

    fn harness_with_first_failure(config: SmuxConfig, fail_first: bool) -> TestHarness {
        let (sender, mut receiver) = mpsc::unbounded_channel();
        let physical_dials = Arc::new(AtomicUsize::new(0));
        let logical_streams = Arc::new(AtomicUsize::new(0));
        let underlay: Arc<dyn Outbound> = Arc::new(MockUnderlay {
            sender,
            dials: Arc::clone(&physical_dials),
        });
        let protocol = config.protocol;
        let padding = config.padding;
        let server_logical_streams = Arc::clone(&logical_streams);
        let server = tokio::spawn(async move {
            let mut accepted = 0usize;
            while let Some(base) = receiver.recv().await {
                accepted += 1;
                if fail_first && accepted == 1 {
                    drop(base);
                    continue;
                }
                let logical_streams = Arc::clone(&server_logical_streams);
                tokio::spawn(async move {
                    if let Err(error) =
                        serve_physical(base, protocol, padding, logical_streams).await
                    {
                        tracing::debug!(error = %error, "sing-mux test server ended");
                    }
                });
            }
        });
        TestHarness {
            pool: MuxPool::new(underlay, config),
            physical_dials,
            logical_streams,
            server,
        }
    }

    struct BlockingUnderlay {
        dials: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl Outbound for BlockingUnderlay {
        fn name(&self) -> &str {
            "blocking-underlay"
        }

        fn kind(&self) -> &'static str {
            "mock"
        }

        fn capability(&self) -> OutboundCapability {
            OutboundCapability::tcp_only("blocking test underlay")
        }

        async fn connect(
            &self,
            _destination: &Destination,
            _timeout_ms: u64,
        ) -> anyhow::Result<BoxedStream> {
            self.dials.fetch_add(1, Ordering::Relaxed);
            std::future::pending().await
        }
    }

    async fn serve_physical(
        base: BoxedStream,
        protocol: SmuxProtocol,
        padding: bool,
        logical_streams: Arc<AtomicUsize>,
    ) -> anyhow::Result<()> {
        let wire = accept_protocol_stream(base, protocol, padding).await?;
        match protocol {
            SmuxProtocol::Smux => {
                let mut config = smux::Config::default();
                config.enable_keep_alive = false;
                let session = smux::Session::server(wire, config).await?;
                while let Ok(stream) = session.accept_stream().await {
                    let logical_streams = Arc::clone(&logical_streams);
                    tokio::spawn(handle_echo_stream(stream, logical_streams));
                }
            }
            SmuxProtocol::Yamux => {
                let mut config = yamux::Config::default();
                config.set_max_num_streams(4096);
                let mut connection =
                    yamux::Connection::new(wire.compat(), config, yamux::Mode::Server);
                while let Some(stream) = poll_fn(|cx| connection.poll_next_inbound(cx)).await {
                    let stream = stream?;
                    let logical_streams = Arc::clone(&logical_streams);
                    tokio::spawn(handle_echo_stream(stream.compat(), logical_streams));
                }
            }
            SmuxProtocol::H2Mux => {
                let mut connection = h2::server::handshake(wire).await?;
                while let Some(request) = connection.accept().await {
                    let (request, mut respond) = request?;
                    if request.method() != http::Method::CONNECT {
                        return Err(anyhow::anyhow!("expected h2mux CONNECT request"));
                    }
                    let recv = request.into_body();
                    let response = http::Response::builder()
                        .status(http::StatusCode::OK)
                        .body(())?;
                    let send = respond.send_response(response, false)?;
                    let stream = H2ServerStream {
                        send,
                        recv,
                        read_buffer: BytesMut::new(),
                        closed: false,
                    };
                    let logical_streams = Arc::clone(&logical_streams);
                    tokio::spawn(handle_echo_stream(stream, logical_streams));
                }
            }
        }
        Ok(())
    }

    async fn handle_echo_stream<S>(mut stream: S, logical_streams: Arc<AtomicUsize>)
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let result = async {
            let flags = stream.read_u16().await?;
            let atyp = stream.read_u8().await?;
            let _destination = read_socks5_destination_after_atyp(&mut stream, atyp).await?;
            logical_streams.fetch_add(1, Ordering::Relaxed);
            stream.write_u8(0).await?;
            stream.flush().await?;
            if flags & 1 != 0 {
                let len = stream.read_u16().await? as usize;
                let mut packet = vec![0u8; len];
                stream.read_exact(&mut packet).await?;
                stream.write_u16(len as u16).await?;
                stream.write_all(&packet).await?;
                stream.shutdown().await?;
                return Ok::<_, anyhow::Error>(());
            }
            let mut buffer = [0u8; 8192];
            loop {
                let read = stream.read(&mut buffer).await?;
                if read == 0 {
                    break;
                }
                stream.write_all(&buffer[..read]).await?;
                stream.flush().await?;
            }
            Ok(())
        }
        .await;
        if let Err(error) = result {
            tracing::debug!(error = %error, "sing-mux logical test stream ended");
        }
    }

    struct H2ServerStream {
        send: h2::SendStream<Bytes>,
        recv: h2::RecvStream,
        read_buffer: BytesMut,
        closed: bool,
    }

    impl Drop for H2ServerStream {
        fn drop(&mut self) {
            if !self.closed {
                self.send.send_reset(h2::Reason::CANCEL);
            }
        }
    }

    impl AsyncRead for H2ServerStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut TaskContext<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            loop {
                if !self.read_buffer.is_empty() {
                    let len = self.read_buffer.len().min(buf.remaining());
                    let chunk = self.read_buffer.split_to(len);
                    buf.put_slice(&chunk);
                    return Poll::Ready(Ok(()));
                }
                match self.recv.poll_data(cx) {
                    Poll::Ready(Some(Ok(chunk))) => {
                        let len = chunk.len();
                        self.read_buffer.extend_from_slice(&chunk);
                        let _ = self.recv.flow_control().release_capacity(len);
                    }
                    Poll::Ready(Some(Err(error))) => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::ConnectionAborted,
                            error,
                        )));
                    }
                    Poll::Ready(None) => return Poll::Ready(Ok(())),
                    Poll::Pending => return Poll::Pending,
                }
            }
        }
    }

    impl AsyncWrite for H2ServerStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut TaskContext<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            if self.closed {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "h2mux test stream is closed",
                )));
            }
            if buf.is_empty() {
                return Poll::Ready(Ok(0));
            }
            let len = buf.len().min(16 * 1024);
            self.send.reserve_capacity(len);
            match self.send.poll_capacity(cx) {
                Poll::Ready(Some(Ok(capacity))) if capacity >= len => {}
                Poll::Ready(Some(Ok(_))) | Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Err(error))) => {
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, error)));
                }
                Poll::Ready(None) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "h2mux test stream has no capacity",
                    )));
                }
            }
            match self
                .send
                .send_data(Bytes::copy_from_slice(&buf[..len]), false)
            {
                Ok(()) => Poll::Ready(Ok(len)),
                Err(error) => Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, error))),
            }
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            _cx: &mut TaskContext<'_>,
        ) -> Poll<io::Result<()>> {
            if !self.closed {
                self.closed = true;
                self.send
                    .send_data(Bytes::new(), true)
                    .map_err(|error| io::Error::new(io::ErrorKind::BrokenPipe, error))?;
            }
            Poll::Ready(Ok(()))
        }
    }

    fn config(protocol: SmuxProtocol) -> SmuxConfig {
        SmuxConfig {
            enabled: true,
            protocol,
            max_connections: 1,
            min_streams: 1,
            statistic: true,
            ..SmuxConfig::default()
        }
    }

    #[tokio::test]
    async fn all_backends_share_one_physical_connection_for_concurrent_streams() {
        for protocol in [SmuxProtocol::Smux, SmuxProtocol::Yamux, SmuxProtocol::H2Mux] {
            let harness = harness(config(protocol));
            let first_context = DialContext::new(Destination::new("one.example", 443), 3_000);
            let second_context = DialContext::new(Destination::new("two.example", 8443), 3_000);
            let mut first = harness.pool.connect(&first_context, None).await.unwrap();
            let mut second = harness.pool.connect(&second_context, None).await.unwrap();

            first.write_all(b"first").await.unwrap();
            second.write_all(b"second").await.unwrap();
            let mut first_reply = [0u8; 5];
            let mut second_reply = [0u8; 6];
            first.read_exact(&mut first_reply).await.unwrap();
            second.read_exact(&mut second_reply).await.unwrap();
            assert_eq!(&first_reply, b"first");
            assert_eq!(&second_reply, b"second");
            assert_eq!(harness.physical_dials.load(Ordering::Relaxed), 1);
            assert_eq!(harness.logical_streams.load(Ordering::Relaxed), 2);

            first.shutdown().await.unwrap();
            second.shutdown().await.unwrap();
            drop(first);
            drop(second);
            let snapshot = harness.pool.snapshot();
            assert_eq!(snapshot.physical_created, 1);
            assert_eq!(snapshot.logical_opened, 2);
            assert_eq!(snapshot.logical_closed, 2);
            assert_eq!(snapshot.reused, 1);
            assert_eq!(snapshot.uploaded, 11);
            assert_eq!(snapshot.downloaded, 11);
        }
    }

    #[tokio::test]
    async fn max_streams_opens_another_physical_connection() {
        let harness = harness(SmuxConfig {
            enabled: true,
            protocol: SmuxProtocol::Smux,
            max_connections: 0,
            min_streams: 0,
            max_streams: 1,
            ..SmuxConfig::default()
        });
        let first_context = DialContext::new(Destination::new("one.example", 443), 3_000);
        let second_context = DialContext::new(Destination::new("two.example", 443), 3_000);
        let first = harness.pool.connect(&first_context, None).await.unwrap();
        let second = harness.pool.connect(&second_context, None).await.unwrap();
        assert_eq!(harness.physical_dials.load(Ordering::Relaxed), 2);
        drop(first);
        drop(second);
    }

    #[tokio::test]
    async fn padding_and_udp_round_trip_are_wire_compatible() {
        let harness = harness(SmuxConfig {
            padding: true,
            ..config(SmuxProtocol::H2Mux)
        });
        let context = DialContext::new(Destination::new("dns.example", 53), 3_000);
        let response = harness
            .pool
            .udp_exchange(&context, b"dns-packet", None)
            .await
            .unwrap();
        assert_eq!(response, b"dns-packet");
        assert_eq!(harness.physical_dials.load(Ordering::Relaxed), 1);
        let snapshot = harness.pool.snapshot();
        assert_eq!(snapshot.uploaded, 10);
        assert_eq!(snapshot.downloaded, 10);
        assert!(snapshot.underlay_visible);
    }

    #[tokio::test]
    async fn unhealthy_session_is_evicted_and_replaced_once() {
        let harness = harness_with_first_failure(config(SmuxProtocol::Smux), true);
        let context = DialContext::new(Destination::new("recover.example", 443), 3_000);
        let mut stream = harness.pool.connect(&context, None).await.unwrap();
        stream.write_all(b"recovered").await.unwrap();
        let mut reply = [0u8; 9];
        stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"recovered");
        assert_eq!(harness.physical_dials.load(Ordering::Relaxed), 2);
        let snapshot = harness.pool.snapshot();
        assert!(snapshot.open_failures >= 1);
        assert_eq!(snapshot.physical_created, 2);
        assert_eq!(snapshot.evicted, 1);
    }

    #[tokio::test]
    async fn caller_cancellation_stops_underlay_creation() {
        let dials = Arc::new(AtomicUsize::new(0));
        let underlay: Arc<dyn Outbound> = Arc::new(BlockingUnderlay {
            dials: Arc::clone(&dials),
        });
        let pool = MuxPool::new(underlay, config(SmuxProtocol::H2Mux));
        let context = DialContext::new(Destination::new("cancel.example", 443), 5_000);
        let cancellation = context.cancellation.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            cancellation.cancel();
        });
        let error = match pool.connect(&context, None).await {
            Ok(_) => panic!("cancelled mux dial unexpectedly succeeded"),
            Err(error) => error,
        };
        assert!(format!("{error:#}").contains("cancel"));
        assert_eq!(dials.load(Ordering::Relaxed), 1);
        let snapshot = pool.snapshot();
        assert_eq!(snapshot.physical_created, 0);
        assert!(snapshot.open_failures >= 1);
    }
}
