use std::{
    future::poll_fn,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use anyhow::{anyhow, Context};
use bytes::Bytes;
use tokio::sync::{mpsc, oneshot};
use tokio_util::{
    compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt},
    sync::CancellationToken,
};

use crate::{
    config::SmuxProtocol,
    outbound::{context::DialContext, transports::Http2TunnelStream, BoxedStream},
};

use super::within_context;

pub(super) enum MuxBackend {
    Smux(smux::Session),
    Yamux(YamuxClient),
    H2(H2Client),
}

impl MuxBackend {
    pub(super) async fn connect(
        protocol: SmuxProtocol,
        wire: tokio::io::DuplexStream,
        cancellation: CancellationToken,
        context: &DialContext,
        max_streams: usize,
    ) -> anyhow::Result<Self> {
        match protocol {
            SmuxProtocol::Smux => {
                let mut config = smux::Config::default();
                config.version = 1;
                config.enable_keep_alive = false;
                let session = within_context(context, "smux session handshake", async move {
                    smux::Session::client(wire, config)
                        .await
                        .context("smux session handshake failed")
                })
                .await?;
                Ok(Self::Smux(session))
            }
            SmuxProtocol::Yamux => Ok(Self::Yamux(YamuxClient::new(
                wire,
                cancellation,
                max_streams,
            ))),
            SmuxProtocol::H2Mux => Ok(Self::H2(
                H2Client::connect(wire, cancellation, context).await?,
            )),
        }
    }

    pub(super) fn is_closed(&self) -> bool {
        match self {
            Self::Smux(session) => session.is_closed(),
            Self::Yamux(client) => client.is_closed(),
            Self::H2(client) => client.is_closed(),
        }
    }

    pub(super) async fn open(&self, context: &DialContext) -> anyhow::Result<BoxedStream> {
        match self {
            Self::Smux(session) => {
                within_context(context, "smux open stream", async {
                    session
                        .open_stream()
                        .await
                        .map(|stream| Box::new(stream) as BoxedStream)
                        .context("smux open stream failed")
                })
                .await
            }
            Self::Yamux(client) => client.open(context).await,
            Self::H2(client) => client.open(context).await,
        }
    }
}

type YamuxOpenResult = Result<yamux::Stream, String>;
type YamuxOpenRequest = oneshot::Sender<YamuxOpenResult>;

pub(super) struct YamuxClient {
    requests: mpsc::Sender<YamuxOpenRequest>,
    closed: Arc<AtomicBool>,
}

impl YamuxClient {
    fn new(
        wire: tokio::io::DuplexStream,
        cancellation: CancellationToken,
        max_streams: usize,
    ) -> Self {
        let (requests, receiver) = mpsc::channel(64);
        let closed = Arc::new(AtomicBool::new(false));
        let driver_closed = Arc::clone(&closed);
        tokio::spawn(async move {
            drive_yamux(wire, receiver, cancellation, max_streams).await;
            driver_closed.store(true, Ordering::Release);
        });
        Self { requests, closed }
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire) || self.requests.is_closed()
    }

    async fn open(&self, context: &DialContext) -> anyhow::Result<BoxedStream> {
        let (response, receiver) = oneshot::channel();
        within_context(context, "yamux queue stream", async {
            self.requests
                .send(response)
                .await
                .map_err(|_| anyhow!("yamux session is closed"))
        })
        .await?;
        let stream = within_context(context, "yamux open stream", async {
            receiver
                .await
                .map_err(|_| anyhow!("yamux session closed before opening stream"))?
                .map_err(anyhow::Error::msg)
        })
        .await?;
        Ok(Box::new(stream.compat()) as BoxedStream)
    }
}

enum YamuxEvent {
    Open(YamuxOpenRequest),
    Inbound(Result<yamux::Stream, yamux::ConnectionError>),
    Closed,
}

async fn drive_yamux(
    wire: tokio::io::DuplexStream,
    mut requests: mpsc::Receiver<YamuxOpenRequest>,
    cancellation: CancellationToken,
    max_streams: usize,
) {
    let mut config = yamux::Config::default();
    config.set_max_num_streams(max_streams.max(512));
    let mut connection = yamux::Connection::new(wire.compat(), config, yamux::Mode::Client);
    loop {
        let event = tokio::select! {
            _ = cancellation.cancelled() => break,
            event = next_yamux_event(&mut connection, &mut requests) => event,
        };
        match event {
            YamuxEvent::Open(response) => {
                let result = tokio::select! {
                    _ = cancellation.cancelled() => Err("yamux session cancelled".to_string()),
                    result = poll_fn(|cx| connection.poll_new_outbound(cx)) => {
                        result.map_err(|error| error.to_string())
                    }
                };
                let _ = response.send(result);
            }
            YamuxEvent::Inbound(Ok(stream)) => drop(stream),
            YamuxEvent::Inbound(Err(error)) => {
                tracing::debug!(error = %error, "yamux connection ended");
                break;
            }
            YamuxEvent::Closed => break,
        }
    }
    while let Ok(response) = requests.try_recv() {
        let _ = response.send(Err("yamux session is closed".to_string()));
    }
}

async fn next_yamux_event<T>(
    connection: &mut yamux::Connection<T>,
    requests: &mut mpsc::Receiver<YamuxOpenRequest>,
) -> YamuxEvent
where
    T: futures::AsyncRead + futures::AsyncWrite + Unpin,
{
    poll_fn(|cx| {
        if let std::task::Poll::Ready(request) = requests.poll_recv(cx) {
            return std::task::Poll::Ready(match request {
                Some(request) => YamuxEvent::Open(request),
                None => YamuxEvent::Closed,
            });
        }
        match connection.poll_next_inbound(cx) {
            std::task::Poll::Ready(Some(stream)) => {
                std::task::Poll::Ready(YamuxEvent::Inbound(stream))
            }
            std::task::Poll::Ready(None) => std::task::Poll::Ready(YamuxEvent::Closed),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    })
    .await
}

pub(super) struct H2Client {
    sender: h2::client::SendRequest<Bytes>,
    closed: Arc<AtomicBool>,
}

impl H2Client {
    async fn connect(
        wire: tokio::io::DuplexStream,
        cancellation: CancellationToken,
        context: &DialContext,
    ) -> anyhow::Result<Self> {
        let (sender, connection) = within_context(context, "h2mux handshake", async move {
            h2::client::Builder::new()
                .handshake(wire)
                .await
                .context("h2mux handshake failed")
        })
        .await?;
        let closed = Arc::new(AtomicBool::new(false));
        let driver_closed = Arc::clone(&closed);
        tokio::spawn(async move {
            tokio::select! {
                _ = cancellation.cancelled() => {}
                result = connection => {
                    if let Err(error) = result {
                        tracing::debug!(error = %error, "h2mux connection ended");
                    }
                }
            }
            driver_closed.store(true, Ordering::Release);
        });
        Ok(Self { sender, closed })
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    async fn open(&self, context: &DialContext) -> anyhow::Result<BoxedStream> {
        let sender = self.sender.clone();
        let mut sender = within_context(context, "h2mux stream readiness", async move {
            sender.ready().await.context("h2mux session is not ready")
        })
        .await?;
        let request = http::Request::builder()
            .method(http::Method::CONNECT)
            .version(http::Version::HTTP_2)
            .uri("https://localhost")
            .body(())
            .context("failed to build h2mux CONNECT request")?;
        let (response, send) = sender
            .send_request(request, false)
            .context("failed to open h2mux CONNECT stream")?;
        Ok(Box::new(Http2TunnelStream::from_parts(send, response)) as BoxedStream)
    }
}
