use std::{
    future::Future,
    io::{Error, ErrorKind},
    pin::Pin,
    task::{Context as TaskContext, Poll},
    time::Duration,
};

use anyhow::{anyhow, Context};
use bytes::{Bytes, BytesMut};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    time::timeout,
};

use crate::outbound::context::{active_dial_context, DialContext};

use super::headers::normalize_http_path;

pub(crate) async fn open_h2_tunnel<S>(
    stream: S,
    host: &str,
    path: &str,
    timeout_ms: u64,
) -> anyhow::Result<Http2TunnelStream>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let context = active_dial_context();
    let (send_request, connection) = run_h2_phase(
        context.as_ref(),
        timeout_ms,
        "h2 handshake",
        h2::client::Builder::new().handshake(stream),
    )
    .await?
    .context("h2 handshake failed")?;
    tokio::spawn(async move {
        if let Err(error) = connection.await {
            tracing::debug!(error = %error, "h2 connection ended");
        }
    });

    let mut send_request = run_h2_phase(
        context.as_ref(),
        timeout_ms,
        "h2 client readiness",
        send_request.ready(),
    )
    .await?
    .context("h2 client is not ready")?;
    let path = normalize_http_path(path);
    let uri = format!("https://{host}{path}");
    let request = http::Request::builder()
        .method(http::Method::PUT)
        .version(http::Version::HTTP_2)
        .uri(uri)
        .header(http::header::USER_AGENT, "Supercore/0.1")
        .body(())
        .context("failed to build h2 request")?;
    let (response, send) = send_request
        .send_request(request, false)
        .context("failed to send h2 request")?;

    Ok(Http2TunnelStream {
        send,
        response: Some(response),
        recv: None,
        read_buffer: BytesMut::new(),
        closed: false,
    })
}

async fn run_h2_phase<F, T>(
    context: Option<&DialContext>,
    timeout_ms: u64,
    phase: &'static str,
    future: F,
) -> anyhow::Result<T>
where
    F: Future<Output = T>,
{
    let remaining = context
        .map(DialContext::remaining_timeout)
        .unwrap_or_else(|| Duration::from_millis(timeout_ms));
    if remaining.is_zero() {
        return Err(anyhow!("{phase} timed out"));
    }
    if let Some(context) = context {
        tokio::select! {
            _ = context.cancellation.cancelled() => Err(anyhow!("{phase} cancelled")),
            result = timeout(remaining, future) => {
                result.map_err(|_| anyhow!("{phase} timed out"))
            }
        }
    } else {
        timeout(remaining, future)
            .await
            .map_err(|_| anyhow!("{phase} timed out"))
    }
}

pub(crate) struct Http2TunnelStream {
    send: h2::SendStream<Bytes>,
    response: Option<h2::client::ResponseFuture>,
    recv: Option<h2::RecvStream>,
    read_buffer: BytesMut,
    closed: bool,
}

impl Drop for Http2TunnelStream {
    fn drop(&mut self) {
        if !self.closed {
            self.send.send_reset(h2::Reason::CANCEL);
        }
    }
}

impl Http2TunnelStream {
    pub(crate) fn from_parts(
        send: h2::SendStream<Bytes>,
        response: h2::client::ResponseFuture,
    ) -> Self {
        Self {
            send,
            response: Some(response),
            recv: None,
            read_buffer: BytesMut::new(),
            closed: false,
        }
    }

    fn poll_response(&mut self, cx: &mut TaskContext<'_>) -> Poll<Result<(), Error>> {
        if self.recv.is_some() {
            return Poll::Ready(Ok(()));
        }
        let response = self
            .response
            .as_mut()
            .ok_or_else(|| Error::new(ErrorKind::UnexpectedEof, "h2 response missing"))?;
        let response = match Pin::new(response).poll(cx) {
            Poll::Ready(Ok(response)) => response,
            Poll::Ready(Err(error)) => {
                return Poll::Ready(Err(Error::new(
                    ErrorKind::ConnectionAborted,
                    format!("h2 response failed: {error}"),
                )));
            }
            Poll::Pending => return Poll::Pending,
        };
        if !response.status().is_success() {
            return Poll::Ready(Err(Error::new(
                ErrorKind::ConnectionAborted,
                format!("h2 response status {}", response.status()),
            )));
        }
        self.recv = Some(response.into_body());
        self.response = None;
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for Http2TunnelStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), Error>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if !self.read_buffer.is_empty() {
                let len = self.read_buffer.len().min(buf.remaining());
                let chunk = self.read_buffer.split_to(len);
                buf.put_slice(&chunk);
                return Poll::Ready(Ok(()));
            }
            match self.poll_response(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
            let recv = self
                .recv
                .as_mut()
                .ok_or_else(|| Error::new(ErrorKind::UnexpectedEof, "h2 receive stream missing"));
            let recv = match recv {
                Ok(recv) => recv,
                Err(error) => return Poll::Ready(Err(error)),
            };
            match recv.poll_data(cx) {
                Poll::Ready(Some(Ok(chunk))) => {
                    let len = chunk.len();
                    self.read_buffer.extend_from_slice(&chunk);
                    if let Some(recv) = self.recv.as_mut() {
                        let _ = recv.flow_control().release_capacity(len);
                    }
                }
                Poll::Ready(Some(Err(error))) => {
                    return Poll::Ready(Err(Error::new(
                        ErrorKind::ConnectionAborted,
                        format!("h2 receive failed: {error}"),
                    )));
                }
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for Http2TunnelStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        if self.closed {
            return Poll::Ready(Err(Error::new(
                ErrorKind::BrokenPipe,
                "h2 send stream is closed",
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
                return Poll::Ready(Err(Error::new(
                    ErrorKind::BrokenPipe,
                    format!("h2 send capacity failed: {error}"),
                )));
            }
            Poll::Ready(None) => {
                return Poll::Ready(Err(Error::new(
                    ErrorKind::BrokenPipe,
                    "h2 send stream has no capacity",
                )));
            }
        }
        match self
            .send
            .send_data(Bytes::copy_from_slice(&buf[..len]), false)
        {
            Ok(()) => Poll::Ready(Ok(len)),
            Err(error) => Poll::Ready(Err(Error::new(
                ErrorKind::BrokenPipe,
                format!("h2 send failed: {error}"),
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<Result<(), Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        _cx: &mut TaskContext<'_>,
    ) -> Poll<Result<(), Error>> {
        if !self.closed {
            self.closed = true;
            if let Err(error) = self.send.send_data(Bytes::new(), true) {
                return Poll::Ready(Err(Error::new(
                    ErrorKind::BrokenPipe,
                    format!("h2 shutdown failed: {error}"),
                )));
            }
        }
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use std::{io::ErrorKind, time::Duration};

    use bytes::Bytes;
    use http::Response;
    use tokio::io::AsyncReadExt;

    use super::open_h2_tunnel;

    #[tokio::test]
    async fn remote_rst_is_reported_without_hanging() {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let server_task = tokio::spawn(async move {
            let mut connection = h2::server::handshake(server)
                .await
                .expect("server handshake");
            let (_request, mut respond) = connection
                .accept()
                .await
                .expect("request available")
                .expect("request accepted");
            let response = Response::builder().status(200).body(()).expect("response");
            let mut send = respond
                .send_response(response, false)
                .expect("response headers");
            send.send_reset(h2::Reason::REFUSED_STREAM);
            let _ = tokio::time::timeout(Duration::from_millis(100), connection.accept()).await;
        });

        let mut tunnel = open_h2_tunnel(client, "example.com", "/tunnel", 1_000)
            .await
            .expect("h2 tunnel");
        let mut byte = [0u8; 1];
        let error = tokio::time::timeout(Duration::from_secs(1), tunnel.read(&mut byte))
            .await
            .expect("RST handling must not hang")
            .expect_err("RST must fail the stream");
        assert_eq!(error.kind(), ErrorKind::ConnectionAborted);
        assert!(
            error.to_string().contains("h2 response failed")
                || error.to_string().contains("h2 receive failed"),
            "unexpected RST error: {error}"
        );
        server_task.await.expect("server task");
    }

    #[tokio::test]
    async fn remote_goaway_before_response_is_reported_without_hanging() {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let server_task = tokio::spawn(async move {
            let mut connection = h2::server::handshake(server)
                .await
                .expect("server handshake");
            let (_request, _respond) = connection
                .accept()
                .await
                .expect("request available")
                .expect("request accepted");
            connection.abrupt_shutdown(h2::Reason::ENHANCE_YOUR_CALM);
            let _ = tokio::time::timeout(Duration::from_secs(1), async {
                while connection.accept().await.is_some() {}
            })
            .await;
        });

        let mut tunnel = open_h2_tunnel(client, "example.com", "/tunnel", 1_000)
            .await
            .expect("h2 tunnel");
        let mut byte = [0u8; 1];
        let error = tokio::time::timeout(Duration::from_secs(1), tunnel.read(&mut byte))
            .await
            .expect("GOAWAY handling must not hang")
            .expect_err("GOAWAY must fail the pending response");
        assert_eq!(error.kind(), ErrorKind::ConnectionAborted);
        assert!(error.to_string().contains("h2 response failed"));
        server_task.await.expect("server task");
    }

    #[tokio::test]
    async fn graceful_goaway_allows_active_stream_to_finish() {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let server_task = tokio::spawn(async move {
            let mut connection = h2::server::handshake(server)
                .await
                .expect("server handshake");
            let (_request, mut respond) = connection
                .accept()
                .await
                .expect("request available")
                .expect("request accepted");
            let response = Response::builder().status(200).body(()).expect("response");
            let mut send = respond
                .send_response(response, false)
                .expect("response headers");
            send.send_data(Bytes::from_static(b"ok"), true)
                .expect("response body");
            connection.graceful_shutdown();
            let _ = tokio::time::timeout(Duration::from_secs(1), async {
                while connection.accept().await.is_some() {}
            })
            .await;
        });

        let mut tunnel = open_h2_tunnel(client, "example.com", "/tunnel", 1_000)
            .await
            .expect("h2 tunnel");
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(1), tunnel.read_to_end(&mut response))
            .await
            .expect("graceful GOAWAY must not hang")
            .expect("active stream must finish");
        assert_eq!(response, b"ok");
        server_task.await.expect("server task");
    }
}
