use std::{
    future::Future,
    io::{Error, ErrorKind},
    pin::Pin,
    task::{Context as TaskContext, Poll},
    time::Duration,
};

use anyhow::Context;
use bytes::{Bytes, BytesMut};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    time::timeout,
};

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
    let (send_request, connection) = timeout(
        Duration::from_millis(timeout_ms),
        h2::client::Builder::new().handshake(stream),
    )
    .await
    .context("h2 handshake timed out")?
    .context("h2 handshake failed")?;
    tokio::spawn(async move {
        if let Err(error) = connection.await {
            tracing::debug!(error = %error, "h2 connection ended");
        }
    });

    let mut send_request = timeout(Duration::from_millis(timeout_ms), send_request.ready())
        .await
        .context("h2 client readiness timed out")?
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
