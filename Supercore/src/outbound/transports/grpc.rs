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

pub(crate) async fn open_grpc_tunnel<S>(
    stream: S,
    host: &str,
    service_name: Option<&str>,
    timeout_ms: u64,
) -> anyhow::Result<GrpcTunnelStream>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (send_request, connection) = timeout(
        Duration::from_millis(timeout_ms),
        h2::client::Builder::new().handshake(stream),
    )
    .await
    .context("grpc h2 handshake timed out")?
    .context("grpc h2 handshake failed")?;
    tokio::spawn(async move {
        if let Err(error) = connection.await {
            tracing::debug!(error = %error, "grpc h2 connection ended");
        }
    });

    let mut send_request = timeout(Duration::from_millis(timeout_ms), send_request.ready())
        .await
        .context("grpc h2 client readiness timed out")?
        .context("grpc h2 client is not ready")?;
    let path = grpc_service_path(service_name);
    let uri = format!("https://{host}{path}");
    let request = http::Request::builder()
        .method(http::Method::POST)
        .version(http::Version::HTTP_2)
        .uri(uri)
        .header(http::header::CONTENT_TYPE, "application/grpc")
        .header("te", "trailers")
        .header(http::header::USER_AGENT, "Supercore/0.1")
        .body(())
        .context("failed to build grpc request")?;
    let (response, send) = send_request
        .send_request(request, false)
        .context("failed to send grpc request")?;

    Ok(GrpcTunnelStream {
        send,
        response: Some(response),
        recv: None,
        incoming: BytesMut::new(),
        read_buffer: BytesMut::new(),
        closed: false,
    })
}

fn grpc_service_path(service_name: Option<&str>) -> String {
    let Some(service_name) = service_name.map(str::trim).filter(|item| !item.is_empty()) else {
        return "/Tun".to_string();
    };
    if service_name.starts_with('/') {
        return service_name.to_string();
    }
    format!("/{}/Tun", service_name.trim_matches('/'))
}

pub(crate) struct GrpcTunnelStream {
    send: h2::SendStream<Bytes>,
    response: Option<h2::client::ResponseFuture>,
    recv: Option<h2::RecvStream>,
    incoming: BytesMut,
    read_buffer: BytesMut,
    closed: bool,
}

impl Drop for GrpcTunnelStream {
    fn drop(&mut self) {
        if !self.closed {
            self.send.send_reset(h2::Reason::CANCEL);
        }
    }
}

impl GrpcTunnelStream {
    fn poll_response(&mut self, cx: &mut TaskContext<'_>) -> Poll<Result<(), Error>> {
        if self.recv.is_some() {
            return Poll::Ready(Ok(()));
        }
        let response = self
            .response
            .as_mut()
            .ok_or_else(|| Error::new(ErrorKind::UnexpectedEof, "grpc response missing"))?;
        let response = match Pin::new(response).poll(cx) {
            Poll::Ready(Ok(response)) => response,
            Poll::Ready(Err(error)) => {
                return Poll::Ready(Err(Error::new(
                    ErrorKind::ConnectionAborted,
                    format!("grpc response failed: {error}"),
                )));
            }
            Poll::Pending => return Poll::Pending,
        };
        if !response.status().is_success() {
            return Poll::Ready(Err(Error::new(
                ErrorKind::ConnectionAborted,
                format!("grpc response status {}", response.status()),
            )));
        }
        if let Err(error) = validate_grpc_status(response.headers()) {
            return Poll::Ready(Err(error));
        }
        self.recv = Some(response.into_body());
        self.response = None;
        Poll::Ready(Ok(()))
    }

    fn decode_next_message(&mut self) -> Result<bool, Error> {
        if self.incoming.len() < 5 {
            return Ok(false);
        }
        let compressed = self.incoming[0];
        if compressed != 0 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "compressed grpc messages are not supported",
            ));
        }
        let len = u32::from_be_bytes([
            self.incoming[1],
            self.incoming[2],
            self.incoming[3],
            self.incoming[4],
        ]) as usize;
        if self.incoming.len() < 5 + len {
            return Ok(false);
        }
        bytes::Buf::advance(&mut self.incoming, 5);
        let payload = self.incoming.split_to(len);
        self.read_buffer.extend_from_slice(&payload);
        Ok(true)
    }
}

impl AsyncRead for GrpcTunnelStream {
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

            match self.decode_next_message() {
                Ok(true) => continue,
                Ok(false) => {}
                Err(error) => return Poll::Ready(Err(error)),
            }

            match self.poll_response(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }

            let recv = self
                .recv
                .as_mut()
                .ok_or_else(|| Error::new(ErrorKind::UnexpectedEof, "grpc receive stream missing"));
            let recv = match recv {
                Ok(recv) => recv,
                Err(error) => return Poll::Ready(Err(error)),
            };
            match recv.poll_data(cx) {
                Poll::Ready(Some(Ok(chunk))) => {
                    let len = chunk.len();
                    self.incoming.extend_from_slice(&chunk);
                    if let Some(recv) = self.recv.as_mut() {
                        let _ = recv.flow_control().release_capacity(len);
                    }
                }
                Poll::Ready(Some(Err(error))) => {
                    return Poll::Ready(Err(Error::new(
                        ErrorKind::ConnectionAborted,
                        format!("grpc receive failed: {error}"),
                    )));
                }
                Poll::Ready(None) => match recv.poll_trailers(cx) {
                    Poll::Ready(Ok(Some(trailers))) => {
                        if let Err(error) = validate_grpc_status(&trailers) {
                            return Poll::Ready(Err(error));
                        }
                        return Poll::Ready(Ok(()));
                    }
                    Poll::Ready(Ok(None)) => return Poll::Ready(Ok(())),
                    Poll::Ready(Err(error)) => {
                        return Poll::Ready(Err(Error::new(
                            ErrorKind::ConnectionAborted,
                            format!("grpc trailers failed: {error}"),
                        )));
                    }
                    Poll::Pending => return Poll::Pending,
                },
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

fn validate_grpc_status(headers: &http::HeaderMap) -> Result<(), Error> {
    let Some(status) = headers.get("grpc-status") else {
        return Ok(());
    };
    let status = status.to_str().map_err(|error| {
        Error::new(
            ErrorKind::InvalidData,
            format!("invalid grpc-status header: {error}"),
        )
    })?;
    if status == "0" {
        return Ok(());
    }
    let message = headers
        .get("grpc-message")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("remote gRPC tunnel failed");
    Err(Error::new(
        ErrorKind::ConnectionAborted,
        format!("grpc-status {status}: {message}"),
    ))
}

impl AsyncWrite for GrpcTunnelStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        if self.closed {
            return Poll::Ready(Err(Error::new(
                ErrorKind::BrokenPipe,
                "grpc send stream is closed",
            )));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let len = buf.len().min(16 * 1024);
        let frame_len = 5 + len;
        self.send.reserve_capacity(frame_len);
        match self.send.poll_capacity(cx) {
            Poll::Ready(Some(Ok(capacity))) if capacity >= frame_len => {}
            Poll::Ready(Some(Ok(_))) | Poll::Pending => return Poll::Pending,
            Poll::Ready(Some(Err(error))) => {
                return Poll::Ready(Err(Error::new(
                    ErrorKind::BrokenPipe,
                    format!("grpc send capacity failed: {error}"),
                )));
            }
            Poll::Ready(None) => {
                return Poll::Ready(Err(Error::new(
                    ErrorKind::BrokenPipe,
                    "grpc send stream has no capacity",
                )));
            }
        }
        let mut frame = Vec::with_capacity(5 + len);
        frame.push(0);
        frame.extend_from_slice(&(len as u32).to_be_bytes());
        frame.extend_from_slice(&buf[..len]);
        match self.send.send_data(Bytes::from(frame), false) {
            Ok(()) => Poll::Ready(Ok(len)),
            Err(error) => Poll::Ready(Err(Error::new(
                ErrorKind::BrokenPipe,
                format!("grpc send failed: {error}"),
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
                    format!("grpc shutdown failed: {error}"),
                )));
            }
        }
        Poll::Ready(Ok(()))
    }
}
