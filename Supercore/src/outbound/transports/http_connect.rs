use std::{
    io::Error,
    pin::Pin,
    task::{Context, Poll},
};

use anyhow::anyhow;
use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::routing::Destination;

use super::super::target::destination_socket_addr;

pub(crate) async fn establish_http_connect<S>(
    mut stream: S,
    destination: &Destination,
    username: Option<&str>,
    password: Option<&str>,
    keep_alive: bool,
) -> anyhow::Result<HttpConnectStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let authority = destination_socket_addr(destination);
    let mut request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
    if keep_alive {
        request.push_str("Proxy-Connection: Keep-Alive\r\n");
    }
    if let (Some(username), Some(password)) = (username, password) {
        let token = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            format!("{username}:{password}"),
        );
        request.push_str(&format!("Proxy-Authorization: Basic {token}\r\n"));
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;

    let mut response = Vec::with_capacity(1024);
    let mut buffer = [0u8; 512];
    loop {
        if response.len() >= 64 * 1024 {
            return Err(anyhow!("http CONNECT response headers are too large"));
        }
        let count = stream.read(&mut buffer).await?;
        if count == 0 {
            return Err(anyhow!("http CONNECT ended before response headers"));
        }
        response.extend_from_slice(&buffer[..count]);
        if let Some(header_end) = find_header_end(&response) {
            let text = std::str::from_utf8(&response[..header_end])?;
            let status_line = text.lines().next().unwrap_or("");
            let status = status_line
                .split_whitespace()
                .nth(1)
                .and_then(|value| value.parse::<u16>().ok());
            if !status.is_some_and(|status| (200..300).contains(&status)) {
                return Err(anyhow!("http proxy connect failed: {status_line}"));
            }
            return Ok(HttpConnectStream {
                stream,
                prefetched: BytesMut::from(&response[header_end..]),
            });
        }
    }
}

fn find_header_end(data: &[u8]) -> Option<usize> {
    data.windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
}

pub(crate) struct HttpConnectStream<S> {
    stream: S,
    prefetched: BytesMut,
}

impl<S> AsyncRead for HttpConnectStream<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), Error>> {
        if !self.prefetched.is_empty() && buffer.remaining() > 0 {
            let length = self.prefetched.len().min(buffer.remaining());
            let chunk = self.prefetched.split_to(length);
            buffer.put_slice(&chunk);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.stream).poll_read(cx, buffer)
    }
}

impl<S> AsyncWrite for HttpConnectStream<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, Error>> {
        Pin::new(&mut self.stream).poll_write(cx, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use crate::routing::Destination;

    use super::establish_http_connect;

    #[tokio::test]
    async fn sends_authenticated_connect_and_accepts_200() {
        let (client, mut server) = tokio::io::duplex(4096);
        let server_task = tokio::spawn(async move {
            let mut request = Vec::new();
            let mut byte = [0_u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                server.read_exact(&mut byte).await.unwrap();
                request.push(byte[0]);
            }
            let request = String::from_utf8(request).unwrap();
            assert!(request.starts_with("CONNECT example.com:443 HTTP/1.1\r\n"));
            assert!(request.contains("Proxy-Connection: Keep-Alive\r\n"));
            assert!(request.contains("Proxy-Authorization: Basic dXNlcjpwYXNz\r\n"));
            server
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await
                .unwrap();
        });

        let _stream = establish_http_connect(
            client,
            &Destination::new("example.com", 443),
            Some("user"),
            Some("pass"),
            true,
        )
        .await
        .unwrap();
        server_task.await.unwrap();
    }
}
