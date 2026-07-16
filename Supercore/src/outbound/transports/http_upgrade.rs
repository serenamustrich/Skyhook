use std::{
    collections::BTreeMap,
    io::Error,
    pin::Pin,
    task::{Context, Poll},
};

use anyhow::anyhow;
use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use super::headers::{normalize_http_path, render_transport_headers};

pub(crate) async fn open_http_upgrade_tunnel<S>(
    mut stream: S,
    host: &str,
    path: &str,
    headers: &BTreeMap<String, String>,
) -> anyhow::Result<HttpUpgradeStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let path = normalize_http_path(path);
    let custom_headers =
        render_transport_headers(headers, &["host", "connection", "upgrade", "user-agent"])?;
    let request = format!(
        "GET {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         {custom_headers}\
         Connection: Upgrade\r\n\
         Upgrade: websocket\r\n\
         User-Agent: Supercore/0.1\r\n\
         \r\n"
    );
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;

    let mut response = Vec::with_capacity(1024);
    let mut buffer = [0u8; 512];
    let header_end = loop {
        if response.len() >= 64 * 1024 {
            return Err(anyhow!("http upgrade response headers are too large"));
        }
        let count = stream.read(&mut buffer).await?;
        if count == 0 {
            return Err(anyhow!("http upgrade ended before response headers"));
        }
        response.extend_from_slice(&buffer[..count]);
        if let Some(header_end) = find_header_end(&response) {
            break header_end;
        }
    };
    let header_text = std::str::from_utf8(&response[..header_end])?;
    let status_line = header_text.lines().next().unwrap_or("");
    if !status_line.contains(" 101 ") {
        return Err(anyhow!("http upgrade failed: {status_line}"));
    }
    let mut connection_upgrade = false;
    let mut upgrade_websocket = false;
    for line in header_text.lines().skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("connection") {
            connection_upgrade = value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("upgrade"));
        } else if name.eq_ignore_ascii_case("upgrade") {
            upgrade_websocket = value.trim().eq_ignore_ascii_case("websocket");
        }
    }
    if !connection_upgrade || !upgrade_websocket {
        return Err(anyhow!(
            "http upgrade response is missing Connection: Upgrade or Upgrade: websocket"
        ));
    }

    Ok(HttpUpgradeStream {
        stream,
        prefetched: BytesMut::from(&response[header_end..]),
    })
}

pub(crate) struct HttpUpgradeStream<S> {
    stream: S,
    prefetched: BytesMut,
}

impl<S> AsyncRead for HttpUpgradeStream<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), Error>> {
        if !self.prefetched.is_empty() && buf.remaining() > 0 {
            let length = self.prefetched.len().min(buf.remaining());
            let chunk = self.prefetched.split_to(length);
            buf.put_slice(&chunk);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl<S> AsyncWrite for HttpUpgradeStream<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

fn find_header_end(data: &[u8]) -> Option<usize> {
    data.windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
}
