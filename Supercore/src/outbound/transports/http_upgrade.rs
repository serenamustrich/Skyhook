use std::{
    collections::BTreeMap,
    future::Future,
    io::Error,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use anyhow::anyhow;
use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::time::timeout;

use crate::outbound::context::{active_dial_context, DialContext};

use super::headers::{normalize_http_path, render_transport_headers};

pub(crate) async fn open_http_upgrade_tunnel<S>(
    mut stream: S,
    host: &str,
    path: &str,
    headers: &BTreeMap<String, String>,
    timeout_ms: u64,
) -> anyhow::Result<HttpUpgradeStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let context = active_dial_context();
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
    run_http_upgrade_phase(
        context.as_ref(),
        timeout_ms,
        "http upgrade request write",
        async {
            stream.write_all(request.as_bytes()).await?;
            stream.flush().await?;
            Ok(())
        },
    )
    .await?;

    let (response, header_end) = run_http_upgrade_phase(
        context.as_ref(),
        timeout_ms,
        "http upgrade response headers",
        async {
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
            Ok((response, header_end))
        },
    )
    .await?;
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

async fn run_http_upgrade_phase<F, T>(
    context: Option<&DialContext>,
    timeout_ms: u64,
    phase: &'static str,
    future: F,
) -> anyhow::Result<T>
where
    F: Future<Output = anyhow::Result<T>>,
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
                result.map_err(|_| anyhow!("{phase} timed out"))?
            }
        }
    } else {
        timeout(remaining, future)
            .await
            .map_err(|_| anyhow!("{phase} timed out"))?
    }
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

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, time::Duration};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use crate::{
        outbound::context::{scope_dial_context, DialContext},
        routing::Destination,
    };

    use super::open_http_upgrade_tunnel;

    #[tokio::test]
    async fn preserves_bytes_prefetched_with_upgrade_response() {
        let (client, mut server) = tokio::io::duplex(16 * 1024);
        let server_task = tokio::spawn(async move {
            let request = read_headers(&mut server).await;
            assert!(request.starts_with(b"GET /upgrade HTTP/1.1\r\n"));
            server
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\n\
                      Connection: keep-alive, Upgrade\r\n\
                      Upgrade: websocket\r\n\r\nready",
                )
                .await
                .expect("upgrade response");
        });

        let mut stream =
            open_http_upgrade_tunnel(client, "example.com", "/upgrade", &BTreeMap::new(), 1_000)
                .await
                .expect("upgrade tunnel");
        let mut ready = [0u8; 5];
        stream
            .read_exact(&mut ready)
            .await
            .expect("prefetched data");
        assert_eq!(&ready, b"ready");
        server_task.await.expect("server task");
    }

    #[tokio::test]
    async fn stalled_response_reports_response_phase_timeout() {
        let (client, mut server) = tokio::io::duplex(16 * 1024);
        let server_task = tokio::spawn(async move {
            let _ = read_headers(&mut server).await;
            tokio::time::sleep(Duration::from_millis(100)).await;
        });
        let context = DialContext::new(Destination::new("example.com", 443), 30);
        let error = scope_dial_context(&context, async {
            open_http_upgrade_tunnel(client, "example.com", "/upgrade", &BTreeMap::new(), 30).await
        })
        .await
        .err()
        .expect("stalled response must time out");
        assert!(
            format!("{error:#}").contains("http upgrade response headers timed out"),
            "unexpected error: {error:#}"
        );
        server_task.await.expect("server task");
    }

    #[tokio::test]
    async fn cancellation_interrupts_response_phase() {
        let (client, mut server) = tokio::io::duplex(16 * 1024);
        let server_task = tokio::spawn(async move {
            let _ = read_headers(&mut server).await;
            tokio::time::sleep(Duration::from_millis(100)).await;
        });
        let context = DialContext::new(Destination::new("example.com", 443), 1_000);
        let cancellation = context.cancellation.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            cancellation.cancel();
        });
        let error = scope_dial_context(&context, async {
            open_http_upgrade_tunnel(client, "example.com", "/upgrade", &BTreeMap::new(), 1_000)
                .await
        })
        .await
        .err()
        .expect("cancelled response must fail");
        assert!(
            format!("{error:#}").contains("http upgrade response headers cancelled"),
            "unexpected error: {error:#}"
        );
        server_task.await.expect("server task");
    }

    async fn read_headers<S>(stream: &mut S) -> Vec<u8>
    where
        S: tokio::io::AsyncRead + Unpin,
    {
        let mut request = Vec::new();
        let mut byte = [0u8; 1];
        while !request.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).await.expect("request byte");
            request.push(byte[0]);
            assert!(request.len() < 64 * 1024);
        }
        request
    }
}
