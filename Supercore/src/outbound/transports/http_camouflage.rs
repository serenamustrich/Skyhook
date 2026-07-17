use std::{
    collections::BTreeMap,
    io::Error,
    pin::Pin,
    task::{Context, Poll},
};

use anyhow::anyhow;
use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use super::{
    headers::{normalize_http_path, render_transport_headers},
    run_dial_phase,
};

pub(crate) async fn open_http_camouflage_transport<S>(
    mut stream: S,
    host: &str,
    path: &str,
    headers: &BTreeMap<String, String>,
    initial_payload: &[u8],
    timeout_ms: u64,
) -> anyhow::Result<HttpCamouflageStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let path = normalize_http_path(path);
    let custom_headers = render_transport_headers(
        headers,
        &["host", "content-length", "connection", "transfer-encoding"],
    )?;
    let request = format!(
        "GET {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         {custom_headers}\
         Content-Length: {}\r\n\
         Connection: keep-alive\r\n\
         \r\n",
        initial_payload.len()
    );
    run_dial_phase(timeout_ms, "http camouflage request write", async {
        stream.write_all(request.as_bytes()).await?;
        stream.write_all(initial_payload).await?;
        stream.flush().await
    })
    .await??;

    let (response, header_end) = run_dial_phase(
        timeout_ms,
        "http camouflage response headers",
        read_response_headers(&mut stream),
    )
    .await??;
    let header_text = std::str::from_utf8(&response[..header_end])?;
    let status_line = header_text.lines().next().unwrap_or("");
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|value| value.parse::<u16>().ok());
    if !status.is_some_and(|status| (200..300).contains(&status)) {
        return Err(anyhow!("http camouflage failed: {status_line}"));
    }

    Ok(HttpCamouflageStream {
        stream,
        prefetched: BytesMut::from(&response[header_end..]),
    })
}

async fn read_response_headers<S>(stream: &mut S) -> anyhow::Result<(Vec<u8>, usize)>
where
    S: AsyncRead + Unpin,
{
    let mut response = Vec::with_capacity(1024);
    let mut buffer = [0u8; 512];
    loop {
        if response.len() >= 64 * 1024 {
            return Err(anyhow!("http camouflage response headers are too large"));
        }
        let count = stream.read(&mut buffer).await?;
        if count == 0 {
            return Err(anyhow!(
                "http camouflage server closed before response headers"
            ));
        }
        response.extend_from_slice(&buffer[..count]);
        if let Some(header_end) = find_header_end(&response) {
            return Ok((response, header_end));
        }
    }
}

pub(crate) struct HttpCamouflageStream<S> {
    stream: S,
    prefetched: BytesMut,
}

impl<S> AsyncRead for HttpCamouflageStream<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), Error>> {
        if !self.prefetched.is_empty() && buffer.remaining() > 0 {
            let length = self.prefetched.len().min(buffer.remaining());
            let chunk = self.prefetched.split_to(length);
            buffer.put_slice(&chunk);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.stream).poll_read(context, buffer)
    }
}

impl<S> AsyncWrite for HttpCamouflageStream<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, Error>> {
        Pin::new(&mut self.stream).poll_write(context, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Pin::new(&mut self.stream).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), Error>> {
        Pin::new(&mut self.stream).poll_shutdown(context)
    }
}

fn find_header_end(data: &[u8]) -> Option<usize> {
    data.windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::open_http_camouflage_transport;

    #[tokio::test]
    async fn sends_initial_body_and_preserves_prefetched_response() {
        let (client, mut server) = tokio::io::duplex(4096);
        let server_task = tokio::spawn(async move {
            let mut request = Vec::new();
            let mut byte = [0u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                server.read_exact(&mut byte).await.unwrap();
                request.push(byte[0]);
            }
            let text = String::from_utf8(request).unwrap();
            assert!(text.starts_with("GET /vmess HTTP/1.1\r\n"));
            assert!(text.contains("Host: edge.example\r\n"));
            assert!(text
                .lines()
                .any(|line| line.eq_ignore_ascii_case("X-Test: enabled")));
            assert!(text.contains("Content-Length: 5\r\n"));
            let mut payload = [0u8; 5];
            server.read_exact(&mut payload).await.unwrap();
            assert_eq!(&payload, b"hello");
            server
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\nready")
                .await
                .unwrap();
        });

        let mut stream = open_http_camouflage_transport(
            client,
            "edge.example",
            "/vmess",
            &BTreeMap::from([("X-Test".to_string(), "enabled".to_string())]),
            b"hello",
            1_000,
        )
        .await
        .unwrap();
        let mut ready = [0u8; 5];
        stream.read_exact(&mut ready).await.unwrap();
        assert_eq!(&ready, b"ready");
        server_task.await.unwrap();
    }
}
