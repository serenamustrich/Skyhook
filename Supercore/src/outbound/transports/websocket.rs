use std::collections::BTreeMap;

use anyhow::anyhow;
use sha1::{Digest, Sha1};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};

use super::headers::render_transport_headers;

pub(crate) async fn perform_websocket_handshake<S>(
    stream: &mut S,
    host: &str,
    path: &str,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let headers = BTreeMap::new();
    perform_websocket_handshake_with_headers(stream, host, path, &headers).await
}

pub(crate) async fn perform_websocket_handshake_with_headers<S>(
    stream: &mut S,
    host: &str,
    path: &str,
    headers: &BTreeMap<String, String>,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut key_bytes = [0u8; 16];
    getrandom::fill(&mut key_bytes)
        .map_err(|error| anyhow!("failed to generate websocket key: {error}"))?;
    let key = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, key_bytes);
    let path = if path.is_empty() { "/" } else { path };
    let custom_headers = render_transport_headers(
        headers,
        &[
            "host",
            "upgrade",
            "connection",
            "sec-websocket-key",
            "sec-websocket-version",
        ],
    )?;
    let request = format!(
        "GET {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         {custom_headers}\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: {key}\r\n\
         Sec-WebSocket-Version: 13\r\n\
         \r\n"
    );
    stream.write_all(request.as_bytes()).await?;

    let mut response = Vec::with_capacity(1024);
    let mut buf = [0u8; 512];
    while response.len() < 64 * 1024 {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            return Err(anyhow!("websocket handshake ended before headers"));
        }
        response.extend_from_slice(&buf[..n]);
        if find_header_end(&response).is_some() {
            break;
        }
    }
    let text = std::str::from_utf8(&response)?;
    let status_line = text.lines().next().unwrap_or("");
    if !status_line.contains(" 101 ") {
        return Err(anyhow!("websocket upgrade failed: {status_line}"));
    }
    let expected_accept = websocket_accept_key(&key);
    let accept_ok = text.lines().any(|line| {
        line.split_once(':')
            .map(|(name, value)| {
                name.eq_ignore_ascii_case("sec-websocket-accept") && value.trim() == expected_accept
            })
            .unwrap_or(false)
    });
    if !accept_ok {
        return Err(anyhow!("websocket upgrade missing valid accept key"));
    }
    Ok(())
}

pub(crate) fn spawn_websocket_stream<S>(stream: S) -> DuplexStream
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (app_side, relay_side) = tokio::io::duplex(64 * 1024);
    let (mut local_read, mut local_write) = tokio::io::split(relay_side);
    let (mut remote_read, mut remote_write) = tokio::io::split(stream);

    tokio::spawn(async move {
        let mut buf = [0u8; 16 * 1024];
        loop {
            match local_read.read(&mut buf).await {
                Ok(0) => {
                    let _ = write_websocket_close_frame(&mut remote_write).await;
                    let _ = remote_write.shutdown().await;
                    break;
                }
                Ok(n) => {
                    if write_websocket_binary_frame(&mut remote_write, &buf[..n])
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    tokio::spawn(async move {
        loop {
            match read_websocket_frame(&mut remote_read).await {
                Ok(Some(frame)) => {
                    if local_write.write_all(&frame).await.is_err() {
                        break;
                    }
                }
                Ok(None) | Err(_) => {
                    let _ = local_write.shutdown().await;
                    break;
                }
            }
        }
    });

    app_side
}

pub(crate) fn websocket_accept_key(key: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(key.as_bytes());
    hasher.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        hasher.finalize(),
    )
}

pub(crate) async fn write_websocket_binary_frame<W>(
    writer: &mut W,
    payload: &[u8],
) -> anyhow::Result<()>
where
    W: AsyncWrite + Unpin,
{
    write_websocket_frame(writer, 0x2, payload).await
}

async fn write_websocket_close_frame<W>(writer: &mut W) -> anyhow::Result<()>
where
    W: AsyncWrite + Unpin,
{
    write_websocket_frame(writer, 0x8, &[]).await
}

pub(crate) async fn write_websocket_frame<W>(
    writer: &mut W,
    opcode: u8,
    payload: &[u8],
) -> anyhow::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut mask = [0u8; 4];
    getrandom::fill(&mut mask)
        .map_err(|error| anyhow!("failed to generate websocket mask: {error}"))?;
    let mut frame = Vec::with_capacity(payload.len() + 14);
    frame.push(0x80 | (opcode & 0x0f));
    match payload.len() {
        0..=125 => frame.push(0x80 | payload.len() as u8),
        126..=65_535 => {
            frame.push(0x80 | 126);
            frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        }
        _ => {
            frame.push(0x80 | 127);
            frame.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        }
    }
    frame.extend_from_slice(&mask);
    for (index, byte) in payload.iter().enumerate() {
        frame.push(byte ^ mask[index % 4]);
    }
    writer.write_all(&frame).await?;
    Ok(())
}

pub(crate) async fn read_websocket_frame<R>(reader: &mut R) -> anyhow::Result<Option<Vec<u8>>>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; 2];
    if !read_exact_or_eof(reader, &mut header).await? {
        return Ok(None);
    }
    let opcode = header[0] & 0x0f;
    let masked = header[1] & 0x80 != 0;
    let mut len = (header[1] & 0x7f) as u64;
    if len == 126 {
        let mut ext = [0u8; 2];
        reader.read_exact(&mut ext).await?;
        len = u16::from_be_bytes(ext) as u64;
    } else if len == 127 {
        let mut ext = [0u8; 8];
        reader.read_exact(&mut ext).await?;
        len = u64::from_be_bytes(ext);
    }
    if len > 16 * 1024 * 1024 {
        return Err(anyhow!("websocket frame is too large"));
    }
    let mut mask = [0u8; 4];
    if masked {
        reader.read_exact(&mut mask).await?;
    }
    let mut payload = vec![0u8; len as usize];
    reader.read_exact(&mut payload).await?;
    if masked {
        for (index, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask[index % 4];
        }
    }
    match opcode {
        0x0..=0x2 => Ok(Some(payload)),
        0x8 => Ok(None),
        0x9 | 0xA => Ok(Some(Vec::new())),
        other => Err(anyhow!("unsupported websocket opcode {other}")),
    }
}

fn find_header_end(data: &[u8]) -> Option<usize> {
    data.windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
}

async fn read_exact_or_eof<R>(reader: &mut R, buf: &mut [u8]) -> anyhow::Result<bool>
where
    R: AsyncRead + Unpin,
{
    let mut offset = 0;
    while offset < buf.len() {
        let read = reader.read(&mut buf[offset..]).await?;
        if read == 0 {
            if offset == 0 {
                return Ok(false);
            }
            return Err(
                std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "partial read").into(),
            );
        }
        offset += read;
    }
    Ok(true)
}
