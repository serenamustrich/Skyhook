use std::{
    collections::BTreeMap,
    future::Future,
    io::{Cursor, Error, ErrorKind},
    pin::Pin,
    task::{Context as TaskContext, Poll, Waker},
    time::Duration,
};

use anyhow::anyhow;
use sha1::{Digest, Sha1};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf},
    time::timeout,
};

use crate::outbound::{
    context::{active_dial_context, DialContext},
    BoxedStream,
};

use super::headers::render_transport_headers;

const MAX_INITIAL_WRITE: usize = 64 * 1024;

pub(crate) async fn open_websocket_transport_without_headers<S>(
    stream: S,
    host: &str,
    path: &str,
    timeout_ms: u64,
) -> anyhow::Result<BoxedStream>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    open_websocket_transport(stream, host, path, &BTreeMap::new(), timeout_ms).await
}

pub(crate) async fn open_websocket_transport<S>(
    stream: S,
    host: &str,
    path: &str,
    headers: &BTreeMap<String, String>,
    timeout_ms: u64,
) -> anyhow::Result<BoxedStream>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let context = active_dial_context();
    let mut max_early_data = context
        .as_ref()
        .map(|context| context.websocket_max_early_data)
        .unwrap_or(0);
    let mut early_data_header = context
        .as_ref()
        .and_then(|context| context.websocket_early_data_header.clone());
    let mut path = path.to_string();
    if max_early_data == 0 {
        let (normalized, query_early_data) = extract_early_data_query(&path);
        if let Some(query_early_data) = query_early_data {
            path = normalized;
            max_early_data = query_early_data;
            early_data_header.get_or_insert_with(|| "Sec-WebSocket-Protocol".to_string());
        }
    }

    if max_early_data == 0 {
        let mut stream = stream;
        let prefetched = run_websocket_phase(
            context.as_ref(),
            timeout_ms,
            "websocket handshake",
            perform_websocket_handshake_request(&mut stream, host, &path, headers, None, None),
        )
        .await?;
        return Ok(Box::new(spawn_websocket_stream_with_prefetched(
            stream, prefetched,
        )));
    }

    Ok(Box::new(LazyWebSocketStream::new(LazyWebSocketInit {
        stream,
        host: host.to_string(),
        path,
        headers: headers.clone(),
        early_data_header,
        max_early_data,
        timeout_ms,
        context,
    })))
}

async fn perform_websocket_handshake_request<S>(
    stream: &mut S,
    host: &str,
    path: &str,
    headers: &BTreeMap<String, String>,
    early_data_header: Option<&str>,
    early_data: Option<&[u8]>,
) -> anyhow::Result<Vec<u8>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut key_bytes = [0u8; 16];
    getrandom::fill(&mut key_bytes)
        .map_err(|error| anyhow!("failed to generate websocket key: {error}"))?;
    let key = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, key_bytes);
    let mut request_headers = headers.clone();
    let mut path = if path.is_empty() {
        "/".to_string()
    } else {
        path.to_string()
    };
    if let Some(early_data) = early_data.filter(|data| !data.is_empty()) {
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            early_data,
        );
        if let Some(header) = early_data_header {
            request_headers.insert(header.to_string(), encoded);
        } else {
            path = append_early_data_to_path(&path, &encoded);
        }
    }
    let custom_headers = render_transport_headers(
        &request_headers,
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
    stream.flush().await?;

    let mut response = Vec::with_capacity(1024);
    let mut buf = [0u8; 512];
    let header_end = loop {
        if response.len() >= 64 * 1024 {
            return Err(anyhow!("websocket response headers are too large"));
        }
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            return Err(anyhow!("websocket handshake ended before headers"));
        }
        response.extend_from_slice(&buf[..n]);
        if let Some(header_end) = find_header_end(&response) {
            break header_end;
        }
    };
    let text = std::str::from_utf8(&response[..header_end])?;
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
    Ok(response[header_end..].to_vec())
}

fn spawn_websocket_stream_with_prefetched<S>(stream: S, prefetched: Vec<u8>) -> DuplexStream
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (app_side, relay_side) = tokio::io::duplex(64 * 1024);
    let (mut local_read, mut local_write) = tokio::io::split(relay_side);
    let (remote_read, mut remote_write) = tokio::io::split(stream);
    let mut remote_read = Cursor::new(prefetched).chain(remote_read);

    tokio::spawn(async move {
        let mut buf = [0u8; 16 * 1024];
        let mut fragments = None;
        loop {
            tokio::select! {
                local = local_read.read(&mut buf) => {
                    match local {
                        Ok(0) => {
                            let _ = write_websocket_close_frame(&mut remote_write, &[]).await;
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
                remote = read_websocket_message(&mut remote_read) => {
                    match remote {
                        Ok(Some(WebSocketMessage::Data { opcode, fin, payload })) => {
                            match reassemble_data(&mut fragments, opcode, fin, payload) {
                                Ok(Some(frame)) => {
                                    if local_write.write_all(&frame).await.is_err() {
                                        break;
                                    }
                                }
                                Ok(None) => {}
                                Err(_) => break,
                            }
                        }
                        Ok(Some(WebSocketMessage::Ping(payload))) => {
                            if write_websocket_frame(&mut remote_write, 0xA, &payload)
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                        Ok(Some(WebSocketMessage::Pong)) => {}
                        Ok(Some(WebSocketMessage::Close(payload))) => {
                            let _ = write_websocket_close_frame(&mut remote_write, &payload).await;
                            let _ = local_write.shutdown().await;
                            break;
                        }
                        Ok(None) | Err(_) => {
                            let _ = local_write.shutdown().await;
                            break;
                        }
                    }
                }
            }
        }
    });

    app_side
}

struct LazyWebSocketInit<S> {
    stream: S,
    host: String,
    path: String,
    headers: BTreeMap<String, String>,
    early_data_header: Option<String>,
    max_early_data: usize,
    timeout_ms: u64,
    context: Option<DialContext>,
}

type WebSocketHandshakeFuture =
    Pin<Box<dyn Future<Output = Result<DuplexStream, Error>> + Send + 'static>>;

enum LazyWebSocketState<S> {
    Initial(Option<LazyWebSocketInit<S>>),
    Handshaking {
        future: WebSocketHandshakeFuture,
        accepted: usize,
    },
    ReadyPendingWrite {
        stream: DuplexStream,
        accepted: usize,
    },
    Ready(DuplexStream),
    Failed(String),
    Closed,
}

struct LazyWebSocketStream<S> {
    state: LazyWebSocketState<S>,
    read_waiter: Option<Waker>,
}

impl<S> LazyWebSocketStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    fn new(init: LazyWebSocketInit<S>) -> Self {
        Self {
            state: LazyWebSocketState::Initial(Some(init)),
            read_waiter: None,
        }
    }

    fn start_handshake(&mut self, buf: &[u8]) {
        let init = match &mut self.state {
            LazyWebSocketState::Initial(init) => init.take().expect("websocket init missing"),
            _ => return,
        };
        let accepted = buf.len().min(MAX_INITIAL_WRITE);
        let first_write = buf[..accepted].to_vec();
        let future = Box::pin(async move {
            initialize_lazy_websocket(init, first_write)
                .await
                .map_err(websocket_io_error)
        });
        self.state = LazyWebSocketState::Handshaking { future, accepted };
    }

    fn wake_reader(&mut self) {
        if let Some(waiter) = self.read_waiter.take() {
            waiter.wake();
        }
    }
}

impl<S> AsyncRead for LazyWebSocketStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), Error>> {
        let this = self.get_mut();
        loop {
            match &mut this.state {
                LazyWebSocketState::Initial(_) => {
                    if this
                        .read_waiter
                        .as_ref()
                        .is_none_or(|waiter| !waiter.will_wake(cx.waker()))
                    {
                        this.read_waiter = Some(cx.waker().clone());
                    }
                    return Poll::Pending;
                }
                LazyWebSocketState::Handshaking { future, accepted } => {
                    let accepted = *accepted;
                    match future.as_mut().poll(cx) {
                        Poll::Ready(Ok(stream)) => {
                            this.state = LazyWebSocketState::ReadyPendingWrite { stream, accepted };
                            this.wake_reader();
                        }
                        Poll::Ready(Err(error)) => {
                            let message = error.to_string();
                            this.state = LazyWebSocketState::Failed(message);
                            this.wake_reader();
                        }
                        Poll::Pending => return Poll::Pending,
                    }
                }
                LazyWebSocketState::ReadyPendingWrite { stream, .. }
                | LazyWebSocketState::Ready(stream) => {
                    return Pin::new(stream).poll_read(cx, buf);
                }
                LazyWebSocketState::Failed(message) => {
                    return Poll::Ready(Err(Error::new(
                        ErrorKind::ConnectionAborted,
                        message.clone(),
                    )));
                }
                LazyWebSocketState::Closed => return Poll::Ready(Ok(())),
            }
        }
    }
}

impl<S> AsyncWrite for LazyWebSocketStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        let this = self.get_mut();
        loop {
            match &mut this.state {
                LazyWebSocketState::Initial(_) => {
                    if buf.is_empty() {
                        return Poll::Ready(Ok(0));
                    }
                    this.start_handshake(buf);
                }
                LazyWebSocketState::Handshaking { future, accepted } => {
                    let accepted = *accepted;
                    match future.as_mut().poll(cx) {
                        Poll::Ready(Ok(stream)) => {
                            this.state = LazyWebSocketState::Ready(stream);
                            this.wake_reader();
                            return Poll::Ready(Ok(accepted));
                        }
                        Poll::Ready(Err(error)) => {
                            let kind = error.kind();
                            let message = error.to_string();
                            this.state = LazyWebSocketState::Failed(message.clone());
                            this.wake_reader();
                            return Poll::Ready(Err(Error::new(kind, message)));
                        }
                        Poll::Pending => return Poll::Pending,
                    }
                }
                LazyWebSocketState::ReadyPendingWrite { accepted, .. } => {
                    let accepted = *accepted;
                    let state = std::mem::replace(&mut this.state, LazyWebSocketState::Closed);
                    let LazyWebSocketState::ReadyPendingWrite { stream, .. } = state else {
                        unreachable!();
                    };
                    this.state = LazyWebSocketState::Ready(stream);
                    return Poll::Ready(Ok(accepted));
                }
                LazyWebSocketState::Ready(stream) => {
                    return Pin::new(stream).poll_write(cx, buf);
                }
                LazyWebSocketState::Failed(message) => {
                    return Poll::Ready(Err(Error::new(
                        ErrorKind::ConnectionAborted,
                        message.clone(),
                    )));
                }
                LazyWebSocketState::Closed => {
                    return Poll::Ready(Err(Error::new(
                        ErrorKind::BrokenPipe,
                        "websocket stream is closed",
                    )));
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Result<(), Error>> {
        let this = self.get_mut();
        match &mut this.state {
            LazyWebSocketState::ReadyPendingWrite { stream, .. }
            | LazyWebSocketState::Ready(stream) => Pin::new(stream).poll_flush(cx),
            LazyWebSocketState::Failed(message) => Poll::Ready(Err(Error::new(
                ErrorKind::ConnectionAborted,
                message.clone(),
            ))),
            LazyWebSocketState::Closed => Poll::Ready(Err(Error::new(
                ErrorKind::BrokenPipe,
                "websocket stream is closed",
            ))),
            LazyWebSocketState::Initial(_) | LazyWebSocketState::Handshaking { .. } => {
                Poll::Ready(Ok(()))
            }
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Result<(), Error>> {
        let this = self.get_mut();
        match &mut this.state {
            LazyWebSocketState::ReadyPendingWrite { stream, .. }
            | LazyWebSocketState::Ready(stream) => Pin::new(stream).poll_shutdown(cx),
            LazyWebSocketState::Failed(_) | LazyWebSocketState::Closed => Poll::Ready(Ok(())),
            LazyWebSocketState::Initial(_) | LazyWebSocketState::Handshaking { .. } => {
                this.state = LazyWebSocketState::Closed;
                this.wake_reader();
                Poll::Ready(Ok(()))
            }
        }
    }
}

async fn initialize_lazy_websocket<S>(
    mut init: LazyWebSocketInit<S>,
    first_write: Vec<u8>,
) -> anyhow::Result<DuplexStream>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let early_length = first_write.len().min(init.max_early_data);
    let prefetched = run_websocket_phase(
        init.context.as_ref(),
        init.timeout_ms,
        "websocket early-data handshake",
        perform_websocket_handshake_request(
            &mut init.stream,
            &init.host,
            &init.path,
            &init.headers,
            init.early_data_header.as_deref(),
            Some(&first_write[..early_length]),
        ),
    )
    .await?;
    let mut stream = spawn_websocket_stream_with_prefetched(init.stream, prefetched);
    if early_length < first_write.len() {
        run_websocket_phase(
            init.context.as_ref(),
            init.timeout_ms,
            "websocket initial frame",
            async {
                stream.write_all(&first_write[early_length..]).await?;
                stream.flush().await?;
                Ok(())
            },
        )
        .await?;
    }
    Ok(stream)
}

async fn run_websocket_phase<F, T>(
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

fn websocket_io_error(error: anyhow::Error) -> Error {
    let message = format!("{error:#}");
    let kind = if message.contains("timed out") {
        ErrorKind::TimedOut
    } else if message.contains("cancelled") {
        ErrorKind::Interrupted
    } else {
        ErrorKind::ConnectionAborted
    };
    Error::new(kind, message)
}

fn append_early_data_to_path(path: &str, encoded: &str) -> String {
    match path.split_once('?') {
        Some((base, query)) => format!("{base}{encoded}?{query}"),
        None => format!("{path}{encoded}"),
    }
}

fn extract_early_data_query(path: &str) -> (String, Option<usize>) {
    let Some((base, query)) = path.split_once('?') else {
        return (path.to_string(), None);
    };
    let mut early_data = None;
    let mut retained = Vec::new();
    for pair in query.split('&').filter(|pair| !pair.is_empty()) {
        let Some((key, value)) = pair.split_once('=') else {
            retained.push(pair);
            continue;
        };
        if key == "ed" {
            early_data = value.parse::<usize>().ok().filter(|value| *value > 0);
            if early_data.is_some() {
                continue;
            }
        }
        retained.push(pair);
    }
    let normalized = if retained.is_empty() {
        base.to_string()
    } else {
        format!("{base}?{}", retained.join("&"))
    };
    (normalized, early_data)
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

async fn write_websocket_close_frame<W>(writer: &mut W, payload: &[u8]) -> anyhow::Result<()>
where
    W: AsyncWrite + Unpin,
{
    write_websocket_frame(writer, 0x8, payload).await
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

#[cfg(test)]
pub(crate) async fn read_websocket_frame<R>(reader: &mut R) -> anyhow::Result<Option<Vec<u8>>>
where
    R: AsyncRead + Unpin,
{
    let mut fragments = None;
    loop {
        match read_websocket_message(reader).await? {
            Some(WebSocketMessage::Data {
                opcode,
                fin,
                payload,
            }) => {
                if let Some(payload) = reassemble_data(&mut fragments, opcode, fin, payload)? {
                    return Ok(Some(payload));
                }
            }
            Some(WebSocketMessage::Close(_)) | None => return Ok(None),
            Some(WebSocketMessage::Ping(_)) | Some(WebSocketMessage::Pong) => {}
        }
    }
}

enum WebSocketMessage {
    Data {
        opcode: u8,
        fin: bool,
        payload: Vec<u8>,
    },
    Ping(Vec<u8>),
    Pong,
    Close(Vec<u8>),
}

async fn read_websocket_message<R>(reader: &mut R) -> anyhow::Result<Option<WebSocketMessage>>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; 2];
    if !read_exact_or_eof(reader, &mut header).await? {
        return Ok(None);
    }
    let fin = header[0] & 0x80 != 0;
    if header[0] & 0x70 != 0 {
        return Err(anyhow!(
            "websocket RSV bits require an unsupported extension"
        ));
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
    if opcode >= 0x8 && (!fin || payload.len() > 125) {
        return Err(anyhow!("invalid fragmented websocket control frame"));
    }
    match opcode {
        0x0..=0x2 => Ok(Some(WebSocketMessage::Data {
            opcode,
            fin,
            payload,
        })),
        0x8 => Ok(Some(WebSocketMessage::Close(payload))),
        0x9 => Ok(Some(WebSocketMessage::Ping(payload))),
        0xA => Ok(Some(WebSocketMessage::Pong)),
        other => Err(anyhow!("unsupported websocket opcode {other}")),
    }
}

fn reassemble_data(
    fragments: &mut Option<Vec<u8>>,
    opcode: u8,
    fin: bool,
    payload: Vec<u8>,
) -> anyhow::Result<Option<Vec<u8>>> {
    match opcode {
        0x0 => {
            let buffer = fragments
                .as_mut()
                .ok_or_else(|| anyhow!("websocket continuation has no initial frame"))?;
            if buffer.len().saturating_add(payload.len()) > 16 * 1024 * 1024 {
                return Err(anyhow!("websocket fragmented message is too large"));
            }
            buffer.extend_from_slice(&payload);
            if fin {
                Ok(fragments.take())
            } else {
                Ok(None)
            }
        }
        0x1 | 0x2 if fin => {
            if fragments.is_some() {
                return Err(anyhow!(
                    "websocket data frame interrupted fragmented message"
                ));
            }
            Ok(Some(payload))
        }
        0x1 | 0x2 => {
            if fragments.replace(payload).is_some() {
                return Err(anyhow!("websocket started a second fragmented message"));
            }
            Ok(None)
        }
        _ => Err(anyhow!("unsupported websocket data opcode {opcode}")),
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

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, time::Duration};

    use base64::Engine;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use crate::{
        outbound::context::{scope_dial_context, DialContext},
        routing::Destination,
    };

    use super::{open_websocket_transport, read_websocket_frame, websocket_accept_key};

    #[tokio::test]
    async fn early_data_in_path_preserves_query_and_frames_remainder() {
        let (client, mut server) = tokio::io::duplex(128 * 1024);
        let server_task = tokio::spawn(async move {
            let request = read_headers(&mut server).await;
            let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"abcde");
            assert!(request.starts_with(&format!("GET /ws{encoded}?token=1 HTTP/1.1\r\n")));
            respond_websocket(&mut server, &request, Some(b"ready")).await;
            assert_eq!(
                read_websocket_frame(&mut server)
                    .await
                    .expect("read remainder")
                    .expect("remainder frame"),
                b"fgh"
            );
        });

        let mut context = DialContext::new(Destination::new("example.com", 443), 1_000);
        context.websocket_max_early_data = 5;
        let mut stream = scope_dial_context(&context, async {
            open_websocket_transport(
                client,
                "example.com",
                "/ws?token=1",
                &BTreeMap::new(),
                1_000,
            )
            .await
        })
        .await
        .expect("lazy websocket");
        stream.write_all(b"abcdefgh").await.expect("first write");
        stream.flush().await.expect("flush");
        let mut reply = [0u8; 5];
        stream
            .read_exact(&mut reply)
            .await
            .expect("prefetched reply");
        assert_eq!(&reply, b"ready");
        server_task.await.expect("server task");
    }

    #[tokio::test]
    async fn early_data_header_and_ed_query_are_supported() {
        let (client, mut server) = tokio::io::duplex(128 * 1024);
        let server_task = tokio::spawn(async move {
            let request = read_headers(&mut server).await;
            assert!(request.starts_with("GET /vmess?token=1 HTTP/1.1\r\n"));
            let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"hello");
            assert!(request.lines().any(|line| {
                line.eq_ignore_ascii_case(&format!("Sec-WebSocket-Protocol: {encoded}"))
            }));
            respond_websocket(&mut server, &request, None).await;
        });

        let context = DialContext::new(Destination::new("example.com", 443), 1_000);
        let mut stream = scope_dial_context(&context, async {
            open_websocket_transport(
                client,
                "example.com",
                "/vmess?ed=16&token=1",
                &BTreeMap::new(),
                1_000,
            )
            .await
        })
        .await
        .expect("query early-data websocket");
        stream.write_all(b"hello").await.expect("early write");
        server_task.await.expect("server task");
    }

    #[tokio::test]
    async fn lazy_handshake_honors_total_deadline() {
        let (client, mut server) = tokio::io::duplex(16 * 1024);
        let server_task = tokio::spawn(async move {
            let _ = read_headers(&mut server).await;
            tokio::time::sleep(Duration::from_millis(100)).await;
        });

        let mut context = DialContext::new(Destination::new("example.com", 443), 30);
        context.websocket_max_early_data = 8;
        let mut stream = scope_dial_context(&context, async {
            open_websocket_transport(client, "example.com", "/ws", &BTreeMap::new(), 30).await
        })
        .await
        .expect("lazy websocket");
        let error = stream
            .write_all(b"request")
            .await
            .expect_err("stalled handshake must time out");
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert!(error.to_string().contains("early-data handshake timed out"));
        server_task.await.expect("server task");
    }

    async fn read_headers<S>(stream: &mut S) -> String
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
        String::from_utf8(request).expect("request utf8")
    }

    async fn respond_websocket<S>(stream: &mut S, request: &str, prefetched: Option<&[u8]>)
    where
        S: tokio::io::AsyncWrite + Unpin,
    {
        let key = request
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("sec-websocket-key")
                    .then(|| value.trim())
            })
            .expect("websocket key");
        let mut response = format!(
            "HTTP/1.1 101 Switching Protocols\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Accept: {}\r\n\r\n",
            websocket_accept_key(key)
        )
        .into_bytes();
        if let Some(payload) = prefetched {
            response.push(0x82);
            response.push(payload.len() as u8);
            response.extend_from_slice(payload);
        }
        stream
            .write_all(&response)
            .await
            .expect("handshake response");
        stream.flush().await.expect("handshake flush");
    }
}
