use std::{
    io::{Error, ErrorKind},
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex as StdMutex,
    },
    task::{Context, Poll},
};

use anyhow::anyhow;
use rustls::ClientConfig;
use rustls_pki_types::ServerName;
use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf, ReadHalf, WriteHalf,
};
use tokio_rustls::{client::TlsStream, TlsConnector};
use uuid::Uuid;

use super::{transports::run_dial_phase, BoxedStream};

const VISION_PADDING_CONTINUE: u8 = 0x00;
const VISION_PADDING_END: u8 = 0x01;
const VISION_PADDING_DIRECT: u8 = 0x02;
const VISION_FIRST_HEADER_LEN: usize = 21;
const VISION_HEADER_LEN: usize = 5;
const VISION_PAYLOAD_LIMIT: usize = 8192 - VISION_FIRST_HEADER_LEN;
const TLS_RECORD_HEADER_LEN: usize = 5;
const TLS_RECORD_PAYLOAD_LIMIT: usize = 18 * 1024;

type SharedReadHalf = Arc<StdMutex<ReadHalf<BoxedStream>>>;
type SharedWriteHalf = Arc<StdMutex<WriteHalf<BoxedStream>>>;

pub(crate) struct VlessVisionTransport {
    tls: TlsStream<RecordBoundedIo>,
    raw_reader: RawReadHandle,
    raw_writer: RawWriteHandle,
}

impl VlessVisionTransport {
    pub(crate) async fn open(
        stream: BoxedStream,
        tls_config: ClientConfig,
        server_name: ServerName<'static>,
        timeout_ms: u64,
    ) -> anyhow::Result<Self> {
        let (record_io, raw_reader, raw_writer) = RecordBoundedIo::new(stream);
        let connector = TlsConnector::from(Arc::new(tls_config));
        let tls = run_dial_phase(
            timeout_ms,
            "vless vision tls handshake",
            connector.connect(server_name, record_io),
        )
        .await??;
        Ok(Self {
            tls,
            raw_reader,
            raw_writer,
        })
    }

    pub(crate) fn tls_mut(&mut self) -> &mut TlsStream<RecordBoundedIo> {
        &mut self.tls
    }

    pub(crate) fn into_stream(self, user_id: Uuid) -> DuplexStream {
        spawn_vision_stream(self.tls, self.raw_reader, self.raw_writer, user_id)
    }
}

struct RawReadHandle {
    inner: SharedReadHalf,
}

impl Clone for RawReadHandle {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl AsyncRead for RawReadHandle {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), Error>> {
        let mut reader = self
            .inner
            .lock()
            .map_err(|_| Error::other("vision raw reader lock poisoned"))?;
        Pin::new(&mut *reader).poll_read(context, buffer)
    }
}

struct RawWriteHandle {
    inner: SharedWriteHalf,
}

impl Clone for RawWriteHandle {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl AsyncWrite for RawWriteHandle {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, Error>> {
        let mut writer = self
            .inner
            .lock()
            .map_err(|_| Error::other("vision raw writer lock poisoned"))?;
        Pin::new(&mut *writer).poll_write(context, buffer)
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Result<(), Error>> {
        let mut writer = self
            .inner
            .lock()
            .map_err(|_| Error::other("vision raw writer lock poisoned"))?;
        Pin::new(&mut *writer).poll_flush(context)
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Result<(), Error>> {
        let mut writer = self
            .inner
            .lock()
            .map_err(|_| Error::other("vision raw writer lock poisoned"))?;
        Pin::new(&mut *writer).poll_shutdown(context)
    }
}

pub(crate) struct RecordBoundedIo {
    raw_reader: RawReadHandle,
    raw_writer: RawWriteHandle,
    record: Vec<u8>,
    loaded: usize,
    cursor: usize,
    yield_after_record: bool,
}

impl RecordBoundedIo {
    fn new(stream: BoxedStream) -> (Self, RawReadHandle, RawWriteHandle) {
        let (reader, writer) = tokio::io::split(stream);
        let raw_reader = RawReadHandle {
            inner: Arc::new(StdMutex::new(reader)),
        };
        let raw_writer = RawWriteHandle {
            inner: Arc::new(StdMutex::new(writer)),
        };
        (
            Self {
                raw_reader: raw_reader.clone(),
                raw_writer: raw_writer.clone(),
                record: Vec::new(),
                loaded: 0,
                cursor: 0,
                yield_after_record: false,
            },
            raw_reader,
            raw_writer,
        )
    }

    fn prepare_record(&mut self) {
        if self.record.is_empty() {
            self.record.resize(TLS_RECORD_HEADER_LEN, 0);
            self.loaded = 0;
            self.cursor = 0;
        }
    }

    fn validate_and_resize_record(&mut self) -> Result<(), Error> {
        let content_type = self.record[0];
        if !(20..=23).contains(&content_type) || self.record[1] != 0x03 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "invalid outer TLS record before Vision direct switch",
            ));
        }
        let payload_len = u16::from_be_bytes([self.record[3], self.record[4]]) as usize;
        if payload_len > TLS_RECORD_PAYLOAD_LIMIT {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "outer TLS record exceeds Vision boundary",
            ));
        }
        self.record.resize(TLS_RECORD_HEADER_LEN + payload_len, 0);
        Ok(())
    }
}

impl AsyncRead for RecordBoundedIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), Error>> {
        if buffer.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if self.yield_after_record {
            self.yield_after_record = false;
            context.waker().wake_by_ref();
            return Poll::Pending;
        }
        self.prepare_record();

        loop {
            if self.loaded == self.record.len() {
                let length = (self.record.len() - self.cursor).min(buffer.remaining());
                buffer.put_slice(&self.record[self.cursor..self.cursor + length]);
                self.cursor += length;
                if self.cursor == self.record.len() {
                    self.record.clear();
                    self.loaded = 0;
                    self.cursor = 0;
                    self.yield_after_record = true;
                }
                return Poll::Ready(Ok(()));
            }

            let loaded = self.loaded;
            let target = self.record.len();
            let mut raw_reader = self.raw_reader.clone();
            let mut raw_buffer = ReadBuf::new(&mut self.record[loaded..target]);
            match Pin::new(&mut raw_reader).poll_read(context, &mut raw_buffer) {
                Poll::Ready(Ok(())) => {
                    let count = raw_buffer.filled().len();
                    if count == 0 {
                        if loaded == 0 && target == TLS_RECORD_HEADER_LEN {
                            self.record.clear();
                            return Poll::Ready(Ok(()));
                        }
                        return Poll::Ready(Err(Error::new(
                            ErrorKind::UnexpectedEof,
                            "outer TLS record was truncated",
                        )));
                    }
                    self.loaded += count;
                    if self.loaded == TLS_RECORD_HEADER_LEN
                        && self.record.len() == TLS_RECORD_HEADER_LEN
                    {
                        self.validate_and_resize_record()?;
                    }
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for RecordBoundedIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, Error>> {
        Pin::new(&mut self.raw_writer).poll_write(context, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Pin::new(&mut self.raw_writer).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), Error>> {
        Pin::new(&mut self.raw_writer).poll_shutdown(context)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum VisionDirectionMode {
    Padded,
    OuterPlain,
    Direct,
}

fn spawn_vision_stream(
    tls: TlsStream<RecordBoundedIo>,
    raw_reader: RawReadHandle,
    raw_writer: RawWriteHandle,
    user_id: Uuid,
) -> DuplexStream {
    let (app_side, relay_side) = tokio::io::duplex(64 * 1024);
    let (local_read, local_write) = tokio::io::split(relay_side);
    let (outer_read, outer_write) = tokio::io::split(tls);
    let direct_enabled = Arc::new(AtomicBool::new(false));

    tokio::spawn(vision_uplink(
        local_read,
        outer_write,
        raw_writer,
        user_id,
        Arc::clone(&direct_enabled),
    ));
    tokio::spawn(vision_downlink(
        local_write,
        outer_read,
        raw_reader,
        user_id,
        direct_enabled,
    ));
    app_side
}

async fn vision_uplink(
    mut local: ReadHalf<DuplexStream>,
    mut outer: WriteHalf<TlsStream<RecordBoundedIo>>,
    mut direct: RawWriteHandle,
    user_id: Uuid,
    direct_enabled: Arc<AtomicBool>,
) {
    let mut mode = VisionDirectionMode::Padded;
    let mut first_frame = true;
    let mut packets_to_filter = 8u8;
    let mut inner_tls = false;
    let mut inspection_tail = Vec::with_capacity(4);
    let mut buffer = vec![0u8; VISION_PAYLOAD_LIMIT];

    loop {
        let count = match local.read(&mut buffer).await {
            Ok(0) => {
                let _ = match mode {
                    VisionDirectionMode::Direct => direct.shutdown().await,
                    _ => outer.shutdown().await,
                };
                return;
            }
            Ok(count) => count,
            Err(_) => return,
        };
        let payload = &buffer[..count];
        let write_result = match mode {
            VisionDirectionMode::Direct => direct.write_all(payload).await,
            VisionDirectionMode::OuterPlain => outer.write_all(payload).await,
            VisionDirectionMode::Padded => {
                packets_to_filter = packets_to_filter.saturating_sub(1);
                let mut inspection = inspection_tail.clone();
                inspection.extend_from_slice(payload);
                if contains_tls_record(&inspection, 0x16) {
                    inner_tls = true;
                }
                let sees_application_data = contains_tls_record(&inspection, 0x17);
                inspection_tail.clear();
                inspection_tail.extend_from_slice(
                    &inspection[inspection.len().saturating_sub(2)..inspection.len()],
                );

                let command = if inner_tls && sees_application_data {
                    if direct_enabled.load(Ordering::Acquire) {
                        VISION_PADDING_DIRECT
                    } else {
                        VISION_PADDING_END
                    }
                } else if !inner_tls && packets_to_filter <= 1 {
                    VISION_PADDING_END
                } else {
                    VISION_PADDING_CONTINUE
                };
                let frame = match build_vision_frame(
                    payload,
                    command,
                    first_frame.then_some(user_id.as_bytes()),
                    inner_tls,
                ) {
                    Ok(frame) => frame,
                    Err(_) => return,
                };
                first_frame = false;
                let result = outer.write_all(&frame).await;
                if result.is_ok() {
                    let _ = outer.flush().await;
                    mode = match command {
                        VISION_PADDING_DIRECT => VisionDirectionMode::Direct,
                        VISION_PADDING_END => VisionDirectionMode::OuterPlain,
                        _ => VisionDirectionMode::Padded,
                    };
                }
                result
            }
        };
        if write_result.is_err() {
            return;
        }
    }
}

async fn vision_downlink(
    mut local: WriteHalf<DuplexStream>,
    mut outer: ReadHalf<TlsStream<RecordBoundedIo>>,
    mut direct: RawReadHandle,
    user_id: Uuid,
    direct_enabled: Arc<AtomicBool>,
) {
    let mut mode = VisionDirectionMode::Padded;
    let mut first_frame = true;
    let mut tls_observation = Vec::with_capacity(4096);

    loop {
        match mode {
            VisionDirectionMode::OuterPlain => {
                let _ = tokio::io::copy(&mut outer, &mut local).await;
                let _ = local.shutdown().await;
                return;
            }
            VisionDirectionMode::Direct => {
                let _ = tokio::io::copy(&mut direct, &mut local).await;
                let _ = local.shutdown().await;
                return;
            }
            VisionDirectionMode::Padded => {}
        }

        let header_len = if first_frame {
            VISION_FIRST_HEADER_LEN
        } else {
            VISION_HEADER_LEN
        };
        let mut header = vec![0u8; header_len];
        if outer.read_exact(&mut header).await.is_err() {
            let _ = local.shutdown().await;
            return;
        }
        let fields = if first_frame {
            if header[..16] != user_id.as_bytes()[..] {
                let _ = local.shutdown().await;
                return;
            }
            first_frame = false;
            &header[16..]
        } else {
            &header[..]
        };
        let command = fields[0];
        if !matches!(
            command,
            VISION_PADDING_CONTINUE | VISION_PADDING_END | VISION_PADDING_DIRECT
        ) {
            let _ = local.shutdown().await;
            return;
        }
        let content_len = u16::from_be_bytes([fields[1], fields[2]]) as usize;
        let padding_len = u16::from_be_bytes([fields[3], fields[4]]) as usize;
        let mut content = vec![0u8; content_len];
        if outer.read_exact(&mut content).await.is_err() {
            let _ = local.shutdown().await;
            return;
        }
        if tls_observation.len() < 64 * 1024 {
            let remaining = 64 * 1024 - tls_observation.len();
            tls_observation.extend_from_slice(&content[..content.len().min(remaining)]);
            if observes_tls13_server_hello(&tls_observation) {
                direct_enabled.store(true, Ordering::Release);
            }
        }
        if local.write_all(&content).await.is_err() {
            return;
        }
        if discard_exact(&mut outer, padding_len).await.is_err() {
            let _ = local.shutdown().await;
            return;
        }
        mode = match command {
            VISION_PADDING_DIRECT => VisionDirectionMode::Direct,
            VISION_PADDING_END => VisionDirectionMode::OuterPlain,
            _ => VisionDirectionMode::Padded,
        };
    }
}

fn build_vision_frame(
    payload: &[u8],
    command: u8,
    user_id: Option<&[u8; 16]>,
    padding_tls: bool,
) -> anyhow::Result<Vec<u8>> {
    if payload.len() > u16::MAX as usize {
        return Err(anyhow!("Vision payload is too large"));
    }
    let padding_len = vision_padding_len(payload.len(), padding_tls)?;
    let mut frame = Vec::with_capacity(
        user_id.map(|_| 16).unwrap_or(0) + VISION_HEADER_LEN + payload.len() + padding_len,
    );
    if let Some(user_id) = user_id {
        frame.extend_from_slice(user_id);
    }
    frame.push(command);
    frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    frame.extend_from_slice(&(padding_len as u16).to_be_bytes());
    frame.extend_from_slice(payload);
    if padding_len > 0 {
        let offset = frame.len();
        frame.resize(offset + padding_len, 0);
        getrandom::fill(&mut frame[offset..])
            .map_err(|error| anyhow!("Vision padding randomness failed: {error}"))?;
    }
    Ok(frame)
}

fn vision_padding_len(content_len: usize, padding_tls: bool) -> anyhow::Result<usize> {
    if content_len >= 900 {
        return Ok(0);
    }
    let mut random = [0u8; 2];
    getrandom::fill(&mut random)
        .map_err(|error| anyhow!("Vision padding length randomness failed: {error}"))?;
    let random = u16::from_be_bytes(random) as usize;
    if padding_tls {
        Ok(900 - content_len + random % 500)
    } else {
        Ok(random % 256)
    }
}

fn contains_tls_record(data: &[u8], content_type: u8) -> bool {
    data.windows(3)
        .any(|window| window[0] == content_type && window[1] == 0x03)
}

fn observes_tls13_server_hello(data: &[u8]) -> bool {
    let mut record_cursor = 0usize;
    while record_cursor + TLS_RECORD_HEADER_LEN <= data.len() {
        let record_len =
            u16::from_be_bytes([data[record_cursor + 3], data[record_cursor + 4]]) as usize;
        let record_end = record_cursor + TLS_RECORD_HEADER_LEN + record_len;
        if record_end > data.len() {
            break;
        }
        if data[record_cursor] == 0x16 && data[record_cursor + 1] == 0x03 {
            let mut handshake_cursor = record_cursor + TLS_RECORD_HEADER_LEN;
            while handshake_cursor + 4 <= record_end {
                let handshake_len = ((data[handshake_cursor + 1] as usize) << 16)
                    | ((data[handshake_cursor + 2] as usize) << 8)
                    | data[handshake_cursor + 3] as usize;
                let handshake_end = handshake_cursor + 4 + handshake_len;
                if handshake_end > record_end {
                    break;
                }
                if data[handshake_cursor] == 0x02
                    && server_hello_selects_tls13(&data[handshake_cursor + 4..handshake_end])
                {
                    return true;
                }
                handshake_cursor = handshake_end;
            }
        }
        record_cursor = record_end;
    }
    false
}

fn server_hello_selects_tls13(server_hello: &[u8]) -> bool {
    if server_hello.len() < 38 {
        return false;
    }
    let session_id_len = server_hello[34] as usize;
    let cipher_offset = 35 + session_id_len;
    if cipher_offset + 5 > server_hello.len() {
        return false;
    }
    let cipher_suite =
        u16::from_be_bytes([server_hello[cipher_offset], server_hello[cipher_offset + 1]]);
    if cipher_suite == 0x1305 {
        return false;
    }
    let extensions_len_offset = cipher_offset + 3;
    let extensions_len = u16::from_be_bytes([
        server_hello[extensions_len_offset],
        server_hello[extensions_len_offset + 1],
    ]) as usize;
    let mut cursor = extensions_len_offset + 2;
    let extensions_end = cursor + extensions_len;
    if extensions_end > server_hello.len() {
        return false;
    }
    while cursor + 4 <= extensions_end {
        let extension_type = u16::from_be_bytes([server_hello[cursor], server_hello[cursor + 1]]);
        let extension_len =
            u16::from_be_bytes([server_hello[cursor + 2], server_hello[cursor + 3]]) as usize;
        cursor += 4;
        let extension_end = cursor + extension_len;
        if extension_end > extensions_end {
            return false;
        }
        if extension_type == 0x002b
            && extension_len == 2
            && server_hello[cursor..extension_end] == [0x03, 0x04]
        {
            return true;
        }
        cursor = extension_end;
    }
    false
}

async fn discard_exact<R>(reader: &mut R, mut length: usize) -> Result<(), Error>
where
    R: AsyncRead + Unpin,
{
    let mut buffer = [0u8; 1024];
    while length > 0 {
        let count = length.min(buffer.len());
        reader.read_exact(&mut buffer[..count]).await?;
        length -= count;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::{build_vision_frame, VISION_FIRST_HEADER_LEN, VISION_PADDING_CONTINUE};

    #[test]
    fn first_vision_frame_contains_uuid_lengths_and_payload() {
        let user_id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        let frame = build_vision_frame(
            b"hello",
            VISION_PADDING_CONTINUE,
            Some(user_id.as_bytes()),
            false,
        )
        .unwrap();
        assert!(frame.len() >= VISION_FIRST_HEADER_LEN + 5);
        assert_eq!(&frame[..16], user_id.as_bytes());
        assert_eq!(frame[16], VISION_PADDING_CONTINUE);
        assert_eq!(u16::from_be_bytes([frame[17], frame[18]]), 5);
        assert_eq!(&frame[21..26], b"hello");
    }
}
