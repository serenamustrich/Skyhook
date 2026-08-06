mod table;
mod go_rand;
mod httpmask;

use std::{collections::{BTreeMap, VecDeque}, net::IpAddr, sync::{atomic::{AtomicUsize, Ordering}, Arc}, time::{Duration, SystemTime, UNIX_EPOCH}};

use aes_gcm::{aead::{Aead, KeyInit}, Aes128Gcm, Nonce};
use anyhow::{anyhow, bail, Context};
use async_trait::async_trait;
use chacha20poly1305::ChaCha20Poly1305;
use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, edwards::CompressedEdwardsY, scalar::Scalar};
use hmac::{Hmac, Mac};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use tokio::io::{self, AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use rustls_pki_types::ServerName;
use tokio_rustls::TlsConnector;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::routing::Destination;

use super::{transports::connect_tcp, BoxedStream, Outbound, OutboundCapability, UdpNatMode};

const KIP_MAGIC: &[u8; 3] = b"kip";
const KIP_CLIENT_HELLO: u8 = 0x01;
const KIP_SERVER_HELLO: u8 = 0x02;
const KIP_OPEN_TCP: u8 = 0x10;
const KIP_START_UOT: u8 = 0x12;
const KIP_FEATURES: u32 = 0x1f;
const MAX_KIP_PAYLOAD: usize = u16::MAX as usize;
const MAX_RECORD_BODY: usize = u16::MAX as usize;
const RECORD_HEADER_SIZE: usize = 12;
const DUPLEX_CAPACITY: usize = 256 * 1024;

pub(super) struct SudokuOutbound {
    name: String,
    server: String,
    port: u16,
    key: String,
    aead: String,
    padding_min: u8,
    padding_max: u8,
    http_mask: bool,
    http_mask_mode: String,
    http_mask_tls: bool,
    http_mask_host: Option<String>,
    path_root: Option<String>,
    pure_downlink: bool,
    tables: Vec<(Arc<table::SudokuTable>, Arc<table::SudokuTable>)>,
    next_table: AtomicUsize,
}

impl SudokuOutbound {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        name: String,
        server: String,
        port: u16,
        key: String,
        aead: Option<String>,
        padding_min: Option<u8>,
        padding_max: Option<u8>,
        table_type: Option<String>,
        enable_pure_downlink: Option<bool>,
        http_mask: Option<bool>,
        http_mask_mode: Option<String>,
        http_mask_tls: bool,
        http_mask_host: Option<String>,
        path_root: Option<String>,
        _multiplex: Option<String>,
        custom_table: Option<String>,
        custom_tables: Vec<String>,
    ) -> anyhow::Result<Self> {
        if server.trim().is_empty() || port == 0 {
            bail!("sudoku server and port are required");
        }
        if key.trim().is_empty() {
            bail!("sudoku key is required");
        }
        let aead = aead.unwrap_or_else(|| "chacha20-poly1305".to_string()).to_ascii_lowercase();
        if !matches!(aead.as_str(), "none" | "aes-128-gcm" | "chacha20-poly1305") {
            bail!("unsupported sudoku AEAD method {aead}");
        }
        let padding_min = padding_min.unwrap_or(10).min(100);
        let padding_max = padding_max.unwrap_or(30).min(100);
        if padding_max < padding_min {
            bail!("sudoku padding-max must be >= padding-min");
        }
        let table_type = table_type.unwrap_or_else(|| "prefer_entropy".to_string());
        let pure_downlink = enable_pure_downlink.unwrap_or(true);
        if !pure_downlink && aead == "none" {
            bail!("sudoku packed downlink requires AEAD");
        }
        let patterns = if custom_tables.is_empty() {
            vec![custom_table]
        } else {
            custom_tables.into_iter().map(Some).collect()
        };
        let tables = patterns
            .into_iter()
            .map(|pattern| {
                let (write, read) = table::SudokuTable::pair(&canonical_seed(&key), &table_type, pattern.as_deref())?;
                Ok((Arc::new(write), Arc::new(read)))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        let http_mask = http_mask.unwrap_or(true);
        let http_mask_mode = http_mask_mode.unwrap_or_else(|| "legacy".to_string()).to_ascii_lowercase();
        if !matches!(http_mask_mode.as_str(), "legacy" | "stream" | "poll" | "auto" | "ws") {
            bail!("unsupported sudoku HTTP mask mode {http_mask_mode}");
        }
        Ok(Self {
            name,
            server,
            port,
            key,
            aead,
            padding_min,
            padding_max,
            http_mask,
            http_mask_mode,
            http_mask_tls,
            http_mask_host,
            path_root,
            pure_downlink,
            tables,
            next_table: AtomicUsize::new(0),
        })
    }

    async fn open_wire(&self, timeout_ms: u64) -> anyhow::Result<SudokuWire> {
        let mut raw: BoxedStream = if !self.http_mask || self.http_mask_mode == "legacy" {
            Box::new(connect_tcp(&format!("{}:{}", self.server, self.port), timeout_ms).await?)
        } else if self.http_mask_mode == "ws" {
            self.open_websocket_mask(timeout_ms).await?
        } else {
            httpmask::open(
                &self.server,
                self.port,
                self.http_mask_tls,
                self.http_mask_host.as_deref(),
                self.path_root.as_deref(),
                &self.http_mask_mode,
                timeout_ms,
            ).await?
        };
        if self.http_mask && self.http_mask_mode == "legacy" {
            let host = self.http_mask_host.as_deref().unwrap_or(&self.server);
            let path = self.path_root.as_deref().filter(|value| !value.trim().is_empty()).map(|value| format!("/{value}/session")).unwrap_or_else(|| "/session".to_string());
            let request = format!("POST {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: keep-alive\r\nContent-Length: 0\r\n\r\n");
            raw.write_all(request.as_bytes()).await.context("write sudoku HTTP mask")?;
            raw.flush().await?;
        }
        let index = self.next_table.fetch_add(1, Ordering::Relaxed) % self.tables.len();
        let (write_table, read_table) = &self.tables[index];
        let mut wire = SudokuWire::new_with_downlink(
            raw,
            Arc::clone(write_table),
            Arc::clone(read_table),
            &self.aead,
            &canonical_seed(&self.key),
            self.padding_min,
            self.padding_max,
            self.pure_downlink,
        )?;
        let (session_c2s, session_s2c) = wire.client_handshake(&canonical_seed(&self.key)).await?;
        wire.rekey(session_c2s, session_s2c)?;
        Ok(wire)
    }

    async fn open_websocket_mask(&self, timeout_ms: u64) -> anyhow::Result<BoxedStream> {
        let raw = connect_tcp(&format!("{}:{}", self.server, self.port), timeout_ms).await?;
        let host = self.http_mask_host.as_deref().unwrap_or(&self.server);
        let path = self.path_root.as_deref()
            .filter(|value| !value.trim().is_empty())
            .map(|value| format!("/{value}"))
            .unwrap_or_else(|| "/".to_string());
        if !self.http_mask_tls {
            return super::transports::open_websocket_transport(raw, host, &path, &BTreeMap::new(), timeout_ms).await;
        }
        let mut config = super::transports::tls_client_config(false)?;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let server_name = ServerName::try_from(host.to_string())
            .map_err(|error| anyhow!("invalid Sudoku HTTP mask TLS host: {error}"))?;
        let tls = tokio::time::timeout(
            Duration::from_millis(timeout_ms.max(1)),
            TlsConnector::from(Arc::new(config)).connect(server_name, raw),
        ).await.context("Sudoku HTTP mask TLS handshake timed out")??;
        super::transports::open_websocket_transport(tls, host, &path, &BTreeMap::new(), timeout_ms).await
    }

    async fn connect_tcp_target(&self, destination: &Destination, timeout_ms: u64) -> anyhow::Result<BoxedStream> {
        let mut wire = self.open_wire(timeout_ms).await?;
        let address = encode_address(destination)?;
        wire.write_message(KIP_OPEN_TCP, &address).await?;
        wire.into_stream().await
    }

    async fn udp_exchange_inner(&self, destination: &Destination, payload: &[u8], timeout_ms: u64) -> anyhow::Result<Vec<u8>> {
        let mut wire = self.open_wire(timeout_ms).await?;
        wire.write_message(KIP_START_UOT, &[]).await?;
        let address = encode_address(destination)?;
        let mut frame = Vec::with_capacity(4 + address.len() + payload.len());
        frame.extend_from_slice(&(address.len() as u16).to_be_bytes());
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        frame.extend_from_slice(&address);
        frame.extend_from_slice(payload);
        wire.write_plain(&frame).await?;
        let header = wire.read_plain_exact(4).await?;
        let address_len = u16::from_be_bytes([header[0], header[1]]) as usize;
        let payload_len = u16::from_be_bytes([header[2], header[3]]) as usize;
        if address_len == 0 || address_len > 512 || payload_len > 65_535 {
            bail!("invalid sudoku UoT response frame");
        }
        let _ = wire.read_plain_exact(address_len).await?;
        wire.read_plain_exact(payload_len).await
    }
}

#[async_trait]
impl Outbound for SudokuOutbound {
    fn name(&self) -> &str { &self.name }
    fn kind(&self) -> &'static str { "sudoku" }
    fn capability(&self) -> OutboundCapability {
        let limitations = Vec::new();
        OutboundCapability { tcp_supported: limitations.is_empty(), udp_supported: limitations.is_empty(), udp_mode: Some("uot".into()), limitations }
    }
    fn udp_nat_mode(&self) -> UdpNatMode { UdpNatMode::EndpointDependent }
    async fn connect(&self, destination: &Destination, timeout_ms: u64) -> anyhow::Result<BoxedStream> {
        self.connect_tcp_target(destination, timeout_ms).await
    }
    async fn udp_exchange(&self, destination: &Destination, payload: &[u8], timeout_ms: u64) -> anyhow::Result<Vec<u8>> {
        tokio::time::timeout(Duration::from_millis(timeout_ms), self.udp_exchange_inner(destination, payload, timeout_ms))
            .await
            .context("sudoku UoT exchange timed out")?
    }
}

struct SudokuWire {
    reader: SudokuReader,
    writer: SudokuWriter,
}

impl SudokuWire {
    #[allow(clippy::too_many_arguments)]
    fn new_with_downlink(inner: BoxedStream, write_table: Arc<table::SudokuTable>, read_table: Arc<table::SudokuTable>, aead: &str, seed: &str, min: u8, max: u8, pure_downlink: bool) -> anyhow::Result<Self> {
        Self::new_with_direction(inner, write_table, read_table, aead, seed, min, max, pure_downlink, "c2s", "s2c")
    }

    #[cfg(test)]
    fn new_server(inner: BoxedStream, write_table: Arc<table::SudokuTable>, read_table: Arc<table::SudokuTable>, aead: &str, seed: &str, min: u8, max: u8) -> anyhow::Result<Self> {
        Self::new_server_with_downlink(inner, write_table, read_table, aead, seed, min, max, true)
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    fn new_server_with_downlink(inner: BoxedStream, write_table: Arc<table::SudokuTable>, read_table: Arc<table::SudokuTable>, aead: &str, seed: &str, min: u8, max: u8, pure_downlink: bool) -> anyhow::Result<Self> {
        Self::new_with_direction(inner, write_table, read_table, aead, seed, min, max, pure_downlink, "s2c", "c2s")
    }

    #[allow(clippy::too_many_arguments)]
    fn new_with_direction(inner: BoxedStream, write_table: Arc<table::SudokuTable>, read_table: Arc<table::SudokuTable>, aead: &str, seed: &str, min: u8, max: u8, pure_downlink: bool, send_direction: &str, recv_direction: &str) -> anyhow::Result<Self> {
        let (read_half, write_half) = io::split(inner);
        Ok(Self {
            reader: SudokuReader::new(read_half, read_table, aead, seed, recv_direction, min, max, !pure_downlink),
            writer: SudokuWriter::new(write_half, write_table, aead, seed, send_direction, min, max),
        })
    }

    async fn client_handshake(&mut self, seed: &str) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
        let secret = random_bytes::<32>()?;
        let ephemeral = StaticSecret::from(secret);
        let client_public = PublicKey::from(&ephemeral);
        let nonce = random_bytes::<16>()?;
        let mut user_hash = [0u8; 8];
        let key_bytes = decode_hex(seed).unwrap_or_else(|| seed.as_bytes().to_vec());
        let digest = Sha256::digest(key_bytes);
        user_hash.copy_from_slice(&digest[..8]);
        let mut hello = Vec::with_capacity(72);
        hello.extend_from_slice(&(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs()).to_be_bytes());
        hello.extend_from_slice(&user_hash);
        hello.extend_from_slice(&nonce);
        hello.extend_from_slice(client_public.as_bytes());
        hello.extend_from_slice(&KIP_FEATURES.to_be_bytes());
        hello.extend_from_slice(&self.writer.table_hint().to_be_bytes());
        self.write_message(KIP_CLIENT_HELLO, &hello).await?;
        let (kind, server_hello) = self.read_message().await?;
        if kind != KIP_SERVER_HELLO || server_hello.len() != 52 {
            bail!("invalid sudoku server hello");
        }
        if server_hello[..16] != nonce {
            bail!("sudoku handshake nonce mismatch");
        }
        let server_public = PublicKey::from(<[u8; 32]>::try_from(&server_hello[16..48]).map_err(|_| anyhow!("invalid server key"))?);
        let shared = ephemeral.diffie_hellman(&server_public);
        derive_session_keys(seed, shared.as_bytes(), &nonce)
    }

    fn rekey(&mut self, send: Vec<u8>, recv: Vec<u8>) -> anyhow::Result<()> {
        self.writer.rekey(send.clone())?;
        self.reader.rekey(recv)?;
        Ok(())
    }

    async fn write_message(&mut self, kind: u8, payload: &[u8]) -> anyhow::Result<()> {
        if payload.len() > MAX_KIP_PAYLOAD { bail!("sudoku KIP payload is too large"); }
        let mut message = Vec::with_capacity(6 + payload.len());
        message.extend_from_slice(KIP_MAGIC);
        message.push(kind);
        message.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        message.extend_from_slice(payload);
        self.write_plain(&message).await
    }

    async fn read_message(&mut self) -> anyhow::Result<(u8, Vec<u8>)> {
        let header = self.read_plain_exact(6).await?;
        if &header[..3] != KIP_MAGIC { bail!("invalid sudoku KIP magic"); }
        let len = u16::from_be_bytes([header[4], header[5]]) as usize;
        Ok((header[3], self.read_plain_exact(len).await?))
    }

    async fn write_plain(&mut self, plaintext: &[u8]) -> anyhow::Result<()> { self.writer.write_plain(plaintext).await }
    async fn read_plain_exact(&mut self, size: usize) -> anyhow::Result<Vec<u8>> { self.reader.read_exact_plain(size).await }

    async fn into_stream(self) -> anyhow::Result<BoxedStream> {
        let (app, app_peer) = io::duplex(DUPLEX_CAPACITY);
        let reader = self.reader;
        let writer = self.writer;
        let (mut app_read, mut app_write) = io::split(app_peer);
        let (mut remote_read, mut remote_write) = (reader, writer);
        tokio::spawn(async move {
            let uplink = async {
                let mut buffer = vec![0u8; 32 * 1024];
                loop {
                    let count = app_read.read(&mut buffer).await?;
                    if count == 0 { remote_write.shutdown().await?; break; }
                    remote_write.write_plain(&buffer[..count]).await?;
                }
                Ok::<(), anyhow::Error>(())
            };
            let downlink = async {
                loop {
                    let chunk = remote_read.read_plain_chunk().await?;
                    if chunk.is_empty() { app_write.shutdown().await?; break; }
                    app_write.write_all(&chunk).await?;
                }
                Ok::<(), anyhow::Error>(())
            };
            let _ = tokio::join!(uplink, downlink);
        });
        Ok(Box::new(app))
    }
}

struct SudokuWriter {
    inner: WriteHalf<BoxedStream>,
    table: Arc<table::SudokuTable>,
    record: RecordWriter,
    rng: TinyRng,
    padding_min: u8,
    padding_max: u8,
}

impl SudokuWriter {
    fn new(inner: WriteHalf<BoxedStream>, table: Arc<table::SudokuTable>, aead: &str, seed: &str, direction: &str, min: u8, max: u8) -> Self {
        Self { inner, table, record: RecordWriter::new(aead, seed, direction), rng: TinyRng::new(), padding_min: min, padding_max: max }
    }
    fn table_hint(&self) -> u32 { self.table.hint }
    fn rekey(&mut self, key: Vec<u8>) -> anyhow::Result<()> { self.record.rekey(key) }
    async fn write_plain(&mut self, plaintext: &[u8]) -> anyhow::Result<()> {
        let frames = self.record.encode(plaintext)?;
        let mut encoded = Vec::with_capacity(frames.len() * 6);
        encode_sudoku(&mut encoded, &self.table, &mut self.rng, self.padding_min, self.padding_max, &frames);
        self.inner.write_all(&encoded).await?;
        self.inner.flush().await?;
        Ok(())
    }
    async fn shutdown(&mut self) -> anyhow::Result<()> { self.inner.shutdown().await.map_err(Into::into) }
}

struct SudokuReader {
    inner: ReadHalf<BoxedStream>,
    table: Arc<table::SudokuTable>,
    record: RecordReader,
    raw: [u8; 32 * 1024],
    decoded: VecDeque<u8>,
    hints: Vec<u8>,
    packed_downlink: Option<PackedDecoder>,
    eof: bool,
}

impl SudokuReader {
    #[allow(clippy::too_many_arguments)]
    fn new(inner: ReadHalf<BoxedStream>, table: Arc<table::SudokuTable>, aead: &str, seed: &str, direction: &str, min: u8, max: u8, packed_downlink: bool) -> Self {
        let _ = (min, max);
        Self {
            inner,
            table: Arc::clone(&table),
            record: RecordReader::new(aead, seed, direction),
            raw: [0; 32 * 1024],
            decoded: VecDeque::new(),
            hints: Vec::with_capacity(4),
            packed_downlink: packed_downlink.then(|| PackedDecoder::new(table.packed_pad_marker())),
            eof: false,
        }
    }
    fn rekey(&mut self, key: Vec<u8>) -> anyhow::Result<()> { self.record.rekey(key) }
    async fn fill_decoded(&mut self) -> anyhow::Result<()> {
        let count = self.inner.read(&mut self.raw).await?;
        if count == 0 { self.eof = true; return Ok(()); }
        let mut decoded = Vec::with_capacity(count / 2);
        if let Some(packed) = &mut self.packed_downlink {
            decode_packed(&mut decoded, &self.table, packed, &self.raw[..count]);
        } else {
            decode_sudoku(&mut decoded, &self.table, &mut self.raw[..count], &mut self.hints);
        }
        self.decoded.extend(decoded);
        Ok(())
    }
    async fn read_exact_plain(&mut self, size: usize) -> anyhow::Result<Vec<u8>> {
        let mut output = Vec::with_capacity(size);
        while output.len() < size {
            let chunk = self.read_plain_chunk().await?;
            if chunk.is_empty() { bail!("unexpected EOF in sudoku stream"); }
            let take = (size - output.len()).min(chunk.len());
            output.extend_from_slice(&chunk[..take]);
            for byte in chunk[take..].iter().rev() { self.record.pending.push_front(*byte); }
        }
        Ok(output)
    }
    async fn read_plain_chunk(&mut self) -> anyhow::Result<Vec<u8>> {
        if !self.record.pending.is_empty() {
            return Ok(self.record.pending.drain(..).collect());
        }
        if !self.record.is_encrypted() {
            while self.decoded.is_empty() {
                self.fill_decoded().await?;
                if self.decoded.is_empty() { return Ok(Vec::new()); }
            }
            return Ok(self.decoded.drain(..).collect());
        }
        let header = self.read_decoded_exact(2).await?;
        let body_len = u16::from_be_bytes([header[0], header[1]]) as usize;
        if !(RECORD_HEADER_SIZE..=MAX_RECORD_BODY).contains(&body_len) { bail!("invalid sudoku record length {body_len}"); }
        let body = self.read_decoded_exact(body_len).await?;
        self.record.decode_frame(&body)
    }
    async fn read_decoded_exact(&mut self, size: usize) -> anyhow::Result<Vec<u8>> {
        while self.decoded.len() < size {
            self.fill_decoded().await?;
            if self.decoded.len() < size && self.eof { bail!("unexpected EOF in sudoku codec"); }
        }
        Ok(self.decoded.drain(..size).collect())
    }
}

struct PackedDecoder {
    bit_buffer: u64,
    bit_count: u8,
    pad_marker: u8,
}

impl PackedDecoder {
    fn new(pad_marker: u8) -> Self {
        Self { bit_buffer: 0, bit_count: 0, pad_marker }
    }

    fn push(&mut self, output: &mut Vec<u8>, table: &table::SudokuTable, byte: u8) {
        if byte == self.pad_marker {
            self.bit_buffer = 0;
            self.bit_count = 0;
            return;
        }
        let Some(group) = table.is_packed_group(byte) else { return; };
        self.bit_buffer = (self.bit_buffer << 6) | u64::from(group & 0x3f);
        self.bit_count = self.bit_count.saturating_add(6);
        while self.bit_count >= 8 {
            self.bit_count -= 8;
            output.push((self.bit_buffer >> self.bit_count) as u8);
            if self.bit_count == 0 {
                self.bit_buffer = 0;
            } else {
                self.bit_buffer &= (1u64 << self.bit_count) - 1;
            }
        }
    }
}

struct RecordWriter { method: String, base: Vec<u8>, epoch: u32, seq: u64 }
struct RecordReader { method: String, base: Vec<u8>, epoch: u32, seq: u64, initialized: bool, pending: VecDeque<u8> }

impl RecordWriter {
    fn new(method: &str, seed: &str, direction: &str) -> Self { Self { method: method.into(), base: derive_psk(seed, &format!("sudoku-psk-{direction}")), epoch: random_u32(), seq: random_u64() } }
    fn rekey(&mut self, key: Vec<u8>) -> anyhow::Result<()> { self.base = key; self.epoch = random_u32(); self.seq = random_u64(); Ok(()) }
    fn encode(&mut self, plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
        if self.method == "none" { return Ok(plaintext.to_vec()); }
        let overhead = 16;
        let max_plain = MAX_RECORD_BODY - RECORD_HEADER_SIZE - overhead;
        let mut result = Vec::new();
        for chunk in plaintext.chunks(max_plain) {
            let mut header = [0u8; RECORD_HEADER_SIZE];
            header[..4].copy_from_slice(&self.epoch.to_be_bytes());
            header[4..].copy_from_slice(&self.seq.to_be_bytes());
            self.seq = self.seq.wrapping_add(1);
            let ciphertext = encrypt_payload(&self.method, &derive_epoch_key(&self.base, self.epoch, &self.method), &header, chunk)?;
            let body_len = RECORD_HEADER_SIZE + ciphertext.len();
            result.extend_from_slice(&(body_len as u16).to_be_bytes());
            result.extend_from_slice(&header);
            result.extend_from_slice(&ciphertext);
        }
        Ok(result)
    }
}

impl RecordReader {
    fn new(method: &str, seed: &str, direction: &str) -> Self { Self { method: method.into(), base: derive_psk(seed, &format!("sudoku-psk-{direction}")), epoch: 0, seq: 0, initialized: false, pending: VecDeque::new() } }
    fn rekey(&mut self, key: Vec<u8>) -> anyhow::Result<()> { self.base = key; self.epoch = 0; self.seq = 0; self.initialized = false; self.pending.clear(); Ok(()) }
    fn is_encrypted(&self) -> bool { self.method != "none" }
    fn decode_frame(&mut self, body: &[u8]) -> anyhow::Result<Vec<u8>> {
        if body.len() < RECORD_HEADER_SIZE { bail!("sudoku record is too short"); }
        let header = &body[..RECORD_HEADER_SIZE];
        let epoch = u32::from_be_bytes(header[..4].try_into()?);
        let seq = u64::from_be_bytes(header[4..].try_into()?);
        if self.initialized && (epoch < self.epoch || (epoch == self.epoch && seq != self.seq)) { bail!("sudoku record is out of order"); }
        let key = derive_epoch_key(&self.base, epoch, &self.method);
        let plaintext = decrypt_payload(&self.method, &key, header, &body[RECORD_HEADER_SIZE..])?;
        self.epoch = epoch; self.seq = seq.wrapping_add(1); self.initialized = true;
        Ok(plaintext)
    }
}

#[derive(Clone, Copy)]
struct TinyRng(u64);
impl TinyRng {
    fn new() -> Self { Self(random_u64()) }
    fn next(&mut self) -> u64 { let mut x = self.0; x ^= x >> 12; x ^= x << 25; x ^= x >> 27; self.0 = x; x.wrapping_mul(0x2545f4914f6cdd1d) }
    fn index(&mut self, len: usize) -> usize { ((self.next() as u128 * len as u128) >> 64) as usize }
    fn chance(&mut self, percent: u8) -> bool { (self.next() % 100) < percent as u64 }
}

fn encode_sudoku(output: &mut Vec<u8>, table: &table::SudokuTable, rng: &mut TinyRng, min: u8, max: u8, input: &[u8]) {
    let padding = &table.padding;
    let probability = if min == max { min } else { min.saturating_add((rng.next() % (u64::from(max - min) + 1)) as u8) };
    for byte in input {
        if rng.chance(probability) { output.push(padding[rng.index(padding.len())]); }
        let choices = &table.encode[*byte as usize];
        let puzzle = choices[rng.index(choices.len())];
        let mut order = [0usize, 1, 2, 3];
        for index in (1..4).rev() { order.swap(index, rng.index(index + 1)); }
        for slot in order {
            if rng.chance(probability) { output.push(padding[rng.index(padding.len())]); }
            output.push(puzzle[slot]);
        }
    }
    if rng.chance(probability) { output.push(padding[rng.index(padding.len())]); }
}

fn decode_sudoku(output: &mut Vec<u8>, table: &table::SudokuTable, input: &mut [u8], hints: &mut Vec<u8>) {
    for byte in input.iter().copied() {
        if !table.is_hint(byte) { continue; }
            hints.push(byte);
        if hints.len() == 4 {
            hints.sort_unstable();
            if let Some(value) = table.decode.get(&pack4(hints[0], hints[1], hints[2], hints[3])) { output.push(*value); }
            hints.clear();
        }
    }
}

fn decode_packed(output: &mut Vec<u8>, table: &table::SudokuTable, decoder: &mut PackedDecoder, input: &[u8]) {
    for byte in input.iter().copied() {
        decoder.push(output, table, byte);
    }
}

fn pack4(a: u8, b: u8, c: u8, d: u8) -> u32 { u32::from_be_bytes([a, b, c, d]) }

fn derive_psk(seed: &str, info: &str) -> Vec<u8> { let digest = Sha256::digest(seed.as_bytes()); let hk = Hkdf::<Sha256>::from_prk(&digest).expect("sha256 output is valid HKDF PRK"); let mut output = vec![0u8; 32]; hk.expand(info.as_bytes(), &mut output).expect("valid HKDF output size"); output }
fn derive_session_keys(seed: &str, shared: &[u8], nonce: &[u8; 16]) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let salt = Sha256::digest(seed.as_bytes());
    let mut ikm = Vec::with_capacity(shared.len() + nonce.len()); ikm.extend_from_slice(shared); ikm.extend_from_slice(nonce);
    let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
    let mut c2s = vec![0u8; 32]; let mut s2c = vec![0u8; 32];
    hk.expand(b"sudoku-session-c2s", &mut c2s).map_err(|_| anyhow!("derive sudoku c2s key"))?;
    hk.expand(b"sudoku-session-s2c", &mut s2c).map_err(|_| anyhow!("derive sudoku s2c key"))?;
    Ok((c2s, s2c))
}
fn derive_epoch_key(base: &[u8], epoch: u32, method: &str) -> Vec<u8> { let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(base).expect("HMAC accepts any key"); mac.update(b"sudoku-record:"); mac.update(method.as_bytes()); mac.update(&epoch.to_be_bytes()); mac.finalize().into_bytes().to_vec() }

fn encrypt_payload(method: &str, key: &[u8], nonce: &[u8; 12], payload: &[u8]) -> anyhow::Result<Vec<u8>> {
    match method {
        "aes-128-gcm" => Ok(Aes128Gcm::new_from_slice(&key[..16])?.encrypt(Nonce::from_slice(nonce), payload).map_err(|_| anyhow!("sudoku AES-GCM encryption failed"))?),
        "chacha20-poly1305" => Ok(ChaCha20Poly1305::new_from_slice(key)?.encrypt(chacha20poly1305::Nonce::from_slice(nonce), payload).map_err(|_| anyhow!("sudoku ChaCha20-Poly1305 encryption failed"))?),
        _ => bail!("unsupported sudoku AEAD {method}"),
    }
}
fn decrypt_payload(method: &str, key: &[u8], nonce: &[u8], payload: &[u8]) -> anyhow::Result<Vec<u8>> {
    match method {
        "aes-128-gcm" => Ok(Aes128Gcm::new_from_slice(&key[..16])?.decrypt(Nonce::from_slice(nonce), payload).map_err(|_| anyhow!("sudoku AES-GCM decryption failed"))?),
        "chacha20-poly1305" => Ok(ChaCha20Poly1305::new_from_slice(key)?.decrypt(chacha20poly1305::Nonce::from_slice(nonce), payload).map_err(|_| anyhow!("sudoku ChaCha20-Poly1305 decryption failed"))?),
        _ => bail!("unsupported sudoku AEAD {method}"),
    }
}

fn canonical_seed(key: &str) -> String {
    let trimmed = key.trim();
    if let Some(bytes) = decode_hex(trimmed) {
        if bytes.len() == 32 {
            if let Some(point) = CompressedEdwardsY::from_slice(&bytes).ok().and_then(|value| value.decompress()) {
                return encode_hex(point.compress().as_bytes());
            }
        }
        if bytes.len() == 64 {
            if let (Some(left), Some(right)) = (canonical_scalar(&bytes[..32]), canonical_scalar(&bytes[32..])) {
                let sum = left + right;
                let point = &sum * ED25519_BASEPOINT_TABLE;
                return encode_hex(point.compress().as_bytes());
            }
        }
    }
    trimmed.to_string()
}

fn canonical_scalar(bytes: &[u8]) -> Option<Scalar> {
    let raw: [u8; 32] = bytes.try_into().ok()?;
    Option::<Scalar>::from(Scalar::from_canonical_bytes(raw))
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(2) { return None; }
    let mut output = Vec::with_capacity(value.len() / 2);
    let bytes = value.as_bytes();
    for pair in bytes.chunks_exact(2) {
        let high = (pair[0] as char).to_digit(16)? as u8;
        let low = (pair[1] as char).to_digit(16)? as u8;
        output.push((high << 4) | low);
    }
    Some(output)
}

fn encode_address(destination: &Destination) -> anyhow::Result<Vec<u8>> {
    let host = destination.host.as_str();
    let mut output = Vec::new();
    if let Ok(ip) = host.parse::<IpAddr>() {
        match ip { IpAddr::V4(ip) => { output.push(1); output.extend_from_slice(&ip.octets()); }, IpAddr::V6(ip) => { output.push(4); output.extend_from_slice(&ip.octets()); } }
    } else {
        if host.len() > 255 { bail!("sudoku target hostname is too long"); }
        output.push(3); output.push(host.len() as u8); output.extend_from_slice(host.as_bytes());
    }
    output.extend_from_slice(&destination.port.to_be_bytes());
    Ok(output)
}

fn random_bytes<const N: usize>() -> anyhow::Result<[u8; N]> { let mut bytes = [0u8; N]; getrandom::fill(&mut bytes).map_err(|error| anyhow!("random bytes: {error}"))?; Ok(bytes) }
fn random_u32() -> u32 { random_bytes::<4>().map(u32::from_be_bytes).unwrap_or(1).max(1) }
fn random_u64() -> u64 { random_bytes::<8>().map(u64::from_be_bytes).unwrap_or(1).max(1) }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_all_sudoku_tables_with_unique_byte_mappings() {
        let (up, down) = table::SudokuTable::pair("test-key", "prefer_entropy", None).unwrap();
        assert_eq!(up.encode.len(), 256);
        assert_eq!(down.decode.len(), up.decode.len());
        assert!(up.encode.iter().all(|entries| !entries.is_empty()));
    }

    #[test]
    fn packed_downlink_decoder_round_trips_entropy_payload() {
        let (_, table) = table::SudokuTable::pair("packed-key", "prefer_entropy", None).unwrap();
        let payload = b"packed-downlink payload with a partial tail";
        let mut wire = Vec::new();
        let mut bits = 0u64;
        let mut bit_count = 0u8;
        for byte in payload.iter().copied() {
            bits = (bits << 8) | u64::from(byte);
            bit_count += 8;
            while bit_count >= 6 {
                bit_count -= 6;
                wire.push(table.packed_encode((bits >> bit_count) as u8));
                if bit_count == 0 { bits = 0; } else { bits &= (1u64 << bit_count) - 1; }
            }
        }
        if bit_count > 0 {
            wire.push(table.packed_encode((bits << (6 - bit_count)) as u8));
            wire.push(table.packed_pad_marker());
        }

        let mut decoder = PackedDecoder::new(table.packed_pad_marker());
        let mut decoded = Vec::new();
        decode_packed(&mut decoded, &table, &mut decoder, &wire);
        assert_eq!(decoded, payload);
    }

    #[test]
    fn address_encoding_preserves_domains_and_ip_versions() {
        let domain = encode_address(&Destination::new("example.com", 443)).unwrap();
        assert_eq!(&domain[..2], &[3, 11]);
        let ipv6 = encode_address(&Destination::new("::1", 53)).unwrap();
        assert_eq!(ipv6[0], 4);
        assert_eq!(&ipv6[17..], &[0, 53]);
    }

    #[tokio::test]
    async fn native_tcp_session_round_trips_through_a_sudoku_peer() {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let seed = canonical_seed("test-key");
        let (client_write, client_read) = table::SudokuTable::pair(&seed, "prefer_entropy", None).unwrap();
        let server_write = Arc::new(client_read.clone());
        let server_read = Arc::new(client_write.clone());
        let server_seed = seed.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut wire = SudokuWire::new_server(Box::new(stream), server_write, server_read, "chacha20-poly1305", &server_seed, 0, 0).unwrap();
            let (kind, hello) = wire.read_message().await.unwrap();
            assert_eq!(kind, KIP_CLIENT_HELLO);
            let nonce: [u8; 16] = hello[16..32].try_into().unwrap();
            let client_public = PublicKey::from(<[u8; 32]>::try_from(&hello[32..64]).unwrap());
            let ephemeral = StaticSecret::from(random_bytes::<32>().unwrap());
            let shared = ephemeral.diffie_hellman(&client_public);
            let (c2s, s2c) = derive_session_keys(&server_seed, shared.as_bytes(), &nonce).unwrap();
            let mut response = Vec::with_capacity(52);
            response.extend_from_slice(&nonce);
            response.extend_from_slice(PublicKey::from(&ephemeral).as_bytes());
            response.extend_from_slice(&KIP_FEATURES.to_be_bytes());
            wire.write_message(KIP_SERVER_HELLO, &response).await.unwrap();
            wire.rekey(s2c, c2s).unwrap();
            let (kind, _) = wire.read_message().await.unwrap();
            assert_eq!(kind, KIP_OPEN_TCP);
            let mut tunnel = wire.into_stream().await.unwrap();
            let mut buffer = [0u8; 4];
            tunnel.read_exact(&mut buffer).await.unwrap();
            tunnel.write_all(&buffer).await.unwrap();
            tunnel.shutdown().await.unwrap();
        });

        let outbound = SudokuOutbound::new(
            "test".into(), "127.0.0.1".into(), port, "test-key".into(),
            Some("chacha20-poly1305".into()), Some(0), Some(0), Some("prefer_entropy".into()),
            Some(true),
            Some(false), None, false, None, None, None, None, Vec::new(),
        ).unwrap();
        let mut stream = outbound.connect(&Destination::new("example.com", 443), 3_000).await.unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut response = [0u8; 4];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"ping");
        server.await.unwrap();
    }
}
