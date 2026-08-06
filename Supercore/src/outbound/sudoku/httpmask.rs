use std::{net::IpAddr, time::Duration};

use anyhow::{anyhow, Context};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use futures::StreamExt;
use reqwest::{header::{HeaderValue, HOST, USER_AGENT}, Client, Response};
use tokio::io::{self, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::outbound::BoxedStream;

const MAX_BATCH: usize = 64 * 1024;
const QUEUE_SIZE: usize = 32;

pub(super) async fn open(
    server: &str,
    port: u16,
    tls: bool,
    host_override: Option<&str>,
    path_root: Option<&str>,
    mode: &str,
    timeout_ms: u64,
) -> anyhow::Result<BoxedStream> {
    let scheme = if tls { "https" } else { "http" };
    let authority = format_authority(server, port)?;
    let base = format!("{scheme}://{authority}");
    let host = host_override.filter(|value| !value.trim().is_empty()).unwrap_or(server).to_string();
    let client = Client::builder()
        .no_proxy()
        .http2_adaptive_window(true)
        .build()
        .context("build Sudoku HTTP mask client")?;
    let session_url = endpoint(&base, path_root, "session", None);
    let mut request = client
        .get(&session_url)
        .header(USER_AGENT, "Mozilla/5.0")
        .header("Accept", "*/*")
        .header("X-Sudoku-Tunnel", mode);
    if let Ok(value) = HeaderValue::from_str(&host) { request = request.header(HOST, value); }
    let response = tokio::time::timeout(Duration::from_millis(timeout_ms.max(1)), request.send())
        .await
        .context("Sudoku HTTP mask authorization timed out")??;
    let status = response.status();
    let body = response.bytes().await.context("read Sudoku HTTP mask authorization")?;
    if !status.is_success() {
        return Err(anyhow!("Sudoku HTTP mask authorization returned {status}"));
    }
    let token = parse_token(&body)?;
    let (app, relay) = io::duplex(256 * 1024);
    let mode = normalize_mode(mode);
    let client_for_upload = client.clone();
    let client_for_download = client.clone();
    let push_url = endpoint(&base, path_root, "api/v1/upload", Some(&token));
    let pull_url = endpoint(&base, path_root, "stream", Some(&token));
    let host_for_upload = host.clone();
    let host_for_download = host.clone();
    let (mut app_read, mut app_write) = io::split(relay);
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(QUEUE_SIZE);

    tokio::spawn(async move {
        let mut buffer = vec![0u8; 32 * 1024];
        loop {
            match app_read.read(&mut buffer).await {
                Ok(0) | Err(_) => break,
                Ok(size) => {
                    if tx.send(buffer[..size].to_vec()).await.is_err() { break; }
                }
            }
        }
    });

    let upload_mode = mode.clone();
    tokio::spawn(async move {
        let mut pending = Vec::with_capacity(MAX_BATCH);
        let mut ticker = tokio::time::interval(Duration::from_millis(5));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                chunk = rx.recv() => {
                    let Some(chunk) = chunk else {
                        let _ = flush_upload(&client_for_upload, &push_url, &host_for_upload, &upload_mode, &mut pending).await;
                        return;
                    };
                    if pending.len() + chunk.len() > MAX_BATCH
                        && flush_upload(&client_for_upload, &push_url, &host_for_upload, &upload_mode, &mut pending).await.is_err() {
                        return;
                    }
                    pending.extend_from_slice(&chunk);
                    if pending.len() >= MAX_BATCH && flush_upload(&client_for_upload, &push_url, &host_for_upload, &upload_mode, &mut pending).await.is_err() { return; }
                }
                _ = ticker.tick(), if !pending.is_empty() => {
                    if flush_upload(&client_for_upload, &push_url, &host_for_upload, &upload_mode, &mut pending).await.is_err() { return; }
                }
            }
        }
    });

    tokio::spawn(async move {
        let result = download_loop(
            &client_for_download,
            &pull_url,
            &host_for_download,
            &mode,
            &mut app_write,
        ).await;
        if result.is_err() { let _ = app_write.shutdown().await; }
    });

    Ok(Box::new(app))
}

fn normalize_mode(mode: &str) -> String {
    match mode.trim().to_ascii_lowercase().as_str() {
        "poll" => "poll".into(),
        _ => "stream".into(),
    }
}

fn format_authority(server: &str, port: u16) -> anyhow::Result<String> {
    if server.trim().is_empty() || port == 0 { return Err(anyhow!("Sudoku HTTP mask server and port are required")); }
    if server.parse::<IpAddr>().map(|ip| ip.is_ipv6()).unwrap_or(false) {
        Ok(format!("[{server}]:{port}"))
    } else {
        Ok(format!("{server}:{port}"))
    }
}

fn endpoint(base: &str, root: Option<&str>, path: &str, token: Option<&str>) -> String {
    let root = root.unwrap_or("").trim_matches('/');
    let path = if root.is_empty() { format!("/{path}") } else { format!("/{root}/{path}") };
    let mut output = format!("{base}{path}");
    if let Some(token) = token {
        output.push_str("?token=");
        output.push_str(token);
    }
    output
}

fn parse_token(body: &[u8]) -> anyhow::Result<String> {
    let text = String::from_utf8_lossy(body);
    let token = text
        .split_once("token=")
        .map(|(_, value)| value.lines().next().unwrap_or(value).trim())
        .unwrap_or("");
    if token.is_empty() { return Err(anyhow!("Sudoku HTTP mask response has no token")); }
    Ok(token.chars().take(512).collect())
}

async fn flush_upload(
    client: &Client,
    url: &str,
    host: &str,
    mode: &str,
    pending: &mut Vec<u8>,
) -> anyhow::Result<()> {
    if pending.is_empty() { return Ok(()); }
    let body = if mode == "poll" {
        format!("{}\n", STANDARD.encode(&*pending)).into_bytes()
    } else {
        std::mem::take(pending)
    };
    let mut request = client
        .post(url)
        .header(USER_AGENT, "Mozilla/5.0")
        .header("X-Sudoku-Tunnel", mode)
        .body(body);
    if let Ok(value) = HeaderValue::from_str(host) { request = request.header(HOST, value); }
    let response = request.send().await.context("Sudoku HTTP mask upload")?;
    if !response.status().is_success() { return Err(anyhow!("Sudoku HTTP mask upload returned {}", response.status())); }
    if mode == "poll" { pending.clear(); }
    Ok(())
}

async fn download_loop(
    client: &Client,
    url: &str,
    host: &str,
    mode: &str,
    output: &mut (impl AsyncWrite + Unpin),
) -> anyhow::Result<()> {
    loop {
        let mut request = client
            .get(url)
            .header(USER_AGENT, "Mozilla/5.0")
            .header("X-Sudoku-Tunnel", mode);
        if let Ok(value) = HeaderValue::from_str(host) { request = request.header(HOST, value); }
        let response: Response = request.send().await.context("Sudoku HTTP mask download")?;
        if !response.status().is_success() { return Err(anyhow!("Sudoku HTTP mask download returned {}", response.status())); }
        if mode == "poll" {
            let bytes = response.bytes().await.context("read Sudoku HTTP mask poll")?;
            for line in bytes.split(|byte| *byte == b'\n') {
                if line.is_empty() { continue; }
                let payload = base64::engine::general_purpose::STANDARD
                    .decode(line)
                    .context("decode Sudoku HTTP mask poll frame")?;
                output.write_all(&payload).await?;
            }
        } else {
            let mut stream = response.bytes_stream();
            while let Some(chunk) = stream.next().await {
                output.write_all(&chunk.context("read Sudoku HTTP mask stream")?).await?;
                output.flush().await?;
            }
        }
    }
}
