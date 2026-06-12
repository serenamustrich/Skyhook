use std::sync::Arc;

use anyhow::Context;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
};

use crate::core::Runtime;

pub async fn serve(runtime: Arc<Runtime>) -> anyhow::Result<()> {
    let config = runtime.config().dns;
    if !config.enabled {
        return Ok(());
    }
    let Some(listen) = config.listen else {
        return Ok(());
    };

    let udp = Arc::new(
        UdpSocket::bind(listen)
            .await
            .with_context(|| format!("failed to bind dns udp listener {listen}"))?,
    );
    let tcp = TcpListener::bind(listen)
        .await
        .with_context(|| format!("failed to bind dns tcp listener {listen}"))?;

    runtime
        .telemetry()
        .log(
            "info",
            format!(
                "dns listener on {listen}, enhanced_mode={:?}, cache={:?}, respect_rules={}",
                config.enhanced_mode, config.cache_algorithm, config.respect_rules
            ),
        )
        .await;

    tokio::try_join!(serve_udp(runtime.clone(), udp), serve_tcp(runtime, tcp))?;
    Ok(())
}

async fn serve_udp(runtime: Arc<Runtime>, udp: Arc<UdpSocket>) -> anyhow::Result<()> {
    let mut buf = vec![0u8; 65_535];
    loop {
        let (len, peer) = udp.recv_from(&mut buf).await?;
        let query = buf[..len].to_vec();
        let runtime = runtime.clone();
        let udp = udp.clone();
        tokio::spawn(async move {
            match runtime.exchange_dns_over_tcp(&query).await {
                Ok(response) => {
                    runtime
                        .telemetry()
                        .add_transfer(
                            uuid::Uuid::nil(),
                            query.len() as u64,
                            response.len() as u64,
                            crate::telemetry::Protocol::Dns,
                            "",
                        )
                        .await;
                    let _ = udp.send_to(&response, peer).await;
                }
                Err(error) => {
                    runtime
                        .telemetry()
                        .log(
                            "warn",
                            format!("dns udp query from {peer} failed: {error:#}"),
                        )
                        .await;
                }
            }
        });
    }
}

async fn serve_tcp(runtime: Arc<Runtime>, tcp: TcpListener) -> anyhow::Result<()> {
    loop {
        let (stream, peer) = tcp.accept().await?;
        let runtime = runtime.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_tcp_client(runtime.clone(), stream).await {
                runtime
                    .telemetry()
                    .log("warn", format!("dns tcp client {peer} failed: {error:#}"))
                    .await;
            }
        });
    }
}

async fn handle_tcp_client(runtime: Arc<Runtime>, mut stream: TcpStream) -> anyhow::Result<()> {
    loop {
        let mut len = [0u8; 2];
        match stream.read_exact(&mut len).await {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(error) => return Err(error.into()),
        }
        let query_len = u16::from_be_bytes(len) as usize;
        let mut query = vec![0u8; query_len];
        stream.read_exact(&mut query).await?;
        let response = runtime.exchange_dns_over_tcp(&query).await?;
        if response.len() > u16::MAX as usize {
            anyhow::bail!("dns response is too large");
        }
        runtime
            .telemetry()
            .add_transfer(
                uuid::Uuid::nil(),
                query.len() as u64,
                response.len() as u64,
                crate::telemetry::Protocol::Dns,
                "",
            )
            .await;
        stream
            .write_all(&(response.len() as u16).to_be_bytes())
            .await?;
        stream.write_all(&response).await?;
    }
}
