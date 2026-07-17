use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};
use tokio_util::sync::CancellationToken;

use crate::{config::SmuxProtocol, outbound::BoxedStream};

const BRIDGE_CAPACITY: usize = 64 * 1024;
const COPY_BUFFER_SIZE: usize = u16::MAX as usize;
const INITIAL_PADDING_FRAMES: usize = 16;

pub(super) fn spawn_protocol_stream(
    base: BoxedStream,
    protocol: SmuxProtocol,
    padding: bool,
    cancellation: CancellationToken,
) -> DuplexStream {
    let (client, bridge) = tokio::io::duplex(BRIDGE_CAPACITY);
    tokio::spawn(async move {
        let result = relay_protocol_stream(base, bridge, protocol, padding, cancellation).await;
        if let Err(error) = result {
            tracing::debug!(error = %error, "sing-mux protocol stream ended");
        }
    });
    client
}

async fn relay_protocol_stream(
    base: BoxedStream,
    bridge: DuplexStream,
    protocol: SmuxProtocol,
    padding: bool,
    cancellation: CancellationToken,
) -> io::Result<()> {
    let (mut app_reader, mut app_writer) = tokio::io::split(bridge);
    let (mut base_reader, mut base_writer) = tokio::io::split(base);
    let outbound = async {
        write_protocol_request(&mut base_writer, protocol, padding).await?;
        if padding {
            copy_padded_outbound(&mut app_reader, &mut base_writer).await?;
        } else {
            tokio::io::copy(&mut app_reader, &mut base_writer).await?;
        }
        base_writer.shutdown().await
    };
    let inbound = async {
        if padding {
            copy_padded_inbound(&mut base_reader, &mut app_writer).await?;
        } else {
            tokio::io::copy(&mut base_reader, &mut app_writer).await?;
        }
        app_writer.shutdown().await
    };

    tokio::select! {
        _ = cancellation.cancelled() => Ok(()),
        result = async { tokio::try_join!(outbound, inbound).map(|_| ()) } => result,
    }
}

async fn write_protocol_request<W>(
    writer: &mut W,
    protocol: SmuxProtocol,
    padding: bool,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let protocol = match protocol {
        SmuxProtocol::Smux => 0,
        SmuxProtocol::Yamux => 1,
        SmuxProtocol::H2Mux => 2,
    };
    if !padding {
        return writer.write_all(&[0, protocol]).await;
    }

    let padding_len = random_padding_len()?;
    writer.write_all(&[1, protocol, 1]).await?;
    writer.write_all(&padding_len.to_be_bytes()).await?;
    write_random_padding(writer, padding_len as usize).await
}

async fn copy_padded_outbound<R, W>(reader: &mut R, writer: &mut W) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = vec![0u8; COPY_BUFFER_SIZE];
    let mut padded = 0usize;
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            return Ok(());
        }
        if padded < INITIAL_PADDING_FRAMES {
            let padding_len = random_padding_len()?;
            writer.write_all(&(read as u16).to_be_bytes()).await?;
            writer.write_all(&padding_len.to_be_bytes()).await?;
            writer.write_all(&buffer[..read]).await?;
            write_random_padding(writer, padding_len as usize).await?;
            padded += 1;
        } else {
            writer.write_all(&buffer[..read]).await?;
        }
    }
}

async fn copy_padded_inbound<R, W>(reader: &mut R, writer: &mut W) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = vec![0u8; COPY_BUFFER_SIZE];
    for _ in 0..INITIAL_PADDING_FRAMES {
        let mut header = [0u8; 4];
        reader.read_exact(&mut header).await?;
        let original_len = u16::from_be_bytes([header[0], header[1]]) as usize;
        let padding_len = u16::from_be_bytes([header[2], header[3]]) as usize;
        reader.read_exact(&mut buffer[..original_len]).await?;
        writer.write_all(&buffer[..original_len]).await?;
        discard_exact(reader, padding_len, &mut buffer).await?;
    }
    tokio::io::copy(reader, writer).await?;
    Ok(())
}

async fn discard_exact<R>(reader: &mut R, mut len: usize, buffer: &mut [u8]) -> io::Result<()>
where
    R: AsyncRead + Unpin,
{
    while len > 0 {
        let chunk = len.min(buffer.len());
        reader.read_exact(&mut buffer[..chunk]).await?;
        len -= chunk;
    }
    Ok(())
}

fn random_padding_len() -> io::Result<u16> {
    let mut random = [0u8; 2];
    getrandom::fill(&mut random)
        .map_err(|error| io::Error::other(format!("padding randomness failed: {error}")))?;
    Ok(256 + u16::from_be_bytes(random) % 512)
}

async fn write_random_padding<W>(writer: &mut W, len: usize) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut padding = vec![0u8; len];
    getrandom::fill(&mut padding)
        .map_err(|error| io::Error::other(format!("padding randomness failed: {error}")))?;
    writer.write_all(&padding).await
}

#[cfg(test)]
pub(super) async fn accept_protocol_stream(
    mut base: BoxedStream,
    expected_protocol: SmuxProtocol,
    expected_padding: bool,
) -> io::Result<DuplexStream> {
    let mut header = [0u8; 2];
    base.read_exact(&mut header).await?;
    let expected_protocol = match expected_protocol {
        SmuxProtocol::Smux => 0,
        SmuxProtocol::Yamux => 1,
        SmuxProtocol::H2Mux => 2,
    };
    if header[1] != expected_protocol {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "unexpected sing-mux protocol {}, expected {expected_protocol}",
                header[1]
            ),
        ));
    }
    let padding = match header[0] {
        0 => false,
        1 => {
            let enabled = base.read_u8().await?;
            if enabled > 1 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid sing-mux padding flag",
                ));
            }
            if enabled == 1 {
                let len = base.read_u16().await? as usize;
                let mut discard = vec![0u8; len];
                base.read_exact(&mut discard).await?;
            }
            enabled == 1
        }
        version => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported sing-mux version {version}"),
            ));
        }
    };
    if padding != expected_padding {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "sing-mux padding mode did not match test server",
        ));
    }

    let (server, bridge) = tokio::io::duplex(BRIDGE_CAPACITY);
    tokio::spawn(async move {
        let (mut app_reader, mut app_writer) = tokio::io::split(bridge);
        let (mut base_reader, mut base_writer) = tokio::io::split(base);
        let outbound = async {
            if padding {
                copy_padded_outbound(&mut app_reader, &mut base_writer).await?;
            } else {
                tokio::io::copy(&mut app_reader, &mut base_writer).await?;
            }
            base_writer.shutdown().await
        };
        let inbound = async {
            if padding {
                copy_padded_inbound(&mut base_reader, &mut app_writer).await?;
            } else {
                tokio::io::copy(&mut base_reader, &mut app_writer).await?;
            }
            app_writer.shutdown().await
        };
        if let Err(error) = async { tokio::try_join!(outbound, inbound).map(|_| ()) }.await {
            tracing::debug!(error = %error, "sing-mux test server wire ended");
        }
    });
    Ok(server)
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_util::sync::CancellationToken;

    use crate::{config::SmuxProtocol, outbound::BoxedStream};

    use super::spawn_protocol_stream;

    #[tokio::test]
    async fn protocol_ids_and_version_zero_prefix_match_sing_mux() {
        for (protocol, protocol_id) in [
            (SmuxProtocol::Smux, 0u8),
            (SmuxProtocol::Yamux, 1u8),
            (SmuxProtocol::H2Mux, 2u8),
        ] {
            let (base_client, mut base_server) = tokio::io::duplex(4096);
            let cancellation = CancellationToken::new();
            let mut client = spawn_protocol_stream(
                Box::new(base_client) as BoxedStream,
                protocol,
                false,
                cancellation.clone(),
            );
            client.write_all(b"mux-data").await.unwrap();
            let mut wire = [0u8; 10];
            base_server.read_exact(&mut wire).await.unwrap();
            assert_eq!(
                wire,
                [
                    0,
                    protocol_id,
                    b'm',
                    b'u',
                    b'x',
                    b'-',
                    b'd',
                    b'a',
                    b't',
                    b'a'
                ]
            );
            cancellation.cancel();
        }
    }

    #[tokio::test]
    async fn version_one_padding_has_bounded_reference_framing() {
        let (base_client, mut base_server) = tokio::io::duplex(8192);
        let cancellation = CancellationToken::new();
        let mut client = spawn_protocol_stream(
            Box::new(base_client) as BoxedStream,
            SmuxProtocol::H2Mux,
            true,
            cancellation.clone(),
        );
        client.write_all(b"abc").await.unwrap();

        assert_eq!(base_server.read_u8().await.unwrap(), 1);
        assert_eq!(base_server.read_u8().await.unwrap(), 2);
        assert_eq!(base_server.read_u8().await.unwrap(), 1);
        let request_padding = base_server.read_u16().await.unwrap() as usize;
        assert!((256..=767).contains(&request_padding));
        let mut discard = vec![0u8; request_padding];
        base_server.read_exact(&mut discard).await.unwrap();

        assert_eq!(base_server.read_u16().await.unwrap(), 3);
        let frame_padding = base_server.read_u16().await.unwrap() as usize;
        assert!((256..=767).contains(&frame_padding));
        let mut payload = [0u8; 3];
        base_server.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"abc");
        discard.resize(frame_padding, 0);
        base_server.read_exact(&mut discard).await.unwrap();

        base_server.write_u16(3).await.unwrap();
        base_server.write_u16(256).await.unwrap();
        base_server.write_all(b"xyz").await.unwrap();
        base_server.write_all(&[0u8; 256]).await.unwrap();
        let mut response = [0u8; 3];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"xyz");
        cancellation.cancel();
    }
}
