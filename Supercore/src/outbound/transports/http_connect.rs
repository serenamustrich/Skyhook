use anyhow::anyhow;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::routing::Destination;

pub(crate) async fn establish_http_connect<S>(
    stream: &mut S,
    destination: &Destination,
    username: Option<&str>,
    password: Option<&str>,
    keep_alive: bool,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let authority = destination.authority();
    let mut request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
    if keep_alive {
        request.push_str("Proxy-Connection: Keep-Alive\r\n");
    }
    if let (Some(username), Some(password)) = (username, password) {
        let token = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            format!("{username}:{password}"),
        );
        request.push_str(&format!("Proxy-Authorization: Basic {token}\r\n"));
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;

    let mut response = Vec::with_capacity(1024);
    let mut buffer = [0u8; 512];
    loop {
        if response.len() >= 64 * 1024 {
            return Err(anyhow!("http CONNECT response headers are too large"));
        }
        let count = stream.read(&mut buffer).await?;
        if count == 0 {
            return Err(anyhow!("http CONNECT ended before response headers"));
        }
        response.extend_from_slice(&buffer[..count]);
        if find_header_end(&response).is_some() {
            break;
        }
    }
    let text = std::str::from_utf8(&response)?;
    let status_line = text.lines().next().unwrap_or("");
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|value| value.parse::<u16>().ok());
    if status != Some(200) {
        return Err(anyhow!("http proxy connect failed: {status_line}"));
    }
    Ok(())
}

fn find_header_end(data: &[u8]) -> Option<usize> {
    data.windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use crate::routing::Destination;

    use super::establish_http_connect;

    #[tokio::test]
    async fn sends_authenticated_connect_and_accepts_200() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let server_task = tokio::spawn(async move {
            let mut request = Vec::new();
            let mut byte = [0_u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                server.read_exact(&mut byte).await.unwrap();
                request.push(byte[0]);
            }
            let request = String::from_utf8(request).unwrap();
            assert!(request.starts_with("CONNECT example.com:443 HTTP/1.1\r\n"));
            assert!(request.contains("Proxy-Connection: Keep-Alive\r\n"));
            assert!(request.contains("Proxy-Authorization: Basic dXNlcjpwYXNz\r\n"));
            server
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await
                .unwrap();
        });

        establish_http_connect(
            &mut client,
            &Destination::new("example.com", 443),
            Some("user"),
            Some("pass"),
            true,
        )
        .await
        .unwrap();
        server_task.await.unwrap();
    }
}
