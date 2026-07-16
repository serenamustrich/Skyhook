use std::io::{Error, ErrorKind};

use tokio::io::{AsyncRead, AsyncReadExt};

pub(super) async fn read_exact_or_eof<R>(reader: &mut R, buffer: &mut [u8]) -> anyhow::Result<bool>
where
    R: AsyncRead + Unpin,
{
    let mut offset = 0;
    while offset < buffer.len() {
        let read = reader.read(&mut buffer[offset..]).await?;
        if read == 0 {
            if offset == 0 {
                return Ok(false);
            }
            return Err(Error::new(ErrorKind::UnexpectedEof, "partial read").into());
        }
        offset += read;
    }
    Ok(true)
}
