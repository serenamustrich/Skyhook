use std::time::{SystemTime, UNIX_EPOCH};

use aes::Aes256;
use anyhow::{anyhow, bail};
use ctr::cipher::{KeyIvInit, StreamCipher};
use hmac::{Hmac, Mac};
use md5::Md5;
use sha1::Sha1;
use sha2::{Sha256, Sha384, Sha512};
use subtle::ConstantTimeEq;

use super::{
    config::{decode_static_key, OpenVpnDigest},
    packet::ReplayWindow,
};

const HEADER_LEN: usize = 9;
const REPLAY_ID_LEN: usize = 8;
const TLS_CRYPT_TAG_LEN: usize = 32;
const MAX_CLOCK_SKEW_SECONDS: u64 = 180;

type Aes256Ctr = ctr::Ctr128BE<Aes256>;

pub(super) enum ControlWrap {
    None,
    TlsAuth(TlsAuth),
    TlsCrypt(TlsCrypt),
}

impl ControlWrap {
    pub(super) fn none() -> Self {
        Self::None
    }

    pub(super) fn tls_auth(
        material: &[u8],
        digest: OpenVpnDigest,
        direction: Option<u8>,
    ) -> anyhow::Result<Self> {
        let key = decode_static_key(material)?;
        Ok(Self::TlsAuth(TlsAuth::new(&key, digest, direction)?))
    }

    pub(super) fn tls_crypt(material: &[u8]) -> anyhow::Result<Self> {
        let key = decode_static_key(material)?;
        Ok(Self::TlsCrypt(TlsCrypt::new(&key)))
    }

    pub(super) fn wrap(&mut self, plain: &[u8]) -> anyhow::Result<Vec<u8>> {
        match self {
            Self::None => Ok(plain.to_vec()),
            Self::TlsAuth(value) => value.wrap(plain),
            Self::TlsCrypt(value) => value.wrap(plain),
        }
    }

    pub(super) fn unwrap(&mut self, packet: &[u8]) -> anyhow::Result<Vec<u8>> {
        match self {
            Self::None => Ok(packet.to_vec()),
            Self::TlsAuth(value) => value.unwrap(packet),
            Self::TlsCrypt(value) => value.unwrap(packet),
        }
    }
}

pub(super) struct TlsAuth {
    send_key: Vec<u8>,
    receive_key: Vec<u8>,
    digest: OpenVpnDigest,
    next_packet_id: u32,
    replay: ReplayWindow,
}

impl TlsAuth {
    fn new(
        static_key: &[u8; 256],
        digest: OpenVpnDigest,
        direction: Option<u8>,
    ) -> anyhow::Result<Self> {
        let key_len = digest.output_len();
        let slot0 = &static_key[64..64 + key_len];
        let slot1 = &static_key[192..192 + key_len];
        let (send_key, receive_key) = match direction {
            None => (slot0, slot0),
            Some(1) => (slot1, slot0),
            Some(0) => (slot0, slot1),
            Some(value) => bail!("invalid OpenVPN tls-auth key direction {value}"),
        };
        Ok(Self {
            send_key: send_key.to_vec(),
            receive_key: receive_key.to_vec(),
            digest,
            next_packet_id: 1,
            replay: ReplayWindow::new(),
        })
    }

    fn wrap(&mut self, plain: &[u8]) -> anyhow::Result<Vec<u8>> {
        if plain.len() < HEADER_LEN {
            bail!("OpenVPN control packet is too short for tls-auth");
        }
        let packet_id = self.allocate_packet_id()?;
        let timestamp = unix_time()?;
        let mut authenticated = Vec::with_capacity(REPLAY_ID_LEN + plain.len());
        authenticated.extend_from_slice(&packet_id.to_be_bytes());
        authenticated.extend_from_slice(&timestamp.to_be_bytes());
        authenticated.extend_from_slice(plain);
        let tag = compute_hmac(self.digest, &self.send_key, &authenticated)?;
        let mut output = Vec::with_capacity(plain.len() + tag.len() + REPLAY_ID_LEN);
        output.extend_from_slice(&plain[..HEADER_LEN]);
        output.extend_from_slice(&tag);
        output.extend_from_slice(&packet_id.to_be_bytes());
        output.extend_from_slice(&timestamp.to_be_bytes());
        output.extend_from_slice(&plain[HEADER_LEN..]);
        Ok(output)
    }

    fn unwrap(&mut self, packet: &[u8]) -> anyhow::Result<Vec<u8>> {
        let tag_len = self.digest.output_len();
        let minimum = HEADER_LEN + tag_len + REPLAY_ID_LEN;
        if packet.len() < minimum {
            bail!("OpenVPN tls-auth packet is too short");
        }
        let tag = &packet[HEADER_LEN..HEADER_LEN + tag_len];
        let replay_offset = HEADER_LEN + tag_len;
        let packet_id = u32::from_be_bytes(packet[replay_offset..replay_offset + 4].try_into()?);
        let timestamp = u32::from_be_bytes(packet[replay_offset + 4..replay_offset + 8].try_into()?);
        let mut plain = Vec::with_capacity(packet.len() - tag_len - REPLAY_ID_LEN);
        plain.extend_from_slice(&packet[..HEADER_LEN]);
        plain.extend_from_slice(&packet[minimum..]);
        let mut authenticated = Vec::with_capacity(REPLAY_ID_LEN + plain.len());
        authenticated.extend_from_slice(&packet_id.to_be_bytes());
        authenticated.extend_from_slice(&timestamp.to_be_bytes());
        authenticated.extend_from_slice(&plain);
        let expected = compute_hmac(self.digest, &self.receive_key, &authenticated)?;
        if tag.ct_eq(expected.as_slice()).unwrap_u8() != 1 {
            bail!("OpenVPN tls-auth authentication failed");
        }
        validate_replay(&mut self.replay, packet_id, timestamp)?;
        Ok(plain)
    }

    fn allocate_packet_id(&mut self) -> anyhow::Result<u32> {
        let packet_id = self.next_packet_id;
        self.next_packet_id = self
            .next_packet_id
            .checked_add(1)
            .ok_or_else(|| anyhow!("OpenVPN tls-auth packet id exhausted"))?;
        Ok(packet_id)
    }
}

pub(super) struct TlsCrypt {
    send_cipher_key: [u8; 32],
    send_hmac_key: [u8; 32],
    receive_cipher_key: [u8; 32],
    receive_hmac_key: [u8; 32],
    next_packet_id: u32,
    replay: ReplayWindow,
}

impl TlsCrypt {
    fn new(static_key: &[u8; 256]) -> Self {
        let mut send_cipher_key = [0; 32];
        let mut send_hmac_key = [0; 32];
        let mut receive_cipher_key = [0; 32];
        let mut receive_hmac_key = [0; 32];
        send_cipher_key.copy_from_slice(&static_key[128..160]);
        send_hmac_key.copy_from_slice(&static_key[192..224]);
        receive_cipher_key.copy_from_slice(&static_key[..32]);
        receive_hmac_key.copy_from_slice(&static_key[64..96]);
        Self {
            send_cipher_key,
            send_hmac_key,
            receive_cipher_key,
            receive_hmac_key,
            next_packet_id: 1,
            replay: ReplayWindow::new(),
        }
    }

    fn wrap(&mut self, plain: &[u8]) -> anyhow::Result<Vec<u8>> {
        if plain.len() < HEADER_LEN {
            bail!("OpenVPN control packet is too short for tls-crypt");
        }
        let packet_id = self.next_packet_id;
        self.next_packet_id = self
            .next_packet_id
            .checked_add(1)
            .ok_or_else(|| anyhow!("OpenVPN tls-crypt packet id exhausted"))?;
        let timestamp = unix_time()?;
        let mut associated = Vec::with_capacity(HEADER_LEN + REPLAY_ID_LEN);
        associated.extend_from_slice(&plain[..HEADER_LEN]);
        associated.extend_from_slice(&packet_id.to_be_bytes());
        associated.extend_from_slice(&timestamp.to_be_bytes());
        let mut authenticated = associated.clone();
        authenticated.extend_from_slice(&plain[HEADER_LEN..]);
        let tag = compute_hmac(OpenVpnDigest::Sha256, &self.send_hmac_key, &authenticated)?;
        let mut ciphertext = plain[HEADER_LEN..].to_vec();
        let mut cipher = Aes256Ctr::new_from_slices(&self.send_cipher_key, &tag[..16])?;
        cipher.apply_keystream(&mut ciphertext);
        let mut output = associated;
        output.extend_from_slice(&tag);
        output.extend_from_slice(&ciphertext);
        Ok(output)
    }

    fn unwrap(&mut self, packet: &[u8]) -> anyhow::Result<Vec<u8>> {
        let minimum = HEADER_LEN + REPLAY_ID_LEN + TLS_CRYPT_TAG_LEN;
        if packet.len() < minimum {
            bail!("OpenVPN tls-crypt packet is too short");
        }
        let packet_id = u32::from_be_bytes(packet[HEADER_LEN..HEADER_LEN + 4].try_into()?);
        let timestamp = u32::from_be_bytes(packet[HEADER_LEN + 4..HEADER_LEN + 8].try_into()?);
        let tag = &packet[HEADER_LEN + REPLAY_ID_LEN..minimum];
        let mut plaintext = packet[minimum..].to_vec();
        let mut cipher = Aes256Ctr::new_from_slices(&self.receive_cipher_key, &tag[..16])?;
        cipher.apply_keystream(&mut plaintext);
        let mut authenticated = packet[..HEADER_LEN + REPLAY_ID_LEN].to_vec();
        authenticated.extend_from_slice(&plaintext);
        let expected = compute_hmac(
            OpenVpnDigest::Sha256,
            &self.receive_hmac_key,
            &authenticated,
        )?;
        if tag.ct_eq(expected.as_slice()).unwrap_u8() != 1 {
            bail!("OpenVPN tls-crypt authentication failed");
        }
        validate_replay(&mut self.replay, packet_id, timestamp)?;
        let mut plain = packet[..HEADER_LEN].to_vec();
        plain.extend_from_slice(&plaintext);
        Ok(plain)
    }
}

pub(super) fn compute_hmac(
    digest: OpenVpnDigest,
    key: &[u8],
    message: &[u8],
) -> anyhow::Result<Vec<u8>> {
    macro_rules! calculate {
        ($digest:ty) => {{
            let mut mac = <Hmac<$digest> as Mac>::new_from_slice(key)?;
            mac.update(message);
            mac.finalize().into_bytes().to_vec()
        }};
    }
    Ok(match digest {
        OpenVpnDigest::Md5 => calculate!(Md5),
        OpenVpnDigest::Sha1 => calculate!(Sha1),
        OpenVpnDigest::Sha256 => calculate!(Sha256),
        OpenVpnDigest::Sha384 => calculate!(Sha384),
        OpenVpnDigest::Sha512 => calculate!(Sha512),
    })
}

fn validate_replay(
    replay: &mut ReplayWindow,
    packet_id: u32,
    timestamp: u32,
) -> anyhow::Result<()> {
    let now = u64::from(unix_time()?);
    let timestamp = u64::from(timestamp);
    if now.abs_diff(timestamp) > MAX_CLOCK_SKEW_SECONDS {
        bail!("OpenVPN control packet timestamp is outside the replay window");
    }
    if !replay.accept(packet_id) {
        bail!("OpenVPN control packet replay detected");
    }
    Ok(())
}

fn unix_time() -> anyhow::Result<u32> {
    let seconds = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    u32::try_from(seconds).map_err(|_| anyhow!("system time exceeds OpenVPN timestamp range"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn static_key() -> Vec<u8> {
        format!(
            "-----BEGIN OpenVPN Static key V1-----\n{}\n-----END OpenVPN Static key V1-----\n",
            (0..256).map(|value| format!("{value:02x}")).collect::<String>()
        )
        .into_bytes()
    }

    #[test]
    fn tls_crypt_client_server_round_trip() {
        let key = decode_static_key(&static_key()).unwrap();
        let mut client = TlsCrypt::new(&key);
        let mut server = TlsCrypt {
            send_cipher_key: client.receive_cipher_key,
            send_hmac_key: client.receive_hmac_key,
            receive_cipher_key: client.send_cipher_key,
            receive_hmac_key: client.send_hmac_key,
            next_packet_id: 1,
            replay: ReplayWindow::new(),
        };
        let plain = [vec![0x38], b"client01".to_vec(), vec![0, 0, 0, 0, 0]].concat();
        let wrapped = client.wrap(&plain).unwrap();
        assert_eq!(server.unwrap(&wrapped).unwrap(), plain);
        assert!(server.unwrap(&wrapped).is_err());
    }
}
