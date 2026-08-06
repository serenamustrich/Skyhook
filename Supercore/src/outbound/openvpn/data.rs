use aes::{Aes128, Aes192, Aes256};
use aes_gcm::{
    aead::{consts::U12, AeadInPlace, KeyInit},
    Aes128Gcm, Aes256Gcm, AesGcm,
};
use anyhow::{anyhow, bail};
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use chacha20poly1305::ChaCha20Poly1305;
use getrandom::fill as random_fill;
use subtle::ConstantTimeEq;

use super::{
    config::{OpenVpnCipher, OpenVpnDigest},
    key_method::KeyMaterial,
    packet::{OpCode, ReplayWindow},
    wrap::compute_hmac,
};

const AEAD_NONCE_LEN: usize = 12;
const AEAD_TAG_LEN: usize = 16;
const CBC_IV_LEN: usize = 16;
const MAX_LZO_PACKET: usize = u16::MAX as usize;
const LZO_UNCOMPRESSED: u8 = 0xfa;
const LZO_COMPRESSED: u8 = 0x66;
pub(super) const OPENVPN_PING: [u8; 16] = [
    0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb, 0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7,
    0x48,
];

type Aes192Gcm = AesGcm<Aes192, U12>;

pub(super) struct DataChannel {
    cipher: OpenVpnCipher,
    auth: OpenVpnDigest,
    send_cipher: Vec<u8>,
    receive_cipher: Vec<u8>,
    send_hmac: [u8; 64],
    receive_hmac: [u8; 64],
    key_id: u8,
    peer_id: Option<u32>,
    compression_lzo: bool,
    next_packet_id: u32,
    replay: ReplayWindow,
}

impl DataChannel {
    pub(super) fn new(
        cipher: OpenVpnCipher,
        auth: OpenVpnDigest,
        keys: KeyMaterial,
        key_id: u8,
        peer_id: Option<u32>,
        compression_lzo: bool,
    ) -> anyhow::Result<Self> {
        if keys.send_cipher.len() != cipher.key_len()
            || keys.receive_cipher.len() != cipher.key_len()
            || key_id > 7
            || peer_id.is_some_and(|value| value > 0x00ff_ffff)
        {
            bail!("invalid OpenVPN data channel key material");
        }
        Ok(Self {
            cipher,
            auth,
            send_cipher: keys.send_cipher,
            receive_cipher: keys.receive_cipher,
            send_hmac: keys.send_hmac,
            receive_hmac: keys.receive_hmac,
            key_id,
            peer_id,
            compression_lzo,
            next_packet_id: 1,
            replay: ReplayWindow::new(),
        })
    }

    pub(super) fn encrypt(&mut self, payload: &[u8]) -> anyhow::Result<Vec<u8>> {
        let packet_id = self.allocate_packet_id()?;
        let payload = encode_compression(payload, self.compression_lzo);
        if self.cipher.is_aead() {
            self.encrypt_aead(packet_id, &payload)
        } else {
            self.encrypt_cbc(packet_id, &payload)
        }
    }

    pub(super) fn decrypt(&mut self, packet: &[u8]) -> anyhow::Result<Vec<u8>> {
        let header_len = validate_header(packet, self.key_id, self.peer_id)?;
        let plain = if self.cipher.is_aead() {
            self.decrypt_aead(packet, header_len)?
        } else {
            self.decrypt_cbc(packet, header_len)?
        };
        decode_compression(&plain, self.compression_lzo)
    }

    fn encrypt_aead(&self, packet_id: u32, payload: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut header = data_header(self.key_id, self.peer_id)?;
        let packet_id = packet_id.to_be_bytes();
        let mut nonce = [0u8; AEAD_NONCE_LEN];
        nonce[..4].copy_from_slice(&packet_id);
        nonce[4..].copy_from_slice(&self.send_hmac[..8]);
        let mut associated = header.clone();
        associated.extend_from_slice(&packet_id);
        let mut ciphertext = payload.to_vec();
        let tag = encrypt_aead(
            self.cipher,
            &self.send_cipher,
            &nonce,
            &associated,
            &mut ciphertext,
        )?;
        header.extend_from_slice(&packet_id);
        header.extend_from_slice(&tag);
        header.extend_from_slice(&ciphertext);
        Ok(header)
    }

    fn decrypt_aead(&mut self, packet: &[u8], header_len: usize) -> anyhow::Result<Vec<u8>> {
        if packet.len() < header_len + 4 + AEAD_TAG_LEN {
            bail!("OpenVPN AEAD data packet is truncated");
        }
        let packet_id_bytes: [u8; 4] = packet[header_len..header_len + 4].try_into()?;
        let packet_id = u32::from_be_bytes(packet_id_bytes);
        let tag: [u8; AEAD_TAG_LEN] = packet[header_len + 4..header_len + 4 + AEAD_TAG_LEN]
            .try_into()?;
        let mut nonce = [0u8; AEAD_NONCE_LEN];
        nonce[..4].copy_from_slice(&packet_id_bytes);
        nonce[4..].copy_from_slice(&self.receive_hmac[..8]);
        let associated = &packet[..header_len + 4];
        let mut plaintext = packet[header_len + 4 + AEAD_TAG_LEN..].to_vec();
        decrypt_aead(
            self.cipher,
            &self.receive_cipher,
            &nonce,
            associated,
            &tag,
            &mut plaintext,
        )?;
        if !self.replay.accept(packet_id) {
            bail!("OpenVPN data packet replay detected");
        }
        Ok(plaintext)
    }

    fn encrypt_cbc(&self, packet_id: u32, payload: &[u8]) -> anyhow::Result<Vec<u8>> {
        let header = data_header(self.key_id, self.peer_id)?;
        let mut plaintext = Vec::with_capacity(4 + payload.len() + CBC_IV_LEN);
        plaintext.extend_from_slice(&packet_id.to_be_bytes());
        plaintext.extend_from_slice(payload);
        let mut iv = [0u8; CBC_IV_LEN];
        random_fill(&mut iv)?;
        let ciphertext = cbc_encrypt(self.cipher, &self.send_cipher, &iv, &plaintext)?;
        let mut authenticated = Vec::with_capacity(iv.len() + ciphertext.len());
        authenticated.extend_from_slice(&iv);
        authenticated.extend_from_slice(&ciphertext);
        let tag = compute_hmac(self.auth, &self.send_hmac, &authenticated)?;
        let mut packet = header;
        packet.extend_from_slice(&tag);
        packet.extend_from_slice(&authenticated);
        Ok(packet)
    }

    fn decrypt_cbc(&mut self, packet: &[u8], header_len: usize) -> anyhow::Result<Vec<u8>> {
        let tag_len = self.auth.output_len();
        if packet.len() < header_len + tag_len + CBC_IV_LEN + CBC_IV_LEN {
            bail!("OpenVPN CBC data packet is truncated");
        }
        let tag = &packet[header_len..header_len + tag_len];
        let authenticated = &packet[header_len + tag_len..];
        let expected = compute_hmac(self.auth, &self.receive_hmac, authenticated)?;
        if tag.ct_eq(expected.as_slice()).unwrap_u8() != 1 {
            bail!("OpenVPN CBC data authentication failed");
        }
        let iv: [u8; CBC_IV_LEN] = authenticated[..CBC_IV_LEN].try_into()?;
        let mut plaintext = cbc_decrypt(
            self.cipher,
            &self.receive_cipher,
            &iv,
            &authenticated[CBC_IV_LEN..],
        )?;
        if plaintext.len() < 4 {
            bail!("OpenVPN CBC plaintext is missing its packet id");
        }
        let packet_id = u32::from_be_bytes(plaintext[..4].try_into()?);
        if !self.replay.accept(packet_id) {
            bail!("OpenVPN data packet replay detected");
        }
        plaintext.drain(..4);
        Ok(plaintext)
    }

    fn allocate_packet_id(&mut self) -> anyhow::Result<u32> {
        let packet_id = self.next_packet_id;
        self.next_packet_id = self
            .next_packet_id
            .checked_add(1)
            .ok_or_else(|| anyhow!("OpenVPN data packet id exhausted; renegotiation is required"))?;
        Ok(packet_id)
    }
}

fn data_header(key_id: u8, peer_id: Option<u32>) -> anyhow::Result<Vec<u8>> {
    let opcode = if peer_id.is_some() {
        OpCode::DataV2
    } else {
        OpCode::DataV1
    };
    let mut output = vec![opcode.header(key_id)?];
    if let Some(peer_id) = peer_id {
        let bytes = peer_id.to_be_bytes();
        output.extend_from_slice(&bytes[1..]);
    }
    Ok(output)
}

fn validate_header(packet: &[u8], key_id: u8, peer_id: Option<u32>) -> anyhow::Result<usize> {
    let expected = data_header(key_id, peer_id)?;
    if packet.len() < expected.len() || packet[..expected.len()] != expected {
        bail!("OpenVPN data packet header does not match the active key");
    }
    Ok(expected.len())
}

fn encrypt_aead(
    cipher: OpenVpnCipher,
    key: &[u8],
    nonce: &[u8; AEAD_NONCE_LEN],
    associated: &[u8],
    buffer: &mut [u8],
) -> anyhow::Result<[u8; AEAD_TAG_LEN]> {
    macro_rules! encrypt {
        ($ty:ty) => {{
            let cipher = <$ty>::new_from_slice(key)?;
            let tag = cipher
                .encrypt_in_place_detached(nonce.into(), associated, buffer)
                .map_err(|_| anyhow!("OpenVPN AEAD encryption failed"))?;
            Ok::<_, anyhow::Error>(tag.into())
        }};
    }
    match cipher {
        OpenVpnCipher::Aes128Gcm => encrypt!(Aes128Gcm),
        OpenVpnCipher::Aes192Gcm => encrypt!(Aes192Gcm),
        OpenVpnCipher::Aes256Gcm => encrypt!(Aes256Gcm),
        OpenVpnCipher::ChaCha20Poly1305 => encrypt!(ChaCha20Poly1305),
        _ => bail!("OpenVPN CBC cipher was passed to the AEAD encryptor"),
    }
}

fn decrypt_aead(
    cipher: OpenVpnCipher,
    key: &[u8],
    nonce: &[u8; AEAD_NONCE_LEN],
    associated: &[u8],
    tag: &[u8; AEAD_TAG_LEN],
    buffer: &mut [u8],
) -> anyhow::Result<()> {
    macro_rules! decrypt {
        ($ty:ty) => {{
            let cipher = <$ty>::new_from_slice(key)?;
            cipher
                .decrypt_in_place_detached(nonce.into(), associated, buffer, tag.into())
                .map_err(|_| anyhow!("OpenVPN AEAD authentication failed"))
        }};
    }
    match cipher {
        OpenVpnCipher::Aes128Gcm => decrypt!(Aes128Gcm),
        OpenVpnCipher::Aes192Gcm => decrypt!(Aes192Gcm),
        OpenVpnCipher::Aes256Gcm => decrypt!(Aes256Gcm),
        OpenVpnCipher::ChaCha20Poly1305 => decrypt!(ChaCha20Poly1305),
        _ => bail!("OpenVPN CBC cipher was passed to the AEAD decryptor"),
    }
}

fn cbc_encrypt(
    cipher: OpenVpnCipher,
    key: &[u8],
    iv: &[u8; CBC_IV_LEN],
    plaintext: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let capacity = plaintext.len() + CBC_IV_LEN;
    let mut buffer = vec![0; capacity];
    buffer[..plaintext.len()].copy_from_slice(plaintext);
    macro_rules! encrypt {
        ($ty:ty) => {{
            let cipher = cbc::Encryptor::<$ty>::new_from_slices(key, iv)?;
            cipher
                .encrypt_padded_mut::<Pkcs7>(&mut buffer, plaintext.len())
                .map_err(|_| anyhow!("OpenVPN CBC padding failed"))?
                .len()
        }};
    }
    let length = match cipher {
        OpenVpnCipher::Aes128Cbc => encrypt!(Aes128),
        OpenVpnCipher::Aes192Cbc => encrypt!(Aes192),
        OpenVpnCipher::Aes256Cbc => encrypt!(Aes256),
        _ => bail!("OpenVPN AEAD cipher was passed to the CBC encryptor"),
    };
    buffer.truncate(length);
    Ok(buffer)
}

fn cbc_decrypt(
    cipher: OpenVpnCipher,
    key: &[u8],
    iv: &[u8; CBC_IV_LEN],
    ciphertext: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let mut buffer = ciphertext.to_vec();
    macro_rules! decrypt {
        ($ty:ty) => {{
            let cipher = cbc::Decryptor::<$ty>::new_from_slices(key, iv)?;
            cipher
                .decrypt_padded_mut::<Pkcs7>(&mut buffer)
                .map_err(|_| anyhow!("OpenVPN CBC decryption or padding validation failed"))?
                .len()
        }};
    }
    let length = match cipher {
        OpenVpnCipher::Aes128Cbc => decrypt!(Aes128),
        OpenVpnCipher::Aes192Cbc => decrypt!(Aes192),
        OpenVpnCipher::Aes256Cbc => decrypt!(Aes256),
        _ => bail!("OpenVPN AEAD cipher was passed to the CBC decryptor"),
    };
    buffer.truncate(length);
    Ok(buffer)
}

fn encode_compression(payload: &[u8], enabled: bool) -> Vec<u8> {
    if !enabled {
        return payload.to_vec();
    }
    let mut output = Vec::with_capacity(payload.len() + 1);
    output.push(LZO_UNCOMPRESSED);
    output.extend_from_slice(payload);
    output
}

fn decode_compression(payload: &[u8], enabled: bool) -> anyhow::Result<Vec<u8>> {
    if !enabled {
        return Ok(payload.to_vec());
    }
    match payload.split_first() {
        Some((&LZO_UNCOMPRESSED, body)) => Ok(body.to_vec()),
        Some((&LZO_COMPRESSED, body)) => lzo::decompress(body, MAX_LZO_PACKET)
            .map_err(|error| anyhow!("OpenVPN LZO decompression failed: {error}")),
        Some((marker, _)) => bail!("unsupported OpenVPN compression marker {marker:#04x}"),
        None => bail!("OpenVPN compressed packet is empty"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys() -> (KeyMaterial, KeyMaterial) {
        let client = KeyMaterial {
            send_cipher: vec![0x11; 32],
            send_hmac: [0x22; 64],
            receive_cipher: vec![0x33; 32],
            receive_hmac: [0x44; 64],
        };
        let server = KeyMaterial {
            send_cipher: client.receive_cipher.clone(),
            send_hmac: client.receive_hmac,
            receive_cipher: client.send_cipher.clone(),
            receive_hmac: client.send_hmac,
        };
        (client, server)
    }

    #[test]
    fn aes_gcm_v2_round_trip_and_replay_rejection() {
        let (client_keys, server_keys) = keys();
        let mut client = DataChannel::new(
            OpenVpnCipher::Aes256Gcm,
            OpenVpnDigest::Sha256,
            client_keys,
            0,
            Some(7),
            false,
        )
        .unwrap();
        let mut server = DataChannel::new(
            OpenVpnCipher::Aes256Gcm,
            OpenVpnDigest::Sha256,
            server_keys,
            0,
            Some(7),
            false,
        )
        .unwrap();
        let packet = client.encrypt(b"hello").unwrap();
        assert_eq!(server.decrypt(&packet).unwrap(), b"hello");
        assert!(server.decrypt(&packet).is_err());
    }

    #[test]
    fn aes_cbc_sha1_round_trip() {
        let (mut client_keys, mut server_keys) = keys();
        client_keys.send_cipher.truncate(24);
        client_keys.receive_cipher.truncate(24);
        server_keys.send_cipher.truncate(24);
        server_keys.receive_cipher.truncate(24);
        let mut client = DataChannel::new(
            OpenVpnCipher::Aes192Cbc,
            OpenVpnDigest::Sha1,
            client_keys,
            1,
            None,
            true,
        )
        .unwrap();
        let mut server = DataChannel::new(
            OpenVpnCipher::Aes192Cbc,
            OpenVpnDigest::Sha1,
            server_keys,
            1,
            None,
            true,
        )
        .unwrap();
        let packet = client.encrypt(b"payload").unwrap();
        assert_eq!(server.decrypt(&packet).unwrap(), b"payload");
    }
}
