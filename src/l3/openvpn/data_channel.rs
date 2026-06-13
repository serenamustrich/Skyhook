use anyhow::anyhow;

const AEAD_TAG_LEN: usize = 16;
const AEAD_NONCE_LEN: usize = 12;
const PACKET_ID_LEN: usize = 4;

#[derive(Debug)]
pub struct OpenVpnDataChannel {
    cipher: DataCipher,
    encrypt_key: Vec<u8>,
    decrypt_key: Vec<u8>,
    encrypt_nonce: u64,
    decrypt_nonce: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataCipher {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
}

impl DataCipher {
    pub fn key_len(&self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            Self::Aes256Gcm => 32,
            Self::ChaCha20Poly1305 => 32,
        }
    }

    pub fn parse_from_str(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "aes-128-gcm" => Some(Self::Aes128Gcm),
            "aes-256-gcm" => Some(Self::Aes256Gcm),
            "chacha20-poly1305" => Some(Self::ChaCha20Poly1305),
            _ => None,
        }
    }
}

impl OpenVpnDataChannel {
    pub fn new(
        cipher: DataCipher,
        encrypt_key: Vec<u8>,
        decrypt_key: Vec<u8>,
    ) -> anyhow::Result<Self> {
        if encrypt_key.len() != cipher.key_len() {
            return Err(anyhow!("invalid encrypt key length"));
        }
        if decrypt_key.len() != cipher.key_len() {
            return Err(anyhow!("invalid decrypt key length"));
        }
        Ok(Self {
            cipher,
            encrypt_key,
            decrypt_key,
            encrypt_nonce: 0,
            decrypt_nonce: 0,
        })
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
        let nonce = self.next_encrypt_nonce();
        let (ciphertext, tag) = self.encrypt_inner(plaintext, &nonce)?;

        let mut output =
            Vec::with_capacity(PACKET_ID_LEN + AEAD_NONCE_LEN + ciphertext.len() + AEAD_TAG_LEN);
        output.extend_from_slice(&(self.encrypt_nonce as u32).to_be_bytes());
        output.extend_from_slice(&nonce);
        output.extend_from_slice(&ciphertext);
        output.extend_from_slice(&tag);

        Ok(output)
    }

    pub fn decrypt(&mut self, ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
        if ciphertext.len() < PACKET_ID_LEN + AEAD_NONCE_LEN + AEAD_TAG_LEN {
            return Err(anyhow!("ciphertext too short"));
        }

        let nonce = &ciphertext[PACKET_ID_LEN..PACKET_ID_LEN + AEAD_NONCE_LEN];
        let encrypted =
            &ciphertext[PACKET_ID_LEN + AEAD_NONCE_LEN..ciphertext.len() - AEAD_TAG_LEN];
        let tag = &ciphertext[ciphertext.len() - AEAD_TAG_LEN..];

        let plaintext = self.decrypt_inner(encrypted, nonce, tag)?;
        self.decrypt_nonce += 1;
        Ok(plaintext)
    }

    fn encrypt_inner(&self, plaintext: &[u8], nonce: &[u8]) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
        match self.cipher {
            DataCipher::Aes128Gcm => {
                use aes_gcm::aead::generic_array::GenericArray;
                use aes_gcm::{AeadInPlace, KeyInit};
                let key = aes_gcm::Key::<aes_gcm::Aes128Gcm>::from_slice(&self.encrypt_key);
                let cipher = aes_gcm::Aes128Gcm::new(key);
                let nonce = GenericArray::from_slice(nonce);
                let mut buffer = plaintext.to_vec();
                let tag = cipher
                    .encrypt_in_place_detached(nonce, b"", &mut buffer)
                    .map_err(|e| anyhow!("AES-128-GCM encrypt failed: {e}"))?;
                Ok((buffer, tag.to_vec()))
            }
            DataCipher::Aes256Gcm => {
                use aes_gcm::aead::generic_array::GenericArray;
                use aes_gcm::{AeadInPlace, KeyInit};
                let key = aes_gcm::Key::<aes_gcm::Aes256Gcm>::from_slice(&self.encrypt_key);
                let cipher = aes_gcm::Aes256Gcm::new(key);
                let nonce = GenericArray::from_slice(nonce);
                let mut buffer = plaintext.to_vec();
                let tag = cipher
                    .encrypt_in_place_detached(nonce, b"", &mut buffer)
                    .map_err(|e| anyhow!("AES-256-GCM encrypt failed: {e}"))?;
                Ok((buffer, tag.to_vec()))
            }
            DataCipher::ChaCha20Poly1305 => {
                use chacha20poly1305::aead::generic_array::GenericArray;
                use chacha20poly1305::{AeadInPlace, KeyInit};
                let key = chacha20poly1305::Key::from_slice(&self.encrypt_key);
                let cipher = chacha20poly1305::ChaCha20Poly1305::new(key);
                let nonce = GenericArray::from_slice(nonce);
                let mut buffer = plaintext.to_vec();
                let tag = cipher
                    .encrypt_in_place_detached(nonce, b"", &mut buffer)
                    .map_err(|e| anyhow!("ChaCha20 encrypt failed: {e}"))?;
                Ok((buffer, tag.to_vec()))
            }
        }
    }

    fn decrypt_inner(&self, encrypted: &[u8], nonce: &[u8], tag: &[u8]) -> anyhow::Result<Vec<u8>> {
        match self.cipher {
            DataCipher::Aes128Gcm => {
                use aes_gcm::aead::generic_array::GenericArray;
                use aes_gcm::{AeadInPlace, KeyInit};
                let key = aes_gcm::Key::<aes_gcm::Aes128Gcm>::from_slice(&self.decrypt_key);
                let cipher = aes_gcm::Aes128Gcm::new(key);
                let nonce = GenericArray::from_slice(nonce);
                let tag = GenericArray::from_slice(tag);
                let mut buffer = encrypted.to_vec();
                cipher
                    .decrypt_in_place_detached(nonce, b"", &mut buffer, tag)
                    .map_err(|e| anyhow!("AES-128-GCM decrypt failed: {e}"))?;
                Ok(buffer)
            }
            DataCipher::Aes256Gcm => {
                use aes_gcm::aead::generic_array::GenericArray;
                use aes_gcm::{AeadInPlace, KeyInit};
                let key = aes_gcm::Key::<aes_gcm::Aes256Gcm>::from_slice(&self.decrypt_key);
                let cipher = aes_gcm::Aes256Gcm::new(key);
                let nonce = GenericArray::from_slice(nonce);
                let tag = GenericArray::from_slice(tag);
                let mut buffer = encrypted.to_vec();
                cipher
                    .decrypt_in_place_detached(nonce, b"", &mut buffer, tag)
                    .map_err(|e| anyhow!("AES-256-GCM decrypt failed: {e}"))?;
                Ok(buffer)
            }
            DataCipher::ChaCha20Poly1305 => {
                use chacha20poly1305::aead::generic_array::GenericArray;
                use chacha20poly1305::{AeadInPlace, KeyInit};
                let key = chacha20poly1305::Key::from_slice(&self.decrypt_key);
                let cipher = chacha20poly1305::ChaCha20Poly1305::new(key);
                let nonce = GenericArray::from_slice(nonce);
                let tag = GenericArray::from_slice(tag);
                let mut buffer = encrypted.to_vec();
                cipher
                    .decrypt_in_place_detached(nonce, b"", &mut buffer, tag)
                    .map_err(|e| anyhow!("ChaCha20 decrypt failed: {e}"))?;
                Ok(buffer)
            }
        }
    }

    fn next_encrypt_nonce(&mut self) -> [u8; AEAD_NONCE_LEN] {
        self.encrypt_nonce += 1;
        let mut nonce = [0u8; AEAD_NONCE_LEN];
        nonce[4..12].copy_from_slice(&self.encrypt_nonce.to_be_bytes());
        nonce
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes128gcm_encrypt_decrypt_roundtrip() {
        let key = vec![0x42u8; 16];
        let mut channel = OpenVpnDataChannel::new(DataCipher::Aes128Gcm, key.clone(), key).unwrap();
        let plaintext = b"hello world from OpenVPN data channel";
        let encrypted = channel.encrypt(plaintext).unwrap();
        let decrypted = channel.decrypt(&encrypted).unwrap();
        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn aes256gcm_encrypt_decrypt_roundtrip() {
        let key = vec![0x42u8; 32];
        let mut channel = OpenVpnDataChannel::new(DataCipher::Aes256Gcm, key.clone(), key).unwrap();
        let plaintext = b"test AES-256-GCM encryption";
        let encrypted = channel.encrypt(plaintext).unwrap();
        let decrypted = channel.decrypt(&encrypted).unwrap();
        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn chacha20_encrypt_decrypt_roundtrip() {
        let key = vec![0x42u8; 32];
        let mut channel =
            OpenVpnDataChannel::new(DataCipher::ChaCha20Poly1305, key.clone(), key).unwrap();
        let plaintext = b"test ChaCha20-Poly1305 encryption";
        let encrypted = channel.encrypt(plaintext).unwrap();
        let decrypted = channel.decrypt(&encrypted).unwrap();
        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn cipher_from_str() {
        assert_eq!(
            DataCipher::parse_from_str("aes-128-gcm"),
            Some(DataCipher::Aes128Gcm)
        );
        assert_eq!(
            DataCipher::parse_from_str("AES-256-GCM"),
            Some(DataCipher::Aes256Gcm)
        );
        assert_eq!(
            DataCipher::parse_from_str("chacha20-poly1305"),
            Some(DataCipher::ChaCha20Poly1305)
        );
        assert_eq!(DataCipher::parse_from_str("unknown"), None);
    }

    #[test]
    fn invalid_key_length() {
        let key = vec![0u8; 10];
        let result = OpenVpnDataChannel::new(DataCipher::Aes128Gcm, key.clone(), key);
        assert!(result.is_err());
    }
}
