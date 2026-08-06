//! 6.4.1 + 6.4.7 Shadowsocks / ShadowsocksR 真实拨号测试
//!
//! 覆盖：
//! - SS AEAD 3 cipher (aes-128-gcm / aes-256-gcm / chacha20-ietf-poly1305) 真实握手
//! - SS 2022-blake3-aes-128-gcm 配置解析
//! - SSR 配置 build 不 panic
//! - SSR UDP 显式 unsupported
//! - Shadowsocks plugin 配置解析
//!
//! 关键约束：
//! - 内部 cipher (SsCipher) 是 mod.rs private，不直接 import
//! - mock server 用 RustCrypto crate (aes-gcm, chacha20poly1305) 重新实现等价 AEAD
//! - 用 build_outbounds 拿真实 ShadowsocksOutbound，调真实 connect 路径

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use aes::{
    cipher::{
        inout::InOut, Block, BlockBackend, BlockCipher, BlockClosure, BlockDecrypt, BlockEncrypt,
        BlockSizeUser, Key, KeyInit as BlockKeyInit, KeySizeUser, ParBlocksSizeUser,
    },
    Aes128, Aes192, Aes256,
};
use aes_gcm::{
    aead::{consts::U12, consts::U16, Aead},
    Aes128Gcm, Aes256Gcm, AesGcm, Nonce as AesNonce,
};
use base64::Engine;
use ccm::Ccm;
use chacha20poly1305::{
    ChaCha20Poly1305, ChaCha8Poly1305, Nonce as ChaNonce, XChaCha20Poly1305, XChaCha8Poly1305,
};
use hkdf::Hkdf;
use md5::{Digest, Md5};
use sha1::Sha1;
use shadowsocks::{
    config::{ServerConfig as ShadowsocksServerConfig, ServerType},
    context::Context as ShadowsocksContext,
    crypto::CipherKind,
    relay::{
        socks5::Address as ShadowsocksAddress,
        tcprelay::proxy_stream::ProxyServerStream,
        udprelay::{
            crypto_io::{decrypt_client_payload, encrypt_server_payload},
            options::UdpSocketControlData,
        },
    },
    ServerAddr,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
    time::timeout,
};

use supercore::{
    config::{CoreConfig, OutboundConfig, SuperConfig},
    outbound::context::DialContext,
    outbound::{build_outbounds, encode_socks5_destination, OutboundMap},
    routing::Destination,
};

#[path = "../src/outbound/rabbit_compat.rs"]
mod rabbit_compat;

macro_rules! define_test_lea_adapter {
    ($adapter:ident, $backend:ident, $lea:ty, $key_size:ty) => {
        struct $adapter($lea);

        impl KeySizeUser for $adapter {
            type KeySize = $key_size;
        }

        impl BlockSizeUser for $adapter {
            type BlockSize = U16;
        }

        impl BlockCipher for $adapter {}

        impl BlockKeyInit for $adapter {
            fn new(key: &Key<Self>) -> Self {
                let legacy_key = lea::cipher::generic_array::GenericArray::clone_from_slice(key);
                Self(<$lea as lea::cipher::NewBlockCipher>::new(&legacy_key))
            }
        }

        struct $backend<'a>(&'a $adapter);

        impl BlockSizeUser for $backend<'_> {
            type BlockSize = U16;
        }

        impl ParBlocksSizeUser for $backend<'_> {
            type ParBlocksSize = aes::cipher::consts::U1;
        }

        impl BlockBackend for $backend<'_> {
            fn proc_block(&mut self, mut block: InOut<'_, '_, Block<Self>>) {
                let mut legacy_block =
                    lea::cipher::generic_array::GenericArray::clone_from_slice(block.get_in());
                lea::cipher::BlockEncrypt::encrypt_block(&self.0 .0, &mut legacy_block);
                block.get_out().copy_from_slice(&legacy_block);
            }
        }

        impl BlockEncrypt for $adapter {
            fn encrypt_with_backend(&self, f: impl BlockClosure<BlockSize = U16>) {
                f.call(&mut $backend(self));
            }
        }
    };
}

define_test_lea_adapter!(
    TestLea128Adapter,
    TestLea128EncryptBackend,
    lea::Lea128,
    U16
);
define_test_lea_adapter!(
    TestLea192Adapter,
    TestLea192EncryptBackend,
    lea::Lea192,
    aes::cipher::consts::U24
);
define_test_lea_adapter!(
    TestLea256Adapter,
    TestLea256EncryptBackend,
    lea::Lea256,
    aes::cipher::consts::U32
);

type TestLea128Gcm = AesGcm<TestLea128Adapter, U12>;
type TestLea192Gcm = AesGcm<TestLea192Adapter, U12>;
type TestLea256Gcm = AesGcm<TestLea256Adapter, U12>;

fn test_encrypt_aegis(
    method: &str,
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let (mut ciphertext, tag) = match method {
        "aegis-128l" => {
            let key: [u8; 16] = key.try_into()?;
            let nonce: [u8; 16] = nonce.try_into()?;
            let (ciphertext, tag) =
                aegis::aegis128l::Aegis128L::<16>::new(&key, &nonce).encrypt(plaintext, &[]);
            (ciphertext, tag)
        }
        "aegis-256" => {
            let key: [u8; 32] = key.try_into()?;
            let nonce: [u8; 32] = nonce.try_into()?;
            let (ciphertext, tag) =
                aegis::aegis256::Aegis256::<16>::new(&key, &nonce).encrypt(plaintext, &[]);
            (ciphertext, tag)
        }
        _ => return Err(anyhow::anyhow!("unsupported test AEGIS method {method}")),
    };
    ciphertext.extend_from_slice(&tag);
    Ok(ciphertext)
}

fn test_decrypt_aegis(
    method: &str,
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let split = ciphertext
        .len()
        .checked_sub(16)
        .ok_or_else(|| anyhow::anyhow!("short test AEGIS ciphertext"))?;
    let tag: [u8; 16] = ciphertext[split..].try_into()?;
    match method {
        "aegis-128l" => {
            let key: [u8; 16] = key.try_into()?;
            let nonce: [u8; 16] = nonce.try_into()?;
            aegis::aegis128l::Aegis128L::<16>::new(&key, &nonce)
                .decrypt(&ciphertext[..split], &tag, &[])
                .map_err(|_| anyhow::anyhow!("test AEGIS decryption failed"))
        }
        "aegis-256" => {
            let key: [u8; 32] = key.try_into()?;
            let nonce: [u8; 32] = nonce.try_into()?;
            aegis::aegis256::Aegis256::<16>::new(&key, &nonce)
                .decrypt(&ciphertext[..split], &tag, &[])
                .map_err(|_| anyhow::anyhow!("test AEGIS decryption failed"))
        }
        _ => Err(anyhow::anyhow!("unsupported test AEGIS method {method}")),
    }
}

fn test_crypt_deoxys(
    encrypt: bool,
    key: &[u8],
    nonce: &[u8],
    input: &[u8],
) -> anyhow::Result<Vec<u8>> {
    use deoxys::aead::{Aead, KeyInit};

    let cipher = deoxys::DeoxysII256::new_from_slice(key)
        .map_err(|_| anyhow::anyhow!("invalid test Deoxys key"))?;
    let nonce: &deoxys::Nonce<deoxys::consts::U15> = nonce.try_into()?;
    if encrypt {
        cipher
            .encrypt(nonce, input)
            .map_err(|_| anyhow::anyhow!("test Deoxys encryption failed"))
    } else {
        cipher
            .decrypt(nonce, input)
            .map_err(|_| anyhow::anyhow!("test Deoxys decryption failed"))
    }
}

fn test_crypt_ascon(
    method: &str,
    encrypt: bool,
    key: &[u8],
    nonce: &[u8],
    input: &[u8],
) -> anyhow::Result<Vec<u8>> {
    use ascon_aead::aead::{Aead, KeyInit};

    match method {
        "ascon128" => {
            let cipher = ascon_aead::Ascon128::new_from_slice(key)?;
            let nonce = ascon_aead::Nonce::<ascon_aead::Ascon128>::from_slice(nonce);
            if encrypt {
                Ok(cipher
                    .encrypt(nonce, input)
                    .map_err(|_| anyhow::anyhow!("test Ascon encryption failed"))?)
            } else {
                Ok(cipher
                    .decrypt(nonce, input)
                    .map_err(|_| anyhow::anyhow!("test Ascon decryption failed"))?)
            }
        }
        "ascon128a" => {
            let cipher = ascon_aead::Ascon128a::new_from_slice(key)?;
            let nonce = ascon_aead::Nonce::<ascon_aead::Ascon128a>::from_slice(nonce);
            if encrypt {
                Ok(cipher
                    .encrypt(nonce, input)
                    .map_err(|_| anyhow::anyhow!("test Ascon encryption failed"))?)
            } else {
                Ok(cipher
                    .decrypt(nonce, input)
                    .map_err(|_| anyhow::anyhow!("test Ascon decryption failed"))?)
            }
        }
        _ => Err(anyhow::anyhow!("unsupported test Ascon method {method}")),
    }
}

// ---------------------------------------------------------------------------
// Test-side cipher helpers (mirror src/outbound/mod.rs:7000-7111)
// ---------------------------------------------------------------------------
// (The mock server only DECRYPTS the production client's first frame, so we
// don't need a symmetric ss_handshake_send helper.  The dead `ss_handshake_send`
// helper has been removed; production key derivation is in mod.rs.)

/// Server-side: read salt + encrypted addr, decrypt, parse SOCKS5-style addr.
async fn ss_server_handshake(
    stream: &mut tokio::net::TcpStream,
    method: &str,
    password: &[u8],
) -> anyhow::Result<(String, u16, Vec<u8>, Vec<u8>)> {
    let key_len = legacy_ss_key_len(method)?;
    let master_key = evp_bytes_to_key_test(password, key_len);
    let mut salt = vec![0u8; key_len];
    stream.read_exact(&mut salt).await?;
    let subkey = legacy_ss_subkey(&master_key, &salt, key_len)?;
    let mut nonce = vec![0u8; legacy_ss_nonce_len(method)?];
    let plaintext = read_legacy_ss_chunk(stream, method, &subkey, &mut nonce).await?;
    if plaintext.is_empty() {
        return Err(anyhow::anyhow!("empty Shadowsocks request"));
    }
    let atyp = plaintext[0];
    let mut pos = 1;
    let host = match atyp {
        0x01 => {
            let ip = std::net::Ipv4Addr::new(
                plaintext[pos],
                plaintext[pos + 1],
                plaintext[pos + 2],
                plaintext[pos + 3],
            );
            pos += 4;
            format!("{ip}")
        }
        0x03 => {
            let len = plaintext[pos] as usize;
            pos += 1;
            let s = std::str::from_utf8(&plaintext[pos..pos + len])?.to_string();
            pos += len;
            s
        }
        _ => return Err(anyhow::anyhow!("bad atyp {atyp}")),
    };
    if plaintext.len() < pos + 2 {
        return Err(anyhow::anyhow!("short port"));
    }
    let port = u16::from_be_bytes([plaintext[pos], plaintext[pos + 1]]);
    Ok((host, port, subkey, nonce))
}

fn legacy_ss_key_len(method: &str) -> anyhow::Result<usize> {
    match method {
        "aes-128-gcm" | "lea-128-gcm" | "aegis-128l" | "ascon128" | "ascon128a"
        | "rabbit128-poly1305" => Ok(16),
        "aes-192-gcm" | "aes-192-ccm" | "lea-192-gcm" => Ok(24),
        "aes-256-gcm"
        | "lea-256-gcm"
        | "aegis-256"
        | "deoxys-ii-256-128"
        | "chacha20-ietf-poly1305"
        | "chacha8-ietf-poly1305"
        | "xchacha8-ietf-poly1305" => Ok(32),
        "aez-384" => Ok(48),
        _ => Err(anyhow::anyhow!("unsupported legacy test method {method}")),
    }
}

fn legacy_ss_nonce_len(method: &str) -> anyhow::Result<usize> {
    match method {
        "rabbit128-poly1305" => Ok(8),
        "xchacha8-ietf-poly1305" => Ok(24),
        "aegis-128l" | "aez-384" | "ascon128" | "ascon128a" => Ok(16),
        "aegis-256" => Ok(32),
        "deoxys-ii-256-128" => Ok(15),
        _ => {
            legacy_ss_key_len(method)?;
            Ok(12)
        }
    }
}

fn evp_bytes_to_key_test(password: &[u8], key_len: usize) -> Vec<u8> {
    let mut key = Vec::with_capacity(key_len);
    let mut previous = Vec::new();
    while key.len() < key_len {
        let mut digest = Md5::new();
        if !previous.is_empty() {
            digest.update(&previous);
        }
        digest.update(password);
        previous = digest.finalize().to_vec();
        key.extend_from_slice(&previous);
    }
    key.truncate(key_len);
    key
}

fn legacy_ss_subkey(master_key: &[u8], salt: &[u8], key_len: usize) -> anyhow::Result<Vec<u8>> {
    let hkdf = Hkdf::<Sha1>::new(Some(salt), master_key);
    let mut subkey = vec![0u8; key_len];
    hkdf.expand(b"ss-subkey", &mut subkey)
        .map_err(|_| anyhow::anyhow!("legacy Shadowsocks subkey derivation failed"))?;
    Ok(subkey)
}

fn legacy_ss_decrypt(
    method: &str,
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
) -> anyhow::Result<Vec<u8>> {
    match method {
        "aes-128-gcm" => Ok(Aes128Gcm::new_from_slice(key)?
            .decrypt(AesNonce::from_slice(nonce), ciphertext)
            .map_err(|_| anyhow::anyhow!("legacy aes-128 decrypt failed"))?),
        "aes-192-gcm" => Ok(AesGcm::<Aes192, U12>::new_from_slice(key)?
            .decrypt(AesNonce::from_slice(nonce), ciphertext)
            .map_err(|_| anyhow::anyhow!("legacy aes-192 decrypt failed"))?),
        "aes-256-gcm" => Ok(Aes256Gcm::new_from_slice(key)?
            .decrypt(AesNonce::from_slice(nonce), ciphertext)
            .map_err(|_| anyhow::anyhow!("legacy aes-256 decrypt failed"))?),
        "aes-192-ccm" => Ok(Ccm::<Aes192, U16, U12>::new_from_slice(key)?
            .decrypt(ccm::Nonce::<U12>::from_slice(nonce), ciphertext)
            .map_err(|_| anyhow::anyhow!("legacy aes-192-ccm decrypt failed"))?),
        "lea-128-gcm" => Ok(TestLea128Gcm::new_from_slice(key)?
            .decrypt(AesNonce::from_slice(nonce), ciphertext)
            .map_err(|_| anyhow::anyhow!("legacy lea-128 decrypt failed"))?),
        "lea-192-gcm" => Ok(TestLea192Gcm::new_from_slice(key)?
            .decrypt(AesNonce::from_slice(nonce), ciphertext)
            .map_err(|_| anyhow::anyhow!("legacy lea-192 decrypt failed"))?),
        "lea-256-gcm" => Ok(TestLea256Gcm::new_from_slice(key)?
            .decrypt(AesNonce::from_slice(nonce), ciphertext)
            .map_err(|_| anyhow::anyhow!("legacy lea-256 decrypt failed"))?),
        "aegis-128l" | "aegis-256" => test_decrypt_aegis(method, key, nonce, ciphertext),
        "aez-384" => zears::Aez::new(key)
            .decrypt(nonce, &[], 16, ciphertext)
            .ok_or_else(|| anyhow::anyhow!("test AEZ decryption failed")),
        "deoxys-ii-256-128" => test_crypt_deoxys(false, key, nonce, ciphertext),
        "ascon128" | "ascon128a" => test_crypt_ascon(method, false, key, nonce, ciphertext),
        "rabbit128-poly1305" => test_decrypt_rabbit_poly1305(key, nonce, ciphertext),
        "chacha20-ietf-poly1305" => Ok(ChaCha20Poly1305::new_from_slice(key)?
            .decrypt(ChaNonce::from_slice(nonce), ciphertext)
            .map_err(|_| anyhow::anyhow!("legacy chacha decrypt failed"))?),
        "chacha8-ietf-poly1305" => Ok(ChaCha8Poly1305::new_from_slice(key)?
            .decrypt(ChaNonce::from_slice(nonce), ciphertext)
            .map_err(|_| anyhow::anyhow!("legacy chacha8 decrypt failed"))?),
        "xchacha8-ietf-poly1305" => Ok(XChaCha8Poly1305::new_from_slice(key)?
            .decrypt(chacha20poly1305::XNonce::from_slice(nonce), ciphertext)
            .map_err(|_| anyhow::anyhow!("legacy xchacha8 decrypt failed"))?),
        _ => Err(anyhow::anyhow!("unsupported legacy method {method}")),
    }
}

fn legacy_ss_encrypt(
    method: &str,
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
) -> anyhow::Result<Vec<u8>> {
    match method {
        "aes-128-gcm" => Ok(Aes128Gcm::new_from_slice(key)?
            .encrypt(AesNonce::from_slice(nonce), plaintext)
            .map_err(|_| anyhow::anyhow!("legacy aes-128 encrypt failed"))?),
        "aes-192-gcm" => Ok(AesGcm::<Aes192, U12>::new_from_slice(key)?
            .encrypt(AesNonce::from_slice(nonce), plaintext)
            .map_err(|_| anyhow::anyhow!("legacy aes-192 encrypt failed"))?),
        "aes-256-gcm" => Ok(Aes256Gcm::new_from_slice(key)?
            .encrypt(AesNonce::from_slice(nonce), plaintext)
            .map_err(|_| anyhow::anyhow!("legacy aes-256 encrypt failed"))?),
        "aes-192-ccm" => Ok(Ccm::<Aes192, U16, U12>::new_from_slice(key)?
            .encrypt(ccm::Nonce::<U12>::from_slice(nonce), plaintext)
            .map_err(|_| anyhow::anyhow!("legacy aes-192-ccm encrypt failed"))?),
        "lea-128-gcm" => Ok(TestLea128Gcm::new_from_slice(key)?
            .encrypt(AesNonce::from_slice(nonce), plaintext)
            .map_err(|_| anyhow::anyhow!("legacy lea-128 encrypt failed"))?),
        "lea-192-gcm" => Ok(TestLea192Gcm::new_from_slice(key)?
            .encrypt(AesNonce::from_slice(nonce), plaintext)
            .map_err(|_| anyhow::anyhow!("legacy lea-192 encrypt failed"))?),
        "lea-256-gcm" => Ok(TestLea256Gcm::new_from_slice(key)?
            .encrypt(AesNonce::from_slice(nonce), plaintext)
            .map_err(|_| anyhow::anyhow!("legacy lea-256 encrypt failed"))?),
        "aegis-128l" | "aegis-256" => test_encrypt_aegis(method, key, nonce, plaintext),
        "aez-384" => Ok(zears::Aez::new(key).encrypt(nonce, &[], 16, plaintext)),
        "deoxys-ii-256-128" => test_crypt_deoxys(true, key, nonce, plaintext),
        "ascon128" | "ascon128a" => test_crypt_ascon(method, true, key, nonce, plaintext),
        "rabbit128-poly1305" => test_encrypt_rabbit_poly1305(key, nonce, plaintext),
        "chacha20-ietf-poly1305" => Ok(ChaCha20Poly1305::new_from_slice(key)?
            .encrypt(ChaNonce::from_slice(nonce), plaintext)
            .map_err(|_| anyhow::anyhow!("legacy chacha encrypt failed"))?),
        "chacha8-ietf-poly1305" => Ok(ChaCha8Poly1305::new_from_slice(key)?
            .encrypt(ChaNonce::from_slice(nonce), plaintext)
            .map_err(|_| anyhow::anyhow!("legacy chacha8 encrypt failed"))?),
        "xchacha8-ietf-poly1305" => Ok(XChaCha8Poly1305::new_from_slice(key)?
            .encrypt(chacha20poly1305::XNonce::from_slice(nonce), plaintext)
            .map_err(|_| anyhow::anyhow!("legacy xchacha8 encrypt failed"))?),
        _ => Err(anyhow::anyhow!("unsupported legacy method {method}")),
    }
}

fn test_rabbit_poly1305_tag(
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
) -> anyhow::Result<[u8; 16]> {
    use poly1305::universal_hash::{KeyInit, UniversalHash};

    let mut one_time_key = [0u8; poly1305::KEY_SIZE];
    let mut rabbit = rabbit_compat::RabbitCompat::new(key, nonce)?;
    rabbit.apply_keystream(&mut one_time_key);
    let mut authenticator = poly1305::Poly1305::new((&one_time_key).into());
    authenticator.update_padded(&[]);
    authenticator.update_padded(ciphertext);
    let mut lengths = poly1305::Block::default();
    lengths[8..].copy_from_slice(&(ciphertext.len() as u64).to_le_bytes());
    authenticator.update(&[lengths]);
    Ok(authenticator.finalize().into())
}

fn test_encrypt_rabbit_poly1305(
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let mut ciphertext = plaintext.to_vec();
    let mut rabbit = rabbit_compat::RabbitCompat::new(key, nonce)?;
    rabbit.apply_keystream(&mut ciphertext);
    let tag = test_rabbit_poly1305_tag(key, nonce, &ciphertext)?;
    ciphertext.extend_from_slice(&tag);
    Ok(ciphertext)
}

fn test_decrypt_rabbit_poly1305(
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
) -> anyhow::Result<Vec<u8>> {
    use subtle::ConstantTimeEq;

    let split = ciphertext
        .len()
        .checked_sub(16)
        .ok_or_else(|| anyhow::anyhow!("short Rabbit ciphertext"))?;
    let expected = test_rabbit_poly1305_tag(key, nonce, &ciphertext[..split])?;
    if !bool::from(expected.ct_eq(&ciphertext[split..])) {
        return Err(anyhow::anyhow!("Rabbit authentication failed"));
    }
    let mut plaintext = ciphertext[..split].to_vec();
    let mut rabbit = rabbit_compat::RabbitCompat::new(key, nonce)?;
    rabbit.apply_keystream(&mut plaintext);
    Ok(plaintext)
}

async fn read_legacy_ss_chunk(
    stream: &mut tokio::net::TcpStream,
    method: &str,
    key: &[u8],
    nonce: &mut [u8],
) -> anyhow::Result<Vec<u8>> {
    let mut encrypted_length = [0u8; 18];
    stream.read_exact(&mut encrypted_length).await?;
    let length = legacy_ss_decrypt(method, key, nonce, &encrypted_length)?;
    increment_nonce(nonce);
    if length.len() != 2 {
        return Err(anyhow::anyhow!("invalid Shadowsocks length chunk"));
    }
    let payload_length = u16::from_be_bytes([length[0], length[1]]) as usize;
    let mut encrypted_payload = vec![0u8; payload_length + 16];
    stream.read_exact(&mut encrypted_payload).await?;
    let payload = legacy_ss_decrypt(method, key, nonce, &encrypted_payload)?;
    increment_nonce(nonce);
    Ok(payload)
}

fn encode_legacy_ss_chunk(
    method: &str,
    key: &[u8],
    nonce: &mut [u8],
    payload: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let mut output = legacy_ss_encrypt(method, key, nonce, &(payload.len() as u16).to_be_bytes())?;
    increment_nonce(nonce);
    output.extend_from_slice(&legacy_ss_encrypt(method, key, nonce, payload)?);
    increment_nonce(nonce);
    Ok(output)
}

fn increment_nonce(nonce: &mut [u8]) {
    for byte in nonce {
        let (next, overflow) = byte.overflowing_add(1);
        *byte = next;
        if !overflow {
            break;
        }
    }
}

fn ss2022_subkey(psk: &[u8], salt: &[u8], key_len: usize) -> Vec<u8> {
    let mut material = Vec::with_capacity(psk.len() + salt.len());
    material.extend_from_slice(psk);
    material.extend_from_slice(salt);
    blake3::derive_key("shadowsocks 2022 session subkey", &material)[..key_len].to_vec()
}

fn ss2022_decrypt(
    method: &str,
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
) -> anyhow::Result<Vec<u8>> {
    match method {
        "2022-blake3-aes-128-gcm" => Ok(Aes128Gcm::new_from_slice(key)?
            .decrypt(AesNonce::from_slice(nonce), ciphertext)
            .map_err(|_| anyhow::anyhow!("ss2022 aes-128 decrypt failed"))?),
        "2022-blake3-aes-256-gcm" => Ok(Aes256Gcm::new_from_slice(key)?
            .decrypt(AesNonce::from_slice(nonce), ciphertext)
            .map_err(|_| anyhow::anyhow!("ss2022 aes-256 decrypt failed"))?),
        "2022-blake3-chacha20-poly1305" => Ok(ChaCha20Poly1305::new_from_slice(key)?
            .decrypt(ChaNonce::from_slice(nonce), ciphertext)
            .map_err(|_| anyhow::anyhow!("ss2022 chacha decrypt failed"))?),
        "2022-blake3-chacha8-poly1305" => Ok(ChaCha8Poly1305::new_from_slice(key)?
            .decrypt(ChaNonce::from_slice(nonce), ciphertext)
            .map_err(|_| anyhow::anyhow!("ss2022 chacha8 decrypt failed"))?),
        _ => Err(anyhow::anyhow!("unsupported ss2022 method {method}")),
    }
}

fn ss2022_encrypt(
    method: &str,
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
) -> anyhow::Result<Vec<u8>> {
    match method {
        "2022-blake3-aes-128-gcm" => Ok(Aes128Gcm::new_from_slice(key)?
            .encrypt(AesNonce::from_slice(nonce), plaintext)
            .map_err(|_| anyhow::anyhow!("ss2022 aes-128 encrypt failed"))?),
        "2022-blake3-aes-256-gcm" => Ok(Aes256Gcm::new_from_slice(key)?
            .encrypt(AesNonce::from_slice(nonce), plaintext)
            .map_err(|_| anyhow::anyhow!("ss2022 aes-256 encrypt failed"))?),
        "2022-blake3-chacha20-poly1305" => Ok(ChaCha20Poly1305::new_from_slice(key)?
            .encrypt(ChaNonce::from_slice(nonce), plaintext)
            .map_err(|_| anyhow::anyhow!("ss2022 chacha encrypt failed"))?),
        "2022-blake3-chacha8-poly1305" => Ok(ChaCha8Poly1305::new_from_slice(key)?
            .encrypt(ChaNonce::from_slice(nonce), plaintext)
            .map_err(|_| anyhow::anyhow!("ss2022 chacha8 encrypt failed"))?),
        _ => Err(anyhow::anyhow!("unsupported ss2022 method {method}")),
    }
}

fn parse_test_destination(input: &[u8]) -> anyhow::Result<(Destination, usize)> {
    let mut cursor = 1;
    let host = match input.first().copied() {
        Some(0x01) => {
            let address: [u8; 4] = input[cursor..cursor + 4].try_into()?;
            cursor += 4;
            std::net::Ipv4Addr::from(address).to_string()
        }
        Some(0x03) => {
            let length = input[cursor] as usize;
            cursor += 1;
            let host = std::str::from_utf8(&input[cursor..cursor + length])?.to_string();
            cursor += length;
            host
        }
        Some(0x04) => {
            let address: [u8; 16] = input[cursor..cursor + 16].try_into()?;
            cursor += 16;
            std::net::Ipv6Addr::from(address).to_string()
        }
        other => return Err(anyhow::anyhow!("unsupported destination type {other:?}")),
    };
    let port = u16::from_be_bytes(input[cursor..cursor + 2].try_into()?);
    cursor += 2;
    Ok((Destination::new(host, port), cursor))
}

fn test_destination_length(input: &[u8]) -> anyhow::Result<Option<usize>> {
    let Some(address_type) = input.first().copied() else {
        return Ok(None);
    };
    let length = match address_type {
        0x01 => 1 + 4 + 2,
        0x04 => 1 + 16 + 2,
        0x03 => {
            let Some(domain_length) = input.get(1).copied() else {
                return Ok(None);
            };
            if domain_length == 0 {
                return Err(anyhow::anyhow!("empty test destination domain"));
            }
            1 + 1 + domain_length as usize + 2
        }
        other => return Err(anyhow::anyhow!("unsupported destination type {other:#04x}")),
    };
    Ok((input.len() >= length).then_some(length))
}

fn parse_test_uot_destination(input: &[u8]) -> anyhow::Result<(Destination, usize)> {
    let mut cursor = 1;
    let host = match input.first().copied() {
        Some(0x00) => {
            let address: [u8; 4] = input[cursor..cursor + 4].try_into()?;
            cursor += 4;
            std::net::Ipv4Addr::from(address).to_string()
        }
        Some(0x01) => {
            let address: [u8; 16] = input[cursor..cursor + 16].try_into()?;
            cursor += 16;
            std::net::Ipv6Addr::from(address).to_string()
        }
        Some(0x02) => {
            let length = input[cursor] as usize;
            cursor += 1;
            let host = std::str::from_utf8(&input[cursor..cursor + length])?.to_string();
            cursor += length;
            host
        }
        other => {
            return Err(anyhow::anyhow!(
                "unsupported UoT destination type {other:?}"
            ))
        }
    };
    let port = u16::from_be_bytes(input[cursor..cursor + 2].try_into()?);
    cursor += 2;
    Ok((Destination::new(host, port), cursor))
}

fn test_uot_destination_length(input: &[u8]) -> anyhow::Result<Option<usize>> {
    let Some(address_type) = input.first().copied() else {
        return Ok(None);
    };
    let length = match address_type {
        0x00 => 1 + 4 + 2,
        0x01 => 1 + 16 + 2,
        0x02 => {
            let Some(domain_length) = input.get(1).copied() else {
                return Ok(None);
            };
            if domain_length == 0 {
                return Err(anyhow::anyhow!("empty test UoT destination domain"));
            }
            1 + 1 + domain_length as usize + 2
        }
        other => {
            return Err(anyhow::anyhow!(
                "unsupported UoT destination type {other:#04x}"
            ))
        }
    };
    Ok((input.len() >= length).then_some(length))
}

fn encode_test_uot_destination(destination: &Destination) -> anyhow::Result<Vec<u8>> {
    let mut output = Vec::new();
    match destination.host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(address)) => {
            output.push(0x00);
            output.extend_from_slice(&address.octets());
        }
        Ok(std::net::IpAddr::V6(address)) => {
            output.push(0x01);
            output.extend_from_slice(&address.octets());
        }
        Err(_) => {
            let domain = destination.host.as_bytes();
            if domain.is_empty() || domain.len() > u8::MAX as usize {
                return Err(anyhow::anyhow!("invalid test UoT destination domain"));
            }
            output.push(0x02);
            output.push(domain.len() as u8);
            output.extend_from_slice(domain);
        }
    }
    output.extend_from_slice(&destination.port.to_be_bytes());
    Ok(output)
}

async fn read_uot_request_from_ss(
    stream: &mut tokio::net::TcpStream,
    method: &str,
    request_key: &[u8],
    request_nonce: &mut [u8],
    version: u8,
) -> anyhow::Result<(Option<Destination>, Destination, Vec<u8>)> {
    let mut logical = Vec::new();
    loop {
        let mut cursor = 0;
        let initial_destination = if version == 2 {
            let Some(mode) = logical.first().copied() else {
                logical.extend_from_slice(
                    &read_legacy_ss_chunk(stream, method, request_key, request_nonce).await?,
                );
                continue;
            };
            if mode != 0 {
                return Err(anyhow::anyhow!("expected UoT v2 packet mode, got {mode}"));
            }
            let Some(destination_length) = test_destination_length(&logical[1..])? else {
                logical.extend_from_slice(
                    &read_legacy_ss_chunk(stream, method, request_key, request_nonce).await?,
                );
                continue;
            };
            let (destination, consumed) = parse_test_destination(&logical[1..])?;
            assert_eq!(consumed, destination_length);
            cursor = 1 + consumed;
            Some(destination)
        } else {
            None
        };

        let Some(destination_length) = test_uot_destination_length(&logical[cursor..])? else {
            logical.extend_from_slice(
                &read_legacy_ss_chunk(stream, method, request_key, request_nonce).await?,
            );
            continue;
        };
        if logical.len() < cursor + destination_length + 2 {
            logical.extend_from_slice(
                &read_legacy_ss_chunk(stream, method, request_key, request_nonce).await?,
            );
            continue;
        }
        let (destination, consumed) = parse_test_uot_destination(&logical[cursor..])?;
        assert_eq!(consumed, destination_length);
        cursor += consumed;
        let payload_length = u16::from_be_bytes(logical[cursor..cursor + 2].try_into()?) as usize;
        cursor += 2;
        if logical.len() < cursor + payload_length {
            logical.extend_from_slice(
                &read_legacy_ss_chunk(stream, method, request_key, request_nonce).await?,
            );
            continue;
        }
        return Ok((
            initial_destination,
            destination,
            logical[cursor..cursor + payload_length].to_vec(),
        ));
    }
}

async fn run_ss2022_tcp_real_dial(method: &'static str, keys: Vec<Vec<u8>>) -> anyhow::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let listen_addr = listener.local_addr()?;
    let key_len = keys
        .last()
        .ok_or_else(|| anyhow::anyhow!("missing ss2022 key"))?
        .len();
    let expected_destination = Destination::new("target.example", 443);
    let server_destination = expected_destination.clone();
    let server_keys = keys.clone();

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let mut request_salt = vec![0u8; key_len];
        stream.read_exact(&mut request_salt).await?;
        for pair in server_keys.windows(2) {
            let mut encrypted_identity = [0u8; 16];
            stream.read_exact(&mut encrypted_identity).await?;
            let mut material = Vec::new();
            material.extend_from_slice(&pair[0]);
            material.extend_from_slice(&request_salt);
            let identity_key = blake3::derive_key("shadowsocks 2022 identity subkey", &material);
            let identity = ss2022_identity_block_test(
                &identity_key[..pair[0].len()],
                &encrypted_identity,
                false,
            )?;
            assert_eq!(&identity, &blake3::hash(&pair[1]).as_bytes()[..16]);
        }
        let server_key = server_keys
            .last()
            .ok_or_else(|| anyhow::anyhow!("missing ss2022 user key"))?;
        let request_key = ss2022_subkey(server_key, &request_salt, key_len);
        let mut request_nonce = [0u8; 12];

        let mut fixed = vec![0u8; 11 + 16];
        stream.read_exact(&mut fixed).await?;
        let fixed = ss2022_decrypt(method, &request_key, &request_nonce, &fixed)?;
        increment_nonce(&mut request_nonce);
        assert_eq!(fixed[0], 0);
        let timestamp = u64::from_be_bytes(fixed[1..9].try_into()?);
        assert!(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)?
                .as_secs()
                .abs_diff(timestamp)
                <= 30
        );
        let variable_length = u16::from_be_bytes(fixed[9..11].try_into()?) as usize;

        let mut variable = vec![0u8; variable_length + 16];
        stream.read_exact(&mut variable).await?;
        let variable = ss2022_decrypt(method, &request_key, &request_nonce, &variable)?;
        increment_nonce(&mut request_nonce);
        let (destination, cursor) = parse_test_destination(&variable)?;
        assert_eq!(destination, server_destination);
        let padding_length = u16::from_be_bytes(variable[cursor..cursor + 2].try_into()?) as usize;
        assert!(padding_length > 0);
        assert_eq!(cursor + 2 + padding_length, variable.len());

        let mut encrypted_length = [0u8; 18];
        stream.read_exact(&mut encrypted_length).await?;
        let length = ss2022_decrypt(method, &request_key, &request_nonce, &encrypted_length)?;
        increment_nonce(&mut request_nonce);
        if length.len() != 2 {
            return Err(anyhow::anyhow!("invalid ss2022 payload length block"));
        }
        let payload_length = u16::from_be_bytes([length[0], length[1]]) as usize;
        let mut encrypted_payload = vec![0u8; payload_length + 16];
        stream.read_exact(&mut encrypted_payload).await?;
        let payload = ss2022_decrypt(method, &request_key, &request_nonce, &encrypted_payload)?;
        assert_eq!(payload, b"ping");

        let response_salt = vec![0x42; key_len];
        let response_key = ss2022_subkey(server_key, &response_salt, key_len);
        let mut response_nonce = [0u8; 12];
        let mut response_header = Vec::with_capacity(1 + 8 + key_len + 2);
        response_header.push(1);
        response_header.extend_from_slice(
            &SystemTime::now()
                .duration_since(UNIX_EPOCH)?
                .as_secs()
                .to_be_bytes(),
        );
        response_header.extend_from_slice(&request_salt);
        response_header.extend_from_slice(&4u16.to_be_bytes());
        let encrypted_header =
            ss2022_encrypt(method, &response_key, &response_nonce, &response_header)?;
        increment_nonce(&mut response_nonce);
        let encrypted_payload = ss2022_encrypt(method, &response_key, &response_nonce, b"pong")?;
        let mut response = response_salt;
        response.extend_from_slice(&encrypted_header);
        response.extend_from_slice(&encrypted_payload);
        stream.write_all(&response).await?;
        stream.flush().await?;
        Ok::<_, anyhow::Error>(())
    });

    let password = keys
        .iter()
        .map(|key| base64::engine::general_purpose::STANDARD.encode(key))
        .collect::<Vec<_>>()
        .join(":");
    let config = SuperConfig {
        core: CoreConfig {
            default_outbound: "ss".to_string(),
            ..CoreConfig::default()
        },
        outbounds: vec![OutboundConfig::Shadowsocks {
            name: "ss".to_string(),
            server: "127.0.0.1".to_string(),
            port: listen_addr.port(),
            method: method.to_string(),
            password,
            plugin: None,
            udp_over_tcp: false,
            udp_over_tcp_version: 1,
        }],
        ..SuperConfig::default()
    };
    let outbounds = build_outbounds(&config.outbounds, None)?;
    let outbound = get_outbound(&outbounds, "ss");
    let mut stream = outbound.connect(&expected_destination, 3000).await?;
    stream.write_all(b"ping").await?;
    stream.flush().await?;
    let mut response = [0u8; 4];
    timeout(Duration::from_secs(3), stream.read_exact(&mut response)).await??;
    assert_eq!(&response, b"pong");
    timeout(Duration::from_secs(3), server).await???;
    Ok(())
}

fn ss2022_aes_block_test(
    method: &str,
    key: &[u8],
    input: &[u8; 16],
    encrypt: bool,
) -> anyhow::Result<[u8; 16]> {
    if !matches!(
        method,
        "2022-blake3-aes-128-gcm" | "2022-blake3-aes-256-gcm"
    ) {
        return Err(anyhow::anyhow!("AES Shadowsocks 2022 method required"));
    }
    ss2022_identity_block_test(key, input, encrypt)
}

fn ss2022_identity_block_test(
    key: &[u8],
    input: &[u8; 16],
    encrypt: bool,
) -> anyhow::Result<[u8; 16]> {
    let mut output = [0u8; 16];
    match key.len() {
        16 => {
            let cipher = Aes128::new_from_slice(key)?;
            let mut block = Block::<Aes128>::default();
            block.copy_from_slice(input);
            if encrypt {
                cipher.encrypt_block(&mut block);
            } else {
                cipher.decrypt_block(&mut block);
            }
            output.copy_from_slice(&block);
        }
        32 => {
            let cipher = Aes256::new_from_slice(key)?;
            let mut block = Block::<Aes256>::default();
            block.copy_from_slice(input);
            if encrypt {
                cipher.encrypt_block(&mut block);
            } else {
                cipher.decrypt_block(&mut block);
            }
            output.copy_from_slice(&block);
        }
        length => return Err(anyhow::anyhow!("invalid identity key length {length}")),
    }
    Ok(output)
}

async fn run_ss2022_udp_real_dial(method: &'static str, keys: Vec<Vec<u8>>) -> anyhow::Result<()> {
    let server = UdpSocket::bind("127.0.0.1:0").await?;
    let listen_addr = server.local_addr()?;
    let server_keys = keys.clone();
    let expected_destination = Destination::new("dns.example", 53);
    let server_destination = expected_destination.clone();

    let server_task = tokio::spawn(async move {
        let mut buffer = vec![0u8; 65_535];
        let (length, peer) = server.recv_from(&mut buffer).await?;
        let packet = &buffer[..length];
        let (client_session_id, packet_id, body) = if matches!(
            method,
            "2022-blake3-chacha20-poly1305" | "2022-blake3-chacha8-poly1305"
        ) {
            assert_eq!(server_keys.len(), 1);
            let server_key = &server_keys[0];
            let nonce = &packet[..24];
            let body = if method == "2022-blake3-chacha8-poly1305" {
                XChaCha8Poly1305::new_from_slice(server_key)?
                    .decrypt(chacha20poly1305::XNonce::from_slice(nonce), &packet[24..])
                    .map_err(|_| anyhow::anyhow!("ss2022 UDP request decrypt failed"))?
            } else {
                XChaCha20Poly1305::new_from_slice(server_key)?
                    .decrypt(chacha20poly1305::XNonce::from_slice(nonce), &packet[24..])
                    .map_err(|_| anyhow::anyhow!("ss2022 UDP request decrypt failed"))?
            };
            let client_session_id: [u8; 8] = body[..8].try_into()?;
            let packet_id = u64::from_be_bytes(body[8..16].try_into()?);
            (client_session_id, packet_id, body[16..].to_vec())
        } else {
            let encrypted_header: [u8; 16] = packet[..16].try_into()?;
            let separate_header =
                ss2022_aes_block_test(method, &server_keys[0], &encrypted_header, false)?;
            let client_session_id: [u8; 8] = separate_header[..8].try_into()?;
            let packet_id = u64::from_be_bytes(separate_header[8..].try_into()?);
            let mut body_offset = 16;
            for pair in server_keys.windows(2) {
                let encrypted_identity: [u8; 16] =
                    packet[body_offset..body_offset + 16].try_into()?;
                body_offset += 16;
                let mut identity =
                    ss2022_identity_block_test(&pair[0], &encrypted_identity, false)?;
                for (byte, header_byte) in identity.iter_mut().zip(separate_header) {
                    *byte ^= header_byte;
                }
                assert_eq!(&identity, &blake3::hash(&pair[1]).as_bytes()[..16]);
            }
            let server_key = server_keys
                .last()
                .ok_or_else(|| anyhow::anyhow!("missing ss2022 user key"))?;
            let request_key = ss2022_subkey(server_key, &client_session_id, server_key.len());
            let body = ss2022_decrypt(
                method,
                &request_key,
                &separate_header[4..16],
                &packet[body_offset..],
            )?;
            (client_session_id, packet_id, body)
        };
        assert_eq!(packet_id, 0);
        assert_eq!(body[0], 0);
        let timestamp = u64::from_be_bytes(body[1..9].try_into()?);
        assert!(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)?
                .as_secs()
                .abs_diff(timestamp)
                <= 30
        );
        let padding_length = u16::from_be_bytes(body[9..11].try_into()?) as usize;
        let destination_offset = 11 + padding_length;
        let (destination, destination_length) =
            parse_test_destination(&body[destination_offset..])?;
        assert_eq!(destination, server_destination);
        assert_eq!(
            &body[destination_offset + destination_length..],
            b"hello-ss2022-udp"
        );

        let server_session_id = [0x44; 8];
        let server_packet_id = 0u64;
        let mut response_main = Vec::new();
        response_main.push(1);
        response_main.extend_from_slice(
            &SystemTime::now()
                .duration_since(UNIX_EPOCH)?
                .as_secs()
                .to_be_bytes(),
        );
        response_main.extend_from_slice(&client_session_id);
        response_main.extend_from_slice(&0u16.to_be_bytes());
        let mut destination_bytes = Vec::new();
        destination_bytes.push(0x03);
        destination_bytes.push("dns.example".len() as u8);
        destination_bytes.extend_from_slice(b"dns.example");
        destination_bytes.extend_from_slice(&53u16.to_be_bytes());
        response_main.extend_from_slice(&destination_bytes);
        response_main.extend_from_slice(b"echo-ss2022-udp");

        let response = if matches!(
            method,
            "2022-blake3-chacha20-poly1305" | "2022-blake3-chacha8-poly1305"
        ) {
            let server_key = server_keys
                .last()
                .ok_or_else(|| anyhow::anyhow!("missing ss2022 user key"))?;
            let nonce = [0x55; 24];
            let mut body = Vec::new();
            body.extend_from_slice(&server_session_id);
            body.extend_from_slice(&server_packet_id.to_be_bytes());
            body.extend_from_slice(&response_main);
            let encrypted = if method == "2022-blake3-chacha8-poly1305" {
                XChaCha8Poly1305::new_from_slice(server_key)?
                    .encrypt(chacha20poly1305::XNonce::from_slice(&nonce), body.as_ref())
                    .map_err(|_| anyhow::anyhow!("ss2022 UDP response encrypt failed"))?
            } else {
                XChaCha20Poly1305::new_from_slice(server_key)?
                    .encrypt(chacha20poly1305::XNonce::from_slice(&nonce), body.as_ref())
                    .map_err(|_| anyhow::anyhow!("ss2022 UDP response encrypt failed"))?
            };
            let mut response = nonce.to_vec();
            response.extend_from_slice(&encrypted);
            response
        } else {
            let server_key = server_keys
                .last()
                .ok_or_else(|| anyhow::anyhow!("missing ss2022 user key"))?;
            let mut separate_header = [0u8; 16];
            separate_header[..8].copy_from_slice(&server_session_id);
            separate_header[8..].copy_from_slice(&server_packet_id.to_be_bytes());
            let encrypted_header =
                ss2022_aes_block_test(method, server_key, &separate_header, true)?;
            let response_key = ss2022_subkey(server_key, &server_session_id, server_key.len());
            let encrypted_body = ss2022_encrypt(
                method,
                &response_key,
                &separate_header[4..16],
                &response_main,
            )?;
            let mut response = encrypted_header.to_vec();
            response.extend_from_slice(&encrypted_body);
            response
        };
        server.send_to(&response, peer).await?;
        Ok::<_, anyhow::Error>(())
    });

    let password = keys
        .iter()
        .map(|key| base64::engine::general_purpose::STANDARD.encode(key))
        .collect::<Vec<_>>()
        .join(":");
    let config = SuperConfig {
        core: CoreConfig {
            default_outbound: "ss".to_string(),
            ..CoreConfig::default()
        },
        outbounds: vec![OutboundConfig::Shadowsocks {
            name: "ss".to_string(),
            server: "127.0.0.1".to_string(),
            port: listen_addr.port(),
            method: method.to_string(),
            password,
            plugin: None,
            udp_over_tcp: false,
            udp_over_tcp_version: 1,
        }],
        ..SuperConfig::default()
    };
    let outbounds = build_outbounds(&config.outbounds, None)?;
    let outbound = get_outbound(&outbounds, "ss");
    let response = outbound
        .udp_exchange(&expected_destination, b"hello-ss2022-udp", 3000)
        .await?;
    assert_eq!(response, b"echo-ss2022-udp");
    timeout(Duration::from_secs(3), server_task).await???;
    Ok(())
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn build_just_ss(method: &str, port: u16) -> SuperConfig {
    SuperConfig {
        core: CoreConfig {
            default_outbound: "ss".to_string(),
            ..CoreConfig::default()
        },
        outbounds: vec![
            OutboundConfig::Direct {
                name: "direct".to_string(),
            },
            OutboundConfig::Shadowsocks {
                name: "ss".to_string(),
                server: "127.0.0.1".to_string(),
                port,
                method: method.to_string(),
                password: "supersecret".to_string(),
                plugin: None,
                udp_over_tcp: false,
                udp_over_tcp_version: 1,
            },
        ],
        ..SuperConfig::default()
    }
}

fn build_just_ss_uot(port: u16, version: u8) -> SuperConfig {
    let mut config = build_just_ss("aes-128-gcm", port);
    for outbound in &mut config.outbounds {
        if let OutboundConfig::Shadowsocks {
            udp_over_tcp,
            udp_over_tcp_version,
            ..
        } = outbound
        {
            *udp_over_tcp = true;
            *udp_over_tcp_version = version;
        }
    }
    config
}

fn build_just_ssr() -> SuperConfig {
    SuperConfig {
        core: CoreConfig {
            default_outbound: "ssr".to_string(),
            ..CoreConfig::default()
        },
        outbounds: vec![
            OutboundConfig::Direct {
                name: "direct".to_string(),
            },
            OutboundConfig::Ssr {
                name: "ssr".to_string(),
                server: "127.0.0.1".to_string(),
                port: 8388,
                method: "aes-128-cfb".to_string(),
                password: "pwd".to_string(),
                protocol: "auth_aes128_md5".to_string(),
                obfs: "http_simple".to_string(),
                protocol_param: None,
                obfs_param: None,
            },
        ],
        ..SuperConfig::default()
    }
}

fn get_outbound(map: &OutboundMap, name: &str) -> Arc<dyn supercore::outbound::Outbound> {
    map.get(name)
        .unwrap_or_else(|| panic!("missing outbound {name}"))
        .clone()
}

/// Spawn a mock SS server that:
/// 1. Reads the request, decrypts, parses the embedded target
/// 2. Replies with a tiny echo (best-effort)
/// 3. Closes
async fn spawn_ss_mock(
    method: &'static str,
    password: &'static str,
    expected_destination: Destination,
) -> (SocketAddr, tokio::task::JoinHandle<anyhow::Result<()>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let (host, port, request_key, mut request_nonce) =
            ss_server_handshake(&mut stream, method, password.as_bytes()).await?;
        assert_eq!(Destination::new(host, port), expected_destination);
        let payload =
            read_legacy_ss_chunk(&mut stream, method, &request_key, &mut request_nonce).await?;
        assert_eq!(payload, b"ping");

        let key_len = legacy_ss_key_len(method)?;
        let master_key = evp_bytes_to_key_test(password.as_bytes(), key_len);
        let response_salt = vec![0x42; key_len];
        let response_key = legacy_ss_subkey(&master_key, &response_salt, key_len)?;
        let mut response_nonce = vec![0u8; legacy_ss_nonce_len(method)?];
        let response_chunk =
            encode_legacy_ss_chunk(method, &response_key, &mut response_nonce, b"pong")?;
        stream.write_all(&response_salt).await?;
        stream.write_all(&response_chunk).await?;
        stream.flush().await?;
        Ok(())
    });
    (addr, handle)
}

fn assert_shadowsocks_address(address: ShadowsocksAddress, expected: &Destination) {
    match address {
        ShadowsocksAddress::SocketAddress(address) => {
            assert_eq!(address.ip().to_string(), expected.host);
            assert_eq!(address.port(), expected.port);
        }
        ShadowsocksAddress::DomainNameAddress(host, port) => {
            assert_eq!(host, expected.host);
            assert_eq!(port, expected.port);
        }
    }
}

async fn run_managed_cipher_tcp(method: &'static str) -> anyhow::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let listen_addr = listener.local_addr()?;
    let destination = Destination::new("managed.example", 8443);
    let cipher = method
        .parse::<CipherKind>()
        .map_err(|_| anyhow::anyhow!("unsupported test cipher {method}"))?;
    let server_config =
        ShadowsocksServerConfig::new(ServerAddr::SocketAddr(listen_addr), "supersecret", cipher)?;
    let server_key = server_config.key().to_vec();
    let expected_destination = destination.clone();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await?;
        let context = ShadowsocksContext::new_shared(ServerType::Server);
        let mut stream = ProxyServerStream::from_stream(context, stream, cipher, &server_key);
        let address = stream.handshake().await?;
        assert_shadowsocks_address(address, &expected_destination);
        let mut payload = [0u8; 4];
        stream.read_exact(&mut payload).await?;
        assert_eq!(&payload, b"ping");
        stream.write_all(b"pong").await?;
        stream.shutdown().await?;
        anyhow::Ok(())
    });

    let cfg = build_just_ss(method, listen_addr.port());
    let map = build_outbounds(&cfg.outbounds, None)?;
    let outbound = get_outbound(&map, "ss");
    let mut stream =
        timeout(Duration::from_secs(3), outbound.connect(&destination, 2000)).await??;
    stream.write_all(b"ping").await?;
    stream.flush().await?;
    let mut response = [0u8; 4];
    timeout(Duration::from_secs(3), stream.read_exact(&mut response)).await??;
    assert_eq!(&response, b"pong");
    server.await??;
    Ok(())
}

async fn run_managed_cipher_udp(method: &'static str) -> anyhow::Result<()> {
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let listen_addr = socket.local_addr()?;
    let destination = Destination::new("udp-managed.example", 5353);
    let cipher = method
        .parse::<CipherKind>()
        .map_err(|_| anyhow::anyhow!("unsupported test cipher {method}"))?;
    let server_config =
        ShadowsocksServerConfig::new(ServerAddr::SocketAddr(listen_addr), "supersecret", cipher)?;
    let server_key = server_config.key().to_vec();
    let expected_destination = destination.clone();
    let server = tokio::spawn(async move {
        let context = ShadowsocksContext::new(ServerType::Server);
        let mut packet = vec![0u8; 65_535];
        let (packet_len, peer) = socket.recv_from(&mut packet).await?;
        packet.truncate(packet_len);
        let (payload_len, address, _) =
            decrypt_client_payload(&context, cipher, &server_key, &mut packet, None)?;
        assert_shadowsocks_address(address.clone(), &expected_destination);
        assert_eq!(&packet[..payload_len], b"ping");
        let mut response = bytes::BytesMut::new();
        encrypt_server_payload(
            &context,
            cipher,
            &server_key,
            &address,
            &UdpSocketControlData::default(),
            b"pong",
            &mut response,
        );
        socket.send_to(&response, peer).await?;
        anyhow::Ok(())
    });

    let cfg = build_just_ss(method, listen_addr.port());
    let map = build_outbounds(&cfg.outbounds, None)?;
    let outbound = get_outbound(&map, "ss");
    let response = timeout(
        Duration::from_secs(3),
        outbound.udp_exchange(&destination, b"ping", 2000),
    )
    .await??;
    assert_eq!(response, b"pong");
    server.await??;
    Ok(())
}

async fn run_native_aead_udp(method: &'static str) -> anyhow::Result<()> {
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let listen_addr = socket.local_addr()?;
    let destination = Destination::new("native-udp.example", 5353);
    let expected_destination = destination.clone();
    let server = tokio::spawn(async move {
        let key_len = legacy_ss_key_len(method)?;
        let nonce = vec![0u8; legacy_ss_nonce_len(method)?];
        let master_key = evp_bytes_to_key_test(b"supersecret", key_len);
        let mut packet = vec![0u8; 65_535];
        let (packet_len, peer) = socket.recv_from(&mut packet).await?;
        packet.truncate(packet_len);
        let request_key = legacy_ss_subkey(&master_key, &packet[..key_len], key_len)?;
        let plaintext = legacy_ss_decrypt(method, &request_key, &nonce, &packet[key_len..])?;
        let (request_destination, consumed) = parse_test_destination(&plaintext)?;
        assert_eq!(request_destination, expected_destination);
        assert_eq!(&plaintext[consumed..], b"ping");

        let response_salt = vec![0x42; key_len];
        let response_key = legacy_ss_subkey(&master_key, &response_salt, key_len)?;
        let mut response_plaintext = Vec::new();
        response_plaintext.push(0x03);
        response_plaintext.push(request_destination.host.len() as u8);
        response_plaintext.extend_from_slice(request_destination.host.as_bytes());
        response_plaintext.extend_from_slice(&request_destination.port.to_be_bytes());
        response_plaintext.extend_from_slice(b"pong");
        let encrypted = legacy_ss_encrypt(method, &response_key, &nonce, &response_plaintext)?;
        let mut response = response_salt;
        response.extend_from_slice(&encrypted);
        socket.send_to(&response, peer).await?;
        anyhow::Ok(())
    });

    let config = build_just_ss(method, listen_addr.port());
    let outbounds = build_outbounds(&config.outbounds, None)?;
    let outbound = get_outbound(&outbounds, "ss");
    let response = timeout(
        Duration::from_secs(3),
        outbound.udp_exchange(&destination, b"ping", 2000),
    )
    .await??;
    assert_eq!(response, b"pong");
    timeout(Duration::from_secs(3), server).await???;
    Ok(())
}

fn test_apply_legacy_stream(
    method: &str,
    key: &[u8],
    iv: &[u8],
    data: &mut [u8],
) -> anyhow::Result<()> {
    use chacha20::cipher::{KeyIvInit, StreamCipher};

    match method {
        "chacha20" => chacha20::ChaCha20Legacy::new_from_slices(key, iv)?.apply_keystream(data),
        "xchacha20" => chacha20::XChaCha20::new_from_slices(key, iv)?.apply_keystream(data),
        _ => return Err(anyhow::anyhow!("unsupported test stream method {method}")),
    }
    Ok(())
}

fn legacy_stream_iv_len(method: &str) -> anyhow::Result<usize> {
    match method {
        "chacha20" => Ok(8),
        "xchacha20" => Ok(24),
        _ => Err(anyhow::anyhow!("unsupported test stream method {method}")),
    }
}

async fn run_native_stream_tcp(method: &'static str) -> anyhow::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let listen_addr = listener.local_addr()?;
    let destination = Destination::new("legacy-stream.example", 443);
    let expected_destination = destination.clone();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let key = evp_bytes_to_key_test(b"supersecret", 32);
        let mut request_iv = vec![0u8; legacy_stream_iv_len(method)?];
        stream.read_exact(&mut request_iv).await?;
        let mut expected = Vec::new();
        encode_socks5_destination(&expected_destination, &mut expected)?;
        expected.extend_from_slice(b"ping");
        let mut request = vec![0u8; expected.len()];
        stream.read_exact(&mut request).await?;
        test_apply_legacy_stream(method, &key, &request_iv, &mut request)?;
        assert_eq!(request, expected);

        let response_iv = vec![0x42; legacy_stream_iv_len(method)?];
        let mut response = b"pong".to_vec();
        test_apply_legacy_stream(method, &key, &response_iv, &mut response)?;
        stream.write_all(&response_iv).await?;
        stream.write_all(&response).await?;
        stream.shutdown().await?;
        anyhow::Ok(())
    });

    let config = build_just_ss(method, listen_addr.port());
    let outbounds = build_outbounds(&config.outbounds, None)?;
    let outbound = get_outbound(&outbounds, "ss");
    let mut stream =
        timeout(Duration::from_secs(3), outbound.connect(&destination, 2000)).await??;
    stream.write_all(b"ping").await?;
    stream.flush().await?;
    let mut response = [0u8; 4];
    timeout(Duration::from_secs(3), stream.read_exact(&mut response)).await??;
    assert_eq!(&response, b"pong");
    timeout(Duration::from_secs(3), server).await???;
    Ok(())
}

async fn run_native_stream_udp(method: &'static str) -> anyhow::Result<()> {
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let listen_addr = socket.local_addr()?;
    let destination = Destination::new("legacy-stream-udp.example", 5353);
    let expected_destination = destination.clone();
    let server = tokio::spawn(async move {
        let key = evp_bytes_to_key_test(b"supersecret", 32);
        let iv_len = legacy_stream_iv_len(method)?;
        let mut packet = vec![0u8; 65_535];
        let (length, peer) = socket.recv_from(&mut packet).await?;
        packet.truncate(length);
        let mut plaintext = packet[iv_len..].to_vec();
        test_apply_legacy_stream(method, &key, &packet[..iv_len], &mut plaintext)?;
        let (request_destination, offset) = parse_test_destination(&plaintext)?;
        assert_eq!(request_destination, expected_destination);
        assert_eq!(&plaintext[offset..], b"ping");

        let response_iv = vec![0x42; iv_len];
        let mut response = Vec::new();
        encode_socks5_destination(&request_destination, &mut response)?;
        response.extend_from_slice(b"pong");
        test_apply_legacy_stream(method, &key, &response_iv, &mut response)?;
        let mut response_packet = response_iv;
        response_packet.extend_from_slice(&response);
        socket.send_to(&response_packet, peer).await?;
        anyhow::Ok(())
    });

    let config = build_just_ss(method, listen_addr.port());
    let outbounds = build_outbounds(&config.outbounds, None)?;
    let outbound = get_outbound(&outbounds, "ss");
    let response = timeout(
        Duration::from_secs(3),
        outbound.udp_exchange(&destination, b"ping", 2000),
    )
    .await??;
    assert_eq!(response, b"pong");
    timeout(Duration::from_secs(3), server).await???;
    Ok(())
}

async fn run_ss_large_duplex_real_dial() -> anyhow::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let listen_addr = listener.local_addr()?;
    let destination = Destination::new("large.example", 443);
    let expected_destination = destination.clone();
    let upload = (0..96 * 1024)
        .map(|index| (index % 251) as u8)
        .collect::<Vec<_>>();
    let download = upload.iter().map(|byte| byte ^ 0x5a).collect::<Vec<_>>();
    let expected_upload = upload.clone();
    let expected_download = download.clone();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let (host, port, request_key, mut request_nonce) =
            ss_server_handshake(&mut stream, "aes-128-gcm", b"supersecret").await?;
        assert_eq!(Destination::new(host, port), expected_destination);
        let mut received = Vec::with_capacity(expected_upload.len());
        while received.len() < expected_upload.len() {
            received.extend_from_slice(
                &read_legacy_ss_chunk(&mut stream, "aes-128-gcm", &request_key, &mut request_nonce)
                    .await?,
            );
        }
        assert_eq!(received, expected_upload);

        let master_key = evp_bytes_to_key_test(b"supersecret", 16);
        let response_salt = vec![0x42; 16];
        let response_key = legacy_ss_subkey(&master_key, &response_salt, 16)?;
        let mut response_nonce = vec![0u8; 12];
        stream.write_all(&response_salt).await?;
        for chunk in expected_download.chunks(0x3fff) {
            stream
                .write_all(&encode_legacy_ss_chunk(
                    "aes-128-gcm",
                    &response_key,
                    &mut response_nonce,
                    chunk,
                )?)
                .await?;
        }
        stream.shutdown().await?;
        anyhow::Ok(())
    });

    let config = build_just_ss("aes-128-gcm", listen_addr.port());
    let outbounds = build_outbounds(&config.outbounds, None)?;
    let outbound = get_outbound(&outbounds, "ss");
    let mut stream = outbound.connect(&destination, 2000).await?;
    stream.write_all(&upload).await?;
    stream.flush().await?;
    let mut response = vec![0u8; download.len()];
    timeout(Duration::from_secs(5), stream.read_exact(&mut response)).await??;
    assert_eq!(response, download);
    timeout(Duration::from_secs(5), server).await???;
    Ok(())
}

async fn run_shadowsocks_uot_real_dial(version: u8) -> anyhow::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let listen_addr = listener.local_addr()?;
    let destination = Destination::new("uot-target.example", 5353);
    let expected_destination = destination.clone();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let (magic_host, magic_port, request_key, mut request_nonce) =
            ss_server_handshake(&mut stream, "aes-128-gcm", b"supersecret").await?;
        let expected_magic = match version {
            1 => "sp.udp-over-tcp.arpa",
            2 => "sp.v2.udp-over-tcp.arpa",
            other => return Err(anyhow::anyhow!("invalid test UoT version {other}")),
        };
        assert_eq!(magic_host, expected_magic);
        assert_eq!(magic_port, 0);

        let (initial_destination, packet_destination, payload) = read_uot_request_from_ss(
            &mut stream,
            "aes-128-gcm",
            &request_key,
            &mut request_nonce,
            version,
        )
        .await?;
        if version == 2 {
            assert_eq!(initial_destination.as_ref(), Some(&expected_destination));
        } else {
            assert!(initial_destination.is_none());
        }
        assert_eq!(packet_destination, expected_destination);
        assert_eq!(payload, b"ping");

        let mut response_frame = encode_test_uot_destination(&packet_destination)?;
        response_frame.extend_from_slice(&4u16.to_be_bytes());
        response_frame.extend_from_slice(b"pong");
        let master_key = evp_bytes_to_key_test(b"supersecret", 16);
        let response_salt = vec![0x42; 16];
        let response_key = legacy_ss_subkey(&master_key, &response_salt, 16)?;
        let mut response_nonce = vec![0u8; 12];
        let response_chunk = encode_legacy_ss_chunk(
            "aes-128-gcm",
            &response_key,
            &mut response_nonce,
            &response_frame,
        )?;
        stream.write_all(&response_salt).await?;
        stream.write_all(&response_chunk).await?;
        stream.flush().await?;
        anyhow::Ok(())
    });

    let config = build_just_ss_uot(listen_addr.port(), version);
    let outbounds = build_outbounds(&config.outbounds, None)?;
    let outbound = get_outbound(&outbounds, "ss");
    let response = timeout(
        Duration::from_secs(3),
        outbound.udp_exchange(&destination, b"ping", 2000),
    )
    .await??;
    assert_eq!(response, b"pong");
    timeout(Duration::from_secs(3), server).await???;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ss_aes_128_gcm_real_dial_against_mock() {
    let destination = Destination::new("example.com", 443);
    let (addr, server) = spawn_ss_mock("aes-128-gcm", "supersecret", destination.clone()).await;
    let cfg = build_just_ss("aes-128-gcm", addr.port());
    let map = build_outbounds(&cfg.outbounds, None).unwrap();
    let outbound = get_outbound(&map, "ss");
    let mut stream = timeout(Duration::from_secs(3), outbound.connect(&destination, 2000))
        .await
        .unwrap()
        .unwrap();
    stream.write_all(b"ping").await.unwrap();
    stream.flush().await.unwrap();
    let mut response = [0u8; 4];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"pong");
    server.await.unwrap().unwrap();
}

#[tokio::test]
async fn ss_aes_256_gcm_real_dial_against_mock() {
    let destination = Destination::new("test.example", 80);
    let (addr, server) = spawn_ss_mock("aes-256-gcm", "supersecret", destination.clone()).await;
    let cfg = build_just_ss("aes-256-gcm", addr.port());
    let map = build_outbounds(&cfg.outbounds, None).unwrap();
    let outbound = get_outbound(&map, "ss");
    let mut stream = timeout(Duration::from_secs(3), outbound.connect(&destination, 2000))
        .await
        .unwrap()
        .unwrap();
    stream.write_all(b"ping").await.unwrap();
    stream.flush().await.unwrap();
    let mut response = [0u8; 4];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"pong");
    server.await.unwrap().unwrap();
}

#[tokio::test]
async fn ss_chacha20_ietf_poly1305_real_dial_against_mock() {
    let destination = Destination::new("github.com", 22);
    let (addr, server) =
        spawn_ss_mock("chacha20-ietf-poly1305", "supersecret", destination.clone()).await;
    let cfg = build_just_ss("chacha20-ietf-poly1305", addr.port());
    let map = build_outbounds(&cfg.outbounds, None).unwrap();
    let outbound = get_outbound(&map, "ss");
    let mut stream = timeout(Duration::from_secs(3), outbound.connect(&destination, 2000))
        .await
        .unwrap()
        .unwrap();
    stream.write_all(b"ping").await.unwrap();
    stream.flush().await.unwrap();
    let mut response = [0u8; 4];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"pong");
    server.await.unwrap().unwrap();
}

#[tokio::test]
async fn ss_extended_cipher_tcp_matrix_real_dial() -> anyhow::Result<()> {
    for method in [
        "none",
        "rc4-md5",
        "aes-128-ctr",
        "aes-192-ctr",
        "aes-256-ctr",
        "aes-128-cfb",
        "aes-192-cfb",
        "aes-256-cfb",
        "chacha20-ietf",
        "aes-128-ccm",
        "aes-256-ccm",
        "aes-128-gcm-siv",
        "aes-256-gcm-siv",
        "xchacha20-ietf-poly1305",
    ] {
        run_managed_cipher_tcp(method).await?;
    }
    Ok(())
}

#[tokio::test]
async fn ss_extended_native_aead_tcp_matrix_real_dial() -> anyhow::Result<()> {
    for method in [
        "aes-192-gcm",
        "aes-192-ccm",
        "chacha8-ietf-poly1305",
        "xchacha8-ietf-poly1305",
        "lea-128-gcm",
        "lea-192-gcm",
        "lea-256-gcm",
        "aegis-128l",
        "aegis-256",
        "aez-384",
        "deoxys-ii-256-128",
        "ascon128",
        "ascon128a",
        "rabbit128-poly1305",
    ] {
        let destination = Destination::new("extended-native.example", 443);
        let (address, server) = spawn_ss_mock(method, "supersecret", destination.clone()).await;
        let config = build_just_ss(method, address.port());
        let outbounds = build_outbounds(&config.outbounds, None)?;
        let outbound = get_outbound(&outbounds, "ss");
        let mut stream = outbound.connect(&destination, 2000).await?;
        stream.write_all(b"ping").await?;
        stream.flush().await?;
        let mut response = [0u8; 4];
        timeout(Duration::from_secs(3), stream.read_exact(&mut response)).await??;
        assert_eq!(&response, b"pong", "method {method}");
        timeout(Duration::from_secs(3), server).await???;
    }
    Ok(())
}

#[tokio::test]
async fn ss_extended_native_aead_udp_matrix_real_dial() -> anyhow::Result<()> {
    for method in [
        "aes-192-gcm",
        "aes-192-ccm",
        "chacha8-ietf-poly1305",
        "xchacha8-ietf-poly1305",
        "lea-128-gcm",
        "lea-192-gcm",
        "lea-256-gcm",
        "aegis-128l",
        "aegis-256",
        "aez-384",
        "deoxys-ii-256-128",
        "ascon128",
        "ascon128a",
        "rabbit128-poly1305",
    ] {
        run_native_aead_udp(method).await?;
    }
    Ok(())
}

#[tokio::test]
async fn ss_native_stream_tcp_matrix_real_dial() -> anyhow::Result<()> {
    for method in ["chacha20", "xchacha20"] {
        run_native_stream_tcp(method).await?;
    }
    Ok(())
}

#[tokio::test]
async fn ss_native_stream_udp_matrix_real_dial() -> anyhow::Result<()> {
    for method in ["chacha20", "xchacha20"] {
        run_native_stream_udp(method).await?;
    }
    Ok(())
}

#[tokio::test]
async fn ss_large_bidirectional_stream_real_dial() -> anyhow::Result<()> {
    run_ss_large_duplex_real_dial().await
}

#[tokio::test]
async fn ss_server_close_propagates_eof() -> anyhow::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let listen_addr = listener.local_addr()?;
    let destination = Destination::new("close.example", 443);
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let _ = ss_server_handshake(&mut stream, "aes-128-gcm", b"supersecret").await?;
        anyhow::Ok(())
    });
    let config = build_just_ss("aes-128-gcm", listen_addr.port());
    let outbounds = build_outbounds(&config.outbounds, None)?;
    let outbound = get_outbound(&outbounds, "ss");
    let mut stream = outbound.connect(&destination, 2000).await?;
    let mut byte = [0u8; 1];
    let read = timeout(Duration::from_secs(3), stream.read(&mut byte)).await??;
    assert_eq!(read, 0);
    server.await??;
    Ok(())
}

#[tokio::test]
async fn ss_udp_timeout_and_cancellation_are_bounded() -> anyhow::Result<()> {
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let config = build_just_ss("aes-128-gcm", socket.local_addr()?.port());
    let outbounds = build_outbounds(&config.outbounds, None)?;
    let outbound = get_outbound(&outbounds, "ss");
    let destination = Destination::new("timeout.example", 53);

    let timeout_error = outbound
        .udp_exchange(&destination, b"ping", 30)
        .await
        .unwrap_err();
    assert!(timeout_error.to_string().contains("timed out"));

    let context = DialContext::new(destination, 5_000);
    let cancellation = context.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(20)).await;
        cancellation.cancel();
    });
    let cancelled = outbound
        .udp_exchange_context(&context, b"ping")
        .await
        .unwrap_err();
    assert!(cancelled.to_string().contains("cancelled"));
    Ok(())
}

#[tokio::test]
async fn ss_extended_cipher_udp_categories_real_dial() -> anyhow::Result<()> {
    for method in [
        "none",
        "rc4-md5",
        "aes-192-ctr",
        "aes-128-ccm",
        "xchacha20-ietf-poly1305",
    ] {
        run_managed_cipher_udp(method).await?;
    }
    Ok(())
}

#[tokio::test]
async fn ss_udp_over_tcp_v1_real_dial() -> anyhow::Result<()> {
    run_shadowsocks_uot_real_dial(1).await
}

#[tokio::test]
async fn ss_udp_over_tcp_v2_real_dial() -> anyhow::Result<()> {
    run_shadowsocks_uot_real_dial(2).await
}

#[test]
fn ss_udp_over_tcp_rejects_invalid_version() -> anyhow::Result<()> {
    let config = build_just_ss_uot(8388, 3);
    let outbounds = build_outbounds(&config.outbounds, None)?;
    let capability = get_outbound(&outbounds, "ss").capability();
    assert!(!capability.tcp_supported);
    assert!(!capability.udp_supported);
    assert!(capability
        .limitations
        .iter()
        .any(|limitation| limitation.contains("udp-over-tcp-version must be 1 or 2")));
    Ok(())
}

#[tokio::test]
async fn ss_2022_blake3_aes_128_gcm_real_dial() -> anyhow::Result<()> {
    run_ss2022_tcp_real_dial("2022-blake3-aes-128-gcm", vec![vec![0x11; 16]]).await
}

#[tokio::test]
async fn ss_2022_blake3_aes_256_gcm_real_dial() -> anyhow::Result<()> {
    run_ss2022_tcp_real_dial("2022-blake3-aes-256-gcm", vec![vec![0x22; 32]]).await
}

#[tokio::test]
async fn ss_2022_blake3_chacha20_poly1305_real_dial() -> anyhow::Result<()> {
    run_ss2022_tcp_real_dial("2022-blake3-chacha20-poly1305", vec![vec![0x33; 32]]).await
}

#[tokio::test]
async fn ss_2022_blake3_chacha8_poly1305_real_dial() -> anyhow::Result<()> {
    run_ss2022_tcp_real_dial("2022-blake3-chacha8-poly1305", vec![vec![0x34; 32]]).await
}

#[tokio::test]
async fn ss_2022_tcp_sip023_identity_headers_real_dial() -> anyhow::Result<()> {
    run_ss2022_tcp_real_dial(
        "2022-blake3-aes-128-gcm",
        vec![vec![0x10; 16], vec![0x20; 16], vec![0x30; 16]],
    )
    .await
}

#[tokio::test]
async fn ss_2022_blake3_aes_128_gcm_udp_real_dial() -> anyhow::Result<()> {
    run_ss2022_udp_real_dial("2022-blake3-aes-128-gcm", vec![vec![0x11; 16]]).await
}

#[tokio::test]
async fn ss_2022_blake3_aes_256_gcm_udp_real_dial() -> anyhow::Result<()> {
    run_ss2022_udp_real_dial("2022-blake3-aes-256-gcm", vec![vec![0x22; 32]]).await
}

#[tokio::test]
async fn ss_2022_blake3_chacha20_poly1305_udp_real_dial() -> anyhow::Result<()> {
    run_ss2022_udp_real_dial("2022-blake3-chacha20-poly1305", vec![vec![0x33; 32]]).await
}

#[tokio::test]
async fn ss_2022_blake3_chacha8_poly1305_udp_real_dial() -> anyhow::Result<()> {
    run_ss2022_udp_real_dial("2022-blake3-chacha8-poly1305", vec![vec![0x34; 32]]).await
}

#[tokio::test]
async fn ss_2022_udp_sip023_identity_headers_real_dial() -> anyhow::Result<()> {
    run_ss2022_udp_real_dial(
        "2022-blake3-aes-128-gcm",
        vec![vec![0x10; 16], vec![0x20; 16], vec![0x30; 16]],
    )
    .await
}

#[tokio::test]
async fn ssr_build_outbound_does_not_panic() {
    let cfg = build_just_ssr();
    let result = build_outbounds(&cfg.outbounds, None);
    assert!(result.is_ok(), "SSR build failed: {:?}", result.err());
    let map = result.unwrap();
    assert!(map.contains_key("ssr"));
}

#[tokio::test]
async fn ssr_auth_sha1_v4_udp_exchange_reports_unsupported() {
    let mut cfg = build_just_ssr();
    for outbound in &mut cfg.outbounds {
        if let OutboundConfig::Ssr { protocol, .. } = outbound {
            *protocol = "auth_sha1_v4".to_string();
        }
    }
    let map = build_outbounds(&cfg.outbounds, None).unwrap();
    let outbound = get_outbound(&map, "ssr");
    let dest = Destination::new("test.example", 53);
    let result = outbound.udp_exchange(&dest, b"ping", 1000).await;
    assert!(
        result.is_err(),
        "auth_sha1_v4 UDP must return Err, got Ok: {:?}",
        result
    );
    let err = result.unwrap_err().to_string().to_lowercase();
    assert!(
        err.contains("udp") || err.contains("not implement") || err.contains("unsupported"),
        "SSR UDP error msg should mention 'udp' / 'not implement' / 'unsupported', got: {err}"
    );
}

#[tokio::test]
async fn ss_plugin_config_parses() {
    let mut cfg = build_just_ss("aes-128-gcm", 8388);
    // 替换 SS 的 plugin 字段
    for ob in cfg.outbounds.iter_mut() {
        if let OutboundConfig::Shadowsocks { plugin, .. } = ob {
            *plugin = Some(supercore::config::ShadowsocksPluginConfig {
                mode: "obfs-local".to_string(),
                host: Some("example.com".to_string()),
                path: None,
                tls: false,
                skip_cert_verify: false,
                password: None,
                version: None,
            });
        }
    }
    let result = build_outbounds(&cfg.outbounds, None);
    assert!(
        result.is_ok(),
        "plugin config build failed: {:?}",
        result.err()
    );
}

#[tokio::test]
async fn ss_cargo_test_smoke() {
    // 最小冒烟: 验证关键类型都 import 到
    let _ = std::any::type_name::<HashMap<String, Arc<dyn supercore::outbound::Outbound>>>();
    let _ = build_just_ss("aes-128-gcm", 0);
    let _ = build_just_ssr();
}
