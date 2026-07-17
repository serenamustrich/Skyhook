use std::time::Duration;

use aes::{
    cipher::{Block, BlockDecrypt, KeyInit as AesKeyInit},
    Aes128, Aes192, Aes256,
};
use anyhow::{anyhow, Context};
use cfb_mode::cipher::KeyIvInit;
use chacha20::cipher::StreamCipher;
use md5::{Digest, Md5};
use sha1::Sha1;
use supercore::{
    config::OutboundConfig,
    outbound::{build_outbounds, context::DialContext},
    routing::Destination,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    time::timeout,
};

#[derive(Clone, Copy)]
enum TestCipher {
    Dummy,
    Aes128Ctr,
    Aes192Ctr,
    Aes256Ctr,
    Aes128Cfb,
    Aes192Cfb,
    Aes256Cfb,
    Rc4Md5,
    Chacha20Legacy,
    Chacha20Ietf,
    XChacha20,
}

impl TestCipher {
    fn method(self) -> &'static str {
        match self {
            Self::Dummy => "none",
            Self::Aes128Ctr => "aes-128-ctr",
            Self::Aes192Ctr => "aes-192-ctr",
            Self::Aes256Ctr => "aes-256-ctr",
            Self::Aes128Cfb => "aes-128-cfb",
            Self::Aes192Cfb => "aes-192-cfb",
            Self::Aes256Cfb => "aes-256-cfb",
            Self::Rc4Md5 => "rc4-md5",
            Self::Chacha20Legacy => "chacha20",
            Self::Chacha20Ietf => "chacha20-ietf",
            Self::XChacha20 => "xchacha20",
        }
    }

    fn key_len(self) -> usize {
        match self {
            Self::Dummy | Self::Aes128Ctr | Self::Aes128Cfb | Self::Rc4Md5 => 16,
            Self::Aes192Ctr | Self::Aes192Cfb => 24,
            Self::Aes256Ctr
            | Self::Aes256Cfb
            | Self::Chacha20Legacy
            | Self::Chacha20Ietf
            | Self::XChacha20 => 32,
        }
    }

    fn iv_len(self) -> usize {
        match self {
            Self::Dummy => 0,
            Self::Chacha20Legacy => 8,
            Self::Chacha20Ietf => 12,
            Self::XChacha20 => 24,
            _ => 16,
        }
    }

    fn encryptor(self, key: &[u8], iv: &[u8]) -> anyhow::Result<TestStreamCipher> {
        match self {
            Self::Dummy => Ok(TestStreamCipher::Dummy),
            Self::Aes128Ctr => Ok(TestStreamCipher::Aes128Ctr(
                ctr::Ctr128BE::<Aes128>::new_from_slices(key, iv)
                    .map_err(|_| anyhow!("invalid AES-128-CTR key/iv"))?,
            )),
            Self::Aes192Ctr => Ok(TestStreamCipher::Aes192Ctr(
                ctr::Ctr128BE::<Aes192>::new_from_slices(key, iv)
                    .map_err(|_| anyhow!("invalid AES-192-CTR key/iv"))?,
            )),
            Self::Aes256Ctr => Ok(TestStreamCipher::Aes256Ctr(
                ctr::Ctr128BE::<Aes256>::new_from_slices(key, iv)
                    .map_err(|_| anyhow!("invalid AES-256-CTR key/iv"))?,
            )),
            Self::Aes128Cfb => Ok(TestStreamCipher::Aes128Enc(
                cfb_mode::BufEncryptor::<Aes128>::new_from_slices(key, iv)
                    .map_err(|_| anyhow!("invalid AES-128-CFB key/iv"))?,
            )),
            Self::Aes192Cfb => Ok(TestStreamCipher::Aes192Enc(
                cfb_mode::BufEncryptor::<Aes192>::new_from_slices(key, iv)
                    .map_err(|_| anyhow!("invalid AES-192-CFB key/iv"))?,
            )),
            Self::Aes256Cfb => Ok(TestStreamCipher::Aes256Enc(
                cfb_mode::BufEncryptor::<Aes256>::new_from_slices(key, iv)
                    .map_err(|_| anyhow!("invalid AES-256-CFB key/iv"))?,
            )),
            Self::Rc4Md5 => {
                let key = rc4_md5_key(key, iv);
                Ok(TestStreamCipher::Rc4(
                    rc4::Rc4::<rc4::consts::U16>::new_from_slice(&key)
                        .map_err(|_| anyhow!("invalid RC4-MD5 key"))?,
                ))
            }
            Self::Chacha20Legacy => Ok(TestStreamCipher::ChachaLegacy(
                chacha20::ChaCha20Legacy::new_from_slices(key, iv)
                    .map_err(|_| anyhow!("invalid ChaCha20 key/iv"))?,
            )),
            Self::Chacha20Ietf => Ok(TestStreamCipher::ChachaIetf(
                chacha20::ChaCha20::new_from_slices(key, iv)
                    .map_err(|_| anyhow!("invalid ChaCha20-IETF key/iv"))?,
            )),
            Self::XChacha20 => Ok(TestStreamCipher::XChacha(
                chacha20::XChaCha20::new_from_slices(key, iv)
                    .map_err(|_| anyhow!("invalid XChaCha20 key/iv"))?,
            )),
        }
    }

    fn decryptor(self, key: &[u8], iv: &[u8]) -> anyhow::Result<TestStreamCipher> {
        match self {
            Self::Dummy
            | Self::Aes128Ctr
            | Self::Aes192Ctr
            | Self::Aes256Ctr
            | Self::Rc4Md5
            | Self::Chacha20Legacy
            | Self::Chacha20Ietf
            | Self::XChacha20 => self.encryptor(key, iv),
            Self::Aes128Cfb => Ok(TestStreamCipher::Aes128Dec(
                cfb_mode::BufDecryptor::<Aes128>::new_from_slices(key, iv)
                    .map_err(|_| anyhow!("invalid AES-128-CFB key/iv"))?,
            )),
            Self::Aes192Cfb => Ok(TestStreamCipher::Aes192Dec(
                cfb_mode::BufDecryptor::<Aes192>::new_from_slices(key, iv)
                    .map_err(|_| anyhow!("invalid AES-192-CFB key/iv"))?,
            )),
            Self::Aes256Cfb => Ok(TestStreamCipher::Aes256Dec(
                cfb_mode::BufDecryptor::<Aes256>::new_from_slices(key, iv)
                    .map_err(|_| anyhow!("invalid AES-256-CFB key/iv"))?,
            )),
        }
    }
}

enum TestStreamCipher {
    Dummy,
    Aes128Ctr(ctr::Ctr128BE<Aes128>),
    Aes192Ctr(ctr::Ctr128BE<Aes192>),
    Aes256Ctr(ctr::Ctr128BE<Aes256>),
    Aes128Enc(cfb_mode::BufEncryptor<Aes128>),
    Aes192Enc(cfb_mode::BufEncryptor<Aes192>),
    Aes256Enc(cfb_mode::BufEncryptor<Aes256>),
    Aes128Dec(cfb_mode::BufDecryptor<Aes128>),
    Aes192Dec(cfb_mode::BufDecryptor<Aes192>),
    Aes256Dec(cfb_mode::BufDecryptor<Aes256>),
    Rc4(rc4::Rc4<rc4::consts::U16>),
    ChachaLegacy(chacha20::ChaCha20Legacy),
    ChachaIetf(chacha20::ChaCha20),
    XChacha(chacha20::XChaCha20),
}

impl TestStreamCipher {
    fn apply(&mut self, data: &mut [u8]) {
        match self {
            Self::Dummy => {}
            Self::Aes128Ctr(cipher) => cipher.apply_keystream(data),
            Self::Aes192Ctr(cipher) => cipher.apply_keystream(data),
            Self::Aes256Ctr(cipher) => cipher.apply_keystream(data),
            Self::Aes128Enc(cipher) => cipher.encrypt(data),
            Self::Aes192Enc(cipher) => cipher.encrypt(data),
            Self::Aes256Enc(cipher) => cipher.encrypt(data),
            Self::Aes128Dec(cipher) => cipher.decrypt(data),
            Self::Aes192Dec(cipher) => cipher.decrypt(data),
            Self::Aes256Dec(cipher) => cipher.decrypt(data),
            Self::Rc4(cipher) => cipher.apply_keystream(data),
            Self::ChachaLegacy(cipher) => cipher.apply_keystream(data),
            Self::ChachaIetf(cipher) => cipher.apply_keystream(data),
            Self::XChacha(cipher) => cipher.apply_keystream(data),
        }
    }
}

#[derive(Clone, Copy)]
enum TestObfs {
    Plain,
    RandomHead,
    HttpSimple,
    HttpPost,
}

#[derive(Clone, Copy)]
enum TestAuthHash {
    Md5,
    Sha1,
}

#[derive(Clone, Copy)]
enum TestAuthChainKind {
    A,
    B,
    C,
    D,
    E,
    F,
}

#[derive(Clone, Copy)]
enum TestLegacyProtocol {
    VerifySimple,
    AuthSimple,
    AuthSha1,
    AuthSha1V2,
}

impl TestLegacyProtocol {
    fn protocol(self) -> &'static str {
        match self {
            Self::VerifySimple => "verify_simple",
            Self::AuthSimple => "auth_simple",
            Self::AuthSha1 => "auth_sha1",
            Self::AuthSha1V2 => "auth_sha1_v2",
        }
    }

    fn initial_prefix_len(self) -> usize {
        match self {
            Self::VerifySimple | Self::AuthSimple => 2,
            Self::AuthSha1 | Self::AuthSha1V2 => 6,
        }
    }
}

impl TestAuthChainKind {
    fn protocol(self) -> &'static str {
        match self {
            Self::A => "auth_chain_a",
            Self::B => "auth_chain_b",
            Self::C => "auth_chain_c",
            Self::D => "auth_chain_d",
            Self::E => "auth_chain_e",
            Self::F => "auth_chain_f",
        }
    }
}

impl TestAuthHash {
    fn hmac(self, key: &[u8], message: &[u8]) -> Vec<u8> {
        match self {
            Self::Md5 => hmac_md5(key, message).to_vec(),
            Self::Sha1 => hmac_sha1(key, message).to_vec(),
        }
    }

    fn hash(self, value: &[u8]) -> Vec<u8> {
        match self {
            Self::Md5 => Md5::digest(value).to_vec(),
            Self::Sha1 => Sha1::digest(value).to_vec(),
        }
    }
}

fn evp_bytes_to_key(password: &[u8], key_len: usize) -> Vec<u8> {
    let mut key = Vec::with_capacity(key_len);
    let mut previous = Vec::new();
    while key.len() < key_len {
        let mut hasher = Md5::new();
        hasher.update(&previous);
        hasher.update(password);
        previous = hasher.finalize().to_vec();
        key.extend_from_slice(&previous);
    }
    key.truncate(key_len);
    key
}

fn rc4_md5_key(key: &[u8], iv: &[u8]) -> Vec<u8> {
    let mut hasher = Md5::new();
    hasher.update(key);
    hasher.update(iv);
    hasher.finalize().to_vec()
}

fn ssr_crc32(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                0xedb8_8320 ^ (crc >> 1)
            } else {
                crc >> 1
            };
        }
    }
    crc ^ 0xffff_ffff
}

fn ssr_adler32(data: &[u8]) -> u32 {
    let mut a = 1u32;
    let mut b = 0u32;
    for byte in data {
        a = (a + u32::from(*byte)) % 65_521;
        b = (b + a) % 65_521;
    }
    (b << 16) | a
}

fn hmac_sha1(key: &[u8], message: &[u8]) -> [u8; 20] {
    let mut normalized = [0u8; 64];
    if key.len() > normalized.len() {
        let digest = Sha1::digest(key);
        normalized[..digest.len()].copy_from_slice(&digest);
    } else {
        normalized[..key.len()].copy_from_slice(key);
    }
    let mut inner_pad = [0x36u8; 64];
    let mut outer_pad = [0x5cu8; 64];
    for index in 0..64 {
        inner_pad[index] ^= normalized[index];
        outer_pad[index] ^= normalized[index];
    }
    let mut inner = Sha1::new();
    inner.update(inner_pad);
    inner.update(message);
    let inner = inner.finalize();
    let mut outer = Sha1::new();
    outer.update(outer_pad);
    outer.update(inner);
    outer.finalize().into()
}

fn hmac_md5(key: &[u8], message: &[u8]) -> [u8; 16] {
    let mut normalized = [0u8; 64];
    if key.len() > normalized.len() {
        let digest = Md5::digest(key);
        normalized[..digest.len()].copy_from_slice(&digest);
    } else {
        normalized[..key.len()].copy_from_slice(key);
    }
    let mut inner_pad = [0x36u8; 64];
    let mut outer_pad = [0x5cu8; 64];
    for index in 0..64 {
        inner_pad[index] ^= normalized[index];
        outer_pad[index] ^= normalized[index];
    }
    let mut inner = Md5::new();
    inner.update(inner_pad);
    inner.update(message);
    let inner = inner.finalize();
    let mut outer = Md5::new();
    outer.update(outer_pad);
    outer.update(inner);
    outer.finalize().into()
}

fn decrypt_aes128_block(key: &[u8], ciphertext: &[u8]) -> anyhow::Result<[u8; 16]> {
    let cipher = Aes128::new_from_slice(key).map_err(|_| anyhow!("invalid AES auth key"))?;
    let mut block = Block::<Aes128>::clone_from_slice(ciphertext);
    cipher.decrypt_block(&mut block);
    Ok(block.into())
}

fn auth_chain_rc4(user_key: &[u8], client_hash: &[u8; 16]) -> anyhow::Result<TestStreamCipher> {
    use base64::Engine as _;

    let mut password = base64::engine::general_purpose::STANDARD.encode(user_key);
    password.push_str(&base64::engine::general_purpose::STANDARD.encode(client_hash));
    let key = evp_bytes_to_key(password.as_bytes(), 16);
    Ok(TestStreamCipher::Rc4(
        rc4::Rc4::<rc4::consts::U16>::new_from_slice(&key)
            .map_err(|_| anyhow!("invalid auth-chain RC4 key"))?,
    ))
}

#[derive(Clone, Copy)]
struct TestShift128Plus {
    values: [u64; 2],
}

impl TestShift128Plus {
    fn from_hash(hash: &[u8; 16], data_len: Option<usize>) -> Self {
        let mut bytes = *hash;
        if let Some(data_len) = data_len {
            bytes[0] = data_len as u8;
            bytes[1] = (data_len >> 8) as u8;
        }
        let mut state = Self {
            values: [
                u64::from_le_bytes(bytes[..8].try_into().unwrap()),
                u64::from_le_bytes(bytes[8..].try_into().unwrap()),
            ],
        };
        if data_len.is_some() {
            for _ in 0..4 {
                state.next();
            }
        }
        state
    }

    fn next(&mut self) -> u64 {
        let mut x = self.values[0];
        let y = self.values[1];
        self.values[0] = y;
        x ^= x << 23;
        x ^= y ^ (x >> 17) ^ (y >> 26);
        self.values[1] = x;
        x.wrapping_add(y)
    }
}

fn auth_chain_padding(
    kind: TestAuthChainKind,
    server_key: &[u8],
    data_len: usize,
    hash: &[u8; 16],
    chain_f_epoch: u64,
) -> (usize, usize) {
    let mut random = TestShift128Plus::from_hash(hash, Some(data_len));
    let rand_len = match kind {
        TestAuthChainKind::A => auth_chain_a_rand_len(data_len, &mut random),
        TestAuthChainKind::B => auth_chain_b_rand_len(server_key, data_len, &mut random),
        TestAuthChainKind::C => auth_chain_c_rand_len(server_key, data_len, &mut random),
        TestAuthChainKind::D => auth_chain_d_rand_len(server_key, data_len, &mut random),
        TestAuthChainKind::E => auth_chain_e_rand_len(server_key, data_len, None),
        TestAuthChainKind::F => auth_chain_e_rand_len(server_key, data_len, Some(chain_f_epoch)),
    };
    if rand_len == 0 {
        return (0, 0);
    }
    let start = (random.next() % 8_589_934_609 % rand_len as u64) as usize;
    (rand_len, start)
}

fn auth_chain_a_rand_len(data_len: usize, random: &mut TestShift128Plus) -> usize {
    if data_len > 1440 {
        return 0;
    }
    if data_len > 1300 {
        (random.next() % 31) as usize
    } else if data_len > 900 {
        (random.next() % 127) as usize
    } else if data_len > 400 {
        (random.next() % 521) as usize
    } else {
        (random.next() % 1021) as usize
    }
}

fn auth_chain_b_rand_len(
    server_key: &[u8],
    data_len: usize,
    random: &mut TestShift128Plus,
) -> usize {
    if data_len >= 1440 {
        return 0;
    }
    let (sizes, sizes2) = auth_chain_b_size_lists(server_key);
    let target = data_len + 4;
    let pos = sizes.partition_point(|value| *value < target);
    let final_pos = pos + (random.next() % sizes.len() as u64) as usize;
    if final_pos < sizes.len() {
        return sizes[final_pos] - target;
    }
    let pos2 = sizes2.partition_point(|value| *value < target);
    let final_pos2 = pos2 + (random.next() % sizes2.len() as u64) as usize;
    if final_pos2 < sizes2.len() {
        return sizes2[final_pos2] - target;
    }
    if final_pos2 < pos2 + sizes2.len() - 1 {
        return 0;
    }
    auth_chain_a_rand_len(data_len, random)
}

fn auth_chain_b_size_lists(server_key: &[u8]) -> (Vec<usize>, Vec<usize>) {
    let mut seed = [0u8; 16];
    let copy_len = server_key.len().min(seed.len());
    seed[..copy_len].copy_from_slice(&server_key[..copy_len]);
    let mut random = TestShift128Plus::from_hash(&seed, None);

    let first_len = (random.next() % 8 + 4) as usize;
    let mut first = Vec::with_capacity(first_len);
    for _ in 0..first_len {
        first.push((random.next() % 2340 % 2040 % 1440) as usize);
    }
    first.sort_unstable();

    let second_len = (random.next() % 16 + 8) as usize;
    let mut second = Vec::with_capacity(second_len);
    for _ in 0..second_len {
        second.push((random.next() % 2340 % 2040 % 1440) as usize);
    }
    second.sort_unstable();
    (first, second)
}

fn auth_chain_c_rand_len(
    server_key: &[u8],
    data_len: usize,
    random: &mut TestShift128Plus,
) -> usize {
    let sizes = auth_chain_c_size_list(server_key, false, None);
    let target = data_len + 4;
    if target >= *sizes.last().unwrap() {
        return auth_chain_a_rand_len(data_len, random);
    }
    let pos = sizes.partition_point(|value| *value < target);
    let final_pos = pos + (random.next() % (sizes.len() - pos) as u64) as usize;
    sizes[final_pos] - target
}

fn auth_chain_d_rand_len(
    server_key: &[u8],
    data_len: usize,
    random: &mut TestShift128Plus,
) -> usize {
    let sizes = auth_chain_c_size_list(server_key, true, None);
    let target = data_len + 4;
    if target >= *sizes.last().unwrap() {
        return 0;
    }
    let pos = sizes.partition_point(|value| *value < target);
    let final_pos = pos + (random.next() % (sizes.len() - pos) as u64) as usize;
    sizes[final_pos] - target
}

fn auth_chain_e_rand_len(server_key: &[u8], data_len: usize, epoch: Option<u64>) -> usize {
    let sizes = auth_chain_c_size_list(server_key, true, epoch);
    let target = data_len + 4;
    if target >= *sizes.last().unwrap() {
        return 0;
    }
    let pos = sizes.partition_point(|value| *value < target);
    sizes[pos] - target
}

fn auth_chain_c_size_list(
    server_key: &[u8],
    patch_to_1300: bool,
    epoch: Option<u64>,
) -> Vec<usize> {
    let mut seed = [0u8; 16];
    let copy_len = server_key.len().min(seed.len());
    seed[..copy_len].copy_from_slice(&server_key[..copy_len]);
    if let Some(epoch) = epoch {
        for (target, value) in seed.iter_mut().take(8).zip(epoch.to_be_bytes()) {
            *target ^= value;
        }
    }
    let mut random = TestShift128Plus::from_hash(&seed, None);
    let length = (random.next() % 24 + 12) as usize;
    let mut sizes = Vec::with_capacity(if patch_to_1300 { 64 } else { length });
    for _ in 0..length {
        sizes.push((random.next() % 2340 % 2040 % 1440) as usize);
    }
    sizes.sort_unstable();
    if patch_to_1300 {
        while sizes.last().copied().unwrap_or_default() < 1300 && sizes.len() < 64 {
            sizes.push((random.next() % 2340 % 2040 % 1440) as usize);
        }
        sizes.sort_unstable();
    }
    sizes
}

fn auth_chain_udp_rand_len(hash: &[u8; 16]) -> usize {
    (TestShift128Plus::from_hash(hash, None).next() % 127) as usize
}

async fn read_auth_chain_frame(
    kind: TestAuthChainKind,
    stream: &mut TcpStream,
    outer: &mut TestStreamCipher,
    inner: &mut TestStreamCipher,
    server_key: &[u8],
    user_key: &[u8],
    last_hash: [u8; 16],
    packet_id: u32,
    chain_f_epoch: u64,
) -> anyhow::Result<(Vec<u8>, [u8; 16])> {
    let mut prefix = [0u8; 2];
    stream.read_exact(&mut prefix).await?;
    outer.apply(&mut prefix);
    let data_len =
        usize::from(prefix[0] ^ last_hash[14]) | (usize::from(prefix[1] ^ last_hash[15]) << 8);
    let (rand_len, start) =
        auth_chain_padding(kind, server_key, data_len, &last_hash, chain_f_epoch);
    let mut remainder = vec![0u8; rand_len + data_len + 2];
    stream.read_exact(&mut remainder).await?;
    outer.apply(&mut remainder);

    let mut frame = prefix.to_vec();
    frame.extend_from_slice(&remainder);
    let mut packet_key = user_key.to_vec();
    packet_key.extend_from_slice(&packet_id.to_le_bytes());
    let next_hash = hmac_md5(&packet_key, &frame[..frame.len() - 2]);
    assert_eq!(&frame[frame.len() - 2..], &next_hash[..2]);

    let mut payload = frame[2 + start..2 + start + data_len].to_vec();
    inner.apply(&mut payload);
    Ok((payload, next_hash))
}

fn build_auth_chain_frame(
    kind: TestAuthChainKind,
    payload: &[u8],
    inner: &mut TestStreamCipher,
    server_key: &[u8],
    user_key: &[u8],
    last_hash: [u8; 16],
    packet_id: u32,
    chain_f_epoch: u64,
) -> (Vec<u8>, [u8; 16]) {
    let (rand_len, start) =
        auth_chain_padding(kind, server_key, payload.len(), &last_hash, chain_f_epoch);
    let mut encrypted = payload.to_vec();
    inner.apply(&mut encrypted);

    let mut frame = vec![0x5a; 2 + rand_len + payload.len()];
    frame[0] = (payload.len() as u8) ^ last_hash[14];
    frame[1] = ((payload.len() >> 8) as u8) ^ last_hash[15];
    frame[2 + start..2 + start + payload.len()].copy_from_slice(&encrypted);

    let mut packet_key = user_key.to_vec();
    packet_key.extend_from_slice(&packet_id.to_le_bytes());
    let next_hash = hmac_md5(&packet_key, &frame);
    frame.extend_from_slice(&next_hash[..2]);
    (frame, next_hash)
}

fn build_auth_aes_data(
    hash: TestAuthHash,
    user_key: &[u8],
    packet_id: u32,
    payload: &[u8],
) -> Vec<u8> {
    let length = payload.len() + 9;
    let mut packet_key = user_key.to_vec();
    packet_key.extend_from_slice(&packet_id.to_le_bytes());
    let mut frame = vec![0u8; length];
    frame[..2].copy_from_slice(&(length as u16).to_le_bytes());
    let prefix_hmac = hash.hmac(&packet_key, &frame[..2]);
    frame[2..4].copy_from_slice(&prefix_hmac[..2]);
    frame[4] = 1;
    frame[5..5 + payload.len()].copy_from_slice(payload);
    let hmac = hash.hmac(&packet_key, &frame[..length - 4]);
    frame[length - 4..].copy_from_slice(&hmac[..4]);
    frame
}

fn verify_crc_frame(frame: &[u8]) {
    assert_eq!(ssr_crc32(frame), u32::MAX);
}

fn build_legacy_crc_response(payload: &[u8]) -> Vec<u8> {
    let rand_len = 1usize;
    let length = 2 + rand_len + payload.len() + 4;
    let mut frame = vec![0u8; length];
    frame[..2].copy_from_slice(&(length as u16).to_be_bytes());
    frame[2] = rand_len as u8;
    frame[2 + rand_len..2 + rand_len + payload.len()].copy_from_slice(payload);
    let checksum = !ssr_crc32(&frame[..length - 4]);
    frame[length - 4..].copy_from_slice(&checksum.to_le_bytes());
    frame
}

fn build_legacy_adler_response(payload: &[u8]) -> Vec<u8> {
    let rand_len = 1usize;
    let length = 2 + rand_len + payload.len() + 4;
    let mut frame = vec![0u8; length];
    frame[..2].copy_from_slice(&(length as u16).to_be_bytes());
    frame[2] = rand_len as u8;
    frame[2 + rand_len..2 + rand_len + payload.len()].copy_from_slice(payload);
    let checksum = ssr_adler32(&frame[..length - 4]);
    frame[length - 4..].copy_from_slice(&checksum.to_le_bytes());
    frame
}

async fn read_outer_frame(
    stream: &mut TcpStream,
    outer: &mut TestStreamCipher,
    prefix_len: usize,
    length_offset: usize,
) -> anyhow::Result<Vec<u8>> {
    let mut prefix = vec![0u8; prefix_len];
    stream.read_exact(&mut prefix).await?;
    outer.apply(&mut prefix);
    let length = u16::from_be_bytes(prefix[length_offset..length_offset + 2].try_into()?) as usize;
    let mut frame = prefix;
    frame.resize(length, 0);
    stream.read_exact(&mut frame[prefix_len..]).await?;
    outer.apply(&mut frame[prefix_len..]);
    Ok(frame)
}

fn legacy_padding_offset(frame: &[u8], offset: usize, extended: bool) -> anyhow::Result<usize> {
    let value = frame[offset];
    if extended && value == 0xff {
        Ok(offset + u16::from_be_bytes([frame[offset + 1], frame[offset + 2]]) as usize)
    } else {
        Ok(offset + usize::from(value))
    }
}

fn build_auth_sha1_v4_data(payload: &[u8]) -> Vec<u8> {
    let length = payload.len() + 9;
    let mut frame = vec![0u8; length];
    frame[..2].copy_from_slice(&(length as u16).to_be_bytes());
    let crc = ssr_crc32(&frame[..2]) as u16;
    frame[2..4].copy_from_slice(&crc.to_le_bytes());
    frame[4] = 1;
    frame[5..5 + payload.len()].copy_from_slice(payload);
    let adler = ssr_adler32(&frame[..length - 4]);
    frame[length - 4..].copy_from_slice(&adler.to_le_bytes());
    frame
}

fn destination_bytes(destination: &Destination) -> Vec<u8> {
    let mut output = vec![3, destination.host.len() as u8];
    output.extend_from_slice(destination.host.as_bytes());
    output.extend_from_slice(&destination.port.to_be_bytes());
    output
}

fn tls_record(content_type: u8, payload: &[u8]) -> Vec<u8> {
    let mut record = Vec::with_capacity(payload.len() + 5);
    record.extend_from_slice(&[content_type, 0x03, 0x03]);
    record.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    record.extend_from_slice(payload);
    record
}

async fn read_tls_record(stream: &mut TcpStream) -> anyhow::Result<(u8, [u8; 2], Vec<u8>)> {
    let mut header = [0u8; 5];
    stream.read_exact(&mut header).await?;
    let mut payload = vec![0u8; u16::from_be_bytes([header[3], header[4]]) as usize];
    stream.read_exact(&mut payload).await?;
    Ok((header[0], [header[1], header[2]], payload))
}

async fn take_exact(
    stream: &mut TcpStream,
    prefetched: &mut Vec<u8>,
    length: usize,
) -> anyhow::Result<Vec<u8>> {
    while prefetched.len() < length {
        let mut buffer = [0u8; 4096];
        let count = stream.read(&mut buffer).await?;
        if count == 0 {
            return Err(anyhow!("unexpected EOF in SSR mock server"));
        }
        prefetched.extend_from_slice(&buffer[..count]);
    }
    Ok(prefetched.drain(..length).collect())
}

fn decode_percent_path(path: &str) -> anyhow::Result<Vec<u8>> {
    let mut output = Vec::new();
    let bytes = path.as_bytes();
    let mut offset = bytes
        .iter()
        .position(|byte| *byte == b'%')
        .ok_or_else(|| anyhow!("SSR HTTP obfs path has no encoded payload"))?;
    while offset + 2 < bytes.len() && bytes[offset] == b'%' {
        let hex = std::str::from_utf8(&bytes[offset + 1..offset + 3])?;
        output.push(u8::from_str_radix(hex, 16)?);
        offset += 3;
    }
    Ok(output)
}

async fn read_ssr_initial(stream: &mut TcpStream, obfs: TestObfs) -> anyhow::Result<Vec<u8>> {
    if matches!(obfs, TestObfs::Plain) {
        return Ok(Vec::new());
    }
    if matches!(obfs, TestObfs::RandomHead) {
        return Err(anyhow!(
            "random_head must be acknowledged before SSR payload"
        ));
    }
    let mut data = Vec::new();
    let header_end = loop {
        let mut buffer = [0u8; 1024];
        let count = stream.read(&mut buffer).await?;
        if count == 0 {
            return Err(anyhow!("SSR HTTP obfs request ended early"));
        }
        data.extend_from_slice(&buffer[..count]);
        if let Some(index) = data.windows(4).position(|item| item == b"\r\n\r\n") {
            break index + 4;
        }
    };
    let header = std::str::from_utf8(&data[..header_end])?;
    let request_line = header.lines().next().context("missing SSR request line")?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().context("missing SSR HTTP method")?;
    assert_eq!(
        method,
        if matches!(obfs, TestObfs::HttpPost) {
            "POST"
        } else {
            "GET"
        }
    );
    let path = parts.next().context("missing SSR HTTP path")?;
    assert!(header.contains("Host: obfs.example"));
    let mut initial = decode_percent_path(path)?;
    initial.extend_from_slice(&data[header_end..]);
    Ok(initial)
}

async fn run_ssr_tcp(cipher: TestCipher, obfs: TestObfs) -> anyhow::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let password = "ssr-test-password";
    let destination = Destination::new("target.example", 443);
    let expected_destination = destination_bytes(&destination);
    let server_password = password.as_bytes().to_vec();

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let mut prefetched = if matches!(obfs, TestObfs::RandomHead) {
            let mut header = [0u8; 128];
            let length = stream.read(&mut header).await?;
            assert!((8..=103).contains(&length));
            let payload_len = length - 4;
            let checksum = u32::from_le_bytes(header[payload_len..length].try_into()?);
            assert_eq!(
                checksum,
                u32::MAX.wrapping_sub(ssr_crc32(&header[..payload_len]))
            );
            stream.write_all(b"random-head-ok").await?;
            stream.flush().await?;
            Vec::new()
        } else {
            read_ssr_initial(&mut stream, obfs).await?
        };
        let request_iv = take_exact(&mut stream, &mut prefetched, cipher.iv_len()).await?;
        let key = evp_bytes_to_key(&server_password, cipher.key_len());
        let mut decryptor = cipher.decryptor(&key, &request_iv)?;
        let mut target =
            take_exact(&mut stream, &mut prefetched, expected_destination.len()).await?;
        decryptor.apply(&mut target);
        assert_eq!(target, expected_destination);

        let mut upload = take_exact(&mut stream, &mut prefetched, 4).await?;
        decryptor.apply(&mut upload);
        assert_eq!(upload, b"ping");

        let response_iv = vec![0x50 + cipher.iv_len() as u8; cipher.iv_len()];
        if cipher.iv_len() > 0 {
            assert_ne!(response_iv, request_iv);
        }
        let mut encryptor = cipher.encryptor(&key, &response_iv)?;
        let mut pong = b"pong".to_vec();
        encryptor.apply(&mut pong);
        if matches!(obfs, TestObfs::Plain | TestObfs::RandomHead) {
            stream.write_all(&response_iv).await?;
        } else {
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nConnection: keep-alive\r\n\r\n")
                .await?;
            stream.write_all(&response_iv).await?;
        }
        stream.write_all(&pong).await?;
        stream.flush().await?;
        anyhow::Ok(())
    });

    let outbounds = build_outbounds(
        &[OutboundConfig::Ssr {
            name: "ssr".to_string(),
            server: "127.0.0.1".to_string(),
            port: address.port(),
            method: cipher.method().to_string(),
            password: password.to_string(),
            protocol: "origin".to_string(),
            obfs: match obfs {
                TestObfs::Plain => "plain",
                TestObfs::RandomHead => "random_head",
                TestObfs::HttpSimple => "http_simple",
                TestObfs::HttpPost => "http_post",
            }
            .to_string(),
            protocol_param: None,
            obfs_param: Some("obfs.example".to_string()),
        }],
        None,
    )?;
    let outbound = outbounds.get("ssr").context("missing SSR outbound")?;
    let mut tunnel = outbound.connect(&destination, 3000).await?;
    tunnel.write_all(b"ping").await?;
    tunnel.flush().await?;
    let mut response = [0u8; 4];
    timeout(Duration::from_secs(3), tunnel.read_exact(&mut response))
        .await
        .context("SSR TCP response timed out")??;
    assert_eq!(&response, b"pong");
    server.await??;
    Ok(())
}

async fn run_ssr_udp(cipher: TestCipher) -> anyhow::Result<()> {
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let address = socket.local_addr()?;
    let password = "ssr-udp-password";
    let destination = Destination::new("dns.example", 53);
    let expected_destination = destination_bytes(&destination);
    let server_password = password.as_bytes().to_vec();

    let server = tokio::spawn(async move {
        let mut packet = vec![0u8; 65_535];
        let (length, source) = socket.recv_from(&mut packet).await?;
        packet.truncate(length);
        let request_iv = packet[..cipher.iv_len()].to_vec();
        let key = evp_bytes_to_key(&server_password, cipher.key_len());
        let mut plaintext = packet[cipher.iv_len()..].to_vec();
        cipher.decryptor(&key, &request_iv)?.apply(&mut plaintext);
        assert_eq!(
            &plaintext[..expected_destination.len()],
            expected_destination
        );
        assert_eq!(&plaintext[expected_destination.len()..], b"query");

        let response_iv = vec![0x70 + cipher.iv_len() as u8; cipher.iv_len()];
        let mut response = expected_destination;
        response.extend_from_slice(b"answer");
        cipher.encryptor(&key, &response_iv)?.apply(&mut response);
        let mut response_packet = response_iv;
        response_packet.extend_from_slice(&response);
        socket.send_to(&response_packet, source).await?;
        anyhow::Ok(())
    });

    let outbounds = build_outbounds(
        &[OutboundConfig::Ssr {
            name: "ssr-udp".to_string(),
            server: "127.0.0.1".to_string(),
            port: address.port(),
            method: cipher.method().to_string(),
            password: password.to_string(),
            protocol: "origin".to_string(),
            obfs: "plain".to_string(),
            protocol_param: None,
            obfs_param: None,
        }],
        None,
    )?;
    let response = outbounds
        .get("ssr-udp")
        .context("missing SSR UDP outbound")?
        .udp_exchange(&destination, b"query", 3000)
        .await?;
    assert_eq!(response, b"answer");
    server.await??;
    Ok(())
}

async fn run_ssr_large_duplex_real_dial() -> anyhow::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let cipher = TestCipher::Aes256Ctr;
    let password = "ssr-large-password";
    let destination = Destination::new("large.example", 443);
    let target = destination_bytes(&destination);
    let upload = (0..96 * 1024)
        .map(|index| (index % 251) as u8)
        .collect::<Vec<_>>();
    let download = upload.iter().map(|byte| byte ^ 0xa5).collect::<Vec<_>>();
    let expected_upload = upload.clone();
    let expected_download = download.clone();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let key = evp_bytes_to_key(password.as_bytes(), cipher.key_len());
        let mut request_iv = vec![0u8; cipher.iv_len()];
        stream.read_exact(&mut request_iv).await?;
        let mut decryptor = cipher.decryptor(&key, &request_iv)?;
        let mut request_target = vec![0u8; target.len()];
        stream.read_exact(&mut request_target).await?;
        decryptor.apply(&mut request_target);
        assert_eq!(request_target, target);
        let mut received = vec![0u8; expected_upload.len()];
        stream.read_exact(&mut received).await?;
        decryptor.apply(&mut received);
        assert_eq!(received, expected_upload);

        let response_iv = vec![0x72; cipher.iv_len()];
        let mut response = expected_download;
        cipher.encryptor(&key, &response_iv)?.apply(&mut response);
        stream.write_all(&response_iv).await?;
        stream.write_all(&response).await?;
        stream.shutdown().await?;
        anyhow::Ok(())
    });

    let outbounds = build_outbounds(
        &[OutboundConfig::Ssr {
            name: "ssr-large".to_string(),
            server: "127.0.0.1".to_string(),
            port: address.port(),
            method: cipher.method().to_string(),
            password: password.to_string(),
            protocol: "origin".to_string(),
            obfs: "plain".to_string(),
            protocol_param: None,
            obfs_param: None,
        }],
        None,
    )?;
    let outbound = outbounds.get("ssr-large").context("missing SSR outbound")?;
    let mut tunnel = outbound.connect(&destination, 3000).await?;
    tunnel.write_all(&upload).await?;
    tunnel.flush().await?;
    let mut response = vec![0u8; download.len()];
    timeout(Duration::from_secs(5), tunnel.read_exact(&mut response)).await??;
    assert_eq!(response, download);
    server.await??;
    Ok(())
}

async fn run_ssr_legacy_tcp(protocol: TestLegacyProtocol) -> anyhow::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let password = "ssr-legacy-password";
    let destination = Destination::new("legacy.example", 443);
    let expected_destination = destination_bytes(&destination);
    let server_password = password.as_bytes().to_vec();

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let cipher = TestCipher::Aes128Cfb;
        let server_key = evp_bytes_to_key(&server_password, cipher.key_len());
        let mut request_iv = vec![0u8; cipher.iv_len()];
        stream.read_exact(&mut request_iv).await?;
        let mut decryptor = cipher.decryptor(&server_key, &request_iv)?;

        let initial = read_outer_frame(
            &mut stream,
            &mut decryptor,
            protocol.initial_prefix_len(),
            if protocol.initial_prefix_len() == 2 {
                0
            } else {
                4
            },
        )
        .await?;
        let target = match protocol {
            TestLegacyProtocol::VerifySimple => {
                verify_crc_frame(&initial);
                let offset = legacy_padding_offset(&initial, 2, false)?;
                initial[offset..initial.len() - 4].to_vec()
            }
            TestLegacyProtocol::AuthSimple => {
                verify_crc_frame(&initial);
                let auth_offset = legacy_padding_offset(&initial, 2, false)?;
                let timestamp =
                    u32::from_le_bytes(initial[auth_offset..auth_offset + 4].try_into()?);
                assert!(timestamp > 1_700_000_000);
                initial[auth_offset + 12..initial.len() - 4].to_vec()
            }
            TestLegacyProtocol::AuthSha1 => {
                assert_eq!(
                    u32::from_le_bytes(initial[..4].try_into()?),
                    ssr_crc32(&server_key)
                );
                let auth_offset = legacy_padding_offset(&initial, 6, false)?;
                let timestamp =
                    u32::from_le_bytes(initial[auth_offset..auth_offset + 4].try_into()?);
                assert!(timestamp > 1_700_000_000);
                let mut hmac_key = request_iv.clone();
                hmac_key.extend_from_slice(&server_key);
                assert_eq!(
                    &initial[initial.len() - 10..],
                    &hmac_sha1(&hmac_key, &initial[..initial.len() - 10])[..10]
                );
                initial[auth_offset + 12..initial.len() - 10].to_vec()
            }
            TestLegacyProtocol::AuthSha1V2 => {
                let mut crc_input = b"auth_sha1_v2".to_vec();
                crc_input.extend_from_slice(&server_key);
                assert_eq!(
                    u32::from_le_bytes(initial[..4].try_into()?),
                    ssr_crc32(&crc_input)
                );
                let auth_offset = legacy_padding_offset(&initial, 6, true)?;
                let mut hmac_key = request_iv.clone();
                hmac_key.extend_from_slice(&server_key);
                assert_eq!(
                    &initial[initial.len() - 10..],
                    &hmac_sha1(&hmac_key, &initial[..initial.len() - 10])[..10]
                );
                initial[auth_offset + 12..initial.len() - 10].to_vec()
            }
        };
        assert_eq!(target, expected_destination);

        let upload = read_outer_frame(&mut stream, &mut decryptor, 2, 0).await?;
        let upload_offset = match protocol {
            TestLegacyProtocol::VerifySimple | TestLegacyProtocol::AuthSimple => {
                verify_crc_frame(&upload);
                legacy_padding_offset(&upload, 2, false)?
            }
            TestLegacyProtocol::AuthSha1 => {
                assert_eq!(
                    u32::from_le_bytes(upload[upload.len() - 4..].try_into()?),
                    ssr_adler32(&upload[..upload.len() - 4])
                );
                legacy_padding_offset(&upload, 2, false)?
            }
            TestLegacyProtocol::AuthSha1V2 => {
                assert_eq!(
                    u32::from_le_bytes(upload[upload.len() - 4..].try_into()?),
                    ssr_adler32(&upload[..upload.len() - 4])
                );
                legacy_padding_offset(&upload, 2, true)?
            }
        };
        assert_eq!(&upload[upload_offset..upload.len() - 4], b"ping");

        let response_iv = vec![0xd1; cipher.iv_len()];
        let mut response = match protocol {
            TestLegacyProtocol::VerifySimple | TestLegacyProtocol::AuthSimple => {
                build_legacy_crc_response(b"pong")
            }
            TestLegacyProtocol::AuthSha1 | TestLegacyProtocol::AuthSha1V2 => {
                build_legacy_adler_response(b"pong")
            }
        };
        cipher
            .encryptor(&server_key, &response_iv)?
            .apply(&mut response);
        stream.write_all(&response_iv).await?;
        stream.write_all(&response).await?;
        stream.flush().await?;
        anyhow::Ok(())
    });

    let outbounds = build_outbounds(
        &[OutboundConfig::Ssr {
            name: "ssr-legacy".to_string(),
            server: "127.0.0.1".to_string(),
            port: address.port(),
            method: "aes-128-cfb".to_string(),
            password: password.to_string(),
            protocol: protocol.protocol().to_string(),
            obfs: "plain".to_string(),
            protocol_param: None,
            obfs_param: None,
        }],
        None,
    )?;
    let mut tunnel = outbounds
        .get("ssr-legacy")
        .context("missing SSR legacy outbound")?
        .connect(&destination, 3000)
        .await?;
    tunnel.write_all(b"ping").await?;
    tunnel.flush().await?;
    let mut response = [0u8; 4];
    timeout(Duration::from_secs(3), tunnel.read_exact(&mut response))
        .await
        .context("SSR legacy response timed out")??;
    assert_eq!(&response, b"pong");
    server.await??;
    Ok(())
}

async fn run_ssr_legacy_udp(protocol: TestLegacyProtocol) -> anyhow::Result<()> {
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let address = socket.local_addr()?;
    let password = "ssr-legacy-udp-password";
    let destination = Destination::new("dns.example", 53);
    let expected_destination = destination_bytes(&destination);
    let server_password = password.as_bytes().to_vec();

    let server = tokio::spawn(async move {
        let mut packet = vec![0u8; 65_535];
        let (length, source) = socket.recv_from(&mut packet).await?;
        packet.truncate(length);
        let cipher = TestCipher::Aes128Cfb;
        let server_key = evp_bytes_to_key(&server_password, cipher.key_len());
        let request_iv = packet[..cipher.iv_len()].to_vec();
        let mut request = packet[cipher.iv_len()..].to_vec();
        cipher
            .decryptor(&server_key, &request_iv)?
            .apply(&mut request);
        assert_eq!(&request[..expected_destination.len()], expected_destination);
        assert_eq!(&request[expected_destination.len()..], b"query");

        let response_iv = vec![0xd2; cipher.iv_len()];
        let mut response = expected_destination;
        response.extend_from_slice(b"answer");
        cipher
            .encryptor(&server_key, &response_iv)?
            .apply(&mut response);
        let mut response_packet = response_iv;
        response_packet.extend_from_slice(&response);
        socket.send_to(&response_packet, source).await?;
        anyhow::Ok(())
    });

    let outbounds = build_outbounds(
        &[OutboundConfig::Ssr {
            name: "ssr-legacy-udp".to_string(),
            server: "127.0.0.1".to_string(),
            port: address.port(),
            method: "aes-128-cfb".to_string(),
            password: password.to_string(),
            protocol: protocol.protocol().to_string(),
            obfs: "plain".to_string(),
            protocol_param: None,
            obfs_param: None,
        }],
        None,
    )?;
    let response = outbounds
        .get("ssr-legacy-udp")
        .context("missing SSR legacy UDP outbound")?
        .udp_exchange(&destination, b"query", 3000)
        .await?;
    assert_eq!(response, b"answer");
    server.await??;
    Ok(())
}

#[tokio::test]
async fn ssr_auth_sha1_v4_tcp_real_dial() -> anyhow::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let password = "ssr-auth-password";
    let destination = Destination::new("target.example", 443);
    let expected_destination = destination_bytes(&destination);
    let server_password = password.as_bytes().to_vec();

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let cipher = TestCipher::Aes128Cfb;
        let key = evp_bytes_to_key(&server_password, cipher.key_len());
        let mut request_iv = vec![0u8; cipher.iv_len()];
        stream.read_exact(&mut request_iv).await?;
        let mut decryptor = cipher.decryptor(&key, &request_iv)?;

        let mut encrypted_length = [0u8; 2];
        stream.read_exact(&mut encrypted_length).await?;
        decryptor.apply(&mut encrypted_length);
        let frame_len = u16::from_be_bytes(encrypted_length) as usize;
        let mut frame = vec![0u8; frame_len];
        frame[..2].copy_from_slice(&encrypted_length);
        stream.read_exact(&mut frame[2..]).await?;
        decryptor.apply(&mut frame[2..]);

        let mut crc_input = Vec::new();
        crc_input.extend_from_slice(&frame[..2]);
        crc_input.extend_from_slice(b"auth_sha1_v4");
        crc_input.extend_from_slice(&key);
        assert_eq!(
            u32::from_le_bytes(frame[2..6].try_into()?),
            ssr_crc32(&crc_input)
        );
        let rand_len = frame[6] as usize;
        let auth_offset = 6 + rand_len;
        let timestamp = u32::from_le_bytes(frame[auth_offset..auth_offset + 4].try_into()?);
        assert!(timestamp > 1_700_000_000);
        let payload_offset = auth_offset + 12;
        let payload_end = frame_len - 10;
        assert_eq!(&frame[payload_offset..payload_end], expected_destination);
        let mut hmac_key = request_iv.clone();
        hmac_key.extend_from_slice(&key);
        assert_eq!(
            &frame[payload_end..],
            &hmac_sha1(&hmac_key, &frame[..payload_end])[..10]
        );

        let mut encrypted_prefix = [0u8; 4];
        stream.read_exact(&mut encrypted_prefix).await?;
        decryptor.apply(&mut encrypted_prefix);
        let data_len = u16::from_be_bytes(encrypted_prefix[..2].try_into()?) as usize;
        let mut data_frame = vec![0u8; data_len];
        data_frame[..4].copy_from_slice(&encrypted_prefix);
        stream.read_exact(&mut data_frame[4..]).await?;
        decryptor.apply(&mut data_frame[4..]);
        assert_eq!(
            u16::from_le_bytes(data_frame[2..4].try_into()?),
            ssr_crc32(&data_frame[..2]) as u16
        );
        let payload_offset = 4 + data_frame[4] as usize;
        assert_eq!(&data_frame[payload_offset..data_len - 4], b"ping");
        assert_eq!(
            u32::from_le_bytes(data_frame[data_len - 4..].try_into()?),
            ssr_adler32(&data_frame[..data_len - 4])
        );

        let response_iv = vec![0x88; cipher.iv_len()];
        let mut response = build_auth_sha1_v4_data(b"pong");
        cipher.encryptor(&key, &response_iv)?.apply(&mut response);
        stream.write_all(&response_iv).await?;
        stream.write_all(&response).await?;
        stream.flush().await?;
        anyhow::Ok(())
    });

    let outbounds = build_outbounds(
        &[OutboundConfig::Ssr {
            name: "ssr-auth".to_string(),
            server: "127.0.0.1".to_string(),
            port: address.port(),
            method: "aes-128-cfb".to_string(),
            password: password.to_string(),
            protocol: "auth_sha1_v4".to_string(),
            obfs: "plain".to_string(),
            protocol_param: None,
            obfs_param: None,
        }],
        None,
    )?;
    let mut tunnel = outbounds
        .get("ssr-auth")
        .context("missing auth_sha1_v4 outbound")?
        .connect(&destination, 3000)
        .await?;
    tunnel.write_all(b"ping").await?;
    tunnel.flush().await?;
    let mut response = [0u8; 4];
    timeout(Duration::from_secs(3), tunnel.read_exact(&mut response))
        .await
        .context("auth_sha1_v4 response timed out")??;
    assert_eq!(&response, b"pong");
    server.await??;
    Ok(())
}

async fn run_ssr_auth_aes(
    protocol: &'static str,
    hash: TestAuthHash,
    protocol_param: Option<&'static str>,
    corrupt_response: bool,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let password = "ssr-auth-aes-password";
    let destination = Destination::new("target.example", 443);
    let expected_destination = destination_bytes(&destination);
    let server_password = password.as_bytes().to_vec();
    let expected_user = protocol_param.map(|value| {
        let (uid, password) = value.split_once(':').unwrap();
        (uid.parse::<u32>().unwrap(), hash.hash(password.as_bytes()))
    });

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let cipher = TestCipher::Aes128Cfb;
        let server_key = evp_bytes_to_key(&server_password, cipher.key_len());
        let mut request_iv = vec![0u8; cipher.iv_len()];
        stream.read_exact(&mut request_iv).await?;
        let mut decryptor = cipher.decryptor(&server_key, &request_iv)?;

        let mut prefix = vec![0u8; 31];
        stream.read_exact(&mut prefix).await?;
        decryptor.apply(&mut prefix);
        let mut request_hmac_key = request_iv.clone();
        request_hmac_key.extend_from_slice(&server_key);
        assert_eq!(
            &prefix[1..7],
            &hash.hmac(&request_hmac_key, &prefix[..1])[..6]
        );
        assert_eq!(
            &prefix[27..31],
            &hash.hmac(&request_hmac_key, &prefix[7..27])[..4]
        );

        let uid = u32::from_le_bytes(prefix[7..11].try_into()?);
        let user_key = expected_user
            .as_ref()
            .map(|(_, key)| key.clone())
            .unwrap_or_else(|| server_key.clone());
        if let Some((expected_uid, _)) = expected_user.as_ref() {
            assert_eq!(uid, *expected_uid);
        }
        use base64::Engine as _;
        let mut aes_password = base64::engine::general_purpose::STANDARD.encode(&user_key);
        aes_password.push_str(protocol);
        let aes_key = evp_bytes_to_key(aes_password.as_bytes(), 16);
        let auth = decrypt_aes128_block(&aes_key, &prefix[11..27])?;
        let timestamp = u32::from_le_bytes(auth[..4].try_into()?);
        assert!(timestamp > 1_700_000_000);
        let frame_len = u16::from_le_bytes(auth[12..14].try_into()?) as usize;
        let rand_len = u16::from_le_bytes(auth[14..16].try_into()?) as usize;
        let mut frame = prefix;
        frame.resize(frame_len, 0);
        stream.read_exact(&mut frame[31..]).await?;
        decryptor.apply(&mut frame[31..]);
        let payload_offset = 31 + rand_len;
        assert_eq!(&frame[payload_offset..frame_len - 4], expected_destination);
        assert_eq!(
            &frame[frame_len - 4..],
            &hash.hmac(&user_key, &frame[..frame_len - 4])[..4]
        );

        let mut encrypted_prefix = [0u8; 4];
        stream.read_exact(&mut encrypted_prefix).await?;
        decryptor.apply(&mut encrypted_prefix);
        let data_len = u16::from_le_bytes(encrypted_prefix[..2].try_into()?) as usize;
        let mut data_frame = vec![0u8; data_len];
        data_frame[..4].copy_from_slice(&encrypted_prefix);
        stream.read_exact(&mut data_frame[4..]).await?;
        decryptor.apply(&mut data_frame[4..]);
        let mut packet_key = user_key.clone();
        packet_key.extend_from_slice(&1u32.to_le_bytes());
        assert_eq!(
            &data_frame[2..4],
            &hash.hmac(&packet_key, &data_frame[..2])[..2]
        );
        let data_offset = 4 + data_frame[4] as usize;
        assert_eq!(&data_frame[data_offset..data_len - 4], b"ping");
        assert_eq!(
            &data_frame[data_len - 4..],
            &hash.hmac(&packet_key, &data_frame[..data_len - 4])[..4]
        );

        let response_iv = vec![0x99; cipher.iv_len()];
        let mut response = build_auth_aes_data(hash, &user_key, 1, b"pong");
        if corrupt_response {
            let last = response.len() - 1;
            response[last] ^= 0x80;
        }
        cipher
            .encryptor(&server_key, &response_iv)?
            .apply(&mut response);
        stream.write_all(&response_iv).await?;
        stream.write_all(&response).await?;
        stream.flush().await?;
        anyhow::Ok(())
    });

    let outbounds = build_outbounds(
        &[OutboundConfig::Ssr {
            name: "ssr-auth-aes".to_string(),
            server: "127.0.0.1".to_string(),
            port: address.port(),
            method: "aes-128-cfb".to_string(),
            password: password.to_string(),
            protocol: protocol.to_string(),
            obfs: "plain".to_string(),
            protocol_param: protocol_param.map(ToString::to_string),
            obfs_param: None,
        }],
        None,
    )?;
    let mut tunnel = outbounds
        .get("ssr-auth-aes")
        .context("missing SSR AES auth outbound")?
        .connect(&destination, 3000)
        .await?;
    tunnel.write_all(b"ping").await?;
    tunnel.flush().await?;
    let mut response = [0u8; 4];
    let read = timeout(Duration::from_secs(3), tunnel.read_exact(&mut response))
        .await
        .context("SSR AES auth response timed out")?;
    if corrupt_response {
        assert!(read.is_err(), "corrupt SSR response unexpectedly succeeded");
    } else {
        read?;
        assert_eq!(&response, b"pong");
    }
    server.await??;
    Ok(())
}

async fn run_ssr_auth_aes_udp(
    protocol: &'static str,
    hash: TestAuthHash,
    protocol_param: Option<&'static str>,
) -> anyhow::Result<()> {
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let address = socket.local_addr()?;
    let password = "ssr-auth-udp-password";
    let destination = Destination::new("dns.example", 53);
    let expected_destination = destination_bytes(&destination);
    let server_password = password.as_bytes().to_vec();
    let expected_user = protocol_param.map(|value| {
        let (uid, password) = value.split_once(':').unwrap();
        (uid.parse::<u32>().unwrap(), hash.hash(password.as_bytes()))
    });

    let server = tokio::spawn(async move {
        let mut packet = vec![0u8; 65_535];
        let (length, source) = socket.recv_from(&mut packet).await?;
        packet.truncate(length);
        let cipher = TestCipher::Aes128Cfb;
        let request_iv = packet[..cipher.iv_len()].to_vec();
        let server_key = evp_bytes_to_key(&server_password, cipher.key_len());
        let mut plaintext = packet[cipher.iv_len()..].to_vec();
        cipher
            .decryptor(&server_key, &request_iv)?
            .apply(&mut plaintext);
        assert!(plaintext.len() > expected_destination.len() + 8);
        let hmac_offset = plaintext.len() - 4;
        let uid_offset = hmac_offset - 4;
        let uid = u32::from_le_bytes(plaintext[uid_offset..hmac_offset].try_into()?);
        let user_key = expected_user
            .as_ref()
            .map(|(_, key)| key.clone())
            .unwrap_or_else(|| server_key.clone());
        if let Some((expected_uid, _)) = expected_user.as_ref() {
            assert_eq!(uid, *expected_uid);
        }
        assert_eq!(
            &plaintext[hmac_offset..],
            &hash.hmac(&user_key, &plaintext[..hmac_offset])[..4]
        );
        assert_eq!(
            &plaintext[..expected_destination.len()],
            expected_destination
        );
        assert_eq!(&plaintext[expected_destination.len()..uid_offset], b"query");

        let response_iv = vec![0xaa; cipher.iv_len()];
        let mut response = expected_destination;
        response.extend_from_slice(b"answer");
        let hmac = hash.hmac(&server_key, &response);
        response.extend_from_slice(&hmac[..4]);
        cipher
            .encryptor(&server_key, &response_iv)?
            .apply(&mut response);
        let mut response_packet = response_iv;
        response_packet.extend_from_slice(&response);
        socket.send_to(&response_packet, source).await?;
        anyhow::Ok(())
    });

    let outbounds = build_outbounds(
        &[OutboundConfig::Ssr {
            name: "ssr-auth-udp".to_string(),
            server: "127.0.0.1".to_string(),
            port: address.port(),
            method: "aes-128-cfb".to_string(),
            password: password.to_string(),
            protocol: protocol.to_string(),
            obfs: "plain".to_string(),
            protocol_param: protocol_param.map(ToString::to_string),
            obfs_param: None,
        }],
        None,
    )?;
    let response = outbounds
        .get("ssr-auth-udp")
        .context("missing SSR AES auth UDP outbound")?
        .udp_exchange(&destination, b"query", 3000)
        .await?;
    assert_eq!(response, b"answer");
    server.await??;
    Ok(())
}

async fn run_ssr_auth_chain_tcp(
    kind: TestAuthChainKind,
    protocol_param: Option<&'static str>,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let password = "ssr-auth-chain-password";
    let destination = Destination::new("target.example", 443);
    let expected_destination = destination_bytes(&destination);
    let server_password = password.as_bytes().to_vec();
    let chain_f_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs()
        / 86_400;
    let expected_user = protocol_param.map(|value| {
        let (uid, password) = value.split_once(':').unwrap();
        (uid.parse::<u32>().unwrap(), password.as_bytes().to_vec())
    });

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let cipher = TestCipher::Aes128Cfb;
        let server_key = evp_bytes_to_key(&server_password, cipher.key_len());
        let mut request_iv = vec![0u8; cipher.iv_len()];
        stream.read_exact(&mut request_iv).await?;
        let mut outer_decryptor = cipher.decryptor(&server_key, &request_iv)?;

        let mut header = [0u8; 36];
        stream.read_exact(&mut header).await?;
        outer_decryptor.apply(&mut header);
        let mut request_hmac_key = request_iv.clone();
        request_hmac_key.extend_from_slice(&server_key);
        let client_hash = hmac_md5(&request_hmac_key, &header[..4]);
        assert_eq!(&header[4..12], &client_hash[..8]);

        let uid = u32::from_le_bytes([
            header[12] ^ client_hash[8],
            header[13] ^ client_hash[9],
            header[14] ^ client_hash[10],
            header[15] ^ client_hash[11],
        ]);
        let user_key = expected_user
            .as_ref()
            .map(|(_, key)| key.clone())
            .unwrap_or_else(|| server_key.clone());
        if let Some((expected_uid, _)) = expected_user.as_ref() {
            assert_eq!(uid, *expected_uid);
        }

        use base64::Engine as _;
        let mut aes_password = base64::engine::general_purpose::STANDARD.encode(&user_key);
        aes_password.push_str(kind.protocol());
        let aes_key = evp_bytes_to_key(aes_password.as_bytes(), 16);
        let auth = decrypt_aes128_block(&aes_key, &header[16..32])?;
        let timestamp = u32::from_le_bytes(auth[..4].try_into()?);
        assert!(timestamp > 1_700_000_000);
        assert_eq!(u16::from_le_bytes(auth[12..14].try_into()?), 4);
        assert_eq!(u16::from_le_bytes(auth[14..16].try_into()?), 0);

        let server_hash = hmac_md5(&user_key, &header[12..32]);
        assert_eq!(&header[32..36], &server_hash[..4]);
        let mut inner_decryptor = auth_chain_rc4(&user_key, &client_hash)?;
        let (target, next_client_hash) = read_auth_chain_frame(
            kind,
            &mut stream,
            &mut outer_decryptor,
            &mut inner_decryptor,
            &server_key,
            &user_key,
            client_hash,
            1,
            chain_f_epoch,
        )
        .await?;
        assert_eq!(target, expected_destination);
        let (upload, _) = read_auth_chain_frame(
            kind,
            &mut stream,
            &mut outer_decryptor,
            &mut inner_decryptor,
            &server_key,
            &user_key,
            next_client_hash,
            2,
            chain_f_epoch,
        )
        .await?;
        assert_eq!(upload, b"ping");

        let response_iv = vec![0xc1; cipher.iv_len()];
        let mut inner_encryptor = auth_chain_rc4(&user_key, &client_hash)?;
        let mut response_payload = 1460u16.to_le_bytes().to_vec();
        response_payload.extend_from_slice(b"pong");
        let (mut response, _) = build_auth_chain_frame(
            kind,
            &response_payload,
            &mut inner_encryptor,
            &server_key,
            &user_key,
            server_hash,
            1,
            chain_f_epoch,
        );
        cipher
            .encryptor(&server_key, &response_iv)?
            .apply(&mut response);
        stream.write_all(&response_iv).await?;
        stream.write_all(&response).await?;
        stream.flush().await?;
        anyhow::Ok(())
    });

    let outbounds = build_outbounds(
        &[OutboundConfig::Ssr {
            name: "ssr-auth-chain".to_string(),
            server: "127.0.0.1".to_string(),
            port: address.port(),
            method: "aes-128-cfb".to_string(),
            password: password.to_string(),
            protocol: kind.protocol().to_string(),
            obfs: "plain".to_string(),
            protocol_param: protocol_param.map(ToString::to_string),
            obfs_param: None,
        }],
        None,
    )?;
    let mut tunnel = outbounds
        .get("ssr-auth-chain")
        .context("missing SSR auth-chain outbound")?
        .connect(&destination, 3000)
        .await?;
    tunnel.write_all(b"ping").await?;
    tunnel.flush().await?;
    let mut response = [0u8; 4];
    timeout(Duration::from_secs(3), tunnel.read_exact(&mut response))
        .await
        .context("SSR auth-chain response timed out")??;
    assert_eq!(&response, b"pong");
    server.await??;
    Ok(())
}

async fn run_ssr_auth_chain_udp(kind: TestAuthChainKind) -> anyhow::Result<()> {
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let address = socket.local_addr()?;
    let password = "ssr-auth-chain-udp-password";
    let destination = Destination::new("dns.example", 53);
    let expected_destination = destination_bytes(&destination);
    let server_password = password.as_bytes().to_vec();

    let server = tokio::spawn(async move {
        let mut packet = vec![0u8; 65_535];
        let (length, source) = socket.recv_from(&mut packet).await?;
        packet.truncate(length);
        let cipher = TestCipher::Aes128Cfb;
        let server_key = evp_bytes_to_key(&server_password, cipher.key_len());
        let request_iv = packet[..cipher.iv_len()].to_vec();
        let mut plaintext = packet[cipher.iv_len()..].to_vec();
        cipher
            .decryptor(&server_key, &request_iv)?
            .apply(&mut plaintext);
        assert!(plaintext.len() > 8);

        let auth_data = &plaintext[plaintext.len() - 8..plaintext.len() - 5];
        let hash = hmac_md5(&server_key, auth_data);
        let uid_offset = plaintext.len() - 5;
        let _uid = u32::from_le_bytes([
            plaintext[uid_offset] ^ hash[0],
            plaintext[uid_offset + 1] ^ hash[1],
            plaintext[uid_offset + 2] ^ hash[2],
            plaintext[uid_offset + 3] ^ hash[3],
        ]);
        let request_hmac = hmac_md5(&server_key, &plaintext[..plaintext.len() - 1]);
        assert_eq!(plaintext[plaintext.len() - 1], request_hmac[0]);
        let rand_len = auth_chain_udp_rand_len(&hash);
        let payload_len = plaintext.len() - rand_len - 8;
        let mut request = plaintext[..payload_len].to_vec();
        auth_chain_rc4(&server_key, &hash)?.apply(&mut request);
        assert_eq!(&request[..expected_destination.len()], expected_destination);
        assert_eq!(&request[expected_destination.len()..], b"query");

        let auth_data = [0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27];
        let response_hash = hmac_md5(&server_key, &auth_data);
        let response_rand_len = auth_chain_udp_rand_len(&response_hash);
        let mut response = expected_destination;
        response.extend_from_slice(b"answer");
        auth_chain_rc4(&server_key, &response_hash)?.apply(&mut response);
        response.resize(response.len() + response_rand_len, 0x6b);
        response.extend_from_slice(&auth_data);
        let response_hmac = hmac_md5(&server_key, &response);
        response.push(response_hmac[0]);

        let response_iv = vec![0xc2; cipher.iv_len()];
        cipher
            .encryptor(&server_key, &response_iv)?
            .apply(&mut response);
        let mut response_packet = response_iv;
        response_packet.extend_from_slice(&response);
        socket.send_to(&response_packet, source).await?;
        anyhow::Ok(())
    });

    let outbounds = build_outbounds(
        &[OutboundConfig::Ssr {
            name: "ssr-auth-chain-udp".to_string(),
            server: "127.0.0.1".to_string(),
            port: address.port(),
            method: "aes-128-cfb".to_string(),
            password: password.to_string(),
            protocol: kind.protocol().to_string(),
            obfs: "plain".to_string(),
            protocol_param: None,
            obfs_param: None,
        }],
        None,
    )?;
    let response = outbounds
        .get("ssr-auth-chain-udp")
        .context("missing SSR auth-chain UDP outbound")?
        .udp_exchange(&destination, b"query", 3000)
        .await?;
    assert_eq!(response, b"answer");
    server.await??;
    Ok(())
}

async fn run_ssr_tls12_ticket_obfs(mode: &'static str) -> anyhow::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let password = "ssr-ticket-password";
    let destination = Destination::new("target.example", 443);
    let expected_destination = destination_bytes(&destination);
    let server_password = password.as_bytes().to_vec();

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let cipher = TestCipher::Aes128Cfb;
        let server_key = evp_bytes_to_key(&server_password, cipher.key_len());

        let (content_type, version, client_hello) = read_tls_record(&mut stream).await?;
        assert_eq!(content_type, 0x16);
        assert_eq!(version, [0x03, 0x01]);
        assert_eq!(client_hello[0], 0x01);
        assert_eq!(&client_hello[4..6], &[0x03, 0x03]);
        let client_auth = &client_hello[6..38];
        assert_eq!(client_hello[38], 32);
        let mut client_id = [0u8; 32];
        client_id.copy_from_slice(&client_hello[39..71]);
        let mut hmac_key = server_key.clone();
        hmac_key.extend_from_slice(&client_id);
        assert_eq!(
            &client_auth[22..],
            &hmac_sha1(&hmac_key, &client_auth[..22])[..10]
        );

        let mut server_auth = [0u8; 32];
        server_auth[..4].copy_from_slice(
            &(std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs() as u32)
                .to_be_bytes(),
        );
        server_auth[4..22].fill(0x55);
        let server_auth_hmac = hmac_sha1(&hmac_key, &server_auth[..22]);
        server_auth[22..].copy_from_slice(&server_auth_hmac[..10]);
        let mut server_hello_body = Vec::new();
        server_hello_body.extend_from_slice(&[0x03, 0x03]);
        server_hello_body.extend_from_slice(&server_auth);
        server_hello_body.push(32);
        server_hello_body.extend_from_slice(&client_id);
        server_hello_body
            .extend_from_slice(&[0xc0, 0x2f, 0x00, 0x00, 0x05, 0xff, 0x01, 0x00, 0x01, 0x00]);
        let mut server_hello = vec![0x02, 0x00];
        server_hello.extend_from_slice(&(server_hello_body.len() as u16).to_be_bytes());
        server_hello.extend_from_slice(&server_hello_body);

        let mut server_handshake = tls_record(0x16, &server_hello);
        server_handshake.extend_from_slice(&tls_record(0x14, &[0x01]));
        let mut finish_payload = vec![0x66; 22];
        let finish_header = tls_record(0x16, &[0u8; 32]);
        let mut finish_prefix = finish_header[..5].to_vec();
        finish_prefix.extend_from_slice(&finish_payload);
        let mut hmac_input = server_handshake.clone();
        hmac_input.extend_from_slice(&finish_prefix);
        finish_payload.extend_from_slice(&hmac_sha1(&hmac_key, &hmac_input)[..10]);
        server_handshake.extend_from_slice(&tls_record(0x16, &finish_payload));
        stream.write_all(&server_handshake).await?;
        stream.flush().await?;

        let (content_type, _, change_cipher) = read_tls_record(&mut stream).await?;
        assert_eq!(content_type, 0x14);
        assert_eq!(change_cipher, [0x01]);
        let (content_type, version, client_finish) = read_tls_record(&mut stream).await?;
        assert_eq!(content_type, 0x16);
        let mut finish_message = tls_record(content_type, &client_finish);
        finish_message[1..3].copy_from_slice(&version);
        let mut full_client_finish = tls_record(0x14, &[0x01]);
        full_client_finish.extend_from_slice(&finish_message);
        let finish_offset = full_client_finish.len() - 10;
        assert_eq!(
            &full_client_finish[finish_offset..],
            &hmac_sha1(&hmac_key, &full_client_finish[..finish_offset])[..10]
        );

        let (content_type, _, initial) = read_tls_record(&mut stream).await?;
        assert_eq!(content_type, 0x17);
        let request_iv = initial[..cipher.iv_len()].to_vec();
        let mut decryptor = cipher.decryptor(&server_key, &request_iv)?;
        let mut target = initial[cipher.iv_len()..].to_vec();
        decryptor.apply(&mut target);
        assert_eq!(target, expected_destination);

        let (content_type, _, mut upload) = read_tls_record(&mut stream).await?;
        assert_eq!(content_type, 0x17);
        decryptor.apply(&mut upload);
        assert_eq!(upload, b"ping");

        let response_iv = vec![0xbb; cipher.iv_len()];
        let mut pong = b"pong".to_vec();
        cipher
            .encryptor(&server_key, &response_iv)?
            .apply(&mut pong);
        let mut response = response_iv;
        response.extend_from_slice(&pong);
        stream.write_all(&tls_record(0x17, &response)).await?;
        stream.flush().await?;
        anyhow::Ok(())
    });

    let outbounds = build_outbounds(
        &[OutboundConfig::Ssr {
            name: "ssr-ticket".to_string(),
            server: "127.0.0.1".to_string(),
            port: address.port(),
            method: "aes-128-cfb".to_string(),
            password: password.to_string(),
            protocol: "origin".to_string(),
            obfs: mode.to_string(),
            protocol_param: None,
            obfs_param: Some("obfs.example".to_string()),
        }],
        None,
    )?;
    let mut tunnel = outbounds
        .get("ssr-ticket")
        .context("missing SSR TLS ticket outbound")?
        .connect(&destination, 3000)
        .await?;
    tunnel.write_all(b"ping").await?;
    tunnel.flush().await?;
    let mut response = [0u8; 4];
    timeout(Duration::from_secs(3), tunnel.read_exact(&mut response))
        .await
        .context("SSR TLS ticket response timed out")??;
    assert_eq!(&response, b"pong");
    server.await??;
    Ok(())
}

#[tokio::test]
async fn ssr_tls12_ticket_auth_obfs_real_dial() -> anyhow::Result<()> {
    run_ssr_tls12_ticket_obfs("tls1.2_ticket_auth").await
}

#[tokio::test]
async fn ssr_tls12_ticket_fastauth_obfs_real_dial() -> anyhow::Result<()> {
    run_ssr_tls12_ticket_obfs("tls1.2_ticket_fastauth").await
}

#[tokio::test]
async fn ssr_auth_aes128_md5_tcp_real_dial() -> anyhow::Result<()> {
    run_ssr_auth_aes("auth_aes128_md5", TestAuthHash::Md5, None, false).await
}

#[tokio::test]
async fn ssr_auth_aes128_sha1_multi_user_tcp_real_dial() -> anyhow::Result<()> {
    run_ssr_auth_aes(
        "auth_aes128_sha1",
        TestAuthHash::Sha1,
        Some("1001:user-secret"),
        false,
    )
    .await
}

#[tokio::test]
async fn ssr_auth_aes_rejects_corrupt_response_state() -> anyhow::Result<()> {
    run_ssr_auth_aes("auth_aes128_md5", TestAuthHash::Md5, None, true).await
}

#[tokio::test]
async fn ssr_auth_aes_wrong_password_cannot_authenticate() -> anyhow::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let destination = Destination::new("wrong-password.example", 443);
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let cipher = TestCipher::Aes128Cfb;
        let server_key = evp_bytes_to_key(b"correct-password", cipher.key_len());
        let mut request_iv = vec![0u8; cipher.iv_len()];
        stream.read_exact(&mut request_iv).await?;
        let mut prefix = vec![0u8; 31];
        stream.read_exact(&mut prefix).await?;
        cipher
            .decryptor(&server_key, &request_iv)?
            .apply(&mut prefix);
        let mut hmac_key = request_iv;
        hmac_key.extend_from_slice(&server_key);
        assert_ne!(
            &prefix[1..7],
            &TestAuthHash::Md5.hmac(&hmac_key, &prefix[..1])[..6]
        );
        anyhow::Ok(())
    });
    let outbounds = build_outbounds(
        &[OutboundConfig::Ssr {
            name: "ssr-wrong-password".to_string(),
            server: "127.0.0.1".to_string(),
            port: address.port(),
            method: "aes-128-cfb".to_string(),
            password: "wrong-password".to_string(),
            protocol: "auth_aes128_md5".to_string(),
            obfs: "plain".to_string(),
            protocol_param: None,
            obfs_param: None,
        }],
        None,
    )?;
    let outbound = outbounds
        .get("ssr-wrong-password")
        .context("missing SSR wrong-password outbound")?;
    let mut tunnel = outbound.connect(&destination, 3000).await?;
    tunnel.write_all(b"ping").await?;
    tunnel.flush().await?;
    let mut response = [0u8; 1];
    let read = timeout(Duration::from_secs(3), tunnel.read(&mut response)).await??;
    assert_eq!(read, 0);
    server.await??;
    Ok(())
}

#[tokio::test]
async fn ssr_auth_aes128_md5_udp_real_dial() -> anyhow::Result<()> {
    run_ssr_auth_aes_udp("auth_aes128_md5", TestAuthHash::Md5, None).await
}

#[tokio::test]
async fn ssr_auth_aes128_sha1_multi_user_udp_real_dial() -> anyhow::Result<()> {
    run_ssr_auth_aes_udp(
        "auth_aes128_sha1",
        TestAuthHash::Sha1,
        Some("1001:user-secret"),
    )
    .await
}

#[tokio::test]
async fn ssr_verify_simple_tcp_real_dial() -> anyhow::Result<()> {
    run_ssr_legacy_tcp(TestLegacyProtocol::VerifySimple).await
}

#[tokio::test]
async fn ssr_verify_simple_udp_real_dial() -> anyhow::Result<()> {
    run_ssr_legacy_udp(TestLegacyProtocol::VerifySimple).await
}

#[tokio::test]
async fn ssr_auth_simple_tcp_real_dial() -> anyhow::Result<()> {
    run_ssr_legacy_tcp(TestLegacyProtocol::AuthSimple).await
}

#[tokio::test]
async fn ssr_auth_simple_udp_real_dial() -> anyhow::Result<()> {
    run_ssr_legacy_udp(TestLegacyProtocol::AuthSimple).await
}

#[tokio::test]
async fn ssr_auth_sha1_tcp_real_dial() -> anyhow::Result<()> {
    run_ssr_legacy_tcp(TestLegacyProtocol::AuthSha1).await
}

#[tokio::test]
async fn ssr_auth_sha1_udp_real_dial() -> anyhow::Result<()> {
    run_ssr_legacy_udp(TestLegacyProtocol::AuthSha1).await
}

#[tokio::test]
async fn ssr_auth_sha1_v2_tcp_real_dial() -> anyhow::Result<()> {
    run_ssr_legacy_tcp(TestLegacyProtocol::AuthSha1V2).await
}

#[tokio::test]
async fn ssr_auth_sha1_v2_udp_real_dial() -> anyhow::Result<()> {
    run_ssr_legacy_udp(TestLegacyProtocol::AuthSha1V2).await
}

#[tokio::test]
async fn ssr_auth_chain_a_multi_user_tcp_real_dial() -> anyhow::Result<()> {
    run_ssr_auth_chain_tcp(TestAuthChainKind::A, Some("1001:user-secret")).await
}

#[tokio::test]
async fn ssr_auth_chain_a_udp_real_dial() -> anyhow::Result<()> {
    run_ssr_auth_chain_udp(TestAuthChainKind::A).await
}

#[tokio::test]
async fn ssr_auth_chain_b_multi_user_tcp_real_dial() -> anyhow::Result<()> {
    run_ssr_auth_chain_tcp(TestAuthChainKind::B, Some("1002:chain-b-secret")).await
}

#[tokio::test]
async fn ssr_auth_chain_b_udp_real_dial() -> anyhow::Result<()> {
    run_ssr_auth_chain_udp(TestAuthChainKind::B).await
}

#[tokio::test]
async fn ssr_auth_chain_c_tcp_real_dial() -> anyhow::Result<()> {
    run_ssr_auth_chain_tcp(TestAuthChainKind::C, None).await
}

#[tokio::test]
async fn ssr_auth_chain_c_udp_real_dial() -> anyhow::Result<()> {
    run_ssr_auth_chain_udp(TestAuthChainKind::C).await
}

#[tokio::test]
async fn ssr_auth_chain_d_tcp_real_dial() -> anyhow::Result<()> {
    run_ssr_auth_chain_tcp(TestAuthChainKind::D, None).await
}

#[tokio::test]
async fn ssr_auth_chain_d_udp_real_dial() -> anyhow::Result<()> {
    run_ssr_auth_chain_udp(TestAuthChainKind::D).await
}

#[tokio::test]
async fn ssr_auth_chain_e_tcp_real_dial() -> anyhow::Result<()> {
    run_ssr_auth_chain_tcp(TestAuthChainKind::E, None).await
}

#[tokio::test]
async fn ssr_auth_chain_e_udp_real_dial() -> anyhow::Result<()> {
    run_ssr_auth_chain_udp(TestAuthChainKind::E).await
}

#[tokio::test]
async fn ssr_auth_chain_f_tcp_real_dial() -> anyhow::Result<()> {
    run_ssr_auth_chain_tcp(TestAuthChainKind::F, None).await
}

#[tokio::test]
async fn ssr_auth_chain_f_udp_real_dial() -> anyhow::Result<()> {
    run_ssr_auth_chain_udp(TestAuthChainKind::F).await
}

macro_rules! tcp_test {
    ($name:ident, $cipher:expr) => {
        #[tokio::test]
        async fn $name() -> anyhow::Result<()> {
            run_ssr_tcp($cipher, TestObfs::Plain).await
        }
    };
}

macro_rules! udp_test {
    ($name:ident, $cipher:expr) => {
        #[tokio::test]
        async fn $name() -> anyhow::Result<()> {
            run_ssr_udp($cipher).await
        }
    };
}

tcp_test!(ssr_dummy_tcp_real_dial, TestCipher::Dummy);
tcp_test!(ssr_aes128_ctr_tcp_real_dial, TestCipher::Aes128Ctr);
tcp_test!(ssr_aes192_ctr_tcp_real_dial, TestCipher::Aes192Ctr);
tcp_test!(ssr_aes256_ctr_tcp_real_dial, TestCipher::Aes256Ctr);
tcp_test!(ssr_aes128_cfb_tcp_real_dial, TestCipher::Aes128Cfb);
tcp_test!(ssr_aes192_cfb_tcp_real_dial, TestCipher::Aes192Cfb);
tcp_test!(ssr_aes256_cfb_tcp_real_dial, TestCipher::Aes256Cfb);
tcp_test!(ssr_rc4_md5_tcp_real_dial, TestCipher::Rc4Md5);
tcp_test!(
    ssr_chacha20_legacy_tcp_real_dial,
    TestCipher::Chacha20Legacy
);
tcp_test!(ssr_chacha20_ietf_tcp_real_dial, TestCipher::Chacha20Ietf);
tcp_test!(ssr_xchacha20_tcp_real_dial, TestCipher::XChacha20);

udp_test!(ssr_dummy_udp_real_dial, TestCipher::Dummy);
udp_test!(ssr_aes128_ctr_udp_real_dial, TestCipher::Aes128Ctr);
udp_test!(ssr_aes192_ctr_udp_real_dial, TestCipher::Aes192Ctr);
udp_test!(ssr_aes256_ctr_udp_real_dial, TestCipher::Aes256Ctr);
udp_test!(ssr_aes128_cfb_udp_real_dial, TestCipher::Aes128Cfb);
udp_test!(ssr_aes192_cfb_udp_real_dial, TestCipher::Aes192Cfb);
udp_test!(ssr_aes256_cfb_udp_real_dial, TestCipher::Aes256Cfb);
udp_test!(ssr_rc4_md5_udp_real_dial, TestCipher::Rc4Md5);
udp_test!(
    ssr_chacha20_legacy_udp_real_dial,
    TestCipher::Chacha20Legacy
);
udp_test!(ssr_chacha20_ietf_udp_real_dial, TestCipher::Chacha20Ietf);
udp_test!(ssr_xchacha20_udp_real_dial, TestCipher::XChacha20);

#[tokio::test]
async fn ssr_large_bidirectional_stream_real_dial() -> anyhow::Result<()> {
    run_ssr_large_duplex_real_dial().await
}

#[tokio::test]
async fn ssr_udp_timeout_and_cancellation_are_bounded() -> anyhow::Result<()> {
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let outbounds = build_outbounds(
        &[OutboundConfig::Ssr {
            name: "ssr-timeout".to_string(),
            server: "127.0.0.1".to_string(),
            port: socket.local_addr()?.port(),
            method: "aes-128-cfb".to_string(),
            password: "password".to_string(),
            protocol: "origin".to_string(),
            obfs: "plain".to_string(),
            protocol_param: None,
            obfs_param: None,
        }],
        None,
    )?;
    let outbound = outbounds
        .get("ssr-timeout")
        .context("missing SSR timeout outbound")?;
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
    let cancel_error = outbound
        .udp_exchange_context(&context, b"ping")
        .await
        .unwrap_err();
    assert!(cancel_error.to_string().contains("cancelled"));
    Ok(())
}

#[tokio::test]
async fn ssr_http_simple_real_dial() -> anyhow::Result<()> {
    run_ssr_tcp(TestCipher::Aes128Cfb, TestObfs::HttpSimple).await
}

#[tokio::test]
async fn ssr_random_head_real_dial() -> anyhow::Result<()> {
    run_ssr_tcp(TestCipher::Aes128Cfb, TestObfs::RandomHead).await
}

#[tokio::test]
async fn ssr_http_post_real_dial() -> anyhow::Result<()> {
    run_ssr_tcp(TestCipher::Aes128Cfb, TestObfs::HttpPost).await
}

#[tokio::test]
async fn ssr_auth_chain_protocol_is_rejected_before_network_dial() -> anyhow::Result<()> {
    let outbounds = build_outbounds(
        &[OutboundConfig::Ssr {
            name: "ssr-auth".to_string(),
            server: "127.0.0.1".to_string(),
            port: 1,
            method: "aes-128-cfb".to_string(),
            password: "password".to_string(),
            protocol: "auth_chain_g".to_string(),
            obfs: "plain".to_string(),
            protocol_param: None,
            obfs_param: None,
        }],
        None,
    )?;
    let result = outbounds
        .get("ssr-auth")
        .context("missing SSR auth outbound")?
        .connect(&Destination::new("target.example", 443), 100)
        .await;
    let error = match result {
        Ok(_) => {
            return Err(anyhow!(
                "unsupported SSR auth protocol unexpectedly connected"
            ))
        }
        Err(error) => error,
    };
    assert!(error.to_string().contains("not implemented safely yet"));
    Ok(())
}

#[tokio::test]
async fn ssr_invalid_multi_user_param_is_rejected_before_network_dial() -> anyhow::Result<()> {
    let outbounds = build_outbounds(
        &[OutboundConfig::Ssr {
            name: "ssr-invalid-user".to_string(),
            server: "127.0.0.1".to_string(),
            port: 1,
            method: "aes-128-cfb".to_string(),
            password: "password".to_string(),
            protocol: "auth_aes128_sha1".to_string(),
            obfs: "plain".to_string(),
            protocol_param: Some("missing-separator".to_string()),
            obfs_param: None,
        }],
        None,
    )?;
    let outbound = outbounds
        .get("ssr-invalid-user")
        .context("missing SSR invalid-user outbound")?;
    let capability = outbound.capability();
    assert!(!capability.tcp_supported);
    assert!(!capability.udp_supported);
    assert!(capability
        .limitations
        .iter()
        .any(|item| item.contains("uid:password")));
    let error = outbound
        .connect(&Destination::new("target.example", 443), 100)
        .await
        .err()
        .context("invalid SSR protocol-param unexpectedly connected")?;
    assert!(error.to_string().contains("uid:password"));
    Ok(())
}
