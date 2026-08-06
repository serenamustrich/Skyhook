use anyhow::{anyhow, bail};
use getrandom::fill as random_fill;
use hmac::{Hmac, Mac};
use md5::Md5;
use sha1::Sha1;

use super::config::{OpenVpnCipher, OpenVpnDigest, OpenVpnProfile, OpenVpnTransport};

const PREMASTER_LEN: usize = 48;
const RANDOM_LEN: usize = 32;
const KEY_SLOT_LEN: usize = 128;
const EXPANDED_KEY_LEN: usize = KEY_SLOT_LEN * 2;
const TLS_EXPORTER_LABEL: &[u8] = b"EXPORTER-OpenVPN-datakeys";

#[derive(Clone)]
pub(super) struct ClientKeySource {
    pub(super) premaster: [u8; PREMASTER_LEN],
    pub(super) random1: [u8; RANDOM_LEN],
    pub(super) random2: [u8; RANDOM_LEN],
}

#[derive(Clone)]
pub(super) struct ServerKeySource {
    pub(super) random1: [u8; RANDOM_LEN],
    pub(super) random2: [u8; RANDOM_LEN],
}

pub(super) struct ServerKeyRecord {
    pub(super) source: ServerKeySource,
    pub(super) options: String,
    pub(super) consumed: usize,
}

#[derive(Clone, Debug)]
pub(super) struct KeyMaterial {
    pub(super) send_cipher: Vec<u8>,
    pub(super) send_hmac: [u8; 64],
    pub(super) receive_cipher: Vec<u8>,
    pub(super) receive_hmac: [u8; 64],
}

impl ClientKeySource {
    pub(super) fn random() -> anyhow::Result<Self> {
        let mut value = Self {
            premaster: [0; PREMASTER_LEN],
            random1: [0; RANDOM_LEN],
            random2: [0; RANDOM_LEN],
        };
        random_fill(&mut value.premaster)?;
        random_fill(&mut value.random1)?;
        random_fill(&mut value.random2)?;
        Ok(value)
    }

    pub(super) fn encode(&self, profile: &OpenVpnProfile, remote_index: usize) -> anyhow::Result<Vec<u8>> {
        let remote = profile
            .remotes
            .get(remote_index)
            .ok_or_else(|| anyhow!("OpenVPN remote index is out of range"))?;
        let options = client_options(profile, remote.transport);
        let peer_info = profile
            .peer_info
            .iter()
            .map(|(key, value)| format!("{key}={value}\n"))
            .collect::<String>();
        let mut output = Vec::with_capacity(256 + options.len() + peer_info.len());
        output.extend_from_slice(&0u32.to_be_bytes());
        output.push(2);
        output.extend_from_slice(&self.premaster);
        output.extend_from_slice(&self.random1);
        output.extend_from_slice(&self.random2);
        append_string(&mut output, &options)?;
        append_string(&mut output, profile.username.as_deref().unwrap_or(""))?;
        append_string(&mut output, profile.password.as_deref().unwrap_or(""))?;
        append_string(&mut output, &peer_info)?;
        Ok(output)
    }
}

impl ServerKeyRecord {
    pub(super) fn decode(packet: &[u8]) -> anyhow::Result<Self> {
        const FIXED: usize = 4 + 1 + RANDOM_LEN * 2;
        if packet.len() < FIXED + 2 {
            bail!("OpenVPN server key-method-2 record is truncated");
        }
        if packet[..4] != [0; 4] || packet[4] & 0x0f != 2 {
            bail!("OpenVPN server selected an unsupported key method");
        }
        let mut random1 = [0; RANDOM_LEN];
        let mut random2 = [0; RANDOM_LEN];
        random1.copy_from_slice(&packet[5..5 + RANDOM_LEN]);
        random2.copy_from_slice(&packet[5 + RANDOM_LEN..FIXED]);
        let mut offset = FIXED;
        let options = read_string(packet, &mut offset)?;
        let _username = read_string(packet, &mut offset)?;
        let _password = read_string(packet, &mut offset)?;
        let _peerinfo = read_string(packet, &mut offset)?;
        Ok(Self {
            source: ServerKeySource {
                random1,
                random2,
            },
            options,
            consumed: offset,
        })
    }

    pub(super) fn uses_tls_exporter(&self) -> bool {
        self.options
            .split(',')
            .any(|option| option.trim().eq_ignore_ascii_case("key-derivation tls-ekm"))
    }

    pub(super) fn negotiated_cipher(
        &self,
        profile: &OpenVpnProfile,
    ) -> anyhow::Result<OpenVpnCipher> {
        let server_cipher = self.options.split(',').find_map(|option| {
            let mut tokens = option.split_whitespace();
            match (tokens.next(), tokens.next()) {
                (Some(name), Some(value)) if name.eq_ignore_ascii_case("cipher") => Some(value),
                _ => None,
            }
        });
        let cipher = server_cipher
            .map(OpenVpnCipher::parse)
            .transpose()?
            .unwrap_or(profile.cipher);
        if !profile.data_ciphers.contains(&cipher) {
            bail!("OpenVPN server selected unadvertised data cipher {}", cipher.name());
        }
        Ok(cipher)
    }
}

pub(super) fn derive_key_material(
    client: &ClientKeySource,
    server: &ServerKeySource,
    client_session: &[u8; 8],
    server_session: &[u8; 8],
    cipher: OpenVpnCipher,
    exported: Option<&[u8]>,
) -> anyhow::Result<KeyMaterial> {
    let expanded = if let Some(exported) = exported {
        if exported.len() != EXPANDED_KEY_LEN {
            bail!("OpenVPN TLS exporter returned the wrong key length");
        }
        exported.to_vec()
    } else {
        let mut master = [0u8; 48];
        let mut master_seed = Vec::with_capacity(64);
        master_seed.extend_from_slice(&client.random1);
        master_seed.extend_from_slice(&server.random1);
        tls10_prf(
            &client.premaster,
            b"OpenVPN master secret",
            &master_seed,
            &mut master,
        )?;
        let mut key_seed = Vec::with_capacity(80);
        key_seed.extend_from_slice(&client.random2);
        key_seed.extend_from_slice(&server.random2);
        key_seed.extend_from_slice(client_session);
        key_seed.extend_from_slice(server_session);
        let mut expanded = vec![0; EXPANDED_KEY_LEN];
        tls10_prf(
            &master,
            b"OpenVPN key expansion",
            &key_seed,
            &mut expanded,
        )?;
        expanded
    };
    split_expanded_keys(&expanded, cipher.key_len())
}

pub(super) fn tls_exporter_label() -> &'static [u8] {
    TLS_EXPORTER_LABEL
}

fn split_expanded_keys(expanded: &[u8], cipher_len: usize) -> anyhow::Result<KeyMaterial> {
    if expanded.len() != EXPANDED_KEY_LEN || !matches!(cipher_len, 16 | 24 | 32) {
        bail!("invalid OpenVPN expanded key material");
    }
    let mut send_hmac = [0; 64];
    let mut receive_hmac = [0; 64];
    send_hmac.copy_from_slice(&expanded[64..128]);
    receive_hmac.copy_from_slice(&expanded[192..256]);
    Ok(KeyMaterial {
        send_cipher: expanded[..cipher_len].to_vec(),
        send_hmac,
        receive_cipher: expanded[128..128 + cipher_len].to_vec(),
        receive_hmac,
    })
}

fn client_options(profile: &OpenVpnProfile, transport: OpenVpnTransport) -> String {
    let protocol = match transport {
        OpenVpnTransport::Udp => "UDPv4",
        OpenVpnTransport::Tcp => "TCPv4_CLIENT",
    };
    let compression = if profile.compression_lzo { "comp-lzo," } else { "" };
    let link_mtu = profile.mtu.saturating_add(if profile.compression_lzo { 44 } else { 50 });
    format!(
        "V4,dev-type tun,link-mtu {link_mtu},tun-mtu {},proto {protocol},{compression}cipher {},auth {},keysize {},key-method 2,tls-client",
        profile.mtu,
        profile.cipher.name(),
        profile.auth.name(),
        profile.cipher.key_len() * 8,
    )
}

fn append_string(output: &mut Vec<u8>, value: &str) -> anyhow::Result<()> {
    if value.is_empty() {
        output.extend_from_slice(&0u16.to_be_bytes());
        return Ok(());
    }
    let length = value
        .len()
        .checked_add(1)
        .ok_or_else(|| anyhow!("OpenVPN key-method string length overflow"))?;
    let length = u16::try_from(length).map_err(|_| anyhow!("OpenVPN key-method string is too long"))?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value.as_bytes());
    output.push(0);
    Ok(())
}

fn read_string(packet: &[u8], offset: &mut usize) -> anyhow::Result<String> {
    if packet.len() < *offset + 2 {
        bail!("OpenVPN key-method string length is truncated");
    }
    let length = u16::from_be_bytes(packet[*offset..*offset + 2].try_into()?) as usize;
    *offset += 2;
    if packet.len() < *offset + length {
        bail!("OpenVPN key-method string is truncated");
    }
    let raw = &packet[*offset..*offset + length];
    *offset += length;
    let raw = raw.strip_suffix(&[0]).unwrap_or(raw);
    Ok(std::str::from_utf8(raw)?.to_string())
}

fn tls10_prf(secret: &[u8], label: &[u8], seed: &[u8], output: &mut [u8]) -> anyhow::Result<()> {
    let split = secret.len().div_ceil(2);
    let first = &secret[..split];
    let second = &secret[secret.len() - split..];
    let mut full_seed = Vec::with_capacity(label.len() + seed.len());
    full_seed.extend_from_slice(label);
    full_seed.extend_from_slice(seed);
    let md5 = p_hash(first, &full_seed, output.len(), hmac_md5)?;
    let sha1 = p_hash(second, &full_seed, output.len(), hmac_sha1)?;
    for ((target, left), right) in output.iter_mut().zip(md5).zip(sha1) {
        *target = left ^ right;
    }
    Ok(())
}

fn p_hash(
    secret: &[u8],
    seed: &[u8],
    length: usize,
    hmac: fn(&[u8], &[u8]) -> anyhow::Result<Vec<u8>>,
) -> anyhow::Result<Vec<u8>> {
    let mut output = Vec::with_capacity(length);
    let mut a = hmac(secret, seed)?;
    while output.len() < length {
        let mut input = Vec::with_capacity(a.len() + seed.len());
        input.extend_from_slice(&a);
        input.extend_from_slice(seed);
        output.extend_from_slice(&hmac(secret, &input)?);
        a = hmac(secret, &a)?;
    }
    output.truncate(length);
    Ok(output)
}

fn hmac_md5(key: &[u8], value: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut mac = <Hmac<Md5> as Mac>::new_from_slice(key)?;
    mac.update(value);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn hmac_sha1(key: &[u8], value: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(key)?;
    mac.update(value);
    Ok(mac.finalize().into_bytes().to_vec())
}

pub(super) fn parse_peer_id(options: &str) -> Option<u32> {
    options.split(',').find_map(|option| {
        let mut tokens = option.split_whitespace();
        match (tokens.next(), tokens.next()) {
            (Some(name), Some(value)) if name.eq_ignore_ascii_case("peer-id") => {
                value.parse::<u32>().ok().filter(|value| *value <= 0x00ff_ffff)
            }
            _ => None,
        }
    })
}

pub(super) fn parse_server_auth(options: &str, fallback: OpenVpnDigest) -> anyhow::Result<OpenVpnDigest> {
    for option in options.split(',') {
        let mut tokens = option.split_whitespace();
        if tokens.next().is_some_and(|name| name.eq_ignore_ascii_case("auth")) {
            if let Some(value) = tokens.next() {
                if value.eq_ignore_ascii_case("[NULL-DIGEST]")
                    || value.eq_ignore_ascii_case("none")
                {
                    return Ok(fallback);
                }
                return OpenVpnDigest::parse(value);
            }
        }
    }
    Ok(fallback)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls10_prf_is_stable() {
        let mut output = [0; 32];
        tls10_prf(b"secret", b"label", b"seed", &mut output).unwrap();
        assert_eq!(
            output,
            [
                181, 186, 244, 114, 43, 145, 133, 26, 136, 22, 210, 46, 189, 140, 29, 140,
                194, 233, 77, 85, 98, 12, 120, 0, 240, 220, 98, 85, 141, 228, 176, 60,
            ]
        );
    }

    #[test]
    fn splits_client_and_server_key_slots() {
        let expanded = (0..256).map(|value| value as u8).collect::<Vec<_>>();
        let keys = split_expanded_keys(&expanded, 24).unwrap();
        assert_eq!(keys.send_cipher, &expanded[..24]);
        assert_eq!(keys.send_hmac, expanded[64..128]);
        assert_eq!(keys.receive_cipher, &expanded[128..152]);
    }
}
