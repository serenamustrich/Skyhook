use std::{
    collections::BTreeMap,
    fs,
    net::IpAddr,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{anyhow, bail, Context};

use crate::config::OpenVpnOptions;

const MAX_PROFILE_SIZE: u64 = 4 * 1024 * 1024;
const DEFAULT_PORT: u16 = 1194;
const DEFAULT_MTU: u16 = 1_500;
const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);
const DEFAULT_RENEGOTIATION: Duration = Duration::from_secs(3_600);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum OpenVpnTransport {
    Udp,
    Tcp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum OpenVpnCipher {
    Aes128Gcm,
    Aes192Gcm,
    Aes256Gcm,
    Aes128Cbc,
    Aes192Cbc,
    Aes256Cbc,
    ChaCha20Poly1305,
}

impl OpenVpnCipher {
    pub(super) fn parse(value: &str) -> anyhow::Result<Self> {
        match value.trim().to_ascii_uppercase().as_str() {
            "AES-128-GCM" => Ok(Self::Aes128Gcm),
            "AES-192-GCM" => Ok(Self::Aes192Gcm),
            "AES-256-GCM" => Ok(Self::Aes256Gcm),
            "AES-CBC" | "AES-128-CBC" => Ok(Self::Aes128Cbc),
            "AES-192-CBC" => Ok(Self::Aes192Cbc),
            "AES-256-CBC" => Ok(Self::Aes256Cbc),
            "CHACHA20-POLY1305" => Ok(Self::ChaCha20Poly1305),
            other => bail!("unsupported OpenVPN data cipher {other}"),
        }
    }

    pub(super) fn name(self) -> &'static str {
        match self {
            Self::Aes128Gcm => "AES-128-GCM",
            Self::Aes192Gcm => "AES-192-GCM",
            Self::Aes256Gcm => "AES-256-GCM",
            Self::Aes128Cbc => "AES-128-CBC",
            Self::Aes192Cbc => "AES-192-CBC",
            Self::Aes256Cbc => "AES-256-CBC",
            Self::ChaCha20Poly1305 => "CHACHA20-POLY1305",
        }
    }

    pub(super) fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm | Self::Aes128Cbc => 16,
            Self::Aes192Gcm | Self::Aes192Cbc => 24,
            Self::Aes256Gcm | Self::Aes256Cbc | Self::ChaCha20Poly1305 => 32,
        }
    }

    pub(super) fn is_aead(self) -> bool {
        matches!(
            self,
            Self::Aes128Gcm
                | Self::Aes192Gcm
                | Self::Aes256Gcm
                | Self::ChaCha20Poly1305
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum OpenVpnDigest {
    Md5,
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl OpenVpnDigest {
    pub(super) fn parse(value: &str) -> anyhow::Result<Self> {
        match value.trim().to_ascii_uppercase().as_str() {
            "MD5" => Ok(Self::Md5),
            "SHA1" | "SHA-1" => Ok(Self::Sha1),
            "SHA256" | "SHA-256" => Ok(Self::Sha256),
            "SHA384" | "SHA-384" => Ok(Self::Sha384),
            "SHA512" | "SHA-512" => Ok(Self::Sha512),
            other => bail!("unsupported OpenVPN auth digest {other}"),
        }
    }

    pub(super) fn name(self) -> &'static str {
        match self {
            Self::Md5 => "MD5",
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
            Self::Sha384 => "SHA384",
            Self::Sha512 => "SHA512",
        }
    }

    pub(super) fn output_len(self) -> usize {
        match self {
            Self::Md5 => 16,
            Self::Sha1 => 20,
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }
}

#[derive(Clone, Debug)]
pub(super) struct OpenVpnRemote {
    pub(super) host: String,
    pub(super) port: u16,
    pub(super) transport: OpenVpnTransport,
}

#[derive(Clone, Debug)]
pub(super) struct OpenVpnProfile {
    pub(super) remotes: Vec<OpenVpnRemote>,
    pub(super) cipher: OpenVpnCipher,
    pub(super) data_ciphers: Vec<OpenVpnCipher>,
    pub(super) auth: OpenVpnDigest,
    pub(super) compression_lzo: bool,
    pub(super) ca: Vec<u8>,
    pub(super) cert: Option<Vec<u8>>,
    pub(super) key: Option<Vec<u8>>,
    pub(super) tls_crypt: Option<Vec<u8>>,
    pub(super) tls_auth: Option<Vec<u8>>,
    pub(super) key_direction: Option<u8>,
    pub(super) username: Option<String>,
    pub(super) password: Option<String>,
    pub(super) peer_info: BTreeMap<String, String>,
    pub(super) ping_interval: Duration,
    pub(super) ping_restart: Duration,
    pub(super) renegotiate_after: Duration,
    pub(super) handshake_timeout: Duration,
    pub(super) mtu: u16,
    pub(super) remote_cert_tls_server: bool,
    pub(super) verify_x509_name: Option<String>,
    pub(super) server_name: Option<String>,
    pub(super) remote_dns_resolve: bool,
    pub(super) static_dns: Vec<IpAddr>,
}

#[derive(Default)]
struct ProfileDocument {
    directives: Vec<Vec<String>>,
    inline: BTreeMap<String, Vec<u8>>,
}

impl OpenVpnProfile {
    pub(super) fn load(
        profile_path: Option<&Path>,
        inline_profile: Option<&str>,
        options: &OpenVpnOptions,
    ) -> anyhow::Result<Self> {
        let (source, base_dir) = match (profile_path, inline_profile) {
            (Some(_), Some(_)) => bail!("OpenVPN accepts either profile or inline_profile, not both"),
            (Some(path), None) => {
                let source = read_limited(path)
                    .with_context(|| format!("failed to read OpenVPN profile {}", path.display()))?;
                let base = path.parent().unwrap_or_else(|| Path::new(".")).to_path_buf();
                (String::from_utf8(source).context("OpenVPN profile is not UTF-8")?, base)
            }
            (None, Some(source)) => {
                if source.len() as u64 > MAX_PROFILE_SIZE {
                    bail!("OpenVPN inline profile exceeds {MAX_PROFILE_SIZE} bytes");
                }
                (source.to_string(), std::env::current_dir()?)
            }
            (None, None) => (
                direct_profile(options)?,
                std::env::current_dir()?,
            ),
        };
        let mut profile = Self::from_document(parse_document(&source)?, &base_dir)?;
        apply_option_overrides(&mut profile, options)?;
        Ok(profile)
    }

    fn from_document(document: ProfileDocument, base_dir: &Path) -> anyhow::Result<Self> {
        let mut default_transport = OpenVpnTransport::Udp;
        let mut remote_specs = Vec::<(String, Option<u16>, Option<OpenVpnTransport>)>::new();
        let mut cipher = OpenVpnCipher::Aes128Gcm;
        let mut cipher_explicit = false;
        let mut data_ciphers = Vec::new();
        let mut auth = OpenVpnDigest::Sha256;
        let mut compression_lzo = false;
        let mut ca = None;
        let mut cert = None;
        let mut key = None;
        let mut tls_crypt = None;
        let mut tls_auth = None;
        let mut key_direction = None;
        let mut username = None;
        let mut password = None;
        let mut peer_info = default_peer_info();
        let mut ping_interval = Duration::from_secs(10);
        let mut ping_restart = Duration::from_secs(60);
        let mut renegotiate_after = DEFAULT_RENEGOTIATION;
        let mut handshake_timeout = DEFAULT_HANDSHAKE_TIMEOUT;
        let mut mtu = DEFAULT_MTU;
        let mut remote_cert_tls_server = false;
        let mut verify_x509_name = None;
        let mut server_name = None;
        let mut remote_dns_resolve = false;
        let mut static_dns = Vec::new();

        for tokens in &document.directives {
            let Some(name) = tokens.first().map(|value| value.to_ascii_lowercase()) else {
                continue;
            };
            match name.as_str() {
                "client" | "pull" | "nobind" | "persist-key" | "persist-tun"
                | "resolv-retry" | "remote-random" | "remote-random-hostname"
                | "explicit-exit-notify" | "verb" | "mute" | "auth-nocache"
                | "script-security" | "route-delay" | "route-metric" | "connect-retry"
                | "connect-retry-max" | "sndbuf" | "rcvbuf" | "inactive" => {}
                "dev" => {
                    let value = required_arg(tokens, 1, "dev")?;
                    if !value.to_ascii_lowercase().starts_with("tun") {
                        bail!("OpenVPN only supports layer-3 tun profiles, got dev {value}");
                    }
                }
                "proto" => default_transport = parse_transport(required_arg(tokens, 1, "proto")?)?,
                "remote" => {
                    let host = required_arg(tokens, 1, "remote")?.to_string();
                    let port = tokens.get(2).map(|value| parse_u16(value, "remote port")).transpose()?;
                    let transport = tokens.get(3).map(|value| parse_transport(value)).transpose()?;
                    remote_specs.push((host, port, transport));
                }
                "port" | "rport" => {
                    let port = parse_u16(required_arg(tokens, 1, &name)?, &name)?;
                    if remote_specs.is_empty() {
                        remote_specs.push((String::new(), Some(port), None));
                    } else if let Some(last) = remote_specs.last_mut() {
                        last.1 = Some(port);
                    }
                }
                "cipher" => {
                    cipher = OpenVpnCipher::parse(required_arg(tokens, 1, "cipher")?)?;
                    cipher_explicit = true;
                }
                "data-ciphers" | "ncp-ciphers" => {
                    data_ciphers = required_arg(tokens, 1, &name)?
                        .split(':')
                        .filter(|value| !value.trim().is_empty())
                        .map(OpenVpnCipher::parse)
                        .collect::<anyhow::Result<Vec<_>>>()?;
                }
                "data-ciphers-fallback" => {
                    cipher = OpenVpnCipher::parse(required_arg(tokens, 1, &name)?)?;
                    cipher_explicit = true;
                }
                "auth" => auth = OpenVpnDigest::parse(required_arg(tokens, 1, "auth")?)?,
                "comp-lzo" => {
                    compression_lzo = !matches!(
                        tokens.get(1).map(|value| value.to_ascii_lowercase()).as_deref(),
                        Some("no") | Some("disable")
                    );
                }
                "compress" => {
                    let algorithm = tokens.get(1).map(|value| value.to_ascii_lowercase());
                    compression_lzo = matches!(algorithm.as_deref(), Some("lzo") | Some("stub") | Some("stub-v2"));
                }
                "ca" => ca = Some(load_material(tokens, 1, "ca", &document, base_dir)?),
                "cert" => cert = Some(load_material(tokens, 1, "cert", &document, base_dir)?),
                "key" => key = Some(load_material(tokens, 1, "key", &document, base_dir)?),
                "tls-crypt" => {
                    tls_crypt = Some(load_material(tokens, 1, "tls-crypt", &document, base_dir)?)
                }
                "tls-auth" => {
                    tls_auth = Some(load_material(tokens, 1, "tls-auth", &document, base_dir)?);
                    if let Some(value) = tokens.get(2) {
                        key_direction = Some(parse_direction(value)?);
                    }
                }
                "key-direction" => key_direction = Some(parse_direction(required_arg(tokens, 1, "key-direction")?)?),
                "auth-user-pass" => {
                    let credentials = load_optional_material(tokens, 1, "auth-user-pass", &document, base_dir)?;
                    if let Some(credentials) = credentials {
                        let text = String::from_utf8(credentials)
                            .context("OpenVPN auth-user-pass data is not UTF-8")?;
                        let mut lines = text.lines();
                        username = lines.next().map(str::to_string).filter(|value| !value.is_empty());
                        password = lines.next().map(str::to_string);
                    }
                }
                "setenv" => {
                    if let (Some(key), Some(value)) = (tokens.get(1), tokens.get(2)) {
                        if key.starts_with("UV_") || key.starts_with("IV_") {
                            peer_info.insert(key.clone(), value.clone());
                        }
                    }
                }
                "ping" => ping_interval = parse_duration(tokens, 1, "ping")?,
                "ping-restart" => ping_restart = parse_duration(tokens, 1, "ping-restart")?,
                "keepalive" => {
                    ping_interval = parse_duration(tokens, 1, "keepalive")?;
                    ping_restart = parse_duration(tokens, 2, "keepalive")?;
                }
                "reneg-sec" => renegotiate_after = parse_duration(tokens, 1, "reneg-sec")?,
                "hand-window" | "connect-timeout" | "tls-timeout" => {
                    handshake_timeout = parse_duration(tokens, 1, &name)?
                }
                "tun-mtu" => mtu = parse_u16(required_arg(tokens, 1, "tun-mtu")?, "tun-mtu")?,
                "remote-cert-tls" => {
                    remote_cert_tls_server = required_arg(tokens, 1, "remote-cert-tls")?
                        .eq_ignore_ascii_case("server");
                }
                "verify-x509-name" => {
                    verify_x509_name = Some(required_arg(tokens, 1, "verify-x509-name")?.to_string())
                }
                "tls-remote" => server_name = Some(required_arg(tokens, 1, "tls-remote")?.to_string()),
                "dhcp-option" => {
                    if tokens.get(1).is_some_and(|value| value.eq_ignore_ascii_case("DNS")) {
                        if let Some(value) = tokens.get(2) {
                            static_dns.push(value.parse().with_context(|| format!("invalid OpenVPN DNS address {value}"))?);
                            remote_dns_resolve = true;
                        }
                    }
                }
                "route" | "route-ipv6" | "redirect-gateway" | "redirect-private"
                | "topology" | "ifconfig" | "ifconfig-ipv6" | "block-outside-dns"
                | "register-dns" | "route-gateway" | "route-ipv6-gateway" => {}
                "tls-crypt-v2" => bail!("OpenVPN tls-crypt-v2 is not yet supported"),
                _ => {}
            }
        }

        ca = ca.or_else(|| document.inline.get("ca").cloned());
        cert = cert.or_else(|| document.inline.get("cert").cloned());
        key = key.or_else(|| document.inline.get("key").cloned());
        tls_crypt = tls_crypt.or_else(|| document.inline.get("tls-crypt").cloned());
        tls_auth = tls_auth.or_else(|| document.inline.get("tls-auth").cloned());

        if !cipher_explicit && !data_ciphers.is_empty() {
            cipher = data_ciphers[0];
        }
        if !data_ciphers.contains(&cipher) {
            data_ciphers.push(cipher);
        }
        let remotes = remote_specs
            .into_iter()
            .filter(|(host, _, _)| !host.trim().is_empty())
            .map(|(host, port, transport)| OpenVpnRemote {
                host,
                port: port.unwrap_or(DEFAULT_PORT),
                transport: transport.unwrap_or(default_transport),
            })
            .collect::<Vec<_>>();
        if remotes.is_empty() {
            bail!("OpenVPN profile has no remote directive");
        }
        if tls_crypt.is_some() && tls_auth.is_some() {
            bail!("OpenVPN profile cannot enable tls-crypt and tls-auth together");
        }
        if cert.is_some() != key.is_some() {
            bail!("OpenVPN cert and key must be configured together");
        }
        if cert.is_none() && username.is_none() {
            bail!("OpenVPN requires a client cert/key pair or auth-user-pass credentials");
        }
        if !(576..=65_535).contains(&mtu) {
            bail!("OpenVPN tun-mtu must be between 576 and 65535");
        }
        let ca = ca.ok_or_else(|| anyhow!("OpenVPN profile requires a CA certificate"))?;
        Ok(Self {
            remotes,
            cipher,
            data_ciphers,
            auth,
            compression_lzo,
            ca,
            cert,
            key,
            tls_crypt,
            tls_auth,
            key_direction,
            username,
            password,
            peer_info,
            ping_interval,
            ping_restart,
            renegotiate_after,
            handshake_timeout,
            mtu,
            remote_cert_tls_server,
            verify_x509_name,
            server_name,
            remote_dns_resolve,
            static_dns,
        })
    }
}

fn direct_profile(options: &OpenVpnOptions) -> anyhow::Result<String> {
    let server = options
        .server
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("OpenVPN requires profile, inline_profile, or server fields"))?;
    let ca = options
        .ca
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| anyhow!("OpenVPN direct configuration requires ca"))?;
    let mut output = String::from("client\npull\nnobind\npersist-key\npersist-tun\n");
    output.push_str(&format!("dev {}\n", quote(options.dev.as_deref().unwrap_or("tun"))));
    output.push_str(&format!("proto {}\n", quote(options.proto.as_deref().unwrap_or("udp"))));
    output.push_str(&format!(
        "remote {} {}\n",
        quote(server),
        options.port.unwrap_or(DEFAULT_PORT)
    ));
    if let Some(cipher) = &options.cipher {
        output.push_str(&format!("cipher {}\n", quote(cipher)));
    }
    if let Some(ciphers) = &options.data_ciphers {
        output.push_str(&format!("data-ciphers {}\n", quote(ciphers)));
    }
    if let Some(auth) = &options.auth {
        output.push_str(&format!("auth {}\n", quote(auth)));
    }
    if let Some(comp_lzo) = &options.comp_lzo {
        output.push_str(&format!("comp-lzo {}\n", quote(comp_lzo)));
    }
    append_inline(&mut output, "ca", ca);
    if let Some(cert) = options.cert.as_deref().filter(|value| !value.trim().is_empty()) {
        append_inline(&mut output, "cert", cert);
    }
    if let Some(key) = options.key.as_deref().filter(|value| !value.trim().is_empty()) {
        append_inline(&mut output, "key", key);
    }
    if let Some(key) = options
        .tls_crypt
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        append_inline(&mut output, "tls-crypt", key);
    }
    if let Some(key) = options
        .tls_auth
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        append_inline(&mut output, "tls-auth", key);
        if let Some(direction) = options.key_direction {
            output.push_str(&format!("key-direction {direction}\n"));
        }
    }
    if let Some(username) = &options.username {
        output.push_str("auth-user-pass [inline]\n<auth-user-pass>\n");
        output.push_str(username);
        output.push('\n');
        output.push_str(options.password.as_deref().unwrap_or(""));
        output.push_str("\n</auth-user-pass>\n");
    }
    for (key, value) in &options.peer_info {
        output.push_str(&format!("setenv {} {}\n", quote(key), quote(value)));
    }
    if let Some(seconds) = options.ping {
        output.push_str(&format!("ping {seconds}\n"));
    }
    if let Some(seconds) = options.ping_restart {
        output.push_str(&format!("ping-restart {seconds}\n"));
    }
    if let Some(seconds) = options.handshake_timeout {
        output.push_str(&format!("hand-window {seconds}\n"));
    }
    if let Some(seconds) = options.reneg_sec {
        output.push_str(&format!("reneg-sec {seconds}\n"));
    }
    if let Some(mtu) = options.mtu {
        output.push_str(&format!("tun-mtu {mtu}\n"));
    }
    if let Some(value) = &options.remote_cert_tls {
        output.push_str(&format!("remote-cert-tls {}\n", quote(value)));
    }
    if let Some(value) = &options.verify_x509_name {
        output.push_str(&format!("verify-x509-name {}\n", quote(value)));
    }
    if let Some(value) = &options.sni {
        output.push_str(&format!("tls-remote {}\n", quote(value)));
    }
    for dns in &options.dns {
        output.push_str(&format!("dhcp-option DNS {}\n", quote(dns)));
    }
    Ok(output)
}

fn apply_option_overrides(
    profile: &mut OpenVpnProfile,
    options: &OpenVpnOptions,
) -> anyhow::Result<()> {
    if options.remote_dns_resolve {
        profile.remote_dns_resolve = true;
    }
    for value in &options.dns {
        let address = value
            .parse::<IpAddr>()
            .with_context(|| format!("invalid OpenVPN DNS address {value}"))?;
        if !profile.static_dns.contains(&address) {
            profile.static_dns.push(address);
        }
    }
    if let Some(seconds) = options.handshake_timeout {
        profile.handshake_timeout = Duration::from_secs(seconds);
    }
    if let Some(seconds) = options.reneg_sec {
        profile.renegotiate_after = Duration::from_secs(seconds);
    }
    if let Some(mtu) = options.mtu {
        if !(576..=65_535).contains(&mtu) {
            bail!("OpenVPN mtu must be between 576 and 65535");
        }
        profile.mtu = mtu;
    }
    Ok(())
}

fn append_inline(output: &mut String, name: &str, value: &str) {
    output.push('<');
    output.push_str(name);
    output.push_str(">\n");
    output.push_str(value.trim());
    output.push('\n');
    output.push_str("</");
    output.push_str(name);
    output.push_str(">\n");
}

fn quote(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

pub(super) fn decode_static_key(material: &[u8]) -> anyhow::Result<[u8; 256]> {
    let text = std::str::from_utf8(material).context("OpenVPN static key is not UTF-8")?;
    let encoded = text
        .lines()
        .map(str::trim)
        .filter(|line| {
            !line.is_empty()
                && !line.starts_with('#')
                && !line.starts_with("-----BEGIN OpenVPN Static key")
                && !line.starts_with("-----END OpenVPN Static key")
        })
        .collect::<String>();
    if encoded.len() != 512 || !encoded.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("OpenVPN static key must contain exactly 256 bytes of hexadecimal key data");
    }
    let mut output = [0u8; 256];
    for (index, chunk) in encoded.as_bytes().chunks_exact(2).enumerate() {
        let pair = std::str::from_utf8(chunk)?;
        output[index] = u8::from_str_radix(pair, 16)?;
    }
    Ok(output)
}

fn parse_document(source: &str) -> anyhow::Result<ProfileDocument> {
    let mut document = ProfileDocument::default();
    let mut block_name: Option<String> = None;
    let mut block = Vec::<String>::new();

    for raw in source.lines() {
        let trimmed = raw.trim();
        if let Some(name) = &block_name {
            if trimmed.eq_ignore_ascii_case(&format!("</{name}>")) {
                document.inline.insert(name.clone(), block.join("\n").into_bytes());
                block_name = None;
                block.clear();
            } else {
                block.push(raw.to_string());
            }
            continue;
        }
        if trimmed.starts_with('<') && trimmed.ends_with('>') && !trimmed.starts_with("</") {
            let name = trimmed[1..trimmed.len() - 1].trim().to_ascii_lowercase();
            if name.is_empty() || name.bytes().any(|byte| !byte.is_ascii_alphanumeric() && byte != b'-') {
                bail!("invalid OpenVPN inline block {trimmed}");
            }
            block_name = Some(name);
            continue;
        }
        let tokens = tokenize(raw)?;
        if !tokens.is_empty() {
            document.directives.push(tokens);
        }
    }
    if let Some(name) = block_name {
        bail!("unterminated OpenVPN inline block <{name}>");
    }
    Ok(document)
}

fn tokenize(line: &str) -> anyhow::Result<Vec<String>> {
    let mut tokens = Vec::new();
    let mut token = String::new();
    let mut quote = None;
    let mut escaped = false;
    for character in line.chars() {
        if escaped {
            token.push(character);
            escaped = false;
            continue;
        }
        if character == '\\' {
            escaped = true;
            continue;
        }
        if let Some(expected) = quote {
            if character == expected {
                quote = None;
            } else {
                token.push(character);
            }
            continue;
        }
        match character {
            '\'' | '"' => quote = Some(character),
            '#' | ';' if token.is_empty() => break,
            character if character.is_whitespace() => {
                if !token.is_empty() {
                    tokens.push(std::mem::take(&mut token));
                }
            }
            character => token.push(character),
        }
    }
    if escaped {
        token.push('\\');
    }
    if quote.is_some() {
        bail!("unterminated quote in OpenVPN profile line");
    }
    if !token.is_empty() {
        tokens.push(token);
    }
    Ok(tokens)
}

fn load_material(
    tokens: &[String],
    index: usize,
    block_name: &str,
    document: &ProfileDocument,
    base_dir: &Path,
) -> anyhow::Result<Vec<u8>> {
    load_optional_material(tokens, index, block_name, document, base_dir)?.ok_or_else(|| {
        anyhow!("OpenVPN directive {block_name} requires inline data or a file path")
    })
}

fn load_optional_material(
    tokens: &[String],
    index: usize,
    block_name: &str,
    document: &ProfileDocument,
    base_dir: &Path,
) -> anyhow::Result<Option<Vec<u8>>> {
    if let Some(inline) = document.inline.get(block_name) {
        return Ok(Some(inline.clone()));
    }
    let Some(value) = tokens.get(index) else {
        return Ok(None);
    };
    if value.eq_ignore_ascii_case("[inline]") {
        return Err(anyhow!("OpenVPN <{block_name}> inline block is missing"));
    }
    let path = PathBuf::from(value);
    let path = if path.is_absolute() { path } else { base_dir.join(path) };
    read_limited(&path)
        .with_context(|| format!("failed to read OpenVPN {block_name} file {}", path.display()))
        .map(Some)
}

fn read_limited(path: &Path) -> anyhow::Result<Vec<u8>> {
    let metadata = fs::metadata(path)?;
    if !metadata.is_file() {
        bail!("{} is not a regular file", path.display());
    }
    if metadata.len() > MAX_PROFILE_SIZE {
        bail!("{} exceeds {MAX_PROFILE_SIZE} bytes", path.display());
    }
    Ok(fs::read(path)?)
}

fn required_arg<'a>(tokens: &'a [String], index: usize, name: &str) -> anyhow::Result<&'a str> {
    tokens
        .get(index)
        .map(String::as_str)
        .ok_or_else(|| anyhow!("OpenVPN directive {name} is missing an argument"))
}

fn parse_transport(value: &str) -> anyhow::Result<OpenVpnTransport> {
    match value.trim().to_ascii_lowercase().as_str() {
        "udp" | "udp4" | "udp6" => Ok(OpenVpnTransport::Udp),
        "tcp" | "tcp-client" | "tcp4" | "tcp4-client" | "tcp6" | "tcp6-client" => {
            Ok(OpenVpnTransport::Tcp)
        }
        other => bail!("unsupported OpenVPN transport {other}"),
    }
}

fn parse_direction(value: &str) -> anyhow::Result<u8> {
    match value.trim() {
        "0" => Ok(0),
        "1" => Ok(1),
        other => bail!("OpenVPN key direction must be 0 or 1, got {other}"),
    }
}

fn parse_u16(value: &str, field: &str) -> anyhow::Result<u16> {
    value
        .parse::<u16>()
        .with_context(|| format!("invalid OpenVPN {field} {value}"))
}

fn parse_duration(tokens: &[String], index: usize, field: &str) -> anyhow::Result<Duration> {
    let seconds = required_arg(tokens, index, field)?
        .parse::<u64>()
        .with_context(|| format!("invalid OpenVPN {field}"))?;
    Ok(Duration::from_secs(seconds))
}

fn default_peer_info() -> BTreeMap<String, String> {
    BTreeMap::from([
        ("IV_VER".to_string(), "3.11.3 Skyhook".to_string()),
        ("IV_PLAT".to_string(), "mac".to_string()),
        ("IV_PROTO".to_string(), "334".to_string()),
        (
            "IV_CIPHERS".to_string(),
            "AES-256-GCM:AES-192-GCM:AES-128-GCM:CHACHA20-POLY1305".to_string(),
        ),
        ("IV_LZO".to_string(), "1".to_string()),
        ("IV_LZ4".to_string(), "1".to_string()),
        ("IV_LZ4v2".to_string(), "1".to_string()),
        ("IV_TCPNL".to_string(), "1".to_string()),
        ("IV_GUI_VER".to_string(), "Skyhook_0.1.0".to_string()),
        ("IV_SSO".to_string(), "webauth,openurl,crtext".to_string()),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_profile(extra: &str) -> String {
        format!(
            "client\nproto udp\nremote vpn.example 443 tcp-client\ndev tun\ncipher AES-256-GCM\nauth SHA256\nauth-user-pass [inline]\n<auth-user-pass>\nuser\npass\n</auth-user-pass>\n<ca>\n-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n</ca>\n{extra}"
        )
    }

    #[test]
    fn parses_inline_profile_and_credentials() {
        let profile = OpenVpnProfile::load(
            None,
            Some(&sample_profile("tun-mtu 1400\n")),
            &OpenVpnOptions::default(),
        )
        .unwrap();
        assert_eq!(profile.remotes[0].transport, OpenVpnTransport::Tcp);
        assert_eq!(profile.remotes[0].port, 443);
        assert_eq!(profile.cipher, OpenVpnCipher::Aes256Gcm);
        assert_eq!(profile.username.as_deref(), Some("user"));
        assert_eq!(profile.password.as_deref(), Some("pass"));
        assert_eq!(profile.mtu, 1_400);
    }

    #[test]
    fn rejects_non_tun_profile() {
        let profile = sample_profile("dev tap\n");
        assert!(OpenVpnProfile::load(None, Some(&profile), &OpenVpnOptions::default())
            .unwrap_err()
            .to_string()
            .contains("layer-3"));
    }

    #[test]
    fn decodes_openvpn_static_key() {
        let value = format!(
            "-----BEGIN OpenVPN Static key V1-----\n{}\n-----END OpenVPN Static key V1-----\n",
            "ab".repeat(256)
        );
        assert_eq!(decode_static_key(value.as_bytes()).unwrap(), [0xab; 256]);
    }
}
