use std::str::FromStr;

use anyhow::{anyhow, Context};
use serde::Serialize;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct OpenVpnParsedProfile {
    pub remotes: Vec<OpenVpnRemote>,
    pub proto: OpenVpnTransport,
    pub dev: OpenVpnDeviceMode,
    pub ca: Vec<Vec<u8>>,
    pub cert: Option<Vec<u8>>,
    pub key: Option<Vec<u8>>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub tls_auth: Option<Vec<u8>>,
    pub tls_crypt: Option<Vec<u8>>,
    pub ciphers: Vec<String>,
    pub auth: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct OpenVpnRemote {
    pub host: String,
    pub port: u16,
    pub proto: Option<OpenVpnTransport>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub enum OpenVpnTransport {
    Udp,
    TcpClient,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub enum OpenVpnDeviceMode {
    Tun,
    Tap,
}

impl FromStr for OpenVpnTransport {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "udp" => Ok(Self::Udp),
            "tcp-client" | "tcp" => Ok(Self::TcpClient),
            _ => Err(anyhow!("unsupported OpenVPN transport: {s}")),
        }
    }
}

impl FromStr for OpenVpnDeviceMode {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "tun" => Ok(Self::Tun),
            "tap" => Ok(Self::Tap),
            _ => Err(anyhow!("unsupported OpenVPN device mode: {s}")),
        }
    }
}

pub fn parse_openvpn_profile(text: &str) -> anyhow::Result<OpenVpnParsedProfile> {
    let mut remotes = Vec::new();
    let mut proto = OpenVpnTransport::Udp;
    let mut dev = OpenVpnDeviceMode::Tun;
    let mut ca = Vec::new();
    let mut cert = None;
    let mut key = None;
    let mut username = None;
    let mut password = None;
    let mut tls_auth = None;
    let mut tls_crypt = None;
    let mut ciphers = Vec::new();
    let mut auth = None;

    let mut inline_block: Option<&str> = None;
    let mut inline_content = String::new();

    for line in text.lines() {
        let line = line.trim();

        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }

        if line.starts_with('<') && line.ends_with('>') {
            let tag = &line[1..line.len() - 1];
            if tag.starts_with('/') {
                if let Some(block_type) = inline_block {
                    let expected_end = format!("</{}>", block_type);
                    if line.to_lowercase() == expected_end.to_lowercase() {
                        match block_type.to_lowercase().as_str() {
                            "ca" => ca.push(inline_content.as_bytes().to_vec()),
                            "cert" => cert = Some(inline_content.as_bytes().to_vec()),
                            "key" => key = Some(inline_content.as_bytes().to_vec()),
                            "tls-auth" => tls_auth = Some(inline_content.as_bytes().to_vec()),
                            "tls-crypt" => tls_crypt = Some(inline_content.as_bytes().to_vec()),
                            _ => {}
                        }
                        inline_block = None;
                        inline_content.clear();
                    }
                }
            } else {
                inline_block = Some(tag);
                inline_content.clear();
            }
            continue;
        }

        if inline_block.is_some() {
            if !inline_content.is_empty() {
                inline_content.push('\n');
            }
            inline_content.push_str(line);
            continue;
        }

        let parts: Vec<&str> = line.splitn(2, ' ').collect();
        let directive = parts[0].to_lowercase();
        let value = parts.get(1).map(|s| s.trim());

        match directive.as_str() {
            "remote" => {
                if let Some(value) = value {
                    let remote_parts: Vec<&str> = value.split_whitespace().collect();
                    if remote_parts.len() >= 2 {
                        let host = remote_parts[0].to_string();
                        let port: u16 = remote_parts[1].parse().with_context(|| {
                            format!("invalid port in remote: {}", remote_parts[1])
                        })?;
                        let remote_proto = if remote_parts.len() > 2 {
                            Some(OpenVpnTransport::from_str(remote_parts[2])?)
                        } else {
                            None
                        };
                        remotes.push(OpenVpnRemote {
                            host,
                            port,
                            proto: remote_proto,
                        });
                    }
                }
            }
            "proto" => {
                if let Some(value) = value {
                    proto = OpenVpnTransport::from_str(value)?;
                }
            }
            "dev" => {
                if let Some(value) = value {
                    dev = OpenVpnDeviceMode::from_str(value)?;
                }
            }
            "cipher" => {
                if let Some(value) = value {
                    ciphers.push(value.to_string());
                }
            }
            "data-ciphers" => {
                if let Some(value) = value {
                    for cipher in value.split(':') {
                        let cipher = cipher.trim();
                        if !cipher.is_empty() {
                            ciphers.push(cipher.to_string());
                        }
                    }
                }
            }
            "auth" => {
                if let Some(value) = value {
                    auth = Some(value.to_string());
                }
            }
            "auth-user-pass" => {
                if let Some(value) = value {
                    let parts: Vec<&str> = value.splitn(2, ' ').collect();
                    if parts.len() >= 2 {
                        username = Some(parts[0].to_string());
                        password = Some(parts[1].to_string());
                    }
                }
            }
            "remote-cert-tls" => {
                // Validate later
            }
            "verify-x509-name" => {
                // Validate later
            }
            "comp-lzo" | "compress" => {
                return Err(anyhow!(
                    "compression is not supported and must not be silently enabled"
                ));
            }
            _ => {}
        }
    }

    if remotes.is_empty() {
        return Err(anyhow!("no remote servers specified"));
    }

    Ok(OpenVpnParsedProfile {
        remotes,
        proto,
        dev,
        ca,
        cert,
        key,
        username,
        password,
        tls_auth,
        tls_crypt,
        ciphers,
        auth,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic_udp_profile() {
        let text = r#"
remote 1.2.3.4 1194
proto udp
dev tun
cipher AES-256-GCM
auth SHA256
        "#;

        let profile = parse_openvpn_profile(text).unwrap();
        assert_eq!(profile.remotes.len(), 1);
        assert_eq!(profile.remotes[0].host, "1.2.3.4");
        assert_eq!(profile.remotes[0].port, 1194);
        assert_eq!(profile.proto, OpenVpnTransport::Udp);
        assert_eq!(profile.dev, OpenVpnDeviceMode::Tun);
        assert_eq!(profile.ciphers, vec!["AES-256-GCM"]);
        assert_eq!(profile.auth, Some("SHA256".to_string()));
    }

    #[test]
    fn parse_tcp_profile_with_multiple_remotes() {
        let text = r#"
remote 10.0.0.1 443
remote 10.0.0.2 443 tcp-client
proto tcp-client
dev tun
        "#;

        let profile = parse_openvpn_profile(text).unwrap();
        assert_eq!(profile.remotes.len(), 2);
        assert_eq!(profile.remotes[0].host, "10.0.0.1");
        assert_eq!(profile.remotes[0].port, 443);
        assert_eq!(profile.remotes[0].proto, None);
        assert_eq!(profile.remotes[1].host, "10.0.0.2");
        assert_eq!(profile.remotes[1].port, 443);
        assert_eq!(profile.remotes[1].proto, Some(OpenVpnTransport::TcpClient));
        assert_eq!(profile.proto, OpenVpnTransport::TcpClient);
    }

    #[test]
    fn parse_inline_ca_profile() {
        let text = r#"
remote 1.2.3.4 1194
proto udp
dev tun
<ca>
-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAL...
-----END CERTIFICATE-----
</ca>
        "#;

        let profile = parse_openvpn_profile(text).unwrap();
        assert_eq!(profile.ca.len(), 1);
        assert!(profile.ca[0].starts_with(b"-----BEGIN CERTIFICATE-----"));
    }

    #[test]
    fn parse_profile_with_auth_user_pass() {
        let text = r#"
remote 1.2.3.4 1194
proto udp
dev tun
auth-user-pass myuser mypassword
        "#;

        let profile = parse_openvpn_profile(text).unwrap();
        assert_eq!(profile.username, Some("myuser".to_string()));
        assert_eq!(profile.password, Some("mypassword".to_string()));
    }

    #[test]
    fn parse_profile_with_data_ciphers() {
        let text = r#"
remote 1.2.3.4 1194
proto udp
dev tun
data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305
        "#;

        let profile = parse_openvpn_profile(text).unwrap();
        assert_eq!(profile.ciphers.len(), 3);
        assert_eq!(profile.ciphers[0], "AES-256-GCM");
        assert_eq!(profile.ciphers[1], "AES-128-GCM");
        assert_eq!(profile.ciphers[2], "CHACHA20-POLY1305");
    }

    #[test]
    fn reject_compression() {
        let text = r#"
remote 1.2.3.4 1194
proto udp
dev tun
comp-lzo
        "#;

        let result = parse_openvpn_profile(text);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("compression"));
    }

    #[test]
    fn reject_missing_remote() {
        let text = r#"
proto udp
dev tun
        "#;

        let result = parse_openvpn_profile(text);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("no remote"));
    }
}
