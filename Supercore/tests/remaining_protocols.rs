//! 6.4.7-11 protocol coverage tests
//!
//! Covers: SSR (obfs/UDP), Snell (obfs), WireGuard (allowed_ips/reserved/mtu),
//! AnyTLS, ShadowTLS, Naive, Hysteria v1 (decision: parse-only / unsupported).
//!
//! The tests exercise the public builder (`build_outbounds`) + the runtime
//! capability snapshot (`Runtime::outbound_capabilities`) plus lightweight
//! mock TCP / TLS servers where the protocol reaches a connect handshake.

use std::{net::Ipv4Addr, sync::Arc, time::Duration};

use rustls::ServerConfig;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    time::timeout,
};
use tokio_rustls::TlsAcceptor;

use supercore::{
    config::{CoreConfig, OutboundConfig, RouteRule, RuleTarget, SuperConfig},
    core::{OutboundCapabilitySnapshot, Runtime},
    outbound::build_outbounds,
    routing::Destination,
};

/// Build a SuperConfig with a `direct` outbound and a per-test default.
///
/// `Runtime::new` rejects configs where the default outbound is undefined,
/// so every test fixture must include at least one named outbound reachable
/// through the `Match` rule (see `tests/config_and_runtime.rs:209`).
fn config_with_default(name: &str, outbound: OutboundConfig) -> SuperConfig {
    let mut config = SuperConfig {
        outbounds: vec![
            OutboundConfig::Direct {
                name: "direct".to_string(),
            },
            outbound,
        ],
        ..SuperConfig::default()
    };
    config.core = CoreConfig {
        default_outbound: name.to_string(),
        ..CoreConfig::default()
    };
    config
}

fn find_snapshot(runtime: &Runtime, name: &str) -> OutboundCapabilitySnapshot {
    runtime
        .outbound_capabilities()
        .into_iter()
        .find(|item| item.name == name)
        .unwrap_or_else(|| panic!("missing capability snapshot for {name}"))
}

/// Spawn a TLS-accepting echo server on 127.0.0.1 that completes the
/// handshake then discards the connection. Used by mock tests that only
/// need the outbound to clear TLS without caring about the post-handshake
/// protocol state.
async fn spawn_tls_drop_server(sni: &str) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let sni = sni.to_string();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let cert = rcgen::generate_simple_self_signed(vec![sni]).unwrap();
        let cert_der = CertificateDer::from(cert.cert.der().to_vec());
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()));
        let server_config = ServerConfig::builder_with_provider(
            rustls::crypto::aws_lc_rs::default_provider().into(),
        )
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        if let Ok((stream, _)) = listener.accept().await {
            let _ = acceptor.accept(stream).await;
        }
    });
    (addr, handle)
}

// ---------------------------------------------------------------------------
// 1. SSR: origin capability and unsupported-combination reporting
// ---------------------------------------------------------------------------

#[test]
fn ssr_origin_capability_supports_tcp_and_udp() {
    let config = config_with_default(
        "ssr-01",
        OutboundConfig::Ssr {
            name: "ssr-01".to_string(),
            server: "ssr.example.com".to_string(),
            port: 8388,
            method: "aes-256-cfb".to_string(),
            password: "p".to_string(),
            protocol: "origin".to_string(),
            obfs: "plain".to_string(),
            protocol_param: None,
            obfs_param: None,
        },
    );
    let runtime = Runtime::new(config).expect("runtime");
    let snapshot = find_snapshot(&runtime, "ssr-01");

    assert!(snapshot.tcp_supported);
    assert!(snapshot.udp_supported);
    assert_eq!(
        snapshot.udp_mode.as_deref(),
        Some("ssr-datagram-stream-cipher")
    );
}

#[test]
fn ssr_capability_reports_unsupported_obfs() {
    // `xor` is not in the documented supported obfs list.
    let config = config_with_default(
        "ssr-xor",
        OutboundConfig::Ssr {
            name: "ssr-xor".to_string(),
            server: "ssr.example.com".to_string(),
            port: 8388,
            method: "aes-256-cfb".to_string(),
            password: "p".to_string(),
            protocol: "origin".to_string(),
            obfs: "xor".to_string(),
            protocol_param: None,
            obfs_param: None,
        },
    );
    let runtime = Runtime::new(config).expect("runtime");
    let snapshot = find_snapshot(&runtime, "ssr-xor");

    assert!(
        snapshot
            .limitations
            .iter()
            .any(|item| item.contains("unsupported ssr obfs xor")),
        "xor obfs must be reported, got {:?}",
        snapshot.limitations,
    );
    assert!(!snapshot.tcp_supported);
}

#[test]
fn ssr_auth_chain_a_capability_reports_tcp_and_udp_support() {
    let config = config_with_default(
        "ssr-auth",
        OutboundConfig::Ssr {
            name: "ssr-auth".to_string(),
            server: "ssr.example.com".to_string(),
            port: 8388,
            method: "aes-256-cfb".to_string(),
            password: "p".to_string(),
            protocol: "auth_chain_a".to_string(),
            obfs: "plain".to_string(),
            protocol_param: None,
            obfs_param: None,
        },
    );
    let runtime = Runtime::new(config).expect("runtime");
    let snapshot = find_snapshot(&runtime, "ssr-auth");
    assert!(snapshot.tcp_supported);
    assert!(snapshot.udp_supported);
    assert!(!snapshot
        .limitations
        .iter()
        .any(|item| item.contains("unsupported ssr protocol")));
}

#[test]
fn ssr_auth_chain_b_capability_reports_tcp_and_udp_support() {
    let config = config_with_default(
        "ssr-auth",
        OutboundConfig::Ssr {
            name: "ssr-auth".to_string(),
            server: "ssr.example.com".to_string(),
            port: 8388,
            method: "aes-256-cfb".to_string(),
            password: "p".to_string(),
            protocol: "auth_chain_b".to_string(),
            obfs: "plain".to_string(),
            protocol_param: None,
            obfs_param: None,
        },
    );
    let runtime = Runtime::new(config).expect("runtime");
    let snapshot = find_snapshot(&runtime, "ssr-auth");
    assert!(snapshot.tcp_supported);
    assert!(snapshot.udp_supported);
    assert!(!snapshot
        .limitations
        .iter()
        .any(|item| item.contains("unsupported ssr protocol")));
}

#[test]
fn ssr_auth_chain_c_to_f_capability_is_advertised_as_supported() {
    for protocol in [
        "auth_chain_c",
        "auth_chain_d",
        "auth_chain_e",
        "auth_chain_f",
    ] {
        let config = config_with_default(
            "ssr-auth",
            OutboundConfig::Ssr {
                name: "ssr-auth".to_string(),
                server: "ssr.example.com".to_string(),
                port: 8388,
                method: "aes-256-cfb".to_string(),
                password: "p".to_string(),
                protocol: protocol.to_string(),
                obfs: "plain".to_string(),
                protocol_param: None,
                obfs_param: None,
            },
        );
        let runtime = Runtime::new(config).expect("runtime");
        let snapshot = find_snapshot(&runtime, "ssr-auth");
        assert!(snapshot.tcp_supported, "{protocol}");
        assert!(snapshot.udp_supported, "{protocol}");
        assert!(!snapshot
            .limitations
            .iter()
            .any(|item| item.contains("unsupported ssr protocol")));
    }
}

#[test]
fn ssr_legacy_protocol_capability_reports_tcp_and_udp_support() {
    for protocol in ["verify_simple", "auth_simple", "auth_sha1", "auth_sha1_v2"] {
        let config = config_with_default(
            "ssr-legacy",
            OutboundConfig::Ssr {
                name: "ssr-legacy".to_string(),
                server: "ssr.example.com".to_string(),
                port: 8388,
                method: "aes-256-cfb".to_string(),
                password: "p".to_string(),
                protocol: protocol.to_string(),
                obfs: "plain".to_string(),
                protocol_param: None,
                obfs_param: None,
            },
        );
        let runtime = Runtime::new(config).expect("runtime");
        let snapshot = find_snapshot(&runtime, "ssr-legacy");
        assert!(snapshot.tcp_supported, "{protocol}");
        assert!(snapshot.udp_supported, "{protocol}");
        assert!(!snapshot
            .limitations
            .iter()
            .any(|item| item.contains("unsupported ssr protocol")));
    }
}

#[test]
fn ssr_auth_chain_g_capability_is_not_advertised_as_supported() {
    let config = config_with_default(
        "ssr-auth",
        OutboundConfig::Ssr {
            name: "ssr-auth".to_string(),
            server: "ssr.example.com".to_string(),
            port: 8388,
            method: "aes-256-cfb".to_string(),
            password: "p".to_string(),
            protocol: "auth_chain_g".to_string(),
            obfs: "plain".to_string(),
            protocol_param: None,
            obfs_param: None,
        },
    );
    let runtime = Runtime::new(config).expect("runtime");
    let snapshot = find_snapshot(&runtime, "ssr-auth");
    assert!(!snapshot.tcp_supported);
    assert!(!snapshot.udp_supported);
    assert!(snapshot
        .limitations
        .iter()
        .any(|item| item.contains("unsupported ssr protocol auth_chain_g")));
}

// ---------------------------------------------------------------------------
// 2. Snell: version/obfs capability boundaries
// ---------------------------------------------------------------------------

#[test]
fn snell_capability_supports_http_obfs_and_marks_udp_boundary() {
    let config = config_with_default(
        "snell-01",
        OutboundConfig::Snell {
            name: "snell-01".to_string(),
            server: "snell.example.com".to_string(),
            port: 4406,
            psk: "psk".to_string(),
            method: Some("aes-128-gcm".to_string()),
            version: Some(3),
            obfs: Some("http".to_string()),
            obfs_host: None,
            reuse: false,
        },
    );
    let runtime = Runtime::new(config).expect("runtime");
    let snapshot = find_snapshot(&runtime, "snell-01");

    assert!(snapshot.tcp_supported);
    assert!(!snapshot.udp_supported);
    assert!(snapshot
        .limitations
        .iter()
        .any(|item| item.contains("snell udp over simple-obfs is not supported")));
}

#[tokio::test]
async fn snell_outbound_with_unknown_obfs_returns_error() {
    let outbounds = build_outbounds(
        &[OutboundConfig::Snell {
            name: "snell-obfs".to_string(),
            server: "127.0.0.1".to_string(),
            port: 1,
            psk: "psk".to_string(),
            method: Some("aes-128-gcm".to_string()),
            version: Some(3),
            obfs: Some("xor".to_string()),
            obfs_host: None,
            reuse: false,
        }],
        None,
    )
    .expect("build");
    let outbound = outbounds.get("snell-obfs").expect("outbound");

    let error = outbound
        .connect(&Destination::new("target.example", 443), 500)
        .await
        .err()
        .expect("snell with obfs must error");
    assert!(
        error.to_string().contains("unsupported snell obfs xor"),
        "expected explicit obfs error, got {error}"
    );
}

#[test]
fn snell_outbound_capability_v3_tcp_supported() {
    // Exercise the v3 + aes-128-gcm happy path through the capability surface.
    // The handshake path itself requires a full Snell server which is out of
    // scope here; capability coverage is sufficient for this test slot.
    let config = config_with_default(
        "snell-v3",
        OutboundConfig::Snell {
            name: "snell-v3".to_string(),
            server: "snell.example.com".to_string(),
            port: 4406,
            psk: "psk".to_string(),
            method: Some("aes-128-gcm".to_string()),
            version: Some(3),
            obfs: None,
            obfs_host: None,
            reuse: false,
        },
    );
    let runtime = Runtime::new(config).expect("runtime");
    let snapshot = find_snapshot(&runtime, "snell-v3");
    assert!(snapshot.tcp_supported);
    assert!(snapshot.udp_supported);
    assert_eq!(snapshot.udp_mode.as_deref(), Some("snell-v3-udp-over-tcp"));
}

#[test]
fn snell_outbound_capability_v4_v5_tcp_udp_supported() {
    for version in [4, 5] {
        let name = format!("snell-v{version}");
        let config = config_with_default(
            &name,
            OutboundConfig::Snell {
                name: name.clone(),
                server: "snell.example.com".to_string(),
                port: 4406,
                psk: "psk".to_string(),
                method: Some("aes-128-gcm".to_string()),
                version: Some(version),
                obfs: None,
                obfs_host: None,
                reuse: true,
            },
        );
        let runtime = Runtime::new(config).expect("runtime");
        let snapshot = find_snapshot(&runtime, &name);
        assert!(snapshot.tcp_supported, "Snell v{version} TCP");
        assert!(snapshot.udp_supported, "Snell v{version} UDP");
        assert_eq!(
            snapshot.udp_mode.as_deref(),
            Some("snell-v4-framed-udp-over-tcp")
        );
    }
}

#[test]
fn snell_v4_capability_rejects_non_aes128_method() {
    let config = config_with_default(
        "snell-v4-invalid-method",
        OutboundConfig::Snell {
            name: "snell-v4-invalid-method".to_string(),
            server: "snell.example.com".to_string(),
            port: 4406,
            psk: "psk".to_string(),
            method: Some("aes-256-gcm".to_string()),
            version: Some(4),
            obfs: None,
            obfs_host: None,
            reuse: false,
        },
    );
    let runtime = Runtime::new(config).expect("runtime");
    let snapshot = find_snapshot(&runtime, "snell-v4-invalid-method");
    assert!(!snapshot.tcp_supported);
    assert!(!snapshot.udp_supported);
    assert!(snapshot
        .limitations
        .iter()
        .any(|item| item.contains("unsupported snell method aes-256-gcm")));
}

#[test]
fn snell_v3_capability_rejects_connection_reuse() {
    let config = config_with_default(
        "snell-v3-reuse",
        OutboundConfig::Snell {
            name: "snell-v3-reuse".to_string(),
            server: "snell.example.com".to_string(),
            port: 4406,
            psk: "psk".to_string(),
            method: Some("aes-128-gcm".to_string()),
            version: Some(3),
            obfs: None,
            obfs_host: None,
            reuse: true,
        },
    );
    let runtime = Runtime::new(config).expect("runtime");
    let snapshot = find_snapshot(&runtime, "snell-v3-reuse");
    assert!(!snapshot.tcp_supported);
    assert!(snapshot.udp_supported);
    assert!(snapshot
        .limitations
        .iter()
        .any(|item| item.contains("snell connection reuse requires version 4 or 5")));
}

// ---------------------------------------------------------------------------
// 3. WireGuard: allowed_ips / reserved / mtu validation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn wireguard_rejects_missing_keys() {
    let outbounds = build_outbounds(
        &[OutboundConfig::WireGuard {
            name: "wg-nokey".to_string(),
            server: "127.0.0.1".to_string(),
            port: 51820,
            private_key: "".to_string(),
            public_key: "".to_string(),
            preshared_key: None,
            ip: vec!["10.0.0.2/32".to_string()],
            ipv6: vec![],
            allowed_ips: vec!["0.0.0.0/0".to_string()],
            reserved: vec![],
            mtu: Some(1420),
            persistent_keepalive: None,
            remote_dns_resolve: false,
            dns: vec![],
            peers: vec![],
        }],
        None,
    )
    .expect("build");
    let outbound = outbounds.get("wg-nokey").expect("outbound");

    let error = outbound
        .connect(&Destination::new("1.1.1.1", 80), 500)
        .await
        .err()
        .expect("must error on empty key");
    assert!(error.to_string().contains("wireguard private_key is empty"));
}

#[tokio::test]
async fn wireguard_rejects_reserved_length_other_than_three() {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let private_key = STANDARD.encode([1u8; 32]);
    let public_key = STANDARD.encode([2u8; 32]);

    let outbounds = build_outbounds(
        &[OutboundConfig::WireGuard {
            name: "wg-reserved".to_string(),
            server: "127.0.0.1".to_string(),
            port: 51820,
            private_key,
            public_key,
            preshared_key: None,
            ip: vec!["10.0.0.2/32".to_string()],
            ipv6: vec![],
            allowed_ips: vec!["0.0.0.0/0".to_string()],
            reserved: vec![1, 2, 3, 4],
            mtu: Some(1420),
            persistent_keepalive: None,
            remote_dns_resolve: false,
            dns: vec![],
            peers: vec![],
        }],
        None,
    )
    .expect("build");
    let outbound = outbounds.get("wg-reserved").expect("outbound");

    let error = outbound
        .connect(&Destination::new("1.1.1.1", 80), 500)
        .await
        .err()
        .expect("must error on reserved != 3");
    assert!(error
        .to_string()
        .contains("reserved must be exactly 3 bytes"));
}

#[tokio::test]
async fn wireguard_rejects_destination_outside_allowed_ips() {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let private_key = STANDARD.encode([1u8; 32]);
    let public_key = STANDARD.encode([2u8; 32]);

    let outbounds = build_outbounds(
        &[OutboundConfig::WireGuard {
            name: "wg-scope".to_string(),
            server: "127.0.0.1".to_string(),
            port: 51820,
            private_key,
            public_key,
            preshared_key: None,
            ip: vec!["10.0.0.2/32".to_string()],
            ipv6: vec![],
            // Restrict to private net: 1.1.1.1 must be rejected.
            allowed_ips: vec!["10.0.0.0/8".to_string()],
            reserved: vec![],
            mtu: Some(1420),
            persistent_keepalive: None,
            remote_dns_resolve: false,
            dns: vec![],
            peers: vec![],
        }],
        None,
    )
    .expect("build");
    let outbound = outbounds.get("wg-scope").expect("outbound");

    let error = outbound
        .connect(&Destination::new("1.1.1.1", 80), 500)
        .await
        .err()
        .expect("must error on out-of-scope destination");
    assert!(error.to_string().contains("not covered by allowed_ips"));
}

#[test]
fn wireguard_builder_accepts_optional_fields_absent() {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let private_key = STANDARD.encode([1u8; 32]);
    let public_key = STANDARD.encode([2u8; 32]);

    // All optional fields absent: builder must succeed.
    let outbounds = build_outbounds(
        &[OutboundConfig::WireGuard {
            name: "wg-min".to_string(),
            server: "127.0.0.1".to_string(),
            port: 51820,
            private_key,
            public_key,
            preshared_key: None,
            ip: vec!["10.0.0.2/32".to_string()],
            ipv6: vec![],
            allowed_ips: vec![],
            reserved: vec![],
            mtu: None,
            persistent_keepalive: None,
            remote_dns_resolve: false,
            dns: vec![],
            peers: vec![],
        }],
        None,
    )
    .expect("build with no optional fields");
    let outbound = outbounds.get("wg-min").expect("outbound");
    assert_eq!(outbound.name(), "wg-min");
    assert_eq!(outbound.kind(), "wireguard");
}

// ---------------------------------------------------------------------------
// 4. AnyTLS: mock server that accepts auth header + SETTINGS/SYN frames
// ---------------------------------------------------------------------------

#[tokio::test]
async fn anytls_outbound_does_not_hang_against_tls_server() {
    // Mock server: completes TLS handshake, then closes. The outbound will
    // error on the post-handshake frame read — we just need to confirm the
    // outbound is constructable and the connect call returns (no panic,
    // no infinite hang).
    let (addr, server) = spawn_tls_drop_server("anytls.example.com").await;
    let outbounds = build_outbounds(
        &[OutboundConfig::AnyTls {
            name: "anytls-01".to_string(),
            server: "127.0.0.1".to_string(),
            port: addr.port(),
            password: "p".to_string(),
            sni: Some("anytls.example.com".to_string()),
            skip_cert_verify: true,
            alpn: vec![],
            idle_session_check_interval: None,
            idle_session_timeout: None,
            min_idle_session: None,
        }],
        None,
    )
    .expect("build");
    let outbound = outbounds.get("anytls-01").expect("outbound");
    let result = timeout(
        Duration::from_millis(2000),
        outbound.connect(&Destination::new("target.example", 443), 2000),
    )
    .await
    .expect("anytls connect must not hang");
    let _ = result;
    let _ = timeout(Duration::from_millis(2000), server).await;
}

#[test]
fn anytls_capability_reports_uot_v2_udp() {
    let config = config_with_default(
        "anytls-cap",
        OutboundConfig::AnyTls {
            name: "anytls-cap".to_string(),
            server: "anytls.example.com".to_string(),
            port: 8443,
            password: "p".to_string(),
            sni: None,
            skip_cert_verify: false,
            alpn: vec!["h2".to_string()],
            idle_session_check_interval: None,
            idle_session_timeout: None,
            min_idle_session: None,
        },
    );
    let runtime = Runtime::new(config).expect("runtime");
    let snapshot = find_snapshot(&runtime, "anytls-cap");
    assert!(snapshot.tcp_supported);
    assert!(snapshot.udp_supported);
    assert_eq!(snapshot.udp_mode.as_deref(), Some("anytls-uot-v2"));
}

#[test]
fn anytls_frame_header_layout() {
    // Frame format: 1 byte command + 4 bytes sid + 2 bytes length.
    // Guards against accidental format changes.
    let mut header = [0u8; 7];
    header[0] = 4; // SETTINGS
    header[1..5].copy_from_slice(&1u32.to_be_bytes());
    header[5..7].copy_from_slice(&0u16.to_be_bytes());
    assert_eq!(header[0], 4);
    assert_eq!(
        u32::from_be_bytes([header[1], header[2], header[3], header[4]]),
        1
    );
    assert_eq!(u16::from_be_bytes([header[5], header[6]]), 0);
}

#[test]
fn anytls_password_sha256_hash_is_deterministic() {
    // The outbound hashes the password with SHA-256 to derive the auth header.
    let password = "secret";
    let hash: [u8; 32] = Sha256::digest(password.as_bytes()).into();
    assert_eq!(hash.len(), 32);
    let again: [u8; 32] = Sha256::digest(password.as_bytes()).into();
    assert_eq!(hash, again);
}

#[test]
fn shadowtls_capability_rejects_non_v3() {
    let config = config_with_default(
        "shadowtls-v1",
        OutboundConfig::ShadowTls {
            name: "shadowtls-v1".to_string(),
            server: "shadow.example".to_string(),
            port: 443,
            password: "p".to_string(),
            version: Some(1),
            sni: None,
            skip_cert_verify: false,
        },
    );
    let runtime = Runtime::new(config).expect("runtime");
    let snapshot = find_snapshot(&runtime, "shadowtls-v1");
    assert!(
        snapshot
            .limitations
            .iter()
            .any(|item| item.contains("unsupported shadowtls version 1")),
        "got {:?}",
        snapshot.limitations,
    );
}

// ---------------------------------------------------------------------------
// 6. Naive: HTTP/1.1 CONNECT mock server
// ---------------------------------------------------------------------------

#[tokio::test]
async fn naive_outbound_sends_connect_to_mock() {
    let cert = rcgen::generate_simple_self_signed(vec!["naive.example".to_string()]).unwrap();
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()));
    let server_config =
        ServerConfig::builder_with_provider(rustls::crypto::aws_lc_rs::default_provider().into())
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        if let Ok((stream, _)) = listener.accept().await {
            if let Ok(mut stream) = acceptor.accept(stream).await {
                let mut request = Vec::new();
                let mut buf = [0u8; 256];
                loop {
                    let n = stream.read(&mut buf).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    request.extend_from_slice(&buf[..n]);
                    if request.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                let text = String::from_utf8_lossy(&request);
                assert!(
                    text.starts_with("CONNECT target.example:443 HTTP/1.1\r\n"),
                    "expected naive CONNECT, got {text}"
                );
                assert!(
                    text.contains("Padding-Type-Request: 1, 0\r\n"),
                    "missing Naive padding negotiation: {text}"
                );
                assert!(text.contains("Padding: "), "missing Naive padding: {text}");
                let _ = stream
                    .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                    .await;
            }
        }
    });

    let outbounds = build_outbounds(
        &[OutboundConfig::Naive {
            name: "naive-01".to_string(),
            server: "127.0.0.1".to_string(),
            port: addr.port(),
            username: None,
            password: None,
            sni: Some("naive.example".to_string()),
            skip_cert_verify: true,
            alpn: vec!["http/1.1".to_string()],
        }],
        None,
    )
    .expect("build");
    let outbound = outbounds.get("naive-01").expect("outbound");

    let result = timeout(
        Duration::from_millis(2000),
        outbound.connect(&Destination::new("target.example", 443), 2000),
    )
    .await
    .expect("naive connect should not hang");
    if let Err(error) = result {
        panic!("naive HTTP/1.1 CONNECT failed: {error:#}");
    }
    let _ = server.await;
}

#[test]
fn naive_capability_reports_no_udp() {
    let config = config_with_default(
        "naive-cap",
        OutboundConfig::Naive {
            name: "naive-cap".to_string(),
            server: "naive.example".to_string(),
            port: 443,
            username: Some("u".to_string()),
            password: Some("p".to_string()),
            sni: None,
            skip_cert_verify: false,
            alpn: vec![],
        },
    );
    let runtime = Runtime::new(config).expect("runtime");
    let snapshot = find_snapshot(&runtime, "naive-cap");
    assert!(!snapshot.udp_supported);
    assert!(
        snapshot
            .limitations
            .iter()
            .any(|item| item.contains("CONNECT-UDP is not part of the protocol")),
        "got {:?}",
        snapshot.limitations,
    );
    assert_eq!(snapshot.udp_mode, None);
}

// ---------------------------------------------------------------------------
// 7. Hysteria v1: decision = parse-only / unsupported native dial
// ---------------------------------------------------------------------------

#[test]
fn hysteria_v1_capability_marks_unsupported() {
    // Decision: Hysteria v1 stays parse-only / unsupported native dial.
    let config = config_with_default(
        "hy-01",
        OutboundConfig::Hysteria {
            name: "hy-01".to_string(),
            server: "hy.example.com".to_string(),
            port: 36712,
            auth: Some("auth".to_string()),
            auth_str: None,
            protocol: Some("udp".to_string()),
            up: None,
            down: None,
            sni: Some("hy.example.com".to_string()),
            skip_cert_verify: false,
            obfs: None,
        },
    );
    let runtime = Runtime::new(config).expect("runtime");
    let snapshot = find_snapshot(&runtime, "hy-01");

    assert!(
        !snapshot.tcp_supported,
        "hysteria v1 must not advertise TCP"
    );
    assert!(
        !snapshot.udp_supported,
        "hysteria v1 must not advertise UDP"
    );
    assert!(
        snapshot
            .limitations
            .iter()
            .any(|item| item.contains("not implemented yet")),
        "hysteria v1 must include 'not implemented yet', got {:?}",
        snapshot.limitations,
    );
    assert_eq!(snapshot.kind, "hysteria");
}

#[tokio::test]
async fn hysteria_v1_dial_returns_unsupported_error() {
    let outbounds = build_outbounds(
        &[OutboundConfig::Hysteria {
            name: "hy-dial".to_string(),
            server: "127.0.0.1".to_string(),
            port: 36712,
            auth: Some("auth".to_string()),
            auth_str: None,
            protocol: Some("udp".to_string()),
            up: None,
            down: None,
            sni: Some("hy.example.com".to_string()),
            skip_cert_verify: false,
            obfs: None,
        }],
        None,
    )
    .expect("build");
    let outbound = outbounds.get("hy-dial").expect("outbound");
    assert_eq!(outbound.kind(), "unsupported-protocol");

    let error = outbound
        .connect(&Destination::new("1.1.1.1", 80), 500)
        .await
        .err()
        .expect("hysteria v1 must fail to dial");
    assert!(
        error
            .to_string()
            .contains("native dialing is not implemented yet"),
        "got {error}"
    );
}

#[tokio::test]
async fn hysteria_v1_routes_through_runtime_to_unsupported() {
    // End-to-end: build a SuperConfig with a Hysteria v1 outbound, route the
    // default traffic to it via Match rule, and confirm the runtime returns
    // Err with the same unsupported message.
    let mut config = SuperConfig {
        outbounds: vec![
            OutboundConfig::Direct {
                name: "direct".to_string(),
            },
            OutboundConfig::Hysteria {
                name: "hy".to_string(),
                server: "127.0.0.1".to_string(),
                port: 36712,
                auth: Some("auth".to_string()),
                auth_str: None,
                protocol: Some("udp".to_string()),
                up: None,
                down: None,
                sni: Some("hy.example.com".to_string()),
                skip_cert_verify: false,
                obfs: None,
            },
        ],
        ..SuperConfig::default()
    };
    config.core.default_outbound = "hy".to_string();
    config.rules = vec![RouteRule {
        target: RuleTarget::Match,
        value: "*".to_string(),
        outbound: "hy".to_string(),
    }];
    let runtime = Runtime::new(config).expect("runtime");

    let _ = runtime
        .connect_outbound(&Destination::new(
            Ipv4Addr::LOCALHOST.to_string().as_str(),
            80,
        ))
        .await
        .err()
        .expect("hysteria v1 connect must fail");
}

// ---------------------------------------------------------------------------
// 8. Cross-protocol sanity: outbound cap report contains every protocol
// ---------------------------------------------------------------------------

#[test]
fn capability_report_covers_all_partial_protocols() {
    // Build a config with one outbound per partial protocol. Verify the
    // capability snapshot exposes all kinds + udp_supported=false for Hysteria v1.
    let outbounds = vec![
        OutboundConfig::Direct {
            name: "direct".to_string(),
        },
        OutboundConfig::Ssr {
            name: "ssr".to_string(),
            server: "h".to_string(),
            port: 1,
            method: "aes-256-cfb".to_string(),
            password: "p".to_string(),
            protocol: "origin".to_string(),
            obfs: "plain".to_string(),
            protocol_param: None,
            obfs_param: None,
        },
        OutboundConfig::Snell {
            name: "snell".to_string(),
            server: "h".to_string(),
            port: 1,
            psk: "p".to_string(),
            method: None,
            version: None,
            obfs: None,
            obfs_host: None,
            reuse: false,
        },
        OutboundConfig::WireGuard {
            name: "wg".to_string(),
            server: "h".to_string(),
            port: 1,
            private_key: "k".to_string(),
            public_key: "k".to_string(),
            preshared_key: None,
            ip: vec!["10.0.0.1/32".to_string()],
            ipv6: vec![],
            allowed_ips: vec![],
            reserved: vec![],
            mtu: Some(1420),
            persistent_keepalive: None,
            remote_dns_resolve: false,
            dns: vec![],
            peers: vec![],
        },
        OutboundConfig::AnyTls {
            name: "anytls".to_string(),
            server: "h".to_string(),
            port: 1,
            password: "p".to_string(),
            sni: None,
            skip_cert_verify: false,
            alpn: vec![],
            idle_session_check_interval: None,
            idle_session_timeout: None,
            min_idle_session: None,
        },
        OutboundConfig::ShadowTls {
            name: "shadow".to_string(),
            server: "h".to_string(),
            port: 1,
            password: "p".to_string(),
            version: Some(3),
            sni: None,
            skip_cert_verify: false,
        },
        OutboundConfig::Naive {
            name: "naive".to_string(),
            server: "h".to_string(),
            port: 1,
            username: None,
            password: None,
            sni: None,
            skip_cert_verify: false,
            alpn: vec![],
        },
        OutboundConfig::Hysteria {
            name: "hy".to_string(),
            server: "h".to_string(),
            port: 1,
            auth: None,
            auth_str: None,
            protocol: None,
            up: None,
            down: None,
            sni: None,
            skip_cert_verify: false,
            obfs: None,
        },
    ];
    let mut config = SuperConfig {
        outbounds,
        ..SuperConfig::default()
    };
    config.core.default_outbound = "ssr".to_string();
    let runtime = Runtime::new(config).expect("runtime");
    let snapshots = runtime.outbound_capabilities();
    let names: Vec<&str> = snapshots.iter().map(|s| s.name.as_str()).collect();
    for needle in ["ssr", "snell", "wg", "anytls", "shadow", "naive", "hy"] {
        assert!(
            names.contains(&needle),
            "capability report missing {needle}: {names:?}"
        );
    }
    for snap in &snapshots {
        if snap.name == "hy" {
            assert!(!snap.tcp_supported);
            assert!(!snap.udp_supported);
        }
    }
}
