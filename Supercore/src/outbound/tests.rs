use super::*;
use std::{
    collections::BTreeMap,
    io::{Cursor, Error, ErrorKind},
    pin::Pin,
    sync::{Arc, Mutex as StdMutex},
    task::{Context as TaskContext, Poll},
    time::Duration,
};

use ::shadowsocks::{
    config::{ServerConfig as ShadowsocksServerConfig, ServerType as ShadowsocksServerType},
    context::Context as ShadowsocksContext,
    crypto::CipherKind as ShadowsocksCipherKind,
    relay::{
        socks5::Address as ShadowsocksAddress,
        tcprelay::proxy_stream::ProxyServerStream as ShadowsocksServerStream,
    },
    ServerAddr as ShadowsocksServerAddr,
};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm,
};
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use md5::Digest;
use rustls::crypto::aws_lc_rs;
use rustls::ServerConfig;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::Sha224;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use uuid::Uuid;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

use crate::{config::ShadowsocksPluginConfig, routing::Destination};

use super::{
    context::DialContext,
    error::{OutboundError, OutboundErrorKind},
    group::GroupOutbound,
    hysteria2::{
        build_hysteria2_tcp_request, build_hysteria2_udp_messages, parse_hysteria2_udp_message,
        Hysteria2UdpReassembly,
    },
    shadowsocks::{
        encode_ss_chunk, evp_bytes_to_key, find_header_end, read_simple_obfs_tls_record,
        read_ss_chunk, spawn_simple_obfs_transport, write_ss_chunk, ShadowsocksOutbound,
        Ss2022ReplayWindow, SsCipher, SIMPLE_OBFS_TLS_FIXED_CLIENT_HELLO_LEN,
        SIMPLE_OBFS_TLS_SESSION_TICKET_HEADER_LEN, SS_NONCE_LEN,
    },
    transports::{
        read_websocket_frame, render_transport_headers, websocket_accept_key,
        write_websocket_binary_frame, write_websocket_frame,
    },
    trojan::{build_trojan_request, trojan_alpn_protocols, TrojanOutbound},
    tuic::{
        build_tuic_connect_request, build_tuic_packet_messages, parse_tuic_packet_message,
        TuicUdpReassembly,
    },
    util::hex_lower,
    vless::{
        build_vless_request, build_vless_request_with_flow, decode_reality_public_key,
        decode_reality_short_id, seal_reality_session_id, VlessOutbound, REALITY_CLIENT_VERSION,
    },
    vmess::{
        read_vmess_chunk, vmess_aes128gcm_decrypt, vmess_aes128gcm_encrypt, vmess_fnv1a,
        vmess_instruction_key, vmess_kdf, vmess_sha256_16, write_vmess_chunk, VmessAeadState,
        VmessCipher, VmessDownloadState, VmessLengthMask, VmessOutbound, VmessUploadState,
        VMESS_TAG_LEN,
    },
};

struct ContextRecordingOutbound {
    trace_id: Arc<StdMutex<Option<String>>>,
}

struct PendingOutbound;

#[async_trait]
impl Outbound for PendingOutbound {
    fn name(&self) -> &str {
        "pending"
    }

    fn kind(&self) -> &'static str {
        "test"
    }

    fn capability(&self) -> OutboundCapability {
        OutboundCapability::tcp_only("test outbound")
    }

    async fn connect(
        &self,
        _destination: &Destination,
        _timeout_ms: u64,
    ) -> anyhow::Result<BoxedStream> {
        std::future::pending().await
    }
}

#[async_trait]
impl Outbound for ContextRecordingOutbound {
    fn name(&self) -> &str {
        "context-recorder"
    }

    fn kind(&self) -> &'static str {
        "test"
    }

    fn capability(&self) -> OutboundCapability {
        OutboundCapability::tcp_only("test outbound")
    }

    async fn connect(
        &self,
        _destination: &Destination,
        _timeout_ms: u64,
    ) -> anyhow::Result<BoxedStream> {
        let (stream, peer) = tokio::io::duplex(64);
        drop(peer);
        Ok(Box::new(stream))
    }

    async fn connect_context(&self, context: &DialContext) -> anyhow::Result<BoxedStream> {
        *self.trace_id.lock().expect("trace lock") = Some(context.trace_id.clone());
        self.connect(&context.destination, context.timeout_ms())
            .await
    }
}

#[tokio::test]
async fn group_propagates_dial_context_to_selected_member() {
    let recorded = Arc::new(StdMutex::new(None));
    let member: Arc<dyn Outbound> = Arc::new(ContextRecordingOutbound {
        trace_id: Arc::clone(&recorded),
    });
    let group = GroupOutbound::new(
        "group".to_string(),
        "select".to_string(),
        vec![member],
        None,
    );
    let context = DialContext::new(Destination::new("example.com", 443), 500);
    let expected = context.trace_id.clone();
    group
        .connect_context(&context)
        .await
        .expect("group connect");
    assert_eq!(
        recorded.lock().expect("trace lock").as_deref(),
        Some(expected.as_str())
    );
}

#[tokio::test]
async fn dial_context_cancellation_stops_pending_outbound() {
    let outbound = PendingOutbound;
    let context = DialContext::new(Destination::new("example.com", 443), 30_000);
    context.cancel();
    let error = match outbound.connect_context(&context).await {
        Ok(_) => panic!("cancelled dial should fail"),
        Err(error) => error,
    };
    assert_eq!(
        error
            .downcast_ref::<OutboundError>()
            .map(|error| error.kind),
        Some(OutboundErrorKind::Cancelled)
    );
}

#[tokio::test]
async fn shadowsocks_outbound_encrypts_tcp_stream() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen_addr = listener.local_addr().unwrap();
    let password = "correct horse battery staple".to_string();
    let destination = Destination::new("target.example", 443);
    let mut expected_destination = Vec::new();
    encode_socks5_destination(&destination, &mut expected_destination).unwrap();
    let server_password = password.clone();

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let cipher = SsCipher::Aes128Gcm;
        let master_key = evp_bytes_to_key(server_password.as_bytes(), cipher.key_len());
        let mut salt = vec![0u8; cipher.salt_len()];
        stream.read_exact(&mut salt).await.unwrap();
        let subkey = cipher.derive_subkey(&master_key, &salt).unwrap();

        let mut inbound_nonce = [0u8; SS_NONCE_LEN];
        let destination_payload = read_ss_chunk(cipher, &subkey, &mut inbound_nonce, &mut stream)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(destination_payload, expected_destination);

        let payload = read_ss_chunk(cipher, &subkey, &mut inbound_nonce, &mut stream)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(payload, b"ping");

        let response_salt = vec![0x42; cipher.salt_len()];
        let response_key = cipher.derive_subkey(&master_key, &response_salt).unwrap();
        stream.write_all(&response_salt).await.unwrap();
        let mut outbound_nonce = [0u8; SS_NONCE_LEN];
        write_ss_chunk(
            cipher,
            &response_key,
            &mut outbound_nonce,
            &mut stream,
            b"pong",
        )
        .await
        .unwrap();
    });

    let outbound = ShadowsocksOutbound::new(
        "ss-test".to_string(),
        "127.0.0.1".to_string(),
        listen_addr.port(),
        "aes-128-gcm".to_string(),
        password,
        None,
        false,
        1,
    );
    let mut stream = outbound.connect(&destination, 1000).await.unwrap();
    stream.write_all(b"ping").await.unwrap();
    let mut response = [0u8; 4];
    stream.read_exact(&mut response).await.unwrap();

    assert_eq!(&response, b"pong");
    server.await.unwrap();
}

#[tokio::test]
async fn shadowsocks_simple_obfs_http_wraps_first_packet() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen_addr = listener.local_addr().unwrap();
    let password = "secret".to_string();
    let destination = Destination::new("target.example", 443);
    let mut expected_destination = Vec::new();
    encode_socks5_destination(&destination, &mut expected_destination).unwrap();
    let server_password = password.clone();

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut first_packet = Vec::new();
        let mut buf = [0u8; 512];
        loop {
            let n = stream.read(&mut buf).await.unwrap();
            assert!(n > 0);
            first_packet.extend_from_slice(&buf[..n]);
            if let Some(index) = find_header_end(&first_packet) {
                let header_bytes = first_packet[..index].to_vec();
                let mut body = first_packet[index..].to_vec();
                let header = String::from_utf8(header_bytes).unwrap();
                assert!(header.starts_with("GET / HTTP/1.1"));
                assert!(header.contains("Host: edge.example.com"));
                assert!(header.contains("Upgrade: websocket"));
                let content_length = header
                    .lines()
                    .find_map(|line| {
                        line.split_once(':').and_then(|(name, value)| {
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().ok())
                                .flatten()
                        })
                    })
                    .unwrap();
                while body.len() < content_length {
                    let n = stream.read(&mut buf).await.unwrap();
                    assert!(n > 0);
                    body.extend_from_slice(&buf[..n]);
                }

                let cipher = SsCipher::Aes128Gcm;
                let master_key = evp_bytes_to_key(server_password.as_bytes(), cipher.key_len());
                let salt = body[..cipher.salt_len()].to_vec();
                let subkey = cipher.derive_subkey(&master_key, &salt).unwrap();
                let mut inbound_nonce = [0u8; SS_NONCE_LEN];
                let mut body_reader = Cursor::new(body.split_off(cipher.salt_len()));
                let destination_payload =
                    read_ss_chunk(cipher, &subkey, &mut inbound_nonce, &mut body_reader)
                        .await
                        .unwrap()
                        .unwrap();
                assert_eq!(destination_payload, expected_destination);

                stream
                    .write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\n\r\n")
                    .await
                    .unwrap();
                let response_salt = vec![0x42; cipher.salt_len()];
                let response_key = cipher.derive_subkey(&master_key, &response_salt).unwrap();
                stream.write_all(&response_salt).await.unwrap();
                let mut outbound_nonce = [0u8; SS_NONCE_LEN];
                write_ss_chunk(
                    cipher,
                    &response_key,
                    &mut outbound_nonce,
                    &mut stream,
                    b"pong",
                )
                .await
                .unwrap();
                break;
            }
        }
    });

    let outbound = ShadowsocksOutbound::new(
        "ss-obfs-test".to_string(),
        "127.0.0.1".to_string(),
        listen_addr.port(),
        "aes-128-gcm".to_string(),
        password,
        Some(ShadowsocksPluginConfig {
            mode: "http_simple".to_string(),
            host: Some("edge.example.com".to_string()),
            path: None,
            tls: false,
            skip_cert_verify: false,
        }),
        false,
        1,
    );
    let mut stream = outbound.connect(&destination, 1000).await.unwrap();
    let mut response = [0u8; 4];
    stream.read_exact(&mut response).await.unwrap();

    assert_eq!(&response, b"pong");
    server.await.unwrap();
}

#[tokio::test]
async fn shadowsocks_simple_obfs_tls_wraps_stream() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen_addr = listener.local_addr().unwrap();
    let password = "secret".to_string();
    let destination = Destination::new("target.example", 443);
    let mut expected_destination = Vec::new();
    encode_socks5_destination(&destination, &mut expected_destination).unwrap();
    let server_password = password.clone();

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let (record_type, _version, client_hello) = read_simple_obfs_tls_record(&mut stream)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(record_type, 0x16);
        assert_eq!(client_hello[0], 0x01);
        assert_eq!(&client_hello[4..6], &[0x03, 0x03]);
        assert!(client_hello
            .windows("edge.example.com".len())
            .any(|window| window == b"edge.example.com"));
        let ticket_offset = SIMPLE_OBFS_TLS_FIXED_CLIENT_HELLO_LEN - 5;
        assert_eq!(
            &client_hello[ticket_offset..ticket_offset + 2],
            &[0x00, 0x23]
        );
        let ticket_len = u16::from_be_bytes([
            client_hello[ticket_offset + 2],
            client_hello[ticket_offset + 3],
        ]) as usize;
        let body_start = ticket_offset + SIMPLE_OBFS_TLS_SESSION_TICKET_HEADER_LEN;
        let body_end = body_start + ticket_len;
        let body = client_hello[body_start..body_end].to_vec();

        let cipher = SsCipher::Aes128Gcm;
        let master_key = evp_bytes_to_key(server_password.as_bytes(), cipher.key_len());
        let salt = body[..cipher.salt_len()].to_vec();
        let subkey = cipher.derive_subkey(&master_key, &salt).unwrap();
        let mut inbound_nonce = [0u8; SS_NONCE_LEN];
        let mut body_reader = Cursor::new(body[cipher.salt_len()..].to_vec());
        let destination_payload =
            read_ss_chunk(cipher, &subkey, &mut inbound_nonce, &mut body_reader)
                .await
                .unwrap()
                .unwrap();
        assert_eq!(destination_payload, expected_destination);

        let (record_type, _version, upload) = read_simple_obfs_tls_record(&mut stream)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(record_type, 0x17);
        let mut upload_reader = Cursor::new(upload);
        let payload = read_ss_chunk(cipher, &subkey, &mut inbound_nonce, &mut upload_reader)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(payload, b"ping");

        let response_salt = vec![0x42; cipher.salt_len()];
        let response_key = cipher.derive_subkey(&master_key, &response_salt).unwrap();
        let mut outbound_nonce = [0u8; SS_NONCE_LEN];
        let response_chunk =
            encode_ss_chunk(cipher, &response_key, &mut outbound_nonce, b"pong").unwrap();
        let mut response_payload = response_salt;
        response_payload.extend_from_slice(&response_chunk);
        let mut response = vec![
            0x16, 0x03, 0x01, 0x00, 0x00, 0x14, 0x03, 0x03, 0x00, 0x01, 0x01,
        ];
        response.extend_from_slice(&[0x16, 0x03, 0x03]);
        response.extend_from_slice(&(response_payload.len() as u16).to_be_bytes());
        response.extend_from_slice(&response_payload);
        stream.write_all(&response).await.unwrap();
    });

    let outbound = ShadowsocksOutbound::new(
        "ss-obfs-tls-test".to_string(),
        "127.0.0.1".to_string(),
        listen_addr.port(),
        "aes-128-gcm".to_string(),
        password,
        Some(ShadowsocksPluginConfig {
            mode: "tls".to_string(),
            host: Some("edge.example.com".to_string()),
            path: None,
            tls: false,
            skip_cert_verify: false,
        }),
        false,
        1,
    );
    let mut stream = outbound.connect(&destination, 1000).await.unwrap();
    stream.write_all(b"ping").await.unwrap();
    let mut response = [0u8; 4];
    stream.read_exact(&mut response).await.unwrap();

    assert_eq!(&response, b"pong");
    server.await.unwrap();
}

#[tokio::test]
async fn shadowsocks_simple_obfs_http_transparent_transport() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen_addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut buffer = [0u8; 512];
        loop {
            let read = stream.read(&mut buffer).await.unwrap();
            assert!(read > 0);
            request.extend_from_slice(&buffer[..read]);
            let Some(header_end) = find_header_end(&request) else {
                continue;
            };
            let header = String::from_utf8(request[..header_end].to_vec()).unwrap();
            let content_length = header
                .lines()
                .find_map(|line| {
                    line.split_once(':').and_then(|(name, value)| {
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().ok())
                            .flatten()
                    })
                })
                .unwrap();
            while request.len() - header_end < content_length {
                let read = stream.read(&mut buffer).await.unwrap();
                assert!(read > 0);
                request.extend_from_slice(&buffer[..read]);
            }
            assert_eq!(&request[header_end..header_end + content_length], b"hello");
            stream
                .write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\n\r\nworld")
                .await
                .unwrap();
            break;
        }
    });

    let raw = tokio::net::TcpStream::connect(listen_addr).await.unwrap();
    let mut stream = spawn_simple_obfs_transport(
        Box::new(raw),
        ShadowsocksPluginConfig {
            mode: "http_simple".to_string(),
            host: Some("edge.example.com".to_string()),
            path: None,
            tls: false,
            skip_cert_verify: false,
        },
        "127.0.0.1".to_string(),
        listen_addr.port(),
    );
    stream.write_all(b"hello").await.unwrap();
    let mut response = [0u8; 5];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"world");
    server.await.unwrap();
}

#[tokio::test]
async fn shadowsocks_simple_obfs_tls_transparent_transport() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen_addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let (record_type, _, client_hello) = read_simple_obfs_tls_record(&mut stream)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(record_type, 0x16);
        let ticket_offset = SIMPLE_OBFS_TLS_FIXED_CLIENT_HELLO_LEN - 5;
        let ticket_len = u16::from_be_bytes([
            client_hello[ticket_offset + 2],
            client_hello[ticket_offset + 3],
        ]) as usize;
        let body_start = ticket_offset + SIMPLE_OBFS_TLS_SESSION_TICKET_HEADER_LEN;
        assert_eq!(&client_hello[body_start..body_start + ticket_len], b"hello");

        let mut response = vec![
            0x16, 0x03, 0x01, 0x00, 0x00, 0x14, 0x03, 0x03, 0x00, 0x01, 0x01,
        ];
        response.extend_from_slice(&[0x16, 0x03, 0x03, 0x00, 0x05]);
        response.extend_from_slice(b"world");
        stream.write_all(&response).await.unwrap();
    });

    let raw = tokio::net::TcpStream::connect(listen_addr).await.unwrap();
    let mut stream = spawn_simple_obfs_transport(
        Box::new(raw),
        ShadowsocksPluginConfig {
            mode: "tls".to_string(),
            host: Some("edge.example.com".to_string()),
            path: None,
            tls: false,
            skip_cert_verify: false,
        },
        "127.0.0.1".to_string(),
        listen_addr.port(),
    );
    stream.write_all(b"hello").await.unwrap();
    let mut response = [0u8; 5];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"world");
    server.await.unwrap();
}

#[tokio::test]
async fn shadowsocks_extended_cipher_over_simple_obfs_real_dial() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen_addr = listener.local_addr().unwrap();
    let destination = Destination::new("managed-obfs.example", 443);
    let expected_destination = destination.clone();
    let method = "aes-192-ctr".parse::<ShadowsocksCipherKind>().unwrap();
    let server_config = ShadowsocksServerConfig::new(
        ShadowsocksServerAddr::SocketAddr(listen_addr),
        "secret",
        method,
    )
    .unwrap();
    let server_key = server_config.key().to_vec();
    let server = tokio::spawn(async move {
        let (mut raw, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut buffer = [0u8; 512];
        let (header_end, content_length) = loop {
            let read = raw.read(&mut buffer).await.unwrap();
            assert!(read > 0);
            request.extend_from_slice(&buffer[..read]);
            let Some(header_end) = find_header_end(&request) else {
                continue;
            };
            let header = String::from_utf8(request[..header_end].to_vec()).unwrap();
            let content_length = header
                .lines()
                .find_map(|line| {
                    line.split_once(':').and_then(|(name, value)| {
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().ok())
                            .flatten()
                    })
                })
                .unwrap();
            break (header_end, content_length);
        };
        while request.len() - header_end < content_length {
            let read = raw.read(&mut buffer).await.unwrap();
            assert!(read > 0);
            request.extend_from_slice(&buffer[..read]);
        }
        let initial = request[header_end..header_end + content_length].to_vec();
        let trailing = request[header_end + content_length..].to_vec();

        let (proxy_side, relay_side) = tokio::io::duplex(64 * 1024);
        let (mut relay_read, mut relay_write) = tokio::io::split(relay_side);
        relay_write.write_all(&initial).await.unwrap();
        relay_write.write_all(&trailing).await.unwrap();
        let (mut raw_read, mut raw_write) = raw.into_split();
        raw_write
            .write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\n\r\n")
            .await
            .unwrap();
        let uplink = tokio::spawn(async move {
            let _ = tokio::io::copy(&mut raw_read, &mut relay_write).await;
        });
        let downlink = tokio::spawn(async move {
            let _ = tokio::io::copy(&mut relay_read, &mut raw_write).await;
        });

        let context = ShadowsocksContext::new_shared(ShadowsocksServerType::Server);
        let mut stream =
            ShadowsocksServerStream::from_stream(context, proxy_side, method, &server_key);
        let address = stream.handshake().await.unwrap();
        match address {
            ShadowsocksAddress::DomainNameAddress(host, port) => {
                assert_eq!(host, expected_destination.host);
                assert_eq!(port, expected_destination.port);
            }
            other => panic!("unexpected Shadowsocks target {other}"),
        }
        let mut payload = [0u8; 4];
        stream.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"ping");
        stream.write_all(b"pong").await.unwrap();
        stream.shutdown().await.unwrap();
        drop(stream);
        uplink.abort();
        let _ = downlink.await;
    });

    let outbound = ShadowsocksOutbound::new(
        "ss-managed-obfs".to_string(),
        "127.0.0.1".to_string(),
        listen_addr.port(),
        "aes-192-ctr".to_string(),
        "secret".to_string(),
        Some(ShadowsocksPluginConfig {
            mode: "http_simple".to_string(),
            host: Some("edge.example.com".to_string()),
            path: None,
            tls: false,
            skip_cert_verify: false,
        }),
        false,
        1,
    );
    let mut stream = outbound.connect(&destination, 1000).await.unwrap();
    stream.write_all(b"ping").await.unwrap();
    stream.flush().await.unwrap();
    let mut response = [0u8; 4];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"pong");
    server.await.unwrap();
}

#[tokio::test]
async fn shadowsocks_v2ray_plugin_websocket_real_dial() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen_addr = listener.local_addr().unwrap();
    let password = "secret".to_string();
    let server_password = password.clone();
    let destination = Destination::new("target.example", 443);
    let mut expected_destination = Vec::new();
    encode_socks5_destination(&destination, &mut expected_destination).unwrap();

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut buffer = [0u8; 512];
        let header_end = loop {
            let count = stream.read(&mut buffer).await.unwrap();
            assert!(count > 0);
            request.extend_from_slice(&buffer[..count]);
            if let Some(index) = find_header_end(&request) {
                break index;
            }
        };
        let header = String::from_utf8(request[..header_end].to_vec()).unwrap();
        assert!(header.starts_with("GET /ss HTTP/1.1"));
        assert!(header.contains("Host: cdn.example.com"));
        let key = header
            .lines()
            .find_map(|line| {
                line.split_once(':').and_then(|(name, value)| {
                    name.eq_ignore_ascii_case("sec-websocket-key")
                        .then(|| value.trim().to_string())
                })
            })
            .unwrap();
        let response = format!(
            "HTTP/1.1 101 Switching Protocols\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Accept: {}\r\n\
             \r\n",
            websocket_accept_key(&key)
        );
        stream.write_all(response.as_bytes()).await.unwrap();

        let request = read_websocket_frame(&mut stream).await.unwrap().unwrap();
        let cipher = SsCipher::Aes128Gcm;
        let master_key = cipher.master_key(server_password.as_bytes()).unwrap();
        let request_salt = &request[..cipher.salt_len()];
        let request_key = cipher.derive_subkey(&master_key, request_salt).unwrap();
        let mut request_nonce = vec![0u8; cipher.nonce_len()];
        let mut request_reader = Cursor::new(&request[cipher.salt_len()..]);
        let target = read_ss_chunk(
            cipher,
            &request_key,
            &mut request_nonce,
            &mut request_reader,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(target, expected_destination);

        let payload = read_websocket_frame(&mut stream).await.unwrap().unwrap();
        let mut payload_reader = Cursor::new(payload);
        let payload = read_ss_chunk(
            cipher,
            &request_key,
            &mut request_nonce,
            &mut payload_reader,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(payload, b"ping");

        let response_salt = vec![0x42; cipher.salt_len()];
        let response_key = cipher.derive_subkey(&master_key, &response_salt).unwrap();
        let mut response_nonce = vec![0u8; cipher.nonce_len()];
        let response_chunk =
            encode_ss_chunk(cipher, &response_key, &mut response_nonce, b"pong").unwrap();
        let mut response = response_salt;
        response.extend_from_slice(&response_chunk);
        write_websocket_frame(&mut stream, 0x2, &response)
            .await
            .unwrap();
    });

    let outbound = ShadowsocksOutbound::new(
        "ss-v2ray-plugin-test".to_string(),
        "127.0.0.1".to_string(),
        listen_addr.port(),
        "aes-128-gcm".to_string(),
        password,
        Some(ShadowsocksPluginConfig {
            mode: "v2ray-plugin".to_string(),
            host: Some("cdn.example.com".to_string()),
            path: Some("/ss".to_string()),
            tls: false,
            skip_cert_verify: false,
        }),
        false,
        1,
    );
    let mut stream = outbound.connect(&destination, 1000).await.unwrap();
    stream.write_all(b"ping").await.unwrap();
    stream.flush().await.unwrap();
    let mut response = [0u8; 4];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"pong");
    server.await.unwrap();
}

#[test]
fn custom_shadowsocks_codec_rejects_managed_method() {
    let error = SsCipher::from_method("rc4-md5").unwrap_err();
    assert!(error.to_string().contains("unsupported shadowsocks method"));
}

#[test]
fn rabbit128_poly1305_matches_independent_reference_vector() {
    let key = [0xff; 16];
    let nonce = [0xfa; 8];
    let plaintext = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10,
    ];
    let expected = [
        0x83, 0x5b, 0x45, 0x81, 0x2f, 0x48, 0xd7, 0xc0, 0xc3, 0x9f, 0x72, 0x53, 0x9c, 0xfb, 0xde,
        0x6f, 0xad, 0x22, 0x9a, 0x1a, 0x03, 0x6b, 0xe5, 0xe3, 0x98, 0x41, 0x92, 0xcf, 0x11, 0x80,
        0xaa, 0x6b,
    ];
    let actual =
        super::shadowsocks::encrypt_rabbit_poly1305_with_aad(&key, &nonce, &plaintext, &[0x01; 4])
            .unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn shadowsocks_aead_rejects_wrong_password_key() {
    let cipher = SsCipher::Aes128Gcm;
    let salt = [0x44; 16];
    let nonce = [0u8; SS_NONCE_LEN];
    let correct_master = evp_bytes_to_key(b"correct-password", cipher.key_len());
    let wrong_master = evp_bytes_to_key(b"wrong-password", cipher.key_len());
    let correct_key = cipher.derive_subkey(&correct_master, &salt).unwrap();
    let wrong_key = cipher.derive_subkey(&wrong_master, &salt).unwrap();
    let ciphertext = cipher
        .encrypt(&correct_key, &nonce, b"authenticated")
        .unwrap();
    let error = cipher.decrypt(&wrong_key, &nonce, &ciphertext).unwrap_err();
    assert!(error.to_string().contains("decrypt failed"));
}

#[tokio::test]
async fn trojan_outbound_sends_valid_connect_request_over_tls() {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()));
    let provider = aws_lc_rs::default_provider();
    let server_config = ServerConfig::builder_with_provider(provider.into())
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen_addr = listener.local_addr().unwrap();
    let destination = Destination::new("target.example", 443);
    let mut expected_destination = Vec::new();
    encode_socks5_destination(&destination, &mut expected_destination).unwrap();

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut stream = acceptor.accept(stream).await.unwrap();
        let mut request = Vec::new();
        let mut buf = [0u8; 512];
        loop {
            let n = stream.read(&mut buf).await.unwrap();
            assert!(n > 0);
            request.extend_from_slice(&buf[..n]);
            if request.ends_with(b"\r\n")
                && request.len() >= 56 + 2 + 1 + expected_destination.len() + 2
            {
                break;
            }
        }

        let expected_hash = hex_lower(&Sha224::digest(b"secret"));
        assert_eq!(&request[..56], expected_hash.as_bytes());
        assert_eq!(&request[56..58], b"\r\n");
        assert_eq!(request[58], 0x01);
        assert_eq!(
            &request[59..59 + expected_destination.len()],
            expected_destination.as_slice()
        );
        assert_eq!(
            &request[59 + expected_destination.len()..61 + expected_destination.len()],
            b"\r\n"
        );
        stream.write_all(b"pong").await.unwrap();
    });

    let outbound = TrojanOutbound::new(
        "trojan-test".to_string(),
        "127.0.0.1".to_string(),
        listen_addr.port(),
        "secret".to_string(),
        Some("localhost".to_string()),
        true,
        None,
        None,
        None,
        None,
        BTreeMap::new(),
        Vec::new(),
    );
    let mut stream = outbound.connect(&destination, 1000).await.unwrap();
    let mut response = [0u8; 4];
    stream.read_exact(&mut response).await.unwrap();

    assert_eq!(&response, b"pong");
    server.await.unwrap();
}

#[test]
fn trojan_request_uses_sha224_password_hash() {
    let request = build_trojan_request("secret", &Destination::new("example.com", 443)).unwrap();

    assert_eq!(
        &request[..56],
        hex_lower(&Sha224::digest(b"secret")).as_bytes()
    );
    assert_eq!(&request[56..58], b"\r\n");
    assert_eq!(request[58], 0x01);
}

#[test]
fn trojan_transport_alpn_rejects_incompatible_protocols() {
    let grpc_error = trojan_alpn_protocols("grpc", &["http/1.1".to_string()])
        .expect_err("gRPC without h2 must fail");
    assert!(grpc_error.to_string().contains("requires h2"));

    let ws_error = trojan_alpn_protocols("ws", &["h2".to_string()])
        .expect_err("WebSocket without http/1.1 must fail");
    assert!(ws_error.to_string().contains("requires http/1.1"));
}

#[test]
fn transport_headers_reject_line_injection() {
    let headers = BTreeMap::from([("X-Test".to_string(), "safe\r\nInjected: true".to_string())]);
    let error = render_transport_headers(&headers, &[])
        .expect_err("header line injection must be rejected");
    assert!(error.to_string().contains("invalid transport header value"));
}

#[test]
fn shadowsocks_2022_udp_replay_window_rejects_duplicates_and_old_packets() {
    let mut window = Ss2022ReplayWindow::default();
    assert!(window.accept(100));
    assert!(!window.accept(100));
    assert!(window.accept(99));
    assert!(window.accept(164));
    assert!(!window.accept(99));
    assert!(!window.accept(90));
}

#[tokio::test]
async fn vless_outbound_sends_valid_tcp_request_over_tls_and_strips_response_header() {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()));
    let provider = aws_lc_rs::default_provider();
    let server_config = ServerConfig::builder_with_provider(provider.into())
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen_addr = listener.local_addr().unwrap();
    let destination = Destination::new("target.example", 443);
    let user_id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut stream = acceptor.accept(stream).await.unwrap();
        let mut fixed = [0u8; 1 + 16 + 1 + 1 + 2 + 1];
        stream.read_exact(&mut fixed).await.unwrap();
        assert_eq!(fixed[0], 0x00);
        assert_eq!(&fixed[1..17], user_id.as_bytes());
        assert_eq!(fixed[17], 0x00);
        assert_eq!(fixed[18], 0x01);
        assert_eq!(u16::from_be_bytes([fixed[19], fixed[20]]), 443);
        assert_eq!(fixed[21], 0x02);

        let mut domain_len = [0u8; 1];
        stream.read_exact(&mut domain_len).await.unwrap();
        let mut domain = vec![0u8; domain_len[0] as usize];
        stream.read_exact(&mut domain).await.unwrap();
        assert_eq!(domain, b"target.example");

        stream.write_all(&[0x00, 0x00]).await.unwrap();
        let mut payload = [0u8; 4];
        stream.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"ping");
        stream.write_all(b"pong").await.unwrap();
    });

    let outbound = VlessOutbound::new(
        "vless-test".to_string(),
        "127.0.0.1".to_string(),
        listen_addr.port(),
        "11111111-1111-1111-1111-111111111111".to_string(),
        None,
        None,
        true,
        Some("localhost".to_string()),
        true,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    );
    let mut stream = outbound.connect(&destination, 1000).await.unwrap();
    stream.write_all(b"ping").await.unwrap();
    let mut response = [0u8; 4];
    stream.read_exact(&mut response).await.unwrap();

    assert_eq!(&response, b"pong");
    server.await.unwrap();
}

#[test]
fn websocket_accept_key_matches_rfc_example() {
    assert_eq!(
        websocket_accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
        "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
    );
}

#[tokio::test]
async fn websocket_client_frames_are_masked_and_decodable() {
    let (mut client, mut server) = tokio::io::duplex(1024);
    let writer = tokio::spawn(async move {
        write_websocket_binary_frame(&mut client, b"hello")
            .await
            .unwrap();
    });

    let mut header = [0u8; 2];
    server.read_exact(&mut header).await.unwrap();
    assert_eq!(header[0], 0x82);
    assert_eq!(header[1] & 0x80, 0x80);
    assert_eq!(header[1] & 0x7f, 5);
    let mut mask = [0u8; 4];
    server.read_exact(&mut mask).await.unwrap();
    let mut payload = [0u8; 5];
    server.read_exact(&mut payload).await.unwrap();
    for (index, byte) in payload.iter_mut().enumerate() {
        *byte ^= mask[index % 4];
    }
    assert_eq!(&payload, b"hello");
    writer.await.unwrap();
}

#[tokio::test]
async fn vless_outbound_supports_websocket_transport() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen_addr = listener.local_addr().unwrap();
    let destination = Destination::new("target.example", 443);
    let user_id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut buf = [0u8; 512];
        let header_end = loop {
            let n = stream.read(&mut buf).await.unwrap();
            assert!(n > 0);
            request.extend_from_slice(&buf[..n]);
            if let Some(index) = find_header_end(&request) {
                break index;
            }
        };
        let header = String::from_utf8(request[..header_end].to_vec()).unwrap();
        assert!(header.starts_with("GET /ray HTTP/1.1"));
        assert!(header.contains("Host: cdn.example.com"));
        let key = header
            .lines()
            .find_map(|line| {
                line.split_once(':').and_then(|(name, value)| {
                    name.eq_ignore_ascii_case("sec-websocket-key")
                        .then(|| value.trim().to_string())
                })
            })
            .unwrap();
        let response = format!(
            "HTTP/1.1 101 Switching Protocols\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Accept: {}\r\n\
             \r\n",
            websocket_accept_key(&key)
        );
        stream.write_all(response.as_bytes()).await.unwrap();

        let request_payload = read_websocket_frame(&mut stream).await.unwrap().unwrap();
        assert_eq!(request_payload[0], 0x00);
        assert_eq!(&request_payload[1..17], user_id.as_bytes());
        assert_eq!(request_payload[17], 0x00);
        assert_eq!(request_payload[18], 0x01);
        assert_eq!(
            u16::from_be_bytes([request_payload[19], request_payload[20]]),
            443
        );
        assert_eq!(request_payload[21], 0x02);
        assert_eq!(request_payload[22], "target.example".len() as u8);
        assert_eq!(&request_payload[23..], b"target.example");

        write_websocket_frame(&mut stream, 0x2, &[0x00, 0x00])
            .await
            .unwrap();
        let payload = read_websocket_frame(&mut stream).await.unwrap().unwrap();
        assert_eq!(payload, b"ping");
        write_websocket_frame(&mut stream, 0x2, b"pong")
            .await
            .unwrap();
    });

    let outbound = VlessOutbound::new(
        "vless-ws-test".to_string(),
        "127.0.0.1".to_string(),
        listen_addr.port(),
        "11111111-1111-1111-1111-111111111111".to_string(),
        None,
        None,
        false,
        None,
        false,
        Some("ws".to_string()),
        Some("/ray".to_string()),
        Some("cdn.example.com".to_string()),
        None,
        None,
        None,
        None,
        None,
    );
    let mut stream = outbound.connect(&destination, 1000).await.unwrap();
    stream.write_all(b"ping").await.unwrap();
    let mut response = [0u8; 4];
    stream.read_exact(&mut response).await.unwrap();

    assert_eq!(&response, b"pong");
    server.await.unwrap();
}

#[tokio::test]
async fn vless_outbound_supports_grpc_transport() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen_addr = listener.local_addr().unwrap();
    let destination = Destination::new("target.example", 443);
    let user_id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut h2 = h2::server::handshake(stream).await.unwrap();
        let (request, mut respond) = h2.accept().await.unwrap().unwrap();
        let handler = tokio::spawn(async move {
            assert_eq!(request.uri().path(), "/ray/Tun");
            assert_eq!(
                request
                    .headers()
                    .get(http::header::CONTENT_TYPE)
                    .and_then(|value| value.to_str().ok()),
                Some("application/grpc")
            );
            let mut body = request.into_body();
            let request_payload = read_grpc_message_for_test(&mut body).await;
            assert_eq!(request_payload[0], 0x00);
            assert_eq!(&request_payload[1..17], user_id.as_bytes());
            assert_eq!(request_payload[17], 0x00);
            assert_eq!(request_payload[18], 0x01);
            assert_eq!(
                u16::from_be_bytes([request_payload[19], request_payload[20]]),
                443
            );
            assert_eq!(request_payload[21], 0x02);
            assert_eq!(request_payload[22], "target.example".len() as u8);
            assert_eq!(&request_payload[23..], b"target.example");

            let response = http::Response::builder()
                .status(200)
                .header(http::header::CONTENT_TYPE, "application/grpc")
                .body(())
                .unwrap();
            let mut send = respond.send_response(response, false).unwrap();
            send.send_data(grpc_frame_for_test(&[0x00, 0x00]), false)
                .unwrap();

            let payload = read_grpc_message_for_test(&mut body).await;
            assert_eq!(payload, b"ping");
            send.send_data(grpc_frame_for_test(b"pong"), false).unwrap();
        });
        let driver = tokio::spawn(async move { while h2.accept().await.is_some() {} });
        handler.await.unwrap();
        driver.abort();
    });

    let outbound = VlessOutbound::new(
        "vless-grpc-test".to_string(),
        "127.0.0.1".to_string(),
        listen_addr.port(),
        "11111111-1111-1111-1111-111111111111".to_string(),
        None,
        None,
        false,
        None,
        false,
        Some("grpc".to_string()),
        None,
        Some("cdn.example.com".to_string()),
        Some("ray".to_string()),
        None,
        None,
        None,
        None,
    );
    let mut stream =
        tokio::time::timeout(Duration::from_secs(2), outbound.connect(&destination, 1000))
            .await
            .expect("vless grpc connect timed out")
            .unwrap();
    stream.write_all(b"ping").await.unwrap();
    let mut response = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut response))
        .await
        .expect("vless grpc read timed out")
        .unwrap();

    assert_eq!(&response, b"pong");
    tokio::time::timeout(Duration::from_secs(2), server)
        .await
        .expect("vless grpc server timed out")
        .unwrap();
}

#[tokio::test]
async fn vless_outbound_supports_h2_transport() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen_addr = listener.local_addr().unwrap();
    let destination = Destination::new("target.example", 443);
    let user_id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut h2 = h2::server::handshake(stream).await.unwrap();
        let (request, mut respond) = h2.accept().await.unwrap().unwrap();
        let handler = tokio::spawn(async move {
            assert_eq!(request.method(), http::Method::PUT);
            assert_eq!(request.uri().path(), "/h2");
            let mut body = H2BodyReaderForTest::new(request.into_body());
            let mut fixed = [0u8; 23];
            body.read_exact(&mut fixed).await.unwrap();
            assert_eq!(fixed[0], 0x00);
            assert_eq!(&fixed[1..17], user_id.as_bytes());
            assert_eq!(fixed[17], 0x00);
            assert_eq!(fixed[18], 0x01);
            assert_eq!(u16::from_be_bytes([fixed[19], fixed[20]]), 443);
            assert_eq!(fixed[21], 0x02);
            assert_eq!(fixed[22], "target.example".len() as u8);
            let mut domain = vec![0u8; "target.example".len()];
            body.read_exact(&mut domain).await.unwrap();
            assert_eq!(domain, b"target.example");

            let response = http::Response::builder().status(200).body(()).unwrap();
            let mut send = respond.send_response(response, false).unwrap();
            send.send_data(Bytes::from_static(&[0x00, 0x00]), false)
                .unwrap();

            let mut payload = [0u8; 4];
            body.read_exact(&mut payload).await.unwrap();
            assert_eq!(&payload, b"ping");
            send.send_data(Bytes::from_static(b"pong"), false).unwrap();
        });
        let driver = tokio::spawn(async move { while h2.accept().await.is_some() {} });
        handler.await.unwrap();
        driver.abort();
    });

    let outbound = VlessOutbound::new(
        "vless-h2-test".to_string(),
        "127.0.0.1".to_string(),
        listen_addr.port(),
        "11111111-1111-1111-1111-111111111111".to_string(),
        None,
        None,
        false,
        None,
        false,
        Some("h2".to_string()),
        Some("/h2".to_string()),
        Some("cdn.example.com".to_string()),
        None,
        None,
        None,
        None,
        None,
    );
    let mut stream =
        tokio::time::timeout(Duration::from_secs(2), outbound.connect(&destination, 1000))
            .await
            .expect("vless h2 connect timed out")
            .unwrap();
    stream.write_all(b"ping").await.unwrap();
    let mut response = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut response))
        .await
        .expect("vless h2 read timed out")
        .unwrap();

    assert_eq!(&response, b"pong");
    tokio::time::timeout(Duration::from_secs(2), server)
        .await
        .expect("vless h2 server timed out")
        .unwrap();
}

#[tokio::test]
async fn vmess_outbound_supports_tcp_aead_stream() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen_addr = listener.local_addr().unwrap();
    let destination = Destination::new("target.example", 443);
    let expected_destination = destination.clone();
    let user_id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let setup = read_vmess_client_setup_for_test(&mut stream, &user_id).await;
        assert_eq!(setup.destination, expected_destination);
        assert_eq!(setup.cipher, VmessCipher::Chacha20Poly1305);

        let mut client_reader = VmessDownloadState {
            response_header_key: [0u8; 16],
            response_header_iv: [0u8; 16],
            response_authentication: setup.response_authentication,
            cipher: VmessAeadState::new(setup.cipher, &setup.data_key, &setup.data_iv).unwrap(),
            length_mask: VmessLengthMask::new(&setup.data_iv),
        };
        let payload = read_vmess_chunk(&mut stream, &mut client_reader)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(payload, b"ping");

        write_vmess_response_header_for_test(
            &mut stream,
            &setup.response_header_key,
            &setup.response_header_iv,
            setup.response_authentication,
        )
        .await;
        let mut server_writer = VmessUploadState {
            cipher: VmessAeadState::new(
                setup.cipher,
                &setup.response_header_key,
                &setup.response_header_iv,
            )
            .unwrap(),
            length_mask: VmessLengthMask::new(&setup.response_header_iv),
        };
        write_vmess_chunk(&mut stream, &mut server_writer, b"pong")
            .await
            .unwrap();
    });

    let outbound = VmessOutbound::new(
        "vmess-test".to_string(),
        "127.0.0.1".to_string(),
        listen_addr.port(),
        "11111111-1111-1111-1111-111111111111".to_string(),
        "auto".to_string(),
        false,
        None,
        false,
        None,
        None,
        None,
        None,
    );
    let mut stream = outbound.connect(&destination, 1000).await.unwrap();
    stream.write_all(b"ping").await.unwrap();
    stream.flush().await.unwrap();
    let mut response = [0u8; 4];
    stream.read_exact(&mut response).await.unwrap();

    assert_eq!(&response, b"pong");
    server.await.unwrap();
}

#[tokio::test]
async fn vmess_outbound_supports_grpc_transport() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen_addr = listener.local_addr().unwrap();
    let destination = Destination::new("target.example", 443);
    let expected_destination = destination.clone();
    let user_id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut h2 = h2::server::handshake(stream).await.unwrap();
        let (request, mut respond) = h2.accept().await.unwrap().unwrap();
        let handler = tokio::spawn(async move {
            assert_eq!(request.uri().path(), "/vmess/Tun");
            let mut body = GrpcBodyReaderForTest::new(request.into_body());
            let setup = read_vmess_client_setup_for_test(&mut body, &user_id).await;
            assert_eq!(setup.destination, expected_destination);
            assert_eq!(setup.cipher, VmessCipher::Chacha20Poly1305);

            let response = http::Response::builder()
                .status(200)
                .header(http::header::CONTENT_TYPE, "application/grpc")
                .body(())
                .unwrap();
            let mut send = respond.send_response(response, false).unwrap();
            let mut response_header = Vec::new();
            write_vmess_response_header_for_test(
                &mut response_header,
                &setup.response_header_key,
                &setup.response_header_iv,
                setup.response_authentication,
            )
            .await;
            send.send_data(grpc_frame_for_test(&response_header), false)
                .unwrap();

            let mut client_reader = VmessDownloadState {
                response_header_key: [0u8; 16],
                response_header_iv: [0u8; 16],
                response_authentication: setup.response_authentication,
                cipher: VmessAeadState::new(setup.cipher, &setup.data_key, &setup.data_iv).unwrap(),
                length_mask: VmessLengthMask::new(&setup.data_iv),
            };
            let payload = read_vmess_chunk(&mut body, &mut client_reader)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(payload, b"ping");

            let mut server_writer = VmessUploadState {
                cipher: VmessAeadState::new(
                    setup.cipher,
                    &setup.response_header_key,
                    &setup.response_header_iv,
                )
                .unwrap(),
                length_mask: VmessLengthMask::new(&setup.response_header_iv),
            };
            let mut response_payload = Vec::new();
            write_vmess_chunk(&mut response_payload, &mut server_writer, b"pong")
                .await
                .unwrap();
            send.send_data(grpc_frame_for_test(&response_payload), false)
                .unwrap();
        });
        let driver = tokio::spawn(async move { while h2.accept().await.is_some() {} });
        handler.await.unwrap();
        driver.abort();
    });

    let outbound = VmessOutbound::new(
        "vmess-grpc-test".to_string(),
        "127.0.0.1".to_string(),
        listen_addr.port(),
        "11111111-1111-1111-1111-111111111111".to_string(),
        "auto".to_string(),
        false,
        None,
        false,
        Some("grpc".to_string()),
        None,
        Some("cdn.example.com".to_string()),
        Some("vmess".to_string()),
    );
    let mut stream =
        tokio::time::timeout(Duration::from_secs(2), outbound.connect(&destination, 1000))
            .await
            .expect("vmess grpc connect timed out")
            .unwrap();
    stream.write_all(b"ping").await.unwrap();
    stream.flush().await.unwrap();
    let mut response = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut response))
        .await
        .expect("vmess grpc read timed out")
        .unwrap();

    assert_eq!(&response, b"pong");
    tokio::time::timeout(Duration::from_secs(2), server)
        .await
        .expect("vmess grpc server timed out")
        .unwrap();
}

#[tokio::test]
async fn vmess_outbound_supports_h2_transport() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen_addr = listener.local_addr().unwrap();
    let destination = Destination::new("target.example", 443);
    let expected_destination = destination.clone();
    let user_id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut h2 = h2::server::handshake(stream).await.unwrap();
        let (request, mut respond) = h2.accept().await.unwrap().unwrap();
        let handler = tokio::spawn(async move {
            assert_eq!(request.method(), http::Method::PUT);
            assert_eq!(request.uri().path(), "/vmess-h2");
            let mut body = H2BodyReaderForTest::new(request.into_body());
            let setup = read_vmess_client_setup_for_test(&mut body, &user_id).await;
            assert_eq!(setup.destination, expected_destination);
            assert_eq!(setup.cipher, VmessCipher::Chacha20Poly1305);

            let response = http::Response::builder().status(200).body(()).unwrap();
            let mut send = respond.send_response(response, false).unwrap();
            let mut response_header = Vec::new();
            write_vmess_response_header_for_test(
                &mut response_header,
                &setup.response_header_key,
                &setup.response_header_iv,
                setup.response_authentication,
            )
            .await;
            send.send_data(Bytes::from(response_header), false).unwrap();

            let mut client_reader = VmessDownloadState {
                response_header_key: [0u8; 16],
                response_header_iv: [0u8; 16],
                response_authentication: setup.response_authentication,
                cipher: VmessAeadState::new(setup.cipher, &setup.data_key, &setup.data_iv).unwrap(),
                length_mask: VmessLengthMask::new(&setup.data_iv),
            };
            let payload = read_vmess_chunk(&mut body, &mut client_reader)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(payload, b"ping");

            let mut server_writer = VmessUploadState {
                cipher: VmessAeadState::new(
                    setup.cipher,
                    &setup.response_header_key,
                    &setup.response_header_iv,
                )
                .unwrap(),
                length_mask: VmessLengthMask::new(&setup.response_header_iv),
            };
            let mut response_payload = Vec::new();
            write_vmess_chunk(&mut response_payload, &mut server_writer, b"pong")
                .await
                .unwrap();
            send.send_data(Bytes::from(response_payload), false)
                .unwrap();
        });
        let driver = tokio::spawn(async move { while h2.accept().await.is_some() {} });
        handler.await.unwrap();
        driver.abort();
    });

    let outbound = VmessOutbound::new(
        "vmess-h2-test".to_string(),
        "127.0.0.1".to_string(),
        listen_addr.port(),
        "11111111-1111-1111-1111-111111111111".to_string(),
        "auto".to_string(),
        false,
        None,
        false,
        Some("h2".to_string()),
        Some("/vmess-h2".to_string()),
        Some("cdn.example.com".to_string()),
        None,
    );
    let mut stream =
        tokio::time::timeout(Duration::from_secs(2), outbound.connect(&destination, 1000))
            .await
            .expect("vmess h2 connect timed out")
            .unwrap();
    stream.write_all(b"ping").await.unwrap();
    stream.flush().await.unwrap();
    let mut response = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut response))
        .await
        .expect("vmess h2 read timed out")
        .unwrap();

    assert_eq!(&response, b"pong");
    tokio::time::timeout(Duration::from_secs(2), server)
        .await
        .expect("vmess h2 server timed out")
        .unwrap();
}

async fn read_grpc_message_for_test(body: &mut h2::RecvStream) -> Vec<u8> {
    let mut data = BytesMut::new();
    loop {
        let chunk = body.data().await.unwrap().unwrap();
        let len = chunk.len();
        data.extend_from_slice(&chunk);
        body.flow_control().release_capacity(len).unwrap();
        if data.len() < 5 {
            continue;
        }
        let payload_len = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;
        if data.len() < 5 + payload_len {
            continue;
        }
        assert_eq!(data[0], 0);
        bytes::Buf::advance(&mut data, 5);
        return data.split_to(payload_len).to_vec();
    }
}

fn grpc_frame_for_test(payload: &[u8]) -> Bytes {
    let mut frame = Vec::with_capacity(5 + payload.len());
    frame.push(0);
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    Bytes::from(frame)
}

struct H2BodyReaderForTest {
    body: h2::RecvStream,
    read_buffer: BytesMut,
}

impl H2BodyReaderForTest {
    fn new(body: h2::RecvStream) -> Self {
        Self {
            body,
            read_buffer: BytesMut::new(),
        }
    }
}

impl AsyncRead for H2BodyReaderForTest {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), Error>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if !self.read_buffer.is_empty() {
                let len = self.read_buffer.len().min(buf.remaining());
                let chunk = self.read_buffer.split_to(len);
                buf.put_slice(&chunk);
                return Poll::Ready(Ok(()));
            }
            match self.body.poll_data(cx) {
                Poll::Ready(Some(Ok(chunk))) => {
                    let len = chunk.len();
                    self.read_buffer.extend_from_slice(&chunk);
                    let _ = self.body.flow_control().release_capacity(len);
                }
                Poll::Ready(Some(Err(error))) => {
                    return Poll::Ready(Err(Error::new(
                        ErrorKind::ConnectionAborted,
                        format!("h2 body failed: {error}"),
                    )));
                }
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

struct GrpcBodyReaderForTest {
    body: h2::RecvStream,
    incoming: BytesMut,
    read_buffer: BytesMut,
}

impl GrpcBodyReaderForTest {
    fn new(body: h2::RecvStream) -> Self {
        Self {
            body,
            incoming: BytesMut::new(),
            read_buffer: BytesMut::new(),
        }
    }

    fn decode_next_message(&mut self) -> bool {
        if self.incoming.len() < 5 {
            return false;
        }
        let payload_len = u32::from_be_bytes([
            self.incoming[1],
            self.incoming[2],
            self.incoming[3],
            self.incoming[4],
        ]) as usize;
        if self.incoming.len() < 5 + payload_len {
            return false;
        }
        assert_eq!(self.incoming[0], 0);
        bytes::Buf::advance(&mut self.incoming, 5);
        let payload = self.incoming.split_to(payload_len);
        self.read_buffer.extend_from_slice(&payload);
        true
    }
}

impl AsyncRead for GrpcBodyReaderForTest {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), Error>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if !self.read_buffer.is_empty() {
                let len = self.read_buffer.len().min(buf.remaining());
                let chunk = self.read_buffer.split_to(len);
                buf.put_slice(&chunk);
                return Poll::Ready(Ok(()));
            }
            if self.decode_next_message() {
                continue;
            }
            match self.body.poll_data(cx) {
                Poll::Ready(Some(Ok(chunk))) => {
                    let len = chunk.len();
                    self.incoming.extend_from_slice(&chunk);
                    let _ = self.body.flow_control().release_capacity(len);
                }
                Poll::Ready(Some(Err(error))) => {
                    return Poll::Ready(Err(Error::new(
                        ErrorKind::ConnectionAborted,
                        format!("grpc body failed: {error}"),
                    )));
                }
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

struct VmessClientSetupForTest {
    destination: Destination,
    cipher: VmessCipher,
    data_iv: [u8; 16],
    data_key: [u8; 16],
    response_header_iv: [u8; 16],
    response_header_key: [u8; 16],
    response_authentication: u8,
}

async fn read_vmess_client_setup_for_test<S>(
    stream: &mut S,
    user_id: &Uuid,
) -> VmessClientSetupForTest
where
    S: AsyncRead + Unpin,
{
    let instruction_key = vmess_instruction_key(user_id);
    let mut auth_id = [0u8; 16];
    stream.read_exact(&mut auth_id).await.unwrap();
    let mut encrypted_len = [0u8; 18];
    stream.read_exact(&mut encrypted_len).await.unwrap();
    let mut nonce = [0u8; 8];
    stream.read_exact(&mut nonce).await.unwrap();

    let len_key = vmess_kdf(
        &instruction_key,
        &[b"VMess Header AEAD Key_Length", &auth_id, &nonce],
    );
    let len_nonce = vmess_kdf(
        &instruction_key,
        &[b"VMess Header AEAD Nonce_Length", &auth_id, &nonce],
    );
    let len = vmess_aes128gcm_decrypt(&len_key[..16], &len_nonce[..12], &auth_id, &encrypted_len)
        .unwrap();
    let header_len = u16::from_be_bytes([len[0], len[1]]) as usize;
    let mut encrypted_header = vec![0u8; header_len + VMESS_TAG_LEN];
    stream.read_exact(&mut encrypted_header).await.unwrap();
    let header_key = vmess_kdf(
        &instruction_key,
        &[b"VMess Header AEAD Key", &auth_id, &nonce],
    );
    let header_nonce = vmess_kdf(
        &instruction_key,
        &[b"VMess Header AEAD Nonce", &auth_id, &nonce],
    );
    let header = vmess_aes128gcm_decrypt(
        &header_key[..16],
        &header_nonce[..12],
        &auth_id,
        &encrypted_header,
    )
    .unwrap();

    assert_eq!(header[0], 0x01);
    assert_eq!(header[34] & 0x01, 0x01);
    assert_eq!(header[34] & 0x04, 0x04);
    assert_eq!(header[37], 0x01);
    let mut data_iv = [0u8; 16];
    data_iv.copy_from_slice(&header[1..17]);
    let mut data_key = [0u8; 16];
    data_key.copy_from_slice(&header[17..33]);
    let response_authentication = header[33];
    let cipher = match header[35] & 0x0f {
        3 => VmessCipher::Aes128Gcm,
        4 => VmessCipher::Chacha20Poly1305,
        5 => VmessCipher::None,
        other => panic!("unexpected vmess cipher {other}"),
    };

    let mut cursor = 38;
    let port = u16::from_be_bytes([header[cursor], header[cursor + 1]]);
    cursor += 2;
    let host = match header[cursor] {
        0x01 => {
            cursor += 1;
            let host = std::net::Ipv4Addr::new(
                header[cursor],
                header[cursor + 1],
                header[cursor + 2],
                header[cursor + 3],
            )
            .to_string();
            cursor += 4;
            host
        }
        0x02 => {
            cursor += 1;
            let len = header[cursor] as usize;
            cursor += 1;
            let host = std::str::from_utf8(&header[cursor..cursor + len])
                .unwrap()
                .to_string();
            cursor += len;
            host
        }
        0x03 => {
            cursor += 1;
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&header[cursor..cursor + 16]);
            cursor += 16;
            std::net::Ipv6Addr::from(octets).to_string()
        }
        other => panic!("unexpected vmess address type {other}"),
    };
    let margin_len = (header[35] >> 4) as usize;
    cursor += margin_len;
    let expected_checksum = u32::from_be_bytes([
        header[cursor],
        header[cursor + 1],
        header[cursor + 2],
        header[cursor + 3],
    ]);
    assert_eq!(expected_checksum, vmess_fnv1a(&header[..cursor]));

    VmessClientSetupForTest {
        destination: Destination::new(host, port),
        cipher,
        data_iv,
        data_key,
        response_header_iv: vmess_sha256_16(&data_iv),
        response_header_key: vmess_sha256_16(&data_key),
        response_authentication,
    }
}

async fn write_vmess_response_header_for_test<S>(
    stream: &mut S,
    response_header_key: &[u8; 16],
    response_header_iv: &[u8; 16],
    response_authentication: u8,
) where
    S: AsyncWrite + Unpin,
{
    let response_header = [response_authentication, 0x00, 0x00, 0x00];
    let len_key = vmess_kdf(response_header_key, &[b"AEAD Resp Header Len Key"]);
    let len_nonce = vmess_kdf(response_header_iv, &[b"AEAD Resp Header Len IV"]);
    let encrypted_len = vmess_aes128gcm_encrypt(
        &len_key[..16],
        &len_nonce[..12],
        &[],
        &(response_header.len() as u16).to_be_bytes(),
    )
    .unwrap();
    let header_key = vmess_kdf(response_header_key, &[b"AEAD Resp Header Key"]);
    let header_nonce = vmess_kdf(response_header_iv, &[b"AEAD Resp Header IV"]);
    let encrypted_header = vmess_aes128gcm_encrypt(
        &header_key[..16],
        &header_nonce[..12],
        &[],
        &response_header,
    )
    .unwrap();
    stream.write_all(&encrypted_len).await.unwrap();
    stream.write_all(&encrypted_header).await.unwrap();
    stream.flush().await.unwrap();
}

#[test]
fn vless_request_uses_port_then_vless_address_type() {
    let user_id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
    let request = build_vless_request(&user_id, &Destination::new("example.com", 8443)).unwrap();

    assert_eq!(request[0], 0x00);
    assert_eq!(&request[1..17], user_id.as_bytes());
    assert_eq!(request[17], 0x00);
    assert_eq!(request[18], 0x01);
    assert_eq!(u16::from_be_bytes([request[19], request[20]]), 8443);
    assert_eq!(request[21], 0x02);
    assert_eq!(request[22], "example.com".len() as u8);
}

#[test]
fn vless_request_encodes_vision_flow_addon() {
    let user_id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
    let request = build_vless_request_with_flow(
        &user_id,
        &Destination::new("example.com", 8443),
        Some("xtls-rprx-vision"),
    )
    .unwrap();

    assert_eq!(request[0], 0x00);
    assert_eq!(&request[1..17], user_id.as_bytes());
    assert_eq!(request[17], 18);
    assert_eq!(&request[18..36], b"\x0a\x10xtls-rprx-vision");
    assert_eq!(request[36], 0x01);
    assert_eq!(u16::from_be_bytes([request[37], request[38]]), 8443);
    assert_eq!(request[39], 0x02);
}

#[test]
fn hysteria2_tcp_request_encodes_command_address_and_padding() {
    let request = build_hysteria2_tcp_request(&Destination::new("example.com", 443)).unwrap();

    assert_eq!(&request[0..2], &[0x44, 0x01]);
    assert_eq!(request[2], b"example.com:443".len() as u8);
    assert_eq!(&request[3..18], b"example.com:443");
    assert_eq!(request[18], 0x00);
}

#[test]
fn hysteria2_udp_message_round_trips_payload() {
    let request = build_hysteria2_udp_messages(
        0x0102_0304,
        0x0506,
        &Destination::new("example.com", 53),
        b"dns",
        None,
    )
    .unwrap()
    .remove(0);

    assert_eq!(&request[0..4], &[1, 2, 3, 4]);
    assert_eq!(&request[4..8], &[5, 6, 0, 1]);
    assert_eq!(request[8], b"example.com:53".len() as u8);
    assert_eq!(&request[9..23], b"example.com:53");
    assert_eq!(&request[23..], b"dns");
    let mut reassembly = Hysteria2UdpReassembly::default();
    assert_eq!(
        parse_hysteria2_udp_message(&request, 0x0102_0304, &mut reassembly)
            .unwrap()
            .unwrap(),
        b"dns"
    );
    assert!(parse_hysteria2_udp_message(
        &request,
        0x9999_0000,
        &mut Hysteria2UdpReassembly::default()
    )
    .unwrap()
    .is_none());
}

#[test]
fn tuic_connect_request_encodes_domain_target() {
    let request = build_tuic_connect_request(&Destination::new("example.com", 443)).unwrap();

    assert_eq!(&request[0..3], &[0x05, 0x01, 0x00]);
    assert_eq!(request[3], b"example.com".len() as u8);
    assert_eq!(&request[4..15], b"example.com");
    assert_eq!(u16::from_be_bytes([request[15], request[16]]), 443);
}

#[test]
fn tuic_connect_request_encodes_ip_target() {
    let request = build_tuic_connect_request(&Destination::new("1.2.3.4", 53)).unwrap();

    assert_eq!(&request, &[0x05, 0x01, 0x01, 1, 2, 3, 4, 0, 53]);
}

#[test]
fn tuic_packet_request_round_trips_payload() {
    let request = build_tuic_packet_messages(
        0x0102,
        0x0304,
        &Destination::new("example.com", 53),
        b"dns",
        None,
    )
    .unwrap()
    .remove(0);

    assert_eq!(&request[0..10], &[0x05, 0x02, 1, 2, 3, 4, 1, 0, 0, 3]);
    assert_eq!(request[10], 0x00);
    assert_eq!(request[11], b"example.com".len() as u8);
    assert_eq!(&request[12..23], b"example.com");
    assert_eq!(u16::from_be_bytes([request[23], request[24]]), 53);
    assert_eq!(&request[25..], b"dns");
    let mut reassembly = TuicUdpReassembly::default();
    assert_eq!(
        parse_tuic_packet_message(&request, 0x0102, &mut reassembly)
            .unwrap()
            .unwrap(),
        b"dns"
    );
    assert!(
        parse_tuic_packet_message(&request, 0x9999, &mut TuicUdpReassembly::default())
            .unwrap()
            .is_none()
    );
}

#[test]
fn reality_decodes_public_key_and_short_id() {
    let server_secret = X25519StaticSecret::from([9u8; 32]);
    let server_public = X25519PublicKey::from(&server_secret).to_bytes();
    let encoded = base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        server_public,
    );

    assert_eq!(
        decode_reality_public_key(&encoded).unwrap().to_bytes(),
        server_public
    );
    assert_eq!(
        decode_reality_short_id(Some("01aB")).unwrap(),
        vec![0x01, 0xab]
    );
    assert!(decode_reality_short_id(Some("abc")).is_err());
    assert!(decode_reality_short_id(Some("001122334455667788")).is_err());
}

#[test]
fn reality_session_id_seals_version_time_and_short_id() {
    let server_secret = X25519StaticSecret::from([9u8; 32]);
    let server_public = X25519PublicKey::from(&server_secret);
    let client_secret = X25519StaticSecret::from([7u8; 32]);
    let shared_secret = client_secret.diffie_hellman(&server_public);
    let mut hello_random = [0u8; 32];
    hello_random
        .iter_mut()
        .enumerate()
        .for_each(|(index, byte)| *byte = index as u8);
    let hello_raw = b"synthetic client hello";
    let (session_id, auth_key) = seal_reality_session_id(
        shared_secret.as_bytes(),
        &[0x01, 0xab],
        &hello_random,
        hello_raw,
        0x0102_0304,
    )
    .unwrap();

    let cipher = Aes256Gcm::new_from_slice(&auth_key).unwrap();
    let plaintext = cipher
        .decrypt(
            aes_gcm::Nonce::from_slice(&hello_random[20..]),
            aes_gcm::aead::Payload {
                msg: &session_id,
                aad: hello_raw,
            },
        )
        .unwrap();
    assert_eq!(&plaintext[..3], &REALITY_CLIENT_VERSION);
    assert_eq!(plaintext[3], 0);
    assert_eq!(&plaintext[4..8], &[0x01, 0x02, 0x03, 0x04]);
    assert_eq!(&plaintext[8..10], &[0x01, 0xab]);
    assert_eq!(&plaintext[10..], &[0u8; 6]);
}
