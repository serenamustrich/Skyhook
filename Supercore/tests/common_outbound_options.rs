use std::collections::BTreeMap;

use supercore::{
    config::{OutboundCommonConfig, OutboundConfig, SmuxConfig, SmuxProtocol},
    outbound::{build_outbounds_with_options, context::IpVersionStrategy},
    routing::Destination,
    subscription::parse_subscription,
};
#[cfg(target_os = "macos")]
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    time::{timeout, Duration},
};

#[test]
fn clash_common_outbound_options_are_preserved() {
    let document = parse_subscription(
        r#"
proxies:
  - name: rich-options
    type: http
    server: proxy.example
    port: 8080
    ip-version: prefer-ipv6
    interface-name: en7
    routing-mark: "0x2a"
    tfo: true
    mptcp: false
    udp: false
    certificate-fingerprint: "00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff"
    keepalive: 15
    quic-mtu: 1300
    quic-zero-rtt: true
    ws-opts:
      max-early-data: 2048
      early-data-header-name: Sec-WebSocket-Protocol
    smux:
      enabled: true
      protocol: h2mux
      max-connections: 3
      min-streams: 6
      max-streams: 0
      statistic: true
      padding: true
      only-tcp: false
  - name: mptcp-only
    type: http
    server: mptcp.example
    port: 8080
    mptcp: true
"#,
    )
    .expect("subscription should parse");

    let options = document.nodes[0]
        .common_options()
        .expect("common options should be valid")
        .expect("non-default options should be retained");
    assert_eq!(options.ip_version, IpVersionStrategy::PreferIpv6);
    assert_eq!(options.interface_name.as_deref(), Some("en7"));
    assert_eq!(options.routing_mark, Some(42));
    assert!(options.tfo);
    assert!(!options.mptcp);
    assert_eq!(options.dialer_proxy, None);
    assert!(!options.udp);
    assert_eq!(options.keepalive_secs, Some(15));
    assert_eq!(options.quic_mtu, Some(1300));
    assert!(options.quic_zero_rtt);
    assert_eq!(
        options.websocket_early_data_header.as_deref(),
        Some("Sec-WebSocket-Protocol")
    );
    assert_eq!(options.websocket_max_early_data, 2048);
    let smux = options.smux.expect("smux options");
    assert_eq!(smux.protocol, SmuxProtocol::H2Mux);
    assert_eq!(smux.max_connections, 3);
    assert_eq!(smux.min_streams, 6);
    assert_eq!(smux.max_streams, 0);
    assert!(smux.statistic);
    assert!(smux.padding);
    assert!(!smux.only_tcp);
    assert!(
        document.nodes[1]
            .common_options()
            .expect("MPTCP options")
            .expect("non-default MPTCP options")
            .mptcp
    );
}

#[test]
fn smux_defaults_use_h2mux_and_a_bounded_connection_pool() {
    let document = parse_subscription(
        r#"
proxies:
  - name: default-smux
    type: http
    server: proxy.example
    port: 8080
    smux:
      enabled: true
"#,
    )
    .unwrap();
    let smux = document.nodes[0]
        .common_options()
        .unwrap()
        .unwrap()
        .smux
        .unwrap();
    assert_eq!(smux.protocol, SmuxProtocol::H2Mux);
    assert_eq!(smux.max_connections, 4);
    assert_eq!(smux.min_streams, 4);
    assert_eq!(smux.max_streams, 0);
    assert!(!smux.only_tcp);
}

#[test]
fn smux_rejects_conflicting_connection_and_stream_limits() {
    let options = OutboundCommonConfig {
        smux: Some(SmuxConfig {
            enabled: true,
            max_connections: 2,
            min_streams: 2,
            max_streams: 8,
            ..SmuxConfig::default()
        }),
        ..OutboundCommonConfig::default()
    };
    let error = options.validate().unwrap_err();
    assert!(error.to_string().contains("max-streams conflicts"));
}

#[cfg(not(target_os = "linux"))]
#[test]
fn smux_reports_tcp_brutal_as_linux_only() {
    let options = OutboundCommonConfig {
        smux: Some(SmuxConfig {
            enabled: true,
            brutal: Some(supercore::config::SmuxBrutalConfig {
                enabled: true,
                up_mbps: 100,
                down_mbps: 100,
            }),
            ..SmuxConfig::default()
        }),
        ..OutboundCommonConfig::default()
    };
    let error = options.validate().unwrap_err();
    assert!(error.to_string().contains("only supported on Linux"));
}

#[test]
fn malformed_common_options_are_rejected_during_subscription_parse() {
    let document = parse_subscription(
        r#"
proxies:
  - name: bad-fingerprint
    type: http
    server: proxy.example
    port: 8080
    certificate-fingerprint: definitely-not-sha256
"#,
    )
    .expect("the document should report the bad node");

    assert!(document.nodes.is_empty());
    assert_eq!(document.unsupported.len(), 1);
    assert!(document.unsupported[0]
        .reason
        .contains("certificate fingerprint must be a 32-byte SHA-256"));
}

#[tokio::test]
async fn udp_disable_changes_capability_and_blocks_exchange() {
    let configs = vec![OutboundConfig::Direct {
        name: "direct".to_string(),
    }];
    let options = BTreeMap::from([(
        "direct".to_string(),
        OutboundCommonConfig {
            udp: false,
            ..OutboundCommonConfig::default()
        },
    )]);
    let outbounds = build_outbounds_with_options(&configs, &options, None).expect("outbounds");
    let direct = outbounds.get("direct").expect("direct outbound");

    assert!(!direct.capability().udp_supported);
    let error = direct
        .udp_exchange(&Destination::new("127.0.0.1", 9), b"probe", 100)
        .await
        .expect_err("UDP should be blocked before network I/O");
    assert!(error.to_string().contains("UDP is disabled"));
}

#[tokio::test]
async fn routing_mark_reports_the_macos_platform_limit() {
    let configs = vec![OutboundConfig::Direct {
        name: "direct".to_string(),
    }];
    let options = BTreeMap::from([(
        "direct".to_string(),
        OutboundCommonConfig {
            routing_mark: Some(42),
            ..OutboundCommonConfig::default()
        },
    )]);
    let outbounds = build_outbounds_with_options(&configs, &options, None).expect("outbounds");
    let error = match outbounds["direct"]
        .connect(&Destination::new("127.0.0.1", 9), 100)
        .await
    {
        Ok(_) => panic!("routing-mark must not be silently ignored"),
        Err(error) => error,
    };

    assert!(error.to_string().contains("not supported by the macOS"));
}

#[test]
fn unknown_outbound_option_target_is_rejected() {
    let configs = vec![OutboundConfig::Direct {
        name: "direct".to_string(),
    }];
    let options = BTreeMap::from([("missing".to_string(), OutboundCommonConfig::default())]);

    let error = build_outbounds_with_options(&configs, &options, None)
        .err()
        .expect("unknown target should fail configuration");
    assert!(error
        .to_string()
        .contains("outbound-options references unknown outbound missing"));
}

#[test]
fn invalid_common_option_values_fail_runtime_construction() {
    let configs = vec![OutboundConfig::Direct {
        name: "direct".to_string(),
    }];
    let options = BTreeMap::from([(
        "direct".to_string(),
        OutboundCommonConfig {
            keepalive_secs: Some(0),
            ..OutboundCommonConfig::default()
        },
    )]);

    let error = build_outbounds_with_options(&configs, &options, None)
        .err()
        .expect("invalid common options should fail configuration");
    assert!(error
        .to_string()
        .contains("keepalive must be greater than zero"));
}

#[test]
fn mptcp_rejects_options_that_defeat_multipath_selection() {
    let configs = vec![OutboundConfig::Direct {
        name: "direct".to_string(),
    }];
    for options in [
        OutboundCommonConfig {
            mptcp: true,
            interface_name: Some("en0".to_string()),
            ..OutboundCommonConfig::default()
        },
        OutboundCommonConfig {
            mptcp: true,
            dialer_proxy: Some("direct".to_string()),
            ..OutboundCommonConfig::default()
        },
        OutboundCommonConfig {
            mptcp: true,
            tfo: true,
            ..OutboundCommonConfig::default()
        },
    ] {
        let error = build_outbounds_with_options(
            &configs,
            &BTreeMap::from([("direct".to_string(), options)]),
            None,
        )
        .err()
        .expect("conflicting MPTCP options should fail configuration");
        assert!(error.to_string().contains("mptcp cannot be combined"));
    }
}

#[test]
fn missing_dialer_proxy_is_rejected_during_runtime_construction() {
    let configs = vec![OutboundConfig::Direct {
        name: "direct".to_string(),
    }];
    let options = BTreeMap::from([(
        "direct".to_string(),
        OutboundCommonConfig {
            dialer_proxy: Some("missing".to_string()),
            ..OutboundCommonConfig::default()
        },
    )]);

    let error = build_outbounds_with_options(&configs, &options, None)
        .err()
        .expect("missing dialer should fail configuration");
    assert!(error
        .to_string()
        .contains("dialer-proxy missing referenced by direct does not exist"));
}

#[tokio::test]
async fn dialer_proxy_takes_over_the_underlying_tcp_dial() {
    let configs = vec![
        OutboundConfig::Reject {
            name: "blocked-dialer".to_string(),
        },
        OutboundConfig::Http {
            name: "http-proxy".to_string(),
            server: "127.0.0.1".to_string(),
            port: 9,
            username: None,
            password: None,
            tls: false,
            sni: None,
            skip_cert_verify: false,
        },
    ];
    let options = BTreeMap::from([(
        "http-proxy".to_string(),
        OutboundCommonConfig {
            dialer_proxy: Some("blocked-dialer".to_string()),
            ..OutboundCommonConfig::default()
        },
    )]);
    let outbounds = build_outbounds_with_options(&configs, &options, None).expect("outbounds");
    let error = match outbounds["http-proxy"]
        .connect(&Destination::new("example.com", 443), 500)
        .await
    {
        Ok(_) => panic!("reject dialer should intercept the proxy server connection"),
        Err(error) => error,
    };

    assert!(error.to_string().contains("rejected by outbound rule"));
}

#[test]
fn dialer_proxy_cycles_are_detected_during_runtime_construction() {
    let configs = vec![
        OutboundConfig::Http {
            name: "proxy-a".to_string(),
            server: "127.0.0.1".to_string(),
            port: 9,
            username: None,
            password: None,
            tls: false,
            sni: None,
            skip_cert_verify: false,
        },
        OutboundConfig::Http {
            name: "proxy-b".to_string(),
            server: "127.0.0.1".to_string(),
            port: 9,
            username: None,
            password: None,
            tls: false,
            sni: None,
            skip_cert_verify: false,
        },
    ];
    let options = BTreeMap::from([
        (
            "proxy-a".to_string(),
            OutboundCommonConfig {
                dialer_proxy: Some("proxy-b".to_string()),
                ..OutboundCommonConfig::default()
            },
        ),
        (
            "proxy-b".to_string(),
            OutboundCommonConfig {
                dialer_proxy: Some("proxy-a".to_string()),
                ..OutboundCommonConfig::default()
            },
        ),
    ]);
    let error = build_outbounds_with_options(&configs, &options, None)
        .err()
        .expect("dialer cycle should fail configuration");

    assert!(error.to_string().contains("dialer-proxy cycle detected"));
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn unsigned_mptcp_runtime_reports_the_required_entitlement_immediately() {
    let configs = vec![OutboundConfig::Direct {
        name: "direct".to_string(),
    }];
    let options = BTreeMap::from([(
        "direct".to_string(),
        OutboundCommonConfig {
            mptcp: true,
            ..OutboundCommonConfig::default()
        },
    )]);
    let outbounds = build_outbounds_with_options(&configs, &options, None).expect("outbounds");
    let requires_entitlement = outbounds["direct"]
        .capability()
        .limitations
        .iter()
        .any(|limitation| limitation.contains("multipath entitlement"));
    if !requires_entitlement {
        return;
    }

    let started = std::time::Instant::now();
    let error = match outbounds["direct"]
        .connect(&Destination::new("127.0.0.1", 9), 1_000)
        .await
    {
        Ok(_) => panic!("unsigned MPTCP runtime must not dial without entitlement"),
        Err(error) => error,
    };
    assert!(started.elapsed() < Duration::from_millis(250));
    assert!(error
        .to_string()
        .contains("com.apple.developer.networking.multipath entitlement"));
}

#[cfg(target_os = "macos")]
#[tokio::test]
#[ignore = "requires a signed test executable with the macOS multipath entitlement"]
async fn mptcp_network_framework_stream_relays_bidirectional_data() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
    let address = listener.local_addr().expect("listener address");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let mut request = [0u8; 4];
        stream.read_exact(&mut request).await.expect("server read");
        assert_eq!(&request, b"ping");
        stream.write_all(b"pong").await.expect("server write");
        stream.shutdown().await.expect("server shutdown");
    });
    let configs = vec![OutboundConfig::Direct {
        name: "direct".to_string(),
    }];
    let options = BTreeMap::from([(
        "direct".to_string(),
        OutboundCommonConfig {
            mptcp: true,
            keepalive_secs: Some(5),
            ..OutboundCommonConfig::default()
        },
    )]);
    let outbounds = build_outbounds_with_options(&configs, &options, None).expect("outbounds");
    assert!(!outbounds["direct"]
        .capability()
        .limitations
        .iter()
        .any(|limitation| limitation.contains("native macOS dial backend")));

    let mut stream = match timeout(
        Duration::from_secs(5),
        outbounds["direct"].connect(
            &Destination::new(address.ip().to_string(), address.port()),
            4_000,
        ),
    )
    .await
    .expect("MPTCP connect deadline")
    {
        Ok(stream) => stream,
        Err(error) => panic!("MPTCP stream: {error:#}"),
    };
    stream.write_all(b"ping").await.expect("client write");
    let mut response = [0u8; 4];
    timeout(Duration::from_secs(2), stream.read_exact(&mut response))
        .await
        .expect("MPTCP read deadline")
        .expect("client read");
    assert_eq!(&response, b"pong");
    stream.shutdown().await.expect("client shutdown");
    server.await.expect("server task");
}
