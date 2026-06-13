# Skyhook Protocol Support Matrix

Last updated: 2026-06-13

| Protocol | Config Parse | Subscription Parse | TCP Runtime | UDP Runtime | Transports | Obfs | TLS/Security | Mock Server Test | Real Server Test | Default Probe | Limitations | Status |
|----------|:---:|:---:|:---:|:---:|---|---|---|:---:|:---:|:---:|---|---|
| Direct | ✅ | ✅ | ✅ | ✅ | - | - | - | ✅ | ✅ | ✅ | - | `production` |
| HTTP Proxy | ✅ | ✅ | ✅ | ❌ | TCP | - | - | ✅ | ❌ | ✅ | No UDP | `production` |
| SOCKS5 | ✅ | ✅ | ✅ | ✅ | TCP | - | - | ✅ | ❌ | ✅ | - | `production` |
| Shadowsocks AEAD | ✅ | ✅ | ✅ | ✅ | TCP | - | AEAD | ✅ | ❌ | ✅ | - | `production` |
| Shadowsocks simple-obfs | ✅ | ✅ | ✅ | ✅ | TCP | http/tls | AEAD | ✅ | ❌ | ✅ | - | `production` |
| SSR | ✅ | ✅ | ✅ | ❌ | TCP | plain/http/tls1.2_ticket_auth | - | ✅ | ❌ | ✅ | auth_sha1_v4/auth_aes128 supported | `partial` |
| Trojan | ✅ | ✅ | ✅ | ✅ | TCP | - | TLS 1.3 | ✅ | ❌ | ✅ | - | `production` |
| VMess AEAD | ✅ | ✅ | ✅ | ✅ | TCP/WS/gRPC/H2 | - | AEAD | ✅ | ❌ | ✅ | - | `production` |
| VLESS | ✅ | ✅ | ✅ | ✅ | TCP/WS/gRPC/H2 | - | TLS/XTLS | ✅ | ❌ | ✅ | - | `production` |
| Reality/Vision | ✅ | ✅ | ✅ | ✅ | TCP | - | Reality | ✅ | ❌ | ✅ | - | `production` |
| Hysteria2 | ✅ | ✅ | ✅ | ✅ | QUIC | - | QUIC/TLS | ✅ | ❌ | ✅ | - | `production` |
| Hysteria v1 | ✅ | ✅ | ⚠️ | ⚠️ | QUIC | xplus incomplete | QUIC/TLS | ❌ | ❌ | ✅ | Runtime path exists; obfs not applied; real-server proof missing | `partial` |
| TUIC | ✅ | ✅ | ✅ | ✅ | QUIC | - | QUIC/TLS | ❌ | ❌ | ✅ | Limited testing | `partial` |
| Naive | ✅ | ✅ | ✅ | ❌ | TCP | - | TLS | ❌ | ❌ | ✅ | HTTP CONNECT only; no UDP | `production` |
| SSH | ✅ | ✅ | ✅ | ❌ | TCP | - | SSH | ❌ | ❌ | ✅ | No UDP | `partial` |
| Snell | ✅ | ✅ | ✅ | ❌ | TCP | http/tls obfs | - | ❌ | ❌ | ✅ | No native UDP | `partial` |
| AnyTLS | ✅ | ✅ | ✅ | ❌ | TCP | - | TLS | ✅ | ❌ | ✅ | - | `production` |
| ShadowTLS | ✅ | ✅ | ✅ | ❌ | TCP | - | ShadowTLS v3 | ✅ | ❌ | ✅ | v3 only | `production` |
| WireGuard | ✅ | ✅ | ✅ | ✅ | L3 | - | Noise | ❌ | ❌ | ❌ | L3 only | `experimental` |
| OpenVPN | ✅ | ✅ | ❌ | ❌ | L3 | - | TLS | ❌ | ❌ | ❌ | Parser/profile registration only; no production TLS/control/data dialing | `parser-only` |
| Mieru | ✅ | ❌ | ❌ | ❌ | - | - | - | ❌ | ❌ | ❌ | Parse only | `parser-only` |
| Juicity | ✅ | ❌ | ❌ | ❌ | - | - | - | ❌ | ❌ | ❌ | Parse only | `parser-only` |
| MASQUE | ✅ | ❌ | ❌ | ❌ | - | - | - | ❌ | ❌ | ❌ | Parse only | `parser-only` |

## Status Definitions

- **`production`**: Real dialing capability with mock server tests. Can be advertised as supported.
- **`partial`**: Has real connection path but missing important features or real environment verification.
- **`experimental`**: Has connection path but needs significant work. Can be manually enabled but not advertised as stable.
- **`parser-only`**: Can parse from subscription/config but cannot establish real connections.
- **`planned`**: Not yet implemented.

## Notes

1. **Shadowsocks AEAD**: Supports aes-128-gcm, aes-256-gcm, chacha20-ietf-poly1305.
2. **SSR**: Supports basic methods (aes-128-cfb, aes-256-cfb, chacha20-ietf). Protocol variants (auth_sha1_v4, auth_aes128_md5) partially supported.
3. **VMess AEAD**: Full AEAD support with TCP/WS/gRPC/H2 transports.
4. **VLESS**: Supports Reality/Vision with XTLS.
5. **Hysteria2**: Full QUIC support with congestion control.
6. **Hysteria v1**: Runtime path exists but obfs is not applied and real-server tests remain env-gated.
7. **Snell**: TCP relay works. UDP relay not native (UDP over TCP tunnel only).
8. **OpenVPN**: Parser and profile registration only. Not production native dialing.
9. **WireGuard/OpenVPN**: L3 tunnel mode only, works with Native TUN.

## Test References

- Direct/HTTP/SOCKS5: `tests/protocol_mock_tests.rs`, `tests/config_and_runtime.rs`
- Shadowsocks: `tests/protocol_echo_tests.rs`, unit tests in `src/outbound/mod.rs`
- Trojan: unit tests in `src/outbound/mod.rs`
- VMess/VLESS: unit tests in `src/outbound/mod.rs`
- Hysteria2: unit tests in `src/outbound/mod.rs`
- TCP Forwarder: `tests/tcp_forwarder_e2e.rs`
- UDP Relay: `tests/native_l3_udp_tests.rs`
- Native TUN Dispatcher: `tests/native_l4_dispatcher_tests.rs`
