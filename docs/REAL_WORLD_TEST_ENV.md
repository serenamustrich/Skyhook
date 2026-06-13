# Skyhook Real World Test Environment

Last updated: 2026-06-13

## Overview

This document describes the environment variables and setup needed for real-world protocol testing. Tests marked with `#[ignore]` require these environment variables to run.

## Environment Variables

### Hysteria v1

```bash
export SKYHOOK_HYSTERIA_V1_SERVER="your-server.com"
export SKYHOOK_HYSTERIA_V1_PORT="8443"
export SKYHOOK_HYSTERIA_V1_AUTH="your-password"
```

Run test:
```bash
cargo test --test protocol_integration hysteria_v1 -- --ignored --nocapture
```

### OpenVPN

```bash
export SKYHOOK_OPENVPN_PROFILE="/path/to/openvpn.ovpn"
# OR
export SKYHOOK_OPENVPN_SERVER="your-server.com"
export SKYHOOK_OPENVPN_PORT="1194"
export SKYHOOK_OPENVPN_CA="/path/to/ca.crt"
export SKYHOOK_OPENVPN_CERT="/path/to/client.crt"
export SKYHOOK_OPENVPN_KEY="/path/to/client.key"
```

Run test:
```bash
cargo test --test protocol_integration openvpn_connects_to_real_server -- --ignored --nocapture
```

### Snell

```bash
export SKYHOOK_SNELL_SERVER="your-server.com"
export SKYHOOK_SNELL_PORT="8388"
export SKYHOOK_SNELL_PSK="your-psk"
```

Run test:
```bash
# Not implemented yet.
# Add tests/snell_real_integration.rs before claiming real Snell verification.
```

### Shadowsocks

```bash
export SKYHOOK_SHADOWSOCKS_SERVER="your-server.com"
export SKYHOOK_SHADOWSOCKS_PORT="8388"
export SKYHOOK_SHADOWSOCKS_PASSWORD="your-password"
export SKYHOOK_SHADOWSOCKS_METHOD="aes-256-gcm"
```

Run test:
```bash
cargo test --test shadowsocks_real -- --ignored --nocapture
```

### Trojan

```bash
export SKYHOOK_TROJAN_SERVER="your-server.com"
export SKYHOOK_TROJAN_PORT="443"
export SKYHOOK_TROJAN_PASSWORD="your-password"
```

Run test:
```bash
cargo test --test trojan_real -- --ignored --nocapture
```

### VMess/VLESS

```bash
export SKYHOOK_VMESS_SERVER="your-server.com"
export SKYHOOK_VMESS_PORT="443"
export SKYHOOK_VMESS_UUID="your-uuid"
```

Run test:
```bash
cargo test --test vmess_real -- --ignored --nocapture
```

### Hysteria2

```bash
export SKYHOOK_HYSTERIA2_SERVER="your-server.com"
export SKYHOOK_HYSTERIA2_PORT="443"
export SKYHOOK_HYSTERIA2_PASSWORD="your-password"
```

Run test:
```bash
cargo test --test hysteria2_real -- --ignored --nocapture
```

### Subscription URLs

```bash
export SKYHOOK_TEST_SUBSCRIPTION_URLS='https://example.com/sub1,https://example.com/sub2'
```

Run test:
```bash
cargo test --test real_subscription_compat -- --ignored --nocapture
```

## Native TUN Real Tests

Native TUN tests require sudo privileges on macOS. Run:

```bash
sudo -E cargo test --test native_tun_privileged -- --ignored --nocapture
```

Or use the script:
```bash
sudo -E scripts/verify_native_tun_real.sh
```

## Test Reports

After running real tests, generate reports:

```bash
scripts/verify_real_protocols.sh > docs/REAL_WORLD_TEST_REPORT.md 2>&1
```

## Notes

- Never commit real server credentials to the repository
- Use environment variables for all sensitive test configuration
- Real server tests are excluded from CI by default (require `--ignored`)
- Mock server tests should cover all protocol variants
