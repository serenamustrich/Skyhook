# Skyhook Security Policy

Last updated: 2026-06-13

## Overview

Skyhook is a Rust-native proxy core that prioritizes security and privacy. This document describes the security measures implemented in Skyhook and best practices for deployment.

## Security Features

### TLS Verification

- TLS verification is enabled by default for all TLS-based protocols.
- `skip_cert_verify` option is available but marked as insecure in capability metadata.
- Certificate pinning is supported for high-security deployments.

### Credential Protection

- Subscription URLs are never logged or exposed in API responses.
- Passwords and tokens are stored in memory only, never written to disk.
- Private keys are loaded from files and never copied to logs.
- Auth credentials are redacted in error messages.

### Network Security

- All proxy protocols use authenticated encryption where available.
- QUIC-based protocols (Hysteria2, TUIC) provide built-in encryption.
- Shadowsocks AEAD prevents replay attacks.
- VMess/VLESS use AES-GCM or ChaCha20-Poly1305.

### Memory Safety

- Written in Rust, preventing buffer overflows and use-after-free.
- No unsafe code in critical paths (TUN, TCP forwarding, UDP relay).
- Panic boundaries prevent cascading failures.

### Configuration Security

- YAML configuration files are validated before use.
- Invalid configurations are rejected with clear error messages.
- No arbitrary code execution from configuration.

## Security Recommendations

### Deployment

1. Run Skyhook with minimal privileges.
2. Use a dedicated user account for the proxy service.
3. Restrict access to the control API (bind to localhost only).
4. Use firewall rules to limit incoming connections.

### Configuration

1. Enable TLS verification for all proxy connections.
2. Use strong passwords and authentication methods.
3. Rotate subscription URLs periodically.
4. Monitor logs for suspicious activity.

### Network

1. Use encrypted DNS (DoH/DoT) to prevent DNS leaks.
2. Enable DNS hijack for TUN mode to prevent DNS leaks.
3. Use split tunneling judiciously.
4. Monitor traffic patterns for anomalies.

## Known Security Considerations

### TUN Mode

- Requires elevated privileges (sudo/admin).
- Can potentially route all system traffic.
- Ensure proper route configuration to prevent leaks.

### Subscription URLs

- May contain sensitive information (tokens, passwords).
- Transport security depends on the URL scheme (HTTPS recommended).
- Consider using local subscription files for sensitive deployments.

### API Access

- Control API provides full access to proxy configuration.
- Should be protected with authentication in production.
- Consider using a reverse proxy with TLS.

## Reporting Security Issues

If you discover a security vulnerability in Skyhook, please report it responsibly:

1. Do NOT create a public GitHub issue.
2. Email security concerns to the maintainers.
3. Provide detailed steps to reproduce the issue.
4. Allow reasonable time for a fix before public disclosure.

## Security Audit

- `cargo audit` is run regularly to check for known vulnerabilities.
- Dependencies are reviewed before updates.
- Critical paths are tested with fuzzing.

## Compliance

Skyhook implements the following security standards:

- TLS 1.2/1.3 for encrypted connections.
- AES-256-GCM for data encryption.
- ChaCha20-Poly1305 as an alternative cipher.
- SHA-256 for hashing.
- HKDF for key derivation.

## Contact

For security-related questions or concerns, please contact the project maintainers.
