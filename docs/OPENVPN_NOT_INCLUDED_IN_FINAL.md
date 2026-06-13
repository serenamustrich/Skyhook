# OpenVPN Not Included in Final Production

Last updated: 2026-06-13

## Summary

OpenVPN support is explicitly excluded from the Skyhook final production release.

## Reason

OpenVPN native L3 integration requires:
1. Full TLS over OpenVPN control packets implementation
2. Server option negotiation for common profiles
3. Data channel key derivation and encrypt/decrypt
4. TUN packet bridging to/from OpenVPN data packets
5. Real server integration testing

These components exist as primitives (parser, control channel, data channel) but are not fully integrated into a production-ready L3 tunnel engine.

## Current Status

- **Parser**: ✅ Complete - can parse .ovpn profiles
- **Control Channel**: ✅ Partial - basic handshake implemented
- **Data Channel**: ✅ Partial - AES-GCM/ChaCha20 encrypt/decrypt implemented
- **L3 Integration**: ❌ Not complete - exposed as parser/profile registration only
- **Real Server Test**: ❌ Not available

## Decision

OpenVPN remains `parser-only` for the final production claim. It is not part of the final production feature set.

## Future Work

To include OpenVPN in a future release:
1. Complete the L3 bridge integration
2. Add real OpenVPN server integration tests
3. Update documentation to reflect production status

## References

- `src/l3/openvpn/parser.rs` - Profile parser
- `src/l3/openvpn/control.rs` - Control channel
- `src/l3/openvpn/data_channel.rs` - Data channel
- `src/l3/mod.rs` - L3 manager and parser/profile registration boundary
