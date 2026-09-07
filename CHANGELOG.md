# Changelog

## 0.1.0

First release.

- `auditchain`: append-only hash chain over an ordered list of typed fields, with optional HMAC keying under a keyring and a verifier that distinguishes an edited record, a gap, an unverifiable key and an unsigned tail.
- `auditchain/anchor`: Merkle trees over stretches of a chain, with Ed25519 signed checkpoints covering a sequence range, which is what closes tail truncation.
