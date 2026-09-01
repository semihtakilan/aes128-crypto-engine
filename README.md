# AES-128 Cryptography Engine

> **Warning:** This implementation is for education and validation only. It must not be used in production.

A platform-independent C11 AES-128 block cipher with CBC/PKCS#7 support and a planned Swift/SwiftUI iOS integration. The implementation is validated against FIPS-197 and NIST SP 800-38A test vectors.

## Scope

Included:

- AES-128 key expansion, encryption, and decryption in C.
- CBC mode and PKCS#7 padding.
- Encrypt-then-MAC using CommonCrypto HMAC-SHA256.
- PBKDF2-HMAC-SHA256 key derivation and Keychain-backed key handling.
- An iOS message flow with a Hex Inspector and tamper demonstration.

Excluded by design:

- Networking, multi-device messaging, key exchange, multi-user accounts.
- AES-192/AES-256, custom SHA-256/HMAC, and hardware AES implementation.

## Architecture

```text
core (C11) → Bridging Header → Swift services → SwiftUI / SwiftData
```

The C core remains stateless and buildable without Xcode. Swift owns iOS integration, password-based key management, persistence, and presentation. Persisted messages contain IV, ciphertext, MAC tag, and metadata; plaintext and key material are never stored in SwiftData.

## Build and Test

```sh
cd core
make test       # Build and run the test suite
make sanitize   # Run with AddressSanitizer and UndefinedBehaviorSanitizer
make clean      # Remove generated artifacts
```

The repository is being built incrementally by phase. The current AES core passes the FIPS-197 key-expansion and single-block encryption vectors under the C11 warning policy.

## Development Principles

MAC verification happens before decryption and padding removal. MAC tags are compared in constant time. Sensitive buffers are wiped after use. Table-based AES is retained for learning and documented as a cache side-channel risk in `docs/side-channels.md`.
