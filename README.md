# AES-128 Cryptography Engine

> **Warning:** This implementation is for education and validation only. It must not be used in production.

A platform-independent C11 AES-128 block cipher with CBC/PKCS#7 support and a Swift/SwiftUI iOS integration. The implementation is validated against FIPS-197 and NIST SP 800-38A test vectors.

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

## Design Decisions

- AES-128, CBC, and PKCS#7 are handwritten for learning and FIPS/NIST validation.
- HMAC-SHA256, PBKDF2, secure randomness, and Keychain use reviewed Apple APIs rather than custom cryptographic primitives.
- Encrypt-then-MAC authenticates `IV || ciphertext`; decryption verifies the tag before invoking CBC or padding removal.
- `k_enc` and `k_mac` are derived as separate keys from one PBKDF2 output.

See [`docs/design.md`](docs/design.md) for the complete data flow and [`docs/side-channels.md`](docs/side-channels.md) for the cache-timing analysis.

## Build and Test

```sh
cd core
make test       # Build and run the test suite
make sanitize   # Run with AddressSanitizer and UndefinedBehaviorSanitizer
make clean      # Remove generated artifacts
```

For the iOS target:

```sh
xcodebuild -project ios/AES128CryptoEngine.xcodeproj \
  -scheme AES128CryptoEngine -sdk iphonesimulator \
  -configuration Debug -derivedDataPath /tmp/aes128-derived \
  CODE_SIGNING_ALLOWED=NO build-for-testing

xcodebuild -project ios/AES128CryptoEngine.xcodeproj \
  -scheme AES128CryptoEngine \
  -destination 'platform=iOS Simulator,name=iPhone 15 Pro' \
  CODE_SIGNING_ALLOWED=NO test
```

The repository is being built incrementally by phase. The current AES core passes the FIPS-197 key-expansion, single-block encryption/decryption, NIST CBC, PKCS#7 boundary, and deterministic round-trip vectors. The Swift bridge and CommonCrypto Encrypt-then-MAC smoke path also pass typecheck and runtime interop validation.

The iOS app and Swift Testing target also build with the iOS Simulator SDK. Running UI or Swift Testing requires an available simulator runtime.

## Development Principles

MAC verification happens before decryption and padding removal. MAC tags are compared in constant time. Sensitive buffers are wiped after use. Table-based AES is retained for learning and documented as a cache side-channel risk in `docs/side-channels.md`.

## Known Limitations

This implementation does not provide networking, key exchange, multi-user accounts, AES-192/AES-256, hardware AES, or a production security guarantee. Use CryptoKit or another reviewed library for real application data.
