# AES-128 Cryptography Engine

> **Warning:** This implementation is for education and validation only. It must not be used in production.

A platform-independent C11 AES-128 block cipher with CBC/PKCS#7 support and a Swift/SwiftUI iOS integration. The implementation is validated against FIPS-197 and NIST SP 800-38A test vectors.

## Scope

Included:

- AES-128 key expansion, encryption, and decryption in C.
- CBC mode and PKCS#7 padding.
- Encrypt-then-MAC using CommonCrypto HMAC-SHA256.
- PBKDF2-HMAC-SHA256 key derivation and authenticated wrapping of a random vault key.
- An iOS message flow with a Hex Inspector and tamper demonstration.

Excluded by design:

- Networking, multi-device messaging, key exchange, multi-user accounts.
- AES-192/AES-256, custom SHA-256/HMAC, and hardware AES implementation.

## Architecture

```text
core (C11) → Bridging Header → Swift services → SwiftUI / SwiftData
```

The C core remains stateless and buildable without Xcode. Swift owns iOS integration, password-based key management, persistence, and presentation. Persisted messages contain IV, ciphertext, MAC tag, and metadata. SwiftData also stores the encrypted vault-key envelope, salt, and iteration count; plaintext messages and unwrapped keys are never persisted.

## Design Decisions

- AES-128, CBC, and PKCS#7 are handwritten for learning and FIPS/NIST validation.
- HMAC-SHA256, PBKDF2, and secure randomness use reviewed Apple APIs rather than custom cryptographic primitives.
- Encrypt-then-MAC authenticates `IV || ciphertext`; decryption verifies the tag before invoking CBC or padding removal.
- A random 48-byte vault key supplies separate AES and MAC keys. The password-derived keys only wrap that vault key; they are not stored in Keychain.
- PBKDF2 calibration has a 600,000-iteration floor. Older configurations below the floor are upgraded after a successful unlock without re-encrypting messages.
- Key derivation runs off the main actor. Decrypted message text is cached in memory until refresh or lock, rather than recomputed during every UI render.

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
  build-for-testing

xcodebuild -project ios/AES128CryptoEngine.xcodeproj \
  -scheme AES128CryptoEngine \
  -destination 'platform=iOS Simulator,name=iPhone 15 Pro' \
  test
```

The AES core covers FIPS-197 key expansion, single-block encryption/decryption, NIST CBC, PKCS#7 boundaries, deterministic round trips, and wiping buffers larger than 255 bytes. Swift Testing covers the bridge, authenticated encryption, long passwords, key wrapping, legacy migration, backup recovery, and cached message presentation.

The iOS app and Swift Testing target also build with the iOS Simulator SDK. Running UI or Swift Testing requires an available simulator runtime.

GitHub Actions runs `make test` and `make sanitize` on Linux and builds the iOS app and test target on macOS for every push and pull request.

## Development Principles

MAC verification happens before decryption and padding removal. MAC tags are compared in constant time. Sensitive buffers are wiped after use on a best-effort basis; Swift `Data` copy-on-write can leave other copies untouched. S-Box lookup timing and memory-wiping limitations are documented in `docs/side-channels.md`.

## Known Limitations

This implementation does not provide networking, key exchange, multi-user accounts, AES-192/AES-256, hardware AES, or a production security guarantee. Use CryptoKit or another reviewed library for real application data.
