# Design Notes

> This project is educational and must not be used in production.

## Layering

```text
SwiftUI → MessageListViewModel → MessageCrypto → CryptoEngine → C core
                                  ↘ KeyManager → CommonCrypto / Security / Keychain
```

The C core is stateless and platform-independent. It owns AES-128, key expansion, CBC, and PKCS#7. Its callers provide input, output, capacity, and expanded-key buffers; the core does not allocate message storage or depend on iOS.

The Swift layer owns password handling, key derivation, authenticated message composition, persistence, and presentation. `CryptoEngine` is the only Swift service that crosses the C boundary, and every pointer obtained from `withUnsafeBytes` is consumed inside its closure.

## Key and Message Flow

1. A password is converted to UTF-8 bytes and processed with PBKDF2-HMAC-SHA256.
2. A 16-byte random salt and calibrated iteration count produce 48 bytes.
3. The first 16 bytes become `k_enc`; the remaining 32 bytes become `k_mac`.
4. Each encryption receives a fresh 16-byte IV from `SecRandomCopyBytes`.
5. C produces `AES-CBC(k_enc, IV, PKCS7(plaintext))`.
6. CommonCrypto computes `HMAC-SHA256(k_mac, IV || ciphertext)`.
7. SwiftData stores only IV, ciphertext, tag, and creation time. The salt and iteration count live in a separate configuration record; the derived key is kept in Keychain with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`.

Decryption validates the message shape, recomputes the tag, compares it with the C constant-time helper, and only then calls CBC decryption and padding removal. A failed authentication never reaches the decryption path.

## Dependency Boundary

AES, CBC, and padding are intentionally handwritten to make the standard visible and testable. HMAC-SHA256, PBKDF2, secure randomness, and Keychain are delegated to Apple’s reviewed APIs instead of reimplementing security-sensitive primitives.
