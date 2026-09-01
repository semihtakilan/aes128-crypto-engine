# Design Notes

> This project is educational and must not be used in production.

## Layering

```text
SwiftUI → MessageListViewModel → CryptoSession → MessageCrypto → CryptoEngine → C core
                                  ↘ KeyManager → CommonCrypto / Security
```

The C core is stateless and platform-independent. It owns AES-128, key expansion, CBC, and PKCS#7. Its callers provide input, output, capacity, and expanded-key buffers; the core does not allocate message storage or depend on iOS.

The Swift layer owns password handling, key derivation, authenticated message composition, persistence, and presentation. `CryptoEngine` is the only Swift service that crosses the C boundary, and every pointer obtained from `withUnsafeBytes` is consumed inside its closure.

## Password and Vault-Key Separation

A new vault receives 48 random bytes from `SecRandomCopyBytes`: 16 bytes for message encryption and 32 bytes for message authentication. These unwrapped vault keys live only in memory.

The password is processed with PBKDF2-HMAC-SHA256, a 16-byte random salt, and a calibrated iteration count. Its 48-byte output supplies separate wrapping-encryption and wrapping-authentication keys. The vault key is then wrapped using AES-CBC/PKCS#7 plus HMAC-SHA256. SwiftData stores only this authenticated ciphertext envelope, its IV/tag, the salt, and the iteration count.

Unlocking derives the wrapping keys again, authenticates the envelope, and unwraps the vault key. Reading persisted configuration or an old Keychain item no longer provides the keys for a newly created vault. A backup containing the configuration and encrypted messages can be opened on another device with the correct password; a device-bound Keychain entry is not required.

PBKDF2 calibration targets approximately 100 ms but never goes below 600,000 iterations, including when calibration fails. This floor follows the [OWASP PBKDF2-HMAC-SHA256 guidance](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2). The floor may make derivation take longer than 100 ms on slower devices. A successfully unlocked configuration below the floor is rewrapped with a new salt and current iteration count; message ciphertext is unchanged.

## Message Flow

1. Each encryption receives a fresh 16-byte IV from `SecRandomCopyBytes`.
2. C produces `AES-CBC(k_enc, IV, PKCS7(plaintext))` using the unwrapped vault key.
3. CommonCrypto computes `HMAC-SHA256(k_mac, IV || ciphertext)`.
4. SwiftData stores IV, ciphertext, tag, and creation time, never message plaintext.

Decryption validates the message shape, recomputes the tag, compares it with the C constant-time helper, and only then calls CBC decryption and padding removal. A failed authentication never reaches the decryption path.

## Legacy Migration

Older configurations have no wrapped-key fields. On the first successful unlock, the app derives their existing message keys and validates them against the legacy Keychain entry. If that entry did not migrate with a backup, an authenticated stored message provides the password check instead. An empty legacy vault without either source has no data to validate and is initialized with new random keys using the submitted password.

Existing message keys are preserved during migration and wrapped under newly derived keys with a new salt and iteration count. The configuration is saved before the old direct Keychain key is deleted. Failed cleanup can be retried on the next unlock; no new direct key is ever written to Keychain.

Migration does not revoke key material that was copied before the upgrade. It preserves existing message keys rather than rotating them and re-encrypting every message.

## UI and Memory Lifetime

PBKDF2 calibration, derivation, and key unwrapping run in a detached task. SwiftData access and published UI state remain on the main actor, allowing the progress indicator to render during unlock. Password fields are cleared when an attempt starts, including failed attempts.

Message plaintext is decoded once during refresh and cached only in memory. Rendering or typing a draft performs a dictionary lookup instead of HMAC/AES work. Locking clears the cache and draft. Authentication, malformed-message, padding, and UTF-8 failures have distinct display text. Key storage owns its own cleanup so deinitialization does not access main-actor-isolated properties.

## Dependency Boundary

AES, CBC, and padding are intentionally handwritten to make the standard visible and testable. HMAC-SHA256, PBKDF2, and secure randomness are delegated to Apple’s reviewed APIs. Keychain is accessed only to read and remove legacy keys during migration.
