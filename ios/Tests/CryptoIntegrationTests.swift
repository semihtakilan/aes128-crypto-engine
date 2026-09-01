//
//  CryptoIntegrationTests.swift
//  AES128CryptoEngine
//
//  Created by Semih TAKILAN on 01.09.2026.
//

import Foundation
import Security
import Testing
@testable import AES128CryptoEngine

@Suite("Crypto integration")
struct CryptoIntegrationTests {
    @Test("encrypting then decrypting returns the original plaintext")
    func encryptThenDecryptReturnsPlaintext() throws {
        let encryptionKey = Data(repeating: 0x11, count: KeyManager.encryptionKeyLength)
        let authenticationKey = Data(repeating: 0x22, count: KeyManager.authenticationKeyLength)
        let plaintext = Data("Swift and C integration".utf8)

        let encryptedMessage = try MessageCrypto.encrypt(
            plaintext: plaintext,
            encryptionKey: encryptionKey,
            authenticationKey: authenticationKey
        )
        let decrypted = try MessageCrypto.decrypt(
            message: encryptedMessage,
            encryptionKey: encryptionKey,
            authenticationKey: authenticationKey
        )

        #expect(decrypted == plaintext)
        #expect(encryptedMessage.iv.count == CryptoEngine.blockSize)
        #expect(encryptedMessage.tag.count == MessageCrypto.tagLength)
    }

    @Test("derived encryption and authentication keys are separate")
    func derivedKeysHaveSeparateLengthsAndValues() throws {
        let salt = Data(repeating: 0x33, count: KeyManager.saltLength)
        let keys = try KeyManager.deriveKeys(
            from: "correct horse battery staple",
            salt: salt,
            iterations: 10_000
        )

        #expect(keys.encryptionKey.count == KeyManager.encryptionKeyLength)
        #expect(keys.authenticationKey.count == KeyManager.authenticationKeyLength)
        #expect(
            keys.encryptionKey != Data(keys.authenticationKey.prefix(KeyManager.encryptionKeyLength))
        )
    }

    @Test("Keychain stores and loads the derived vault key")
    func keychainStoresAndLoadsDerivedKey() throws {
        let account = "com.semihtakilan.aes128cryptoengine.test-derived-key"
        let key = Data(repeating: 0xA5, count: KeyManager.derivedKeyLength)
        let cleanupQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account
        ]
        defer {
            SecItemDelete(cleanupQuery as CFDictionary)
        }

        try KeyManager.saveDerivedKey(key, account: account)
        let storedKey = try KeyManager.loadDerivedKey(account: account)

        #expect(storedKey == key)
    }

    @Test("tampered authenticated fields are rejected before decryption")
    func tamperedAuthenticatedFieldsAreRejectedBeforeDecryption() throws {
        let encryptionKey = Data(repeating: 0x44, count: KeyManager.encryptionKeyLength)
        let authenticationKey = Data(repeating: 0x55, count: KeyManager.authenticationKeyLength)
        let encryptedMessage = try MessageCrypto.encrypt(
            plaintext: Data("tamper me".utf8),
            encryptionKey: encryptionKey,
            authenticationKey: authenticationKey
        )

        var tamperedIV = encryptedMessage.iv
        tamperedIV[0] ^= 0x01
        let ivTamperedMessage = EncryptedMessage(
            iv: tamperedIV,
            ciphertext: encryptedMessage.ciphertext,
            tag: encryptedMessage.tag
        )
        #expect(isAuthenticationFailure(
            for: ivTamperedMessage,
            encryptionKey: encryptionKey,
            authenticationKey: authenticationKey
        ))

        var tamperedCiphertext = encryptedMessage.ciphertext
        tamperedCiphertext[0] ^= 0x01
        let ciphertextTamperedMessage = EncryptedMessage(
            iv: encryptedMessage.iv,
            ciphertext: tamperedCiphertext,
            tag: encryptedMessage.tag
        )
        #expect(isAuthenticationFailure(
            for: ciphertextTamperedMessage,
            encryptionKey: encryptionKey,
            authenticationKey: authenticationKey
        ))

        var tamperedTag = encryptedMessage.tag
        tamperedTag[0] ^= 0x01
        let tagTamperedMessage = EncryptedMessage(
            iv: encryptedMessage.iv,
            ciphertext: encryptedMessage.ciphertext,
            tag: tamperedTag
        )
        #expect(isAuthenticationFailure(
            for: tagTamperedMessage,
            encryptionKey: encryptionKey,
            authenticationKey: authenticationKey
        ))
    }

    private func isAuthenticationFailure(
        for message: EncryptedMessage,
        encryptionKey: Data,
        authenticationKey: Data
    ) -> Bool {
        do {
            _ = try MessageCrypto.decrypt(
                message: message,
                encryptionKey: encryptionKey,
                authenticationKey: authenticationKey
            )
            return false
        } catch MessageCryptoError.authenticationFailed {
            return true
        } catch {
            return false
        }
    }
}
