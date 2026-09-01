//
//  CryptoIntegrationTests.swift
//  AES128CryptoEngine
//
//  Created by Semih TAKILAN on 01.09.2026.
//

import Foundation
import XCTest
@testable import AES128CryptoEngine

final class CryptoIntegrationTests: XCTestCase {
    func testEncryptThenDecryptReturnsPlaintext() throws {
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

        XCTAssertEqual(decrypted, plaintext)
        XCTAssertEqual(encryptedMessage.iv.count, CryptoEngine.blockSize)
        XCTAssertEqual(encryptedMessage.tag.count, MessageCrypto.tagLength)
    }

    func testDerivedKeysHaveSeparateLengthsAndValues() throws {
        let salt = Data(repeating: 0x33, count: KeyManager.saltLength)
        let keys = try KeyManager.deriveKeys(
            from: "correct horse battery staple",
            salt: salt,
            iterations: 10_000
        )

        XCTAssertEqual(keys.encryptionKey.count, KeyManager.encryptionKeyLength)
        XCTAssertEqual(keys.authenticationKey.count, KeyManager.authenticationKeyLength)
        XCTAssertNotEqual(
            keys.encryptionKey,
            Data(keys.authenticationKey.prefix(KeyManager.encryptionKeyLength))
        )
    }

    func testTamperedAuthenticatedFieldsAreRejectedBeforeDecryption() throws {
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
        try assertAuthenticationFailure(
            for: ivTamperedMessage,
            encryptionKey: encryptionKey,
            authenticationKey: authenticationKey
        )

        var tamperedCiphertext = encryptedMessage.ciphertext
        tamperedCiphertext[0] ^= 0x01
        let ciphertextTamperedMessage = EncryptedMessage(
            iv: encryptedMessage.iv,
            ciphertext: tamperedCiphertext,
            tag: encryptedMessage.tag
        )
        try assertAuthenticationFailure(
            for: ciphertextTamperedMessage,
            encryptionKey: encryptionKey,
            authenticationKey: authenticationKey
        )

        var tamperedTag = encryptedMessage.tag
        tamperedTag[0] ^= 0x01
        let tagTamperedMessage = EncryptedMessage(
            iv: encryptedMessage.iv,
            ciphertext: encryptedMessage.ciphertext,
            tag: tamperedTag
        )
        try assertAuthenticationFailure(
            for: tagTamperedMessage,
            encryptionKey: encryptionKey,
            authenticationKey: authenticationKey
        )
    }

    private func assertAuthenticationFailure(
        for message: EncryptedMessage,
        encryptionKey: Data,
        authenticationKey: Data
    ) throws {
        var authenticationFailed = false

        do {
            _ = try MessageCrypto.decrypt(
                message: message,
                encryptionKey: encryptionKey,
                authenticationKey: authenticationKey
            )
        } catch MessageCryptoError.authenticationFailed {
            authenticationFailed = true
        }

        XCTAssertTrue(authenticationFailed)
    }
}
