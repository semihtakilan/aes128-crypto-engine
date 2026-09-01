//
//  MessageCrypto.swift
//  AES128CryptoEngine
//
//  Created by Semih TAKILAN on 01.09.2026.
//

import CommonCrypto
import Foundation
import Security

struct EncryptedMessage: Sendable {
    let iv: Data
    let ciphertext: Data
    let tag: Data
}

enum MessageCryptoError: Error {
    case invalidEncryptionKeyLength
    case invalidAuthenticationKeyLength
    case invalidIVLength
    case invalidCiphertext
    case invalidTagLength
    case authenticationFailed
    case randomGenerationFailed(OSStatus)
}

struct MessageCrypto {
    static let tagLength = Int(CC_SHA256_DIGEST_LENGTH)

    static func encrypt(
        plaintext: Data,
        encryptionKey: Data,
        authenticationKey: Data
    ) throws -> EncryptedMessage {
        guard encryptionKey.count == KeyManager.encryptionKeyLength else {
            throw MessageCryptoError.invalidEncryptionKeyLength
        }
        guard authenticationKey.count == KeyManager.authenticationKeyLength else {
            throw MessageCryptoError.invalidAuthenticationKeyLength
        }

        let iv = try makeRandomData(count: CryptoEngine.blockSize)
        let ciphertext = try CryptoEngine.encrypt(
            plaintext: plaintext,
            key: encryptionKey,
            iv: iv
        )
        let tag = makeTag(key: authenticationKey, iv: iv, ciphertext: ciphertext)

        return EncryptedMessage(iv: iv, ciphertext: ciphertext, tag: tag)
    }

    static func decrypt(
        message: EncryptedMessage,
        encryptionKey: Data,
        authenticationKey: Data
    ) throws -> Data {
        guard encryptionKey.count == KeyManager.encryptionKeyLength else {
            throw MessageCryptoError.invalidEncryptionKeyLength
        }
        guard authenticationKey.count == KeyManager.authenticationKeyLength else {
            throw MessageCryptoError.invalidAuthenticationKeyLength
        }
        guard message.iv.count == CryptoEngine.blockSize else {
            throw MessageCryptoError.invalidIVLength
        }
        guard !message.ciphertext.isEmpty,
              message.ciphertext.count % CryptoEngine.blockSize == 0 else {
            throw MessageCryptoError.invalidCiphertext
        }
        guard message.tag.count == tagLength else {
            throw MessageCryptoError.invalidTagLength
        }

        let expectedTag = makeTag(
            key: authenticationKey,
            iv: message.iv,
            ciphertext: message.ciphertext
        )
        guard CryptoEngine.constantTimeEqual(expectedTag, message.tag) else {
            throw MessageCryptoError.authenticationFailed
        }

        return try CryptoEngine.decrypt(
            ciphertext: message.ciphertext,
            key: encryptionKey,
            iv: message.iv
        )
    }

    private static func makeTag(key: Data, iv: Data, ciphertext: Data) -> Data {
        var authenticatedData = Data()
        authenticatedData.reserveCapacity(iv.count + ciphertext.count)
        authenticatedData.append(iv)
        authenticatedData.append(ciphertext)

        var tag = Data(count: tagLength)
        key.withUnsafeBytes { keyBuffer in
            authenticatedData.withUnsafeBytes { dataBuffer in
                tag.withUnsafeMutableBytes { tagBuffer in
                    CCHmac(
                        CCHmacAlgorithm(kCCHmacAlgSHA256),
                        keyBuffer.baseAddress,
                        key.count,
                        dataBuffer.baseAddress,
                        authenticatedData.count,
                        tagBuffer.baseAddress
                    )
                }
            }
        }
        return tag
    }

    private static func makeRandomData(count: Int) throws -> Data {
        var data = Data(count: count)
        let status = data.withUnsafeMutableBytes { buffer -> OSStatus in
            guard let baseAddress = buffer.baseAddress else {
                return errSecParam
            }
            return SecRandomCopyBytes(kSecRandomDefault, count, baseAddress)
        }

        guard status == errSecSuccess else {
            throw MessageCryptoError.randomGenerationFailed(status)
        }
        return data
    }
}
