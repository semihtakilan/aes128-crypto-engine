//
//  CryptoEngine.swift
//  AES128CryptoEngine
//
//  Created by Semih TAKILAN on 01.09.2026.
//

import Foundation

enum CryptoEngineError: Error {
    case invalidKeyLength
    case invalidIVLength
    case invalidBuffer
    case encryptionFailed(aes_cbc_status)
    case decryptionFailed(aes_cbc_status)
}

struct CryptoEngine {
    static let blockSize = Int(AES_BLOCK_SIZE)
    static let keySize = Int(AES_128_KEY_SIZE)
    static let expandedKeySize = blockSize * 11

    static func encrypt(plaintext: Data, key: Data, iv: Data) throws -> Data {
        guard key.count == keySize else {
            throw CryptoEngineError.invalidKeyLength
        }
        guard iv.count == blockSize else {
            throw CryptoEngineError.invalidIVLength
        }
        guard plaintext.count <= Int.max - blockSize else {
            throw CryptoEngineError.invalidBuffer
        }

        var expandedKey = try makeExpandedKey(from: key)
        defer { wipe(&expandedKey) }

        var ciphertext = Data(count: plaintext.count + blockSize)
        let ciphertextCapacity = ciphertext.count
        var ciphertextLength = 0
        var status = AES_CBC_INVALID_ARGUMENT

        plaintext.withUnsafeBytes { plaintextBuffer in
            iv.withUnsafeBytes { ivBuffer in
                expandedKey.withUnsafeBytes { expandedKeyBuffer in
                    ciphertext.withUnsafeMutableBytes { ciphertextBuffer in
                        status = aes_cbc_encrypt(
                            plaintextBuffer.bindMemory(to: UInt8.self).baseAddress,
                            plaintext.count,
                            ivBuffer.bindMemory(to: UInt8.self).baseAddress,
                            expandedKeyBuffer.bindMemory(to: UInt8.self).baseAddress,
                            ciphertextBuffer.bindMemory(to: UInt8.self).baseAddress,
                            ciphertextCapacity,
                            &ciphertextLength
                        )
                    }
                }
            }
        }

        guard status == AES_CBC_SUCCESS else {
            throw CryptoEngineError.encryptionFailed(status)
        }
        guard ciphertextLength >= 0, ciphertextLength <= ciphertext.count else {
            throw CryptoEngineError.invalidBuffer
        }

        ciphertext.removeSubrange(ciphertextLength..<ciphertext.count)
        return ciphertext
    }

    static func decrypt(ciphertext: Data, key: Data, iv: Data) throws -> Data {
        guard key.count == keySize else {
            throw CryptoEngineError.invalidKeyLength
        }
        guard iv.count == blockSize else {
            throw CryptoEngineError.invalidIVLength
        }

        var expandedKey = try makeExpandedKey(from: key)
        defer { wipe(&expandedKey) }

        var plaintext = Data(count: ciphertext.count)
        let plaintextCapacity = plaintext.count
        var plaintextLength = 0
        var status = AES_CBC_INVALID_ARGUMENT

        ciphertext.withUnsafeBytes { ciphertextBuffer in
            iv.withUnsafeBytes { ivBuffer in
                expandedKey.withUnsafeBytes { expandedKeyBuffer in
                    plaintext.withUnsafeMutableBytes { plaintextBuffer in
                        status = aes_cbc_decrypt(
                            ciphertextBuffer.bindMemory(to: UInt8.self).baseAddress,
                            ciphertext.count,
                            ivBuffer.bindMemory(to: UInt8.self).baseAddress,
                            expandedKeyBuffer.bindMemory(to: UInt8.self).baseAddress,
                            plaintextBuffer.bindMemory(to: UInt8.self).baseAddress,
                            plaintextCapacity,
                            &plaintextLength
                        )
                    }
                }
            }
        }

        guard status == AES_CBC_SUCCESS else {
            throw CryptoEngineError.decryptionFailed(status)
        }
        guard plaintextLength >= 0, plaintextLength <= plaintext.count else {
            throw CryptoEngineError.invalidBuffer
        }

        plaintext.removeSubrange(plaintextLength..<plaintext.count)
        return plaintext
    }

    static func constantTimeEqual(_ left: Data, _ right: Data) -> Bool {
        guard left.count == right.count else {
            return false
        }

        var result: UInt8 = 0
        left.withUnsafeBytes { leftBuffer in
            right.withUnsafeBytes { rightBuffer in
                result = aes_constant_time_equal(
                    leftBuffer.bindMemory(to: UInt8.self).baseAddress,
                    rightBuffer.bindMemory(to: UInt8.self).baseAddress,
                    left.count
                )
            }
        }

        return result != 0
    }

    static func wipe(_ data: inout Data) {
        data.withUnsafeMutableBytes { buffer in
            guard let baseAddress = buffer.bindMemory(to: UInt8.self).baseAddress else {
                return
            }
            aes_secure_zero(baseAddress, buffer.count)
        }
    }

    private static func makeExpandedKey(from key: Data) throws -> Data {
        var expandedKey = Data(count: expandedKeySize)
        let didExpand = key.withUnsafeBytes { keyBuffer in
            expandedKey.withUnsafeMutableBytes { expandedKeyBuffer in
                guard let keyAddress = keyBuffer.bindMemory(to: UInt8.self).baseAddress,
                      let expandedKeyAddress = expandedKeyBuffer.bindMemory(to: UInt8.self).baseAddress else {
                    return false
                }

                aes_expand_key(keyAddress, expandedKeyAddress)
                return true
            }
        }

        guard didExpand else {
            throw CryptoEngineError.invalidBuffer
        }
        return expandedKey
    }
}
