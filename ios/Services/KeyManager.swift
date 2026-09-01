//
//  KeyManager.swift
//  AES128CryptoEngine
//
//  Created by Semih TAKILAN on 01.09.2026.
//

import CommonCrypto
import Foundation
import Security

enum KeyManagerError: LocalizedError {
    case invalidPassword
    case invalidSaltLength
    case invalidIterationCount
    case keyDerivationFailed(Int32)
    case randomGenerationFailed(OSStatus)
    case invalidKeyLength
    case keychain(OSStatus)

    var errorDescription: String? {
        switch self {
        case .invalidPassword:
            return "Enter a password to continue."
        case .invalidSaltLength, .invalidIterationCount, .invalidKeyLength:
            return "The vault configuration is invalid."
        case .keyDerivationFailed:
            return "The password could not be converted into vault keys."
        case .randomGenerationFailed:
            return "The device could not create secure random data."
        case .keychain(let status) where status == errSecMissingEntitlement:
            return "Keychain access is unavailable in this build. Enable code signing in Xcode and try again."
        case .keychain(let status):
            return "Keychain access failed (status \(status)). Try again."
        }
    }
}

struct KeyManager {
    static let saltLength = 16
    static let encryptionKeyLength = Int(AES_128_KEY_SIZE)
    static let authenticationKeyLength = 32
    static let derivedKeyLength = encryptionKeyLength + authenticationKeyLength

    static func makeSalt() throws -> Data {
        try makeRandomData(count: saltLength)
    }

    static func calibratedIterationCount(
        passwordLength: Int,
        targetMilliseconds: UInt32 = 100
    ) -> UInt32 {
        let rounds = CCCalibratePBKDF(
            CCPBKDFAlgorithm(kCCPBKDF2),
            passwordLength,
            saltLength,
            CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
            derivedKeyLength,
            targetMilliseconds
        )

        return rounds == UInt32.max ? 10_000 : rounds
    }

    static func deriveKeys(
        from password: String,
        salt: Data,
        iterations: UInt32
    ) throws -> (encryptionKey: Data, authenticationKey: Data) {
        guard !password.isEmpty else {
            throw KeyManagerError.invalidPassword
        }
        guard salt.count == saltLength else {
            throw KeyManagerError.invalidSaltLength
        }
        guard iterations > 0 else {
            throw KeyManagerError.invalidIterationCount
        }

        var passwordData = Data(password.utf8)
        var derivedKey = Data(count: derivedKeyLength)
        let derivedKeyByteCount = derivedKey.count
        defer {
            CryptoEngine.wipe(&passwordData)
            CryptoEngine.wipe(&derivedKey)
        }

        let status: Int32 = passwordData.withUnsafeBytes { passwordBuffer in
            salt.withUnsafeBytes { saltBuffer in
                derivedKey.withUnsafeMutableBytes { derivedKeyBuffer in
                    guard let passwordAddress = passwordBuffer.bindMemory(to: CChar.self).baseAddress,
                          let saltAddress = saltBuffer.bindMemory(to: UInt8.self).baseAddress,
                          let derivedKeyAddress = derivedKeyBuffer.bindMemory(to: UInt8.self).baseAddress else {
                        return Int32(kCCParamError)
                    }

                    return CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        passwordAddress,
                        passwordData.count,
                        saltAddress,
                        salt.count,
                        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                        iterations,
                        derivedKeyAddress,
                        derivedKeyByteCount
                    )
                }
            }
        }

        guard status == Int32(kCCSuccess) else {
            throw KeyManagerError.keyDerivationFailed(status)
        }

        let encryptionKey = Data(derivedKey.prefix(encryptionKeyLength))
        let authenticationKey = Data(derivedKey.suffix(authenticationKeyLength))
        return (encryptionKey, authenticationKey)
    }

    static func saveDerivedKey(_ key: Data, account: String) throws {
        guard key.count == derivedKeyLength else {
            throw KeyManagerError.invalidKeyLength
        }

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecValueData as String: key
        ]
        let status = SecItemAdd(query as CFDictionary, nil)

        if status == errSecDuplicateItem {
            let lookup: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrAccount as String: account
            ]
            let attributes: [String: Any] = [kSecValueData as String: key]
            let updateStatus = SecItemUpdate(
                lookup as CFDictionary,
                attributes as CFDictionary
            )
            guard updateStatus == errSecSuccess else {
                throw KeyManagerError.keychain(updateStatus)
            }
            return
        }

        guard status == errSecSuccess else {
            throw KeyManagerError.keychain(status)
        }
    }

    static func loadDerivedKey(account: String) throws -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        if status == errSecItemNotFound {
            return nil
        }
        guard status == errSecSuccess else {
            throw KeyManagerError.keychain(status)
        }
        guard let data = result as? Data, data.count == derivedKeyLength else {
            throw KeyManagerError.invalidKeyLength
        }
        return data
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
            throw KeyManagerError.randomGenerationFailed(status)
        }
        return data
    }
}
