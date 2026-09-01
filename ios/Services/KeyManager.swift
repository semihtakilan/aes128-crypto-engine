//
//  KeyManager.swift
//  AES128CryptoEngine
//
//  Created by Semih TAKILAN on 01.09.2026.
//

import CommonCrypto
import Foundation
import Security

struct VaultKeys: Sendable {
    var encryptionKey: Data
    var authenticationKey: Data

    init(encryptionKey: Data, authenticationKey: Data) throws {
        guard encryptionKey.count == KeyManager.encryptionKeyLength,
              authenticationKey.count == KeyManager.authenticationKeyLength else {
            throw KeyManagerError.invalidKeyLength
        }

        self.encryptionKey = encryptionKey
        self.authenticationKey = authenticationKey
    }

    init(combinedKey: Data) throws {
        guard combinedKey.count == KeyManager.combinedKeyLength else {
            throw KeyManagerError.invalidKeyLength
        }

        try self.init(
            encryptionKey: Data(combinedKey.prefix(KeyManager.encryptionKeyLength)),
            authenticationKey: Data(combinedKey.suffix(KeyManager.authenticationKeyLength))
        )
    }

    var combinedKey: Data {
        var key = Data()
        key.reserveCapacity(KeyManager.combinedKeyLength)
        key.append(encryptionKey)
        key.append(authenticationKey)
        return key
    }

    mutating func wipe() {
        CryptoEngine.wipe(&encryptionKey)
        CryptoEngine.wipe(&authenticationKey)
    }
}

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
    static let combinedKeyLength = encryptionKeyLength + authenticationKeyLength
    static let minimumIterationCount: UInt32 = 600_000

    static let legacyKeychainAccount =
        "com.semihtakilan.aes128cryptoengine.derived-key"

    static func makeSalt() throws -> Data {
        try makeRandomData(count: saltLength)
    }

    static func makeVaultKeys() throws -> VaultKeys {
        var combinedKey = try makeRandomData(count: combinedKeyLength)
        defer { CryptoEngine.wipe(&combinedKey) }
        return try VaultKeys(combinedKey: combinedKey)
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
            combinedKeyLength,
            targetMilliseconds
        )

        guard rounds != UInt32.max else {
            return minimumIterationCount
        }
        return max(rounds, minimumIterationCount)
    }

    static func deriveWrappingKeys(
        from password: String,
        salt: Data,
        iterations: UInt32
    ) throws -> VaultKeys {
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
        var derivedKey = Data(count: combinedKeyLength)
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

        return try VaultKeys(combinedKey: derivedKey)
    }

    static func loadLegacyVaultKey(account: String) throws -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        if status == errSecItemNotFound || status == errSecMissingEntitlement {
            return nil
        }
        guard status == errSecSuccess else {
            throw KeyManagerError.keychain(status)
        }
        guard let data = result as? Data, data.count == combinedKeyLength else {
            throw KeyManagerError.invalidKeyLength
        }
        return data
    }

    static func deleteLegacyVaultKey(account: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account
        ]
        let status = SecItemDelete(query as CFDictionary)

        guard status == errSecSuccess
                || status == errSecItemNotFound
                || status == errSecMissingEntitlement else {
            throw KeyManagerError.keychain(status)
        }
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
