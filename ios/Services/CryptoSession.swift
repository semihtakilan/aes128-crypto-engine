//
//  CryptoSession.swift
//  AES128CryptoEngine
//
//  Created by Semih TAKILAN on 01.09.2026.
//

import Combine
import Foundation
import SwiftData

enum CryptoSessionError: LocalizedError {
    case locked
    case multipleConfigurations
    case missingStoredKey
    case invalidStoredIterations
    case invalidPassword

    var errorDescription: String? {
        switch self {
        case .locked:
            return "The vault is locked."
        case .multipleConfigurations:
            return "The vault configuration is ambiguous."
        case .missingStoredKey:
            return "The vault key is missing from Keychain. It cannot be unlocked until the Keychain entry is restored."
        case .invalidStoredIterations:
            return "The stored PBKDF2 configuration is invalid."
        case .invalidPassword:
            return "The password does not unlock this vault."
        }
    }
}

@MainActor
final class CryptoSession: ObservableObject {
    @Published private(set) var isUnlocked = false
    @Published private(set) var isWorking = false
    @Published private(set) var errorMessage: String?

    private static let keychainAccount = "com.semihtakilan.aes128cryptoengine.derived-key"

    private var encryptionKey = Data()
    private var authenticationKey = Data()

    func unlock(password: String, modelContext: ModelContext) {
        guard !isWorking else {
            return
        }

        errorMessage = nil
        isWorking = true
        defer { isWorking = false }

        do {
            let configuration = try loadConfiguration(from: modelContext)
            let salt: Data
            let iterations: UInt32

            if let configuration {
                guard configuration.iterations > 0,
                      configuration.iterations <= Int(UInt32.max) else {
                    throw CryptoSessionError.invalidStoredIterations
                }
                salt = configuration.salt
                iterations = UInt32(configuration.iterations)
            } else {
                salt = try KeyManager.makeSalt()
                let passwordLength = Data(password.utf8).count
                iterations = KeyManager.calibratedIterationCount(
                    passwordLength: passwordLength
                )
            }

            let keys = try KeyManager.deriveKeys(
                from: password,
                salt: salt,
                iterations: iterations
            )
            var derivedKey = Data()
            derivedKey.append(keys.encryptionKey)
            derivedKey.append(keys.authenticationKey)
            defer { CryptoEngine.wipe(&derivedKey) }

            if configuration == nil {
                try KeyManager.saveDerivedKey(
                    derivedKey,
                    account: Self.keychainAccount
                )
                modelContext.insert(
                    CryptoConfiguration(
                        salt: salt,
                        iterations: Int(iterations)
                    )
                )
                try modelContext.save()
            } else {
                guard let storedKey = try KeyManager.loadDerivedKey(
                    account: Self.keychainAccount
                ) else {
                    throw CryptoSessionError.missingStoredKey
                }
                guard CryptoEngine.constantTimeEqual(derivedKey, storedKey) else {
                    throw CryptoSessionError.invalidPassword
                }
            }

            encryptionKey = keys.encryptionKey
            authenticationKey = keys.authenticationKey
            isUnlocked = true
        } catch {
            isUnlocked = false
            errorMessage = (error as? LocalizedError)?.errorDescription
                ?? String(describing: error)
        }
    }

    func lock() {
        CryptoEngine.wipe(&encryptionKey)
        CryptoEngine.wipe(&authenticationKey)
        isUnlocked = false
        errorMessage = nil
    }

    func encrypt(_ plaintext: Data) throws -> EncryptedMessage {
        guard isUnlocked else {
            throw CryptoSessionError.locked
        }
        return try MessageCrypto.encrypt(
            plaintext: plaintext,
            encryptionKey: encryptionKey,
            authenticationKey: authenticationKey
        )
    }

    func decrypt(_ message: EncryptedMessage) throws -> Data {
        guard isUnlocked else {
            throw CryptoSessionError.locked
        }
        return try MessageCrypto.decrypt(
            message: message,
            encryptionKey: encryptionKey,
            authenticationKey: authenticationKey
        )
    }

    deinit {
        CryptoEngine.wipe(&encryptionKey)
        CryptoEngine.wipe(&authenticationKey)
    }

    private func loadConfiguration(from modelContext: ModelContext) throws -> CryptoConfiguration? {
        let configurations = try modelContext.fetch(FetchDescriptor<CryptoConfiguration>())
        guard configurations.count <= 1 else {
            throw CryptoSessionError.multipleConfigurations
        }
        return configurations.first
    }
}
