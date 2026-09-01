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
    case invalidConfiguration
    case invalidStoredIterations
    case invalidPassword

    var errorDescription: String? {
        switch self {
        case .locked:
            return "The vault is locked."
        case .multipleConfigurations:
            return "The vault configuration is ambiguous."
        case .invalidConfiguration:
            return "The vault key configuration is incomplete."
        case .invalidStoredIterations:
            return "The stored PBKDF2 configuration is invalid."
        case .invalidPassword:
            return "The password does not unlock this vault."
        }
    }
}

private final class SessionKeyStorage {
    private(set) var encryptionKey = Data()
    private(set) var authenticationKey = Data()

    func replace(with keys: VaultKeys) {
        clear()
        encryptionKey = keys.encryptionKey
        authenticationKey = keys.authenticationKey
    }

    func clear() {
        CryptoEngine.wipe(&encryptionKey)
        CryptoEngine.wipe(&authenticationKey)
    }

    deinit {
        clear()
    }
}

private struct VaultConfigurationSnapshot: Sendable {
    let salt: Data
    let iterations: UInt32
    let wrappedKey: EncryptedMessage?
}

private struct VaultConfigurationUpdate: Sendable {
    let salt: Data
    let iterations: UInt32
    let wrappedKey: EncryptedMessage
}

private struct VaultUnlockResult: Sendable {
    var keys: VaultKeys
    let configurationUpdate: VaultConfigurationUpdate?
}

@MainActor
final class CryptoSession: ObservableObject {
    @Published private(set) var isUnlocked = false
    @Published private(set) var isWorking = false
    @Published private(set) var errorMessage: String?

    private let sessionKeys = SessionKeyStorage()
    private let legacyKeychainAccount: String

    init(legacyKeychainAccount: String = KeyManager.legacyKeychainAccount) {
        self.legacyKeychainAccount = legacyKeychainAccount
    }

    func unlock(password: String, modelContext: ModelContext) async {
        guard !isWorking else {
            return
        }

        errorMessage = nil
        isWorking = true
        defer { isWorking = false }

        do {
            let configuration = try loadConfiguration(from: modelContext)
            let snapshot = try configuration.map(configurationSnapshot)
            let legacyMessage = snapshot?.wrappedKey == nil
                ? try loadFirstStoredMessage(from: modelContext)
                : nil
            let legacyAccount = legacyKeychainAccount

            var result = try await Task.detached(priority: .userInitiated) {
                try Self.prepareUnlock(
                    password: password,
                    configuration: snapshot,
                    legacyMessage: legacyMessage,
                    legacyKeychainAccount: legacyAccount
                )
            }.value
            defer { result.keys.wipe() }

            if let update = result.configurationUpdate {
                try apply(
                    update,
                    to: configuration,
                    modelContext: modelContext
                )
            }

            try KeyManager.deleteLegacyVaultKey(account: legacyKeychainAccount)
            sessionKeys.replace(with: result.keys)
            isUnlocked = true
        } catch {
            sessionKeys.clear()
            isUnlocked = false
            errorMessage = (error as? LocalizedError)?.errorDescription
                ?? String(describing: error)
        }
    }

    func lock() {
        sessionKeys.clear()
        isUnlocked = false
        errorMessage = nil
    }

    func encrypt(_ plaintext: Data) throws -> EncryptedMessage {
        guard isUnlocked else {
            throw CryptoSessionError.locked
        }
        return try MessageCrypto.encrypt(
            plaintext: plaintext,
            encryptionKey: sessionKeys.encryptionKey,
            authenticationKey: sessionKeys.authenticationKey
        )
    }

    func decrypt(_ message: EncryptedMessage) throws -> Data {
        guard isUnlocked else {
            throw CryptoSessionError.locked
        }
        return try MessageCrypto.decrypt(
            message: message,
            encryptionKey: sessionKeys.encryptionKey,
            authenticationKey: sessionKeys.authenticationKey
        )
    }

    private func loadConfiguration(from modelContext: ModelContext) throws -> CryptoConfiguration? {
        let configurations = try modelContext.fetch(FetchDescriptor<CryptoConfiguration>())
        guard configurations.count <= 1 else {
            throw CryptoSessionError.multipleConfigurations
        }
        return configurations.first
    }

    private func configurationSnapshot(
        from configuration: CryptoConfiguration
    ) throws -> VaultConfigurationSnapshot {
        guard configuration.iterations > 0,
              configuration.iterations <= Int(UInt32.max) else {
            throw CryptoSessionError.invalidStoredIterations
        }

        let wrappedKey: EncryptedMessage?
        switch (
            configuration.wrappedKeyIV,
            configuration.wrappedKeyCiphertext,
            configuration.wrappedKeyTag
        ) {
        case let (.some(iv), .some(ciphertext), .some(tag)):
            wrappedKey = EncryptedMessage(
                iv: iv,
                ciphertext: ciphertext,
                tag: tag
            )
        case (nil, nil, nil):
            wrappedKey = nil
        default:
            throw CryptoSessionError.invalidConfiguration
        }

        return VaultConfigurationSnapshot(
            salt: configuration.salt,
            iterations: UInt32(configuration.iterations),
            wrappedKey: wrappedKey
        )
    }

    private func loadFirstStoredMessage(
        from modelContext: ModelContext
    ) throws -> EncryptedMessage? {
        var descriptor = FetchDescriptor<StoredMessage>(
            sortBy: [SortDescriptor(\.createdAt)]
        )
        descriptor.fetchLimit = 1

        guard let message = try modelContext.fetch(descriptor).first else {
            return nil
        }
        return EncryptedMessage(
            iv: message.iv,
            ciphertext: message.ciphertext,
            tag: message.tag
        )
    }

    private func apply(
        _ update: VaultConfigurationUpdate,
        to configuration: CryptoConfiguration?,
        modelContext: ModelContext
    ) throws {
        if let configuration {
            configuration.salt = update.salt
            configuration.iterations = Int(update.iterations)
            configuration.wrappedKeyIV = update.wrappedKey.iv
            configuration.wrappedKeyCiphertext = update.wrappedKey.ciphertext
            configuration.wrappedKeyTag = update.wrappedKey.tag
        } else {
            modelContext.insert(
                CryptoConfiguration(
                    salt: update.salt,
                    iterations: Int(update.iterations),
                    wrappedKeyIV: update.wrappedKey.iv,
                    wrappedKeyCiphertext: update.wrappedKey.ciphertext,
                    wrappedKeyTag: update.wrappedKey.tag
                )
            )
        }
        try modelContext.save()
    }

    nonisolated private static func prepareUnlock(
        password: String,
        configuration: VaultConfigurationSnapshot?,
        legacyMessage: EncryptedMessage?,
        legacyKeychainAccount: String
    ) throws -> VaultUnlockResult {
        guard let configuration else {
            guard legacyMessage == nil else {
                throw CryptoSessionError.invalidConfiguration
            }
            return try createVault(password: password)
        }

        if let wrappedKey = configuration.wrappedKey {
            return try unlockWrappedVault(
                password: password,
                configuration: configuration,
                wrappedKey: wrappedKey
            )
        }

        return try migrateLegacyVault(
            password: password,
            configuration: configuration,
            legacyMessage: legacyMessage,
            legacyKeychainAccount: legacyKeychainAccount
        )
    }

    nonisolated private static func createVault(
        password: String
    ) throws -> VaultUnlockResult {
        var vaultKeys = try KeyManager.makeVaultKeys()

        do {
            let update = try makeConfigurationUpdate(
                password: password,
                vaultKeys: vaultKeys
            )
            return VaultUnlockResult(
                keys: vaultKeys,
                configurationUpdate: update
            )
        } catch {
            vaultKeys.wipe()
            throw error
        }
    }

    nonisolated private static func unlockWrappedVault(
        password: String,
        configuration: VaultConfigurationSnapshot,
        wrappedKey: EncryptedMessage
    ) throws -> VaultUnlockResult {
        var wrappingKeys = try KeyManager.deriveWrappingKeys(
            from: password,
            salt: configuration.salt,
            iterations: configuration.iterations
        )
        defer { wrappingKeys.wipe() }

        var combinedKey: Data
        do {
            combinedKey = try MessageCrypto.decrypt(
                message: wrappedKey,
                encryptionKey: wrappingKeys.encryptionKey,
                authenticationKey: wrappingKeys.authenticationKey
            )
        } catch MessageCryptoError.authenticationFailed {
            throw CryptoSessionError.invalidPassword
        }
        defer { CryptoEngine.wipe(&combinedKey) }

        var vaultKeys = try VaultKeys(combinedKey: combinedKey)
        do {
            let update = configuration.iterations < KeyManager.minimumIterationCount
                ? try makeConfigurationUpdate(password: password, vaultKeys: vaultKeys)
                : nil
            return VaultUnlockResult(
                keys: vaultKeys,
                configurationUpdate: update
            )
        } catch {
            vaultKeys.wipe()
            throw error
        }
    }

    nonisolated private static func migrateLegacyVault(
        password: String,
        configuration: VaultConfigurationSnapshot,
        legacyMessage: EncryptedMessage?,
        legacyKeychainAccount: String
    ) throws -> VaultUnlockResult {
        var vaultKeys = try KeyManager.deriveWrappingKeys(
            from: password,
            salt: configuration.salt,
            iterations: configuration.iterations
        )

        do {
            var combinedKey = vaultKeys.combinedKey
            defer { CryptoEngine.wipe(&combinedKey) }

            if var storedKey = try KeyManager.loadLegacyVaultKey(
                account: legacyKeychainAccount
            ) {
                defer { CryptoEngine.wipe(&storedKey) }
                guard CryptoEngine.constantTimeEqual(combinedKey, storedKey) else {
                    throw CryptoSessionError.invalidPassword
                }
            } else if let legacyMessage {
                do {
                    var plaintext = try MessageCrypto.decrypt(
                        message: legacyMessage,
                        encryptionKey: vaultKeys.encryptionKey,
                        authenticationKey: vaultKeys.authenticationKey
                    )
                    CryptoEngine.wipe(&plaintext)
                } catch MessageCryptoError.authenticationFailed {
                    throw CryptoSessionError.invalidPassword
                }
            } else {
                vaultKeys.wipe()
                vaultKeys = try KeyManager.makeVaultKeys()
            }

            let update = try makeConfigurationUpdate(
                password: password,
                vaultKeys: vaultKeys
            )
            return VaultUnlockResult(
                keys: vaultKeys,
                configurationUpdate: update
            )
        } catch {
            vaultKeys.wipe()
            throw error
        }
    }

    nonisolated private static func makeConfigurationUpdate(
        password: String,
        vaultKeys: VaultKeys
    ) throws -> VaultConfigurationUpdate {
        let salt = try KeyManager.makeSalt()
        let iterations = KeyManager.calibratedIterationCount(
            passwordLength: password.utf8.count
        )
        var wrappingKeys = try KeyManager.deriveWrappingKeys(
            from: password,
            salt: salt,
            iterations: iterations
        )
        defer { wrappingKeys.wipe() }

        var combinedKey = vaultKeys.combinedKey
        defer { CryptoEngine.wipe(&combinedKey) }
        let wrappedKey = try MessageCrypto.encrypt(
            plaintext: combinedKey,
            encryptionKey: wrappingKeys.encryptionKey,
            authenticationKey: wrappingKeys.authenticationKey
        )

        return VaultConfigurationUpdate(
            salt: salt,
            iterations: iterations,
            wrappedKey: wrappedKey
        )
    }
}
