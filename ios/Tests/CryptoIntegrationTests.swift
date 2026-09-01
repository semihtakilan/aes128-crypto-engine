//
//  CryptoIntegrationTests.swift
//  AES128CryptoEngine
//
//  Created by Semih TAKILAN on 01.09.2026.
//

import Foundation
import Security
import SwiftData
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
        let keys = try KeyManager.deriveWrappingKeys(
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

    @Test("password buffers larger than 255 bytes are wiped without hanging")
    func longPasswordsDeriveWrappingKeys() throws {
        var keys = try KeyManager.deriveWrappingKeys(
            from: String(repeating: "a", count: 512),
            salt: Data(repeating: 0x66, count: KeyManager.saltLength),
            iterations: 1_000
        )
        defer { keys.wipe() }

        #expect(keys.encryptionKey.count == KeyManager.encryptionKeyLength)
        #expect(keys.authenticationKey.count == KeyManager.authenticationKeyLength)
    }

    @Test("PBKDF2 calibration never falls below the security floor")
    func calibrationHasMinimumIterationCount() {
        let iterations = KeyManager.calibratedIterationCount(
            passwordLength: 16,
            targetMilliseconds: 1
        )

        #expect(iterations >= KeyManager.minimumIterationCount)
    }

    @Test("the password unwraps a separate vault key and rejects a wrong password")
    @MainActor
    func wrappedVaultKeySurvivesLockAndUnlock() async throws {
        let container = try makeModelContainer()
        let context = ModelContext(container)
        let session = CryptoSession(legacyKeychainAccount: UUID().uuidString)
        let password = "correct horse battery staple"

        await session.unlock(password: password, modelContext: context)
        #expect(session.isUnlocked)
        let configuration = try #require(
            context.fetch(FetchDescriptor<CryptoConfiguration>()).first
        )
        #expect(configuration.wrappedKeyIV?.count == CryptoEngine.blockSize)
        #expect(configuration.wrappedKeyTag?.count == MessageCrypto.tagLength)
        #expect(configuration.iterations >= Int(KeyManager.minimumIterationCount))

        let plaintext = Data("A wrapped vault key protects this message".utf8)
        let encrypted = try session.encrypt(plaintext)
        var wrappingKeys = try KeyManager.deriveWrappingKeys(
            from: password,
            salt: configuration.salt,
            iterations: UInt32(configuration.iterations)
        )
        defer { wrappingKeys.wipe() }
        #expect(isAuthenticationFailure(
            for: encrypted,
            encryptionKey: wrappingKeys.encryptionKey,
            authenticationKey: wrappingKeys.authenticationKey
        ))

        session.lock()
        await session.unlock(password: "wrong password", modelContext: context)
        #expect(!session.isUnlocked)
        #expect(session.errorMessage == CryptoSessionError.invalidPassword.errorDescription)

        let restoredContainer = try makeModelContainer()
        let restoredContext = ModelContext(restoredContainer)
        restoredContext.insert(CryptoConfiguration(
            salt: configuration.salt,
            iterations: configuration.iterations,
            wrappedKeyIV: configuration.wrappedKeyIV,
            wrappedKeyCiphertext: configuration.wrappedKeyCiphertext,
            wrappedKeyTag: configuration.wrappedKeyTag
        ))
        try restoredContext.save()
        let restoredSession = CryptoSession(legacyKeychainAccount: UUID().uuidString)
        await restoredSession.unlock(password: password, modelContext: restoredContext)
        #expect(restoredSession.isUnlocked)
        #expect(try restoredSession.decrypt(encrypted) == plaintext)
    }

    @Test("an older wrapped key is upgraded without changing its message keys")
    @MainActor
    func wrappedVaultUpgradesItsIterationCount() async throws {
        let container = try makeModelContainer()
        let context = ModelContext(container)
        let password = "iteration upgrade password"
        let salt = Data(repeating: 0x99, count: KeyManager.saltLength)
        var vaultKeys = try KeyManager.makeVaultKeys()
        var wrappingKeys = try KeyManager.deriveWrappingKeys(
            from: password,
            salt: salt,
            iterations: 1_000
        )
        var combinedKey = vaultKeys.combinedKey
        defer {
            vaultKeys.wipe()
            wrappingKeys.wipe()
            CryptoEngine.wipe(&combinedKey)
        }
        let wrappedKey = try MessageCrypto.encrypt(
            plaintext: combinedKey,
            encryptionKey: wrappingKeys.encryptionKey,
            authenticationKey: wrappingKeys.authenticationKey
        )
        let configuration = CryptoConfiguration(
            salt: salt,
            iterations: 1_000,
            wrappedKeyIV: wrappedKey.iv,
            wrappedKeyCiphertext: wrappedKey.ciphertext,
            wrappedKeyTag: wrappedKey.tag
        )
        context.insert(configuration)
        try context.save()

        let plaintext = Data("The vault key survives a KDF upgrade".utf8)
        let encrypted = try MessageCrypto.encrypt(
            plaintext: plaintext,
            encryptionKey: vaultKeys.encryptionKey,
            authenticationKey: vaultKeys.authenticationKey
        )
        let session = CryptoSession(legacyKeychainAccount: UUID().uuidString)
        await session.unlock(password: password, modelContext: context)

        #expect(session.isUnlocked)
        #expect(configuration.iterations >= Int(KeyManager.minimumIterationCount))
        #expect(configuration.salt != salt)
        #expect(try session.decrypt(encrypted) == plaintext)
    }

    @Test("legacy Keychain keys are wrapped and removed after a successful migration")
    @MainActor
    func legacyKeychainKeyMigratesWithoutChangingMessages() async throws {
        let container = try makeModelContainer()
        let context = ModelContext(container)
        let account = "aes128-test-\(UUID().uuidString)"
        let password = "legacy vault password"
        let salt = Data(repeating: 0x77, count: KeyManager.saltLength)
        var legacyKeys = try KeyManager.deriveWrappingKeys(
            from: password,
            salt: salt,
            iterations: 1_000
        )
        defer { legacyKeys.wipe() }
        var combinedKey = legacyKeys.combinedKey
        defer { CryptoEngine.wipe(&combinedKey) }
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecValueData as String: combinedKey
        ]
        let cleanupQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account
        ]
        defer { SecItemDelete(cleanupQuery as CFDictionary) }
        try #require(SecItemAdd(query as CFDictionary, nil) == errSecSuccess)

        let configuration = CryptoConfiguration(salt: salt, iterations: 1_000)
        context.insert(configuration)
        let plaintext = Data("Existing encrypted message".utf8)
        let encrypted = try MessageCrypto.encrypt(
            plaintext: plaintext,
            encryptionKey: legacyKeys.encryptionKey,
            authenticationKey: legacyKeys.authenticationKey
        )
        context.insert(StoredMessage(
            iv: encrypted.iv,
            ciphertext: encrypted.ciphertext,
            tag: encrypted.tag
        ))
        try context.save()

        let session = CryptoSession(legacyKeychainAccount: account)
        await session.unlock(password: password, modelContext: context)

        #expect(session.isUnlocked)
        #expect(configuration.wrappedKeyCiphertext != nil)
        #expect(configuration.iterations >= Int(KeyManager.minimumIterationCount))
        #expect(try KeyManager.loadLegacyVaultKey(account: account) == nil)
        #expect(try session.decrypt(encrypted) == plaintext)
    }

    @Test("a restored legacy vault can validate its password without a Keychain entry")
    @MainActor
    func legacyVaultRestoresFromEncryptedMessages() async throws {
        let container = try makeModelContainer()
        let context = ModelContext(container)
        let password = "restored vault password"
        let salt = Data(repeating: 0x88, count: KeyManager.saltLength)
        var legacyKeys = try KeyManager.deriveWrappingKeys(
            from: password,
            salt: salt,
            iterations: 1_000
        )
        defer { legacyKeys.wipe() }
        let plaintext = Data("Message restored from a backup".utf8)
        let encrypted = try MessageCrypto.encrypt(
            plaintext: plaintext,
            encryptionKey: legacyKeys.encryptionKey,
            authenticationKey: legacyKeys.authenticationKey
        )
        context.insert(CryptoConfiguration(salt: salt, iterations: 1_000))
        context.insert(StoredMessage(
            iv: encrypted.iv,
            ciphertext: encrypted.ciphertext,
            tag: encrypted.tag
        ))
        try context.save()

        let session = CryptoSession(legacyKeychainAccount: UUID().uuidString)
        await session.unlock(password: "wrong password", modelContext: context)
        #expect(!session.isUnlocked)

        await session.unlock(password: password, modelContext: context)
        #expect(session.isUnlocked)
        #expect(try session.decrypt(encrypted) == plaintext)
    }

    @Test("message display uses cached plaintext and reports distinct failure categories")
    @MainActor
    func messageDisplayCachesDecryptionResults() async throws {
        let container = try makeModelContainer()
        let context = ModelContext(container)
        let session = CryptoSession(legacyKeychainAccount: UUID().uuidString)
        await session.unlock(password: "cache test password", modelContext: context)
        try #require(session.isUnlocked)

        let viewModel = MessageListViewModel(modelContext: context, session: session)
        viewModel.draft = "Cached message"
        viewModel.sendMessage()
        let storedMessage = try #require(viewModel.messages.first)
        var tamperedTag = storedMessage.tag
        tamperedTag[0] ^= 0x01
        storedMessage.tag = tamperedTag

        #expect(viewModel.displayText(for: storedMessage) == "Cached message")
        viewModel.refresh()
        #expect(viewModel.displayText(for: storedMessage) == "[message authentication failed]")

        let invalidText = try session.encrypt(Data([0xff]))
        let invalidTextMessage = StoredMessage(
            iv: invalidText.iv,
            ciphertext: invalidText.ciphertext,
            tag: invalidText.tag
        )
        let invalidFormatMessage = StoredMessage(
            iv: Data(),
            ciphertext: Data(),
            tag: Data()
        )
        context.insert(invalidTextMessage)
        context.insert(invalidFormatMessage)
        try context.save()
        viewModel.refresh()

        #expect(viewModel.displayText(for: invalidTextMessage) == "[message is not valid UTF-8]")
        #expect(viewModel.displayText(for: invalidFormatMessage) == "[message format is invalid]")

        viewModel.draft = "Unsent plaintext"
        viewModel.lockVault()
        #expect(!session.isUnlocked)
        #expect(viewModel.draft.isEmpty)
        #expect(viewModel.displayText(for: storedMessage) == "[message is unavailable]")
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

    @MainActor
    private func makeModelContainer() throws -> ModelContainer {
        let schema = Schema([StoredMessage.self, CryptoConfiguration.self])
        let configuration = ModelConfiguration(
            schema: schema,
            isStoredInMemoryOnly: true
        )
        return try ModelContainer(for: schema, configurations: [configuration])
    }
}
