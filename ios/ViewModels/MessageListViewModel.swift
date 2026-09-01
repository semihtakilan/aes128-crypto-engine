//
//  MessageListViewModel.swift
//  AES128CryptoEngine
//
//  Created by Semih TAKILAN on 01.09.2026.
//

import Combine
import Foundation
import SwiftData

enum TamperResult {
    case rejected
    case accepted
    case failed(String)

    var message: String {
        switch self {
        case .rejected:
            return "Tampering rejected: MAC verification failed before decryption."
        case .accepted:
            return "Warning: tampered data was accepted."
        case .failed(let reason):
            return "Tampering test failed: \(reason)"
        }
    }

    var isSafe: Bool {
        if case .rejected = self {
            return true
        }
        return false
    }
}

@MainActor
final class MessageListViewModel: ObservableObject {
    @Published private(set) var messages: [StoredMessage] = []
    @Published var draft = ""
    @Published private(set) var errorMessage: String?
    @Published private var displayedTextByMessageID: [UUID: String] = [:]

    private let modelContext: ModelContext
    private let session: CryptoSession

    init(modelContext: ModelContext, session: CryptoSession) {
        self.modelContext = modelContext
        self.session = session
        refresh()
    }

    func refresh() {
        do {
            let descriptor = FetchDescriptor<StoredMessage>(
                sortBy: [SortDescriptor(\.createdAt)]
            )
            let fetchedMessages = try modelContext.fetch(descriptor)
            var displayedText: [UUID: String] = [:]
            displayedText.reserveCapacity(fetchedMessages.count)

            for message in fetchedMessages {
                displayedText[message.id] = decryptDisplayText(for: message)
            }

            messages = fetchedMessages
            displayedTextByMessageID = displayedText
            errorMessage = nil
        } catch {
            errorMessage = String(describing: error)
        }
    }

    func sendMessage() {
        guard !draft.isEmpty else {
            return
        }

        do {
            let plaintext = draft
            let encryptedMessage = try session.encrypt(Data(plaintext.utf8))
            let storedMessage = StoredMessage(
                iv: encryptedMessage.iv,
                ciphertext: encryptedMessage.ciphertext,
                tag: encryptedMessage.tag
            )
            modelContext.insert(storedMessage)
            try modelContext.save()
            messages.append(storedMessage)
            displayedTextByMessageID[storedMessage.id] = plaintext
            draft = ""
            errorMessage = nil
        } catch {
            errorMessage = String(describing: error)
        }
    }

    func displayText(for message: StoredMessage) -> String {
        displayedTextByMessageID[message.id] ?? "[message is unavailable]"
    }

    func lockVault() {
        displayedTextByMessageID.removeAll()
        draft = ""
        session.lock()
    }

    private func decryptDisplayText(for message: StoredMessage) -> String {
        do {
            let encryptedMessage = EncryptedMessage(
                iv: message.iv,
                ciphertext: message.ciphertext,
                tag: message.tag
            )
            var plaintext = try session.decrypt(encryptedMessage)
            defer { CryptoEngine.wipe(&plaintext) }
            return String(data: plaintext, encoding: .utf8)
                ?? "[message is not valid UTF-8]"
        } catch let error as MessageCryptoError {
            switch error {
            case .authenticationFailed:
                return "[message authentication failed]"
            case .invalidIVLength, .invalidCiphertext, .invalidTagLength:
                return "[message format is invalid]"
            default:
                return "[message cryptography failed]"
            }
        } catch CryptoEngineError.decryptionFailed(let status) {
            if status == AES_CBC_INVALID_PADDING {
                return "[message padding is invalid]"
            }
            return "[message decryption failed]"
        } catch CryptoSessionError.locked {
            return "[vault is locked]"
        } catch {
            return "[message could not be decrypted]"
        }
    }

    func hexadecimal(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }

    func tamper(_ message: StoredMessage) -> TamperResult {
        guard !message.ciphertext.isEmpty else {
            return .failed("ciphertext is empty")
        }

        var ciphertext = message.ciphertext
        ciphertext[0] ^= 0x01
        let tamperedMessage = EncryptedMessage(
            iv: message.iv,
            ciphertext: ciphertext,
            tag: message.tag
        )

        do {
            _ = try session.decrypt(tamperedMessage)
            return .accepted
        } catch MessageCryptoError.authenticationFailed {
            return .rejected
        } catch {
            return .failed(String(describing: error))
        }
    }
}
