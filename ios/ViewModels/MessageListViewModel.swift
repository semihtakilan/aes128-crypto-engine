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
            messages = try modelContext.fetch(descriptor)
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
            let encryptedMessage = try session.encrypt(Data(draft.utf8))
            let storedMessage = StoredMessage(
                iv: encryptedMessage.iv,
                ciphertext: encryptedMessage.ciphertext,
                tag: encryptedMessage.tag
            )
            modelContext.insert(storedMessage)
            try modelContext.save()
            messages.append(storedMessage)
            draft = ""
            errorMessage = nil
        } catch {
            errorMessage = String(describing: error)
        }
    }

    func displayText(for message: StoredMessage) -> String {
        do {
            let encryptedMessage = EncryptedMessage(
                iv: message.iv,
                ciphertext: message.ciphertext,
                tag: message.tag
            )
            let plaintext = try session.decrypt(encryptedMessage)
            return String(data: plaintext, encoding: .utf8)
                ?? "[message is not valid UTF-8]"
        } catch {
            return "[message authentication failed]"
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
