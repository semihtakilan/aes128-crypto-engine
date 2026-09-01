//
//  StoredMessage.swift
//  AES128CryptoEngine
//
//  Created by Semih TAKILAN on 01.09.2026.
//

import Foundation
import SwiftData

@Model
final class StoredMessage: Identifiable {
    @Attribute(.unique) var id: UUID
    var iv: Data
    var ciphertext: Data
    var tag: Data
    var createdAt: Date

    init(
        iv: Data,
        ciphertext: Data,
        tag: Data,
        createdAt: Date = .now
    ) {
        self.id = UUID()
        self.iv = iv
        self.ciphertext = ciphertext
        self.tag = tag
        self.createdAt = createdAt
    }
}
