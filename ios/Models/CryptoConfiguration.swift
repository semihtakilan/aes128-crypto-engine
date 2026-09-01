//
//  CryptoConfiguration.swift
//  AES128CryptoEngine
//
//  Created by Semih TAKILAN on 01.09.2026.
//

import Foundation
import SwiftData

@Model
final class CryptoConfiguration {
    @Attribute(.unique) var id: UUID
    var salt: Data
    var iterations: Int
    // Optional fields allow existing stores to migrate before their keys are wrapped.
    var wrappedKeyIV: Data?
    var wrappedKeyCiphertext: Data?
    var wrappedKeyTag: Data?

    init(
        salt: Data,
        iterations: Int,
        wrappedKeyIV: Data? = nil,
        wrappedKeyCiphertext: Data? = nil,
        wrappedKeyTag: Data? = nil
    ) {
        self.id = UUID()
        self.salt = salt
        self.iterations = iterations
        self.wrappedKeyIV = wrappedKeyIV
        self.wrappedKeyCiphertext = wrappedKeyCiphertext
        self.wrappedKeyTag = wrappedKeyTag
    }
}
