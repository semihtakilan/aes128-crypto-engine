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

    init(salt: Data, iterations: Int) {
        self.id = UUID()
        self.salt = salt
        self.iterations = iterations
    }
}
