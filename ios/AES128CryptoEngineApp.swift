//
//  AES128CryptoEngineApp.swift
//  AES128CryptoEngine
//
//  Created by Semih TAKILAN on 01.09.2026.
//

import SwiftData
import SwiftUI

@main
struct AES128CryptoEngineApp: App {
    var body: some Scene {
        WindowGroup {
            RootView()
        }
        .modelContainer(for: [StoredMessage.self, CryptoConfiguration.self])
    }
}
