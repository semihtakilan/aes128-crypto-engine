//
//  RootView.swift
//  AES128CryptoEngine
//
//  Created by Semih TAKILAN on 01.09.2026.
//

import SwiftData
import SwiftUI

struct RootView: View {
    @Environment(\.modelContext) private var modelContext
    @StateObject private var session = CryptoSession()

    var body: some View {
        Group {
            if session.isUnlocked {
                MessageListView(session: session, modelContext: modelContext)
            } else {
                UnlockView(session: session)
            }
        }
        .preferredColorScheme(.dark)
    }
}
