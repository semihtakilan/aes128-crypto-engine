//
//  UnlockView.swift
//  AES128CryptoEngine
//
//  Created by Semih TAKILAN on 01.09.2026.
//

import SwiftUI

struct UnlockView: View {
    @Environment(\.modelContext) private var modelContext
    @ObservedObject var session: CryptoSession
    @State private var password = ""

    var body: some View {
        VStack(spacing: 24) {
            Spacer()

            Image(systemName: "lock.shield")
                .font(.system(size: 56))
                .foregroundStyle(.green)

            VStack(spacing: 8) {
                Text("AES128CryptoEngine")
                    .font(.title2.weight(.semibold))
                    .fontDesign(.monospaced)
                Text("Educational encrypted local storage")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }

            SecureField("Password", text: $password)
                .textFieldStyle(.roundedBorder)
                .fontDesign(.monospaced)
                .submitLabel(.go)
                .onSubmit(unlock)

            Button(action: unlock) {
                Label("Unlock vault", systemImage: "arrow.right.circle.fill")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .tint(.green)
            .disabled(password.isEmpty)

            if let errorMessage = session.errorMessage {
                Text(errorMessage)
                    .font(.footnote)
                    .foregroundStyle(.red)
                    .multilineTextAlignment(.center)
            }

            Spacer()

            Text("For education and validation only — never use in production.")
                .font(.caption2)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
        }
        .padding(32)
        .fontDesign(.monospaced)
    }

    private func unlock() {
        session.unlock(password: password, modelContext: modelContext)
        if session.isUnlocked {
            password = ""
        }
    }
}
