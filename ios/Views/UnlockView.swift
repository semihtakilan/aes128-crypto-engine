//
//  UnlockView.swift
//  AES128CryptoEngine
//
//  Created by Semih TAKILAN on 01.09.2026.
//

import SwiftData
import SwiftUI

struct UnlockView: View {
    private enum FocusField: Hashable {
        case password
        case confirmation
    }

    @Environment(\.modelContext) private var modelContext
    @Query private var configurations: [CryptoConfiguration]
    @ObservedObject var session: CryptoSession
    @State private var password = ""
    @State private var confirmationPassword = ""
    @FocusState private var focusedField: FocusField?

    private var isCreatingVault: Bool {
        configurations.isEmpty
    }

    private var passwordsMatch: Bool {
        password == confirmationPassword
    }

    private var canSubmit: Bool {
        guard !password.isEmpty else {
            return false
        }

        if isCreatingVault {
            return !confirmationPassword.isEmpty && passwordsMatch
        }

        return true
    }

    var body: some View {
        ZStack {
            Color.black
                .ignoresSafeArea()

            ScrollView {
                VStack(alignment: .leading, spacing: 28) {
                    header
                    securitySummary
                    passwordForm

                    if let errorMessage = session.errorMessage {
                        errorCard(message: errorMessage)
                    }

                    footer
                }
                .frame(maxWidth: 520)
                .padding(.horizontal, 24)
                .padding(.vertical, 32)
                .frame(maxWidth: .infinity)
            }
            .scrollDismissesKeyboard(.interactively)
        }
        .fontDesign(.monospaced)
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 18) {
            HStack(spacing: 12) {
                Image(systemName: isCreatingVault ? "lock.shield.fill" : "lock.open.fill")
                    .font(.title2.weight(.bold))
                    .foregroundStyle(.black)
                    .frame(width: 48, height: 48)
                    .background(Color.green)
                    .clipShape(RoundedRectangle(cornerRadius: 14))

                VStack(alignment: .leading, spacing: 4) {
                    Text("AES128CryptoEngine")
                        .font(.headline.weight(.bold))
                    Text("LOCAL ENCRYPTED VAULT")
                        .font(.caption2.weight(.semibold))
                        .foregroundStyle(.green)
                }
            }

            VStack(alignment: .leading, spacing: 8) {
                ViewThatFits(in: .horizontal) {
                    Text(isCreatingVault ? "Create your vault" : "Unlock your vault")
                        .lineLimit(1)
                        .fixedSize(horizontal: true, vertical: false)
                    Text(isCreatingVault ? "Create your\nvault" : "Unlock your\nvault")
                }
                .font(.system(.title, design: .monospaced).weight(.bold))

                Text(
                    isCreatingVault
                        ? "Choose the password that will protect your local encrypted messages."
                        : "Enter the password you chose when this vault was created."
                )
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private var securitySummary: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label("On-device only", systemImage: "iphone")
            Label("No account or network connection", systemImage: "wifi.slash")
            Label("Password derives separate encryption and MAC keys", systemImage: "key.fill")
        }
        .font(.footnote)
        .foregroundStyle(.secondary)
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.white.opacity(0.06))
        .overlay {
            RoundedRectangle(cornerRadius: 14)
                .stroke(Color.green.opacity(0.25), lineWidth: 1)
        }
        .clipShape(RoundedRectangle(cornerRadius: 14))
    }

    private var passwordForm: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(isCreatingVault ? "Create password" : "Vault password")
                .font(.headline)

            SecureField(
                isCreatingVault ? "Choose a password" : "Enter your password",
                text: $password
            )
            .textInputAutocapitalization(.never)
            .autocorrectionDisabled()
            .textFieldStyle(.roundedBorder)
            .focused($focusedField, equals: .password)
            .submitLabel(isCreatingVault ? .next : .go)
            .onSubmit {
                if isCreatingVault {
                    focusedField = .confirmation
                } else {
                    unlock()
                }
            }

            if isCreatingVault {
                SecureField("Confirm password", text: $confirmationPassword)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .textFieldStyle(.roundedBorder)
                    .focused($focusedField, equals: .confirmation)
                    .submitLabel(.go)
                    .onSubmit(unlock)

                if !confirmationPassword.isEmpty && !passwordsMatch {
                    Label("Passwords do not match.", systemImage: "exclamationmark.circle")
                        .font(.caption)
                        .foregroundStyle(.orange)
                }

                Text("This password cannot be recovered. Keep it somewhere safe.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Button(action: unlock) {
                Group {
                    if session.isWorking {
                        ProgressView()
                            .tint(.black)
                    } else {
                        Label(
                            isCreatingVault ? "Create encrypted vault" : "Unlock vault",
                            systemImage: isCreatingVault ? "plus.lock.fill" : "arrow.right.circle.fill"
                        )
                    }
                }
                .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .tint(.green)
            .disabled(!canSubmit || session.isWorking)
        }
    }

    private func errorCard(message: String) -> some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: "xmark.octagon.fill")
                .foregroundStyle(.red)

            VStack(alignment: .leading, spacing: 6) {
                Text(isCreatingVault ? "Vault could not be created" : "Vault could not be unlocked")
                    .font(.subheadline.weight(.semibold))
                Text(message)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Text("No vault data was changed. Resolve the issue and try again.")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.red.opacity(0.12))
        .overlay {
            RoundedRectangle(cornerRadius: 14)
                .stroke(Color.red.opacity(0.35), lineWidth: 1)
        }
        .clipShape(RoundedRectangle(cornerRadius: 14))
    }

    private var footer: some View {
        Text("Educational project • No account • No server • Never use for production secrets")
            .font(.caption2)
            .foregroundStyle(.secondary)
            .multilineTextAlignment(.center)
            .frame(maxWidth: .infinity)
    }

    private func unlock() {
        guard canSubmit else {
            return
        }

        session.unlock(password: password, modelContext: modelContext)
        if session.isUnlocked {
            password = ""
            confirmationPassword = ""
            focusedField = nil
        }
    }
}
