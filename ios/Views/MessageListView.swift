//
//  MessageListView.swift
//  AES128CryptoEngine
//
//  Created by Semih TAKILAN on 01.09.2026.
//

import SwiftData
import SwiftUI

struct MessageListView: View {
    @StateObject private var viewModel: MessageListViewModel
    @State private var selectedMessage: StoredMessage?

    init(session: CryptoSession, modelContext: ModelContext) {
        _viewModel = StateObject(
            wrappedValue: MessageListViewModel(
                modelContext: modelContext,
                session: session
            )
        )
    }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    vaultHeader

                    if viewModel.messages.isEmpty {
                        emptyState
                    } else {
                        LazyVStack(alignment: .leading, spacing: 12) {
                            ForEach(viewModel.messages) { message in
                                MessageBubbleView(
                                    text: viewModel.displayText(for: message),
                                    date: message.createdAt
                                )
                                .contentShape(Rectangle())
                                .onLongPressGesture {
                                    selectedMessage = message
                                }
                                .accessibilityHint("Long press to inspect the encrypted data.")
                            }
                        }
                    }

                    if let errorMessage = viewModel.errorMessage {
                        errorBanner(message: errorMessage)
                    }
                }
                .padding()
            }
            .scrollDismissesKeyboard(.interactively)
            .background(Color.black)
            .safeAreaInset(edge: .bottom) {
                composer
            }
            .navigationTitle("Vault")
            .navigationBarTitleDisplayMode(.inline)
            .toolbarBackground(Color.black, for: .navigationBar)
            .toolbarBackground(.visible, for: .navigationBar)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button {
                        viewModel.lockVault()
                    } label: {
                        Label("Lock vault", systemImage: "lock.fill")
                    }
                    .tint(.green)
                }
            }
            .sheet(item: $selectedMessage) { message in
                HexInspectorView(message: message, viewModel: viewModel)
                    .presentationDetents([.large])
                    .presentationDragIndicator(.visible)
            }
        }
        .fontDesign(.monospaced)
    }

    private var vaultHeader: some View {
        HStack(alignment: .top, spacing: 16) {
            VStack(alignment: .leading, spacing: 6) {
                Label("LOCAL VAULT", systemImage: "lock.shield.fill")
                    .font(.caption.weight(.bold))
                    .foregroundStyle(.green)
                Text("AES-128-CBC • HMAC-SHA256")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                Text("Messages are encrypted before they are saved.")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }

            Spacer(minLength: 12)

            VStack(alignment: .trailing, spacing: 4) {
                Text("\(viewModel.messages.count)")
                    .font(.title3.weight(.bold))
                    .foregroundStyle(.green)
                Text(viewModel.messages.count == 1 ? "message" : "messages")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.green.opacity(0.08))
        .overlay {
            RoundedRectangle(cornerRadius: 14)
                .stroke(Color.green.opacity(0.25), lineWidth: 1)
        }
        .clipShape(RoundedRectangle(cornerRadius: 14))
    }

    private var emptyState: some View {
        VStack(spacing: 12) {
            Image(systemName: "lock.open.display")
                .font(.system(size: 42))
                .foregroundStyle(.green)

            Text("Your vault is empty")
                .font(.headline)

            Text("Write a message below. It will be encrypted and authenticated before it is stored on this device.")
                .font(.footnote)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
        }
        .frame(maxWidth: .infinity)
        .padding(28)
        .background(Color.white.opacity(0.06))
        .clipShape(RoundedRectangle(cornerRadius: 14))
    }

    private func errorBanner(message: String) -> some View {
        Label(message, systemImage: "exclamationmark.triangle.fill")
            .font(.caption)
            .foregroundStyle(.orange)
            .padding(12)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color.orange.opacity(0.12))
            .clipShape(RoundedRectangle(cornerRadius: 10))
    }

    private var composer: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .bottom, spacing: 10) {
                TextField("Write a message to encrypt…", text: $viewModel.draft, axis: .vertical)
                    .textFieldStyle(.plain)
                    .lineLimit(1...5)
                    .padding(.horizontal, 14)
                    .padding(.vertical, 12)
                    .frame(minHeight: 48)
                    .tint(.green)
                    .background(Color.white.opacity(0.07), in: RoundedRectangle(cornerRadius: 12))

                Button(action: viewModel.sendMessage) {
                    Image(systemName: "arrow.up")
                        .font(.headline.weight(.bold))
                        .foregroundStyle(.black)
                        .frame(width: 48, height: 48)
                        .background(canSendMessage ? Color.green : Color.green.opacity(0.3), in: Circle())
                }
                .buttonStyle(.plain)
                .accessibilityLabel("Encrypt and save message")
                .disabled(!canSendMessage)
            }

            Text("Long press a message to inspect its IV, ciphertext, and MAC tag.")
                .font(.caption2)
                .foregroundStyle(.secondary)
        }
        .padding(.horizontal, 16)
        .padding(.top, 12)
        .padding(.bottom, 8)
        .background(.thinMaterial)
        .overlay(alignment: .top) {
            Rectangle()
                .fill(Color.green.opacity(0.2))
                .frame(height: 1)
        }
    }

    private var canSendMessage: Bool {
        !viewModel.draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }
}

private struct MessageBubbleView: View {
    let text: String
    let date: Date

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(text)
                .foregroundStyle(.primary)
            Text(date, format: .dateTime.hour().minute().second())
                .font(.caption2)
                .foregroundStyle(.secondary)
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.green.opacity(0.12))
        .clipShape(RoundedRectangle(cornerRadius: 10))
        .overlay {
            RoundedRectangle(cornerRadius: 10)
                .stroke(Color.green.opacity(0.35), lineWidth: 1)
        }
        .accessibilityElement(children: .combine)
    }
}
