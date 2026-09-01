//
//  MessageListView.swift
//  AES128CryptoEngine
//
//  Created by Semih TAKILAN on 01.09.2026.
//

import SwiftData
import SwiftUI

struct MessageListView: View {
    @ObservedObject private var session: CryptoSession
    @StateObject private var viewModel: MessageListViewModel
    @State private var selectedMessage: StoredMessage?

    init(session: CryptoSession, modelContext: ModelContext) {
        self.session = session
        _viewModel = StateObject(
            wrappedValue: MessageListViewModel(
                modelContext: modelContext,
                session: session
            )
        )
    }

    var body: some View {
        NavigationStack {
            Group {
                if viewModel.messages.isEmpty {
                    ContentUnavailableView(
                        "No encrypted messages",
                        systemImage: "lock.open.display",
                        description: Text("Write a message to create the first ciphertext.")
                    )
                } else {
                    ScrollView {
                        LazyVStack(alignment: .leading, spacing: 12) {
                            ForEach(viewModel.messages) { message in
                                MessageBubbleView(
                                    text: viewModel.displayText(for: message),
                                    date: message.createdAt
                                )
                                .onLongPressGesture {
                                    selectedMessage = message
                                }
                            }
                        }
                        .padding()
                    }
                }
            }
            .safeAreaInset(edge: .bottom) {
                composer
            }
            .navigationTitle("Encrypted Messages")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Lock", systemImage: "lock.fill") {
                        session.lock()
                    }
                    .tint(.green)
                }
            }
            .sheet(item: $selectedMessage) { message in
                HexInspectorView(message: message, viewModel: viewModel)
            }
        }
        .fontDesign(.monospaced)
    }

    private var composer: some View {
        HStack(alignment: .bottom, spacing: 8) {
            TextField("Write an encrypted message", text: $viewModel.draft, axis: .vertical)
                .textFieldStyle(.roundedBorder)
                .lineLimit(1...5)

            Button(action: viewModel.sendMessage) {
                Image(systemName: "arrow.up.circle.fill")
                    .font(.title2)
                    .foregroundStyle(.green)
            }
            .disabled(viewModel.draft.isEmpty)
        }
        .padding(.horizontal)
        .padding(.vertical, 8)
        .background(.thinMaterial)
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
    }
}
