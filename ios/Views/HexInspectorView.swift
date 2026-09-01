//
//  HexInspectorView.swift
//  AES128CryptoEngine
//
//  Created by Semih TAKILAN on 01.09.2026.
//

import SwiftUI

struct HexInspectorView: View {
    let message: StoredMessage
    @ObservedObject var viewModel: MessageListViewModel
    @Environment(\.dismiss) private var dismiss
    @State private var tamperResult: TamperResult?

    var body: some View {
        NavigationStack {
            List {
                Section {
                    VStack(alignment: .leading, spacing: 8) {
                        Label("Authenticated message", systemImage: "checkmark.shield.fill")
                            .font(.headline)
                            .foregroundStyle(.green)
                        Text("These are the exact bytes stored for this message. The plaintext is not stored.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    .padding(.vertical, 4)
                }

                HexSection(
                    title: "IV",
                    value: viewModel.hexadecimal(message.iv),
                    byteCount: message.iv.count
                )
                HexSection(
                    title: "Ciphertext",
                    value: viewModel.hexadecimal(message.ciphertext),
                    byteCount: message.ciphertext.count
                )
                HexSection(
                    title: "MAC tag",
                    value: viewModel.hexadecimal(message.tag),
                    byteCount: message.tag.count
                )

                Section {
                    Button {
                        tamperResult = viewModel.tamper(message)
                    } label: {
                        Label("Flip one ciphertext bit", systemImage: "exclamationmark.triangle")
                            .foregroundStyle(.orange)
                    }

                    if let tamperResult {
                        Label(
                            tamperResult.message,
                            systemImage: tamperResult.isSafe ? "checkmark.circle.fill" : "xmark.circle.fill"
                        )
                        .font(.footnote)
                        .foregroundStyle(tamperResult.isSafe ? .green : .red)
                    }
                } footer: {
                    Text("This test changes a copy of the ciphertext without changing the stored MAC tag. The saved message is never modified.")
                }
            }
            .listStyle(.insetGrouped)
            .navigationTitle("Hex Inspector")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Done") {
                        dismiss()
                    }
                }
            }
        }
        .fontDesign(.monospaced)
    }
}

private struct HexSection: View {
    let title: String
    let value: String
    let byteCount: Int

    var body: some View {
        Section(title) {
            VStack(alignment: .leading, spacing: 8) {
                Text("\(byteCount) bytes")
                    .font(.caption2)
                    .foregroundStyle(.secondary)

                Text(value)
                    .font(.footnote)
                    .textSelection(.enabled)
                    .textCase(nil)
            }
        }
    }
}
