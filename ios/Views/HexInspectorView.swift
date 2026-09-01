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
                HexSection(title: "IV", value: viewModel.hexadecimal(message.iv))
                HexSection(
                    title: "Ciphertext",
                    value: viewModel.hexadecimal(message.ciphertext)
                )
                HexSection(title: "MAC tag", value: viewModel.hexadecimal(message.tag))

                Section {
                    Button {
                        tamperResult = viewModel.tamper(message)
                    } label: {
                        Label("Tamper ciphertext", systemImage: "exclamationmark.triangle")
                            .foregroundStyle(.orange)
                    }

                    if let tamperResult {
                        Text(tamperResult.message)
                            .font(.footnote)
                            .foregroundStyle(tamperResult.isSafe ? .green : .red)
                    }
                } footer: {
                    Text("The test flips one ciphertext bit without changing the stored MAC tag.")
                }
            }
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

    var body: some View {
        Section(title) {
            Text(value)
                .font(.footnote)
                .textSelection(.enabled)
                .textCase(nil)
        }
    }
}
