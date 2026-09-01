//
//  AppPresentationTests.swift
//  AES128CryptoEngine
//
//  Created by Semih TAKILAN on 01.09.2026.
//

import Foundation
import Testing

@Suite("App presentation")
struct AppPresentationTests {
    @Test("the app declares a launch screen to avoid compatibility letterboxing")
    func appDeclaresLaunchScreen() {
        #expect(Bundle.main.object(forInfoDictionaryKey: "UILaunchScreen") is [String: Any])
    }
}
