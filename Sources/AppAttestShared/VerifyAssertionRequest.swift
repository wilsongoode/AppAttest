//
//  VerifyAssertionRequest.swift
//  AppAttestShared
//
//  Created by Wilson Goode on 7/21/25.
//

import Foundation

/// AppAttest verify assertion request
///
/// This request contains the assertion, key ID, and challenge ID
public struct VerifyAssertionRequest: Sendable, Codable {
    public var assertion: Data
    public var keyID: Data
    public var challengeID: UUID
    
    public init(assertion: Data, keyID: Data, challengeID: UUID) {
        self.assertion = assertion
        self.keyID = keyID
        self.challengeID = challengeID
    }
}
