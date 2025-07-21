//
//  VerifyAttestationRequest.swift
//  AppAttestShared
//
//  Created by Wilson Goode on 7/21/25.
//

import Foundation

/// AppAttest verify attestation request
///
/// This request contains the attestation, key ID, and challenge ID
public struct VerifyAttestationRequest: Sendable, Codable {
    public var attestation: Data
    public var keyID: Data
    public var challengeID: UUID
    
    public init(attestation: Data, keyID: Data, challengeID: UUID) {
        self.attestation = attestation
        self.keyID = keyID
        self.challengeID = challengeID
    }
}
