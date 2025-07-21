//
//  ChallengeResponse.swift
//  AppAttestShared
//
//  Created by Wilson Goode on 7/21/25.
//

import Foundation

/// AppAttest challenge response
///
/// This response contains the challenge from the server and the challenge ID
public struct ChallengeResponse: Sendable, Codable {
    public var challenge: Data
    public var challengeID: UUID
    
    public init(challenge: Data, challengeID: UUID) {
        self.challenge = challenge
        self.challengeID = challengeID
    }
}
