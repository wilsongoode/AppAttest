//
//  AssertionPayload.swift
//  AppAttestShared
//
//  Created by Wilson Goode on 7/21/25.
//

import Foundation

/// AppAttest assertion payload
///
/// This payload contains the request payload and the challenge from the server
public struct AssertionPayload: Sendable, Codable {
    public var payload: Data
    public var challenge: Data
    
    public init(payload: Data, challenge: Data) {
        self.payload = payload
        self.challenge = challenge
    }
}
