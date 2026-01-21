//
//  Assertion.swift
//  
//
//  Created by Ian Sampson on 2020-12-21.
//

import Foundation
import Crypto
import SwiftCBOR

struct Assertion {
    let signature: Data
    let authenticatorData: AuthenticatorData
    
    init(cbor data: Data) throws {
        let decoder = CodableCBORDecoder()
        let decoded = try decoder.decode(CodableCBOR.self, from: data)
        signature = decoded.signature
        authenticatorData = try AuthenticatorData(bytes: decoded.authenticatorData)
    }
}

extension Assertion {
    struct CodableCBOR: Codable {
        let signature: Data
        let authenticatorData: Data
    }
}

extension Assertion {
    enum ValidationError: Error {
        case invalidSignature
        case invalidAppIDHash
        case invalidCounter
        case invalidClientData
    }
    
    func verify(
        clientData: Data,
        publicKey: P256.Signing.PublicKey,
        appID: String,
        previousCounter: Int?,
        receivedChallenge: Data,
        storedChallenge: Data
    ) throws {
        // 1 & 2.
        let nonce = self.nonce(clientData: clientData)
        
        // 3.
        try verifySignature(nonce: nonce, publicKey: publicKey)
        
        // 4.
        guard authenticatorData.verifyAppID(appID) else {
            throw ValidationError.invalidAppIDHash
        }

        // 5.
        guard authenticatorData.verifyCounter(isAttestation: false, previous: previousCounter) else {
            throw ValidationError.invalidCounter
        }

        // 6.
        try verify(receivedChallenge: receivedChallenge, storedChallenge: storedChallenge)
    }
    
    /// 1. Compute clientDataHash as the SHA256 hash of clientData.
    /// 2. Concatenate authenticatorData and clientDataHash
    /// and apply a SHA256 hash over the result to form nonce.
    func nonce(clientData: Data) -> SHA256.Digest {
        let clientDataHash = SHA256.hash(data: clientData)
        return SHA256.hash(data: authenticatorData.bytes + clientDataHash)
    }
    
    /// 3. Use the public key that you stored from the attestation object
    /// to verify that the assertion’s signature is valid for nonce.
    func verifySignature(nonce: SHA256.Digest, publicKey: P256.Signing.PublicKey) throws {
        let ecdsaSignature = try P256.Signing.ECDSASignature(derRepresentation: self.signature)
        guard publicKey.isValidSignature(ecdsaSignature, for: Data(nonce)) else {
            throw ValidationError.invalidSignature
        }
    }
    
    /// 6. Verify that the challenge used to generate the clientDataHash
    /// matches the challenge you sent to the app.
    func verify(receivedChallenge: Data, storedChallenge: Data) throws {
        guard receivedChallenge == storedChallenge else {
            throw ValidationError.invalidClientData
        }
    }
}

