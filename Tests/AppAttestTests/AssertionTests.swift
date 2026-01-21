//
//  AssertionTests.swift
//  AppAttest
//
//  Created by Wilson Goode on 1/20/26.
//

import Testing
import Foundation
import Crypto
@testable import AppAttest

@Suite("Assertion Diagnostic Tests")
struct AssertionTests {
    // Using the provided iOS 14.3 sample data
    let sample = AssertionSample.iOS14_3.encoded
    
    @Test("1. Public Key Byte Integrity")
    func testPublicKeyBytes() throws {
        let keyData = sample.publicKey
        
        // Uncompressed P-256 keys are 1 byte header (0x04) + 32 bytes X + 32 bytes Y = 65 bytes.
        #expect(keyData.count == 65, "Key should be 65 bytes. Found \(keyData.count).")
        #expect(keyData[0] == 0x04, "Uncompressed P-256 keys must start with 0x04. Found \(keyData[0]).")
    }
    
    @Test("2. PublicKey Round-trip")
    func testPublicKeyRoundTrip() throws {
        let originalBytes = sample.publicKey
        let publicKey = try P256.Signing.PublicKey(x963Representation: originalBytes)
        
        let exportedBytes = publicKey.x963Representation
        #expect(originalBytes == exportedBytes, "PublicKey re-export must match original input bytes.")
    }
    
    @Test("3. RP ID Hash Alignment (Step 4 of Verification)")
    func testRPIDHash() throws {
        let assertion = try Assertion(cbor: sample.assertion)
        let authData = assertion.authenticatorData
        
        // Step 4: appID = TeamID + "." + BundleID
        let appID = "\(sample.teamID).\(sample.bundleID)"
        let expectedHash = Data(SHA256.hash(data: Data(appID.utf8)))
        
        #expect(authData.rpID.count == 32, "RP ID Hash must be 32 bytes.")
        #expect(authData.rpID == expectedHash, "Computed RP ID hash does not match AuthenticatorData. Check for typos in App ID or Team ID.")
    }
    
    @Test("4. Signature Parsing Sanity")
    func testSignatureParsing() throws {
        let assertion = try Assertion(cbor: sample.assertion)
        let sigData = assertion.signature
        
        #expect(sigData.count > 60, "DER signatures are typically 70-72 bytes. Found \(sigData.count).")
        #expect(sigData[sigData.startIndex] == 0x30, "DER signature must start with sequence byte 0x30.")
        
        // Ensure CryptoKit accepts the DER representation
        #expect(throws: Never.self) {
            _ = try P256.Signing.ECDSASignature(derRepresentation: sigData)
        }
    }
    
    @Test("5. AuthenticatorData Geometry")
    func testAuthDataGeometry() throws {
        let assertion = try Assertion(cbor: sample.assertion)
        let bytes = assertion.authenticatorData.bytes
        
        #expect(bytes.count == 37, "AuthenticatorData for assertions must be exactly 37 bytes.")
        
        // Bytes 33-36 are the counter.
        // Index check: authData[32] is flags. authData[33..36] is counter.
        let counterBytes = bytes[bytes.startIndex+33..<bytes.startIndex+37]
        #expect(counterBytes.count == 4)
    }

    @Test("6. Full Verification Logic")
    func testFullVerification() throws {
        let assertion = try Assertion(cbor: sample.assertion)
        let publicKey = try P256.Signing.PublicKey(x963Representation: sample.publicKey)
        let appID = "\(sample.teamID).\(sample.bundleID)"
        
        // This is the specific test that was failing with .invalidSignature
        try assertion.verify(
            clientData: sample.clientData,
            publicKey: publicKey,
            appID: appID,
            previousCounter: 0,
            receivedChallenge: sample.receivedChallenge,
            storedChallenge: sample.storedChallenge
        )
    }
    
    @Test("Fail verification when client data is tampered")
    func testSignatureVerificationFailure() throws {
        let assertion = try Assertion(cbor: sample.assertion)
        let publicKey = try P256.Signing.PublicKey(x963Representation: sample.publicKey)
        let appID = "\(sample.teamID).\(sample.bundleID)"
        
        // Changing even one byte of client data should invalidate the signature
        var tamperedClientData = sample.clientData
        tamperedClientData.append(0x00)
        
        #expect(throws: Assertion.ValidationError.invalidSignature) {
            try assertion.verify(
                clientData: tamperedClientData,
                publicKey: publicKey,
                appID: appID,
                previousCounter: 0,
                receivedChallenge: sample.receivedChallenge,
                storedChallenge: sample.storedChallenge
            )
        }
    }
    
    @Test("Verify counter increment logic")
    func testCounterValidation() throws {
        let assertion = try Assertion(cbor: sample.assertion)
        let publicKey = try P256.Signing.PublicKey(x963Representation: sample.publicKey)
        let appID = "\(sample.teamID).\(sample.bundleID)"
        
        // Current counter is 1. Verification should fail if previous counter >= 1.
        #expect(throws: Assertion.ValidationError.invalidCounter) {
            try assertion.verify(
                clientData: sample.clientData,
                publicKey: publicKey,
                appID: appID,
                previousCounter: 1, 
                receivedChallenge: sample.receivedChallenge,
                storedChallenge: sample.storedChallenge
            )
        }
    }
    
    @Test("Verify challenge matching")
    func testChallengeMismatch() throws {
        let assertion = try Assertion(cbor: sample.assertion)
        let publicKey = try P256.Signing.PublicKey(x963Representation: sample.publicKey)
        let appID = "\(sample.teamID).\(sample.bundleID)"
        
        let differentChallenge = Data("not-the-right-challenge".utf8)
        
        #expect(throws: Assertion.ValidationError.invalidClientData) {
            try assertion.verify(
                clientData: sample.clientData,
                publicKey: publicKey,
                appID: appID,
                previousCounter: 0,
                receivedChallenge: sample.receivedChallenge,
                storedChallenge: differentChallenge
            )
        }
    }
}
