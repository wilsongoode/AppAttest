import Testing
import Foundation
import Crypto
@testable import AppAttest

@Suite("Assertion Verification Tests")
struct AssertionTests {
    // Using the provided iOS 14.3 sample data
    let sample = AssertionSample.iOS14_3.encoded
    
    @Test("Successfully decode an assertion object")
    func testAssertionDecoding() throws {
        let assertion = try Assertion(cbor: sample.assertion)
        
        #expect(!assertion.signature.isEmpty, "Signature should not be empty")
        #expect(assertion.authenticatorData.bytes.count == 37, "Authenticator data for assertions must be exactly 37 bytes")
    }
    
    @Test("Verify authenticator data fields")
    func testAuthenticatorDataParsing() throws {
        let assertion = try Assertion(cbor: sample.assertion)
        let authData = assertion.authenticatorData
        
        // Validate RP ID Hash
        let appID = "\(sample.teamID).\(sample.bundleID)"
        let expectedRPIDHash = SHA256.hash(data: Data(appID.utf8))
        #expect(authData.rpID == Data(expectedRPIDHash), "RP ID Hash in authData should match SHA256 of App ID")
        
        // Validate Counter (Sample data has counter = 1)
        #expect(authData.counter == 1, "Counter should be correctly parsed from bytes 33-37")
    }
    
    @Test("Verify signature for valid sample data")
    func testSignatureVerificationSuccess() throws {
        let assertion = try Assertion(cbor: sample.assertion)
        let publicKey = try P256.Signing.PublicKey(x963Representation: sample.publicKey)
        let appID = "\(sample.teamID).\(sample.bundleID)"
        
        // This test replicates the 'verify' call with known good data.
        // If this fails, the issue is likely in nonce concatenation or public key format.
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