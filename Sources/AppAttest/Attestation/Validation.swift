//
//  Validation.swift
//  
//
//  Created by Ian Sampson on 2020-12-18.
//

import Foundation
import Crypto
import Anchor

extension Attestation {
    enum ValidationError: Error {
        case invalidNonce
        case invalidAppIDHash
        case invalidPublicKey
        case invalidCounter
        case invalidCredentialID
    }
    // TODO: Rewrite as a struct with expected and received
    // or with compared values. Or add associated types.
    
    func verify(challenge: Data, appID: String, keyID: Data, date: Date? = nil) throws {
        // 1.
        try verifyCertificates(date: date)
        // Fails to validate leaf certificate
        
        // 2 & 3.
        let nonce = self.nonce(for: challenge)
        
        // 4.
        let octet = try extractOctet()
        guard octet == Array(nonce) else {
            throw ValidationError.invalidNonce
        }
        
        // 5.
        guard publicKeyMatchesKeyID(keyID) else {
            throw ValidationError.invalidPublicKey
        }
        
        // 6.
        guard authenticatorData.verifyAppID(appID) else {
            throw ValidationError.invalidAppIDHash
        }
        
        // 7.
        guard authenticatorData.verifyCounter(isAttestation: true) else {
            throw ValidationError.invalidCounter
        }
        
        // 8.
        // Already checked aaguid.
        // However we could change that to a method,
        // e.g. verifyAAGUID or extractAAGUID.
        
        // 9.
        guard authenticatorData.verifyKeyID(keyID) else {
            throw ValidationError.invalidCredentialID
        }
    }
    
    /// 1. Verify that the x5c array contains the intermediate and leaf certificates for App Attest,
    /// starting from the credential certificate stored in the first data buffer in the array (credcert).
    /// Verify the validity of the certificates using [Apple’s App Attest root certificate](https://www.apple.com/certificateauthority/private/).
    func verifyCertificates(date: Date?) throws {
        let anchor = try X509.Certificate(
            base64Encoded: Certificates.appleAppAttestationRootCA,
            format: .der
        )
        
        let _ = try X509.Chain(trustAnchor: anchor)
            .validatingAndAppending(
                certificates: statement.certificates.reversed(),
                posixTime: date?.timeIntervalSince1970
            )
    }
    
    /// 2. Create clientDataHash as the SHA256 hash of the one-time challenge sent to your app
    /// before performing the attestation, and append that hash to the end of the authenticator data
    /// (authData from the decoded object).
    /// 3. Generate a new SHA256 hash of the composite item to create nonce.
    func nonce(for challenge: Data) -> SHA256.Digest {
        let clientDataHash = SHA256.hash(data: challenge)
        return SHA256.hash(data: authenticatorData.bytes + clientDataHash)
    }
    
    /// 4. Obtain the value of the credCert extension with OID 1.2.840.113635.100.8.2,
    /// which is a DER-encoded ASN.1 sequence. Decode the sequence and extract
    /// the single octet string that it contains. Verify that the string equals nonce.
    // See extractOctet()
    
    /// 5. Create the SHA256 hash of the public key in credCert, and verify that it matches
    /// the key identifier from your app.
    func publicKeyMatchesKeyID(_ keyID: Data) -> Bool {
        let certificate = statement.certificates[0]
        guard let publicKey = certificate.publicKey else {
            return false
            //fatalError()
            // TODO: Throw meaningful error.
        }
        let hash = SHA256.hash(data: publicKey)
        return hash == keyID
    }
}
