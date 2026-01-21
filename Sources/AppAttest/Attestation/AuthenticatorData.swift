//
//  AuthenticatorData.swift
//  
//
//  Created by Ian Sampson on 2020-12-18.
//

import Foundation
import Crypto

/// Authenticator data as specified by the
/// [Web Authentication](https://www.w3.org/TR/webauthn/#sec-authenticator-data) specification.
struct AuthenticatorData: Equatable {
    let bytes: Data
    
    enum Error: Swift.Error {
        case invalidAAGUID
        case invalidLength
    }
    
    init(bytes: Data) throws {
        guard bytes.count >= 37 else {
            throw Error.invalidLength
        }
        self.bytes = bytes
    }
    
    /// A hash of your app’s App ID, which is the concatenation of your 10-digit team identifier,
    /// a period, and your app’s CFBundleIdentifier value.
    var rpID: Data {
        bytes[0..<32]
    }
    
    /// The number of times your app used the attested key to sign an assertion.
    var counter: UInt32 {
        bytes[33..<37].reduce(0) { value, byte in
            value << 8 | UInt32(byte)
        }
    }
    
    /// Indicates whether attested credential data is included.
    var hasAttestedCredentialData: Bool {
        (bytes[32] & 0x40) != 0
    }
    
    /// An App Attest-specific constant that indicates whether the attested key belongs
    /// to the development or production environment.
    var aaguid: AAGUID? {
        guard hasAttestedCredentialData, bytes.count >= 53 else { return nil }
        return AAGUID(bytes: bytes[37..<53])
    }
    
    enum AAGUID: String, CaseIterable {
        case appAttest = "appattest"
        case appAttestDevelop = "appattestdevelop"
        case appAttestSandbox = "appattestsandbox"
        
        init?(bytes: Data) {
            if let id = AAGUID.allCases.first(where: { bytes == $0.bytes }) {
                self = id
            } else {
                return nil
            }
        }
        
        var bytes: Data {
            let data = rawValue.data(using: .utf8)!
            switch self {
            case .appAttestDevelop, .appAttestSandbox:
                return data
            case .appAttest:
                return data + Data(repeatElement(0x00, count: 7))
            }
        }
    }
    
    /// The credential identifier, if present in the attested credential data.
    var credentialID: Data? {
        guard hasAttestedCredentialData, bytes.count >= 55 else { return nil }
        // Retrieve the two bytes that encode the length
        // of the credentialID as a UInt16.
        let length = bytes[53..<55].reduce(0) { value, byte in
            value << 8 | UInt16(byte)
        }
        let end = 55 + Int(length)
        guard bytes.count >= end else { return nil }
        return bytes[55..<end]
    }
}

extension AuthenticatorData {
    /// Verifies that the RP ID hash matches the SHA256 hash of the provided App ID.
    func verifyAppID(_ appID: String) -> Bool {
        guard let appIDData = appID.data(using: .utf8) else { return false }
        let hash = SHA256.hash(data: appIDData)
        return rpID == Data(hash)
    }
    
    /// Verifies that the counter is valid for the given context.
    ///
    /// For **attestations**, the counter must be 0.
    /// For **assertions**, the counter must be greater than the previous counter (or greater than 0 if no previous counter is provided).
    func verifyCounter(isAttestation: Bool, previous: Int? = nil) -> Bool {
        let current = Int(self.counter)
        if isAttestation {
            return current == 0
        } else {
            return current > (previous ?? 0)
        }
    }
    
    /// Verify that the authenticator data’s credentialId field is the same as the key identifier.
    func verifyKeyID(_ keyID: Data) -> Bool {
        return credentialID == keyID
    }
}
