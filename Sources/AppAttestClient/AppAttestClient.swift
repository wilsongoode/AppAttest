//
//  AppAttestClient.swift
//  AppAttestClient
//
//  Created by Wilson Goode on 7/21/25.
//

import Foundation
@preconcurrency import DeviceCheck
import CryptoKit
import os
import AppAttestShared

public enum AppAttestClientError: Error {
    case attestNotSupported
    case attestVerificationFailed
    case assertionFailed
    case serverError
    case noKey
    case retryCountExceeded
    case invalidKeyID
}

public enum AppAttestEnvironment: String, Sendable {
    case development
    case production
}

/// AppAttestClient
///
/// A client to connect to a server running the ``AppAttest`` API as implemented in ``AppAttestVapor``.
///
/// Use this client when you want to abstract the AppAttest process out of your app and just send and receive data from the server. The client handles attestation and assertion on your behalf using the DeviceCheck framework.
///
/// Example usage:
/// ```swift
/// let client = AppAttestClient(baseURL: URL(string: "https://example.com")!, userAgent: "MyApp/1.0")
/// let data = try await client.getDataWithAssertion(from: URL(string ,: "https://example.com/data")!, requestPayload: Data())
/// ```
///
@available(iOS 16.0, *)
public actor AppAttestClient {
    
    /// The base URL of the server running the AppAttest API.
    private let baseURL: URL
    
    /// The user agent to use when making requests to the server.
    private let userAgent: String
    
    /// The AppAttest environment (either `development` or `production`)
    private let environment: AppAttestEnvironment
    
    
    private let service: DCAppAttestService = DCAppAttestService.shared
    private let session: URLSession
    
    /// An optional token for overriding the AppAttest process.
    ///
    /// To use this feature, set the same token in the environment of both the app and the server.
    /// This token works with AppAttestClient and AppAttestVapor.
    /// If the token sent by AppAttestClient does not match the one configured for the server, the request fails.
    private static let overrideToken: String? = ProcessInfo.processInfo.environment["APP_ATTEST_OVERRIDE_TOKEN"]
    
    /// The bundle identifier for the client app.
    private static let bundleID: String = Bundle.main.bundleIdentifier ?? "com.unknown.app"

    /// The key used to store the AppAttest key in the user defaults.
    private var userDefaultsKey: String {
        "appAttest.\(environment.rawValue).\(Self.bundleID)"
    }

    private let logger: Logger = Logger(subsystem: bundleID, category: "AppAttestClient")

    /// - Parameters:
    ///     - baseURL: The base URL of the server running the AppAttest API.
    ///     - userAgent: The user agent to use when making requests to the server.
    ///     - environment: Whether to use the development or production AppAttest key.
    public init(
        baseURL: URL,
        userAgent: String,
        environment: AppAttestEnvironment = .production
    ) {
        self.baseURL = baseURL
        self.userAgent = userAgent
        self.environment = environment
        
        // Fixed global side effect: Use a private URLSession configuration instead of URLSession.shared. [3, 4]
        let config = URLSessionConfiguration.ephemeral
        config.httpAdditionalHeaders = ["User-Agent": userAgent]
        self.session = URLSession(configuration: config)
    }

    // MARK: - Key Management (Fixed Persistence)

    /// Fixed Premature Persistence: generateKey now returns the ID without writing to UserDefaults. [4]
    private func generateKey() async throws -> String {
        let keyIdentifier = try await service.generateKey()
        logger.debug("Generated keyID: \(keyIdentifier)")
        return keyIdentifier
    }

    private func readKey() -> String? {
        UserDefaults.standard.string(forKey: userDefaultsKey)
    }

    private func writeKey(keyID: String) {
        UserDefaults.standard.set(keyID, forKey: userDefaultsKey)
    }

    private func deleteKey() {
        logger.debug("Deleting AppAttest key.")
        UserDefaults.standard.removeObject(forKey: userDefaultsKey)
    }

    // MARK: - Attestation Phase

    private func retrieveChallenge() async throws -> ChallengeResponse {
        let (data, _) = try await session.data(from: baseURL.appending(path: "attest/challenge"))
        return try JSONDecoder().decode(ChallengeResponse.self, from: data)
    }

    private func attestKey() async throws -> String {
        guard service.isSupported else { throw AppAttestClientError.attestNotSupported }
        
        let challengeResponse = try await retrieveChallenge()
        let keyID = try await generateKey() // No immediate write to persistence here.
        
        let clientDataHash = Data(SHA256.hash(data: challengeResponse.challenge))
        let attestation = try await service.attestKey(keyID, clientDataHash: clientDataHash)
        
        // Fixed Force Unwrap: Safely handle Base64 decoding of the keyID. [8]
        guard let keyIDData = Data(base64Encoded: keyID) else {
            throw AppAttestClientError.invalidKeyID
        }

        let attestationRequest = VerifyAttestationRequest(
            attestation: attestation,
            keyID: keyIDData,
            challengeID: challengeResponse.challengeID
        )

        var request = URLRequest(url: baseURL.appending(path: "attest/verify"))
        request.httpMethod = "POST"
        request.httpBody = try JSONEncoder().encode(attestationRequest)
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        let (_, response) = try await session.data(for: request)
        
        if (response as? HTTPURLResponse)?.statusCode == 202 {
            // Fixed: Only persist the key after the server has successfully verified it. [9]
            self.writeKey(keyID: keyID)
            return keyID
        }
        
        throw AppAttestClientError.attestVerificationFailed
    }

    // MARK: - Assertion Phase

    private func createAssertion(with body: Data, challengeID: UUID) async throws -> String {
        // 1. Attempt to read the existing key synchronously
        var keyID = self.readKey()

        // 2. If no key is found, await the asynchronous attestation process
        if keyID == nil {
            logger.debug("No keyID found, generating new keyID")
            keyID = try await attestKey()
        }

        // 3. Final guard to ensure a keyID exists before proceeding
        guard let finalKeyID = keyID else {
            throw AppAttestClientError.noKey
        }
        
        // Proceed with using finalKeyID for hashing and signing...
        logger.debug("createAssertion: Using keyID: \(finalKeyID)")
        let hash = Data(SHA256.hash(data: body))
        
        do {
            let assertion = try await service.generateAssertion(finalKeyID, clientDataHash: hash)
            
            // Fixed Force Unwrap: Safely handle keyID data. [11]
            guard let keyIDData = Data(base64Encoded: finalKeyID) else {
                throw AppAttestClientError.invalidKeyID
            }

            let assertionRequest = VerifyAssertionRequest(
                assertion: assertion,
                keyID: keyIDData,
                challengeID: challengeID
            )

            return try JSONEncoder().encode(assertionRequest).base64EncodedString()
        } catch {
            if let dcError = error as? DCError {
                logger.error("createAssertion: DCError: \(dcError)")
                switch dcError.code {
                case .featureUnsupported:
                    logger.error("createAssertion: AppAttest is not supported on this device.")
                case .invalidInput:
                    logger.error("createAssertion: Invalid input.")
                case .invalidKey:
                    logger.error("createAssertion: Invalid key. Deleting key.")
                    self.deleteKey()
                case .serverUnavailable:
                    logger.error("createAssertion: Server unavailable.")
                case .unknownSystemFailure:
                    logger.error("createAssertion: Unknown system failure.")
                @unknown default:
                    logger.error("createAssertion: Unknown error: \(error.localizedDescription)")
                }
            } else {
                logger.error("createAssertion: Error: \(error.localizedDescription)")
            }
            throw AppAttestClientError.assertionFailed
        }
    }
    
    /// Uses a token from the environment to bypass AppAttest on a server running AppAttestVapor
    ///
    /// Requires matching tokens set for `APP_ATTEST_OVERRIDE_TOKEN` on both client and server.
    private func getDataWithOverrideToken(
        from url: URL,
        requestPayload payload: Data,
        token: String
    ) async throws -> Data {
        var request = URLRequest(url: url)
        request.setValue("Bearer \(token)", forHTTPHeaderField: AppAttestHTTPHeaders.appAttestBearerAuthorization)
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpMethod = "POST"
        request.httpBody = payload
        let (data, _) = try await session.data(for: request)
        return data
    }
    
    /// Applies AppAttest assertion to a request for data from the server
    ///
    /// - Parameters:
    ///   - url: The URL to send the request to
    ///   - payload: The request payload (encoded with JSONEncoder)
    ///   - maxRetryCount: The maximum number of times to retry the request
    public func getDataWithAssertion(
        from url: URL,
        requestPayload payload: Data,
        maxRetryCount: Int = 1
    ) async throws -> Data {
        // Handle override tokens for development/testing bypass.
        if let token = Self.overrideToken {
            return try await getDataWithOverrideToken(from: url, requestPayload: payload, token: token)
        }

        guard service.isSupported else { throw AppAttestClientError.attestNotSupported }

        var currentTry = 1
        while currentTry <= maxRetryCount {
            do {
                let challengeResponse = try await retrieveChallenge()
                let assertionPayload = AssertionPayload(payload: payload, challenge: challengeResponse.challenge)
                
                // Encode ONCE to ensure hash consistency.
                let body = try JSONEncoder().encode(assertionPayload)
                let assertion = try await createAssertion(with: body, challengeID: challengeResponse.challengeID)

                var request = URLRequest(url: url)
                request.httpMethod = "POST"
                request.httpBody = body
                request.setValue("application/json", forHTTPHeaderField: "Content-Type")
                request.setValue(assertion, forHTTPHeaderField: AppAttestHTTPHeaders.appAttestAssertion)

                let (data, response) = try await session.data(for: request)
                
                if let httpResponse = response as? HTTPURLResponse {
                    if httpResponse.statusCode == 401 {
                        self.deleteKey() // Key is likely invalid on server.
                        throw AppAttestClientError.assertionFailed
                    }
                    // Fixed: Removed deleteKey() on HTTP 500 as it is a server-side transient error.
                    if httpResponse.statusCode == 500 { throw AppAttestClientError.serverError }
                }

                return data
            } catch {
                logger.error("Error during request: \(error)")
                if currentTry < maxRetryCount {
                    logger.debug("Attempt \(currentTry) failed. Retrying...")
                    currentTry += 1
                } else {
                    throw error
                }
            }
        }
        throw AppAttestClientError.retryCountExceeded
    }
}
