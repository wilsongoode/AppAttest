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
}

/// AppAttestClient
///
/// A client to connect to a server running the ``AppAttest`` API as implemented in ``AppAttestVapor``.
///
/// Use this client when you want to abstract the AppAttest process out of your app and just send and recieve data from the server. The client handles attestation and assertion on your behalf using the DeviceCheck framework.
///
/// Example usage:
/// ```swift
/// let client = AppAttestClient(baseURL: URL(string: "https://example.com")!, userAgent: "MyApp/1.0")
/// let data = try await client.getDataWithAssertion(from: URL(string ,: "https://example.com/data")!, requestPayload: Data())
/// ```
///
@available(iOS 16.0, *)
public final class AppAttestClient: Sendable {
    
    /// The base URL of the server running the AppAttest API.
    private let baseURL: URL
    
    /// The user agent to use when making requests to the server.
    private let userAgent: String
    
    /// - Parameters:
    ///     - baseURL: The base URL of the server running the AppAttest API.
    ///     - userAgent: The user agent to use when making requests to the server.
    public init(
        baseURL: URL,
        userAgent: String,
    ) {
        self.baseURL = baseURL
        self.userAgent = userAgent
    }
    
    /// An optional token for overriding the AppAttest process.
    ///
    /// To use this feature, set the same token in the environment of both the app and the server.
    /// This token works with AppAttestClient and AppAttestVapor.
    /// If the token sent by AppAttestClient does not match the one configured for the server, the request fails.
    private static let overrideToken: String? = ProcessInfo.processInfo.environment["APP_ATTEST_OVERRIDE_TOKEN"]
    
    /// The bundle identifier for the client app.
    private static let bundleID: String = Bundle.main.bundleIdentifier!
    
    /// The key used to store the AppAttest key in the user defaults.
    private let userDefaultsKey: String = "appAttest.\(bundleID)"
    
    private let logger: Logger = Logger(subsystem: bundleID, category: "AppAttestClient")
    
    /// The DeviceCheck service to use for attestation and assertion.
    private let service: DCAppAttestService = DCAppAttestService.shared
    
    /// Fetches data from the server using the provided URL, appending the User-Agent header to the request.
    private func dataForURL(_ url: URL) async throws -> Data {
        URLSession.shared.configuration.httpAdditionalHeaders = [
            "User-Agent": userAgent
        ]
        let (data, _) = try await URLSession.shared.data(from: url)
        return data
    }
    
    /// Fetches data from the server using the provided URL request, appending the User-Agent header to the request.
    private func dataForRequest(_ urlRequest: URLRequest) async throws -> (Data, URLResponse) {
        URLSession.shared.configuration.httpAdditionalHeaders = [
            "User-Agent": userAgent
        ]
        return try await URLSession.shared.data(for: urlRequest)
    }
    
    /// Generates a new key and writes it to the user defaults.
    private func generateKey() async throws -> String {
        let keyIdentifier = try await service.generateKey()
        logger.debug("Generated keyID: \(keyIdentifier)")
        self.writeKey(keyID: keyIdentifier)
        return keyIdentifier
    }
    
    /// Retrieves a challenge from the server and returns it.
    private func retrieveChallenge() async throws -> ChallengeResponse {
        let data = try await dataForURL(baseURL.appending(path: "attest/challenge"))
        logger.debug("Received challenge data: \(String(data: data, encoding: .utf8) ?? "unable to parse data as utf8")")
        let challengeResponse = try JSONDecoder().decode(ChallengeResponse.self, from: data)
        logger.debug("Received challenge with ID: \(challengeResponse.challengeID.uuidString)")
        return challengeResponse
    }
    
    /// Attests a key with the server.
    private func attestKey() async throws -> String {
        guard service.isSupported else {
            logger.error("App Attest is not supported on this device.")
            throw AppAttestClientError.attestNotSupported
        }
        
        logger.debug("Beginning attestation")
        
        let challengeResponse = try await retrieveChallenge()
        
        var keyID: String
        if let existingKey = readKey() {
            keyID = existingKey
        } else {
            keyID = try await generateKey()
        }

        logger.debug("attestKey: Using keyID: \(keyID)")
        
        let clientDataHash = Data(SHA256.hash(data: challengeResponse.challenge))
        let attestation = try await service.attestKey(keyID, clientDataHash: clientDataHash)
        logger.debug("Received attestation: \(attestation)")
        
        let keyIDData = Data(base64Encoded: keyID)!
        
        let attestationRequest = VerifyAttestationRequest(
            attestation: attestation,
            keyID: keyIDData,
            challengeID: challengeResponse.challengeID
        )
        var request = URLRequest(url: baseURL.appending(path: "attest/verify"))
        request.httpMethod = "POST"
        request.httpBody = try JSONEncoder().encode(attestationRequest)
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        
        let (_, response) = try await dataForRequest(request)
        
        if let httpResponse = response as? HTTPURLResponse {
            logger.debug("Response status code: \(httpResponse.statusCode)")
            if httpResponse.statusCode == 202 { // Accepted
                // Store keyID in user defaults
                self.writeKey(keyID: keyID)
                logger.debug("Saving attested keyID: \(keyID)")
                return keyID
            }
        }
        
        throw AppAttestClientError.attestVerificationFailed
    }
    
    /// Creates an assertion for the provided payload.
    /// - Parameters:
    ///   - payload: The request payload (encoded with JSONEncoder)
    ///   - challengeID: The challenge ID to use for the assertion
    private func createAssertion(_ payload: AssertionPayload, challengeID: UUID) async throws -> String {
        var keyID = self.readKey()
        
        if keyID == nil {
            logger.debug("No keyID found, generating new keyID")
            keyID = try await attestKey()
        }
        guard let keyID else {
            throw AppAttestClientError.noKey
        }
        
        logger.debug("createAssertion: Using keyID: \(keyID)")
        
        let encodedPayload = try JSONEncoder().encode(payload)
        let hash = Data(SHA256.hash(data: encodedPayload))

        do {
            let assertion = try await service.generateAssertion(keyID, clientDataHash: hash)
            
            logger.debug("Created assertion: \(assertion.base64EncodedString())")
            
            let keyIDData = Data(base64Encoded: keyID)!
            
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
        let (data, _) = try await dataForRequest(request)
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
        
        if let token = Self.overrideToken {
            logger.debug("Using override token for App Attest.")
            return try await getDataWithOverrideToken(
                from: url,
                requestPayload: payload,
                token: token
            )
        }
        
        guard service.isSupported else {
            logger.error("App Attest is not supported on this device.")
            throw AppAttestClientError.attestNotSupported
        }
        
        logger.debug("Beginning data request with assertion")
        
        var currentTry = 1
        while currentTry <= maxRetryCount {
            
            do {
                let challengeResponse = try await retrieveChallenge()
                
                let assertionPayload = AssertionPayload(
                    payload: payload,
                    challenge: challengeResponse.challenge
                )
                let assertion = try await createAssertion(
                    assertionPayload,
                    challengeID: challengeResponse.challengeID
                )
                let body = try JSONEncoder().encode(assertionPayload)
                
                var request = URLRequest(url: url)
                request.httpMethod = "POST"
                request.httpBody = body
                request.setValue(
                    "application/json",
                    forHTTPHeaderField: "Content-Type"
                )
                request.setValue(
                    assertion,
                    forHTTPHeaderField: AppAttestHTTPHeaders.appAttestAssertion
                )
                request.cachePolicy = .useProtocolCachePolicy
                
                logger.debug("Sending request")
                let (data, response) = try await dataForRequest(request)
                
                if let httpResponse = response as? HTTPURLResponse {
                    logger.debug("Response status code: \(httpResponse.statusCode)")
                    
//                    let cc = httpResponse.value(forHTTPHeaderField: "Cache-Control")
//                    
//                    logger.debug("Cache-Control: \(cc ?? "nil")")
                    
                    // log all headers
                    logger.debug("Response headers: \(httpResponse.allHeaderFields)")
                    
                    if httpResponse.statusCode == 401 {
                        self.deleteKey()
                        throw AppAttestClientError.assertionFailed
                    }
                    if httpResponse.statusCode == 500 {
                        self.deleteKey()
                        throw AppAttestClientError.serverError
                    }
                }
                return data
                
            } catch {
                if error is AppAttestClientError {
                    logger.debug("Error: \(error)")
                    logger.debug("Retry attempt \(currentTry) of \(maxRetryCount)")
                    currentTry += 1
                } else {
                    throw error
                }
            }
            
        } //: while
        throw AppAttestClientError.retryCountExceeded
    }
    
    /// Writes the provided keyID to the user defaults
    private func writeKey(keyID: String) {
        UserDefaults.standard.set(keyID, forKey: userDefaultsKey)
    }
    
    /// Reads the keyID from the user defaults
    private func readKey() -> String? {
        UserDefaults.standard.string(forKey: userDefaultsKey)
    }
    
    /// Deletes the keyID from the user defaults
    private func deleteKey() {
        logger.debug("Deleting AppAttest key: \(self.readKey() ?? "nil")")
        UserDefaults.standard.removeObject(forKey: userDefaultsKey)
    }
}
