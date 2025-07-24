//
//  AppAttestAssertionMiddleware.swift
//  AppAttestVapor
//
//  Created by Wilson Goode on 7/21/25.
//

import Vapor
import Redis
import AppAttest
import AppAttestShared

/// AppAttestAssertionMiddleware
///
/// Middleware to verify AppAttest assertions are formatted correctly and completely. Compares assertion with information stored in Redis.
public struct AppAttestAssertionMiddleware: AsyncMiddleware {
    
    private let teamID: String
    private let bundleID: String
    
    public init(teamID: String, bundleID: String) {
        self.teamID = teamID
        self.bundleID = bundleID
    }
    
//    private func
    
    public func respond(to request: Vapor.Request, chainingTo next: any Vapor.AsyncResponder) async throws -> Vapor.Response {
        
        // Check for override token to short-circuit assertion process
        if request.isAppAttestOverrideAuthorized {
            return try await next.respond(to: request)
        }
        
        // Extract assertion from request header
        guard let assertionTokenBase64EncodedString = request.headers.first(name: AppAttestHTTPHeaders.appAttestAssertion) else {
            throw Abort(.unauthorized, reason: "No \(AppAttestHTTPHeaders.appAttestAssertion) header")
        }
        guard let assertionToken = Data(base64Encoded: assertionTokenBase64EncodedString) else {
            throw Abort(.unauthorized, reason: "Invalid \(AppAttestHTTPHeaders.appAttestAssertion) header")
        }
        
        // MARK: - Decode assertion from assertion header
        let assertionRequest = try JSONDecoder().decode(VerifyAssertionRequest.self, from: assertionToken)

        // MARK: - Retrieve client data from request body (AssertionPayload)
        guard let byteBuffer = request.body.data else {
            throw Abort(.badRequest, reason: "No request body")
        }
        let clientData = Data(buffer: byteBuffer)
        
        // MARK: - Retrieve challenge from Redis
        let redisChallengeKey = RedisKey(assertionRequest.challengeID.uuidString)
        
        guard let challenge = try await request.application.redis.get(
            redisChallengeKey,
            as: String.self
        ).get() else {
            request.logger.error("Redis error retrieving challenge for challengeID: \(redisChallengeKey)")
            throw Abort(.internalServerError, reason: "Challenge retrieval failed")
        }
        
        guard let challengeData = Data(base64Encoded: challenge) else {
            request.logger.error("Invalid base64 encoding for challenge data")
            throw Abort(.internalServerError, reason: "Invalid challenge data")
        }
        
        // MARK: - Retrieve attestation from Redis
        let redisAttestationKey = RedisKey("attestation" + assertionRequest.keyID.base64EncodedString())
        
        guard let attestationData = try await request.application.redis.get(
            redisAttestationKey,
            as: Data.self
        ).get() else {
            request.logger.error("Redis error retrieving attestation for keyID: \(redisAttestationKey)")
            throw Abort(.internalServerError, reason: "Attestation retrieval failed")
        }
        let attestation = try JSONDecoder().decode(AppAttest.AttestationResult.self, from: attestationData)
        
        // MARK: - Retrieve previous assertion
        // If this is not the first assertion for this instance
        // of the app (i.e. for this unique key ID),
        // retrieve the previous AssertionResult. Otherwise,
        // use nil for this value.
        let redisAssertionKey = RedisKey("assertion" + assertionRequest.keyID.base64EncodedString())
        
        var previousAssertion: AppAttest.AssertionResult? = nil
        if let previousCodableAssertionData = try? await request.application.redis.get(redisAssertionKey, as: Data.self).get() {
            previousAssertion = try? JSONDecoder().decode(AppAttest.AssertionResult.self, from: previousCodableAssertionData)
        }
        
        // MARK: - Construct the assertion request
        let appAttestAssertionRequest = AppAttest.AssertionRequest(
            assertion: assertionRequest.assertion,
            clientData: clientData,
            challenge: challengeData
        )
        
        let appID = AppAttest.AppID(teamID: teamID, bundleID: bundleID)
        
        do {
            let result = try AppAttest.verifyAssertion(
                challenge: challengeData,
                request: appAttestAssertionRequest,
                previousResult: previousAssertion,
                publicKey: attestation.publicKey,
                appID: appID
            )
            let encodedResult = try JSONEncoder().encode(result)
            // Store result in Redis
            do {
                try await request.application.redis.set(redisAssertionKey, to: encodedResult).get()
                request.logger.debug("Successfully stored assertion for keyID: \(redisAssertionKey)")
            } catch {
                request.logger.error("Redis error saving assertion result: \(error) \(error.localizedDescription)")
                throw Abort(.internalServerError, reason: "Redis error saving assertion result")
            }
            
            return try await next.respond(to: request)
            
            
        } catch {
          // Handle the error
            request.logger.error("Error verifying assertion: \(error) \(error.localizedDescription)")
            throw Abort(.internalServerError, reason: "Assertion verification failed")
        }
        
    }
}
