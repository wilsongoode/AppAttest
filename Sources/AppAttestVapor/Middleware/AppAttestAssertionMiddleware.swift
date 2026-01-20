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
        
        if request.isAppAttestOverrideAuthorized {
            return try await next.respond(to: request)
        }
        
        guard let assertionTokenBase64EncodedString = request.headers.first(name: AppAttestHTTPHeaders.appAttestAssertion) else {
            throw Abort(.unauthorized, reason: "No \(AppAttestHTTPHeaders.appAttestAssertion) header")
        }
        guard let assertionToken = Data(base64Encoded: assertionTokenBase64EncodedString) else {
            throw Abort(.unauthorized, reason: "Invalid \(AppAttestHTTPHeaders.appAttestAssertion) header")
        }
        
        let assertionRequest = try JSONDecoder().decode(VerifyAssertionRequest.self, from: assertionToken)

        guard let byteBuffer = request.body.data else {
            throw Abort(.badRequest, reason: "No request body")
        }
        let clientData = Data(buffer: byteBuffer)
        
        // MARK: - Extract challenge from client data (Step 6)
        // We must decode the body to find the challenge the client actually signed.
        let assertionPayload = try JSONDecoder().decode(AssertionPayload.self, from: clientData)
        let receivedChallenge = assertionPayload.challenge
        
        // MARK: - Retrieve challenge from Redis
        let redisChallengeKey = RedisKey(assertionRequest.challengeID.uuidString)
        
        guard let challenge = try await request.application.redis.get(
            redisChallengeKey,
            as: String.self
        ).get() else {
            request.logger.error("Redis error retrieving challenge for challengeID: \(redisChallengeKey)")
            throw Abort(.internalServerError, reason: "Challenge retrieval failed")
        }
        
        guard let storedChallengeData = Data(base64Encoded: challenge) else {
            request.logger.error("Invalid base64 encoding for challenge data")
            throw Abort(.internalServerError, reason: "Invalid challenge data")
        }
        
        // MARK: - Retrieve attestation result
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
        let redisAssertionKey = RedisKey("assertion" + assertionRequest.keyID.base64EncodedString())
        var previousAssertion: AppAttest.AssertionResult? = nil
        if let previousCodableAssertionData = try? await request.application.redis.get(redisAssertionKey, as: Data.self).get() {
            previousAssertion = try? JSONDecoder().decode(AppAttest.AssertionResult.self, from: previousCodableAssertionData)
        }
        
        // MARK: - Construct the assertion request
        // Note: We use the challenge extracted from the client payload (receivedChallenge)
        let appAttestAssertionRequest = AppAttest.AssertionRequest(
            assertion: assertionRequest.assertion,
            clientData: clientData,
            challenge: receivedChallenge
        )
        
        let appID = AppAttest.AppID(teamID: teamID, bundleID: bundleID)
        
        do {
            let result = try AppAttest.verifyAssertion(
                challenge: storedChallengeData, // The original server challenge
                request: appAttestAssertionRequest,
                previousResult: previousAssertion,
                publicKey: attestation.publicKey,
                appID: appID
            )
            
            // Store result in Redis for the next request's counter check
            let encodedResult = try JSONEncoder().encode(result)
            try await request.application.redis.set(redisAssertionKey, to: encodedResult).get()
            
        } catch {
            request.logger.error("Error verifying assertion: \(error)\nLocalizedDescription: \(error.localizedDescription)")
            throw Abort(.internalServerError, reason: "Assertion verification failed")
        }
        
        return try await next.respond(to: request)
    }
}
