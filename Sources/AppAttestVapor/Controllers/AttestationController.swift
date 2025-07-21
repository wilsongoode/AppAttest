//
//  AttestationController.swift
//  AppAttestVapor
//
//  Created by Wilson Goode on 7/21/25.
//

import Vapor
import Crypto
import AppAttest
import Redis
import AppAttestShared

/// Example AttestationController
///
/// This Vapor route collection handles attestation requests to the server's `attest/challenge` and `attest/verify` endpoints.
struct AttestationController: RouteCollection {
    
    let teamID: String
    let bundleID: String
    
    init(teamID: String, bundleID: String) {
        self.teamID = teamID
        self.bundleID = bundleID
    }
    
    func boot(routes: any RoutesBuilder) throws {
        let appattest = routes.grouped("attest")
        
        appattest.get("challenge", use: getChallenge)
        appattest.post("verify", use: verifyAttestation)
    }
        
    func getChallenge(req: Request) async throws -> ChallengeResponse {
        let challenge = Data(AES.GCM.Nonce())
        let challengeID = UUID()

        let redisChallengeKey = RedisKey(challengeID.uuidString)
        do {
            try await req.application.redis.set(
                redisChallengeKey,
                to: challenge.base64EncodedString()
            ).get()
            req.logger.debug("Redis success saving challenge: \(redisChallengeKey)")
        } catch {
            req.logger.debug("Redis error saving challenge: \(error) \(error.localizedDescription)")
            throw Abort(.internalServerError)
        }
        
        return ChallengeResponse(
            challenge: challenge,
            challengeID: challengeID
        )
    }
    
    func verifyAttestation(req: Request) async throws -> HTTPResponseStatus {
        guard let verifyRequest = try? req.content.decode(VerifyAttestationRequest.self) else {
            throw Abort(.badRequest)
        }
        // Retrieve these values from the HTTP request
        // that your app sends to the server
        let attestation: Data = verifyRequest.attestation
        let keyID: Data = verifyRequest.keyID
        let challengeID: UUID = verifyRequest.challengeID

        let redisChallengeKey = RedisKey(challengeID.uuidString)
        // Retrieve the challenge you generated in the previous step
        guard let challenge = try await req.application.redis.get(
            redisChallengeKey,
            as: String.self
        ).get() else {
            throw Abort(.badRequest)
        }
        guard let challengeData = Data(base64Encoded: challenge) else {
            req.logger.error("Invalid base64 encoding for challenge data")
            throw Abort(.internalServerError, reason: "Invalid challenge data")
        }
        // Construct the attestation request and app ID,
        // which are simple structs
        let request = AppAttest.AttestationRequest(attestation: attestation, keyID: keyID)
        let appID = AppAttest.AppID(teamID: teamID, bundleID: bundleID)

        // Verify the attestation
        do {
            let result = try AppAttest.verifyAttestation(
                challenge: challengeData,
                request: request,
                appID: appID
            )
            
            // If successful, store result in Redis
            let encodedResult = try JSONEncoder().encode(result)
                                    
            do {
                let redisAttestationKey = RedisKey("attestation" + keyID.base64EncodedString())

                // Store result in Redis
                try await req.application.redis.set(
                    redisAttestationKey,
                    to: encodedResult
                ).get()
                req.logger.debug("Successfully stored attestation for keyID: \(redisAttestationKey)")
            } catch {
                req.logger.debug("Redis error saving attestation result: \(error) \(error.localizedDescription)")
                throw Abort(.internalServerError, reason: "Redis error saving attestation result")
            }

            return .accepted
        } catch {
            // Handle the error
            req.logger.debug("Error verifying attestation: \(error) \(error.localizedDescription)")
            return .internalServerError
        }
    }
}








