//
//  Request+AssertionPayload.swift
//  AppAttest
//
//  Created by Wilson Goode on 7/23/25.
//

import Vapor
import AppAttestShared

extension Request {
    /// Decodes an `AssertionPayload` and extracts the content of the specified type.
    ///
    /// If the request contains an override token to bypass AppAttest, the content is decoded directly.
    func decodeAssertionPayload<T: Decodable>(_ type: T.Type) throws -> T {
        if self.authorizedAppAttestOverride() {
            guard let payload = try? self.content.decode(T.self) else {
                throw Abort(.badRequest, reason: "Invalid request content")
            }
            return payload
        }
        
        guard let assertionPayload = try? self.content.decode(AssertionPayload.self) else {
            throw Abort(.badRequest, reason: "Invalid assertion payload")
        }

        guard let decodedContent = try? JSONDecoder().decode(T.self, from: assertionPayload.payload) else {
            throw Abort(.badRequest, reason: "Invalid request content")
        }

        return decodedContent
    }
    
    func authorizedAppAttestOverride() -> Bool {
        if let providedToken = self.headers.first(name: AppAttestHTTPHeaders.appAttestBearerAuthorization),
           let overrideToken = Environment.get("APP_ATTEST_OVERRIDE_TOKEN"),
           providedToken == "Bearer \(overrideToken)" {
            self.logger.debug("Skipping AppAttest validation due to override token.")
            return true
        } else {
            return false
        }
    }
}
