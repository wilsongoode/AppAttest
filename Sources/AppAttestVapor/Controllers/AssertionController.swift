//
//  AssertionController.swift
//  AppAttestVapor
//
//  Created by Wilson Goode on 7/21/25.
//

import Vapor
import AppAttestShared

/// Example AssertionController
///
/// A Vapor controller for handling assertion requests. These are requests that are made to the server that contain an ``AppAttestShared/AssertionPayload`` object. The route handler will validate that the payload is
public struct ExampleAssertionController: RouteCollection {
    
    let teamID: String
    let bundleID: String
    
    public init(teamID: String, bundleID: String) {
        self.teamID = teamID
        self.bundleID = bundleID
    }
    
    public func boot(routes: any Vapor.RoutesBuilder) throws {
        let attestedRoutes = routes.grouped(
            AppAttestAssertionMiddleware(
                teamID: teamID,
                bundleID: bundleID
            )
        )
        attestedRoutes.group("api") { api in
            api.post("hello", use: hello)
            api.post("example", use: example)
        }
    }
    
    struct EmptyPayload: Decodable {}

    func hello(req: Request) async throws -> String {
        _ = try req.decodeAssertionPayload(EmptyPayload.self)
        return "Hello, world! (attested)"
    }

    struct ExampleRequest: Content {
        let name: String
        let age: Int
    }
    
    /// Example route handler that takes an ExampleRequest wrapped in an ``AppAttestShared/AssertionPayload`` object
    func example(req: Request) async throws -> String {
        let exampleRequest = try req.decodeAssertionPayload(ExampleRequest.self)
        req.logger.debug("Example request: \(exampleRequest)")
        return "Hello, \(exampleRequest.name)! You are \(exampleRequest.age) years old."
    }
}
