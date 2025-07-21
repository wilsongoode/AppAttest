//
//  AppAttestShared+Content.swift
//  AppAttestVapor
//
//  Created by Wilson Goode on 7/21/25.
//

import AppAttestShared
import Vapor

extension AssertionPayload: @retroactive Content {}
extension VerifyAssertionRequest: @retroactive Content { }
extension ChallengeResponse: @retroactive Content { }
extension VerifyAttestationRequest: @retroactive Content { }
