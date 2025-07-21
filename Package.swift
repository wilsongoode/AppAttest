// swift-tools-version:5.5

import PackageDescription

let package = Package(
    name: "AppAttest",
    platforms: [.iOS(.v14), .macOS(.v10_15)],
    products: [
        .library(
            name: "AppAttest",
            targets: ["AppAttest"]
        ),
        .library(
            name: "AppAttestVapor",
            targets: ["AppAttestVapor"]
        ),
        .library(
            name: "AppAttestClient",
            targets: ["AppAttestClient"]
        ),
    ],
    dependencies: [
        .package(url: "https://github.com/myfreeweb/SwiftCBOR", from: "0.4.6"),
        .package(url: "https://github.com/apple/swift-crypto", from: "3.1.0"),
        .package(url: "https://github.com/iansampson/Anchor", branch: "main"),
        .package(url: "https://github.com/vapor/vapor", from: "4.0.0"),
        .package(url: "https://github.com/vapor/redis", from: "4.0.0"),
    ],
    targets: [
        .target(
            name: "AppAttest",
            dependencies: [
                "SwiftCBOR",
                .product(name: "Crypto", package: "swift-crypto"),
                "Anchor"
            ]
        ),
        .target(
            name: "AppAttestShared",
            dependencies: []
        ),
        .target(
            name: "AppAttestVapor",
            dependencies: [
                "AppAttest",
                "AppAttestShared",
                .product(name: "Vapor", package: "vapor"),
                .product(name: "Redis", package: "redis"),
            ],
            path: "Sources/AppAttestVapor"
        ),
        .target(
            name: "AppAttestClient",
            dependencies: [
                "AppAttest",
                "AppAttestShared",
            ],
            path: "Sources/AppAttestClient"
        ),
        .testTarget(
            name: "AppAttestTests",
            dependencies: ["AppAttest"]
        )
    ]
)
