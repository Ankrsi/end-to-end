// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "E2ECrypto",
    platforms: [.iOS(.v13), .macOS(.v10_15), .tvOS(.v13), .watchOS(.v6)],
    products: [
        .library(name: "E2ECrypto", targets: ["E2ECrypto"]),
    ],
    dependencies: [
        // Only used on Linux (servers, CI). Apple platforms use the system CryptoKit.
        .package(url: "https://github.com/apple/swift-crypto.git", "3.0.0" ..< "4.0.0"),
    ],
    targets: [
        .target(
            name: "E2ECrypto",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto", condition: .when(platforms: [.linux])),
            ]
        ),
        .testTarget(name: "E2ECryptoTests", dependencies: ["E2ECrypto"]),
    ]
)
