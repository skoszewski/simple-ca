// swift-tools-version: 6.4

import PackageDescription

let package = Package(
    name: "simple-ca-trust",
    platforms: [.macOS(.v15)],
    targets: [
        .executableTarget(
            name: "simple-ca-trust",
            swiftSettings: [.enableExperimentalFeature("SourceWarningControl")]
        )
    ]
)
