// swift-tools-version:5.9
//
// CoCoreShell is intended to be opened in Xcode for the actual app
// build (because of code signing entitlements + .app bundle layout),
// but it's structured as a Swift Package so:
//   1. CI can run `swift build` to type-check on every push, and
//   2. swift-format / swift-lint can operate over the full tree.
//
// The Xcode project references these source files directly; do not
// duplicate them.

import PackageDescription

let package = Package(
    name: "CoCoreShell",
    platforms: [.macOS(.v13)],
    products: [
        .executable(name: "CoCoreShell", targets: ["CoCoreShell"]),
    ],
    dependencies: [
        .package(path: "../provider/enclave"),
    ],
    targets: [
        .executableTarget(
            name: "CoCoreShell",
            dependencies: [
                .product(name: "CoCoreEnclave", package: "enclave"),
            ],
            path: "Sources/CoCoreShell",
            // Info.plist and the entitlements file are consumed by the
            // Xcode app target, not by SwiftPM — and SwiftPM forbids a
            // top-level Info.plist in the resource bundle. Exclude them
            // from `swift build`'s resource processing; Xcode still
            // references them directly from disk.
            exclude: [
                "Resources/Info.plist",
                "Resources/cocore.entitlements",
            ],
            resources: [
                .process("Resources"),
            ]
        ),
        .testTarget(
            name: "CoCoreShellTests",
            dependencies: ["CoCoreShell"],
            path: "Tests/CoCoreShellTests"
        ),
    ]
)
