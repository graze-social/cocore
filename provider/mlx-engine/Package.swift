// swift-tools-version:5.9
import PackageDescription

// CoCoreMLX: native in-process MLX inference engine the Rust agent links over a
// C ABI (mirrors provider/enclave). Uses the upstream, Apache-2.0 MLX-Swift
// stack (NOT darkbloom's proprietary code) — the same libraries darkbloom's
// provider-swift builds on. The prompt is decrypted + run entirely inside this
// statically-linked code, so the measured `cocore` binary covers it.
let package = Package(
    name: "CoCoreMLX",
    platforms: [.macOS(.v14)],
    products: [
        // Dynamic: the Rust agent links one libCoCoreMLX.dylib (which pulls its
        // MLX/Swift deps), rather than static-linking the entire Swift+C++ world
        // into the Rust Mach-O. Security is preserved by enforced library
        // validation (only our-Team-signed dylibs load) + pinning the dylib +
        // metallib hashes in the attestation.
        .library(name: "CoCoreMLX", type: .dynamic, targets: ["CoCoreMLX"]),
        // Standalone harness to prove MLX runs + streams tokens in-process,
        // independent of the Rust link.
        .executable(name: "cocore-mlx-smoke", targets: ["cocore-mlx-smoke"]),
    ],
    dependencies: [
        // High-level LLM API (MLXLLM, MLXLMCommon) — pulls mlx-swift +
        // swift-transformers transitively. Pinned to a release for
        // reproducibility (the known-good set depends on a stable build).
        .package(url: "https://github.com/ml-explore/mlx-swift-examples", from: "2.21.0"),
        // Direct deps so the diffusion engine can `import MLX` (eval/MLXArray)
        // and `import Hub` (HubApi). Constraints match mlx-swift-examples' own
        // so the resolved version graph is shared (single MLX build).
        .package(url: "https://github.com/ml-explore/mlx-swift", .upToNextMinor(from: "0.29.1")),
        .package(
            url: "https://github.com/huggingface/swift-transformers",
            .upToNextMinor(from: "1.0.0")),
    ],
    targets: [
        .target(
            name: "CoCoreMLX",
            dependencies: [
                .product(name: "MLXLLM", package: "mlx-swift-examples"),
                .product(name: "MLXVLM", package: "mlx-swift-examples"),
                .product(name: "MLXLMCommon", package: "mlx-swift-examples"),
                // In-process diffusion (image generation) — SDXL-Turbo / SD-2.1.
                // The confidential image engine (DiffusionEngine.swift) runs this
                // entirely inside the measured binary.
                .product(name: "StableDiffusion", package: "mlx-swift-examples"),
                .product(name: "MLX", package: "mlx-swift"),
                .product(name: "Hub", package: "swift-transformers"),
            ],
            path: "Sources/CoCoreMLX",
            publicHeadersPath: "include"
        ),
        .executableTarget(
            name: "cocore-mlx-smoke",
            dependencies: ["CoCoreMLX"],
            path: "Sources/cocore-mlx-smoke"
        ),
    ]
)
