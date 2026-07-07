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
        // swift-transformers transitively. Pinned to the 2.x MLX Swift LM
        // line that adds Qwen3.5/Qwen3.5-MoE architecture support while
        // preserving the API shape this bridge uses.
        .package(url: "https://github.com/ml-explore/mlx-swift-lm", from: "2.31.3"),
    ],
    targets: [
        .target(
            name: "CoCoreMLX",
            dependencies: [
                .product(name: "MLXLLM", package: "mlx-swift-lm"),
                .product(name: "MLXVLM", package: "mlx-swift-lm"),
                .product(name: "MLXLMCommon", package: "mlx-swift-lm"),
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
