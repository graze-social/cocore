// Native in-process MLX inference engine. The prompt is decrypted by the Rust
// agent and handed here; generation runs entirely inside this statically-linked
// code (no subprocess, no IPC), so the measured `cocore` binary covers it.
//
// Built on the upstream Apache-2.0 MLX-Swift stack (MLXLLM / MLXLMCommon) — the
// same libraries darkbloom's provider-swift uses, NOT their proprietary code.

import Foundation
import CoreImage
import MLXLLM
import MLXVLM
import MLXLMCommon
import CryptoKit

public final class MLXEngine {
    private let container: ModelContainer
    public let metallibHash: String?

    private init(container: ModelContainer, metallibHash: String?) {
        self.container = container
        self.metallibHash = metallibHash
    }

    /// Load an MLX model (safetensors weights + tokenizer) from a local
    /// directory into this process. No network — the directory is the
    /// already-downloaded HF snapshot.
    ///
    /// A vision-language model (its `config.json` carries a `vision_config`)
    /// is loaded through `VLMModelFactory` so image input works in-process;
    /// everything else loads through `LLMModelFactory`. Both return a uniform
    /// `ModelContainer`, so generation below is identical.
    public static func load(modelDir: String) async throws -> MLXEngine {
        let config = ModelConfiguration(
            directory: URL(fileURLWithPath: modelDir),
            extraEOSTokens: extraEOSTokens(modelDir: modelDir))
        let container: ModelContainer
        if isVisionModelDir(modelDir) {
            container = try await VLMModelFactory.shared.loadContainer(configuration: config)
        } else {
            container = try await LLMModelFactory.shared.loadContainer(configuration: config)
        }
        return MLXEngine(container: container, metallibHash: locateMetallibHash())
    }

    /// A model directory is a VLM when its `config.json` contains a
    /// `vision_config` object — the reliable cross-architecture marker the
    /// mlx-vlm/transformers ecosystems use for image-capable models.
    private static func isVisionModelDir(_ modelDir: String) -> Bool {
        let url = URL(fileURLWithPath: modelDir).appendingPathComponent("config.json")
        guard let data = try? Data(contentsOf: url),
            let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { return false }
        return obj["vision_config"] != nil
    }

    /// Stop tokens that must end generation but that the loaded tokenizer may
    /// not expose as its single `eosTokenId`.
    ///
    /// Instruction-tuned models close each turn with a delimiter token —
    /// Gemma's `<end_of_turn>`, Qwen/ChatML's `<|im_end|>`, Llama-3's
    /// `<|eot_id|>` — that is listed in `generation_config.json`'s
    /// `eos_token_id` and baked into the chat template, yet swift-transformers
    /// only loads the lone `eos_token` from `tokenizer_config.json` as the
    /// stop id. Without these the model emits its turn-ender forever (it never
    /// counts as a stop) until `maxTokens` — the runaway-`<end_of_turn>` bug.
    ///
    /// We resolve every id in `generation_config.json`'s `eos_token_id` to its
    /// string form via `tokenizer_config.json`'s `added_tokens_decoder`, and
    /// union a small static set of well-known chat delimiters as a safety net
    /// for models with a missing/partial `generation_config.json`. Strings a
    /// given model doesn't have resolve to nil downstream
    /// (`convertTokenToId`) and are simply ignored.
    private static func extraEOSTokens(modelDir: String) -> Set<String> {
        var tokens: Set<String> = ["<end_of_turn>", "<|im_end|>", "<|eot_id|>", "<|end|>"]
        let dir = URL(fileURLWithPath: modelDir)

        // id -> token string, from tokenizer_config.json's added_tokens_decoder.
        var idToContent: [Int: String] = [:]
        if let data = try? Data(
            contentsOf: dir.appendingPathComponent("tokenizer_config.json")),
            let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
            let decoder = obj["added_tokens_decoder"] as? [String: Any]
        {
            for (idStr, info) in decoder {
                if let id = Int(idStr), let info = info as? [String: Any],
                    let content = info["content"] as? String
                {
                    idToContent[id] = content
                }
            }
        }

        // eos_token_id (Int or [Int]) from generation_config.json — the
        // authoritative stop set the model was trained/exported with.
        if let data = try? Data(
            contentsOf: dir.appendingPathComponent("generation_config.json")),
            let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        {
            var ids: [Int] = []
            if let one = obj["eos_token_id"] as? Int {
                ids = [one]
            } else if let many = obj["eos_token_id"] as? [Int] {
                ids = many
            }
            for id in ids {
                if let content = idToContent[id] { tokens.insert(content) }
            }
        }
        return tokens
    }

    /// Stream a completion token-by-token through `onDelta`, in-process.
    /// `images` are raw image-file bytes (PNG/JPEG/...) carried inline from
    /// the requester's sealed envelope; each becomes a `CIImage` fed to the
    /// VLM. Empty for a text-only request. Returns
    /// (promptTokenCount, generationTokenCount) for the receipt.
    public func generate(
        prompt: String, images: [Data], maxTokens: Int, onDelta: (String) -> Void
    ) async throws -> (Int, Int) {
        let params = GenerateParameters(maxTokens: maxTokens)
        var tokensIn = 0
        var tokensOut = 0
        let stream: AsyncStream<Generation> = try await container.perform {
            (context: ModelContext) in
            let inputImages: [UserInput.Image] = images.compactMap { data in
                CIImage(data: data).map { UserInput.Image.ciImage($0) }
            }
            let userInput =
                inputImages.isEmpty
                ? UserInput(chat: [.user(prompt)])
                : UserInput(chat: [.user(prompt, images: inputImages)])
            let input = try await context.processor.prepare(input: userInput)
            return try MLXLMCommon.generate(input: input, parameters: params, context: context)
        }
        for await item in stream {
            switch item {
            case .chunk(let text):
                onDelta(text)
            case .info(let info):
                tokensIn = info.promptTokenCount
                tokensOut = info.generationTokenCount
            case .toolCall:
                break
            }
        }
        return (tokensIn, tokensOut)
    }

    /// Locate the precompiled `mlx.metallib` the GPU kernels load and hash it
    /// (SHA-256 hex) so the attestation can pin it. Search order mirrors
    /// darkbloom's: env override, sibling of the executable, then any
    /// `*.metallib` bundled under the executable's directory tree.
    static func locateMetallibHash() -> String? {
        guard let url = locateMetallib() else { return nil }
        guard let data = try? Data(contentsOf: url) else { return nil }
        return SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    private static func locateMetallib() -> URL? {
        let fm = FileManager.default
        if let env = ProcessInfo.processInfo.environment["MLX_METALLIB_PATH"],
            !env.isEmpty, fm.fileExists(atPath: env)
        {
            return URL(fileURLWithPath: env)
        }
        // Search directories in MLX's own load order: next to THIS dylib (the
        // image that contains the MLX code — found via #dsohandle, exactly how
        // MLX's device.cpp locates it), then next to the executable.
        var dirs: [URL] = []
        if let dy = currentDylibDir() { dirs.append(dy) }
        dirs.append(
            URL(fileURLWithPath: CommandLine.arguments.first ?? "")
                .resolvingSymlinksInPath().deletingLastPathComponent())
        for dir in dirs {
            for name in ["mlx.metallib", "default.metallib"] {
                let c = dir.appendingPathComponent(name)
                if fm.fileExists(atPath: c.path) { return c }
            }
            // Fall back to any *.metallib bundled under this directory tree
            // (SwiftPM/Xcode place Cmlx's metallib in a *.bundle).
            if let en = fm.enumerator(at: dir, includingPropertiesForKeys: nil) {
                for case let u as URL in en where u.pathExtension == "metallib" {
                    return u
                }
            }
        }
        return nil
    }

    /// Directory containing THIS dylib, via `dladdr(#dsohandle)`.
    private static func currentDylibDir() -> URL? {
        var info = Dl_info()
        guard dladdr(#dsohandle, &info) != 0, let fname = info.dli_fname else { return nil }
        return URL(fileURLWithPath: String(cString: fname)).deletingLastPathComponent()
    }
}
