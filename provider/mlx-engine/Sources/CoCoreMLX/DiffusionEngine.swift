// Native in-process MLX DIFFUSION (image-generation) engine — the image
// counterpart of MLXEngine. The prompt is decrypted by the Rust agent and
// handed here; generation runs entirely inside this statically-linked code
// (no subprocess, no IPC), so the measured `cocore` binary covers it and the
// confidential tier becomes reachable for image models too.
//
// Built on the upstream MLX-Swift `StableDiffusion` library (Apache-2.0, from
// mlx-swift-examples). That library ships TWO in-process models — SDXL-Turbo
// (fast, 2-step) and Stable Diffusion 2.1 base — so the confidential image
// tier is a curated set: SDXL-Turbo is the default. FLUX and other models run
// on the best-effort subprocess path (mflux), NOT here. Expanding the
// in-process model set means vendoring more model code into this measured
// binary (an ADR-level change), which is intentionally not done implicitly.

import Foundation
import CoreGraphics
import ImageIO
import UniformTypeIdentifiers
import Hub
import MLX
import StableDiffusion

public final class DiffusionEngine {
    private let configuration: StableDiffusionConfiguration
    private let hub: HubApi
    private let loadConfiguration: LoadConfiguration
    public let metallibHash: String?

    // Lazily-loaded generators (loading downloads + mmaps weights). Serialized
    // by the Rust side's mutex; we cache so repeated requests don't reload.
    private var t2i: TextToImageGenerator?
    private var i2i: ImageToImageGenerator?

    private init(
        configuration: StableDiffusionConfiguration,
        hub: HubApi,
        loadConfiguration: LoadConfiguration,
        metallibHash: String?
    ) {
        self.configuration = configuration
        self.hub = hub
        self.loadConfiguration = loadConfiguration
        self.metallibHash = metallibHash
    }

    /// Map a requested model id to one of the upstream in-process presets.
    /// SDXL-Turbo is the default (fast, 2-step); an id that names SD-2.1 picks
    /// that preset. FLUX/other ids never reach here — the registry routes them
    /// to the subprocess engine — but if one does, it falls back to SDXL-Turbo.
    private static func preset(for modelId: String) -> StableDiffusionConfiguration {
        let m = modelId.lowercased()
        if m.contains("2-1") || m.contains("2.1") || m.contains("sd21") || m.contains("v2-1") {
            return .presetStableDiffusion21Base
        }
        return .presetSDXLTurbo
    }

    /// Construct the engine for `modelId`. `modelDir`, when non-empty, is used
    /// as the HubApi download base (where weights are cached); empty uses the
    /// default Hub cache. The weights are downloaded lazily on first generate
    /// so construction is cheap and can't hang the serve loop.
    public static func load(modelId: String, modelDir: String) async throws -> DiffusionEngine {
        let configuration = preset(for: modelId)
        let hub =
            modelDir.isEmpty
            ? HubApi()
            : HubApi(downloadBase: URL(fileURLWithPath: modelDir))
        // float16 weights, quantized text-encoder/UNet to keep RAM modest.
        let loadConfiguration = LoadConfiguration(float16: true, quantize: true)
        return DiffusionEngine(
            configuration: configuration,
            hub: hub,
            loadConfiguration: loadConfiguration,
            metallibHash: MLXEngine.locateMetallibHash()
        )
    }

    /// Generate one image as PNG `Data`. `referenceImages` (raw file bytes)
    /// drive img2img when non-empty; empty = text-to-image. Returns
    /// `(png, tokensIn, tokensOut)` (byte-estimate token counts).
    public func generate(
        prompt: String,
        referenceImages: [Data],
        steps: Int,
        seed: Int
    ) async throws -> (Data, Int, Int) {
        let image: CGImage
        if let refData = referenceImages.first, let ref = decodeCGImage(from: refData) {
            image = try generateImageToImage(
                prompt: prompt, reference: ref, steps: steps, seed: seed)
        } else {
            image = try generateTextToImage(prompt: prompt, steps: steps, seed: seed)
        }
        guard let png = pngData(from: image) else {
            throw NSError(
                domain: "CoCoreMLX", code: -10,
                userInfo: [NSLocalizedDescriptionKey: "failed to PNG-encode generated image"])
        }
        let tokensIn = max(1, prompt.utf8.count / 4)
        let tokensOut = max(1, png.count / 4)
        return (png, tokensIn, tokensOut)
    }

    // MARK: - Generation

    private func generateTextToImage(prompt: String, steps: Int, seed: Int) throws -> CGImage {
        if t2i == nil {
            guard
                let generator = try configuration.textToImageGenerator(
                    hub: hub, configuration: loadConfiguration)
            else {
                throw NSError(
                    domain: "CoCoreMLX", code: -12,
                    userInfo: [
                        NSLocalizedDescriptionKey:
                            "model \(configuration.id) does not support text-to-image"
                    ])
            }
            generator.ensureLoaded()
            t2i = generator
        }
        let generator = t2i!
        let params = evaluateParameters(prompt: prompt, steps: steps, seed: seed)
        let latents = generator.generateLatents(parameters: params)
        var lastXt: MLXArray!
        for xt in latents {
            eval(xt)
            lastXt = xt
        }
        return decode(generator.detachedDecoder(), latent: lastXt)
    }

    private func generateImageToImage(
        prompt: String, reference: CGImage, steps: Int, seed: Int
    ) throws -> CGImage {
        if i2i == nil {
            guard
                let generator = try configuration.imageToImageGenerator(
                    hub: hub, configuration: loadConfiguration)
            else {
                throw NSError(
                    domain: "CoCoreMLX", code: -13,
                    userInfo: [
                        NSLocalizedDescriptionKey:
                            "model \(configuration.id) does not support image-to-image"
                    ])
            }
            generator.ensureLoaded()
            i2i = generator
        }
        let generator = i2i!
        let params = evaluateParameters(prompt: prompt, steps: steps, seed: seed)
        let initImage = Image(image: reference, maximumEdge: params.latentSize[0] * 8).data
        let latents = generator.generateLatents(
            image: initImage, parameters: params, strength: 0.6)
        var lastXt: MLXArray!
        for xt in latents {
            eval(xt)
            lastXt = xt
        }
        return decode(generator.detachedDecoder(), latent: lastXt)
    }

    /// Build EvaluateParameters from the preset defaults, overriding the
    /// caller's prompt + step count (and seed when > 0).
    private func evaluateParameters(prompt: String, steps: Int, seed: Int) -> EvaluateParameters {
        var params = configuration.defaultParameters()
        params.prompt = prompt
        if steps > 0 { params.steps = steps }
        if seed > 0 { params.seed = UInt64(seed) }
        params.imageCount = 1
        return params
    }

    private func decode(_ decoder: ImageDecoder, latent: MLXArray) -> CGImage {
        let image = decoder(latent[0..<1])
        eval(image)
        return Image(image).asCGImage()
    }

    private func decodeCGImage(from data: Data) -> CGImage? {
        guard let src = CGImageSourceCreateWithData(data as CFData, nil) else { return nil }
        return CGImageSourceCreateImageAtIndex(src, 0, nil)
    }

    private func pngData(from image: CGImage) -> Data? {
        let out = NSMutableData()
        guard
            let dest = CGImageDestinationCreateWithData(
                out, UTType.png.identifier as CFString, 1, nil)
        else { return nil }
        CGImageDestinationAddImage(dest, image, nil)
        guard CGImageDestinationFinalize(dest) else { return nil }
        return out as Data
    }
}
