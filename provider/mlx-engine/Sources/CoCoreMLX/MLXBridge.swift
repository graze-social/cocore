// C ABI bridge (mirrors provider/enclave's @_cdecl pattern: handle-based,
// 0=success, negative=error). The Rust agent links this static library and
// calls these symbols from provider/src/engines/native_mlx.rs. Each function
// bridges the async MLXEngine API to a synchronous C call via a semaphore — the
// Rust side already runs generation on a dedicated blocking thread.

import Foundation

@_cdecl("cocore_mlx_load_model")
public func cocore_mlx_load_model(
    _ modelDir: UnsafePointer<CChar>?,
    _ outHandle: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> Int32 {
    guard let modelDir, let outHandle else { return -1 }
    let dir = String(cString: modelDir)
    let sem = DispatchSemaphore(value: 0)
    var engine: MLXEngine?
    var failure: Error?
    Task {
        do { engine = try await MLXEngine.load(modelDir: dir) } catch { failure = error }
        sem.signal()
    }
    sem.wait()
    guard let engine, failure == nil else {
        NSLog("cocore_mlx_load_model failed: \(String(describing: failure))")
        return -1
    }
    outHandle.pointee = UnsafeMutableRawPointer(Unmanaged.passRetained(engine).toOpaque())
    return 0
}

@_cdecl("cocore_mlx_generate")
public func cocore_mlx_generate(
    _ handle: UnsafeMutableRawPointer?,
    _ prompt: UnsafePointer<CChar>?,
    _ promptLen: Int,
    // Parallel arrays of inline image bytes (already base64-decoded by Rust).
    // `imageCount` is 0 for a text-only request, where the pointers may be null.
    _ imagePtrs: UnsafePointer<UnsafePointer<UInt8>?>?,
    _ imageLens: UnsafePointer<Int>?,
    _ imageCount: Int,
    _ maxTokens: Int32,
    _ onDelta: (@convention(c) (UnsafePointer<CChar>?, Int, UnsafeMutableRawPointer?) -> Void)?,
    _ ctx: UnsafeMutableRawPointer?,
    _ outTokensIn: UnsafeMutablePointer<Int32>?,
    _ outTokensOut: UnsafeMutablePointer<Int32>?
) -> Int32 {
    guard let handle, let prompt, let onDelta else { return -1 }
    let engine = Unmanaged<MLXEngine>.fromOpaque(handle).takeUnretainedValue()
    // The prompt may not be NUL-terminated within promptLen; build the String
    // from exactly promptLen bytes.
    let promptStr = prompt.withMemoryRebound(to: UInt8.self, capacity: promptLen) {
        String(decoding: UnsafeBufferPointer(start: $0, count: promptLen), as: UTF8.self)
    }
    // Copy each inline image into an owned `Data`. The borrow only has to last
    // until generation reads it, but copying keeps the async boundary safe.
    var images: [Data] = []
    if imageCount > 0, let imagePtrs, let imageLens {
        for i in 0..<imageCount {
            guard let p = imagePtrs[i] else { continue }
            images.append(Data(bytes: p, count: imageLens[i]))
        }
    }
    let sem = DispatchSemaphore(value: 0)
    var tin = 0
    var tout = 0
    var failure: Error?
    Task {
        do {
            (tin, tout) = try await engine.generate(
                prompt: promptStr, images: images, maxTokens: Int(maxTokens)
            ) {
                delta in
                var bytes = Array(delta.utf8)
                bytes.withUnsafeMutableBufferPointer { buf in
                    buf.baseAddress?.withMemoryRebound(to: CChar.self, capacity: buf.count) { cptr in
                        onDelta(cptr, buf.count, ctx)
                    }
                }
            }
        } catch { failure = error }
        sem.signal()
    }
    sem.wait()
    if failure != nil {
        NSLog("cocore_mlx_generate failed: \(String(describing: failure))")
        return -3
    }
    outTokensIn?.pointee = Int32(tin)
    outTokensOut?.pointee = Int32(tout)
    return 0
}

@_cdecl("cocore_mlx_metallib_hash")
public func cocore_mlx_metallib_hash(
    _ handle: UnsafeMutableRawPointer?,
    _ out: UnsafeMutablePointer<CChar>?,
    _ len: Int
) -> Int32 {
    guard let handle, let out else { return -1 }
    let engine = Unmanaged<MLXEngine>.fromOpaque(handle).takeUnretainedValue()
    guard let hash = engine.metallibHash else { return -2 }
    guard hash.utf8.count + 1 <= len else { return -3 }
    _ = hash.withCString { strcpy(out, $0) }
    return 0
}

@_cdecl("cocore_mlx_release")
public func cocore_mlx_release(_ handle: UnsafeMutableRawPointer?) {
    guard let handle else { return }
    Unmanaged<MLXEngine>.fromOpaque(handle).release()
}

// ---- Diffusion (image generation) bridge ------------------------------

@_cdecl("cocore_mlx_load_diffusion_model")
public func cocore_mlx_load_diffusion_model(
    _ modelId: UnsafePointer<CChar>?,
    _ modelDir: UnsafePointer<CChar>?,
    _ outHandle: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> Int32 {
    guard let modelId, let modelDir, let outHandle else { return -1 }
    let id = String(cString: modelId)
    let dir = String(cString: modelDir)
    let sem = DispatchSemaphore(value: 0)
    var engine: DiffusionEngine?
    var failure: Error?
    Task {
        do { engine = try await DiffusionEngine.load(modelId: id, modelDir: dir) } catch {
            failure = error
        }
        sem.signal()
    }
    sem.wait()
    guard let engine, failure == nil else {
        NSLog("cocore_mlx_load_diffusion_model failed: \(String(describing: failure))")
        return -1
    }
    outHandle.pointee = UnsafeMutableRawPointer(Unmanaged.passRetained(engine).toOpaque())
    return 0
}

@_cdecl("cocore_mlx_generate_image")
public func cocore_mlx_generate_image(
    _ handle: UnsafeMutableRawPointer?,
    _ prompt: UnsafePointer<CChar>?,
    _ promptLen: Int,
    _ imagePtrs: UnsafePointer<UnsafePointer<UInt8>?>?,
    _ imageLens: UnsafePointer<Int>?,
    _ imageCount: Int,
    _ steps: Int32,
    _ seed: Int32,
    _ outPng: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outPngLen: UnsafeMutablePointer<Int>?,
    _ outTokensIn: UnsafeMutablePointer<Int32>?,
    _ outTokensOut: UnsafeMutablePointer<Int32>?
) -> Int32 {
    guard let handle, let prompt, let outPng, let outPngLen else { return -1 }
    let engine = Unmanaged<DiffusionEngine>.fromOpaque(handle).takeUnretainedValue()
    let promptStr = prompt.withMemoryRebound(to: UInt8.self, capacity: promptLen) {
        String(decoding: UnsafeBufferPointer(start: $0, count: promptLen), as: UTF8.self)
    }
    var refs: [Data] = []
    if imageCount > 0, let imagePtrs, let imageLens {
        for i in 0..<imageCount {
            guard let p = imagePtrs[i] else { continue }
            refs.append(Data(bytes: p, count: imageLens[i]))
        }
    }
    let sem = DispatchSemaphore(value: 0)
    var png: Data?
    var tin = 0
    var tout = 0
    var failure: Error?
    Task {
        do {
            (png, tin, tout) = try await engine.generate(
                prompt: promptStr, referenceImages: refs, steps: Int(steps), seed: Int(seed))
        } catch { failure = error }
        sem.signal()
    }
    sem.wait()
    guard let png, failure == nil else {
        NSLog("cocore_mlx_generate_image failed: \(String(describing: failure))")
        return -3
    }
    // Hand the PNG to C in a malloc'd buffer the caller frees with
    // cocore_mlx_free_buffer.
    let buf = UnsafeMutablePointer<UInt8>.allocate(capacity: png.count)
    png.copyBytes(to: buf, count: png.count)
    outPng.pointee = buf
    outPngLen.pointee = png.count
    outTokensIn?.pointee = Int32(tin)
    outTokensOut?.pointee = Int32(tout)
    return 0
}

@_cdecl("cocore_mlx_free_buffer")
public func cocore_mlx_free_buffer(_ buf: UnsafeMutablePointer<UInt8>?) {
    buf?.deallocate()
}

@_cdecl("cocore_mlx_diffusion_metallib_hash")
public func cocore_mlx_diffusion_metallib_hash(
    _ handle: UnsafeMutableRawPointer?,
    _ out: UnsafeMutablePointer<CChar>?,
    _ len: Int
) -> Int32 {
    guard let handle, let out else { return -1 }
    let engine = Unmanaged<DiffusionEngine>.fromOpaque(handle).takeUnretainedValue()
    guard let hash = engine.metallibHash else { return -2 }
    guard hash.utf8.count + 1 <= len else { return -3 }
    _ = hash.withCString { strcpy(out, $0) }
    return 0
}

@_cdecl("cocore_mlx_release_diffusion")
public func cocore_mlx_release_diffusion(_ handle: UnsafeMutableRawPointer?) {
    guard let handle else { return }
    Unmanaged<DiffusionEngine>.fromOpaque(handle).release()
}
