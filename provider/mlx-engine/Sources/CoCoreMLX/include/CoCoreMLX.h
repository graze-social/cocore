// C ABI for the native in-process MLX inference engine. The Rust agent
// (provider/src/engines/native_mlx.rs, feature `native_mlx`) links this static
// library and calls these symbols. Mirrors provider/enclave/.../CoCoreEnclave.h:
// handle-based, 0 = success, negative = error.
#ifndef COCORE_MLX_H
#define COCORE_MLX_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Load an MLX model (safetensors + tokenizer) from `model_dir` into THIS
// process. Returns an opaque handle in *out_handle. 0 on success.
int cocore_mlx_load_model(const char *model_dir, void **out_handle);

// Stream a completion for `prompt` token-by-token. Each decoded delta is passed
// to `on_delta(delta_utf8, len, ctx)`; the engine never buffers the plaintext
// outside this process. `out_tokens_in`/`out_tokens_out` receive the counts.
// Returns 0 on success, negative on error.
int cocore_mlx_generate(
    void *handle,
    const char *prompt,
    size_t prompt_len,
    int max_tokens,
    void (*on_delta)(const char *delta, size_t len, void *ctx),
    void *ctx,
    int *out_tokens_in,
    int *out_tokens_out);

// SHA-256 hex (64 chars + NUL) of the precompiled mlx.metallib the engine
// loaded, written into `out` (capacity `len` >= 65). 0 on success.
int cocore_mlx_metallib_hash(void *handle, char *out, size_t len);

// Evict the Metal allocator's cached buffers (KV cache + scratch) so a served
// prompt's generation state doesn't linger in the GPU pool between jobs.
// Best-effort scrub; the handle is unused (clearCache is process-global).
void cocore_mlx_clear_cache(void *handle);

// Release a handle from cocore_mlx_load_model. Safe with NULL.
void cocore_mlx_release(void *handle);

#ifdef __cplusplus
}
#endif

#endif // COCORE_MLX_H
