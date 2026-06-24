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

// Release a handle from cocore_mlx_load_model. Safe with NULL.
void cocore_mlx_release(void *handle);

// ---- Diffusion (image generation) -------------------------------------
// Same in-process, measured-binary posture as the LLM path: the prompt is
// decrypted by the Rust agent and the image is generated entirely inside
// libCoCoreMLX (no subprocess), so the SE attestation covers it.

// Load an MLX diffusion model into THIS process. `model_id` selects the
// in-process preset (SDXL-Turbo default, or SD-2.1 when the id names it);
// `model_dir`, when non-empty, is the HubApi download base (weight cache).
// Opaque handle in *out_handle. 0 on success.
int cocore_mlx_load_diffusion_model(
    const char *model_id, const char *model_dir, void **out_handle);

// Generate ONE image for `prompt` (optionally conditioned on reference
// images for img2img — parallel arrays of raw, already-base64-decoded image
// bytes; `image_count` 0 for text-to-image). The encoded PNG is written to a
// freshly malloc'd buffer returned via *out_png / *out_png_len; the caller
// MUST free it with cocore_mlx_free_buffer. `out_tokens_in`/`out_tokens_out`
// receive byte-estimate token counts until step pricing lands. Returns 0 on
// success, negative on error.
int cocore_mlx_generate_image(
    void *handle,
    const char *prompt,
    size_t prompt_len,
    const unsigned char *const *image_ptrs,
    const size_t *image_lens,
    size_t image_count,
    int steps,
    int seed,
    unsigned char **out_png,
    size_t *out_png_len,
    int *out_tokens_in,
    int *out_tokens_out);

// Free a buffer returned by cocore_mlx_generate_image. Safe with NULL.
void cocore_mlx_free_buffer(unsigned char *buf);

// SHA-256 hex of the metallib the diffusion engine loaded (capacity >= 65).
int cocore_mlx_diffusion_metallib_hash(void *handle, char *out, size_t len);

// Release a diffusion handle. Safe with NULL.
void cocore_mlx_release_diffusion(void *handle);

#ifdef __cplusplus
}
#endif

#endif // COCORE_MLX_H
