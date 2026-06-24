#!/usr/bin/env python3
"""
cocore IMAGE-generation subprocess wrapper.

Sibling of ``cocore_inference_server.py`` (chat/VLM). The Rust agent
(`cocore agent serve`) spawns one instance per image model it serves;
this script loads an MLX diffusion backend (mflux — FLUX.1), binds a
small FastAPI app to a Unix domain socket, and serves until the parent
SIGTERMs it *or* the parent goes away.

The lifecycle (UDS, per-instance socket, parent-death watchdog,
WARN-only/no-content logging) is intentionally identical to the chat
wrapper — see that file's module docstring for the full rationale. The
ONLY differences are the backend (diffusion, not vllm-mlx) and the wire
API, which is cocore-owned and minimal rather than OpenAI-shaped:

  GET  /health             -> 200 {"status":"ok"}  (readiness probe)
  POST /generate           -> {"images":[{"mime":"image/png","data":"<b64>"}]}
       body: {"prompt": str,
              "images": [{"mime","data"}]?,   # img2img reference(s)
              "steps": int?, "seed": int?,
              "width": int?, "height": int?}

The Rust ImageSubprocessEngine builds the images-v1 receipt envelope from
the returned images; this server never touches receipts or commitments.

Usage (the agent calls this; users don't):
  cocore_image_server.py --model <id> --uds <socket-path> --parent-pid <pid>
"""

from __future__ import annotations

import argparse
import base64
import io
import logging
import os
import signal
import stat
import sys
import threading
import time
from pathlib import Path

# Silence content-leaking loggers BEFORE importing the backend — same
# discipline as the chat wrapper. Diffusion backends log prompts and
# progress at INFO; we want only WARN/ERROR so a postmortem of this
# child's stderr (captured by the agent's ring buffer) holds no user
# content.
logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")
for _noisy in (
    "mflux",
    "mlx",
    "diffusers",
    "transformers",
    "huggingface_hub",
    "uvicorn",
    "uvicorn.error",
    "uvicorn.access",
    "fastapi",
    "httpx",
    "asyncio",
    "PIL",
):
    logging.getLogger(_noisy).setLevel(logging.WARNING)

try:
    import hf_transfer  # noqa: F401

    os.environ.setdefault("HF_HUB_ENABLE_HF_TRANSFER", "1")
except Exception:
    pass

import uvicorn  # noqa: E402  (after logging config — intentional)
from fastapi import FastAPI, Request  # noqa: E402
from fastapi.responses import JSONResponse  # noqa: E402

# ---------------------------------------------------------------------------
# Socket / parent-death lifecycle — copied verbatim in shape from
# cocore_inference_server.py so the two wrappers behave identically.
# ---------------------------------------------------------------------------

_PARENT_WATCH_INTERVAL_S = 2.0


def _unlink_if_owned(socket_path: Path, owned_ino: "int | None") -> None:
    if owned_ino is None:
        return
    try:
        st = socket_path.stat()
    except FileNotFoundError:
        return
    if st.st_ino != owned_ino:
        return
    try:
        socket_path.unlink()
    except FileNotFoundError:
        pass


def _start_parent_death_watch(
    parent_pid: int, socket_path: Path, bound_ino: "list[int | None]"
) -> None:
    def _watch() -> None:
        while True:
            time.sleep(_PARENT_WATCH_INTERVAL_S)
            if os.getppid() != parent_pid:
                _unlink_if_owned(socket_path, bound_ino[0])
                os._exit(0)

    threading.Thread(target=_watch, name="parent-death-watch", daemon=True).start()


# ---------------------------------------------------------------------------
# Diffusion backend (mflux / FLUX.1).
# ---------------------------------------------------------------------------


def _resolve_flux_name(model: str) -> str:
    """Map an agent-supplied model id to an mflux model name. mflux's
    built-in names are ``schnell`` (fast, 4 steps) and ``dev`` (slower,
    higher quality); a full HF path is also accepted by recent mflux.
    """
    m = model.lower()
    if "schnell" in m:
        return "schnell"
    if "dev" in m:
        return "dev"
    # Pass the id through; recent mflux resolves an HF repo path directly.
    return model


class _FluxBackend:
    """Thin wrapper over mflux that hides API drift across versions.

    Loads once at startup (the slow phase: weight download + MLX mmap)
    and serializes generation behind a lock — MLX isn't concurrent-safe
    for one model instance.
    """

    def __init__(self, model: str, quantize: int) -> None:
        self._lock = threading.Lock()
        self._default_steps = 4 if _resolve_flux_name(model) == "schnell" else 20
        self._flux, self._Config = _construct_flux(model, quantize)

    def default_steps(self) -> int:
        return self._default_steps

    def generate_png(
        self,
        prompt: str,
        steps: int,
        seed: int,
        width: int,
        height: int,
        init_image_path: "str | None",
    ) -> bytes:
        Config = self._Config
        cfg_kwargs = {"num_inference_steps": steps, "height": height, "width": width}
        # img2img: recent mflux accepts an init image + strength on Config.
        # Older versions don't; fall back to plain t2i if construction with
        # the image kwargs fails.
        config = None
        if init_image_path is not None:
            for kwargs in (
                {**cfg_kwargs, "image_path": init_image_path, "image_strength": 0.6},
                {**cfg_kwargs, "init_image_path": init_image_path, "init_image_strength": 0.6},
            ):
                try:
                    config = Config(**kwargs)
                    break
                except TypeError:
                    continue
        if config is None:
            config = Config(**cfg_kwargs)

        with self._lock:
            result = self._flux.generate_image(seed=seed, prompt=prompt, config=config)
        pil = getattr(result, "image", result)
        buf = io.BytesIO()
        pil.save(buf, format="PNG")
        return buf.getvalue()


def _construct_flux(model: str, quantize: int):
    """Construct an mflux Flux1 across a couple of known API shapes.
    Returns ``(flux_instance, Config_class)``.
    """
    name = _resolve_flux_name(model)
    from mflux import Config  # type: ignore

    # Newer API: Flux1(model_config=ModelConfig..., quantize=...).
    try:
        from mflux import Flux1, ModelConfig  # type: ignore

        try:
            model_config = ModelConfig.from_name(name)
        except Exception:
            model_config = ModelConfig.from_alias(name)  # type: ignore[attr-defined]
        return Flux1(model_config=model_config, quantize=quantize), Config
    except Exception:
        pass

    # Older API: Flux1.from_name(model_name=..., quantize=...).
    from mflux import Flux1  # type: ignore

    return Flux1.from_name(model_name=name, quantize=quantize), Config


# ---------------------------------------------------------------------------
# HTTP app.
# ---------------------------------------------------------------------------


def _build_app(backend: _FluxBackend) -> FastAPI:
    app = FastAPI()

    @app.get("/health")
    async def health() -> JSONResponse:  # type: ignore[unused-ignore]
        return JSONResponse({"status": "ok"})

    @app.post("/generate")
    async def generate(req: Request) -> JSONResponse:  # type: ignore[unused-ignore]
        body = await req.json()
        prompt = body.get("prompt")
        if not isinstance(prompt, str):
            return JSONResponse({"error": "prompt must be a string"}, status_code=400)
        steps = int(body.get("steps") or backend.default_steps())
        seed = int(body.get("seed") if body.get("seed") is not None else int(time.time()))
        width = int(body.get("width") or 512)
        height = int(body.get("height") or 512)

        # img2img: take the FIRST reference image, decode to a temp PNG the
        # backend can read. (Multi-reference is backend-specific; v1 uses one.)
        init_path = None
        ref_images = body.get("images") or []
        if isinstance(ref_images, list) and ref_images:
            first = ref_images[0]
            if isinstance(first, dict) and isinstance(first.get("data"), str):
                raw = base64.b64decode(first["data"])
                init_path = str(Path(args_uds_dir() / f"ref-{os.getpid()}-{seed}.png"))
                with open(init_path, "wb") as fh:
                    fh.write(raw)

        try:
            png = backend.generate_png(prompt, steps, seed, width, height, init_path)
        except Exception as e:  # noqa: BLE001
            # Never echo the prompt back in the error.
            return JSONResponse(
                {"error": f"image generation failed: {type(e).__name__}"}, status_code=500
            )
        finally:
            if init_path:
                try:
                    os.unlink(init_path)
                except OSError:
                    pass

        data_b64 = base64.b64encode(png).decode("ascii")
        return JSONResponse({"images": [{"mime": "image/png", "data": data_b64}]})

    return app


# The socket dir is a convenient scratch location for temp reference images.
_UDS_DIR: "Path | None" = None


def args_uds_dir() -> Path:
    return _UDS_DIR or Path("/tmp")


def main() -> None:
    global _UDS_DIR
    ap = argparse.ArgumentParser(description="cocore image-generation subprocess wrapper")
    ap.add_argument("--model", required=True, help="Image model id (e.g. FLUX.1-schnell or schnell)")
    ap.add_argument("--uds", required=True, help="Unix domain socket path to bind")
    ap.add_argument("--parent-pid", type=int, default=None, help="Spawning agent PID for the watchdog")
    ap.add_argument(
        "--quantize",
        type=int,
        default=8,
        help="Weight quantization bits for mflux (4 or 8). Lower = less RAM.",
    )
    args = ap.parse_args()

    socket_path = Path(args.uds)
    _UDS_DIR = socket_path.parent

    try:
        socket_path.unlink()
    except FileNotFoundError:
        pass

    bound_ino: "list[int | None]" = [None]

    def _record_bound_socket() -> None:
        deadline = time.monotonic() + 60.0
        while time.monotonic() < deadline:
            try:
                st = socket_path.stat()
            except FileNotFoundError:
                time.sleep(0.05)
                continue
            if stat.S_ISSOCK(st.st_mode):
                bound_ino[0] = st.st_ino
                return
            time.sleep(0.05)

    threading.Thread(target=_record_bound_socket, name="socket-ino-recorder", daemon=True).start()

    _start_parent_death_watch(
        args.parent_pid if args.parent_pid is not None else os.getppid(),
        socket_path,
        bound_ino,
    )

    print(f"[cocore-image-engine] loading diffusion model {args.model!r}...", flush=True)
    backend = _FluxBackend(args.model, args.quantize)
    print(f"[cocore-image-engine] model loaded; binding {socket_path}", flush=True)

    app = _build_app(backend)

    def _on_term(_signo, _frame):
        _unlink_if_owned(socket_path, bound_ino[0])
        sys.exit(0)

    signal.signal(signal.SIGTERM, _on_term)

    # The parent decides readiness via an HTTP probe to /health (see
    # ImageSubprocessEngine::probe_ready) — no READY token needed.
    uvicorn.run(app, uds=str(socket_path), log_level="warning", loop="asyncio", access_log=False)


if __name__ == "__main__":
    main()
