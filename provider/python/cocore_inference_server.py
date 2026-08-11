#!/usr/bin/env python3
"""
cocore inference subprocess wrapper.

The Rust agent (`cocore agent serve`) spawns one instance of this
script per model it wants to serve. The script loads vllm-mlx, binds
its FastAPI app to a Unix domain socket, and serves until the parent
sends SIGTERM *or* the parent goes away.

The second condition is a hard failsafe. An explicit SIGTERM is the
clean teardown path, but it is not the only one the parent can take:
the agent can be SIGKILLed, crash, get `launchctl kickstart -k`'d, or
exit non-gracefully on a trust-tier / model switch (`std::process::exit`
skips Rust destructors), and an uninstall removes the app without
signalling its children at all. In every one of those cases this child
would otherwise reparent to launchd (PPID 1) and run forever, holding
hundreds of MB of RAM on a socket nobody can reach. So a daemon thread
watches the parent PID and exits this process the moment the parent is
gone — see `_start_parent_death_watch`. The agent cannot leak us.

Why a subprocess and not in-process PyO3:
  * The Rust binary stays free of libpython linkage — `otool -L
    /usr/local/bin/cocore` shows only system frameworks, so the
    binary runs unchanged on any macOS arm64 regardless of which
    Python (if any) the user has installed system-wide.
  * Python crashes (vllm-mlx segfault, OOM kill, Metal-layer panic)
    kill only this child. The agent restarts it on the next request
    and keeps publishing receipts in the meantime.
  * Model swap = kill + respawn, no daemon restart.

Why Unix domain sockets and not TCP localhost:
  * No port-allocation race or collision risk.
  * File-mode 0600 on the socket gives access control by uid, so a
    different local user can't hit our inference engine.
  * Slightly faster (no TCP stack).

Usage (the agent calls this; users don't):
  cocore_inference_server.py --model <hf-id> --uds <socket-path>

The script writes a single line `READY` to stdout once the model is
loaded and the socket is bound — the parent watches for this so it
knows when to call `engine.ready() = true`.
"""

from __future__ import annotations

import argparse
import json
import logging
import signal
import stat
import sys
import threading
import time
from pathlib import Path

# Silence loggers BEFORE importing vllm_mlx / transformers /
# uvicorn — these libraries log prompt fragments, generated-token
# previews, and full request bodies at INFO. We want only WARN/ERROR
# from anywhere downstream so a postmortem of the subprocess (or its
# stderr captured by the Rust agent's ring buffer) doesn't contain
# user content. Configured at import time because Python's logging
# module caches handler attachments at module-load.
logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")
for _noisy in (
    "vllm_mlx",
    "vllm",
    "transformers",
    "huggingface_hub",
    "mlx",
    "uvicorn",
    "uvicorn.error",
    "uvicorn.access",
    "fastapi",
    "httpx",
    "asyncio",
):
    logging.getLogger(_noisy).setLevel(logging.WARNING)

# Faster, more reliable weight downloads: enable huggingface_hub's
# hf_transfer backend (parallel, byte-range, Rust-based) when the package is
# present. Without it, huggingface_hub falls back to a single-connection
# downloader that stalls and bursts on large weights. Must be set BEFORE
# huggingface_hub is first imported (it reads the flag at import), i.e. before
# the vllm_mlx import below. Silently no-ops on older venvs that predate the
# hf_transfer dependency, so they keep working (just without the speedup).
import os  # noqa: E402

try:
    import hf_transfer  # noqa: E402,F401

    os.environ.setdefault("HF_HUB_ENABLE_HF_TRANSFER", "1")
except Exception:
    pass

import uvicorn  # noqa: E402  (after logging config — intentional)
import vllm_mlx.server as srv  # noqa: E402
# LFM is not present in every installed vllm-mlx release. Importing the
# bundled parser registers it with the same ToolParserManager used by the
# server before request handling starts.
import cocore_lfm_tool_parser as _lfm_tool_parser  # noqa: E402,F401
_lfm_tool_parser.LFMToolParser.register_streaming_markers(srv)


def _unlink_if_owned(socket_path: Path, owned_ino: "int | None") -> None:
    """Unlink ``socket_path`` only if it is the exact socket we bound.

    Ownership is decided by inode identity: ``owned_ino`` is the
    ``st_ino`` of the socket uvicorn bound for *this* process, captured
    at bind time. We unlink only when the file still present at the path
    is that same inode. If the file is already gone, has a different
    inode (someone rebound the path), or we never recorded one (SIGTERM
    arrived before our socket was bound), we leave it untouched.

    The agent now hands each engine instance a per-instance socket path
    (model + pid + nonce), so a mismatch is nearly impossible in
    practice. This check is the belt-and-suspenders guarantee that a
    stray SIGTERM to this process can never delete a socket file that a
    *different* live engine is serving on — the failure that broke
    inference when paths were shared.
    """
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


# How often the parent-death watchdog checks whether the agent is still
# our parent. 2s is a negligible cost (one getppid() syscall) and bounds
# how long an orphan can linger after the parent dies — far below the
# minutes-long TCP timeout that left engines running in the field.
_PARENT_WATCH_INTERVAL_S = 2.0


def _start_parent_death_watch(
    parent_pid: int, socket_path: Path, bound_ino: "list[int | None]"
) -> None:
    """Exit this process if the parent agent ever goes away.

    The only *clean* teardown is an explicit SIGTERM from the parent, but
    that path is not guaranteed: the agent can be SIGKILLed, crash, be
    ``launchctl kickstart -k``'d, exit via ``std::process::exit`` on a
    tier/model switch (which skips its Rust ``Drop`` that would SIGTERM
    us), or be removed wholesale by an uninstall. In all of those the
    kernel reparents us to launchd (PID 1) and our ``getppid()`` stops
    equalling ``parent_pid``. A daemon thread polls for exactly that and,
    when it sees it, unlinks our own socket and hard-exits — so an engine
    can never outlive the agent that spawned it.

    ``parent_pid`` is the agent's PID, passed explicitly via ``--parent-pid``
    (PID reuse can't cause a false negative: an orphan's parent is launchd,
    never the recycled agent PID). We compare against it rather than just
    checking ``getppid() == 1`` so the watch also fires under a process
    reaper / subreaper that adopts orphans at a PID other than 1.
    """

    def _watch() -> None:
        while True:
            time.sleep(_PARENT_WATCH_INTERVAL_S)
            if os.getppid() != parent_pid:
                # Parent is gone. Drop our socket so we don't leave a dead
                # file behind, then hard-exit: uvicorn owns the main thread
                # and won't honour sys.exit() from here, so os._exit is the
                # only reliable way out of a foreign event loop.
                _unlink_if_owned(socket_path, bound_ino[0])
                os._exit(0)

    threading.Thread(target=_watch, name="parent-death-watch", daemon=True).start()


def main() -> None:
    ap = argparse.ArgumentParser(description="cocore inference subprocess wrapper")
    ap.add_argument(
        "--model",
        required=True,
        help="HuggingFace model id (e.g. mlx-community/Qwen2.5-7B-Instruct-4bit)",
    )
    ap.add_argument(
        "--uds",
        required=True,
        help="Unix domain socket path to bind",
    )
    ap.add_argument(
        "--parent-pid",
        type=int,
        default=None,
        help=(
            "PID of the spawning agent. When set, a watchdog thread exits "
            "this process if the parent goes away (reparent off this PID), so "
            "the engine can't outlive the agent. Defaults to the actual parent "
            "PID at startup for older agents that don't pass it."
        ),
    )
    ap.add_argument(
        "--vision",
        action="store_true",
        help=(
            "Force the multimodal (MLLM) load path (vllm-mlx force_mllm). Not "
            "normally needed: load_model auto-detects MLLM vs LLM from the "
            "model's config, so a real vision model loads multimodal on its own "
            "and the /v1/chat/completions endpoint accepts image_url parts. This "
            "is a manual override for a VLM that auto-detection misses."
        ),
    )
    ap.add_argument(
        "--enable-auto-tool-choice",
        action="store_true",
        help=(
            "Enable OpenAI-compatible tool calling (function calling) in "
            "vllm-mlx. When set, the /v1/chat/completions endpoint can parse "
            "and emit structured tool_calls so the model can invoke functions. "
            "Requires --tool-call-parser to select the format parser for the "
            "model family (e.g. hermes for Qwen, mistral for Mistral/Devstral)."
        ),
    )
    ap.add_argument(
        "--tool-call-parser",
        default=None,
        help=(
            "Tool call parser name (e.g. auto, hermes, mistral, qwen, llama, "
            "deepseek, kimi, granite, nemotron, xlam, functionary, glm47). "
            "Only used when --enable-auto-tool-choice is set. Defaults to "
            "'auto' which tries all formats."
        ),
    )
    ap.add_argument(
        "--default-chat-template-kwargs",
        default=None,
        help=(
            "JSON object passed through to vllm-mlx as default chat_template_kwargs "
            "for every request (for example: '{\"enable_thinking\": false}')."
        ),
    )
    args = ap.parse_args()

    socket_path = Path(args.uds)

    # Best-effort: remove any stale file sitting at our socket path
    # before binding, so uvicorn doesn't refuse with "Address already
    # in use". This path is unique to this engine instance (the agent
    # derives it from model + pid + nonce), so anything here is a
    # leftover at *our* address — never another live engine's socket.
    try:
        socket_path.unlink()
    except FileNotFoundError:
        pass

    # Track the identity (st_ino) of the socket uvicorn binds so our
    # SIGTERM handler only ever removes a socket THIS process created.
    # The socket doesn't exist until uvicorn.run() binds it, so a daemon
    # thread polls briefly for it to appear and records its inode. If we
    # never observe our own socket (e.g. SIGTERM arrives during model
    # load, before bind), bound_ino stays None and the handler unlinks
    # nothing — better to leave a path than delete one we can't prove is
    # ours.
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

    threading.Thread(
        target=_record_bound_socket, name="socket-ino-recorder", daemon=True
    ).start()

    # Parent-death failsafe: exit if the agent ever goes away, however it
    # goes (SIGKILL, crash, kickstart -k, std::process::exit on a tier/model
    # switch, uninstall). Capture the parent PID now — explicit from the
    # agent when given, else our actual parent at startup for older agents.
    # Started before the slow model load so an agent that dies *during* load
    # still reaps us. Shares bound_ino so it unlinks only our own socket.
    _start_parent_death_watch(
        args.parent_pid if args.parent_pid is not None else os.getppid(),
        socket_path,
        bound_ino,
    )

    # Load the model into vllm-mlx's module-level global. The
    # FastAPI routes inside vllm_mlx.server pick it up via
    # get_engine() at request time. This is the slow phase — 30-90s
    # for a 4-bit Qwen 7B on first cold load, mostly weight mmap
    # into Metal-managed buffers.
    print(
        f"[cocore-engine] loading model {args.model!r}"
        f"{' (vision/mllm)' if args.vision else ''}...",
        flush=True,
    )
    srv.load_model(args.model, force_mllm=args.vision)

    if args.default_chat_template_kwargs:
        try:
            _kwargs = json.loads(args.default_chat_template_kwargs)
        except Exception as exc:
            raise SystemExit(
                f"--default-chat-template-kwargs must be a JSON object: {exc}"
            ) from exc
        if not isinstance(_kwargs, dict):
            raise SystemExit("--default-chat-template-kwargs must decode to a JSON object")
        if hasattr(srv, "_default_chat_template_kwargs"):
            srv._default_chat_template_kwargs = _kwargs
            print(
                "[cocore-engine] default chat_template_kwargs configured",
                flush=True,
            )
        else:
            print(
                "[cocore-engine] WARNING: --default-chat-template-kwargs was passed "
                "but this vllm-mlx version does not expose _default_chat_template_kwargs.",
                flush=True,
            )

    # Enable tool calling when the flag was passed. vllm-mlx uses
    # module-level globals (_enable_auto_tool_choice, _tool_call_parser)
    # that the FastAPI routes read at request time. Setting them here
    # (after load_model, before uvicorn.run) configures the server so
    # /v1/chat/completions can parse and emit structured tool_calls.
    #
    # We verify the globals exist on the module before setting them.
    # If they don't, the installed vllm-mlx version doesn't support
    # tool calling — we warn and continue. The Rust parent separately
    # runs a forced-tool startup canary and will not advertise tool
    # support if this configuration doesn't produce structured tool_calls.
    if args.enable_auto_tool_choice:
        _has_tool_support = hasattr(srv, "_enable_auto_tool_choice")
        if not _has_tool_support:
            print(
                "[cocore-engine] WARNING: --enable-auto-tool-choice was passed "
                "but this vllm-mlx version does not expose _enable_auto_tool_choice. "
                "Tool calling will NOT work. Upgrade vllm-mlx to a version that "
                "supports tool calling (look for _enable_auto_tool_choice and "
                "_tool_call_parser globals in vllm_mlx.server).",
                flush=True,
            )
            # Still set the attributes so a future vllm-mlx upgrade picks
            # them up without needing a restart — but they're inert on
            # versions that don't read them.
            srv._enable_auto_tool_choice = True
            srv._tool_call_parser = args.tool_call_parser or "auto"
        else:
            srv._enable_auto_tool_choice = True
            srv._tool_call_parser = args.tool_call_parser or "auto"
            # Verify the parser is known. vllm-mlx supports a fixed set;
            # an unknown parser will cause request-time errors.
            _known_parsers = {
                "auto", "hermes", "nous", "mistral", "qwen", "qwen3_xml",
                "llama", "deepseek", "kimi", "granite", "harmony", "nemotron",
                "xlam", "functionary", "glm47", "gemma4", "minimax", "lfm",
            }
            _parser = srv._tool_call_parser
            if _parser not in _known_parsers:
                print(
                    f"[cocore-engine] WARNING: tool call parser {_parser!r} is not "
                    f"in the known set {sorted(_known_parsers)}. It may not work "
                    f"with this vllm-mlx version.",
                    flush=True,
                )
            print(
                f"[cocore-engine] tool calling enabled (parser: {srv._tool_call_parser})",
                flush=True,
            )

    print(f"[cocore-engine] model loaded; binding {socket_path}", flush=True)

    # SIGTERM handler that exits cleanly. uvicorn installs its own
    # signal handlers when it owns the event loop; we set ours BEFORE
    # uvicorn.run() so this only matters if uvicorn fails to install
    # them (which can happen if the loop isn't running yet).
    def _on_term(_signo, _frame):
        _unlink_if_owned(socket_path, bound_ino[0])
        sys.exit(0)

    signal.signal(signal.SIGTERM, _on_term)

    # The parent (Rust SubprocessEngine.start) decides we're ready by
    # polling the socket + sending an HTTP probe to `/v1/models` and
    # waiting for a 200 OK. We don't print a READY token here — the
    # parent's HTTP probe is the truth (catches "uvicorn bound but
    # crashed during routing setup" cases that a stdout token would
    # miss). See provider/src/engines/subprocess.rs::start for the
    # probe loop.
    #
    # Earlier revisions tried `@srv.app.on_event("startup")` and
    # `await server.startup()` patterns. on_event runs too late /
    # depends on FastAPI's lifespan ordering relative to vllm-mlx's
    # own setup; server.startup() isn't a public API in uvicorn 0.46+.
    # Polling sidesteps both.

    uvicorn.run(
        srv.app,
        uds=str(socket_path),
        log_level="warning",
        # Single worker — vllm-mlx isn't concurrent-safe for the same
        # engine instance; we serialize requests through the FastAPI
        # event loop.
        loop="asyncio",
        access_log=False,
    )


if __name__ == "__main__":
    main()
