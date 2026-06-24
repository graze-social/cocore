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
    print(f"[cocore-engine] loading model {args.model!r}...", flush=True)
    srv.load_model(args.model)
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
