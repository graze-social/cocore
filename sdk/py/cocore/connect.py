"""``Sign in with co/core`` for applications: the requester side of device pairing.

An app that wants to act on a user's co/core account starts a pairing, sends
the user to co/core to approve "Connect <app> to co/core", and collects an
API key scoped to that user. The app identifies itself with a
``dev.cocore.app.registration`` record on its own account (``app_did``); the
user is returned to one of that record's ``returnUrls`` provided the return
host serves ``/.well-known/cocore-app.json`` naming the app's DID.

Server-side only: the ``device_id`` returned by :func:`start_app_pairing` is the
credential that collects the key, so it must never reach a browser.

Standard library only — no dependencies.
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Optional

DEFAULT_CONSOLE_URL = "https://cocore.dev"


class AppPairingError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(f"{message} (HTTP {status})" if status else message)
        self.status = status


@dataclass(frozen=True)
class AppPairing:
    device_id: str
    user_code: str
    verification_uri: str
    poll_interval_secs: int
    expires_in_secs: int


@dataclass(frozen=True)
class PairedSession:
    did: str
    handle: str
    api_key: str
    api_base: str


@dataclass(frozen=True)
class AppPairingPoll:
    status: str  # pending | session | denied | expired | consumed | unknown
    session: Optional[PairedSession] = None


def _request(url: str, *, method: str = "GET", body: Optional[dict] = None, timeout: float = 15.0):
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={"content-type": "application/json", "accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed https host
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as exc:
        try:
            payload = json.loads(exc.read() or b"{}")
        except ValueError:
            payload = {}
        return exc.code, payload


def start_app_pairing(
    app_did: str,
    *,
    key_name: Optional[str] = None,
    return_url: Optional[str] = None,
    console_url: str = DEFAULT_CONSOLE_URL,
) -> AppPairing:
    """Begin a pairing. Send the user to ``verification_uri``; keep ``device_id`` server-side."""
    body = {"appDid": app_did}
    if key_name:
        body["keyName"] = key_name
    if return_url:
        body["returnUrl"] = return_url
    status, payload = _request(f"{console_url.rstrip('/')}/api/xrpc/dev.cocore.devicePair.start", method="POST", body=body)
    if status != 200:
        raise AppPairingError(status, str(payload.get("message") or payload.get("error") or "start failed"))
    return AppPairing(
        device_id=payload["deviceId"],
        user_code=payload["userCode"],
        verification_uri=payload["verificationUri"],
        poll_interval_secs=int(payload.get("pollIntervalSecs") or 3),
        expires_in_secs=int(payload.get("expiresInSecs") or 600),
    )


def poll_app_pairing(device_id: str, *, console_url: str = DEFAULT_CONSOLE_URL) -> AppPairingPoll:
    """One poll. ``session`` arrives exactly once; afterwards the attempt is ``consumed``."""
    url = f"{console_url.rstrip('/')}/api/xrpc/dev.cocore.devicePair.poll?deviceId={urllib.parse.quote(device_id)}"
    status, payload = _request(url)
    state = str(payload.get("status") or "")
    if status == 200 and state == "session" and isinstance(payload.get("session"), dict):
        s = payload["session"]
        return AppPairingPoll("session", PairedSession(s["did"], s.get("handle") or s["did"], s["apiKey"], s["apiBase"]))
    if status == 200 and state == "pending":
        return AppPairingPoll("pending")
    if status == 403:
        return AppPairingPoll("denied")
    if status == 404:
        return AppPairingPoll("unknown")
    if status == 410:
        return AppPairingPoll("consumed" if state == "consumed" else "expired")
    raise AppPairingError(status, str(payload.get("message") or payload.get("error") or "poll failed"))


def wait_for_app_pairing(pairing: AppPairing, *, console_url: str = DEFAULT_CONSOLE_URL) -> PairedSession:
    """Poll until the user acts or the attempt expires. Returns the session on approval."""
    deadline = time.monotonic() + pairing.expires_in_secs + 5
    interval = max(1, pairing.poll_interval_secs)
    while time.monotonic() < deadline:
        result = poll_app_pairing(pairing.device_id, console_url=console_url)
        if result.status == "session" and result.session is not None:
            return result.session
        if result.status != "pending":
            raise AppPairingError(0, f"pairing {result.status}")
        time.sleep(interval)
    raise AppPairingError(0, "pairing expired")
