"""System-One decision receipts: canonical bytes, and replay verification.

Python mirror of ``packages/sdk/src/decision.ts``. The three implementations —
the Rust engine that produces the bytes, the TypeScript verifier, and this one —
MUST agree byte for byte, or honest receipts fail verification as if they were
forged. The cross-language fixture written by
``provider/tests/cross_lang_fixture.rs`` pins all three together; see
``tests/test_decision.py``.

Why a decision receipt can be verified at all
---------------------------------------------
For an autoregressive completion, ``outputCommitment`` is unfalsifiable: the
provider sampled with a random seed, so nobody can re-run the job and compare.
A System-One decision is one deterministic encoder pass with no sampler, so the
same artifact over the same state gives the same probabilities. The requester,
who already holds the plaintext they sent, can re-run it and check the
commitment — offline, with no cooperation from the provider.

What this does NOT prove
------------------------
Not confidentiality. A decision is served by an out-of-process engine, so the
machine operator could read the state. Nothing here changes that, and nothing
here should be described as confidential or attested.

Not the artifact by itself. ``receipt.params.modelDigest`` is a provider CLAIM;
nothing verifies it at publish time. What makes it worth having is that this
module makes it falsifiable — run the artifact the receipt names and either the
commitment matches or you hold a signed receipt that contradicts its own
computation. Pass ``ran_digest`` to pin that you ran what was claimed.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Callable, Mapping, Optional

from .validate import Finding, ValidationReport, _err, _ok

__all__ = [
    "canonical_decision_request",
    "canonical_decision_answers",
    "verify_decision_receipt",
]


def canonical_decision_request(request: Mapping[str, Any], model: str) -> str:
    """The exact bytes the requester sealed — what ``inputCommitment`` covers.

    Keys are sorted recursively so the same logical request commits to the same
    digest regardless of how any implementation's JSON serializer ordered its
    object keys. Arrays keep their order: a score question's ``criteria`` levels
    are ordered, and reordering them would change the question being asked.
    """
    payload = {
        "model": model,
        "state": request.get("state"),
        "questions": request.get("questions") or {},
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _f64(value: Any) -> str:
    """Format a decision number the way the provider does.

    This is the subtle one. Every probability, score and confidence is an f64 on
    the provider, and both Rust's serde_json and Python's json print an integral
    f64 with a trailing ``.0``. A Python ``int`` would print as ``1``, so values
    are coerced to float first — otherwise a confident answer (``noul: 1``,
    ``noul: 0``, ``score: 2``) parsed from JSON as an int would hash differently
    here than on the provider and fail an honest receipt as if it were forged.

    Exponent notation is refused rather than guessed at: no probability or score
    should ever be out there, and the three languages format it differently.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"decision value is not a number: {value!r}")
    text = repr(float(value))
    if "e" in text or "E" in text or text in ("inf", "-inf", "nan"):
        raise ValueError(f"decision value {text} is outside the canonical range")
    return text


def _int(value: Any) -> str:
    """Token counts are integers on the provider (u64), so no ``.0``."""
    if isinstance(value, bool) or not isinstance(value, int):
        return "0"
    return str(value)


def _probabilities(value: Any) -> str:
    if not isinstance(value, Mapping):
        return "{}"
    body = ",".join(
        f"{json.dumps(k, ensure_ascii=False)}:{_f64(value[k])}" for k in sorted(value)
    )
    return "{" + body + "}"


def _confidence(value: Any) -> str:
    if value is None:
        return ""
    return f',"confidence":{_f64(value)}'


def _legend(value: Any) -> str:
    """Level descriptions, always strings.

    A raw JSON value here would be uncanonicalizable: JavaScript cannot tell
    ``1`` from ``1.0``, so a numeric legend entry would hash differently in a
    TypeScript verifier. Non-strings are coerced to their JSON text, matching
    the Rust engine. Omitted entirely when empty, as the provider omits it.
    """
    if not isinstance(value, Mapping) or len(value) == 0:
        return ""
    parts = []
    for k in sorted(value):
        v = value[k]
        text = v if isinstance(v, str) else json.dumps(v, separators=(",", ":"))
        parts.append(f"{json.dumps(k, ensure_ascii=False)}:{json.dumps(text, ensure_ascii=False)}")
    return ',"legend":{' + ",".join(parts) + "}"


def _canonical_answer(raw: Any) -> str:
    answer = raw if isinstance(raw, Mapping) else {}
    kind = answer.get("type")
    if kind == "noul":
        return '{"type":"noul","noul":' + _f64(answer.get("noul")) + "}"
    if kind == "choice":
        return (
            '{"type":"choice","choice":'
            + json.dumps(answer.get("choice"), ensure_ascii=False)
            + ',"probabilities":'
            + _probabilities(answer.get("probabilities"))
            + _confidence(answer.get("confidence"))
            + "}"
        )
    return (
        '{"type":"score","score":'
        + _f64(answer.get("score"))
        + _legend(answer.get("legend"))
        + ',"probabilities":'
        + _probabilities(answer.get("probabilities"))
        + _confidence(answer.get("confidence"))
        + "}"
    )


def canonical_decision_answers(envelope: Mapping[str, Any]) -> str:
    """Re-emit an answers envelope in the engine's canonical form — what
    ``outputCommitment`` covers.

    Field order is fixed and every map is emitted with sorted keys, so two
    honest providers whose decision servers happened to order JSON keys
    differently still produce byte-identical output. Unknown answer fields are
    dropped: the canonical form is a closed shape, and silently carrying an
    extra key would let two implementations disagree on the bytes.
    """
    answers = envelope.get("answers") or {}
    body = ",".join(
        f"{json.dumps(qid, ensure_ascii=False)}:{_canonical_answer(answers[qid])}"
        for qid in sorted(answers)
    )
    usage = envelope.get("usage") or {}
    return (
        '{"model":'
        + json.dumps(envelope.get("model"), ensure_ascii=False)
        + ',"answers":{'
        + body
        + '},"usage":{"input_tokens":'
        + _int(usage.get("input_tokens", 0))
        + ',"output_tokens":'
        + _int(usage.get("output_tokens", 0))
        + "}}"
    )


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify_decision_receipt(
    receipt: Mapping[str, Any],
    job: Mapping[str, Any],
    request: Mapping[str, Any],
    runner: Optional[Callable[[Mapping[str, Any]], Mapping[str, Any]]] = None,
    ran_digest: Optional[str] = None,
) -> ValidationReport:
    """Check a decision receipt against the computation it claims to describe.

    Three things are verified, in increasing strength:

    1. ``inputCommitment`` — the job really commits to the request you sent, so
       the provider was asked what you think it was asked.
    2. ``outputCommitment`` — re-running the decision reproduces the exact bytes
       the provider signed. This is the one chat can never offer.
    3. ``params.modelDigest`` — the artifact you ran is the one the receipt
       named (only when ``ran_digest`` is supplied).

    ``runner`` takes the request (with ``model`` filled in) and returns the
    answers envelope. Point it at a model server YOU control: re-running against
    the provider that issued the receipt proves nothing. Omit it to check the
    commitments' internal consistency only.

    A mismatch at step 2 is not ambiguous: the provider signed a receipt whose
    output its own claimed model does not produce.
    """
    findings: list[Finding] = []
    params = receipt.get("params") or {}
    claimed_digest = params.get("modelDigest")

    if receipt.get("model") != job.get("model"):
        _err(
            findings,
            "decision-model-mismatch",
            f'receipt.model "{receipt.get("model")}" is not the job\'s model "{job.get("model")}"',
        )

    # 0. Does the record say these bytes are a decision at all? A job without
    # inputFormat "decision-v1" can still be verified — the commitments are
    # what they are — but nothing except the caller's say-so identifies the
    # sealed bytes as a decision request. A warning, not an error: jobs
    # published before the format existed are legitimate.
    if job.get("inputFormat") != "decision-v1":
        findings.append(
            Finding(
                "warn",
                "decision-job-format-missing",
                f'the job declares inputFormat {job.get("inputFormat")!r} rather than '
                '"decision-v1", so the record does not describe its own bytes as a decision — '
                "this verification rests on you knowing what you sent",
            )
        )

    # 1. Did the job commit to the request we actually sent?
    canonical_request = canonical_decision_request(request, receipt.get("model") or "")
    input_commitment = _sha256_hex(canonical_request.encode("utf-8"))
    if input_commitment != job.get("inputCommitment"):
        _err(
            findings,
            "decision-input-commitment-mismatch",
            f'the job commits to {job.get("inputCommitment")} but the request supplied here '
            f"canonicalizes to {input_commitment} — this receipt is not for the decision you passed in",
        )
    if receipt.get("inputCommitment") != job.get("inputCommitment"):
        _err(
            findings,
            "decision-input-commitment-disagreement",
            "receipt.inputCommitment does not match job.inputCommitment",
        )

    # 3. Did we run what the receipt named? Checked before the replay so the
    # report says so even if the replay then fails.
    if ran_digest is not None:
        if claimed_digest is None:
            findings.append(
                Finding(
                    "warn",
                    "decision-no-model-digest",
                    "the receipt names no model artifact, so a matching replay proves only that "
                    "SOME model agrees — ask the provider to declare COCORE_MODEL_DIGESTS",
                )
            )
        elif str(claimed_digest).lower() != ran_digest.lower():
            _err(
                findings,
                "decision-model-digest-mismatch",
                f"the receipt claims artifact {claimed_digest} but you replayed {ran_digest}",
            )

    if runner is None:
        return ValidationReport(ok=_ok(findings), findings=findings)

    # 2. The replay itself.
    try:
        payload = dict(request)
        payload["model"] = receipt.get("model")
        envelope = runner(payload)
        recomputed = _sha256_hex(canonical_decision_answers(envelope).encode("utf-8"))
        if recomputed != receipt.get("outputCommitment"):
            _err(
                findings,
                "decision-output-commitment-mismatch",
                f'the receipt commits to output {receipt.get("outputCommitment")} but re-running '
                f"the decision produced {recomputed}. Either the provider did not run the model it "
                "named, or it altered the answer. Both contradict a receipt it signed.",
            )
    except Exception as exc:  # noqa: BLE001 — any runner failure leaves it unverified
        findings.append(
            Finding(
                "warn",
                "decision-replay-failed",
                f"could not re-run the decision, so the output is unverified: {exc}",
            )
        )

    return ValidationReport(ok=_ok(findings), findings=findings)
