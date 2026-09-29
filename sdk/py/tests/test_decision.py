"""Decision-receipt replay verification.

The load-bearing test is the cross-language fixture: the Rust engine produces
the canonical bytes, and Python and TypeScript must reproduce them exactly. A
single disagreement — a key order, or an integral float printed as `1` instead
of `1.0` — would fail every honest receipt as if it were forged.
"""
from __future__ import annotations

import hashlib
import json
import os
import pathlib

import pytest

from cocore.decision import (
    canonical_decision_answers,
    canonical_decision_request,
    verify_decision_receipt,
)

FIXTURE = (
    pathlib.Path(__file__).resolve().parents[3] / "target" / "decision-cross-lang-fixture.json"
)


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@pytest.mark.skipif(
    not FIXTURE.exists(),
    reason="run `cargo test --test cross_lang_fixture` in provider/ to generate it",
)
def test_reproduces_the_rust_engines_canonical_bytes():
    fixture = json.loads(FIXTURE.read_text())
    assert canonical_decision_answers(fixture["upstreamReply"]) == fixture["canonicalAnswers"]


@pytest.mark.skipif(not FIXTURE.exists(), reason="fixture not generated")
def test_and_therefore_the_same_output_commitment():
    fixture = json.loads(FIXTURE.read_text())
    assert _sha(canonical_decision_answers(fixture["upstreamReply"])) == fixture["outputCommitment"]


def test_integral_values_print_as_floats():
    # The case that would ship broken if only non-integral values were tested:
    # a confident model answers with exactly 1 and 0, and the provider prints
    # those as `1.0` / `0.0`.
    canonical = canonical_decision_answers(
        {"model": "m", "answers": {"q": {"type": "noul", "noul": 1}}, "usage": {}}
    )
    assert '"noul":1.0' in canonical
    # Token counts are u64 on the provider, so they must NOT gain a `.0`.
    assert '"input_tokens":0,"output_tokens":0' in canonical


def test_request_canonicalization_is_stable_across_key_order():
    a = canonical_decision_request(
        {
            "state": "x",
            "questions": {
                "zeta": {"type": "noul", "instructions": "z"},
                "alpha": {"type": "choice", "instructions": "a", "criteria": {"b": "bee", "a": "ay"}},
            },
        },
        "m",
    )
    b = canonical_decision_request(
        {
            "questions": {
                "alpha": {"criteria": {"a": "ay", "b": "bee"}, "instructions": "a", "type": "choice"},
                "zeta": {"instructions": "z", "type": "noul"},
            },
            "state": "x",
        },
        "m",
    )
    assert a == b


def test_score_levels_keep_their_order():
    canonical = canonical_decision_request(
        {"state": "x", "questions": {"sev": {"type": "score", "instructions": "s", "criteria": ["low", "high"]}}},
        "m",
    )
    assert '["low","high"]' in canonical


# --- verifier ---------------------------------------------------------------

REQUEST = {
    "state": "Third time this year you've double-charged me.",
    "questions": {"urgent": {"type": "noul", "instructions": "The message conveys urgency."}},
}
ANSWERS = {
    "model": "convaiinnovations/laya",
    "answers": {"urgent": {"type": "noul", "noul": 0.97}},
    "usage": {"input_tokens": 31, "output_tokens": 0},
}


def _fixtures(model_digest=None):
    model = "convaiinnovations/laya"
    input_commitment = _sha(canonical_decision_request(REQUEST, model))
    receipt = {
        "model": model,
        "inputCommitment": input_commitment,
        "outputCommitment": _sha(canonical_decision_answers(ANSWERS)),
    }
    if model_digest:
        receipt["params"] = {"modelDigest": model_digest}
    return {"model": model, "inputCommitment": input_commitment}, receipt


def test_an_honest_receipt_verifies_by_replay():
    job, receipt = _fixtures()
    report = verify_decision_receipt(receipt, job, REQUEST, runner=lambda _req: ANSWERS)
    assert report.ok, report.codes()


def test_a_tampered_answer_fails():
    job, receipt = _fixtures()
    flipped = dict(ANSWERS, answers={"urgent": {"type": "noul", "noul": 0.02}})
    report = verify_decision_receipt(receipt, job, REQUEST, runner=lambda _req: flipped)
    assert not report.ok
    assert "decision-output-commitment-mismatch" in report.codes()


def test_a_receipt_for_a_different_request_is_caught_before_replay():
    job, receipt = _fixtures()
    other = dict(REQUEST, state="something else entirely")
    report = verify_decision_receipt(receipt, job, other)
    assert not report.ok
    assert "decision-input-commitment-mismatch" in report.codes()


def test_without_a_runner_it_checks_commitments_only():
    job, receipt = _fixtures()
    report = verify_decision_receipt(receipt, job, REQUEST)
    assert report.ok


def test_replaying_a_different_artifact_is_an_error():
    job, receipt = _fixtures(model_digest="a" * 64)
    report = verify_decision_receipt(
        receipt, job, REQUEST, runner=lambda _req: ANSWERS, ran_digest="b" * 64
    )
    assert not report.ok
    assert "decision-model-digest-mismatch" in report.codes()


def test_a_receipt_naming_no_artifact_warns_instead_of_silently_passing():
    job, receipt = _fixtures()
    report = verify_decision_receipt(
        receipt, job, REQUEST, runner=lambda _req: ANSWERS, ran_digest="b" * 64
    )
    assert report.ok, "a missing claim is not a failure"
    assert "decision-no-model-digest" in report.codes()


def test_an_unreachable_server_leaves_the_output_unverified():
    job, receipt = _fixtures()

    def boom(_req):
        raise RuntimeError("connection refused")

    report = verify_decision_receipt(receipt, job, REQUEST, runner=boom)
    assert "decision-replay-failed" in report.codes()
