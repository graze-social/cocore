#!/usr/bin/env python3
"""Deterministic tests for the engine wrapper's known-corrupt-stack guard.

Run inside the provider venv (the module imports vllm_mlx at import time):
    ~/.cocore/python/bin/python -m unittest provider/python/test_cocore_inference_server.py
"""
from __future__ import annotations

import unittest

import asyncio
import glob
import json
import os
import tempfile
import types

from cocore_inference_server import (
    QWEN35_MIN_MLX_VLM,
    _model_type_of,
    _parse_version,
    eos_token_ids_in,
    install_mllm_text_route_patches,
    qwen35_norm_shift_hazard,
    wants_mllm_text_route,
)


class ParseVersionTests(unittest.TestCase):
    def test_plain(self) -> None:
        self.assertEqual(_parse_version("0.6.4"), (0, 6, 4))

    def test_prerelease_suffix_is_ignored(self) -> None:
        self.assertEqual(_parse_version("0.7.0rc0"), (0, 7, 0))

    def test_garbage_never_raises(self) -> None:
        self.assertEqual(_parse_version("dev"), ())


class ModelTypeTests(unittest.TestCase):
    def test_top_level(self) -> None:
        self.assertEqual(_model_type_of({"model_type": "qwen3_5"}), "qwen3_5")

    def test_falls_back_to_text_config(self) -> None:
        cfg = {"architectures": ["X"], "text_config": {"model_type": "qwen3_5_moe"}}
        self.assertEqual(_model_type_of(cfg), "qwen3_5_moe")

    def test_missing_is_empty_string(self) -> None:
        self.assertEqual(_model_type_of({}), "")


class Qwen35HazardTests(unittest.TestCase):
    """The mlx-vlm 0.6.4 norm double-shift (Blaizzy/mlx-vlm#1528)."""

    def test_floor_is_0_6_5(self) -> None:
        self.assertEqual(QWEN35_MIN_MLX_VLM, (0, 6, 5))

    def test_qwen35_on_0_6_4_is_refused_with_reason(self) -> None:
        reason = qwen35_norm_shift_hazard("qwen3_5", "0.6.4")
        self.assertIsNotNone(reason)
        assert reason is not None
        self.assertIn("0.6.4", reason)
        self.assertIn("mlx-vlm>=0.6.5", reason)
        self.assertIn("#1528", reason)

    def test_qwen35_moe_on_0_6_4_is_refused(self) -> None:
        self.assertIsNotNone(qwen35_norm_shift_hazard("qwen3_5_moe", "0.6.4"))

    def test_qwen35_on_fixed_versions_loads(self) -> None:
        for v in ("0.6.5", "0.6.17", "0.7.0", "0.7.0rc0", "1.0.0"):
            with self.subTest(v=v):
                self.assertIsNone(qwen35_norm_shift_hazard("qwen3_5", v))

    def test_other_families_are_never_gated(self) -> None:
        for mt in ("qwen3_vl", "qwen3", "qwen2_5_vl", "gemma4", "llama", ""):
            with self.subTest(model_type=mt):
                self.assertIsNone(qwen35_norm_shift_hazard(mt, "0.6.4"))

    def test_missing_mlx_vlm_defers_to_vllm_import_error(self) -> None:
        self.assertIsNone(qwen35_norm_shift_hazard("qwen3_5", None))



class MllmTextRouteGateTests(unittest.TestCase):
    def test_gemma4_families_take_the_route(self) -> None:
        for mt in ("gemma4", "gemma4_text", "gemma4_unified", "gemma4_unified_text"):
            self.assertTrue(wants_mllm_text_route(mt), mt)

    def test_other_families_are_untouched(self) -> None:
        for mt in ("gemma3", "qwen3_5", "qwen3_5_moe", "llama", ""):
            self.assertFalse(wants_mllm_text_route(mt), mt)


class EosIdsTests(unittest.TestCase):
    def _dir(self, **files: object) -> str:
        d = tempfile.mkdtemp()
        for name, body in files.items():
            with open(os.path.join(d, name + ".json"), "w") as fh:
                json.dump(body, fh)
        return d

    def test_union_of_generation_config_and_config(self) -> None:
        d = self._dir(generation_config={"eos_token_id": [1, 106, 50]}, config={"eos_token_id": 1})
        self.assertEqual(eos_token_ids_in(d), {1, 50, 106})

    def test_scalar_and_missing(self) -> None:
        self.assertEqual(eos_token_ids_in(self._dir(config={"eos_token_id": 2})), {2})
        self.assertEqual(eos_token_ids_in(self._dir()), set())


GEMMA4_SNAPSHOTS = glob.glob(os.path.expanduser(
    "~/.cache/huggingface/hub/models--mlx-community--gemma-4-12B-it-qat-4bit/snapshots/*"))


@unittest.skipUnless(GEMMA4_SNAPSHOTS, "needs the cached gemma-4-12B-it-qat-4bit snapshot")
class MllmTextRoutePatchTests(unittest.TestCase):
    """The two seams, against fake vllm-mlx modules and the real Gemma 4 tokenizer."""

    def setUp(self) -> None:
        from transformers import AutoTokenizer

        snap = GEMMA4_SNAPSHOTS[0]
        self.raw_tok = AutoTokenizer.from_pretrained(snap)
        seen = self.seen = []

        class SimpleEngine:
            async def _stream_generate_text(self, *a, **k):
                seen.append(self._text_tokenizer)
                yield "chunk"

        self.simple = types.SimpleNamespace(SimpleEngine=SimpleEngine)
        self.server = types.SimpleNamespace(_get_engine_tokenizer=lambda engine: "PROCESSOR")
        install_mllm_text_route_patches(self.server, self.simple)
        self.engine = SimpleEngine()
        self.engine._model_name = snap
        self.engine._text_model = object()
        self.engine._text_tokenizer = self.raw_tok

    def test_json_builder_gets_the_text_tokenizer_with_gemma_eos(self) -> None:
        tok = self.server._get_engine_tokenizer(self.engine)
        self.assertNotEqual(tok, "PROCESSOR")
        self.assertTrue({1, 106}.issubset(set(tok.eos_token_ids)))

    def test_text_route_streams_with_the_fixed_tokenizer(self) -> None:
        async def drain():
            return [c async for c in self.engine._stream_generate_text([])]

        self.assertEqual(asyncio.run(drain()), ["chunk"])
        self.assertIn(106, set(self.seen[0].eos_token_ids))

    def test_engines_without_a_text_route_keep_the_original(self) -> None:
        self.engine._text_model = None
        self.assertEqual(self.server._get_engine_tokenizer(self.engine), "PROCESSOR")


if __name__ == "__main__":
    unittest.main()
