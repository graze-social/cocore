#!/usr/bin/env python3
"""Deterministic tests for the engine wrapper's known-corrupt-stack guard.

Run inside the provider venv (the module imports vllm_mlx at import time):
    ~/.cocore/python/bin/python -m unittest provider/python/test_cocore_inference_server.py
"""
from __future__ import annotations

import unittest

from cocore_inference_server import (
    QWEN35_MIN_MLX_VLM,
    _model_type_of,
    _parse_version,
    qwen35_norm_shift_hazard,
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


if __name__ == "__main__":
    unittest.main()
