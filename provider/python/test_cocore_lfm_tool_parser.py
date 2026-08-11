#!/usr/bin/env python3
"""Deterministic tests for Cocore's LFM tool parser."""

from __future__ import annotations

import json
import unittest

from cocore_lfm_tool_parser import LFMToolParser
from vllm_mlx.tool_parsers import ToolParserManager


TOOLS = {
    "tools": [
        {"type": "function", "function": {"name": "get_weather"}},
        {"type": "function", "function": {"name": "search"}},
    ]
}


class LFMToolParserTests(unittest.TestCase):
    def test_registers_with_vllm_parser_manager(self) -> None:
        self.assertIs(ToolParserManager.get_tool_parser("lfm"), LFMToolParser)

    def test_registers_lfm_marker_prefixes_with_streaming_gate(self) -> None:
        class FakeServer:
            _STREAMING_TOOL_MARKERS = ("<tool_call>",)

        LFMToolParser.register_streaming_markers(FakeServer)
        self.assertIn("<|tool_call_", FakeServer._STREAMING_TOOL_MARKERS)
        self.assertIn("<|tool_call_start|>", FakeServer._STREAMING_TOOL_MARKERS)
        self.assertIn("<|tool_call_end|>", FakeServer._STREAMING_TOOL_MARKERS)

    def test_extracts_single_call_and_preserves_prefix(self) -> None:
        result = LFMToolParser().extract_tool_calls(
            "I will check. <|tool_call_start|>[get_weather(city='Rotterdam')]<|tool_call_end|>",
            TOOLS,
        )
        self.assertTrue(result.tools_called)
        self.assertEqual(result.content, "I will check.")
        self.assertEqual(result.tool_calls[0]["name"], "get_weather")
        self.assertTrue(result.tool_calls[0]["id"].startswith("call_"))
        self.assertEqual(json.loads(result.tool_calls[0]["arguments"]), {"city": "Rotterdam"})

    def test_handles_multiple_calls_and_nested_literals(self) -> None:
        result = LFMToolParser().extract_tool_calls(
            "<|tool_call_start|>[search(query='a,b [c]', filters={'lang': 'nl', 'k': [1, True, None]}), get_weather(city='Tokyo')]<|tool_call_end|>",
            TOOLS,
        )
        self.assertEqual([call["name"] for call in result.tool_calls], ["search", "get_weather"])
        self.assertEqual(
            json.loads(result.tool_calls[0]["arguments"]),
            {"query": "a,b [c]", "filters": {"lang": "nl", "k": [1, True, None]}},
        )

    def test_accepts_json_literal_spellings(self) -> None:
        result = LFMToolParser().extract_tool_calls(
            "<|tool_call_start|>[search(enabled=true, missing=null, ratio=-1.5)]<|tool_call_end|>",
            TOOLS,
        )
        self.assertEqual(
            json.loads(result.tool_calls[0]["arguments"]),
            {"enabled": True, "missing": None, "ratio": -1.5},
        )

    def test_rejects_unsafe_or_unknown_calls(self) -> None:
        output = (
            "<|tool_call_start|>[__import__('os').system('touch /tmp/pwned')]"
            "<|tool_call_end|>"
        )
        result = LFMToolParser().extract_tool_calls(output, TOOLS)
        self.assertFalse(result.tools_called)
        self.assertEqual(result.tool_calls, [])
        self.assertIn("tool_call_start", result.content)

        unknown = LFMToolParser().extract_tool_calls(
            "<|tool_call_start|>[delete_everything()]<|tool_call_end|>", TOOLS
        )
        self.assertFalse(unknown.tools_called)
        self.assertIn("delete_everything", unknown.content or "")

        mixed = LFMToolParser().extract_tool_calls(
            "<|tool_call_start|>[search(query='ok'), __import__('os').system('x')]<|tool_call_end|>",
            TOOLS,
        )
        self.assertFalse(mixed.tools_called)
        self.assertIn("__import__", mixed.content or "")

        duplicate = LFMToolParser().extract_tool_calls(
            "<|tool_call_start|>[search(query='first', query='second')]<|tool_call_end|>",
            TOOLS,
        )
        self.assertFalse(duplicate.tools_called)
        self.assertIn("query='first'", duplicate.content or "")

        deep = "<|tool_call_start|>[search(filters=" + ("[" * 400) + "0" + ("]" * 400)
        deep += ")]<|tool_call_end|>"
        result = LFMToolParser().extract_tool_calls(deep, TOOLS)
        self.assertFalse(result.tools_called)

    def test_strips_thinking_tags(self) -> None:
        result = LFMToolParser().extract_tool_calls(
            "<think>private reasoning</think>answer <|tool_call_start|>[search(query='x')]<|tool_call_end|>",
            TOOLS,
        )
        self.assertEqual(result.content, "answer")

    def test_streaming_suppresses_incomplete_block_then_emits_calls(self) -> None:
        parser = LFMToolParser()
        incomplete = "I will check. <|tool_call_start|>[get_weather(city='Rotterdam')]"
        suppressed = parser.extract_tool_calls_streaming("", incomplete, incomplete, request=TOOLS)
        self.assertEqual(suppressed, {"content": "I will check. "})

        complete = incomplete + "<|tool_call_end|>"
        delta = "<|tool_call_end|>"
        emitted = parser.extract_tool_calls_streaming(incomplete, complete, delta, request=TOOLS)
        self.assertIsNotNone(emitted)
        assert emitted is not None
        self.assertEqual(emitted["tool_calls"][0]["function"]["name"], "get_weather")
        self.assertEqual(emitted["tool_calls"][0]["index"], 0)

    def test_streaming_preserves_text_adjacent_to_control_block(self) -> None:
        parser = LFMToolParser()
        current = (
            "before <|tool_call_start|>[search(query='x')]<|tool_call_end|> after"
        )
        emitted = parser.extract_tool_calls_streaming("", current, current, request=TOOLS)
        self.assertIsNotNone(emitted)
        assert emitted is not None
        self.assertEqual(emitted["content"], "before  after")
        self.assertEqual(emitted["tool_calls"][0]["function"]["name"], "search")

    def test_streaming_emits_all_calls_in_one_block(self) -> None:
        parser = LFMToolParser()
        previous = "<|tool_call_start|>["
        current = previous + "search(query='x'), get_weather(city='Tokyo')]<|tool_call_end|>"
        emitted = parser.extract_tool_calls_streaming(previous, current, current[len(previous):], request=TOOLS)
        self.assertIsNotNone(emitted)
        assert emitted is not None
        self.assertEqual([c["function"]["name"] for c in emitted["tool_calls"]], ["search", "get_weather"])
        self.assertEqual([c["index"] for c in emitted["tool_calls"]], [0, 1])

    def test_streaming_handles_split_markers_and_multiple_blocks(self) -> None:
        parser = LFMToolParser()
        partial = "before <|tool_call_"
        self.assertEqual(
            parser.extract_tool_calls_streaming("", partial, partial, request=TOOLS),
            {"content": "before "},
        )

        first = partial + "start|>[search(query='x')]<|tool_call_end|>middle "
        first_result = parser.extract_tool_calls_streaming(partial, first, first[len(partial) :], request=TOOLS)
        self.assertEqual(first_result["content"], "middle ")  # type: ignore[index]

        second = first + "<|tool_call_start|>[get_weather(city='Tokyo')]<|tool_call_end|>after"
        second_result = parser.extract_tool_calls_streaming(first, second, second[len(first) :], request=TOOLS)
        self.assertEqual(second_result["content"], "after")  # type: ignore[index]
        self.assertEqual(second_result["tool_calls"][0]["index"], 1)  # type: ignore[index]

    def test_streaming_preserves_completed_malformed_block(self) -> None:
        parser = LFMToolParser()
        incomplete = "before <|tool_call_start|>[delete_everything()]"
        parser.extract_tool_calls_streaming("", incomplete, incomplete, request=TOOLS)
        complete = incomplete + "<|tool_call_end|>after"
        emitted = parser.extract_tool_calls_streaming(incomplete, complete, complete[len(incomplete) :], request=TOOLS)
        self.assertEqual(emitted, {"content": "<|tool_call_start|>[delete_everything()]<|tool_call_end|>after"})


if __name__ == "__main__":
    unittest.main()
