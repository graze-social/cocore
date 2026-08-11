#!/usr/bin/env python3
"""Tool-call parser for Liquid AI LFM models.

LFM2.5 emits Pythonic calls inside a single list::

    <|tool_call_start|>[get_weather(city='Rotterdam', units='metric')]<|tool_call_end|>

This parser is bundled with Cocore because the format is specific to LFM and
may not be available in the installed vllm-mlx release. Values are decoded
with a deliberately small, safe AST interpreter; model output is never
executed.
"""

from __future__ import annotations

import ast
import json
import keyword
import re
import uuid
from collections.abc import Sequence
from typing import Any

from vllm_mlx.tool_parsers.abstract_tool_parser import (
    ExtractedToolCallInformation,
    ToolParser,
    ToolParserManager,
)

_START = "<|tool_call_start|>"
_END = "<|tool_call_end|>"
_BLOCK_RE = re.compile(re.escape(_START) + r"(.*?)" + re.escape(_END), re.DOTALL)
_START_PREFIXES = tuple(_START[:index] for index in range(2, len(_START)))
_THINK_MARKERS = ("<think>", "</think>")
_THINK_PREFIXES = tuple(
    marker[:index] for marker in _THINK_MARKERS for index in range(2, len(marker))
)


class LFMToolParser(ToolParser):
    """Parse LFM's ``[function(keyword=value), ...]`` tool-call format."""

    # LFM's chat template handles role=tool messages and assistant tool_calls.
    SUPPORTS_NATIVE_TOOL_FORMAT = True

    @staticmethod
    def register_streaming_markers(server_module: Any) -> None:
        """Teach vllm-mlx's streaming fast path about LFM marker prefixes."""
        existing = tuple(getattr(server_module, "_STREAMING_TOOL_MARKERS", ()))
        markers = (*existing, *_START_PREFIXES, _START, _END)
        server_module._STREAMING_TOOL_MARKERS = tuple(dict.fromkeys(markers))

    @staticmethod
    def _literal(node: ast.AST) -> Any:
        """Decode the supported literal subset without evaluating code."""
        if isinstance(node, ast.Constant):
            if node.value is None or isinstance(node.value, (str, int, float, bool)):
                return node.value
            raise ValueError("unsupported constant")

        # LFM documentation/examples use Python's None/True/False, while some
        # checkpoints also emit JSON spellings. Accept both explicitly.
        if isinstance(node, ast.Name) and node.id in {
            "None",
            "True",
            "False",
            "null",
            "true",
            "false",
        }:
            return {
                "None": None,
                "null": None,
                "True": True,
                "true": True,
                "False": False,
                "false": False,
            }[node.id]

        if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.USub, ast.UAdd)):
            value = LFMToolParser._literal(node.operand)
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                return -value if isinstance(node.op, ast.USub) else value
            raise ValueError("unary operators are only allowed on numbers")

        if isinstance(node, (ast.List, ast.Tuple)):
            return [LFMToolParser._literal(element) for element in node.elts]

        if isinstance(node, ast.Dict):
            result: dict[str, Any] = {}
            for key_node, value_node in zip(node.keys, node.values):
                if key_node is None:
                    raise ValueError("dictionary unpacking is not supported")
                key = LFMToolParser._literal(key_node)
                if not isinstance(key, str):
                    raise ValueError("tool argument object keys must be strings")
                result[key] = LFMToolParser._literal(value_node)
            return result

        raise ValueError(f"unsupported AST node: {type(node).__name__}")

    @classmethod
    def _parse_block(cls, block: str, request: dict[str, Any] | None) -> list[dict[str, str]]:
        try:
            expression = ast.parse(block.strip(), mode="eval").body
        except (SyntaxError, ValueError, RecursionError):
            return []
        if not isinstance(expression, ast.List):
            return []

        allowed_names: set[str] | None = None
        if request and isinstance(request.get("tools"), list):
            allowed_names = {
                tool.get("function", {}).get("name", "")
                for tool in request["tools"]
                if isinstance(tool, dict) and isinstance(tool.get("function"), dict)
            }

        calls: list[dict[str, str]] = []
        for item in expression.elts:
            if not isinstance(item, ast.Call) or not isinstance(item.func, ast.Name):
                return []
            name = item.func.id
            if not name.isidentifier() or keyword.iskeyword(name):
                return []
            if allowed_names is not None and name not in allowed_names:
                return []
            if item.args or any(argument.arg is None for argument in item.keywords):
                # The wire format has named function arguments. Rejecting
                # positional args avoids inventing parameter names.
                return []
            argument_names = [argument.arg for argument in item.keywords]
            if len(argument_names) != len(set(argument_names)):
                # Duplicate keyword names have ambiguous wire semantics.
                return []
            try:
                arguments = {
                    argument.arg: cls._literal(argument.value)
                    for argument in item.keywords
                    if argument.arg is not None
                }
                arguments_json = json.dumps(
                    arguments,
                    ensure_ascii=False,
                    separators=(",", ":"),
                    allow_nan=False,
                )
            except (TypeError, ValueError, OverflowError, RecursionError):
                return []
            calls.append(
                {
                    "id": f"call_{uuid.uuid4().hex}",
                    "name": name,
                    "arguments": arguments_json,
                }
            )
        return calls

    @staticmethod
    def _clean_text(text: str) -> str | None:
        return text.strip() or None

    @staticmethod
    def _strip_streaming_think_tags(text: str) -> str:
        """Remove complete think tags and withhold an incomplete tag suffix."""
        for marker in _THINK_MARKERS:
            text = text.replace(marker, "")
        for prefix in sorted(_THINK_PREFIXES, key=len, reverse=True):
            if text.endswith(prefix):
                return text[: -len(prefix)]
        return text

    @classmethod
    def _stream_visible_text(cls, text: str, request: dict[str, Any] | None) -> str:
        """Return text that is safe to emit while a response is still streaming."""
        del request
        pieces: list[str] = []
        cursor = 0
        for match in _BLOCK_RE.finditer(text):
            # Tool markers delimit protocol control output, not assistant text.
            # Drop every completed block, including malformed or unapproved ones:
            # parsing failures must not become rendered Pythonic-call syntax.
            pieces.append(text[cursor : match.start()])
            cursor = match.end()

        trailing = text[cursor:]
        for prefix in reversed(_START_PREFIXES):
            if trailing.endswith(prefix):
                trailing = trailing[: -len(prefix)]
                break
        else:
            incomplete_start = trailing.find(_START)
            if incomplete_start >= 0:
                trailing = trailing[:incomplete_start]
        pieces.append(trailing)
        return cls._strip_streaming_think_tags("".join(pieces))

    def extract_tool_calls(
        self, model_output: str, request: dict[str, Any] | None = None
    ) -> ExtractedToolCallInformation:
        cleaned = self.strip_think_tags(model_output)
        calls: list[dict[str, str]] = []
        pieces: list[str] = []
        cursor = 0
        for match in _BLOCK_RE.finditer(cleaned):
            block_calls = self._parse_block(match.group(1), request)
            if block_calls:
                calls.extend(block_calls)
                pieces.append(cleaned[cursor : match.start()])
                cursor = match.end()
            else:
                # Preserve malformed/unsupported model output rather than
                # silently deleting text or fabricating a call.
                pieces.append(cleaned[cursor : match.end()])
                cursor = match.end()
        pieces.append(cleaned[cursor:])
        content = self._clean_text("".join(pieces))
        return ExtractedToolCallInformation(
            tools_called=bool(calls),
            tool_calls=calls,
            content=content,
        )

    @staticmethod
    def _format_streaming_tool_calls(calls: list[dict[str, str]], start_index: int) -> dict[str, Any]:
        return {
            "tool_calls": [
                {
                    "index": start_index + index,
                    "id": call["id"],
                    "type": "function",
                    "function": {
                        "name": call["name"],
                        "arguments": call["arguments"],
                    },
                }
                for index, call in enumerate(calls)
            ]
        }

    def extract_tool_calls_streaming(
        self,
        previous_text: str,
        current_text: str,
        delta_text: str,
        previous_token_ids: Sequence[int] | None = None,
        current_token_ids: Sequence[int] | None = None,
        delta_token_ids: Sequence[int] | None = None,
        request: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        del previous_token_ids, current_token_ids, delta_token_ids

        previous_visible = self._stream_visible_text(previous_text, request)
        current_visible = self._stream_visible_text(current_text, request)
        if current_visible.startswith(previous_visible):
            visible_delta = current_visible[len(previous_visible) :]
        elif not (_START in delta_text or _END in delta_text):
            visible_delta = self._strip_streaming_think_tags(delta_text)
        else:
            visible_delta = ""

        previous_end_count = previous_text.count(_END)
        current_end_count = current_text.count(_END)
        if current_end_count <= previous_end_count:
            # Do not stream the control marker or an incomplete Python list as
            # assistant content. The completed block is emitted below.
            return {"content": visible_delta} if visible_delta else None

        result = self.extract_tool_calls(current_text, request)
        # A single completed block may contain multiple calls, and a malformed
        # block may contain none. Track calls actually emitted rather than
        # assuming one call per closing marker.
        emitted_count = len(self.prev_tool_call_arr)
        new_calls = result.tool_calls[emitted_count:]
        if not new_calls:
            return {"content": visible_delta} if visible_delta else None
        self.prev_tool_call_arr = result.tool_calls
        response = self._format_streaming_tool_calls(new_calls, emitted_count)
        if visible_delta:
            response["content"] = visible_delta
        return response


# Registration is intentionally performed at import time. The Cocore wrapper
# imports this module before vllm-mlx handles any chat-completion request.
ToolParserManager.register_module("lfm", LFMToolParser)


__all__ = ["LFMToolParser"]
