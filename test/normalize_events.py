#!/usr/bin/env python3
"""Normalize pi --mode json output into deterministic tool-result lines.

Input:  pi --mode json event stream (one JSON object per line)
Output: one line per finished tool call: "TOOL <name> OK|ERR <text>"
"""
import json
import sys

for line in sys.stdin:
    try:
        e = json.loads(line)
    except Exception:
        continue
    if e.get("type") == "tool_execution_end":
        name = e.get("toolName") or "?"
        err = "ERR" if e.get("isError") else "OK"
        content = (e.get("result") or {}).get("content") or []
        texts = " ⏎ ".join(
            c.get("text", "") for c in content if c.get("type") == "text"
        ).replace("\n", " ⏎ ")
        print(f"TOOL {name} {err} {texts[:900]}")
