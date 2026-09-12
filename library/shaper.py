"""ResponseShaper — make every response as small as it can be without losing data.

Pipeline (each stage is `str -> str`, applied in order):
    json_stage   parse JSON objects: drop naming-lint chatter, unwrap
                 {"success":true,"data":X}, turn {addr: code, ...} maps
                 (batch_decompile) into plain text blocks, re-dump compactly
    text_stage   \\r\\n -> \\n, strip trailing spaces, collapse blank runs
    cap_stage    truncate past max_chars with a note about what was cut
"""

from __future__ import annotations

import json
import re
from typing import Callable

# Server-side style-lint phrases. Pure noise for the model; ~500 chars per write call.
LINT_MARKERS: tuple[str, ...] = (
    "is not PascalCase", "is not snake_case", "contains underscores",
    "not in allowed list", "does not start with a recognized verb",
    "Plate comment missing", "Expected format:", "Expected:",
)
_LINT_KEYS = ("warnings", "errors")
_BLANK_RUN = re.compile(r"\n{3,}")


def _is_lint(msg) -> bool:
    return isinstance(msg, str) and any(m in msg for m in LINT_MARKERS)


class ResponseShaper:
    def __init__(self, max_chars: int = 40_000, keep_lint: bool = False):
        self.max_chars = max_chars
        self.keep_lint = keep_lint
        self.stages: list[Callable[[str], str]] = [self.json_stage, self.text_stage, self.cap_stage]

    def shape(self, text: str) -> str:
        for stage in self.stages:
            text = stage(text)
        return text

    # -- stages --------------------------------------------------------------

    def json_stage(self, text: str) -> str:
        s = text.lstrip()
        if not s.startswith("{"):
            return text
        try:
            obj = json.loads(s)
        except ValueError:
            return text
        if not isinstance(obj, dict):
            return text

        if not self.keep_lint:
            for key in _LINT_KEYS:
                if isinstance(obj.get(key), list):
                    kept = [m for m in obj[key] if not _is_lint(m)]
                    if kept:
                        obj[key] = kept
                    else:
                        del obj[key]

        if set(obj) <= {"success", "data"} and obj.get("success") is True and "data" in obj:
            obj = obj["data"]
            if not isinstance(obj, dict):
                return obj if isinstance(obj, str) else json.dumps(obj, separators=(",", ":"), ensure_ascii=False)

        # {"0x8000": "<code>", "0x8010": "<code>"}  ->  text blocks (no JSON escaping of code)
        if obj and all(isinstance(v, str) and "\n" in v for v in obj.values()):
            return "\n".join(f"// ===== {k} =====\n{v.strip()}\n" for k, v in obj.items())

        return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)

    @staticmethod
    def text_stage(text: str) -> str:
        text = text.replace("\r\n", "\n").replace("\r", "\n")
        text = "\n".join(line.rstrip() for line in text.split("\n"))
        return _BLANK_RUN.sub("\n\n", text).strip("\n")

    def cap_stage(self, text: str) -> str:
        if len(text) <= self.max_chars:
            return text
        cut = text.rfind("\n", 0, self.max_chars)
        cut = cut if cut > self.max_chars // 2 else self.max_chars
        return (text[:cut] + f"\n...[truncated {len(text) - cut:,} of {len(text):,} chars; "
                "narrow the query or use offset/limit]")
