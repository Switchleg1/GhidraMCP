"""ToolCatalog — every endpoint the connected Ghidra advertises, by name."""

from __future__ import annotations

import re

from .tooldef import ToolDef

_INVALID = re.compile(r"[^a-zA-Z0-9_-]+")
_UNDERSCORES = re.compile(r"_+")
MAX_NAME = 64


def sanitize_name(raw: str) -> str:
    """'debugger/status' -> 'debugger_status'; CAPI-safe, <= 64 chars."""
    s = _UNDERSCORES.sub("_", _INVALID.sub("_", raw)).strip("_") or "tool"
    if s[0].isdigit():
        s = "t_" + s
    return s[:MAX_NAME].rstrip("_")


class ToolCatalog:
    def __init__(self, tools: list[ToolDef]):
        self.by_name: dict[str, ToolDef] = {t.name: t for t in tools}

    @classmethod
    def from_schema(cls, raw: dict, reserved: set[str]) -> "ToolCatalog":
        tools: list[ToolDef] = []
        used = set(reserved)
        for t in raw.get("tools", []):
            td = ToolDef.from_schema(t)
            base = sanitize_name(td.name)
            name, n = base, 2
            while name in used:               # collision with a static tool or earlier endpoint
                name, n = f"{base}_{n}", n + 1
            used.add(name)
            td.name = name
            tools.append(td)
        return cls(tools)

    # -- lookup --------------------------------------------------------------

    def __len__(self) -> int:
        return len(self.by_name)

    def __contains__(self, name: str) -> bool:
        return name in self.by_name

    def get(self, name: str) -> ToolDef | None:
        return self.by_name.get(name)

    def similar(self, name: str, limit: int = 10) -> list[str]:
        q = name.lower()
        return [n for n in self.by_name if q in n.lower()][:limit]

    def search(self, terms: list[str], names: list[str] | None = None) -> list[str]:
        """Rank by keyword hits: name hit = 3, description hit = 1."""
        scored = []
        for n in (names if names is not None else self.by_name):
            td = self.by_name[n]
            hay = f"{td.category} {td.description}".lower()
            score = sum(3 if t in n.lower() else 1 if t in hay else 0 for t in terms)
            if score or not terms:
                scored.append((-score, n))
        return [n for _, n in sorted(scored)]
