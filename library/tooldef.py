"""ToolDef / ParamDef — one parsed Ghidra endpoint."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

# Boilerplate the server appends to ~60 descriptions; stated once per section instead.
_BOILERPLATE = re.compile(r"\s*On programs with multiple address spaces.*?ambiguous resolution\.", re.S)

# Long, repeated parameter descriptions -> short form.
PARAM_DESCRIPTIONS = {
    "program": "Program name (omit = active program; set it when several are open)",
    "address": "Address: 0x<hex> or <space>:<hex> (e.g. mem:1000)",
    "function_address": "Function entry address",
}
_SENTENCE_END = re.compile(r"(?<=[a-z0-9)])\. ")


@dataclass(frozen=True)
class ParamDef:
    name: str
    type: str = "string"
    description: str = ""
    required: bool = False
    default: Any = None
    source: str = "body"          # "query" | "body" (POST only)
    is_address: bool = False

    @classmethod
    def from_schema(cls, p: dict) -> "ParamDef":
        name = p["name"]
        desc = PARAM_DESCRIPTIONS.get(name) or p.get("description", "")
        if len(desc) > 200:
            desc = desc[:197] + "..."
        return cls(
            name=name,
            type=p.get("type", "string"),
            description=desc,
            required=bool(p.get("required", False)),
            default=p.get("default"),
            source="query" if p.get("source") == "query" else "body",
            is_address=p.get("param_type") == "address",
        )


@dataclass
class ToolDef:
    name: str                     # MCP-visible / action name
    endpoint: str                 # HTTP path, e.g. "/decompile_function"
    method: str                   # GET | POST
    category: str                 # upstream category
    description: str
    params: dict[str, ParamDef] = field(default_factory=dict)

    @classmethod
    def from_schema(cls, t: dict) -> "ToolDef":
        path = t["path"]
        params = {p["name"]: ParamDef.from_schema(p) for p in t.get("params", [])}
        return cls(
            name=t.get("name") or path.lstrip("/"),
            endpoint=path,
            method=t.get("method", "GET").upper(),
            category=t.get("category", "unknown"),
            description=_BOILERPLATE.sub("", t.get("description", "")).strip(),
            params=params,
        )

    # -- derived views ------------------------------------------------------

    @property
    def is_post(self) -> bool:
        return self.method == "POST"

    @property
    def required(self) -> list[str]:
        return [n for n, p in self.params.items() if p.required and n != "program"]

    @property
    def program_selectors(self) -> list[str]:
        return [n for n in self.params
                if n == "program" or n.endswith("_program") or n.startswith("program_")]

    @property
    def synthetic_dry_run(self) -> bool:
        """POST endpoints without their own dry_run get one from the bridge (query param)."""
        return self.is_post and "dry_run" not in self.params

    def one_liner(self, width: int = 72) -> str:
        d = self.description.split("\n")[0]
        d = _SENTENCE_END.split(d)[0].rstrip(".")
        return d[: width - 1] + "…" if len(d) > width else d

    def param_summary(self, limit: int = 5) -> str:
        names = [n for n in self.params if n != "program"]
        parts = [n if self.params[n].required else f"[{n}]" for n in names[:limit]]
        if len(names) > limit:
            parts.append("…")
        return ", ".join(parts)

    def http_call(self) -> str:
        """How to reach this endpoint without the MCP layer: verb, path, param placement.
        Scripts that talk to the Ghidra server directly must match the verb — a POST to a
        GET endpoint reaches the handler with no parameters and reports them as missing."""
        names = [n for n in self.params if n != "program"]
        if not self.is_post:
            qs = "&".join(f"{n}=<{self.params[n].type}>" for n in names[:4])
            return f"GET {self.endpoint}" + (f"?{qs}" if qs else "") + "   (query string only; no JSON body)"
        in_query = [n for n in names if self.params[n].source == "query"]
        in_body = [n for n in names if self.params[n].source != "query"]
        parts = [f"POST {self.endpoint}" + ("?" + "&".join(f"{n}=<{self.params[n].type}>" for n in in_query)
                                            if in_query else "")]
        parts.append("body={" + ", ".join(f'"{n}": <{self.params[n].type}>' for n in in_body) + "}"
                     if in_body else "no body params")
        return "   ".join(parts)

    def help(self, section: str) -> dict:
        return {
            "tool": self.name,
            "section": f"ghidra_{section}",
            "method": self.method,
            "endpoint": self.endpoint,
            "http": self.http_call(),
            "description": self.description,
            "params": {n: {"type": p.type, "description": p.description,
                           **({"default": p.default} if p.default is not None else {})}
                       for n, p in self.params.items()},
            "required": self.required,
            "call": f"ghidra_{section}(action='{self.name}', args={{...}})",
        }
