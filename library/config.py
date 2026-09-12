"""Config — everything tunable, resolved once from argv + environment."""

from __future__ import annotations

import argparse
import os
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_PORT = 8089
PORT_SCAN_SPAN = 16          # plugin's TCP fallback range: 8089 .. 8089+15
DEFAULT_MAX_CHARS = 40_000   # cap on any single tool response


def _env_flag(name: str) -> bool:
    return (os.getenv(name) or "").strip().lower() in {"1", "true", "yes", "on"}


@dataclass
class Config:
    url: str = os.getenv("GHIDRA_MCP_URL") or f"http://127.0.0.1:{DEFAULT_PORT}"
    transport: str = "stdio"                 # stdio | streamable-http | sse
    mcp_host: str = "127.0.0.1"
    mcp_port: int | None = None
    flat: bool = False                       # one MCP tool per endpoint (stock layout)
    brief: bool = False                      # section descriptions: names only
    expose: list[str] = field(default_factory=list)   # extra first-class tools
    sections_file: Path | None = None        # JSON override of the SECTIONS table
    max_chars: int = DEFAULT_MAX_CHARS
    keep_lint: bool = False                  # keep server naming-lint warnings
    require_program: bool = _env_flag("GHIDRA_MCP_REQUIRE_PROGRAM_SELECTORS")
    log_level: str = os.getenv("GHIDRA_MCP_LOG_LEVEL", "INFO")

    @classmethod
    def from_argv(cls, argv: list[str] | None = None) -> "Config":
        p = argparse.ArgumentParser(description="GhidraMCP bridge (sectioned)")
        p.add_argument("--url", default=None, help="Ghidra plugin base URL (default $GHIDRA_MCP_URL or 127.0.0.1:8089)")
        p.add_argument("--transport", default="stdio", choices=["stdio", "streamable-http", "sse"])
        p.add_argument("--mcp-host", default="127.0.0.1")
        p.add_argument("--mcp-port", type=int, default=None)
        p.add_argument("--flat", action="store_true", help="one MCP tool per endpoint (stock layout)")
        p.add_argument("--brief", action="store_true", help="section descriptions list action names only")
        p.add_argument("--expose", default="", help="comma-separated endpoints to also expose first-class")
        p.add_argument("--sections", default=None, help="JSON file overriding the built-in section table")
        p.add_argument("--max-chars", type=int, default=DEFAULT_MAX_CHARS, help="truncate responses beyond this")
        p.add_argument("--keep-lint", action="store_true", help="keep server naming-lint warnings in responses")
        a = p.parse_args(argv)
        cfg = cls()
        cfg.url = a.url or cfg.url
        cfg.transport = a.transport
        cfg.mcp_host = a.mcp_host
        cfg.mcp_port = a.mcp_port
        cfg.flat = a.flat
        cfg.brief = a.brief
        cfg.expose = [t.strip() for t in a.expose.split(",") if t.strip()]
        cfg.sections_file = Path(a.sections) if a.sections else None
        cfg.max_chars = a.max_chars
        cfg.keep_lint = a.keep_lint
        return cfg
