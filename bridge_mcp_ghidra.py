# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "mcp>=1.2.0,<2",
# ]
# ///
"""
GhidraMCP bridge — sectioned, drop-in replacement for the stock bridge_mcp_ghidra.py.

Presents the Ghidra plugin's ~200 endpoints as one MCP tool per section
(ghidra_functions, ghidra_xrefs, ghidra_types, ...), each taking
action=<endpoint>, args={...}. Responses are trimmed (lint noise removed,
line endings normalised, batch code un-escaped, hard size cap).

Everything lives in ./library (one class per file); this file only parses
flags and starts the Bridge.

Flags: --flat --brief --expose a,b --sections file.json --max-chars N --keep-lint
       --url http://127.0.0.1:8089 --transport stdio|streamable-http|sse
       --mcp-host H --mcp-port P
Env:   GHIDRA_MCP_URL, GHIDRA_MCP_LOG_LEVEL, GHIDRA_MCP_REQUIRE_PROGRAM_SELECTORS=1
"""

import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from library import Bridge, Config  # noqa: E402


def main() -> None:
    cfg = Config.from_argv()
    logging.basicConfig(level=getattr(logging, cfg.log_level.upper(), logging.INFO),
                        format="%(asctime)s %(name)s %(levelname)s %(message)s")
    Bridge(cfg).run()


if __name__ == "__main__":
    main()
