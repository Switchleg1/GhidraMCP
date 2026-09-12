"""ActionDispatcher — validate an action call, send it to Ghidra, shape the reply.

    call(name, args) -> str

Argument handling is table-driven: COERCERS by declared param type, and
ROUTING by (method, param.source) deciding query-string vs JSON body.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Callable

from .address import AddressNormalizer
from .catalog import ToolCatalog
from .client import GhidraClient
from .shaper import ResponseShaper
from .tooldef import ToolDef

log = logging.getLogger("ghidra-mcp")

_TRUTHY = {"1", "true", "yes", "on"}


def _to_bool(v) -> bool:
    return v.strip().lower() in _TRUTHY if isinstance(v, str) else bool(v)


def _to_int(v):
    if isinstance(v, str) and v.strip().lstrip("-").isdigit():
        return int(v)
    return v


def _to_float(v):
    try:
        return float(v) if isinstance(v, str) else v
    except ValueError:
        return v


def _to_json(v):
    if isinstance(v, str):
        s = v.strip()
        if s[:1] in "[{":
            try:
                return json.loads(s)
            except ValueError:
                pass
    return v


# declared schema type -> coercer for values arriving as strings
COERCERS: dict[str, Callable[[Any], Any]] = {
    "integer": _to_int, "number": _to_float, "boolean": _to_bool,
    "json": _to_json, "object": _to_json, "array": _to_json,
}


def _error(**fields) -> str:
    return json.dumps(fields)


class ActionDispatcher:
    def __init__(self, catalog: ToolCatalog, client_getter: Callable[[], GhidraClient | None],
                 shaper: ResponseShaper, reconnect: Callable[[], bool],
                 require_program: bool = False):
        self.catalog = catalog
        self._client = client_getter
        self.shaper = shaper
        self._reconnect = reconnect
        self.require_program = require_program

    # -- validation ----------------------------------------------------------

    def _validate(self, td: ToolDef, args: dict) -> str | None:
        allowed = set(td.params) | ({"dry_run"} if td.synthetic_dry_run else set())
        unknown = [k for k in args if k not in allowed]
        if unknown:
            return _error(error=f"unknown args for {td.name}: {unknown}",
                          valid={n: p.type for n, p in td.params.items()}, required=td.required)
        missing = [r for r in td.required if r not in args]
        if missing:
            return _error(error=f"missing required args for {td.name}: {missing}",
                          help=f"ghidra_help('{td.name}')")
        if self.require_program:
            absent = [p for p in td.program_selectors if p not in args]
            if absent:
                return _error(error=f"missing program selector(s) {absent} "
                                    "(GHIDRA_MCP_REQUIRE_PROGRAM_SELECTORS is set)")
        return None

    def _prepare(self, td: ToolDef, args: dict) -> tuple[dict, dict | None]:
        """-> (query_params, json_body|None) with coercion + address normalising applied."""
        query: dict = {}
        body: dict = {}
        for k, v in args.items():
            if v is None or v == "":
                continue                     # empty = omitted (server treats "" as present-but-empty)
            p = td.params.get(k)
            if p is None:                    # synthetic dry_run
                if _to_bool(v):
                    query["dry_run"] = "true"
                continue
            if p.is_address:
                v = AddressNormalizer.normalize(v)
            elif isinstance(v, str) and p.type in COERCERS:
                v = COERCERS[p.type](v)
            elif p.type == "boolean" and not isinstance(v, str):
                v = bool(v)
            target = query if (not td.is_post or p.source == "query") else body
            target[k] = v
        return query, (body if td.is_post else None)

    # -- call ----------------------------------------------------------------

    def call(self, name: str, args: dict | None) -> str:
        td = self.catalog.get(name)
        if td is None:
            return _error(error=f"unknown tool '{name}'", did_you_mean=self.catalog.similar(name))
        args = dict(args or {})
        err = self._validate(td, args)
        if err:
            return err
        query, body = self._prepare(td, args)
        return self.shaper.shape(self._send(td, query, body))

    def _send(self, td: ToolDef, query: dict, body: dict | None) -> str:
        for attempt in (0, 1):
            client = self._client()
            if client is None:
                return _error(error="No Ghidra instance connected. Use connect_instance().")
            try:
                text, status = client.request(td.method, td.endpoint, query or None, body)
            except OSError as e:
                if attempt == 0 and not td.is_post and self._reconnect():
                    continue                 # GET: safe to resend after reconnect
                return _error(error=f"{td.name}: {e}")
            if status == 200:
                return text
            return _error(error=f"{td.name}: HTTP {status}: {text.strip()[:2000]}")
        return _error(error=f"{td.name}: request failed")
