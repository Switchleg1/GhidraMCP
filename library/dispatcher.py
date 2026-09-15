"""ActionDispatcher — validate an action call, send it to Ghidra, shape the reply.

    call(name, args) -> str

Argument handling is table-driven: COERCERS by declared param type, and
ROUTING by (method, param.source) deciding query-string vs JSON body.

Bridge-side extras on every action:
    _grep=<regex>      keep only response lines matching (case-insensitive)
    post_hooks         per-action response post-processing (containing-function
                       hints on "no function" errors, unmapped-target notes on
                       halt_baddata decompiles, index refresh after create/delete)
"""

from __future__ import annotations

import json
import logging
import re
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
# declared type -> coercer for values arriving as lists (models often pass ["a","b"] for "a,b")
LIST_COERCERS: dict[str, Callable[[list], Any]] = {
    "string": lambda v: ",".join(str(x) for x in v),
}

_NO_FUNCTION = re.compile(r"(?:No function (?:found )?(?:at|for) (?:address:? )?|Function not found:? )(0x[0-9a-fA-F]+|[0-9a-fA-F]{6,})")
_BADDATA = "halt_baddata()"


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
        self.resolver = None                     # AddressResolver, attached by Bridge
        # action -> post-processor(text, args) -> text
        self.post_hooks: dict[str, Callable[[str, dict], str]] = {
            "decompile_function": self._note_baddata,
            "batch_decompile": self._note_baddata,
            "create_function": self._refresh_index,
            "delete_function": self._refresh_index,
        }

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
            elif isinstance(v, list) and p.type in LIST_COERCERS:
                v = LIST_COERCERS[p.type](v)
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
        grep = args.pop("_grep", None)
        err = self._validate(td, args)
        if err:
            return err
        query, body = self._prepare(td, args)
        text = self.shaper.shape(self._send(td, query, body))
        text = self._hint_containing(text)
        hook = self.post_hooks.get(name)
        if hook:
            text = hook(text, args)
        if grep:
            text = self._grep(text, grep)
        return text

    # -- post-processing -----------------------------------------------------

    @staticmethod
    def _grep(text: str, pattern: str) -> str:
        try:
            rx = re.compile(pattern, re.I)
        except re.error as e:
            return _error(error=f"bad _grep pattern: {e}")
        lines = text.split("\n")
        kept = [l for l in lines if rx.search(l)]
        return "\n".join(kept) + f"\n[_grep {pattern!r}: {len(kept)}/{len(lines)} lines]"

    def _hint_containing(self, text: str) -> str:
        """'No function at 0x...' -> name the function whose body holds that address."""
        if self.resolver is None or len(text) > 400:
            return text
        m = _NO_FUNCTION.search(text)
        if not m:
            return text
        try:
            fn = self.resolver.containing(int(m.group(1).replace("0x", ""), 16))
        except Exception:
            return text
        if not fn:
            return text
        name, entry, end = fn
        return text.rstrip() + f"\n[containing function: {name} @ 0x{entry:x} (body to 0x{end:x}) - use that entry]"

    def _note_baddata(self, text: str, args: dict) -> str:
        """Ghidra emits halt_baddata() when flow leaves the image (e.g. a far tail call into an
        unmapped library region). Say so and name the targets so the code isn't misread."""
        if _BADDATA not in text or self.resolver is None:
            return text
        notes = []
        for addr in self._decompiled_addresses(text, args):
            asm = self._send_plain("disassemble_function", {"address": addr})
            for src, tgt in self.resolver.unmapped_targets(asm):
                notes.append(f"{addr}: {src} -> {tgt} (outside every memory block)")
        note = ("\n// NOTE halt_baddata(): control flow leaves mapped memory - a call/jump to an "
                "address outside the image (external library / unmapped region), NOT bad code. "
                "Treat it as an unresolved external call.")
        if notes:
            note += "\n//   " + "\n//   ".join(notes)
        return text + note

    @staticmethod
    def _decompiled_addresses(text: str, args: dict) -> list[str]:
        if "address" in args:
            return [str(args["address"])]
        return re.findall(r"^// ===== (\S+) =====$", text, re.M)

    def raw(self, action: str, args: dict) -> str:
        """Unshaped, uncapped call for bridge-internal use (indexes, hooks)."""
        td = self.catalog.get(action)
        if td is None:
            return ""
        query, body = self._prepare(td, args)
        return self._send(td, query, body)

    _send_plain = raw

    def _refresh_index(self, text: str, args: dict) -> str:
        if self.resolver is not None and '"success":true' in text.replace(" ", ""):
            try:
                self.resolver.refresh_functions()
            except Exception as e:
                log.warning(f"function index refresh failed: {e}")
        return text

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
