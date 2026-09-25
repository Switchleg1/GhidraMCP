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

# Server defaults that hide data: applied when the caller did not say otherwise.
DEFAULT_ARGS: dict[str, dict] = {
    "list_globals": {"include_all_sections": True},   # else only the default section is searched
}
# Hard caps on request args whose replies would blow past any response cap anyway.
ARG_LIMITS: dict[tuple[str, str], tuple[int, str]] = {
    ("read_memory", "length"): (8192, "read in chunks of <= 8192 bytes, or use search_byte_patterns for scans"),
}
# Hints appended to specific empty replies so a silent false negative is at least labelled.
EMPTY_HINTS: dict[str, tuple[str, str]] = {
    "search_functions": ("No functions matching",
                         "[search_functions is a case-insensitive SUBSTRING match, not regex; use ghidra_find(pattern=...) for regex]"),
}

_NO_FUNCTION = re.compile(r"(?:No function (?:found )?(?:at|for) (?:address:? )?|Function not found:? )(0x[0-9a-fA-F]+|[0-9a-fA-F]{6,})")
_BADDATA = "halt_baddata()"
# Endpoints that identify the function to rename by NAME. They carry no address parameter,
# so a duplicated name (thunk + implementation, or two functions a naming pass gave the same
# name) makes the target arbitrary: refuse rather than rename something at random.
_BY_NAME_RENAMES = {"rename_function"}
# Address-ish arguments a caller may attach to a by-name rename. The endpoint has no such
# parameter, so rather than reject or ignore them, they redirect the write to the
# address-authoritative endpoint after the name at that entry is confirmed.
_ADDR_KEYS = ("function_address", "address", "at")


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
        self.on_program_change: Callable[[], None] | None = None   # set by Bridge
        # action -> post-processor(text, args) -> text
        self.post_hooks: dict[str, Callable[[str, dict], str]] = {
            "switch_program": self._program_changed,
            "open_program": self._program_changed,
            "close_program": self._program_changed,
            "decompile_function": self._note_baddata,
            "batch_decompile": self._note_baddata,
            "create_function": self._refresh_index,
            "delete_function": self._refresh_index,
            "rename_function_by_address": self._track_rename,
            "rename_function": self._track_rename,
            "batch_rename_function_components": self._track_rename,
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
                          keys_seen_in_args=sorted(args), note="parameters go inside args={...}",
                          help=f"ghidra_help('{td.name}')")
        for (action, key), (cap, advice) in ARG_LIMITS.items():
            if action == td.name and key in args:
                try:
                    if int(args[key]) > cap:
                        return _error(error=f"{key}={args[key]} exceeds {cap} for {td.name}; {advice}")
                except (TypeError, ValueError):
                    pass
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
        if name in _BY_NAME_RENAMES:
            redirected = self._redirect_rename(dict(args or {}))
            if isinstance(redirected, str):
                return redirected                      # address/name mismatch: refuse
            if redirected is not None:
                name, args = redirected                # address wins: rename by address instead
        td = self.catalog.get(name)
        if td is None:
            return _error(error=f"unknown tool '{name}'", did_you_mean=self.catalog.similar(name))
        args = {**DEFAULT_ARGS.get(name, {}), **(args or {})}
        grep = args.pop("_grep", None)
        err = self._validate(td, args) or self._block_ambiguous_rename(name, args)
        if err:
            return err
        query, body = self._prepare(td, args)
        text = self.shaper.shape(self._send(td, query, body), name)
        text = self._hint_containing(text)
        text = self._hint_route(text, td, args)
        marker_hint = EMPTY_HINTS.get(name)
        if marker_hint and text.startswith(marker_hint[0]):
            text = text.rstrip() + "\n" + marker_hint[1]
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

    @staticmethod
    def _hint_route(text: str, td: ToolDef, args: dict) -> str:
        """Server says a parameter is missing although we sent it: almost always the verb/param
        placement, so name the exact route. Same hint a hand-written HTTP client needs."""
        if len(text) > 400 or "required" not in text or "error" not in text:
            return text
        sent = [k for k in args if k in td.params]
        if not sent:
            return text
        return text.rstrip() + f"\n[sent {sent} to {td.http_call()} - a mismatched verb or " \
                               f"query/body placement reaches the handler with no parameters]"

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

    def _track_rename(self, text: str, args: dict) -> str:
        """Update the function index in place so ghidra_find never lags a rename."""
        if self.resolver is None or '"error"' in text[:40] or '"rejected"' in text[:60]:
            return text
        new = args.get("new_name") or args.get("newName") or args.get("function_name")
        if not new:
            self.resolver.stale = True         # renamed something we cannot locate: rebuild later
            return text
        addr = args.get("function_address")
        try:
            if addr:
                self.resolver.rename(new, addr=int(str(addr).split(":")[-1].replace("0x", ""), 16))
            elif args.get("oldName"):
                self.resolver.rename(new, old=args["oldName"])
            else:
                self.resolver.stale = True
        except ValueError:
            self.resolver.stale = True
        return text

    def ambiguous_name(self, name: str) -> list[int] | None:
        """Entry addresses if this function name is carried by more than one function."""
        if self.resolver is None or not self.resolver.entries:
            return None
        try:
            hits = self.resolver.addresses_named(name)
        except Exception:
            return None
        return hits if len(hits) > 1 else None

    def _name_at_entry(self, address: str) -> tuple[str | None, str | None]:
        """(name, error) for the function whose ENTRY is this address."""
        try:
            addr = int(str(address).split(":")[-1].replace("0x", "").replace("0X", ""), 16)
        except ValueError:
            return None, _error(error=f"not a hex address: {address}")
        if self.resolver is None:
            return None, None
        try:
            fn = self.resolver.containing(addr)
        except Exception:
            return None, None
        if fn is None:
            return None, _error(error=f"no function at 0x{addr:x}")
        fn_name, entry, _ = fn
        if entry != addr:
            return None, _error(error=f"0x{addr:x} is not a function entry",
                                inside=f"{fn_name} @ 0x{entry:x}",
                                use="pass the entry address")
        return fn_name, None

    def _redirect_rename(self, args: dict) -> tuple[str, dict] | str | None:
        """A by-name rename given an address: make the ADDRESS authoritative.

        /rename_function has no address parameter - the server resolves oldName alone and
        renames the first match, so an address passed alongside it is silently ignored and a
        stale or duplicated oldName rewrites the wrong function. When an address is supplied,
        check that the function at that entry really holds oldName and then route the write
        through /rename_function_by_address, which is address-authoritative.
        """
        key = next((k for k in _ADDR_KEYS if args.get(k)), None)
        if key is None:
            return None
        target = self.catalog.action_for_path("/rename_function_by_address")
        if target is None:
            return _error(error="address given for a by-name rename, but this Ghidra build has no "
                                "/rename_function_by_address endpoint; omit the address or upgrade")
        address = args.pop(key)
        old = args.get("oldName") or args.get("old_name")
        new = args.get("newName") or args.get("new_name")
        if not new:
            return _error(error="rename with an address needs newName", got=sorted(args))
        current, err = self._name_at_entry(address)
        if err:
            return err
        if old and current and current != old:
            return _error(
                error=f"oldName '{old}' does not match the function at {address}",
                name_at_address=current,
                note="/rename_function ignores the address and resolves oldName alone, so this "
                     "would have renamed a different function. Fix oldName, or drop it and let "
                     "the address decide.",
                use=f"rename_function_by_address(function_address='{address}', new_name='{new}')")
        fwd = {"function_address": address, "new_name": new}
        for carry in ("program", "dry_run"):
            if args.get(carry) is not None:
                fwd[carry] = args[carry]
        if "_grep" in args:
            fwd["_grep"] = args["_grep"]
        return target, fwd

    def _block_ambiguous_rename(self, action: str, args: dict) -> str | None:
        """Refuse a by-NAME rename of a duplicated name. /rename_function resolves its target
        by oldName only (it has no address parameter), so with several functions sharing that
        name the server renames whichever it finds first - silently the wrong one. A thunk and
        its implementation are the common case."""
        if action not in _BY_NAME_RENAMES:
            return None
        old = args.get("oldName") or args.get("old_name") or args.get("function_name")
        if not old:
            return None                      # dry_run is refused too: a plan that cannot be
                                             # applied safely should fail while it is still a plan
        hits = self.ambiguous_name(str(old))
        if not hits:
            return None
        return _error(
            error=f"'{old}' names {len(hits)} functions; a by-name rename would hit an arbitrary one",
            addresses=[f"0x{a:x}" for a in hits[:12]],
            use="rename_function_by_address(function_address=<the one you mean>, new_name=...)",
            note="/rename_function has no address parameter - the server resolves oldName alone. "
                 "A thunk and its implementation share a name, so pick the address deliberately.")

    def program_selector(self, action: str) -> str | None:
        """Name of the endpoint's program-selector param, if it has one."""
        td = self.catalog.get(action)
        sel = td.program_selectors if td else []
        return sel[0] if sel else None

    def _program_changed(self, text: str, args: dict) -> str:
        """The active program moved: every cached index belongs to the old one."""
        if self.resolver is not None:
            self.resolver.stale = True
        if self.on_program_change is not None:
            try:
                self.on_program_change()
            except Exception as e:
                log.warning(f"program-state refresh failed: {e}")
        return text

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
