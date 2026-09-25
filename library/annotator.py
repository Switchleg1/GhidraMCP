"""BatchAnnotator — apply a whole labelling pass in one MCP call.

    ghidra_annotate(functions=[{address, name?, prototype?, variables?, plate?, comment?}, ...],
                    labels=[{address, name}, ...],
                    globals=[{address, name?, type?, comment?}, ...],
                    save=True, dry_run=False)

The server has no endpoint for "rename + document many functions", so this
composes the per-item endpoints and returns one compact summary instead of
one reply per write. Each step is a row in STEPS: (item key, endpoint,
arg-builder), so adding another per-function write is one more row.

Writes listed in VERIFY are read back after the call and counted only if the
value actually took; a mismatch is retried once, then reported per item.
"""

from __future__ import annotations

import json
import re
from typing import Callable

from .dispatcher import ActionDispatcher

# (field on the function item, endpoint, args builder)
STEPS: list[tuple[str, str, Callable[[str, object], dict]]] = [
    ("name",      "rename_function_by_address", lambda addr, v: {"function_address": addr, "new_name": v}),
    ("prototype", "set_function_prototype",     lambda addr, v: {"function_address": addr, "prototype": v}),
    ("variables", "rename_variables",           lambda addr, v: {"function_address": addr, "variable_renames": v}),
    ("plate",     "set_plate_comment",          lambda addr, v: {"address": addr, "comment": v}),
    ("comment",   "set_decompiler_comment",     lambda addr, v: {"address": addr, "comment": v}),
]

# Per-global writes. Not set_global / rename_or_label: both reject any name
# that isn't g_-Hungarian ("name_quality"), which rules out every ECU-style
# name. create_label only lint-warns (and the shaper drops that).
GLOBAL_STEPS: list[tuple[str, str, Callable[[str, object], dict]]] = [
    ("name",    "create_label",      lambda addr, v: {"address": addr, "name": v}),
    ("type",    "apply_data_type",   lambda addr, v: {"address": addr, "type_name": v, "clear_existing": True}),
    ("comment", "batch_set_comments", lambda addr, v: {"address": addr, "plate_comment": v}),
]


def _failed(reply: str) -> str | None:
    """Server replies are JSON with status/success, or plain text; return an error string or None."""
    try:
        obj = json.loads(reply)
    except ValueError:
        return None if "error" not in reply.lower() else reply[:200]
    if not isinstance(obj, dict):
        return None
    if obj.get("error"):
        issue = obj.get("issue")
        return (f"{obj['error']} ({issue})" if issue else str(obj["error"]))[:200]
    if obj.get("status") not in (None, "success") or obj.get("success") is False:
        return (obj.get("message") or reply)[:200]
    return None


_ALREADY = ("already exists", "already has")

# rename_function_by_address enforces a "token-subset" name policy (a new name sharing the
# token set of an existing function, e.g. MulDivRound_S16Sat vs MulDivRound_S16SatRemainder,
# is rejected as name_collision). rename_function (by name) does not. ECU code is full of
# such families, so on that specific rejection fall back to the by-name path.
_TOKEN_SUBSET = "token_subset"

# field -> (read-back endpoint, args builder, extractor(reply) -> current value)
_FN_NAME = re.compile(r"Function:\s*(\S+)\s+at\s")
VERIFY: dict[str, tuple[str, Callable[[str], dict], Callable[[str], str | None]]] = {
    "name": ("get_function_by_address", lambda addr: {"address": addr},
             lambda reply: (m.group(1) if (m := _FN_NAME.search(reply)) else None)),
}


class BatchAnnotator:
    def __init__(self, dispatcher: ActionDispatcher):
        self.dispatcher = dispatcher
        self._program: str | None = None       # per-apply target, injected into every step
        self._unscoped: set[str] = set()       # endpoints with no program selector to inject into

    def _call(self, endpoint: str, args: dict) -> str:
        """Add the program selector when the endpoint has one, so every write in a pass
        (and every read-back) targets the same program instead of whatever the server
        currently considers active."""
        if self._program:
            sel = self.dispatcher.program_selector(endpoint)
            if sel:
                if sel not in args:
                    args = args | {sel: self._program}
            else:
                self._unscoped.add(endpoint)   # goes to the server's active program; say so
        return self.dispatcher.call(endpoint, args)

    def _rename_by_name(self, addr: str, new_name: str, extra: dict) -> str | None:
        endpoint, build, extract = VERIFY["name"]
        current = extract(self._call(endpoint, build(addr)))
        if not current:
            return "token-subset rejection and current name unreadable"
        return _failed(self._call("rename_function", {"oldName": current, "newName": new_name} | extra))

    def _verified(self, field: str, addr: str, value) -> bool | None:
        """True/False if the write can be read back, None if no verifier for this field."""
        spec = VERIFY.get(field)
        if spec is None:
            return None
        endpoint, build, extract = spec
        return extract(self._call(endpoint, build(addr))) == value

    def _run(self, steps, item: dict, addr: str, prefix: str, extra: dict,
             counts: dict, errors: list) -> None:
        for field, endpoint, build in steps:
            value = item.get(field)
            if not value:
                continue
            key = f"{prefix}{field}"
            err = None
            for attempt in (1, 2):
                err = _failed(self._call(endpoint, build(addr, value) | extra))
                if err and field == "name" and _TOKEN_SUBSET in err:
                    err = self._rename_by_name(addr, value, extra)
                    if err is None:
                        counts["name_via_byname_path"] = counts.get("name_via_byname_path", 0) + 1
                if err is None and not extra:               # not on dry_run
                    ok = self._verified(field, addr, value)
                    if ok is False:
                        err = "write reported success but read-back differs"
                        if attempt == 1:
                            continue                        # one clean retry
                break
            if err is None:
                counts[key] = counts.get(key, 0) + 1
            elif any(a in err for a in _ALREADY):
                counts[key + "_existing"] = counts.get(key + "_existing", 0) + 1
            else:
                errors.append(f"{endpoint} {addr}: {err}")

    def apply(self, functions: list[dict] | None, labels: list[dict] | None,
              globals_: list[dict] | None = None, save: bool = True, dry_run: bool = False,
              program: str | None = None, explicit_program: bool = False) -> str:
        counts: dict[str, int] = {}
        errors: list[str] = []
        extra = {"dry_run": True} if dry_run else {}
        self._program = program if explicit_program else None
        self._unscoped = set()

        for item in functions or []:
            addr = item.get("address")
            if not addr:
                errors.append(f"function item without address: {item}")
                continue
            self._run(STEPS, item, addr, "", extra, counts, errors)

        for item in globals_ or []:
            addr = item.get("address")
            if not addr:
                errors.append(f"globals item without address: {item}")
                continue
            self._run(GLOBAL_STEPS, item, addr, "global_", extra, counts, errors)

        if labels:
            reply = self._call("batch_create_labels", {"labels": labels} | extra)
            err = _failed(reply)
            if err:
                errors.append(f"batch_create_labels: {err}")
            else:
                try:
                    r = json.loads(reply)
                    counts["labels"] = r.get("labels_created", len(labels))
                    if r.get("labels_skipped"):
                        counts["labels_existing"] = r["labels_skipped"]
                except ValueError:
                    counts["labels"] = len(labels)

        if save and not dry_run:
            err = _failed(self._call("save_program", {}))
            counts["saved"] = 0 if err else 1
            if err:
                errors.append(f"save_program: {err}")

        self._program = None
        out: dict = {"applied": counts}
        if program:
            out["program"] = program
            out["program_targeting"] = "explicit" if explicit_program else "server's active program"
            if self._unscoped:
                out["program_not_enforced_on"] = sorted(self._unscoped)
                out["warning"] = ("these endpoints take no program selector, so they hit the server's "
                                  "active program; switch to it before the pass if several are open")
        if dry_run:
            out["dry_run"] = True
        if errors:
            out["errors"] = errors
        return json.dumps(out, separators=(",", ":"), ensure_ascii=False)
