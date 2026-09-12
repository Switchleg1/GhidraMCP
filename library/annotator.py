"""BatchAnnotator — apply a whole labelling pass in one MCP call.

    ghidra_annotate(functions=[{address, name?, prototype?, variables?, plate?, comment?}, ...],
                    labels=[{address, name}, ...],
                    globals=[{address, name?, type?, comment?}, ...],
                    save=True, dry_run=False)

The server has no endpoint for "rename + document many functions", so this
composes the per-item endpoints and returns one compact summary instead of
one reply per write. Each step is a row in STEPS: (item key, endpoint,
arg-builder), so adding another per-function write is one more row.
"""

from __future__ import annotations

import json
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
        return str(obj["error"])[:200]
    if obj.get("status") not in (None, "success") or obj.get("success") is False:
        return (obj.get("message") or reply)[:200]
    return None


_ALREADY = ("already exists", "already has")


class BatchAnnotator:
    def __init__(self, dispatcher: ActionDispatcher):
        self.dispatcher = dispatcher

    def _run(self, steps, item: dict, addr: str, prefix: str, extra: dict,
             counts: dict, errors: list) -> None:
        for field, endpoint, build in steps:
            value = item.get(field)
            if not value:
                continue
            err = _failed(self.dispatcher.call(endpoint, build(addr, value) | extra))
            key = f"{prefix}{field}"
            if err is None:
                counts[key] = counts.get(key, 0) + 1
            elif any(a in err for a in _ALREADY):
                counts[key + "_existing"] = counts.get(key + "_existing", 0) + 1
            else:
                errors.append(f"{endpoint} {addr}: {err}")

    def apply(self, functions: list[dict] | None, labels: list[dict] | None,
              globals_: list[dict] | None = None, save: bool = True, dry_run: bool = False) -> str:
        counts: dict[str, int] = {}
        errors: list[str] = []
        extra = {"dry_run": True} if dry_run else {}

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
            reply = self.dispatcher.call("batch_create_labels", {"labels": labels} | extra)
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
            err = _failed(self.dispatcher.call("save_program", {}))
            counts["saved"] = 0 if err else 1
            if err:
                errors.append(f"save_program: {err}")

        out: dict = {"applied": counts}
        if dry_run:
            out["dry_run"] = True
        if errors:
            out["errors"] = errors
        return json.dumps(out, separators=(",", ":"), ensure_ascii=False)
