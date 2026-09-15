"""AddressResolver — cheap answers to "what is at this address?".

Caches two things per connected program, both fetched once (bridge-side,
never sent to the model):

    blocks     list_segments   -> [(start, end, name)]
    functions  list_functions  -> sorted [(entry, name)]

and answers:

    block(addr)        -> (name, start, end) | None        is it mapped, where
    containing(addr)   -> (name, entry, end) | None        which function owns it
    find(regex, unnamed, region, limit)                     function index search
    unmapped_targets(disassembly_text)                     j/call targets outside the image
"""

from __future__ import annotations

import bisect
import re
import time
from typing import Callable

_SEG_LINE = re.compile(r"^(?P<name>.+?):\s*(?P<start>[0-9a-fA-F]+)\s*-\s*(?P<end>[0-9a-fA-F]+)\s*$")
_FN_LINE = re.compile(r"^(?P<name>\S+)\s+(?:at|@)\s+(?P<addr>[0-9a-fA-F]+)\s*$")
_FN_HEAD = re.compile(r"Function:\s*(\S+)\s+at\s+([0-9a-fA-F]+)")
_BODY = re.compile(r"Body:\s*([0-9a-fA-F]+)\s*-\s*([0-9a-fA-F]+)")
_UNNAMED = re.compile(r"^(FUN|SUB|thunk_FUN|LAB)_[0-9a-fA-F]+$")
_EDGE = re.compile(r"^\s*(\S+)\s*->\s*(\S+)\s*$")
# control-transfer mnemonics with an absolute target operand (TriCore + generic)
_FLOW = re.compile(r"^\s*([0-9a-fA-F]+):\s*(?:j|ja|jl|jla|call|calla|jump|b|bl|jmp)\s+(?:0x)?([0-9a-fA-F]{6,})\s*$", re.M)


def _hex(s: str) -> int:
    return int(s.replace("0x", "").replace("0X", ""), 16)


class AddressResolver:
    def __init__(self, call: Callable[[str, dict], str]):
        self._call = call                  # dispatcher.raw(action, args): unshaped, uncapped
        self.blocks: list[tuple[int, int, str]] = []
        self.entries: list[int] = []
        self.names: list[str] = []
        self.indexed_at: float = 0.0
        self._callees: dict[int, int] | None = None     # entry -> callee count (lazy)
        self._callers: dict[int, int] | None = None     # entry -> caller count (lazy)

    # -- caches --------------------------------------------------------------

    def refresh(self) -> None:
        self.refresh_blocks()
        self.refresh_functions()

    def refresh_blocks(self) -> None:
        text = self._call("list_segments", {"limit": 10000})
        self.blocks = sorted(
            (_hex(m["start"]), _hex(m["end"]), m["name"])
            for line in text.splitlines() if (m := _SEG_LINE.match(line)))

    def refresh_functions(self) -> None:
        text = self._call("list_functions", {})
        pairs = sorted((_hex(m["addr"]), m["name"])
                       for line in text.splitlines() if (m := _FN_LINE.match(line)))
        self.entries = [a for a, _ in pairs]
        self.names = [n for _, n in pairs]
        self.indexed_at = time.time()
        self._callees = self._callers = None

    def rename(self, new: str, addr: int | None = None, old: str | None = None) -> None:
        """Keep the index current after a rename (by address, or by old name)."""
        if addr is not None:
            i = bisect.bisect_left(self.entries, addr)
            if i < len(self.entries) and self.entries[i] == addr:
                self.names[i] = new
        elif old is not None:
            for i, n in enumerate(self.names):
                if n == old:
                    self.names[i] = new
                    break

    def _load_call_counts(self) -> None:
        """One get_full_call_graph (edges) -> callee/caller counts keyed by entry address."""
        by_name = {}
        for a, n in zip(self.entries, self.names):
            by_name.setdefault(n, a)
        text = self._call("get_full_call_graph", {"format": "edges", "limit": 1_000_000})
        callees: dict[int, int] = {}
        callers: dict[int, int] = {}
        for line in text.splitlines():
            m = _EDGE.match(line)
            if not m:
                continue
            a, b = by_name.get(m.group(1)), by_name.get(m.group(2))
            if a is not None:
                callees[a] = callees.get(a, 0) + 1
            if b is not None:
                callers[b] = callers.get(b, 0) + 1
        self._callees, self._callers = callees, callers

    # -- queries -------------------------------------------------------------

    def block(self, addr: int) -> tuple[str, int, int] | None:
        for start, end, name in self.blocks:
            if start <= addr <= end:
                return name, start, end
        return None

    def containing(self, addr: int) -> tuple[str, int, int] | None:
        """(name, entry, body_end) of the function whose body holds addr, else None.
        The server's get_function_by_address already resolves containment; this
        just parses it (one GET)."""
        info = self._call("get_function_by_address", {"address": f"0x{addr:x}"})
        head = _FN_HEAD.search(info)
        if not head:
            return None
        body = _BODY.search(info)
        entry = _hex(head.group(2))
        return head.group(1), entry, (_hex(body.group(2)) if body else entry)

    def describe(self, address: str) -> dict:
        try:
            addr = _hex(address.split(":")[-1])
        except ValueError:
            return {"error": f"not a hex address: {address}"}
        out: dict = {"address": f"0x{addr:x}"}
        blk = self.block(addr)
        out["mapped"] = blk is not None
        if blk:
            out["block"] = {"name": blk[0], "start": f"0x{blk[1]:x}", "end": f"0x{blk[2]:x}"}
        fn = self.containing(addr)
        if fn:
            name, entry, end = fn
            out["function"] = {"name": name, "entry": f"0x{entry:x}", "end": f"0x{end:x}",
                               "offset": addr - entry}
        elif blk:
            i = bisect.bisect_right(self.entries, addr) - 1
            if i >= 0:
                out["previous_function"] = f"{self.names[i]} @ 0x{self.entries[i]:x}"
        return out

    def find(self, pattern: str = "", unnamed: bool = False, region: str = "",
             limit: int = 50, max_callees: int | None = None, min_callers: int | None = None,
             sort: str = "") -> dict:
        rx = re.compile(pattern, re.I) if pattern else None
        need_counts = max_callees is not None or min_callers is not None or sort in ("callers", "callees")
        if need_counts and self._callees is None:
            self._load_call_counts()
        lo, hi = 0, 1 << 64
        if region:
            if "-" in region:
                a, b = region.split("-", 1)
                lo, hi = _hex(a), _hex(b)
            else:                                  # block name
                for start, end, name in self.blocks:
                    if name == region:
                        lo, hi = start, end
                        break
                else:
                    return {"error": f"unknown region '{region}'",
                            "blocks": [b[2] for b in self.blocks][:40]}
        rows = [(a, n) for a, n in zip(self.entries, self.names)
                if lo <= a <= hi and (not unnamed or _UNNAMED.match(n)) and (rx is None or rx.search(n))]
        if need_counts:
            ce, cr = self._callees or {}, self._callers or {}
            rows = [(a, n) for a, n in rows
                    if (max_callees is None or ce.get(a, 0) <= max_callees)
                    and (min_callers is None or cr.get(a, 0) >= min_callers)]
            if sort == "callers":
                rows.sort(key=lambda r: -cr.get(r[0], 0))
            elif sort == "callees":
                rows.sort(key=lambda r: -ce.get(r[0], 0))
            hits = [f"{n} @ {a:x}  callers={cr.get(a, 0)} callees={ce.get(a, 0)}" for a, n in rows[:limit]]
        else:
            hits = [f"{n} @ {a:x}" for a, n in rows[:limit]]
        return {"matches": len(rows), "shown": len(hits),
                "index_as_of": time.strftime("%H:%M:%S", time.localtime(self.indexed_at)),
                "functions": hits}

    def unmapped_targets(self, disassembly: str) -> list[tuple[str, str]]:
        """[(from_addr, target)] for jumps/calls whose target lies outside every block."""
        return [(src, f"0x{_hex(tgt):x}") for src, tgt in _FLOW.findall(disassembly)
                if self.blocks and self.block(_hex(tgt)) is None]
