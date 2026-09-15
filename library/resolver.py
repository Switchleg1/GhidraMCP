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
from typing import Callable

_SEG_LINE = re.compile(r"^(?P<name>.+?):\s*(?P<start>[0-9a-fA-F]+)\s*-\s*(?P<end>[0-9a-fA-F]+)\s*$")
_FN_LINE = re.compile(r"^(?P<name>\S+)\s+(?:at|@)\s+(?P<addr>[0-9a-fA-F]+)\s*$")
_FN_HEAD = re.compile(r"Function:\s*(\S+)\s+at\s+([0-9a-fA-F]+)")
_BODY = re.compile(r"Body:\s*([0-9a-fA-F]+)\s*-\s*([0-9a-fA-F]+)")
_UNNAMED = re.compile(r"^(FUN|SUB|thunk_FUN|LAB)_[0-9a-fA-F]+$")
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
             limit: int = 50) -> dict:
        rx = re.compile(pattern, re.I) if pattern else None
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
        hits = [f"{n} @ {a:x}" for a, n in zip(self.entries, self.names)
                if lo <= a <= hi and (not unnamed or _UNNAMED.match(n)) and (rx is None or rx.search(n))]
        return {"matches": len(hits), "shown": min(len(hits), limit), "functions": hits[:limit]}

    def unmapped_targets(self, disassembly: str) -> list[tuple[str, str]]:
        """[(from_addr, target)] for jumps/calls whose target lies outside every block."""
        return [(src, f"0x{_hex(tgt):x}") for src, tgt in _FLOW.findall(disassembly)
                if self.blocks and self.block(_hex(tgt)) is None]
