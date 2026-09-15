"""Explorer — one call to understand a function and everything under it.

    ghidra_explore(address, depth=2, max_functions=12, callers=True)

    callers of <root>          (who reaches it)
    call tree                  (root -> callees, to `depth`)
    decompiled code            (root first, then callees, up to max_functions)

Collapses the usual call_graph -> batch_decompile -> callers sequence into a
single reply; the ResponseShaper cap still applies, so deep trees are bounded
by max_functions rather than by luck.
"""

from __future__ import annotations

import re

from .dispatcher import ActionDispatcher

_EDGE = re.compile(r"^\s*(\S+)\s*->\s*(\S+)\s*$")


class Explorer:
    def __init__(self, dispatcher: ActionDispatcher, resolver=None):
        self.dispatcher = dispatcher
        self.resolver = resolver

    def _root(self, address: str) -> tuple[str, str, str]:
        """-> (name, entry address, note). A mid-function address resolves to its entry."""
        info = self.dispatcher.call("get_function_by_address", {"address": address})
        m = re.search(r"Function:\s*(\S+)", info)
        if m:
            return m.group(1), address, ""
        if self.resolver is not None:
            try:
                fn = self.resolver.containing(int(address.split(":")[-1].replace("0x", ""), 16))
            except ValueError:
                fn = None
            if fn:
                name, entry, _ = fn
                return name, f"0x{entry:x}", f"(resolved: {address} is inside {name}, entry 0x{entry:x})"
            where = self.resolver.describe(address)
            blk = where.get("block", {}).get("name")
            return address, address, f"(no function at {address}; " + (f"in block {blk}" if blk else "not mapped") + ")"
        return address, address, f"(no function at {address})"

    def _edges(self, address: str, depth: int) -> list[tuple[str, str]]:
        text = self.dispatcher.call("get_function_call_graph",
                                    {"address": address, "depth": depth, "direction": "callees"})
        return [(m.group(1), m.group(2)) for line in text.splitlines() if (m := _EDGE.match(line))]

    def explore(self, address: str, depth: int = 2, max_functions: int = 12,
                callers: bool = True, code: bool = True) -> str:
        roots = [a.strip() for a in address.split(",") if a.strip()]
        if len(roots) > 1:
            return "\n\n".join(self._explore_one(a, depth, max_functions, callers, code) for a in roots)
        return self._explore_one(roots[0] if roots else address, depth, max_functions, callers, code)

    def _explore_one(self, address: str, depth: int, max_functions: int, callers: bool, code: bool) -> str:
        root, address, note = self._root(address)
        out: list[str] = [f"# {root} @ {address} {note}".rstrip()]
        if note.startswith("(no function"):
            return out[0]

        if callers:
            out.append("\n## callers\n" + self.dispatcher.call("get_function_callers", {"address": address}))

        edges = self._edges(address, depth)
        children: dict[str, list[str]] = {}
        for a, b in edges:
            children.setdefault(a, []).append(b)
        order: list[str] = [root]
        seen = {root}
        i = 0
        while i < len(order):                      # BFS so shallow callees come first
            for c in children.get(order[i], []):
                if c not in seen:
                    seen.add(c)
                    order.append(c)
            i += 1
        if edges:
            out.append("\n## call tree\n" + "\n".join(f"{a} -> {b}" for a, b in edges))
        else:
            out.append("\n## call tree\n(leaf: no callees)")

        if not code:
            return "\n".join(out)
        wanted = order[:max_functions]
        skipped = order[max_functions:]
        out.append("\n## code\n" + self.dispatcher.call("batch_decompile", {"functions": ",".join(wanted)}))
        if skipped:
            out.append(f"\n## not decompiled ({len(skipped)} beyond max_functions={max_functions})\n"
                       + ", ".join(skipped))
        return "\n".join(out)
