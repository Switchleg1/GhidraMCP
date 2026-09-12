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
    def __init__(self, dispatcher: ActionDispatcher):
        self.dispatcher = dispatcher

    def _root_name(self, address: str) -> str | None:
        info = self.dispatcher.call("get_function_by_address", {"address": address})
        m = re.search(r"Function:\s*(\S+)", info)
        return m.group(1) if m else None

    def _edges(self, address: str, depth: int) -> list[tuple[str, str]]:
        text = self.dispatcher.call("get_function_call_graph",
                                    {"address": address, "depth": depth, "direction": "callees"})
        return [(m.group(1), m.group(2)) for line in text.splitlines() if (m := _EDGE.match(line))]

    def explore(self, address: str, depth: int = 2, max_functions: int = 12, callers: bool = True) -> str:
        root = self._root_name(address) or address
        out: list[str] = [f"# {root} @ {address}"]

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

        wanted = order[:max_functions]
        skipped = order[max_functions:]
        code = self.dispatcher.call("batch_decompile", {"functions": ",".join(wanted)})
        out.append("\n## code\n" + code)
        if skipped:
            out.append(f"\n## not decompiled ({len(skipped)} beyond max_functions={max_functions})\n"
                       + ", ".join(skipped))
        return "\n".join(out)
