"""ToolRegistry — what the MCP client sees.

Sectioned mode: one tool per section, `ghidra_<section>(action, args)`, whose
description lists every action with params + one-liner.
Flat mode / --expose: an ordinary FastMCP tool per endpoint, signature built
from the endpoint's params.
"""

from __future__ import annotations

import inspect
import logging

from mcp.server.fastmcp import FastMCP

from .catalog import ToolCatalog
from .dispatcher import ActionDispatcher
from .sections import SectionMap
from .tooldef import ToolDef

log = logging.getLogger("ghidra-mcp")

PY_TYPES = {"string": str, "json": str, "integer": int, "boolean": bool,
            "number": float, "object": dict, "array": list}

SECTION_HEADER = ("Call with action=<name>, args={...}; ghidra_help(name) for full params; "
                  "write actions accept dry_run=true; any action accepts _grep=<regex> to keep only "
                  "matching reply lines (e.g. get_xrefs_to with _grep='WRITE' = writers only).\nActions:")


class ToolRegistry:
    def __init__(self, mcp: FastMCP, dispatcher: ActionDispatcher, brief: bool = False):
        self.mcp = mcp
        self.dispatcher = dispatcher
        self.brief = brief
        self.registered: list[str] = []        # names we own (for reload)
        self.section_tools: list[str] = []
        self.first_class: list[str] = []

    # -- lifecycle -----------------------------------------------------------

    def clear(self) -> None:
        for name in self.registered:
            self.mcp._tool_manager._tools.pop(name, None)
        self.registered.clear()
        self.section_tools.clear()
        self.first_class.clear()

    def register(self, catalog: ToolCatalog, sections: SectionMap,
                 flat: bool, expose: list[str]) -> None:
        self.clear()
        members = sections.assign(catalog)
        if flat:
            expose = list(catalog.by_name)
        else:
            for section, tools in members.items():
                self._register_section(section, sections, tools, catalog)
        for name in expose:
            td = catalog.get(name)
            if td is None:
                log.warning(f"--expose: '{name}' not in catalog")
            elif name not in self.registered:
                self._register_first_class(td)
        log.info(f"{len(catalog)} endpoints -> {len(self.section_tools)} section tools, "
                 f"{len(self.first_class)} first-class")

    # -- section tools -------------------------------------------------------

    def _register_section(self, section: str, sections: SectionMap,
                          tools: list[str], catalog: ToolCatalog) -> None:
        lines = [t if self.brief else f"{t}({catalog.by_name[t].param_summary()}) — {catalog.by_name[t].one_liner()}"
                 for t in tools]
        desc = f"{sections.description(section)}\n{SECTION_HEADER}\n  " + "\n  ".join(lines)
        members = set(tools)
        listing = ", ".join(tools)
        dispatcher = self.dispatcher

        def handler(action: str, args: dict | None = None) -> str:
            if action in members:
                return dispatcher.call(action, args)
            owner = sections.section_of.get(action)
            if owner:
                return f'{{"error": "\'{action}\' belongs to ghidra_{owner}"}}'
            return f'{{"error": "unknown action \'{action}\'", "actions": "{listing}"}}'

        name = f"ghidra_{section}"
        handler.__name__ = name
        self.mcp.tool(name=name, description=desc)(handler)
        self.registered.append(name)
        self.section_tools.append(name)

    # -- first-class tools ---------------------------------------------------

    def _register_first_class(self, td: ToolDef) -> None:
        dispatcher = self.dispatcher

        def handler(**kwargs) -> str:
            return dispatcher.call(td.name, kwargs)

        required, optional = [], []
        for n, p in td.params.items():
            py = PY_TYPES.get(p.type, str)
            if p.required and p.default is None:
                required.append(inspect.Parameter(n, inspect.Parameter.KEYWORD_ONLY, annotation=py))
            else:
                optional.append(inspect.Parameter(n, inspect.Parameter.KEYWORD_ONLY,
                                                  default=p.default, annotation=py | None))
        if td.synthetic_dry_run:
            optional.append(inspect.Parameter("dry_run", inspect.Parameter.KEYWORD_ONLY,
                                              default=False, annotation=bool))
        params = required + optional
        handler.__signature__ = inspect.Signature(params, return_annotation=str)
        handler.__annotations__ = {p.name: p.annotation for p in params} | {"return": str}
        handler.__name__ = td.name
        self.mcp.tool(name=td.name, description=td.description)(handler)
        self.registered.append(td.name)
        self.first_class.append(td.name)
