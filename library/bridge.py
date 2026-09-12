"""Bridge — wires everything together and owns the static MCP tools.

    list_instances()            running Ghidra instances on the loopback port range
    connect_instance(project)   switch to an instance, (re)load its catalog
    ghidra_help(tool)           full params for one action
    ghidra_tools(query, section) keyword search / section summary
    ghidra_annotate(...)        whole labelling pass in one call
    ghidra_explore(address)     callers + call tree + subtree decompiles in one call
    import_file(...)            import a binary and optionally follow analysis
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from mcp.server.fastmcp import Context, FastMCP
from mcp.server.lowlevel.server import NotificationOptions

from .annotator import BatchAnnotator
from .catalog import ToolCatalog
from .client import GhidraClient
from .config import Config
from .discovery import InstanceScanner
from .dispatcher import ActionDispatcher
from .explorer import Explorer
from .registry import ToolRegistry
from .sections import SectionMap
from .shaper import ResponseShaper

log = logging.getLogger("ghidra-mcp")

STATIC_TOOLS = {"list_instances", "connect_instance", "ghidra_help", "ghidra_tools", "ghidra_annotate", "ghidra_explore", "import_file"}


def _dumps(obj: Any) -> str:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)


class Bridge:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.mcp = FastMCP("ghidra-mcp")
        self._enable_list_changed()
        self.scanner = InstanceScanner()
        self.sections = SectionMap.load(cfg.sections_file)
        self.shaper = ResponseShaper(cfg.max_chars, cfg.keep_lint)
        self.catalog = ToolCatalog([])
        self.client: GhidraClient | None = None
        self.project: str | None = None
        self.dispatcher = ActionDispatcher(self.catalog, lambda: self.client, self.shaper,
                                           self.reconnect, cfg.require_program)
        self.registry = ToolRegistry(self.mcp, self.dispatcher, cfg.brief)
        self.annotator = BatchAnnotator(self.dispatcher)
        self.explorer = Explorer(self.dispatcher)
        self._register_static_tools()

    def _enable_list_changed(self) -> None:
        """Clients must re-list tools after connect_instance registers the catalog."""
        orig = self.mcp._mcp_server.create_initialization_options

        def patched(**kw):
            return orig(notification_options=NotificationOptions(tools_changed=True), **kw)

        self.mcp._mcp_server.create_initialization_options = patched

    # -- connection ----------------------------------------------------------

    def connect(self, url: str, project: str | None = None) -> int:
        """Point at a Ghidra instance and (re)build the tool catalog. Returns endpoint count."""
        client = GhidraClient(url)
        text, status = client.request("GET", "/mcp/schema", timeout=10)
        if status != 200:
            raise RuntimeError(f"schema fetch failed: HTTP {status}")
        if self.client is not None and self.client is not client:
            self.client.close()
        self.client = client
        self.project = project
        self.catalog.by_name = ToolCatalog.from_schema(json.loads(text), STATIC_TOOLS).by_name
        self.registry.register(self.catalog, self.sections, self.cfg.flat, self.cfg.expose)
        return len(self.catalog)

    def auto_connect(self) -> None:
        instances = self.scanner.scan()
        if len(instances) > 1:
            names = ", ".join(i.get("project") or i["url"] for i in instances)
            log.info(f"{len(instances)} Ghidra instances ({names}); call connect_instance() to choose")
            return
        if instances:
            url, project = instances[0]["url"], instances[0].get("project")
        elif not self.scanner.covers(self.cfg.url):
            url, project = self.cfg.url, None          # explicit URL outside the scanned range
        else:
            log.info("no Ghidra instance found; tools register on connect_instance()")
            return
        try:
            n = self.connect(url, project)
            log.info(f"connected to {project or url}: {n} endpoints")
        except Exception as e:
            log.info(f"no Ghidra at {url} ({e}); tools register on connect_instance()")

    def reconnect(self) -> bool:
        """After Ghidra restarts: find the same project again, else the sole instance."""
        instances = self.scanner.scan()
        inst = self.scanner.find(self.project, instances) if self.project else None
        if inst is None and len(instances) == 1:
            inst = instances[0]
        if inst is None:
            return False
        try:
            self.connect(inst["url"], inst.get("project"))
            log.info(f"reconnected to {inst.get('project') or inst['url']}")
            return True
        except Exception as e:
            log.warning(f"reconnect failed: {e}")
            return False

    # -- static tools --------------------------------------------------------

    def _register_static_tools(self) -> None:
        bridge = self

        @self.mcp.tool()
        def list_instances() -> str:
            """List running Ghidra instances (project, open programs, url) and which one is connected."""
            found = bridge.scanner.scan()
            if not found:
                return _dumps({"instances": [], "note": "No running Ghidra instances found."})
            for inst in found:
                inst["connected"] = bridge.client is not None and inst["url"] == bridge.client.base_url
            return _dumps({"instances": found})

        @self.mcp.tool()
        async def connect_instance(project: str, ctx: Context | None = None) -> str:
            """
            Connect the bridge to a Ghidra instance by project name (or substring) and load its
            tool catalog into the ghidra_<section> tools. Clients that cache tools/list must
            re-list after this call. Use list_instances() to see what is running.
            """
            found = bridge.scanner.scan()
            inst = bridge.scanner.find(project, found)
            if inst is None:
                return _dumps({"error": f"no instance matching '{project}'",
                               "available": [i.get("project") or i["url"] for i in found]})
            try:
                n = bridge.connect(inst["url"], inst.get("project"))
            except Exception as e:
                return _dumps({"error": f"connect failed: {e}", "url": inst["url"]})
            if ctx is not None and ctx._request_context is not None:
                await ctx.request_context.session.send_tool_list_changed()
            return _dumps({"connected": True, "project": inst.get("project"), "url": inst["url"],
                           "endpoints": n, "section_tools": list(bridge.registry.section_tools)})

        @self.mcp.tool()
        def ghidra_help(tool: str) -> str:
            """Full description and parameter schema for one action, plus which ghidra_<section> tool runs it."""
            td = bridge.catalog.get(tool)
            if td is None:
                return _dumps({"error": f"unknown tool '{tool}'", "did_you_mean": bridge.catalog.similar(tool)})
            return json.dumps(td.help(bridge.sections.section_of.get(tool, "?")), indent=1, ensure_ascii=False)

        @self.mcp.tool()
        def ghidra_tools(query: str = "", section: str = "") -> str:
            """
            Keyword search across every action (name, description, section); no query = section
            summary. Each hit shows the ghidra_<section> tool to call it through.
            """
            if not bridge.catalog:
                return _dumps({"error": "Not connected. Call list_instances() / connect_instance()."})
            terms = [t.lower() for t in query.split() if t.strip()]
            want = section.removeprefix("ghidra_")
            if not terms and not want:
                return _dumps({"sections": {
                    f"ghidra_{s}": {"actions": len(t), "about": bridge.sections.description(s)}
                    for s, t in bridge.sections.members.items()}})
            pool = bridge.sections.members.get(want) if want else None
            if want and pool is None:
                return _dumps({"error": f"unknown section '{section}'",
                               "sections": [f"ghidra_{s}" for s in bridge.sections.members]})
            hits = bridge.catalog.search(terms, pool)
            rows = [f"ghidra_{bridge.sections.section_of[n]} → {n}({bridge.catalog.by_name[n].param_summary()})"
                    f" — {bridge.catalog.by_name[n].one_liner()}" for n in hits[:40]]
            return _dumps({"matches": len(hits), "shown": len(rows), "tools": rows})

        @self.mcp.tool()
        def ghidra_annotate(functions: list[dict] | None = None, labels: list[dict] | None = None,
                            globals: list[dict] | None = None, save: bool = True,
                            dry_run: bool = False) -> str:
            """
            Apply a whole labelling pass in one call and get one summary back.
            functions: [{address, name?, prototype?, variables?{old:new}, plate?, comment?}]
            labels:    [{address, name}]                       plain labels on data/code
            globals:   [{address, name?, type?, comment?}]      data: label + data type + plate comment
            save: save the program afterwards. dry_run: validate only.
            """
            return bridge.annotator.apply(functions, labels, globals, save, dry_run)

        @self.mcp.tool()
        def ghidra_explore(address: str, depth: int = 2, max_functions: int = 12, callers: bool = True) -> str:
            """
            Understand a function and its subtree in one call: callers of it, the callee tree to
            `depth`, and decompiled code for the root plus callees (BFS order, up to max_functions).
            Replaces call_graph -> batch_decompile -> callers as separate calls.
            """
            return bridge.shaper.cap_stage(bridge.explorer.explore(address, depth, max_functions, callers))

        @self.mcp.tool()
        async def import_file(file_path: str, project_folder: str = "/", language: str | None = None,
                              compiler_spec: str | None = None, auto_analyze: bool = True,
                              ctx: Context | None = None) -> str:
            """
            Import a binary into the current Ghidra project and open it. For raw firmware give
            language (e.g. "tricore:LE:32:tc29x") and optionally compiler_spec; otherwise Ghidra
            auto-detects ELF/PE/Mach-O. With auto_analyze, a log notification is sent when
            analysis finishes.
            """
            args = {"file_path": file_path, "project_folder": project_folder, "auto_analyze": auto_analyze,
                    "language": language, "compiler_spec": compiler_spec}
            result = bridge.dispatcher.call("import_file", args)
            try:
                data = json.loads(result)
            except ValueError:
                return result
            name = data.get("name") if isinstance(data, dict) else None
            if isinstance(data, dict) and data.get("analyzing") and name and ctx is not None:
                session = ctx.request_context.session

                async def follow():
                    for _ in range(360):                    # up to 30 min
                        await asyncio.sleep(5)
                        st = bridge.client.get_json("/analysis_status", {"program": name}) if bridge.client else None
                        if st is not None and not st.get("analyzing", True):
                            await session.send_log_message(
                                level="info",
                                data=f"Analysis complete for {name}: {st.get('function_count', '?')} functions")
                            return

                asyncio.create_task(follow())
            return result

    # -- run -----------------------------------------------------------------

    def run(self) -> None:
        self.auto_connect()
        self.mcp.settings.log_level = "INFO"
        self.mcp.settings.host = self.cfg.mcp_host
        if self.cfg.mcp_port:
            self.mcp.settings.port = self.cfg.mcp_port
        log.info(f"starting MCP bridge ({self.cfg.transport})")
        self.mcp.run(transport=self.cfg.transport)
