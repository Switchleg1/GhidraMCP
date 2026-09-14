# GhidraMCP — sectioned bridge

Drop-in replacement for the `bridge_mcp_ghidra.py` that ships with GhidraMCP (the `mcp/`
folder of your Ghidra install). Same launch command, same Ghidra plugin, same endpoints —
different presentation and a leaner wire format. The stock bridge is one 2500-line file;
this is ~1300 lines across an entry point and a `library/` package with one class per file.

```
bridge_mcp_ghidra.py       entry: argv -> Config -> Bridge.run()
library/
  config.py      Config             flags + env resolved once
  tooldef.py     ToolDef, ParamDef  one parsed endpoint
  catalog.py     ToolCatalog        /mcp/schema -> ToolDefs, name sanitising, search
  sections.py    SectionMap         the SECTIONS table + assignment
  address.py     AddressNormalizer  ordered (regex -> transform) rules
  client.py      GhidraClient       keep-alive HTTP, lock, timeout + retry tables
  discovery.py   InstanceScanner    parallel loopback port scan, matcher table
  shaper.py      ResponseShaper     (stage pipeline) lint strip, normalise, cap
  dispatcher.py  ActionDispatcher   coercer table -> GET/POST -> shape
  annotator.py   BatchAnnotator     rename/prototype/variables/comments/labels/globals in one call
  explorer.py    Explorer           callers + call tree + subtree decompiles in one call
  registry.py    ToolRegistry       section tools / first-class tools on FastMCP
  bridge.py      Bridge             orchestration + the 7 static tools
```

## Why

**Per-session cost.** The stock bridge registers every endpoint (196) as its own MCP tool,
plus 22 WinDbg proxies on Windows that collide with Ghidra's own `/debugger/*` and produce
`*_2` duplicates: 222 tools, ~141 KB of schema, **~35k tokens on every turn**.

**Per-call cost.** Every write returned ~500 chars of naming-lint chatter ("is not
PascalCase… Expected: …", "Plate comment missing Algorithm section"); decompiles came back
with `\r\n`; `batch_decompile` returned code JSON-escaped inside JSON; and a large answer
(e.g. `get_bulk_xrefs` on a hot helper) could exceed the client's tool-result limit and get
dumped to a file.

## What this version does

**13 section tools** instead of 200 flat ones:

| tool | actions | covers |
|---|---|---|
| `ghidra_program` | 27 | open/switch/save programs, metadata, memory map, address spaces, analysis, scripts, project files |
| `ghidra_functions` | 25 | list/search, decompile, disassemble, p-code, create/delete, rename, prototypes |
| `ghidra_variables` | 8 | locals/params: list, rename, retype, storage, dataflow |
| `ghidra_xrefs` | 12 | xrefs to/from, callers/callees, call graph, control flow, instruction search |
| `ghidra_memory` | 22 | read/inspect bytes, byte-pattern search, strings, data items, globals, apply types, bookmarks |
| `ghidra_symbols` | 16 | labels, namespaces, imports/exports, externals |
| `ghidra_comments` | 6 | decompiler / disassembly / plate comments |
| `ghidra_types` | 20 | Data Type Manager: browse, create struct/union/enum/typedef/ptr/array, import headers |
| `ghidra_structs` | 7 | fields of an existing struct, usage analysis, naming hints |
| `ghidra_tags` | 10 | function tags |
| `ghidra_docs` | 18 | documentation completeness, hashes/similarity, diff & merge between programs |
| `ghidra_dynamic` | 20 | Ghidra debugger (TraceRmi) + p-code emulation |
| `ghidra_malware` | 5 | crypto constants, anti-analysis, IOCs |

Each takes `action` (endpoint name, unchanged) and `args` (dict). The description lists every
action with params and a one-liner, so the whole catalog is visible up front, grouped. Bad
calls return the fix (valid params / right section / action list). `dry_run: true` works on
every write. Plus `ghidra_help(tool)`, `ghidra_tools(query)`, `list_instances`,
`connect_instance`, `import_file`, and two bridge-side batches (the server has neither):

- **`ghidra_annotate`** — a whole labelling pass in one call:
  `functions=[{address, name?, prototype?, variables?{old:new}, plate?, comment?}]`,
  `labels=[{address, name}]`, `globals=[{address, name?, type?, comment?}]`, `save=True`.
  Per-item writes are the `STEPS` / `GLOBAL_STEPS` tables in `annotator.py`. (Globals use
  `create_label` + `apply_data_type` + plate comment rather than `set_global` or `rename_or_label`, whose
  `g_`-Hungarian name policy rejects every ECU-style name.) Measured on an 8-function +
  7-label pass: 18 calls / 8.9 KB on the wire → 1 call / 4.3 KB, reply 1795 → 53 chars, 17
  fewer model round-trips.
- **`ghidra_explore(address, depth=2, max_functions=12)`** — callers, callee tree to `depth`,
  and decompiled code for the root + callees (BFS, bounded) in one reply. Same bytes as
  `get_function_call_graph` + `batch_decompile` + `get_function_callers`, one round-trip.

**Response shaping** (`ResponseShaper`, every call): server lint warnings dropped
(`--keep-lint` restores), `{"success":true,"data":X}` unwrapped, `{addr: code}` maps emitted as
plain text blocks, a single list of flat records (`disassemble_bytes` instructions,
`list_functions_enhanced`, …) rendered as a header + rows table (57 % smaller than the JSON for
a 141-instruction disassembly; derivable columns such as instruction `length` dropped via
`_DROP_COLUMNS`), `\r\n` → `\n`, trailing spaces and blank runs collapsed, compact JSON, and a
hard cap (`--max-chars`, default 40 000) with a truncation note instead of an oversized reply.

**Transport**: one keep-alive HTTP connection (reopened on failure) instead of a new TCP
connection per call (reopened proactively after 20 s idle, so a server-side keep-alive timeout
cannot race the next write); GETs retry on transport error / 5xx and re-discover Ghidra after a
restart; POSTs are re-sent only if the send itself failed (server never saw them). UDS and WinDbg proxies
are gone (on Windows neither works: no `AF_UNIX`, and the dbgeng server is rarely run).

### Measured (live TriCore firmware, ~20k functions)

| | stock | this |
|---|---|---|
| tools advertised | 222 | 18 |
| `tools/list` payload | ~141 KB (~35k tok) | ~31 KB (~7.7k tok); `--brief` ~18 KB |
| `rename_function_by_address` reply | 670 chars | 146 |
| `batch_decompile` (2 fns) | 1536 chars, escaped | 1416, plain text |
| `disassemble_bytes` (141 instr) | 13 574 chars JSON | 5 766, table |
| `decompile_function` | 2824 | 2737 |
| cached read latency (keep-alive) | new conn/call | ~2 ms |
| oversized reply | client dumps to file | capped at 40 000 chars + note |

## Install

Requires Python 3.10+ and `pip install -r requirements.txt` (the `mcp` package).

Either point your MCP client at this repo's entry point:

```json
"ghidra": { "command": "python", "args": ["<path to this repo>/bridge_mcp_ghidra.py"] }
```

or copy `bridge_mcp_ghidra.py` **and** the `library/` folder over the stock file in your
Ghidra install's `mcp/` directory (elevated shell if Ghidra lives under Program Files).
Either way, restart the MCP client. If you install over the stock file, a future GhidraMCP
update will overwrite it — recopy both.

### Flags

| flag | effect |
|---|---|
| `--brief` | section descriptions list action names only |
| `--expose a,b,c` | ALSO register these endpoints as ordinary first-class tools |
| `--flat` | stock layout, one tool per endpoint (still shaped, no WinDbg) |
| `--sections PATH` | JSON override of the `SECTIONS` table (same shape as the dict in `sections.py`) |
| `--max-chars N` | response cap (default 40000) |
| `--keep-lint` | keep the server's naming-lint warnings |
| `--url`, `--transport`, `--mcp-host`, `--mcp-port` | as stock |

Env: `GHIDRA_MCP_URL`, `GHIDRA_MCP_LOG_LEVEL`, `GHIDRA_MCP_REQUIRE_PROGRAM_SELECTORS=1`.

### Editing behaviour — it's all tables

| want to change | edit |
|---|---|
| which actions sit in which section, order, descriptions | `SECTIONS` in `sections.py` |
| repeated param blurbs | `PARAM_DESCRIPTIONS` in `tooldef.py` |
| what counts as lint noise | `LINT_MARKERS` in `shaper.py` |
| record-table columns to drop / meta keys to hide | `_DROP_COLUMNS`, `_DROP_META` in `shaper.py` |
| per-endpoint timeouts / scaling | `TIMEOUTS`, `TIMEOUT_SCALING` in `client.py` |
| retry behaviour per HTTP method | `RETRY` in `client.py` |
| how arg values are coerced by declared type | `COERCERS` in `dispatcher.py` |
| address string forms | `_RULES` in `address.py` |
| project-name matching order | `_MATCHERS` in `discovery.py` |

Endpoints upstream adds later that aren't in `SECTIONS` land in a section named after their
upstream category, so nothing is hidden; `test/test_bridge.py` reports them.

## Testing

With Ghidra running, drives the bridge over stdio exactly as the app launches it:

```bash
python test/test_bridge.py
```

Advertised tools + payload size, then section calls, wrong-section / unknown-action /
missing-arg / bad-arg errors, a `dry_run` write, `ghidra_help`, `ghidra_tools`, and any
fallback sections. Flags pass through: `python test/test_bridge.py --brief`.
