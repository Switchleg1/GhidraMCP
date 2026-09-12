"""Drive bridge_mcp_ghidra.py (entry + library/) over stdio exactly as Claude launches it.
Reports advertised tools + payload size, then exercises section calls, error
paths, a dry-run write, ghidra_help and ghidra_tools. Ghidra must be running.

    python test_bridge.py [bridge args, e.g. --brief --flat --expose x,y]
"""
import io
import json
import subprocess
import sys
import time
from pathlib import Path

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

BRIDGE = Path(__file__).with_name("bridge_mcp_ghidra.py")
p = subprocess.Popen([sys.executable, str(BRIDGE), *sys.argv[1:]],
                     stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                     stderr=subprocess.PIPE, text=True, encoding="utf-8")
_id = 0


def rpc(method, **params):
    global _id
    _id += 1
    p.stdin.write(json.dumps({"jsonrpc": "2.0", "id": _id, "method": method, "params": params}) + "\n")
    p.stdin.flush()
    while True:
        line = p.stdout.readline()
        if not line:
            raise SystemExit("bridge exited:\n" + p.stderr.read()[-3000:])
        m = json.loads(line)
        if m.get("id") == _id:
            return m


def call(name, **kw):
    m = rpc("tools/call", name=name, arguments=kw)
    return m["result"]["content"][0]["text"]


t0 = time.time()
rpc("initialize", protocolVersion="2024-11-05", capabilities={}, clientInfo={"name": "t", "version": "0"})
p.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n"); p.stdin.flush()
tools = rpc("tools/list")["result"]["tools"]
blob = json.dumps(tools)
print(f"advertised tools: {len(tools)}   tools/list payload: {len(blob):,} chars ~ {len(blob)//4:,} tokens   ({time.time()-t0:.1f}s)")
for t in tools:
    print(f"  {t['name']:28s} {len(t.get('description') or ''):5d} chars")

if any(t["name"] == "ghidra_functions" for t in tools):
    print("\n--- ghidra_functions description (head)")
    print(next(t["description"] for t in tools if t["name"] == "ghidra_functions")[:600])
    print("\n--- ghidra_functions(get_function_count)")
    print(call("ghidra_functions", action="get_function_count")[:200])
    print("--- ghidra_program(get_current_program_info)")
    print(call("ghidra_program", action="get_current_program_info")[:160])
    print("--- wrong section")
    print(call("ghidra_xrefs", action="get_struct_layout"))
    print("--- unknown action")
    print(call("ghidra_structs", action="nope")[:160])
    print("--- missing arg")
    print(call("ghidra_structs", action="get_struct_layout"))
    print("--- bad arg")
    print(call("ghidra_structs", action="get_struct_layout", args={"bogus": 1}))
    print("--- dry-run write")
    print(call("ghidra_comments", action="set_plate_comment",
               args={"address": "0x80000000", "comment": "x", "dry_run": True}))
    print("--- ghidra_help(get_struct_layout)")
    print(call("ghidra_help", tool="get_struct_layout")[:300])
    print("--- ghidra_tools('struct field')")
    print(call("ghidra_tools", query="struct field")[:400])
    print("--- ghidra_tools() sections")
    secs = json.loads(call("ghidra_tools"))["sections"]
    print({k: v["actions"] for k, v in secs.items()})
    known = {"program","functions","variables","xrefs","memory","symbols","comments","types","structs","tags","docs","dynamic","malware"}
    print("sections not in SECTIONS (upstream-category fallback):",
          [k for k in secs if k.removeprefix("ghidra_") not in known] or "none")

p.kill()
