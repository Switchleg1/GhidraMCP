"""GhidraMCP bridge library — one class per module.

    Config            flags / env -> settings
    ToolDef, ParamDef parsed endpoint definition
    ToolCatalog       /mcp/schema -> ToolDefs, name sanitising, search
    SectionMap        endpoint -> section table
    AddressNormalizer address string rules
    GhidraClient      keep-alive HTTP to the Ghidra plugin
    InstanceScanner   find running Ghidra instances
    ResponseShaper    trim / normalise / cap responses
    ActionDispatcher  validate args, call endpoint, shape result
    BatchAnnotator    rename + comment + label many things in one call
    Explorer          callers + call tree + subtree decompiles in one call
    ToolRegistry      register section + first-class tools on FastMCP
    Bridge            orchestration and static MCP tools
"""

from .config import Config
from .bridge import Bridge

__all__ = ["Config", "Bridge"]
