"""SectionMap — which endpoints belong to which ghidra_<section> tool.

The table is data: edit it (or pass --sections file.json with the same
shape). Order here = order in tools/list and within each section. An
endpoint is placed by name (`tools`) or by upstream category
(`upstream_categories`); anything unmapped falls into a section named after
its upstream category so nothing is ever hidden.
"""

from __future__ import annotations

import json
from pathlib import Path

from .catalog import ToolCatalog

SECTIONS: dict[str, dict] = {
    "program": {
        "description": "Program/project session: which programs are open, metadata, memory map, address spaces, analysis, scripts, project files.",
        "tools": [
            "get_current_program_info", "list_open_programs", "open_program", "close_program", "switch_program",
            "save_program", "save_all_programs", "get_metadata", "get_language_metadata", "get_address_spaces",
            "list_segments", "get_entry_points", "set_image_base", "create_memory_block",
            "analysis_status", "run_analysis", "reanalyze", "list_analyzers",
            "list_project_files", "create_folder", "delete_file",
            "list_scripts", "run_ghidra_script", "run_script_inline",
            "prompt_policy", "convert_number",
        ],
    },
    "functions": {
        "description": "Find, decompile, disassemble, create, rename and prototype functions.",
        "tools": [
            "list_functions", "list_functions_enhanced", "list_methods", "get_function_count",
            "search_functions", "search_functions_enhanced", "get_function_by_address",
            "decompile_function", "batch_decompile", "force_decompile", "disassemble_function",
            "get_function_pcode", "get_function_signature", "get_function_jump_targets",
            "create_function", "delete_function", "find_next_undefined_function", "find_code_gaps",
            "rename_function", "rename_function_by_address", "batch_rename_function_components",
            "set_function_prototype", "validate_function_prototype", "set_function_no_return",
            "clear_instruction_flow_override",
        ],
    },
    "variables": {
        "description": "Locals and parameters inside a function: list, rename, retype, storage, dataflow.",
        "tools": [
            "get_function_variables", "rename_variable", "rename_variables", "set_variables",
            "set_local_variable_type", "set_parameter_type", "set_variable_storage", "analyze_dataflow",
        ],
    },
    "xrefs": {
        "description": "Cross-references, callers/callees, call graph, control flow, instruction search.",
        "tools": [
            "get_xrefs_to", "get_xrefs_from", "get_function_xrefs", "get_bulk_xrefs",
            "get_function_callers", "get_function_callees", "get_function_call_graph", "get_full_call_graph",
            "analyze_call_graph", "analyze_control_flow", "find_dead_code", "search_instructions",
        ],
    },
    "memory": {
        "description": "Raw bytes and defined data: read/inspect memory, byte-pattern search, strings, data items, globals, apply types at addresses, bookmarks.",
        "tools": [
            "read_memory", "inspect_memory_content", "search_byte_patterns", "disassemble_bytes",
            "list_strings", "search_strings", "list_data_items", "list_data_items_by_xrefs", "list_globals",
            "analyze_data_region", "detect_array_bounds", "get_assembly_context",
            "apply_data_type", "apply_data_classification", "set_global", "rename_data",
            "validate_data_type", "audit_global", "audit_globals_in_function",
            "set_bookmark", "list_bookmarks", "delete_bookmark",
        ],
    },
    "symbols": {
        "description": "Labels, namespaces/classes, imports/exports, external locations.",
        "tools": [
            "create_label", "delete_label", "rename_label", "batch_create_labels", "batch_delete_labels",
            "rename_or_label", "can_rename_at_address", "get_function_labels", "rename_global_variable",
            "list_classes", "list_namespaces", "list_imports", "list_exports",
            "list_external_locations", "get_external_location", "rename_external_location",
        ],
    },
    "comments": {
        "description": "Decompiler / disassembly / plate comments.",
        "tools": [
            "set_decompiler_comment", "set_disassembly_comment", "set_plate_comment", "get_plate_comment",
            "batch_set_comments", "clear_function_comments",
        ],
    },
    "types": {
        "description": "Data Type Manager: browse/search types and categories, create struct/union/enum/typedef/pointer/array/function-signature types, import C headers.",
        "tools": [
            "list_data_types", "search_data_types", "list_data_type_categories", "create_data_type_category",
            "move_data_type_to_category", "get_valid_data_types", "get_type_size", "validate_data_type_exists",
            "create_struct", "create_union", "create_enum", "get_enum_values", "create_typedef",
            "create_pointer_type", "create_array_type", "create_function_signature", "clone_data_type",
            "delete_data_type", "import_data_types", "list_calling_conventions",
        ],
    },
    "structs": {
        "description": "Work on an existing structure: layout, add/modify/remove fields, field usage and naming hints.",
        "tools": [
            "get_struct_layout", "add_struct_field", "modify_struct_field", "remove_struct_field",
            "analyze_struct_field_usage", "get_field_access_context", "suggest_field_names",
        ],
    },
    "tags": {
        "description": "Function tags: define, attach/detach (single or batch), search by tag.",
        "tools": [
            "list_function_tags", "create_function_tag", "delete_function_tag", "set_function_tag_comment",
            "add_function_tag", "remove_function_tag", "batch_add_function_tags", "batch_remove_function_tags",
            "get_function_tags", "search_functions_by_tag",
        ],
    },
    "docs": {
        "description": "Documentation completeness, function hashes/similarity, diffing and porting documentation between programs.",
        "tools": [
            "analyze_for_documentation", "analyze_function_complete", "analyze_function_completeness",
            "batch_analyze_completeness", "apply_function_documentation", "get_function_documentation",
            "archive_ingest_function", "archive_ingest_program", "batch_string_anchor_report",
            "find_undocumented_by_string", "get_function_hash", "get_bulk_function_hashes",
            "find_similar_functions", "find_similar_functions_fuzzy", "bulk_fuzzy_match",
            "diff_functions", "compare_programs_documentation", "merge_program_documentation",
        ],
    },
    "dynamic": {
        "description": "Ghidra debugger (TraceRmi) and p-code emulation: launch/attach, breakpoints, stepping, registers, traces.",
        "tools": ["emulate_function", "emulate_hash_batch"],
        "upstream_categories": ["debugger", "emulation"],
    },
    "malware": {
        "description": "Malware triage heuristics: crypto constants, anti-analysis, IOCs, API call chains.",
        "tools": [],
        "upstream_categories": ["malware"],
    },
}


class SectionMap:
    def __init__(self, table: dict[str, dict] | None = None):
        self.table = table or SECTIONS
        self.by_tool: dict[str, str] = {t: s for s, g in self.table.items() for t in g.get("tools", [])}
        self.by_category: dict[str, str] = {c: s for s, g in self.table.items()
                                            for c in g.get("upstream_categories", [])}
        self.members: dict[str, list[str]] = {}      # filled by assign()
        self.section_of: dict[str, str] = {}

    @classmethod
    def load(cls, path: Path | None) -> "SectionMap":
        if path is None:
            return cls()
        with open(path, encoding="utf-8") as f:
            table = {k: v for k, v in json.load(f).items() if not k.startswith("_")}
        return cls(table)

    def description(self, section: str) -> str:
        return self.table.get(section, {}).get("description") or f"Upstream category '{section}'."

    def assign(self, catalog: ToolCatalog) -> dict[str, list[str]]:
        members: dict[str, list[str]] = {s: [] for s in self.table}
        for name, td in catalog.by_name.items():
            s = self.by_tool.get(name) or self.by_category.get(td.category) or td.category
            members.setdefault(s, []).append(name)
            self.section_of[name] = s
        for s, tools in members.items():
            order = {t: i for i, t in enumerate(self.table.get(s, {}).get("tools", []))}
            tools.sort(key=lambda t: (order.get(t, len(order)), t))
        self.members = {s: t for s, t in members.items() if t}
        return self.members
