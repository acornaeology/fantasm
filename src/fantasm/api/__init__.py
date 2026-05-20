"""Programmatic API for fantasm.

Sub-modules will hold per-topic surfaces (labels, comments, cfg, audit, ...).
This package re-exports the stable, flat surface so callers can do either:

    from fantasm.api import rename_labels
    from fantasm.api.labels import rename_labels

The flat re-exports are populated as topics are ported in from the sibling
``disasm_tools`` packages.
"""

from __future__ import annotations

from .asm_extract import (
    AsmSection,
    build_index,
    extract_section,
    find_line_for_target,
    parse_address,
)
from .labels import (
    AUTO_LABEL_RE,
    CATEGORY_ORDER,
    LABEL_SOURCES,
    build_target_refs,
    classify_labels,
    collect_auto_labels,
    collect_labels,
    find_containing_sub_for_addr,
    inbound_refs_to,
    label_inventory,
    sort_labels,
)
from .cfg import (
    BasicBlock,
    BasicBlockEntry,
    BasicBlockExit,
    build_call_graph,
    find_basic_blocks,
    resolve_sub_node,
)
from .dot import (
    DotBinaryNotFoundError,
    basic_blocks_to_dot,
    basic_blocks_to_graph,
    basic_blocks_to_graphml,
    call_graph_to_dot,
    call_graph_to_graphml,
    filter_call_graph,
    render_dot,
)
from .backfill import (
    AnnotationDiff,
    PropagationCandidate,
    PropagationReport,
    build_confidence_map,
    build_confidence_map_for_block,
    diff_annotations,
    group_logical_statements,
    parse_annotations,
    propose_propagations,
    translate_address_in_text,
    translate_subroutine,
)
from .blockmatch import (
    RelocatedBlock,
    build_full_address_map,
    build_primary_map,
    disassemble_to_opcodes,
    find_relocated_blocks,
)
from .bytes_search import (
    BytePattern,
    ByteMatch,
    find_byte_pattern,
    parse_byte_pattern,
)
from .driver_sort import (
    ANCHOR_FUNCTIONS,
    SORTABLE_FUNCTIONS,
    Unit,
    build_units,
    emit_units,
    is_sorted,
    sort_driver_text,
)
from .data_review import (
    Classification,
    CodeClassification,
    DataRun,
    HiBytesTableClassification,
    PaddingClassification,
    StringClassification,
    classify_run_bytes,
    find_classification_candidates,
    find_data_runs,
    looks_like_code,
    looks_like_hi_bytes_table,
    looks_like_padding,
    looks_like_string,
)
from .fingerprint import (
    find_duplicate_blocks,
    fingerprint_blocks,
    fingerprint_rom_file,
    fingerprint_window,
    opcode_fingerprint,
)
from .find_shared import (
    find_matching_spans,
    is_trivial_span,
    load_rom,
    matching_byte_count,
    parse_rom_spec,
    sweep_opcodes,
)
from .hooks import (
    HookCandidate,
    find_hook_candidates,
    render_hook_subroutine_line,
)
from .suggest import (
    CommentSuggestion,
    DEFAULT_INSTRUCTION_HINTS,
    suggest_comments,
    suggest_for_instruction,
)
from .promote import (
    CALL_MNEMONICS,
    TERMINAL_MNEMONICS,
    analyze_labels,
    load_and_analyze_labels,
)
from .compare import (
    Instruction,
    RomHeader,
    compare_headers,
    compare_roms,
    disassemble_linear,
    format_address,
    format_instruction,
    parse_rom_header,
)
from .rename_labels import (
    apply_renames_inline,
    apply_renames_to_lines,
    find_insert_position,
    find_rename_section,
    parse_label_decl_lines,
    parse_label_declarations,
    update_ref_strings,
)
from .project import (
    ProjectInitConfig,
    VersionInfo,
    add_version,
    init_project,
    list_versions,
    render_fantasm_toml,
)
from .verify import BeebasmNotFoundError, VerifyResult, verify_round_trip
from .version_graph import (
    Edge,
    NoPathError,
    Region,
    RelocBlock,
    Version,
    VersionGraph,
    VersionGraphCycleError,
    VersionGraphError,
    VersionNotInGraphError,
    compose_chained_map,
    load_version_graph,
)
from .context import (
    CallSiteContext,
    CoverageGroup,
    CoverageReport,
    ExitPointContext,
    SubContext,
    UncommentedSubReport,
    analyse_uncommented_subs,
    compute_call_depths,
    compute_coverage,
    extract_sub_context,
)
from .lint import (
    address_in_ranges,
    address_ranges_from_data,
    extract_annotations,
    find_code_block_ranges,
    find_nth_occurrence,
    load_address_ranges,
    load_valid_addresses,
    offset_in_code_block,
    valid_addresses_from_data,
)
from .insert_point import (
    AlreadyDeclared,
    InsertPoint,
    compute_insert_point,
    find_main_block,
    parse_subroutine_declarations,
)
from .comment_check import (
    ALL_CHECKS,
    CR_ADDRESSES,
    IMM_REG_MNEMONICS,
    TUBE_REGISTERS,
    build_known_addrs,
    check_block_stale_addr,
    check_branch_target,
    check_chain_comments,
    check_cr_value,
    check_desc_stale_addr,
    check_reg_value,
    check_stale_addr,
    check_tube_register,
    find_chains,
    find_stale_addrs,
    parse_imm_value,
    run_checks,
)
from .audit import (
    ALL_FLAGS,
    build_memory_regions,
    end_type,
    find_containing_sub,
    find_sub,
    find_undeclared_subs,
    load_subroutines,
    region_for_addr,
    scan_routine_range,
)
from .mos6502 import (
    BRANCH_MNEMONICS,
    OPCODE_LENGTHS,
    OPCODE_LENGTHS_65C02,
    OPCODE_MNEMONICS,
    OPCODE_MNEMONICS_65C02,
    TERMINATING_MNEMONICS,
    instruction_length,
    mnemonic,
    opcode_tables,
)
from .paths import (
    VersionNotFoundError,
    project_rom_prefixes,
    project_versions_dirpath,
    resolve_version_dirpath,
    resolve_version_dirpath_for_project,
    rom_prefix,
    rom_prefix_for_project,
)

__all__ = [
    "ALL_FLAGS",
    "AUTO_LABEL_RE",
    "AsmSection",
    "BRANCH_MNEMONICS",
    "CATEGORY_ORDER",
    "DotBinaryNotFoundError",
    "LABEL_SOURCES",
    "OPCODE_LENGTHS",
    "OPCODE_LENGTHS_65C02",
    "OPCODE_MNEMONICS",
    "OPCODE_MNEMONICS_65C02",
    "TERMINATING_MNEMONICS",
    "VersionNotFoundError",
    "basic_blocks_to_dot",
    "basic_blocks_to_graph",
    "basic_blocks_to_graphml",
    "build_index",
    "build_memory_regions",
    "build_target_refs",
    "call_graph_to_dot",
    "call_graph_to_graphml",
    "classify_labels",
    "collect_auto_labels",
    "collect_labels",
    "end_type",
    "extract_section",
    "filter_call_graph",
    "find_containing_sub",
    "find_containing_sub_for_addr",
    "find_line_for_target",
    "find_sub",
    "find_undeclared_subs",
    "inbound_refs_to",
    "instruction_length",
    "label_inventory",
    "load_subroutines",
    "mnemonic",
    "opcode_tables",
    "parse_address",
    "project_rom_prefixes",
    "project_versions_dirpath",
    "region_for_addr",
    "render_dot",
    "resolve_version_dirpath",
    "resolve_version_dirpath_for_project",
    "rom_prefix",
    "rom_prefix_for_project",
    "scan_routine_range",
    "sort_labels",
]
