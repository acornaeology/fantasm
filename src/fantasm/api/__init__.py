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
    build_target_refs,
    classify_labels,
    collect_auto_labels,
    find_containing_sub_for_addr,
    sort_labels,
)
from .audit import (
    ALL_FLAGS,
    BASE_MEMORY_REGIONS,
    BRANCH_MNEMONICS,
    TERMINATING_MNEMONICS,
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
    OPCODE_LENGTHS,
    OPCODE_LENGTHS_65C02,
    OPCODE_MNEMONICS,
    OPCODE_MNEMONICS_65C02,
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
    "BASE_MEMORY_REGIONS",
    "BRANCH_MNEMONICS",
    "CATEGORY_ORDER",
    "OPCODE_LENGTHS",
    "OPCODE_LENGTHS_65C02",
    "OPCODE_MNEMONICS",
    "OPCODE_MNEMONICS_65C02",
    "TERMINATING_MNEMONICS",
    "VersionNotFoundError",
    "build_index",
    "build_memory_regions",
    "build_target_refs",
    "classify_labels",
    "collect_auto_labels",
    "end_type",
    "extract_section",
    "find_containing_sub",
    "find_containing_sub_for_addr",
    "find_line_for_target",
    "find_sub",
    "find_undeclared_subs",
    "instruction_length",
    "load_subroutines",
    "mnemonic",
    "opcode_tables",
    "parse_address",
    "project_rom_prefixes",
    "project_versions_dirpath",
    "region_for_addr",
    "resolve_version_dirpath",
    "resolve_version_dirpath_for_project",
    "rom_prefix",
    "rom_prefix_for_project",
    "scan_routine_range",
    "sort_labels",
]
