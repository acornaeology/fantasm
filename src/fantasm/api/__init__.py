"""Programmatic API for fantasm.

Sub-modules will hold per-topic surfaces (labels, comments, cfg, audit, ...).
This package re-exports the stable, flat surface so callers can do either:

    from fantasm.api import rename_labels
    from fantasm.api.labels import rename_labels

The flat re-exports are populated as topics are ported in from the sibling
``disasm_tools`` packages.
"""

from __future__ import annotations

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
    "OPCODE_LENGTHS",
    "OPCODE_LENGTHS_65C02",
    "OPCODE_MNEMONICS",
    "OPCODE_MNEMONICS_65C02",
    "VersionNotFoundError",
    "instruction_length",
    "mnemonic",
    "opcode_tables",
    "project_rom_prefixes",
    "project_versions_dirpath",
    "resolve_version_dirpath",
    "resolve_version_dirpath_for_project",
    "rom_prefix",
    "rom_prefix_for_project",
]
