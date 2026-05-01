# Inventory of `disasm_tools/` across the four sibling projects

Living document. Captures the state of the four `disasm_tools/` packages at
the time of fantasm's initial consolidation, and notes the strategy for
each module.

| Project              | path                       |
|----------------------|----------------------------|
| acorn-6502-tube-client | `src/disasm_tools/`      |
| acorn-adfs           | `src/disasm_tools/`        |
| acorn-econet-bridge  | `src/disasm_tools/`        |
| acorn-nfs            | `src/disasm_tools/`        |

All four packages share a near-identical surface, but `acorn-nfs` has
absorbed the most additions over time and is the working baseline for most
modules. A handful of modules exist in only one fork.

## Per-module status

Line counts and diff-line counts (versus NFS) collected on 2026-05-01.

| Module           | NFS | ADFS | EBR | TUBE | Status                                      | Port |
|------------------|----:|-----:|----:|-----:|---------------------------------------------|------|
| `__init__.py`    |   0 |    1 |   1 |    1 | Trivial                                     | ✅ done |
| `mos6502.py`     | 152 |   97 |  98 |   99 | NFS adds CMOS (65C02) overrides + dispatcher | ✅ done — ROM_BASE/ROM_SIZE moved out, set up for `[rom] cpu` config |
| `paths.py`       |  28 |   32 |  32 |   36 | Project-specific PREFIX; NFS supports two   | ✅ done — refactored against ProjectContext; `[versions]` config |
| `asm_extract.py` | 105 |  100 | 100 |  100 | NFS has 5 extra lines (relocation indexing) | ✅ done — typed extract_section() returning AsmSection |
| `audit.py`       | 828 |  828 | 828 |  828 | **Byte-identical**                          | ⚠️ partial — pure-logic + load_subroutines + find_undeclared_subs ported; `format_*` and top-level `audit()` deferred to CLI integration |
| `backfill.py`    | 621 |  621 | 621 |  621 | **Byte-identical**                          | ⏳ pending |
| `cfg.py`         | 415 |  415 | 415 |  415 | NFS = ADFS = TUBE; EBR has 4 diff lines     | ⚠️ partial — build_call_graph + resolve_sub_node ported with KEY FIX (uses audit.build_memory_regions(meta), not hardcoded NFS regions); format_* deferred |
| `comment_check.py` | 677 |  677 | 677 |  677 | **Byte-identical**                        | ⚠️ partial — every check function + run_checks ported; format_findings + comment_check() deferred |
| `compare.py`     | 470 |  319 | 319 |  319 | NFS has ~150 extra lines of capability      | ⏳ pending |
| `context.py`     | 459 |  459 | 459 |  459 | **Byte-identical**                          | ⚠️ partial — compute_call_depths ported; generate_context (file IO) deferred |
| `insert_point.py`| 183 |  183 | 183 |  183 | **Byte-identical**                          | ⚠️ partial — parse_subroutine_declarations + find_main_block + new compute_insert_point ported; print/IO wrapper deferred |
| `labels.py`      | 495 |  495 | 495 |  495 | **Byte-identical**                          | ⚠️ partial — classify_labels + sort_labels + collect_auto_labels (was `_collect_auto_labels`); generate_labels file-IO deferred |
| `lint.py`        | 555 |  522 | 522 |  492 | NFS most capable; check others for unique rules | ⏳ pending |
| `rename_labels.py`| 284 |  284 | 284 |  284 | **Byte-identical**                          | ⚠️ partial — parse_label_declarations + find_rename_section + find_insert_position + new apply_renames_to_lines pure transformer; rename_labels() and show_sub_labels() file-IO deferred |
| `verify.py`      | 102 |  102 | 102 |  112 | Trivial diffs (project-name strings); TUBE has 24 extra | ✅ done — verify_round_trip() returns VerifyResult dataclass; BeebasmNotFoundError raised |
| `cli.py`         | 417 |  401 | 445 |  358 | All diverge — Click sub-commands             | ⏳ pending — designing fresh hierarchical CLI |
| `promote.py`     |   – |  235 | 235 |    – | ADFS+EBR identical; not in NFS or TUBE       | ⏳ pending |
| `find_shared.py` |   – |    – | 254 |    – | EBR only                                     | ⏳ pending |
| `blockmatch.py`  | 299 |    – |   – |    – | NFS only                                     | ⏳ pending |
| `fingerprint.py` | 112 |    – |   – |    – | NFS only                                     | ⏳ pending |

### Porting strategy that emerged

For each ported module the same shape recurs: lift the pure-logic surface
into `fantasm.api.<topic>` with type hints, frozen dataclasses for results,
typed exceptions instead of `sys.exit`/stderr-print, and `warnings.warn`
for soft diagnostics. Tests are characterisation tests against
hand-crafted in-memory data — small enough to read, complete enough to
pin behaviour for refactors.

The `format_*` and file-reading top-level entry functions (the CLI side)
are intentionally deferred for each module. They will land alongside the
`fantasm <topic>` Click sub-commands in a follow-up pass, where the
project-specific strings and `rom_prefix(version_dirpath)` calls can be
threaded through a `ProjectContext` once.

Legend: NFS = `acorn-nfs`, ADFS = `acorn-adfs`, EBR = `acorn-econet-bridge`,
TUBE = `acorn-6502-tube-client`. Em-dash (`–`) means the module is absent
in that fork.

## Cross-cutting refactors

A handful of concerns appear in multiple modules and need to be lifted out
during consolidation:

- **Project layout assumptions.** `paths.py` knows the directory naming
  convention (`{PREFIX}-{version_id}/`) and the ROM-name prefix. fantasm
  expresses these in `fantasm.toml` instead of hardcoded module constants.
- **ROM bank constants.** `ROM_BASE` and `ROM_SIZE` live in `mos6502.py`
  today, but they are properties of how a ROM was *banked*, not of the
  6502. They move into `fantasm.toml` (and a future `fantasm.api.rom`
  module) so the same disassembly tools can target the BBC's 16K sideways
  ROMs, the 8K NFS sideways "half-bank", and other layouts.
- **`SystemExit` from library code.** Several siblings call `sys.exit(1)`
  on error inside library functions (e.g. `paths.resolve_version_dirpath`).
  The fantasm port raises a typed exception (e.g. `VersionNotFound`) and
  the CLI layer translates it to a clean exit code with a useful message.
- **Console-script names.** Sibling code references the project-specific
  `acorn-{x}-disasm-tool` console-script name in error messages. fantasm
  uses `fantasm`.

## Porting order

Foundational first, so later modules can build on a stable base:

1. `mos6502` (no deps; opcode tables are the bedrock)
2. `paths` (refactored against `ProjectContext` + `fantasm.toml`)
3. `labels` (used by many)
4. `comment_check`
5. `compare`
6. `audit`, `lint`, `verify`
7. `cfg`, `context`, `insert_point`
8. `rename_labels`, `asm_extract`, `backfill`
9. Specialised: `blockmatch`, `fingerprint`, `promote`, `find_shared`

CLI integration happens alongside each module: a `fantasm <topic>` group is
added with the relevant sub-commands, and the public surface is re-exported
from `fantasm.api.__init__` so callers can either `from fantasm.api import
…` or reach into `fantasm.api.<topic>`.

Tests are characterisation tests: small hand-crafted inputs whose expected
output is captured from the working code, plus round-trip tests against
`beebasm` for any module that emits assembly source.
