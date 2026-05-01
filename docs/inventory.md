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

| Module           | NFS | ADFS | EBR | TUBE | Status                                      | Strategy |
|------------------|----:|-----:|----:|-----:|---------------------------------------------|----------|
| `__init__.py`    |   0 |    1 |   1 |    1 | Trivial                                     | New empty in fantasm |
| `mos6502.py`     | 152 |   97 |  98 |   99 | NFS adds CMOS (65C02) overrides + dispatcher | Take NFS; move `ROM_BASE`/`ROM_SIZE` to project config |
| `paths.py`       |  28 |   32 |  32 |   36 | Project-specific PREFIX; NFS supports two   | Rewrite against `ProjectContext` + fantasm.toml |
| `asm_extract.py` | 105 |  100 | 100 |  100 | NFS has 5 extra lines (relocation indexing) | Take NFS |
| `audit.py`       | 828 |  828 | 828 |  828 | **Byte-identical**                          | Take NFS |
| `backfill.py`    | 621 |  621 | 621 |  621 | **Byte-identical**                          | Take NFS |
| `cfg.py`         | 415 |  415 | 415 |  415 | NFS = ADFS = TUBE; EBR has 4 diff lines     | Take NFS |
| `comment_check.py` | 677 |  677 | 677 |  677 | **Byte-identical**                        | Take NFS |
| `compare.py`     | 470 |  319 | 319 |  319 | NFS has ~150 extra lines of capability      | Take NFS |
| `context.py`     | 459 |  459 | 459 |  459 | **Byte-identical**                          | Take NFS |
| `insert_point.py`| 183 |  183 | 183 |  183 | **Byte-identical**                          | Take NFS |
| `labels.py`      | 495 |  495 | 495 |  495 | **Byte-identical**                          | Take NFS |
| `lint.py`        | 555 |  522 | 522 |  492 | NFS most capable; check others for unique rules | Take NFS, then merge any unique rules |
| `rename_labels.py`| 284 |  284 | 284 |  284 | **Byte-identical**                          | Take NFS |
| `verify.py`      | 102 |  102 | 102 |  112 | Trivial diffs (project-name strings); TUBE has 24 extra | Take NFS, merge TUBE additions; parameterise project name |
| `cli.py`         | 417 |  401 | 445 |  358 | All diverge — Click sub-commands             | Design fresh hierarchical CLI in fantasm |
| `promote.py`     |   – |  235 | 235 |    – | ADFS+EBR identical; not in NFS or TUBE       | Port from ADFS |
| `find_shared.py` |   – |    – | 254 |    – | EBR only                                     | Port; assess generality |
| `blockmatch.py`  | 299 |    – |   – |    – | NFS only                                     | Port from NFS |
| `fingerprint.py` | 112 |    – |   – |    – | NFS only                                     | Port from NFS |

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
