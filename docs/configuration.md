# `fantasm.toml`

Per-project configuration for fantasm. Sits at the project root. Fantasm
discovers it by walking upwards from the current working directory; the
top-level `--project-root` option and the `FANTASM_PROJECT_ROOT`
environment variable both override discovery.

## Schema

The schema is grown opportunistically as modules are ported in. Today
the following sections are recognised:

```toml
[project]
# Project name. Used as a fallback for [versions] prefixes when that
# option is omitted, and for the project-specific strings the CLI
# emits in error/help messages.
name = "acorn-nfs"

[rom]
# Default CPU for downstream commands that decode opcodes. Recognised
# values (case-insensitive): "6502" / "nmos" (default) and "65c02" /
# "65sc12" / "65c12" / "cmos".
cpu = "6502"

# (Future) base load address and bank size for the ROM(s); these will
# be threaded into modules that previously hardcoded NFS-specific
# 0x8000 / 0x2000 constants.
# base_address = 0x8000
# size = 0x2000

[versions]
# Directory under the project root that holds version subdirectories.
# Default: "versions".
directory = "versions"

# Ordered list of acceptable ROM-name prefixes. Version directories are
# named "{prefix}-{version_id}/"; resolution tries each prefix in order
# and returns the first existing directory. NFS uses two ("anfs" and
# "nfs"); other projects use one. If omitted, [project] name is used as
# a single-element fallback.
prefixes = ["anfs", "nfs"]
```

## Examples

A minimal config for a single-prefix project:

```toml
[project]
name = "acorn-adfs"
```

Equivalent to:

```toml
[project]
name = "acorn-adfs"

[versions]
directory = "versions"
prefixes  = ["acorn-adfs"]
```

NFS, with two prefixes:

```toml
[project]
name = "acorn-nfs"

[versions]
prefixes = ["anfs", "nfs"]
```

## Driver-script paths

py8dis driver scripts (the Python files that build a disassembly)
sit by convention under each version directory. Their location and
filename follow a project-wide template:

```toml
[versions]
# Subdirectory under each version's directory holding the driver
# script. Default: "disassemble".
driver_dirname = "disassemble"

# Filename template. Tokens: {prefix}, {version_id},
# {version_id_no_dots}. Default:
driver_filename = "disasm_{prefix}_{version_id_no_dots}.py"
```

So for NFS version ``3.10`` (prefix ``anfs``), with the defaults,
the driver script's path is
``versions/anfs-3.10/disassemble/disasm_anfs_310.py``.

Commands that need a driver script (e.g. ``fantasm backfill``,
``fantasm lint``) compute this path automatically from the version
ID. Pass an explicit path with the relevant ``--source-driver`` /
``--target-driver`` / ``DRIVER_FILEPATH`` argument when the project
diverges from the convention.

## Resolution semantics

`fantasm.api.paths.resolve_version_dirpath_for_project(project, version_id)`
reads `[versions]` and looks for `{prefix}-{version_id}/` under
`{project_root}/{directory}/` — first match wins. A
`VersionNotFoundError` carrying the available directory names is raised
if nothing matches.

`fantasm.api.paths.rom_prefix_for_project(project, version_dirpath)` does
the inverse: extracts the prefix from a directory name using the
configured prefix list.

## `[memory]` — non-ROM addresses where code and labels can live

Two lists at the project level. Both can be omitted if the project has
no non-ROM workspace (a one-bank pure-ROM project).

```toml
[memory]
# Where subroutines and labels can live, outside the ROM range. Used
# by audit (extent analysis), lint (annotation validity), and the
# label-propagation logic in backfill. The ROM range itself is
# discovered from each version's JSON metadata, so don't list it here.
# Reloc-block destinations from a version's `reloc_blocks` list are
# auto-merged into that version's *effective* regions, so don't
# duplicate them here either.
regions = [
  { start = 0x0016, end = 0x0076 },   # zero-page workspace
  { start = 0x0D00, end = 0x0FFF },   # NMI workspace
]

# Hardware / OS-mapped addresses that label references can point at,
# but where no assembly items are emitted. Used by lint and
# comment_check to allow references to OS routines, hardware
# registers, etc.
external_regions = [
  { start = 0x0000, end = 0x03FF },   # zero page + OS workspace + vectors
  { start = 0xFC00, end = 0xFFFF },   # SHEILA / Tube / FRED / JIM / MOS
]
```

`end` is **inclusive** in both lists, matching the convention in the
audit module.

A version can override `regions` (but not `external_regions` —
hardware mapping is invariant) by setting it in its
`[[versions.entry]]`:

```toml
[[versions.entry]]
id = "page7-variant"
parents = ["3.34B"]
memory.regions = [
  { start = 0x0016, end = 0x0076 },
  { start = 0x0700, end = 0x07FF },   # this variant uses page 7
]
```

Override is **complete replacement**, not merge — explicit and
non-magical. Reloc-destination regions still auto-add even when
`memory.regions` is overridden.

## `[[versions.entry]]` — the version DAG

Each entry is a node in the version graph. Edges are declared by the
`parents` list (parent → child, older → newer). A version with no
parents is a root or an as-yet-unplaced node; both are valid.

```toml
[[versions.entry]]
id = "3.34"
# parents omitted = root, or ancestry not yet known
reloc_blocks = [
  { source = 0x9307, dest = 0x0016, length = 0x61 },
  { source = 0x934C, dest = 0x0400, length = 0x100 },
  { source = 0x944C, dest = 0x0500, length = 0x100 },
  { source = 0x954C, dest = 0x0600, length = 0x100 },
]

[[versions.entry]]
id = "3.34B"
parents = ["3.34"]
reloc_blocks = [
  { source = 0x9308, dest = 0x0016, length = 0x61 },
  { source = 0x934D, dest = 0x0400, length = 0x100 },
  { source = 0x944D, dest = 0x0500, length = 0x100 },
  { source = 0x954D, dest = 0x0600, length = 0x100 },
]

# A regional variant branching off 3.34B but not on the main line:
[[versions.entry]]
id = "3.34B-japan"
parents = ["3.34B"]
notes = "Japanese keyboard handling diverged at 3.34B"
reloc_blocks = [ ... ]

# A merged version pulling in fixes from both branches (multiple parents):
[[versions.entry]]
id = "3.40"
parents = ["3.35K", "3.34B-japan"]
reloc_blocks = [ ... ]

# A version we have ROM bytes for but haven't placed yet:
[[versions.entry]]
id = "mystery-anfs"
notes = "Found on a 5.25\" disk; ancestry TBD pending opcode analysis"
reloc_blocks = []
```

### Free-form metadata per version

Each ``[[versions.entry]]`` may carry the following fields. None of
them affect analysis — they're surfaced for tooling and
documentation:

```toml
[[versions.entry]]
id = "3.34"
description = "First public release; zero-based workspace layout"
release_date = "1984-01-15"   # ISO-8601, not parsed
source = "Acorn Cambridge archive disk #ANFS-001"
notes = "Reverse-engineered from binary; no source survives"
```

### `reloc_blocks`

Per-version list of `move()`-style relocation directives. Each block
has:

- `source` — the ROM address where the bytes live in *this* version
- `dest`   — the runtime address where they execute
- `length` — block length in bytes

Across versions, `dest` and `length` are usually stable (driven by the
project's runtime memory map); `source` shifts as code is added or
removed elsewhere in the ROM.

`reloc_blocks` may be empty or omitted for versions with no
`move()` blocks — the schema accommodates simple firmware with no
relocation as well as the NFS-style architecture.

### Path-finding

`backfill` walks the shortest path between two versions in the
undirected projection of the DAG. For each edge:

- If walked **forward** (parent → child): the per-hop confidence map
  is built directly via opcode-LCS between parent and child.
- If walked **backward** (child → parent): the same map is built and
  then inverted before composition.

Composition takes the minimum `block_length` along the path as the
composed confidence (weakest link).

If no path exists between source and target (disconnected components,
or a version that lacks parents and is not anyone's parent), `backfill`
errors with the disconnected components listed.

### What modules read what

For a given version `V`:

| Module           | Reads                                                                  |
|------------------|------------------------------------------------------------------------|
| `audit`          | `effective_regions(V)` ∪ ROM-range-of(V)                               |
| `comment_check`  | `effective_regions(V)` ∪ `effective_external_regions(V)` ∪ ROM         |
| `lint`           | same as `comment_check`                                                |
| `backfill`       | `effective_regions(V_source) ∩ effective_regions(V_target)` for identity-mapping; per-edge reloc tuples derived by matching `(dest, length)` across endpoints |
| `cfg`/`compare`/etc. | only ROM bytes (existing behaviour, no graph involvement)          |

`effective_regions(V)` = (`memory.regions` from V's override, or the
project default) ∪ {dest..dest+length-1 for each reloc in V's
`reloc_blocks`}, with overlapping ranges merged.

`effective_external_regions(V)` = the project's `memory.external_regions`
(no per-version override).

## Programmatic access

`fantasm.api.version_graph` exposes:

- `load_version_graph(project_context) -> VersionGraph`
- `VersionGraph.find_path(source_id, target_id) -> list[Edge]`
- `VersionGraph.effective_regions(version_id) -> list[Region]`
- `VersionGraph.effective_external_regions(version_id) -> list[Region]`
- `VersionGraph.get(version_id) -> Version`
- Errors: `VersionGraphError`, `VersionNotInGraphError`, `NoPathError`,
  `VersionGraphCycleError`
