# Migration readiness — sibling `tools/` and root scripts

Survey of the 33 Python scripts in the four sibling repositories that
weren't part of the `disasm_tools/` package consolidation, conducted
2026-05-01. Goal: determine how close fantasm is to subsuming the
sibling tooling so the four projects can drop their bundled
`disasm_tools/` and (where appropriate) their workflow scripts and
depend on fantasm.

Each script gets one of:

- **fantasm-covered** — capability is in fantasm; sibling can drop
  after migration.
- **port-to-fantasm** — generic capability worth lifting into
  `fantasm.api`; new fantasm work required.
- **cli-gap** — primitive exists in `fantasm.api` but no CLI command
  exposes the workflow these scripts encode.
- **project-specific** — stays in the sibling repo; one-off fixup,
  workflow orchestration, or domain-specific ingestion.

## Per-script verdict

### `acorn-adfs/tools/`

| Script | Lines | Purpose | Verdict |
|---|---:|---|---|
| `analyse_uncommented.py` | 80 | Cross-reference uncommented regions with named callees/callers/workspace accesses | **port-to-fantasm** |
| `basic_blocks.py` | 211 | Identify uncommented basic blocks with predecessor / successor relationships | **port-to-fantasm** |
| `extract_jgh_comments.py` | 76 | Extract block comments from J.G. Harston's ADFS 1.30 BBC BASIC source | project-specific |
| `extract_multitarget_symbols.py` | 114 | Extract symbols from ld65 debug file | project-specific |
| `find_duplicate_comments.py` | 82 | Find doubled inline comments | fantasm-covered (`comments check`) |
| `generate_labels_from_symbols.py` | 133 | Generate label() calls from ld65 debug symbols | project-specific |
| `import_hoglet_labels.py` | 90 | Import labels from Hoglet's BeebAsm disassembly | project-specific |
| `import_multitarget_labels.py` | 107 | Cross-reference multi-target labels against ADFS 1.30 ROM | project-specific |
| `label_context.py` | 57 | Extract label usage context | fantasm-covered (`cfg sub` + `labels classify`) |
| `remove_duplicate_comments.py` | 119 | Remove manual comments duplicating py8dis auto text | fantasm-covered (`comments check`) |
| `sub_context.py` | 166 | Extract subroutine calling-convention context | **port-to-fantasm** |
| `suggest_comments.py` | 146 | Pattern-based comment suggestions for uncommented instructions | **port-to-fantasm** |
| `wksp_label_context.py` | 109 | Workspace-label usage context | fantasm-covered (`cfg sub`) |

### `acorn-econet-bridge/tools/`

| Script | Lines | Purpose | Verdict |
|---|---:|---|---|
| `find_shared_with_siblings.py` | 123 | Find shared opcodes vs sibling-repo ROMs | fantasm-covered (`shared`) |
| `refresh_shared_code.py` | 271 | Scan all sibling ROMs, merge results into JSON | fantasm-covered (`shared` + project-specific orchestration) |
| `render_shared_code.py` | 189 | Render shared-code JSON as Markdown | project-specific |

### `acorn-nfs/tools/`

| Script | Lines | Purpose | Verdict |
|---|---:|---|---|
| `compare_334b_vs_334.py` | 532 | Diff annotations between two NFS versions | **cli-gap** |
| `compare_annotations.py` | 480 | Diff annotations across three NFS versions | **cli-gap** |
| `compare_label_consistency.py` | 495 | Report semantic-label inconsistencies across NFS versions | **cli-gap** |
| `find_label_addresses.py` | 143 | Map source labels to target ROM via opcode fingerprinting | **cli-gap** |
| `find_stale_comments.py` | 222 | Find comment() calls pointing to non-instruction addresses | fantasm-covered (`lint`) |
| `fix_stale_comments.py` | 669 | Resolve stale comments via opcode fingerprinting + cross-version | **cli-gap** (or close cousin of `backfill`) |

### `acorn-nfs/` (root level)

| Script | Lines | Purpose | Verdict |
|---|---:|---|---|
| `fix_335k_comments.py` | 330 | Map 3.35K addresses from earlier versions via merged JSON maps | project-specific |
| `generate_335d.py` ... `generate_421_variant_1.py` (8 scripts) | ~360–530 each | Bootstrap each version's py8dis driver from the previous version via opcode mapping | project-specific (workflow orchestration) |
| `generate_readme.py` | 96 | Render NFS README from Jinja template | project-specific |
| `investigate_360.py` | 266 | Side-by-side disassembly of UNMAPPED regions | project-specific |
| `resolve_unmapped_340.py` / `resolve_unmapped_360.py` | ~455 each | Resolve UNMAPPED annotations via interpolation + fingerprinting | project-specific |

## Capability gaps

### 1. `port-to-fantasm` — new api work (4 items)

These four scripts encode genuine generic capability that fantasm
hasn't subsumed yet. All ADFS-originated, but each is project-agnostic
in shape.

| Capability | Sibling source | Where it would land |
|---|---|---|
| Uncommented-region context analysis (callees / callers / workspace accesses around uncommented gaps) | `analyse_uncommented.py` | `fantasm.api.context.analyse_uncommented(...)` + `fantasm context uncommented` CLI |
| Basic-block identification with annotation-coverage stats | `basic_blocks.py` | `fantasm.api.cfg.basic_blocks(...)` + `fantasm cfg blocks` CLI |
| Subroutine calling-convention extraction (entry, callers, exits, post-call sites) | `sub_context.py` | Extension to existing `fantasm.api.context` + `fantasm cfg sub-context` CLI (or fold into existing `cfg sub`) |
| Pattern-based comment suggestion for uncommented instructions | `suggest_comments.py` | `fantasm.api.suggest` (new module) + `fantasm comments suggest` CLI |

Estimate: ~600 LOC of api code + ~150 LOC of CLI integration + tests.

### 2. `cli-gap` — exposing existing primitives (5 items)

These scripts encode workflows whose underlying primitives are already
in `fantasm.api`. They need CLI commands, not new api work.

| Workflow | Sibling source | Sketch |
|---|---|---|
| Cross-version annotation diff / inconsistency report | `compare_334b_vs_334.py`, `compare_annotations.py` | `fantasm annotations diff V1 V2 [V3...]` — uses `parse_annotations` + `compose_chained_map` + report inconsistencies |
| Cross-version semantic-label consistency | `compare_label_consistency.py` | Subset of the above, filtering auto-generated labels via `fantasm.api.labels.AUTO_LABEL_RE` |
| Pairwise address mapping export | `find_label_addresses.py` | `fantasm addresses map SOURCE TARGET [--addrs ...]` — wraps `blockmatch.build_full_address_map` |
| Comment-address rewriting via fingerprinting | `fix_stale_comments.py` | A `fantasm backfill --apply` mode or sister command that rewrites the target driver in place |

Estimate: ~250 LOC of CLI + tests; no api changes needed.

### 3. `fantasm-covered` (drop after migration, ~5 items)

`find_duplicate_comments.py`, `remove_duplicate_comments.py`,
`label_context.py`, `wksp_label_context.py`, `find_stale_comments.py`,
`find_shared_with_siblings.py`, `refresh_shared_code.py` (the
shared-finding part). The siblings can delete these once they switch
to fantasm.

### 4. `project-specific` (~17 items)

The eleven `generate_*.py` driver-translation scripts, the four ADFS
multi-target / Hoglet / JGH ingestion scripts, the two
`resolve_unmapped_*.py` investigation tools, `investigate_360.py`,
`fix_335k_comments.py`, `render_shared_code.py`, and each project's
own README generator. These stay where they are. Several of them
*could* eventually move to fantasm with enough generalisation, but
that's a generalisation task per script, not a migration blocker.

## Migration readiness verdict

**Status: blocked by 4 ports + 5 CLI commands** (≈ 850 LOC, plus
tests and docs).

What "blocked" means in practice: the siblings *could* migrate today
and drop their `disasm_tools/`, but ADFS specifically loses four
useful tools (`analyse_uncommented`, `basic_blocks`, `sub_context`,
`suggest_comments`) until the ports land, and NFS loses its
cross-version annotation review workflow until the CLI commands
land. Migration is technically possible but with regression in
day-to-day capability.

The blocking items split cleanly:

- **(a) New API capabilities**: 4 ports (~600 LOC). Mostly
  project-agnostic logic that combines existing fantasm primitives in
  new ways.
- **(b) CLI integration over existing primitives**: 5 commands
  (~250 LOC). No new api needed; just new entry points.

(b) is half a session of work. (a) is a session or two. Neither is
deep — the patterns are the same as what's already landed.

Once those land, **all four siblings are migration-ready**: each can
delete its `src/disasm_tools/` package, declare a `fantasm`
dependency, run `fantasm project init` at the repo root, and migrate
its `acorn-{x}-disasm-tool` console-script entry to the unified
`fantasm` command (or a thin shim if muscle memory matters).

The eleven `generate_*.py` driver-translation scripts in NFS and the
ADFS ld65/Hoglet/JGH ingestion scripts stay in their repos
indefinitely — they're version-specific orchestration that doesn't
generalise.
