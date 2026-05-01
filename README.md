# Fantasm

The Fantastic (dis-/re-)Assembly tools for 6502 code, version `0.1.0`.

Fantasm is a consolidated suite of tools for working on annotated
disassemblies of 6502-based ROMs (originally those from the Acorn / BBC
Microcomputer family). It brings together capabilities that previously
lived in per-project forks under the `acornaeology` umbrella, behind a
single `fantasm` command and a programmatic `fantasm.api` package.

## Status

Early scaffolding. The CLI shell is in place; the consolidation of
per-project tools into `fantasm` is in progress.

## Install (development)

```sh
uv sync
```

## CLI

```console
$ fantasm --help
Usage: fantasm [OPTIONS] COMMAND [ARGS]...

  Fantasm — the Fantastic (dis-/re-)Assembly tools for 6502 code.

Options:
  --version                 Show the version and exit.
  --project-root DIRECTORY  Project root directory. Overrides
                            FANTASM_PROJECT_ROOT. If neither is given, fantasm
                            searches upwards from the current directory for a
                            fantasm.toml.
  -h, --help                Show this message and exit.

Commands:
  asm       Assembly-source extraction and inspection.
  audit     Subroutine annotation audit.
  cfg       Inter-procedural call-graph queries.
  comments  Comment / annotation consistency checks.
  compare   Compare two ROM versions at byte / opcode / full-instruction...
  info      Show the resolved project context.
  project   Initialise and manage fantasm projects.
  shared    Find shared 6502 code fragments between a primary ROM and one...
  verify    Verify a disassembly round-trips: assemble its .asm with...
```

The top-level `fantasm` command accepts a `--project-root` option and
also reads `FANTASM_PROJECT_ROOT` from the environment. When neither is
given, fantasm walks upwards from the current working directory looking
for a `fantasm.toml` to identify the project root.

### `fantasm info`

The `info` sub-command shows the resolved project context for the
current invocation. Like every fantasm command that produces structured
output, it inherits a uniform `--as display | tsv | json` story (and
friends) from
[asyoulikeit](https://github.com/sixty-north/asyoulikeit):

```console
$ fantasm info --help
Usage: fantasm info [OPTIONS]

  Show the resolved project context.

Options:
  Report Output Options: 
    --no-reports              Suppress all report output. The handler still runs
                              (useful for action commands whose reports are
                              incidental); only rendering is skipped. Mutually
                              exclusive with --report and --all-reports.
    --all-reports             Render every report the handler returns,
                              regardless of the command's default_reports.
                              Useful for commands whose default is a subset (or
                              silent) but where you want the full picture this
                              time. Mutually exclusive with --report and --no-
                              reports.
    --report [project]        Report name(s) to display (can be specified
                              multiple times). Shows all if omitted. Valid
                              values: project.
    --header / --no-header    Include column headers in output. Overrides each
                              report's default. Format-specific: TSV prefixes
                              first cell with '#', display omits
                              headers/title/caption, JSON ignores this flag.
    --detailed / --essential  Include detailed columns or only essential
                              columns. Auto-detects based on output format if
                              not specified.
    --as [display|json|tsv]   Output format for tabular data. Defaults to
                              'display' for terminals, 'tsv' for pipes.
  -h, --help                  Show this message and exit.
```

Sample output (an explicit project root that does not contain a
`fantasm.toml`):

```console
$ fantasm --project-root /path/to/your/project info
              Fantasm project              
┏━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Key             ┃ Value                 ┃
┡━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━┩
│ project_root    │ /path/to/your/project │
│ config_filepath │ (none)                │
│ config_keys     │ (empty)               │
└─────────────────┴───────────────────────┘
 Resolved project context for the current  
                invocation.
```

The same invocation through a pipe (or with `--as tsv`) emits
tab-separated output suitable for downstream tooling:

```console
$ fantasm --project-root /path/to/your/project info --as tsv
# Key	Value
project_root	/path/to/your/project
config_filepath	(none)
config_keys	(empty)
```

## Programmatic API

```python
from fantasm.api import ...  # surface filled in as modules are ported
```

## Testing

The codebase fantasm consolidates is untested. As modules are ported in,
fantasm adds **characterisation tests** that pin down observable
behaviour on representative inputs — these are the safety net for
merging the four upstream forks. Modules that emit 6502 assembly source
are exercised with **round-trip tests** that re-assemble the output with
`beebasm` and compare bytes; the `beebasm_filepath` pytest fixture skips
such tests when the assembler is not on `PATH`. See `docs/testing.md`
for the patterns and `CLAUDE.md` for the project-level guidance.

## Layout

```
src/fantasm/             the package
src/fantasm/cli.py       Click entrypoint
src/fantasm/api/         programmatic API (re-exports the public surface)
src/fantasm/config.py    project-root resolution + fantasm.toml loading
tests/                   pytest suite (with shared fixtures in conftest.py)
docs/                    user and developer documentation
scripts/                 README generator + Jinja2 template
```

## Related projects

- [py8dis (fork)](https://github.com/acornaeology/py8dis) — the tracing
  disassembler fantasm builds on top of (will eventually become
  `msabeeb`).
- The four sibling repositories under `acornaeology` from which fantasm
  draws its initial tooling: `acorn-6502-tube-client`, `acorn-adfs`,
  `acorn-econet-bridge`, `acorn-nfs`.

---

This README is generated from `scripts/readme_template.md.j2` by
`scripts/generate_readme.py`. **Do not edit it directly** — edit the
template (or the generator, or the source files whose output it
captures) and re-run `uv run python scripts/generate_readme.py`. The
pre-commit hook and the `readme-check` CI job both run the
generator's `--check` mode and will refuse stale READMEs.
