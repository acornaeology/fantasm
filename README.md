<p align="center">
  <img src="https://raw.githubusercontent.com/acornaeology/fantasm/master/docs/_static/fantasm-hero.png"
       alt="fantasm" width="533">
</p>

# Fantasm

The Fantastic (dis-/re-)Assembly tools for 6502 code, version `0.16.0`.

<p align="center">
  <a href="https://pypi.org/project/fantasm/"><img src="https://img.shields.io/pypi/v/fantasm.svg" alt="PyPI"></a>
  <a href="https://github.com/acornaeology/fantasm/actions/workflows/release.yml"><img src="https://img.shields.io/github/actions/workflow/status/acornaeology/fantasm/release.yml?label=release" alt="Release"></a>
  <a href="https://github.com/acornaeology/fantasm/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/acornaeology/fantasm/ci.yml?branch=master&label=CI" alt="CI"></a>
  <a href="https://pypi.org/project/fantasm/"><img src="https://img.shields.io/pypi/pyversions/fantasm.svg" alt="Python versions"></a>
</p>

<p align="center">
  <strong>Full user guide and CLI / API reference: <a href="https://acornaeology.github.io/fantasm/">acornaeology.github.io/fantasm</a></strong>
</p>

Fantasm is a consolidated suite of tools for working on annotated
disassemblies of 6502-based ROMs (originally those from the Acorn / BBC
Microcomputer family). It brings together capabilities that previously
lived in per-project forks under the `acornaeology` umbrella, behind a
single `fantasm` command and a programmatic `fantasm.api` package.

This README covers the absolute basics; for everything else (the
`fantasm.toml` schema, the version graph, command-by-command
workflows, the importable `fantasm.api`) follow [the docs][docs].

[docs]: https://acornaeology.github.io/fantasm/

## Install

`fantasm` is on PyPI. Add it to your project as a regular
dependency:

```toml
[project]
dependencies = [
    "fantasm>=0.16.0",
]
```

Or for a one-off install:

```sh
pip install fantasm
```

The disassembly itself is performed by a per-version Python driver
script — typically built on
[dasmos](https://github.com/acornaeology/dasmos) or
[py8dis](https://github.com/acornaeology/py8dis), but fantasm only
sees the artefacts those scripts emit (`.asm`, `.json`) and stays
disassembler-agnostic. Round-trip verification needs
[beebasm](https://github.com/stardot/beebasm) on `PATH`.

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
  addresses    Address translation across ROM versions.
  annotations  Cross-version annotation diff and management.
  asm          Assembly-source extraction and inspection.
  audit        Subroutine annotation audit.
  backfill     Propose annotation propagations from SOURCE_VERSION to...
  bytes        Byte-signature search across ROM images.
  cfg          Inter-procedural call-graph queries.
  comments     Comment / annotation consistency checks.
  compare      Compare two ROM versions at byte / opcode / full-instruction...
  context      Code context queries (depth, sub-context, uncommented gaps).
  coverage     Report the disassembly's inline-comment coverage as a single...
  data         Data-declaration review (runs, heuristic reclassification).
  disassemble  Run the version's disassembly driver script to (re-)generate...
  driver       Driver-script housekeeping (sorting, formatting).
  fingerprint  Fingerprint each block of a ROM version's bytes and report...
  hooks        hook_subroutine() discovery and review.
  info         Show the resolved project context.
  labels       Auto-generated label classification and renaming.
  lint         Validate that a driver script's annotation addresses...
  project      Initialise and manage fantasm projects.
  promote      Score labelled code items as candidates for promotion to...
  shared       Find shared 6502 code fragments between a primary ROM and...
  sub          Subroutine workflow helpers.
  verify       Verify a disassembly round-trips: assemble its .asm with...
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

fantasm pins down observable behaviour with **characterisation
tests** against hand-crafted JSON / ROM fixtures — the original
codebase fantasm consolidates had no tests of its own. Modules that
emit 6502 assembly source are exercised with **round-trip tests**
that re-assemble the output with `beebasm` and compare bytes; the
`beebasm_filepath` pytest fixture skips such tests when the
assembler is not on `PATH`. See [docs/testing.rst](docs/testing.rst)
for the patterns and `CLAUDE.md` for the project-level guidance.

## Layout

```
src/fantasm/             the package
src/fantasm/cli/         Click entrypoint, one module per command group
src/fantasm/api/         programmatic API (re-exports the public surface)
src/fantasm/cli_helpers.py  shared CLI helpers (AnalysisContext, …)
src/fantasm/config.py    project-root resolution + fantasm.toml loading
tests/api/               api-side pytest suite
tests/cli/               cli-side pytest suite
docs/                    Sphinx site (published to GitHub Pages)
scripts/                 README generator + Jinja2 template
```

## Related projects

- [dasmos](https://github.com/acornaeology/dasmos) — the tracing
  disassembler fantasm now builds on top of (a Python rewrite of
  py8dis with a stable API and stricter classification semantics).
- [py8dis (fork)](https://github.com/acornaeology/py8dis) — the
  predecessor disassembler; driver scripts written against py8dis
  still work end-to-end with fantasm, since fantasm runs them as a
  subprocess and only consumes the JSON / asm output.
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
