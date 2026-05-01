# Fantasm

The Fantastic (dis-/re-)Assembly tools for 6502 code.

Fantasm is a consolidated suite of tools for working on annotated disassemblies of
6502-based ROMs (originally those from the Acorn / BBC Microcomputer family). It
brings together capabilities that previously lived in per-project forks under the
`acornaeology` umbrella, behind a single `fantasm` command and a programmatic
`fantasm.api` package.

## Status

Early scaffolding. The CLI shell is in place; the consolidation of per-project
tools into `fantasm` is in progress.

## Install (development)

```sh
uv sync
```

## CLI

```sh
fantasm --help
fantasm info
```

The top-level `fantasm` command accepts a `--project-root` option and also reads
`FANTASM_PROJECT_ROOT` from the environment. When neither is given, fantasm walks
upwards from the current working directory looking for a `fantasm.toml` to
identify the project root.

## Testing

The codebase fantasm consolidates is untested. As modules are ported in,
fantasm adds **characterisation tests** that pin down observable behaviour
on representative inputs — these are the safety net for merging the four
upstream forks. Modules that emit 6502 assembly source are exercised with
**round-trip tests** that re-assemble the output with `beebasm` and
compare bytes; the `beebasm_filepath` pytest fixture skips such tests when
the assembler is not on `PATH`. See `docs/testing.md` for the patterns and
`CLAUDE.md` for the project-level guidance.

## Programmatic API

```python
from fantasm.api import ...  # surface filled in as modules are ported
```

## Layout

```
src/fantasm/         the package
src/fantasm/cli.py   Click entrypoint
src/fantasm/api/     programmatic API (re-exports the public surface)
src/fantasm/config.py project-root resolution + fantasm.toml loading
tests/               pytest suite
docs/                user and developer documentation
```

## Related projects

- [py8dis (fork)](https://github.com/acornaeology/py8dis) — the tracing
  disassembler fantasm builds on top of (will eventually become `msabeeb`).
- The four sibling repositories under `acornaeology` from which fantasm draws its
  initial tooling: `acorn-6502-tube-client`, `acorn-adfs`,
  `acorn-econet-bridge`, `acorn-nfs`.
