# Fantasm — guidance for AI assistants

Project goal: consolidate 6502 disassembly tooling from four sibling
acornaeology repositories (`acorn-6502-tube-client`, `acorn-adfs`,
`acorn-econet-bridge`, `acorn-nfs`) into a single `fantasm` package with a
Click CLI and a programmatic `fantasm.api` package.

## Layout

- `src/fantasm/` — package
- `src/fantasm/cli.py` — Click entrypoint, hierarchical sub-command groups
- `src/fantasm/api/` — programmatic API; flat re-exports from `__init__.py`
- `src/fantasm/config.py` — project-root resolution and `fantasm.toml` loading
- `tests/` — pytest suite with shared fixtures in `conftest.py`
- `docs/` — user/developer docs

## Testing strategy

The original code being consolidated has **no tests**. As code is ported in
we add tests, but the approach is constrained by the recovery context:

- We cannot TDD pre-existing behaviour. Instead, write **characterisation
  tests** that pin down current observable behaviour on representative
  inputs. These are the safety net that lets us merge the four divergent
  forks and refactor afterwards.
- Prefer small hand-crafted fixtures (a few bytes, a tiny `.asm` file) over
  full ROM dumps — fast, reviewable, and easy to reason about.
- For modules that emit assembly source, write **round-trip tests** that
  assemble the output with `beebasm` and compare the resulting bytes to the
  original input.

See `docs/testing.md` for a fuller treatment.

## README is generated, not hand-written

`README.md` is produced by `scripts/generate_readme.py` from a Jinja2
template at `scripts/readme_template.md.j2`. The generator imports
`fantasm.cli.main` and runs it via `click.testing.CliRunner` (inside
`isolated_filesystem`, with `COLUMNS=80` / `NO_COLOR=1` and
`FANTASM_PROJECT_ROOT` cleared) to capture deterministic `--help` text
and a sample `info` table.

```bash
uv run python scripts/generate_readme.py           # regenerate README.md
uv run python scripts/generate_readme.py --check   # verify; prints diff + exits 1 on drift
```

A pre-commit hook (`.pre-commit-config.yaml`) runs the `--check`
variant whenever `README.md`, the generator, the template, or any
`src/fantasm/*.py` changes — so editing the public CLI surface forces
a README regeneration before the commit lands. First-time setup in a
fresh clone:

```bash
uv run pre-commit install
```

A `readme-check` job in `.github/workflows/ci.yml` runs the same
`--check` on every push and PR as a safety net for contributors who
bypass the local hook. **Never hand-edit `README.md`** — edit the
template (or the generator, or the CLI source) and re-run the
generator.

## External tooling assumed available

- **beebasm** (the BBC Micro 6502 cross-assembler) — assumed on `PATH`.
  Tests obtain its location via the `beebasm_filepath` fixture in
  `tests/conftest.py` and skip cleanly when it is absent.
- **uv** for dependency management. Use `uv sync` and `uv run`.

## Project-root resolution

Three-step lookup, highest priority first:

1. `--project-root` on the top-level `fantasm` group
2. `FANTASM_PROJECT_ROOT` environment variable
3. Walk upwards from cwd looking for `fantasm.toml`

Commands that need a project root should check `ctx.obj["project"].has_root`
and fail with a clear message if unresolved.

## Output formatting

Commands that produce structured results use `asyoulikeit.report_output`,
which gives them a uniform `--as display|tsv|json` story. See
`src/fantasm/cli.py::info` for the canonical pattern. When a command needs
the Click context, use `click.get_current_context()` inside the body
rather than mixing `@click.pass_context` with `@report_output`.

## Versioning and releases

Version is managed via `bump-my-version` (configured in `pyproject.toml`
under `[tool.bumpversion]`). The single source of truth is `__version__`
in `src/fantasm/__init__.py`; hatchling reads it dynamically via
`[tool.hatch.version]` and exposes it as the wheel's installed version.
Do not edit the version by hand in more than one place — let
`bump-my-version` update both the module and the
`[tool.bumpversion] current_version` copy in lock-step.

Release flow (on a clean working tree, from `master`):

```bash
uv run bump-my-version bump --dry-run --verbose patch   # preview
uv run bump-my-version bump patch                       # or `minor` / `major`
git push --follow-tags                                  # publish commit + v<X.Y.Z> tag
```

Each real bump produces one commit (`Bump version: X.Y.Z → X.Y.Z+1`) and
one annotated tag (`vX.Y.Z+1`). bump-my-version refuses to run with a
dirty tree — that is the intended safety net.

A `release.yml` workflow triggers on `v*` tags (the ones
`bump-my-version` produces) plus manual `workflow_dispatch`. Two
parallel gates — the full test matrix from `test.yml` and the
README-sync check from `readme-check.yml` — feed a single
`publish-pypi` job. Nothing is published unless **both** gates are
green. PyPI publication uses `uv publish` with `UV_PUBLISH_TOKEN`
from the `PYPI_TOKEN` repo secret, scoped to the `pypi` GitHub
deployment environment. To release: bump the version, push the
`v<X.Y.Z>` tag, watch the Actions UI. A failed publish can be
re-attempted via the **Run workflow** button.

## Naming conventions

- Use `_filename`, `_filepath`, `_dirpath`, `_dirname` suffixes; avoid the
  ambiguous `_dir` / `_file` suffixes.
- Keep code comments and commit messages free of references to specific AI
  tools or model providers.
