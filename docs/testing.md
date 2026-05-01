# Testing

Fantasm replaces an untested codebase with a tested one. The recovery
context — code being lifted out of four sibling repositories that have no
tests of their own — shapes how those tests are written.

## Why we cannot do TDD

Behaviour is defined by what the existing code currently does on real ROM
inputs. As forks are consolidated we cannot write a failing test first; we
can only pin down what the merged code should do. The aim is not to prove
the original code correct, but to make the consolidated code refactorable
without silent regressions.

## Characterisation tests

For each module brought in:

1. Identify a small representative input — a hand-crafted byte sequence,
   a tiny `.asm` snippet, or a slice of a known ROM.
2. Capture the current output and assert against it.
3. As the four forks are merged, expand the inputs to cover whatever each
   fork uniquely handled.

Goal: enough behavioural pinning to make subsequent refactors safe; not
100% line coverage.

## Round-trip with beebasm

Some recovered modules emit 6502 assembly source. To verify that the
emitted source is valid and round-trips to the same bytes, tests can
assemble the output with **beebasm** and compare against the original
input.

Use the `beebasm_filepath` fixture from `tests/conftest.py`:

```python
import subprocess


def test_round_trip(beebasm_filepath, tmp_path):
    source_filepath = tmp_path / "out.asm"
    source_filepath.write_text(emit_my_assembly(...), encoding="utf-8")
    output_filepath = tmp_path / "out.bin"
    subprocess.run(
        [str(beebasm_filepath), "-i", str(source_filepath), "-o", str(output_filepath)],
        check=True,
    )
    assert output_filepath.read_bytes() == EXPECTED_BYTES
```

The fixture skips the test when `beebasm` is not on `PATH`, so the rest of
the suite continues to run in environments where the assembler is not
installed (e.g. minimal CI containers).

## Where to put tests

- Unit tests for utility functions: `tests/test_<module>.py`.
- Characterisation tests with fixture inputs: keep small inputs inline in
  the test file; for anything bigger, place it in `tests/data/` and load
  with `pathlib.Path(__file__).parent / "data" / "..."`.
- Round-trip tests: under `tests/round_trip/` so they can be selected (or
  excluded) with `pytest tests/round_trip/` or `pytest --ignore=tests/round_trip`.
