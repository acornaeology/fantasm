Testing strategy
================

fantasm replaces an untested codebase with a tested one. The recovery
context — code being lifted out of four sibling repositories that
have no tests of their own — shapes how those tests are written.

This page is for contributors and AI agents working **inside the
fantasm repository**. Users of fantasm don't need to read it.


Why TDD doesn't apply
---------------------

Behaviour is defined by what the existing code currently does on
real ROM inputs. As the four forks were consolidated we couldn't
write a failing test first; we could only pin down what the merged
code should do. The aim is not to prove the original code correct,
but to make the consolidated code refactorable without silent
regressions.


Characterisation tests
----------------------

For each module brought in:

1. Identify a small representative input — a hand-crafted byte
   sequence, a tiny ``.asm`` snippet, or a slice of a known ROM.
2. Capture the current output and assert against it.
3. As the forks were merged, expand the inputs to cover whatever
   each fork uniquely handled.

Goal: enough behavioural pinning to make subsequent refactors safe;
not 100% line coverage.


Round-trip with beebasm
-----------------------

Some modules emit 6502 assembly source. To verify that the emitted
source is valid and round-trips to the same bytes, tests can
assemble the output with **beebasm** and compare against the
original input.

Use the ``beebasm_filepath`` fixture from ``tests/conftest.py``:

.. code-block:: python

   import subprocess


   def test_round_trip(beebasm_filepath, tmp_path):
       source_filepath = tmp_path / "out.asm"
       source_filepath.write_text(emit_my_assembly(...), encoding="utf-8")
       output_filepath = tmp_path / "out.bin"
       subprocess.run(
           [str(beebasm_filepath), "-i", str(source_filepath),
            "-o", str(output_filepath)],
           check=True,
       )
       assert output_filepath.read_bytes() == EXPECTED_BYTES

The fixture skips the test when ``beebasm`` is not on ``PATH``, so
the rest of the suite continues to run in environments where the
assembler is not installed (e.g. minimal CI containers).


Where to put tests
------------------

* Unit tests for utility functions: ``tests/api/test_<module>.py``.
* CLI tests: ``tests/cli/test_<command>.py``, mirroring the
  ``cli/`` package layout. Shared CLI test helpers live in
  ``tests/cli/_helpers.py``.
* Characterisation tests with fixture inputs: keep small inputs
  inline in the test file; for anything bigger, place it in
  ``tests/data/`` and load with
  ``pathlib.Path(__file__).parent / "data" / "..."``.
* Round-trip tests: alongside whatever module produces the source,
  using the ``beebasm_filepath`` fixture so they skip cleanly when
  beebasm is unavailable.


Running the suite
-----------------

.. code-block:: bash

   uv run pytest -q              # full suite (~550 tests, ~0.5 s)
   uv run pytest tests/api -q    # API-side only
   uv run pytest tests/cli -q    # CLI-side only

Each commit on master is expected to keep the suite green. The
``test.yml`` workflow runs the same suite across the supported
Python / OS matrix on every push and PR.
