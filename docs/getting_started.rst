Getting started
===============

This page walks through bringing a brand-new project under fantasm.
By the end you will have a working ``fantasm.toml``, a single ROM
version registered, a disassembly driver script that produces
``.asm`` and ``.json`` artefacts, and a CI-ready
``disassemble → lint → verify`` pipeline.

What fantasm does — and doesn't
-------------------------------

``fantasm`` operates on the **output** of a per-version
disassembly driver — a Python script that turns ROM bytes plus an
annotation script into a ``.asm`` listing and a ``.json`` index.
The driver typically uses one of:

* `dasmos`_ — the current recommendation. A pluggable tracing
  disassembler with a stable 1.0 API, byte-faithful round-trip
  guarantees, and bundled BBC-Micro / 6502 environments.
* `py8dis`_ — the predecessor library. Existing py8dis drivers
  continue to work end-to-end with fantasm; new projects should
  reach for dasmos.

fantasm itself is disassembler-agnostic — it runs the driver as a
subprocess and reads the artefacts. The same fantasm install
handles dasmos and py8dis projects side by side, and a project can
migrate from one to the other without touching its fantasm
configuration.

fantasm does not perform the disassembly itself; instead it
provides:

* a CLI for orchestrating per-version disassembly runs
  (``fantasm disassemble VID``);
* round-trip verification against `beebasm`_
  (``fantasm verify VID``);
* annotation lint, basic-block / call-graph analysis, address mapping
  across versions, and annotation propagation along a multi-version
  DAG.

Both the chosen disassembler library and beebasm (the
cross-assembler) are **workflow prerequisites**: they need to be
available in your environment but fantasm doesn't ship them. Both
are documented under :doc:`installation prerequisites
<configuration>` below.

.. _dasmos: https://github.com/acornaeology/dasmos
.. _py8dis: https://github.com/acornaeology/py8dis
.. _beebasm: https://github.com/stardot/beebasm


Installing fantasm
------------------

fantasm is on PyPI and intended to be added as a normal dependency to
your project's ``pyproject.toml``:

.. code-block:: toml

   # in your project's pyproject.toml
   [project]
   dependencies = [
       "fantasm>=0.4.0",
       # Pick whichever disassembler your driver uses. dasmos is the
       # current recommendation; py8dis still works for projects that
       # haven't migrated yet.
       "dasmos>=2.0",
       # ...or, for a py8dis-based driver:
       # "py8dis @ git+https://github.com/acornaeology/py8dis.git",
   ]

After ``uv sync`` the ``fantasm`` console script is on ``PATH`` and
runs as ``uv run fantasm <command>``. Standalone installs work too:

.. code-block:: bash

   pip install fantasm
   fantasm --help

You also need ``beebasm`` on ``PATH``. Build it from `the upstream
sources <https://github.com/stardot/beebasm>`_, or install via your
distribution if available.


Initialising a project
----------------------

In a new repo, run:

.. code-block:: bash

   uv run fantasm project init --name acorn-myrom --prefix myrom

This writes a minimal ``fantasm.toml`` at the project root and
ensures a ``versions/`` directory exists. The ``--prefix`` option
declares the leading component of each version directory's name —
e.g. ``versions/myrom-1.0/``. Multi-prefix projects (NFS uses two:
``anfs`` and ``nfs``) repeat the option:

.. code-block:: bash

   uv run fantasm project init --name acorn-nfs --prefix anfs --prefix nfs

The generated ``fantasm.toml`` covers the bare minimum. Edit it to
add ``[rom] base_address``, ``[memory]`` regions, and per-version
``[[versions.entry]]`` entries — see :doc:`configuration`.


Adding the first version
------------------------

Each ROM image lives in its own directory under ``versions/``:

.. code-block:: bash

   uv run fantasm project add 1.0

That creates ``versions/myrom-1.0/`` with three subdirectories:

.. code-block:: text

   versions/myrom-1.0/
     rom/        # drop the original ROM bytes here as myrom-1.0.rom
     disassemble/  # the disassembly driver script will live here
     output/     # generated .asm and .json land here

Drop the ROM file into ``rom/`` (the filename must match
``{prefix}-{version_id}.rom``).


Writing a disassembly driver
----------------------------

The driver is a Python script that calls into the disassembler
library of your choice to declare the ROM's load address, entry
points, labels, comments, subroutine boundaries, and any relocated
code blocks. The conventional path is
``versions/{prefix}-{version_id}/disassemble/disasm_{prefix}_{version_id_no_dots}.py``;
fantasm looks there automatically.

A minimal dasmos driver (the current recommendation):

.. code-block:: python

   """Disassembly driver for myrom 1.0."""

   import os
   from pathlib import Path

   import dasmos

   # `fantasm disassemble VID` sets these env vars; direct python
   # invocations fall back to the conventional layout.
   _script_dirpath = Path(__file__).resolve().parent
   _version_dirpath = _script_dirpath.parent
   _rom_filepath = os.environ.get(
       "FANTASM_ROM",
       str(_version_dirpath / "rom" / "myrom-1.0.rom"),
   )
   _output_dirpath = Path(os.environ.get(
       "FANTASM_OUTPUT_DIR",
       str(_version_dirpath / "output"),
   ))

   d = dasmos.Disassembler.create(cpu="6502")
   d.load(_rom_filepath, 0x8000)
   d.entry(0x8000, name="reset")

   # ... declare entry points, labels, comments, subroutine() calls ...

   ir = d.disassemble()
   _output_dirpath.mkdir(parents=True, exist_ok=True)
   (_output_dirpath / "myrom-1.0.asm").write_text(
       str(ir.render("beebasm")), encoding="utf-8",
   )
   (_output_dirpath / "myrom-1.0.json").write_text(
       str(ir.render("json")), encoding="utf-8",
   )

The exact dasmos DSL is beyond the scope of fantasm's docs (see the
`dasmos project <https://github.com/acornaeology/dasmos>`_ for the
full driver-API reference), but the sibling repos linked from the
front page have working drivers you can copy.

py8dis drivers also work — fantasm runs whichever driver script
the version directory contains. The
`py8dis project <https://github.com/acornaeology/py8dis>`_ has
its own DSL reference; py8dis's ``scripts/py8dis2dasmos.py``
porter (shipped with dasmos) translates a py8dis driver to the
dasmos shape automatically when you're ready to migrate.


Running the pipeline
--------------------

With the driver in place:

.. code-block:: bash

   # 1. Run the disassembly driver to generate .asm and .json.
   uv run fantasm disassemble 1.0

   # 2. Validate every comment / label / subroutine address in the
   #    driver matches an address fantasm knows about. Zero output
   #    means every annotation lined up.
   uv run fantasm lint 1.0 versions/myrom-1.0/disassemble/disasm_myrom_10.py

   # 3. Reassemble the .asm with beebasm and byte-compare to the
   #    original ROM. The single load-bearing correctness check.
   uv run fantasm verify 1.0

That's the loop. ``fantasm verify`` failing means the disassembly is
not faithful — usually because a label, an instruction, or a data
declaration in the driver doesn't match what's actually in the ROM
bytes. Iterate on the driver until verify passes; then start
annotating.

Once you have a project running, see :doc:`workflows` for the next
layer of analysis commands (``audit``, ``cfg``, ``comments``,
``backfill``, ``addresses``, …) and :doc:`configuration` for the
``fantasm.toml`` knobs that govern them.


CI integration
--------------

The four sibling repos all use a tiny GitHub Actions workflow built
around the three commands above. The shape:

.. code-block:: yaml

   - name: Disassemble
     run: uv run fantasm disassemble ${{ matrix.version }}

   - name: Lint
     run: |
       uv run fantasm lint ${{ matrix.version }} \
         versions/myrom-${{ matrix.version }}/disassemble/disasm_myrom_${{ matrix.version }}.py

   - name: Verify
     run: uv run fantasm verify ${{ matrix.version }}

Each step exits non-zero on failure, so the workflow halts and
surfaces the diagnostic. The ``matrix.version`` indirection lets one
workflow cover every registered version.
