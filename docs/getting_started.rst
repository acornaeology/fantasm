Getting started
===============

This page walks through bringing a brand-new project under fantasm.
By the end you will have a working ``fantasm.toml``, a single ROM
version registered, a py8dis driver that produces ``.asm`` and
``.json`` artefacts, and a CI-ready ``disassemble → lint → verify``
pipeline.

What fantasm does — and doesn't
-------------------------------

``fantasm`` operates on the **output** of `py8dis`_ — a programmable
6502 disassembler that turns ROM bytes plus an annotation script into
a ``.asm`` listing and a ``.json`` index. fantasm does not perform
the disassembly itself; instead it provides:

* a CLI for orchestrating per-version py8dis runs
  (``fantasm disassemble VID``);
* round-trip verification against `beebasm`_
  (``fantasm verify VID``);
* annotation lint, basic-block / call-graph analysis, address mapping
  across versions, and annotation propagation along a multi-version
  DAG.

py8dis (the disassembler) and beebasm (the cross-assembler) are
**workflow prerequisites**: they need to be available in your
environment but fantasm doesn't ship them. Both are documented under
:doc:`installation prerequisites <configuration>` below.

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
       "py8dis @ git+https://github.com/acornaeology/py8dis.git",
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
     disassemble/  # the py8dis driver script will live here
     output/     # generated .asm and .json land here

Drop the ROM file into ``rom/`` (the filename must match
``{prefix}-{version_id}.rom``).


Writing a py8dis driver
-----------------------

The driver is a Python script that calls into py8dis to declare the
ROM's load address, entry points, labels, comments, subroutine
boundaries, and any relocated code blocks. The conventional path is
``versions/{prefix}-{version_id}/disassemble/disasm_{prefix}_{version_id_no_dots}.py``;
fantasm 0.4.0 looks here automatically.

A minimal driver:

.. code-block:: python

   """py8dis driver for myrom 1.0."""

   import json
   import os
   import sys
   from pathlib import Path

   from py8dis.commands import *

   init(assembler_name="beebasm", lower_case=True)

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

   load(0x8000, _rom_filepath, "6502")

   # ... declare entry points, labels, comments, subroutine() calls ...

   output = go(print_output=False)
   _output_dirpath.mkdir(parents=True, exist_ok=True)
   (_output_dirpath / "myrom-1.0.asm").write_text(output)

   structured = get_structured()
   (_output_dirpath / "myrom-1.0.json").write_text(json.dumps(structured))

The exact py8dis DSL is beyond the scope of fantasm's docs (see the
`py8dis project <https://github.com/acornaeology/py8dis>`_ for that),
but the sibling repos linked from the front page have working
drivers you can copy.


Running the pipeline
--------------------

With the driver in place:

.. code-block:: bash

   # 1. Run the py8dis driver to generate .asm and .json.
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
