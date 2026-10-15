Disassembling a disc-loaded program
===================================

fantasm grew up around sideways ROMs, but nothing in it depends on the
code being a ROM. A program loaded from disc — a DFS ``*RUN`` utility, a
game loader, a file server split across several files — is just a
binary loaded at some address. This page covers bringing one under
fantasm, including a project that already has its own layout and
shouldn't be reorganised.

Everything fantasm needs to know about a **target** (one thing being
disassembled) is:

* the binary, and the address it loads at;
* the driver script that disassembles it;
* where that driver writes the ``.asm`` and ``.json``.

Any metadata (``rom.json``-style docs lists), acornaeology website
files and documentation links are optional extras; every command runs
without them.


A single-file program in an existing project
--------------------------------------------

Suppose a project already looks like this, with a working dasmos
driver:

.. code-block:: text

   elite-loader/
     orig/ELITE          # the program, extracted from the disc image
     orig/ELITE.inf      # its .inf sidecar: $.ELITE FF1900 FF8023 ...
     tools/dis_loader.py # the driver
     build/              # where the driver writes loader.asm / .json

Adopt it as it stands:

.. code-block:: bash

   cd elite-loader
   uv run fantasm project init --name elite-loader --layout explicit \
       --target loader \
       --binary orig/ELITE \
       --driver tools/dis_loader.py \
       --asm build/loader.asm \
       --json build/loader.json

This writes ``fantasm.toml`` and touches nothing else:

.. code-block:: toml

   [project]
   name = "elite-loader"

   [binary]
   cpu = "6502"

   [[targets]]
   id = "loader"
   binary = "orig/ELITE"
   load_address = 0x1900  # from orig/ELITE.inf
   exec_address = 0x8023  # from orig/ELITE.inf
   driver = "tools/dis_loader.py"
   asm = "build/loader.asm"
   json = "build/loader.json"

The load and execution addresses came from the ``.inf`` sidecar.
fantasm reads the classic DFS form and the extended ADFS / stardot
variants (8-digit fields, access bytes and strings, ``CRC=`` and
other extras); if a sidecar can't be parsed, or there isn't one, give
the address on the command line as ``--binary orig/ELITE@1900``.

With one target, the target argument can be left out of every
command:

.. code-block:: bash

   uv run fantasm disassemble   # run the driver
   uv run fantasm verify        # reassemble and byte-compare
   uv run fantasm lint          # check the driver's annotation addresses
   uv run fantasm comments check

The driver doesn't have to change. fantasm runs it with environment
variables describing the target (``FANTASM_BINARY``,
``FANTASM_IMAGES`` with the load address, ``FANTASM_ASM``,
``FANTASM_JSON`` …; see :doc:`configuration`), but a driver that uses
its own paths keeps working, provided its outputs land where
``fantasm.toml`` says. If the driver expects to be run from its own
directory, add ``driver_cwd = "tools"`` to the target.

A driver written with fantasm in mind can take everything from the
environment:

.. code-block:: python

   import json
   import os
   from pathlib import Path

   import dasmos

   (image,) = json.loads(os.environ["FANTASM_IMAGES"])

   d = dasmos.Disassembler.create(cpu="6502")
   d.load(image["path"], image["load_addr"])
   d.program(load_addr=image["load_addr"], exec_addr=image["exec_addr"])
   d.entry(image["exec_addr"], name="start")

   # ... labels, comments, subroutines ...

   ir = d.disassemble()
   Path(os.environ["FANTASM_ASM"]).write_text(str(ir.render("beebasm")))
   Path(os.environ["FANTASM_JSON"]).write_text(str(ir.render("json")))

Verifying with another assembler
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``fantasm verify`` runs ``beebasm -i <asm> -o <tmp>`` and compares the
temporary output with the binary. If the listing names its own output
(``SAVE "ELITE", ...``), or the project uses a different assembler or
a wrapper script, say so in ``[verify]``:

.. code-block:: toml

   [verify]
   command = ["beebasm", "-i", "{asm}"]
   output  = "ELITE"     # relative to the listing's directory

See :doc:`configuration` for the tokens available.


Starting from scratch
---------------------

For a new disassembly there are two choices.

**Keep it explicit.** Put the files wherever suits you and register
the program the same way, with ``project init --layout explicit``.
fantasm will suggest ``disasm_<id>.py`` and ``output/<id>.asm`` /
``.json`` for any path you don't give.

**Use the versions/ convention**, which suits a program that exists in
several versions you want to compare and port annotations between.
Set ``[binary]`` so the per-version directory holds the binary under
its disc name:

.. code-block:: toml

   [binary]
   cpu          = "6502"
   base_address = 0x1900
   dir          = "binary"
   extension    = ""                   # KEYPAD, not KEYPAD.rom
   metadata     = "binary.json"
   filename     = "{version_id_upper}" # id "keypad" -> binary "KEYPAD"

A project that keeps several versions somewhere other than
``versions/`` can describe its layout with ``[layout]`` templates
instead (:doc:`configuration`).


A program made of several files
-------------------------------

Larger disc programs are often split across several files, each
loaded at its own address: a main body, utilities loaded on demand,
overlays that share a window of memory. Disassemble these as **one
target per file**:

.. code-block:: toml

   [project]
   name = "l3fs"
   default_target = "fs3"        # the file most commands are about

   [[targets]]
   id = "fs3"
   binary = "disc/FS3"           # load/exec from disc/FS3.inf
   driver = "disasm/fs3.py"
   asm = "out/fs3.asm"
   json = "out/fs3.json"

   [[targets]]
   id = "fs3util"
   binary = "disc/FS3UTIL"
   load_address = 0x6800
   driver = "disasm/fs3util.py"
   asm = "out/fs3util.asm"
   json = "out/fs3util.json"

   [[targets]]
   id = "ovl1"
   binary = "disc/OVL1"
   driver = "disasm/ovl1.py"
   asm = "out/ovl1.asm"
   json = "out/ovl1.json"

``fantasm project add`` appends further entries without editing the
file by hand:

.. code-block:: bash

   uv run fantasm project add ovl2 --binary disc/OVL2 \
       --driver disasm/ovl2.py --asm out/ovl2.asm --json out/ovl2.json

Each file then gets its own disassembly, round-trip and checks —
``fantasm verify --all`` verifies them all — and overlays that share
addresses are no problem, because each is disassembled on its own.

Cross-file references
~~~~~~~~~~~~~~~~~~~~~

The files call into one another, so each driver needs names for the
other files' entry points. Declare each one as a label in every driver
that refers to it. A label at an address the driver hasn't loaded
becomes an *external label*: the listing defines it as a constant, the
JSON records it under ``external_labels``, and ``fantasm lint``
accepts annotations that use it.

Keeping those shared names in one module avoids drift between the
drivers:

.. code-block:: python

   # disasm/shared_labels.py — entry points other files call
   ENTRY_POINTS = {
       0x1903: "fs3_command_dispatch",
       0x6800: "util_entry",
       0x7400: "overlay_entry",
   }

.. code-block:: python

   # in each driver, after d.load(...)
   from shared_labels import ENTRY_POINTS

   for addr, name in ENTRY_POINTS.items():
       d.label(addr, name)

In the file that *defines* an entry point the same call names the real
code there; in every other file it names the external address. Set
``driver_cwd = "disasm"`` on each target (or put ``disasm/`` on
``PYTHONPATH``) so the import resolves.

What this approach doesn't give you is a single view of the whole
program: the call graph, ``comments check`` and the other analyses
work one file at a time, and a reference into another file shows up
as an external label rather than being traced. Disassembling several
images in one target is planned for a later release.
