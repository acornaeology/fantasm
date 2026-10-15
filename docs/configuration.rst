``fantasm.toml`` reference
==========================

Per-project configuration for fantasm. ``fantasm.toml`` sits at the
project root. fantasm discovers it by walking upwards from the
current working directory; the top-level ``--project-root`` option
and the ``FANTASM_PROJECT_ROOT`` environment variable both override
discovery.


Discovery and project context
-----------------------------

Three lookup steps, highest priority first:

1. ``--project-root <DIR>`` on the top-level ``fantasm`` group;
2. The ``FANTASM_PROJECT_ROOT`` environment variable;
3. Walk upwards from the current working directory looking for a
   ``fantasm.toml``.

``fantasm info`` shows what got resolved.

Commands that need a project root fail with ``no project root
resolved`` if all three lookups miss; pass ``--project-root``
explicitly or run from inside the project tree to fix that.


Top-level structure
-------------------

The config is plain TOML. Only sections fantasm understands are
listed below; unknown keys are ignored, so your editor or other
tooling can scribble its own metadata under any prefix it likes
without confusing fantasm.

.. code-block:: toml

   [project]            # name, used in messages and as a fallback
   [binary]             # CPU, base address, and per-version binary layout
   [versions]           # directory layout + version-name prefixes
   [layout]             # path templates for projects outside versions/
   [[targets]]          # explicit per-target paths for any existing layout
   [verify]             # the assembler used by ``fantasm verify``
   [memory]             # workspace + hardware regions used by every version
   [[versions.entry]]   # one block per version, with the version graph

(``[rom]`` is accepted as a back-compatible alias for ``[binary]`` —
see below.)


``[project]``
~~~~~~~~~~~~~

.. code-block:: toml

   [project]
   name = "acorn-myrom"
   default_target = "1.0"    # optional

* ``name`` *(required)* — used as a fallback for ``[versions]
  prefixes`` when that option is omitted, and for the project-specific
  strings the CLI emits in error and help messages.
* ``default_target`` — the target per-target commands use when the
  ``TARGET`` argument is left out. Optional: a project with exactly one
  target uses that one without being told. See `Targets`_.


``[binary]``
~~~~~~~~~~~~

The program binary each version disassembles — a sideways ROM image,
or any other load-and-run binary. ``cpu`` and ``base_address`` describe
how to decode it; the layout keys say where its bytes and metadata live
under the version directory.

.. code-block:: toml

   [binary]
   cpu          = "6502"     # default; overridden by drivers as needed
   base_address = 0x8000     # the address the binary is mapped at
   dir          = "rom"      # per-version subdirectory (default)
   extension    = "rom"      # binary file extension, no dot (default)
   metadata     = "rom.json" # metadata filename (default)
   filename     = "{prefix}-{version_id}"  # basename template (default)

* ``cpu`` — recognised values, case-insensitive: ``"6502"``,
  ``"nmos"`` (alias), ``"65c02"``, ``"65sc12"``, ``"65c12"``,
  ``"cmos"`` (alias). fantasm's audit / cfg / context / compare
  commands read this default so the right opcode table is used. A
  driver can pass a different CPU to the disassembler for a
  specific version (ANFS 4.21 does this — base default of 6502 with
  the driver overriding to 65c02).
* ``base_address`` — defaults to ``0x8000`` (BBC sideways-ROM
  convention). Override for binaries mapped elsewhere — for example
  ``0xE000`` for the standalone Acorn Econet Bridge, ``0xF800`` for
  the BBC Tube Client, or ``0x1900`` for a DFS ``*RUN`` program that
  loads into main memory.
* ``dir`` — the per-version subdirectory holding the binary and its
  metadata. Default ``"rom"``.
* ``extension`` — the binary file's extension, **without** a leading
  dot. Default ``"rom"``. An empty string (``""``) means the binary
  has no extension — as for a DFS program named literally ``KEYPAD``.
* ``metadata`` — the metadata filename inside ``dir`` (its ``docs``
  list is consulted by ``fantasm lint``). Default ``"rom.json"``.
* ``filename`` — a template for the binary's **basename** (the
  ``extension``, if any, is appended afterwards). Default
  ``"{prefix}-{version_id}"``. Recognised tokens, the same set as
  ``[versions] driver_filename`` plus case variants:

  * ``{prefix}`` / ``{prefix_upper}`` / ``{prefix_lower}``
  * ``{version_id}`` — the id as written
  * ``{version_id_no_dots}`` — the id with all ``.`` removed
  * ``{version_id_upper}`` / ``{version_id_lower}``

  Set ``filename = "{version_id_upper}"`` to keep an Acorn DFS-style
  name — id ``keypad`` renders the on-disk binary ``KEYPAD`` — so an
  extracted DFS program (and its ``KEYPAD.inf`` sidecar, which the
  versions/ convention ignores — ``base_address`` applies) stays
  intact. The ``.asm`` / ``.json`` disassembly
  outputs always keep the ``{prefix}-{version_id}`` name; only the
  binary basename follows this template.

The binary for version ``V`` (prefix ``P``) resolves to
``versions/P-V/<dir>/<filename>[.<extension>]`` and its metadata to
``versions/P-V/<dir>/<metadata>``. With the defaults this is the
historical ``rom/P-V.rom`` + ``rom/rom.json`` layout.

The driver script receives the resolved binary path in the
``FANTASM_BINARY`` environment variable (and, for back-compat, the
same value in ``FANTASM_ROM``); see `The driver's environment`_ for
the full set.

.. note::

   ``[rom]`` is still accepted as an alias for ``[binary]`` — a project
   that predates the neutral vocabulary needs no changes. When both
   sections are present ``[binary]`` wins (they are not merged), so move
   all keys together when migrating.

A DFS ``*RUN`` program disassembly, for example:

.. code-block:: toml

   [binary]
   cpu          = "6502"
   base_address = 0x1900
   dir          = "binary"
   extension    = ""                   # KEYPAD, not KEYPAD.rom
   metadata     = "binary.json"
   filename     = "{version_id_upper}" # id "keypad" -> binary "KEYPAD"


``[versions]``
~~~~~~~~~~~~~~

.. code-block:: toml

   [versions]
   directory       = "versions"   # default
   prefixes        = ["anfs", "nfs"]
   driver_dirname  = "disassemble"  # default
   driver_filename = "disasm_{prefix}_{version_id_no_dots}.py"  # default

* ``directory`` — subdirectory under the project root that holds
  per-version directories. Default ``"versions"``.

* ``prefixes`` — ordered list of acceptable ROM-name prefixes. Version
  directories are named ``{prefix}-{version_id}/``; resolution tries
  each prefix in order and returns the first existing directory. NFS
  uses two; most projects use one. If omitted, ``[project] name`` is
  used as a single-element fallback.

* ``driver_dirname`` — subdirectory under each version directory
  holding the disassembly driver script. Default ``"disassemble"``.

* ``driver_filename`` — filename template for the driver. Tokens:
  ``{prefix}``, ``{version_id}``, ``{version_id_no_dots}``. The
  default works when the prefix has no hyphens; projects whose prefix
  has a hyphen must override (the Econet Bridge's prefix is
  ``econet-bridge`` but its driver is named
  ``disasm_econet_bridge_*.py``):

  .. code-block:: toml

     [versions]
     prefixes        = ["econet-bridge"]
     driver_filename = "disasm_econet_bridge_{version_id_no_dots}.py"

For NFS version ``3.10`` (prefix ``anfs``), with the defaults, the
driver script's path is
``versions/anfs-3.10/disassemble/disasm_anfs_310.py``.


Targets
-------

A **target** is one thing being disassembled: a program binary loaded
at some address, the driver script that disassembles it, the ``.asm``
and ``.json`` the driver writes, and an optional metadata file. Every
per-target command — ``disassemble``, ``verify``, ``lint``, ``audit``,
``cfg``, ``comments`` and the rest — takes a ``TARGET`` argument; in a
multi-version project each version is a target.

The ``TARGET`` argument is optional when the project has exactly one
target, or sets ``[project] default_target``::

   fantasm verify              # the only (or default) target
   fantasm asm extract &1900   # likewise, with a further argument
   fantasm verify 1.30         # name one explicitly

Leaving it out of a project with several targets and no default fails
with a message listing them.

Where a target's files live is resolved in three layers. Each overrides
the one before it **key by key**, so a project can override just the
driver path for one target and keep the convention for everything
else:

1. **The versions/ convention** — ``versions/<prefix>-<id>/`` as
   described under ``[binary]`` and ``[versions]`` above. A project
   with neither ``[layout]`` nor ``[[targets]]`` uses only this layer,
   exactly as it always has.
2. **``[layout]`` templates** — for multi-version projects that keep
   their files somewhere else.
3. **``[[targets]]`` entries** — explicit paths for one target each,
   for adopting an existing project as it stands.

The set of targets is the ``[[targets]]`` ids, then — when
``[layout]`` is configured — the ``[[versions.entry]]`` ids and any
ids found by ``[layout] discover``, then the version directories on
disk. ``fantasm project list`` shows them all, with where each one
resolved from.

``[[targets]]``
~~~~~~~~~~~~~~~

One table per target. Paths are relative to the project root:

.. code-block:: toml

   [[targets]]
   id           = "loader"
   binary       = "orig/ELITE"
   load_address = 0x1900          # optional: see below
   exec_address = 0x8023          # optional
   driver       = "tools/dis_loader.py"
   asm          = "build/loader.asm"
   json         = "build/loader.json"
   metadata     = "notes/loader.json"   # optional
   driver_cwd   = "tools"               # optional

* ``id`` *(required)* — the name commands use for the target. Letters,
  digits, ``.``, ``_`` and ``-``.
* ``binary``, ``driver``, ``asm``, ``json`` — the files. Any of them
  may be left out when the target also has a version directory (or
  ``[layout]`` supplies it); otherwise each is required.
* ``metadata`` — optional JSON file whose ``docs`` list ``fantasm
  lint`` checks for broken ``label:`` / ``glossary:`` links. Relative
  ``docs`` paths resolve against the project root (or the version
  directory, for a target that has one).
* ``load_address`` / ``exec_address`` — integers (``0x1900``) or hex
  strings (``"&1900"``, ``"$1900"``, ``"1900"``). When
  ``load_address`` is absent, fantasm reads the binary's ``.inf``
  sidecar (``ELITE.inf`` beside ``ELITE``) if there is one, and
  otherwise falls back to ``[binary] base_address``.
* ``inf`` — ``true`` to require the sidecar (an error if it's
  missing), ``false`` to ignore it, or a path to a ``.inf`` stored
  elsewhere.
* ``driver_cwd`` — the directory the driver runs in. By default it
  runs in the directory ``fantasm`` was invoked from; set this when an
  existing driver uses paths relative to its own location.
* ``prefix`` — the ``{prefix}`` used for this target in messages and
  templates. Defaults to the project's first prefix.
* ``verify`` — a table overriding ``[verify]`` keys for this target.
* ``images`` — an alternative to ``binary`` / ``load_address`` /
  ``exec_address`` / ``inf``, as a list of one table with ``path``,
  ``name`` and those address keys. Only a single image is supported
  at present; disassemble a multi-file program as one target per file
  (see :doc:`disc_programs`).

Unknown keys are rejected, so a typo such as ``binry`` is reported
rather than silently ignored.

``.inf`` files
^^^^^^^^^^^^^^

fantasm reads the many ``.inf`` variants archiving tools have written:
the classic DFS form (``$.ELITE FF1900 FF8023 000400 L``), the
8-digit ADFS form with an access byte (``FS3 00001900 00001900
00004C00 33``), quoted names, ``&``/``$``/``0x``-prefixed numbers,
``Locked`` / ``L`` flags and ADFS access strings (``WR/r``), and
trailing ``CRC=`` / ``CRC32=`` / ``NEXT=`` extras. High bits of
``&FF``/``&FFFF`` mark an I/O-processor address and are dropped. A
``.inf`` that can't be parsed — or whose address isn't a 6502 address,
such as a RISC OS filetype stamp — is reported with a suggestion to
give ``load_address`` explicitly.

``[layout]``
~~~~~~~~~~~~

Path templates rendered for every target, for multi-version projects
that don't use ``versions/<prefix>-<id>/``:

.. code-block:: toml

   [layout]
   binary   = "roms/{id}.rom"
   driver   = "scripts/dis_{id_no_dots}.py"
   asm      = "build/{id}.asm"
   json     = "build/{id}.json"
   metadata = "docs/{id}.json"    # optional
   discover = "roms/{id}.rom"     # optional: find ids on disk

   [[versions.entry]]
   id = "1.20"

   [[versions.entry]]
   id = "1.30"
   parents = ["1.20"]

Tokens: ``{id}``, ``{id_no_dots}``, ``{id_upper}``, ``{id_lower}``,
the ``{version_id}`` family (aliases of the ``{id}`` ones),
``{prefix}``, ``{prefix_upper}`` and ``{prefix_lower}``.

* ``discover`` — a path with exactly one ``{id}`` token. Every
  matching file or directory adds a target. Without it, the targets
  are the ``[[versions.entry]]`` ids (plus any ``[[targets]]``).
* ``load_address``, ``exec_address``, ``inf`` and ``driver_cwd`` may
  also be given here, applying to every target (``inf`` and
  ``driver_cwd`` are templates).


``[verify]`` — the round-trip assembler
---------------------------------------

``fantasm verify`` assembles a target's ``.asm`` and compares the
result with the original binary. The assembler is beebasm unless this
section says otherwise:

.. code-block:: toml

   [verify]
   command = ["beebasm", "-i", "{asm}", "-o", "{output}"]   # default
   cwd     = "{asm_dirpath}"                                # default
   output  = "{output}"                                     # default

* ``command`` — the argument list, or a single string split with
  shell-style quoting. A bare program name is looked up on ``PATH``;
  a relative path with a directory part resolves against the project
  root, so a wrapper script in the repository works
  (``command = ["tools/assemble.sh", "{asm}", "{output}"]``).
* ``cwd`` — the directory the assembler runs in. The default, the
  listing's own directory, keeps ``INCBIN`` and similar relative
  directives working.
* ``output`` — the file to compare against the binary, relative to
  ``cwd`` unless absolute. The default ``{output}`` is a fresh
  temporary file fantasm deletes afterwards. An assembler that always
  writes a fixed file — for example from a ``SAVE "NAME"`` directive —
  names that file here instead.

Tokens available in all three: ``{asm}`` (absolute path of the
listing), ``{asm_dirpath}``, ``{asm_filename}``, ``{output}``,
``{output_dirpath}`` (the temporary directory), ``{binary}`` (absolute
path of the original binary) and ``{project_root}``.

A ``[[targets]]`` entry's ``verify`` table overrides these keys for
that target.


The driver's environment
------------------------

``fantasm disassemble`` runs the target's driver with these
environment variables set:

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Variable
     - Value
   * - ``FANTASM_TARGET``
     - the target id
   * - ``FANTASM_BINARY``
     - the target's binary (``FANTASM_ROM`` holds the same value, for
       older drivers)
   * - ``FANTASM_IMAGES``
     - JSON list describing the binary image:
       ``[{"name", "path", "load_addr", "exec_addr"}]``, with
       ``load_addr`` resolved as described under ``[[targets]]``
   * - ``FANTASM_ASM`` / ``FANTASM_JSON``
     - where fantasm expects the generated ``.asm`` / ``.json``
   * - ``FANTASM_OUTPUT_DIR``
     - the directory holding the ``.json``

A driver is free to ignore them and use its own paths, as long as its
outputs land where the configuration says they do — an existing
driver needs no changes to be adopted.


``[memory]`` — non-ROM addresses where code and labels can live
---------------------------------------------------------------

Two lists at the project level. Both are optional.

.. code-block:: toml

   [memory]
   regions = [
     { start = 0x0016, end = 0x0076 },   # zero-page workspace
     { start = 0x0D00, end = 0x0FFF },   # NMI workspace
   ]
   external_regions = [
     { start = 0xFC00, end = 0xFFFF },   # MOS / hardware
   ]

* ``regions`` — RAM ranges where subroutines and labels can live
  outside the ROM range. The ROM range itself is discovered from each
  version's JSON metadata, so don't list it here. Reloc-block
  destinations from a version's ``reloc_blocks`` list are
  automatically merged into that version's *effective* regions, so
  don't duplicate them here either.

* ``external_regions`` — hardware / OS-mapped addresses that label
  references can point at, but where no assembly items are emitted.
  Used by lint and ``comments check`` to allow references to OS
  routines, hardware registers, etc.

``end`` is **inclusive** in both lists.

When ``fantasm`` 0.4.0+ runs ``lint``, the JSON's own
``external_labels`` map is consulted directly, so a workspace address
declared via the driver's ``external_label()`` (the same call shape
on both dasmos and py8dis) *does not* need a matching ``[memory]``
entry. ``[memory]`` regions still cover addresses that the driver
references but doesn't formally declare — typically hardware
registers and OS workspace pages where the project doesn't want a
name for every byte.

A version can override ``regions`` (but not ``external_regions`` —
hardware mapping is invariant) by setting ``memory.regions`` in its
``[[versions.entry]]``:

.. code-block:: toml

   [[versions.entry]]
   id = "page7-variant"
   parents = ["3.34B"]
   memory.regions = [
     { start = 0x0016, end = 0x0076 },
     { start = 0x0700, end = 0x07FF },   # this variant uses page 7
   ]

Override is **complete replacement**, not merge — explicit and
non-magical. Reloc-destination regions still auto-add even when
``memory.regions`` is overridden.


``[[versions.entry]]`` — the version graph
------------------------------------------

Each entry is a node in the version graph. Edges are declared by the
``parents`` list (parent → child, older → newer). A version with no
parents is a root or an as-yet-unplaced node; both are valid.

For the cookbook on what the graph buys you (path-finding, reloc
matching, annotation propagation), see :doc:`version_graph`.

Minimal entry
~~~~~~~~~~~~~

.. code-block:: toml

   [[versions.entry]]
   id = "1.0"

That's enough to make commands like ``audit`` / ``cfg`` /
``comments check`` use the project's ``[memory]`` regions for this
version. Without an entry, those commands fall back to the ROM range
alone.

With reloc blocks
~~~~~~~~~~~~~~~~~

NFS-style firmware copies blocks of code from ROM into RAM at
runtime, then jumps there. Each ``move()`` block in the driver gets a
matching entry in ``reloc_blocks``:

.. code-block:: toml

   [[versions.entry]]
   id = "3.34"
   reloc_blocks = [
     { source = 0x9307, dest = 0x0016, length = 0x61 },
     { source = 0x934C, dest = 0x0400, length = 0x100 },
     { source = 0x944C, dest = 0x0500, length = 0x100 },
     { source = 0x954C, dest = 0x0600, length = 0x100 },
   ]

Per block:

* ``source`` — the ROM address where the bytes live in *this*
  version;
* ``dest`` — the runtime address where they execute;
* ``length`` — block length in bytes.

Across versions, ``dest`` and ``length`` are usually stable (driven
by the project's runtime memory map); ``source`` shifts as code is
added or removed elsewhere in the ROM. Across an edge,
``compose_chained_map`` matches reloc blocks by ``(dest, length)``;
see :doc:`version_graph` for the consequences.

``reloc_blocks`` may be empty or omitted for versions with no
``move()`` blocks — the schema accommodates simple firmware with no
relocation as well as the NFS-style architecture.

With parents
~~~~~~~~~~~~

Most non-root versions descend from a previous one:

.. code-block:: toml

   [[versions.entry]]
   id = "3.34B"
   parents = ["3.34"]
   reloc_blocks = [
     # ... 3.34B's source addresses for the same dest pages
   ]

A version may declare multiple parents — fantasm handles merge
nodes:

.. code-block:: toml

   [[versions.entry]]
   id = "3.40"
   parents = ["3.35K", "3.34B-japan"]

Free-form metadata
~~~~~~~~~~~~~~~~~~

Each ``[[versions.entry]]`` may carry the following fields. None of
them affect analysis — they're surfaced for tooling and
documentation.

.. code-block:: toml

   [[versions.entry]]
   id = "3.34"
   description  = "First public release; zero-based workspace layout"
   release_date = "1984-01-15"   # ISO-8601 string, not parsed
   source       = "Acorn Cambridge archive disk #ANFS-001"
   notes        = "Reverse-engineered from binary; no source survives"


``[comments.suggest]`` — label hints for ``fantasm comments suggest``
---------------------------------------------------------------------

Pattern → description map for project-specific comment hints.
``fantasm comments suggest`` mixes these in with the generic 6502
instruction-pattern heuristics so workspace-label references get
project-meaningful suggestions.

.. code-block:: toml

   [comments.suggest.label_hints]
   wksp_drive    = "current drive"
   wksp_filename = "filename buffer"
   tube_r1       = "Tube FIFO 1 (data)"

Patterns are substring-matched against item labels. Per-invocation
hints can be added with ``--label-hint PATTERN=description`` on the
command.


Per-module summary
------------------

Which modules look at which configuration, for a given version ``V``:

.. list-table::
   :header-rows: 1
   :widths: 22 78

   * - Module
     - Reads
   * - ``audit``
     - ``effective_regions(V)`` ∪ ROM-range-of(V)
   * - ``comment_check``
     - ``effective_regions(V)`` ∪ ``effective_external_regions(V)`` ∪ ROM
   * - ``lint``
     - JSON's ``items`` / ``external_labels`` / ``sub_labels`` /
       ``subroutines`` ∪ ROM ∪ ``effective_regions(V)`` ∪
       ``effective_external_regions(V)``
   * - ``backfill`` / ``annotations diff``
     - ``effective_regions(V_source) ∩ effective_regions(V_target)``
       for identity mapping; per-edge reloc tuples derived by matching
       ``(dest, length)`` across endpoints
   * - ``cfg`` / ``compare`` / ``fingerprint`` / ``shared``
     - only ROM bytes (no version-graph involvement)

``effective_regions(V)`` = (``memory.regions`` from V's override, or
the project default) ∪ ``{dest..dest+length-1 for each reloc in V's
reloc_blocks}``, with overlapping ranges merged.

``effective_external_regions(V)`` = the project's
``memory.external_regions`` (no per-version override).


Example: a complete config
--------------------------

A single-version project with a custom driver-filename template,
declared workspace, and one ``[[versions.entry]]``:

.. code-block:: toml

   [project]
   name = "acorn-econet-bridge"

   [binary]
   cpu          = "6502"
   base_address = 0xE000     # standalone 6502, ROM at &E000-&FFFF

   [versions]
   prefixes        = ["econet-bridge"]
   driver_filename = "disasm_econet_bridge_{version_id_no_dots}.py"

   [memory]
   regions = [
     { start = 0x0000, end = 0x00FF },   # zero page (workspace)
     { start = 0x0200, end = 0x04FF },   # workspace tables
   ]
   external_regions = [
     { start = 0xC000, end = 0xCFFF },   # ADLC A
     { start = 0xD000, end = 0xDFFF },   # ADLC B
   ]

   [[versions.entry]]
   id = "variant_1"

A multi-version project with the version graph populated — see the
NFS migration commit on `acorn-nfs`_ for the live example covering
eleven versions across two prefixes with full ``reloc_blocks``.

.. _acorn-nfs: https://github.com/acornaeology/acorn-nfs
