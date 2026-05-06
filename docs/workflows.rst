Workflows
=========

A grouped tour of fantasm's commands, organised by what you're
actually trying to do. Each section names the relevant commands,
shows a typical invocation, and links to the CLI reference and
configuration schema for the details. See :doc:`cli` for every
option of every command, and :doc:`configuration` for the
``fantasm.toml`` knobs the commands read.


I want to verify my disassembly is byte-correct
-----------------------------------------------

After every change to the disassembly driver, the load-bearing
question is: does the regenerated ``.asm`` reassemble back to the
original ROM bytes?

.. code-block:: bash

   uv run fantasm disassemble 1.0      # rerun the disassembly driver
   uv run fantasm verify 1.0           # beebasm round-trip + byte compare

* **Pass** → "Verification PASSED: N bytes match". The disassembly
  is faithful.
* **Fail** → "Verification FAILED: rom=Nb assembled=Mb
  first_diff=&XXXX". Look at the first differing offset; it's almost
  always either a typo'd ``constant()`` / ``label()``, an instruction
  that the disassembler decoded differently from what's in the bytes
  (rare; a ``code()`` annotation usually fixes it), or an inline-data
  block with wrong length.

Sub-banked images — where the ROM file is larger than what the CPU
sees mapped at runtime — are handled automatically: ``verify``
slices the trailing portion of the file matching the assembled
length. The Tube Client's 4 KB / 2 KB shape "just works" without a
project-side wrapper.

Useful options:

* ``fantasm verify --all`` runs verify across every version under
  the project's ``versions/`` directory, useful as a CI safety net.

See :doc:`cli` for the full reference, ``fantasm verify`` section.


I want to validate annotation addresses
---------------------------------------

``fantasm lint`` checks every ``comment(0xADDR, ...)``,
``label(0xADDR, ...)``, and ``subroutine(0xADDR, ...)`` in your driver
script against the JSON disassembly: does each address actually
appear in the output?

.. code-block:: bash

   uv run fantasm lint 1.0 versions/myrom-1.0/disassemble/disasm_myrom_10.py

Zero output = clean. Anything reported is an annotation pointing at
an address fantasm can't account for — typically a stale address
copied from another version, a typo, or a workspace label that needs
declaring via ``external_label()`` in the driver (or, falling back,
in ``fantasm.toml``'s ``[memory]`` regions).

fantasm 0.4.0 reads the JSON's ``external_labels`` and ``sub_labels``
maps directly, so any address you've named in the driver is accepted
without needing a duplicate ``[memory]`` declaration.


I want to find missing or wrong comments
----------------------------------------

Two complementary commands.

``fantasm comments check`` runs the comment-vs-code consistency
checks: detects branch comments that disagree with the actual flag,
register-load comments that name the wrong value, stale "see also"
addresses that no longer match an instruction, and Markdown
address-links accidentally trapped inside a backtick code span
(``\`MNEMONIC [label](address:HEX)\``` — the link won't render
inside ``<code>``; see ``AUTHORING.md §1.3``).

.. code-block:: bash

   uv run fantasm comments check 1.0
   uv run fantasm comments check 1.0 --sub 0x8027    # one subroutine
   uv run fantasm comments check 1.0 --strict        # CI gate

``--strict`` exits non-zero whenever any HIGH-confidence finding is
reported (wrong register / wrong branch target / wrong CR / wrong
tube register / Markdown link inside a code span). The report
still renders before the exit, so CI logs show the offences.

``fantasm comments suggest`` looks for uncommented instructions and
proposes paste-ready ``comment()`` lines based on:

* generic 6502 instruction-pattern heuristics ("PHA → Save A on
  stack", "BNE → Branch if not equal", …);
* project-specific workspace labels declared in
  ``[comments.suggest.label_hints]`` (see :doc:`configuration`);
* any extra label hints passed via ``--label-hint
  PATTERN=description`` on the command line.

.. code-block:: bash

   uv run fantasm comments suggest 1.0
   uv run fantasm comments suggest 1.0 --start &8027 --end &805F
   uv run fantasm comments suggest 1.0 --label-hint "wksp_drive=current drive"


I want to understand a subroutine's role
----------------------------------------

Three views of a subroutine, each pivoting on a different question.

``fantasm audit detail VID NAME``
  Full report on one routine: title / description from the driver,
  extent, callers (JSR + JMP entries), branch entries, escaping
  branches, computed flags. Use it to see whether your annotation
  matches the actual control flow.

``fantasm cfg sub VID NAME``
  Flat call-graph view: who calls this routine, who it calls, with
  the call sites listed. Useful for "is this a leaf?" or "what's the
  fan-out?".

``fantasm cfg sub-context VID NAME``
  Calling-convention detail: body lines, every call site with
  surrounding context, every exit point. Use it when you're trying
  to figure out the calling convention (which registers carry inputs
  / outputs).

Combine with the analysis-side commands:

* ``fantasm cfg leaves``, ``fantasm cfg roots``, ``fantasm cfg depth``
  — call-graph topology.
* ``fantasm audit summary`` — every subroutine with computed flags
  (FALL_THROUGH, BRANCH_ESCAPE, NO_REFS, …); use ``--flag X`` to
  filter.
* ``fantasm audit undeclared`` — JSR / JMP targets that lack
  ``subroutine()`` declarations. Run this after large annotation
  passes.
* ``fantasm audit placeholders`` — tracer-auto-discovered routines
  that the driver script has never named. The disassembler traces
  JSR / branch targets via code-flow and emits hex-tail placeholders
  (``.sub_cXXXX``, ``.loop_cXXXX``, ``.lXXXX``, ``.cXXXX``) for
  any address it discovers without an explicit declaration. They
  are visible in ``output/<ver>.asm`` but never reach the JSON's
  ``subroutines`` list, so ``audit summary`` and ``audit
  undeclared`` can't see them. Use this command to drive a CI gate
  ("zero placeholders before merge"):

  .. code-block:: bash

     uv run fantasm audit placeholders 1.0
     uv run fantasm audit placeholders 1.0 --as json | jq '.placeholders | length'

  ``audit summary`` also surfaces the same count under the
  ``placeholders`` report block, so a single ``audit summary``
  invocation can serve both purposes.


I want to find the gaps in my annotation work
---------------------------------------------

``fantasm context uncommented`` flags subroutines below a comment
density threshold. A useful starting point for "what's still
uncommented?" — sorted by significance, with named callees and
workspace references shown so you can pick the next routine to tackle.

.. code-block:: bash

   uv run fantasm context uncommented 1.0
   uv run fantasm context uncommented 1.0 --threshold-pct 50

``fantasm cfg blocks`` identifies basic blocks; pair it with
``--uncommented-only`` to surface the blocks where every line is
uncommented (your remaining work front).

.. code-block:: bash

   uv run fantasm cfg blocks 1.0 --uncommented-only --min-items 3


I want a global comment-coverage snapshot
-----------------------------------------

Where ``context uncommented`` is a per-subroutine view, ``coverage``
is the headline number across the whole disassembly: total code
items, how many carry a ``comment_inline`` annotation, and the
percentage. Useful for tracking annotation progress over time and
for "how far through this version are we?" check-ins.

.. code-block:: bash

   uv run fantasm coverage 1.0
   uv run fantasm coverage 1.0 --by page    # 256-byte breakdown
   uv run fantasm coverage 1.0 --by sub     # per-subroutine breakdown

The headline summary report carries the percentage plus the raw
counts; ``--by`` adds a second report with one row per page or
subroutine, sorted by start address. A subroutine with no code
items emits a zero-count row rather than disappearing — the
"this sub needs annotation" findings stay visible.

Only ``comment_inline`` counts towards "commented"; block-level
``comment_above`` / ``comment_below`` are intentionally excluded so
the metric is the per-instruction-density one most useful for
"what's still uncommented".


I want to review my data declarations
-------------------------------------

After the call graph and most subroutines are annotated, the
standing question is: are the long ``EQUB``/``EQUW``/``EQUS``
runs really raw bytes, or is there structure I haven't spotted —
a string table, a vector list, a small look-up table that wants
its own labels?

``fantasm data runs`` is the entry point. It surfaces every
contiguous run of same-type data items, longest first, so the
biggest unstructured stretches surface immediately:

.. code-block:: bash

   uv run fantasm data runs 1.0
   uv run fantasm data runs 1.0 --min-bytes 16        # only longer runs
   uv run fantasm data runs 1.0 --type word           # vector tables
   uv run fantasm data runs 1.0 --unannotated         # work front

Each row carries the run's start address, type, item count, byte
length, leading label (if any), and a ``Y`` marker when the run
has either a label or per-item inline comments. ``--annotated`` /
``--unannotated`` filter on that marker — ``--unannotated`` is
the "what should I look at next?" view.


I want to know what's in this byte run
--------------------------------------

The companion to ``data runs``. Once the listing flags a long
unannotated byte run, ``fantasm data classify`` applies four
heuristic classifiers to it:

* **Padding** — repeating-byte patterns of length 1–4 (the
  ``FF FF FF…`` / ``00 00 00…`` / ``EA EA EA…`` fills, plus
  alternating two-byte fillers like ``AB CD AB CD``). Catches ROM
  pad bytes that should be declared as such rather than left as
  raw EQUB.
* **String** — runs of printable ASCII (0x20–0x7E plus tab / CR /
  LF) optionally terminated by a null byte. Catches embedded
  text that the disassembler hasn't recognised as a string.
* **High-byte address table** — runs where every byte falls in
  the project's ROM-page band (e.g. 0x80–0xBF for a 16 KB
  sideways ROM at &8000). Catches the high-byte halves of
  PHA/PHA/RTS-style dispatch tables, which would otherwise be
  mis-read as long valid-code sweeps because most opcodes in
  0x80–0xBF exist as real 6502 instructions. The band is derived
  from the JSON's ``meta.load_addr`` / ``meta.end_addr``.
* **Code** — every starting alignment is tried; the longest sweep
  consuming valid 6502 opcode lengths wins. Catches code that the
  disassembler emitted as bytes (often because no ``entry()``
  reached it).

Run it:

.. code-block:: bash

   uv run fantasm data classify 1.0
   uv run fantasm data classify 1.0 --min-string 8 --min-code 16

The orchestrator walks every run of byte-typed items left to
right, applying the classifiers in priority order **padding →
string → hi_bytes_table → code**: the first classifier to claim
bytes at the cursor wins, the cursor advances past the match,
then the next round runs. Output is sorted by length descending
so the strongest candidates surface first.

Confidence is exact (1.0) for padding, pure-printable strings,
and high-byte address tables; for code it is a coarse length
heuristic (``min(length / 32, 1.0)``) — a nudge towards "this is
more likely real code" rather than a guarantee. The candidate
list is *advisory*; treat it as a guide for which byte runs
deserve a closer look, not as a directive to reclassify
automatically.

Use ``--target-type string`` (or word) to also re-examine items
the disassembler already classified as strings/words — useful for
sanity checks ("did the disassembler get the boundaries right?").
The default ``--target-type byte`` is the dominant case.


I want to find missing print-inline hooks
-----------------------------------------

A common cause of mysterious unannotated byte runs in Acorn-style
ROMs is a missing ``hook_subroutine()`` for a print-inline helper.
The shape: a routine that prints an inline string after its ``JSR``
(the bytes following each call site are ``EQUS "..."`` then a
terminator then resume code). Without the hook the disassembler
treats the resume code as raw bytes — and a single missing hook
can leave dozens of mysterious byte runs strewn across the ROM.
``hook_subroutine`` is the same call shape on both dasmos and
py8dis driver APIs.

``fantasm hooks suggest`` flips the diagnostic. Instead of
chasing each downstream byte run, it scans every JSR target and
looks for the **shape at the call sites**: a string item
followed by a byte run that decodes as valid 6502 code. Targets
matching the signature at multiple call sites are almost
certainly print-inline helpers waiting to be hooked.

.. code-block:: bash

   uv run fantasm hooks suggest 1.0
   uv run fantasm hooks suggest 1.0 --min-call-sites 5     # only the strong-signal targets

Two reports come back:

- ``candidates`` — table form for human review: target address,
  driver-assigned label if any, suggested hook kind (``stringz`` /
  ``stringcr`` / ``stringhi`` / ``unknown``), matching call-site
  count, total call-site count, confidence, and a sample of the
  inline strings observed.
- ``paste`` — paste-ready ``hook_subroutine()`` lines, one per
  candidate, e.g.:

  .. code-block:: python

     hook_subroutine(0x928A, "print_inline_no_spool", stringcr_hook)  # 14 sites, conf=1.00

  Drop these into your driver, regenerate, and the downstream
  byte runs collapse into normal code.

Hook-kind detection has to deal with the asymmetric terminator
encoding the disassembler emits (the same shape from dasmos and
py8dis). ``stringz`` and ``stringcr`` include the terminator
(``0x00`` or ``0x0D``) as the last byte of the string item, but
``stringhi`` *excludes* its bit-7 terminator — that byte lives as
the first byte of the following item, doing double duty as
terminator and resume opcode. The classifier therefore looks at
both the string's last byte *and* the next item's first byte,
applied in this priority:

* string ends in ``0x00`` → ``stringz_hook`` (unambiguous)
* next byte has bit 7 set → ``stringhi_hook`` (the structural
  signal — beats a ``\r``-looking last byte, since the printed
  text may itself end in ``\r``)
* string ends in ``0x0D`` and next byte has bit 7 clear →
  ``stringcr_hook``
* otherwise → ``unknown`` (paste line emits ``<HOOK_FN>`` for
  manual selection)

Already-hooked targets are silent in the output: their post-call
items are ``string`` then ``code``, not ``string`` then ``byte``,
so they don't match the missing-hook signature. A clean ROM
reports zero candidates. The default ``--min-call-sites 2`` plus
``--min-confidence 0.5`` lets a target through when at least two
call sites match the signature and at least half of all call
sites match — the user's "5+ is almost certainly" threshold is a
conservative ``--min-call-sites 5`` away.


I want to bring annotations from a known version to a new one
-------------------------------------------------------------

The defining workflow when porting annotations across releases.

1. Make sure both versions have ``[[versions.entry]]`` blocks in
   ``fantasm.toml``, with ``parents`` chained as appropriate.
2. ``fantasm backfill SOURCE TARGET`` walks the version graph and
   proposes propagations:

   .. code-block:: bash

      uv run fantasm backfill 3.34 3.65

   The output lists candidate propagations (comments, labels,
   subroutine declarations) above the configured ``--threshold``
   that don't conflict with annotations already in the target driver.

3. The output is **report-only** — copy promising rows into the
   target driver yourself, run ``fantasm disassemble`` and
   ``fantasm verify`` to confirm nothing broke, and iterate.

For project scripts that need to drive the same engine
programmatically — e.g. a ``generate_<new_version>.py`` baseline
generator — call :func:`fantasm.api.backfill.propose_translations`
directly:

.. code-block:: python

   from pathlib import Path

   from fantasm.api.backfill import propose_translations
   from fantasm.config import resolve_project_context

   project = resolve_project_context(Path("."))
   report = propose_translations(
       project,
       source_version="4.18",
       target_version="4.21_variant_1",
       source_driver=Path("versions/anfs-4.18/disassemble/disasm_anfs_418.py"),
       threshold=10,
   )
   for candidate in report.candidates:
       ...   # render into the new driver
   # report.skipped_no_mapping is the count to route to '# UNMAPPED:'

Anchoring is identical to the CLI: every candidate sits inside a
composed shared block of ``threshold`` opcodes through the
version graph (the weakest hop binds). Source addresses outside
such a block produce no candidate — the consumer is expected to
route those to ``# UNMAPPED:`` rather than silently fall back to
identity, which is the failure mode the threshold protects
against.

Cross-version diff:

.. code-block:: bash

   uv run fantasm annotations diff 3.34 3.65

reports source-side annotations whose mapped target is missing,
differs, or can't be reached. ``--kind comment|label|subroutine``
and ``--status differs|missing_in_target|no_mapping`` narrow the
view.

Both commands rely on the version graph — see :doc:`version_graph`.


I want to know which addresses moved between versions
-----------------------------------------------------

``fantasm addresses map`` exposes the opcode-level address map
between two versions:

.. code-block:: bash

   # full map (large for real ROMs — pipe through --as tsv)
   uv run fantasm addresses map 3.34 3.65 --as tsv

   # just specific addresses
   uv run fantasm addresses map 3.34 3.65 --addr 0x8027 --addr &809E

The map combines an LCS-derived "primary" mapping with a seed-and-
extend "supplementary" pass that catches reordered blocks the LCS
misses. Use ``--primary-only`` to see just the LCS mappings.

Every emitted mapping is anchored in a contiguous run of ≥
``--threshold`` matching opcodes (default 5, matching ``fantasm
backfill``). Source addresses outside such a run are absent from
the output (rendered as ``(no mapping)`` when queried with
``--addr``). Short coincidence matches are silently wrong whenever
the surrounding code has diverged — the threshold protects callers
who would otherwise see e.g. ``&A84D → &A84D`` when in fact the
target ROM has unrelated code at that numeric address. Lower
``--threshold 1`` deliberately when working on tiny ROMs where the
default would cull legitimate matches.


I want to find a specific byte sequence in a ROM
------------------------------------------------

``fantasm bytes find`` is the natural complement to ``fingerprint``
when you have an exact (or near-exact) byte sequence in mind and
want to know whether it appears in a given ROM. Typical use cases:
locating the call site of a known opcode + operand, confirming a
particular routine has been relocated rather than removed, or
asking whether the byte body of a deleted routine survives intact
elsewhere in the image.

.. code-block:: bash

   # Find every occurrence of a literal three-byte sequence:
   uv run fantasm bytes find 1.0 "4C B9 FF"

   # ?? wildcards match any single byte. JSR + 16-bit operand:
   uv run fantasm bytes find 1.0 "20 ?? ??"

   # Cross-version presence check — the "is this gone in 4.21?" view:
   uv run fantasm bytes find 4.18 "A9 00 8D 7E 02" --cross 4.21_variant_1

Pattern grammar: hex pairs (lower or upper case) optionally
separated by whitespace, with per-token ``$`` or ``0x`` prefixes
tolerated; ``??`` (exactly two question marks) is the any-byte
wildcard. ``"4C B9 FF"``, ``"4cb9ff"``, ``"$4C $?? $FF"``, and
``"0x4C 0xb9 0xff"`` all parse as the same three-byte pattern.
Nibble-level wildcards (``"4?"``) and patterns made entirely of
wildcards are rejected — the latter would match every position.

The ``matches`` report adds a ``Captures`` column when the pattern
contains wildcards, showing the bytes the wildcards captured at
each hit (in pattern order). For pure-literal patterns the column
is suppressed. The ``summary`` report (populated when ``--cross``
is used) gives one row per version with the match count and the
first eight addresses — the at-a-glance "is this routine present
across these releases?" view.


I want to find duplicated code within a ROM
-------------------------------------------

``fantasm fingerprint`` divides the ROM into fixed-size blocks,
fingerprints each at the opcode level, and reports any duplicates —
a quick cross-check for relocated code or unused copies of a routine.

.. code-block:: bash

   uv run fantasm fingerprint 1.0
   uv run fantasm fingerprint 1.0 --block-size 32


I want to find code shared with another ROM
-------------------------------------------

``fantasm shared`` looks for matching opcode runs between a primary
ROM and one or more reference ROMs — useful for spotting utility
routines borrowed from sibling projects (a ROM borrowing from the
BBC MOS, or NFS sharing routines with ANFS).

.. code-block:: bash

   uv run fantasm shared \
       "myrom=versions/myrom-1.0/rom/myrom-1.0.rom@&8000" \
       "nfs=../acorn-nfs/versions/nfs-3.65/rom/nfs-3.65.rom@&8000" \
       "mos=/path/to/mos.rom@&C000" \
       --min-len 8

Specs use the form ``[label=]path@load-addr``. ``--min-len`` is the
minimum match length in instructions; the matcher reports the
longest matches first.


I want to promote auto-generated labels to entry points
-------------------------------------------------------

The disassembler emits anonymous labels like ``c8027`` / ``l8060``
for branch targets and JSR targets that don't have a name yet.
Turning the useful ones into proper ``subroutine()`` or ``entry()``
declarations is part of the annotation cycle.

``fantasm promote`` scores each auto-label (call count, after-
terminator-instruction position, JSR-vs-branch references) and
ranks them.

.. code-block:: bash

   uv run fantasm promote 1.0
   uv run fantasm promote 1.0 --not-declared       # only labels not yet declared

``fantasm labels classify`` puts each auto-label in a category
(``subroutine``, ``shared_tail``, ``data``, ``internal_loop``,
``internal_conditional``) so you can pick the right driver-API
primitive to declare it with.

``fantasm labels apply`` applies a TOML rename file to a driver
script — useful when you want to rename a batch of auto-labels in
one pass.


I want to extract a slice of the assembly listing
-------------------------------------------------

``fantasm asm extract`` pulls a section of the generated ``.asm``
file — by address range, by label, or both:

.. code-block:: bash

   uv run fantasm asm extract 1.0 0x8027            # 40 lines from address
   uv run fantasm asm extract 1.0 0x8027 0x8060     # explicit end address
   uv run fantasm asm extract 1.0 my_routine        # by label
   uv run fantasm asm extract 1.0 my_routine my_other_routine

Useful for pasting into bug reports or readouts.


I want to add a new subroutine declaration to a driver
------------------------------------------------------

Disassembly driver scripts conventionally keep their
``subroutine()`` declarations sorted by address.
``fantasm sub insert`` finds the right line to add a new one:

.. code-block:: bash

   uv run fantasm sub insert versions/myrom-1.0/disassemble/disasm_myrom_10.py 0x8027

The output names the predecessor and successor subroutines and the
exact line number where the new declaration should land.


Checking the project / CLI
--------------------------

* ``fantasm info`` — show the resolved project root, ``fantasm.toml``
  path, and the keys it read.
* ``fantasm project list`` — list every ROM version registered under
  ``versions/``.
* ``fantasm --help`` — top-level group; every sub-command has its
  own ``--help``.
* ``fantasm describe-formatter <NAME>`` and ``fantasm
  list-formatters`` — discover the available output formats (``--as
  display | tsv | json``); the output formatting is provided by
  `asyoulikeit`_.

.. _asyoulikeit: https://sixty-north.github.io/asyoulikeit/
