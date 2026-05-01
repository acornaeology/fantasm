The version graph
==================

A ROM's history is rarely a clean linear sequence of releases: chains
fork, side-branches diverge, regional variants pick up patches in a
different order. Most analysis questions become tractable only when
fantasm knows the topology — "show me what changed between A and B"
needs to know how A and B are connected; "propagate this annotation
forward" needs a path to walk.

fantasm models this with a **directed acyclic graph** of versions.
Each version is a node; ``parents`` lists declare edges from older to
newer. The graph lives in ``fantasm.toml`` as a sequence of
``[[versions.entry]]`` blocks — see :doc:`configuration` for the
schema. This page describes what the graph is *for*.


Why a DAG, not a chain
----------------------

A linear chain only handles the simple case. Real firmware:

* **Forks** — a regional variant or experimental branch leaves the
  main line and never rejoins. ``3.34B-japan`` descends from
  ``3.34B`` but doesn't show up in later mainline versions.
* **Merges** — fixes from a side-branch make it back into a later
  mainline release. ``3.40`` might inherit from both ``3.35K`` (the
  main line) and ``3.34B-japan`` (the regional branch).
* **Roots** — sometimes the lineage is genuinely unknown ("we found
  this ROM on a 5.25-inch disk, ancestry TBD"). Roots are a perfectly
  valid graph state.

A DAG admits all of these without contortion. fantasm rejects cycles
at config-load time (``VersionGraphCycleError``), so the
"D" — directed and acyclic — is enforced.


Path-finding and walked direction
---------------------------------

``VersionGraph.find_path(source, target)`` returns a list of edges
forming the shortest path between two versions in the **undirected
projection** of the DAG. Each edge carries:

* ``parent_id`` — the older end of the underlying directed edge;
* ``child_id`` — the newer end;
* ``walked_forward`` — ``True`` when the path traverses the edge in
  the parent → child direction, ``False`` when going against the
  arrow.

That distinction matters because the per-edge analyses fantasm builds
on top (most importantly ``compose_chained_map``) are direction-aware.
A confidence map built parent → child can be inverted on the fly when
the path traverses backward, so you can ask "annotations from 3.62
applied to 3.34" and fantasm walks 3.62 → 3.60 → 3.40 → 3.35K → 3.35D
→ 3.34B → 3.34, inverting each forward-built map as needed.

If no path exists between source and target — disconnected components,
say, or a still-unplaced root — the path lookup raises
``NoPathError`` with both ids attached.


Reloc blocks across edges
-------------------------

NFS-style firmware copies blocks of code from ROM into RAM at
runtime, then jumps there. The ROM-resident **source** addresses
shift as the rest of the ROM grows and shrinks across releases, but
the runtime **dest** addresses (and the block lengths) stay stable —
they're properties of the project's memory map, not of any one
version.

fantasm uses that stability to match reloc blocks across an edge.
``VersionGraph.reloc_pairs_for_edge(edge)`` walks the parent's and
child's ``reloc_blocks`` lists and pairs them off by ``(dest,
length)``, returning ``(src_parent, src_child, dest, length)`` tuples
the address-mapping primitives consume.

When a version's ``reloc_blocks`` ``dest`` and ``length`` differ
across versions (rare but possible — a project might widen or move a
workspace page in a release), the block is silently dropped from the
edge's pair list: it can't contribute to opcode matching anyway. The
matched pairs sort by parent source address for determinism.

The lone version's reloc destinations are also auto-merged into its
**effective regions**: a block at ``dest=0x0400, length=0x100`` makes
``0x0400-0x04FF`` part of that version's workspace as far as audit,
lint, and comment_check are concerned. You don't have to repeat the
range under ``[memory] regions``; just declare the reloc block once.


Composing maps along a path
---------------------------

The high-value primitive is ``compose_chained_map``, exposed both as
``fantasm.api.version_graph.compose_chained_map`` and through the
``fantasm backfill`` and ``fantasm annotations diff`` CLI commands.

For each edge on the path it builds a per-hop **confidence map** —
``{parent_addr: (child_addr, block_length)}`` — by running an
opcode-level Longest Common Subsequence between the two ROMs (with
the relocated blocks matched separately at their runtime
destinations). It then composes the maps end-to-end with
**min-confidence**: the composed block_length is the smallest value
seen along the path, because the chain is only as strong as its
weakest link.

Practical consequences:

* **Annotations propagate cleanly through unchanged stretches.** A
  16-instruction routine that's untouched across five releases will
  compose to a confidence-16 map across all five hops — a label or
  comment placed at the parent end maps cleanly to the corresponding
  child address.
* **Refactored stretches drop in confidence.** A routine where
  release N rearranged six instructions still maps, but its composed
  block_length drops to whatever the smallest matching run was on the
  refactored hop. ``--threshold`` on ``backfill`` lets callers
  reject low-confidence propagations.
* **Disconnected addresses simply don't appear.** If an address
  doesn't compose through every hop on the path, it's absent from the
  result — ``backfill`` reports those as ``skipped: no-mapping``.


Common shapes
-------------

A linear chain
~~~~~~~~~~~~~~

The simplest case. Each version has one parent, the previous release.

.. code-block:: text

   [[versions.entry]]
   id = "3.34"
   reloc_blocks = [...]

   [[versions.entry]]
   id = "3.34B"
   parents = ["3.34"]
   reloc_blocks = [...]

   [[versions.entry]]
   id = "3.35D"
   parents = ["3.34B"]
   reloc_blocks = [...]

A linear chain handles "I want every comment from 3.34 propagated to
3.35D" perfectly: the path is two hops, both walked forward.

A fork with a branch
~~~~~~~~~~~~~~~~~~~~

Side-branch picks up where the mainline diverged.

.. code-block:: toml

   [[versions.entry]]
   id = "3.34B"
   parents = ["3.34"]

   [[versions.entry]]
   id = "3.34B-japan"
   parents = ["3.34B"]
   notes = "Japanese keyboard handling diverged at 3.34B"

   [[versions.entry]]
   id = "3.35D"
   parents = ["3.34B"]

``3.34B-japan`` and ``3.35D`` are siblings; a path between them goes
``3.34B-japan`` → ``3.34B`` (backward) → ``3.35D`` (forward). The
backward walk inverts the canonical map automatically.

A merged version
~~~~~~~~~~~~~~~~

Multiple parents.

.. code-block:: toml

   [[versions.entry]]
   id = "3.40"
   parents = ["3.35K", "3.34B-japan"]

A merge reflects "this release pulled in fixes from both lines".
Path-finding picks the shortest route through one of the parent
edges; the other parent only matters if you specifically ask for the
disconnected-from-3.35K side.

A separate root
~~~~~~~~~~~~~~~

Versions whose ancestry isn't yet placed.

.. code-block:: toml

   [[versions.entry]]
   id = "mystery-anfs"
   notes = "Found on a 5.25\" disk; ancestry TBD pending opcode analysis"
   reloc_blocks = []

The graph happily holds disconnected components. ``find_path`` to or
from one will fail with ``NoPathError`` until the lineage is added —
which is the right behaviour: better an explicit error than a
silently-empty result.


Discovering the structure
-------------------------

Two CLI commands are the everyday windows into the graph:

* ``fantasm addresses map A B`` shows the opcode-level address
  mapping between any two versions, computed via
  ``compose_chained_map``. Useful for "I have an address in 3.34;
  where does it land in 3.65?".
* ``fantasm backfill A B`` proposes annotation propagations from
  ``A`` to ``B`` by walking the path between them and reading the
  source driver script. The companion ``fantasm annotations diff``
  reports source-side annotations whose mapped target is missing,
  differs, or can't be reached.

Both commands take ``--threshold`` to drop low-confidence
propagations and ``--cpu`` / ``--rom-base`` to override the project
defaults from ``fantasm.toml``.


Programmatic surface
--------------------

For Python callers, ``fantasm.api.version_graph`` exposes:

* :func:`~fantasm.api.version_graph.load_version_graph` —
  read ``fantasm.toml`` into a graph;
* :class:`~fantasm.api.version_graph.VersionGraph` — the graph itself;
* :meth:`~fantasm.api.version_graph.VersionGraph.find_path`,
  :meth:`~fantasm.api.version_graph.VersionGraph.effective_regions`,
  :meth:`~fantasm.api.version_graph.VersionGraph.effective_external_regions`,
  :meth:`~fantasm.api.version_graph.VersionGraph.reloc_pairs_for_edge`,
  :meth:`~fantasm.api.version_graph.VersionGraph.get`;
* :func:`~fantasm.api.version_graph.compose_chained_map` for the
  per-edge composition;
* exceptions
  :class:`~fantasm.api.version_graph.VersionGraphError`,
  :class:`~fantasm.api.version_graph.VersionNotInGraphError`,
  :class:`~fantasm.api.version_graph.NoPathError`,
  :class:`~fantasm.api.version_graph.VersionGraphCycleError`.

See :doc:`api` for the full reference.
