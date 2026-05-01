fantasm
=======

The Fantastic (dis-/re-)Assembly tools for 6502 code.

``fantasm`` is a Python library and CLI for working with annotated 6502
disassemblies. It consumes the JSON / ASM / driver-script artefacts a
py8dis run produces and exposes them through a coherent set of
sub-commands: round-trip verification, annotation linting, basic-block
and call-graph analysis, cross-version annotation diffing,
opcode-level address mapping between versions, and propagation of
annotations along a project's version DAG.

It is the consolidation of the per-project ``disasm_tools/`` packages
that used to live in `acorn-nfs`_, `acorn-adfs`_, `acorn-econet-bridge`_
and `acorn-6502-tube-client`_; the four siblings now depend on
``fantasm`` and the duplication is gone.

.. _acorn-nfs: https://github.com/acornaeology/acorn-nfs
.. _acorn-adfs: https://github.com/acornaeology/acorn-adfs
.. _acorn-econet-bridge: https://github.com/acornaeology/acorn-econet-bridge
.. _acorn-6502-tube-client: https://github.com/acornaeology/acorn-6502-tube-client


Where to start
--------------

* **Brand new to fantasm?** Read :doc:`getting_started`. It walks
  through the first hour: install, ``fantasm project init``, dropping
  in a py8dis driver, running the first ``disassemble`` /
  ``verify`` / ``lint`` cycle.

* **Setting up a new project's** ``fantasm.toml`` **?** See
  :doc:`configuration` for the full schema, then :doc:`version_graph`
  for the multi-version pieces (``[[versions.entry]]``, ``parents``,
  ``reloc_blocks``).

* **Asking "how do I X?"** Check :doc:`workflows` — recipe-style
  pages keyed on common questions (find missing comments, port
  annotations between versions, locate shared code with another ROM,
  …).

* **Reaching for the CLI reference?** :doc:`cli` is an exhaustive
  command-by-command listing, generated from the same Click
  definitions the binary uses, so it never goes stale.

* **Calling fantasm from your own Python code?** The :doc:`api` is
  the importable surface — every public symbol from
  ``fantasm.api.*``.


.. toctree::
   :maxdepth: 2
   :caption: Tutorial

   getting_started
   configuration
   version_graph
   workflows


.. toctree::
   :maxdepth: 2
   :caption: Reference

   cli
   api
   testing


.. toctree::
   :maxdepth: 1
   :caption: Project history

   internals/inventory
   internals/migration_readiness


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
