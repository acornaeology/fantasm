API reference
=============

Every public symbol fantasm exposes is re-exported from the top-level
``fantasm.api`` package, so ``from fantasm.api import
verify_round_trip, build_call_graph, …`` is the intended import
path. The per-module documentation below is for readers who want the
full picture.

The CLI surface is documented separately in :doc:`cli` and lives
under ``fantasm.cli`` (one module per command group); it is not
covered here.


Top-level package
-----------------

.. automodule:: fantasm.api
   :members:
   :imported-members:


6502 / 65C02 opcodes and mnemonics
----------------------------------

.. automodule:: fantasm.api.mos6502


Project paths and version directory layout
------------------------------------------

.. automodule:: fantasm.api.paths

.. automodule:: fantasm.config


Round-trip verification
-----------------------

.. automodule:: fantasm.api.verify


Subroutine audit and memory regions
-----------------------------------

.. automodule:: fantasm.api.audit


Comment-vs-code consistency checks
----------------------------------

.. automodule:: fantasm.api.comment_check


Comment suggestions
-------------------

.. automodule:: fantasm.api.suggest


Lint
----

.. automodule:: fantasm.api.lint


Call graph and basic blocks
---------------------------

.. automodule:: fantasm.api.cfg


Code context (depth, sub-context, uncommented gaps)
---------------------------------------------------

.. automodule:: fantasm.api.context


Auto-label classification and rename application
------------------------------------------------

.. automodule:: fantasm.api.labels

.. automodule:: fantasm.api.rename_labels


Subroutine-declaration insertion
--------------------------------

.. automodule:: fantasm.api.insert_point


Promotion candidates
--------------------

.. automodule:: fantasm.api.promote


ROM comparison
--------------

.. automodule:: fantasm.api.compare


Cross-version address mapping
-----------------------------

.. automodule:: fantasm.api.blockmatch


Fingerprinting (block-level deduplication)
------------------------------------------

.. automodule:: fantasm.api.fingerprint


Byte-signature search (literal + wildcard patterns)
---------------------------------------------------

.. automodule:: fantasm.api.bytes_search


Data-declaration review and heuristic classification
----------------------------------------------------

.. automodule:: fantasm.api.data_review


Print-inline hook discovery
---------------------------

.. automodule:: fantasm.api.hooks


Cross-ROM shared-code matching
------------------------------

.. automodule:: fantasm.api.find_shared


Annotation backfill across versions
-----------------------------------

.. automodule:: fantasm.api.backfill


Version graph (DAG) and chain composition
-----------------------------------------

.. automodule:: fantasm.api.version_graph


Assembly-source extraction
--------------------------

.. automodule:: fantasm.api.asm_extract


Project bootstrap (``fantasm project init`` / ``add`` / ``list``)
-----------------------------------------------------------------

.. automodule:: fantasm.api.project
