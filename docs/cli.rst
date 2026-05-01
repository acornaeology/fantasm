CLI reference
=============

Every sub-command of the ``fantasm`` CLI, generated directly from
the Click definitions used by the binary so this page never goes
stale. Use it as a lookup; for narrative shape (when to reach for
which command), see :doc:`workflows`.

The top-level ``fantasm`` group accepts the universal options below;
each sub-command inherits them. Output-formatting options
(``--as``, ``--report``, ``--header``, ``--detailed``) come from
`asyoulikeit`_ — see its documentation for the cross-cutting
formatting controls.

.. _asyoulikeit: https://sixty-north.github.io/asyoulikeit/

.. click:: fantasm.cli:main
   :prog: fantasm
   :nested: full
