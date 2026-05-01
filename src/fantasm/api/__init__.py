"""Programmatic API for fantasm.

Sub-modules will hold per-topic surfaces (labels, comments, cfg, audit, ...).
This package re-exports the stable, flat surface so callers can do either:

    from fantasm.api import rename_labels
    from fantasm.api.labels import rename_labels

The flat re-exports are populated as topics are ported in from the sibling
``disasm_tools`` packages.
"""

from __future__ import annotations

__all__: list[str] = []
