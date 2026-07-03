"""Accessors for the ``references`` field of a dasmos JSON item.

dasmos 2.0 (``meta.schema_version`` 2) changed each incoming
cross-reference from a bare ``int`` caller address to a structured
object::

    {"addr": int, "kind": str, "move_id": int?}

where ``kind`` is the ``ReferenceKind`` value (``direct`` / ``pointer``
/ ``indexed`` / ``indexed_pointer``) and ``move_id`` is present only
when non-zero. The pre-2.0 schema (through dasmos 1.14.0) emitted the
bare address instead.

These accessors read either shape so fantasm can consume JSON produced
by an old or new disassembler run without the caller having to branch
on ``meta.schema_version``.
"""

from __future__ import annotations

from collections.abc import Iterable

__all__ = ["reference_addr", "reference_addrs", "reference_kind"]


def reference_addr(ref: int | dict) -> int:
    """Return the caller runtime address of a single ``references`` entry.

    Accepts the dasmos >= 2.0 ``{"addr", "kind", "move_id"?}`` object or
    the pre-2.0 bare-int address.
    """
    return ref["addr"] if isinstance(ref, dict) else ref


def reference_addrs(refs: Iterable[int | dict] | None) -> list[int]:
    """Return the caller addresses of a whole ``references`` list.

    ``None`` (the field absent) yields an empty list.
    """
    if not refs:
        return []
    return [reference_addr(ref) for ref in refs]


def reference_kind(ref: int | dict) -> str | None:
    """Return the ``ReferenceKind`` of a ``references`` entry, if known.

    dasmos >= 2.0 objects carry a ``kind``; the pre-2.0 bare-int schema
    did not classify references, so this is ``None`` for those.
    """
    return ref.get("kind") if isinstance(ref, dict) else None
