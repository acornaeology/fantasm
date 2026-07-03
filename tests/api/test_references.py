"""Accessors for the dasmos ``references`` field across schema versions.

dasmos 2.0 (``meta.schema_version`` 2) changed each incoming reference
from a bare-int caller address to a ``{"addr", "kind", "move_id"?}``
object; the accessors must read either shape.
"""

from __future__ import annotations

from fantasm.api.references import (
    reference_addr,
    reference_addrs,
    reference_kind,
)


class TestReferenceAddr:
    def test_reads_2_0_object(self) -> None:
        assert reference_addr({"addr": 0x8000, "kind": "direct"}) == 0x8000

    def test_reads_object_with_move_id(self) -> None:
        ref = {"addr": 0x0030, "kind": "indexed", "move_id": 1}
        assert reference_addr(ref) == 0x0030

    def test_reads_pre_2_0_bare_int(self) -> None:
        assert reference_addr(0x933E) == 0x933E


class TestReferenceAddrs:
    def test_mixed_and_ordered(self) -> None:
        refs = [
            {"addr": 0x8006, "kind": "direct"},
            {"addr": 0x8003, "kind": "indexed"},
        ]
        assert reference_addrs(refs) == [0x8006, 0x8003]

    def test_pre_2_0_list(self) -> None:
        assert reference_addrs([0x8000, 0x8100]) == [0x8000, 0x8100]

    def test_none_and_empty(self) -> None:
        assert reference_addrs(None) == []
        assert reference_addrs([]) == []


class TestReferenceKind:
    def test_object_kind(self) -> None:
        assert reference_kind({"addr": 1, "kind": "indexed_pointer"}) == (
            "indexed_pointer"
        )

    def test_bare_int_has_no_kind(self) -> None:
        assert reference_kind(0x8000) is None
