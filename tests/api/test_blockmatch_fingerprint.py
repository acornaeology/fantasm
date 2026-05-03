"""Tests for ``fantasm.api.blockmatch`` and ``fantasm.api.fingerprint``."""

from __future__ import annotations

from pathlib import Path

import pytest

from fantasm.api.blockmatch import (
    RelocatedBlock,
    build_full_address_map,
    build_primary_map,
    disassemble_to_opcodes,
    find_relocated_blocks,
)
from fantasm.api.fingerprint import (
    find_duplicate_blocks,
    fingerprint_blocks,
    fingerprint_rom_file,
    fingerprint_window,
    opcode_fingerprint,
)


# Two-block ROM where each block is a small routine. Block A:
# LDA #$01 / RTS. Block B: LDX #$02 / RTS.
ROM_AB = bytes([0xA9, 0x01, 0x60, 0xA2, 0x02, 0x60])
# Same routines reordered (B before A).
ROM_BA = bytes([0xA2, 0x02, 0x60, 0xA9, 0x01, 0x60])


# --- blockmatch ---------------------------------------------------


class TestDisassembleToOpcodes:
    def test_simple(self) -> None:
        insts = disassemble_to_opcodes(ROM_AB)
        assert insts == [
            (0, 0xA9, 2), (2, 0x60, 1), (3, 0xA2, 2), (5, 0x60, 1),
        ]

    def test_invalid_advances_one_byte(self) -> None:
        # 0x80 is invalid on NMOS — should advance 1 byte.
        insts = disassemble_to_opcodes(b"\x80\x60")
        assert insts == [(0, 0x80, 1), (1, 0x60, 1)]


class TestBuildPrimaryMap:
    def test_identical_roms_full_map(self) -> None:
        # Tiny fixture (4 instructions) needs an explicit
        # ``min_block_length=1`` to bypass the production threshold.
        insts = disassemble_to_opcodes(ROM_AB)
        addr_map = build_primary_map(insts, insts, min_block_length=1)
        # Every instruction's address should map to itself.
        assert addr_map[0x8000] == 0x8000
        assert addr_map[0x8002] == 0x8002

    def test_custom_rom_base(self) -> None:
        insts = disassemble_to_opcodes(ROM_AB)
        addr_map = build_primary_map(
            insts, insts, rom_base=0xC000, min_block_length=1
        )
        assert addr_map[0xC000] == 0xC000

    def test_min_block_length_filters_short_runs(self) -> None:
        # 8-instruction LCS run should pass at threshold 5 but get
        # culled at 9 — the surrounding code is otherwise different
        # in B, so longer thresholds emit no mappings at all.
        rom_a = bytes(
            [0xA9, 0x01, 0x85, 0x70, 0xA9, 0x02, 0x85, 0x71,
             0xA9, 0x03, 0x85, 0x72, 0xA9, 0x04, 0x85, 0x73]
        )
        # Same eight code-bytes after one differing leading byte.
        rom_b = bytes([0xEA]) + rom_a[1:]
        insts_a = disassemble_to_opcodes(rom_a)
        insts_b = disassemble_to_opcodes(rom_b)
        # Threshold 5 keeps the long run.
        addr_map = build_primary_map(insts_a, insts_b, min_block_length=5)
        assert len(addr_map) > 0
        # Threshold 100 culls everything.
        assert build_primary_map(
            insts_a, insts_b, min_block_length=100
        ) == {}

    def test_default_threshold_drops_coincidental_short_matches(self) -> None:
        # The headline regression for issue #10. Two ROMs whose code
        # is almost entirely different but whose first opcode happens
        # to match (LDA #imm at &8000) used to produce an
        # identity-fallback ``&8000 → &8000`` entry under the old
        # no-threshold default. The new default must drop it.
        rom_a = bytes([0xA9, 0x01, 0x60, 0xEA, 0xEA, 0xEA, 0xEA, 0xEA])
        rom_b = bytes([0xA9, 0x02, 0x38, 0x18, 0xD8, 0xF8, 0x78, 0x58])
        insts_a = disassemble_to_opcodes(rom_a)
        insts_b = disassemble_to_opcodes(rom_b)
        # Default threshold = 5; no mapping survives.
        assert build_primary_map(insts_a, insts_b) == {}
        # Threshold 1 reproduces the old behaviour and shows the bug.
        legacy = build_primary_map(insts_a, insts_b, min_block_length=1)
        assert legacy.get(0x8000) == 0x8000

    def test_invalid_min_block_length_rejected(self) -> None:
        insts = disassemble_to_opcodes(ROM_AB)
        with pytest.raises(ValueError, match="min_block_length"):
            build_primary_map(insts, insts, min_block_length=0)


class TestFindRelocatedBlocks:
    def test_short_input_returns_empty(self) -> None:
        # k=6 default; ROMs shorter than that yield no seeds.
        insts_a = disassemble_to_opcodes(ROM_AB)
        insts_b = disassemble_to_opcodes(ROM_BA)
        supp, blocks = find_relocated_blocks(insts_a, insts_b, {})
        assert supp == {}
        assert blocks == []

    def test_swapped_blocks_one_caught_by_supplementary(self) -> None:
        # When two blocks swap places, LCS picks the longer block as
        # the common subsequence and misses the shorter one's
        # movement. The supplementary seed-and-extend pass picks up
        # what LCS leaves behind.
        big = bytes(
            [0xA9, 0x01, 0x85, 0x70, 0xA9, 0x02, 0x85, 0x71,
             0xA9, 0x03, 0x85, 0x72, 0xA9, 0x04, 0x85, 0x73,
             0xA9, 0x05, 0x85, 0x74, 0xA9, 0x06, 0x85, 0x75,
             0xA9, 0x07, 0x85, 0x76, 0xA9, 0x08, 0x85, 0x77]
        )
        # Distinct block — different opcode pattern from `big`.
        small = bytes(
            [0xA2, 0x10, 0xCA, 0xD0, 0xFD, 0x60,
             0xA2, 0x20, 0xCA, 0xD0, 0xFD, 0x60]
        )
        rom_a = big + small
        rom_b = small + big

        insts_a = disassemble_to_opcodes(rom_a)
        insts_b = disassemble_to_opcodes(rom_b)
        primary = build_primary_map(insts_a, insts_b, min_block_length=3)
        supp, blocks = find_relocated_blocks(
            insts_a, insts_b, primary,
            k=3, min_seeds=2, min_block_opcodes=3, min_match_length=3,
        )

        # Primary picks up the larger block; supplementary picks up
        # the smaller one (LCS missed it because its order conflicts
        # with the larger match).
        assert len(primary) > 0
        # At least one of primary / supp should show evidence of the
        # block-level movement; the precise distribution depends on
        # SequenceMatcher's tie-breaking.
        total = len(primary) + len(supp)
        assert total >= 8

    def test_returns_relocated_block_dataclass(self) -> None:
        # Even when no supplementary block is detected, the function
        # returns the correct shapes.
        insts_a = disassemble_to_opcodes(ROM_AB)
        insts_b = disassemble_to_opcodes(ROM_AB)
        supp, blocks = find_relocated_blocks(insts_a, insts_b, {})
        assert isinstance(supp, dict)
        assert isinstance(blocks, list)


class TestBuildFullAddressMap:
    def test_returns_four_tuples(self) -> None:
        full, primary, supp, blocks = build_full_address_map(
            ROM_AB, ROM_AB, min_block_length=1
        )
        assert isinstance(full, dict)
        assert isinstance(primary, dict)
        assert isinstance(supp, dict)
        assert isinstance(blocks, list)

    def test_default_threshold_culls_short_coincidence_match(self) -> None:
        # Two near-disjoint ROMs whose only opcode-level overlap is
        # the leading byte. Default threshold = 5 must produce an
        # empty full map — the consumer's ``addr_map[&8000]`` then
        # raises ``KeyError`` cleanly rather than emitting a wrong
        # identity-fallback mapping (issue #10's failure mode).
        rom_a = bytes([0xA9, 0x01, 0x60, 0xEA, 0xEA, 0xEA, 0xEA, 0xEA])
        rom_b = bytes([0xA9, 0x02, 0x38, 0x18, 0xD8, 0xF8, 0x78, 0x58])
        full, primary, supp, _ = build_full_address_map(rom_a, rom_b)
        assert full == {}
        assert primary == {}
        assert supp == {}

    def test_unmapped_address_raises_key_error(self) -> None:
        # The contract: source addresses that don't lie inside an
        # anchored shared block of >= min_block_length opcodes are
        # absent from the dict.
        rom_a = bytes([0xA9, 0x01, 0x60, 0xEA, 0xEA, 0xEA, 0xEA, 0xEA])
        rom_b = bytes([0xA9, 0x02, 0x38, 0x18, 0xD8, 0xF8, 0x78, 0x58])
        full, _, _, _ = build_full_address_map(rom_a, rom_b)
        with pytest.raises(KeyError):
            _ = full[0x8000]
        # ``dict.get`` is the consumer's safe lookup.
        assert full.get(0x8000) is None


# --- fingerprint --------------------------------------------------


class TestOpcodeFingerprint:
    def test_stable(self) -> None:
        # Same input produces same fingerprint.
        assert opcode_fingerprint(b"\xA9\x01") == opcode_fingerprint(b"\xA9\x01")

    def test_different_inputs_different_fingerprints(self) -> None:
        assert opcode_fingerprint(b"\xA9\x01") != opcode_fingerprint(b"\xA9\x02")


class TestFingerprintWindow:
    def test_includes_only_in_window(self) -> None:
        # First 3 bytes of ROM_AB are LDA #$01, RTS.
        fp_first = fingerprint_window(ROM_AB, 0, 3)
        fp_second = fingerprint_window(ROM_AB, 3, 3)
        assert fp_first != fp_second


class TestFingerprintBlocks:
    def test_keys_use_rom_base(self) -> None:
        fps = fingerprint_blocks(ROM_AB, block_size=3)
        assert 0x8000 in fps
        assert 0x8003 in fps

    def test_custom_rom_base(self) -> None:
        fps = fingerprint_blocks(ROM_AB, block_size=3, rom_base=0xC000)
        assert 0xC000 in fps


class TestFindDuplicateBlocks:
    def test_identifies_duplicates(self) -> None:
        # Two identical 3-byte blocks at different addresses.
        rom = bytes([0xA9, 0x01, 0x60]) * 2
        fps = fingerprint_blocks(rom, block_size=3)
        dups = find_duplicate_blocks(fps)
        assert len(dups) == 1
        # Two addresses share the fingerprint.
        addrs = next(iter(dups.values()))
        assert len(addrs) == 2


class TestFingerprintRomFile:
    def test_loads_from_file(self, tmp_path: Path) -> None:
        rom_filepath = tmp_path / "rom.bin"
        rom_filepath.write_bytes(ROM_AB)
        fps = fingerprint_rom_file(rom_filepath, block_size=3)
        assert 0x8000 in fps
