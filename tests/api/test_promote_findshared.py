"""Tests for ``fantasm.api.promote`` and ``fantasm.api.find_shared``."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from fantasm.api.find_shared import (
    Instruction,
    RomData,
    find_matching_spans,
    is_trivial_span,
    load_rom,
    matching_byte_count,
    parse_rom_spec,
    sweep_opcodes,
)
from fantasm.api.promote import (
    CALL_MNEMONICS,
    TERMINAL_MNEMONICS,
    analyze_labels,
    load_and_analyze_labels,
)


# --- promote -------------------------------------------------------


def _promote_data() -> dict:
    """Synthesize a small JSON data structure for promote tests."""
    return {
        "items": [
            # 0x8000: routine_a, called from 0x8100 and 0x8200 (JSR)
            {
                "addr": 0x8000,
                "type": "code",
                "mnemonic": "lda",
                "operand": "#0",
                "labels": ["routine_a"],
            },
            {"addr": 0x8002, "type": "code", "mnemonic": "rts"},
            # 0x8003: labelled but immediately follows non-terminal,
            # only one branch ref
            {
                "addr": 0x8003,
                "type": "code",
                "mnemonic": "lda",
                "operand": "#1",
                "labels": ["fall_through_target"],
            },
            {"addr": 0x8005, "type": "code", "mnemonic": "rts"},
            # JSR routine_a from far away.
            {
                "addr": 0x8100,
                "type": "code",
                "mnemonic": "jsr",
                "target": 0x8000,
            },
            {
                "addr": 0x8200,
                "type": "code",
                "mnemonic": "jsr",
                "target": 0x8000,
            },
            # Branch to fall_through_target.
            {
                "addr": 0x8002,
                "type": "code",
                "mnemonic": "bne",
                "target": 0x8003,
            },
        ],
        "subroutines": [],
    }


class TestAnalyzeLabels:
    def test_finds_strong_promotion_candidate(self) -> None:
        candidates = analyze_labels(_promote_data())
        names = [c["name"] for c in candidates]
        assert "routine_a" in names
        routine_a = next(c for c in candidates if c["name"] == "routine_a")
        # routine_a is after_terminal (the rts-then-routine pattern)
        # AND has 2+ JSR refs => strong score
        assert routine_a["after_terminal"] is False  # nothing precedes 0x8000
        # Still has refs from JSRs.
        assert routine_a["jsr_refs"] >= 2

    def test_sorted_by_score_descending(self) -> None:
        candidates = analyze_labels(_promote_data())
        scores = [c["score"] for c in candidates]
        assert scores == sorted(scores, reverse=True)

    def test_skips_unlabelled(self) -> None:
        # Items without "labels" should not appear.
        data = {
            "items": [
                {"addr": 0x8000, "type": "code", "mnemonic": "rts"},
            ],
            "subroutines": [],
        }
        assert analyze_labels(data) == []

    def test_marks_subroutine_when_already_declared(self) -> None:
        data = {
            "items": [
                {
                    "addr": 0x8000,
                    "type": "code",
                    "mnemonic": "rts",
                    "labels": ["foo"],
                },
            ],
            "subroutines": [{"addr": 0x8000}],
        }
        candidates = analyze_labels(data)
        assert candidates[0]["is_subroutine"] is True

    def test_load_and_analyze_labels(self, tmp_path: Path) -> None:
        json_filepath = tmp_path / "out.json"
        json_filepath.write_text(json.dumps(_promote_data()))
        candidates = load_and_analyze_labels(json_filepath)
        assert len(candidates) >= 1


def test_promote_constants_consistent() -> None:
    assert "rts" in TERMINAL_MNEMONICS
    assert "jsr" in CALL_MNEMONICS
    # JMP appears in BOTH (terminating control flow AND a call).
    assert "jmp" in TERMINAL_MNEMONICS
    assert "jmp" in CALL_MNEMONICS


# --- find_shared --------------------------------------------------


class TestSweepOpcodes:
    def test_simple(self) -> None:
        # LDA #$01 / RTS
        data = bytes([0xA9, 0x01, 0x60])
        instructions, opcodes = sweep_opcodes(data)
        assert opcodes == [0xA9, 0x60]
        assert instructions[0].length == 2
        assert instructions[1].length == 1

    def test_invalid_advances_one(self) -> None:
        # 0x80 is invalid on NMOS; sweep advances one byte.
        instructions, opcodes = sweep_opcodes(b"\x80\x60")
        assert opcodes == [0x80, 0x60]
        assert instructions[0].length == 1


class TestIsTrivialSpan:
    def test_runs_of_padding_are_trivial(self) -> None:
        opcodes = [0xFF] * 10
        assert is_trivial_span(opcodes, 0, 10) is True

    def test_three_distinct_opcodes_not_trivial(self) -> None:
        opcodes = [0xA9, 0x85, 0x60, 0xA9, 0x85]
        assert is_trivial_span(opcodes, 0, 5) is False


class TestFindMatchingSpans:
    def test_identical_roms(self) -> None:
        data = bytes([0xA9, 0x01, 0x85, 0x70, 0xA9, 0x02, 0x85, 0x71, 0x60])
        primary = load_rom("a", _write_rom(data), 0x8000)
        reference = load_rom("b", _write_rom(data), 0x8000)
        spans = find_matching_spans(primary, reference, min_len=3)
        assert len(spans) >= 1

    def test_no_overlap_yields_no_spans(self) -> None:
        a = bytes([0xA9, 0x01, 0x85, 0x70, 0x60])
        b = bytes([0xA2, 0x01, 0x86, 0x71, 0x60])
        primary = load_rom("a", _write_rom(a), 0x8000)
        reference = load_rom("b", _write_rom(b), 0x8000)
        spans = find_matching_spans(primary, reference, min_len=3)
        assert spans == []

    def test_min_len_filter(self) -> None:
        data = bytes([0xA9, 0x01, 0x60])
        primary = load_rom("a", _write_rom(data), 0x8000)
        reference = load_rom("b", _write_rom(data), 0x8000)
        # min_len higher than the longest matching block.
        assert find_matching_spans(primary, reference, min_len=10) == []


class TestMatchingByteCount:
    def test_sums_instruction_lengths(self) -> None:
        # 4-instruction block, each 2 bytes long => 8 bytes total.
        data = bytes([0xA9, 0x01, 0x85, 0x70, 0xA9, 0x02, 0x85, 0x71])
        primary = load_rom("a", _write_rom(data), 0x8000)
        # match the first 4 instructions
        matches = [(0, 0, 4)]
        assert matching_byte_count(primary, matches) == 8


class TestParseRomSpec:
    def test_with_label(self, tmp_path: Path) -> None:
        rom_filepath = tmp_path / "test.rom"
        rom_filepath.write_bytes(b"\x60")
        label, path, addr = parse_rom_spec(f"foo={rom_filepath}@&E000")
        assert label == "foo"
        assert path == rom_filepath
        assert addr == 0xE000

    def test_default_label_is_filename_stem(self, tmp_path: Path) -> None:
        rom_filepath = tmp_path / "test.rom"
        rom_filepath.write_bytes(b"\x60")
        label, _, _ = parse_rom_spec(f"{rom_filepath}@0x8000")
        assert label == "test"

    def test_decimal_address(self, tmp_path: Path) -> None:
        # Address is parsed as hex; "8000" becomes 0x8000.
        rom_filepath = tmp_path / "test.rom"
        rom_filepath.write_bytes(b"\x60")
        _, _, addr = parse_rom_spec(f"{rom_filepath}@8000")
        assert addr == 0x8000

    def test_missing_at_raises(self, tmp_path: Path) -> None:
        rom_filepath = tmp_path / "test.rom"
        rom_filepath.write_bytes(b"\x60")
        with pytest.raises(ValueError, match="@"):
            parse_rom_spec(str(rom_filepath))

    def test_missing_file_raises(self) -> None:
        with pytest.raises(FileNotFoundError):
            parse_rom_spec("/nonexistent/rom.bin@0x8000")


def _write_rom(data: bytes) -> Path:
    """Helper: write data to a temp file and return its path."""
    import tempfile
    tmp = tempfile.NamedTemporaryFile(suffix=".rom", delete=False)
    tmp.write(data)
    tmp.close()
    return Path(tmp.name)
