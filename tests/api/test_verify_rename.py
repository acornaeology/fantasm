"""Tests for ``fantasm.api.verify`` and ``fantasm.api.rename_labels``."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from fantasm.api.rename_labels import (
    LABEL_RE,
    apply_renames_to_lines,
    find_insert_position,
    find_rename_section,
    parse_label_declarations,
)
from fantasm.api.verify import (
    BeebasmNotFoundError,
    VerifyResult,
    verify_round_trip,
)


# --- rename_labels -------------------------------------------------


SAMPLE_DRIVER_LINES = [
    "import py8dis\n",
    "\n",
    "# =================== Subroutines ===================\n",
    'subroutine(0x8000, "init")\n',
    "\n",
    "# Code label renames\n",
    'label(0x8010, "first")\n',
    'label(0x8020, "second")\n',
    'label(0x8030, "third")\n',
    "\n",
    "# =================== End ===================\n",
    "tail()\n",
]


class TestParseLabelDeclarations:
    def test_finds_labels(self) -> None:
        decls = parse_label_declarations(SAMPLE_DRIVER_LINES)
        assert [(d["addr"], d["name"]) for d in decls] == [
            (0x8010, "first"),
            (0x8020, "second"),
            (0x8030, "third"),
        ]

    def test_ignores_subroutine(self) -> None:
        # subroutine(0x8000, ...) shouldn't match LABEL_RE.
        decls = parse_label_declarations(SAMPLE_DRIVER_LINES)
        assert all(d["addr"] != 0x8000 for d in decls)


class TestFindRenameSection:
    def test_finds_section(self) -> None:
        start, end = find_rename_section(SAMPLE_DRIVER_LINES)
        assert start is not None
        assert end is not None
        assert SAMPLE_DRIVER_LINES[start].startswith("# Code label renames")
        # Ends before the next === separator.
        assert SAMPLE_DRIVER_LINES[end + 1].startswith(
            "# =================== End"
        )

    def test_missing_section(self) -> None:
        start, end = find_rename_section(["import py8dis\n", "tail()\n"])
        assert start is None
        assert end is None


class TestFindInsertPosition:
    def test_inserts_in_address_order(self) -> None:
        start, end = find_rename_section(SAMPLE_DRIVER_LINES)
        assert start is not None and end is not None
        # 0x8025 should slot between 0x8020 and 0x8030.
        pos = find_insert_position(
            SAMPLE_DRIVER_LINES, start, end, 0x8025
        )
        assert SAMPLE_DRIVER_LINES[pos].strip() == 'label(0x8030, "third")'

    def test_after_last(self) -> None:
        start, end = find_rename_section(SAMPLE_DRIVER_LINES)
        assert start is not None and end is not None
        pos = find_insert_position(SAMPLE_DRIVER_LINES, start, end, 0x9000)
        assert pos == end + 1


class TestApplyRenamesToLines:
    def test_updates_existing(self) -> None:
        out = apply_renames_to_lines(
            SAMPLE_DRIVER_LINES, {0x8020: "renamed_second"}
        )
        rejoined = "".join(out)
        assert 'label(0x8020, "renamed_second")' in rejoined
        # The sibling line for 0x8010 / 0x8030 is unchanged.
        assert 'label(0x8010, "first")' in rejoined
        assert 'label(0x8030, "third")' in rejoined

    def test_inserts_new_in_order(self) -> None:
        out = apply_renames_to_lines(
            SAMPLE_DRIVER_LINES, {0x8025: "between"}
        )
        # Find the new line; it should sit between 0x8020 and 0x8030.
        lines_only_with_labels = [
            line.strip() for line in out if LABEL_RE.match(line)
        ]
        assert lines_only_with_labels == [
            'label(0x8010, "first")',
            'label(0x8020, "second")',
            'label(0x8025, "between")',
            'label(0x8030, "third")',
        ]

    def test_missing_section_raises(self) -> None:
        with pytest.raises(LookupError, match="no '# Code label renames'"):
            apply_renames_to_lines(["import py8dis\n"], {0x8000: "x"})

    def test_does_not_mutate_input(self) -> None:
        copy = list(SAMPLE_DRIVER_LINES)
        apply_renames_to_lines(SAMPLE_DRIVER_LINES, {0x8020: "x"})
        assert SAMPLE_DRIVER_LINES == copy

    def test_multiple_edits_independent(self) -> None:
        out = apply_renames_to_lines(
            SAMPLE_DRIVER_LINES,
            {0x8025: "new_between", 0x8020: "renamed"},
        )
        rejoined = "".join(out)
        assert 'label(0x8020, "renamed")' in rejoined
        assert 'label(0x8025, "new_between")' in rejoined


# --- verify --------------------------------------------------------


class TestVerifyRoundTripErrors:
    def test_missing_rom_raises(self, tmp_path: Path) -> None:
        asm_filepath = tmp_path / "out.asm"
        asm_filepath.write_text("ORG &8000\nRTS\n")
        with pytest.raises(FileNotFoundError, match="ROM"):
            verify_round_trip(
                tmp_path / "missing.rom", asm_filepath, beebasm_filepath="/bin/echo"
            )

    def test_missing_asm_raises(self, tmp_path: Path) -> None:
        rom_filepath = tmp_path / "rom.bin"
        rom_filepath.write_bytes(b"\x00")
        with pytest.raises(FileNotFoundError, match="assembly"):
            verify_round_trip(
                rom_filepath, tmp_path / "missing.asm", beebasm_filepath="/bin/echo"
            )

    def test_missing_beebasm_raises(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        rom_filepath = tmp_path / "rom.bin"
        asm_filepath = tmp_path / "out.asm"
        rom_filepath.write_bytes(b"")
        asm_filepath.write_text("")
        # Force shutil.which to return None.
        monkeypatch.setattr("shutil.which", lambda _name: None)
        with pytest.raises(BeebasmNotFoundError):
            verify_round_trip(rom_filepath, asm_filepath)


class TestVerifyResultDataclass:
    def test_fields_are_frozen(self) -> None:
        result = VerifyResult(
            matched=True,
            rom_size=1,
            assembled_size=1,
            first_diff_offset=None,
            beebasm_returncode=0,
            beebasm_stderr="",
        )
        with pytest.raises(Exception):
            result.matched = False  # type: ignore[misc]


# Real round-trip integration tests against beebasm will land once
# we have ROM fixtures under tests/data/. Production code is exercised
# by the missing-file/missing-beebasm error paths above.
