"""Tests for ``fantasm bytes find``."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from fantasm.cli import main

from ._helpers import add_version, init_project


def _setup_with_rom(
    tmp_path: Path, version_id: str, rom_bytes: bytes, prefix: str = "demo"
) -> CliRunner:
    """Boot a demo project and write ``rom_bytes`` for ``version_id``."""
    runner = CliRunner()
    init_project(tmp_path, runner, prefix, prefix)
    add_version(tmp_path, runner, version_id, prefix)

    rom_filepath = (
        tmp_path / "versions" / f"{prefix}-{version_id}"
        / "rom" / f"{prefix}-{version_id}.rom"
    )
    rom_filepath.parent.mkdir(parents=True, exist_ok=True)
    rom_filepath.write_bytes(rom_bytes)
    return runner


def test_bytes_find_literal_match(tmp_path: Path) -> None:
    runner = _setup_with_rom(
        tmp_path,
        version_id="1.0",
        rom_bytes=bytes.fromhex("00 4C B9 FF 00 00".replace(" ", "")),
    )
    result = runner.invoke(
        main,
        ["--project-root", str(tmp_path),
         "bytes", "find", "1.0", "4C B9 FF",
         "--report", "matches", "--as", "tsv"],
    )
    assert result.exit_code == 0, result.output
    # Default rom_base is 0x8000; offset 1 → addr &8001.
    assert "&8001" in result.output


def test_bytes_find_with_wildcards_emits_captures_column(
    tmp_path: Path,
) -> None:
    runner = _setup_with_rom(
        tmp_path,
        version_id="1.0",
        rom_bytes=bytes.fromhex("4C B9 FF AA 4C 12 FF"),
    )
    result = runner.invoke(
        main,
        ["--project-root", str(tmp_path),
         "bytes", "find", "1.0", "4C ?? FF",
         "--report", "matches", "--as", "tsv"],
    )
    assert result.exit_code == 0, result.output
    # The captures column appears (header label "Captures") and the
    # captured wildcard bytes show up.
    assert "Captures" in result.output
    assert "[B9]" in result.output
    assert "[12]" in result.output


def test_bytes_find_pure_literal_omits_captures_column(
    tmp_path: Path,
) -> None:
    runner = _setup_with_rom(
        tmp_path,
        version_id="1.0",
        rom_bytes=bytes.fromhex("4C B9 FF AA"),
    )
    result = runner.invoke(
        main,
        ["--project-root", str(tmp_path),
         "bytes", "find", "1.0", "4C B9 FF",
         "--report", "matches", "--as", "tsv"],
    )
    assert result.exit_code == 0, result.output
    # No wildcards → no Captures column.
    assert "Captures" not in result.output


def test_bytes_find_cross_versions(tmp_path: Path) -> None:
    runner = _setup_with_rom(
        tmp_path,
        version_id="1.0",
        rom_bytes=bytes.fromhex("4C B9 FF AA"),
    )
    add_version(tmp_path, runner, "2.0", "demo")
    rom2 = tmp_path / "versions" / "demo-2.0" / "rom" / "demo-2.0.rom"
    rom2.parent.mkdir(parents=True, exist_ok=True)
    # 2.0 lacks the pattern entirely — the "GONE in next version" case.
    rom2.write_bytes(bytes.fromhex("AA AA AA AA"))

    result = runner.invoke(
        main,
        ["--project-root", str(tmp_path),
         "bytes", "find", "1.0", "4C B9 FF",
         "--cross", "2.0",
         "--report", "summary", "--as", "tsv"],
    )
    assert result.exit_code == 0, result.output
    # Both versions appear in the summary; 2.0 has zero matches.
    assert "1.0" in result.output
    assert "2.0" in result.output
    # The dash-marker for "no matches" appears for 2.0.
    assert "—" in result.output


def test_bytes_find_invalid_pattern(tmp_path: Path) -> None:
    runner = _setup_with_rom(
        tmp_path,
        version_id="1.0",
        rom_bytes=b"\x00",
    )
    result = runner.invoke(
        main,
        ["--project-root", str(tmp_path),
         "bytes", "find", "1.0", "ZZ"],
    )
    assert result.exit_code != 0
    assert "invalid hex" in result.output


def test_bytes_find_missing_rom(tmp_path: Path) -> None:
    runner = CliRunner()
    init_project(tmp_path, runner, "demo", "demo")
    add_version(tmp_path, runner, "1.0", "demo")
    # Don't write a ROM file.
    result = runner.invoke(
        main,
        ["--project-root", str(tmp_path),
         "bytes", "find", "1.0", "4C B9 FF"],
    )
    assert result.exit_code != 0
    assert "ROM not found" in result.output


def test_bytes_find_help_lists_cross_option() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["bytes", "find", "--help"])
    assert result.exit_code == 0
    assert "--cross" in result.output
    assert "VERSION_ID" in result.output
