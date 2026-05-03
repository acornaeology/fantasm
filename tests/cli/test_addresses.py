"""Tests for ``fantasm addresses`` subcommands."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from fantasm.cli import main

from ._helpers import add_version, init_project


def test_addresses_map_full(tmp_path: Path) -> None:
    runner = CliRunner()
    init_project(tmp_path, runner, "demo", "demo")
    add_version(tmp_path, runner, "1.0", "demo")
    add_version(tmp_path, runner, "2.0", "demo")

    rom = bytes([0xA9, 0x01, 0x60, 0xA9, 0x02, 0x60])
    for vid in ("1.0", "2.0"):
        (tmp_path / "versions" / f"demo-{vid}" / "rom" / f"demo-{vid}.rom").write_bytes(rom)

    # Tiny ROM (4 instructions) — below the production threshold,
    # so pass --threshold 1 to exercise the no-filter path.
    result = runner.invoke(
        main,
        [
            "--project-root", str(tmp_path),
            "addresses", "map", "1.0", "2.0",
            "--threshold", "1",
            "--as", "tsv",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "8000" in result.output


def test_addresses_map_default_threshold_culls_short_runs(
    tmp_path: Path,
) -> None:
    # Two ROMs whose code is mostly different but where the leading
    # opcode happens to match. Under the new default --threshold 5
    # the CLI must drop the coincidental match so the user doesn't
    # see a misleading identity-fallback row.
    runner = CliRunner()
    init_project(tmp_path, runner, "demo", "demo")
    add_version(tmp_path, runner, "1.0", "demo")
    add_version(tmp_path, runner, "2.0", "demo")

    rom_a = bytes([0xA9, 0x01, 0x60, 0xEA, 0xEA, 0xEA, 0xEA, 0xEA])
    rom_b = bytes([0xA9, 0x02, 0x38, 0x18, 0xD8, 0xF8, 0x78, 0x58])
    (tmp_path / "versions" / "demo-1.0" / "rom" / "demo-1.0.rom").write_bytes(rom_a)
    (tmp_path / "versions" / "demo-2.0" / "rom" / "demo-2.0.rom").write_bytes(rom_b)

    result = runner.invoke(
        main,
        [
            "--project-root", str(tmp_path),
            "addresses", "map", "1.0", "2.0",
            "--addr", "0x8000",
            "--as", "tsv",
        ],
    )
    assert result.exit_code == 0, result.output
    # Address row exists but with "(no mapping)" rather than an
    # identity-fallback target.
    assert "no mapping" in result.output


def test_addresses_map_explicit(tmp_path: Path) -> None:
    runner = CliRunner()
    init_project(tmp_path, runner, "demo", "demo")
    add_version(tmp_path, runner, "1.0", "demo")
    add_version(tmp_path, runner, "2.0", "demo")

    rom = bytes([0xA9, 0x01, 0x60, 0xA9, 0x02, 0x60])
    for vid in ("1.0", "2.0"):
        (tmp_path / "versions" / f"demo-{vid}" / "rom" / f"demo-{vid}.rom").write_bytes(rom)

    result = runner.invoke(
        main,
        [
            "--project-root", str(tmp_path),
            "addresses", "map", "1.0", "2.0",
            "--addr", "0x8000",
            "--addr", "&8002",
            "--as", "tsv",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "8000" in result.output
    assert "8002" in result.output


def test_addresses_map_invalid_addr(tmp_path: Path) -> None:
    runner = CliRunner()
    init_project(tmp_path, runner, "demo", "demo")
    add_version(tmp_path, runner, "1.0", "demo")
    add_version(tmp_path, runner, "2.0", "demo")
    rom = b"\x60"
    for vid in ("1.0", "2.0"):
        (tmp_path / "versions" / f"demo-{vid}" / "rom" / f"demo-{vid}.rom").write_bytes(rom)

    result = runner.invoke(
        main,
        [
            "--project-root", str(tmp_path),
            "addresses", "map", "1.0", "2.0",
            "--addr", "not-hex",
        ],
    )
    assert result.exit_code != 0
    assert "invalid address" in result.output
