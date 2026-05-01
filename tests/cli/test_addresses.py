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

    result = runner.invoke(
        main,
        [
            "--project-root", str(tmp_path),
            "addresses", "map", "1.0", "2.0", "--as", "tsv",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "8000" in result.output


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
