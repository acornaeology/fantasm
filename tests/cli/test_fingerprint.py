"""Tests for ``fantasm fingerprint``."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from fantasm.cli import main

from ._helpers import add_version, init_project


def test_fingerprint(tmp_path: Path) -> None:
    runner = CliRunner()
    init_project(tmp_path, runner, "demo", "demo")
    add_version(tmp_path, runner, "1.0", "demo")

    version_dirpath = tmp_path / "versions" / "demo-1.0"
    rom_filepath = version_dirpath / "rom" / "demo-1.0.rom"
    rom_filepath.parent.mkdir(exist_ok=True)
    # 4 blocks of 16 bytes; first two duplicate.
    rom_filepath.write_bytes((b"\xA9\x00" * 8) * 2 + b"\x60" * 32)

    result = runner.invoke(
        main,
        [
            "--project-root", str(tmp_path),
            "fingerprint", "1.0", "--block-size", "16", "--as", "tsv",
        ],
    )
    assert result.exit_code == 0, result.output
