"""Tests for ``fantasm backfill``."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from fantasm.cli import main

from ._helpers import add_version, init_project


def test_backfill_help() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["backfill", "--help"])
    assert result.exit_code == 0
    assert "version graph" in result.output


def test_backfill_no_versions_configured(tmp_path: Path) -> None:
    runner = CliRunner()
    init_project(tmp_path, runner, "demo", "demo")
    # No [[versions.entry]] in fantasm.toml.
    driver_a = tmp_path / "driver_a.py"
    driver_b = tmp_path / "driver_b.py"
    driver_a.write_text("")
    driver_b.write_text("")
    result = runner.invoke(
        main,
        [
            "--project-root", str(tmp_path),
            "backfill", "1.0", "2.0",
            "--source-driver", str(driver_a),
            "--target-driver", str(driver_b),
        ],
    )
    assert result.exit_code != 0
    assert "no [[versions.entry]]" in result.output


def test_backfill_with_minimal_graph(tmp_path: Path) -> None:
    runner = CliRunner()
    init_project(tmp_path, runner, "demo", "demo")
    add_version(tmp_path, runner, "1.0", "demo")
    add_version(tmp_path, runner, "2.0", "demo")

    toml_filepath = tmp_path / "fantasm.toml"
    existing = toml_filepath.read_text()
    toml_filepath.write_text(
        existing
        + "\n[[versions.entry]]\nid = \"1.0\"\n"
        + "\n[[versions.entry]]\nid = \"2.0\"\nparents = [\"1.0\"]\n"
    )

    rom = bytes([0xA9, 0x01, 0x60, 0xA9, 0x02, 0x60])
    for vid in ("1.0", "2.0"):
        (tmp_path / "versions" / f"demo-{vid}" / "rom" / f"demo-{vid}.rom").write_bytes(rom)

    source_driver = tmp_path / "src.py"
    source_driver.write_text(
        'comment(0x8000, "first inline", inline=True)\n'
        'label(0x8003, "second_inst")\n'
        'subroutine(0x8000, "main", hook=None)\n'
    )
    target_driver = tmp_path / "tgt.py"
    target_driver.write_text("")

    result = runner.invoke(
        main,
        [
            "--project-root", str(tmp_path),
            "backfill", "1.0", "2.0",
            "--source-driver", str(source_driver),
            "--target-driver", str(target_driver),
            "--threshold", "1",
            "--as", "tsv",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "first inline" in result.output
    assert "second_inst" in result.output
    assert "main" in result.output
