"""Tests for ``fantasm driver sort``."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from fantasm.cli import main


_UNSORTED_DRIVER_TEXT = (
    'd.label(0x9000, "high")\n'
    'd.label(0x8000, "low")\n'
)


_SORTED_DRIVER_TEXT = (
    'd.label(0x8000, "low")\n'
    'd.label(0x9000, "high")\n'
)


def test_default_writes_sorted_text_to_stdout(tmp_path: Path) -> None:
    runner = CliRunner()
    driver_filepath = tmp_path / "driver.py"
    driver_filepath.write_text(_UNSORTED_DRIVER_TEXT)

    result = runner.invoke(main, ["driver", "sort", str(driver_filepath)])
    assert result.exit_code == 0, result.output
    assert result.output == _SORTED_DRIVER_TEXT
    # File on disk is unchanged when --in-place is not passed.
    assert driver_filepath.read_text() == _UNSORTED_DRIVER_TEXT


def test_in_place_rewrites_file(tmp_path: Path) -> None:
    runner = CliRunner()
    driver_filepath = tmp_path / "driver.py"
    driver_filepath.write_text(_UNSORTED_DRIVER_TEXT)

    result = runner.invoke(
        main, ["driver", "sort", str(driver_filepath), "--in-place"]
    )
    assert result.exit_code == 0, result.output
    assert driver_filepath.read_text() == _SORTED_DRIVER_TEXT


def test_check_passes_for_sorted_file(tmp_path: Path) -> None:
    runner = CliRunner()
    driver_filepath = tmp_path / "driver.py"
    driver_filepath.write_text(_SORTED_DRIVER_TEXT)

    result = runner.invoke(
        main, ["driver", "sort", str(driver_filepath), "--check"]
    )
    assert result.exit_code == 0, result.output


def test_check_fails_with_diff_for_unsorted_file(tmp_path: Path) -> None:
    runner = CliRunner()
    driver_filepath = tmp_path / "driver.py"
    driver_filepath.write_text(_UNSORTED_DRIVER_TEXT)

    result = runner.invoke(
        main,
        ["driver", "sort", str(driver_filepath), "--check"],
    )
    assert result.exit_code == 1
    # CliRunner captures stderr separately on Click 8.2+.
    assert "0x8000" in result.stderr
    assert "0x9000" in result.stderr
    # File on disk is untouched by --check.
    assert driver_filepath.read_text() == _UNSORTED_DRIVER_TEXT


def test_in_place_and_check_are_mutually_exclusive(tmp_path: Path) -> None:
    runner = CliRunner()
    driver_filepath = tmp_path / "driver.py"
    driver_filepath.write_text(_SORTED_DRIVER_TEXT)

    result = runner.invoke(
        main,
        ["driver", "sort", str(driver_filepath), "--in-place", "--check"],
    )
    assert result.exit_code != 0
    assert "mutually exclusive" in result.output


def test_missing_file_errors_cleanly(tmp_path: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(
        main, ["driver", "sort", str(tmp_path / "nope.py")]
    )
    assert result.exit_code != 0
    assert "does not exist" in result.output.lower()
