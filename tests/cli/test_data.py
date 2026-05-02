"""Tests for ``fantasm data`` (runs / classify)."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from fantasm.cli import main

from ._helpers import add_version, init_project


def _setup(tmp_path: Path, items, subroutines=()):
    """Boot a demo project and write a JSON disassembly with the given items."""
    runner = CliRunner()
    init_project(tmp_path, runner, "demo", "demo")
    add_version(tmp_path, runner, "1.0", "demo")

    version_dirpath = tmp_path / "versions" / "demo-1.0"
    json_filepath = version_dirpath / "output" / "demo-1.0.json"
    json_filepath.parent.mkdir(exist_ok=True)
    json_filepath.write_text(
        json.dumps({
            "meta": {"load_addr": 0x8000, "end_addr": 0x8200},
            "items": list(items),
            "subroutines": list(subroutines),
        })
    )
    return runner


# --- data runs ---------------------------------------------------


def test_data_runs_lists_long_runs(tmp_path: Path) -> None:
    runner = _setup(tmp_path, items=[
        {"addr": 0x8000, "type": "byte",
         "bytes": [0xAA] * 16, "labels": ["table_a"]},
        {"addr": 0x8010, "type": "code",
         "bytes": [0x60], "mnemonic": "rts"},
        {"addr": 0x8011, "type": "byte",
         "bytes": [0xBB] * 32, "labels": ["table_b"]},
    ])
    result = runner.invoke(
        main,
        ["--project-root", str(tmp_path),
         "data", "runs", "1.0", "--as", "tsv"],
    )
    assert result.exit_code == 0, result.output
    # Both runs surface; the longer one is first.
    out = result.output
    assert "table_a" in out
    assert "table_b" in out
    assert out.find("table_b") < out.find("table_a")


def test_data_runs_min_bytes_filter(tmp_path: Path) -> None:
    runner = _setup(tmp_path, items=[
        {"addr": 0x8000, "type": "byte",
         "bytes": [0xAA, 0xBB], "labels": ["short"]},     # 2 bytes
        {"addr": 0x8002, "type": "code",
         "bytes": [0x60], "mnemonic": "rts"},
        {"addr": 0x8003, "type": "byte",
         "bytes": [0xCC] * 32, "labels": ["long"]},
    ])
    # Default min-bytes is 8 → "short" filtered out.
    result = runner.invoke(
        main,
        ["--project-root", str(tmp_path),
         "data", "runs", "1.0", "--as", "tsv"],
    )
    assert result.exit_code == 0, result.output
    assert "long" in result.output
    assert "short" not in result.output

    # Lower the threshold and "short" reappears.
    result = runner.invoke(
        main,
        ["--project-root", str(tmp_path),
         "data", "runs", "1.0", "--min-bytes", "2", "--as", "tsv"],
    )
    assert result.exit_code == 0, result.output
    assert "short" in result.output


def test_data_runs_type_filter(tmp_path: Path) -> None:
    runner = _setup(tmp_path, items=[
        {"addr": 0x8000, "type": "byte", "bytes": [0xAA] * 16},
        {"addr": 0x8010, "type": "word", "bytes": [0xBB, 0xCC] * 8},
    ])
    result = runner.invoke(
        main,
        ["--project-root", str(tmp_path),
         "data", "runs", "1.0", "--type", "word", "--as", "tsv"],
    )
    assert result.exit_code == 0, result.output
    # Only the word run; the byte run is hidden.
    assert "word" in result.output
    # The byte-run row would carry "byte\t" — its absence is what we check.
    assert "byte\t" not in result.output


def test_data_runs_unannotated_filter(tmp_path: Path) -> None:
    runner = _setup(tmp_path, items=[
        {"addr": 0x8000, "type": "byte",
         "bytes": [0xAA] * 16, "labels": ["named"]},
        {"addr": 0x8010, "type": "code",
         "bytes": [0x60], "mnemonic": "rts"},
        {"addr": 0x8011, "type": "byte",
         "bytes": [0xBB] * 16},
    ])
    result = runner.invoke(
        main,
        ["--project-root", str(tmp_path),
         "data", "runs", "1.0", "--unannotated", "--as", "tsv"],
    )
    assert result.exit_code == 0, result.output
    # The unlabelled run shows; the labelled one doesn't.
    assert "named" not in result.output


def test_data_runs_help_lists_options() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["data", "runs", "--help"])
    assert result.exit_code == 0
    assert "--min-bytes" in result.output
    assert "--type" in result.output
    assert "--annotated" in result.output


# --- data classify -----------------------------------------------


def test_data_classify_finds_string_in_byte_run(tmp_path: Path) -> None:
    runner = _setup(tmp_path, items=[{
        "addr": 0x8000, "type": "byte",
        "bytes": list(b"Hello, world!\x00") + [0xFF] * 16,
    }])
    result = runner.invoke(
        main,
        ["--project-root", str(tmp_path),
         "data", "classify", "1.0", "--as", "tsv"],
    )
    assert result.exit_code == 0, result.output
    # Both classifications surface.
    assert "string" in result.output
    assert "padding" in result.output
    assert "Hello" in result.output


def test_data_classify_skips_non_target_types(tmp_path: Path) -> None:
    runner = _setup(tmp_path, items=[{
        "addr": 0x8000, "type": "string",
        "bytes": list(b"already classified"), "string": "already classified",
    }])
    result = runner.invoke(
        main,
        ["--project-root", str(tmp_path),
         "data", "classify", "1.0", "--as", "tsv"],
    )
    assert result.exit_code == 0, result.output
    # Default target is byte-only; the string item isn't examined,
    # so no candidate row appears.
    assert "already classified" not in result.output


def test_data_classify_target_type_override(tmp_path: Path) -> None:
    runner = _setup(tmp_path, items=[{
        "addr": 0x8000, "type": "string",
        "bytes": list(b"Embedded   string here"), "string": "Embedded   string here",
    }])
    # With --target-type string we re-examine string-typed items.
    result = runner.invoke(
        main,
        ["--project-root", str(tmp_path),
         "data", "classify", "1.0",
         "--target-type", "string", "--as", "tsv"],
    )
    assert result.exit_code == 0, result.output
    assert "Embedded" in result.output


def test_data_classify_help() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["data", "classify", "--help"])
    assert result.exit_code == 0
    assert "--cpu" in result.output
    assert "--min-string" in result.output
    assert "--min-code" in result.output
    assert "--min-padding" in result.output
