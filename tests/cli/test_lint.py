"""Tests for ``fantasm lint``."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from fantasm.cli import main

from ._helpers import add_version, init_project, write_minimal_disasm


def test_lint_annotations(tmp_path: Path) -> None:
    runner = CliRunner()
    init_project(tmp_path, runner, "demo", "demo")
    add_version(tmp_path, runner, "1.0", "demo")

    version_dirpath = tmp_path / "versions" / "demo-1.0"
    write_minimal_disasm(version_dirpath, "demo", "1.0")

    driver_filepath = tmp_path / "driver.py"
    driver_filepath.write_text(
        'comment(0x8001, "in-range")\n'
        'comment(0x9999, "out-of-range")\n'
    )

    result = runner.invoke(
        main,
        [
            "--project-root", str(tmp_path),
            "lint", "1.0", str(driver_filepath), "--as", "tsv",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "9999" in result.output


def test_lint_accepts_external_label_addresses(tmp_path: Path) -> None:
    """Workspace addresses declared via the driver's
    ``external_label()`` must be accepted by ``fantasm lint`` without
    each project re-declaring them in ``[memory] regions`` — the
    JSON's ``external_labels`` map is authoritative.
    """
    runner = CliRunner()
    init_project(tmp_path, runner, "demo", "demo")
    add_version(tmp_path, runner, "1.0", "demo")

    version_dirpath = tmp_path / "versions" / "demo-1.0"
    json_filepath = version_dirpath / "output" / "demo-1.0.json"
    json_filepath.parent.mkdir(exist_ok=True)
    # Minimal disassembly + an external label at &00C0 (zero page,
    # outside the ROM range and outside any [memory] region).
    json_filepath.write_text(
        json.dumps({
            "meta": {"load_addr": 0x8000, "end_addr": 0x8100},
            "subroutines": [{"addr": 0x8000, "name": "main"}],
            "external_labels": {"wksp_drive": 0x00C0},
            "items": [
                {"addr": 0x8000, "type": "code", "mnemonic": "lda"},
                {"addr": 0x8002, "type": "code", "mnemonic": "rts"},
            ],
        })
    )

    driver_filepath = tmp_path / "driver.py"
    driver_filepath.write_text(
        'label(0x00C0, "wksp_drive")\n'
        'label(0x00C5, "wksp_uncovered")\n'
    )

    result = runner.invoke(
        main,
        [
            "--project-root", str(tmp_path),
            "lint", "1.0", str(driver_filepath), "--as", "tsv",
        ],
    )
    assert result.exit_code == 0, result.output
    # &00C0 has an external_labels entry → covered.
    assert "00C0" not in result.output
    # &00C5 has neither item nor external_label entry nor region →
    # still flagged as unmapped.
    assert "00C5" in result.output


def test_lint_accepts_sub_labels_addresses(tmp_path: Path) -> None:
    """``sub_labels`` (per-item label aliases the disassembler emits
    for move()-block source addresses) must also count as valid."""
    runner = CliRunner()
    init_project(tmp_path, runner, "demo", "demo")
    add_version(tmp_path, runner, "1.0", "demo")

    version_dirpath = tmp_path / "versions" / "demo-1.0"
    json_filepath = version_dirpath / "output" / "demo-1.0.json"
    json_filepath.parent.mkdir(exist_ok=True)
    json_filepath.write_text(
        json.dumps({
            "meta": {"load_addr": 0x8000, "end_addr": 0x8100},
            "subroutines": [{"addr": 0x8000, "name": "main"}],
            "items": [
                {
                    "addr": 0x8000,
                    "type": "code",
                    "mnemonic": "lda",
                    # Alias address 0x9050 -> "alt_name"; the
                    # disassembler emits this for move()-block source
                    # labels and similar.
                    "sub_labels": {"36944": "alt_name"},
                },
                {"addr": 0x8002, "type": "code", "mnemonic": "rts"},
            ],
        })
    )

    driver_filepath = tmp_path / "driver.py"
    driver_filepath.write_text('label(0x9050, "alt_name")\n')

    result = runner.invoke(
        main,
        [
            "--project-root", str(tmp_path),
            "lint", "1.0", str(driver_filepath), "--as", "tsv",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "9050" not in result.output
