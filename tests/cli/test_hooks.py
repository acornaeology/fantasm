"""Tests for ``fantasm hooks suggest``."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from fantasm.cli import main

from ._helpers import add_version, init_project


def _setup(tmp_path: Path, items, *, meta=None):
    """Boot a demo project and write a JSON disassembly."""
    runner = CliRunner()
    init_project(tmp_path, runner, "demo", "demo")
    add_version(tmp_path, runner, "1.0", "demo")

    version_dirpath = tmp_path / "versions" / "demo-1.0"
    json_filepath = version_dirpath / "output" / "demo-1.0.json"
    json_filepath.parent.mkdir(exist_ok=True)
    json_filepath.write_text(
        json.dumps({
            "meta": meta or {"load_addr": 0x8000, "end_addr": 0x8400},
            "items": list(items),
            "subroutines": [],
        })
    )
    return runner


# Bytes that decode as valid 6502 (LDA #imm; STA abs; RTS).
_RESUME = [0xA9, 0x00, 0x8D, 0x34, 0x12, 0x60]


def _missing_hook_call_site(addr, target):
    """Three items: JSR + string-with-CR-terminator + byte-run-as-code."""
    return [
        {"addr": addr, "type": "code", "mnemonic": "jsr",
         "bytes": [0x20, target & 0xFF, target >> 8],
         "target": target,
         "target_label": "print_inline_no_spool"},
        {"addr": addr + 3, "type": "string",
         "bytes": list(b"Hello\r"),
         "string": "Hello\r"},
        {"addr": addr + 9, "type": "byte", "bytes": _RESUME},
    ]


def test_hooks_suggest_finds_print_inline_target(tmp_path: Path) -> None:
    items = []
    for i in range(3):
        items.extend(_missing_hook_call_site(0x8000 + i * 0x100, 0x9000))
    runner = _setup(tmp_path, items)

    result = runner.invoke(
        main,
        ["--project-root", str(tmp_path),
         "hooks", "suggest", "1.0",
         "--report", "candidates", "--as", "tsv"],
    )
    assert result.exit_code == 0, result.output
    # Target address surfaces, plus the matched kind.
    assert "&9000" in result.output
    assert "stringcr" in result.output
    # All 3 of 3 call sites match → confidence 1.00.
    assert "1.00" in result.output


def test_hooks_suggest_paste_report(tmp_path: Path) -> None:
    items = []
    for i in range(3):
        items.extend(_missing_hook_call_site(0x8000 + i * 0x100, 0x9000))
    runner = _setup(tmp_path, items)

    result = runner.invoke(
        main,
        ["--project-root", str(tmp_path),
         "hooks", "suggest", "1.0",
         "--report", "paste", "--as", "tsv"],
    )
    assert result.exit_code == 0, result.output
    # Paste-ready hook_subroutine() line uses the target_label.
    assert 'hook_subroutine(0x9000, "print_inline_no_spool", stringcr_hook)' in result.output


def test_hooks_suggest_min_call_sites_filter(tmp_path: Path) -> None:
    # One matching site only; --min-call-sites 2 (default) drops it.
    items = _missing_hook_call_site(0x8000, 0x9000)
    runner = _setup(tmp_path, items)

    result = runner.invoke(
        main,
        ["--project-root", str(tmp_path),
         "hooks", "suggest", "1.0",
         "--report", "candidates", "--as", "tsv"],
    )
    assert result.exit_code == 0, result.output
    # No data row — only the header row for the table.
    data_lines = [
        ln for ln in result.output.strip().splitlines()
        if ln.strip() and not ln.startswith("#")
    ]
    assert data_lines == []

    # Lower the threshold and the candidate appears.
    result = runner.invoke(
        main,
        ["--project-root", str(tmp_path),
         "hooks", "suggest", "1.0",
         "--min-call-sites", "1",
         "--report", "candidates", "--as", "tsv"],
    )
    assert result.exit_code == 0, result.output
    assert "&9000" in result.output


def test_hooks_suggest_already_hooked_reports_nothing(
    tmp_path: Path,
) -> None:
    # Post-call sequence is string -> code (already hooked); the
    # detector should not flag the target.
    items = []
    for i in range(5):
        base = 0x8000 + i * 0x100
        items += [
            {"addr": base, "type": "code", "mnemonic": "jsr",
             "bytes": [0x20, 0x00, 0x90], "target": 0x9000},
            {"addr": base + 3, "type": "string",
             "bytes": list(b"Hello\r"), "string": "Hello\r"},
            {"addr": base + 9, "type": "code", "mnemonic": "lda",
             "bytes": [0xA9, 0x00]},
        ]
    runner = _setup(tmp_path, items)

    result = runner.invoke(
        main,
        ["--project-root", str(tmp_path),
         "hooks", "suggest", "1.0", "--as", "tsv"],
    )
    assert result.exit_code == 0, result.output
    # No row carrying &9000.
    assert "&9000" not in result.output


def test_hooks_suggest_help_lists_options() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["hooks", "suggest", "--help"])
    assert result.exit_code == 0
    assert "--cpu" in result.output
    assert "--min-call-sites" in result.output
    assert "--min-resume-code-bytes" in result.output
    assert "--min-confidence" in result.output
