"""Tests for ``fantasm comments`` subcommands."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from fantasm.cli import main
from fantasm.cli_helpers import resolve_version_files
from fantasm.config import resolve_project_context

from ._helpers import add_version, init_project, write_minimal_disasm


def test_comments_check_runs_clean(tmp_path: Path) -> None:
    runner = CliRunner()
    init_project(tmp_path, runner, "demo", "demo")
    add_version(tmp_path, runner, "1.0", "demo")

    version_dirpath = tmp_path / "versions" / "demo-1.0"
    write_minimal_disasm(version_dirpath, "demo", "1.0")

    result = runner.invoke(
        main,
        [
            "--project-root", str(tmp_path),
            "comments", "check", "1.0", "--as", "tsv",
        ],
    )
    assert result.exit_code == 0, result.output


def test_comments_check_md_link_in_code_span(tmp_path: Path) -> None:
    # The headline regression for issue #9: a Markdown address-link
    # inside a backtick code span won't render as a hyperlink. The
    # check should surface it as HIGH-confidence.
    runner = CliRunner()
    init_project(tmp_path, runner, "demo", "demo")
    add_version(tmp_path, runner, "1.0", "demo")

    version_dirpath = tmp_path / "versions" / "demo-1.0"
    json_filepath = version_dirpath / "output" / "demo-1.0.json"
    json_filepath.parent.mkdir(exist_ok=True)
    json_filepath.write_text(json.dumps({
        "meta": {"load_addr": 0x8000, "end_addr": 0x8100},
        "items": [{"addr": 0x8000, "type": "code", "mnemonic": "rts"}],
        "subroutines": [{
            "addr": 0x8000,
            "name": "set_nmi_vector",
            "description": (
                "Performs `STY [nmi_jmp_hi](address:0D0D?hex)`"
            ),
        }],
    }))

    result = runner.invoke(
        main,
        [
            "--project-root", str(tmp_path),
            "comments", "check", "1.0", "--as", "tsv",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "md_link_in_code_span" in result.output
    assert "HIGH" in result.output


def test_comments_check_strict_exits_nonzero_on_high(tmp_path: Path) -> None:
    # Acceptance criterion: --strict makes the command suitable as a
    # CI gate by exiting non-zero when any HIGH finding is present.
    # Report still renders before the exit.
    runner = CliRunner()
    init_project(tmp_path, runner, "demo", "demo")
    add_version(tmp_path, runner, "1.0", "demo")

    version_dirpath = tmp_path / "versions" / "demo-1.0"
    json_filepath = version_dirpath / "output" / "demo-1.0.json"
    json_filepath.parent.mkdir(exist_ok=True)
    json_filepath.write_text(json.dumps({
        "meta": {"load_addr": 0x8000, "end_addr": 0x8100},
        "items": [{"addr": 0x8000, "type": "code", "mnemonic": "rts"}],
        "subroutines": [{
            "addr": 0x8000,
            "name": "set_nmi_vector",
            "description": (
                "Performs `STY [nmi_jmp_hi](address:0D0D?hex)`"
            ),
        }],
    }))

    result = runner.invoke(
        main,
        [
            "--project-root", str(tmp_path),
            "comments", "check", "1.0",
            "--strict", "--as", "tsv",
        ],
    )
    assert result.exit_code == 1, result.output
    assert "md_link_in_code_span" in result.output


def test_comments_check_strict_clean_exits_zero(tmp_path: Path) -> None:
    # No HIGH findings → --strict exits 0.
    runner = CliRunner()
    init_project(tmp_path, runner, "demo", "demo")
    add_version(tmp_path, runner, "1.0", "demo")

    version_dirpath = tmp_path / "versions" / "demo-1.0"
    write_minimal_disasm(version_dirpath, "demo", "1.0")

    result = runner.invoke(
        main,
        [
            "--project-root", str(tmp_path),
            "comments", "check", "1.0", "--strict", "--as", "tsv",
        ],
    )
    assert result.exit_code == 0, result.output


def test_comments_check_invalid_sub_address(tmp_path: Path) -> None:
    runner = CliRunner()
    init_project(tmp_path, runner, "demo", "demo")
    add_version(tmp_path, runner, "1.0", "demo")

    version_dirpath = tmp_path / "versions" / "demo-1.0"
    write_minimal_disasm(version_dirpath, "demo", "1.0")

    result = runner.invoke(
        main,
        [
            "--project-root", str(tmp_path),
            "comments", "check", "1.0", "--sub", "not-hex",
        ],
    )
    assert result.exit_code != 0
    assert "invalid address" in result.output


def test_comments_suggest(tmp_path: Path) -> None:
    runner = CliRunner()
    init_project(tmp_path, runner, "demo", "demo")
    add_version(tmp_path, runner, "1.0", "demo")

    version_dirpath = tmp_path / "versions" / "demo-1.0"
    json_filepath = version_dirpath / "output" / "demo-1.0.json"
    json_filepath.parent.mkdir(exist_ok=True)
    json_filepath.write_text(
        json.dumps({
            "meta": {"load_addr": 0x8000, "end_addr": 0x8100},
            "subroutines": [],
            "items": [
                {"addr": 0x8000, "type": "code", "mnemonic": "pha"},
                {"addr": 0x8001, "type": "code", "mnemonic": "tax"},
                {
                    "addr": 0x8002,
                    "type": "code",
                    "mnemonic": "pla",
                    "comment_inline": "existing",
                },
            ],
        })
    )

    result = runner.invoke(
        main,
        [
            "--project-root", str(tmp_path),
            "comments", "suggest", "1.0", "--as", "tsv",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "Save A on stack" in result.output
    assert "Transfer A to X" in result.output
    assert "existing" not in result.output


def test_comments_suggest_invalid_label_hint(tmp_path: Path) -> None:
    runner = CliRunner()
    init_project(tmp_path, runner, "demo", "demo")
    add_version(tmp_path, runner, "1.0", "demo")
    version_dirpath = tmp_path / "versions" / "demo-1.0"
    json_filepath = version_dirpath / "output" / "demo-1.0.json"
    json_filepath.parent.mkdir(exist_ok=True)
    json_filepath.write_text(
        json.dumps({
            "meta": {"load_addr": 0x8000, "end_addr": 0x8100},
            "subroutines": [],
            "items": [],
        })
    )
    result = runner.invoke(
        main,
        [
            "--project-root", str(tmp_path),
            "comments", "suggest", "1.0",
            "--label-hint", "no-equals-sign",
        ],
    )
    assert result.exit_code != 0
    assert "PATTERN=description" in result.output


def _write_placement_project(tmp_path: Path, runner: CliRunner) -> None:
    """Two versions, 2.0 a child of 1.0, with a misplaced comment each way."""
    init_project(tmp_path, runner, "demo", "demo")
    add_version(tmp_path, runner, "1.0", "demo")
    add_version(tmp_path, runner, "2.0", "demo")
    toml_filepath = tmp_path / "fantasm.toml"
    toml_filepath.write_text(
        toml_filepath.read_text()
        + "\n[[versions.entry]]\nid = \"1.0\"\n"
        + "\n[[versions.entry]]\nid = \"2.0\"\nparents = [\"1.0\"]\n"
    )
    roms = {
        "1.0": bytes([0xA9, 0x64, 0x60]),          # LDA #&64 / RTS
        "2.0": bytes([0xEA, 0xA9, 0x64, 0x60]),    # NOP / LDA #&64 / RTS
    }
    items = {
        "1.0": [
            {"addr": 0x8000, "type": "code", "mnemonic": "lda",
             "operand": "#&64", "bytes": [0xA9, 0x64],
             "comment_inline": "Load hundreds"},
            {"addr": 0x8002, "type": "code", "mnemonic": "rts",
             "bytes": [0x60]},
        ],
        "2.0": [
            {"addr": 0x8000, "type": "code", "mnemonic": "nop",
             "bytes": [0xEA], "comment_inline": "Load hundreds"},
            {"addr": 0x8001, "type": "code", "mnemonic": "lda",
             "operand": "#&64", "bytes": [0xA9, 0x64],
             "comment_inline": "Divisor"},
            {"addr": 0x8003, "type": "code", "mnemonic": "rts",
             "bytes": [0x60]},
        ],
    }
    for vid in ("1.0", "2.0"):
        version_dirpath = tmp_path / "versions" / f"demo-{vid}"
        (version_dirpath / "rom" / f"demo-{vid}.rom").write_bytes(roms[vid])
        output_dirpath = version_dirpath / "output"
        output_dirpath.mkdir(exist_ok=True)
        (output_dirpath / f"demo-{vid}.json").write_text(json.dumps({
            "meta": {"load_addr": 0x8000, "end_addr": 0x8000 + len(roms[vid])},
            "items": items[vid],
        }))

    driver_filepath = resolve_version_files(
        resolve_project_context(tmp_path), "2.0"
    ).driver_filepath
    driver_filepath.parent.mkdir(parents=True, exist_ok=True)
    driver_filepath.write_text(
        'd.comment(0x8000, "Load hundreds", align=Align.INLINE)\n'
        'd.comment(0x8002, "Divisor", align=Align.INLINE)\n'
    )


def test_comments_check_flags_mid_item_and_copied_comments(
    tmp_path: Path,
) -> None:
    runner = CliRunner()
    _write_placement_project(tmp_path, runner)
    result = runner.invoke(
        main,
        [
            "--project-root", str(tmp_path),
            "comments", "check", "2.0", "--as", "tsv",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "mid_item_comment" in result.output
    assert "Inline comment 'Divisor' (driver line 2) is inside LDA #&64" in result.output
    assert "copied_comment" in result.output
    assert "1.0 &8000 corresponds to &8001 here" in result.output


def test_comments_check_no_parents(tmp_path: Path) -> None:
    runner = CliRunner()
    _write_placement_project(tmp_path, runner)
    result = runner.invoke(
        main,
        [
            "--project-root", str(tmp_path),
            "comments", "check", "2.0", "--no-parents", "--as", "tsv",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "mid_item_comment" in result.output
    assert "copied_comment" not in result.output
