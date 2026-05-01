"""Smoke tests for the per-topic CLI commands.

Each command is exercised against minimal hand-crafted JSON / ROM
fixtures. The aim is to catch wiring breaks (wrong argument
plumbing, missing imports, broken @report_output decoration), not
to re-test the api-layer logic, which is covered separately.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from fantasm.cli import main


def _init_project(
    tmp_path: Path, runner: CliRunner, name: str = "test", *prefixes: str
) -> None:
    args = ["project", "init", "--name", name, "--at", str(tmp_path)]
    for prefix in prefixes:
        args.extend(["--prefix", prefix])
    runner.invoke(main, args)


def _add_version(
    tmp_path: Path,
    runner: CliRunner,
    version_id: str,
    prefix: str | None = None,
) -> None:
    args = [
        "--project-root", str(tmp_path),
        "project", "add", version_id,
    ]
    if prefix is not None:
        args.extend(["--prefix", prefix])
    runner.invoke(main, args)


# --- verify -------------------------------------------------------


class TestVerifyCommand:
    def test_help(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["verify", "--help"])
        assert result.exit_code == 0
        assert "round-trips" in result.output

    def test_no_project_root(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv("FANTASM_PROJECT_ROOT", raising=False)
        runner = CliRunner()
        result = runner.invoke(main, ["verify", "1.0"])
        assert result.exit_code != 0
        assert "no project root" in result.output

    def test_unknown_version(self, tmp_path: Path) -> None:
        runner = CliRunner()
        _init_project(tmp_path, runner, "test", "test")
        result = runner.invoke(
            main,
            ["--project-root", str(tmp_path), "verify", "9.99"],
        )
        assert result.exit_code != 0
        assert "not found" in result.output


# --- compare ------------------------------------------------------


class TestCompareCommand:
    def test_help(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["compare", "--help"])
        assert result.exit_code == 0
        assert "diff" in result.output.lower()

    def test_unknown_version_a(self, tmp_path: Path) -> None:
        runner = CliRunner()
        _init_project(tmp_path, runner, "test", "test")
        result = runner.invoke(
            main,
            ["--project-root", str(tmp_path), "compare", "9.99", "8.88"],
        )
        assert result.exit_code != 0


# --- audit --------------------------------------------------------


def _write_minimal_disasm(version_dirpath: Path, prefix: str, version_id: str) -> Path:
    """Create a minimal JSON file under the version's output/ dir."""
    output = version_dirpath / "output"
    output.mkdir(exist_ok=True)
    json_filepath = output / f"{prefix}-{version_id}.json"
    data = {
        "meta": {"load_addr": 0x8000, "end_addr": 0x8100},
        "subroutines": [{"addr": 0x8000, "name": "alpha"}],
        "items": [
            {"addr": 0x8000, "type": "code", "mnemonic": "lda"},
            {"addr": 0x8002, "type": "code", "mnemonic": "rts"},
        ],
    }
    json_filepath.write_text(json.dumps(data))
    return json_filepath


class TestAuditSummary:
    def test_runs_with_minimal_json(self, tmp_path: Path) -> None:
        runner = CliRunner()
        _init_project(tmp_path, runner, "demo", "demo")
        _add_version(tmp_path, runner, "1.0", "demo")

        version_dirpath = tmp_path / "versions" / "demo-1.0"
        _write_minimal_disasm(version_dirpath, "demo", "1.0")

        result = runner.invoke(
            main,
            [
                "--project-root", str(tmp_path),
                "audit", "summary", "1.0", "--as", "tsv",
            ],
        )
        assert result.exit_code == 0, result.output
        assert "alpha" in result.output

    def test_missing_json_errors(self, tmp_path: Path) -> None:
        runner = CliRunner()
        _init_project(tmp_path, runner, "demo", "demo")
        _add_version(tmp_path, runner, "1.0", "demo")
        result = runner.invoke(
            main,
            [
                "--project-root", str(tmp_path),
                "audit", "summary", "1.0",
            ],
        )
        assert result.exit_code != 0
        assert "JSON" in result.output


class TestAuditUndeclared:
    def test_runs(self, tmp_path: Path) -> None:
        runner = CliRunner()
        _init_project(tmp_path, runner, "demo", "demo")
        _add_version(tmp_path, runner, "1.0", "demo")

        version_dirpath = tmp_path / "versions" / "demo-1.0"
        _write_minimal_disasm(version_dirpath, "demo", "1.0")

        result = runner.invoke(
            main,
            [
                "--project-root", str(tmp_path),
                "audit", "undeclared", "1.0", "--as", "tsv",
            ],
        )
        assert result.exit_code == 0, result.output


# --- comments check ----------------------------------------------


class TestCommentsCheck:
    def test_runs_clean(self, tmp_path: Path) -> None:
        runner = CliRunner()
        _init_project(tmp_path, runner, "demo", "demo")
        _add_version(tmp_path, runner, "1.0", "demo")

        version_dirpath = tmp_path / "versions" / "demo-1.0"
        _write_minimal_disasm(version_dirpath, "demo", "1.0")

        result = runner.invoke(
            main,
            [
                "--project-root", str(tmp_path),
                "comments", "check", "1.0", "--as", "tsv",
            ],
        )
        assert result.exit_code == 0, result.output

    def test_cfg_leaves(self, tmp_path: Path) -> None:
        runner = CliRunner()
        _init_project(tmp_path, runner, "demo", "demo")
        _add_version(tmp_path, runner, "1.0", "demo")

        version_dirpath = tmp_path / "versions" / "demo-1.0"
        _write_minimal_disasm(version_dirpath, "demo", "1.0")

        result = runner.invoke(
            main,
            [
                "--project-root", str(tmp_path),
                "cfg", "leaves", "1.0", "--as", "tsv",
            ],
        )
        assert result.exit_code == 0, result.output

    def test_cfg_depth(self, tmp_path: Path) -> None:
        runner = CliRunner()
        _init_project(tmp_path, runner, "demo", "demo")
        _add_version(tmp_path, runner, "1.0", "demo")

        version_dirpath = tmp_path / "versions" / "demo-1.0"
        _write_minimal_disasm(version_dirpath, "demo", "1.0")

        result = runner.invoke(
            main,
            [
                "--project-root", str(tmp_path),
                "cfg", "depth", "1.0", "--as", "tsv",
            ],
        )
        assert result.exit_code == 0, result.output

    def test_asm_extract(self, tmp_path: Path) -> None:
        runner = CliRunner()
        _init_project(tmp_path, runner, "demo", "demo")
        _add_version(tmp_path, runner, "1.0", "demo")

        version_dirpath = tmp_path / "versions" / "demo-1.0"
        asm_filepath = version_dirpath / "output" / "demo-1.0.asm"
        asm_filepath.parent.mkdir(exist_ok=True)
        asm_filepath.write_text(
            "\n.start\n    LDA #$00       ;8000:\n    RTS            ;8002:\n"
        )

        result = runner.invoke(
            main,
            [
                "--project-root", str(tmp_path),
                "asm", "extract", "1.0", "$8000",
            ],
        )
        assert result.exit_code == 0, result.output
        assert "LDA" in result.output

    def test_shared_help(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["shared", "--help"])
        assert result.exit_code == 0
        assert "[label=]path@load-addr" in result.output

    def test_shared_invalid_spec(self) -> None:
        runner = CliRunner()
        # No @load-addr.
        result = runner.invoke(
            main, ["shared", "/nonexistent.rom", "/other.rom@&8000"]
        )
        assert result.exit_code != 0
        assert "@" in result.output or "load" in result.output.lower()

    def test_labels_classify(self, tmp_path: Path) -> None:
        runner = CliRunner()
        _init_project(tmp_path, runner, "demo", "demo")
        _add_version(tmp_path, runner, "1.0", "demo")

        version_dirpath = tmp_path / "versions" / "demo-1.0"
        # Use minimal disasm augmented with an auto label.
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
                        "labels": ["main"],
                    },
                    {
                        "addr": 0x8002,
                        "type": "code",
                        "mnemonic": "rts",
                        "labels": ["c8002"],
                    },
                ],
            })
        )
        result = runner.invoke(
            main,
            [
                "--project-root", str(tmp_path),
                "labels", "classify", "1.0", "--as", "tsv",
            ],
        )
        assert result.exit_code == 0, result.output
        assert "c8002" in result.output

    def test_promote(self, tmp_path: Path) -> None:
        runner = CliRunner()
        _init_project(tmp_path, runner, "demo", "demo")
        _add_version(tmp_path, runner, "1.0", "demo")

        version_dirpath = tmp_path / "versions" / "demo-1.0"
        _write_minimal_disasm(version_dirpath, "demo", "1.0")

        result = runner.invoke(
            main,
            [
                "--project-root", str(tmp_path),
                "promote", "1.0", "--show-all", "--as", "tsv",
            ],
        )
        assert result.exit_code == 0, result.output

    def test_fingerprint(self, tmp_path: Path) -> None:
        runner = CliRunner()
        _init_project(tmp_path, runner, "demo", "demo")
        _add_version(tmp_path, runner, "1.0", "demo")

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

    def test_sub_insert(self, tmp_path: Path) -> None:
        runner = CliRunner()
        driver_filepath = tmp_path / "driver.py"
        driver_filepath.write_text(
            "import py8dis\n"
            "# =================== Subroutines correspondence ===================\n"
            'subroutine(0x8000, "init")\n'
            'subroutine(0x8100, "later")\n'
            "# =================== End ===================\n"
            "tail()\n"
        )
        result = runner.invoke(
            main,
            [
                "sub", "insert", str(driver_filepath), "$8050",
                "--as", "tsv",
            ],
        )
        assert result.exit_code == 0, result.output
        assert "8000" in result.output

    def test_lint_annotations(self, tmp_path: Path) -> None:
        runner = CliRunner()
        _init_project(tmp_path, runner, "demo", "demo")
        _add_version(tmp_path, runner, "1.0", "demo")

        version_dirpath = tmp_path / "versions" / "demo-1.0"
        _write_minimal_disasm(version_dirpath, "demo", "1.0")

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
        # 0x9999 is unmapped (outside the 0x8000-0x80FF ROM range).
        assert "9999" in result.output

    def test_invalid_sub_address(self, tmp_path: Path) -> None:
        runner = CliRunner()
        _init_project(tmp_path, runner, "demo", "demo")
        _add_version(tmp_path, runner, "1.0", "demo")

        version_dirpath = tmp_path / "versions" / "demo-1.0"
        _write_minimal_disasm(version_dirpath, "demo", "1.0")

        result = runner.invoke(
            main,
            [
                "--project-root", str(tmp_path),
                "comments", "check", "1.0", "--sub", "not-hex",
            ],
        )
        assert result.exit_code != 0
        assert "invalid address" in result.output
