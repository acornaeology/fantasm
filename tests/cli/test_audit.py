"""Tests for ``fantasm audit`` subcommands."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from fantasm.cli import main

from ._helpers import add_version, init_project, write_minimal_disasm


class TestAuditSummary:
    def test_runs_with_minimal_json(self, tmp_path: Path) -> None:
        runner = CliRunner()
        init_project(tmp_path, runner, "demo", "demo")
        add_version(tmp_path, runner, "1.0", "demo")

        version_dirpath = tmp_path / "versions" / "demo-1.0"
        write_minimal_disasm(version_dirpath, "demo", "1.0")

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
        init_project(tmp_path, runner, "demo", "demo")
        add_version(tmp_path, runner, "1.0", "demo")
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
        init_project(tmp_path, runner, "demo", "demo")
        add_version(tmp_path, runner, "1.0", "demo")

        version_dirpath = tmp_path / "versions" / "demo-1.0"
        write_minimal_disasm(version_dirpath, "demo", "1.0")

        result = runner.invoke(
            main,
            [
                "--project-root", str(tmp_path),
                "audit", "undeclared", "1.0", "--as", "tsv",
            ],
        )
        assert result.exit_code == 0, result.output


class TestAuditPlaceholders:
    def _write_asm(
        self, version_dirpath: Path, prefix: str, version_id: str, body: str
    ) -> Path:
        asm_filepath = (
            version_dirpath / "output" / f"{prefix}-{version_id}.asm"
        )
        asm_filepath.parent.mkdir(exist_ok=True)
        asm_filepath.write_text(body)
        return asm_filepath

    def _bootstrap(self, tmp_path: Path) -> tuple[CliRunner, Path]:
        runner = CliRunner()
        init_project(tmp_path, runner, "demo", "demo")
        add_version(tmp_path, runner, "1.0", "demo")
        version_dirpath = tmp_path / "versions" / "demo-1.0"
        write_minimal_disasm(version_dirpath, "demo", "1.0")
        return runner, version_dirpath

    def test_finds_sub_and_loop_placeholders(self, tmp_path: Path) -> None:
        runner, version_dirpath = self._bootstrap(tmp_path)
        self._write_asm(
            version_dirpath, "demo", "1.0",
            "; header\n.alpha\n  rts\n.sub_c8a6c\n  rts\n"
            ".loop_ca4fc\n  rts\n.l944c\n  rts\n",
        )

        result = runner.invoke(
            main,
            [
                "--project-root", str(tmp_path),
                "audit", "placeholders", "1.0", "--as", "tsv",
            ],
        )
        assert result.exit_code == 0, result.output
        assert "sub_c8a6c" in result.output
        assert "loop_ca4fc" in result.output
        assert "l944c" in result.output
        assert "&8A6C" in result.output

    def test_clean_asm_reports_zero_rows(self, tmp_path: Path) -> None:
        runner, version_dirpath = self._bootstrap(tmp_path)
        self._write_asm(
            version_dirpath, "demo", "1.0",
            ".alpha\n  rts\n.beta\n  rts\n",
        )
        result = runner.invoke(
            main,
            [
                "--project-root", str(tmp_path),
                "audit", "placeholders", "1.0", "--as", "tsv",
            ],
        )
        assert result.exit_code == 0, result.output
        # No data row for any of the placeholder kinds.
        for kind in ("auto-label", "sub-placeholder", "loop-placeholder"):
            assert kind not in result.output

    def test_missing_asm_does_not_break_summary(self, tmp_path: Path) -> None:
        # ``audit summary`` keeps working when the asm output isn't
        # present — the placeholders block is just empty. Avoids
        # making summary newly hard-dependent on a fresh py8dis run.
        runner, _ = self._bootstrap(tmp_path)
        result = runner.invoke(
            main,
            [
                "--project-root", str(tmp_path),
                "audit", "summary", "1.0", "--as", "tsv",
            ],
        )
        assert result.exit_code == 0, result.output

    def test_summary_surfaces_placeholders(self, tmp_path: Path) -> None:
        # Acceptance criterion: ``audit summary`` reports nonzero
        # placeholders when any are present in the asm output.
        runner, version_dirpath = self._bootstrap(tmp_path)
        self._write_asm(
            version_dirpath, "demo", "1.0",
            ".alpha\n  rts\n.sub_c8a6c\n  rts\n",
        )
        result = runner.invoke(
            main,
            [
                "--project-root", str(tmp_path),
                "audit", "summary", "1.0",
                "--report", "placeholders", "--as", "tsv",
            ],
        )
        assert result.exit_code == 0, result.output
        assert "sub_c8a6c" in result.output


class TestAuditDetail:
    def test_audit_detail(self, tmp_path: Path) -> None:
        runner = CliRunner()
        init_project(tmp_path, runner, "demo", "demo")
        add_version(tmp_path, runner, "1.0", "demo")

        version_dirpath = tmp_path / "versions" / "demo-1.0"
        write_minimal_disasm(version_dirpath, "demo", "1.0")

        result = runner.invoke(
            main,
            [
                "--project-root", str(tmp_path),
                "audit", "detail", "1.0", "alpha", "--as", "tsv",
            ],
        )
        assert result.exit_code == 0, result.output
        assert "alpha" in result.output
        assert "8000" in result.output

    def test_audit_detail_unknown_target(self, tmp_path: Path) -> None:
        runner = CliRunner()
        init_project(tmp_path, runner, "demo", "demo")
        add_version(tmp_path, runner, "1.0", "demo")

        version_dirpath = tmp_path / "versions" / "demo-1.0"
        write_minimal_disasm(version_dirpath, "demo", "1.0")

        result = runner.invoke(
            main,
            [
                "--project-root", str(tmp_path),
                "audit", "detail", "1.0", "nonexistent",
            ],
        )
        assert result.exit_code != 0
        assert "not found" in result.output
