"""Tests for ``fantasm shared``."""

from __future__ import annotations

from click.testing import CliRunner

from fantasm.cli import main


def test_shared_help() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["shared", "--help"])
    assert result.exit_code == 0
    assert "[label=]path@load-addr" in result.output


def test_shared_invalid_spec() -> None:
    runner = CliRunner()
    # No @load-addr.
    result = runner.invoke(
        main, ["shared", "/nonexistent.rom", "/other.rom@&8000"]
    )
    assert result.exit_code != 0
    assert "@" in result.output or "load" in result.output.lower()
