"""Tests for ``fantasm disassemble``."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from fantasm.cli import main

from ._helpers import add_version, init_project


def _write_driver(driver_filepath: Path, body: str) -> None:
    """Write a tiny stand-in driver script to ``driver_filepath``."""
    driver_filepath.parent.mkdir(parents=True, exist_ok=True)
    driver_filepath.write_text(body)


def test_disassemble_runs_driver_and_passes_env(tmp_path: Path) -> None:
    runner = CliRunner()
    init_project(tmp_path, runner, "demo", "demo")
    add_version(tmp_path, runner, "1.0", "demo")

    version_dirpath = tmp_path / "versions" / "demo-1.0"
    rom_filepath = version_dirpath / "rom" / "demo-1.0.rom"
    rom_filepath.parent.mkdir(parents=True, exist_ok=True)
    rom_filepath.write_bytes(b"\x60")

    output_dirpath = version_dirpath / "output"
    driver_filepath = version_dirpath / "disassemble" / "disasm_demo_10.py"
    _write_driver(
        driver_filepath,
        "import os\n"
        "from pathlib import Path\n"
        "rom = os.environ['FANTASM_ROM']\n"
        "out = Path(os.environ['FANTASM_OUTPUT_DIR'])\n"
        "(out / 'env_dump.txt').write_text(f'rom={rom}\\nout={out}\\n')\n",
    )

    result = runner.invoke(
        main,
        [
            "--project-root", str(tmp_path),
            "disassemble", "1.0",
        ],
    )
    assert result.exit_code == 0, result.output

    dump_filepath = output_dirpath / "env_dump.txt"
    assert dump_filepath.exists()
    contents = dump_filepath.read_text()
    assert f"rom={rom_filepath}" in contents
    assert f"out={output_dirpath}" in contents


def test_disassemble_propagates_driver_exit_code(tmp_path: Path) -> None:
    runner = CliRunner()
    init_project(tmp_path, runner, "demo", "demo")
    add_version(tmp_path, runner, "1.0", "demo")

    version_dirpath = tmp_path / "versions" / "demo-1.0"
    (version_dirpath / "rom").mkdir(parents=True, exist_ok=True)
    (version_dirpath / "rom" / "demo-1.0.rom").write_bytes(b"")

    driver_filepath = version_dirpath / "disassemble" / "disasm_demo_10.py"
    _write_driver(
        driver_filepath,
        "import sys\nsys.exit(7)\n",
    )

    result = runner.invoke(
        main,
        [
            "--project-root", str(tmp_path),
            "disassemble", "1.0",
        ],
    )
    assert result.exit_code == 7


def test_disassemble_missing_driver_errors(tmp_path: Path) -> None:
    runner = CliRunner()
    init_project(tmp_path, runner, "demo", "demo")
    add_version(tmp_path, runner, "1.0", "demo")

    result = runner.invoke(
        main,
        [
            "--project-root", str(tmp_path),
            "disassemble", "1.0",
        ],
    )
    assert result.exit_code != 0
    assert "driver script not found" in result.output


def test_disassemble_help_lists_env_var_names() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["disassemble", "--help"])
    assert result.exit_code == 0
    assert "FANTASM_ROM" in result.output
    assert "FANTASM_OUTPUT_DIR" in result.output
