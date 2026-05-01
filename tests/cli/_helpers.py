"""Shared helpers for fantasm CLI command tests.

These tests exercise the Click entrypoints against a hand-crafted
project tree, so each one needs to bootstrap fantasm.toml + a
version directory + a minimal JSON disassembly. Helpers live here so
the per-command test modules don't repeat the boilerplate.
"""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from fantasm.cli import main


def init_project(
    tmp_path: Path, runner: CliRunner, name: str = "test", *prefixes: str
) -> None:
    """Run ``fantasm project init`` against ``tmp_path``."""
    args = ["project", "init", "--name", name, "--at", str(tmp_path)]
    for prefix in prefixes:
        args.extend(["--prefix", prefix])
    runner.invoke(main, args)


def add_version(
    tmp_path: Path,
    runner: CliRunner,
    version_id: str,
    prefix: str | None = None,
) -> None:
    """Run ``fantasm project add VERSION_ID`` against ``tmp_path``."""
    args = [
        "--project-root", str(tmp_path),
        "project", "add", version_id,
    ]
    if prefix is not None:
        args.extend(["--prefix", prefix])
    runner.invoke(main, args)


def write_minimal_disasm(
    version_dirpath: Path, prefix: str, version_id: str
) -> Path:
    """Write a minimal JSON disassembly file under the version's output/ dir."""
    output_dirpath = version_dirpath / "output"
    output_dirpath.mkdir(exist_ok=True)
    json_filepath = output_dirpath / f"{prefix}-{version_id}.json"
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
