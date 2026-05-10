"""Click-based command-line entrypoint for fantasm.

Each subcommand or sub-group lives in its own module. This package
``__init__`` is responsible for assembling them onto the top-level
``main`` group so ``pyproject.toml``'s ``fantasm = "fantasm.cli:main"``
script entrypoint resolves to a fully-wired CLI.
"""

from __future__ import annotations

from .addresses import addresses
from .annotations import annotations
from .asm import asm
from .audit import audit
from .backfill import backfill_cmd
from .bytes import bytes_group
from .cfg import cfg
from .comments import comments
from .compare import compare
from .context import context
from .coverage import coverage
from .data import data_group
from .disassemble import disassemble
from .driver import driver
from .fingerprint import fingerprint_cmd
from .hooks import hooks_group
from .labels import labels
from .lint import lint_annotations
from .main import main
from .project import project
from .promote import promote_cmd
from .shared import shared
from .sub import sub
from .verify import verify

for _cmd in (
    addresses,
    annotations,
    asm,
    audit,
    backfill_cmd,
    bytes_group,
    cfg,
    comments,
    compare,
    context,
    coverage,
    data_group,
    disassemble,
    driver,
    fingerprint_cmd,
    hooks_group,
    labels,
    lint_annotations,
    project,
    promote_cmd,
    shared,
    sub,
    verify,
):
    main.add_command(_cmd)
del _cmd

__all__ = ["main"]
