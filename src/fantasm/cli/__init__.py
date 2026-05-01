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
from .cfg import cfg
from .comments import comments
from .compare import compare
from .context import context
from .fingerprint import fingerprint_cmd
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
    cfg,
    comments,
    compare,
    context,
    fingerprint_cmd,
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
