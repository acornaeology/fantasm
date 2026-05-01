"""Shared Click option decorators for fantasm CLI commands.

``--cpu`` and ``--rom-base`` repeat across the cross-version commands
(compare, fingerprint, backfill, annotations diff, addresses map).
Both default to ``None`` so callers can fall back to project-level
``[rom]`` config via :func:`fantasm.cli_helpers.project_cpu` /
:func:`fantasm.cli_helpers.project_rom_base`.

``project init`` uses its own ``--cpu`` (default ``"6502"``) because it
writes the project config rather than reading it; that variant lives
inline in :mod:`fantasm.cli.project` rather than here.
"""

from __future__ import annotations

import click

cpu_option = click.option(
    "--cpu",
    default=None,
    help='CPU override; defaults to [rom] cpu in fantasm.toml (or "6502").',
)

rom_base_option = click.option(
    "--rom-base",
    type=click.IntRange(0, 0xFFFF),
    default=None,
    help="ROM load address; defaults to [rom] base_address (or 0x8000).",
)
