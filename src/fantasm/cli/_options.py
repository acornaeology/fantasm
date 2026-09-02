"""Shared Click option decorators for fantasm CLI commands.

``--cpu`` and ``--base-address`` (aliased ``--rom-base``) repeat across
the cross-version commands (compare, fingerprint, backfill, annotations
diff, addresses map). Both default to ``None`` so callers can fall back
to project-level ``[binary]`` (or ``[rom]``) config via
:func:`fantasm.cli_helpers.project_cpu` /
:func:`fantasm.cli_helpers.project_binary_base`.

``project init`` uses its own ``--cpu`` (default ``"6502"``) because it
writes the project config rather than reading it; that variant lives
inline in :mod:`fantasm.cli.project` rather than here.
"""

from __future__ import annotations

import click

cpu_option = click.option(
    "--cpu",
    default=None,
    help='CPU override; defaults to [binary]/[rom] cpu (or "6502").',
)

rom_base_option = click.option(
    "--base-address",
    "--rom-base",
    "rom_base",
    type=click.IntRange(0, 0xFFFF),
    default=None,
    help="Load address; defaults to [binary] base_address (or [rom], or 0x8000).",
)


LABEL_SORT_KEYS = ("name", "addr", "len", "refs", "direct", "idx")


label_sort_option = click.option(
    "--sort",
    "sort_key",
    type=click.Choice(LABEL_SORT_KEYS, case_sensitive=False),
    default="name",
    show_default=True,
    help="Sort key.",
)

label_reverse_option = click.option(
    "--reverse",
    is_flag=True,
    help="Reverse the sort order.",
)

label_min_length_option = click.option(
    "--min-length",
    type=click.IntRange(1, 256),
    default=None,
    help="Only labels at least N characters long.",
)

label_max_length_option = click.option(
    "--max-length",
    type=click.IntRange(1, 256),
    default=None,
    help="Only labels at most N characters long.",
)

label_match_option = click.option(
    "--match",
    "match_pattern",
    default=None,
    help="Only labels whose name matches this regular expression.",
)

label_index_base_only_option = click.option(
    "--index-base-only",
    is_flag=True,
    help=(
        "Only labels whose references are exclusively indexing-base "
        "accesses (lda addr,X / sta addr,Y) — the d.index_base() "
        "conversion candidates. Labels with no references are excluded."
    ),
)

label_source_option = click.option(
    "--source",
    type=click.Choice(["driver", "env", "all"], case_sensitive=False),
    default="all",
    show_default=True,
    help=(
        "Restrict to driver-defined labels, environment-supplied "
        "constants, or both."
    ),
)
