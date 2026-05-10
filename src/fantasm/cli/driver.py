"""``fantasm driver`` — driver-script formatting / housekeeping commands.

A ``driver`` group rather than a flat command — leaves room for
future ``driver lint`` / ``driver normalise`` siblings without
re-shuffling the CLI.
"""

from __future__ import annotations

import difflib
import sys
from pathlib import Path

import click

from ..api.driver_sort import is_sorted, sort_driver_text


@click.group(
    "driver",
    help=(
        "Driver-script housekeeping (sorting, formatting). Operates "
        "on the dasmos / py8dis Python driver files that produce a "
        "version's disassembly output."
    ),
)
def driver() -> None:
    pass


@driver.command(
    "sort",
    help=(
        "Sort top-level annotation calls (label, comment, "
        "subroutine, banner, entry, byte, word, string, expr, "
        "expr_label, rts_code_ptr) in DRIVER_FILEPATH by primary "
        "address. Imports, Disassembler.create / load / add_move / "
        "use_environment / hook_subroutine, and any call with a "
        "non-literal first argument or inside an indented block "
        "are anchors that stay where they are and divide the file "
        "into independent sortable runs. Statement text is moved "
        "byte-for-byte; hex literals are not normalised."
    ),
)
@click.argument(
    "driver_filepath",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
@click.option(
    "--in-place",
    "-i",
    "in_place",
    is_flag=True,
    help=(
        "Rewrite DRIVER_FILEPATH in place. Without this flag, the "
        "sorted text is printed to stdout."
    ),
)
@click.option(
    "--check",
    is_flag=True,
    help=(
        "Don't write anything. Exit 0 if the file is already "
        "sorted; exit 1 with a unified diff on stderr otherwise. "
        "Useful for pre-commit / CI."
    ),
)
def driver_sort(
    driver_filepath: Path, in_place: bool, check: bool
) -> None:
    if in_place and check:
        raise click.UsageError("--in-place and --check are mutually exclusive")

    original_text = driver_filepath.read_text()

    if check:
        if is_sorted(original_text):
            return
        sorted_text = sort_driver_text(original_text)
        diff = difflib.unified_diff(
            original_text.splitlines(keepends=True),
            sorted_text.splitlines(keepends=True),
            fromfile=str(driver_filepath),
            tofile=f"{driver_filepath} (sorted)",
        )
        sys.stderr.writelines(diff)
        raise click.exceptions.Exit(1)

    sorted_text = sort_driver_text(original_text)

    if in_place:
        if sorted_text != original_text:
            driver_filepath.write_text(sorted_text)
        return

    click.echo(sorted_text, nl=False)
