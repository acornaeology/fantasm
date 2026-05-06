"""``fantasm disassemble`` — run a version's disassembly driver script.

Resolves the driver filepath via fantasm.toml's
``[versions] driver_dirname/driver_filename`` and runs it as a
subprocess with two environment variables pointing at the
conventional ROM and output locations:

- ``FANTASM_ROM``        — ``<version_dir>/rom/<prefix>-<version>.rom``
- ``FANTASM_OUTPUT_DIR`` — ``<version_dir>/output``

The driver itself is library-agnostic — typically built on
:mod:`dasmos` or :mod:`py8dis`, but fantasm only sees the artefacts
it emits (``.asm``, ``.json``). Drivers that already have their own
per-project env-var fallbacks (``ACORN_NFS_ROM`` etc.) keep working
— fantasm sets the project-agnostic names alongside; the driver
picks whichever it recognises.

The command exits with the driver script's own return code, so a
non-zero exit propagates straight back through CI.
"""

from __future__ import annotations

import os
import subprocess
import sys

import click

from ..cli_helpers import analysis_context


@click.command(
    "disassemble",
    help=(
        "Run the version's disassembly driver script to (re-)generate "
        "the .asm and .json disassembly artefacts. The driver lives "
        "at <versions>/<prefix>-<VERSION_ID>/<driver_dirname>/"
        "<driver_filename> and is run with FANTASM_ROM and "
        "FANTASM_OUTPUT_DIR set to the conventional paths under "
        "the version directory."
    ),
)
@click.argument("version_id")
@click.pass_context
def disassemble(ctx: click.Context, version_id: str) -> None:
    actx = analysis_context(ctx, version_id)
    driver_filepath = actx.files.driver_filepath
    if not driver_filepath.exists():
        raise click.UsageError(
            f"driver script not found: {driver_filepath}"
        )

    output_dirpath = actx.files.json_filepath.parent
    output_dirpath.mkdir(parents=True, exist_ok=True)

    env = os.environ.copy()
    env["FANTASM_ROM"] = str(actx.files.rom_filepath)
    env["FANTASM_OUTPUT_DIR"] = str(output_dirpath)

    result = subprocess.run(
        [sys.executable, str(driver_filepath)],
        env=env,
    )
    ctx.exit(result.returncode)
