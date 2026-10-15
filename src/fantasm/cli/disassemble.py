"""``fantasm disassemble`` — run a target's disassembly driver script.

Resolves the target's driver script (from the ``versions/``
convention, ``[layout]`` or its ``[[targets]]`` entry) and runs it as
a subprocess with environment variables describing the target:

- ``FANTASM_TARGET``     — the target id
- ``FANTASM_BINARY``     — the target's program binary
- ``FANTASM_ROM``        — the same path, kept for back-compat with
  drivers that read the older name
- ``FANTASM_IMAGES``     — a JSON list describing the binary image(s):
  ``[{"name", "path", "load_addr", "exec_addr"}]`` (``name`` and
  ``exec_addr`` may be ``null``)
- ``FANTASM_ASM`` / ``FANTASM_JSON`` — where fantasm expects the
  generated ``.asm`` / ``.json``
- ``FANTASM_OUTPUT_DIR`` — the directory holding the ``.json``
  (``<version_dir>/output`` under the convention)

The driver itself is library-agnostic — typically built on
:mod:`dasmos` or :mod:`py8dis`, but fantasm only sees the artefacts
it emits (``.asm``, ``.json``). A driver is free to ignore all of
these and use its own hard-coded paths, as long as its outputs land
where fantasm's configuration says they do. Drivers that already
have their own per-project env-var fallbacks (``ACORN_NFS_ROM`` etc.)
keep working — fantasm sets the project-agnostic names alongside;
the driver picks whichever it recognises.

The driver runs in the current working directory unless the target
configures ``driver_cwd``. The command exits with the driver script's
own return code, so a non-zero exit propagates straight back through
CI.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

import click

from ..cli_helpers import analysis_context, target_load_address
from ._target import TargetCommand, target_argument


@click.command(
    "disassemble",
    cls=TargetCommand,
    help=(
        "Run the target's disassembly driver script to (re-)generate "
        "the .asm and .json disassembly artefacts. The driver is run "
        "with FANTASM_TARGET, FANTASM_BINARY (and its FANTASM_ROM "
        "back-compat alias), FANTASM_IMAGES, FANTASM_ASM, FANTASM_JSON "
        "and FANTASM_OUTPUT_DIR describing the target's configured "
        "paths."
    ),
)
@target_argument()
@click.pass_context
def disassemble(ctx: click.Context, version_id: str) -> None:
    actx = analysis_context(ctx, version_id)
    driver_filepath = actx.files.driver_filepath
    if not driver_filepath.exists():
        raise click.UsageError(
            f"driver script not found: {driver_filepath}"
        )

    files = actx.files
    output_dirpath = files.json_filepath.parent
    output_dirpath.mkdir(parents=True, exist_ok=True)
    files.asm_filepath.parent.mkdir(parents=True, exist_ok=True)

    env = os.environ.copy()
    binary_filepath = str(files.binary_filepath)
    env["FANTASM_TARGET"] = files.version_id
    env["FANTASM_BINARY"] = binary_filepath
    # Retained alongside FANTASM_BINARY so existing driver scripts that
    # read the older name keep working.
    env["FANTASM_ROM"] = binary_filepath
    env["FANTASM_IMAGES"] = json.dumps([{
        "name": files.image_name,
        "path": binary_filepath,
        "load_addr": target_load_address(actx.project, files),
        "exec_addr": files.exec_address,
    }])
    env["FANTASM_ASM"] = str(files.asm_filepath)
    env["FANTASM_JSON"] = str(files.json_filepath)
    env["FANTASM_OUTPUT_DIR"] = str(output_dirpath)

    run_kwargs = {}
    if files.driver_cwd_dirpath is not None:
        run_kwargs["cwd"] = str(files.driver_cwd_dirpath)
    result = subprocess.run(
        [sys.executable, str(driver_filepath)],
        env=env,
        **run_kwargs,
    )
    ctx.exit(result.returncode)
