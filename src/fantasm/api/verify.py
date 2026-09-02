"""Round-trip assembly verification.

Re-assembles a generated ``.asm`` file with ``beebasm`` and compares
the resulting bytes against the original ROM. Used to catch
regressions where a refactor changes the disassembler's output in a
way that no longer matches the source ROM.

Sibling ``verify.py`` mixed the comparison with print/exit. The
fantasm port returns a :class:`VerifyResult` so callers (CLI,
tests, scripts) can format the outcome themselves.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path


class BeebasmNotFoundError(RuntimeError):
    """Raised when ``beebasm`` is required but not on ``PATH``."""


@dataclass(frozen=True)
class VerifyResult:
    """Outcome of a round-trip verification.

    ``matched`` is ``True`` when the assembled bytes equal the ROM
    bytes used for comparison. On a miss, ``first_diff_offset`` is
    the byte offset of the first differing byte (or, if one stream
    is shorter, the length of the shorter stream).

    For sub-banked ROM images (where the file is larger than what
    is mapped at runtime — e.g. the Tube Client's 4 KB image with
    only the upper 2 KB live at &F800-&FFFF), the comparison runs
    against the trailing portion of the ROM file matching the
    assembled output's length. ``rom_size`` is then the file size
    while ``compared_size`` is the trailing-slice length actually
    compared. When no slice is needed the two are equal.

    ``beebasm_returncode`` and ``beebasm_stderr`` capture the
    assembler's exit info; both are populated even on success.
    """

    matched: bool
    rom_size: int
    assembled_size: int
    compared_size: int
    first_diff_offset: int | None
    beebasm_returncode: int
    beebasm_stderr: str


def verify_round_trip(
    rom_filepath: Path,
    asm_filepath: Path,
    beebasm_filepath: Path | str | None = None,
) -> VerifyResult:
    """Assemble ``asm_filepath`` with beebasm and compare to ``rom_filepath``.

    ``beebasm_filepath`` may be passed explicitly (e.g. from the
    ``beebasm_filepath`` test fixture); when ``None``, looked up on
    ``PATH``. Raises :class:`BeebasmNotFoundError` if not found,
    ``FileNotFoundError`` for missing inputs, ``RuntimeError`` if
    beebasm failed to produce output.

    When the ROM file is larger than the assembled output (sub-banked
    ROM images, like the Tube Client's 4 KB file of which only the
    upper 2 KB is mapped at &F800-&FFFF), the comparison runs against
    the trailing portion of the file matching the assembled length.
    The unsliced file size is reported on the result as ``rom_size``
    and the slice length as ``compared_size``.
    """
    if not Path(rom_filepath).exists():
        raise FileNotFoundError(f"ROM file not found: {rom_filepath}")
    if not Path(asm_filepath).exists():
        raise FileNotFoundError(f"assembly file not found: {asm_filepath}")

    if beebasm_filepath is None:
        found = shutil.which("beebasm")
        if found is None:
            raise BeebasmNotFoundError(
                "beebasm not found on PATH; install beebasm v1.10 or later "
                "from https://github.com/stardot/beebasm"
            )
        beebasm_filepath = found

    rom_bytes = Path(rom_filepath).read_bytes()
    rom_file_size = len(rom_bytes)

    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tmp:
        tmp_filepath = Path(tmp.name)

    # Run beebasm from the listing's own directory so relative file
    # directives (INCBIN/PUTFILE/PUTBASIC) resolve against the payload
    # sitting beside the listing, not against fantasm's invocation
    # directory. ``-i``/``-o`` are made absolute so they are unaffected
    # by the working-directory change.
    asm_filepath = Path(asm_filepath).resolve()

    try:
        result = subprocess.run(
            [
                str(beebasm_filepath),
                "-i", str(asm_filepath),
                "-o", str(tmp_filepath),
            ],
            cwd=str(asm_filepath.parent),
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            return VerifyResult(
                matched=False,
                rom_size=rom_file_size,
                assembled_size=0,
                compared_size=rom_file_size,
                first_diff_offset=None,
                beebasm_returncode=result.returncode,
                beebasm_stderr=(result.stderr or "") + (result.stdout or ""),
            )

        try:
            assembled_bytes = tmp_filepath.read_bytes()
        except FileNotFoundError as exc:
            raise RuntimeError(
                "beebasm did not produce an output file"
            ) from exc
    finally:
        tmp_filepath.unlink(missing_ok=True)

    # Sub-banked ROMs: when the file is longer than what was
    # assembled, the leading bytes are unmapped padding — compare
    # only the trailing portion. Strict size match still applies
    # when assembled is longer, since extra assembled bytes
    # genuinely don't fit the ROM.
    if len(rom_bytes) > len(assembled_bytes):
        rom_compare_bytes = rom_bytes[-len(assembled_bytes):]
    else:
        rom_compare_bytes = rom_bytes
    compared_size = len(rom_compare_bytes)

    if rom_compare_bytes == assembled_bytes:
        return VerifyResult(
            matched=True,
            rom_size=rom_file_size,
            assembled_size=len(assembled_bytes),
            compared_size=compared_size,
            first_diff_offset=None,
            beebasm_returncode=0,
            beebasm_stderr=result.stderr or "",
        )

    min_len = min(len(rom_compare_bytes), len(assembled_bytes))
    first_diff = min_len  # default for length-only differences
    for i in range(min_len):
        if rom_compare_bytes[i] != assembled_bytes[i]:
            first_diff = i
            break

    return VerifyResult(
        matched=False,
        rom_size=rom_file_size,
        assembled_size=len(assembled_bytes),
        compared_size=compared_size,
        first_diff_offset=first_diff,
        beebasm_returncode=0,
        beebasm_stderr=result.stderr or "",
    )


__all__ = [
    "BeebasmNotFoundError",
    "VerifyResult",
    "verify_round_trip",
]
