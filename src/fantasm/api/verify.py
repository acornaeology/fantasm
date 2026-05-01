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

    ``matched`` is ``True`` when the assembled bytes equal the ROM.
    On a miss, ``first_diff_offset`` is the byte offset of the first
    differing byte (or, if one stream is shorter, the length of the
    shorter stream).

    ``beebasm_returncode`` and ``beebasm_stderr`` capture the
    assembler's exit info; both are populated even on success.
    """

    matched: bool
    rom_size: int
    assembled_size: int
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

    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tmp:
        tmp_filepath = Path(tmp.name)

    try:
        result = subprocess.run(
            [
                str(beebasm_filepath),
                "-i", str(asm_filepath),
                "-o", str(tmp_filepath),
            ],
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            return VerifyResult(
                matched=False,
                rom_size=len(rom_bytes),
                assembled_size=0,
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

    if rom_bytes == assembled_bytes:
        return VerifyResult(
            matched=True,
            rom_size=len(rom_bytes),
            assembled_size=len(assembled_bytes),
            first_diff_offset=None,
            beebasm_returncode=0,
            beebasm_stderr=result.stderr or "",
        )

    min_len = min(len(rom_bytes), len(assembled_bytes))
    first_diff = min_len  # default for length-only differences
    for i in range(min_len):
        if rom_bytes[i] != assembled_bytes[i]:
            first_diff = i
            break

    return VerifyResult(
        matched=False,
        rom_size=len(rom_bytes),
        assembled_size=len(assembled_bytes),
        first_diff_offset=first_diff,
        beebasm_returncode=0,
        beebasm_stderr=result.stderr or "",
    )


__all__ = [
    "BeebasmNotFoundError",
    "VerifyResult",
    "verify_round_trip",
]
