"""Round-trip assembly verification.

Re-assembles a generated ``.asm`` file and compares the resulting
bytes against the original binary. Used to catch regressions where a
refactor changes the disassembler's output in a way that no longer
matches the source binary.

The assembler is ``beebasm`` by default. A project using another
assembler (or a wrapper script) describes how to run it with an
:class:`AssemblerConfig` — typically read from ``fantasm.toml``'s
``[verify]`` section by :meth:`AssemblerConfig.from_mapping`.

Sibling ``verify.py`` mixed the comparison with print/exit. The
fantasm port returns a :class:`VerifyResult` so callers (CLI,
tests, scripts) can format the outcome themselves.
"""

from __future__ import annotations

import shlex
import shutil
import subprocess
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class AssemblerNotFoundError(RuntimeError):
    """Raised when the configured assembler can't be found."""


class BeebasmNotFoundError(AssemblerNotFoundError):
    """Raised when ``beebasm`` is required but not on ``PATH``."""


class AssemblerOutputMissingError(RuntimeError):
    """The assembler succeeded but the expected output file is absent."""


class AssemblerConfigError(ValueError):
    """A ``[verify]`` assembler configuration is invalid."""


DEFAULT_ASSEMBLER_COMMAND = ("beebasm", "-i", "{asm}", "-o", "{output}")
DEFAULT_ASSEMBLER_CWD = "{asm_dirpath}"
DEFAULT_ASSEMBLER_OUTPUT = "{output}"

ASSEMBLER_TOKENS = (
    "asm", "asm_dirpath", "asm_filename", "output", "output_dirpath",
    "binary", "project_root",
)
ASSEMBLER_KEYS = frozenset({"command", "cwd", "output"})


@dataclass(frozen=True)
class AssemblerConfig:
    """How to assemble a listing for round-trip verification.

    ``command`` is the argument list; ``cwd`` the directory to run it
    in; ``output`` the file to compare against the original binary,
    relative to ``cwd`` unless absolute. Each may use these tokens:

    - ``{asm}`` — absolute path of the listing;
    - ``{asm_dirpath}`` / ``{asm_filename}`` — its directory and name;
    - ``{output}`` — a fresh temporary file path fantasm reads back
      (and deletes) afterwards;
    - ``{output_dirpath}`` — the temporary directory holding it;
    - ``{binary}`` — absolute path of the original binary;
    - ``{project_root}`` — the project root, when known.

    The defaults reproduce the built-in beebasm invocation:
    ``beebasm -i {asm} -o {output}`` run in the listing's directory,
    comparing ``{output}``. An assembler that always writes a fixed
    file — for example via a ``SAVE "NAME"`` directive — sets
    ``output`` to that file instead.
    """

    command: tuple[str, ...] = DEFAULT_ASSEMBLER_COMMAND
    cwd: str = DEFAULT_ASSEMBLER_CWD
    output: str = DEFAULT_ASSEMBLER_OUTPUT

    @property
    def is_default(self) -> bool:
        return self == AssemblerConfig()

    @property
    def display_name(self) -> str:
        """The assembler's name, for messages."""
        return Path(self.command[0]).name if self.command else "assembler"

    @classmethod
    def from_mapping(cls, settings: Mapping[str, Any]) -> AssemblerConfig:
        """Build from a ``[verify]`` table; missing keys keep defaults.

        ``command`` may be a list of arguments or a single string,
        which is split with shell-like quoting rules.
        """
        unknown = set(settings) - ASSEMBLER_KEYS
        if unknown:
            raise AssemblerConfigError(
                f"[verify] has unknown key(s): {', '.join(sorted(unknown))}; "
                f"recognised keys are {', '.join(sorted(ASSEMBLER_KEYS))}"
            )
        command: Any = settings.get("command", DEFAULT_ASSEMBLER_COMMAND)
        if isinstance(command, str):
            command = shlex.split(command)
        if (
            not isinstance(command, (list, tuple))
            or not command
            or not all(isinstance(arg, str) for arg in command)
        ):
            raise AssemblerConfigError(
                "[verify] command must be a non-empty list of strings "
                "(or a single command-line string)"
            )
        values = {}
        for key, default in (
            ("cwd", DEFAULT_ASSEMBLER_CWD),
            ("output", DEFAULT_ASSEMBLER_OUTPUT),
        ):
            value = settings.get(key, default)
            if not isinstance(value, str) or not value:
                raise AssemblerConfigError(
                    f"[verify] {key} must be a non-empty string"
                )
            values[key] = value
        config = cls(command=tuple(command), **values)
        for text in (*config.command, config.cwd, config.output):
            _render(text, _placeholder_tokens())
        return config


def _placeholder_tokens() -> dict[str, str]:
    return {token: token for token in ASSEMBLER_TOKENS}


def _render(template: str, tokens: Mapping[str, str]) -> str:
    try:
        return template.format(**tokens)
    except (KeyError, IndexError, ValueError) as exc:
        raise AssemblerConfigError(
            f"[verify] {template!r}: unknown or malformed token ({exc}); "
            "recognised tokens are "
            + ", ".join(f"{{{t}}}" for t in ASSEMBLER_TOKENS)
        ) from exc


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
    *,
    assembler: AssemblerConfig | None = None,
    project_root_dirpath: Path | None = None,
) -> VerifyResult:
    """Assemble ``asm_filepath`` and compare it to ``rom_filepath``.

    ``assembler`` describes how to assemble (default: beebasm, see
    :class:`AssemblerConfig`). ``beebasm_filepath`` may be passed
    explicitly (e.g. from the ``beebasm_filepath`` test fixture) and
    replaces a ``beebasm`` command name; otherwise a bare command name
    is looked up on ``PATH``, and a relative path with a directory part
    resolves against ``project_root_dirpath`` (when given).

    Raises :class:`BeebasmNotFoundError` (or, for another assembler,
    :class:`AssemblerNotFoundError`) if the assembler isn't found,
    ``FileNotFoundError`` for missing inputs, and
    :class:`AssemblerOutputMissingError` if the assembler succeeded
    but didn't write the expected output file.

    When the binary is larger than the assembled output (sub-banked
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

    if assembler is None:
        assembler = AssemblerConfig()

    rom_bytes = Path(rom_filepath).read_bytes()
    rom_file_size = len(rom_bytes)

    # By default the assembler runs from the listing's own directory so
    # relative file directives (INCBIN/PUTFILE/PUTBASIC) resolve against
    # the payload sitting beside the listing, not against fantasm's
    # invocation directory. Paths handed to it are absolute so they are
    # unaffected by the working-directory change.
    asm_filepath = Path(asm_filepath).resolve()

    with tempfile.TemporaryDirectory() as tmp_dirname:
        tmp_dirpath = Path(tmp_dirname)
        tokens = {
            "asm": str(asm_filepath),
            "asm_dirpath": str(asm_filepath.parent),
            "asm_filename": asm_filepath.name,
            "output": str(tmp_dirpath / "assembled.bin"),
            "output_dirpath": str(tmp_dirpath),
            "binary": str(Path(rom_filepath).resolve()),
            "project_root": (
                str(project_root_dirpath) if project_root_dirpath else ""
            ),
        }
        command = [_render(arg, tokens) for arg in assembler.command]
        cwd_dirpath = Path(_render(assembler.cwd, tokens))
        if not cwd_dirpath.is_absolute() and project_root_dirpath is not None:
            cwd_dirpath = project_root_dirpath / cwd_dirpath
        output_filepath = Path(_render(assembler.output, tokens))
        if not output_filepath.is_absolute():
            output_filepath = cwd_dirpath / output_filepath

        command[0] = _resolve_executable(
            command[0], beebasm_filepath, project_root_dirpath
        )

        result = subprocess.run(
            command,
            cwd=str(cwd_dirpath),
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
            assembled_bytes = output_filepath.read_bytes()
        except FileNotFoundError as exc:
            raise AssemblerOutputMissingError(
                f"{assembler.display_name} did not produce an output file "
                f"(expected {output_filepath})"
            ) from exc

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


def _resolve_executable(
    name: str,
    beebasm_filepath: Path | str | None,
    project_root_dirpath: Path | None,
) -> str:
    """Locate the assembler executable named by ``command[0]``."""
    if name == "beebasm" and beebasm_filepath is not None:
        return str(beebasm_filepath)
    if "/" in name or "\\" in name:
        executable_filepath = Path(name)
        if not executable_filepath.is_absolute() and project_root_dirpath:
            executable_filepath = project_root_dirpath / executable_filepath
        if not executable_filepath.exists():
            raise AssemblerNotFoundError(
                f"assembler not found: {executable_filepath} "
                "(configured in [verify] command)"
            )
        return str(executable_filepath)
    found = shutil.which(name)
    if found is not None:
        return found
    if name == "beebasm":
        raise BeebasmNotFoundError(
            "beebasm not found on PATH; install beebasm v1.10 or later "
            "from https://github.com/stardot/beebasm"
        )
    raise AssemblerNotFoundError(
        f"assembler {name!r} not found on PATH (configured in [verify] command)"
    )


__all__ = [
    "ASSEMBLER_KEYS",
    "ASSEMBLER_TOKENS",
    "AssemblerConfig",
    "AssemblerConfigError",
    "AssemblerNotFoundError",
    "AssemblerOutputMissingError",
    "BeebasmNotFoundError",
    "DEFAULT_ASSEMBLER_COMMAND",
    "DEFAULT_ASSEMBLER_CWD",
    "DEFAULT_ASSEMBLER_OUTPUT",
    "VerifyResult",
    "verify_round_trip",
]
