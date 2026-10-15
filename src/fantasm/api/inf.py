"""Parse Acorn ``.inf`` sidecar files.

Files extracted from Acorn DFS, ADFS and Econet discs usually travel
with a ``.inf`` sidecar recording the attributes the host filing
system can't hold: load address, execution address, length and
access. There is no single format — every archiving tool wrote its
own variant — but they share a shape: one line holding the file's
name followed by whitespace-separated fields. Typical examples::

    $.ELITE     FF1900 FF8023 000400 L
    $.ELITE     001900 008023 Locked CRC=1A2B NEXT $.ELITE2
    FS3         00001900 00001900 00004C00 33
    "My File"   &1900 &8023 &400 WR/r CRC32=0123ABCD
    $.LOADER    FFFF0E00 FFFF0E00 00000300 19 CRC=E4AB

The parser is deliberately tolerant:

- the filename may be quoted; a leading ``&`` / ``0x`` number in
  place of a filename is taken as "no filename";
- numbers are hexadecimal, with or without a ``&``, ``$`` or ``0x``
  prefix, and of any width (6-digit DFS and 8-digit ADFS fields are
  both common);
- the numeric fields fill *load*, *exec*, *length* and *access* in
  that order; trailing ones may be absent;
- ``L`` / ``Locked`` marks a locked file; ADFS-style access strings
  such as ``WR/r`` are recorded as the access field;
- ``KEY=VALUE`` extras (``CRC=``, ``CRC32=``, ``NEXT=``,
  ``DATETIME=`` …) and the older ``CRC 1A2B`` / ``NEXT $.FILE``
  keyword-then-value forms are collected and otherwise ignored.

Addresses are recorded as written; :func:`inf_address` reduces one to
the 16-bit 6502 address it denotes, accepting the ``FF``/``FFFF``
"I/O processor" high bits and rejecting values that aren't addresses
at all (such as a RISC OS filetype-and-timestamp stamp).
"""

from __future__ import annotations

import re
import shlex
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path


class InfParseError(ValueError):
    """A ``.inf`` file can't be parsed, or holds no usable address."""


@dataclass(frozen=True)
class InfRecord:
    """The fields of one ``.inf`` line, as written.

    ``load_address`` and ``exec_address`` are the raw values (which
    may carry high-order bits); use :meth:`load_address_16` /
    :meth:`exec_address_16` for the 6502 address.
    """

    filename: str | None
    load_address: int
    exec_address: int | None = None
    length: int | None = None
    access: str | None = None
    locked: bool = False
    extras: Mapping[str, str] = field(default_factory=dict)

    def load_address_16(self) -> int:
        """The 16-bit load address. Raises :class:`InfParseError`."""
        return inf_address(self.load_address, "load")

    def exec_address_16(self) -> int | None:
        """The 16-bit execution address, or ``None`` when absent."""
        if self.exec_address is None:
            return None
        return inf_address(self.exec_address, "exec")


_HEX_RE = re.compile(r"^(?:&|\$|0[xX])?([0-9A-Fa-f]+)$")
_PREFIXED_HEX_RE = re.compile(r"^(?:&|0[xX])[0-9A-Fa-f]+$")
_ACCESS_STRING_RE = re.compile(r"^[LWREDPlwredp]*/[LWREDPlwredp]*$")
_LOCKED_TOKENS = {"l", "locked"}
# Older tools write these as a keyword followed by a separate value.
_KEYWORDS_WITH_VALUE = {"crc", "crc32", "next"}


def _hex_value(token: str) -> int | None:
    match = _HEX_RE.match(token)
    if match is None:
        return None
    return int(match.group(1), 16)


def inf_address(value: int, field_name: str = "load") -> int:
    """Reduce a ``.inf`` address field to a 16-bit 6502 address.

    Values up to ``&FFFF`` are returned unchanged. Values whose high
    bits are all set (``&FFxxxx`` / ``&FFFFxxxx``) mark an I/O
    processor address and are reduced to their low 16 bits. Anything
    else — a second-processor address, or a RISC OS
    filetype-and-timestamp stamp (``&FFFtttdd``) — raises
    :class:`InfParseError`.
    """
    if value <= 0xFFFF:
        return value
    high = value >> 16
    if high in (0xFF, 0xFFFF):
        return value & 0xFFFF
    if value >> 20 == 0xFFF:
        raise InfParseError(
            f"{field_name} address &{value:08X} is a RISC OS filetype "
            "and timestamp stamp, not a 6502 address"
        )
    raise InfParseError(
        f"{field_name} address &{value:X} is not a 16-bit 6502 address"
    )


def _first_line(text: str) -> str | None:
    for line in text.lstrip("﻿").splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            return stripped
    return None


def parse_inf(text: str, *, source: str | None = None) -> InfRecord:
    """Parse the text of a ``.inf`` file.

    ``source`` names the file in error messages. Raises
    :class:`InfParseError` when the text holds no line, or no load
    address can be found.
    """
    where = f"{source}: " if source else ""
    line = _first_line(text)
    if line is None:
        raise InfParseError(f"{where}empty .inf file")
    try:
        tokens = shlex.split(line, posix=True)
    except ValueError:
        tokens = line.split()
    if not tokens:
        raise InfParseError(f"{where}empty .inf file")

    filename: str | None = tokens[0]
    rest = tokens[1:]
    if _PREFIXED_HEX_RE.match(tokens[0]):
        filename = None
        rest = tokens

    numbers: list[int] = []
    access: str | None = None
    locked = False
    extras: dict[str, str] = {}
    unrecognised: list[str] = []

    index = 0
    while index < len(rest):
        token = rest[index]
        index += 1
        lowered = token.lower()
        if "=" in token:
            key, _, value = token.partition("=")
            extras[key.upper()] = value
            continue
        if lowered in _KEYWORDS_WITH_VALUE:
            if index < len(rest):
                extras[token.upper()] = rest[index]
                index += 1
            continue
        if lowered in _LOCKED_TOKENS:
            locked = True
            continue
        if _ACCESS_STRING_RE.match(token):
            access = token
            locked = locked or "L" in token.split("/")[0].upper()
            continue
        value = _hex_value(token)
        if value is not None and len(numbers) < 4:
            if len(numbers) == 3:
                access = token
            numbers.append(value)
            continue
        unrecognised.append(token)

    if not numbers:
        detail = (
            f" (unrecognised fields: {' '.join(unrecognised)})"
            if unrecognised
            else ""
        )
        raise InfParseError(f"{where}no load address found{detail}")

    return InfRecord(
        filename=filename,
        load_address=numbers[0],
        exec_address=numbers[1] if len(numbers) > 1 else None,
        length=numbers[2] if len(numbers) > 2 else None,
        access=access,
        locked=locked,
        extras=extras,
    )


def read_inf(inf_filepath: str | Path) -> InfRecord:
    """Read and parse a ``.inf`` file. Raises :class:`InfParseError`."""
    inf_filepath = Path(inf_filepath)
    try:
        text = inf_filepath.read_text(encoding="latin-1")
    except OSError as exc:
        raise InfParseError(f"{inf_filepath}: {exc.strerror}") from exc
    return parse_inf(text, source=str(inf_filepath))


def sidecar_inf_filepath(binary_filepath: str | Path) -> Path | None:
    """Return the existing ``.inf`` sidecar for a binary, else ``None``.

    Tries ``NAME.inf`` / ``NAME.INF`` beside ``NAME``, then — for a
    binary with an extension, such as ``FS3.bin`` — ``FS3.inf`` /
    ``FS3.INF``.
    """
    binary_filepath = Path(binary_filepath)
    candidates = [
        binary_filepath.with_name(binary_filepath.name + ".inf"),
        binary_filepath.with_name(binary_filepath.name + ".INF"),
    ]
    if binary_filepath.suffix:
        candidates += [
            binary_filepath.with_suffix(".inf"),
            binary_filepath.with_suffix(".INF"),
        ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


__all__ = [
    "InfParseError",
    "InfRecord",
    "inf_address",
    "parse_inf",
    "read_inf",
    "sidecar_inf_filepath",
]
