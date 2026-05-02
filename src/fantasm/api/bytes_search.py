"""Byte-signature search across a ROM image.

Locate exact byte sequences (with optional ``??`` wildcards) inside
the raw ROM bytes. Distinct from
:mod:`fantasm.api.fingerprint` (block-level opcode fingerprints
within one ROM) and :mod:`fantasm.api.find_shared` (opcode-sequence
matching across two or more ROMs) — this module operates on raw
bytes only and is the right choice when you have a known sequence
("4C B9 FF" — JMP somewhere ending FF) and want to know whether
and where it appears.

Pattern syntax (mirrors the convention in IDA / Ghidra / radare2):

- ``"4C B9 FF"`` — three literal bytes.
- ``"4c??ff"`` — same three positions, middle byte is a wildcard.
- ``"$4C $?? $FF"`` / ``"0x4C 0x?? 0xFF"`` — per-token ``$`` and
  ``0x`` prefixes are tolerated.
- ``"??"`` for "any single byte"; nibble-level wildcards (e.g.
  ``"4?"``) are intentionally not supported — 6502 opcode encoding
  doesn't reward nibble masking.

Use :func:`parse_byte_pattern` to compile a pattern and
:func:`find_byte_pattern` to scan a ROM. The CLI front-end is at
``fantasm bytes find``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class BytePattern:
    """A compiled byte-search pattern.

    ``bytes_[i]`` is the literal byte expected at position ``i`` for
    every position not in ``wildcards``. Positions in ``wildcards``
    match any byte; the values stored at those indices in ``bytes_``
    are placeholder zeros and should not be inspected directly.
    """

    bytes_: tuple[int, ...]
    wildcards: frozenset[int]

    def __len__(self) -> int:
        return len(self.bytes_)

    @property
    def wildcard_indices(self) -> tuple[int, ...]:
        """Wildcard positions in ascending order, for capture extraction."""
        return tuple(sorted(self.wildcards))

    def matches_at(self, data: bytes, offset: int) -> bool:
        """``True`` iff this pattern matches ``data`` starting at ``offset``."""
        if offset < 0 or offset + len(self) > len(data):
            return False
        for index, expected in enumerate(self.bytes_):
            if index in self.wildcards:
                continue
            if data[offset + index] != expected:
                return False
        return True


@dataclass(frozen=True)
class ByteMatch:
    """One hit of a :class:`BytePattern` against a ROM image.

    ``address`` is the runtime address (``rom_base + offset``);
    ``offset`` is the raw file offset. ``captures`` carries the
    bytes the pattern's wildcard positions matched, in pattern
    order — empty when the pattern has no wildcards.
    """

    address: int
    offset: int
    captures: tuple[int, ...]


_HEX_PAIR_RE = re.compile(r"^[0-9a-fA-F]{2}$")
_PREFIX_RE = re.compile(r"0[xX]")
_WHITESPACE_RE = re.compile(r"\s+")


def parse_byte_pattern(text: str) -> BytePattern:
    """Parse a hex-with-wildcards string into a :class:`BytePattern`.

    Recognises:

    - hex pairs (``4C``, ``4c``);
    - ``??`` wildcards (one wildcard per pair);
    - per-token ``$`` and ``0x`` / ``0X`` prefixes;
    - any amount of whitespace between tokens.

    Raises ``ValueError`` for empty input, lone ``?`` (must be
    ``??``), nibble-level wildcards (``4?``), odd-length hex,
    non-hex characters, or patterns made entirely of wildcards
    (which would match every position).
    """
    if not text or not text.strip():
        raise ValueError("empty byte pattern")

    # Normalise: strip whitespace, "0x"/"0X" prefixes, "$" hints.
    cleaned = _WHITESPACE_RE.sub("", text)
    cleaned = _PREFIX_RE.sub("", cleaned)
    cleaned = cleaned.replace("$", "")

    if not cleaned:
        raise ValueError(
            f"byte pattern {text!r} contains no token characters after "
            "stripping whitespace and prefixes"
        )

    if len(cleaned) % 2:
        if "?" in cleaned:
            raise ValueError(
                f"single '?' in byte pattern {text!r} — wildcards are '??'"
            )
        raise ValueError(
            f"odd-length hex in byte pattern {text!r}"
        )

    bytes_: list[int] = []
    wildcards: set[int] = set()
    for i in range(0, len(cleaned), 2):
        token = cleaned[i:i + 2]
        index = i // 2
        if token == "??":
            bytes_.append(0)
            wildcards.add(index)
        elif _HEX_PAIR_RE.match(token):
            bytes_.append(int(token, 16))
        elif "?" in token:
            raise ValueError(
                f"nibble-level wildcard {token!r} in pattern {text!r} is "
                "not supported; use '??' for any-byte wildcards"
            )
        else:
            raise ValueError(
                f"invalid hex byte {token!r} in pattern {text!r}"
            )

    if len(wildcards) == len(bytes_):
        raise ValueError(
            f"byte pattern {text!r} is entirely wildcards — every "
            "position would match"
        )

    return BytePattern(bytes_=tuple(bytes_), wildcards=frozenset(wildcards))


def find_byte_pattern(
    rom_bytes: bytes,
    pattern: BytePattern,
    *,
    rom_base: int = 0x8000,
) -> list[ByteMatch]:
    """Scan ``rom_bytes`` for every occurrence of ``pattern``.

    Returns matches in ascending offset order. Each match's
    ``captures`` carries the bytes at the pattern's wildcard
    positions, in pattern order; for a pure-literal pattern
    ``captures`` is empty.
    """
    pattern_len = len(pattern)
    if pattern_len == 0 or pattern_len > len(rom_bytes):
        return []

    wildcard_indices = pattern.wildcard_indices
    matches: list[ByteMatch] = []
    for offset in range(len(rom_bytes) - pattern_len + 1):
        if not pattern.matches_at(rom_bytes, offset):
            continue
        captures = tuple(
            rom_bytes[offset + index] for index in wildcard_indices
        )
        matches.append(
            ByteMatch(
                address=rom_base + offset,
                offset=offset,
                captures=captures,
            )
        )
    return matches


__all__ = [
    "BytePattern",
    "ByteMatch",
    "find_byte_pattern",
    "parse_byte_pattern",
]
