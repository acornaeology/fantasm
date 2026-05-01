"""Apply label-rename edits to a py8dis driver script.

Pure-logic helpers for parsing label declarations and finding the
correct insertion point inside a driver's ``# Code label renames``
section. Sibling ``disasm_tools.rename_labels`` mixed parsing with
file IO; the fantasm port lifts the parsers and the
:func:`apply_renames_to_lines` text transformer.
"""

from __future__ import annotations

import re
from collections.abc import Sequence


LABEL_RE = re.compile(r'^label\(0x([0-9A-Fa-f]+),\s*"([^"]*)"')
SECTION_RE = re.compile(r"^# =+")
RENAME_SECTION_RE = re.compile(r"^# Code label renames")


def parse_label_declarations(lines: Sequence[str]) -> list[dict]:
    """Parse all ``label()`` declarations from driver-script lines.

    Returns dicts with ``addr``, ``name``, ``line`` (0-indexed).
    """
    out: list[dict] = []
    for i, line in enumerate(lines):
        match = LABEL_RE.match(line)
        if match:
            out.append(
                {
                    "addr": int(match.group(1), 16),
                    "name": match.group(2),
                    "line": i,
                }
            )
    return out


def find_rename_section(lines: Sequence[str]) -> tuple[int | None, int | None]:
    """Find the ``# Code label renames`` section's body bounds.

    Returns ``(section_start, section_end)`` 0-indexed. ``section_start``
    is the line index of the header itself; ``section_end`` is the
    index of the line BEFORE the next ``# =+`` separator (or the last
    line of the file). Both are ``None`` if the section is absent.
    """
    section_start: int | None = None
    for i, line in enumerate(lines):
        if RENAME_SECTION_RE.match(line):
            section_start = i
            break
    if section_start is None:
        return None, None

    section_end = len(lines) - 1
    for i in range(section_start + 1, len(lines)):
        if SECTION_RE.match(lines[i]):
            section_end = i - 1
            break
    return section_start, section_end


def find_insert_position(
    lines: Sequence[str],
    section_start: int,
    section_end: int,
    target_addr: int,
) -> int:
    """Find the line at which to insert a new ``label()`` for ``target_addr``.

    Maintains address-sorted order within the rename section; falls
    back to ``section_end + 1`` if the section is empty or has no
    label declarations within bounds.
    """
    insert_at = section_end + 1
    for i in range(section_start + 1, section_end + 1):
        match = LABEL_RE.match(lines[i])
        if match and int(match.group(1), 16) > target_addr:
            insert_at = i
            break
    return insert_at


def apply_renames_to_lines(
    lines: Sequence[str], renames: dict[int, str]
) -> list[str]:
    """Return a new list of lines with the requested renames applied.

    For each ``addr -> new_name`` in ``renames``: if the address
    already has a label declaration in the rename section, its name
    is updated in place; otherwise a new ``label(0x{addr:04X}, "name")``
    line is inserted in address-sorted order.

    The input ``lines`` sequence is not mutated. Returns a list of
    lines suitable for writing back to the driver script.
    """
    working: list[str] = list(lines)
    section_start, section_end = find_rename_section(working)
    if section_start is None or section_end is None:
        raise LookupError("no '# Code label renames' section found in driver")

    existing = {
        d["addr"]: d
        for d in parse_label_declarations(working)
        if section_start <= d["line"] <= section_end
    }

    # Apply edits in descending address order so insertion line indices
    # for later (lower-addr) edits don't shift due to insertions of
    # earlier (higher-addr) ones.
    for addr in sorted(renames, reverse=True):
        new_name = renames[addr]
        if addr in existing:
            line_idx = existing[addr]["line"]
            line = working[line_idx]
            working[line_idx] = LABEL_RE.sub(
                f'label(0x{addr:04X}, "{new_name}"', line, count=1
            )
        else:
            section_start, section_end = find_rename_section(working)
            assert section_start is not None and section_end is not None
            insert_at = find_insert_position(
                working, section_start, section_end, addr
            )
            working.insert(insert_at, f'label(0x{addr:04X}, "{new_name}")\n')

    return working


__all__ = [
    "LABEL_RE",
    "RENAME_SECTION_RE",
    "SECTION_RE",
    "apply_renames_to_lines",
    "find_insert_position",
    "find_rename_section",
    "parse_label_declarations",
]
