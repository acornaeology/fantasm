"""Compute insertion points for new ``subroutine()`` declarations.

Parses a disassembly driver script (whether built on dasmos or
py8dis — both expose a ``subroutine()`` API with the same call
shape) to locate existing ``subroutine()`` declarations, identify
the main address-ordered block, and compute where a new declaration
for a given target address should be inserted.

Sibling ``disasm_tools.insert_point`` was byte-identical across all
four forks. The fantasm port lifts the pure-logic helpers
(:func:`parse_subroutine_declarations`, :func:`find_main_block`,
:func:`compute_insert_point`); the file-IO + printing wrapper that
formed the sibling ``find_insert_point`` is deferred to CLI
integration.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass


SUB_RE = re.compile(r"^subroutine\(0x([0-9A-Fa-f]+)")
SECTION_RE = re.compile(r"^# =+")


def _find_call_end(lines: Sequence[str], start_line: int) -> int:
    """Find the line index of the closing ``)`` for a multi-line call."""
    depth = 0
    for i in range(start_line, len(lines)):
        for ch in lines[i]:
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    return i
    return start_line


def parse_subroutine_declarations(lines: Sequence[str]) -> list[dict]:
    """Parse all ``subroutine()`` declarations from driver-script lines.

    Returns a list of dicts with ``addr``, ``name``, ``start_line``,
    ``end_line`` (all 0-indexed line numbers).
    """
    declarations: list[dict] = []
    for i, line in enumerate(lines):
        match = SUB_RE.match(line)
        if not match:
            continue
        addr = int(match.group(1), 16)
        name_match = re.search(
            r'subroutine\(0x[0-9A-Fa-f]+,\s*"([^"]*)"', line
        )
        if not name_match:
            name_match = re.search(r'name="([^"]*)"', line)
        name = name_match.group(1) if name_match else None
        end_line = _find_call_end(lines, i)
        declarations.append(
            {
                "addr": addr,
                "name": name,
                "start_line": i,
                "end_line": end_line,
            }
        )
    return declarations


def find_main_block(
    lines: Sequence[str], declarations: Sequence[dict]
) -> tuple[int, int]:
    """Identify the main address-ordered subroutine block.

    Returns ``(block_start_line, block_end_line)`` (0-indexed). The
    block is identified by a ``# Subroutines`` section header or, as
    a fallback, by the position of the first declaration.
    """
    header_line: int | None = None
    for i, line in enumerate(lines):
        if "# Subroutines" in line and (
            "correspondence" in line or "subroutines" in line.lower()
        ):
            header_line = i
            break

    if header_line is None:
        if declarations:
            header_line = declarations[0]["start_line"] - 1
        else:
            return 0, len(lines) - 1

    block_start = header_line
    block_end = len(lines) - 1

    after_header = [d for d in declarations if d["start_line"] > header_line]
    if not after_header:
        return block_start, block_end

    first_decl_line = after_header[0]["start_line"]
    for i in range(first_decl_line + 1, len(lines)):
        if SECTION_RE.match(lines[i]):
            block_end = i - 1
            break

    return block_start, block_end


@dataclass(frozen=True)
class InsertPoint:
    """Resolved insertion point for a new ``subroutine()`` declaration.

    ``insert_line`` is 0-based. ``predecessor`` and ``successor`` are
    the surrounding declaration dicts (or ``None``).
    """

    insert_line: int
    predecessor: dict | None
    successor: dict | None
    block_start_line: int
    block_end_line: int


class AlreadyDeclared(LookupError):
    """Raised when the target address already has a declaration."""

    def __init__(self, declaration: dict) -> None:
        self.declaration = declaration
        super().__init__(
            f"address &{declaration['addr']:04X} already declared at "
            f"line {declaration['start_line'] + 1}"
        )


def compute_insert_point(
    lines: Sequence[str], target_addr: int
) -> InsertPoint:
    """Compute where in ``lines`` a new ``subroutine()`` for ``target_addr`` belongs.

    Raises :class:`AlreadyDeclared` if the address already has a
    declaration. Raises ``LookupError`` if no declarations are present
    at all (so there's no main block to anchor to).
    """
    declarations = parse_subroutine_declarations(lines)
    if not declarations:
        raise LookupError("no subroutine() declarations found")

    for d in declarations:
        if d["addr"] == target_addr:
            raise AlreadyDeclared(d)

    block_start, block_end = find_main_block(lines, declarations)
    main_decls = sorted(
        [
            d
            for d in declarations
            if block_start <= d["start_line"] <= block_end
        ],
        key=lambda d: d["addr"],
    )
    if not main_decls:
        raise LookupError("no declarations found in main block")

    pred: dict | None = None
    succ: dict | None = None
    for d in main_decls:
        if d["addr"] < target_addr:
            pred = d
        elif d["addr"] > target_addr and succ is None:
            succ = d

    if pred is not None:
        insert_after = pred["end_line"]
    else:
        insert_after = main_decls[0]["start_line"] - 1

    return InsertPoint(
        insert_line=insert_after + 1,
        predecessor=pred,
        successor=succ,
        block_start_line=block_start,
        block_end_line=block_end,
    )


__all__ = [
    "AlreadyDeclared",
    "InsertPoint",
    "SECTION_RE",
    "SUB_RE",
    "compute_insert_point",
    "find_main_block",
    "parse_subroutine_declarations",
]
