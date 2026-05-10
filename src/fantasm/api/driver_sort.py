"""Sort top-level annotation calls in dasmos / py8dis driver scripts by address.

A driver script is a Python file that drives a tracing
disassembler library through annotation calls — ``d.label(0x9000,
"foo")``, ``d.comment(0xA000, "...")``, etc. As these files grow
they tend to drift out of address order, so reading the file
top-to-bottom doesn't follow the address space. This module
rewrites the file text so that recognised top-level annotation
calls within each independently sortable run are in address order.

Design contract: statement text is moved byte-for-byte. We never
reformat anything — hex literals stay hex, multi-line calls keep
their original line breaks and quoting, embedded comments and
blank-line spacing are preserved verbatim. The sort is a pure
permutation of statement texts. That is the property that makes a
``fantasm verify`` byte-identity check viable as the safety net:
if every annotation moves intact and the disassembler is
order-independent for these annotation kinds, the rendered output
is unchanged.

Conservative classification:

- A statement is **sortable** only when its first physical line
  has zero leading whitespace AND its head is a recognised
  annotation function (``label``, ``comment``, ``subroutine``,
  ``banner``, ``entry``, ``byte``, ``word``, ``string``,
  ``expr``, ``expr_label``, ``rts_code_ptr``) AND the first
  positional argument is a literal integer (``0xNNNN``,
  decimal, ``0o…``, ``0b…``).
- Setup calls (``use_environment``, ``hook_subroutine``,
  ``load``, ``add_move``) and ambiguous calls (``format_hint``,
  ``constant``) are **anchors**: they stay in place. Anchors
  divide the file into independent sortable runs, so we never
  move an annotation across a setup boundary.
- Anything else — imports, assignments, ``def``/``for``/``if``
  blocks, indented lines, calls with non-literal first args,
  the ``ir = d.disassemble()`` render coda — is also an anchor.

The receiver is matched permissively: ``d.label(...)`` and bare
``label(...)`` both classify the same way, so this module works
for both dasmos drivers (``d.``-prefixed) and py8dis drivers
(import-* style).
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass

from .backfill import group_logical_statements


SORTABLE_FUNCTIONS: frozenset[str] = frozenset({
    "label",
    "comment",
    "subroutine",
    "banner",
    "entry",
    "byte",
    "word",
    "string",
    "expr",
    "expr_label",
    "rts_code_ptr",
})


# Setup / ambiguous calls are intentionally NOT sorted. ``use_environment``
# and ``add_move`` must precede annotations on the regions they touch;
# ``hook_subroutine`` registers parsers used while the disassembler walks
# code; ``format_hint`` may be consumed during environment setup;
# ``constant``'s first argument may be an address or a value and we
# can't tell syntactically. Treating them as anchors leaves them where
# the human author put them, which is the safest default.
ANCHOR_FUNCTIONS: frozenset[str] = frozenset({
    "load",
    "add_move",
    "use_environment",
    "hook_subroutine",
    "format_hint",
    "constant",
})


# Match ``foo(`` or ``something.foo(`` at the start of a statement
# (after concatenation of multi-line statement text). The receiver is
# permissive because driver scripts use both ``d.foo(...)`` and bare
# ``foo(...)`` styles depending on the disassembler library.
_RE_CALL_HEAD = re.compile(
    r"^\s*(?:[A-Za-z_][A-Za-z_0-9]*\s*\.\s*)?"
    r"(?P<name>[A-Za-z_][A-Za-z_0-9]*)\s*\("
)

# A literal-int first positional argument terminated by ``,`` or ``)``.
# ``int(value, 0)`` parses 0x / 0o / 0b / decimal — the same forms
# Python's tokenizer accepts.
_RE_FIRST_INT_ARG = re.compile(
    r"\s*(?P<value>0x[0-9A-Fa-f]+|0o[0-7]+|0b[01]+|\d+)\s*[,)]"
)


@dataclass(frozen=True)
class Unit:
    """One source-level unit: trailing-of-previous + leading + one statement.

    Filler (blank or ``#``-comment lines) between two real statements
    is split at the first non-blank line. The leading blank run goes
    into the preceding statement's ``trailing_lines`` (so a blank
    line "after" a statement stays after it across a sort). The rest
    — comment lines and their interspersed spacing — goes into the
    following statement's ``leading_lines`` (so ``# heading`` style
    comments travel with the thing they describe).

    ``statement_lines`` are the lines of one balanced-paren statement
    (possibly multi-line). ``kind`` is ``"sortable"``, ``"anchor"``,
    or ``"trailing_filler"`` (the last-only unit holding any
    blank/comment lines after the file's final real statement). For
    sortable units, ``address`` is the literal first-argument value.
    ``original_index`` is the position in the original file (used as
    a stable-sort tiebreaker).
    """

    leading_lines: tuple[str, ...]
    statement_lines: tuple[str, ...]
    trailing_lines: tuple[str, ...]
    kind: str
    address: int | None
    original_index: int


def _is_filler_line(line: str) -> bool:
    """Return True for a blank line or a line that is only a ``#`` comment."""
    stripped = line.strip()
    return stripped == "" or stripped.startswith("#")


def _classify_statement(stmt_lines: Sequence[str]) -> tuple[str, int | None]:
    """Classify a logical statement.

    Returns ``("sortable", address)`` or ``("anchor", None)``. Indented
    statements (loop bodies, ``def`` bodies, etc.) are always anchors
    since their position is constrained by the enclosing block.
    """
    if not stmt_lines:
        return "anchor", None
    first = stmt_lines[0]
    if first[:1] in (" ", "\t"):
        return "anchor", None

    # Concatenate so a literal first arg laid out across multiple
    # physical lines is still found. Newlines become spaces — fine
    # for matching ``\s``.
    full = " ".join(stmt_lines)
    head = _RE_CALL_HEAD.match(full)
    if head is None:
        return "anchor", None
    name = head.group("name")
    if name in ANCHOR_FUNCTIONS:
        return "anchor", None
    if name not in SORTABLE_FUNCTIONS:
        return "anchor", None

    rest = full[head.end():]
    arg_match = _RE_FIRST_INT_ARG.match(rest)
    if arg_match is None:
        return "anchor", None
    return "sortable", int(arg_match.group("value"), 0)


def _split_filler(filler: Sequence[str]) -> tuple[list[str], list[str]]:
    """Split a between-statements filler block.

    Leading blank lines (everything before the first non-blank line)
    become ``trailing`` of the preceding statement. The rest —
    comment lines and any interspersed blanks — become ``leading``
    of the following statement.
    """
    split_at = 0
    for i, line in enumerate(filler):
        if line.strip() != "":
            split_at = i
            break
    else:
        # All lines blank: there's no comment to attach forward, so
        # everything is trailing of the previous statement.
        return list(filler), []
    return list(filler[:split_at]), list(filler[split_at:])


def build_units(text: str) -> list[Unit]:
    """Parse ``text`` into a list of :class:`Unit` records.

    Filler blocks between statements are split: leading blanks
    attach as ``trailing_lines`` of the preceding statement;
    comment lines (and their spacing) attach as ``leading_lines``
    of the following statement. Filler at the start of the file
    becomes leading of the first statement; filler after the last
    real statement attaches as ``trailing_lines`` of that
    statement (so the spacing pattern follows it across a sort).

    The file's EOF newline is normalised away here and re-added
    in :func:`emit_units`, so it never participates in the
    blank-line-attachment logic.
    """
    if text == "":
        return []
    body = text[:-1] if text.endswith("\n") else text
    lines = body.split("\n")
    groups = group_logical_statements(lines)

    pending_filler: list[str] = []
    units: list[Unit] = []
    for _start, _end, group_lines in groups:
        if all(_is_filler_line(ln) for ln in group_lines):
            pending_filler.extend(group_lines)
            continue

        if units:
            trailing_for_prev, leading_for_next = _split_filler(pending_filler)
        else:
            # No previous statement to attach trailing to; everything
            # in pending_filler is leading of this first statement.
            trailing_for_prev, leading_for_next = [], list(pending_filler)

        if trailing_for_prev and units:
            prev = units[-1]
            units[-1] = Unit(
                leading_lines=prev.leading_lines,
                statement_lines=prev.statement_lines,
                trailing_lines=prev.trailing_lines + tuple(trailing_for_prev),
                kind=prev.kind,
                address=prev.address,
                original_index=prev.original_index,
            )

        kind, address = _classify_statement(group_lines)
        units.append(
            Unit(
                leading_lines=tuple(leading_for_next),
                statement_lines=tuple(group_lines),
                trailing_lines=(),
                kind=kind,
                address=address,
                original_index=len(units),
            )
        )
        pending_filler = []

    if pending_filler:
        if units:
            # Attach to the last real statement so its trailing
            # spacing follows it across a sort.
            prev = units[-1]
            units[-1] = Unit(
                leading_lines=prev.leading_lines,
                statement_lines=prev.statement_lines,
                trailing_lines=prev.trailing_lines + tuple(pending_filler),
                kind=prev.kind,
                address=prev.address,
                original_index=prev.original_index,
            )
        else:
            # File contains nothing but filler.
            units.append(
                Unit(
                    leading_lines=(),
                    statement_lines=tuple(pending_filler),
                    trailing_lines=(),
                    kind="trailing_filler",
                    address=None,
                    original_index=0,
                )
            )
    return units


def _sort_runs(units: Sequence[Unit]) -> list[Unit]:
    """Stable-sort each run of consecutive ``sortable`` units by address.

    Anchors and trailing filler are passed through unchanged. Each
    sortable run is sorted independently; runs are bounded by the
    surrounding anchors so a sortable annotation never crosses a
    setup-call boundary.
    """
    result: list[Unit] = []
    i = 0
    n = len(units)
    while i < n:
        if units[i].kind != "sortable":
            result.append(units[i])
            i += 1
            continue
        j = i
        while j < n and units[j].kind == "sortable":
            j += 1
        run = list(units[i:j])
        # ``sorted`` is stable, so the original_index tiebreaker is
        # belt-and-braces — but explicit is good when address aliases
        # are common (banner + label + comment all at the same addr).
        run.sort(
            key=lambda u: (u.address if u.address is not None else 0, u.original_index)
        )
        result.extend(run)
        i = j
    return result


def emit_units(units: Sequence[Unit]) -> str:
    """Concatenate ``units`` back into source text."""
    out: list[str] = []
    for unit in units:
        out.extend(unit.leading_lines)
        out.extend(unit.statement_lines)
        out.extend(unit.trailing_lines)
    return "\n".join(out)


def sort_driver_text(text: str) -> str:
    """Return ``text`` with sortable annotation calls reordered by address.

    The transformation is a permutation of whole statement texts —
    no reformatting, no rewriting of arguments, no change to the
    spelling of integer literals. See the module docstring for the
    classification rules.
    """
    if text == "":
        return text
    units = build_units(text)
    out = emit_units(_sort_runs(units))
    # build_units strips one trailing \n into the EOF marker; re-add
    # it unconditionally if the source had one, so the emitted text
    # always closes with the original file's trailing newline.
    if text.endswith("\n"):
        out += "\n"
    return out


def is_sorted(text: str) -> bool:
    """Return True if every sortable run is already in non-decreasing address order.

    Useful for ``--check`` modes: a true result means the sort is a
    no-op and ``sort_driver_text(text) == text``.
    """
    units = build_units(text)
    i = 0
    n = len(units)
    while i < n:
        if units[i].kind != "sortable":
            i += 1
            continue
        prev_addr = -1
        while i < n and units[i].kind == "sortable":
            assert units[i].address is not None
            if units[i].address < prev_addr:
                return False
            prev_addr = units[i].address
            i += 1
    return True


__all__ = [
    "ANCHOR_FUNCTIONS",
    "SORTABLE_FUNCTIONS",
    "Unit",
    "build_units",
    "emit_units",
    "is_sorted",
    "sort_driver_text",
]
