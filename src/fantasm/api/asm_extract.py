"""Extract sections of a disassembly ``.asm`` file by address or label.

Pure helpers for indexing assembly lines and resolving address/label
targets. CLI-facing wrappers (file open + print) live separately.

Refactors relative to the sibling copies:

- :func:`find_line_for_target` no longer takes the unused ``lines``
  parameter and emits ambiguous-match warnings via :mod:`warnings`
  instead of printing to stderr.
- :func:`extract_section` returns the captured slice (start line and
  text) as a pure function; the file-based ``extract`` entry was a
  CLI-style mixed-IO helper and has been split out so the rest of the
  module is easier to test and re-use.
"""

from __future__ import annotations

import re
import warnings
from collections.abc import Sequence
from dataclasses import dataclass


_ADDR_COMMENT_RE = re.compile(r";\s*([0-9a-f]{4}):")
_RUNTIME_ADDR_RE = re.compile(r":([0-9a-f]{4})\[")
_LABEL_RE = re.compile(r"^\.(\w+)")


def parse_address(text: str) -> int | None:
    """Parse a hex address in any of the conventional notations.

    Recognises ``$8000``, ``&8000``, ``0x8000`` and bare ``8000``.
    Returns ``None`` if the text is not a valid hex integer.
    """
    cleaned = text.strip().lstrip("$&").removeprefix("0x")
    try:
        return int(cleaned, 16)
    except ValueError:
        return None


def build_index(
    asm_lines: Sequence[str],
) -> tuple[dict[int, int], dict[str, int]]:
    """Build ``(addr_to_line, label_to_line)`` indices.

    For each line, looks for a ``;NNNN:`` comment marker (the
    disassembler's address tag) and a ``:NNNN[...]`` runtime-address
    annotation; both are recorded in ``addr_to_line``. Lines starting
    with ``.label`` are recorded in ``label_to_line``. The first
    occurrence wins for any given key.
    """
    addr_to_line: dict[int, int] = {}
    label_to_line: dict[str, int] = {}

    for line_index, line in enumerate(asm_lines):
        match = _ADDR_COMMENT_RE.search(line)
        if match:
            addr = int(match.group(1), 16)
            addr_to_line.setdefault(addr, line_index)

        match = _RUNTIME_ADDR_RE.search(line)
        if match:
            addr = int(match.group(1), 16)
            addr_to_line.setdefault(addr, line_index)

        match = _LABEL_RE.match(line)
        if match:
            label_to_line.setdefault(match.group(1), line_index)

    return addr_to_line, label_to_line


def find_line_for_target(
    target: str,
    addr_to_line: dict[int, int],
    label_to_line: dict[str, int],
) -> int | None:
    """Resolve a textual target to a 0-based line number.

    Resolution order:

    1. If ``target`` parses as a hex address, return the line that maps
       to that address — or, failing an exact match, the line for the
       nearest indexed address less than or equal to ``target``.
    2. If ``target`` matches a label exactly, return that label's line.
    3. If ``target`` is a substring of exactly one label, return that
       label's line. If it matches multiple labels, emits a
       ``UserWarning`` listing the matches and returns the lexically
       first match's line so callers continue to make progress.

    Returns ``None`` when nothing matches.
    """
    addr = parse_address(target)
    if addr is not None:
        if addr in addr_to_line:
            return addr_to_line[addr]
        candidates = [a for a in addr_to_line if a <= addr]
        if candidates:
            return addr_to_line[max(candidates)]
        return None

    if target in label_to_line:
        return label_to_line[target]

    matches = sorted(label for label in label_to_line if target in label)
    if not matches:
        return None
    if len(matches) > 1:
        warnings.warn(
            f"ambiguous label {target!r}; matches: {', '.join(matches)}",
            stacklevel=2,
        )
    return label_to_line[matches[0]]


@dataclass(frozen=True)
class AsmSection:
    """A slice of assembly lines extracted by :func:`extract_section`.

    ``start_line`` and ``end_line`` are 0-based; ``end_line`` is
    exclusive. ``lines`` is the captured text without line numbers.
    """

    start_line: int
    end_line: int
    lines: list[str]


def extract_section(
    asm_lines: Sequence[str],
    start_target: str,
    end_target: str | None = None,
    default_window: int = 40,
) -> AsmSection:
    """Extract a section of assembly lines spanning two targets.

    The section starts at the line resolved from ``start_target`` and
    ends at the line resolved from ``end_target`` (inclusive). When no
    ``end_target`` is given, ``default_window`` lines are taken.

    The start is backed up across preceding blank, comment-only, and
    label-only lines so the captured section includes the natural
    "header" of the routine or block.

    Raises ``LookupError`` if either target cannot be resolved.
    """
    addr_to_line, label_to_line = build_index(asm_lines)

    start_line = find_line_for_target(start_target, addr_to_line, label_to_line)
    if start_line is None:
        raise LookupError(f"could not find {start_target!r}")

    while start_line > 0 and not _ADDR_COMMENT_RE.search(asm_lines[start_line - 1]):
        previous = asm_lines[start_line - 1].strip()
        if previous == "" or previous.startswith(";") or previous.startswith("."):
            start_line -= 1
        else:
            break

    if end_target is not None:
        end_line = find_line_for_target(end_target, addr_to_line, label_to_line)
        if end_line is None:
            raise LookupError(f"could not find {end_target!r}")
        end_line += 1
    else:
        end_line = min(start_line + default_window, len(asm_lines))

    return AsmSection(
        start_line=start_line,
        end_line=end_line,
        lines=list(asm_lines[start_line:end_line]),
    )


__all__ = [
    "AsmSection",
    "build_index",
    "extract_section",
    "find_line_for_target",
    "parse_address",
]
