"""Apply label-rename edits to a disassembly driver script.

Two rewrite strategies live here:

* **Inline** (:func:`apply_renames_inline`) — find every existing
  ``label(0xXXXX, …)`` / ``d.label(0xXXXX, …)`` declaration and
  rewrite its name at that line, wherever it sits in the driver.
  This matches the natural shape of hand-written drivers where
  label calls are interleaved with the code they annotate.
* **Section** (:func:`apply_renames_to_lines`) — find a dedicated
  ``# Code label renames`` cluster, then either update an existing
  entry inside it or insert a new one in address-sorted order.
  Useful for auto-generated drivers that group reversible renames
  in one override section.

Sibling ``disasm_tools.rename_labels`` mixed parsing with file IO;
the fantasm port lifts the parsers and the text transformers and
leaves the IO to the ``fantasm labels apply`` CLI command.
"""

from __future__ import annotations

import re
from collections.abc import Sequence


LABEL_RE = re.compile(r'^label\(0x([0-9A-Fa-f]+),\s*"([^"]*)"')
LABEL_DECL_RE = re.compile(
    r'^(\s*)((?:d\.)?label)\(0x([0-9A-Fa-f]+),\s*"([^"]*)"'
)
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


def parse_label_decl_lines(lines: Sequence[str]) -> list[dict]:
    """Parse every ``label(…)`` / ``d.label(…)`` declaration in ``lines``.

    Like :func:`parse_label_declarations` but recognises the
    ``d.label`` form (dasmos's actual call style) as well as the
    bare ``label`` form. Each record carries the source ``line``
    index, the matched ``addr`` and ``name``, the ``prefix`` (the
    indentation captured at the start of the line), and the
    ``callable`` text (``label`` or ``d.label``) so callers can
    preserve it when rewriting.
    """
    out: list[dict] = []
    for i, line in enumerate(lines):
        match = LABEL_DECL_RE.match(line)
        if match:
            out.append(
                {
                    "line": i,
                    "prefix": match.group(1),
                    "callable": match.group(2),
                    "addr": int(match.group(3), 16),
                    "name": match.group(4),
                }
            )
    return out


def apply_renames_inline(
    lines: Sequence[str], renames: dict[int, str]
) -> tuple[list[str], dict[int, tuple[str, str]]]:
    """Rewrite ``label(…)`` / ``d.label(…)`` declarations in place.

    For each ``addr -> new_name`` in ``renames``: locate the matching
    declaration line and rewrite its name. Indentation and the
    ``label`` vs ``d.label`` callable form are preserved.

    Returns ``(new_lines, name_map)`` where ``name_map`` is the
    ``addr -> (old_name, new_name)`` mapping actually applied —
    callers use this to drive optional textual reference rewrites
    on top of the declaration edits.

    Raises :class:`LookupError` (with every missing address listed)
    if any rename has no matching declaration. The driver is not
    partially rewritten — either every requested rename has a home
    or the function refuses to act.
    """
    working = list(lines)
    declarations_by_addr: dict[int, dict] = {}
    for decl in parse_label_decl_lines(working):
        declarations_by_addr.setdefault(decl["addr"], decl)

    missing = sorted(a for a in renames if a not in declarations_by_addr)
    if missing:
        rendered = ", ".join(f"0x{a:04X}" for a in missing)
        raise LookupError(
            f"no label declaration found for {len(missing)} address(es): {rendered}"
        )

    name_map: dict[int, tuple[str, str]] = {}
    for addr, new_name in renames.items():
        decl = declarations_by_addr[addr]
        old_name = decl["name"]
        if old_name == new_name:
            continue
        line_idx = decl["line"]
        line = working[line_idx]
        replacement = (
            f'{decl["prefix"]}{decl["callable"]}(0x{addr:04X}, "{new_name}"'
        )
        working[line_idx] = LABEL_DECL_RE.sub(replacement, line, count=1)
        name_map[addr] = (old_name, new_name)
    return working, name_map


def _compile_ref_patterns(old_name: str) -> list[re.Pattern[str]]:
    """Build the regexes that match a label name in driver text refs.

    Covers three targeted contexts so the rewrite doesn't touch
    incidental substring matches:

    * ``d.comment("... old ...")`` and ``d.comment(addr, "... old ...")``
      -- string args to ``d.comment`` calls.
    * ``description=<TRIPLE-QUOTED>... old ...<TRIPLE-QUOTED>`` blocks --
      including the surrounding whitespace + triple-quote form.
    * ``[`old`](address:...)`` -- Markdown-style anchored link where
      the label appears as the link text.

    Each pattern uses a word boundary so ``init`` doesn't match the
    ``init`` inside ``initialise``.
    """
    escaped = re.escape(old_name)
    boundary = rf"(?<![A-Za-z0-9_]){escaped}(?![A-Za-z0-9_])"
    return [
        re.compile(rf'(d\.comment\([^)]*?"[^"]*?){boundary}', re.DOTALL),
        re.compile(
            rf'(description\s*=\s*"""[^"]*?){boundary}',
            re.DOTALL,
        ),
        re.compile(rf"(\[`){boundary}(`\]\(address:)"),
    ]


def update_ref_strings(
    lines: Sequence[str], name_map: dict[int, tuple[str, str]]
) -> tuple[list[str], int]:
    """Rewrite textual references to renamed labels.

    Walks each line and replaces occurrences of every ``old_name``
    with the corresponding ``new_name`` in three contexts:
    ``d.comment(...)`` string args, triple-quoted ``description=``
    blocks, and Markdown ``[`name`](address:...)`` anchors. Other
    occurrences (raw identifiers, unrelated string text) are left
    alone.

    Returns ``(new_lines, replacement_count)``. The count totals
    individual textual replacements, not lines touched.
    """
    if not name_map:
        return list(lines), 0

    renames_by_old = {
        old: new for old, new in name_map.values() if old != new
    }
    if not renames_by_old:
        return list(lines), 0

    compiled: list[tuple[re.Pattern[str], str]] = []
    for old_name, new_name in renames_by_old.items():
        for pattern in _compile_ref_patterns(old_name):
            num_groups = pattern.groups
            if num_groups == 1:
                replacement = rf"\g<1>{new_name}"
            elif num_groups == 2:
                replacement = rf"\g<1>{new_name}\g<2>"
            else:
                raise AssertionError(
                    f"unexpected group count {num_groups} in ref pattern"
                )
            compiled.append((pattern, replacement))

    total = 0
    working: list[str] = []
    for line in lines:
        new_line = line
        for pattern, replacement in compiled:
            new_line, n = pattern.subn(replacement, new_line)
            total += n
        working.append(new_line)
    return working, total


__all__ = [
    "LABEL_DECL_RE",
    "LABEL_RE",
    "RENAME_SECTION_RE",
    "SECTION_RE",
    "apply_renames_inline",
    "apply_renames_to_lines",
    "find_insert_position",
    "find_rename_section",
    "parse_label_decl_lines",
    "parse_label_declarations",
    "update_ref_strings",
]
