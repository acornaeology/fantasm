"""Detect missing print-inline ``hook_subroutine()`` declarations.

A common cause of long unannotated ``byte`` runs in Acorn-style
6502 ROMs is a missing ``hook_subroutine()`` for a print-inline
helper (``stringz`` / ``stringcr`` / ``stringhi`` style). The
``hook_subroutine`` API and the bundled hook names are shared
between the supported disassembler libraries (dasmos and py8dis),
so the same detection logic applies regardless of which one the
driver targets. The shape of the missing hook in driver JSON
output is:

.. code-block:: text

    JSR <target>          ← code item, mnemonic="jsr"
    EQUS "..."            ← string item with the inline text.
                            For stringz / stringcr the terminator
                            (0x00 / 0x0D) is the last byte of the
                            string item; for stringhi it is *not* —
                            see `_classify_terminator`.
    EQUB ...              ← resume code, mis-emitted as raw byte
                            items because the hook wasn't wired up

Once ``hook_subroutine(<target>, name, <kind>_hook)`` is added to
the driver, the disassembler treats the post-JSR bytes correctly
and emits the resume code as ``code`` items. Until then, every
call site contributes a mysterious unannotated byte run downstream.

This module surfaces the missing hook by looking at the
*pattern at every call site*, not at the byte runs in isolation.
A JSR target whose call sites consistently match the
"string-then-byte-run-decoding-as-code" signature is almost
certainly a print-inline helper that needs hooking.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from .mos6502 import opcode_tables


# Hook-kind names as they appear in driver scripts (the same
# stringz / stringcr / stringhi naming is used by dasmos and py8dis).
_KIND_HI = "stringhi"
_KIND_Z = "stringz"
_KIND_CR = "stringcr"
_KIND_UNKNOWN = "unknown"

# Map terminator-kind → name of the driver-API hook function the
# user would name in ``hook_subroutine(addr, name, <hook_fn>)``.
_HOOK_FN = {
    _KIND_HI: "stringhi_hook",
    _KIND_Z: "stringz_hook",
    _KIND_CR: "stringcr_hook",
    _KIND_UNKNOWN: None,
}


@dataclass(frozen=True)
class HookCandidate:
    """A JSR target that looks like an unhooked print-inline helper.

    ``matching_call_sites`` lists JSR addresses whose post-call
    pattern matches the missing-hook signature; ``total_call_sites``
    is every JSR (and JMP, treated as tail-call) that targets
    ``target``. ``confidence`` is the ratio — when 1.0, every
    call site matches the pattern, which is the strongest signal
    a hook is missing.
    """

    target: int
    target_label: str | None
    matching_call_sites: tuple[int, ...]
    total_call_sites: int
    hook_kind: str                    # "stringhi" / "stringz" / "stringcr" / "unknown"
    sample_strings: tuple[str, ...]   # first few inline strings observed, for context

    @property
    def confidence(self) -> float:
        if self.total_call_sites == 0:
            return 0.0
        return len(self.matching_call_sites) / self.total_call_sites

    @property
    def hook_function(self) -> str | None:
        """Hook function name (e.g. ``stringz_hook``), or ``None``
        for ``unknown`` kind. The same names are used by dasmos and
        py8dis.
        """
        return _HOOK_FN[self.hook_kind]


def _classify_terminator(
    string_bytes: Sequence[int],
    next_first_byte: int | None,
) -> str:
    """Identify the print-inline kind from the post-JSR items.

    The driver-emitted JSON encodes terminators asymmetrically
    (the same shape from dasmos and py8dis):

    - ``stringz`` and ``stringcr`` include the terminator (``0x00``
      or ``0x0D``) as the last byte of the string item.
    - ``stringhi`` *excludes* its bit-7 terminator: that byte lives
      as the first byte of the following item, doing double duty
      as terminator and resume opcode.

    Priority therefore matters:

    1. String ends in ``0x00`` → stringz (unambiguous).
    2. Next item starts with bit-7 set → stringhi (the structural
       signal — beats a CR-looking last byte, since the printed
       text may itself end in ``\\r``).
    3. String ends in ``0x0D`` and next byte does not have bit 7
       set → stringcr.
    4. Otherwise → unknown (e.g. length-prefixed; let the user pick).
    """
    if not string_bytes:
        return _KIND_UNKNOWN
    if string_bytes[-1] == 0x00:
        return _KIND_Z
    if next_first_byte is not None and next_first_byte & 0x80:
        return _KIND_HI
    if string_bytes[-1] == 0x0D:
        return _KIND_CR
    return _KIND_UNKNOWN


def _decodes_as_code(span: Sequence[int], lengths, *, min_bytes: int) -> bool:
    """``True`` if the first ``min_bytes`` bytes of ``span`` form a
    valid 6502 instruction stream starting at offset 0."""
    if len(span) < min_bytes:
        return False
    i = 0
    while i < len(span):
        opcode = span[i]
        length = lengths[opcode]
        if length == 0 or i + length > len(span):
            break
        i += length
        if i >= min_bytes:
            return True
    return False


def find_hook_candidates(
    items: Sequence[dict],
    *,
    cpu: str = "6502",
    min_call_sites: int = 2,
    min_resume_code_bytes: int = 4,
    min_confidence: float = 0.5,
) -> list[HookCandidate]:
    """Find JSR targets with the missing-print-inline-hook signature.

    Walks ``items`` linearly. For each ``code`` item with
    ``mnemonic == "jsr"`` (or ``jmp``, which the disassembler
    treats similarly when used as a tail-call), the next two items
    are inspected:

    - The first must be a ``string`` item.
    - The second must be a ``byte`` item whose ``bytes`` decode as
      valid 6502 instructions starting at offset 0 for at least
      ``min_resume_code_bytes`` bytes.

    Matching call sites are grouped by target. A target is
    reported as a candidate when:

    - it has at least ``min_call_sites`` matching call sites;
    - the matching ratio (matching / total) is at least
      ``min_confidence``.

    The returned list is sorted by ``confidence`` descending then
    matching call-site count descending.
    """
    if min_call_sites < 1:
        raise ValueError("min_call_sites must be >= 1")
    if not (0.0 <= min_confidence <= 1.0):
        raise ValueError("min_confidence must be in [0.0, 1.0]")

    lengths, _mnemonics = opcode_tables(cpu)

    # Tally every JSR/JMP target (for the denominator) and the
    # subset of call sites whose post-call pattern matches the
    # missing-hook signature (for the numerator).
    total_calls: dict[int, int] = {}
    matching: dict[int, list[tuple[int, str, str]]] = {}
    target_labels: dict[int, str] = {}

    for index, item in enumerate(items):
        if item.get("type") != "code":
            continue
        mnemonic = item.get("mnemonic")
        if mnemonic not in ("jsr", "jmp"):
            continue
        target = item.get("target")
        if target is None:
            continue
        total_calls[target] = total_calls.get(target, 0) + 1
        # Cache an existing label if the disassembler assigned one.
        if target not in target_labels:
            target_label = item.get("target_label") or ""
            if target_label:
                target_labels[target] = target_label

        if index + 2 >= len(items):
            continue
        nxt = items[index + 1]
        nxt2 = items[index + 2]
        if nxt.get("type") != "string":
            continue
        if nxt2.get("type") != "byte":
            continue
        string_bytes = nxt.get("bytes") or ()
        resume_bytes = nxt2.get("bytes") or ()
        if not _decodes_as_code(
            resume_bytes, lengths, min_bytes=min_resume_code_bytes
        ):
            continue

        kind = _classify_terminator(
            string_bytes,
            resume_bytes[0] if resume_bytes else None,
        )
        sample = nxt.get("string") or ""
        matching.setdefault(target, []).append(
            (item["addr"], kind, sample)
        )

    candidates: list[HookCandidate] = []
    for target, matches in matching.items():
        if len(matches) < min_call_sites:
            continue
        total = total_calls.get(target, 0)
        confidence = len(matches) / total if total else 0.0
        if confidence < min_confidence:
            continue
        # The dominant kind across matching call sites wins. Mixed
        # kinds shouldn't really happen for a print-inline helper,
        # but if they do, the most common kind is the safer guess.
        kind_counts: dict[str, int] = {}
        for _site, kind, _sample in matches:
            kind_counts[kind] = kind_counts.get(kind, 0) + 1
        dominant_kind = max(kind_counts, key=lambda k: kind_counts[k])
        # First three distinct sample strings for the report column.
        seen: set[str] = set()
        samples: list[str] = []
        for _site, _kind, sample in matches:
            if sample and sample not in seen:
                samples.append(sample)
                seen.add(sample)
                if len(samples) == 3:
                    break
        candidates.append(
            HookCandidate(
                target=target,
                target_label=target_labels.get(target),
                matching_call_sites=tuple(
                    sorted(site for site, _, _ in matches)
                ),
                total_call_sites=total,
                hook_kind=dominant_kind,
                sample_strings=tuple(samples),
            )
        )

    candidates.sort(
        key=lambda c: (-c.confidence, -len(c.matching_call_sites))
    )
    return candidates


def render_hook_subroutine_line(
    candidate: HookCandidate,
    *,
    placeholder_name: str = "FILL_ME",
) -> str:
    """Render a paste-ready ``hook_subroutine(addr, name, hook)`` line.

    Falls back to ``placeholder_name`` when the candidate has no
    target label, and to a comment marker when the kind is
    ``unknown`` (no hook-function name to emit).
    """
    name = candidate.target_label or placeholder_name
    hook_fn = candidate.hook_function
    if hook_fn is None:
        # Unknown kind — render a paste-ready *placeholder* with a
        # comment so the user can substitute the right hook fn.
        return (
            f'hook_subroutine(0x{candidate.target:04X}, "{name}", '
            f'<HOOK_FN>)  '
            f'# {len(candidate.matching_call_sites)} sites, '
            f'conf={candidate.confidence:.2f}, kind=unknown'
        )
    return (
        f'hook_subroutine(0x{candidate.target:04X}, "{name}", '
        f'{hook_fn})  '
        f'# {len(candidate.matching_call_sites)} sites, '
        f'conf={candidate.confidence:.2f}'
    )


__all__ = [
    "HookCandidate",
    "find_hook_candidates",
    "render_hook_subroutine_line",
]
