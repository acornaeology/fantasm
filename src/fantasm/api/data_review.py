"""Review and reclassification of data declarations.

Two related capabilities, both serving the "Phase D" data-review
workflow on annotated 6502 disassemblies:

- :func:`find_data_runs` ranks contiguous runs of same-type
  data items (``byte`` / ``word`` / ``string``) so the longest
  ones — typical candidates for a closer look — surface first.

- :func:`find_classification_candidates` applies three
  heuristic classifiers (padding, string, code) to runs of bytes
  py8dis flagged as raw ``byte`` data, surfacing spans that
  *might* actually be strings, valid code, or ROM padding —
  candidates for reclassification with stricter py8dis
  declarations.

Both functions read py8dis JSON items directly. The classifiers
are designed to be used both as a suite (via the orchestrator) and
individually (the ``looks_like_*`` functions accept a raw
``bytes`` span).

The code-likelihood classifier walks every starting alignment with
the per-CPU :data:`fantasm.api.mos6502.OPCODE_LENGTHS` /
:data:`fantasm.api.mos6502.OPCODE_LENGTHS_65C02` table; conceptually
this is equivalent to a regex of the form ``(L1|L2.|L3..)+`` over
the byte stream, but the explicit loop is faster, supports both
CPU families cleanly via the existing tables, and produces
per-alignment runs (the longest from any starting alignment within
a span) rather than the regex's left-to-right alternation, which
biases toward shorter matches at each position.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from .mos6502 import opcode_tables


# --- Feature 1: data runs ----------------------------------------


@dataclass(frozen=True)
class DataRun:
    """One contiguous run of same-type data items.

    ``end_addr`` is inclusive; ``item_count`` is the number of
    JSON items in the run, ``byte_length`` the total bytes spanned
    (often larger than ``item_count`` because a single
    ``byte`` / ``word`` item can carry multiple bytes).
    """

    start_addr: int
    end_addr: int
    item_type: str
    item_count: int
    byte_length: int
    label: str | None
    commented_count: int

    @property
    def is_annotated(self) -> bool:
        """True if the run head has a label or any item is commented."""
        return bool(self.label) or self.commented_count > 0


def find_data_runs(
    items: Sequence[dict],
    *,
    min_bytes: int = 8,
    item_types: Iterable[str] = ("byte", "word", "string"),
) -> list[DataRun]:
    """Return contiguous runs of same-type items, longest first.

    A *run* is a maximal stretch of consecutive items whose
    ``type`` matches one in ``item_types``. Items whose type is
    not in ``item_types`` (most importantly ``code``) break runs.
    Within a run, items keep their individual labels and
    comments; only the **leading** label is exposed on the
    returned :class:`DataRun` (the "what is this region?" hint).

    Runs whose total byte length is below ``min_bytes`` are
    dropped — by default 8 bytes, which lets a four-entry vector
    table (4 × 2 = 8) through while filtering out noise from the
    many short EQUB-pair runs in any real ROM.

    Returns runs sorted by ``byte_length`` descending so the
    most-interesting candidates surface first.
    """
    types = set(item_types)
    runs: list[DataRun] = []

    current: list[dict] = []
    current_type: str | None = None

    def flush() -> None:
        if current and current_type is not None:
            run = _build_run(current, current_type)
            if run.byte_length >= min_bytes:
                runs.append(run)
        current.clear()

    for item in items:
        item_type = item.get("type")
        if item_type in types:
            if current_type is None:
                current_type = item_type
            elif item_type != current_type:
                flush()
                current_type = item_type
            current.append(item)
        else:
            flush()
            current_type = None
    flush()

    runs.sort(key=lambda run: -run.byte_length)
    return runs


def _build_run(items: Sequence[dict], item_type: str) -> DataRun:
    first = items[0]
    last = items[-1]
    last_bytes = len(last.get("bytes") or ()) or 1
    end_addr = last["addr"] + last_bytes - 1
    byte_length = sum(len(item.get("bytes") or ()) for item in items)
    label = None
    if first.get("labels"):
        label = first["labels"][0]
    commented = sum(1 for item in items if item.get("comment_inline"))
    return DataRun(
        start_addr=first["addr"],
        end_addr=end_addr,
        item_type=item_type,
        item_count=len(items),
        byte_length=byte_length,
        label=label,
        commented_count=commented,
    )


# --- Feature 2: heuristic classifiers ----------------------------


@dataclass(frozen=True)
class StringClassification:
    """Best printable-ASCII run found within a byte span."""
    start_offset: int
    length: int
    text: str
    confidence: float


@dataclass(frozen=True)
class CodeClassification:
    """Longest valid 6502 instruction sweep found within a byte span."""
    start_offset: int
    length: int
    instruction_count: int
    first_mnemonic: str
    confidence: float


@dataclass(frozen=True)
class PaddingClassification:
    """Repeating-pattern run starting at offset 0 of a span.

    ``fill_byte`` is the leading byte of the pattern; ``pattern_length``
    is 1 for ``FF FF FF`` / 2 for ``AB CD AB CD`` / etc.
    """
    start_offset: int
    length: int
    fill_byte: int
    pattern_length: int
    confidence: float


@dataclass(frozen=True)
class HiBytesTableClassification:
    """A run of bytes all in the project's ROM-page range.

    The high-byte halves of PHA/PHA/RTS-style dispatch tables
    look like this: every entry's high byte is a ROM page number,
    so the contiguous run sits entirely inside the band
    ``rom_base >> 8`` .. ``(rom_end - 1) >> 8``. Such runs happen
    to decode as long sequences of "valid" 6502 instructions
    (because most opcodes in the 0x80-0xBF range exist), which
    the code classifier would otherwise falsely flag as code.
    """
    start_offset: int
    length: int
    rom_page_range: tuple[int, int]
    confidence: float


# Bytes that count as "printable" for string detection: standard
# 0x20-0x7E plus the common whitespace controls. 0x00 is treated
# as a string terminator (allowed once at the end of a run).
_PRINTABLE = (
    set(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}
)


def looks_like_string(
    span: bytes,
    *,
    min_length: int = 4,
) -> StringClassification | None:
    """Find the longest printable-ASCII run within ``span``.

    A character is "printable" if it is in 0x20-0x7E or is one of
    the common whitespace controls (``\\t``, ``\\n``, ``\\r``).
    A trailing ``\\0`` is allowed as a terminator — it ends the
    run and is not included in the returned text — but the run
    must still meet ``min_length``.

    Confidence is the printable density (printables / total run
    bytes) over the matched range; for a clean string this is
    1.0 (or ~0.95 with one terminator).
    """
    if len(span) < min_length:
        return None

    best: StringClassification | None = None
    i = 0
    n = len(span)
    while i < n:
        # Find the maximal printable run starting at i.
        j = i
        while j < n and span[j] in _PRINTABLE:
            j += 1
        terminated = j < n and span[j] == 0x00
        run_end = j + 1 if terminated else j
        printable_count = j - i
        if printable_count >= min_length:
            text = span[i:j].decode("ascii", errors="replace")
            confidence = printable_count / (run_end - i) if run_end > i else 0.0
            if best is None or printable_count > best.length:
                best = StringClassification(
                    start_offset=i,
                    length=run_end - i,
                    text=text,
                    confidence=confidence,
                )
        # Advance past this region.
        i = max(run_end, i + 1)
    return best


def looks_like_hi_bytes_table(
    span: bytes,
    *,
    rom_page_range: tuple[int, int],
    min_length: int = 8,
) -> HiBytesTableClassification | None:
    """Find the longest run of bytes all in ``rom_page_range``.

    ``rom_page_range`` is an inclusive ``(low, high)`` tuple of byte
    values — typically derived from the project's ROM extents
    (e.g. ``(0x80, 0xBF)`` for a 16 KB BBC sideways ROM at &8000,
    ``(0xE0, 0xFF)`` for the Acorn Econet Bridge at &E000). A
    contiguous run of bytes all within this band is a strong
    signal of a high-byte address table — the "lo bytes / hi
    bytes" half of a PHA/PHA/RTS dispatch.

    Such runs happen to decode as long stretches of "valid"
    6502 instructions (most opcodes in 0x80-0xBF exist), which is
    what makes :func:`looks_like_code` mis-fire on them. Running
    this classifier first in the priority chain claims the bytes
    before the code classifier sees them.

    Confidence is 1.0 for an exact in-band run.
    """
    if len(span) < min_length:
        return None

    lo, hi = rom_page_range
    best: HiBytesTableClassification | None = None
    n = len(span)
    i = 0
    while i < n:
        if lo <= span[i] <= hi:
            j = i + 1
            while j < n and lo <= span[j] <= hi:
                j += 1
            run_length = j - i
            if run_length >= min_length and (
                best is None or run_length > best.length
            ):
                best = HiBytesTableClassification(
                    start_offset=i,
                    length=run_length,
                    rom_page_range=rom_page_range,
                    confidence=1.0,
                )
            i = j
        else:
            i += 1
    return best


def looks_like_code(
    span: bytes,
    *,
    cpu: str = "6502",
    min_length: int = 8,
) -> CodeClassification | None:
    """Find the longest valid-opcode sweep within ``span``.

    Walks every starting alignment in ``span`` and consumes
    instructions according to the per-CPU opcode-length table.
    A sweep ends at the first byte that doesn't decode to a
    declared opcode (length 0) or that would extend past the
    end of ``span``. The longest sweep across all alignments
    wins.

    ``cpu`` selects the opcode-length table — ``"6502"`` (NMOS,
    default) or ``"65c02"`` (CMOS).

    Confidence is currently a coarse length heuristic
    (``min(length / 32, 1.0)``); fields are reserved for future
    operand-sanity scoring.
    """
    if len(span) < min_length:
        return None

    lengths, mnemonics = opcode_tables(cpu)

    best: CodeClassification | None = None
    n = len(span)
    for start in range(n):
        i = start
        instructions = 0
        while i < n:
            length = lengths[span[i]]
            if length == 0 or i + length > n:
                break
            i += length
            instructions += 1
        run_length = i - start
        if run_length >= min_length and (
            best is None or run_length > best.length
        ):
            best = CodeClassification(
                start_offset=start,
                length=run_length,
                instruction_count=instructions,
                first_mnemonic=mnemonics[span[start]],
                confidence=min(run_length / 32.0, 1.0),
            )
    return best


def looks_like_padding(
    span: bytes,
    *,
    min_length: int = 4,
    max_pattern_length: int = 4,
) -> PaddingClassification | None:
    """Detect a repeating-byte-pattern run starting at offset 0.

    Tries every pattern length from 1 up to ``max_pattern_length``
    (default 4 — ROM fill is overwhelmingly 1-byte fills like
    ``FF FF FF…`` / ``00 00 00…`` / ``EA EA EA…``, sometimes 2-byte
    alternating fills like ``AB CD AB CD``, very rarely longer).
    The match requires at least two full repetitions of the pattern,
    which avoids classifying coincidentally-repeated short
    instruction sequences as padding.

    Confidence is 1.0 for an exact pattern match.
    """
    if len(span) < min_length:
        return None

    best: PaddingClassification | None = None
    # Need at least two full repetitions to call something padding.
    upper = min(max_pattern_length, len(span) // 2)
    for pattern_length in range(1, upper + 1):
        pattern = span[:pattern_length]
        # How many bytes from the start match the repeating pattern?
        i = pattern_length
        while (
            i + pattern_length <= len(span)
            and span[i:i + pattern_length] == pattern
        ):
            i += pattern_length
        repetitions = i // pattern_length
        if repetitions >= 2 and i >= min_length and (
            best is None or i > best.length
        ):
            best = PaddingClassification(
                start_offset=0,
                length=i,
                fill_byte=span[0],
                pattern_length=pattern_length,
                confidence=1.0,
            )
    return best


# --- Orchestrator ------------------------------------------------


@dataclass(frozen=True)
class Classification:
    """One reclassification candidate produced by the orchestrator."""

    addr: int
    length: int
    kind: str
    confidence: float
    preview: str


def find_classification_candidates(
    items: Sequence[dict],
    *,
    cpu: str = "6502",
    target_types: Iterable[str] = ("byte",),
    rom_page_range: tuple[int, int] | None = None,
    min_string: int = 4,
    min_code: int = 8,
    min_padding: int = 4,
    min_hi_bytes: int = 8,
) -> list[Classification]:
    """Walk runs of target-type items and surface reclassification hints.

    For each contiguous run of items whose type is in
    ``target_types`` (default ``("byte",)`` — the catch-all bucket
    py8dis emits for unclassified data), concatenate the run's
    bytes and apply the classifiers in priority order:
    **padding → string → hi_bytes_table → code**. The first
    classifier to claim bytes at a given offset wins; the cursor
    advances past the match before the next classifier runs.

    The ``hi_bytes_table`` step runs only when ``rom_page_range``
    is provided (typically derived by the caller from the JSON's
    ``meta.load_addr`` / ``meta.end_addr``). It catches runs of
    bytes all in the project's ROM-page band — the high-byte
    halves of dispatch tables, which would otherwise be misread
    as long valid-code sweeps by the code classifier.

    Returns one :class:`Classification` per claimed span, sorted
    by length descending so the most-interesting candidates
    surface first. Spans that no classifier claims do not appear
    in the output (the user is interested in candidates *for*
    reclassification, not in noting that py8dis already got the
    rest right).
    """
    types = set(target_types)
    findings: list[Classification] = []

    current_run: list[dict] = []

    def flush() -> None:
        if not current_run:
            return
        run_bytes = bytearray()
        for item in current_run:
            run_bytes.extend(item.get("bytes") or ())
        run_addr = current_run[0]["addr"]
        findings.extend(
            classify_run_bytes(
                bytes(run_bytes),
                run_addr=run_addr,
                cpu=cpu,
                rom_page_range=rom_page_range,
                min_string=min_string,
                min_code=min_code,
                min_padding=min_padding,
                min_hi_bytes=min_hi_bytes,
            )
        )
        current_run.clear()

    for item in items:
        if item.get("type") in types:
            current_run.append(item)
        else:
            flush()
    flush()

    findings.sort(key=lambda f: -f.length)
    return findings


def classify_run_bytes(
    span: bytes,
    *,
    run_addr: int = 0,
    cpu: str = "6502",
    rom_page_range: tuple[int, int] | None = None,
    min_string: int = 4,
    min_code: int = 8,
    min_padding: int = 4,
    min_hi_bytes: int = 8,
) -> list[Classification]:
    """Apply padding → string → hi_bytes_table → code classifiers across ``span``.

    Walks ``span`` left-to-right, calling each classifier in
    priority order at the current cursor position. The first
    classifier that returns a match consumes those bytes; the
    cursor advances past the match before the next round. The
    hi_bytes_table classifier is skipped when ``rom_page_range``
    is ``None``.

    Returned :class:`Classification` ``addr`` values are
    ``run_addr + match_offset`` so callers can plot the findings
    back onto the ROM directly.
    """
    findings: list[Classification] = []
    cursor = 0
    n = len(span)
    while cursor < n:
        remainder = span[cursor:]

        padding = looks_like_padding(remainder, min_length=min_padding)
        if padding is not None and padding.start_offset == 0:
            findings.append(_padding_to_classification(
                padding, run_addr + cursor, remainder
            ))
            cursor += padding.length
            continue

        string = looks_like_string(remainder, min_length=min_string)
        if string is not None and string.start_offset == 0:
            findings.append(_string_to_classification(
                string, run_addr + cursor
            ))
            cursor += string.length
            continue

        if rom_page_range is not None:
            hi_table = looks_like_hi_bytes_table(
                remainder,
                rom_page_range=rom_page_range,
                min_length=min_hi_bytes,
            )
            if hi_table is not None and hi_table.start_offset == 0:
                findings.append(_hi_bytes_table_to_classification(
                    hi_table, run_addr + cursor, remainder
                ))
                cursor += hi_table.length
                continue

        code = looks_like_code(remainder, cpu=cpu, min_length=min_code)
        if code is not None and code.start_offset == 0:
            findings.append(_code_to_classification(
                code, run_addr + cursor
            ))
            cursor += code.length
            continue

        # Nothing claimed this position; advance one byte and try again.
        cursor += 1

    return findings


def _padding_to_classification(
    p: PaddingClassification, addr: int, span: bytes
) -> Classification:
    if p.pattern_length == 1:
        preview = f"{p.fill_byte:02X} × {p.length}"
    else:
        pattern = span[:p.pattern_length]
        pat_str = " ".join(f"{b:02X}" for b in pattern)
        repeat_count = p.length // p.pattern_length
        preview = f"({pat_str}) × {repeat_count}"
    return Classification(
        addr=addr,
        length=p.length,
        kind="padding",
        confidence=p.confidence,
        preview=preview,
    )


def _string_to_classification(
    s: StringClassification, addr: int
) -> Classification:
    text = s.text if len(s.text) <= 40 else s.text[:39] + "…"
    # Render embedded newlines / tabs as escapes so the preview
    # stays single-line.
    text = (
        text
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
    )
    return Classification(
        addr=addr,
        length=s.length,
        kind="string",
        confidence=s.confidence,
        preview=f'"{text}"',
    )


def _code_to_classification(
    c: CodeClassification, addr: int
) -> Classification:
    return Classification(
        addr=addr,
        length=c.length,
        kind="code",
        confidence=c.confidence,
        preview=(
            f"{c.first_mnemonic}; "
            f"{c.instruction_count} instructions in {c.length} bytes"
        ),
    )


def _hi_bytes_table_to_classification(
    h: HiBytesTableClassification, addr: int, span: bytes
) -> Classification:
    lo, hi = h.rom_page_range
    sample = " ".join(f"{b:02X}" for b in span[:min(h.length, 6)])
    suffix = " …" if h.length > 6 else ""
    return Classification(
        addr=addr,
        length=h.length,
        kind="hi_bytes_table",
        confidence=h.confidence,
        preview=(
            f"{h.length} bytes in &{lo:02X}..&{hi:02X} (sample: {sample}{suffix})"
        ),
    )


__all__ = [
    "Classification",
    "CodeClassification",
    "DataRun",
    "HiBytesTableClassification",
    "PaddingClassification",
    "StringClassification",
    "classify_run_bytes",
    "find_classification_candidates",
    "find_data_runs",
    "looks_like_code",
    "looks_like_hi_bytes_table",
    "looks_like_padding",
    "looks_like_string",
]
