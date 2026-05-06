"""Back-propagate annotations between ROM versions.

Builds an opcode-level confidence map between two ROM images and
parses disassembly driver scripts to extract their annotations
(``comment``/``label``/``subroutine`` calls — the same call shape
in dasmos and py8dis). Together these let annotations from a
richly-annotated version flow back to less annotated ones via
the high-confidence portion of the address map.

Sibling ``disasm_tools.backfill`` (621 lines, byte-identical across
forks) carried two heavy NFS-specific pieces:

- ``VERSION_CHAIN`` — adjacent-version pairs and their relocation
  blocks, hardcoded for NFS.
- ``build_chained_map`` and the top-level ``backfill()`` — file-IO,
  printing, and version-chain walking that depends on the above.

The fantasm port lifts the **pure helpers** out:
:func:`build_confidence_map`, :func:`build_confidence_map_for_block`,
:func:`group_logical_statements`, :func:`parse_annotations`,
:func:`translate_address_in_text`, :func:`translate_subroutine`.

Project-specific concerns are parameters now: ``rom_base`` (was a
module-level constant) and ``workspace_ranges`` (was hardcoded as
``range(0x0000, 0x0100)`` plus NFS's ``range(0x0D00, 0x1000)``).
A future fantasm.toml schema will let projects declare their own
version chains; ``build_chained_map`` will land then alongside the
``fantasm backfill`` Click sub-command.
"""

from __future__ import annotations

import difflib
import re
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from .blockmatch import disassemble_to_opcodes

if TYPE_CHECKING:
    from fantasm.config import ProjectContext


def build_confidence_map_for_block(
    insts_a: Sequence[tuple[int, int, int]],
    insts_b: Sequence[tuple[int, int, int]],
    base_a: int,
    base_b: int,
) -> dict[int, tuple[int, int]]:
    """Build ``{addr_a: (addr_b, block_length)}`` from two instruction lists.

    ``base_a``/``base_b`` are added to raw offsets to produce final
    addresses. ``block_length`` is the number of consecutive matching
    opcodes in the enclosing equal block — the confidence signal.
    """
    opcodes_a = [op for _, op, _ in insts_a]
    opcodes_b = [op for _, op, _ in insts_b]

    matcher = difflib.SequenceMatcher(
        None, opcodes_a, opcodes_b, autojunk=False
    )

    conf_map: dict[int, tuple[int, int]] = {}
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            block_length = i2 - i1
            for k in range(block_length):
                addr_a = base_a + insts_a[i1 + k][0]
                addr_b = base_b + insts_b[j1 + k][0]
                conf_map[addr_a] = (addr_b, block_length)
    return conf_map


def build_confidence_map(
    data_a: bytes,
    data_b: bytes,
    reloc_blocks: Iterable[tuple[int, int, int, int]] = (),
    *,
    rom_base: int = 0x8000,
    workspace_ranges: Iterable[tuple[int, int]] = ((0x0000, 0x0100),),
    high_confidence: int = 1000,
    cpu: str = "6502",
) -> dict[int, tuple[int, int]]:
    """Full confidence map between two ROM versions.

    ``reloc_blocks`` is an iterable of
    ``(src_a, src_b, runtime_dest, length)`` tuples describing
    relocated code — each block is matched separately at its runtime
    destination and merged in. ``workspace_ranges`` get identity
    mappings at ``high_confidence`` so labels for workspace variables
    propagate even when no opcodes anchor them.

    Returns ``{addr_a: (addr_b, block_length)}``.
    """
    insts_a = disassemble_to_opcodes(data_a, cpu)
    insts_b = disassemble_to_opcodes(data_b, cpu)

    conf_map = build_confidence_map_for_block(
        insts_a, insts_b, rom_base, rom_base
    )

    reloc_destination_addrs: set[int] = set()
    for src_a, src_b, dest, length in reloc_blocks:
        block_a = data_a[src_a - rom_base:src_a - rom_base + length]
        block_b = data_b[src_b - rom_base:src_b - rom_base + length]
        reloc_insts_a = disassemble_to_opcodes(block_a, cpu)
        reloc_insts_b = disassemble_to_opcodes(block_b, cpu)
        conf_map.update(
            build_confidence_map_for_block(
                reloc_insts_a, reloc_insts_b, dest, dest
            )
        )
        for a in range(dest, dest + length):
            reloc_destination_addrs.add(a)

    # Identity mappings for workspace addresses (excluding any address
    # already occupied by a relocated block — those addresses are code
    # at runtime, not workspace).
    for start, end in workspace_ranges:
        for addr in range(start, end):
            if addr in conf_map:
                continue
            if addr in reloc_destination_addrs:
                continue
            conf_map[addr] = (addr, high_confidence)

    return conf_map


# --- Annotation parsing -------------------------------------------


# Regex for inline comments: comment(0xADDR, "text", inline=True)
RE_INLINE_COMMENT = re.compile(
    r'^comment\(0x([0-9A-Fa-f]+),\s*"((?:[^"\\]|\\.)*)"\s*,\s*inline\s*=\s*True\)',
    re.MULTILINE,
)
RE_LABEL = re.compile(
    r'^label\(0x([0-9A-Fa-f]+),\s*"([^"]+)"',
    re.MULTILINE,
)
RE_SUBROUTINE = re.compile(
    r'^subroutine\(0x([0-9A-Fa-f]+)',
    re.MULTILINE,
)


def group_logical_statements(
    lines: Sequence[str],
) -> list[tuple[int, int, list[str]]]:
    """Group lines into balanced-paren statements.

    Returns ``(start_line_idx, end_line_idx_exclusive, lines_list)``
    tuples. Quoted strings and ``#`` comments are skipped when
    counting parens.
    """
    groups: list[tuple[int, int, list[str]]] = []
    current_start = 0
    current_lines: list[str] = []
    paren_depth = 0
    in_string: str | None = None
    escaped = False

    for i, line in enumerate(lines):
        current_lines.append(line)

        for j, ch in enumerate(line):
            if in_string is None:
                if ch == "#":
                    break
                if ch in ('"', "'"):
                    triple = line[j:j + 3]
                    if triple in ('"""', "'''"):
                        in_string = triple
                    else:
                        in_string = ch
                elif ch == "(":
                    paren_depth += 1
                elif ch == ")":
                    paren_depth -= 1
            else:
                if escaped:
                    escaped = False
                    continue
                if len(in_string) == 3 and line[j:j + 3] == in_string:
                    in_string = None
                elif len(in_string) == 1 and ch == in_string:
                    in_string = None
                elif ch == "\\":
                    escaped = True

        if paren_depth <= 0:
            paren_depth = 0
            groups.append((current_start, i + 1, current_lines))
            current_start = i + 1
            current_lines = []

    if current_lines:
        groups.append(
            (current_start, current_start + len(current_lines), current_lines)
        )

    return groups


def parse_annotations(
    script_text: str,
) -> tuple[
    dict[int, list[tuple[str, str]]],
    dict[int, tuple[str, str]],
    set[str],
    dict[int, str],
]:
    """Parse driver-script text and return its annotations.

    Returns ``(inline_comments, labels, label_names, subroutines)``:

    - ``inline_comments``: ``{addr -> [(text, full_line), ...]}``
    - ``labels``: ``{addr -> (name, full_line)}`` — last label wins
    - ``label_names``: set of every label name encountered
    - ``subroutines``: ``{addr -> full_statement_text}`` (may be
      multi-line)
    """
    lines = script_text.split("\n")
    groups = group_logical_statements(lines)

    inline_comments: dict[int, list[tuple[str, str]]] = {}
    labels: dict[int, tuple[str, str]] = {}
    label_names: set[str] = set()
    subroutines: dict[int, str] = {}

    for _start, _end, group_lines in groups:
        first_line = group_lines[0].strip()
        full_text = "\n".join(group_lines)

        match = RE_INLINE_COMMENT.match(first_line)
        if match:
            addr = int(match.group(1), 16)
            text = match.group(2)
            inline_comments.setdefault(addr, []).append(
                (text, group_lines[0].rstrip())
            )
            continue

        match = RE_LABEL.match(first_line)
        if match:
            addr = int(match.group(1), 16)
            name = match.group(2)
            labels[addr] = (name, group_lines[0].rstrip())
            label_names.add(name)
            continue

        match = RE_SUBROUTINE.match(first_line)
        if match:
            addr = int(match.group(1), 16)
            subroutines[addr] = full_text

    return inline_comments, labels, label_names, subroutines


def translate_address_in_text(text: str, old_addr: int, new_addr: int) -> str:
    """Replace ``0xOLDADDR`` with ``0xNEWADDR`` everywhere in ``text``."""
    return text.replace(f"0x{old_addr:04X}", f"0x{new_addr:04X}")


def translate_subroutine(full_text: str, old_addr: int, new_addr: int) -> str:
    """Translate the address argument in a ``subroutine()`` call.

    Only replaces the *first* occurrence of ``0xOLDADDR``: the address
    argument. Description text further inside the call is left
    untouched.
    """
    return full_text.replace(f"0x{old_addr:04X}", f"0x{new_addr:04X}", 1)


# --- Propagation candidate selection -----------------------------


@dataclass(frozen=True)
class PropagationCandidate:
    """One annotation that backfill proposes to copy from source to target.

    ``confidence`` is the composed block-length from the chain map.
    ``text`` carries the comment string (for ``kind == "comment"``)
    or the full ``subroutine()`` source text (for
    ``kind == "subroutine"``); for labels it's the label name.
    """

    source_addr: int
    target_addr: int
    confidence: int
    kind: str  # "comment" | "label" | "subroutine"
    name: str | None
    text: str


@dataclass(frozen=True)
class PropagationReport:
    """Result of :func:`propose_propagations` — accepted + skipped tallies."""

    candidates: tuple[PropagationCandidate, ...]
    skipped_no_mapping: int
    skipped_below_threshold: int
    skipped_target_has_annotation: int
    skipped_label_name_conflict: int


def propose_propagations(
    source_text: str,
    target_text: str,
    confidence_map: dict[int, tuple[int, int]],
    *,
    threshold: int = 5,
) -> PropagationReport:
    """Build the list of annotations worth propagating from source to target.

    For each annotation in ``source_text``:

    - drop it if its address has no mapping in ``confidence_map``
      (or maps below ``threshold``);
    - drop it if the target address already carries an annotation of
      the same kind (deduplication is conservative — exact text match
      for comments, any-label-at-addr for labels, any-sub-at-addr for
      subroutines);
    - drop a label if its name is already used elsewhere in the target
      driver script.

    The remaining annotations are returned as
    :class:`PropagationCandidate` records, alongside a tally of
    skip reasons for the user-facing report.
    """
    src_comments, src_labels, _src_label_names, src_subs = parse_annotations(
        source_text
    )
    tgt_comments, tgt_labels, tgt_label_names, tgt_subs = parse_annotations(
        target_text
    )

    candidates: list[PropagationCandidate] = []
    skipped_no_mapping = 0
    skipped_below_threshold = 0
    skipped_target_has_annotation = 0
    skipped_label_name_conflict = 0

    def _resolve(src_addr: int) -> tuple[int, int] | None:
        nonlocal skipped_no_mapping, skipped_below_threshold
        mapped = confidence_map.get(src_addr)
        if mapped is None:
            skipped_no_mapping += 1
            return None
        target_addr, confidence = mapped
        if confidence < threshold:
            skipped_below_threshold += 1
            return None
        return target_addr, confidence

    # Inline comments.
    for src_addr, comment_list in src_comments.items():
        for text, _line in comment_list:
            mapped = _resolve(src_addr)
            if mapped is None:
                continue
            target_addr, confidence = mapped
            existing_texts = {t for t, _ in tgt_comments.get(target_addr, [])}
            if text in existing_texts:
                skipped_target_has_annotation += 1
                continue
            candidates.append(
                PropagationCandidate(
                    source_addr=src_addr,
                    target_addr=target_addr,
                    confidence=confidence,
                    kind="comment",
                    name=None,
                    text=text,
                )
            )

    # Labels.
    for src_addr, (name, _line) in src_labels.items():
        mapped = _resolve(src_addr)
        if mapped is None:
            continue
        target_addr, confidence = mapped
        if target_addr in tgt_labels:
            skipped_target_has_annotation += 1
            continue
        if name in tgt_label_names:
            skipped_label_name_conflict += 1
            continue
        candidates.append(
            PropagationCandidate(
                source_addr=src_addr,
                target_addr=target_addr,
                confidence=confidence,
                kind="label",
                name=name,
                text=name,
            )
        )

    # Subroutines.
    for src_addr, full_text in src_subs.items():
        mapped = _resolve(src_addr)
        if mapped is None:
            continue
        target_addr, confidence = mapped
        if target_addr in tgt_subs:
            skipped_target_has_annotation += 1
            continue
        translated = translate_subroutine(full_text, src_addr, target_addr)
        match = RE_SUBROUTINE.search(translated)
        sub_name: str | None = None
        name_match = re.search(
            r'subroutine\(0x[0-9A-Fa-f]+,\s*"([^"]+)"', translated
        )
        if name_match:
            sub_name = name_match.group(1)
        candidates.append(
            PropagationCandidate(
                source_addr=src_addr,
                target_addr=target_addr,
                confidence=confidence,
                kind="subroutine",
                name=sub_name,
                text=translated,
            )
        )

    candidates.sort(key=lambda c: (c.target_addr, c.kind))
    return PropagationReport(
        candidates=tuple(candidates),
        skipped_no_mapping=skipped_no_mapping,
        skipped_below_threshold=skipped_below_threshold,
        skipped_target_has_annotation=skipped_target_has_annotation,
        skipped_label_name_conflict=skipped_label_name_conflict,
    )


# --- Cross-version annotation diff -----------------------------------


@dataclass(frozen=True)
class AnnotationDiff:
    """A single annotation difference between two driver scripts.

    ``status`` is one of:

    - ``"differs"`` — both source and target carry an annotation of
      this kind at the mapped addresses, but the values differ
      (different comment text, different label name, different sub
      title);
    - ``"missing_in_target"`` — source has an annotation; target's
      mapped address has no annotation of this kind;
    - ``"no_mapping"`` — source's address has no entry in the
      confidence map (or below threshold), so the annotation can't
      be located in the target at all.

    For ``"no_mapping"``, ``target_addr`` is ``None`` and
    ``confidence`` is ``0``.
    """

    source_addr: int
    target_addr: int | None
    confidence: int
    kind: str  # "comment" | "label" | "subroutine"
    source_value: str
    target_value: str | None
    status: str


def diff_annotations(
    source_text: str,
    target_text: str,
    confidence_map: dict[int, tuple[int, int]],
    *,
    threshold: int = 5,
) -> list[AnnotationDiff]:
    """Compare annotations across two driver scripts.

    For each annotation in ``source_text``, looks up its mapped
    target address in ``confidence_map`` (filtered by
    ``threshold``) and compares against the target driver's
    annotations at that address. Returns a list of
    :class:`AnnotationDiff` records covering every discrepancy.

    "Discrepancy" includes addresses with no mapping, addresses
    where the target lacks the same kind of annotation, and
    addresses where both sides have annotations of the same kind
    but with different content.
    """
    src_comments, src_labels, _, src_subs = parse_annotations(source_text)
    tgt_comments, tgt_labels, _, tgt_subs = parse_annotations(target_text)

    diffs: list[AnnotationDiff] = []

    def _resolve(src_addr: int) -> tuple[int | None, int]:
        mapping = confidence_map.get(src_addr)
        if mapping is None or mapping[1] < threshold:
            return None, 0
        return mapping[0], mapping[1]

    for src_addr, comment_list in src_comments.items():
        target_addr, confidence = _resolve(src_addr)
        for text, _line in comment_list:
            if target_addr is None:
                diffs.append(
                    AnnotationDiff(
                        source_addr=src_addr,
                        target_addr=None,
                        confidence=0,
                        kind="comment",
                        source_value=text,
                        target_value=None,
                        status="no_mapping",
                    )
                )
                continue
            tgt_at_addr = tgt_comments.get(target_addr, [])
            tgt_texts = [t for t, _ in tgt_at_addr]
            if text in tgt_texts:
                continue
            diffs.append(
                AnnotationDiff(
                    source_addr=src_addr,
                    target_addr=target_addr,
                    confidence=confidence,
                    kind="comment",
                    source_value=text,
                    target_value=" | ".join(tgt_texts) if tgt_texts else None,
                    status="differs" if tgt_texts else "missing_in_target",
                )
            )

    for src_addr, (name, _line) in src_labels.items():
        target_addr, confidence = _resolve(src_addr)
        if target_addr is None:
            diffs.append(
                AnnotationDiff(
                    source_addr=src_addr,
                    target_addr=None,
                    confidence=0,
                    kind="label",
                    source_value=name,
                    target_value=None,
                    status="no_mapping",
                )
            )
            continue
        tgt_label = tgt_labels.get(target_addr)
        if tgt_label is None:
            diffs.append(
                AnnotationDiff(
                    source_addr=src_addr,
                    target_addr=target_addr,
                    confidence=confidence,
                    kind="label",
                    source_value=name,
                    target_value=None,
                    status="missing_in_target",
                )
            )
        elif tgt_label[0] != name:
            diffs.append(
                AnnotationDiff(
                    source_addr=src_addr,
                    target_addr=target_addr,
                    confidence=confidence,
                    kind="label",
                    source_value=name,
                    target_value=tgt_label[0],
                    status="differs",
                )
            )

    for src_addr, src_full in src_subs.items():
        target_addr, confidence = _resolve(src_addr)
        # Source name from the call's first quoted arg.
        src_name_match = re.search(
            r'subroutine\(0x[0-9A-Fa-f]+,\s*"([^"]+)"', src_full
        )
        src_name = src_name_match.group(1) if src_name_match else "(unnamed)"
        if target_addr is None:
            diffs.append(
                AnnotationDiff(
                    source_addr=src_addr,
                    target_addr=None,
                    confidence=0,
                    kind="subroutine",
                    source_value=src_name,
                    target_value=None,
                    status="no_mapping",
                )
            )
            continue
        tgt_full = tgt_subs.get(target_addr)
        if tgt_full is None:
            diffs.append(
                AnnotationDiff(
                    source_addr=src_addr,
                    target_addr=target_addr,
                    confidence=confidence,
                    kind="subroutine",
                    source_value=src_name,
                    target_value=None,
                    status="missing_in_target",
                )
            )
            continue
        tgt_name_match = re.search(
            r'subroutine\(0x[0-9A-Fa-f]+,\s*"([^"]+)"', tgt_full
        )
        tgt_name = (
            tgt_name_match.group(1) if tgt_name_match else "(unnamed)"
        )
        if src_name != tgt_name:
            diffs.append(
                AnnotationDiff(
                    source_addr=src_addr,
                    target_addr=target_addr,
                    confidence=confidence,
                    kind="subroutine",
                    source_value=src_name,
                    target_value=tgt_name,
                    status="differs",
                )
            )

    diffs.sort(key=lambda d: (d.kind, d.source_addr))
    return diffs


# --- High-level public entry point for cross-version generators ----


def make_project_rom_loader(
    project: "ProjectContext",
) -> Callable[[str], bytes]:
    """Return a memoised ROM-bytes loader keyed by version id.

    The loader resolves each version's directory against the project
    config (``[versions] prefixes`` / ``directory``), then reads
    ``versions/<prefix>-<id>/rom/<prefix>-<id>.rom``. Bytes are
    cached for the lifetime of the returned closure.

    Raises :class:`FileNotFoundError` when a requested version's
    ROM file is missing — the API-layer counterpart to the CLI's
    ``click.UsageError``.
    """
    from .paths import (
        project_rom_prefixes,
        resolve_version_dirpath_for_project,
    )

    prefixes = project_rom_prefixes(project)
    cache: dict[str, bytes] = {}

    def loader(version_id: str) -> bytes:
        if version_id not in cache:
            version_dirpath = resolve_version_dirpath_for_project(
                project, version_id
            )
            name = version_dirpath.name
            matched_prefix = next(
                (p for p in prefixes if name == p or name.startswith(f"{p}-")),
                prefixes[0] if prefixes else "",
            )
            base = f"{matched_prefix}-{version_id}"
            rom_filepath = version_dirpath / "rom" / f"{base}.rom"
            if not rom_filepath.exists():
                raise FileNotFoundError(
                    f"ROM not found for version {version_id!r}: {rom_filepath}"
                )
            cache[version_id] = rom_filepath.read_bytes()
        return cache[version_id]

    return loader


def propose_translations(
    project: "ProjectContext",
    *,
    source_version: str,
    target_version: str,
    source_driver: Path,
    target_driver: Path | None = None,
    threshold: int = 5,
    cpu: str | None = None,
    rom_base: int | None = None,
    workspace_ranges: Iterable[tuple[int, int]] = ((0x0000, 0x0100),),
    high_confidence: int = 1000,
) -> PropagationReport:
    """High-level translation proposal pipeline for generator scripts.

    Glues together the version graph, opcode-level confidence-map
    composition, and annotation parsing — the same pipeline
    ``fantasm backfill`` runs on the CLI side, exposed as a public
    API so cross-version baseline generators (e.g. an
    ``acorn-nfs/scripts/generate_421_variant_1.py``) can use the
    same anchored translation engine instead of reaching for
    :func:`fantasm.api.blockmatch.build_full_address_map` and
    inheriting its weaker contract (see issue #10).

    Anchoring contract: every emitted candidate is anchored in a
    composed shared block of length ≥ ``threshold`` opcodes across
    the full source-to-target path through the version graph (the
    weakest hop is the binding constraint). Source addresses
    outside such a block produce no candidate — the consumer
    should route those to ``# UNMAPPED:``.

    Args:
        project: The project context. Use
            :func:`fantasm.config.resolve_project_context` to
            obtain one (``resolve_project_context(None)`` walks up
            from the current working directory).
        source_version: Version id whose annotations to translate.
        target_version: Version id to translate them to.
        source_driver: Path to the source driver script.
        target_driver: Optional path to an existing target driver.
            When given, candidates whose target address already
            carries an annotation of the same kind are skipped (the
            same dedup rule the CLI applies). When omitted (typical
            for "fresh baseline" use), all anchored translations
            are proposed.
        threshold: Minimum composed block length for a candidate.
            Default 5 matches ``fantasm backfill``'s CLI default.
        cpu: Override for the project's ``[rom] cpu`` setting.
        rom_base: Override for the project's ``[rom] base_address``.
        workspace_ranges: Identity-mapped workspace regions.
        high_confidence: Confidence stamped on workspace mappings.

    Raises:
        FileNotFoundError: ``source_driver`` (or, when given,
            ``target_driver``) does not exist; or any version's ROM
            bytes are missing.
        VersionGraphError: The version graph could not be loaded.
        VersionNotInGraphError: A version isn't in the graph.
        NoPathError: No path between the two versions.
    """
    from .version_graph import compose_chained_map, load_version_graph

    if not source_driver.exists():
        raise FileNotFoundError(
            f"source driver not found: {source_driver}"
        )
    if target_driver is not None and not target_driver.exists():
        raise FileNotFoundError(
            f"target driver not found: {target_driver}"
        )

    rom_section: dict = {}
    if project.has_root:
        rom_section = dict(project.config.get("rom", {}))
    if cpu is None:
        cpu = rom_section.get("cpu", "6502")
    if rom_base is None:
        rom_base = rom_section.get("base_address", 0x8000)

    target_text = (
        target_driver.read_text() if target_driver is not None else ""
    )

    rom_loader = make_project_rom_loader(project)
    graph = load_version_graph(project)

    confidence_map = compose_chained_map(
        graph,
        source_version,
        target_version,
        rom_loader,
        rom_base=rom_base,
        cpu=cpu,
        workspace_ranges=workspace_ranges,
        high_confidence=high_confidence,
    )

    return propose_propagations(
        source_driver.read_text(),
        target_text,
        confidence_map,
        threshold=threshold,
    )


__all__ = [
    "AnnotationDiff",
    "PropagationCandidate",
    "PropagationReport",
    "RE_INLINE_COMMENT",
    "RE_LABEL",
    "RE_SUBROUTINE",
    "build_confidence_map",
    "build_confidence_map_for_block",
    "diff_annotations",
    "group_logical_statements",
    "make_project_rom_loader",
    "parse_annotations",
    "propose_propagations",
    "propose_translations",
    "translate_address_in_text",
    "translate_subroutine",
]
