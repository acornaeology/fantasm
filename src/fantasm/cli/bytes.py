"""``fantasm bytes`` — byte-signature search across ROM images.

A ``bytes`` group rather than a flat command — leaves room for
future ``bytes count``, ``bytes histogram`` and similar without
re-shuffling the CLI.
"""

from __future__ import annotations

import click
from asyoulikeit import Report, Reports, TableContent, report_output

from ..api.bytes_search import (
    BytePattern,
    ByteMatch,
    find_byte_pattern,
    parse_byte_pattern,
)
from ..cli_helpers import (
    analysis_context,
    project_rom_base,
    require_project,
    resolve_version_files,
)


@click.group(
    "bytes",
    help="Byte-signature search across ROM images.",
)
def bytes_group() -> None:
    pass


@bytes_group.command(
    "find",
    help=(
        "Find every occurrence of HEX_SEQUENCE in VERSION_ID's ROM. "
        "The pattern is hex bytes optionally separated by spaces or "
        "$/0x prefixes; '??' matches any single byte. With --cross "
        "VID, the same search runs against the named version too "
        "(repeatable) — useful for confirming a routine has moved or "
        "been removed in another release."
    ),
)
@click.argument("version_id")
@click.argument("hex_sequence")
@click.option(
    "--rom-base",
    type=click.IntRange(0, 0xFFFF),
    default=None,
    help="ROM load address; defaults to [rom] base_address (or 0x8000).",
)
@click.option(
    "--cross",
    "cross_versions",
    multiple=True,
    metavar="VERSION_ID",
    help=(
        "Also search this version's ROM for the same pattern. "
        "Repeatable: '--cross 4.18 --cross 4.21' searches both."
    ),
)
@report_output(reports={
    "matches": "Every occurrence of the pattern (one row per hit)",
    "summary": "Per-version match counts (only with --cross)",
})
def bytes_find(
    version_id: str,
    hex_sequence: str,
    rom_base: int | None,
    cross_versions: tuple[str, ...],
) -> Reports:
    try:
        pattern = parse_byte_pattern(hex_sequence)
    except ValueError as exc:
        raise click.UsageError(str(exc)) from exc

    ctx = click.get_current_context()
    project_context = require_project(ctx)
    if rom_base is None:
        rom_base = project_rom_base(project_context)

    has_wildcards = bool(pattern.wildcards)
    show_cross = bool(cross_versions)

    matches_table = (
        TableContent(
            title=(
                f"Byte-pattern hits across {1 + len(cross_versions)} versions"
                if show_cross
                else f"Byte-pattern hits in {version_id}"
            ),
            description=(
                f"pattern = {hex_sequence!r} "
                f"({len(pattern)} byte{'' if len(pattern) == 1 else 's'}, "
                f"{len(pattern.wildcards)} wildcard"
                f"{'' if len(pattern.wildcards) == 1 else 's'})"
            ),
        )
        .add_column("version", "Version")
        .add_column("addr", "Addr")
        .add_column("offset", "Offset")
    )
    if has_wildcards:
        matches_table.add_column("captures", "Captures")
    matches_table.add_column("context", "Context")

    summary_rows: list[tuple[str, int, str]] = []

    versions_to_search = [version_id, *cross_versions]
    for vid in versions_to_search:
        rom_bytes = _load_rom(project_context, vid)
        hits = find_byte_pattern(rom_bytes, pattern, rom_base=rom_base)

        for hit in hits:
            row: dict[str, str] = {
                "version": vid,
                "addr": f"&{hit.address:04X}",
                "offset": f"0x{hit.offset:04X}",
                "context": _format_context(rom_bytes, hit, len(pattern)),
            }
            if has_wildcards:
                row["captures"] = _format_captures(hit.captures)
            matches_table.add_row(**row)

        addr_summary = (
            ", ".join(f"&{h.address:04X}" for h in hits[:8])
            + (" …" if len(hits) > 8 else "")
            if hits
            else "—"
        )
        summary_rows.append((vid, len(hits), addr_summary))

    summary_table = (
        TableContent(
            title="Per-version match counts",
            description=f"pattern = {hex_sequence!r}",
        )
        .add_column("version", "Version")
        .add_column("count", "Count")
        .add_column("addresses", "Addresses (first 8)")
    )
    for vid, count, addrs in summary_rows:
        summary_table.add_row(version=vid, count=str(count), addresses=addrs)

    return Reports(
        matches=Report(data=matches_table),
        summary=Report(data=summary_table),
    )


def _load_rom(project_context, version_id: str) -> bytes:
    """Resolve and read the ROM bytes for ``version_id``."""
    files = resolve_version_files(project_context, version_id)
    if not files.rom_filepath.exists():
        raise click.UsageError(f"ROM not found: {files.rom_filepath}")
    return files.rom_filepath.read_bytes()


def _format_captures(captures: tuple[int, ...]) -> str:
    """Render the wildcard captures as ``[XX YY ZZ]`` or ``-`` if empty."""
    if not captures:
        return "-"
    return "[" + " ".join(f"{b:02X}" for b in captures) + "]"


def _format_context(
    rom_bytes: bytes, hit: ByteMatch, pattern_len: int, *, half_width: int = 6
) -> str:
    """Render ``half_width`` bytes either side of the match, with brackets.

    Truncated at ROM boundaries; "…" markers fill in when the
    surrounding window crosses an edge so callers can see at a
    glance whether the match is near the start or end of the file.
    """
    start = hit.offset - half_width
    end = hit.offset + pattern_len + half_width
    leading_truncated = start < 0
    trailing_truncated = end > len(rom_bytes)
    start = max(start, 0)
    end = min(end, len(rom_bytes))

    before = rom_bytes[start:hit.offset]
    middle = rom_bytes[hit.offset:hit.offset + pattern_len]
    after = rom_bytes[hit.offset + pattern_len:end]

    parts: list[str] = []
    if leading_truncated:
        parts.append("…")
    if before:
        parts.append(" ".join(f"{b:02X}" for b in before))
    parts.append("[" + " ".join(f"{b:02X}" for b in middle) + "]")
    if after:
        parts.append(" ".join(f"{b:02X}" for b in after))
    if trailing_truncated:
        parts.append("…")
    return " ".join(parts)
