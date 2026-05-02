"""Tests for ``fantasm.api.data_review``."""

from __future__ import annotations

import pytest

from fantasm.api.data_review import (
    Classification,
    classify_run_bytes,
    find_classification_candidates,
    find_data_runs,
    looks_like_code,
    looks_like_padding,
    looks_like_string,
)


# --- helpers -----------------------------------------------------


def _byte(addr, raw_bytes, *, label=None, comment=None):
    item = {"addr": addr, "type": "byte", "bytes": list(raw_bytes)}
    if label is not None:
        item["labels"] = [label]
    if comment is not None:
        item["comment_inline"] = comment
    return item


def _word(addr, raw_bytes, *, label=None):
    item = {"addr": addr, "type": "word", "bytes": list(raw_bytes)}
    if label is not None:
        item["labels"] = [label]
    return item


def _string(addr, text, *, label=None):
    raw = text.encode("ascii")
    item = {"addr": addr, "type": "string", "bytes": list(raw), "string": text}
    if label is not None:
        item["labels"] = [label]
    return item


def _code(addr, raw_bytes):
    return {"addr": addr, "type": "code", "bytes": list(raw_bytes), "mnemonic": "lda"}


# --- find_data_runs ----------------------------------------------


class TestFindDataRuns:
    def test_single_long_run(self) -> None:
        # One run of byte items, sized to clear the default 8-byte threshold.
        items = [
            _byte(0x8000, [0xAA, 0xBB], label="first"),
            _byte(0x8002, [0xCC, 0xDD]),
            _byte(0x8004, [0xEE, 0xFF]),
            _byte(0x8006, [0x11, 0x22], comment="end"),
        ]
        runs = find_data_runs(items)
        assert len(runs) == 1
        run = runs[0]
        assert run.start_addr == 0x8000
        assert run.end_addr == 0x8007
        assert run.item_type == "byte"
        assert run.item_count == 4
        assert run.byte_length == 8
        assert run.label == "first"
        assert run.commented_count == 1
        assert run.is_annotated is True

    def test_runs_break_on_other_type(self) -> None:
        items = [
            _byte(0x8000, [0x00] * 8),
            _code(0x8008, [0x60]),     # rts breaks the run
            _byte(0x8009, [0x00] * 8),
        ]
        runs = find_data_runs(items)
        assert len(runs) == 2
        assert runs[0].start_addr in (0x8000, 0x8009)
        assert runs[1].start_addr in (0x8000, 0x8009)

    def test_runs_break_on_different_data_type(self) -> None:
        # byte → word → byte gives three separate runs (assuming each is
        # long enough; we set the byte runs to 8 bytes each).
        items = [
            _byte(0x8000, [0x00] * 8),
            _word(0x8008, [0xAA, 0xBB]),
            _word(0x800A, [0xCC, 0xDD]),
            _word(0x800C, [0xEE, 0xFF]),
            _word(0x800E, [0x11, 0x22]),
            _byte(0x8010, [0x00] * 8),
        ]
        runs = find_data_runs(items, min_bytes=4)
        types = sorted(r.item_type for r in runs)
        assert types == ["byte", "byte", "word"]
        word_run = next(r for r in runs if r.item_type == "word")
        assert word_run.byte_length == 8

    def test_min_bytes_filter(self) -> None:
        # A short run below min_bytes is filtered out.
        items = [
            _byte(0x8000, [0xAA, 0xBB]),    # 2 bytes — below default 8
            _code(0x8002, [0x60]),
            _byte(0x8003, [0xCC] * 16),    # 16 bytes — kept
        ]
        runs = find_data_runs(items)
        assert len(runs) == 1
        assert runs[0].byte_length == 16

    def test_runs_sorted_longest_first(self) -> None:
        items = [
            _byte(0x8000, [0xAA] * 8),
            _code(0x8008, [0x60]),
            _byte(0x8009, [0xBB] * 32),
            _code(0x8029, [0x60]),
            _byte(0x802A, [0xCC] * 16),
        ]
        runs = find_data_runs(items)
        assert [r.byte_length for r in runs] == [32, 16, 8]

    def test_item_types_filter(self) -> None:
        items = [
            _byte(0x8000, [0xAA] * 8),
            _string(0x8008, "Hello world"),
            _byte(0x8013, [0xBB] * 8),
        ]
        # Restrict to byte only — the string run drops out.
        runs = find_data_runs(items, item_types=("byte",))
        assert all(r.item_type == "byte" for r in runs)

    def test_label_only_from_run_head(self) -> None:
        # A label on a mid-run item doesn't change the run's "head" label.
        items = [
            _byte(0x8000, [0x00] * 4, label="head"),
            _byte(0x8004, [0x00] * 4, label="midway"),
            _byte(0x8008, [0x00] * 4),
        ]
        runs = find_data_runs(items, min_bytes=4)
        assert len(runs) == 1
        assert runs[0].label == "head"

    def test_un_annotated_run(self) -> None:
        items = [_byte(0x8000, [0x00] * 16)]
        runs = find_data_runs(items)
        assert runs[0].is_annotated is False
        assert runs[0].label is None
        assert runs[0].commented_count == 0


# --- looks_like_string -------------------------------------------


class TestLooksLikeString:
    def test_pure_ascii(self) -> None:
        result = looks_like_string(b"Hello world")
        assert result is not None
        assert result.start_offset == 0
        assert result.length == len(b"Hello world")
        assert result.text == "Hello world"
        assert result.confidence == 1.0

    def test_with_terminator(self) -> None:
        result = looks_like_string(b"Hello\x00")
        assert result is not None
        assert result.length == 6              # 5 printable + 1 terminator
        assert result.text == "Hello"

    def test_embedded_run(self) -> None:
        # A printable string in the middle of a binary span.
        result = looks_like_string(b"\xFF\xFFHello world\xFF\xFF")
        assert result is not None
        assert result.start_offset == 2
        assert result.text == "Hello world"

    def test_too_short(self) -> None:
        assert looks_like_string(b"Hi") is None

    def test_no_printable(self) -> None:
        assert looks_like_string(b"\xFF\xFE\xFD\xFC") is None

    def test_min_length_rejects_below(self) -> None:
        assert looks_like_string(b"Hello", min_length=10) is None

    def test_includes_whitespace(self) -> None:
        result = looks_like_string(b"foo\tbar\n")
        assert result is not None
        assert "foo" in result.text


# --- looks_like_code ---------------------------------------------


class TestLooksLikeCode:
    def test_clean_sweep(self) -> None:
        # LDA #00 (A9 00) ; STA &1234 (8D 34 12) ; RTS (60)
        # Six bytes, three valid instructions.
        span = bytes.fromhex("A9 00 8D 34 12 60".replace(" ", ""))
        result = looks_like_code(span, min_length=4)
        assert result is not None
        assert result.start_offset == 0
        assert result.length == 6
        assert result.instruction_count == 3
        assert result.first_mnemonic == "LDA"

    def test_finds_longest_alignment(self) -> None:
        # First byte is invalid (FF — 6502 invalid opcode in the NMOS table),
        # but starting at offset 1 we get a clean 6-byte sweep.
        span = bytes.fromhex("FF A9 00 8D 34 12 60")
        result = looks_like_code(span, min_length=4)
        assert result is not None
        assert result.start_offset == 1
        assert result.length == 6

    def test_too_short(self) -> None:
        # Below min_length — even though the bytes are valid.
        span = bytes.fromhex("A9 00")    # LDA #00 — only 2 bytes
        assert looks_like_code(span, min_length=4) is None

    def test_truncated_instruction(self) -> None:
        # 8D would need 2 more bytes for the operand; only 1 available.
        span = bytes.fromhex("8D 34")
        # The sweep can't complete the instruction; no valid run.
        assert looks_like_code(span, min_length=2) is None

    def test_cmos_only_opcode(self) -> None:
        # 65C02-only opcode 0x80 (BRA), invalid on plain 6502.
        span = bytes.fromhex("80 02 60")    # BRA +2 ; RTS — 65C02 valid
        assert looks_like_code(span, cpu="6502", min_length=2) is None
        result = looks_like_code(span, cpu="65c02", min_length=2)
        assert result is not None


# --- looks_like_padding ------------------------------------------


class TestLooksLikePadding:
    def test_single_byte_fill(self) -> None:
        result = looks_like_padding(b"\xFF" * 16)
        assert result is not None
        assert result.length == 16
        assert result.fill_byte == 0xFF
        assert result.pattern_length == 1

    def test_double_byte_pattern(self) -> None:
        result = looks_like_padding(b"\xAB\xCD" * 8)
        assert result is not None
        assert result.length == 16
        assert result.fill_byte == 0xAB
        assert result.pattern_length == 2

    def test_too_short(self) -> None:
        assert looks_like_padding(b"\xFF\xFF") is None

    def test_no_pattern(self) -> None:
        assert looks_like_padding(b"\x01\x02\x03\x04\x05\x06\x07\x08") is None

    def test_partial_at_tail(self) -> None:
        # A 1-byte fill that runs cleanly to the end.
        result = looks_like_padding(b"\xEA" * 17)
        assert result is not None
        assert result.length == 17

    def test_starts_at_offset_zero(self) -> None:
        # Padding only matches when starting at offset 0; an embedded
        # padding run shouldn't be reported (the orchestrator will
        # advance past the prefix and re-try).
        assert looks_like_padding(b"AB\xFF\xFF\xFF\xFF\xFF\xFF") is None


# --- classify_run_bytes / find_classification_candidates ---------


class TestClassifyRunBytes:
    def test_padding_then_string(self) -> None:
        span = b"\xFF" * 8 + b"Hello, world!" + b"\x00"
        findings = classify_run_bytes(span, run_addr=0x8000)
        kinds = [f.kind for f in findings]
        assert kinds[0] == "padding"
        assert "string" in kinds
        # The string finding's address is past the padding.
        string_finding = next(f for f in findings if f.kind == "string")
        assert string_finding.addr == 0x8000 + 8

    def test_priority_padding_over_code(self) -> None:
        # A 0xEA run is technically valid 6502 NOP code, but the
        # padding classifier wins by priority.
        span = b"\xEA" * 16
        findings = classify_run_bytes(span, run_addr=0x8000)
        assert findings[0].kind == "padding"

    def test_unclaimed_bytes_drop(self) -> None:
        # Two short non-classifiable bytes between two longer claimable
        # runs. The orchestrator advances byte-by-byte through the
        # un-classifiable region.
        span = b"\xFF" * 8 + b"\x12\x34" + b"\xEE" * 8
        findings = classify_run_bytes(span, run_addr=0x8000)
        assert len(findings) == 2
        assert findings[0].kind == "padding"
        assert findings[1].kind == "padding"
        # The middle two bytes don't appear as findings.
        total_claimed = sum(f.length for f in findings)
        assert total_claimed == 16


class TestFindClassificationCandidates:
    def test_orchestrator_walks_byte_runs(self) -> None:
        items = [
            # A byte run that's actually a string.
            {"addr": 0x8000, "type": "byte",
             "bytes": list(b"Acorn ANFS 4.18\x00")},
            # A code item breaks the run.
            {"addr": 0x8010, "type": "code",
             "bytes": [0x60], "mnemonic": "rts"},
            # Another byte run that's really FF padding.
            {"addr": 0x8011, "type": "byte",
             "bytes": [0xFF] * 12},
        ]
        candidates = find_classification_candidates(items)
        kinds = sorted(c.kind for c in candidates)
        assert kinds == ["padding", "string"]

    def test_target_types_restricts_examined_runs(self) -> None:
        items = [
            {"addr": 0x8000, "type": "string",
             "bytes": list(b"Already classified"), "string": "Already classified"},
            {"addr": 0x8012, "type": "byte",
             "bytes": list(b"Hello world")},
        ]
        # Default target_types is byte-only — string item is skipped.
        candidates = find_classification_candidates(items)
        assert all(c.kind == "string" for c in candidates)
        # Address falls within the BYTE run, not the already-classified
        # string item.
        assert candidates[0].addr == 0x8012

    def test_findings_sorted_longest_first(self) -> None:
        items = [
            {"addr": 0x8000, "type": "byte",
             "bytes": list(b"Hi") + [0xFF] * 16 + list(b"Hello world")},
        ]
        candidates = find_classification_candidates(items)
        # Longer findings precede shorter ones in the result list.
        lengths = [c.length for c in candidates]
        assert lengths == sorted(lengths, reverse=True)


class TestPreviewRendering:
    def test_string_preview_truncates_long_text(self) -> None:
        # Varied printable characters so the padding classifier doesn't
        # win on priority.
        long_text = ("The quick brown fox jumps over the lazy dog. " * 4)[:100]
        items = [{"addr": 0x8000, "type": "byte",
                  "bytes": list(long_text.encode("ascii"))}]
        candidates = find_classification_candidates(items)
        string_finding = next(c for c in candidates if c.kind == "string")
        # Truncated to 40 chars including the ellipsis.
        assert len(string_finding.preview) <= 42  # quotes + 40 chars
        assert string_finding.preview.endswith('…"')

    def test_padding_preview_count(self) -> None:
        items = [{"addr": 0x8000, "type": "byte",
                  "bytes": [0xFF] * 32}]
        candidates = find_classification_candidates(items)
        padding = candidates[0]
        assert "FF" in padding.preview
        assert "32" in padding.preview

    def test_code_preview_first_mnemonic(self) -> None:
        # LDA #00 ; STA &1234 ; RTS — three instructions, six bytes.
        items = [{"addr": 0x8000, "type": "byte",
                  "bytes": [0xA9, 0x00, 0x8D, 0x34, 0x12, 0x60,
                            0xA9, 0x00, 0x8D, 0x34, 0x12, 0x60]}]
        candidates = find_classification_candidates(items)
        code = next(c for c in candidates if c.kind == "code")
        assert "LDA" in code.preview
        assert "instructions" in code.preview
