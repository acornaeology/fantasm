"""Tests for ``fantasm.api.suggest``."""

from __future__ import annotations

import pytest

from fantasm.api.suggest import (
    CommentSuggestion,
    DEFAULT_INSTRUCTION_HINTS,
    suggest_comments,
    suggest_for_instruction,
)


# --- suggest_for_instruction ------------------------------------


class TestSuggestForInstruction:
    def test_pha_returns_save_a(self) -> None:
        item = {"addr": 0x8000, "mnemonic": "pha", "operand": "", "type": "code"}
        assert suggest_for_instruction(item) == "Save A on stack"

    def test_rts_returns_none(self) -> None:
        item = {"addr": 0x8000, "mnemonic": "rts", "operand": "", "type": "code"}
        assert suggest_for_instruction(item) is None

    def test_jsr_to_declared_sub_skipped(self) -> None:
        item = {
            "addr": 0x8000,
            "mnemonic": "jsr",
            "operand": "init_state",
            "target": 0x9000,
            "type": "code",
        }
        result = suggest_for_instruction(
            item, declared_subs={0x9000}
        )
        assert result is None

    def test_jsr_to_undeclared_sub_no_suggestion(self) -> None:
        # JSR has no instruction-hint, so result is None.
        item = {
            "addr": 0x8000,
            "mnemonic": "jsr",
            "operand": "unknown",
            "target": 0x9000,
            "type": "code",
        }
        assert suggest_for_instruction(item) is None

    def test_label_hint_match_lda(self) -> None:
        item = {
            "addr": 0x8000,
            "mnemonic": "lda",
            "operand": "wksp_ch_flags",
            "type": "code",
        }
        result = suggest_for_instruction(
            item, label_hints={"wksp_ch_flags": "channel flags"}
        )
        assert result == "Get channel flags"

    def test_label_hint_match_sta(self) -> None:
        item = {
            "addr": 0x8000,
            "mnemonic": "sta",
            "operand": "wksp_drive",
            "type": "code",
        }
        result = suggest_for_instruction(
            item, label_hints={"wksp_drive": "current drive"}
        )
        assert result == "Store in current drive"

    def test_label_hint_substring_matching(self) -> None:
        # The pattern matches anywhere in the operand.
        item = {
            "addr": 0x8000,
            "mnemonic": "lda",
            "operand": "wksp_ch_flags+1",
            "type": "code",
        }
        result = suggest_for_instruction(
            item, label_hints={"wksp_ch_flags": "channel flags"}
        )
        assert result == "Get channel flags"

    def test_custom_instruction_hints(self) -> None:
        item = {"addr": 0x8000, "mnemonic": "nop", "operand": "", "type": "code"}
        result = suggest_for_instruction(
            item, instruction_hints={"nop": "Wait one cycle"}
        )
        assert result == "Wait one cycle"

    def test_label_hint_with_no_template_falls_back(self) -> None:
        # CLC matches no label-store template. Even if its operand
        # had a workspace label substring (unlikely for CLC), we
        # don't return None — we fall back to instruction hints.
        item = {"addr": 0x8000, "mnemonic": "clc", "operand": "", "type": "code"}
        result = suggest_for_instruction(item)
        assert result == "Clear carry"


# --- suggest_comments -----------------------------------------


class TestSuggestComments:
    def test_skips_non_code(self) -> None:
        items = [
            {"addr": 0x8000, "type": "byte"},
            {"addr": 0x8001, "type": "code", "mnemonic": "pha"},
        ]
        suggestions = suggest_comments(items)
        assert [s.addr for s in suggestions] == [0x8001]

    def test_skips_already_commented(self) -> None:
        items = [
            {
                "addr": 0x8000,
                "type": "code",
                "mnemonic": "pha",
                "comment_inline": "existing",
            },
            {"addr": 0x8001, "type": "code", "mnemonic": "pla"},
        ]
        suggestions = suggest_comments(items)
        assert [s.addr for s in suggestions] == [0x8001]

    def test_skips_when_no_match(self) -> None:
        items = [
            {"addr": 0x8000, "type": "code", "mnemonic": "rts"},  # → None
        ]
        assert suggest_comments(items) == []

    def test_address_range_filter(self) -> None:
        items = [
            {"addr": 0x8000, "type": "code", "mnemonic": "pha"},
            {"addr": 0x8050, "type": "code", "mnemonic": "pla"},
            {"addr": 0x8100, "type": "code", "mnemonic": "tax"},
        ]
        suggestions = suggest_comments(
            items, address_range=(0x8000, 0x8100)
        )
        addrs = [s.addr for s in suggestions]
        # 0x8100 is excluded (range is half-open).
        assert addrs == [0x8000, 0x8050]

    def test_returns_dataclass(self) -> None:
        items = [
            {"addr": 0x8000, "type": "code", "mnemonic": "pha"}
        ]
        suggestions = suggest_comments(items)
        assert isinstance(suggestions[0], CommentSuggestion)


def test_default_instruction_hints_covers_common_cases() -> None:
    assert "pha" in DEFAULT_INSTRUCTION_HINTS
    assert "tax" in DEFAULT_INSTRUCTION_HINTS
    assert "clc" in DEFAULT_INSTRUCTION_HINTS
    # CMOS-only mnemonics included.
    assert "phx" in DEFAULT_INSTRUCTION_HINTS
    assert "plx" in DEFAULT_INSTRUCTION_HINTS
