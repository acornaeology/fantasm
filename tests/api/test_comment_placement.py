"""Tests for the comment-placement checks in ``fantasm.api.comment_check``.

These cover comments that are well-formed but sit on the wrong
instruction or describe the wrong value: lo/hi byte claims, quoted
strings placed at the wrong address, character-literal operands
described as address parts, branch phrasing on non-branches, code
that is only ever read as a table, inline comments keyed inside an
item, and comments copied by numeric address from a parent version.
"""

from __future__ import annotations

from fantasm.api.comment_check import (
    ParentVersion,
    check_branch_phrasing,
    check_byte_of_address,
    check_char_literal_operand,
    check_code_read_as_data,
    check_copied_comments,
    check_mid_item_comments,
    check_quoted_string_address,
    run_checks,
)
from fantasm.api.driver_annotations import parse_driver_annotations


def _code(addr: int, mnemonic: str, operand: str, bytes_: list[int], comment: str = "", **extra) -> dict:
    item = {
        "addr": addr,
        "type": "code",
        "mnemonic": mnemonic,
        "operand": operand,
        "bytes": bytes_,
        **extra,
    }
    if comment:
        item["comment_inline"] = comment
    return item


# --- check_byte_of_address -----------------------------------------


class TestCheckByteOfAddress:
    def test_low_byte_mismatch_is_high(self) -> None:
        # 3.65 carried 3.60's address in this comment.
        item = _code(0x8279, "ldx", "#&80", [0xA2, 0x80],
                     "X = lo byte of auto-boot string at &8292")
        (finding,) = check_byte_of_address(item, {})
        assert finding["check"] == "byte_of_address"
        assert finding["confidence"] == "HIGH"
        assert "&8292" in finding["message"]

    def test_low_byte_match_is_clean(self) -> None:
        item = _code(0x8279, "ldx", "#&80", [0xA2, 0x80],
                     "X = lo byte of auto-boot string at &8280")
        assert check_byte_of_address(item, {}) is None

    def test_high_byte_of_symbolic_operand(self) -> None:
        item = _code(0x9E98, "ldy", "#>(discard_reset_listen)", [0xA0, 0x9A],
                     "High byte of &99DB handler")
        (finding,) = check_byte_of_address(item, {})
        assert "(&99)" in finding["message"]
        assert "(&9A)" in finding["message"]

    def test_parenthesised_byte_mismatch_is_medium(self) -> None:
        item = _code(0x8CA7, "lda", "#&9a", [0xA9, 0x9A],
                     "Push return address low (&74)")
        (finding,) = check_byte_of_address(item, {})
        assert finding["confidence"] == "MEDIUM"

    def test_zero_page_location_equal_to_operand_is_clean(self) -> None:
        item = _code(0x04CD, "ldx", "#&53", [0xA2, 0x53],
                     "X=&53: transfer address high byte (&0053)")
        assert check_byte_of_address(item, {}) is None

    def test_lo_inside_identifier_is_ignored(self) -> None:
        item = _code(0x86B8, "lda", "#&c5", [0xA9, 0xC5],
                     "Point fs_crc_lo/hi at &0E30 parse buffer")
        assert check_byte_of_address(item, {}) is None

    def test_non_immediate_is_ignored(self) -> None:
        item = _code(0x8000, "lda", "&8292", [0xAD, 0x92, 0x82],
                     "lo byte of &1234")
        assert check_byte_of_address(item, {}) is None


# --- check_quoted_string_address -----------------------------------


class TestCheckQuotedStringAddress:
    MEMORY = {0x8500 + i: b for i, b in enumerate(b"SP.")} | {0x8529: 0x00}

    def test_wrong_address_flagged(self) -> None:
        item = _code(0x8000, "lda", "#&17", [0xA9, 0x17],
                     "')': offset into \"SP.\" string at &8529")
        (finding,) = check_quoted_string_address(item, {"memory": self.MEMORY})
        assert finding["check"] == "quoted_string_address"
        assert "'SP.'" in finding["message"]

    def test_right_address_clean(self) -> None:
        item = _code(0x8000, "lda", "#&17", [0xA9, 0x17],
                     "offset into \"SP.\" string at &8500")
        assert check_quoted_string_address(item, {"memory": self.MEMORY}) is None

    def test_top_bit_terminator_ignored(self) -> None:
        memory = {0x8500: ord("S"), 0x8501: ord("P"), 0x8502: ord(".") | 0x80}
        item = _code(0x8000, "ldx", "#0", [0xA2, 0x00], "\"SP.\" at &8500")
        assert check_quoted_string_address(item, {"memory": memory}) is None

    def test_address_outside_image_skipped(self) -> None:
        item = _code(0x8000, "ldx", "#0", [0xA2, 0x00], "\"SP.\" at &0E30")
        assert check_quoted_string_address(item, {"memory": self.MEMORY}) is None


# --- check_char_literal_operand ------------------------------------


class TestCheckCharLiteralOperand:
    def test_char_described_as_offset(self) -> None:
        item = _code(0x8000, "lda", "#')'", [0xA9, 0x29],
                     "Offset of close_spool_cmd in the table")
        (finding,) = check_char_literal_operand(item, {})
        assert finding["check"] == "char_literal_operand"

    def test_char_described_as_char_is_clean(self) -> None:
        item = _code(0x8000, "cmp", "#')'", [0xC9, 0x29], "Closing bracket?")
        assert check_char_literal_operand(item, {}) is None

    def test_numeric_operand_ignored(self) -> None:
        item = _code(0x8000, "lda", "#&29", [0xA9, 0x29], "Offset of command")
        assert check_char_literal_operand(item, {}) is None


# --- check_branch_phrasing -----------------------------------------


class TestCheckBranchPhrasing:
    def test_branch_comment_on_load(self) -> None:
        item = _code(0x849B, "lda", "fs_spool0", [0xA5, 0x00],
                     "Branch if flow control set")
        (finding,) = check_branch_phrasing(item, {})
        assert "branch phrasing" in finding["message"]

    def test_loop_until_on_compare_is_clean(self) -> None:
        item = _code(0x8195, "cpy", "#&14", [0xC0, 0x14], "Loop until offset &14 done")
        assert check_branch_phrasing(item, {}) is None

    def test_condition_prefix_on_fall_through_is_clean(self) -> None:
        # "Zero: ..." on the first instruction of a path is normal.
        item = _code(0x85A0, "dey", "", [0x88], "Zero: invalid handle, set Y=&FF")
        assert check_branch_phrasing(item, {}) is None

    def test_load_comment_on_branch(self) -> None:
        item = _code(0x8000, "beq", "skip", [0xF0, 0x02], "Load handler address low byte")
        (finding,) = check_branch_phrasing(item, {})
        assert "load/store phrasing" in finding["message"]

    def test_load_comment_on_bra(self) -> None:
        item = _code(0x8000, "bra", "skip", [0x80, 0x02], "Push return address")
        assert check_branch_phrasing(item, {}) is not None


# --- check_code_read_as_data ---------------------------------------


def _separator_table_items() -> list[dict]:
    # ANFS 4.26 before the fix: the separator table after an
    # always-taken BNE was traced as JSR/BIT/ROL/... code.
    return [
        _code(0xA4A1, "cmp", "sep_table_data,y", [0xD9, 0xAD, 0xA4]),
        _code(0xA4A4, "rts", "", [0x60]),
        _code(0xA4AB, "bne", "loop", [0xD0, 0xF0]),
        _code(0xA4AD, "jsr", "&2322", [0x20, 0x22, 0x23],
              labels=["sep_table_data"],
              references=[{"addr": 0xA4A1, "kind": "indexed"}]),
    ]


class TestCheckCodeReadAsData:
    def test_table_decoded_as_code(self) -> None:
        (finding,) = check_code_read_as_data(_separator_table_items())
        assert finding["addr"] == 0xA4AD
        assert finding["check"] == "code_read_as_data"
        assert "&A4A1" in finding["message"]

    def test_code_with_control_flow_reference_is_clean(self) -> None:
        items = _separator_table_items()
        items[-1]["references"].append({"addr": 0xA4AB, "kind": "direct"})
        assert check_code_read_as_data(items) == []

    def test_copy_loop_is_clean(self) -> None:
        items = [
            _code(0x0400, "lda", "source,x", [0xBD, 0x00, 0x90]),
            _code(0x0403, "sta", "&0D00,x", [0x9D, 0x00, 0x0D]),
            _code(0x9000, "jmp", "&9100", [0x4C, 0x00, 0x91],
                  references=[{"addr": 0x0400, "kind": "indexed"}]),
        ]
        assert check_code_read_as_data(items) == []

    def test_labelled_operand_bytes_are_clean(self) -> None:
        items = _separator_table_items()
        items[-1]["sub_labels"] = {str(0xA4AE): ["handler_lo"]}
        assert check_code_read_as_data(items) == []

    def test_outside_image_is_clean(self) -> None:
        items = _separator_table_items()
        assert check_code_read_as_data(items, image_range=(0x8000, 0xA000)) == []


# --- check_mid_item_comments ---------------------------------------


class TestCheckMidItemComments:
    ITEMS = [
        _code(0x85B1, "lda", "#&64", [0xA9, 0x64]),
        _code(0x85B3, "jsr", "print_digit", [0x20, 0x00, 0x90]),
        {"addr": 0x85B6, "type": "string", "bytes": [0x41, 0x42, 0x43]},
    ]

    def test_comment_inside_instruction_is_high(self) -> None:
        anns = parse_driver_annotations(
            'd.comment(0x85B2, "Print hundreds digit", align=Align.INLINE)\n'
        )
        (finding,) = check_mid_item_comments(self.ITEMS, anns)
        assert finding["confidence"] == "HIGH"
        assert finding["addr"] == 0x85B2
        assert "LDA #&64 at &85B1" in finding["message"]
        assert "driver line 1" in finding["message"]

    def test_comment_inside_data_is_medium(self) -> None:
        anns = parse_driver_annotations('comment(0x85B7, "tail", inline=True)\n')
        (finding,) = check_mid_item_comments(self.ITEMS, anns)
        assert finding["confidence"] == "MEDIUM"
        assert "3-byte string item" in finding["message"]

    def test_comment_at_item_start_is_clean(self) -> None:
        anns = parse_driver_annotations(
            'd.comment(0x85B3, "Print hundreds digit", align=Align.INLINE)\n'
        )
        assert check_mid_item_comments(self.ITEMS, anns) == []

    def test_block_comments_ignored(self) -> None:
        anns = parse_driver_annotations('d.comment(0x85B2, "Block")\n')
        assert check_mid_item_comments(self.ITEMS, anns) == []


# --- check_copied_comments -----------------------------------------


class TestCheckCopiedComments:
    PARENT_ITEMS = [
        _code(0x87B4, "lda", "osword_dispatch_lo_table,x", [0xBD, 0x00, 0x90],
              "Load handler address low byte"),
        _code(0x87B7, "iny", "", [0xC8], "(continued)"),
        _code(0x87B8, "rts", "", [0x60], "Return"),
    ]

    def test_same_text_different_instruction(self) -> None:
        items = [
            _code(0x87B4, "beq", "alloc_run_fcb", [0xF0, 0x10],
                  "Load handler address low byte"),
        ]
        parent = ParentVersion("4.18", {"items": self.PARENT_ITEMS})
        (finding,) = check_copied_comments(items, parent)
        assert finding["check"] == "copied_comment"
        assert "4.18 has LDA osword_dispatch_lo_table,x" in finding["message"]
        assert "here it is BEQ alloc_run_fcb" in finding["message"]

    def test_mapped_address_reported(self) -> None:
        items = [
            _code(0x87B4, "beq", "alloc_run_fcb", [0xF0, 0x10],
                  "Load handler address low byte"),
        ]
        parent = ParentVersion(
            "4.18", {"items": self.PARENT_ITEMS},
            address_map={0x87B4: (0x87B1, 50)},
        )
        (finding,) = check_copied_comments(items, parent)
        assert "4.18 &87B4 corresponds to &87B1 here" in finding["message"]

    def test_same_instruction_is_clean(self) -> None:
        items = [_code(0x87B8, "rts", "", [0x60], "Return")]
        parent = ParentVersion("4.18", {"items": self.PARENT_ITEMS})
        assert check_copied_comments(items, parent) == []

    def test_chain_marker_ignored(self) -> None:
        items = [_code(0x87B7, "dey", "", [0x88], "(continued)")]
        parent = ParentVersion("4.18", {"items": self.PARENT_ITEMS})
        assert check_copied_comments(items, parent) == []

    def test_different_text_is_clean(self) -> None:
        items = [_code(0x87B4, "beq", "alloc_run_fcb", [0xF0, 0x10], "Done?")]
        parent = ParentVersion("4.18", {"items": self.PARENT_ITEMS})
        assert check_copied_comments(items, parent) == []


# --- run_checks integration ----------------------------------------


class TestRunChecksPlacement:
    DATA = {
        "meta": {"load_addr": 0x8000, "end_addr": 0x8100},
        "items": [
            _code(0x8000, "lda", "#&64", [0xA9, 0x64], "Load hundreds"),
            _code(0x8002, "ldx", "#&80", [0xA2, 0x80], "lo byte of &8292"),
            _code(0x8004, "rts", "", [0x60], "Return"),
        ],
    }

    def test_item_checks_run_without_driver_or_parents(self) -> None:
        checks = {f["check"] for f in run_checks(self.DATA)}
        assert "byte_of_address" in checks
        assert "mid_item_comment" not in checks

    def test_driver_and_parent_checks(self) -> None:
        anns = parse_driver_annotations('comment(0x8001, "Stray", inline=True)\n')
        parent = ParentVersion("0.9", {"items": [
            _code(0x8004, "jmp", "&9000", [0x4C, 0x00, 0x90], "Return"),
        ]})
        findings = run_checks(
            self.DATA, driver_annotations=anns, parents=[parent]
        )
        by_check = {f["check"]: f for f in findings}
        assert by_check["mid_item_comment"]["addr"] == 0x8001
        assert by_check["copied_comment"]["addr"] == 0x8004

    def test_sub_range_filters_whole_item_findings(self) -> None:
        data = dict(self.DATA, subroutines=[
            {"addr": 0x8000, "name": "a"}, {"addr": 0x8004, "name": "b"},
        ])
        anns = parse_driver_annotations('comment(0x8001, "Stray", inline=True)\n')
        findings = run_checks(data, "8004", driver_annotations=anns)
        assert all(f["addr"] >= 0x8004 for f in findings)
