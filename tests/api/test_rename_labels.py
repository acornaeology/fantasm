"""Tests for ``fantasm.api.rename_labels`` helpers."""

from __future__ import annotations

import pytest

from fantasm.api.rename_labels import (
    LABEL_DECL_RE,
    apply_renames_inline,
    apply_renames_to_lines,
    parse_label_decl_lines,
    update_ref_strings,
)


# --- LABEL_DECL_RE --------------------------------------------------


class TestLabelDeclRe:
    @pytest.mark.parametrize(
        "line, expected_callable, expected_addr, expected_name",
        [
            ('label(0x8000, "init")\n', "label", 0x8000, "init"),
            ('d.label(0x8000, "init")\n', "d.label", 0x8000, "init"),
            ('  d.label(0xABCD, "deep")\n', "d.label", 0xABCD, "deep"),
            ('\td.label(0xFF00, "ind")\n', "d.label", 0xFF00, "ind"),
        ],
    )
    def test_matches(
        self,
        line: str,
        expected_callable: str,
        expected_addr: int,
        expected_name: str,
    ) -> None:
        match = LABEL_DECL_RE.match(line)
        assert match is not None
        assert match.group(2) == expected_callable
        assert int(match.group(3), 16) == expected_addr
        assert match.group(4) == expected_name

    def test_rejects_other_calls(self) -> None:
        assert LABEL_DECL_RE.match('subroutine(0x8000, "init")\n') is None
        assert LABEL_DECL_RE.match('# label(0x8000, "init")\n') is None


# --- parse_label_decl_lines ----------------------------------------


class TestParseLabelDeclLines:
    def test_extracts_label_and_d_label(self) -> None:
        lines = [
            "import py8dis\n",
            'd.label(0x8000, "init")\n',
            'label(0x8010, "tail")\n',
            "# trailing comment\n",
        ]
        decls = parse_label_decl_lines(lines)
        assert [(d["addr"], d["name"], d["callable"]) for d in decls] == [
            (0x8000, "init", "d.label"),
            (0x8010, "tail", "label"),
        ]
        assert decls[0]["line"] == 1
        assert decls[1]["line"] == 2

    def test_preserves_indentation(self) -> None:
        lines = ['    d.label(0xAB00, "indented")\n']
        decls = parse_label_decl_lines(lines)
        assert decls[0]["prefix"] == "    "


# --- apply_renames_inline ------------------------------------------


class TestApplyRenamesInline:
    def test_rewrites_d_label_in_place(self) -> None:
        lines = ['d.label(0x8000, "old_name")\n']
        new_lines, name_map = apply_renames_inline(lines, {0x8000: "new_name"})
        assert new_lines == ['d.label(0x8000, "new_name")\n']
        assert name_map == {0x8000: ("old_name", "new_name")}

    def test_rewrites_bare_label(self) -> None:
        lines = ['label(0xABCD, "foo")\n']
        new_lines, _ = apply_renames_inline(lines, {0xABCD: "bar"})
        assert new_lines == ['label(0xABCD, "bar")\n']

    def test_preserves_indentation(self) -> None:
        lines = ['    d.label(0x8000, "old")\n']
        new_lines, _ = apply_renames_inline(lines, {0x8000: "new"})
        assert new_lines == ['    d.label(0x8000, "new")\n']

    def test_no_op_when_names_match(self) -> None:
        lines = ['d.label(0x8000, "same")\n']
        new_lines, name_map = apply_renames_inline(lines, {0x8000: "same"})
        assert new_lines == lines
        assert name_map == {}

    def test_missing_address_aborts_with_listing(self) -> None:
        lines = ['d.label(0x8000, "init")\n']
        with pytest.raises(LookupError) as excinfo:
            apply_renames_inline(
                lines,
                {0x8000: "boot", 0x9999: "ghost", 0xAAAA: "ghost2"},
            )
        message = str(excinfo.value)
        assert "0x9999" in message
        assert "0xAAAA" in message

    def test_unchanged_when_aborting_on_missing(self) -> None:
        lines = ['d.label(0x8000, "init")\n']
        with pytest.raises(LookupError):
            apply_renames_inline(lines, {0x9999: "ghost"})
        # Caller passed a non-mutated copy back; the original list
        # is untouched (helper produces a copy anyway).
        assert lines == ['d.label(0x8000, "init")\n']

    def test_handles_multiple_renames(self) -> None:
        lines = [
            'd.label(0x8000, "a_old")\n',
            'd.label(0x8010, "b_old")\n',
            'label(0x8020, "c_old")\n',
        ]
        new_lines, _ = apply_renames_inline(
            lines,
            {0x8000: "a_new", 0x8010: "b_new", 0x8020: "c_new"},
        )
        assert new_lines == [
            'd.label(0x8000, "a_new")\n',
            'd.label(0x8010, "b_new")\n',
            'label(0x8020, "c_new")\n',
        ]


# --- update_ref_strings --------------------------------------------


class TestUpdateRefStrings:
    def test_rewrites_d_comment_args(self) -> None:
        lines = ['d.comment(0xA3FE, "tail of return_from_x")\n']
        new_lines, count = update_ref_strings(
            lines, {0xA3FE: ("return_from_x", "rts_x")}
        )
        assert new_lines == ['d.comment(0xA3FE, "tail of rts_x")\n']
        assert count == 1

    def test_rewrites_description_triple_quoted(self) -> None:
        lines = [
            'description = """The return_from_x tail handles\n',
            'the common return_from_x path."""\n',
        ]
        new_lines, count = update_ref_strings(
            lines, {0xA3FE: ("return_from_x", "rts_x")}
        )
        assert "The rts_x tail" in new_lines[0]
        # Only the first occurrence on the description= line lands
        # because the second one is on a continuation line outside
        # the per-line pattern. The line-by-line scan covers the
        # primary description-opener case; multi-line spans are
        # documented as a known limitation.
        assert count >= 1

    def test_rewrites_markdown_anchor(self) -> None:
        lines = [
            '# See [`return_from_x`](address:0xA3FE) for the tail.\n'
        ]
        new_lines, count = update_ref_strings(
            lines, {0xA3FE: ("return_from_x", "rts_x")}
        )
        assert "[`rts_x`](address:0xA3FE)" in new_lines[0]
        assert count == 1

    def test_word_boundary_skips_substring(self) -> None:
        # init shouldn't match within initialise.
        lines = ['d.comment(0x8000, "initialise the buffer")\n']
        new_lines, count = update_ref_strings(
            lines, {0x8000: ("init", "boot")}
        )
        assert new_lines == lines
        assert count == 0

    def test_no_renames_returns_input_untouched(self) -> None:
        lines = ['d.comment(0x8000, "init the buffer")\n']
        new_lines, count = update_ref_strings(lines, {})
        assert new_lines == lines
        assert count == 0

    def test_skips_no_op_renames(self) -> None:
        # name_map entries where old == new contribute nothing.
        lines = ['d.comment(0x8000, "init the buffer")\n']
        new_lines, count = update_ref_strings(
            lines, {0x8000: ("init", "init")}
        )
        assert new_lines == lines
        assert count == 0


# --- apply_renames_to_lines (section mode, legacy) -----------------


def test_section_mode_unchanged_signature() -> None:
    """Smoke-check: legacy section-mode entry still exists and works."""
    lines = [
        "# Code label renames\n",
        'label(0x8010, "first")\n',
        "\n",
        "# =================== End ===================\n",
    ]
    new_lines = apply_renames_to_lines(lines, {0x8010: "renamed"})
    assert any('"renamed"' in line for line in new_lines)
