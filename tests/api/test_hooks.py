"""Tests for ``fantasm.api.hooks``."""

from __future__ import annotations

import pytest

from fantasm.api.hooks import (
    HookCandidate,
    find_hook_candidates,
    render_hook_subroutine_line,
)


# --- helpers -----------------------------------------------------


def _jsr(addr, target, *, target_label=""):
    item = {
        "addr": addr,
        "type": "code",
        "mnemonic": "jsr",
        "bytes": [0x20, target & 0xFF, (target >> 8) & 0xFF],
        "target": target,
    }
    if target_label:
        item["target_label"] = target_label
    return item


def _string(addr, raw_bytes, *, text=None):
    return {
        "addr": addr,
        "type": "string",
        "bytes": list(raw_bytes),
        "string": text if text is not None
                  else "".join(chr(b) for b in raw_bytes),
    }


def _byte(addr, raw_bytes):
    return {"addr": addr, "type": "byte", "bytes": list(raw_bytes)}


def _code(addr, raw_bytes, mnemonic="lda"):
    return {
        "addr": addr, "type": "code", "bytes": list(raw_bytes),
        "mnemonic": mnemonic,
    }


# Bytes that decode as a clean 6502 instruction stream
# (LDA #imm; STA abs; RTS = 6 bytes / 3 instructions). First byte
# (0xA9) has bit 7 set, so this resume run *also* satisfies the
# stringhi structural signal.
_VALID_RESUME_CODE = [0xA9, 0x00, 0x8D, 0x34, 0x12, 0x60]

# Same idea, but the first byte has bit 7 *clear* — for tests that
# need to exercise stringz/stringcr without tripping the
# bit-7-next-byte stringhi rule. (JMP $8000; RTS = 4 bytes.)
_VALID_RESUME_CODE_NO_BIT7 = [0x4C, 0x00, 0x80, 0x60]


# --- terminator-kind classification ------------------------------


class TestTerminatorClassification:
    def test_stringcr(self) -> None:
        # String ends in 0x0D and the next byte's bit 7 is *clear*
        # → stringcr.
        items = []
        addr = 0x8000
        for _ in range(3):
            items += [
                _jsr(addr, 0x9000),
                _string(addr + 3, b"Hello\r"),
                _byte(addr + 9, _VALID_RESUME_CODE_NO_BIT7),
            ]
            addr += 0x100
        candidates = find_hook_candidates(items)
        assert len(candidates) == 1
        assert candidates[0].hook_kind == "stringcr"
        assert candidates[0].hook_function == "stringcr_hook"

    def test_stringz(self) -> None:
        # String ends in 0x00 → stringz, regardless of next byte.
        items = []
        for i in range(3):
            base = 0x8000 + i * 0x100
            items += [
                _jsr(base, 0x9000),
                _string(base + 3, b"Hi\x00"),
                _byte(base + 6, _VALID_RESUME_CODE),
            ]
        candidates = find_hook_candidates(items)
        assert candidates[0].hook_kind == "stringz"
        assert candidates[0].hook_function == "stringz_hook"

    def test_stringhi_via_bit7_next_byte(self) -> None:
        # py8dis encodes stringhi asymmetrically: the bit-7
        # terminator lives as the first byte of the *next* item,
        # not as the last byte of the string. Here the printed
        # text has no terminator on its own.
        items = []
        for i in range(3):
            base = 0x8000 + i * 0x100
            items += [
                _jsr(base, 0x9000),
                _string(base + 3, b"Hello"),
                _byte(base + 8, _VALID_RESUME_CODE),
            ]
        candidates = find_hook_candidates(items)
        assert candidates[0].hook_kind == "stringhi"
        assert candidates[0].hook_function == "stringhi_hook"

    def test_stringhi_beats_cr_when_next_byte_has_bit7(self) -> None:
        # Printed text ends with CR but the *next* byte has bit 7 —
        # this is stringhi, not stringcr. The CR is part of the
        # printed message; the structural terminator is the bit-7
        # opcode that follows.
        items = []
        for i in range(3):
            base = 0x8000 + i * 0x100
            items += [
                _jsr(base, 0x9000),
                _string(base + 3, b"Space\r"),
                _byte(base + 9, _VALID_RESUME_CODE),
            ]
        candidates = find_hook_candidates(items)
        assert candidates[0].hook_kind == "stringhi"

    def test_stringz_wins_over_bit7_next(self) -> None:
        # Even when the next byte has bit 7 set, an explicit null
        # in the string item is unambiguous: this is stringz.
        items = []
        for i in range(3):
            base = 0x8000 + i * 0x100
            items += [
                _jsr(base, 0x9000),
                _string(base + 3, b"Hi\x00"),
                _byte(base + 6, _VALID_RESUME_CODE),  # 0xA9 first
            ]
        candidates = find_hook_candidates(items)
        assert candidates[0].hook_kind == "stringz"

    def test_unknown(self) -> None:
        # No terminator we recognise: string ends in printable
        # ASCII and the next byte's bit 7 is clear.
        items = []
        for i in range(3):
            base = 0x8000 + i * 0x100
            items += [
                _jsr(base, 0x9000),
                _string(base + 3, b"Hello"),
                _byte(base + 8, _VALID_RESUME_CODE_NO_BIT7),
            ]
        candidates = find_hook_candidates(items)
        assert candidates[0].hook_kind == "unknown"
        assert candidates[0].hook_function is None


# --- detection thresholds ----------------------------------------


class TestDetectionThresholds:
    def test_below_min_call_sites_not_reported(self) -> None:
        # Only 2 matching call sites; default min_call_sites=2 keeps it.
        # Raise the threshold and the target drops.
        items = []
        for i in range(2):
            base = 0x8000 + i * 0x100
            items += [
                _jsr(base, 0x9000),
                _string(base + 3, b"Hi\x00"),
                _byte(base + 6, _VALID_RESUME_CODE),
            ]
        assert len(find_hook_candidates(items)) == 1
        assert find_hook_candidates(items, min_call_sites=3) == []

    def test_below_min_confidence_not_reported(self) -> None:
        # 2 matching + 2 non-matching call sites → confidence 0.5.
        items = []
        for i in range(2):
            base = 0x8000 + i * 0x100
            items += [
                _jsr(base, 0x9000),
                _string(base + 3, b"Hi\x00"),
                _byte(base + 6, _VALID_RESUME_CODE),
            ]
        # 2 calls without the signature.
        items += [_jsr(0x8800, 0x9000), _code(0x8803, [0x60], "rts")]
        items += [_jsr(0x8900, 0x9000), _code(0x8903, [0x60], "rts")]

        # Default min_confidence=0.5 still shows it.
        cands = find_hook_candidates(items)
        assert len(cands) == 1
        assert cands[0].confidence == pytest.approx(0.5)

        # min_confidence=0.7 drops it.
        assert find_hook_candidates(items, min_confidence=0.7) == []

    def test_resume_code_must_decode_as_6502(self) -> None:
        # The resume bytes here include 0x02 (KIL/JAM, length 0 in the
        # NMOS table), so the byte run doesn't decode as code from
        # offset 0 → no candidate.
        items = []
        for i in range(3):
            base = 0x8000 + i * 0x100
            items += [
                _jsr(base, 0x9000),
                _string(base + 3, b"Hi\r"),
                _byte(base + 6, [0x02, 0x02, 0x02, 0x02]),
            ]
        assert find_hook_candidates(items) == []

    def test_resume_code_below_min_bytes(self) -> None:
        # Only 2 bytes of valid 6502 code; default min_resume=4 rejects.
        items = []
        for i in range(3):
            base = 0x8000 + i * 0x100
            items += [
                _jsr(base, 0x9000),
                _string(base + 3, b"Hi\r"),
                _byte(base + 6, [0xA9, 0x00]),     # LDA #imm — only 2 bytes
            ]
        assert find_hook_candidates(items) == []
        # Lowering min_resume_code_bytes resurrects the match.
        cands = find_hook_candidates(items, min_resume_code_bytes=2)
        assert len(cands) == 1


# --- already-hooked targets are silent ---------------------------


class TestAlreadyHooked:
    def test_string_then_code_is_not_a_candidate(self) -> None:
        # A correctly-hooked print-inline helper has post-call items
        # (string -> code), not (string -> byte). The detector must
        # not flag it.
        items = []
        for i in range(5):
            base = 0x8000 + i * 0x100
            items += [
                _jsr(base, 0x9000),
                _string(base + 3, b"Hello\r"),
                _code(base + 9, [0xA9, 0x00], "lda"),
            ]
        assert find_hook_candidates(items) == []


# --- target label propagation ------------------------------------


class TestTargetLabel:
    def test_label_picked_up_from_call_site(self) -> None:
        items = [
            _jsr(0x8000, 0x9000, target_label="print_inline"),
            _string(0x8003, b"Hi\r"),
            _byte(0x8006, _VALID_RESUME_CODE),
            _jsr(0x8100, 0x9000, target_label="print_inline"),
            _string(0x8103, b"Yo\r"),
            _byte(0x8106, _VALID_RESUME_CODE),
        ]
        cands = find_hook_candidates(items)
        assert cands[0].target_label == "print_inline"


# --- sample-string snapshot --------------------------------------


class TestSampleStrings:
    def test_distinct_samples_collected(self) -> None:
        items = [
            _jsr(0x8000, 0x9000),
            _string(0x8003, b"first\r", text="first\r"),
            _byte(0x8009, _VALID_RESUME_CODE),
            _jsr(0x8100, 0x9000),
            _string(0x8103, b"second\r", text="second\r"),
            _byte(0x810A, _VALID_RESUME_CODE),
            _jsr(0x8200, 0x9000),
            _string(0x8203, b"third\r", text="third\r"),
            _byte(0x820A, _VALID_RESUME_CODE),
        ]
        cands = find_hook_candidates(items)
        assert cands[0].sample_strings == ("first\r", "second\r", "third\r")

    def test_samples_capped_at_three(self) -> None:
        items = []
        for i, txt in enumerate(("a", "b", "c", "d", "e")):
            base = 0x8000 + i * 0x100
            text = txt + "\r"
            items += [
                _jsr(base, 0x9000),
                _string(base + 3, text.encode("ascii"), text=text),
                _byte(base + 3 + len(text), _VALID_RESUME_CODE),
            ]
        cands = find_hook_candidates(items)
        assert len(cands[0].sample_strings) == 3


# --- HookCandidate properties ------------------------------------


class TestHookCandidateProperties:
    def test_confidence_zero_when_no_calls(self) -> None:
        c = HookCandidate(
            target=0x9000, target_label=None,
            matching_call_sites=(), total_call_sites=0,
            hook_kind="stringcr", sample_strings=(),
        )
        assert c.confidence == 0.0

    def test_confidence_one(self) -> None:
        c = HookCandidate(
            target=0x9000, target_label=None,
            matching_call_sites=(0x8000, 0x8100, 0x8200),
            total_call_sites=3,
            hook_kind="stringcr", sample_strings=(),
        )
        assert c.confidence == 1.0

    def test_hook_function_lookup(self) -> None:
        for kind, expected in [
            ("stringz", "stringz_hook"),
            ("stringcr", "stringcr_hook"),
            ("stringhi", "stringhi_hook"),
            ("unknown", None),
        ]:
            c = HookCandidate(
                target=0, target_label=None,
                matching_call_sites=(), total_call_sites=0,
                hook_kind=kind, sample_strings=(),
            )
            assert c.hook_function == expected


# --- paste-line rendering ----------------------------------------


class TestRenderHookSubroutineLine:
    def test_named_target(self) -> None:
        c = HookCandidate(
            target=0x928A,
            target_label="print_inline_no_spool",
            matching_call_sites=(0x8000, 0x8100, 0x8200),
            total_call_sites=3,
            hook_kind="stringcr",
            sample_strings=(),
        )
        line = render_hook_subroutine_line(c)
        assert 'hook_subroutine(0x928A, "print_inline_no_spool", stringcr_hook)' in line
        assert "3 sites" in line
        assert "conf=1.00" in line

    def test_unnamed_target_uses_placeholder(self) -> None:
        c = HookCandidate(
            target=0x928A, target_label=None,
            matching_call_sites=(0x8000,) * 4, total_call_sites=4,
            hook_kind="stringcr", sample_strings=(),
        )
        line = render_hook_subroutine_line(c)
        assert "FILL_ME" in line

    def test_unknown_kind_emits_hook_fn_placeholder(self) -> None:
        c = HookCandidate(
            target=0x928A, target_label="my_helper",
            matching_call_sites=(0x8000,) * 3, total_call_sites=3,
            hook_kind="unknown", sample_strings=(),
        )
        line = render_hook_subroutine_line(c)
        assert "<HOOK_FN>" in line
        assert "kind=unknown" in line


# --- input validation --------------------------------------------


class TestValidation:
    def test_min_call_sites_must_be_positive(self) -> None:
        with pytest.raises(ValueError, match="min_call_sites"):
            find_hook_candidates([], min_call_sites=0)

    def test_min_confidence_in_range(self) -> None:
        with pytest.raises(ValueError, match="min_confidence"):
            find_hook_candidates([], min_confidence=1.5)
