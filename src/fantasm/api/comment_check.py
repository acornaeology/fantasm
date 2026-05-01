"""Mechanical comment-vs-code consistency checks.

Runs checks on a disassembly's JSON output to find inline and block
comments that contradict the instruction or surroundings. Each check
returns ``None`` (no finding) or a list of finding dicts, each tagged
with one of two confidence levels:

- ``HIGH``: the comment almost certainly disagrees with the code.
- ``MEDIUM``: flagged for human review.

Sibling ``disasm_tools.comment_check`` was byte-identical across all
four forks at 677 lines. This port lifts the pure-logic surface
(constants, individual check functions, :func:`run_checks`) into
fantasm. The presentational ``format_findings()`` and the top-level
``comment_check()`` entry are deferred until CLI integration.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Iterable, Sequence
from pathlib import Path
from typing import Any


# Tube register addresses (BBC Tube interface).
TUBE_REGISTERS: dict[int, str] = {
    0xFEE0: "R1", 0xFEE1: "R1",
    0xFEE2: "R2", 0xFEE3: "R2",
    0xFEE4: "R3", 0xFEE5: "R3",
    0xFEE6: "R4", 0xFEE7: "R4",
}

# ADLC control register addresses.
CR_ADDRESSES: dict[int, str] = {0xFEA0: "CR1", 0xFEA1: "CR2"}

# Mnemonics that load/modify a register with an immediate operand.
# CMP/CPX/CPY excluded: their comments typically describe what values
# are being compared rather than claiming the operand value.
IMM_REG_MNEMONICS: dict[str, str] = {
    "lda": "A", "ldx": "X", "ldy": "Y",
    "and": "A", "ora": "A", "eor": "A",
    "adc": "A", "sbc": "A",
}

BRANCH_MNEMONICS: frozenset[str] = frozenset(
    {"bcc", "bcs", "beq", "bne", "bmi", "bpl", "bvc", "bvs"}
)


def parse_imm_value(operand: str) -> int | None:
    """Parse an immediate operand like ``#&1C`` or ``#42``. Returns int or None."""
    if not operand or not operand.startswith("#"):
        return None
    val_str = operand[1:]
    if val_str.startswith("&") or val_str.startswith("$"):
        try:
            return int(val_str[1:], 16)
        except ValueError:
            return None
    try:
        return int(val_str)
    except ValueError:
        return None


def check_reg_value(item: dict, _context: dict) -> list[dict] | None:
    """Comment claims A=/X=/Y= with a value not matching the instruction.

    HIGH confidence.
    """
    comment = item.get("comment_inline", "")
    mnemonic = item.get("mnemonic", "")
    operand = item.get("operand", "")

    if mnemonic not in IMM_REG_MNEMONICS:
        return None
    imm_val = parse_imm_value(operand)
    if imm_val is None:
        return None

    expected_reg = IMM_REG_MNEMONICS[mnemonic]
    findings: list[dict] = []

    for m in re.finditer(r"\b([AXY])=&([0-9A-Fa-f]+)\b", comment):
        reg, hex_val = m.group(1), m.group(2)
        claimed_val = int(hex_val, 16)
        if reg == expected_reg and claimed_val != imm_val:
            findings.append({
                "check": "reg_value",
                "confidence": "HIGH",
                "addr": item["addr"],
                "message": f"Comment says {reg}=&{claimed_val:02X} but instruction is {mnemonic.upper()} {operand}",
            })
        elif reg != expected_reg:
            findings.append({
                "check": "reg_value",
                "confidence": "HIGH",
                "addr": item["addr"],
                "message": f"Comment says {reg}=&{int(hex_val, 16):02X} but instruction is {mnemonic.upper()} {operand} (sets {expected_reg}, not {reg})",
            })

    for m in re.finditer(r"\b([AXY])=(\d+)\b", comment):
        reg, dec_val = m.group(1), int(m.group(2))
        if reg == expected_reg and dec_val != imm_val:
            findings.append({
                "check": "reg_value",
                "confidence": "HIGH",
                "addr": item["addr"],
                "message": f"Comment says {reg}={dec_val} but instruction is {mnemonic.upper()} {operand}",
            })
        elif reg != expected_reg:
            findings.append({
                "check": "reg_value",
                "confidence": "HIGH",
                "addr": item["addr"],
                "message": f"Comment says {reg}={dec_val} but instruction is {mnemonic.upper()} {operand} (sets {expected_reg}, not {reg})",
            })

    return findings if findings else None


def check_branch_target(item: dict, _context: dict) -> list[dict] | None:
    """Comment explicitly claims a different branch/jump target.

    Only fires when phrasing indicates the hex address IS the target
    ("branch to &XXXX", "via &XXXX", etc.). HIGH confidence.
    """
    comment = item.get("comment_inline", "")
    mnemonic = item.get("mnemonic", "")
    target = item.get("target")

    if mnemonic not in BRANCH_MNEMONICS and mnemonic not in ("jmp", "jsr"):
        return None
    if target is None:
        return None

    target_claim_patterns = [
        r"(?:branch|jump|jsr|jmp|goto|go\s+to)\s+(?:to\s+)?&([0-9A-Fa-f]{4})\b",
        r"via\s+&([0-9A-Fa-f]{4})\b",
        r"=\s*(?:JSR|JMP|BNE|BEQ|BCC|BCS|BMI|BPL|BVC|BVS)\s+&([0-9A-Fa-f]{4})\b",
        r"(?:exit|return)\s+(?:at|via)\s+&([0-9A-Fa-f]{4})\b",
    ]

    findings: list[dict] = []
    for pattern in target_claim_patterns:
        for m in re.finditer(pattern, comment, re.IGNORECASE):
            claimed = int(m.group(1), 16)
            if claimed != target:
                findings.append({
                    "check": "branch_target",
                    "confidence": "HIGH",
                    "addr": item["addr"],
                    "message": f"Comment claims target &{claimed:04X} but {mnemonic.upper()} target is &{target:04X}",
                })

    return findings if findings else None


def check_cr_value(item: dict, context: dict) -> list[dict] | None:
    """Comment says CR1=&XX / CR2=&XX but preceding LDA loaded a different value.

    HIGH confidence.
    """
    comment = item.get("comment_inline", "")
    mnemonic = item.get("mnemonic", "")
    target = item.get("target")

    if mnemonic != "sta" or target not in CR_ADDRESSES:
        return None

    cr_name = CR_ADDRESSES[target]
    findings: list[dict] = []

    for m in re.finditer(r"\b(CR[12])=&([0-9A-Fa-f]+)\b", comment):
        claimed_cr, hex_val = m.group(1), m.group(2)
        claimed_val = int(hex_val, 16)
        if claimed_cr != cr_name:
            findings.append({
                "check": "cr_value",
                "confidence": "HIGH",
                "addr": item["addr"],
                "message": f"Comment says {claimed_cr}=&{claimed_val:02X} but STA target is {cr_name} (&{target:04X})",
            })
            continue

        prev_item = context.get("prev_item")
        if prev_item and prev_item.get("mnemonic") == "lda":
            prev_imm = parse_imm_value(prev_item.get("operand", ""))
            if prev_imm is not None and prev_imm != claimed_val:
                findings.append({
                    "check": "cr_value",
                    "confidence": "HIGH",
                    "addr": item["addr"],
                    "message": f"Comment says {cr_name}=&{claimed_val:02X} but preceding LDA loaded #&{prev_imm:02X}",
                })

    return findings if findings else None


def check_tube_register(item: dict, _context: dict) -> list[dict] | None:
    """Comment claims a Tube register access that doesn't match the operand.

    MEDIUM confidence.
    """
    comment = item.get("comment_inline", "")
    target = item.get("target")

    if target is None or not (0xFEE0 <= target <= 0xFEE7):
        return None

    actual_reg = TUBE_REGISTERS[target]
    access_patterns = [
        r"(?:read|write|send|receive|poll|check|BIT|LDA|STA|load|store)\s+R([1-4])\b",
        r"\bR([1-4])\s+(?:status|data|register)\b",
        r"(?:via|from|to)\s+R([1-4])\b",
    ]

    findings: list[dict] = []
    for pattern in access_patterns:
        for m in re.finditer(pattern, comment, re.IGNORECASE):
            claimed_reg = f"R{m.group(1)}"
            if claimed_reg != actual_reg:
                findings.append({
                    "check": "tube_register",
                    "confidence": "MEDIUM",
                    "addr": item["addr"],
                    "message": f"Comment claims {claimed_reg} access but operand targets {actual_reg} (&{target:04X})",
                })

    return findings if findings else None


def find_stale_addrs(text: str, known_addrs: set[int]) -> list[int]:
    """Find ``&XXXX`` hex addresses in ``text`` not in ``known_addrs``."""
    stale: list[int] = []
    for m in re.finditer(r"&([0-9A-Fa-f]{4})\b", text):
        addr_val = int(m.group(1), 16)
        if addr_val not in known_addrs:
            stale.append(addr_val)
    return stale


def check_stale_addr(item: dict, context: dict) -> list[dict] | None:
    """Comment contains an ``&XXXX`` not in the version's address space.

    MEDIUM confidence.
    """
    comment = item.get("comment_inline", "")
    findings: list[dict] = []
    for addr_val in find_stale_addrs(comment, context["known_addrs"]):
        findings.append({
            "check": "stale_addr",
            "confidence": "MEDIUM",
            "addr": item["addr"],
            "message": f"Comment contains &{addr_val:04X} which is not a known address in this version",
        })
    return findings if findings else None


# Per-item checks, in order.
ALL_CHECKS: tuple[Callable[[dict, dict], list[dict] | None], ...] = (
    check_reg_value,
    check_branch_target,
    check_cr_value,
    check_tube_register,
    check_stale_addr,
)


_REFERENCE_LINE_RE = re.compile(
    r"^&[0-9A-Fa-f]+ referenced \d+ times? by "
)


def check_desc_stale_addr(sub: dict, known_addrs: set[int]) -> list[dict]:
    """Subroutine description / title / on_entry / on_exit contains stale ``&XXXX``."""
    findings: list[dict] = []
    addr = sub["addr"]

    for field in ("description", "title"):
        for stale in find_stale_addrs(sub.get(field, ""), known_addrs):
            findings.append({
                "check": "desc_stale_addr",
                "confidence": "MEDIUM",
                "addr": addr,
                "message": f"Description contains &{stale:04X} which is not a known address in this version",
            })

    for field in ("on_entry", "on_exit"):
        obj = sub.get(field)
        if isinstance(obj, dict):
            for _reg, text in obj.items():
                for stale in find_stale_addrs(str(text), known_addrs):
                    findings.append({
                        "check": "desc_stale_addr",
                        "confidence": "MEDIUM",
                        "addr": addr,
                        "message": f"Description {field} contains &{stale:04X} which is not a known address in this version",
                    })

    return findings


def check_block_stale_addr(
    item: dict, known_addrs: set[int], seen: set[tuple[int, int]]
) -> list[dict]:
    """``comments_before`` contains stale ``&XXXX`` addresses.

    Excludes py8dis-generated reference lines and ``*****`` separators.
    Skips ``(item_addr, stale)`` pairs already in ``seen`` to avoid
    duplicating findings already produced for descriptions.
    """
    comments = item.get("comments_before", [])
    if not comments:
        return []

    findings: list[dict] = []
    addr = item["addr"]

    for comment in comments:
        if comment.startswith("*****") or _REFERENCE_LINE_RE.match(comment):
            continue
        for stale in find_stale_addrs(comment, known_addrs):
            if (addr, stale) in seen:
                continue
            findings.append({
                "check": "block_stale_addr",
                "confidence": "MEDIUM",
                "addr": addr,
                "message": f"Block comment contains &{stale:04X} which is not a known address in this version",
            })

    return findings


_CHAIN_MNEMONICS = frozenset({"iny", "inx", "dey", "dex"})

_ENUM_PATTERN = re.compile(
    r"(?:Add|Subtract)\s+\d+\s+\(of\s+\d+\)", re.IGNORECASE
)

_BARE_MNEMONIC_RE = re.compile(
    r"^(?:INY|INX|DEY|DEX)(?:\s*\(.*entry\))?$", re.IGNORECASE
)


def find_chains(sorted_items: Sequence[dict]) -> list[list[dict]]:
    """Find chains of 2+ consecutive same-mnemonic increment/decrement ops."""
    chains: list[list[dict]] = []
    i = 0
    while i < len(sorted_items):
        item = sorted_items[i]
        mnem = item.get("mnemonic", "")
        if mnem in _CHAIN_MNEMONICS:
            chain = [item]
            j = i + 1
            while (
                j < len(sorted_items)
                and sorted_items[j].get("mnemonic") == mnem
                and sorted_items[j]["addr"] == chain[-1]["addr"] + 1
            ):
                chain.append(sorted_items[j])
                j += 1
            if len(chain) >= 2:
                chains.append(chain)
            i = j
        else:
            i += 1
    return chains


def check_chain_comments(
    sorted_items: Sequence[dict],
    sub_range: tuple[int, int | None] | None = None,
) -> list[dict]:
    """Increment/decrement chains use consistent comment style.

    For chains of 3+ instructions, each segment-first instruction
    (entry point) should describe the cumulative effect, and
    non-first instructions should say ``(continued)``. Enumeration
    comments like ``Add 1 (of 5)`` are flagged. Chains of exactly 2
    are skipped. MEDIUM confidence.
    """
    findings: list[dict] = []

    for chain in find_chains(sorted_items):
        if sub_range:
            if chain[0]["addr"] < sub_range[0]:
                continue
            if sub_range[1] is not None and chain[0]["addr"] >= sub_range[1]:
                continue

        if len(chain) <= 2:
            continue

        segment_starts: set[int] = {0}
        for ci, item in enumerate(chain):
            if ci == 0:
                continue
            if item.get("references") or item.get("labels") or item.get("sub_labels"):
                segment_starts.add(ci)

        for ci, item in enumerate(chain):
            comment = item.get("comment_inline", "")
            addr = item["addr"]
            if ci in segment_starts:
                if _BARE_MNEMONIC_RE.match(comment):
                    findings.append({
                        "check": "chain_comment",
                        "confidence": "MEDIUM",
                        "addr": addr,
                        "message": f"Chain entry comment \"{comment}\" just restates mnemonic; should describe cumulative effect",
                    })
                if _ENUM_PATTERN.search(comment):
                    findings.append({
                        "check": "chain_comment",
                        "confidence": "MEDIUM",
                        "addr": addr,
                        "message": f"Chain entry has enumeration comment \"{comment}\"; should describe cumulative effect",
                    })
            else:
                if comment and not comment.startswith("(continued)"):
                    findings.append({
                        "check": "chain_comment",
                        "confidence": "MEDIUM",
                        "addr": addr,
                        "message": f"Mid-chain comment \"{comment}\" should be \"(continued)\"",
                    })

    return findings


def build_known_addrs(data: dict) -> set[int]:
    """Build the set of all addresses considered "known" for stale-addr checks.

    Combines item addresses, subroutine addresses, external labels,
    and constants, plus the conventional BBC zero page / OS workspace
    / hardware ranges that don't appear in disassembly output.

    These ranges are currently hardcoded to the BBC Acorn family
    (sibling forks were byte-identical here). A future fantasm.toml
    schema may make them per-project configurable.
    """
    known: set[int] = set()
    for item in data["items"]:
        known.add(item["addr"])
    for sub in data.get("subroutines", []):
        known.add(sub["addr"])
    for _name, addr in data.get("external_labels", {}).items():
        known.add(addr)
    for const in data.get("constants", []):
        known.add(const["value"])
    # Zero page, stack, OS workspace, vectors.
    known.update(range(0x0000, 0x0400))
    # Relocated code pages.
    known.update(range(0x0400, 0x0800))
    # NFS-style workspace pages 0x0D-0x10.
    known.update(range(0x0D00, 0x1100))
    # SHEILA, Tube, FRED, JIM, MOS.
    known.update(range(0xFC00, 0x10000))
    return known


def run_checks(data: dict, sub_target: str | None = None) -> list[dict]:
    """Run every check against ``data`` and return a flat list of findings.

    ``sub_target``, if given, restricts checks to the subroutine
    starting at that hex address. Raises :class:`ValueError` for an
    invalid address (was a stderr print + early-return in the sibling
    code).
    """
    items = data["items"]
    items_by_addr = {item["addr"]: item for item in items}
    sorted_items = sorted(items, key=lambda i: i["addr"])

    known_addrs = build_known_addrs(data)

    sub_range: tuple[int, int | None] | None = None
    if sub_target:
        addr_str = sub_target.strip().lstrip("$&").removeprefix("0x")
        try:
            target_addr = int(addr_str, 16)
        except ValueError as exc:
            raise ValueError(f"invalid address {sub_target!r}") from exc

        rom_subs = sorted(
            [s for s in data.get("subroutines", []) if s["addr"] < 0xFF00],
            key=lambda s: s["addr"],
        )
        end: int | None = None
        for s in rom_subs:
            if s["addr"] > target_addr:
                end = s["addr"]
                break
        sub_range = (target_addr, end)

    findings: list[dict] = []
    prev_item: dict | None = None

    for item in sorted_items:
        if item.get("type") != "code":
            prev_item = item
            continue
        if not item.get("comment_inline"):
            prev_item = item
            continue
        if sub_range:
            if item["addr"] < sub_range[0]:
                prev_item = item
                continue
            if sub_range[1] is not None and item["addr"] >= sub_range[1]:
                break

        context = {
            "prev_item": prev_item,
            "known_addrs": known_addrs,
            "items_by_addr": items_by_addr,
        }

        for check_fn in ALL_CHECKS:
            result = check_fn(item, context)
            if result:
                if isinstance(result, list):
                    findings.extend(result)
                else:
                    findings.append(result)

        prev_item = item

    desc_seen: set[tuple[int, int]] = set()
    for sub in data.get("subroutines", []):
        if sub_range:
            if sub["addr"] < sub_range[0]:
                continue
            if sub_range[1] is not None and sub["addr"] >= sub_range[1]:
                continue
        findings.extend(check_desc_stale_addr(sub, known_addrs))
        for field in ("description", "title"):
            for stale in find_stale_addrs(sub.get(field, ""), known_addrs):
                desc_seen.add((sub["addr"], stale))

    for item in sorted_items:
        if sub_range:
            if item["addr"] < sub_range[0]:
                continue
            if sub_range[1] is not None and item["addr"] >= sub_range[1]:
                break
        findings.extend(check_block_stale_addr(item, known_addrs, desc_seen))

    findings.extend(check_chain_comments(sorted_items, sub_range=sub_range))

    return findings


__all__ = [
    "ALL_CHECKS",
    "BRANCH_MNEMONICS",
    "CR_ADDRESSES",
    "IMM_REG_MNEMONICS",
    "TUBE_REGISTERS",
    "build_known_addrs",
    "check_block_stale_addr",
    "check_branch_target",
    "check_chain_comments",
    "check_cr_value",
    "check_desc_stale_addr",
    "check_reg_value",
    "check_stale_addr",
    "check_tube_register",
    "find_chains",
    "find_stale_addrs",
    "parse_imm_value",
    "run_checks",
]
