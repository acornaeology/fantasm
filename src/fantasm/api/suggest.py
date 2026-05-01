"""Pattern-based comment suggestions for uncommented instructions.

Two layers of heuristics:

- **Instruction patterns** — generic 6502 facts. ``PHA`` always means
  "Save A on stack"; ``CLC`` means "Clear carry"; etc. These don't
  vary per project and ship as :data:`DEFAULT_INSTRUCTION_HINTS`.

- **Workspace label hints** — project-specific. Maps from a label
  substring (e.g. ``"wksp_ch_flags"``) to a human description (e.g.
  ``"channel flags"``). When an instruction's operand contains a
  matching label, the suggestion combines the mnemonic and the hint
  (``"Get channel flags"``, ``"Store in channel flags"``, etc.).
  Defaults to empty — users supply their project's hints via
  ``fantasm.toml`` or CLI arguments.

Sibling ADFS ``tools/suggest_comments.py`` was the model. The
fantasm port lifts the heuristics into pure helpers and parameterises
the workspace hints so any project can adopt the workflow.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass


# Generic 6502 mnemonics whose meaning is the same across projects.
# A value of ``None`` means "no suggestion needed" — the user typically
# doesn't need a comment to know what RTS does.
DEFAULT_INSTRUCTION_HINTS: dict[str, str | None] = {
    "rts": None,
    "rti": None,
    "brk": None,
    "nop": None,
    "pha": "Save A on stack",
    "pla": "Restore A from stack",
    "phx": "Save X on stack",
    "plx": "Restore X from stack",
    "phy": "Save Y on stack",
    "ply": "Restore Y from stack",
    "php": "Save processor flags",
    "plp": "Restore processor flags",
    "tax": "Transfer A to X",
    "tay": "Transfer A to Y",
    "txa": "Transfer X to A",
    "tya": "Transfer Y to A",
    "tsx": "Transfer SP to X",
    "txs": "Transfer X to SP",
    "clc": "Clear carry",
    "sec": "Set carry",
    "cld": "Clear decimal mode",
    "sed": "Set decimal mode",
    "clv": "Clear overflow",
    "cli": "Enable interrupts",
    "sei": "Disable interrupts",
}


# Mnemonic → format-string template for combining with a workspace
# hint. Each template gets the hint substituted with ``%s``.
_LOAD_STORE_TEMPLATES: dict[str, str] = {
    "lda": "Get %s",
    "sta": "Store in %s",
    "cmp": "Compare with %s",
    "ldx": "X = %s",
    "ldy": "Y = %s",
    "inc": "Increment %s",
    "dec": "Decrement %s",
    "ora": "Modify %s",
    "and": "Modify %s",
    "eor": "Modify %s",
    "adc": "Add to %s",
    "sbc": "Subtract from %s",
    "bit": "Test %s",
}


@dataclass(frozen=True)
class CommentSuggestion:
    """One suggested comment for an instruction."""

    addr: int
    text: str


def suggest_for_instruction(
    item: dict,
    *,
    label_hints: Mapping[str, str] = {},
    declared_subs: set[int] = frozenset(),
    instruction_hints: Mapping[str, str | None] | None = None,
) -> str | None:
    """Generate a comment suggestion for a single code item.

    Logic order:

    1. JSR / JMP to a target in ``declared_subs`` returns ``None`` —
       py8dis already emits the subroutine's title.
    2. If the item's operand contains any key from ``label_hints``,
       and the mnemonic has a load/store template, returns the
       templated suggestion (``"Get channel flags"``, etc.).
    3. Falls back to ``instruction_hints`` (default
       :data:`DEFAULT_INSTRUCTION_HINTS`).
    4. Returns ``None`` if nothing matches.
    """
    mnemonic = item.get("mnemonic", "")
    operand = item.get("operand", "")
    target = item.get("target")
    hints = (
        instruction_hints
        if instruction_hints is not None
        else DEFAULT_INSTRUCTION_HINTS
    )

    if mnemonic in ("jsr", "jmp") and target in declared_subs:
        return None

    if label_hints:
        for label_substring, description in label_hints.items():
            if label_substring in operand:
                template = _LOAD_STORE_TEMPLATES.get(mnemonic)
                if template is not None:
                    return template % description
                break  # don't fall through if a label matched but mnemonic didn't

    if mnemonic in hints:
        return hints[mnemonic]

    return None


def suggest_comments(
    items: Iterable[dict],
    *,
    label_hints: Mapping[str, str] = {},
    declared_subs: set[int] = frozenset(),
    instruction_hints: Mapping[str, str | None] | None = None,
    address_range: tuple[int, int] | None = None,
) -> list[CommentSuggestion]:
    """Generate suggestions for every uncommented code item.

    Skips non-code items, items already carrying ``comment_inline``,
    and items where :func:`suggest_for_instruction` returns ``None``.
    With ``address_range = (start, end)``, restricts to items in
    ``[start, end)``.
    """
    results: list[CommentSuggestion] = []
    for item in items:
        if item.get("type") != "code":
            continue
        if item.get("comment_inline"):
            continue
        if address_range is not None:
            if not (address_range[0] <= item["addr"] < address_range[1]):
                continue
        suggestion = suggest_for_instruction(
            item,
            label_hints=label_hints,
            declared_subs=declared_subs,
            instruction_hints=instruction_hints,
        )
        if suggestion is not None:
            results.append(
                CommentSuggestion(addr=item["addr"], text=suggestion)
            )
    return results


__all__ = [
    "CommentSuggestion",
    "DEFAULT_INSTRUCTION_HINTS",
    "suggest_comments",
    "suggest_for_instruction",
]
