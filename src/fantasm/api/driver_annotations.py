"""Parse annotation calls out of disassembly driver scripts.

Driver scripts annotate a binary with ``comment``, ``label`` and
``subroutine`` calls. Two dialects are in use:

- **py8dis** calls them as bare functions, flagging inline comments
  with ``inline=True``::

      comment(0x8430, "Transfer to X", inline=True)
      subroutine(0x8430, "name", hook=None)

- **dasmos** calls them as methods on a ``Disassembler`` (any
  receiver name is accepted), with comment placement given by an
  ``Align`` enum. Long calls are typically split one argument per
  line::

      d.comment(0x8430, "Transfer to X", align=Align.INLINE)
      d.subroutine(
          0x8430,
          "name",
          title="...",
      )

Rather than matching either surface syntax with regular expressions,
the script is parsed with :mod:`ast` and every call to one of the
three annotation functions is inspected. An annotation is reported
only when its address argument is a literal integer (or a constant
``+``/``-`` expression of literals, such as ``0x8000 + 3``); calls
whose address is computed at run time — typically inside a loop
over a table — are skipped, as no static tool can place them.
"""

from __future__ import annotations

import ast
import operator
from dataclasses import dataclass

ANNOTATION_KINDS = ("comment", "label", "subroutine")


class DriverParseError(ValueError):
    """The driver script is not valid Python and can't be parsed."""


@dataclass(frozen=True)
class DriverAnnotation:
    """One annotation call found in a driver script.

    ``name`` is the label or subroutine name, ``text`` the comment
    text; each is ``None`` when absent or not a string literal.
    ``inline`` is only meaningful for comments. ``is_entry_point``
    is only meaningful for subroutines. ``source`` holds the exact
    source lines spanned by the call (lines ``line_number`` to
    ``end_line_number`` inclusive, 1-based).
    """

    kind: str
    address: int
    line_number: int
    end_line_number: int
    name: str | None
    text: str | None
    inline: bool
    is_entry_point: bool
    source: str


_BINARY_OPERATORS = {ast.Add: operator.add, ast.Sub: operator.sub}


def _constant_int(node: ast.expr) -> int | None:
    """Evaluate ``node`` as a literal integer expression, else ``None``."""
    if isinstance(node, ast.Constant):
        value = node.value
        if isinstance(value, int) and not isinstance(value, bool):
            return value
        return None
    if isinstance(node, ast.BinOp) and type(node.op) in _BINARY_OPERATORS:
        left = _constant_int(node.left)
        right = _constant_int(node.right)
        if left is None or right is None:
            return None
        return _BINARY_OPERATORS[type(node.op)](left, right)
    return None


def _constant_str(node: ast.expr | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _call_kind(call: ast.Call) -> str | None:
    """Return the annotation kind a call invokes, or ``None``."""
    func = call.func
    if isinstance(func, ast.Name) and func.id in ANNOTATION_KINDS:
        return func.id
    if (
        isinstance(func, ast.Attribute)
        and func.attr in ANNOTATION_KINDS
        and isinstance(func.value, ast.Name)
    ):
        return func.attr
    return None


def _is_inline(keywords: dict[str, ast.expr]) -> bool:
    """True for ``inline=True`` (py8dis) or ``align=Align.INLINE`` (dasmos)."""
    inline = keywords.get("inline")
    if isinstance(inline, ast.Constant) and inline.value is True:
        return True
    align = keywords.get("align")
    if isinstance(align, ast.Attribute):
        return align.attr == "INLINE"
    if isinstance(align, ast.Name):
        return align.id == "INLINE"
    if isinstance(align, ast.Constant) and isinstance(align.value, str):
        return align.value.lower() == "inline"
    return False


def parse_driver_annotations(driver_text: str) -> list[DriverAnnotation]:
    """Return every literal-addressed annotation call in ``driver_text``.

    Results are in source order. Raises :class:`DriverParseError`
    when the script has a syntax error.
    """
    try:
        module = ast.parse(driver_text)
    except SyntaxError as exc:
        raise DriverParseError(
            f"driver script is not valid Python (line {exc.lineno}): {exc.msg}"
        ) from exc

    lines = driver_text.splitlines()
    found: list[tuple[int, int, DriverAnnotation]] = []

    for node in ast.walk(module):
        if not isinstance(node, ast.Call):
            continue
        kind = _call_kind(node)
        if kind is None:
            continue
        keywords = {kw.arg: kw.value for kw in node.keywords if kw.arg}
        address_node = node.args[0] if node.args else keywords.get("runtime_addr")
        if address_node is None:
            continue
        address = _constant_int(address_node)
        if address is None:
            continue

        second_node = node.args[1] if len(node.args) > 1 else None
        name: str | None = None
        text: str | None = None
        if kind == "comment":
            text = _constant_str(second_node or keywords.get("text"))
        else:
            name = _constant_str(second_node or keywords.get("name"))

        entry_point_node = keywords.get("is_entry_point")
        is_entry_point = not (
            isinstance(entry_point_node, ast.Constant)
            and entry_point_node.value is False
        )

        end_line_number = node.end_lineno or node.lineno
        found.append((
            node.lineno,
            node.col_offset,
            DriverAnnotation(
                kind=kind,
                address=address,
                line_number=node.lineno,
                end_line_number=end_line_number,
                name=name,
                text=text,
                inline=kind == "comment" and _is_inline(keywords),
                is_entry_point=is_entry_point,
                source="\n".join(lines[node.lineno - 1:end_line_number]),
            ),
        ))

    found.sort(key=lambda entry: entry[:2])
    return [annotation for _, _, annotation in found]


__all__ = [
    "ANNOTATION_KINDS",
    "DriverAnnotation",
    "DriverParseError",
    "parse_driver_annotations",
]
