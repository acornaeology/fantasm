"""Sort top-level annotation calls in dasmos / py8dis driver scripts by address.

A driver script is a Python file that drives a tracing
disassembler library through annotation calls — ``d.label(0x9000,
"foo")``, ``d.comment(0xA000, "...")``, etc. As these files grow
they tend to drift out of address order, so reading the file
top-to-bottom doesn't follow the address space. This module
rewrites the file so the output is the unique address-ordered
permutation that satisfies the script's real ordering constraints.

The model is a partial-order topological sort. Each top-level
statement is a node; ordering constraints (Python execution
prerequisites, ``add_move`` translation requirements, the
``disassemble`` → render edge) are explicit edges. Where topology
leaves multiple statements free, the tie is broken by primary
address. The result is a single canonical ordering with no
per-anchor heuristics.

## Hard edges

- ``import`` / ``from`` / module-level assignments precede
  ``d = … Disassembler.create(…)``.
- ``d = … Disassembler.create(…)`` precedes every ``d.X(…)`` call.
- ``d.load(…)`` precedes every other ``d.X(…)`` call.
- ``d.add_move(dest, src, length)`` precedes every annotation
  whose primary address falls inside ``[dest, dest+length)`` or
  ``[src, src+length)``.
- Every annotation, setup, env, hook, hint, constant, and
  indented block precedes ``ir = d.disassemble()``.
- ``ir = d.disassemble()`` precedes every subsequent statement
  (renders, file IO, prints).

## Tiebreak (sort key for free choices)

- Setup (``import``, module assigns, ``Disassembler.create``,
  ``d.load``): ``-inf`` — topology pins them to the top.
- ``d.use_environment(…)``: ``-1`` — clusters ahead of the
  address-keyed run.
- ``d.add_move(dest, src, length)``: ``min(dest, src)``.
- ``d.hook_subroutine(addr, …)`` / ``d.format_hint(addr, …)``:
  ``addr``.
- ``d.constant(value, name)`` with literal int value: ``value``.
- ``d.label`` / ``comment`` / ``subroutine`` / ``banner`` /
  ``entry`` / ``byte`` / ``word`` / ``string`` / ``expr`` /
  ``expr_label`` / ``rts_code_ptr`` with literal first arg:
  the literal value.
- Indented block (``for`` / ``if`` / ``while`` / ``with`` /
  ``def``) with a derivable first-iteration address: that
  address.
- Indented block or unrecognised top-level call with no
  derivable address: a soft anchor — sort key inherited from
  the nearest preceding addressable statement.
- Render block (``ir = d.disassemble()`` and after): ``+inf``,
  again topology-pinned.
- Final tiebreak: original line number.

Indented blocks move as one atomic unit (header + body together).
The block's address is derived (in order of preference) from the
first literal int in the loop iterable, then from the first
literal-int positional arg of any sortable ``d.X(…)`` call in the
body. If neither yields a literal, the block becomes a soft
anchor — pinned to its source neighbourhood by edges to the
immediately surrounding statements — and the rest of the file
sorts around it.

## Byte-identity contract

Statement text is moved verbatim. We never re-emit numeric
literals, never reformat keyword args, never normalise quoting.
``ast.parse`` is used to *understand* structure; the original
source-text bytes are sliced by line range and concatenated in
the new order. Hex literals stay hex.
"""

from __future__ import annotations

import ast
import heapq
import math
from collections.abc import Sequence
from dataclasses import dataclass, field


# Annotation calls that take an address as their first positional
# argument and sort by that address. The receiver may be ``d.foo(…)``
# or bare ``foo(…)``; both forms appear depending on whether the
# driver is dasmos-style or py8dis-style.
SORTABLE_FUNCTIONS: frozenset[str] = frozenset({
    "label",
    "comment",
    "subroutine",
    "banner",
    "entry",
    "byte",
    "word",
    "string",
    "expr",
    "expr_label",
    "rts_code_ptr",
    "hook_subroutine",
    "format_hint",
})


# Vestigial set kept for back-compat with 0.12.0 callers. The
# topo-sort no longer uses a coarse "anchor" classification — every
# statement gets per-kind handling — but consumers of the public
# constant might still introspect it.
ANCHOR_FUNCTIONS: frozenset[str] = frozenset({"add_move"})


# Setup-call names that must precede every other ``d.`` call.
_SETUP_CALLS: frozenset[str] = frozenset({"load"})


# Sentinel sort keys.
_KEY_SETUP = -math.inf
_KEY_USE_ENVIRONMENT = -1
_KEY_RENDER = math.inf


@dataclass(frozen=True)
class Unit:
    """One source-level unit: leading filler + one statement + trailing filler.

    ``leading_lines`` and ``trailing_lines`` are blank or comment-only
    lines that travel with the statement when it moves. ``statement_lines``
    are the lines of one top-level Python statement (possibly multi-line
    or a whole indented block). ``kind`` describes the statement's
    role for the sort. ``address`` is the unit's primary sort
    address (``None`` for setup / render / soft-anchor units).
    ``original_index`` is the unit's position in the original file
    (stable-sort tiebreaker).
    """

    leading_lines: tuple[str, ...]
    statement_lines: tuple[str, ...]
    trailing_lines: tuple[str, ...]
    kind: str
    address: int | None
    original_index: int


@dataclass
class _Statement:
    """Internal: a classified top-level statement plus filler attachments."""

    kind: str
    sort_key: float
    address: int | None
    addr_ranges: tuple[tuple[int, int], ...]
    original_index: int
    leading_lines: list[str] = field(default_factory=list)
    statement_lines: list[str] = field(default_factory=list)
    trailing_lines: list[str] = field(default_factory=list)

    def to_unit(self) -> Unit:
        return Unit(
            leading_lines=tuple(self.leading_lines),
            statement_lines=tuple(self.statement_lines),
            trailing_lines=tuple(self.trailing_lines),
            kind=self.kind,
            address=self.address,
            original_index=self.original_index,
        )


# --- AST classification -------------------------------------------


def _call_name(node: ast.AST) -> str | None:
    """Return the function name of a call, stripping any single-level receiver.

    ``foo(…)`` → ``"foo"``; ``d.foo(…)`` → ``"foo"``;
    ``d.disassembler.foo(…)`` → ``"foo"``. Anything more exotic
    (call expressions as the callee) returns ``None``.
    """
    if isinstance(node, ast.Call):
        callee = node.func
        if isinstance(callee, ast.Name):
            return callee.id
        if isinstance(callee, ast.Attribute):
            return callee.attr
    return None


def _literal_int(node: ast.AST) -> int | None:
    """Return the integer value of ``node`` if it's a literal int (incl. ``-N``)."""
    if isinstance(node, ast.Constant) and isinstance(node.value, int) and not isinstance(node.value, bool):
        return node.value
    if isinstance(
        node, ast.UnaryOp
    ) and isinstance(node.op, ast.USub):
        inner = _literal_int(node.operand)
        if inner is not None:
            return -inner
    return None


def _first_literal_in_expr(node: ast.AST) -> int | None:
    """Find the first literal-int in a (possibly compound) expression.

    Handles ``0x1234``, ``-1``, ``0x1234 + i``, lists / tuples
    (``[0x100, 0x200]``), and ``range(START, STOP)``-style calls
    where the first arg is a literal int. Returns ``None`` when no
    literal can be recovered.
    """
    direct = _literal_int(node)
    if direct is not None:
        return direct
    if isinstance(node, ast.BinOp):
        left = _first_literal_in_expr(node.left)
        if left is not None:
            return left
        return _first_literal_in_expr(node.right)
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        for elt in node.elts:
            lit = _first_literal_in_expr(elt)
            if lit is not None:
                return lit
        return None
    if isinstance(node, ast.Call):
        # ``range(START, STOP)`` and ``range(START, STOP, STEP)`` —
        # the first arg is a real start address. ``range(N)`` is a
        # count, not an address; skip it. We don't peek into other
        # calls — they could be e.g. ``enumerate(table)`` or
        # ``len(x)`` whose literal args aren't addresses.
        callee = node.func
        if (
            isinstance(callee, ast.Name)
            and callee.id == "range"
            and len(node.args) >= 2
        ):
            return _first_literal_in_expr(node.args[0])
        return None
    return None


def _first_literal_arg(call_node: ast.Call) -> int | None:
    """First positional arg of ``call_node`` if it's a literal int."""
    if not call_node.args:
        return None
    return _first_literal_in_expr(call_node.args[0])


def _all_literal_args(call_node: ast.Call, count: int) -> tuple[int, ...] | None:
    """First ``count`` positional args, all literal ints; else ``None``."""
    if len(call_node.args) < count:
        return None
    values = []
    for arg in call_node.args[:count]:
        v = _literal_int(arg)
        if v is None:
            return None
        values.append(v)
    return tuple(values)


def _block_first_address(block: ast.AST) -> int | None:
    """Derive a sort address for an indented block.

    Order of preference:

    1. First literal int in the loop iterable (``for addr in [0x055B, …]``,
       ``for addr in range(0x8015, 0x801D)``).
    2. First literal-int positional arg of any sortable ``d.X(…)`` call
       in the block body, walked recursively.

    Returns ``None`` when no literal can be recovered (the block
    will become a soft anchor).
    """
    if isinstance(block, ast.For):
        addr = _first_literal_in_expr(block.iter)
        if addr is not None:
            return addr
    # Walk the body for the first sortable d.X(literal, …) call.
    body_nodes: list[ast.AST] = []
    for attr in ("body", "orelse", "finalbody", "handlers"):
        body_nodes.extend(getattr(block, attr, []) or [])
    for node in ast.walk(block):
        if isinstance(node, ast.Call):
            name = _call_name(node)
            if name in SORTABLE_FUNCTIONS or name == "constant":
                lit = _first_literal_arg(node)
                if lit is not None:
                    return lit
    return None


def _is_render_start(node: ast.AST) -> bool:
    """True for ``ir = d.disassemble()`` (or any ``X = …disassemble(…)``)."""
    if not isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
        return False
    value = getattr(node, "value", None)
    return isinstance(value, ast.Call) and _call_name(value) == "disassemble"


def _classify_pre_render(
    node: ast.AST, original_index: int
) -> _Statement:
    """Classify a statement appearing before ``ir = d.disassemble()``."""
    if isinstance(node, (ast.Import, ast.ImportFrom)):
        return _Statement(
            kind="setup_import",
            sort_key=_KEY_SETUP,
            address=None,
            addr_ranges=(),
            original_index=original_index,
        )
    if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
        return _Statement(
            kind="setup_assign",
            sort_key=_KEY_SETUP,
            address=None,
            addr_ranges=(),
            original_index=original_index,
        )
    if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
        call = node.value
        name = _call_name(call)
        if name == "create":  # Disassembler.create(...)
            return _Statement(
                kind="setup_create",
                sort_key=_KEY_SETUP,
                address=None,
                addr_ranges=(),
                original_index=original_index,
            )
        if name in _SETUP_CALLS:  # d.load
            return _Statement(
                kind=f"setup_{name}",
                sort_key=_KEY_SETUP,
                address=None,
                addr_ranges=(),
                original_index=original_index,
            )
        if name == "use_environment":
            return _Statement(
                kind="use_environment",
                sort_key=_KEY_USE_ENVIRONMENT,
                address=None,
                addr_ranges=(),
                original_index=original_index,
            )
        if name == "add_move":
            triple = _all_literal_args(call, 3)
            if triple is not None:
                dest, src, length = triple
                return _Statement(
                    kind="add_move",
                    sort_key=float(min(dest, src)),
                    address=min(dest, src),
                    addr_ranges=(
                        (dest, dest + length),
                        (src, src + length),
                    ),
                    original_index=original_index,
                )
            return _Statement(
                kind="soft_anchor",
                sort_key=math.nan,
                address=None,
                addr_ranges=(),
                original_index=original_index,
            )
        if name == "constant":
            value = _first_literal_arg(call)
            if value is not None:
                return _Statement(
                    kind="constant",
                    sort_key=float(value),
                    address=value,
                    addr_ranges=(),
                    original_index=original_index,
                )
            return _Statement(
                kind="soft_anchor",
                sort_key=math.nan,
                address=None,
                addr_ranges=(),
                original_index=original_index,
            )
        if name in SORTABLE_FUNCTIONS:
            addr = _first_literal_arg(call)
            if addr is not None:
                return _Statement(
                    kind="annotation",
                    sort_key=float(addr),
                    address=addr,
                    addr_ranges=(),
                    original_index=original_index,
                )
        return _Statement(
            kind="soft_anchor",
            sort_key=math.nan,
            address=None,
            addr_ranges=(),
            original_index=original_index,
        )
    if isinstance(node, (ast.For, ast.While, ast.If, ast.With, ast.AsyncWith,
                          ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef,
                          ast.Try)):
        addr = _block_first_address(node)
        if addr is not None:
            return _Statement(
                kind="indented_block",
                sort_key=float(addr),
                address=addr,
                addr_ranges=(),
                original_index=original_index,
            )
        return _Statement(
            kind="soft_anchor",
            sort_key=math.nan,
            address=None,
            addr_ranges=(),
            original_index=original_index,
        )
    return _Statement(
        kind="soft_anchor",
        sort_key=math.nan,
        address=None,
        addr_ranges=(),
        original_index=original_index,
    )


def _resolve_soft_anchor_keys(statements: list[_Statement]) -> None:
    """In-place: assign each pre-render soft anchor a sort key.

    Each soft anchor inherits the sort key of the nearest preceding
    *addressable* statement (use_environment, add_move, constant,
    annotation, indented_block — anything but setup_*, render_*,
    or another soft anchor). Setup statements never propagate
    their ``-inf`` key forward, so a for-loop sitting right after
    a big ``_table = [...]`` setup assignment doesn't get pulled
    up into the setup region — it lands at the address of
    whichever annotation last appeared in source before it.

    If a soft anchor has no addressable predecessor (e.g. one
    placed before any annotation), it inherits ``_KEY_USE_ENVIRONMENT``,
    which sandwiches it between setup and the address-keyed run.
    """
    last_addressable_key: float = _KEY_USE_ENVIRONMENT
    for s in statements:
        if s.kind in ("render_start", "render_prelude", "render_tail"):
            continue
        if s.kind == "soft_anchor":
            s.sort_key = last_addressable_key
            continue
        if s.kind.startswith("setup_"):
            continue
        if not math.isnan(s.sort_key):
            last_addressable_key = s.sort_key


# --- Filler attachment ---------------------------------------------


def _is_blank(line: str) -> bool:
    return line.strip() == ""


def _split_filler(filler: Sequence[str]) -> tuple[list[str], list[str]]:
    """Split a between-statements filler block.

    Leading blank lines (everything before the first non-blank line)
    become ``trailing`` of the preceding statement. The rest —
    comment lines and any interspersed blanks — become ``leading``
    of the following statement.
    """
    split_at = 0
    for i, line in enumerate(filler):
        if not _is_blank(line):
            split_at = i
            break
    else:
        return list(filler), []
    return list(filler[:split_at]), list(filler[split_at:])


# --- Parse + classify ----------------------------------------------


def _parse_statements(text: str) -> list[_Statement]:
    """Parse ``text`` and return classified statements with attached filler.

    The returned list is in **original source order**. Each
    statement carries its own source lines plus the leading and
    trailing filler that should travel with it across a sort. The
    render boundary (``ir = d.disassemble()``) is detected first;
    everything from there onwards is classified as ``render_start``
    or ``render_tail`` regardless of construct (a stray
    ``import sys`` placed just before the render block becomes
    ``render_tail``, not ``setup_import``).
    """
    body_text = text[:-1] if text.endswith("\n") else text
    if body_text == "":
        return []
    lines = body_text.split("\n")
    module = ast.parse(text)

    # First pass: locate the render-start node, if any.
    render_start_index: int | None = None
    for index, node in enumerate(module.body):
        if _is_render_start(node):
            render_start_index = index
            break

    statements: list[_Statement] = []
    last_consumed_lineno = 0  # 1-based; lines 1..last_consumed_lineno are taken

    for index, node in enumerate(module.body):
        start_lineno = node.lineno  # 1-based, inclusive
        end_lineno = node.end_lineno or start_lineno  # 1-based, inclusive

        filler_above_lines = lines[last_consumed_lineno:start_lineno - 1]

        if statements:
            trailing_for_prev, leading_for_next = _split_filler(filler_above_lines)
            statements[-1].trailing_lines.extend(trailing_for_prev)
        else:
            leading_for_next = list(filler_above_lines)

        if render_start_index is not None and index == render_start_index:
            stmt = _Statement(
                kind="render_start",
                sort_key=_KEY_RENDER,
                address=None,
                addr_ranges=(),
                original_index=index,
            )
        elif render_start_index is not None and index > render_start_index:
            stmt = _Statement(
                kind="render_tail",
                sort_key=_KEY_RENDER,
                address=None,
                addr_ranges=(),
                original_index=index,
            )
        else:
            stmt = _classify_pre_render(node, original_index=index)

        stmt.leading_lines = leading_for_next
        stmt.statement_lines = lines[start_lineno - 1:end_lineno]
        statements.append(stmt)
        last_consumed_lineno = end_lineno

    # Tail filler after the last statement.
    tail_filler = lines[last_consumed_lineno:]
    if tail_filler and statements:
        statements[-1].trailing_lines.extend(tail_filler)

    # Second pass: extend the render coda upward through any
    # contiguous setup-shaped statements directly preceding
    # ``ir = d.disassemble()``. The convention in dasmos drivers
    # is ``import sys\nir = d.disassemble()\n…sys.stderr…`` —
    # the ``import sys`` belongs with the render block, not with
    # the file's header imports. Stop walking back the moment we
    # see something non-setup (an annotation, a use_environment,
    # an indented block, etc.).
    if render_start_index is not None:
        for i in range(render_start_index - 1, -1, -1):
            if statements[i].kind.startswith("setup_"):
                statements[i].kind = "render_prelude"
                statements[i].sort_key = _KEY_RENDER
            else:
                break

    _resolve_soft_anchor_keys(statements)
    return statements


# --- Topological sort with address tiebreak -----------------------


def _build_graph(
    statements: Sequence[_Statement],
) -> tuple[dict[int, set[int]], dict[int, int]]:
    """Build the dependency DAG.

    Returns ``(successors, in_degree)``. ``successors[i]`` is the set
    of statement indices that ``statements[i]`` must precede.

    Edge sources:

    1. Each ``setup_*`` statement precedes every pre-render
       non-setup statement (and ``render_start``).
    2. Each ``add_move`` precedes every pre-render annotation
       whose address falls inside either its dest range or its
       src range.
    3. Every pre-render non-render statement precedes
       ``render_start``.
    4. ``render_start`` precedes every ``render_tail`` statement.

    Soft anchors are handled purely via their inherited sort_key
    (see :func:`_resolve_soft_anchor_keys`); they don't add any
    edges, so they can never participate in a cycle.
    """
    n = len(statements)
    successors: dict[int, set[int]] = {i: set() for i in range(n)}
    in_degree: dict[int, int] = {i: 0 for i in range(n)}

    setup_indices = [
        i for i, s in enumerate(statements) if s.kind.startswith("setup_")
    ]
    render_start_idx: int | None = next(
        (i for i, s in enumerate(statements) if s.kind == "render_start"),
        None,
    )
    render_prelude_indices = [
        i for i, s in enumerate(statements) if s.kind == "render_prelude"
    ]
    render_tail_indices = [
        i for i, s in enumerate(statements) if s.kind == "render_tail"
    ]
    pre_render_non_setup_indices = [
        i
        for i, s in enumerate(statements)
        if not s.kind.startswith("setup_")
        and s.kind not in ("render_start", "render_prelude", "render_tail")
    ]

    def add_edge(u: int, v: int) -> None:
        if u == v:
            return
        if v not in successors[u]:
            successors[u].add(v)
            in_degree[v] += 1

    # 1. Setup → pre-render-non-setup, render_prelude, and render_start.
    for u in setup_indices:
        for v in pre_render_non_setup_indices:
            add_edge(u, v)
        for v in render_prelude_indices:
            add_edge(u, v)
        if render_start_idx is not None:
            add_edge(u, render_start_idx)

    # 2. add_move → matching annotations.
    for u in range(n):
        s = statements[u]
        if s.kind != "add_move":
            continue
        for v in pre_render_non_setup_indices:
            t = statements[v]
            if t.address is None:
                continue
            if any(lo <= t.address < hi for lo, hi in s.addr_ranges):
                add_edge(u, v)

    # 3. Every pre-render non-render → render_start; and every
    # render_prelude → render_start.
    if render_start_idx is not None:
        for u in pre_render_non_setup_indices:
            add_edge(u, render_start_idx)
        for u in render_prelude_indices:
            add_edge(u, render_start_idx)

    # 4. render_start → render_tail.
    if render_start_idx is not None:
        for v in render_tail_indices:
            add_edge(render_start_idx, v)

    return successors, in_degree


def _topo_sort(
    statements: Sequence[_Statement],
) -> list[_Statement]:
    """Kahn's algorithm with address-keyed priority queue."""
    successors, in_degree = _build_graph(statements)

    def key_for(idx: int) -> tuple[float, int, int]:
        s = statements[idx]
        return (s.sort_key, s.original_index, idx)

    heap: list[tuple[float, int, int]] = []
    for i in range(len(statements)):
        if in_degree[i] == 0:
            heapq.heappush(heap, key_for(i))

    out: list[_Statement] = []
    while heap:
        _, _, idx = heapq.heappop(heap)
        out.append(statements[idx])
        for v in successors[idx]:
            in_degree[v] -= 1
            if in_degree[v] == 0:
                heapq.heappush(heap, key_for(v))

    if len(out) != len(statements):
        # Should not happen — the graph we build is acyclic by
        # construction. Defensive fallback: append remaining items
        # in original order.
        seen = {id(s) for s in out}
        for s in statements:
            if id(s) not in seen:
                out.append(s)
    return out


# --- Public API ---------------------------------------------------


def build_units(text: str) -> list[Unit]:
    """Parse ``text`` into a list of :class:`Unit` records, in source order."""
    return [s.to_unit() for s in _parse_statements(text)]


def emit_units(units: Sequence[Unit]) -> str:
    """Concatenate ``units`` back into source text."""
    out: list[str] = []
    for unit in units:
        out.extend(unit.leading_lines)
        out.extend(unit.statement_lines)
        out.extend(unit.trailing_lines)
    return "\n".join(out)


def sort_driver_text(text: str) -> str:
    """Return ``text`` with statements topologically sorted by address.

    See the module docstring for the full rule set. Statement text
    is moved verbatim — hex literals stay hex, multi-line calls
    keep their original layout.
    """
    if text == "":
        return text
    statements = _parse_statements(text)
    sorted_statements = _topo_sort(statements)
    out = emit_units([s.to_unit() for s in sorted_statements])
    if text.endswith("\n"):
        out += "\n"
    return out


def is_sorted(text: str) -> bool:
    """Return True if ``text`` is already in canonical sorted order.

    Equivalent to ``sort_driver_text(text) == text`` but slightly
    cheaper (skips the emit pass when the topology already
    matches).
    """
    if text == "":
        return True
    statements = _parse_statements(text)
    sorted_statements = _topo_sort(statements)
    return [s.original_index for s in sorted_statements] == list(
        range(len(statements))
    )


__all__ = [
    "ANCHOR_FUNCTIONS",
    "SORTABLE_FUNCTIONS",
    "Unit",
    "build_units",
    "emit_units",
    "is_sorted",
    "sort_driver_text",
]
