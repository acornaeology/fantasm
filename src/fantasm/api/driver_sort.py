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
- **Module-level name dependencies.** For every module-scope name,
  a statement that *writes* it precedes later statements that
  *read* or *write* it, and a statement that *reads* it precedes a
  later statement that *writes* it (RAW / WAR / WAW). Read-after-read
  is free, so the ``d`` receiver — written once, read by every
  ``d.X(…)`` call — never orders annotations relative to each other.
  This edge is what keeps an accumulator setup (``addr = 0x8579``)
  ahead of the ``for`` / ``while`` loop that consumes and reassigns
  ``addr``, and keeps a ``def`` ahead of the statement that calls it.

## Computed setup-assigns

A module-level assignment is normally ``setup`` (keyed ``-inf``,
pinned to the top). But an assignment whose value reads a name
produced *only* by a non-setup statement — e.g. ``ENTRIES =
_parse(…)`` calling a module-level ``def`` — is **demoted** to a
soft anchor so the name edge from the ``def`` can order it after
its definition. Pure-literal / constant assigns (``addr = 0x8579``,
``_table = [...]``, ``TOP = BASE + 0x100``) read no such name and
stay at the top.

## Unsortable inputs

Name edges can, in pathological inputs, close a cycle with the
setup / render edges. When the DAG is cyclic there is no valid
canonical order, so the sort is a **no-op**: ``sort_driver_text``
returns the input unchanged and ``is_sorted`` reports ``True``.
This guarantees the sort never changes whether the driver runs to
completion.

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
    # ``coverage_known`` is False when an ``indented_block`` couldn't
    # resolve every address its body emits at — typically because the
    # loop iterable resolves to a non-literal expression. Such blocks
    # over-constrain: every ``add_move`` adds a precedence edge, so
    # the block can never sort earlier than any move whose range
    # *might* overlap. Ignored for non-block kinds.
    coverage_known: bool = True
    # Module-scope names this statement reads / writes. Drive the
    # data-dependency edges (RAW / WAR / WAW) that keep an accumulator
    # setup ahead of its consumer loop and a ``def`` ahead of its
    # caller. Populated in :func:`_parse_statements` from the AST node.
    reads: frozenset[str] = frozenset()
    writes: frozenset[str] = frozenset()
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


def _collect_module_assigns(module: ast.Module) -> dict[str, ast.AST]:
    """Build a ``{name: value_node}`` map from top-level assignments.

    Drivers commonly hoist large dispatch tables to module scope —
    ``_tube_r2_entries = [(0x0500, …), (0x0502, …), …]`` — and then
    ``for`` over them. To know what addresses the loop covers we have
    to follow the Name back to its bound value. Only top-level
    ``Assign``/``AnnAssign`` are tracked; nested or conditional
    bindings are out of scope.
    """
    assigns: dict[str, ast.AST] = {}
    for node in module.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    assigns[target.id] = node.value
        elif isinstance(node, ast.AnnAssign):
            if isinstance(node.target, ast.Name) and node.value is not None:
                assigns[node.target.id] = node.value
    return assigns


def _extract_addresses_from_iterable(
    iterable: ast.AST,
    assigns: dict[str, ast.AST],
    _visited: frozenset[int] | None = None,
) -> tuple[set[int], bool]:
    """Return ``(addresses, complete)`` derivable from a loop iterable.

    - List / tuple of literal ints: the literals.
    - List / tuple of tuples-or-lists: first literal int of each
      element (the conventional ``(addr, label, …)`` shape).
    - ``range(start, stop)`` / ``range(start, stop, step)`` with
      literal arguments: the inclusive start, exclusive stop integers.
    - ``Name`` bound at module level: recurse into the bound value.
    - Anything else (computed expressions, function calls other than
      ``range``): empty set, ``complete=False``.

    ``complete`` reports whether every iteration value was statically
    derivable. False forces the conservative add_move-edges-from-all
    rule so the block can't sort earlier than any move that *might*
    cover its range.
    """
    visited = _visited or frozenset()

    if isinstance(iterable, (ast.List, ast.Tuple, ast.Set)):
        addrs: set[int] = set()
        complete = True
        for elt in iterable.elts:
            if isinstance(elt, (ast.List, ast.Tuple)):
                if elt.elts:
                    lit = _literal_int(elt.elts[0])
                    if lit is not None:
                        addrs.add(lit)
                        continue
                complete = False
            else:
                lit = _literal_int(elt)
                if lit is not None:
                    addrs.add(lit)
                    continue
                complete = False
        return addrs, complete

    if isinstance(iterable, ast.Call):
        callee = iterable.func
        if (
            isinstance(callee, ast.Name)
            and callee.id == "range"
            and 2 <= len(iterable.args) <= 3
        ):
            start = _literal_int(iterable.args[0])
            stop = _literal_int(iterable.args[1])
            step = (
                _literal_int(iterable.args[2])
                if len(iterable.args) == 3
                else 1
            )
            if start is not None and stop is not None and step:
                return set(range(start, stop, step)), True
        return set(), False

    if isinstance(iterable, ast.Name):
        if iterable.id in visited:
            return set(), False
        target = assigns.get(iterable.id)
        if target is not None:
            return _extract_addresses_from_iterable(
                target, assigns, visited | {iterable.id}
            )
        return set(), False

    return set(), False


def _block_coverage(
    block: ast.AST, assigns: dict[str, ast.AST]
) -> tuple[int | None, tuple[tuple[int, int], ...], bool]:
    """Derive an indented block's address coverage.

    Returns ``(primary_address, addr_ranges, coverage_known)``:

    - ``primary_address`` — the smallest covered address, used as
      the sort key. ``None`` if no address could be derived (caller
      promotes to ``soft_anchor``).
    - ``addr_ranges`` — a single ``(min, max+1)`` range if known
      addresses are contiguous-ish (we use min..max+1 for overlap
      tests; the inner gaps don't matter because ``add_move`` ranges
      are themselves contiguous).
    - ``coverage_known`` — whether the block's full address set was
      derivable. ``False`` triggers conservative ``add_move`` edges.
    """
    if isinstance(block, ast.For):
        addrs, complete = _extract_addresses_from_iterable(block.iter, assigns)
        if addrs:
            ranges = ((min(addrs), max(addrs) + 1),)
            return min(addrs), ranges, complete
    # Fallback: scan the body for a literal-int first arg of any
    # sortable ``d.X(…)`` call. We only know one address from this
    # path, so coverage is incomplete.
    for node in ast.walk(block):
        if isinstance(node, ast.Call):
            name = _call_name(node)
            if name in SORTABLE_FUNCTIONS or name == "constant":
                lit = _first_literal_arg(node)
                if lit is not None:
                    return lit, ((lit, lit + 1),), False
    return None, (), False


def _collect_expr_names(
    node: ast.AST, reads: set[str], writes: set[str]
) -> None:
    """Collect Load names as reads and walrus targets as writes from an expression.

    ``ast.walk`` over an expression subtree. Any ``Name`` in ``Load``
    context is a read; a walrus ``(x := …)`` binds ``x`` in the
    enclosing (module) scope, so its target is a write. Names bound
    by comprehensions or lambdas inside the expression have their own
    scope, but treating an incidental such ``Load`` as a module read
    is safe — it only ever adds edges.
    """
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load):
            reads.add(child.id)
        elif isinstance(child, ast.NamedExpr) and isinstance(
            child.target, ast.Name
        ):
            writes.add(child.target.id)


def _collect_target(
    target: ast.AST, reads: set[str], writes: set[str]
) -> None:
    """Collect the module-scope names bound by an assignment target.

    ``Name`` targets bind; ``Tuple`` / ``List`` / ``Starred`` recurse;
    ``Attribute`` / ``Subscript`` targets *mutate* an existing object
    rather than rebind a name, so their base expression is a read.
    """
    if isinstance(target, ast.Name):
        writes.add(target.id)
    elif isinstance(target, (ast.Tuple, ast.List)):
        for elt in target.elts:
            _collect_target(elt, reads, writes)
    elif isinstance(target, ast.Starred):
        _collect_target(target.value, reads, writes)
    else:  # Attribute / Subscript — mutation, base is read.
        _collect_expr_names(target, reads, writes)


def _walk_module_scope(
    node: ast.AST, reads: set[str], writes: set[str]
) -> None:
    """Accumulate module-scope reads / writes of one statement.

    Recurses through constructs that execute at module scope
    (``For`` / ``While`` / ``If`` / ``With`` / ``Try`` and their
    nested bodies), but *not* into ``def`` / ``class`` bodies —
    those introduce their own scope. A ``def`` / ``class`` binds its
    name (a write) and evaluates its decorators, defaults and
    annotations at module scope (reads).
    """
    if isinstance(node, ast.Import):
        for alias in node.names:
            writes.add((alias.asname or alias.name).split(".")[0])
    elif isinstance(node, ast.ImportFrom):
        for alias in node.names:
            if alias.name != "*":
                writes.add(alias.asname or alias.name)
    elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        writes.add(node.name)
        for dec in node.decorator_list:
            _collect_expr_names(dec, reads, writes)
        if isinstance(node, ast.ClassDef):
            for base in node.bases:
                _collect_expr_names(base, reads, writes)
            for kw in node.keywords:
                _collect_expr_names(kw.value, reads, writes)
        else:
            args = node.args
            for default in (*args.defaults, *args.kw_defaults):
                if default is not None:
                    _collect_expr_names(default, reads, writes)
            for arg in (*args.posonlyargs, *args.args, *args.kwonlyargs,
                        args.vararg, args.kwarg):
                if arg is not None and arg.annotation is not None:
                    _collect_expr_names(arg.annotation, reads, writes)
            if node.returns is not None:
                _collect_expr_names(node.returns, reads, writes)
        # Body is a separate scope — not walked.
    elif isinstance(node, ast.Assign):
        for target in node.targets:
            _collect_target(target, reads, writes)
        _collect_expr_names(node.value, reads, writes)
    elif isinstance(node, ast.AnnAssign):
        _collect_target(node.target, reads, writes)
        _collect_expr_names(node.annotation, reads, writes)
        if node.value is not None:
            _collect_expr_names(node.value, reads, writes)
    elif isinstance(node, ast.AugAssign):
        # ``x += 1`` reads and writes ``x``.
        if isinstance(node.target, ast.Name):
            reads.add(node.target.id)
        _collect_target(node.target, reads, writes)
        _collect_expr_names(node.value, reads, writes)
    elif isinstance(node, ast.Delete):
        for target in node.targets:
            _collect_target(target, reads, writes)
    elif isinstance(node, (ast.For, ast.AsyncFor)):
        _collect_target(node.target, reads, writes)
        _collect_expr_names(node.iter, reads, writes)
        for child in (*node.body, *node.orelse):
            _walk_module_scope(child, reads, writes)
    elif isinstance(node, (ast.While, ast.If)):
        _collect_expr_names(node.test, reads, writes)
        for child in (*node.body, *node.orelse):
            _walk_module_scope(child, reads, writes)
    elif isinstance(node, (ast.With, ast.AsyncWith)):
        for item in node.items:
            _collect_expr_names(item.context_expr, reads, writes)
            if item.optional_vars is not None:
                _collect_target(item.optional_vars, reads, writes)
        for child in node.body:
            _walk_module_scope(child, reads, writes)
    elif isinstance(node, ast.Try):
        for handler in node.handlers:
            if handler.type is not None:
                _collect_expr_names(handler.type, reads, writes)
            if handler.name is not None:
                writes.add(handler.name)
            for child in handler.body:
                _walk_module_scope(child, reads, writes)
        for child in (*node.body, *node.orelse, *node.finalbody):
            _walk_module_scope(child, reads, writes)
    else:
        # Expr, Return, Assert, Raise, bare calls, etc. — reads only.
        _collect_expr_names(node, reads, writes)


def _name_deps(node: ast.AST) -> tuple[frozenset[str], frozenset[str]]:
    """Return ``(reads, writes)`` of module-scope names for one statement."""
    reads: set[str] = set()
    writes: set[str] = set()
    _walk_module_scope(node, reads, writes)
    return frozenset(reads), frozenset(writes)


def _is_render_start(node: ast.AST) -> bool:
    """True for ``ir = d.disassemble()`` (or any ``X = …disassemble(…)``)."""
    if not isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
        return False
    value = getattr(node, "value", None)
    return isinstance(value, ast.Call) and _call_name(value) == "disassemble"


def _classify_pre_render(
    node: ast.AST,
    original_index: int,
    assigns: dict[str, ast.AST],
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
        primary, ranges, coverage_known = _block_coverage(node, assigns)
        if primary is not None:
            return _Statement(
                kind="indented_block",
                sort_key=float(primary),
                address=primary,
                addr_ranges=ranges,
                original_index=original_index,
                coverage_known=coverage_known,
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
    module_assigns = _collect_module_assigns(module)

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
            stmt = _classify_pre_render(
                node, original_index=index, assigns=module_assigns
            )

        stmt.reads, stmt.writes = _name_deps(node)
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

    _demote_computed_setup_assigns(statements)
    _resolve_soft_anchor_keys(statements)
    return statements


def _demote_computed_setup_assigns(statements: list[_Statement]) -> None:
    """In-place: reclassify setup assigns that depend on non-setup output.

    A ``setup_assign`` is normally pinned to the top (``-inf``). But
    an assignment such as ``ENTRIES = _parse(…)`` whose value reads a
    name produced *only* by a non-setup statement (here a module-level
    ``def``) must sort *after* that producer. Leaving it as top-pinned
    setup would both misorder it and — combined with the ``def →
    assignment`` name edge — close a cycle. Demote it to a soft anchor
    so it inherits its neighbour's key and the name edge orders it.

    A name written by any setup statement is "setup-available"; only
    reads of names written *exclusively* by non-setup statements
    trigger demotion. Pure-literal assigns (``addr = 0x8579``,
    ``_table = [...]``) read no such name and stay at the top.
    """
    setup_writes: set[str] = set()
    nonsetup_writes: set[str] = set()
    for s in statements:
        if s.kind.startswith("setup_"):
            setup_writes |= s.writes
        elif s.kind not in ("render_start", "render_prelude", "render_tail"):
            nonsetup_writes |= s.writes
    demotable = nonsetup_writes - setup_writes
    if not demotable:
        return
    for s in statements:
        if s.kind == "setup_assign" and (s.reads & demotable):
            s.kind = "soft_anchor"
            s.sort_key = math.nan
            s.address = None
            s.addr_ranges = ()


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

    # 2. add_move → annotations / blocks / soft anchors whose
    # addresses fall in the moved range. Indented blocks where we
    # couldn't fully resolve coverage (``coverage_known=False``)
    # and soft anchors get an unconditional edge — the conservative
    # rule from issue #14: better to over-constrain than to silently
    # lose annotations because the loop ran before its move.
    def _ranges_overlap(
        a: tuple[tuple[int, int], ...],
        b: tuple[tuple[int, int], ...],
    ) -> bool:
        for a_lo, a_hi in a:
            for b_lo, b_hi in b:
                if a_lo < b_hi and b_lo < a_hi:
                    return True
        return False

    for u in range(n):
        s = statements[u]
        if s.kind != "add_move":
            continue
        for v in pre_render_non_setup_indices:
            if v == u:
                continue
            t = statements[v]
            if t.kind == "soft_anchor":
                add_edge(u, v)
                continue
            if t.kind == "indented_block":
                if not t.coverage_known or _ranges_overlap(
                    s.addr_ranges, t.addr_ranges
                ):
                    add_edge(u, v)
                continue
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

    # 5. Module-level name dependencies. For each name, walk the
    # statements that touch it in original order and add RAW / WAR /
    # WAW edges; read-after-read adds none. This keeps a write-then-
    # read/write chain (an accumulator setup ahead of its consumer
    # loop; a ``def`` ahead of its caller) in a valid execution order
    # without freezing read-only relationships like the ``d`` receiver.
    touchers: dict[str, list[int]] = {}
    for i, s in enumerate(statements):
        for name in s.reads | s.writes:
            touchers.setdefault(name, []).append(i)
    for name, indices in touchers.items():
        last_writer: int | None = None
        readers_since: list[int] = []
        for i in indices:  # already in ascending original order
            s = statements[i]
            reads_it = name in s.reads
            writes_it = name in s.writes
            if reads_it:
                if last_writer is not None:
                    add_edge(last_writer, i)  # RAW
                readers_since.append(i)
            if writes_it:
                for r in readers_since:
                    add_edge(r, i)  # WAR
                if last_writer is not None:
                    add_edge(last_writer, i)  # WAW
                last_writer = i
                readers_since = []

    return successors, in_degree


def _topo_sort(
    statements: Sequence[_Statement],
) -> list[_Statement] | None:
    """Kahn's algorithm with address-keyed priority queue.

    Returns the sorted statements, or ``None`` when the dependency
    graph is cyclic (no valid canonical order exists). Name edges can
    close a cycle with the setup / render edges on pathological input;
    callers treat ``None`` as "leave the file unchanged".
    """
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
        return None  # cyclic — unsortable
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
    if sorted_statements is None:
        return text  # unsortable (cyclic dependencies) — no-op
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
    if sorted_statements is None:
        return True  # unsortable — sort is a no-op, so already "sorted"
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
