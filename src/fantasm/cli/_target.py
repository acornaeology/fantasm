"""Optional leading ``TARGET`` argument for per-target commands.

Every per-target command declares its target as a leading
``version_id`` argument. :class:`TargetCommand` makes that argument
optional: when the command line leaves it out, the project's default
target (its only target, or ``[project] default_target``) is
inserted before Click parses the arguments, so the command body
always receives a target id.

The target counts as omitted when:

- there are fewer positional arguments than the command requires; or
- the command also has optional positional arguments, there's room
  for one more, and the first positional isn't a known target id
  (so ``fantasm asm extract START END`` works in a single-target
  project, while ``fantasm asm extract 1.0 START`` still names the
  target explicitly).

When the target is omitted and there's no default, the command fails
with a message listing the available targets.

:class:`FantasmGroup` makes :class:`TargetCommand` the command class
for every command registered on a group, so a command opts in simply
by naming its first argument ``version_id``.
"""

from __future__ import annotations

from collections.abc import Sequence

import click

from ..api.targets import (
    TargetConfigError,
    default_target_id,
    list_target_ids,
)

TARGET_PARAM_NAME = "version_id"
TARGET_METAVAR = "[TARGET]"


def _option_lookup(command: click.Command) -> dict[str, click.Option]:
    lookup: dict[str, click.Option] = {}
    for param in command.params:
        if isinstance(param, click.Option):
            for opt in (*param.opts, *param.secondary_opts):
                lookup[opt] = param
    return lookup


def _takes_value(option: click.Option) -> bool:
    return not option.is_flag and not option.count


def _scan_positionals(
    command: click.Command, args: Sequence[str]
) -> tuple[list[int], set[str]]:
    """Return the indices of positional tokens, and the option names seen."""
    lookup = _option_lookup(command)
    positional_indices: list[int] = []
    seen: set[str] = set()
    index = 0
    while index < len(args):
        token = args[index]
        if token == "--":
            positional_indices += range(index + 1, len(args))
            break
        if token.startswith("-") and len(token) > 1:
            name, has_equals, _ = token.partition("=")
            option = lookup.get(name)
            if option is None and not token.startswith("--"):
                # A short option with its value attached (-xVALUE) or a
                # cluster of short flags (-abc).
                option = lookup.get(token[:2])
                if option is not None and _takes_value(option):
                    has_equals = "attached"
            if option is not None:
                if option.name:
                    seen.add(option.name)
                if _takes_value(option) and not has_equals:
                    index += option.nargs
            index += 1
            continue
        positional_indices.append(index)
        index += 1
    return positional_indices, seen


class TargetCommand(click.Command):
    """A command whose leading ``version_id`` argument may be omitted.

    ``suppress_default_target_for`` names options (by parameter name)
    whose presence means no target is wanted, such as ``verify --all``.
    """

    suppress_default_target_for: frozenset[str] = frozenset()
    missing_target_hint: str = ""

    def parse_args(self, ctx: click.Context, args: list[str]) -> list[str]:
        if not ctx.resilient_parsing:
            args = self._with_default_target(ctx, list(args))
        return super().parse_args(ctx, args)

    def _with_default_target(
        self, ctx: click.Context, args: list[str]
    ) -> list[str]:
        arguments = [p for p in self.params if isinstance(p, click.Argument)]
        if not arguments or arguments[0].name != TARGET_PARAM_NAME:
            return args
        if any(arg in ctx.help_option_names for arg in args):
            return args
        positional_indices, seen = _scan_positionals(self, args)
        if seen & self.suppress_default_target_for:
            return args

        root_obj = ctx.find_root().obj
        project = root_obj.get("project") if isinstance(root_obj, dict) else None
        if project is None or not project.has_root:
            return args

        required = sum(
            1 for a in arguments
            if (a.required or a.name == TARGET_PARAM_NAME) and a.nargs == 1
        )
        maximum = (
            None if any(a.nargs == -1 for a in arguments)
            else sum(a.nargs for a in arguments)
        )
        count = len(positional_indices)

        try:
            if count < required:
                target_id = default_target_id(project)
                if target_id is None:
                    raise click.UsageError(
                        self._missing_target_message(project), ctx=ctx
                    )
            elif (
                maximum is not None
                and count < maximum
                and args[positional_indices[0]] not in list_target_ids(project)
            ):
                target_id = default_target_id(project)
                if target_id is None:
                    return args
            else:
                return args
        except TargetConfigError as exc:
            raise click.UsageError(str(exc), ctx=ctx) from exc

        insert_at = positional_indices[0] if positional_indices else len(args)
        if not positional_indices and "--" in args:
            insert_at = len(args)
        return [*args[:insert_at], target_id, *args[insert_at:]]


    def _missing_target_message(self, project) -> str:
        available = list_target_ids(project)
        if available:
            message = (
                f"no TARGET given and the project has {len(available)} "
                f"targets: {', '.join(available)}. Name one, or set "
                "[project] default_target in fantasm.toml"
            )
        else:
            message = (
                "no TARGET given and the project has no targets; add a "
                "version directory, [layout] or a [[targets]] entry"
            )
        return message + self.missing_target_hint + "."


class FantasmGroup(click.Group):
    """A group whose commands are :class:`TargetCommand` instances."""

    command_class = TargetCommand
    group_class = type


def target_argument() -> click.Argument:
    """The leading optional ``TARGET`` argument shared by commands."""
    return click.argument(TARGET_PARAM_NAME, metavar=TARGET_METAVAR)


__all__ = [
    "FantasmGroup",
    "TARGET_METAVAR",
    "TARGET_PARAM_NAME",
    "TargetCommand",
    "target_argument",
]
