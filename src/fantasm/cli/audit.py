"""``fantasm audit`` — subroutine annotation audit subcommands."""

from __future__ import annotations

import click
from asyoulikeit import Report, Reports, TableContent, report_output

from ..api.audit import ALL_FLAGS, end_type, find_sub, find_undeclared_subs
from ..cli_helpers import analysis_context


@click.group(help="Subroutine annotation audit.")
def audit() -> None:
    pass


@audit.command(
    "summary",
    help="List every subroutine with its computed flags.",
)
@click.argument("version_id")
@click.option(
    "--flag",
    type=click.Choice(ALL_FLAGS, case_sensitive=False),
    help="Restrict to subroutines carrying this flag.",
)
@report_output(reports={"summary": "Subroutine summary"})
def audit_summary(version_id: str, flag: str | None) -> Reports:
    actx = analysis_context(click.get_current_context(), version_id)
    subs = actx.audit_subs
    if flag:
        flag_upper = flag.upper()
        subs = [s for s in subs if flag_upper in s["flags"]]

    table = (
        TableContent(
            title=f"Subroutines in {version_id}",
            description=(
                f"{len(subs)} subroutines"
                + (f" with flag {flag.upper()}" if flag else "")
            ),
        )
        .add_column("addr", "Addr")
        .add_column("name", "Name")
        .add_column("end", "End")
        .add_column("items", "Code/Data")
        .add_column("flags", "Flags")
    )
    for sub in subs:
        table.add_row(
            addr=f"&{sub['addr']:04X}",
            name=sub["name"],
            end=end_type(sub),
            items=f"{sub['code_count']}/{sub['data_count']}",
            flags=",".join(sorted(sub["flags"])) if sub["flags"] else "",
        )
    return Reports(summary=Report(data=table))


@audit.command(
    "detail",
    help="Show the full audit report for one subroutine.",
)
@click.argument("version_id")
@click.argument("target")
@report_output(reports={
    "info": "Subroutine summary",
    "called_by": "Direct callers (JSR/JMP)",
    "branch_entries": "Branch entries",
    "escaping_branches": "Branches that leave the sub",
})
def audit_detail(version_id: str, target: str) -> Reports:
    actx = analysis_context(click.get_current_context(), version_id)
    sub = find_sub(actx.audit_subs, target)
    if sub is None:
        raise click.UsageError(
            f"subroutine {target!r} not found in {version_id}"
        )

    end_label = end_type(sub)
    range_str = (
        f"&{sub['items'][0]['addr']:04X}-&{sub['items'][-1]['addr']:04X}"
        if sub["items"]
        else "(empty)"
    )
    info = (
        TableContent(
            title=f"{sub['name']} (&{sub['addr']:04X})",
            description=sub["title"] or "(no title)",
        )
        .add_column("key", "Key")
        .add_column("value", "Value")
        .add_row(key="address", value=f"&{sub['addr']:04X}")
        .add_row(key="name", value=sub["name"])
        .add_row(key="title", value=sub["title"] or "")
        .add_row(key="end_type", value=end_label)
        .add_row(key="extent", value=range_str)
        .add_row(
            key="items",
            value=f"{sub['code_count']} code / {sub['data_count']} data",
        )
        .add_row(
            key="flags",
            value=", ".join(sorted(sub["flags"])) if sub["flags"] else "",
        )
        .add_row(key="description", value=sub["description"] or "")
    )

    callers = (
        TableContent(title=f"Callers of {sub['name']}")
        .add_column("addr", "Addr")
        .add_column("mnemonic", "Op")
        .add_column("in_sub", "In subroutine")
    )
    for ref in sorted(sub["entry_refs"], key=lambda r: r["addr"]):
        callers.add_row(
            addr=f"&{ref['addr']:04X}",
            mnemonic=ref["mnemonic"].upper(),
            in_sub=ref["in_sub"],
        )

    branches = (
        TableContent(title=f"Branch entries to {sub['name']}")
        .add_column("addr", "Addr")
        .add_column("mnemonic", "Op")
        .add_column("in_sub", "In subroutine")
    )
    for ref in sorted(sub["branch_entry_refs"], key=lambda r: r["addr"]):
        branches.add_row(
            addr=f"&{ref['addr']:04X}",
            mnemonic=ref["mnemonic"].upper(),
            in_sub=ref["in_sub"],
        )

    escaping = (
        TableContent(title=f"Branches escaping {sub['name']}")
        .add_column("addr", "Addr")
        .add_column("mnemonic", "Op")
        .add_column("target", "Target")
    )
    for br in sorted(sub["escaping_branches"], key=lambda b: b["addr"]):
        escaping.add_row(
            addr=f"&{br['addr']:04X}",
            mnemonic=br["mnemonic"].upper(),
            target=f"&{br['target']:04X} {br['target_label']}",
        )

    return Reports(
        info=Report(data=info),
        called_by=Report(data=callers),
        branch_entries=Report(data=branches),
        escaping_branches=Report(data=escaping),
    )


@audit.command(
    "undeclared",
    help="List JSR targets that lack subroutine() declarations.",
)
@click.argument("version_id")
@report_output(reports={"undeclared": "Undeclared JSR targets"})
def audit_undeclared(version_id: str) -> Reports:
    actx = analysis_context(click.get_current_context(), version_id)
    actx.data
    candidates = find_undeclared_subs(actx.files.json_filepath)
    table = (
        TableContent(
            title=f"Undeclared JSR targets in {version_id}",
            description=f"{len(candidates)} candidates",
        )
        .add_column("addr", "Addr")
        .add_column("name", "Name")
        .add_column("range", "Range")
        .add_column("items", "Code/Data")
        .add_column("calls", "Calls")
        .add_column("container", "Container")
    )
    for c in candidates:
        table.add_row(
            addr=f"&{c['addr']:04X}",
            name=c["name"],
            range=c["range_str"],
            items=f"{c['code_count']}/{c['data_count']}",
            calls=str(c["caller_count"]),
            container=c["container"],
        )
    return Reports(undeclared=Report(data=table))
