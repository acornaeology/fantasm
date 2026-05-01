# `fantasm.toml`

Per-project configuration for fantasm. Sits at the project root. Fantasm
discovers it by walking upwards from the current working directory; the
top-level `--project-root` option and the `FANTASM_PROJECT_ROOT`
environment variable both override discovery.

## Schema

The schema is grown opportunistically as modules are ported in. Today
the following sections are recognised:

```toml
[project]
# Project name. Used as a fallback for [versions] prefixes when that
# option is omitted, and for the project-specific strings the CLI
# emits in error/help messages.
name = "acorn-nfs"

[rom]
# Default CPU for downstream commands that decode opcodes. Recognised
# values (case-insensitive): "6502" / "nmos" (default) and "65c02" /
# "65sc12" / "65c12" / "cmos".
cpu = "6502"

# (Future) base load address and bank size for the ROM(s); these will
# be threaded into modules that previously hardcoded NFS-specific
# 0x8000 / 0x2000 constants.
# base_address = 0x8000
# size = 0x2000

[versions]
# Directory under the project root that holds version subdirectories.
# Default: "versions".
directory = "versions"

# Ordered list of acceptable ROM-name prefixes. Version directories are
# named "{prefix}-{version_id}/"; resolution tries each prefix in order
# and returns the first existing directory. NFS uses two ("anfs" and
# "nfs"); other projects use one. If omitted, [project] name is used as
# a single-element fallback.
prefixes = ["anfs", "nfs"]
```

## Examples

A minimal config for a single-prefix project:

```toml
[project]
name = "acorn-adfs"
```

Equivalent to:

```toml
[project]
name = "acorn-adfs"

[versions]
directory = "versions"
prefixes  = ["acorn-adfs"]
```

NFS, with two prefixes:

```toml
[project]
name = "acorn-nfs"

[versions]
prefixes = ["anfs", "nfs"]
```

## Resolution semantics

`fantasm.api.paths.resolve_version_dirpath_for_project(project, version_id)`
reads `[versions]` and looks for `{prefix}-{version_id}/` under
`{project_root}/{directory}/` — first match wins. A
`VersionNotFoundError` carrying the available directory names is raised
if nothing matches.

`fantasm.api.paths.rom_prefix_for_project(project, version_dirpath)` does
the inverse: extracts the prefix from a directory name using the
configured prefix list.
