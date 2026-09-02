"""Configurable per-version binary layout (issue #21).

fantasm defaults to the historical ROM layout
(``rom/<base>.rom`` + ``rom/rom.json``, ``[rom]`` config) but a project
whose artefacts are program binaries — e.g. an extension-less DFS
``*RUN`` file — can override the directory, extension, metadata
filename, cpu, and base address via a ``[binary]`` section. These tests
pin the resolution and the ``[rom]`` back-compat fallback.
"""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from fantasm.api.paths import (
    project_binary_base,
    project_binary_dirname,
    project_binary_extension,
    project_binary_filename_template,
    project_binary_metadata_filename,
    project_cpu,
    render_binary_filename,
)
from fantasm.cli import main
from fantasm.cli_helpers import resolve_version_files
from fantasm.config import resolve_project_context


def _write_project(root_dirpath: Path, config_body: str) -> None:
    (root_dirpath / "fantasm.toml").write_text(config_body)
    (root_dirpath / "versions" / "demo-1.0").mkdir(parents=True)


# --- [binary] layout ------------------------------------------------


VOLTMACE_STYLE = """\
[project]
name = "demo"

[binary]
cpu = "6502"
base_address = 0x1900
dir = "binary"
extension = ""
metadata = "binary.json"

[versions]
prefixes = ["demo"]
"""


class TestBinarySection:
    def test_readers_use_binary_section(self, tmp_path: Path) -> None:
        _write_project(tmp_path, VOLTMACE_STYLE)
        project = resolve_project_context(tmp_path)

        assert project_cpu(project) == "6502"
        assert project_binary_base(project) == 0x1900
        assert project_binary_dirname(project) == "binary"
        assert project_binary_extension(project) == ""
        assert project_binary_metadata_filename(project) == "binary.json"

    def test_extensionless_binary_and_metadata_paths(
        self, tmp_path: Path
    ) -> None:
        _write_project(tmp_path, VOLTMACE_STYLE)
        project = resolve_project_context(tmp_path)

        files = resolve_version_files(project, "1.0")
        version_dirpath = tmp_path / "versions" / "demo-1.0"
        # No extension -> the bare "demo-1.0" filename.
        assert files.binary_filepath == version_dirpath / "binary" / "demo-1.0"
        assert (
            files.metadata_filepath
            == version_dirpath / "binary" / "binary.json"
        )


# --- configurable binary filename (#22) -----------------------------


DFS_STYLE = """\
[project]
name = "voltmace"

[binary]
base_address = 0x1900
dir = "binary"
extension = ""
metadata = "binary.json"
filename = "{version_id_upper}"

[versions]
prefixes = ["voltmace"]
"""


class TestBinaryFilenameTemplate:
    def test_default_template_is_prefixed_name(self, tmp_path: Path) -> None:
        _write_project(tmp_path, ROM_STYLE)
        project = resolve_project_context(tmp_path)
        assert (
            project_binary_filename_template(project)
            == "{prefix}-{version_id}"
        )

    def test_dfs_name_renders_from_id(self, tmp_path: Path) -> None:
        (tmp_path / "fantasm.toml").write_text(DFS_STYLE)
        (tmp_path / "versions" / "voltmace-keypad").mkdir(parents=True)
        project = resolve_project_context(tmp_path)

        assert project_binary_filename_template(project) == "{version_id_upper}"
        files = resolve_version_files(project, "keypad")
        binary_dirpath = tmp_path / "versions" / "voltmace-keypad" / "binary"
        # DFS name kept: KEYPAD, not voltmace-keypad, and no extension.
        assert files.binary_filepath == binary_dirpath / "KEYPAD"
        # .asm/.json outputs stay prefixed.
        assert files.asm_filepath.name == "voltmace-keypad.asm"
        assert files.json_filepath.name == "voltmace-keypad.json"

    def test_render_binary_filename_tokens(self) -> None:
        assert (
            render_binary_filename("{version_id_upper}", "demo", "keypad")
            == "KEYPAD"
        )
        assert (
            render_binary_filename("{prefix}-{version_id}", "demo", "1.0")
            == "demo-1.0"
        )
        assert (
            render_binary_filename(
                "{prefix_upper}_{version_id_no_dots}", "nfs", "3.10"
            )
            == "NFS_310"
        )


# --- [rom] back-compat fallback -------------------------------------


ROM_STYLE = """\
[project]
name = "demo"

[rom]
cpu = "65c02"
base_address = 0x8000

[versions]
prefixes = ["demo"]
"""


class TestRomFallback:
    def test_rom_section_is_read_when_binary_absent(
        self, tmp_path: Path
    ) -> None:
        _write_project(tmp_path, ROM_STYLE)
        project = resolve_project_context(tmp_path)

        assert project_cpu(project) == "65c02"
        assert project_binary_base(project) == 0x8000

    def test_defaults_reproduce_classic_rom_layout(
        self, tmp_path: Path
    ) -> None:
        _write_project(tmp_path, ROM_STYLE)
        project = resolve_project_context(tmp_path)

        files = resolve_version_files(project, "1.0")
        version_dirpath = tmp_path / "versions" / "demo-1.0"
        assert (
            files.binary_filepath
            == version_dirpath / "rom" / "demo-1.0.rom"
        )
        assert (
            files.metadata_filepath == version_dirpath / "rom" / "rom.json"
        )

    def test_binary_section_wins_over_rom(self, tmp_path: Path) -> None:
        _write_project(
            tmp_path,
            '[project]\nname = "demo"\n'
            '[binary]\nbase_address = 0x1900\n'
            '[rom]\nbase_address = 0x8000\n'
            '[versions]\nprefixes = ["demo"]\n',
        )
        project = resolve_project_context(tmp_path)
        assert project_binary_base(project) == 0x1900


# --- project add honours the configured dir -------------------------


def test_project_add_scaffolds_configured_binary_dir(
    tmp_path: Path,
) -> None:
    (tmp_path / "fantasm.toml").write_text(VOLTMACE_STYLE)
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["--project-root", str(tmp_path), "project", "add", "1.0"],
    )
    assert result.exit_code == 0, result.output
    version_dirpath = tmp_path / "versions" / "demo-1.0"
    assert (version_dirpath / "binary").is_dir()
    assert (version_dirpath / "output").is_dir()
    assert not (version_dirpath / "rom").exists()
    assert "binary/" in result.output


# --- lint consults the configured metadata file ---------------------


def test_lint_reads_docs_from_configured_metadata(tmp_path: Path) -> None:
    (tmp_path / "fantasm.toml").write_text(VOLTMACE_STYLE)
    version_dirpath = tmp_path / "versions" / "demo-1.0"
    binary_dirpath = version_dirpath / "binary"
    binary_dirpath.mkdir(parents=True)

    # Minimal disassembly so the version resolves and has a label set.
    output_dirpath = version_dirpath / "output"
    output_dirpath.mkdir()
    (output_dirpath / "demo-1.0.json").write_text(
        json.dumps(
            {
                "meta": {"load_addr": 0x1900, "end_addr": 0x1A00},
                "subroutines": [{"addr": 0x1900, "name": "alpha"}],
                "items": [{"addr": 0x1900, "type": "code", "mnemonic": "rts"}],
            }
        )
    )

    # A doc referenced only from binary/binary.json, carrying a broken
    # label link. If lint reads the configured metadata file, it finds
    # the doc and reports the dangling target.
    (version_dirpath / "notes.md").write_text(
        "See [the start](label:does_not_exist).\n"
    )
    (binary_dirpath / "binary.json").write_text(
        json.dumps({"docs": [{"path": "notes.md"}]})
    )

    driver_filepath = tmp_path / "driver.py"
    driver_filepath.write_text('subroutine(0x1900, "alpha")\n')

    result = CliRunner().invoke(
        main,
        [
            "--project-root", str(tmp_path),
            "lint", "1.0", str(driver_filepath), "--as", "tsv",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "does_not_exist" in result.output
    assert "notes.md" in result.output
