"""Tests for ``fantasm.api.targets``."""

from __future__ import annotations

import tomllib
from pathlib import Path

import pytest

from fantasm.api.inf import InfParseError
from fantasm.api.paths import VersionNotFoundError
from fantasm.api.targets import (
    TargetConfigError,
    TargetNotFoundError,
    default_target_id,
    discover_target_ids,
    list_target_ids,
    resolve_target,
    target_verify_settings,
)
from fantasm.config import resolve_project_context


def _project(root_dirpath: Path, toml_text: str):
    (root_dirpath / "fantasm.toml").write_text(toml_text)
    return resolve_project_context(root_dirpath)


def _version_dir(root_dirpath: Path, name: str) -> Path:
    dirpath = root_dirpath / "versions" / name
    dirpath.mkdir(parents=True)
    return dirpath


class TestConvention:
    """Projects without [layout] / [[targets]] resolve exactly as before."""

    def test_paths(self, tmp_path: Path) -> None:
        project = _project(
            tmp_path,
            '[project]\nname = "p"\n[versions]\nprefixes = ["anfs", "nfs"]\n',
        )
        version_dirpath = _version_dir(tmp_path, "nfs-3.34")
        files = resolve_target(project, "3.34")
        assert files.source == "convention"
        assert files.prefix == "nfs"
        assert files.version_dirpath == version_dirpath
        assert files.binary_filepath == version_dirpath / "rom" / "nfs-3.34.rom"
        assert files.metadata_filepath == version_dirpath / "rom" / "rom.json"
        assert files.asm_filepath == version_dirpath / "output" / "nfs-3.34.asm"
        assert files.json_filepath == version_dirpath / "output" / "nfs-3.34.json"
        assert files.driver_filepath == (
            version_dirpath / "disassemble" / "disasm_nfs_334.py"
        )
        assert files.load_address == 0x8000
        assert files.exec_address is None

    def test_binary_section_base_address(self, tmp_path: Path) -> None:
        project = _project(
            tmp_path,
            '[project]\nname = "v"\n[binary]\nbase_address = 0x1900\n'
            'dir = "binary"\nextension = ""\nfilename = "{version_id_upper}"\n',
        )
        version_dirpath = _version_dir(tmp_path, "v-keypad")
        (version_dirpath / "binary").mkdir()
        # A sidecar is ignored under the convention.
        (version_dirpath / "binary" / "KEYPAD.inf").write_text("KEYPAD 2000 2000")
        files = resolve_target(project, "keypad")
        assert files.binary_filepath == version_dirpath / "binary" / "KEYPAD"
        assert files.load_address == 0x1900
        assert files.inf_filepath is None

    def test_unknown_version_raises_version_not_found(
        self, tmp_path: Path
    ) -> None:
        project = _project(tmp_path, '[project]\nname = "p"\n')
        _version_dir(tmp_path, "p-1.0")
        with pytest.raises(VersionNotFoundError) as excinfo:
            resolve_target(project, "2.0")
        assert excinfo.value.available == ("p-1.0",)

    def test_target_list_is_version_dirs(self, tmp_path: Path) -> None:
        project = _project(
            tmp_path,
            '[project]\nname = "p"\n[[versions.entry]]\nid = "9.9"\n',
        )
        _version_dir(tmp_path, "p-1.0")
        _version_dir(tmp_path, "p-2.0")
        # Graph entries only count as targets when [layout] is used.
        assert list_target_ids(project) == ["1.0", "2.0"]
        assert default_target_id(project) is None

    def test_single_version_is_default(self, tmp_path: Path) -> None:
        project = _project(tmp_path, '[project]\nname = "p"\n')
        _version_dir(tmp_path, "p-1.0")
        assert default_target_id(project) == "1.0"


class TestExplicitTargets:
    def test_paths_relative_to_root(self, tmp_path: Path) -> None:
        project = _project(
            tmp_path,
            '[project]\nname = "elite"\n'
            "[[targets]]\n"
            'id = "loader"\n'
            'binary = "orig/ELITE"\n'
            "load_address = 0x1900\n"
            'driver = "tools/dis_loader.py"\n'
            'asm = "build/loader.asm"\n'
            'json = "build/loader.json"\n',
        )
        files = resolve_target(project, "loader")
        assert files.source == "explicit"
        assert files.binary_filepath == tmp_path / "orig" / "ELITE"
        assert files.driver_filepath == tmp_path / "tools" / "dis_loader.py"
        assert files.asm_filepath == tmp_path / "build" / "loader.asm"
        assert files.json_filepath == tmp_path / "build" / "loader.json"
        assert files.metadata_filepath is None
        assert files.version_dirpath == tmp_path
        assert files.load_address == 0x1900
        assert files.prefix == "elite"

    def test_inf_sidecar_read_automatically(self, tmp_path: Path) -> None:
        (tmp_path / "orig").mkdir()
        (tmp_path / "orig" / "ELITE").write_bytes(b"\x00")
        (tmp_path / "orig" / "ELITE.inf").write_text(
            "$.ELITE FF1900 FF8023 000400\n"
        )
        project = _project(
            tmp_path,
            '[[targets]]\nid = "loader"\nbinary = "orig/ELITE"\n'
            'driver = "d.py"\nasm = "o.asm"\njson = "o.json"\n',
        )
        files = resolve_target(project, "loader")
        assert files.load_address == 0x1900
        assert files.exec_address == 0x8023
        assert files.inf_filepath == tmp_path / "orig" / "ELITE.inf"

    def test_explicit_address_wins_over_bad_sidecar(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / "X").write_bytes(b"\x00")
        (tmp_path / "X.inf").write_text("garbage\n")
        project = _project(
            tmp_path,
            '[[targets]]\nid = "x"\nbinary = "X"\nload_address = "&2000"\n'
            'driver = "d.py"\nasm = "o.asm"\njson = "o.json"\n',
        )
        assert resolve_target(project, "x").load_address == 0x2000

    def test_unparseable_inf_suggests_load_address(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / "X").write_bytes(b"\x00")
        (tmp_path / "X.inf").write_text("$.X Locked\n")
        project = _project(
            tmp_path,
            '[[targets]]\nid = "x"\nbinary = "X"\n'
            'driver = "d.py"\nasm = "o.asm"\njson = "o.json"\n',
        )
        with pytest.raises(InfParseError, match="load_address"):
            resolve_target(project, "x")

    def test_inf_true_without_sidecar(self, tmp_path: Path) -> None:
        project = _project(
            tmp_path,
            '[[targets]]\nid = "x"\nbinary = "X"\ninf = true\n'
            'driver = "d.py"\nasm = "o.asm"\njson = "o.json"\n',
        )
        with pytest.raises(InfParseError, match="no .inf sidecar"):
            resolve_target(project, "x")

    def test_no_sidecar_falls_back_to_base_address(
        self, tmp_path: Path
    ) -> None:
        project = _project(
            tmp_path,
            "[binary]\nbase_address = 0x3000\n"
            '[[targets]]\nid = "x"\nbinary = "X"\n'
            'driver = "d.py"\nasm = "o.asm"\njson = "o.json"\n',
        )
        assert resolve_target(project, "x").load_address == 0x3000

    def test_single_image_form(self, tmp_path: Path) -> None:
        project = _project(
            tmp_path,
            '[[targets]]\nid = "fs"\ndriver = "d.py"\nasm = "o.asm"\n'
            'json = "o.json"\n'
            '[[targets.images]]\nname = "FS3"\npath = "disc/FS3"\n'
            "load_address = 0x1900\nexec_address = 0x1903\n",
        )
        files = resolve_target(project, "fs")
        assert files.binary_filepath == tmp_path / "disc" / "FS3"
        assert files.image_name == "FS3"
        assert (files.load_address, files.exec_address) == (0x1900, 0x1903)

    def test_multiple_images_not_yet_supported(self, tmp_path: Path) -> None:
        project = _project(
            tmp_path,
            '[[targets]]\nid = "fs"\ndriver = "d.py"\nasm = "o.asm"\n'
            'json = "o.json"\nimages = [{path = "A"}, {path = "B"}]\n',
        )
        with pytest.raises(TargetConfigError, match="one target per file"):
            resolve_target(project, "fs")

    def test_unknown_key_rejected(self, tmp_path: Path) -> None:
        project = _project(
            tmp_path, '[[targets]]\nid = "x"\nbinry = "X"\n'
        )
        with pytest.raises(TargetConfigError, match="binry"):
            list_target_ids(project)

    def test_missing_path_without_version_dir(self, tmp_path: Path) -> None:
        project = _project(
            tmp_path, '[[targets]]\nid = "x"\nbinary = "X"\n'
        )
        with pytest.raises(TargetConfigError, match="no driver path"):
            resolve_target(project, "x")

    def test_explicit_overrides_convention_key_by_key(
        self, tmp_path: Path
    ) -> None:
        project = _project(
            tmp_path,
            '[project]\nname = "p"\n'
            '[[targets]]\nid = "1.0"\ndriver = "elsewhere/driver.py"\n',
        )
        version_dirpath = _version_dir(tmp_path, "p-1.0")
        files = resolve_target(project, "1.0")
        assert files.driver_filepath == tmp_path / "elsewhere" / "driver.py"
        assert files.binary_filepath == version_dirpath / "rom" / "p-1.0.rom"
        assert files.version_dirpath == version_dirpath
        assert files.source == "explicit"

    def test_unknown_target(self, tmp_path: Path) -> None:
        project = _project(
            tmp_path,
            '[[targets]]\nid = "a"\nbinary = "A"\n'
            'driver = "d.py"\nasm = "o.asm"\njson = "o.json"\n',
        )
        with pytest.raises(TargetNotFoundError, match="available: a"):
            resolve_target(project, "b")

    def test_bad_address(self, tmp_path: Path) -> None:
        project = _project(
            tmp_path,
            '[[targets]]\nid = "x"\nbinary = "X"\nload_address = "zz"\n'
            'driver = "d.py"\nasm = "o.asm"\njson = "o.json"\n',
        )
        with pytest.raises(TargetConfigError, match="hexadecimal"):
            resolve_target(project, "x")


class TestLayout:
    TOML = (
        '[project]\nname = "p"\n'
        "[layout]\n"
        'binary = "roms/{id}.rom"\n'
        'driver = "scripts/dis_{id_no_dots}.py"\n'
        'asm = "build/{id}.asm"\n'
        'json = "build/{id}.json"\n'
        "[[versions.entry]]\nid = \"1.20\"\n"
        "[[versions.entry]]\nid = \"1.30\"\nparents = [\"1.20\"]\n"
    )

    def test_templates(self, tmp_path: Path) -> None:
        project = _project(tmp_path, self.TOML)
        files = resolve_target(project, "1.30")
        assert files.source == "layout"
        assert files.binary_filepath == tmp_path / "roms" / "1.30.rom"
        assert files.driver_filepath == tmp_path / "scripts" / "dis_130.py"
        assert files.asm_filepath == tmp_path / "build" / "1.30.asm"
        assert files.load_address == 0x8000

    def test_graph_entries_are_targets(self, tmp_path: Path) -> None:
        project = _project(tmp_path, self.TOML)
        assert list_target_ids(project) == ["1.20", "1.30"]
        assert default_target_id(project) is None

    def test_unknown_id(self, tmp_path: Path) -> None:
        project = _project(tmp_path, self.TOML)
        with pytest.raises(TargetNotFoundError):
            resolve_target(project, "9.99")

    def test_discover(self, tmp_path: Path) -> None:
        project = _project(
            tmp_path,
            '[layout]\ndiscover = "roms/{id}.rom"\nbinary = "roms/{id}.rom"\n'
            'driver = "d_{id}.py"\nasm = "{id}.asm"\njson = "{id}.json"\n',
        )
        (tmp_path / "roms").mkdir()
        for name in ("a.rom", "b.rom", "notes.txt"):
            (tmp_path / "roms" / name).write_bytes(b"")
        assert discover_target_ids(project) == ["a", "b"]
        assert list_target_ids(project) == ["a", "b"]

    def test_discover_needs_exactly_one_id_token(self, tmp_path: Path) -> None:
        project = _project(tmp_path, '[layout]\ndiscover = "roms/*.rom"\n')
        with pytest.raises(TargetConfigError, match="exactly one"):
            discover_target_ids(project)

    def test_unknown_token(self, tmp_path: Path) -> None:
        project = _project(
            tmp_path,
            '[layout]\nbinary = "{nope}.rom"\n[[versions.entry]]\nid = "a"\n',
        )
        with pytest.raises(TargetConfigError, match="unknown or malformed"):
            resolve_target(project, "a")

    def test_unknown_layout_key(self, tmp_path: Path) -> None:
        project = _project(tmp_path, '[layout]\nbinaries = "x"\n')
        with pytest.raises(TargetConfigError, match="binaries"):
            list_target_ids(project)


class TestDefaultTarget:
    def test_configured_default(self, tmp_path: Path) -> None:
        project = _project(
            tmp_path,
            '[project]\nname = "p"\ndefault_target = "2.0"\n',
        )
        _version_dir(tmp_path, "p-1.0")
        _version_dir(tmp_path, "p-2.0")
        assert default_target_id(project) == "2.0"

    def test_configured_default_must_exist(self, tmp_path: Path) -> None:
        project = _project(
            tmp_path, '[project]\nname = "p"\ndefault_target = "nope"\n'
        )
        with pytest.raises(TargetConfigError, match="not a known target"):
            default_target_id(project)


def test_verify_settings_merge(tmp_path: Path) -> None:
    project = _project(
        tmp_path,
        '[verify]\ncommand = ["asm6502", "{asm}"]\ncwd = "{project_root}"\n'
        '[[targets]]\nid = "x"\nbinary = "X"\n'
        'driver = "d.py"\nasm = "o.asm"\njson = "o.json"\n'
        'verify = {output = "OUT"}\n',
    )
    settings = target_verify_settings(project, "x")
    assert settings == {
        "command": ["asm6502", "{asm}"],
        "cwd": "{project_root}",
        "output": "OUT",
    }
    # Sanity-check the fixture is valid TOML.
    tomllib.loads((tmp_path / "fantasm.toml").read_text())
