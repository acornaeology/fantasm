"""Tests for ``fantasm.api.project``."""

from __future__ import annotations

import tomllib
from pathlib import Path

import pytest

from fantasm.api.project import (
    ProjectInitConfig,
    VersionInfo,
    add_version,
    init_project,
    list_versions,
    render_fantasm_toml,
)


# --- ProjectInitConfig validation ---------------------------------


class TestProjectInitConfigValidation:
    def test_basic_construction(self) -> None:
        cfg = ProjectInitConfig(name="acorn-nfs", prefixes=("anfs", "nfs"))
        assert cfg.name == "acorn-nfs"
        assert cfg.prefixes == ("anfs", "nfs")
        assert cfg.cpu == "6502"

    def test_empty_name_rejected(self) -> None:
        with pytest.raises(ValueError, match="name is required"):
            ProjectInitConfig(name="", prefixes=("nfs",))

    def test_empty_prefixes_rejected(self) -> None:
        with pytest.raises(ValueError, match="prefix"):
            ProjectInitConfig(name="x", prefixes=())

    @pytest.mark.parametrize(
        "bad", ["foo bar", "foo/bar", "foo.bar", "", "foo!"]
    )
    def test_invalid_prefix_rejected(self, bad: str) -> None:
        with pytest.raises(ValueError, match="invalid prefix"):
            ProjectInitConfig(name="x", prefixes=(bad,))


# --- render_fantasm_toml ------------------------------------------


class TestRenderFantasmToml:
    def test_round_trips_through_tomllib(self) -> None:
        cfg = ProjectInitConfig(
            name="acorn-nfs", prefixes=("anfs", "nfs"), cpu="65c02"
        )
        rendered = render_fantasm_toml(cfg)
        parsed = tomllib.loads(rendered)
        assert parsed["project"]["name"] == "acorn-nfs"
        assert parsed["rom"]["cpu"] == "65c02"
        assert parsed["versions"]["prefixes"] == ["anfs", "nfs"]

    def test_omits_directory_when_default(self) -> None:
        cfg = ProjectInitConfig(name="x", prefixes=("x",))
        rendered = render_fantasm_toml(cfg)
        parsed = tomllib.loads(rendered)
        assert "directory" not in parsed.get("versions", {})

    def test_emits_directory_when_custom(self) -> None:
        cfg = ProjectInitConfig(
            name="x", prefixes=("x",), versions_dirname="roms"
        )
        rendered = render_fantasm_toml(cfg)
        parsed = tomllib.loads(rendered)
        assert parsed["versions"]["directory"] == "roms"

    def test_includes_comment_header(self) -> None:
        cfg = ProjectInitConfig(name="x", prefixes=("x",))
        assert render_fantasm_toml(cfg).lstrip().startswith("#")


# --- init_project --------------------------------------------------


class TestInitProject:
    def test_writes_toml_and_versions_dir(self, tmp_path: Path) -> None:
        cfg = ProjectInitConfig(name="acorn-nfs", prefixes=("anfs", "nfs"))
        toml_filepath = init_project(tmp_path, cfg)

        assert toml_filepath == tmp_path / "fantasm.toml"
        assert toml_filepath.exists()
        assert (tmp_path / "versions").is_dir()
        # Empty versions dir gets a .gitkeep so it's tracked.
        assert (tmp_path / "versions" / ".gitkeep").exists()

    def test_creates_root_if_missing(self, tmp_path: Path) -> None:
        target = tmp_path / "new_project"
        cfg = ProjectInitConfig(name="x", prefixes=("x",))
        toml_filepath = init_project(target, cfg)
        assert toml_filepath == target / "fantasm.toml"

    def test_refuses_overwrite_without_force(self, tmp_path: Path) -> None:
        cfg = ProjectInitConfig(name="x", prefixes=("x",))
        init_project(tmp_path, cfg)
        with pytest.raises(FileExistsError):
            init_project(tmp_path, cfg)

    def test_force_overwrites(self, tmp_path: Path) -> None:
        init_project(
            tmp_path,
            ProjectInitConfig(name="old", prefixes=("old",)),
        )
        init_project(
            tmp_path,
            ProjectInitConfig(name="new", prefixes=("new",)),
            force=True,
        )
        content = (tmp_path / "fantasm.toml").read_text()
        assert "new" in content
        assert "old" not in content

    def test_does_not_remove_existing_versions(self, tmp_path: Path) -> None:
        # Pre-existing versions dir with content should be preserved.
        (tmp_path / "versions" / "anfs-3.10").mkdir(parents=True)
        cfg = ProjectInitConfig(name="acorn-nfs", prefixes=("anfs", "nfs"))
        init_project(tmp_path, cfg)
        assert (tmp_path / "versions" / "anfs-3.10").is_dir()
        # Empty-dir .gitkeep is NOT created when entries already exist.
        assert not (tmp_path / "versions" / ".gitkeep").exists()


# --- add_version ---------------------------------------------------


class TestAddVersion:
    def test_creates_version_dir_with_subdirs(self, tmp_path: Path) -> None:
        versions = tmp_path / "versions"
        version_dirpath = add_version(versions, "3.10", "anfs")
        assert version_dirpath == versions / "anfs-3.10"
        assert (versions / "anfs-3.10" / "rom" / ".gitkeep").exists()
        assert (versions / "anfs-3.10" / "output" / ".gitkeep").exists()

    def test_creates_versions_dir_if_missing(self, tmp_path: Path) -> None:
        # versions/ doesn't exist yet — add should create it.
        version_dirpath = add_version(tmp_path / "versions", "1.0", "x")
        assert version_dirpath.is_dir()

    def test_refuses_existing(self, tmp_path: Path) -> None:
        (tmp_path / "anfs-3.10").mkdir()
        with pytest.raises(FileExistsError):
            add_version(tmp_path, "3.10", "anfs")

    def test_invalid_prefix(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="invalid prefix"):
            add_version(tmp_path, "1.0", "bad prefix")

    def test_empty_version_id(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="version_id"):
            add_version(tmp_path, "", "x")


# --- list_versions -------------------------------------------------


class TestListVersions:
    def test_filters_by_prefix(self, tmp_path: Path) -> None:
        for name in ("anfs-3.10", "nfs-3.10", "anfs-4.18", "scratch"):
            (tmp_path / name).mkdir()
        # Add a stray file to confirm it's not picked up.
        (tmp_path / "anfs-not-a-dir").write_text("")

        versions = list_versions(tmp_path, ("anfs", "nfs"))
        names = [(v.prefix, v.version_id) for v in versions]
        # Sorted by directory name.
        assert names == [
            ("anfs", "3.10"),
            ("anfs", "4.18"),
            ("nfs", "3.10"),
        ]

    def test_first_prefix_wins_when_overlapping(
        self, tmp_path: Path
    ) -> None:
        # If both "anfs" and "anfs-foo" are valid prefixes, the first
        # in the list wins for a name like "anfs-foo-bar".
        (tmp_path / "anfs-foo-bar").mkdir()
        versions = list_versions(tmp_path, ("anfs",))
        assert len(versions) == 1
        assert versions[0].version_id == "foo-bar"

    def test_missing_dir_returns_empty(self, tmp_path: Path) -> None:
        assert list_versions(tmp_path / "absent", ("nfs",)) == []

    def test_returns_dataclass(self, tmp_path: Path) -> None:
        (tmp_path / "x-1.0").mkdir()
        versions = list_versions(tmp_path, ("x",))
        assert isinstance(versions[0], VersionInfo)
