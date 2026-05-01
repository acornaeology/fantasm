"""Tests for ``fantasm.api.paths``."""

from __future__ import annotations

from pathlib import Path

import pytest

from fantasm.api import paths
from fantasm.config import ProjectContext


# --- resolve_version_dirpath ---------------------------------------


class TestResolveVersionDirpath:
    def test_single_prefix_match(self, tmp_path: Path) -> None:
        (tmp_path / "adfs-2.03").mkdir()
        result = paths.resolve_version_dirpath(tmp_path, "2.03", ["adfs"])
        assert result == tmp_path / "adfs-2.03"

    def test_first_prefix_wins(self, tmp_path: Path) -> None:
        # Both candidates exist; the first prefix in the list wins.
        (tmp_path / "anfs-3.10").mkdir()
        (tmp_path / "nfs-3.10").mkdir()
        result = paths.resolve_version_dirpath(
            tmp_path, "3.10", ["anfs", "nfs"]
        )
        assert result == tmp_path / "anfs-3.10"

    def test_falls_through_to_second_prefix(self, tmp_path: Path) -> None:
        (tmp_path / "nfs-3.10").mkdir()
        result = paths.resolve_version_dirpath(
            tmp_path, "3.10", ["anfs", "nfs"]
        )
        assert result == tmp_path / "nfs-3.10"

    def test_no_match_raises(self, tmp_path: Path) -> None:
        (tmp_path / "adfs-1.00").mkdir()
        (tmp_path / "adfs-2.03").mkdir()
        with pytest.raises(paths.VersionNotFoundError) as exc_info:
            paths.resolve_version_dirpath(tmp_path, "9.99", ["adfs"])
        err = exc_info.value
        assert err.version_id == "9.99"
        assert err.versions_dirpath == tmp_path
        assert err.available == ("adfs-1.00", "adfs-2.03")

    def test_no_prefixes_raises(self, tmp_path: Path) -> None:
        (tmp_path / "adfs-1.00").mkdir()
        with pytest.raises(paths.VersionNotFoundError):
            paths.resolve_version_dirpath(tmp_path, "1.00", [])

    def test_missing_versions_dir_raises_with_empty_available(
        self, tmp_path: Path
    ) -> None:
        missing = tmp_path / "does-not-exist"
        with pytest.raises(paths.VersionNotFoundError) as exc_info:
            paths.resolve_version_dirpath(missing, "1.00", ["adfs"])
        assert exc_info.value.available == ()

    def test_files_are_not_treated_as_versions(self, tmp_path: Path) -> None:
        # A file named adfs-2.03 should not be a match.
        (tmp_path / "adfs-2.03").write_text("not a directory")
        with pytest.raises(paths.VersionNotFoundError):
            paths.resolve_version_dirpath(tmp_path, "2.03", ["adfs"])


# --- rom_prefix -----------------------------------------------------


class TestRomPrefix:
    def test_simple_prefix(self) -> None:
        assert paths.rom_prefix(Path("adfs-2.03"), ["adfs"]) == "adfs"

    def test_first_match_wins(self) -> None:
        # When prefixes overlap, the order in the prefixes argument
        # decides.
        assert paths.rom_prefix(Path("anfs-3.10"), ["anfs", "nfs"]) == "anfs"
        assert paths.rom_prefix(Path("nfs-3.10"), ["anfs", "nfs"]) == "nfs"

    def test_multi_hyphen_prefix(self) -> None:
        # A prefix with embedded hyphens still matches as a unit.
        assert (
            paths.rom_prefix(
                Path("tube-6502-client-1.10"), ["tube-6502-client"]
            )
            == "tube-6502-client"
        )

    def test_fallback_to_pre_hyphen(self) -> None:
        # No configured prefix matches: returns everything before the
        # last hyphen as a best-effort fallback.
        assert paths.rom_prefix(Path("foo-1.0"), ["bar"]) == "foo"

    def test_fallback_no_hyphen(self) -> None:
        assert paths.rom_prefix(Path("solo"), ["bar"]) == "solo"


# --- Project-aware wrappers -----------------------------------------


def _make_project(tmp_path: Path, **config) -> ProjectContext:
    return ProjectContext(
        root_dirpath=tmp_path, config_filepath=None, config=config
    )


class TestProjectVersionsDirpath:
    def test_default_directory(self, tmp_path: Path) -> None:
        project = _make_project(tmp_path)
        assert paths.project_versions_dirpath(project) == tmp_path / "versions"

    def test_custom_directory(self, tmp_path: Path) -> None:
        project = _make_project(tmp_path, versions={"directory": "roms"})
        assert paths.project_versions_dirpath(project) == tmp_path / "roms"

    def test_unresolved_project_raises(self) -> None:
        empty = ProjectContext(root_dirpath=None)
        with pytest.raises(RuntimeError, match="Project root is not resolved"):
            paths.project_versions_dirpath(empty)


class TestProjectRomPrefixes:
    def test_explicit_list(self, tmp_path: Path) -> None:
        project = _make_project(
            tmp_path, versions={"prefixes": ["anfs", "nfs"]}
        )
        assert paths.project_rom_prefixes(project) == ("anfs", "nfs")

    def test_falls_back_to_project_name(self, tmp_path: Path) -> None:
        project = _make_project(tmp_path, project={"name": "adfs"})
        assert paths.project_rom_prefixes(project) == ("adfs",)

    def test_explicit_overrides_project_name(self, tmp_path: Path) -> None:
        project = _make_project(
            tmp_path,
            project={"name": "adfs"},
            versions={"prefixes": ["adfs", "legacy"]},
        )
        assert paths.project_rom_prefixes(project) == ("adfs", "legacy")

    def test_empty_when_unconfigured(self, tmp_path: Path) -> None:
        project = _make_project(tmp_path)
        assert paths.project_rom_prefixes(project) == ()


class TestResolveVersionDirpathForProject:
    def test_uses_project_config(self, tmp_path: Path) -> None:
        (tmp_path / "versions").mkdir()
        (tmp_path / "versions" / "anfs-3.10").mkdir()
        project = _make_project(
            tmp_path, versions={"prefixes": ["anfs", "nfs"]}
        )
        result = paths.resolve_version_dirpath_for_project(project, "3.10")
        assert result == tmp_path / "versions" / "anfs-3.10"

    def test_custom_versions_directory(self, tmp_path: Path) -> None:
        (tmp_path / "roms" / "adfs-2.03").mkdir(parents=True)
        project = _make_project(
            tmp_path,
            versions={"directory": "roms", "prefixes": ["adfs"]},
        )
        result = paths.resolve_version_dirpath_for_project(project, "2.03")
        assert result == tmp_path / "roms" / "adfs-2.03"

    def test_propagates_version_not_found(self, tmp_path: Path) -> None:
        (tmp_path / "versions").mkdir()
        project = _make_project(
            tmp_path, versions={"prefixes": ["anfs", "nfs"]}
        )
        with pytest.raises(paths.VersionNotFoundError):
            paths.resolve_version_dirpath_for_project(project, "9.99")


class TestRomPrefixForProject:
    def test_uses_project_config(self, tmp_path: Path) -> None:
        project = _make_project(
            tmp_path, versions={"prefixes": ["anfs", "nfs"]}
        )
        assert (
            paths.rom_prefix_for_project(project, Path("anfs-3.10"))
            == "anfs"
        )
        assert (
            paths.rom_prefix_for_project(project, Path("nfs-3.10"))
            == "nfs"
        )
