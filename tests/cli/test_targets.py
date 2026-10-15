"""CLI tests for targets: optional TARGET, explicit layouts, verify
assembler configuration, driver environment and project onboarding."""

from __future__ import annotations

import json
import sys
import tomllib
from pathlib import Path

import pytest
from click.testing import CliRunner

from fantasm.cli import main

from ._helpers import add_version, init_project, write_minimal_disasm

ASM_TEXT = "\n.start\n    LDA #$00       ;8000:\n    RTS            ;8002:\n"

# A stand-in assembler: copies the bytes named on the listing's first
# line ("; BYTES <hex>") to the output path. Lets the verify tests run
# without beebasm.
FAKE_ASSEMBLER = '''\
import sys
from pathlib import Path
asm_filepath, output_filepath = Path(sys.argv[1]), Path(sys.argv[2])
first = asm_filepath.read_text().splitlines()[0]
if not first.startswith("; BYTES "):
    sys.stderr.write("no BYTES line\\n")
    sys.exit(3)
if len(sys.argv) > 3 and sys.argv[3] == "--no-output":
    sys.exit(0)
output_filepath.write_bytes(bytes.fromhex(first[len("; BYTES "):]))
'''

# A driver that records the environment fantasm passes it, and writes
# the expected outputs.
RECORDING_DRIVER = '''\
import json
import os
from pathlib import Path
env = {k: v for k, v in os.environ.items() if k.startswith("FANTASM_")}
env["cwd"] = os.getcwd()
Path(os.environ["FANTASM_JSON"]).write_text(json.dumps({
    "meta": {"load_addr": 0x1900, "end_addr": 0x1903},
    "items": [{"addr": 0x1900, "type": "code", "mnemonic": "rts"}],
    "subroutines": [],
    "recorded_env": env,
}))
Path(os.environ["FANTASM_ASM"]).write_text("; BYTES 60\\n")
'''


def _invoke(root_dirpath: Path, *args: str):
    return CliRunner().invoke(
        main, ["--project-root", str(root_dirpath), *args]
    )


def _single_version_project(tmp_path: Path) -> Path:
    runner = CliRunner()
    init_project(tmp_path, runner, "demo", "demo")
    add_version(tmp_path, runner, "1.0", "demo")
    version_dirpath = tmp_path / "versions" / "demo-1.0"
    (version_dirpath / "output" / "demo-1.0.asm").write_text(ASM_TEXT)
    write_minimal_disasm(version_dirpath, "demo", "1.0")
    return version_dirpath


def _explicit_project(tmp_path: Path, extra_toml: str = "") -> Path:
    """A project adopted as-is: disc/FS3 + FS3.inf, a driver, build/."""
    (tmp_path / "disc").mkdir()
    (tmp_path / "disc" / "FS3").write_bytes(b"\x60")
    (tmp_path / "disc" / "FS3.inf").write_text(
        "$.FS3 00001900 00001900 00000001 33\n"
    )
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "l3fs.py").write_text(RECORDING_DRIVER)
    (tmp_path / "assembler.py").write_text(FAKE_ASSEMBLER)
    result = CliRunner().invoke(
        main,
        [
            "project", "init", "--name", "l3fs", "--layout", "explicit",
            "--target", "fs3",
            "--binary", str(tmp_path / "disc" / "FS3"),
            "--driver", str(tmp_path / "src" / "l3fs.py"),
            "--asm", str(tmp_path / "build" / "l3fs.asm"),
            "--json", str(tmp_path / "build" / "l3fs.json"),
            "--at", str(tmp_path),
        ],
    )
    assert result.exit_code == 0, result.output
    toml_filepath = tmp_path / "fantasm.toml"
    toml_filepath.write_text(
        toml_filepath.read_text()
        + "\n[verify]\n"
        + f"command = [{json.dumps(sys.executable)}, "
        + f'{json.dumps(str(tmp_path / "assembler.py"))}, "{{asm}}", "{{output}}"]\n'
        + extra_toml
    )
    return tmp_path


class TestOptionalTarget:
    def test_help_shows_optional_target(self) -> None:
        result = CliRunner().invoke(main, ["cfg", "sub", "--help"])
        assert result.exit_code == 0
        assert "[TARGET] TARGET" in result.output

    def test_single_target_needs_no_argument(self, tmp_path: Path) -> None:
        _single_version_project(tmp_path)
        result = _invoke(tmp_path, "coverage")
        assert result.exit_code == 0, result.output

    def test_omitted_target_before_another_argument(
        self, tmp_path: Path
    ) -> None:
        _single_version_project(tmp_path)
        result = _invoke(tmp_path, "asm", "extract", "$8000")
        assert result.exit_code == 0, result.output
        assert "LDA" in result.output

    def test_named_target_still_works(self, tmp_path: Path) -> None:
        _single_version_project(tmp_path)
        result = _invoke(tmp_path, "asm", "extract", "1.0", "$8000")
        assert result.exit_code == 0, result.output
        assert "LDA" in result.output

    def test_omitted_target_with_options_between(
        self, tmp_path: Path
    ) -> None:
        _single_version_project(tmp_path)
        result = _invoke(tmp_path, "coverage", "--as", "tsv")
        assert result.exit_code == 0, result.output

    def test_ambiguity_lists_targets(self, tmp_path: Path) -> None:
        _single_version_project(tmp_path)
        add_version(tmp_path, CliRunner(), "2.0", "demo")
        result = _invoke(tmp_path, "coverage")
        assert result.exit_code == 2
        assert "2 targets: 1.0, 2.0" in result.output
        assert "default_target" in result.output

    def test_default_target(self, tmp_path: Path) -> None:
        _single_version_project(tmp_path)
        add_version(tmp_path, CliRunner(), "2.0", "demo")
        toml_filepath = tmp_path / "fantasm.toml"
        toml_filepath.write_text(
            toml_filepath.read_text().replace(
                '[project]\n', '[project]\ndefault_target = "1.0"\n'
            )
        )
        result = _invoke(tmp_path, "asm", "extract", "$8000")
        assert result.exit_code == 0, result.output

    def test_bad_default_target_is_a_usage_error(
        self, tmp_path: Path
    ) -> None:
        _single_version_project(tmp_path)
        toml_filepath = tmp_path / "fantasm.toml"
        toml_filepath.write_text(
            toml_filepath.read_text().replace(
                '[project]\n', '[project]\ndefault_target = "9"\n'
            )
        )
        result = _invoke(tmp_path, "coverage")
        assert result.exit_code == 2
        assert "not a known target" in result.output

    def test_help_does_not_need_a_target(self, tmp_path: Path) -> None:
        _single_version_project(tmp_path)
        add_version(tmp_path, CliRunner(), "2.0", "demo")
        result = _invoke(tmp_path, "coverage", "--help")
        assert result.exit_code == 0


class TestExplicitProject:
    def test_init_writes_targets_entry_from_inf(self, tmp_path: Path) -> None:
        _explicit_project(tmp_path)
        config = tomllib.loads((tmp_path / "fantasm.toml").read_text())
        assert "versions" not in config
        assert config["binary"]["cpu"] == "6502"
        (target,) = config["targets"]
        assert target == {
            "id": "fs3",
            "binary": "disc/FS3",
            "load_address": 0x1900,
            "exec_address": 0x1900,
            "driver": "src/l3fs.py",
            "asm": "build/l3fs.asm",
            "json": "build/l3fs.json",
        }
        assert not (tmp_path / "versions").exists()
        assert "# from disc/FS3.inf" in (tmp_path / "fantasm.toml").read_text()

    def test_disassemble_then_verify(self, tmp_path: Path) -> None:
        _explicit_project(tmp_path)
        result = _invoke(tmp_path, "disassemble")
        assert result.exit_code == 0, result.output
        data = json.loads((tmp_path / "build" / "l3fs.json").read_text())
        env = data["recorded_env"]
        assert env["FANTASM_TARGET"] == "fs3"
        assert env["FANTASM_BINARY"] == str(tmp_path / "disc" / "FS3")
        assert env["FANTASM_ROM"] == env["FANTASM_BINARY"]
        assert env["FANTASM_ASM"] == str(tmp_path / "build" / "l3fs.asm")
        assert env["FANTASM_JSON"] == str(tmp_path / "build" / "l3fs.json")
        assert env["FANTASM_OUTPUT_DIR"] == str(tmp_path / "build")
        assert json.loads(env["FANTASM_IMAGES"]) == [{
            "name": None,
            "path": str(tmp_path / "disc" / "FS3"),
            "load_addr": 0x1900,
            "exec_addr": 0x1900,
        }]

        result = _invoke(tmp_path, "verify")
        assert result.exit_code == 0, result.output
        assert "Verification PASSED: 1 bytes match" in result.output

        result = _invoke(tmp_path, "verify", "--all")
        assert result.exit_code == 0, result.output
        assert "fs3: PASSED" in result.output

    def test_driver_cwd(self, tmp_path: Path) -> None:
        _explicit_project(tmp_path)
        toml_filepath = tmp_path / "fantasm.toml"
        toml_filepath.write_text(
            toml_filepath.read_text().replace(
                'json = "build/l3fs.json"\n',
                'json = "build/l3fs.json"\ndriver_cwd = "src"\n',
            )
        )
        result = _invoke(tmp_path, "disassemble")
        assert result.exit_code == 0, result.output
        data = json.loads((tmp_path / "build" / "l3fs.json").read_text())
        assert Path(data["recorded_env"]["cwd"]).resolve() == (
            (tmp_path / "src").resolve()
        )

    def test_verify_mismatch(self, tmp_path: Path) -> None:
        _explicit_project(tmp_path)
        (tmp_path / "build").mkdir()
        (tmp_path / "build" / "l3fs.asm").write_text("; BYTES 61\n")
        result = _invoke(tmp_path, "verify")
        assert result.exit_code == 1
        assert "first_diff=&0000" in result.output

    def test_verify_assembler_error_names_assembler(
        self, tmp_path: Path
    ) -> None:
        _explicit_project(tmp_path)
        (tmp_path / "build").mkdir()
        (tmp_path / "build" / "l3fs.asm").write_text("nothing\n")
        result = _invoke(tmp_path, "verify")
        assert result.exit_code == 1
        assert "(python" in result.output and "error)" in result.output
        assert "no BYTES line" in result.output

    def test_verify_missing_output_is_clean(self, tmp_path: Path) -> None:
        _explicit_project(tmp_path)
        toml_filepath = tmp_path / "fantasm.toml"
        toml_filepath.write_text(
            toml_filepath.read_text().replace(
                '"{output}"]', '"{output}", "--no-output"]'
            )
        )
        (tmp_path / "build").mkdir()
        (tmp_path / "build" / "l3fs.asm").write_text("; BYTES 60\n")
        result = _invoke(tmp_path, "verify")
        assert result.exit_code == 2
        assert "did not produce an output file" in result.output
        assert "Traceback" not in result.output

    def test_verify_fixed_output_file(self, tmp_path: Path) -> None:
        """An assembler that writes a fixed file, e.g. via SAVE "NAME"."""
        _explicit_project(tmp_path)
        toml_filepath = tmp_path / "fantasm.toml"
        toml_filepath.write_text(
            toml_filepath.read_text().replace(
                '"{output}"]', '"{asm_dirpath}/FS3.out"]\noutput = "FS3.out"'
            )
        )
        (tmp_path / "build").mkdir()
        (tmp_path / "build" / "l3fs.asm").write_text("; BYTES 60\n")
        result = _invoke(tmp_path, "verify")
        assert result.exit_code == 0, result.output

    def test_unknown_assembler(self, tmp_path: Path) -> None:
        _explicit_project(tmp_path)
        toml_filepath = tmp_path / "fantasm.toml"
        text = toml_filepath.read_text()
        start = text.index("command = [")
        end = text.index("\n", start)
        toml_filepath.write_text(
            text[:start] + 'command = "no-such-asm {asm}"' + text[end:]
        )
        (tmp_path / "build").mkdir()
        (tmp_path / "build" / "l3fs.asm").write_text("; BYTES 60\n")
        result = _invoke(tmp_path, "verify")
        assert result.exit_code == 2
        assert "'no-such-asm' not found on PATH" in result.output

    def test_bad_verify_token(self, tmp_path: Path) -> None:
        _explicit_project(tmp_path, extra_toml='cwd = "{nope}"\n')
        (tmp_path / "build").mkdir()
        (tmp_path / "build" / "l3fs.asm").write_text("; BYTES 60\n")
        result = _invoke(tmp_path, "verify")
        assert result.exit_code == 2
        assert "unknown or malformed token" in result.output

    def test_lint_uses_target_driver(self, tmp_path: Path) -> None:
        _explicit_project(tmp_path)
        assert _invoke(tmp_path, "disassemble").exit_code == 0
        result = _invoke(tmp_path, "lint")
        assert result.exit_code == 0, result.output

    def test_project_list(self, tmp_path: Path) -> None:
        _explicit_project(tmp_path)
        result = _invoke(tmp_path, "project", "list", "--as", "tsv")
        assert result.exit_code == 0, result.output
        row = result.output.strip().splitlines()[-1].split("\t")
        assert row[:4] == ["fs3", "l3fs", "explicit", "&1900"]


class TestProjectAddExplicit:
    def test_add_appends_target(self, tmp_path: Path) -> None:
        _explicit_project(tmp_path)
        (tmp_path / "disc" / "FS3UTIL").write_bytes(b"\x00")
        result = _invoke(
            tmp_path, "project", "add", "util",
            "--binary", f"{tmp_path / 'disc' / 'FS3UTIL'}@&6800",
        )
        assert result.exit_code == 0, result.output
        config = tomllib.loads((tmp_path / "fantasm.toml").read_text())
        assert [t["id"] for t in config["targets"]] == ["fs3", "util"]
        util = config["targets"][1]
        assert util["load_address"] == 0x6800
        assert util["driver"] == "disasm_util.py"
        assert util["asm"] == "output/util.asm"
        # With two targets the TARGET argument is now required.
        result = _invoke(tmp_path, "coverage")
        assert "2 targets: fs3, util" in result.output

    def test_add_duplicate(self, tmp_path: Path) -> None:
        _explicit_project(tmp_path)
        result = _invoke(
            tmp_path, "project", "add", "fs3", "--binary", "X@1900"
        )
        assert result.exit_code == 2
        assert "already exists" in result.output

    def test_add_without_inf_or_address(self, tmp_path: Path) -> None:
        _explicit_project(tmp_path)
        (tmp_path / "disc" / "NOINF").write_bytes(b"\x00")
        result = _invoke(
            tmp_path, "project", "add", "x",
            "--binary", str(tmp_path / "disc" / "NOINF"),
        )
        assert result.exit_code == 2
        assert "PATH@ADDR" in result.output

    def test_add_version_directory_unchanged(self, tmp_path: Path) -> None:
        runner = CliRunner()
        init_project(tmp_path, runner, "demo", "demo")
        result = _invoke(tmp_path, "project", "add", "1.0")
        assert result.exit_code == 0, result.output
        assert (tmp_path / "versions" / "demo-1.0" / "rom").is_dir()


class TestProjectInitExplicit:
    def test_needs_binary(self, tmp_path: Path) -> None:
        result = CliRunner().invoke(
            main,
            ["project", "init", "--name", "x", "--layout", "explicit",
             "--at", str(tmp_path)],
        )
        assert result.exit_code == 2
        assert "needs --binary" in result.output

    def test_target_options_need_explicit_layout(self, tmp_path: Path) -> None:
        result = CliRunner().invoke(
            main,
            ["project", "init", "--name", "x", "--binary", "X@1900",
             "--at", str(tmp_path)],
        )
        assert result.exit_code == 2
        assert "need --layout explicit" in result.output

    def test_bad_inf_suggests_address(self, tmp_path: Path) -> None:
        (tmp_path / "PROG").write_bytes(b"\x00")
        (tmp_path / "PROG.inf").write_text("$.PROG Locked\n")
        result = CliRunner().invoke(
            main,
            ["project", "init", "--name", "x", "--layout", "explicit",
             "--binary", str(tmp_path / "PROG"), "--at", str(tmp_path)],
        )
        assert result.exit_code == 2
        assert "no load address found" in result.output
        assert "PATH@ADDR" in result.output

    def test_versions_layout_writes_binary_section(
        self, tmp_path: Path
    ) -> None:
        result = CliRunner().invoke(
            main, ["project", "init", "--name", "x", "--at", str(tmp_path)]
        )
        assert result.exit_code == 0, result.output
        config = tomllib.loads((tmp_path / "fantasm.toml").read_text())
        assert config["binary"] == {"cpu": "6502"}
        assert "rom" not in config


class TestMetadata:
    def _project(self, tmp_path: Path, metadata_text: str | None) -> None:
        _single_version_project(tmp_path)
        version_dirpath = tmp_path / "versions" / "demo-1.0"
        driver_dirpath = version_dirpath / "disassemble"
        driver_dirpath.mkdir()
        (driver_dirpath / "disasm_demo_10.py").write_text(
            'd.comment(0x8000, "x")\n'
        )
        if metadata_text is not None:
            (version_dirpath / "rom" / "rom.json").write_text(metadata_text)

    def test_missing_metadata_is_fine(self, tmp_path: Path) -> None:
        self._project(tmp_path, None)
        result = _invoke(tmp_path, "lint")
        assert result.exit_code == 0, result.output

    def test_malformed_metadata_is_a_clean_error(
        self, tmp_path: Path
    ) -> None:
        self._project(tmp_path, "{not json")
        result = _invoke(tmp_path, "lint")
        assert result.exit_code == 2
        assert "is not valid JSON" in result.output

    def test_bad_docs_shape(self, tmp_path: Path) -> None:
        self._project(tmp_path, '{"docs": ["a.md"]}')
        result = _invoke(tmp_path, "lint")
        assert result.exit_code == 2
        assert '"docs" must be a list' in result.output


@pytest.mark.parametrize("command", [["verify", "--all"]])
def test_verify_all_ignores_default_target(
    tmp_path: Path, command: list[str]
) -> None:
    _explicit_project(tmp_path)
    (tmp_path / "build").mkdir()
    (tmp_path / "build" / "l3fs.asm").write_text("; BYTES 60\n")
    result = _invoke(tmp_path, *command)
    assert result.exit_code == 0, result.output
