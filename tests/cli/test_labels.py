"""Tests for ``fantasm labels`` subcommands."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from fantasm.cli import main

from ._helpers import add_version, init_project


def _write_inventory_disasm(tmp_path: Path) -> None:
    """Lay down a project with one version + a JSON exercising
    driver labels, sub-labels, env labels, and inbound refs."""
    json_filepath = (
        tmp_path / "versions" / "demo-1.0" / "output" / "demo-1.0.json"
    )
    json_filepath.parent.mkdir(parents=True, exist_ok=True)
    json_filepath.write_text(
        json.dumps(
            {
                "meta": {"load_addr": 0x8000, "end_addr": 0x8100},
                "subroutines": [{"addr": 0x8000, "name": "init"}],
                "external_labels": {"oswrch": 0xFFEE},
                "items": [
                    {
                        "addr": 0x8000,
                        "type": "code",
                        "mnemonic": "lda",
                        "labels": ["init"],
                    },
                    {
                        "addr": 0x8002,
                        "type": "code",
                        "mnemonic": "jsr",
                        "target": 0xFFEE,
                        "labels": [],
                    },
                    {
                        "addr": 0x8005,
                        "type": "code",
                        "mnemonic": "jmp",
                        "target": 0x8000,
                        "labels": ["really_long_label_name_for_audit"],
                    },
                    {
                        "addr": 0x8008,
                        "type": "code",
                        "mnemonic": "rts",
                        "labels": ["c8008"],
                    },
                ],
            }
        )
    )


def test_labels_classify(tmp_path: Path) -> None:
    runner = CliRunner()
    init_project(tmp_path, runner, "demo", "demo")
    add_version(tmp_path, runner, "1.0", "demo")

    version_dirpath = tmp_path / "versions" / "demo-1.0"
    json_filepath = version_dirpath / "output" / "demo-1.0.json"
    json_filepath.parent.mkdir(exist_ok=True)
    json_filepath.write_text(
        json.dumps({
            "meta": {"load_addr": 0x8000, "end_addr": 0x8100},
            "subroutines": [{"addr": 0x8000, "name": "main"}],
            "items": [
                {
                    "addr": 0x8000,
                    "type": "code",
                    "mnemonic": "lda",
                    "labels": ["main"],
                },
                {
                    "addr": 0x8002,
                    "type": "code",
                    "mnemonic": "rts",
                    "labels": ["c8002"],
                },
            ],
        })
    )
    result = runner.invoke(
        main,
        [
            "--project-root", str(tmp_path),
            "labels", "classify", "1.0", "--as", "tsv",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "c8002" in result.output


def test_labels_apply_section_dry_run(tmp_path: Path) -> None:
    runner = CliRunner()
    driver_filepath = tmp_path / "driver.py"
    driver_filepath.write_text(
        "import py8dis\n"
        "\n"
        "# =================== Subroutines ===================\n"
        'subroutine(0x8000, "init")\n'
        "\n"
        "# Code label renames\n"
        'label(0x8010, "first")\n'
        'label(0x8020, "second")\n'
        "\n"
        "# =================== End ===================\n"
        "tail()\n"
    )
    renames_filepath = tmp_path / "renames.toml"
    renames_filepath.write_text(
        'renames = [\n'
        '  { addr = 0x8010, name = "renamed_first" },\n'
        '  { addr = 0x8030, name = "new_label" },\n'
        ']\n'
    )

    result = runner.invoke(
        main,
        [
            "labels", "apply",
            str(driver_filepath), str(renames_filepath),
            "--section", "--dry-run",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "renamed_first" in result.output
    assert "new_label" in result.output
    assert "renamed_first" not in driver_filepath.read_text()


def test_labels_apply_section_in_place(tmp_path: Path) -> None:
    runner = CliRunner()
    driver_filepath = tmp_path / "driver.py"
    driver_filepath.write_text(
        "# Code label renames\n"
        'label(0x8010, "first")\n'
    )
    renames_filepath = tmp_path / "renames.toml"
    renames_filepath.write_text(
        'renames = [{ addr = 0x8010, name = "renamed" }]\n'
    )
    result = runner.invoke(
        main,
        [
            "labels", "apply",
            str(driver_filepath), str(renames_filepath),
            "--section", "--in-place",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "renamed" in driver_filepath.read_text()


def test_labels_apply_missing_renames_array(tmp_path: Path) -> None:
    runner = CliRunner()
    driver_filepath = tmp_path / "driver.py"
    driver_filepath.write_text("# Code label renames\n")
    renames_filepath = tmp_path / "renames.toml"
    renames_filepath.write_text("# empty\n")
    result = runner.invoke(
        main,
        [
            "labels", "apply",
            str(driver_filepath), str(renames_filepath),
        ],
    )
    assert result.exit_code != 0
    assert "renames" in result.output


# --- labels apply --- inline (default) mode -----------------------


def test_labels_apply_inline_default_rewrites_scattered_decls(
    tmp_path: Path,
) -> None:
    runner = CliRunner()
    driver_filepath = tmp_path / "driver.py"
    driver_filepath.write_text(
        "import py8dis\n"
        "d = py8dis.Disassembler()\n"
        "\n"
        'd.label(0xA3FE, "return_from_2bit_index")\n'
        "# some inline comment\n"
        'd.label(0x853A, "return_from_advance_buf")\n'
        'label(0x9D70, "return_from_advance_y")\n'
    )
    renames_filepath = tmp_path / "renames.toml"
    renames_filepath.write_text(
        'renames = [\n'
        '  { addr = 0xA3FE, name = "rts_2bit_index" },\n'
        '  { addr = 0x853A, name = "rts_advance_buf" },\n'
        '  { addr = 0x9D70, name = "rts_advance_y" },\n'
        ']\n'
    )
    result = runner.invoke(
        main,
        [
            "labels", "apply",
            str(driver_filepath), str(renames_filepath),
            "--in-place",
        ],
    )
    assert result.exit_code == 0, result.output
    rewritten = driver_filepath.read_text()
    assert 'd.label(0xA3FE, "rts_2bit_index")' in rewritten
    assert 'd.label(0x853A, "rts_advance_buf")' in rewritten
    assert 'label(0x9D70, "rts_advance_y")' in rewritten
    assert "return_from_" not in rewritten


def test_labels_apply_inline_errors_on_missing_addr(tmp_path: Path) -> None:
    runner = CliRunner()
    driver_filepath = tmp_path / "driver.py"
    driver_filepath.write_text(
        'd.label(0x8000, "init")\n'
    )
    renames_filepath = tmp_path / "renames.toml"
    renames_filepath.write_text(
        'renames = [\n'
        '  { addr = 0x8000, name = "boot" },\n'
        '  { addr = 0x9999, name = "no_match" },\n'
        ']\n'
    )
    result = runner.invoke(
        main,
        [
            "labels", "apply",
            str(driver_filepath), str(renames_filepath),
            "--in-place",
        ],
    )
    assert result.exit_code != 0
    assert "0x9999" in result.output
    # Driver must not be partially rewritten.
    assert 'd.label(0x8000, "init")' in driver_filepath.read_text()


def test_labels_apply_inline_update_refs(tmp_path: Path) -> None:
    runner = CliRunner()
    driver_filepath = tmp_path / "driver.py"
    driver_filepath.write_text(
        'd.label(0xA3FE, "return_from_2bit_index")\n'
        'd.comment(0xA3FE, "branches into return_from_2bit_index here")\n'
        'description = """The return_from_2bit_index tail handles the\n'
        'common case."""\n'
        '# See [`return_from_2bit_index`](address:0xA3FE) for the tail.\n'
        '# A different identifier: return_from_2bit_index_helper stays put.\n'
    )
    renames_filepath = tmp_path / "renames.toml"
    renames_filepath.write_text(
        'renames = [{ addr = 0xA3FE, name = "rts_2bit_index" }]\n'
    )
    result = runner.invoke(
        main,
        [
            "labels", "apply",
            str(driver_filepath), str(renames_filepath),
            "--update-refs", "--in-place",
        ],
    )
    assert result.exit_code == 0, result.output
    rewritten = driver_filepath.read_text()
    assert 'd.label(0xA3FE, "rts_2bit_index")' in rewritten
    assert 'd.comment(0xA3FE, "branches into rts_2bit_index here")' in rewritten
    assert "The rts_2bit_index tail" in rewritten
    assert "[`rts_2bit_index`](address:0xA3FE)" in rewritten
    # Word-boundary: the longer identifier shouldn't be touched.
    assert "return_from_2bit_index_helper" in rewritten


def test_labels_apply_inline_rejects_update_refs_with_section(
    tmp_path: Path,
) -> None:
    runner = CliRunner()
    driver_filepath = tmp_path / "driver.py"
    driver_filepath.write_text(
        "# Code label renames\n"
        'label(0x8010, "first")\n'
    )
    renames_filepath = tmp_path / "renames.toml"
    renames_filepath.write_text(
        'renames = [{ addr = 0x8010, name = "second" }]\n'
    )
    result = runner.invoke(
        main,
        [
            "labels", "apply",
            str(driver_filepath), str(renames_filepath),
            "--section", "--update-refs",
        ],
    )
    assert result.exit_code != 0
    assert "inline mode" in result.output


# --- labels list --------------------------------------------------


def test_labels_list_lists_all_labels(tmp_path: Path) -> None:
    runner = CliRunner()
    init_project(tmp_path, runner, "demo", "demo")
    add_version(tmp_path, runner, "1.0", "demo")
    _write_inventory_disasm(tmp_path)

    result = runner.invoke(
        main,
        [
            "--project-root", str(tmp_path),
            "labels", "list", "1.0", "--as", "tsv",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "init" in result.output
    assert "oswrch" in result.output
    assert "c8008" in result.output
    assert "really_long_label_name_for_audit" in result.output


def test_labels_list_source_env_only(tmp_path: Path) -> None:
    runner = CliRunner()
    init_project(tmp_path, runner, "demo", "demo")
    add_version(tmp_path, runner, "1.0", "demo")
    _write_inventory_disasm(tmp_path)

    result = runner.invoke(
        main,
        [
            "--project-root", str(tmp_path),
            "labels", "list", "1.0",
            "--source", "env",
            "--as", "tsv",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "oswrch" in result.output
    assert "init" not in result.output
    assert "c8008" not in result.output


def test_labels_list_min_length_filter(tmp_path: Path) -> None:
    runner = CliRunner()
    init_project(tmp_path, runner, "demo", "demo")
    add_version(tmp_path, runner, "1.0", "demo")
    _write_inventory_disasm(tmp_path)

    result = runner.invoke(
        main,
        [
            "--project-root", str(tmp_path),
            "labels", "list", "1.0",
            "--min-length", "20",
            "--as", "tsv",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "really_long_label_name_for_audit" in result.output
    assert "init" not in result.output


def test_labels_list_match_regex(tmp_path: Path) -> None:
    runner = CliRunner()
    init_project(tmp_path, runner, "demo", "demo")
    add_version(tmp_path, runner, "1.0", "demo")
    _write_inventory_disasm(tmp_path)

    result = runner.invoke(
        main,
        [
            "--project-root", str(tmp_path),
            "labels", "list", "1.0",
            "--match", "^c[0-9a-f]+$",
            "--as", "tsv",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "c8008" in result.output
    assert "init" not in result.output
    assert "oswrch" not in result.output


def test_labels_list_invalid_regex_errors(tmp_path: Path) -> None:
    runner = CliRunner()
    init_project(tmp_path, runner, "demo", "demo")
    add_version(tmp_path, runner, "1.0", "demo")
    _write_inventory_disasm(tmp_path)

    result = runner.invoke(
        main,
        [
            "--project-root", str(tmp_path),
            "labels", "list", "1.0",
            "--match", "[unterminated",
        ],
    )
    assert result.exit_code != 0
    assert "regular expression" in result.output


def test_labels_list_sort_by_len_reverse(tmp_path: Path) -> None:
    runner = CliRunner()
    init_project(tmp_path, runner, "demo", "demo")
    add_version(tmp_path, runner, "1.0", "demo")
    _write_inventory_disasm(tmp_path)

    result = runner.invoke(
        main,
        [
            "--project-root", str(tmp_path),
            "labels", "list", "1.0",
            "--sort", "len", "--reverse",
            "--as", "tsv",
        ],
    )
    assert result.exit_code == 0, result.output
    lines = [
        line for line in result.output.splitlines()
        if line and not line.startswith("#")
    ]
    # Longest label first.
    assert lines[0].split("\t")[0] == "really_long_label_name_for_audit"


def _write_index_base_disasm(tmp_path: Path) -> None:
    """Project with schema-v2 references exercising the kind split.

    ``idx_tbl`` is read only as an indexing base (a pure
    d.index_base() candidate); ``mixed_tbl`` is read both directly
    and as an indexing base; ``vector_entry`` is a code item read as
    an indexing base (the caveat case)."""
    json_filepath = (
        tmp_path / "versions" / "demo-1.0" / "output" / "demo-1.0.json"
    )
    json_filepath.parent.mkdir(parents=True, exist_ok=True)
    json_filepath.write_text(
        json.dumps(
            {
                "meta": {
                    "load_addr": 0x8000,
                    "end_addr": 0x8100,
                    "schema_version": 2,
                },
                "items": [
                    {"addr": 0x8000, "type": "code", "mnemonic": "lda"},
                    {"addr": 0x8003, "type": "code", "mnemonic": "lda"},
                    {
                        "addr": 0x8080,
                        "type": "byte",
                        "mnemonic": "byte",
                        "labels": ["idx_tbl"],
                        "references": [{"addr": 0x8000, "kind": "indexed"}],
                    },
                    {
                        "addr": 0x8090,
                        "type": "byte",
                        "mnemonic": "byte",
                        "labels": ["mixed_tbl"],
                        "references": [
                            {"addr": 0x8000, "kind": "indexed"},
                            {"addr": 0x8003, "kind": "direct"},
                        ],
                    },
                    {
                        "addr": 0x80A0,
                        "type": "code",
                        "mnemonic": "rts",
                        "labels": ["vector_entry"],
                        "references": [{"addr": 0x8000, "kind": "indexed"}],
                    },
                ],
            }
        )
    )


def _tsv_rows(output: str) -> list[list[str]]:
    return [
        line.split("\t")
        for line in output.splitlines()
        if line and not line.startswith("#")
    ]


def test_labels_list_kind_split_columns(tmp_path: Path) -> None:
    runner = CliRunner()
    init_project(tmp_path, runner, "demo", "demo")
    add_version(tmp_path, runner, "1.0", "demo")
    _write_index_base_disasm(tmp_path)

    result = runner.invoke(
        main,
        [
            "--project-root", str(tmp_path),
            "labels", "list", "1.0", "--as", "tsv",
        ],
    )
    assert result.exit_code == 0, result.output
    # name  addr  source  len  refs  direct  indexed  code
    rows = {r[0]: r for r in _tsv_rows(result.output)}
    assert rows["idx_tbl"][4:8] == ["1", "0", "1", ""]
    assert rows["mixed_tbl"][4:8] == ["2", "1", "1", ""]
    # Code item read as an index base is flagged.
    assert rows["vector_entry"][7] == "yes"


def test_labels_list_index_base_only_filter(tmp_path: Path) -> None:
    runner = CliRunner()
    init_project(tmp_path, runner, "demo", "demo")
    add_version(tmp_path, runner, "1.0", "demo")
    _write_index_base_disasm(tmp_path)

    result = runner.invoke(
        main,
        [
            "--project-root", str(tmp_path),
            "labels", "list", "1.0", "--index-base-only",
            "--as", "tsv",
        ],
    )
    assert result.exit_code == 0, result.output
    names = {r[0] for r in _tsv_rows(result.output)}
    # Pure index-base candidates only; mixed_tbl has a direct read.
    assert names == {"idx_tbl", "vector_entry"}
    assert "mixed_tbl" not in names


def test_labels_list_sort_by_idx(tmp_path: Path) -> None:
    runner = CliRunner()
    init_project(tmp_path, runner, "demo", "demo")
    add_version(tmp_path, runner, "1.0", "demo")
    _write_index_base_disasm(tmp_path)

    result = runner.invoke(
        main,
        [
            "--project-root", str(tmp_path),
            "labels", "list", "1.0", "--sort", "idx", "--reverse",
            "--as", "tsv",
        ],
    )
    assert result.exit_code == 0, result.output
    rows = _tsv_rows(result.output)
    # Highest indexed count first (all the ,X readers of &8000).
    assert rows[0][0] in {"idx_tbl", "mixed_tbl", "vector_entry"}
    assert rows[0][6] == "1"


# --- labels refs --------------------------------------------------


def test_labels_refs_driver_label(tmp_path: Path) -> None:
    runner = CliRunner()
    init_project(tmp_path, runner, "demo", "demo")
    add_version(tmp_path, runner, "1.0", "demo")
    _write_inventory_disasm(tmp_path)

    result = runner.invoke(
        main,
        [
            "--project-root", str(tmp_path),
            "labels", "refs", "1.0", "init",
        ],
    )
    assert result.exit_code == 0, result.output
    # init is referenced by the jmp at &8005.
    assert "&8005" in result.output
    assert "jmp" in result.output


def test_labels_refs_env_label(tmp_path: Path) -> None:
    runner = CliRunner()
    init_project(tmp_path, runner, "demo", "demo")
    add_version(tmp_path, runner, "1.0", "demo")
    _write_inventory_disasm(tmp_path)

    result = runner.invoke(
        main,
        [
            "--project-root", str(tmp_path),
            "labels", "refs", "1.0", "oswrch",
        ],
    )
    assert result.exit_code == 0, result.output
    # oswrch is referenced by the jsr at &8002.
    assert "&8002" in result.output
    assert "jsr" in result.output


def test_labels_refs_missing_label_errors(tmp_path: Path) -> None:
    runner = CliRunner()
    init_project(tmp_path, runner, "demo", "demo")
    add_version(tmp_path, runner, "1.0", "demo")
    _write_inventory_disasm(tmp_path)

    result = runner.invoke(
        main,
        [
            "--project-root", str(tmp_path),
            "labels", "refs", "1.0", "no_such_label",
        ],
    )
    assert result.exit_code != 0
    assert "no_such_label" in result.output
