"""Tests for ``fantasm.api.inf``."""

from __future__ import annotations

from pathlib import Path

import pytest

from fantasm.api.inf import (
    InfParseError,
    inf_address,
    parse_inf,
    read_inf,
    sidecar_inf_filepath,
)


class TestFormats:
    def test_classic_dfs(self) -> None:
        record = parse_inf("$.ELITE     FF1900 FF8023 000400 L\n")
        assert record.filename == "$.ELITE"
        assert record.load_address_16() == 0x1900
        assert record.exec_address_16() == 0x8023
        assert record.length == 0x400
        assert record.locked

    def test_dfs_without_length_with_locked_and_crc(self) -> None:
        record = parse_inf("$.ELITE 001900 008023 Locked CRC=1A2B NEXT $.ELITE2")
        assert record.load_address_16() == 0x1900
        assert record.exec_address_16() == 0x8023
        assert record.length is None
        assert record.locked
        assert record.extras == {"CRC": "1A2B", "NEXT": "$.ELITE2"}

    def test_adfs_eight_digit_with_access_byte(self) -> None:
        record = parse_inf("FS3 00001900 00001900 00004C00 33\n")
        assert record.load_address_16() == 0x1900
        assert record.exec_address_16() == 0x1900
        assert record.length == 0x4C00
        assert record.access == "33"
        assert not record.locked

    def test_io_processor_high_bits(self) -> None:
        record = parse_inf("$.LOADER FFFF0E00 FFFF0E00 00000300 19 CRC=E4AB")
        assert record.load_address_16() == 0x0E00
        assert record.extras["CRC"] == "E4AB"

    def test_quoted_name_ampersand_hex_and_access_string(self) -> None:
        record = parse_inf('"My File" &1900 &8023 &400 LWR/r CRC32=0123ABCD')
        assert record.filename == "My File"
        assert record.load_address_16() == 0x1900
        assert record.length == 0x400
        assert record.access == "LWR/r"
        assert record.locked
        assert record.extras == {"CRC32": "0123ABCD"}

    def test_keyword_then_value_crc(self) -> None:
        record = parse_inf("$.X 1900 1900 CRC 1234")
        assert record.extras == {"CRC": "1234"}
        assert record.length is None

    def test_no_filename(self) -> None:
        record = parse_inf("&1900 &8023")
        assert record.filename is None
        assert record.load_address_16() == 0x1900

    def test_load_only(self) -> None:
        record = parse_inf("$.DATA 3000")
        assert record.load_address_16() == 0x3000
        assert record.exec_address_16() is None

    def test_crlf_bom_and_leading_blank_lines(self) -> None:
        record = parse_inf("﻿\r\n\r\n$.X FF1900 FF1900\r\n")
        assert record.load_address_16() == 0x1900


class TestErrors:
    def test_empty(self) -> None:
        with pytest.raises(InfParseError, match="empty"):
            parse_inf("   \n")

    def test_no_numbers(self) -> None:
        with pytest.raises(InfParseError, match="no load address"):
            parse_inf("$.X Locked", source="X.inf")

    def test_source_named_in_message(self) -> None:
        with pytest.raises(InfParseError, match="^X.inf: "):
            parse_inf("$.X", source="X.inf")

    def test_risc_os_stamp_rejected(self) -> None:
        record = parse_inf("!Boot FFFFEB12 34567890")
        assert record.load_address_16() == 0xEB12  # read as I/O processor
        record = parse_inf("!Run FFF8EB12 34567890")
        with pytest.raises(InfParseError, match="RISC OS"):
            record.load_address_16()

    def test_non_16_bit_rejected(self) -> None:
        with pytest.raises(InfParseError, match="not a 16-bit"):
            inf_address(0x031900)


def test_read_inf_and_sidecar(tmp_path: Path) -> None:
    binary_filepath = tmp_path / "FS3"
    binary_filepath.write_bytes(b"\x00")
    assert sidecar_inf_filepath(binary_filepath) is None
    (tmp_path / "FS3.inf").write_text("FS3 1900 1900\n")
    inf_filepath = sidecar_inf_filepath(binary_filepath)
    assert inf_filepath == tmp_path / "FS3.inf"
    assert read_inf(inf_filepath).load_address_16() == 0x1900


def test_sidecar_beside_extension(tmp_path: Path) -> None:
    binary_filepath = tmp_path / "FS3.bin"
    (tmp_path / "FS3.INF").write_text("FS3 1900 1900\n")
    found = sidecar_inf_filepath(binary_filepath)
    # Case-insensitive file systems may report either spelling.
    assert found is not None and found.name.lower() == "fs3.inf"


def test_read_missing_file(tmp_path: Path) -> None:
    with pytest.raises(InfParseError):
        read_inf(tmp_path / "missing.inf")
