"""Tests for label:/glossary: inline-link validation helpers in lint."""
from fantasm.api.lint import (
    find_inline_scheme_links,
    glossary_slugs_from_markdown,
    valid_label_names_from_data,
)


class TestValidLabelNames:
    def test_collects_from_all_sources(self):
        data = {
            "meta": {"load_addr": 0x8000, "end_addr": 0x8010},
            "items": [
                {"addr": 0x8000, "labels": ["entry"],
                 "sub_labels": {"32770": ["hdr_byte2"]}},
            ],
            "subroutines": [{"addr": 0x8003, "name": "svc_handler"}],
            "memory_map": [{"addr": 0x0D3E, "name": "net_frame_flags"}],
            "index_bases": [{"addr": 0xA000, "name": "tbl_base"}],
            "external_labels": {"osrdsc": 0xFFB9},
        }
        names = valid_label_names_from_data(data)
        assert names == {"entry", "hdr_byte2", "svc_handler",
                         "net_frame_flags", "tbl_base", "osrdsc"}


class TestGlossarySlugs:
    def test_parses_headings_and_slugifies(self):
        md = ("**MOS** (Machine Operating System)\n: brief\n\n"
              "**Master 128**\n: brief\n\n"
              "**CMOS** (Complementary ...)\n: brief\n")
        assert glossary_slugs_from_markdown(md) == {"mos", "master-128", "cmos"}


class TestFindInlineSchemeLinks:
    def test_finds_label_and_glossary(self):
        text = ("see [x](label:print_cmos_pair) and "
                "[y](glossary:CMOS) here")
        links = find_inline_scheme_links(text)
        assert {(l["scheme"], l["name"]) for l in links} == {
            ("label", "print_cmos_pair"), ("glossary", "cmos")}

    def test_strips_version_and_flag_from_label(self):
        links = find_inline_scheme_links("[a](label:foo@3.60?hex)")
        assert links[0]["name"] == "foo"
        assert links[0]["target"] == "foo@3.60?hex"

    def test_reports_line_numbers(self):
        text = "line1\nline2 [a](label:foo)\n"
        assert find_inline_scheme_links(text)[0]["line_number"] == 2

    def test_ignores_address_scheme(self):
        assert find_inline_scheme_links("[a](address:E263)") == []
