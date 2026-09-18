import unittest

from deepaudit.htmlreport import (bullets, code_block, document, esc, links, para, table,
                                  tag)

HOSTILE = '<script>alert(1)</script>"onload=x'


class Escaping(unittest.TestCase):
    def test_plain_values_are_escaped(self):
        self.assertNotIn("<script>", esc(HOSTILE))
        self.assertIn("&lt;script&gt;", esc(HOSTILE))

    def test_quotes_are_escaped_for_attribute_safety(self):
        self.assertNotIn('"', esc('a"b'))

    def test_paragraphs_escape_their_content(self):
        self.assertNotIn("<script>", para(HOSTILE))

    def test_table_cells_and_headers_escape(self):
        markup = table([HOSTILE], [[esc(HOSTILE)]])
        self.assertNotIn("<script>", markup)

    def test_code_blocks_escape_json_and_text(self):
        self.assertNotIn("<script>", code_block({"k": HOSTILE}))
        self.assertNotIn("<script>", code_block(HOSTILE))

    def test_tag_label_is_escaped_and_class_is_from_a_fixed_map(self):
        markup = tag(HOSTILE)
        self.assertNotIn("<script>", markup)
        self.assertIn("t-muted", markup, "an unknown label must not render as reassuring")

    def test_unknown_status_is_never_styled_as_resolved(self):
        self.assertNotIn("t-ok", tag("SOMETHING_NEW"))

    def test_only_http_urls_become_links(self):
        markup = links(["https://example.test/a", "javascript:alert(1)", HOSTILE])
        self.assertIn('href="https://example.test/a"', markup)
        self.assertNotIn("javascript:", markup.split("<code>")[0])
        self.assertNotIn('href="javascript:', markup)
        self.assertNotIn("<script>", markup)

    def test_document_escapes_title_and_subtitle(self):
        page = document(HOSTILE, HOSTILE, [para("body")])
        self.assertNotIn("<script>alert", page)
        self.assertTrue(page.startswith("<!doctype html>"))

    def test_document_is_self_contained(self):
        page = document("t", "s", [])
        self.assertIn("<style>", page)
        for external in ("http://", "https://", "<script"):
            self.assertNotIn(external, page, "reports open from file:// inside a zip")

    def test_bullets_preserve_supplied_markup_only(self):
        self.assertIn("<li>ok</li>", bullets(["ok"]))


if __name__ == "__main__":
    unittest.main()
