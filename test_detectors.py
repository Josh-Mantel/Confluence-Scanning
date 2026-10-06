"""Synthetic fixtures only; no real credentials or credential validation."""

import json
import unittest

from detectors import scan_html


class DetectorTests(unittest.TestCase):
    def rules(self, html):
        return {finding["rule"] for finding in scan_html(html)}

    def test_token_formats(self):
        examples = {
            "aws-access-key-id": "AKIA" + "A1B2C3D4E5F6G7H8",
            "github-token": "ghp_" + "a1B2" * 9,
            "gitlab-token": "glpat-" + "a1B2" * 5,
            "slack-token": "xoxb-123456789012-123456789012-a1B2c3D4e5F6",
            "jwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.a1B2c3D4e5F6g7H8",
        }
        for rule, value in examples.items():
            with self.subTest(rule=rule):
                self.assertIn(rule, self.rules("<pre>" + value + "</pre>"))

    def test_private_key_block(self):
        html = "<pre>-----BEGIN RSA PRIVATE KEY-----\nabc123\n-----END RSA PRIVATE KEY-----</pre>"
        self.assertEqual(self.rules(html), {"private-key"})

    def test_table_and_inline_formatting(self):
        html = """<table><tr><th>Setting</th><th>Value</th></tr>
        <tr><td>API <strong>token</strong></td>
        <td>a1B2c3D4e5F6g7H8</td></tr></table>"""
        findings = scan_html(html)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule"], "credential-assignment")
        self.assertEqual(findings[0]["line"], 2)

    def test_inline_code_and_entities(self):
        html = '<p>db.<strong>password</strong>=<code>&quot;sword&amp;fish42&quot;</code></p>'
        self.assertIn("credential-assignment", self.rules(html))

    def test_paragraphs_inside_table_cells(self):
        html = '<table><tr><td><p>password</p></td><td><p>swordfish42</p></td></tr></table>'
        self.assertIn("credential-assignment", self.rules(html))

    def test_confluence_storage_cdata(self):
        html = '<ac:plain-text-body><![CDATA[password=swordfish42]]></ac:plain-text-body>'
        self.assertIn("credential-assignment", self.rules(html))

    def test_json_camel_case_and_env_names(self):
        for source in ('"clientSecret": "a1B2c3D4e5F6"', "AT_PER_TOKEN=a1B2c3D4e5F6"):
            self.assertIn("credential-assignment", self.rules("<pre>" + source + "</pre>"))

    def test_url_credentials(self):
        self.assertIn("url-credentials", self.rules("<p>postgres://alice:swordfish42@db/service</p>"))

    def test_url_attributes_without_visible_credentials(self):
        html = '<p><a href="https://alice:swordfish42@host/path">Open</a></p>'
        self.assertIn("url-credentials", self.rules(html))
        html = '<img src="https://host/pixel?api_key=a1B2c3D4e5F6&amp;size=1" />'
        self.assertIn("credential-assignment", self.rules(html))
        html = '<a href="https://host/?api%5Fkey=a1B2c3D4e5F6">Link</a>'
        self.assertIn("credential-assignment", self.rules(html))

    def test_url_attributes_do_not_split_inline_text(self):
        html = '<p>pass<a href="https://host/">word</a>=swordfish42</p>'
        self.assertIn("credential-assignment", self.rules(html))

    def test_malformed_declarations_do_not_abort_scan(self):
        html = '<p>Introduction</p><![not-a-valid-declaration]><p>password=swordfish42</p>'
        self.assertIn("credential-assignment", self.rules(html))

    def test_ignored_script_style_and_comments(self):
        html = """<head><title>password=swordfish42</title></head>
        <script>password=swordfish42</script><style>password=swordfish42</style>
        <!-- password=swordfish42 --><p>Normal text.</p>"""
        self.assertEqual(scan_html(html), [])

    def test_placeholder_and_environment_references(self):
        for value in ("changeme", "[REDACTED]", "${AT_PER_TOKEN}", "$AT_PER_TOKEN",
                      "{{secrets.token}}", "%AT_PER_TOKEN%", "your_api_key", "********",
                      "os.getenv('AT_PER_TOKEN')", "process.env.AT_PER_TOKEN"):
            with self.subTest(value=value):
                self.assertEqual(scan_html("<pre>api_token=" + value + "</pre>"), [])
        self.assertEqual(scan_html("<p>" + "ghp_" + "x" * 36 + "</p>"), [])
        self.assertEqual(scan_html("<p>AKIAIOSFODNN7EXAMPLE</p>"), [])

    def test_non_secret_assignments(self):
        self.assertEqual(scan_html("<pre>token_type=Bearer\nusername=alice\nport=8080</pre>"), [])

    def test_output_never_includes_content(self):
        secret = "SYNTHETIC-a1B2c3D4e5F6"
        findings = scan_html("<p>password=" + secret + "</p>")
        self.assertEqual(len(findings), 1)
        self.assertNotIn(secret, json.dumps(findings))
        self.assertEqual(set(findings[0]), {"rule", "confidence", "line", "value"})
        self.assertEqual(findings[0]["value"], "[REDACTED]")

    def test_deduplication_and_text_line_numbers(self):
        findings = scan_html("<p>Introduction.</p><pre>password=a1B2c3D4\nsecret=e5F6g7H8</pre>")
        self.assertEqual([finding["line"] for finding in findings], [2, 3])
        findings = scan_html("<p>password=a1B2c3D4 secret=e5F6g7H8</p>")
        self.assertEqual(len(findings), 1)


if __name__ == "__main__":
    unittest.main()
