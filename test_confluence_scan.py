"""Offline transport and reporting tests using synthetic credentials only."""

from contextlib import redirect_stderr
from email.message import Message
from http.client import BadStatusLine, IncompleteRead
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
from urllib.error import HTTPError, URLError
from urllib.request import BaseHandler, build_opener
from urllib.response import addinfourl

import confluence_scan as scanner


BASE = "https://wiki.example/confluence"
PAT = "synthetic-pat-for-offline-tests"


def response(raw=b'{"results": []}', content_type="application/json", status=200):
    headers = Message()
    headers["Content-Type"] = content_type
    result = addinfourl(io.BytesIO(raw), headers, BASE, status)
    result.msg = "Mock response"
    return result


class PaginationTests(unittest.TestCase):
    def test_server_page_cap_and_untrusted_next_url(self):
        client = Mock()
        client.get.side_effect = [
            {"start": 0, "results": [{"id": "1"}, {"id": "2"}],
             "_links": {"next": "https://untrusted.example/collect"}},
            {"start": 2, "results": [{"id": "3"}], "_links": {}},
        ]
        items = list(scanner.iter_content(client, "page", "ENG", 100, "view"))
        self.assertEqual([item["id"] for item in items], ["1", "2", "3"])
        self.assertEqual([call.args[1]["start"] for call in client.get.call_args_list], [0, 2])
        for call in client.get.call_args_list:
            self.assertEqual(call.args[0], "/rest/api/content")
            self.assertEqual(call.args[1]["spaceKey"], "ENG")
            self.assertEqual(call.args[1]["limit"], 100)

    def test_empty_or_repeated_batches_cannot_report_completion(self):
        for batches, message in [
            ([{"results": [], "_links": {"next": "/next"}}], "empty batch"),
            ([{"results": [{"id": "1"}], "_links": {"next": "/next"}},
              {"results": [{"id": "1"}], "_links": {}}], "repeated a batch"),
        ]:
            with self.subTest(message=message):
                client = Mock()
                client.get.side_effect = batches
                with self.assertRaisesRegex(scanner.ScanError, message):
                    list(scanner.iter_content(client, "page", None, 25, "view"))

    def test_missing_body_falls_back_to_single_page_endpoint(self):
        client = Mock()
        client.get.return_value = {"id": "42", "body": {"view": {"value": "<p>Text</p>"}}}
        self.assertEqual(scanner.page_html(client, {"id": "42"}, "view"), "<p>Text</p>")
        client.get.assert_called_once_with("/rest/api/content/42", {"expand": "body.view"})
        client.get.return_value = {"id": "42"}
        with self.assertRaisesRegex(scanner.ScanError, "HTML body is missing"):
            scanner.page_html(client, {"id": "42"}, "view")


class ClientTests(unittest.TestCase):
    def client(self):
        client = scanner.Client(BASE, PAT, delay=0)
        client.opener = Mock()
        return client

    def test_pat_is_bearer_header_and_never_in_query(self):
        client = self.client()
        client.opener.open.return_value = response()
        self.assertEqual(client.get("/rest/api/content", {"start": 0}), {"results": []})
        request = client.opener.open.call_args.args[0]
        self.assertEqual(request.get_header("Authorization"), "Bearer " + PAT)
        self.assertEqual(request.get_method(), "GET")
        self.assertEqual(request.full_url, BASE + "/rest/api/content?start=0")
        self.assertNotIn(PAT, request.full_url)

    def test_redirect_statuses_never_issue_a_second_request(self):
        class FakeHTTPS(BaseHandler):
            handler_order = 100

            def __init__(self, status):
                self.status, self.requests = status, []

            def https_open(self, request):
                self.requests.append(request)
                result = response(status=self.status)
                result.headers["Location"] = "https://untrusted.example/collect"
                return result

        for status in (301, 302, 303, 307, 308):
            with self.subTest(status=status):
                client = self.client()
                transport = FakeHTTPS(status)
                client.opener = build_opener(scanner.NoRedirects(), transport)
                with self.assertRaisesRegex(scanner.ScanError, "Redirect refused"):
                    client.get("/rest/api/content", {})
                self.assertEqual(len(transport.requests), 1)
                self.assertTrue(transport.requests[0].full_url.startswith(BASE + "/"))

    def test_failure_messages_do_not_echo_body_exception_or_pat(self):
        private = "SYNTHETIC-PRIVATE-RESPONSE-" + PAT
        errors = [
            HTTPError(BASE, 403, private, Message(), io.BytesIO(private.encode())),
            URLError(private),
            BadStatusLine(private),
            IncompleteRead(private.encode(), len(private) + 1),
        ]
        for error in errors:
            with self.subTest(error=type(error).__name__):
                client = self.client()
                client.opener.open.side_effect = error
                with self.assertRaises(scanner.ScanError) as caught:
                    client.get("/rest/api/content", {})
                self.assertNotIn(private, str(caught.exception))
                self.assertNotIn(PAT, str(caught.exception))
        for raw, content_type in [(private.encode(), "application/json"),
                                  (private.encode(), "text/html")]:
            client = self.client()
            client.opener.open.return_value = response(raw, content_type)
            with self.assertRaises(scanner.ScanError) as caught:
                client.get("/rest/api/content", {})
            self.assertNotIn(private, str(caught.exception))

    def test_rate_limit_retry_is_bounded(self):
        client = self.client()
        headers = Message()
        headers["Retry-After"] = "99999999"
        client.opener.open.side_effect = [
            HTTPError(BASE, 429, "Rate limited", headers, io.BytesIO()) for _ in range(4)
        ]
        with patch.object(scanner.time, "sleep") as sleep:
            with self.assertRaisesRegex(scanner.ScanError, "HTTP 429"):
                client.get("/rest/api/content", {})
        self.assertEqual(client.opener.open.call_count, 4)
        self.assertTrue(all(call.args[0] <= 30 for call in sleep.call_args_list))


class ReportTests(unittest.TestCase):
    def run_report(self, arguments):
        output, stderr = io.StringIO(), io.StringIO()
        args = scanner.parser().parse_args(arguments)
        with redirect_stderr(stderr):
            code = scanner.run(args, output)
        return code, [json.loads(line) for line in output.getvalue().splitlines()], stderr.getvalue()

    def test_offline_report_is_redacted_recursive_and_needs_no_pat(self):
        secret = "SYNTHETIC-a1B2c3D4e5F6"
        with tempfile.TemporaryDirectory() as directory:
            nested = Path(directory, "nested")
            nested.mkdir()
            (nested / "page.HTML").write_text("<p>password=" + secret + "</p>", encoding="utf-8")
            (nested / "ignored.txt").write_text("password=" + secret, encoding="utf-8")
            with patch.dict(os.environ, {}, clear=True):
                code, records, stderr = self.run_report(["--html-dir", directory])
        self.assertEqual(code, 1)
        self.assertEqual(records[1]["file"], "nested/page.HTML")
        self.assertEqual(records[1]["value"], "[REDACTED]")
        self.assertEqual(records[-1]["pages_scanned"], 1)
        self.assertTrue(records[-1]["complete"])
        self.assertNotIn(secret, json.dumps(records) + stderr)

    def test_page_cap_is_incomplete_when_more_content_remains(self):
        items = [{"id": str(i), "body": {"view": {"value": "<p>Safe text</p>"}}}
                 for i in range(1, 3)]
        with patch.dict(os.environ, {"AT_PER_TOKEN": PAT}), patch.object(scanner, "Client") as client:
            client.return_value.get.return_value = {"results": items, "_links": {}}
            code, records, stderr = self.run_report(["--base-url", BASE, "--max-pages", "1"])
        self.assertEqual(code, 2)
        self.assertEqual(records[-1]["pages_scanned"], 1)
        self.assertFalse(records[-1]["complete"])
        self.assertIn("Page limit", records[-2]["message"])
        self.assertNotIn(PAT, json.dumps(records) + stderr)

    def test_missing_pat_or_missing_html_body_reports_incomplete(self):
        with patch.dict(os.environ, {}, clear=True):
            code, records, _ = self.run_report(["--base-url", BASE])
        self.assertEqual(code, 2)
        self.assertFalse(records[-1]["complete"])
        with patch.dict(os.environ, {"AT_PER_TOKEN": PAT}), patch.object(scanner, "Client") as client:
            client.return_value.get.side_effect = [{"results": [{"id": "42"}]}, {"id": "42"}]
            code, records, _ = self.run_report(["--base-url", BASE])
        self.assertEqual(code, 2)
        self.assertEqual(records[-1]["pages_scanned"], 0)
        self.assertFalse(records[-1]["complete"])

    def test_malformed_http_status_reports_incomplete_without_response_text(self):
        private = "SYNTHETIC-SENSITIVE-STATUS-" + PAT
        client = scanner.Client(BASE, PAT, delay=0)
        client.opener = Mock()
        client.opener.open.side_effect = BadStatusLine(private)
        with patch.dict(os.environ, {"AT_PER_TOKEN": PAT}), patch.object(scanner, "Client", return_value=client):
            code, records, stderr = self.run_report(["--base-url", BASE])
        self.assertEqual(code, 2)
        self.assertFalse(records[-1]["complete"])
        self.assertEqual(records[-2]["record"], "error")
        self.assertNotIn(private, json.dumps(records) + stderr)

    def test_html_parser_failure_does_not_echo_sensitive_input(self):
        private = "SYNTHETIC-SENSITIVE-HTML-a1B2c3D4"
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "page.html").write_text("<p>" + private + "</p>", encoding="utf-8")
            with patch.object(scanner, "scan_html", side_effect=AssertionError(private)):
                code, records, stderr = self.run_report(["--html-dir", directory])
        self.assertEqual(code, 2)
        self.assertFalse(records[-1]["complete"])
        self.assertEqual(records[-2]["record"], "error")
        self.assertNotIn(private, json.dumps(records) + stderr)

    def test_exclusive_output_does_not_overwrite_existing_file_or_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory, "existing.jsonl")
            target.write_text("existing content", encoding="utf-8")
            link = Path(directory, "link.jsonl")
            link.symlink_to(target)
            for output in (target, link):
                with redirect_stderr(io.StringIO()):
                    code = scanner.main(["--html-dir", directory, "--output", str(output)])
                self.assertEqual(code, 2)
                self.assertEqual(target.read_text(encoding="utf-8"), "existing content")


if __name__ == "__main__":
    unittest.main()
