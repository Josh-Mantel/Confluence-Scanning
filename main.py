#!/usr/bin/env python3
"""Read accessible Confluence page HTML and report redacted secret candidates."""

import argparse
from datetime import datetime, timezone
from http.client import HTTPException
import json
import math
import os
from pathlib import Path
import re
import ssl
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit, urlunsplit
from urllib.request import build_opener, HTTPRedirectHandler, HTTPSHandler, Request

from detectors import scan_html


class ScanError(Exception):
    """A safe, fixed-message error suitable for a report."""


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # An SSO redirect must not receive the PAT or be mistaken for page HTML.
        return None


def base_url(value):
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        raise argparse.ArgumentTypeError("Invalid Confluence base URL.") from None
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
            or parsed.password is not None or parsed.query or parsed.fragment
            or any(c.isspace() or ord(c) < 32 for c in value)):
        raise argparse.ArgumentTypeError(
            "Use an HTTPS base URL without credentials, query, or fragment; "
            "include the context path if present, e.g. https://wiki.example/confluence."
        )
    if port == 0:
        raise argparse.ArgumentTypeError("Invalid port.")
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", ""))


class Client:
    def __init__(self, base, token, *, ca_bundle=None, delay=0.25, timeout=30,
                 max_bytes=20 * 1024 * 1024):
        self.base = base
        self.token = token
        self.delay = delay
        self.timeout = timeout
        self.max_bytes = max_bytes
        self.last_request = None
        try:
            context = ssl.create_default_context(cafile=ca_bundle)
        except (OSError, ssl.SSLError):
            raise ScanError("Cannot load CA certificates; check --ca-bundle.") from None
        self.opener = build_opener(NoRedirects(), HTTPSHandler(context=context))

    def get(self, endpoint, params):
        # Callers construct only fixed API paths, never server-provided next links.
        if not re.fullmatch(r"/rest/api/content(?:/[0-9]+)?", endpoint):
            raise ScanError("Unexpected API path.")
        url = self.base + endpoint + "?" + urlencode(params)
        for attempt in range(4):
            if self.last_request is not None:
                time.sleep(max(0, self.delay - (time.monotonic() - self.last_request)))
            self.last_request = time.monotonic()
            request = Request(url, headers={
                "Authorization": "Bearer " + self.token,
                "Accept": "application/json",
                "User-Agent": "confluence-secret-audit/1.0",
            }, method="GET")
            try:
                with self.opener.open(request, timeout=self.timeout) as response:
                    if response.headers.get_content_type() != "application/json":
                        raise ScanError("Expected JSON; a login/SSO page or proxy may be blocking the API.")
                    raw = response.read(self.max_bytes + 1)
                    if len(raw) > self.max_bytes:
                        raise ScanError("API response too large; lower --page-size or raise --max-response-mb.")
                try:
                    payload = json.loads(raw)
                except (ValueError, UnicodeError):
                    raise ScanError("API returned invalid JSON.") from None
                if not isinstance(payload, dict):
                    raise ScanError("Unexpected API response format.")
                return payload
            except HTTPError as exc:
                status = exc.code
                retry_after = exc.headers.get("Retry-After", "")
                exc.close()
                if status in (429, 502, 503, 504) and attempt < 3:
                    wait = min(30, int(retry_after)) if re.fullmatch(r"[0-9]{1,8}", retry_after) else 2 ** attempt
                    time.sleep(wait)
                    continue
                messages = {
                    401: "HTTP 401: PAT rejected or expired; check AT_PER_TOKEN.",
                    403: "HTTP 403: this account cannot read the requested API resource.",
                    404: "HTTP 404: check the base URL/context path and REST API availability.",
                }
                if 300 <= status < 400:
                    raise ScanError("Redirect refused; use the final HTTPS base URL and check SSO/API access.") from None
                raise ScanError(messages.get(status, "API request failed with HTTP " + str(status) + ".")) from None
            except (URLError, OSError, ValueError, HTTPException):
                # Do not echo exceptions, URLs, response bodies, or request headers.
                raise ScanError("Connection/TLS failure; check network access, base URL, and --ca-bundle.") from None
        raise ScanError("Retry limit exceeded.")


def content_id(item):
    value = str(item.get("id", ""))
    if not re.fullmatch(r"[0-9]+", value):
        raise ScanError("API returned a missing or invalid numeric content ID.")
    return value


def iter_content(client, content_type, space, page_size, representation):
    start = 0
    seen = set()
    while True:
        params = {
            "type": content_type, "status": "current", "start": start,
            "limit": page_size, "expand": "body." + representation,
        }
        if space:
            params["spaceKey"] = space
        payload = client.get("/rest/api/content", params)
        results = payload.get("results")
        links = payload.get("_links", {})
        if (not isinstance(results, list) or not isinstance(links, dict)
                or ("start" in payload and payload["start"] != start)):
            raise ScanError("Unexpected pagination response; scan is incomplete.")
        new_count = 0
        for item in results:
            if not isinstance(item, dict):
                raise ScanError("Unexpected content response.")
            page_id = content_id(item)
            if page_id in seen:
                continue
            new_count += 1
            seen.add(page_id)
            yield item
        if results and not new_count:
            raise ScanError("Pagination repeated a batch; scan is incomplete.")
        if not links.get("next"):
            return
        if not results:
            raise ScanError("Pagination returned an empty batch with a next link.")
        # Use the returned item count, even if the server silently caps page size.
        # Never follow an arbitrary URL supplied in _links.next.
        start += len(results)


def page_html(client, item, representation):
    for attempt in range(2):
        body = item.get("body", {})
        part = body.get(representation, {}) if isinstance(body, dict) else {}
        value = part.get("value") if isinstance(part, dict) else None
        if isinstance(value, str):
            return value
        if attempt == 0:
            item = client.get("/rest/api/content/" + content_id(item),
                              {"expand": "body." + representation})
    raise ScanError("Requested HTML body is missing; scan is incomplete.")


def inspected_findings(html):
    try:
        return scan_html(html)
    except (ValueError, AssertionError):
        # HTMLParser can include input in exception messages for malformed declarations.
        raise ScanError("Cannot parse page HTML; scan is incomplete.") from None


def positive_int(value):
    result = int(value)
    if result < 1:
        raise argparse.ArgumentTypeError("Must be at least 1.")
    return result


def nonnegative_float(value):
    result = float(value)
    if not math.isfinite(result) or result < 0:
        raise argparse.ArgumentTypeError("Must be a finite nonnegative number.")
    return result


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    source = result.add_mutually_exclusive_group(required=True)
    source.add_argument("--base-url", type=base_url, help="Confluence HTTPS root, including any /confluence context path")
    source.add_argument("--html-dir", type=Path, help="Scan saved .html/.htm files recursively, offline (no PAT needed)")
    result.add_argument("--space", help="Limit API scan to one space key, e.g. ENG")
    result.add_argument("--include-blogposts", action="store_true", help="Also scan current blog posts")
    result.add_argument("--body", choices=("view", "storage"), default="view", help="Confluence body representation (default: rendered view)")
    result.add_argument("--page-size", type=positive_int, default=25)
    result.add_argument("--max-pages", type=positive_int, default=1000, help="Maximum items/files scanned (default: 1000); additional items make the scan incomplete")
    result.add_argument("--delay", type=nonnegative_float, default=0.25, help="Minimum seconds between requests (default: .25)")
    result.add_argument("--timeout", type=positive_int, default=30)
    result.add_argument("--max-response-mb", type=positive_int, default=20)
    result.add_argument("--ca-bundle", help="PEM CA bundle for an internal certificate authority")
    result.add_argument("--output", type=Path, default=Path("confluence-findings.jsonl"), help="New JSON Lines report; existing files are never overwritten")
    return result


def run(args, out):
    def emit(record):
        out.write(json.dumps(record, ensure_ascii=True) + "\n")
        out.flush()

    pages_scanned = findings = 0
    complete = False
    emit({"record": "scan", "started_at": datetime.now(timezone.utc).isoformat(),
          "mode": "rest" if args.base_url else "offline_html", "body": args.body,
          "base_url": args.base_url, "include_blogposts": args.include_blogposts,
          "space": args.space, "max_pages": args.max_pages,
          "redacted": True, "line_reference": "extracted_text",
          "scope": "Current page bodies; blog posts only if requested. Saved HTML files in offline mode.",
          "limitations": "Heuristic candidates; no credential validation. Excludes attachments, comments, history, images, and inaccessible content."})
    try:
        if args.base_url:
            token = os.environ.get("AT_PER_TOKEN", "").strip()
            if not token or any(c.isspace() or ord(c) < 32 for c in token):
                raise ScanError("Set AT_PER_TOKEN to a nonempty PAT without whitespace.")
            client = Client(args.base_url, token, ca_bundle=args.ca_bundle,
                            delay=args.delay, timeout=args.timeout,
                            max_bytes=args.max_response_mb * 1024 * 1024)
            types = ["page", "blogpost"] if args.include_blogposts else ["page"]
            for kind in types:
                for item in iter_content(client, kind, args.space, args.page_size, args.body):
                    if pages_scanned >= args.max_pages:
                        raise ScanError("Page limit reached; increase --max-pages. Scan is incomplete.")
                    page_id = content_id(item)
                    location = {"page_id": page_id, "content_type": kind,
                                "url": args.base_url + "/pages/viewpage.action?pageId=" + page_id}
                    html = page_html(client, item, args.body)
                    for finding in inspected_findings(html):
                        emit({"record": "finding", **location, **finding})
                        findings += 1
                    pages_scanned += 1
                    if pages_scanned % 25 == 0:
                        print("Scanned {} items; {} candidates.".format(pages_scanned, findings), file=sys.stderr)
        else:
            if not args.html_dir.is_dir():
                raise ScanError("--html-dir must point to a directory.")
            paths = sorted(p for p in args.html_dir.rglob("*")
                           if p.suffix.lower() in (".html", ".htm") and p.is_file())
            if not paths:
                raise ScanError("No .html or .htm files found.")
            for path in paths:
                if pages_scanned >= args.max_pages:
                    raise ScanError("File limit reached; increase --max-pages. Scan is incomplete.")
                with path.open("rb") as source:
                    raw = source.read(args.max_response_mb * 1024 * 1024 + 1)
                if len(raw) > args.max_response_mb * 1024 * 1024:
                    raise ScanError("HTML file too large; raise --max-response-mb.")
                # Exported Confluence HTML is UTF-8. Fail explicitly on other encodings.
                html = raw.decode("utf-8-sig")
                for finding in inspected_findings(html):
                    emit({"record": "finding", "file": str(path.relative_to(args.html_dir)), **finding})
                    findings += 1
                pages_scanned += 1
        complete = True
    except ScanError as exc:
        emit({"record": "error", "message": str(exc)})
        print(str(exc), file=sys.stderr)
    except (OSError, UnicodeError):
        emit({"record": "error", "message": "Cannot read/write a local file or decode HTML as UTF-8."})
        print("Local file/encoding error; scan incomplete.", file=sys.stderr)
    except KeyboardInterrupt:
        emit({"record": "error", "message": "Interrupted; scan is incomplete."})
    finally:
        emit({"record": "summary", "finished_at": datetime.now(timezone.utc).isoformat(),
              "pages_scanned": pages_scanned, "findings": findings, "complete": complete})
    print("Scanned {} items; {} candidates; complete={}.".format(pages_scanned, findings, complete), file=sys.stderr)
    return 2 if not complete else (1 if findings else 0)


def main(argv=None):
    arg_parser = parser()
    args = arg_parser.parse_args(argv)
    if args.html_dir and (args.space or args.include_blogposts or args.ca_bundle or args.body != "view"):
        arg_parser.error("--space, --include-blogposts, --ca-bundle, and --body storage apply only to REST mode.")
    try:
        # Exclusive creation also prevents following an existing output symlink.
        descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        print("Report already exists; choose a different --output path.", file=sys.stderr)
        return 2
    except OSError:
        print("Cannot create report; check --output directory and permissions.", file=sys.stderr)
        return 2
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as out:
            return run(args, out)
    except OSError:
        print("Cannot write report; scan incomplete.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
