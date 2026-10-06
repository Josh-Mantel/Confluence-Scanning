"""Best-effort secret detection in visible HTML text, with redacted findings."""

import bisect
import re
from html.parser import HTMLParser
from urllib.parse import unquote


class HTMLExtractionError(ValueError):
    """The HTML could not be parsed; the exception contains no source content."""


class _TextParser(HTMLParser):
    _BLOCKS = {
        "address", "article", "aside", "blockquote", "br", "dd", "div", "dl",
        "dt", "fieldset", "figcaption", "figure", "footer", "form", "h1", "h2",
        "h3", "h4", "h5", "h6", "header", "hr", "li", "main", "nav", "ol",
        "p", "pre", "section", "table", "tr", "ul",
    }
    _IGNORED = {"head", "script", "style", "template"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []
        self.ignored = []
        self.cells = []
        self.table_depth = 0
        self.urls = []

    def _append(self, text):
        (self.cells[-1] if self.cells else self.parts).append(text)

    def handle_starttag(self, tag, attrs):
        if tag in self._IGNORED:
            self.ignored.append(tag)
        if self.ignored:
            return
        self.urls.extend(unquote(value) for name, value in attrs
                         if name in {"href", "src"} and value)
        if tag == "table":
            self.table_depth += 1
        if tag in {"td", "th"}:
            self.cells.append([])
            return
        if tag in self._BLOCKS:
            self._append(" " if self.cells else "\n")

    def handle_startendtag(self, tag, attrs):
        if not self.ignored and tag not in self._IGNORED:
            self.urls.extend(unquote(value) for name, value in attrs
                             if name in {"href", "src"} and value)
            if tag in self._BLOCKS:
                self._append(" " if self.cells else "\n")

    def handle_endtag(self, tag):
        if self.ignored:
            if tag == self.ignored[-1]:
                self.ignored.pop()
            return
        if tag in {"td", "th"}:
            # A table's label/value cells are an assignment boundary.
            if self.cells:
                self._append_cell()
        elif tag in self._BLOCKS:
            self._append(" " if self.cells else "\n")
        if tag == "table":
            self.table_depth = max(0, self.table_depth - 1)

    def _append_cell(self):
        content = "".join(self.cells.pop()).strip()
        self._append(content + "\t")

    def handle_data(self, data):
        if not self.ignored:
            if self.table_depth and not self.cells and not data.strip():
                return
            self._append(data)

    def unknown_decl(self, data):
        # Confluence storage format uses CDATA for code/plain-text macro bodies.
        if data[:6].upper() == "CDATA[":
            self.handle_data(data[6:])


def _extract_text(html):
    parser = _TextParser()
    try:
        parser.feed(html)
        parser.close()
    except (AssertionError, NotImplementedError):
        # Some Python versions reject unknown <![...] declarations. Escape
        # their opening marker and retry without changing valid CDATA blocks.
        parser = _TextParser()
        repaired = re.sub(r"<!\[(?!CDATA\[)", "&lt;![", html, flags=re.I)
        try:
            parser.feed(repaired)
            parser.close()
        except (AssertionError, NotImplementedError):
            raise HTMLExtractionError("Unsupported HTML structure") from None
    while parser.cells:
        parser._append_cell()
    text = "".join(parser.parts).strip()
    if parser.urls:
        text += "\n" + "\n".join(parser.urls)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return re.sub(r"\n[ \t]*\n+", "\n", text).strip()


_PATTERNS = (
    ("private-key", "high", re.compile(
        r"-----BEGIN (?P<kind>(?:(?:RSA|EC|DSA|OPENSSH|ENCRYPTED) )?PRIVATE KEY)-----"
        r"[\s\S]{1,100000}?-----END (?P=kind)-----"
    )),
    ("aws-access-key-id", "medium", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("github-token", "high", re.compile(
        r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{30,255})\b"
    )),
    ("gitlab-token", "high", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,255}\b")),
    ("slack-token", "high", re.compile(r"\bxox[aboprs]-[A-Za-z0-9-]{10,255}\b")),
    ("jwt", "medium", re.compile(
        r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"
    )),
)
_URL_CREDENTIALS = re.compile(
    r"\b[a-z][a-z0-9+.-]*://[^\s:/@]+:(?P<password>[^\s/@]+)@", re.I
)
_ASSIGNMENT = re.compile(
    r'''(?<![\w.-])(?P<quote>["']?)(?P<key>[A-Za-z_][A-Za-z0-9_. -]{0,80}?)'''
    r'''(?P=quote)[ \t]*(?:=|:|\t)[ \t]*'''
    r'''(?P<value>"[^"\r\n]{4,256}"|'[^'\r\n]{4,256}'|[^\s<>"',;]{4,256})'''
)
_QUERY_ASSIGNMENT = re.compile(
    r"[?&;](?P<key>[A-Za-z_][A-Za-z0-9_.-]{0,80})=(?P<value>[^&#;\s]{4,256})"
)
_SENSITIVE_ENDINGS = (
    "password", "passwd", "pwd", "secret", "token", "apikey", "accesskey",
    "privatekey", "authorization",
)
_PLACEHOLDERS = {
    "changeme", "change_me", "replace_me", "replaceme", "placeholder", "example",
    "sample", "dummy", "redacted", "[redacted]", "none", "null", "undefined",
    "password", "secret", "token", "your_password", "your_secret", "your_token",
    "your_api_key", "insert_here", "insert_token_here", "akiaiosfodnn7example",
}


def _is_placeholder(value):
    value = value.strip().strip("\"'")
    lower = value.lower()
    if lower in _PLACEHOLDERS:
        return True
    if lower.startswith(("os.environ", "os.getenv", "getenv(", "process.env.", "env(")):
        return True
    if re.match(r"^(?:\$\{?\w|%\w+%|\{\{|<)", value):
        return True
    if re.fullmatch(r"[xX*_.-]+", value):
        return True
    # Common redacted examples retain a recognizable token prefix.
    if re.fullmatch(r"(?:gh[pousr]_|github_pat_|glpat-|xox[aboprs]-)[xX*_.-]+", value):
        return True
    return False


def scan_html(html: str) -> list[dict]:
    """Return rule/confidence/text-line metadata, never matched values or context.

    Lines are one-based in normalized, extracted text followed by href/src URL
    attribute values (percent-decoded), not in the HTML source. No URLs are fetched.
    Findings are heuristic and do not establish that a credential is active.
    """
    text = _extract_text(html)
    newlines = [match.start() for match in re.finditer("\n", text)]
    findings = {}

    def add(rule, confidence, start):
        line = bisect.bisect_left(newlines, start) + 1
        findings[(line, rule)] = {
            "rule": rule,
            "confidence": confidence,
            "line": line,
            "value": "[REDACTED]",
        }

    for rule, confidence, pattern in _PATTERNS:
        for match in pattern.finditer(text):
            if not _is_placeholder(match.group()):
                add(rule, confidence, match.start())
    for match in _URL_CREDENTIALS.finditer(text):
        if not _is_placeholder(match.group("password")):
            add("url-credentials", "high", match.start())
    for pattern in (_ASSIGNMENT, _QUERY_ASSIGNMENT):
        for match in pattern.finditer(text):
            key = re.sub(r"[^a-z0-9]", "", match.group("key").lower())
            value = match.group("value")
            if key.endswith(_SENSITIVE_ENDINGS) and not _is_placeholder(value):
                add("credential-assignment", "medium", match.start())
    return [findings[key] for key in sorted(findings)]
