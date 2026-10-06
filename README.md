# Confluence secret candidate scanner
Using PAT, Atlassian introduced PAT support in Confluence 7.9. PATs inherit the account's permissions and authenticate REST requests using a Bearer header. Create one under your avatar → Settings → Personal access tokens. See [Atlassian's PAT documentation](https://confluence.atlassian.com/enterprise/using-personal-access-tokens-1026032365.html).

## Quick start

In macOS **zsh**, enter the PAT at a hidden prompt so its value is not written into shell history:

```zsh
cd ./Confluence-Scanning
read -rs 'AT_PER_TOKEN?Confluence PAT: '
echo
export AT_PER_TOKEN
python3 confluence_scan.py \
  --base-url 'https://wiki.example.com/confluence' \
  --space ENG \
  --output findings-eng.jsonl
unset AT_PER_TOKEN
```

Replace the example URL and space key. Include `/confluence` only if it is part of your site's base URL; do not pass an individual page URL. Omit `--space ENG` to scan all current pages visible to your account. Each run needs a new output filename.

For **bash**, replace the `read` and `echo` lines with:

```bash
read -r -s -p 'Confluence PAT: ' AT_PER_TOKEN
echo
```

The script reads the token from `AT_PER_TOKEN`; it does not load a `.env` file. Keep the export and scanner command in the same terminal session.

## Scope and options

The default scan enumerates current pages using `/rest/api/content` and requests `body.view`, the rendered HTML representation. It follows pagination within the configured instance. See the [Confluence Data Center REST API reference](https://developer.atlassian.com/server/confluence/rest/latest/).

| Option | Purpose |
| --- | --- |
| `--space ENG` | Restrict the scan to one space key. |
| `--include-blogposts` | Also scan current blog posts. |
| `--body storage` | Scan stored markup instead of rendered HTML. Useful for some code macros; its coverage differs from `view`. |
| `--max-pages 10000` | Raise the default cap of 1,000 pages/files. Remaining content after the cap makes the run incomplete. |
| `--page-size 10` | Request smaller API batches; default 25. |
| `--delay 0.5` | Minimum seconds between API requests; default 0.25. |
| `--ca-bundle /path/company-ca.pem` | Trust a PEM CA bundle for an internal certificate authority. HTTPS certificate verification stays enabled. |
| `--max-response-mb 40` | Raise the default 20 MiB response/file limit. |
| `--timeout 60` | Raise the default 30-second request timeout. |

The scanner refuses HTTP redirects. If your instance redirects to an SSO login page, check that the base URL is the final HTTPS URL and that your proxy permits PAT-authenticated REST access. HTTP 401 indicates rejected authentication; 403 indicates denied access; 404 can indicate an incorrect context path or unavailable API.

If the API is unavailable, scan saved UTF-8 HTML files offline. This recursively reads `.html` and `.htm` files without a PAT or network connection:

```sh
python3 confluence_scan.py \
  --html-dir '/path/to/saved-pages' \
  --output findings-offline.jsonl
```

## Reading the report

The JSON Lines report contains a scan record, finding records, any error record, and a final summary. Matched values are replaced by `[REDACTED]`; page text, snippets, and page titles are not included. API findings include a page ID and a link for manual review. Offline findings include a relative filename. URLs and filenames are retained as location metadata.

Each finding has a rule, confidence, and approximate location: `line` is one-based in normalized extracted text, including URL attributes, **not** the HTML source or the browser's visual lines. Repeated matches for the same rule on one extracted line produce one finding. The scanner creates reports exclusively, refuses to overwrite existing files, and uses owner-only permissions (`0600`) on POSIX systems.

| Exit code | Meaning |
| --- | --- |
| `0` | Scan completed with no candidates found. |
| `1` | Scan completed with candidates to review. |
| `2` | Scan was incomplete or could not start. Inspect the error and final summary, if written. |

Detection covers recognizable private-key blocks, several provider token formats, JWT-shaped strings, credentials in URLs, and common password/secret/token assignments, including table label/value pairs. Link and resource URL attributes are also inspected without fetching their targets. These are heuristic candidates: false positives and missed secrets are possible. The script never tests whether a credential works. A completed scan with no findings does not establish that the site contains no secrets.

Coverage excludes attachments, comments, historical versions, inaccessible pages, image contents, JavaScript, styles, non-URL HTML attributes, and content loaded only by client-side code. Rendered macros may expose only part of their underlying content. Offline coverage depends on which pages were saved and what their HTML contains.

## Local checks

From this directory, run the synthetic-fixture tests and inspect all options:

```sh
python3 -m unittest discover -v
python3 confluence_scan.py --help
```

The tests do not contact a live Confluence instance or validate real credentials.
