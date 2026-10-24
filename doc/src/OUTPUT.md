# Results

All output paths are relative to the **current working directory**
(`./results/…`), never to the location of the `git2mail` binary or of the
project source tree. The text output is skipped when a scan yields no
email; the `--json` report (if requested) is still written, with empty
`emails`.

## Layout

| Scan | Path |
|------|------|
| Repository (`scan --url …/repo`) | `results/repository/<owner>[_<repo>]` |
| Profile (`scan --url https://github.com/<user>`) | `results/profile/<user>` |
| Search (`search --query …`) | `results/keyword/<query>[_<language>]` |

## Text format (default)

One email address per line, sorted (ASCII case-insensitive), deduplicated
across every scanned page and repository.

Addresses containing a `noreply` domain marker are excluded from the
results.

## JSON report (`--json <path>`)

`--json <path>` additionally writes a JSON report at the path you give (for example `--json report.json`).

```json
{
  "target": "<scan target>",
  "mode": "repository|profile|search",
  "emails": ["…"],
  "scanned": { "repos": 12, "pages": 30 },
  "correlation": {
    "authors": [
      {
        "author": "Alice",
        "emails": ["alice@example.com"],
        "repos": [
          { "name": "a/one", "language": "Rust" },
          { "name": "b/two", "language": "Go" }
        ],
        "languages": ["Rust", "Go"],
        "first_seen_repo": "a/one",
        "total_hits": 3
      }
    ]
  }
}
```

The report is written after the text output, at the end of the scan. The
`correlation` block groups the emails by commit author: for each author it
lists every address seen in their commits, the repositories they appear in
(with the repository's primary language), the languages ordered dominant
first (most commits, ties alphabetical), the repository where the author was first seen, and the total
number of hits. A commit without an author name or a detected email is not
attributed.

## File names

Scan targets become file names after sanitization:

- path separators and reserved characters (`/ \ : ? * " < > |`) and control
  characters are replaced by `_`;
- trailing dots and spaces are stripped, and an empty name becomes `_`;
- Windows reserved device names (`CON`, `NUL`, `COM1`, …), with or without
  extension, are prefixed with `_` (`CON.txt` becomes `_CON.txt`).
