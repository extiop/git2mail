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

`--json` additionally writes a JSON report next to the text output:

```json
{
  "target": "<scan target>",
  "mode": "repository|profile|search",
  "emails": ["…"],
  "scanned": { "repos": 12, "pages": 30 }
}
```

The report is written after the text output, at the end of the scan.

## File names

Scan targets become file names after sanitization:

- path separators and reserved characters (`/ \ : ? * " < > |`) and control
  characters are replaced by `_`;
- trailing dots and spaces are stripped, and an empty name becomes `_`;
- Windows reserved device names (`CON`, `NUL`, `COM1`, …), with or without
  extension, are prefixed with `_` (`CON.txt` becomes `_CON.txt`).
