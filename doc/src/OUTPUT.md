# Results

Results are always saved in a `results` folder inside the folder you ran the command from, not next to the git2mail program itself (`./results/…`). The text output is skipped when a scan yields no
email; the `--json` report (if requested) is still written, with empty
`emails`. These files hold personal data (real people's email addresses):
store and share them with the same care as the data itself, delete them
when you are done, and add `results/` to your `.gitignore` if you run the
tool inside a git repository.

## Terminal markers

Report lines start with one of four markers: `[+]` (a finding or a success),
`[!]` (a warning or an uncertain result), `[-]` (an error or an empty result)
and `[.]` (an informational listing line: the `email` report's candidate
accounts, the `user` report's secondary-account listings). The `[!]` warning lines on stderr are a stable,
grep-able signal (`^\[!\]`): a pipeline can detect partial runs without
parsing the JSON.

Section headers like `============ ORG ============` and the `----`
separators are skippable decoration: screen readers and scripts can jump
straight to the marked lines.

The `scan` and `search` terminal reports end with a summary of the
**top 5 authors** by commit count (their dominant language included); the
complete author list is in the JSON report's `correlation.authors`.

## Exit codes

`0`: the run completed (an empty result is still a completed run: `email`
with no match, `org` with no public email). `1`: the run failed (a
network, authentication or API error); a failed `emails` (bulk) run also
writes the partial report of the lookups it already paid for before
propagating the failure. `2`: the command line itself is invalid (clap
argument error). `3`: the run completed but found nothing (an empty
`scan` or `search` result: the target is live but carries no recoverable
email; the JSON report is still written when `--json` was requested), so
scripting can tell "live but empty" apart from a real failure.

## Layout

| Scan | Path |
|------|------|
| Repository (`scan --url …/repo`) | `results/repository/<owner>[_<repo>].log` |
| Profile (`scan --url https://github.com/<user>`) | `results/profile/<user>.log` |
| Search (`search --query …`) | `results/keyword/<query>[_<language>].log` |
| User investigation (`user <username>`) | `results/user/<username>.log` |
| Organization investigation (`org <org>`) | `results/org/<org>.log` |

Every text result file carries the `.log` extension so a double-click opens
it natively (Notepad, TextEdit, VS Code); the name before the extension is
the sanitized target name (see "File names" below). Each `.log` file is a
complete snapshot of its run, not an append-only log: a rerun replaces it
atomically.

## Startup proxy check

Before the first request, the run resolves the environment's proxy
variables with the same precedence rules as the HTTP stack, mirrored
conservatively: a value the check cannot vouch for is warned about
rather than trusted. What is actually
used is announced in the log, and a set-but-unusable variable is named
with a loud warning instead of the stack's silent fallback to a direct
connection; proxy variable values are never logged (a proxy URL can
carry embedded credentials), only names and schemes are. The full
semantics (variables, schemes, Tor, caveats) live in
[Network egress](API.md#network-egress-proxies-and-tor).

## Text format (default)

One email address per line, sorted case-insensitively, deduplicated
across every scanned page and repository.

Addresses on the `users.noreply.github.com` domain (GitHub's alias addresses, which are not real mailboxes) are excluded from the results.

## JSON report (`--json <path>` or `--json -`)

Every report stamps its own provenance: `generated_at` (the UTC
timestamp of the run, `YYYY-MM-DDTHH:MM:SSZ`) and `tool_version` (the
`git2mail --version` that wrote it). A `search` report additionally
records the request that produced it (`request.query`, `request.language`
and every advanced qualifier actually provided), so two runs with
different qualifiers never write indistinguishable reports. The report
still does not know the full command line (a `--variant-pattern` list or
a token file path, for instance): archive the exact command next to the
report for full reproducibility. A `--json` path that is a symbolic link
is refused before the run (the atomic replace would destroy the link):
write to a timestamped file name and swap the symlink yourself.

`--json <path>` additionally writes a JSON report at the path you give (for example `--json report.json`). With `--json -`, the same JSON document is printed to stdout instead (only the JSON goes to stdout; the log stays on stderr), which makes the report pipeable into other tools.

```json
{
  "target": "<scan target>",
  "mode": "repository|profile|search",
  "request": { "query": "nmap", "language": "rust", "qualifiers": { "stars": ">100" } },
  "emails": ["…"],
  "per_repository": { "owner/repo": ["email@example.com"] },
  "scanned": { "repos": 12, "pages": 30, "partial": false },
  "generated_at": "2026-02-14T18:22:33Z",
  "tool_version": "0.8.0",
  "correlation": {
    "authors": [
      {
        "author": "Alice",
        "emails": ["alice@example.com"],
        "repos": [
          { "name": "a/one", "language": "Rust" },
          { "name": "b/two", "language": null }
        ],
        "languages": ["Rust", "Go"],
        "first_seen_repo": "a/one",
        "total_hits": 3,
        "last_commit_date": "2024-06-01T12:00:00Z"
      }
    ]
  }
}
```

`request` appears only on a `search` report (the query provenance: the
qualifiers that were not provided are omitted, not `null`).

Forked repositories are skipped on the `user`, `org` and `search` subcommands (a warning names the
`--include-forks` opt-in when the skip fires). The reverse-email candidate search keeps forks: it
wants any repository carrying the address, including forks of the subject's own work.

`per_repository` appears on the parallel scans (a keyword search): it
maps each repository's `owner/name` to the emails found in its commits,
so a multi-repository run can be read per project without re-running it.
Only the repositories where at least one email showed up are listed, and
the key is omitted entirely when no repository produced one. The report is written after the text output, at the end of the scan. The
`correlation` block groups the emails by commit author: for each author it
lists every address seen in their commits, the repositories they appear in
(with the repository's primary language; `language` is `null` for `scan`
runs, which do not spend an extra API call on it; only `search` fills it),
the languages ordered dominant
first (most commits, ties alphabetical), the repository where the author was first seen (with a parallel
multi-token scan this follows worker completion order and may vary between
runs), and the total number of hits. `last_commit_date` is the most
recent commit author date seen for the author (the raw ISO 8601 UTC stamp
of the API payload): a freshness indicator for the exposure (self-declared,
forgeable commit metadata, exactly like the author name - never a proof).
`scan`, `search` and `org` can also
export this same per-author report as a CSV spreadsheet with `--csv
<path>` (one row per author: `author_name, emails, repositories,
dominant_language, commits`, multi-valued cells joined with `;`, RFC 4180
escaping so a hostile commit name cannot forge spreadsheet rows). A commit
without a detected (non-noreply) email is not
attributed; a commit with no author name is attributed under the email
itself.

`scanned.partial` is `true` when the scan stopped early (one of your tokens ran out or was refused mid-scan, so
  some listed repositories were never checked) and the reported emails may be incomplete; the matching
warning names the flag in the log. A report with `partial: true` must never
be mistaken for a complete one. Scans that run from start to finish always
report `partial: false` (they fail instead of reporting incompletely);
other limits (the search limit) are announced by their
own warnings and do not set the flag.

## OSINT reports (`user`, `email`, `emails`, `org`)

The investigation subcommands write a JSON report to the path given by
`--json` (`org` and `user` also write the same one-email-per-line text file
as the scan subcommands, at `results/org/<org>.log` and
`results/user/<username>.log`):

- `user`: identity history, external contributions, generated email
  variants and the addresses they matched, potential secondary accounts,
  public SSH keys (full example blocks with every field in
  [the user investigation guide](USER.md));
- `org`: the report also carries a `correlation` object with the
  same per-author shape as the scan reports (person, emails, repositories
  and commit counts): the remediation view attributing an exposure to a
  person;
- `email` / `emails`: the reverse lookup, listing the candidate GitHub
  accounts with a confidence grade (`commit-author` when a commit of the
  candidate account carries the looked-up address, `repo-owner-weak` when
  the address matches a repository it owns), the candidate
  accounts considered, the commit that proved the match (repository, sha, author
  email), and the GitHub account owning the address (heuristic: the search
  surfaces the candidate repositories, each verified over its full
  default-branch history, until a `commit-author` match ends the lookup
  early); `org` additionally writes a
  text file `results/org/<org>.log` with one found email per line,
  ready to paste into a spreadsheet or outreach tool. An `emails` (bulk)
  report carries `skipped_addresses` (an empty list on a clean run): on an
  interrupted run it is the file-order list of the addresses a stopped
  worker never reached (the `summary.skipped` count is this list's
  length), so re-running the interrupted lookups needs no diff of two
  files. Every report carries `generated_at` and `tool_version`. The bulk
  run has no CSV deliverable (its report carries no per-author
  correlation): the `--json` report is its file output. On the other
  subcommands (`user`, `email`, `emails`) `--csv` is accepted, warned
  about, and ignored.

## Developer correlation

Every scan also aggregates its results per author: for each author found
in the scanned commits, it correlates the attributes git2mail already
collects: the emails they used, the repositories they were seen in with
their primary language, the first repository where they appeared and
their total commit count. Authors are sorted by commit count and each
author's languages are ordered dominant first, so the report answers
"who are the main developers behind this topic, and what do they write
in?". With a parallel multi-token scan, the repository order (and the
"first seen" field) follows worker completion and may vary between runs;
the email sets and counts do not.

For a copy-paste list of addresses, use the plain-text `results/` file
(one email per line, ready for a spreadsheet); the names, languages and
per-repository counts live in the JSON report, or as a `--csv`
spreadsheet (one row per developer: name, emails, repositories,
dominant language, commit count).

The report lives in the opt-in `--json` output, as a `correlation` object
added on top of the unchanged legacy fields (the plain-text result files
stay byte-identical):

```bash
git2mail search --query nmap --language rust --token-file tokens.json --json report.json
```

```json
{
  "target": "nmap",
  "mode": "search",
  "emails": ["alice@example.com"],
  "scanned": { "repos": 2, "pages": 3, "partial": false },
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
        "total_hits": 3,
        "last_commit_date": "2024-06-01T12:00:00Z"
      }
    ]
  }
}
```

`scanned.partial` is `true` when the parallel scan kept its findings
although a dedicated token died mid-scan (whole listed repositories may
then have been left unscanned): the JSON report keeps `partial: true`
even when the run itself exits 0.

The primary language comes free with the repository-search metadata, so
`search` runs attribute a language to every repository that has a
detected primary language (GitHub reports `language: null` when it has
none, and the report passes it through, like `scan` (repository/profile)
runs which do not spend an extra API call on it). The same author seen
in several repositories (across pages, workers or scan stages) is
merged: emails deduplicated, hit counts summed. The terminal log also
prints a short summary of the top 5 authors (by commit count) with their
dominant language; the full author list lives in the JSON report's
`correlation.authors`, and the plain-text result files keep the legacy
one-email-per-line format, byte-identical.

## File permissions

Result and report files hold personal data, so a FIRST publish creates
them readable by the owner only (`0600` on Unix) instead of the usual
world-readable default; republishing preserves a mode you set on an
existing file (a tightened `0600` or a deliberately shared `0644`).

## File names

Scan targets become file names after sanitization:

- path separators and reserved characters (`/ \ : ? * " < > |`) and control or invisible characters are replaced by `_`; the directory component is sanitized too;
- trailing dots and spaces are stripped, and an empty name becomes `_`;
- Windows reserved device names (`CON`, `NUL`, `COM1`, …), with or without
  extension, are prefixed with `_` (`CON.txt` becomes `_CON.txt`);
- a name the sanitizer changed carries a 16-hex-digit hash of the raw name (`a/b` becomes
  `a_b-<hash>`): distinct raw names that collapse onto the same sanitized
  form cannot silently overwrite each other (a rerun of the same query
  still refreshes its own file by design). An unchanged name keeps its
  exact file name, whatever its case; on a case-insensitive filesystem
  (macOS APFS, Windows NTFS) two targets differing only by case share one
  file name - the exact target is visible in every report line and in the
  JSON report;
- a name longer than 200 bytes is cut on a character boundary and carries
  the same hash (taken over the full raw name, so two distinct long queries sharing a prefix stay distinct), and the write can no longer fail after
  the scan completed.
