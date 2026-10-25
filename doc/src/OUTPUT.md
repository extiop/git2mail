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
and `[.]` (an informational listing line, used by the `email` report for
candidate accounts). The `[!]` warning lines on stderr are a stable,
grep-able signal (`^\[!\]`): a pipeline can detect capped or partial
runs without parsing the JSON.

Section headers like `============ ORG ============` and the `----`
separators are skippable decoration: screen readers and scripts can jump
straight to the marked lines.

The `scan` and `search` terminal reports end with a summary of the
**top 5 authors** by commit count (their dominant language included); the
complete author list is in the JSON report's `correlation.authors`.

## Exit codes

`0`: the run completed (an empty result is still a completed run: `email`
with no match, `org` with no public email). `1`: the run failed (a network, authentication or API error); note that an empty `scan` or
`search` result also exits `1` (the JSON report is still written when
`--json` was requested). `2`: the command line itself is invalid (clap
argument error).

## Layout

| Scan | Path |
|------|------|
| Repository (`scan --url …/repo`) | `results/repository/<owner>[_<repo>]` |
| Profile (`scan --url https://github.com/<user>`) | `results/profile/<user>` |
| Search (`search --query …`) | `results/keyword/<query>[_<language>]` |

## Text format (default)

One email address per line, sorted case-insensitively, deduplicated
across every scanned page and repository.

Addresses on the `users.noreply.github.com` domain (GitHub's alias addresses, which are not real mailboxes) are excluded from the results.

## JSON report (`--json <path>` or `--json -`)

The report does not record when it ran, which version produced it, or
which search qualifiers or `--variant-pattern` templates were used:
archive the exact command line next to the report (the file name only
carries the target). A `--json` path that is a symbolic link is refused
before the run (the atomic replace would destroy the link): write to a
timestamped file name and swap the symlink yourself.

`--json <path>` additionally writes a JSON report at the path you give (for example `--json report.json`). With `--json -`, the same JSON document is printed to stdout instead (only the JSON goes to stdout; the log stays on stderr), which makes the report pipeable into other tools.

```json
{
  "target": "<scan target>",
  "mode": "repository|profile|search",
  "emails": ["…"],
  "scanned": { "repos": 12, "pages": 30, "partial": false },
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
        "total_hits": 3
      }
    ]
  }
}
```

The report is written after the text output, at the end of the scan. The
`correlation` block groups the emails by commit author: for each author it
lists every address seen in their commits, the repositories they appear in
(with the repository's primary language; `language` is `null` for `scan`
runs, which do not spend an extra API call on it; only `search` fills it),
the languages ordered dominant
first (most commits, ties alphabetical), the repository where the author was first seen (with a parallel
multi-token scan this follows worker completion order and may vary between
runs), and the total number of hits. A commit without a detected (non-noreply) email is not
attributed; a commit with no author name is attributed under the email
itself.

`scanned.partial` is `true` when the scan stopped early (one of your tokens ran out or was refused mid-scan, so
  some listed repositories were never checked) and the reported emails may be incomplete; the matching
warning names the flag in the log. A report with `partial: true` must never
be mistaken for a complete one. Scans that run from start to finish always
report `partial: false` (they fail instead of reporting incompletely);
other limits (the commit page cap, the search limit) are announced by their
own warnings and do not set the flag.

## OSINT reports (`user`, `email`, `emails`, `org`)

The investigation subcommands write a JSON report to the path given by
`--json` (`org` also writes the same one-email-per-line text file as the
scan subcommands, at `results/org/<org>`):

- `user`: identity history, external contributions, generated email
  variants and the addresses they matched, potential secondary accounts,
  public SSH keys (full example blocks with every field in the README's
  investigation section);
- `org`: the report also carries a `correlation` object with the
  same per-author shape as the scan reports (person, emails, repositories
  and commit counts): the remediation view attributing an exposure to a
  person;
- `email` / `emails`: the reverse lookup, listing the candidate GitHub
  accounts with a confidence grade (`commit-author` when a commit of the
  candidate account carries the looked-up address, `repo-owner-weak` when
  the address matches a repository it owns), the candidate
  accounts considered, the commit that proved the match (repository, sha, author
  email), and the GitHub account owning the address (heuristic, capped
  at 50 candidate repositories per address); `org` additionally writes a
  text file `results/org/<org>` with one found email per line,
  ready to paste into a spreadsheet or outreach tool.

## File names

Scan targets become file names after sanitization:

- path separators and reserved characters (`/ \ : ? * " < > |`) and control or invisible characters are replaced by `_`; the directory component is sanitized too;
- trailing dots and spaces are stripped, and an empty name becomes `_`;
- Windows reserved device names (`CON`, `NUL`, `COM1`, …), with or without
  extension, are prefixed with `_` (`CON.txt` becomes `_CON.txt`);
- a name the sanitizer changed (and every name containing an uppercase letter) carries a 16-hex-digit hash of the raw name (`a/b` becomes
  `a_b-<hash>`, `Rust Lang` becomes `Rust Lang-<hash>`): distinct raw names
  that collapse onto the same sanitized form cannot silently overwrite each
  other, and case-only variants (`rust lang` vs `Rust Lang`) cannot clobber
  each other on a case-insensitive filesystem (a rerun of the same query
  still refreshes its own file by design);
- a name longer than 200 bytes is cut on a character boundary and carries
  the same hash (taken over the full raw name, so two distinct long queries sharing a prefix stay distinct), and the write can no longer fail after
  the scan completed.
