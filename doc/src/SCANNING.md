# Scanning: `scan` & `search`

The two core subcommands recover email addresses from GitHub activity:
`scan` targets one repository or one profile, `search` runs a keyword
search and scans every matching repository.

## Scanning a repository or a profile

```bash
git2mail scan --url https://github.com/denoland/deno

git2mail scan --url https://github.com/denoland
```

Use a token to authenticate and fetch many more
commits:

```bash
git2mail scan --url "$TARGET_URL" --token "$YOUR_TOKEN"
```

A token passed with `--token` stays saved on your computer in the record
of commands you have typed, and other programs running at the same time
can see it: prefer `--token-file`, which reads the token(s) from a file
instead. When both are provided, `--token` wins for that run and a
warning is logged (a whitespace-only `--token` counts as absent and falls
back to `--token-file`).

If you don't have a token yet, you can still try the tool: simply leave
`--token` out. GitHub then allows only about 60 requests per hour, so a
token is recommended for any real scan.

### Repository URL rules

The repository URL must follow the following format:

```bash
git://github.com/some-user/my-repo[.git]
git@github.com:some-user/my-repo[.git]
https://github.com/some-user/my-repo[.git]
ssh://git@github.com/group/app[.git]
```

- Every URL must point at `github.com` (or `www.github.com`); any other
  host is rejected as an invalid URL before the scan runs. The API base
  is GitHub's, so a URL pointing at another server (a GitLab or Gitea
  remote, for instance) would otherwise be silently scanned against the
  github.com namesake.
- A trailing `.git` suffix is kept verbatim as part of the repository
  name: it is passed through to the GitHub API request and included in
  the output file name (`results/repository/some-user_my-repo.git.log`,
  the `.log` extension appended after the passthrough name). Since the
  GitHub API only resolves repository names without the suffix
  (`GET /repos/some-user/my-repo.git` answers 404, verified live), a
  scan with a `.git` URL always fails with "GitHub resource not found":
  the suffix documents a passthrough guarantee, not a usable input form:
  drop it before scanning.
- A trailing `/` on the URL is a leftover from copy-pasting, never part
  of the repository name: it is trimmed before the request
  (`https://github.com/some-user/my-repo/` targets `some-user/my-repo`,
  not the guaranteed-404 `my-repo%2F`). A link copied from a file
  browsing page (`/tree/<branch>/…`) targets a subfolder, not the
  repository root: paste the repository root URL instead. The other
  github.com page-navigation leftovers from copy-pasting
  (`?tab=repositories`, `?plain=1#L12`, `#readme`…) are stripped the
  same way, since no GitHub login or repository name contains `?` or
  `#`. The URL scheme is case-insensitive too:
  `HTTPS://GITHUB.COM/some-user/my-repo` parses exactly like its
  lowercase form (login/repository case is preserved).
- A profile URL has no name after its separator to trim, so a trailing
  `/` there is rejected as an invalid URL.

The profile URL must follow the following format:

```bash
git://github.com/some-user
git@github.com:some-user
https://github.com/some-user
ssh://git@github.com/some-user
```

### Result paths and provenance

With several tokens, make your own copy of `tokens.example.json` with
your tokens in it, to look through many more commits:

```bash
git2mail scan --url "$TARGET_URL" --token-file "$YOUR_TOKEN_FILE"
```

With dummy values:

```bash
git2mail scan --url https://github.com/denoland/deno --token-file tokens.json
```

In this mode, your results will be stored per profile with the following
relative path, from your current working directory:
`results/profile/$author.log`. If a repository is defined, it will be at
`results/repository/$author_$repository.log`. A name the tool had to
change (sanitized) carries a 16-hex-digit suffix derived from the
original name, so two different targets whose names collapse onto the
same sanitized file name cannot silently overwrite each other on a
case-sensitive filesystem; on a case-insensitive one (macOS, Windows),
two targets differing only by case share a file name. An unchanged name
keeps its exact file name, and the exact target is always printed with
every report. The run always prints the real path of every file it
writes. The JSON report records when it ran (`generated_at`), which
version produced it (`tool_version`) and, on a keyword search, the exact
query, language filter and qualifiers used (`request`); qualifiers are
GitHub's `key:value` search filters such as `stars:>100`, so two runs
with different qualifiers never write indistinguishable reports. Archive
the full command line next to the report for complete reproducibility
(`--variant-pattern` templates and file paths are not part of the
report).

To also get a JSON report (a structured text file you can open in any
text editor, and other software can read) in addition to the on-screen
results:

```bash
git2mail scan --url "$TARGET_URL" --json "$YOUR_REPORT_PATH"
```

Result files and JSON reports are written to a temporary file first,
then renamed, so a file is never left half-written even if you open it
while a scan is still running.

### The profile events timeline cap

GitHub caps the profile events timeline at 300 events (its documented
API ceiling): the scan never walks past the cap and a warning says so
when the cap cuts a prolific profile's listing, instead of the events
stage failing on the out-of-window request. When the events hold no
email, the scan falls back to the target's repositories' commits, as
always.

## Search: metadata as a keyword

You want to search, for instance, for some Rust developers that create
`nmap` related tools:

```bash
git2mail search --query nmap --language rust --token-file tokens.json
```

You can also limit the number of repositories scanned this way, for
instance:

```bash
git2mail search --query nmap --language rust --token-file tokens.json --limit 5
```

Without `--limit`, the search defaults to scanning 5 repositories.

In this mode, your results will be stored per query with the following
relative path, from your current working directory:
`results/keyword/$query.log`. If a language is defined, it will be at
`results/keyword/$query_$language.log`. As everywhere else, a name the
tool had to change (sanitized) carries a 16-hex-digit suffix derived
from the original name; the run always prints the real path of every
file it writes.

GitHub's repository search includes forks: like the profile and
organization investigations, forked repositories are skipped with a
warning (their commit history mirrors the upstream project's, so
scanning them would report other projects' developers under the fork's
name). Pass `--include-forks` to scan them too when the forks themselves
are your subject.

A keyword search scans several repositories, so its JSON report also
breaks the findings down per project: `per_repository` maps each
repository's `owner/name` to the emails its commits exposed (only the
repositories where at least one email showed up are listed, and the key
is omitted entirely when no repository produced one), and the `request`
object records the exact query, language filter and qualifiers that
produced the report (with `generated_at` and `tool_version`, two runs
with different qualifiers never write indistinguishable reports).

## Advanced search qualifiers

The `search` subcommand also accepts the optional qualifiers of
[GitHub's advanced search](https://github.com/search/advanced). They all
compose with `--query`, `--language` and `--limit`, and only the ones
you provide are appended to the GitHub query:

| Flag | Qualifier | Example values |
| --- | --- | --- |
| `--stars <RANGE>` | `stars:` | `>100`, `>=50`, `10..50`, `100..*` |
| `--forks <RANGE>` | `forks:` | `>10`, `5..20` |
| `--size <RANGE>` | `size:` | `>1000`, `100..5000` |
| `--created <DATE_RANGE>` | `created:` | `>2020-01-01`, `>=2020`, `2019-01-01..2020-01-01` |
| `--pushed <DATE_RANGE>` | `pushed:` | `>2024-01-01`, `>=2023` |
| `--license <ID>` | `license:` | `mit`, `apache-2.0` |
| `--topic <NAME>` | `topic:` | `osint`, `recon` |
| `--user <LOGIN>` | `user:` | `octocat` (mutually exclusive with `--org`) |
| `--org <LOGIN>` | `org:` | `acme` (mutually exclusive with `--user`) |

Quote range values that contain `>` or `<` so the shell does not read
them as redirections: `--stars '>100'`.

For instance, to scan well-established MIT-licensed Rust repositories of
one organization, recently pushed:

```bash
git2mail search --query nmap --language rust --stars '>100' --license mit --org acme --pushed '>2024-01-01' --token-file tokens.json
```

To target one user's repositories on a topic:

```bash
git2mail search --query nmap --topic osint --user octocat --token-file tokens.json
```

`--user` and `--org` are mutually exclusive (the GitHub search API
accepts only one owner filter). Values are validated client-side before
any request: an obviously malformed range or date (say `--stars abc` or
`--created 2020-13-01`) fails fast with a clear `invalid search filter`
error instead of silently returning no result from the API. Count and
date ranges follow the GitHub search range syntax (`>`, `>=`, `<`, `<=`,
`start..end`, with `*` for an open end); dates accept the `YYYY`,
`YYYY-MM` and `YYYY-MM-DD` granularities. An inverted range
(`--stars 50..10`, `--created 2020-01-01..2019-01-01`) is well-formed
but rejected client-side like every other malformed value; for dates
this matters because GitHub itself does not reject an inverted range: it
silently swaps the sides and quietly covers the opposite window. The
stricter name rules are validated client-side too: a `--user`/`--org`
value must be a valid GitHub login (ASCII letters, digits or hyphens; a
login with `.` or `_` would silently match nothing) and a
`--license`/`--topic` value must hold at least one alphanumeric
character (a separator-only `...` or `--` would silently match
nothing). Only one `--topic` value is accepted per run; to combine
topics, pass them in the query itself
(`--query "topic:osint topic:recon"`). The repository listing itself is
capped at GitHub's documented 1000-result search ceiling: the
over-ceiling page is never requested (the API answers it with a raw
422), so a query matching more than 1000 repositories scans at most the
first 1000. The qualifiers are not part of the output file name:
results are stored per query/language, so two runs differing only by
their qualifiers write to the same
`results/keyword/$query_$language.log` file, and the last run overwrites
the previous one. For a systematic sweep over qualifiers, give each run
its own `--json report-<qualifier>.json` path: the text file is the
working list, the JSON reports are the archive.

## Scripting notes

- Exit code `0` means the run completed, `1` that it failed, `2` that
  the command line itself was invalid, and `3` that the run completed
  but found nothing (an empty `scan`/`search` result): branch on `3` to
  tell "the target is live but carries no email" apart from a real
  failure.
- Only warnings and the report lines reach the terminal, and warnings
  go to stderr: a pipeline can detect a partial run by merging the
  streams and matching the `[!]` marker warnings carry, for example
  `git2mail … 2>&1 | grep '^\[!\]'` (PowerShell:
  `git2mail … 2>&1 | Select-String '^\[!\]'`).
- The exit codes and the on-disk layout are documented in
  [Reports & files on disk](OUTPUT.md); see also
  [Data quality, prevention & limitations](QUALITY.md) for what the
  reports can and cannot prove.

## Combining with other OSINT tools

This tool can be combined with other OSINT tooling. For instance, you
can use git2mail to retrieve Gmail addresses, then investigate some of
them further with [GHunt](https://github.com/mxrch/ghunt) (for lawful
research only, as everywhere in this guide).
