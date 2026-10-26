# Organization investigation (`org`)

The `org` subcommand investigates one GitHub organization: its public
members, its public repositories and the developers' emails found
scanning them.

```bash
git2mail org "acme" --token-file tokens.json
```

As with the user investigation, a token is strongly recommended: an org
scan walks every listed repository and aborts on a spent anonymous
allowance. Forked repositories are skipped with a warning (like the
`user` investigation): their commit history mirrors the upstream
project's, so scanning them would report other projects' developers.
Pass `--include-forks` to scan them too when the forks themselves are
your subject.

It accepts the shared `--token`/`--token-file`/`--json` flags plus an
optional `--limit N` capping the number of scanned repositories (all of
them by default), and reports, both in the terminal log (ORG / MEMBERS /
REPOSITORIES / EMAILS) and in the opt-in JSON report.

## What the investigation collects

- **Org**: the `GET /orgs/{org}` fields that carry OSINT value (login,
  name, blog). A missing organization is a clean not-found error.
- **Members**: the organization's publicly visible member usernames
  (just names on GitHub, no contact details; many companies hide this
  list entirely, and the endpoint only lists members who chose to
  publicize: a short list is not a malfunction). The emails below come
  from the repositories' commits, not from these members. To investigate
  one member, run `git2mail user <username>`.
- **Repositories**: the public repositories (`GET /orgs/{org}/repos`,
  paginated).
- **Emails**: the developers' emails found scanning the organization's
  repositories' commits with the same worker-per-token parallelism as
  the parallel `search`, reported per repository and globally (noreply
  addresses excluded, like every scan). The found addresses are also
  saved to `results/org/<org>.log`, one per line, the same paste-able
  file the scan subcommands write. For an exposure audit, the
  `per_repository` map is the finding: it tells you which repository
  leaks which addresses; attribute a person to an address with
  `git2mail email <address>` before contacting them.

## JSON report shape

With `--json`, the report carries the documented shape:

```json
{
  "generated_at": "2026-02-14T18:40:12Z",
  "tool_version": "0.7.0",
  "org": { "login": "acme", "name": "Acme Corp", "blog": "https://acme.example" },
  "members": ["alice", "bob"],
  "repositories": ["one", "two"],
  "emails": {
    "per_repository": { "acme/one": ["alice@acme.com"], "acme/two": ["bob@acme.com"] },
    "all": ["alice@acme.com", "bob@acme.com"]
  },
  "correlation": {
    "authors": [
      {
        "author": "Alice", "emails": ["alice@acme.com"], "total_hits": 1,
        "repos": [{ "name": "acme/one", "language": null }],
        "first_seen_repo": "acme/one",
        "last_commit_date": "2024-06-01T12:00:00Z"
      }
    ]
  },
  "scanned": { "repos": 2, "pages": 9 }
}
```

`per_repository` is keyed by the `owner/name` full names the scan
reports, and only lists the repositories where at least one email showed
up; `scanned.pages` counts the successful API requests of the whole
investigation (org info, members, repositories listing and the workers'
commit pages). The `correlation` object follows the same shape as the
scan and search reports, aggregating the developers found across the
organization's repositories. A repository that is private, deleted or
empty is skipped with a warning; a rate-limit or transport failure
aborts the investigation, and so does a dedicated token dying mid-scan
(a revoked token is not a spent allowance: the run aborts with the
token's real error instead of writing a complete-looking report).
