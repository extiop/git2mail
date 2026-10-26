# Reverse email lookup (`email` & `emails`)

The `email` subcommand traces one email address back to its GitHub
account; the `emails` subcommand runs the same lookup in bulk over the
token pool.

```bash
git2mail email "jane.dupont@acme.com" --token "$YOUR_TOKEN"
```

```bash
git2mail emails addresses.txt --token-file tokens.json --json bulk.json
```

A token is strongly recommended here too: one lookup walks the full
default-branch history of every candidate repository (until a
`commit-author` match ends the lookup early), far beyond the anonymous
60-requests-per-hour budget.

GitHub exposes no email search API, so this subcommand is a **documented
heuristic**, 100% API (no clone, no scraping).

## How the heuristic works

1. **Candidate repositories**: the repository search endpoint is queried
   with the tokens of the local part (split on `.`, `_`, `-` and `+`, so
   `jane.dupont` → `jane dupont`), with the raw local part when it
   differs (so `janedupont` is searched too) and with the domain itself
   (`acme.com`); at most three queries. The repositories whose name,
   description or topics mention these tokens become candidates: every
   candidate the search serves is verified, with no local cap.
2. **Commit verification**: each candidate repository's (default-branch)
   commits are scanned for a commit whose author email is exactly the
   target: the local part case-insensitively, the domain matched exactly
   (no subdomain look-alike), and the lookup stops early once the
   strongest attribution is found. The commits listing is never narrowed
   by the API `author` parameter: the commit author login is not
   necessarily the email local part, and a narrowing would silently drop
   the target's own commits.
3. **Account attribution**: a matching commit whose API payload embeds a
   GitHub author object resolves the account with the `commit-author`
   confidence (login, numeric id, repository and commit sha as
   evidence). When the author object is absent (deleted account), the
   repository owner is only a **weak** candidate, reported with the
   `repo-owner-weak` confidence and a `null` id: a presumption, never
   overstated.

Anti-false-positive rules: a GitHub noreply address
(`@users.noreply.github.com`) is rejected upfront with a clear error (it
never carries a real mailbox; the `user` subcommand's noreply technique
covers those), a malformed address is rejected client-side before any
request, the email match is exact, and the `confidence` field states
only what the API payload actually proved. An unmatched address is
reported as unmatched (a finding, not an error).

## Single-address JSON report shape

With `--json`, the report carries the documented shape:

```json
{
  "email": "jane.dupont@acme.com",
  "account": { "login": "janedoe", "id": 42, "confidence": "commit-author" },
  "evidence": { "repository": "acme/lib", "commit_sha": "abc123", "author_email": "jane.dupont@acme.com" },
  "candidates": [{ "login": "janedoe", "id": 42, "confidence": "commit-author" }]
}
```

## Limitations of the heuristic

Documented API-only deltas:

1. the candidate search can only surface repositories whose name,
   description or topics mention the local-part tokens or the domain
   (forked candidates are kept: the lookup wants any repository carrying
   the address): an email never used in a public commit of one of those
   candidates cannot be found;
2. the commit walk covers the default branch only (per-branch walking
   multiplies the request cost and is not attempted);
3. the `repo-owner-weak` attribution presumes the repository owner is
   the login behind the matching commit: the commit carries no GitHub
   author object, so nothing in the payload actually proves it, and a
   repository owner may be an organization rather than a user, so
   resolve the account type before acting on a weak attribution.

## Bulk mode (`emails`)

The file holds one address per line (`#` comments and blank lines
ignored; a leading UTF-8 BOM, as written by Windows editors, is
stripped); duplicated addresses are deduplicated and noreply or
malformed lines are skipped with a warning (they cannot be reversed,
they are not scan failures). The addresses are processed with the same
worker-per-token parallelism as the parallel `search`, and the report
keeps the file order with a matched/unmatched/skipped summary (`total`
counts only processed addresses):

```json
{
  "generated_at": "2026-02-14T18:22:33Z",
  "tool_version": "0.7.0",
  "results": [
    {
      "generated_at": "2026-02-14T18:22:41Z",
      "tool_version": "0.7.0",
      "email": "jane.dupont@acme.com", "account": null, "evidence": null, "candidates": []
    }
  ],
  "skipped_addresses": [],
  "summary": { "total": 1, "matched": 0, "unmatched": 1, "skipped": 0 }
}
```

Every report also carries `generated_at` (the UTC timestamp of the run)
and `tool_version` (shown here); the one-address report of
`git2mail email` carries them too, and so does every entry of the bulk
`results` list (the moment its own lookup finished).

A worker whose dedicated token died (spent quota or rejected token)
stops pulling work while the other tokens keep draining the queue; any
other worker failure aborts the bulk run. The addresses a stopped worker
never reached are never counted as a verified no-match: they are absent
from `results`, listed in `skipped_addresses` (file order, so re-running
the interrupted lookups needs no diff of two files), counted in
`summary.skipped` and warned about in the log. "Skipped" names two
different things: the read-time skips (noreply/malformed lines, warned
about when the file is read) never enter the pipeline and are **not**
counted in `summary.skipped`, which counts only the work a stopped
worker never reached.
