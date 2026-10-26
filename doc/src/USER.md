# User investigation (`user`)

The `user` subcommand investigates one GitHub profile end to end, 100%
API (no clone, no HTML scraping):

```bash
git2mail user "jane-doe" --token "$YOUR_TOKEN"
```

This investigation walks many pages: a token is strongly recommended (an
anonymous account gets only 60 requests per hour and the walk (the
page-by-page listing traversal) aborts when the quota is spent).

It accepts the shared `--token`/`--token-file`/`--json` flags and
reports, both in the terminal log and in the opt-in JSON report. The
observed email addresses are also saved to `results/user/<username>.log`,
one per line, the same paste-able file the scan and `org` subcommands
write.

## What the investigation collects

- **Profile**: the account fields that carry OSINT value (name, company,
  blog, location, public email, bio, creation date, account type,
  Twitter/X handle and public repository count). An organization target
  is rejected with a clear error pointing at the `org` subcommand.
- **Usernames/names history**: the *noreply technique*: GitHub hides
  users' real email in commits behind an alias like
  `12345+jane@users.noreply.github.com`, and the number in that alias is
  the account's ID, so matching it exposes usernames the account used in
  the past. The username in the alias is written by the commit author's
  Git configuration, not by GitHub: treat it as strong evidence, not as
  a verified fact. The target's own repositories' commits are scanned,
  and every author/committer email shaped
  `<id>+<username>@users.noreply.github.com` whose numeric `id` equals
  the target's reveals a username the account used in the past (with the
  commit names seen with it and the repositories where it appeared). The
  older pre-2017 form `<id>@users.noreply.github.com` attributes the
  current username only.
- **Emails**: every email used on the target's repositories, with the
  names and repositories where each was seen. Noreply addresses are
  excluded: they feed the histories instead, and a malformed noreply
  payload (a non-numeric id…) is dropped entirely. Forked repositories
  are skipped with a warning: their commit history mirrors the upstream
  project's, so scanning them would report other projects' developers.
  Pass `--include-forks` to scan them too when the forks themselves are
  your subject.
- **Variants**: the likely email spellings `{first}.{last}`,
  `{first}{last}`, `{initial}{last}`, `{first}_{last}`,
  `{initial}_{last}`, `{first}`, `{last}`, `{initial}.{last}` applied to
  the first/last names extracted from the profile name and the commit
  names seen with the target's noreply id (a name that appears only with
  a real, non-noreply email does not feed the guessing), combined with
  the domains deduced from the emails already found (noreply excluded).
  Variants actually observed in the commits are reported as `matched`
  (deduplicated by email); the others as `generated` (candidates to
  check elsewhere, not findings). Names are lowercased and accents
  removed (`é`→`e`, plus `ß`→`ss`, `æ`→`ae`, `œ`→`oe`, `ø`→`o`); names
  in other alphabets are kept as written. The candidate names and
  domains are ranked by raw sighting weight and capped (at most 64 name
  pairs and 64 domains are expanded, the generated list at 1000
  candidates, with warnings), so commit-forged metadata cannot drown the
  real ones. Beyond the eight built-in patterns,
  `--variant-pattern <PATTERN>` (repeatable, at most 64 patterns) probes
  your own conventions, e.g.
  `git2mail user janedoe --variant-pattern '{last}{first}'`; the
  placeholders are `{first}`, `{last}` and `{initial}` (the domain is
  not part of the pattern), only printable ASCII is allowed (whitespace,
  `@`, control and zero-width characters are rejected client-side), the
  expansion is lowercased so the literal part matches observed emails
  case-insensitively like the built-ins, the custom patterns are applied
  after the built-ins (deduplicated against them) and are checked
  against the commit data fetched from the API like every other
  candidate. On a broad target the built-ins alone can fill the
  1000-candidate generated list; a warning then names the custom
  patterns as possibly under-listed (matched custom candidates are
  always reported). To check a generated candidate, run
  `git2mail email <candidate>`.
- **Local identities (machine-local addresses)**: emails like
  `jeanpierre@My-Computer.local`, `jeanpierre@box.lan` or a single-label
  domain like `jeanpierre@mycomputer`. This is a **heuristic**: it flags
  the documented mDNS/workgroup conventions and dot-less domains only,
  and a false positive merely adds one candidate to the
  `local_identities` list.
- **Potential secondary accounts** (heuristics, reported with their
  evidence): an email recurring across two or more of the target's
  repositories whose names never overlap the target's own names
  (`co-author`), and noreply pairs (`id+username` or legacy `<id>` form)
  whose id differs from the target's but whose username matches a known
  target username (`noreply-username`) or whose commit names match a
  known target name (`noreply-name`). The web-flow identity GitHub
  stamps on commits made through its UI (name `github`, address
  `noreply@github.com`) is never reported as a secondary account: it is
  automation, not a person (the email itself stays in the emails list).
- **SSH keys**: the account's public keys (`GET /users/{u}/keys`,
  paginated). The public endpoint exposes the key id and material only:
  the user-set title and creation date exist on the authenticated self
  listing, not here.
- **External contributions**: commits authored by the target outside
  their own repositories
  (`search/commits q=author:<user> -user:<user>`, paginated, capped at
  GitHub's documented 1000-result search ceiling), attributed to the
  repositories found.

Like every repository scan, each target repository's commit walk covers
the full default-branch history (the branch a project presents as its
main line) with no local budget: the walk ends when
GitHub's listing ends, so the report never silently pretends it saw only
part of a history.

## JSON report shape

With `--json`, the enriched report carries the documented shape:

```json
{
  "generated_at": "2026-02-14T18:22:33Z",
  "tool_version": "0.8.0",
  "profile": { "login": "jane-doe", "id": 42, "name": "Jane Dupont", "...": null },
  "usernames_history": [{ "username": "oldname", "names": ["jane d."], "repos": ["jane/old"] }],
  "names_history": [{ "name": "jane dupont", "repos": ["jane/old"] }],
  "emails": [{ "email": "jane@example.com", "names": ["jane dupont"], "repos": ["jane/one"] }],
  "variants": {
    "matched": [{ "email": "jane.dupont@acme.com", "pattern": "first.last", "domain": "acme.com" }],
    "generated": ["janedupont@acme.com", "jdupont@acme.com"]
  },
  "secondary_accounts": [{ "kind": "co-author", "identity": "co@acme.com", "names": ["co worker"], "repos": ["jane/one", "jane/two"] }],
  "ssh_keys": [{ "id": 1, "key": "ssh-ed25519 AAAA…" }],
  "external_contributions": [{ "repository": "acme/lib", "url": "https://github.com/acme/lib", "commits": 3 }],
  "local_identities": [{ "email": "jeanpierre@My-Computer.local", "names": [], "repos": ["jane/one"] }]
}
```

(`generated_at` and `tool_version` open the block: every report carries
them.)

## API-only deltas

Two **API-only deltas** are assumed and documented (the clone-based
tools iterate all branches):

1. the commit walk covers the default branch only: the API *can* address
   other branches and tags (a `sha` parameter), but a per-branch walk
   multiplies the request cost by the branch count and is not attempted,
   so the histories and emails are the ones visible on the default
   branches;
2. the noreply history only reveals usernames for targets that committed
   at least once with the `id+username@users.noreply.github.com` form,
   and only usernames matching GitHub's full username shape (1-39 ASCII
   letters, digits or hyphens, without a leading/trailing hyphen or
   consecutive hyphens): a commit email carrying a free-form or
   impossible-shape username payload falls back to the legacy id-only
   handling.

A rate-limit or transport failure aborts the investigation; only a
repository that is private, deleted or empty is skipped with a warning,
so the report can never silently miss whole repositories.
