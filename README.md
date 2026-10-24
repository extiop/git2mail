<div align="center">
  <img src="https://www.zupimages.net/up/22/23/qzk2.png" alt="git2mail logo"/>
</div>

[![Build & test](https://github.com/extiop/git2mail/workflows/Build%20&%20test/badge.svg)](https://github.com/extiop/git2mail/actions)
[![Cargo git2mail](https://img.shields.io/badge/crates.io-git2mail-red)](
https://crates.io/crates/git2mail)
[![Documentation git2mail](https://img.shields.io/badge/docs.rs-git2mail-blue)](
https://docs.rs/git2mail)
[![User guide](https://img.shields.io/badge/mdbook-user%20guide-informational)](
https://extiop.github.io/git2mail/)

Find the email addresses developers leave in GitHub's public commit
history, using only what GitHub's public API already exposes.

# Introduction

git2mail is an OSINT tool (OSINT, open-source intelligence, means
investigating using only information the public can already see) that finds
developers' email addresses from GitHub repositories and profiles. It reads
commit metadata through the GitHub API to retrieve author emails, supporting
both single and multi-token authentication for large-scale investigations.
It is built for recruiters, sales teams, sourcing specialists and
journalists, as well as for large-scale open-source research.

> **Responsible use.** git2mail collects only publicly available data
through the GitHub REST API. Use it solely for lawful, authorized OSINT
research, in accordance with the
[GitHub Terms of Service](https://docs.github.com/en/site-policy/github-terms/github-terms-of-service)
and applicable laws. Email addresses are personal data in many
jurisdictions: check the rules that apply to how you store and use them.
You are solely responsible for your use.

## Quickstart

### 1. Get the program

The easiest way: download the ready-made program from the
[releases page](https://github.com/extiop/git2mail/releases). Pick the file
for your computer:

| Your computer | File to download |
|---|---|
| Windows | `git2mail-windows-<version>.exe` |
| Mac (Apple Silicon M1/M2/M3/M4) | `git2mail-macos-<version>` |
| Linux | `git2mail-linux-static-<version>` ("static" means one single file, nothing else to install) |

Then open a terminal (the text window on your computer: Terminal on Mac
and Linux, PowerShell on Windows) in your Downloads folder and run the
program from there:

* **Windows:** open the Downloads folder in File Explorer, type
  `powershell` in the address bar and press Enter, then type
  `.\git2mail-windows-<version>.exe` followed by one of the commands from
  the [examples](#examples). If Windows shows a "Windows protected your
  PC" screen, click *More info* then *Run anyway* (the program is not
  digitally signed).
* **Mac:** in Terminal, type `cd ~/Downloads` then
  `chmod +x git2mail-macos-*` (make it executable) and run
  `./git2mail-macos-<version>`. If macOS says it "cannot be opened because
  it is from an unidentified developer": right-click the file, choose
  *Open* then *Open* again, or clear the block with
  `xattr -d com.apple.quarantine git2mail-macos-*`. The downloaded program
  is built for Apple Silicon Macs; on an Intel Mac, build from source
  instead (below).
* **Linux:** `chmod +x git2mail-linux-static-*` then run
  `./git2mail-linux-static-<version>`.

To type just `git2mail` from any folder instead, install the command on
your PATH: either build from source (`cargo install --path .` after
cloning, or `cargo install git2mail --locked` from crates.io), which needs
the Rust toolchain plus `cmake`, a C compiler and `pkg-config` (the
bundled TLS library compiles C code; on macOS, start with
`xcode-select --install` then `brew install cmake pkg-config`):

```bash
git clone https://github.com/extiop/git2mail
cd git2mail
cargo install --path .    # or, from crates.io: cargo install git2mail --locked
```

### 2. Try it now, without any account

```bash
git2mail scan --url https://github.com/denoland/deno
```

(In the commands below, `git2mail` means the program downloaded in step 1
unless you installed it on your PATH.)

Without a token, GitHub allows about 60 lookups per hour, enough for a
first try. You should see something like:

```text
Starting git2mail!
[!] no token provided: running anonymously, limited to 60 requests/hour
— create one at github.com/settings/tokens and use --token or
--token-file <tokens.json> for 5000 requests/hour each
--------------------------------
[+] Found 12 emails
[+] Result is available at results/repository/denoland_deno
[+] Top author 1: John Doe <john@doe.example> — unknown language, 42 commits
```

The result file is a plain list of email addresses, one per line: open it
in any text editor, or copy the addresses into a spreadsheet, an email
tool or your outreach workflow. These are addresses read from public
commit metadata: they can be old or spoofed, so see
[Data quality](#data-quality) before contacting anyone. After every scan,
the screen also names the top developers behind the repository (the names
they type in their commits, which is self-declared information exactly
like the addresses); add `--json report.json` to your command to save the
full per-author report.

### 3. Create a token for real scans

A token raises the limit from about 60 to 5,000 lookups per hour. Open
<https://github.com/settings/tokens>, click *Generate new token (classic)*,
pick how long it stays valid under *Expiration* (GitHub defaults to 30
days; "No expiration" means you never have to redo this), leave every box
unticked (reading public data needs none) and copy the `ghp_…` string it
shows. A fine-grained token works too (created under *Settings → Developer
settings → Personal access tokens → Fine-grained tokens*, with *Public
repositories (read-only)* access); both kinds are accepted.

To save several tokens (each adds 5,000 lookups per hour), open the
`tokens.example.json` file, replace the placeholders with your own tokens,
and save the result as `tokens.json` in the folder you run git2mail from
(on Windows, choose "All files" in the save dialog so it does not become
`tokens.json.txt`). One token per account you own, within what GitHub's
Terms of Service allow.

### 4. Adjust the verbosity (optional)

The human-readable report of every subcommand (`scan`, `search`, `user`,
`org`, `email`, `emails`) prints to the terminal by default. Set `RUST_LOG`
to adjust the verbosity, e.g. `RUST_LOG=debug git2mail scan --url …`; on
Windows PowerShell, set it first with `$env:RUST_LOG='debug'`.

> In the examples, replace `$TARGET_URL` with the GitHub page address
> you are investigating (e.g. `https://github.com/denoland/deno`) and
> `$YOUR_TOKEN` with the token you copied (on Windows PowerShell, define
> them first with `$TARGET_URL = '…'` and `$YOUR_TOKEN = '…'`). Typing the
> full values always works.

## Performance

As implemented today (synchronous requests, multi-token round-robin with
automatic rotation on rate limits and skipping of exhausted tokens),
git2mail scans a large repository such as https://github.com/denoland/deno
in under a minute to find the emails of its most active authors: the commit walk is capped at
10 pages of 100 commits (**1000 commits per repository**), which keeps one
repository from burning the whole hourly token pool.

The `search` subcommand scans the found repositories in parallel with one
worker per *live* token: each worker owns a dedicated token and pulls
repositories from a shared queue, so every token budget is used without
contention. Single-repository and single-profile scans stay sequential.

## Examples

### GitHub profile as a target

The URL parameter can be a GitHub repository URL or a profile URL, for instance:

```bash
git2mail scan --url https://github.com/denoland/deno

git2mail scan --url https://github.com/denoland
```

Use a specific token to be authenticated and fetch a large amount of commits:

```bash
git2mail scan --url "$TARGET_URL" --token "$YOUR_TOKEN"
```

A token passed with `--token` stays saved on your computer in the record of commands you have typed, and other programs running at the same time can see it: prefer `--token-file`, which reads the token(s) from a file
instead. When both are provided, `--token` wins for that run and a warning
is logged.

If you don't have a token yet, you can still try the tool: simply leave
`--token` out. GitHub then allows only about 60 lookups per hour, so a token
is recommended for any real scan.

The repository URL must follow the following format:

```bash
git://github.com/some-user/my-repo[.git]
git@github.com:some-user/my-repo[.git]
https://github.com/some-user/my-repo[.git]
ssh://git@domain.com/group/app[.git]
```

Web URLs (`http(s)://`, `git://`) must point at `github.com` (or
`www.github.com`); any other host is rejected as an invalid URL before the
scan runs. The `ssh://git@domain.com/…` form is kept for self-hosted Git
remotes.

A trailing `.git` suffix is kept verbatim as part of the repository name: it is passed through to the GitHub API request and included in the output file name (`results/repository/some-user_my-repo.git`). Since the GitHub API only resolves repository names without the suffix (`GET /repos/some-user/my-repo.git` answers 404, verified live), a scan with a `.git` URL always fails with "GitHub resource not found": the suffix documents a passthrough guarantee, not a usable input form: drop it before scanning.

A trailing `/` on the URL, however, is a paste artifact, never part of the repository name: it is trimmed before the request (`https://github.com/some-user/my-repo/` targets `some-user/my-repo`, not the guaranteed-404 `my-repo%2F`). The other github.com page-navigation paste artifacts (`?tab=repositories`, `?plain=1#L12`, `#readme`…) are stripped the same way, since no GitHub login or repository name contains `?` or `#`. The URL scheme is case-insensitive too: `HTTPS://GITHUB.COM/some-user/my-repo` parses exactly like its lowercase form (login/repository case is preserved). A profile URL has no name after its separator to trim, so a trailing `/` there is rejected as an invalid URL.

The profile URL must follow the following format:

```bash
git://github.com/some-user
git@github.com:some-user
https://github.com/some-user
ssh://git@domain.com/group
```

And if you have several tokens, you can make your own copy of `tokens.example.json` with your tokens in it, to look through many more commits:

```bash
git2mail scan --url "$TARGET_URL" --token-file "$YOUR_TOKEN_FILE"
```

Note that GitHub caps the profile events timeline at 300 events (its documented API ceiling): the scan never walks past the cap and a warning says so when the cap cuts a prolific profile's listing, instead of the events stage failing on the out-of-window request. When the events hold no email, the scan falls back to the target's repositories' commits, as always.

With dummy values:

```bash
git2mail scan --url https://github.com/denoland/deno --token-file tokens.json
```

To also get a JSON report (a structured text file you can open in any text editor, and other software can read) in addition to the on-screen results:

```bash
git2mail scan --url "$TARGET_URL" --json "$YOUR_REPORT_PATH"
```

Result files and JSON reports are written to a temporary file first, then renamed, so a file is never left half-written even if you open it while a scan is still running.

`tokens.example.json` content (obviously fake placeholders: copy the file to `tokens.json` and replace them with your own tokens), which is available at the root of the project:

```json
{
    "0": "ghp_EXAMPLE_DO_NOT_USE_0000000000000000000001",
    "1": "ghp_EXAMPLE_DO_NOT_USE_0000000000000000000002",
    "2": "ghp_EXAMPLE_DO_NOT_USE_0000000000000000000003",
    "3": "ghp_EXAMPLE_DO_NOT_USE_0000000000000000000004",
    "4": "ghp_EXAMPLE_DO_NOT_USE_0000000000000000000005",
    "5": "ghp_EXAMPLE_DO_NOT_USE_0000000000000000000006",
    "6": "ghp_EXAMPLE_DO_NOT_USE_0000000000000000000007",
    "7": "ghp_EXAMPLE_DO_NOT_USE_0000000000000000000008",
    "8": "ghp_EXAMPLE_DO_NOT_USE_0000000000000000000009",
    "9": "ghp_EXAMPLE_DO_NOT_USE_0000000000000000000010"
}
```

In this mode, your results will be stored per profile with the following relative path, from your current working directory: `results/profile/$author`. If a repository is defined, it will be at `results/repository/$author_$repository`.

### Full profile investigation (API-only)

The `user` subcommand investigates one GitHub profile end to end, 100% API (no clone, no HTML scraping):

```bash
git2mail user "jane-doe" --token "$YOUR_TOKEN"
```

It accepts the shared `--token`/`--token-file`/`--json` flags and reports, both in the terminal log and in the opt-in JSON report:

- **Profile**: the account fields that carry OSINT value (name, company, blog, location, public email, bio, creation date, account type, Twitter/X handle and public repository count). An organization target is rejected with a clear error pointing at the `org` subcommand.
- **Usernames/names history**: the *noreply technique*: GitHub hides users' real email in commits behind an alias like `12345+jane@users.noreply.github.com`, and the number in that alias is the account's ID, so matching it reveals usernames the account used in the past. The target's own repositories' commits are scanned, and every author/committer email shaped `<id>+<username>@users.noreply.github.com` whose numeric `id` equals the target's reveals a username the account used in the past (with the commit names seen with it and the repositories where it appeared). The older pre-2017 form `<id>@users.noreply.github.com` attributes the current username only.
- **Emails**: every email used on the target's repositories (the 0.5.0 technique), with the names and repositories where each was seen. Noreply addresses are excluded: they feed the histories instead, and a malformed noreply payload (a non-numeric id…) is dropped entirely.
- **Variants**: the likely email spellings `{first}.{last}`, `{first}{last}`, `{initial}{last}`, `{first}_{last}`, `{initial}_{last}`, `{first}`, `{last}`, `{initial}.{last}` applied to the first/last names extracted from the profile name and the commit names seen with the target's noreply id (a name that appears only with a real, non-noreply email does not feed the guessing), combined with the domains deduced from the emails already found (noreply excluded). Variants actually observed in the commits are reported as `matched` (deduplicated by email); the others as `generated` (candidates to check elsewhere, not findings). Names are lowercased and accents removed (`é`→`e`, plus `ß`→`ss`, `æ`→`ae`, `œ`→`oe`, `ø`→`o`); names in other alphabets are kept as written. The candidate names and domains are ranked by raw sighting weight and capped (at most 64 name pairs and 64 domains are expanded, the generated list at 1000 candidates, with warnings), so commit-forged metadata cannot drown the real ones. Beyond the eight built-in patterns, `--variant-pattern <PATTERN>` (repeatable, at most 64 patterns) probes your own conventions, e.g. `git2mail user janedoe --variant-pattern '{last}{first}'`; the placeholders are `{first}`, `{last}` and `{initial}` (the domain is not part of the pattern), only printable ASCII is allowed (whitespace, `@`, control and zero-width characters are rejected client-side), the expansion is lowercased so the literal part matches observed emails case-insensitively like the built-ins, the custom patterns are applied after the built-ins (deduplicated against them) and are verified against the API like every other candidate. On a broad target the built-ins alone can fill the 1000-candidate generated list; a warning then names the custom patterns as possibly under-listed (matched custom candidates are always reported).
- **Local identities (machine-local addresses)**: emails like `jeanpierre@My-Computer.local`, `jeanpierre@box.lan` or a single-label domain like `jeanpierre@mycomputer`. This is a **heuristic**: it flags the documented mDNS/workgroup conventions and dot-less domains only, and a false positive merely adds one candidate to the `local_identities` list.
- **Potential secondary accounts** (heuristics, reported with their evidence): an email recurring across two or more of the target's repositories whose names never overlap the target's own names (`co-author`), and noreply pairs (`id+username` or legacy `<id>` form) whose id differs from the target's but whose username matches a known target username (`noreply-username`) or whose commit names match a known target name (`noreply-name`). The web-flow identity GitHub stamps on commits made through its UI (name `github`, address `noreply@github.com`) is never reported as a secondary account: it is automation, not a person (the email itself stays in the emails list).
- **SSH keys**: the account's public keys (`GET /users/{u}/keys`, paginated), with title and creation date.
- **External contributions**: commits authored by the target outside their own repositories (`search/commits q=author:<user> -user:<user>`, paginated, capped at GitHub's documented 1000-result search ceiling), attributed to the repositories found.

Like every repository scan, each target repository's commit walk is capped at 10 pages of 100 commits (the shared per-repository budget): when the budget cuts a history, a warning says it may be incomplete instead of the report silently pretending it saw all of it.

With `--json`, the enriched report carries the documented shape:

```json
{
  "profile": { "login": "jane-doe", "id": 42, "name": "Jane Dupont", "...": null },
  "usernames_history": [{ "username": "oldname", "names": ["jane d."], "repos": ["jane/old"] }],
  "names_history": [{ "name": "jane dupont", "repos": ["jane/old"] }],
  "emails": [{ "email": "jane@example.com", "names": ["jane dupont"], "repos": ["jane/one"] }],
  "variants": {
    "matched": [{ "email": "jane.dupont@acme.com", "pattern": "first.last", "domain": "acme.com" }],
    "generated": ["janedupont@acme.com", "jdupont@acme.com"]
  },
  "secondary_accounts": [{ "kind": "co-author", "identity": "co@acme.com", "names": ["co worker"], "repos": ["jane/one", "jane/two"] }],
  "ssh_keys": [{ "id": 1, "key": "ssh-ed25519 AAAA…", "title": "laptop", "created_at": "2020-01-01T00:00:00Z" }],
  "external_contributions": [{ "repository": "acme/lib", "url": "https://github.com/acme/lib", "commits": 3 }],
  "local_identities": [{ "email": "jeanpierre@My-Computer.local", "names": [], "repos": ["jane/one"] }]
}
```

Two **API-only deltas** are assumed and documented (the clone-based tools iterate all branches):

1. the REST commits API exposes the default branch only, so the histories and emails are the ones visible on the default branches;
2. the noreply history only reveals usernames for targets that committed at least once with the `id+username@users.noreply.github.com` form, and only usernames matching GitHub's full username shape (1-39 ASCII letters, digits or hyphens, without a leading/trailing hyphen or consecutive hyphens): a commit email carrying a free-form or impossible-shape username payload falls back to the legacy id-only handling.

A rate-limit or transport failure aborts the investigation; only a repository that is private, deleted or empty is skipped with a warning, so the report can never silently miss whole repositories.

### Organization investigation (API-only)

The `org` subcommand investigates one GitHub organization:

```bash
git2mail org "acme" --token-file tokens.json
```

It accepts the shared `--token`/`--token-file`/`--json` flags plus an optional `--limit N` capping the number of scanned repositories (all of them by default), and reports, both in the terminal log (ORG / MEMBERS / REPOSITORIES / EMAILS) and in the opt-in JSON report:

- **Org**: the `GET /orgs/{org}` fields that carry OSINT value (login, name, blog). A missing organization is a clean not-found error.
- **Members**: the organization's publicly visible member usernames (just names on GitHub, no contact details; many companies hide this list entirely). The emails below come from the repositories' commits, not from these members. To investigate one member, run `git2mail user <username>`.
- **Repositories**: the public repositories (`GET /orgs/{org}/repos`, paginated).
- **Emails**: the developers' emails found scanning the organization's repositories' commits with the same worker-per-token parallelism as the parallel `search`, reported per repository and globally (noreply addresses excluded, like every scan). The found addresses are also saved to `results/org/<org>`, one per line, the same paste-able file the scan subcommands write.

With `--json`, the report carries the documented shape:

```json
{
  "org": { "login": "acme", "name": "Acme Corp", "blog": "https://acme.example" },
  "members": ["alice", "bob"],
  "repositories": ["one", "two"],
  "emails": {
    "per_repository": { "acme/one": ["alice@acme.com"], "acme/two": ["bob@acme.com"] },
    "all": ["alice@acme.com", "bob@acme.com"]
  },
  "scanned": { "repos": 2, "pages": 9 }
}
```

`per_repository` is keyed by the `owner/name` full names the scan reports, and only lists the repositories where at least one email showed up; `scanned.pages` counts the successful API requests of the whole investigation (org info, members, repositories listing and the workers' commit pages). A repository that is private, deleted or empty is skipped with a warning; a rate-limit or transport failure aborts the investigation.

### Reverse email lookup (heuristic, API-only)

The `email` subcommand traces one email address back to its GitHub account:

```bash
git2mail email "jane.dupont@acme.com" --token "$YOUR_TOKEN"
```

GitHub exposes no email search API, so this subcommand is a **documented heuristic**, 100% API (no clone, no scraping):

1. **Candidate repositories**: the repository search endpoint is queried with the tokens of the local part (split on `.`, `_`, `-` and `+`, so `jane.dupont` → `jane dupont`), with the raw local part when it differs (so `janedupont` is searched too) and with the domain itself (`acme.com`); at most three queries. The repositories whose name, description or topics mention these tokens become candidates, capped at 50 distinct repositories. The heuristic budget bounds the API cost of one address: at most 3 candidate queries, 50 candidates, each verified over at most its 10 most recent default-branch commit pages (every commit counts toward the cap).
2. **Commit verification**: each candidate repository's (default-branch) commits are scanned for a commit whose author email is exactly the target: the local part case-insensitively, the domain matched exactly (no subdomain look-alike), and the lookup stops early once the strongest attribution is found. The commits listing is never narrowed by the API `author` parameter: the commit author login is not necessarily the email local part, and a narrowing would silently drop the target's own commits.
3. **Account attribution**: a matching commit whose API payload embeds a GitHub author object resolves the account with the `commit-author` confidence (login, numeric id, repository and commit sha as evidence). When the author object is absent (deleted account), the repository owner is only a **weak** candidate, reported with the `repo-owner-weak` confidence and a `null` id: a presumption, never overstated.

Anti-false-positive rules: a GitHub noreply address (`@users.noreply.github.com`) is rejected upfront with a clear error (it never carries a real mailbox; the `user` subcommand's noreply technique covers those), a malformed address is rejected client-side before any request, the email match is exact, and the `confidence` field states only what the API payload actually proved. An unmatched address is reported as unmatched (a finding, not an error).

With `--json`, the report carries the documented shape:

```json
{
  "email": "jane.dupont@acme.com",
  "account": { "login": "janedoe", "id": 42, "confidence": "commit-author" },
  "evidence": { "repository": "acme/lib", "commit_sha": "abc123", "author_email": "jane.dupont@acme.com" },
  "candidates": [{ "login": "janedoe", "id": 42, "confidence": "commit-author" }]
}
```

**Limitations of the heuristic** (documented API-only deltas):

1. the candidate search can only surface repositories whose name, description or topics mention the local-part tokens or the domain, capped at 50: an email never used in a public commit of one of those candidates cannot be found;
2. the REST commits API exposes the default branch only;
3. the `repo-owner-weak` attribution presumes the repository owner is the login behind the matching commit: the commit carries no GitHub author object, so nothing in the payload actually proves it, and a repository owner may be an organization rather than a user, so resolve the account type before acting on a weak attribution;
4. only the most recent 10 commit pages (1000 commits) of each candidate's default branch are scanned: a matching commit deeper in the repository history cannot be found.

The `emails` subcommand runs the same lookup in bulk over the token pool:

```bash
git2mail emails addresses.txt --token-file tokens.json --json bulk.json
```

The file holds one address per line (`#` comments and blank lines ignored; a leading UTF-8 BOM, as written by Windows editors, is stripped); duplicated addresses are deduplicated and noreply or malformed lines are skipped with a warning (they cannot be reversed, they are not scan failures). The addresses are processed with the same worker-per-token parallelism as the parallel `search`, and the report keeps the file order with a matched/unmatched/skipped summary (`total` counts only processed addresses):

```json
{
  "results": [
    { "email": "jane.dupont@acme.com", "account": null, "evidence": null, "candidates": [] }
  ],
  "summary": { "total": 1, "matched": 0, "unmatched": 1, "skipped": 0 }
}
```

A worker whose dedicated token died (spent quota or rejected token) stops pulling work while the other tokens keep draining the queue; any other worker failure aborts the bulk run. The addresses a stopped worker never reached are never counted as a verified no-match: they are absent from `results`, counted in `summary.skipped` and warned about in the log. Note that "skipped" names two different things: the read-time skips (noreply/malformed lines, warned about when the file is read) never enter the pipeline and are **not** counted in `summary.skipped`, which counts only the work a stopped worker never reached.

### Metadata as a keyword

You want to search, for instance, for some Rust developers that create `nmap` related tools:

```bash
git2mail search --query nmap --language Rust --token-file tokens.json
```

You can also limit the number of repositories scanned this way, for instance:

```bash
git2mail search --query nmap --language Rust --token-file tokens.json --limit 5
```

Without `--limit`, the search defaults to scanning 5 repositories.

In this mode, your results will be stored per query with the following relative path, from your current working directory: `results/keyword/$query`. If a language is defined, it will be at `results/keyword/$query_$language`.

### Advanced search qualifiers

The `search` subcommand also accepts the optional qualifiers of [GitHub's advanced search](https://github.com/search/advanced). They all compose with `--query`, `--language` and `--limit`, and only the ones you provide are appended to the GitHub query:

| Flag | Qualifier | Example values |
| --- | --- | --- |
| `--stars <RANGE>` | `stars:` | `>100`, `>=50`, `10..50`, `100..*` |
| `--forks <RANGE>` | `forks:` | `>10`, `5..20` |
| `--size <RANGE>` | `size:` | `>1000`, `100..5000` |
| `--created <DATE_RANGE>` | `created:` | `>2020-01-01`, `>=2020`, `2019-01-01..2020-01-01` |
| `--pushed <DATE_RANGE>` | `pushed:` | `>2024-01-01`, `>=2023` |
| `--license <ID>` | `license:` | `mit`, `apache-2.0` |
| `--topic <NAME>` | `topic:` | `osint`, `recon` |
| `--user <LOGIN>` | `user:` | `extiop` (mutually exclusive with `--org`) |
| `--org <LOGIN>` | `org:` | `acme` (mutually exclusive with `--user`) |

For instance, to scan well-established MIT-licensed Rust repositories of one organization, recently pushed:

```bash
git2mail search --query nmap --language Rust --stars '>100' --license mit --org acme --pushed '>2024-01-01' --token-file tokens.json
```

To target one user's repositories on a topic:

```bash
git2mail search --query nmap --topic osint --user extiop --token-file tokens.json
```

`--user` and `--org` are mutually exclusive (the GitHub search API accepts only one owner filter). Values are validated client-side before any request: an obviously malformed range or date (say `--stars abc` or `--created 2020-13-01`) fails fast with a clear `invalid search filter` error instead of silently returning no result from the API. Count and date ranges follow the GitHub search range syntax (`>`, `>=`, `<`, `<=`, `start..end`, with `*` for an open end); dates accept the `YYYY`, `YYYY-MM` and `YYYY-MM-DD` granularities. An inverted range (`--stars 50..10`, `--created 2020-01-01..2019-01-01`) is well-formed but rejected client-side like every other malformed value; for dates this matters because GitHub itself does not reject an inverted range: it silently swaps the sides and quietly covers the opposite window. The stricter name rules are validated client-side too: a `--user`/`--org` value must be a valid GitHub login (ASCII letters, digits or hyphens; a login with `.` or `_` would silently match nothing) and a `--license`/`--topic` value must hold at least one alphanumeric character (a separator-only `...` or `--` would silently match nothing). Note that the repository listing itself is capped at GitHub's documented 1000-result search ceiling: the over-ceiling page is never requested (the API answers it with a raw 422), so a query matching more than 1000 repositories scans at most the first 1000. Note also that the qualifiers are not part of the output file name: results are stored per query/language, so two runs differing only by their qualifiers write to the same `results/keyword/$query_$language` file, and the last run overwrites the previous one.

### Developer correlation

Every scan also aggregates its results per author (issue #5): for each author found in the scanned commits, it correlates the attributes git2mail already collects: the emails they used, the repositories they were seen in with their primary language, the first repository where they appeared and their total commit count. Authors are sorted by commit count and each author's languages are ordered dominant first, so the report answers "who are the main developers behind this topic, and what do they write in?".

The report lives in the opt-in `--json` output, as a `correlation` object added on top of the unchanged legacy fields (the roadmap originally sketched a `results/$language/$author` output layout; the delivered feature is this JSON report, and the plain-text result files stay unchanged):

```bash
git2mail search --query nmap --language Rust --token-file tokens.json --json report.json
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
        "total_hits": 3
      }
    ]
  }
}
```

`scanned.partial` is `true` when the parallel scan kept its findings although a dedicated token died mid-scan (whole listed repositories may then have been left unscanned): the JSON report keeps `partial: true` even when the run itself exits 0.

The primary language comes free with the repository-search metadata, so `search` runs attribute a language to every repository that has a detected primary language (GitHub reports `language: null` when it has none, and the report passes it through, like `scan` (repository/profile) runs which do not spend an extra API call on it). The same author seen in several repositories (across pages, workers or scan stages) is merged: emails deduplicated, hit counts summed. The terminal log also prints a short summary of the top authors with their dominant language; the plain-text result files keep the legacy one-email-per-line format, byte-identical.

## How it works

git2mail reads the commit history of a GitHub repository and collects the email addresses its developers left there.

This process extends to multiple repositories: you can search with custom queries and filter by GitHub metadata such as the repository language. You can also cap the number of repositories scanned with `--limit N`.

The GitHub API rate limit for non authenticated users is 60 requests per hour. Because busy repositories such as [ripgrep](https://github.com/BurntSushi/ripgrep) have thousands of commits, use a GitHub account (or a GitHub App) and generate one token **per account**, as described in this [GitHub API documentation](https://docs.github.com/en/rest/overview/resources-in-the-rest-api#rate-limiting). Your token does not need any access to any of your repositories. Anonymous access is supported (`--token ""`), but non authenticated requests are very limited, so tokens remain the practical way to run a real scan. Bear in mind that the rate limit is defined as the number of requests per hour **per account**.

Note that with one token, you can make 5,000 requests to the GitHub API per hour. Within a single repository, though, the commit walk is capped at 10 pages of 100 commits (1000 commits per repository, the same per-repository budget as every scan: `email` reverse lookup, `scan`/`search`/`org` and `user` repository walks): a larger token pool does not deepen one repository's history; extra tokens help **across** many repositories (org scans, bulk `search`/`emails` runs), where each repository spends its own slice of the pooled budget. To grow the pool, add tokens from additional accounts you own, within what GitHub's Terms of Service allow; one legitimate account already buys 5,000 requests per hour.

This project can be combined with other OSINT tools. For instance, you can use git2mail to retrieve Gmail addresses, then investigate some of them further with [GHunt](https://github.com/mxrch/ghunt) (for lawful research only, as above).

### Data quality

One's email can be spoofed in commits: an address read in a commit proves
nothing about who owns the mailbox. Cross-check the confidence grades of the `email` reports and the
per-author summary of the correlation report (`--json`) before drawing
conclusions.

## Prevention

Harden your account privacy by enabling these [settings](https://github.com/settings/emails):

- ✔️ Keep my email addresses private
- ✔️ Block command line pushes that expose my email

These settings protect only future commits: an address you committed with
before stays in the repository's history and clones. Scan your own profile
with this tool to see what is exposed, and rewrite old history (for example
with `git filter-repo`) if you need it gone.

## Limitations

This project is limited to GitHub repositories.

## Roadmap

- [x] From a GitHub repository, search for commits and email of authors with GitHub metadata and parsing
- [x] From a GitHub keyword search, retrieve GitHub repositories URLs
- [x] Handle properly errors and limit, or even remove, panics
- [x] Correlate emails, language and project preferences: per-author correlation report (emails, repositories with their primary language, first seen repository, commit counts) in the `--json` output, plus a top-authors terminal summary (see the [correlation section](#developer-correlation); issue #5)
- [x] Support more advanced parameters (see <https://github.com/search/advanced>): `--stars`, `--forks`, `--size`, `--created`, `--pushed`, `--license`, `--topic`, `--user`/`--org` on the `search` subcommand (issue #6)
- [x] Full profile investigation, API-only: `git2mail user <username>` (usernames/names history via the noreply technique, email variants, local identities, potential secondary accounts, SSH keys, external contributions) (see the [investigation section](#full-profile-investigation-api-only))
- [x] Reverse email lookup, API-only heuristic: `git2mail email <address>` / `git2mail emails <file>` (candidate repositories from the address tokens, verified by commits, `commit-author`/`repo-owner-weak` confidences) (see the [reverse email lookup section](#reverse-email-lookup-heuristic-api-only))
- [x] Organization investigation, API-only: `git2mail org <org>` (public members, public repositories and the emails found scanning them) (see the [organization section](#organization-investigation-api-only))
- [x] Extensible `user` variant combinatorics: `--variant-pattern <PATTERN>` (repeatable) probes custom email conventions (`{first}`, `{last}`, `{initial}` placeholders) after the built-in patterns, still API-verified
- [ ] A graphical or web interface, so non-technical users (recruiters, sales, investigators) can run these searches without a terminal

## Repository

This repository contains:

* `src`: the Rust source code implementing git2mail
* `doc`: the user guide sources, published at https://extiop.github.io/git2mail/
* `.github`: Continuous Integration needs, community files and issue/PR templates
* `.cargo`: Cargo configuration for cross-platform builds
* `tokens.example.json`: example token file showing the multi-token format

## Thoughts

- Fuzzing to find my code vulnerabilities
- ~~Async queries~~ **resolved by design** (issue #4): parallel requests run on std threads with one dedicated token per worker (the v0.5.0 refactor); async was considered and rejected, as per-token parallelism is enough for network I/O at this scale and adds no dependency

## Contributing

If you would like to contribute, read and follow [`CONTRIBUTING.md`](.github/CONTRIBUTING.md).

## License

This project is free software, and is released under the terms of the LGPL (GNU Lesser General Public License) version 3.
