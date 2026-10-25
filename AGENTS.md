# AGENTS.md — onboarding guide for AI agents (and humans)

MLA is [ANSSI-FR/MLA](https://github.com/ANSSI-FR/MLA), the Rust codebase whose engineering standards (dependency budget, hand-made errors, zero panics, offline tests, lints-as-API) this project follows.

This file is the fast path to working productively on **git2mail**. Read it
fully before changing anything: the project has a strict philosophy and
several invisible invariants that are easy to violate by accident.

The design notes that guided the refactor are summarized here; the
shipped documentation lives in `doc/src/` (the mdBook).

## 1. What this project is

`git2mail` is a GitHub OSINT tool: given a repository, a profile, an
organization, an email address or a keyword query, it recovers the
**developers' email addresses** behind public GitHub activity — entirely
through the **GitHub REST API**. No git clone, no HTML scraping, no
headless browser.

Six subcommands (`src/main.rs`, clap derive):

| Subcommand | What it does | Core module |
|---|---|---|
| `scan --url <repo-or-profile>` | emails of a repository or profile | `src/sources/` |
| `search --query <q>` | keyword search + parallel scan | `src/sources/search.rs` |
| `user <username>` | full profile investigation (usernames/names history via the noreply technique, email variants, secondary accounts, SSH keys, external contributions) | `src/user.rs` |
| `email <address>` / `emails <file>` | reverse email → account (heuristic, confidence-graded) | `src/email.rs` |
| `org <org>` | organization members + repositories + emails | `src/org.rs` |

Reports go to the terminal log (sanitized) and to opt-in `--json` files
(shape documented per subcommand in `README.md` and `CHANGELOG.md`).

(Six subcommands: `scan`, `search`, `user`, `email`, `emails`, `org` —
the table's fourth row covers both reverse-lookup spellings.)

## 2. The non-negotiable philosophy (aligned with [ANSSI-FR/MLA](https://github.com/ANSSI-FR/MLA))

Every rule below is enforced or reviewed on every change. If your change
needs an exception, stop and discuss — do not add a dependency, a panic or
an async runtime "just this once".

1. **≤ 7 direct dependencies, all `default-features = false`**:
   `clap`, `regex`, `reqwest`, `serde`, `serde_json`, `log`,
   `pretty_env_logger`. **No new dependency ever** — including
   dev-dependencies. Need percent-encoding, date math, JSON paths? Hand-roll
   it (see `src/sources/search.rs` for both).
2. **Hand-rolled errors** (`src/errors.rs`): no `thiserror`, no `anyhow`
   (they are not in our tree for our code — `thiserror` appears in
   `Cargo.lock` only as a transitive leaf of `reqwest`'s optional
   platform-verifier stack; never compile against it). Every new
   `Error` variant needs: rustdoc (what/why distinct from siblings), a
   `Display` arm that stays on **one terminal line**, Debug-escaping for
   user-typed/API-derived payloads (`{payload:?}`), and a `Display` test.
3. **Zero runtime panics**: `clippy::unwrap_used`, `expect_used`, `panic`,
   `todo`, `unimplemented`, `unreachable` are `deny` in `Cargo.toml`.
   Production code returns `Result`; the only allowed production `expect`s
   are the two documented static-regex inits (`src/parsers.rs`) and the two
   justified `#[expect]` allowances inventoried with their justification in
   `Cargo.toml`'s lint table (`clippy::large_enum_variant` on the CLI
   `Command` enum in `src/main.rs`, `clippy::too_many_arguments` on
   `output::write_json` — `#[expect]`, so a stale allowance fails the
   build). Tests may panic freely.
4. **No async/tokio**: threads from `std` (`std::thread::scope`) +
   `reqwest` blocking client. One dedicated token per parallel worker.
5. **Tests are 100 % offline**: every test drives a loopback mock HTTP
   server (`src/github/mock.rs` — `serve_requests`). No test ever reaches
   `api.github.com`. Make tests **mutation-resistant**: assert on request
   counts, exact report shapes and log lines, so reverting a fix fails a
   test.
6. **No scraping, no fuzzing** (explicit decisions): API-only; the risk
   budget went into review loops instead.
7. **Secrets never land in the repo**: `.pi-release/` (internal release
   kit, may contain a token file) is gitignored — keep that entry.

## 3. Code map

```
src/
├── main.rs            CLI (clap derive), one arm per subcommand, run() dispatch
├── lib.rs             module registry + crate-level contracts (panics, lints)
├── errors.rs          the single Error enum (non_exhaustive, Display, tests)
├── consts.rs          API base URL, web-flow identity, shared constants
├── github/
│   ├── client.rs      Client + TokenPool: rotation, retry-after, quota semantics
│   ├── mod.rs         the fetch_paginated family's shared wiring
│   ├── paginated.rs   the ONE pagination loop (page-size aware, caps, 422 handling)
│   └── mock.rs        loopback mock HTTP server used by every offline test
├── sources/
│   ├── mod.rs         CLI-facing Scanner + shared rules: is_usable_email, noreply handling
│   ├── profile.rs     profile scan (events walk, 300-event cap)
│   ├── repository.rs  repository scan (per-repo commit budget)
│   └── search.rs      keyword search, qualifier validation, parallel workers
├── user.rs            `user` investigation + variant engine (caps, ranking)
├── email.rs           `email`/`emails` reverse lookup (heuristic, budgets)
├── org.rs             `org` investigation (members, repos, parallel scan)
├── correlate.rs       per-author correlation report (JSON)
├── output.rs          text results + JSON reports (atomic publish)
├── test_logger.rs     capturing log sink backing the sanitization pins (test-only)
└── parsers.rs         URL parsing (host rules), static regexes
```

## 4. Invariants you must not break (they are all test-pinned)

- **Everything untrusted is sanitized before the terminal**
  (`log_safe`/`sanitize_log_text`) and before **file names**
  (`sanitize_file_name`: traversal, separators, Windows device names,
  200-byte cap, anti-clobber hash). Control characters must never reach a
  log line or a JSON report.
- **Reports publish atomically** (`output.rs::publish_atomically`): staging
  file + rename, permissions preserved, symlink targets refused. Two
  concurrent instances must never tear a file.
- **Rate limits**: core quota (5000/h) aborts with
  `Error::RateLimitExhausted` only when *every* token is exhausted;
  a 403/429 with `Retry-After` **parks** the token until the deadline
  (capped at 1 h) while others keep working; a 401 rejects the token
  (`Error::TokenRejected`) only after no other token could take over.
- **Caps inventory** (each warns honestly when it bites, never silently
  truncates): per-repository commits 10 pages × 100; profile events
  timeline 300 (GitHub-documented); search results 1000 (GitHub-documented);
  email-lookup candidates 50; variant engine 64 name pairs × 64 domains ×
  1000 generated (+ ≤ 64 custom `--variant-pattern` templates).
- **Noreply discipline**: `id+username@users.noreply.github.com` feeds the
  histories, never the emails list; the web-flow identity
  (`noreply@github.com`) is never a secondary account; foreign-forge
  noreply domains (gitlab.com…) are ordinary emails.
- **Honest partials**: a scan that kept partial results after a token death
  reports `scanned.partial`; never-processed bulk work is `skipped`,
  never "unmatched".
- **Documented API deltas** (README "API-only deltas" sections): the REST
  commits API exposes the default branch only; the noreply history requires
  id+username commits; the reverse-email heuristic only sees candidate
  repositories whose name/description/topics match. Keep these claims in
  sync when touching the code.

## 5. How to work

```bash
cargo build --locked
cargo test --locked            # ~7 s, fully offline
cargo clippy --all-targets --locked -- -D warnings
cargo fmt --check              # or: cargo fmt
cargo doc --no-deps --all-features --locked   # RUSTDOCFLAGS=-D warnings in CI
```

All five gates must pass before any commit; CI (`.github/workflows/test.yml`)
runs the same with `--locked`. Commits are **conventional and atomic**
(`feat(scope):`, `fix(scope):`, `docs:`, `ci:`, `test:`, `chore:`) — one
behavioral change per commit, message body explains the *why*. Releases are
tag-signed by the maintainer; the CHANGELOG section must be **dated** before
tagging (the release workflow reads it).

Writing a test: build the mock with `serve_requests` (closure per request),
drive the `_at`-suffixed internal entry point against the mock base URL,
assert on report shapes **and** on `scanned`/request counts. Look at
`src/user.rs` and `src/org.rs` tests for the patterns (planted-data
adversarial cases, hostile payloads, concurrent publishers).

## 6. Repository conventions (maintainer requirements)

Every rule below has been audited on this repository; violating any of them
is a release blocker.

1. **English everywhere in tracked files**: code, rustdoc, README,
   CHANGELOG, commit messages, workflow bodies. A single French word in a
   tracked file is a review blocker.
2. **No AI-tooling traces**: no agent-framework names, no internal
   spec/roadmap documents in the tree, and no dangling section references
   in rustdoc (a rustdoc claim must be readable on its own or point at the
   shipped `doc/` book).
3. **Docs following the MLA conventions**: the documentation is the mdBook (`doc/`: `book.toml`
   + `SUMMARY.md` + topical pages), deployed to GitHub Pages by CI. Every
   factual claim in `doc/src/` must be **verified against the code** — a
   doc/code divergence (a header format, a rate-limit semantic, a path) is
   a P1, and each claim should be pinned by a test when it can be.
4. **Review regime**: every release candidate goes through three
   independent review passes — doc↔code consistency, hygiene sweep
   (forbidden names, secrets, French, orphan TODOs), adversarial
   (squash-vs-messages, docs as an attack surface, merge simulation) —
   **relaunched until all three return OK/CLEAN**, then the diff is
   re-verified by a human.
5. **History discipline**: one release branch carries a **few logical
   commits** (conventional subjects, no fixup-noise, no "translation"
   or "cleanup" commits — the commits are born clean). Commit messages
   match the repo's existing style (`build(deps):`, `ci:`, `doc:`…).
6. **Releases following the MLA conventions**: the branch is squashed, every commit **GPG-signed
   by the maintainer** (`git rebase HEAD~N --exec 'git commit --amend
   --no-edit -S'`), merged with a merge commit, then tag-signed
   (`git tag -s`). The release workflow builds attested binaries
   (`actions/attest-build-provenance`, SLSA) and generates the release
   body (asset-verification section following the MLA conventions + CHANGELOG link).
   `cargo update` + `cargo audit` clean are mandatory **on every release
   branch** before tagging (a stale lockfile once carried 11 RustSec
   advisories on one branch while the other two were clean).
7. **GitHub Actions are SHA-allowlisted** in the repository settings:
   every new or bumped action (dependabot or manual) fails CI at startup
   until the allowlist is updated — update the allowlist **before** the
   workflow change, never after.
8. **No secrets, ever**: `tokens.example.json` carries only
   `ghp_EXAMPLE_DO_NOT_USE_*` placeholders; a live credential lives in the
   gitignored `.pi-release/` kit and is **revoked after use**.
9. **No local paths** (`/tmp/`, `/root/`, `/workspace`, hostnames) in any
   tracked file — test fixtures included.
10. **No orphan references**: when a document, module or rule is removed,
    grep for everything that pointed at it (rustdoc, README, AGENTS.md)
    and fix the references in the same change.

## 7. Known gotchas

- `quinn` sits in `Cargo.lock` as a weak-dep of reqwest's TLS feature graph
  and is **never compiled** (`cargo tree -i quinn` shows no build path) —
  do not "fix" it out of the lockfile by hand.
- GitHub search API quota is 30 requests/min (no `Retry-After` on that one)
  while core is 5000/h; the park/abort semantics above were validated live.
- A `--token-file` may carry a UTF-8 BOM (Windows editors); the loader
  strips it.
- Empty repositories answer **409** on `/commits` — skipped with a warning
  at every resource boundary, never an abort.
- A `429` is always transient (park), even with `X-RateLimit-Remaining: 0`:
  the quota check is gated on the status before the header is consulted
  (pinned by `src/github/paginated.rs`:
  `a_429_with_a_spent_quota_header_is_transient_not_a_retirement`) — the
  pre-0.7.0 branches once retired such tokens while the doc claimed
  otherwise. Doc claims and code must never diverge: if the doc says it,
  a test pins it.
