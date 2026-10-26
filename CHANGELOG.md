# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.7.0] - 2026-10-26

git2mail grows from 2 to 6 subcommands: the tool now investigates whole
profiles, organizations and individual email addresses, not just
repositories, and every long run is warned and provably honest in
its reports (the commit walks cover full histories: the only caps left are
GitHub's own).

### Added

- result files publish atomically through staging files, and the staging files an interrupted run leaves behind (a crash or a `kill -9` between the staging write and the rename) are swept on the next publish of the same folder
- `--csv <PATH>` on `scan`, `search` and `org`: a spreadsheet export of the per-author correlation report, one row per author (name, emails, repositories, dominant language, commit count), RFC 4180-escaped so a hostile commit name can never forge spreadsheet rows
- `last_commit_date` on every `correlation.authors` entry (scan/search/org JSON reports): the most recent commit author date seen for the author (raw ISO 8601 UTC from the API payload), so an exposure's age can be judged without re-scanning (self-declared forgeable metadata, like the author name)
- `user` also writes the paste-able `results/user/<username>` file (one observed email per line, the same deliverable as `scan`/`search`/`org`)
- exit code `3` when `scan`/`search` complete without finding any email: scripting can tell "a live target that carries no email" apart from a real failure (exit `1`)
- a spent hourly quota parks the token until the `x-ratelimit-reset` instant instead of retiring it for the run, and a run stopped by secondary pauses (per-minute search quota, abuse windows) fails with the dedicated paused error naming the minutes-long wait; a parked token rejoins the pool on its own
- a startup egress-proxy check: the proxy environment variables are resolved exactly the way the HTTP stack resolves them (scope precedence with the `ALL_PROXY` fallback, case-sensitive `socks` schemes, a set-but-empty variable shadowing its lowercase twin, full URI validation), the proxy actually used is announced, and a set-but-unusable one (a typo'd scheme, a stray character, an empty value) is named with a loud warning instead of the stack's silent fallback to a direct connection, so a privacy-sensitive run never believes it is behind Tor while leaving from the real IP; a set `REQUEST_METHOD` (the stack's CGI marker, which discards every proxy variable, warned when any proxy variable is set) and a set `NO_PROXY` (which can bypass the proxy for some hosts, warned when a proxy is in use) are warned about too, and proxy values are never logged (a proxy URL can carry embedded credentials)
- every degrading event (a skipped repository, a parked or dead token, a truncated listing) logs at `warn`, so the terminal never shows a green-looking run that silently lost coverage

- `user` subcommand: a full GitHub profile investigation.
  - recovers the usernames and real names the account exposed through its commit history (the `users.noreply.github.com` technique);
  - lists its external contributions and its public SSH keys;
  - generates the email variants a person named that way would plausibly use (built-in first/last/initial patterns, plus repeatable custom `--variant-pattern` templates), and looks for potential secondary accounts sharing the recovered names and usernames.
- `email` and `emails` subcommands: the reverse lookup, from one or many email addresses to the GitHub accounts likely behind them.
  - heuristic technique with an honest confidence grade per candidate (`commit-author` or `repo-owner-weak`);
  - the bulk mode fans out over the token pool (`#` comment lines and blank lines allowed in the input file), and an interrupted run keeps the lookups already paid for: the partial report reaches the requested `--json` file and the never-processed addresses are listed in `skipped_addresses`.
- `org` subcommand: a GitHub organization investigation covering members, repositories, and a parallel email scan of the repositories' commits, with a per-repository and global email report and the same one-email-per-line result file as the scan subcommands (`results/org/<org>`).
- `--json -`: the JSON report printed to stdout instead of written to a file (usable in pipelines: `git2mail scan --url https://github.com/owner/repo --json -` emits only the JSON document on stdout, the log goes to stderr).
- Caps on the long-running paths the GitHub API itself bounds, each announced in the log when it triggers:
  - profile event scans at 300 events;
  - search results at GitHub's 1000-result ceiling;
  - variant generation at 64 name pairs × 64 domains (1000 generated addresses);
  - custom `--variant-pattern` templates validated client-side (syntax and a 64-pattern cap, rejected before any request).
- No local caps on the commit walks: every repository listing (scan, search, org, user, reverse-lookup candidates) covers its full default-branch history and ends when GitHub's listing ends
- `scanned.partial` in the JSON report: `true` when a parallel scan kept its findings although a dedicated token died mid-scan (a spent quota parked until its reset, a parked window expired or a token was rejected), so listed repositories may have been left unscanned: the report must never be mistaken for a complete one (a scan that scanned every listed repository always reports `partial: false`: the other truncations, namely the search ceiling and a discarded search window, are announced as log warnings); the `scan`/`search` and `org` reports carry `scanned` counters
- Report provenance: every JSON report carries `generated_at` (the UTC timestamp of the run, `YYYY-MM-DDTHH:MM:SSZ`, no new dependency: a hand-rolled RFC 3339 formatter) and `tool_version` (the version that wrote it); a `search` report additionally records the request that produced it (`request.query`, `request.language` and every advanced qualifier actually provided), so two runs with different qualifiers never write indistinguishable reports
- `per_repository` in the `search` JSON report: a keyword search breaks its findings down per repository (`owner/name` → emails), so a multi-repository run can be read per project without re-running it
- `skipped_addresses` in the bulk `emails` JSON report: the file-order list of the addresses a stopped worker never reached (the inventory behind `summary.skipped`), so re-running the interrupted lookups needs no diff of two files
- `--include-forks` on `user`, `org` and `search`: forked repositories are skipped by default on those subcommands (the keyword search previously scanned forks, reporting upstream developers under the fork's name and spending requests on another project's history); the flag scans them too when the forks themselves are the subject. The reverse-email candidate search keeps forks: it wants any repository carrying the address

### Changed

- Rate-limit classification: a `429 Too Many Requests` parks the token (never retires it), a spent search quota parks instead of retiring, and an HTTP 401 explicitly retires the rejected token and reports it as a credentials problem rather than a raw HTTP error
- A transport-level failure (a connection refused or dropped, a timeout) in the parallel search fan-out now skips the one repository with a warning instead of aborting the whole scan, so a one-second network hiccup no longer throws away every finding; the `org` investigation keeps its complete-report contract and still aborts
- Result file names are anti-clobber: a name the sanitizer changed carries a 16-hex name-derived suffix (a hash of the raw name), so distinct targets whose names collapse onto the same sanitized file name can no longer silently overwrite each other; an unchanged name keeps its exact file name. Result file names are also capped at 200 bytes with the hash taken over the full raw name
- Every user-facing string (`--help` texts, error messages, terminal warnings) was rewritten in plain English for non-developers (recruiters, journalists, investigators): internal jargon (pool, qualifier, retired, capped, heuristic) is replaced or explained in place, every error carries a next step
- Terminal warnings carry their own `[!]` marker (success is `[+]`, errors `[-]`): a partial-scan warning stays scannable once terminal colors are stripped (redirects, screen readers, plain terminals), instead of looking like progress chatter
- The startup banner no longer prints above `--help` output, and the "Top authors" summary prints one line per author instead of a single wrapped line
- Result files are published atomically (written to a temporary file then renamed), so an interrupted run can no longer leave a half-written result file, and a symlink at the result path is refused instead of being written through
- URLs targeting another host than github.com (or a port other than the default one) are rejected upfront with a named error instead of being silently scanned against the github.com namesake
- A repository whose commits listing answers `409 Conflict` (an empty repository) is skipped with a warning as a resource-scoped condition instead of surfacing as a raw HTTP error (`Error::EmptyRepository` in the library API), and a scan of an empty repository answers with a plain "GitHub repository is empty" error instead of a raw HTTP failure
- Token-file handling hardened: duplicate tokens are detected and deduplicated with a warning at load time, a UTF-8 BOM is tolerated (Windows editors prepend it), control characters and internal whitespace are rejected at load time instead of failing every request with a misleading "rejected token" error, and reads are size-capped (1 MiB for a token file, 64 MiB for a GitHub response body) so a hostile or broken input can never exhaust memory
- Repository and profile URLs are normalized and hardened before any request: `..` path segments and scheme-less foreign hosts (`gitlab.com/owner/repo` typed without a scheme) are rejected with a named error, URLs are capped at 2048 bytes, trailing slashes and `?`/`#` paste artifacts are stripped, and a hostile listing entry whose name could corrupt a composed URL (a dot segment, a path separator) is skipped with a warning instead of being scanned
- Internal refactors and CI hardening with no user-visible behavior change: one shared token-pool runner, struct-shaped scan results, shared budget/422 helpers, and CI runner images pinned to explicit versions (ubuntu-26.04, macos-26 arm64, windows-2025-vs2026); details in `AGENTS.md` and the code docs

### Fixed

- The noreply filter matches the exact `users.noreply.github.com` domain instead of any address containing the substring `noreply`, which wrongly excluded legitimate third-party addresses (a data-quality regression: old releases silently discarded real, reachable addresses)
- A missing token or addresses file now reads `cannot read the file "tokens.json": … — check the path …` instead of a bare `I/O error: … (os error 2)`, and an intercepted or captive-portal connection gets its own "could not read GitHub's response" guidance instead of "check your internet connection"
- Tokens pasted with a leading or trailing space no longer fail every request with a misleading "rejected token" error: paste artifacts are trimmed at load time

## [0.6.0] - 2026-10-25

### Added

- Per-author attribute correlation (issue #5): every scan now aggregates its results per author with the attributes it already collects, namely the emails used, the repositories seen in (with the primary language the search API metadata reports, `null` for `scan` runs that would need an extra call), the first repository where the author appeared and the total commit count, sorted by commit count, languages dominant first. Exposed in the opt-in `--json` report as a `correlation` object added on top of the unchanged legacy fields, and summarized in the terminal log (top authors with their dominant language). Documented delta from the roadmap sketch: the per-language `results/$language/$author` output layout is delivered as this JSON correlation report instead: the plain-text result files stay unchanged, so no extra output tree is created. The same author seen in several repositories (across pages, workers or scan stages) is merged: emails deduplicated, hits summed. The plain-text outputs stay byte-identical (pinned by a property test), with no new dependency and the zero-panic guarantee
- Advanced repository-search qualifiers on the `search` subcommand (issue #6, following [GitHub's advanced search](https://github.com/search/advanced) semantics): `--stars`, `--forks`, `--size` (KB), `--created`, `--pushed`, `--license`, `--topic` and the mutually exclusive `--user`/`--org` owner filter. They compose with `--query`, `--language` and `--limit`; only the provided qualifiers are appended to the `q` parameter (space-joined, percent-encoded with the existing hand-rolled helper). Values are validated client-side before any network request: a malformed range or date fails fast with the new `Error::InvalidSearchQualifier` ([ANSSI-FR/MLA](https://github.com/ANSSI-FR/MLA)-style hand-made error, no new dependency), and `git2mail search --help` documents every flag with concrete examples

### Changed

- The default log level is now `info`: the scan report is visible without any environment setup (`RUST_LOG` still takes precedence when set). Previously a successful scan printed nothing below `error`
- Token-pool events are visible in the log: each token's hourly allowance running out and GitHub's slow-down pauses are reported as they happen, instead of staying silent
- The CLI `Command` enum's `clippy::large_enum_variant` allowance moves from `#[allow]` to `#[expect]` with its justification at the attribute (a stale or unfulfilled allowance now fails the build), and the `Cargo.toml` lint-table inventory documents the complete allowance set

## [0.5.0] - 2026-10-24

### Hardening

- MLA-style strict lints table in `Cargo.toml` (single-crate equivalent of [ANSSI-FR/MLA](https://github.com/ANSSI-FR/MLA)'s workspace lints): `rust::missing_docs = deny` makes the public documentation part of the API surface, and the clippy restriction lints `unwrap_used`, `expect_used`, `panic`, `todo`, `unimplemented` are denied so the runtime path can never panic (`clippy::all` stays denied through the `-D warnings` convention). The only allowances are the two static regex `LazyLock` inits of `src/parsers.rs` (a static regex failing to compile is a programming error) and the test modules, where failing loudly is the point
- Rustdoc completeness: every public item of the lib (errors, github, output, sources, parsers) documents what it does, which errors it returns and that it never panics; `cargo doc --no-deps` passes with `RUSTDOCFLAGS=-D warnings` (broken intra-doc links of the sources module fixed)
- CI gates: a `doc` job runs `cargo doc --no-deps` with `RUSTDOCFLAGS=-D warnings` alongside the existing build/test/fmt/clippy jobs (the `cargo fmt --check` gate already existed as the `fmt` job)
- Sources reformatted with `cargo fmt`; `cargo fmt --check` is clean

### Changed

- **BREAKING**: replace the flat CLI flags with clap derive subcommands: `git2mail scan --url <URL>` and `git2mail search --query <q> [--language <l>] [--limit N]`, with shared `--token`/`--token-file`/`--json` flags
- Refactor the GitHub access layer: [ANSSI-FR/MLA](https://github.com/ANSSI-FR/MLA)-style hand-made `errors.rs` (`Result<T, Error>` everywhere, zero `expect()`/`unwrap()` on the runtime path), a validated token pool (`TokenPool`), and one generic paginated fetch loop (`fetch_paginated`) replacing the four copy-pasted fetch + token-rotation loops
- Rotate tokens only on real rate limits (429, or 403 with an exhausted quota, a `Retry-After` header, or an abuse/secondary body); other 403s now surface as "GitHub resource is private or unavailable"
- Distinguish primary quota exhaustion (`X-RateLimit-Remaining: 0`, the token is retired for the process) from secondary rate limits (429/`Retry-After`/abuse body, the token is only parked until its window passes and is then reused); rotate immediately to another live token instead of sleeping, and add 30 s request timeouts
- Scan orchestration lives in `src/sources/{profile,repository,search}.rs` instead of the slimmed `src/controller.rs` (same role: CLI → scans; pagination and token rotation live in `github/`)

### Fixed

- The opt-in `--json` report is written even when the scan found no email: the report is then empty and the run still ends with the "no result found" error (a file the user explicitly asked for appears on the failing run)
- Infinite loop when every token was rate-limited: the scan now ends with a clear "rate limit exceeded" error instead of re-requesting forever with the same token
- 404s surface as a clean "GitHub resource not found" error
- Results are written relative to the current working directory (`./results/…`) instead of the original Cargo project root, fixing `cargo install` usage (`get_project_root()` removed)
- `--limit 0` is now rejected by the CLI instead of fetching one page and reporting a misleading "no result found"
- Output file names are sanitized (path separators and Windows-reserved characters replaced, trailing dots/spaces trimmed), so a query like `a/b` or `language:rust` can no longer make the write fail after a full scan
- A successful response whose `X-RateLimit-Remaining` header is `0` (the request that consumed the last credit of the hour) is no longer misread as a spent quota: the page is returned and the token stays usable
- A hostile `Retry-After` header (absurd or `Instant`-overflowing value) can no longer crash the scan: the window is capped to one hour
- A revoked or invalid token no longer aborts a parallel search: its worker stops and the other tokens keep draining the queue, like a spent quota
- A repository that cannot be scanned on its own (404 of a stale search-index entry, 403 of a private repository or a token without the right scope) no longer aborts a parallel search nor silently truncates it to a partial result: the worker skips it with a warning and keeps pulling work; only an HTTP 401 is treated as a dead token
- The JSON report's `scanned.repos` counts the repositories actually scanned instead of the number listed: warn-skipped repositories in the profile fallback, and work never pulled by a stopped search worker, no longer overstate coverage
- The parallel search keeps a complete (or partial) result even when every worker's token died on its final requests, instead of discarding the emails found
- Output file names whose stem is a Windows reserved device name (`CON.txt`, `nul.json`…) are prefixed with `_` too, not only the bare names

### Added

- Parallel repository scanning for `search` (std threads, no async): `min(tokens, repositories)` workers pull repositories from a shared queue, each worker owning one dedicated token with no contention; a worker whose dedicated token is rate-limited stops pulling work but does not fail the scan; the other workers' tokens keep draining the queue and the emails found so far are kept (the scan only fails when no worker can make progress)
- Opt-in JSON report with `--json <path>`: `{ "target", "mode": "repository|profile|search", "emails", "scanned": { "repos", "pages" } }`; the text output format is unchanged

## [0.4.7] - 2026-08-04

### Added

- Professionalize repository structure to match [ANSSI-FR/MLA](https://github.com/ANSSI-FR/MLA)'s conventions

### Fixed

- Modernize CI/CD workflows: replace deprecated `actions-rs/*` with `dtolnay/rust-toolchain`, direct cargo commands, `rustsec/audit-check`
- Replace deprecated release actions with `actions/create-release` + `actions/upload-release-asset`
- Fix release workflow version extraction and `cargo_arg` bug
- Add `.cargo/config.toml` for Windows static linking
- Bump dependencies to fix 11 security vulnerabilities

## [0.4.6] - 2026-02-21

### Added

- Optimize runtime performance at compilation

### Fixed

- Bump and minimize dependencies

## [0.4.5] - 2025-03-03

### Fixed

- Bump dependencies
- Fix for new github release workflow

## [0.4.4] - 2025-01-03

### Added

- Add `Cargo.lock`
- Pin all github actions

### Fixed

- Bump dependencies
- Release github workflow

## [0.4.3] - 2024-06-13

### Added

- Added philosophy and some performances

### Fixed

- Bump dependencies

## [0.4.2] - 2023-05-29

### Fixed

- Size optimization for release mode
- Bump dependencies

## [0.4.1] - 2023-03-10

### Fixed

- Size optimization for release mode
- Bump dependencies

## [0.4.0] - 2022-12-21

### Added

- Idiomatic Rust with Error Handling

### Fixed

- Major codebase refactors and fixes to work with idiomatic Rust

## [0.3.5] - 2022-09-29

### Fixed

- Bump dependencies

## [0.3.4] - 2022-09-21

### Fixed

- Results folder creation fixes

## [0.3.3] - 2022-07-20

### Fixed

- Dependencies update

## [0.3.1] - 2022-07-18

### Fixed

- Profile fetching minor fixes

## [0.3.0] - 2022-07-16

### Added

- Get emails from a GitHub profile
- Unauthenticated requests added
- CI/CD workflow implemented
- Documentation from `cargo` generated

### Fixed

- Code quality improved

## [0.2.0] - 2022-06-08

### Added

- Get emails from a GitHub repository
- Aggregate repositories from a metadata search to retrieve their author emails
- Parse author from several GitHub repository URLs formats
- Parse repository from several GitHub repository URLs formats
