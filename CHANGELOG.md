# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.6.0] - 2026-10-25

### Added

- Per-author attribute correlation (issue #5): every scan now aggregates its results per author with the attributes it already collects — the emails used, the repositories seen in (with the primary language the search API metadata reports, `null` for `scan` runs that would need an extra call), the first repository where the author appeared and the total commit count — sorted by commit count, languages dominant first. Exposed in the opt-in `--json` report as a `correlation` object added on top of the unchanged legacy fields, and summarized in the terminal log (top authors with their dominant language). Documented delta from the roadmap sketch: the per-language `results/$language/$author` output layout is delivered as this JSON correlation report instead — the plain-text result files stay unchanged, so no extra output tree is created. The same author seen in several repositories (across pages, workers or scan stages) is merged: emails deduplicated, hits summed. The plain-text outputs stay byte-identical (pinned by a property test), with no new dependency and the zero-panic guarantee
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
- A repository that cannot be scanned on its own (404 of a stale search-index entry, 403 of a private repository or a token without the right scope) no longer aborts a parallel search nor silently truncates it to a partial result: the worker skips it with a warning and keeps pulling work — only an HTTP 401 is treated as a dead token
- The JSON report's `scanned.repos` counts the repositories actually scanned instead of the number listed: warn-skipped repositories in the profile fallback, and work never pulled by a stopped search worker, no longer overstate coverage
- The parallel search keeps a complete (or partial) result even when every worker's token died on its final requests, instead of discarding the emails found
- Output file names whose stem is a Windows reserved device name (`CON.txt`, `nul.json`…) are prefixed with `_` too, not only the bare names

### Added

- Parallel repository scanning for `search` (std threads, no async): `min(tokens, repositories)` workers pull repositories from a shared queue, each worker owning one dedicated token with no contention; a worker whose dedicated token is rate-limited stops pulling work but does not fail the scan — the other workers' tokens keep draining the queue and the emails found so far are kept (the scan only fails when no worker can make progress)
- Opt-in JSON report with `--json <path>`: `{ "target", "mode": "repository|profile|search", "emails", "scanned": { "repos", "pages" } }` — the text output format is unchanged

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
