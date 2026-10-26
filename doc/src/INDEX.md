# Introduction

git2mail extracts the email addresses a GitHub account exposes through its
public activity: repository commits, profile events, and repository
search. It comes in two shapes: a **command-line tool**, where you type
commands in a terminal (the text window on your computer: Terminal on
Mac and Linux, PowerShell on Windows), and an **anonymous web scan** -
a browser page, no account and no install, capped at GitHub's anonymous quota (its
allowance for unauthenticated calls) - described on [the project site](https://extiop.github.io/git2mail/).

> **Responsible use.** git2mail collects only publicly available data
> through the GitHub REST API. Use it solely for lawful, authorized OSINT
> research, in accordance with the GitHub Terms of Service and applicable
> laws: email addresses are personal data in many jurisdictions, and the
> `results/` and report files this tool writes hold them. The handling
> duties are covered in detail in
> [Data quality, prevention & limitations](QUALITY.md).

```
git2mail scan   --url <github URL> [--token …|--token-file …] [--json <path>]
git2mail search --query <q> [--language <l>] [--limit N] [--include-forks]
                [--token …|--token-file …] [--json <path>]
git2mail email  <address> [--token …|--token-file …] [--json <path>]
git2mail emails <file> [--token …|--token-file …] [--json <path>]
git2mail user   <username> [--variant-pattern <p>] [--include-forks]
                [--token …|--token-file …] [--json <path>]
git2mail org    <org> [--limit N] [--include-forks]
                [--token …|--token-file …] [--json <path>]
```

> How to read the commands above: text in `[square brackets]` is optional,
> `|` means "or", and `<lowercase words>` stand for values you fill in: never type the brackets themselves.

Forked repositories are skipped by default on `user`, `org` and `search` (their
commit history mirrors the upstream project's); `--include-forks` scans
them too.

`search` also accepts filter flags: `--stars`, `--forks`, `--size`,
`--created`, `--pushed`, `--license`, `--topic`, `--user` and `--org`, with
concrete examples in [GitHub API usage](API.md) and `git2mail search --help`.

`scan` accepts a repository URL or a profile URL; `search` runs a
repository search query and scans every result. `email` and `emails`
reverse one address (or a list) into GitHub accounts; `user` investigates
a profile (identity history, external contributions, generated email
variants, secondary accounts, SSH keys); `org` investigates an
organization's members and repositories. The investigation commands (`user`, `email`, `emails`, `org`) report on
screen like the scan commands, and through the opt-in JSON report
(`--json <path>`) when you want to save them (see [Results](OUTPUT.md)).

## What is in this guide

- [Scanning: scan & search](SCANNING.md) - the two core subcommands: URL
  rules, keyword search, advanced qualifiers, scripting notes.
- [User investigation](USER.md) - the `user` subcommand: identity
  history via the noreply technique, email variants, secondary accounts,
  SSH keys, external contributions.
- [Organization investigation](ORG.md) - the `org` subcommand: members,
  repositories, per-repository emails.
- [Reverse email lookup](EMAIL.md) - the `email`/`emails` subcommands:
  the candidate-search heuristic, confidence grades, bulk mode.
- [Reports & files on disk](OUTPUT.md) - terminal output, exit codes,
  JSON report shapes, developer correlation, result file layout,
  sanitization and permissions.
- [Data quality, prevention & limitations](QUALITY.md) - what the
  findings can prove, how to harden your own exposure, coverage limits.
- [GitHub API usage](API.md) - requests, pagination, egress (proxies and
  Tor), rate-limit semantics, caps, search behavior.

## Installation

The easiest way: download the ready-made program from the
[releases page](https://github.com/extiop/git2mail/releases): no
installation needed. If you already have the Rust toolchain, you can instead
install from crates.io:

```
cargo install git2mail --locked
```

Building from source needs the Rust toolchain plus `cmake`, a C compiler
and `pkg-config` (the bundled TLS library compiles C code; on macOS,
start with `xcode-select --install` then `brew install cmake
pkg-config`).

### Running the downloaded binary

Pick the file for your computer: `git2mail-windows-v<version>.exe`
(Windows), `git2mail-macos-v<version>` (Mac, Apple Silicon) or
`git2mail-linux-static-v<version>` (Linux; "static" means one single
file, nothing else to install). The builds are signed and logged by
GitHub's artifact attestation (a receipt GitHub generates at build time,
proving this exact file came from this repository's official build
pipeline); verifying requires the GitHub CLI `gh`:
`gh attestation verify --repo extiop/git2mail <file>`, as described in
each release's notes. Replace `<version>` below with the version you
downloaded, without the leading `v`.

Then open a terminal in your Downloads folder and run the
program from there:

- **Windows:** open the Downloads folder in File Explorer, type
  `powershell` in the address bar and press Enter, then run the program
  with its real file name, for example
  `./git2mail-windows-v0.8.0.exe scan --url https://github.com/octocat/Hello-World`
  (a small repository: the anonymous quickstart in the README completes
  on it). If Windows shows a "Windows protected your PC" screen, first
  verify the file's attestation (`gh attestation verify --repo
  extiop/git2mail <file>`, with the GitHub CLI `gh` installed), then
  click *More info* and *Run anyway* (the program is not digitally
  signed).
- **Mac:** in Terminal, type `cd ~/Downloads` then
  `chmod +x git2mail-macos-*` (make it executable) and run a first scan,
  for example `./git2mail-macos-v0.8.0 scan --url
  https://github.com/octocat/Hello-World`. Running the file bare prints
  the help and exits. If the terminal instead prints `zsh: killed` with
  no dialog, macOS silently refused the quarantined file: clear the
  block with `xattr -d com.apple.quarantine git2mail-macos-*` and run it
  again. If macOS says it "cannot be opened because it is from an
  unidentified developer": right-click the file, choose *Open* then
  *Open* again, or clear the block with the same `xattr` command. The
  downloaded program is built for Apple Silicon Macs; on an Intel Mac,
  build from source instead (above).
- **Linux:** `chmod +x git2mail-linux-static-*` then run a first scan,
  for example `./git2mail-linux-static-v0.8.0 scan --url
  https://github.com/octocat/Hello-World`.

The tool is not on Homebrew: get the release binary (above) or build
from source with Cargo.


## Tokens

### Getting a token

Create a classic token at <https://github.com/settings/tokens> with no
scopes at all (reading public data needs none) or a fine-grained token
with "Public repositories (read-only)".

`tokens.example.json` shows the file format `--token-file` expects: one
JSON object mapping a numeric index (`"0"`, `"1"`, …) to a token
string.

Authentication is optional. With no token, requests are anonymous and
subject to GitHub's low anonymous rate limits. Tokens come from `--token`,
or from a JSON file passed to `--token-file` (see
[`tokens.example.json`](https://github.com/extiop/git2mail/blob/main/tokens.example.json));
the format of each token is validated at startup and a token that fails validation
aborts the run before any request is sent.

All tokens are managed by a token pool that allocates them round-robin and
reacts to rate limiting; [GitHub API usage](API.md) specifies the exact
behavior.

For unattended jobs (CI, cron), write the token to a `0600` file at
runtime and pass it with `--token-file`
(`( umask 077; printf '{"0": "%s"}' "$GH_TOKEN" > tokens.json )`; the
umask is what makes the file `0600` when it is created; if `tokens.json`
already exists, `chmod 600 tokens.json` instead), rather than leaking it
through a process list.

## Interrupting a run

Ctrl-C aborts the run immediately: nothing is written, not even a partial
report, so a truncated scan can never look complete. Re-run the same
command to start over.

## Design principles

- **GitHub REST API only.** No HTML scraping, no binary git dependency:
  every fact git2mail reports comes from the documented API.
- **Minimal dependencies.** Everything doable with `std` is done with
  `std`; every dependency is taken with `default-features = false` and
  explicit features. Errors are hand-made (an `#[non_exhaustive] enum`
  with explicit `From` conversions), panics never occur on the runtime
  path, and the test suite runs fully offline against a local HTTP mock.
- **Blocking I/O with bounded parallelism.** Scans use `reqwest::blocking`
  over `std` threads; the multi-repository fan-outs (the keyword search and
  the org scan, shared with the bulk reverse lookup) spawn
  `min(token_count, work_count)` workers when tokens are configured, each
  dedicated the next live token (retired or parked tokens are skipped),
  draining a shared queue; an anonymous run uses a single shared-quota
  worker, and if every configured token is already dead the run still
  fails loudly. No async runtime.
