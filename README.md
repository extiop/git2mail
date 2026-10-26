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

git2mail finds the email addresses developers leave in GitHub's public
commit history, using only what GitHub's public API already exposes. It
is built for recruitment and sourcing, journalism and fact-checking,
security and compliance investigations, and open-source research.

Trust basics: LGPL-3.0-only free software, built from a pinned,
dependency-minimal Rust codebase, and every release binary is signed and
logged by GitHub's artifact attestation.

> **Responsible use.** git2mail collects only publicly available data
> through the GitHub REST API. Use it solely for lawful, authorized OSINT
> research, in accordance with the
> [GitHub Terms of Service](https://docs.github.com/en/site-policy/github-terms/github-terms-of-service)
> and applicable laws. Email addresses are personal data in many
> jurisdictions: check the rules that apply to how you store and use
> them. Every JSON report stamps its run date and version (`generated_at`,
> `tool_version`), so keep the exact command alongside any report you
> preserve as evidence. You are solely responsible for your use.

## The six subcommands

| Command | When to use it |
|---|---|
| `scan --url <repo-or-profile>` | You have one repository or profile URL: it recovers the emails behind its commits. |
| `search --query <q>` | You have a topic, not a target: it searches GitHub and scans the matching repositories (top 5 by default, `--limit N` to change; metadata filters included). |
| `user <username>` | You have a login: full profile investigation — usernames/names history, email variants, secondary accounts, SSH keys, external contributions. |
| `email <address>` | You have one address: reverse lookup back to the GitHub account, with a confidence grade (`commit-author` proven by a commit, `repo-owner-weak` a presumption only). |
| `emails <file>` | You have many addresses: the same reverse lookup in bulk over the token pool. |
| `org <org>` | You have an organization: members, repositories, and the emails found scanning them. |

Every deep topic — URL rules, JSON report shapes, the confidence grades,
rate-limit semantics, proxies and Tor — has one home: the
[user guide](https://extiop.github.io/git2mail/). This README keeps the
short version.

## Quickstart

### 1. Get the program

Download the ready-made binary for your computer from the
[releases page](https://github.com/extiop/git2mail/releases) (`git2mail-windows-v<version>.exe`,
`git2mail-macos-v<version>`, `git2mail-linux-static-v<version>`) and run
it from a terminal — no installation needed. Install hints:

- Windows shows a "Windows protected your PC" screen: verify the file's
  attestation (`gh attestation verify --repo extiop/git2mail <file>`)
  then *More info* → *Run anyway*.
- macOS refuses a quarantined download: `xattr -d com.apple.quarantine git2mail-macos-*`.
- Prefer `cargo install git2mail --locked` (crates.io) or build from
  source if you have Rust; the build needs `cmake`, a C compiler and
  `pkg-config`.

The full per-OS walkthrough (SmartScreen, Gatekeeper, PATH setup) lives
in the guide's [installation notes](https://extiop.github.io/git2mail/).

### 2. Try it now, without any account

```bash
git2mail scan --url https://github.com/octocat/Hello-World
```

Without a token, GitHub allows about 60 lookups per hour — enough for a
first try on a small repository; a big one spends the whole allowance
and stops with a rate-limit error before writing anything. A successful
scan prints something like:

```text
Starting git2mail!
[!] no token provided: running anonymously, limited to 60 requests/hour — create one at github.com/settings/tokens and use --token or --token-file <tokens.json> for 5000 requests/hour each
--------------------------------
[+] Found 3 emails
[+] Result is available at results/repository/octocat_Hello-World.log
[+] Top author 1: John Doe <john@doe.example> — unknown language, 1 commits
```

Without a token, GitHub attributes every query to your IP address; the
client honors the standard `HTTPS_PROXY`/`ALL_PROXY` variables (Tor's
`socks5h://127.0.0.1:9050` works) and announces a proxy in use at
startup — on a sensitive target, verify your exit IP (see the guide's
[network egress notes](https://extiop.github.io/git2mail/)).

> **These files hold personal data.** The `results/` files are plain-text
> lists of real people's email addresses, created readable by you only
> (0600 on Unix). Store and share them with the same care as the data
> itself, delete them when you are done, and add `results/` to your
> `.gitignore` if you run this tool inside a git repository. They carry a
> `.log` extension, so a double-click opens them in your default text
> editor.

The result file is one email per line, ready to paste. A URL copied
from a GitHub page is cleaned where it can be (trailing `/`, `?tab=…`)
or fails with a named error — a `/tree/…` link targets a subfolder:
paste the repository root. These addresses
are read from public commit metadata: they can be old or spoofed — see
[Data quality](https://extiop.github.io/git2mail/) before contacting
anyone, and remember a prolific pull-request contributor whose PRs were
squash-merged through GitHub's web UI can stay invisible to the scan and
search commands.

### 3. Create a token for real scans

A token raises the limit from about 60 to 5,000 lookups per hour: create
one at <https://github.com/settings/tokens> (classic, no scope needed, or
fine-grained with *Public repositories (read-only)*), save one or more
into a `tokens.json` copied from `tokens.example.json`, and pass it with
`--token-file tokens.json`. Prefer `--token-file` over `--token`: a
command-line token stays in your shell history. Each additional account
you own adds its own 5,000 requests per hour, within what GitHub's Terms
of Service allow.

### 4. Adjust the verbosity (optional)

Set `RUST_LOG=debug` for a chattier run (`$env:RUST_LOG='debug'` first on
PowerShell).

## Performance

Measured on one run (git2mail v0.8.0 release build, one token,
2026-10-26): scanning the full default-branch commit history of
[denoland/deno](https://github.com/denoland/deno) — 17,397 commits across
174 listing pages — recovered 952 unique email addresses in 2 minutes 26
seconds of wall time. The traffic went through an HTTPS egress proxy
during this measurement, so the wall time includes proxy round-trips; a
direct connection may be faster or slower. Extra tokens deepen the
request quota and parallelize multi-repository runs (one worker per live
token pulls repositories from a shared queue), but a single repository's
history walk is sequential and is not made faster by them. A history
walk is bounded only by GitHub's API itself — nothing is truncated
locally — and a scan that loses coverage mid-run says so
(`scanned.partial` in its JSON report).

## Examples

Each example is one command; the flags and caveats are one guide page
away.

```bash
# Scan one repository (or a profile: https://github.com/denoland)
git2mail scan --url https://github.com/denoland/deno --token-file tokens.json

# Keyword search over GitHub, with metadata filters
git2mail search --query nmap --language rust --stars '>100' --token-file tokens.json

# Full profile investigation
git2mail user "jane-doe" --token-file tokens.json

# Reverse email lookup (one address, or a file of addresses)
git2mail email "jane.dupont@acme.com" --token-file tokens.json
git2mail emails addresses.txt --token-file tokens.json --json bulk.json

# Organization investigation
git2mail org "acme" --token-file tokens.json
```

Add `--json report.json` to any command to save the structured report
(`--json -` prints it to stdout for pipes), or `--csv authors.csv` on
scan, search and org for a one-row-per-developer spreadsheet.

## Roadmap

- [x] From a GitHub repository, search for commits and email of authors with GitHub metadata and parsing
- [x] From a GitHub keyword search, retrieve GitHub repositories URLs
- [x] Handle properly errors and limit, or even remove, panics
- [x] Correlate emails, language and project preferences: per-author correlation report (see the guide, [Reports & files on disk](https://extiop.github.io/git2mail/))
- [x] Support more advanced parameters (see <https://github.com/search/advanced>): `--stars`, `--forks`, `--size`, `--created`, `--pushed`, `--license`, `--topic`, `--user`/`--org` on the `search` subcommand
- [x] Full profile investigation, API-only: `git2mail user <username>` (see the guide, [User investigation](https://extiop.github.io/git2mail/))
- [x] Reverse email lookup, API-only heuristic: `git2mail email <address>` / `git2mail emails <file>` (see the guide, [Reverse email lookup](https://extiop.github.io/git2mail/))
- [x] Organization investigation, API-only: `git2mail org <org>` (see the guide, [Organization investigation](https://extiop.github.io/git2mail/))
- [x] Extensible `user` variant combinatorics: `--variant-pattern <PATTERN>` (repeatable) probes custom email conventions (`{first}`, `{last}`, `{initial}` placeholders) after the built-in patterns, still API-verified
- [ ] A graphical or web interface, so non-technical users (recruiters, sales, investigators) can run these searches without a terminal

## Repository

This repository contains:

* `src`: the Rust source code implementing git2mail
* `doc`: the user guide sources, published at https://extiop.github.io/git2mail/
* `.github`: Continuous Integration needs, community files and issue/PR templates
* `.cargo`: Cargo configuration for cross-platform builds
* `tokens.example.json`: example token file showing the multi-token format

Ideas the maintainer keeps in view for future releases: fuzzing to find
code vulnerabilities; ~~async queries~~ **resolved by design**: parallel
requests run on std threads with one dedicated token per worker.

## Contributing

If you would like to contribute, read and follow [`CONTRIBUTING.md`](.github/CONTRIBUTING.md).

## License

This project is free software, and is released under the terms of the LGPL (GNU Lesser General Public License) version 3.
