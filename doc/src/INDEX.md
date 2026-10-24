# Introduction

git2mail extracts the email addresses a GitHub account exposes through its
public activity: repository commits, profile events, and repository
search. It is
a command-line tool: you type commands in a terminal, the text window on
your computer (Terminal on Mac and Linux, PowerShell on Windows), instead
of clicking buttons.

```
git2mail scan   --url <github URL> [--token …|--token-file …] [--json <path>]
git2mail search --query <q> [--language <l>] [--limit N]
                [--token …|--token-file …] [--json <path>]
git2mail email  <address> [--token …|--token-file …] [--json <path>]
git2mail emails <file> [--token …|--token-file …] [--json <path>]
git2mail user   <username> [--variant-pattern <p>]
                [--token …|--token-file …] [--json <path>]
git2mail org    <org> [--limit N] [--token …|--token-file …] [--json <path>]
```

`search` also accepts filter flags: `--stars`, `--forks`, `--size`,
`--created`, `--pushed`, `--license`, `--topic`, `--user` and `--org`, with
concrete examples in [GitHub API usage](API.md) and `git2mail search --help`.

> How to read the commands below: text in `[square brackets]` is optional,
> `|` means "or", and `<lowercase words>` stand for values you fill in: never type the brackets themselves.

`scan` accepts a repository URL or a profile URL; `search` runs a
repository search query and scans every result. `email` and `emails`
reverse one address (or a list) into GitHub accounts; `user` investigates
a profile (identity history, external contributions, generated email
variants, secondary accounts, SSH keys); `org` investigates an
organization's members and repositories. The investigation commands (`user`, `email`, `emails`, `org`) report on
screen like the scan commands, and through the opt-in JSON report
(`--json <path>`) when you want to save them (see [Results](OUTPUT.md)).

## Installation

The easiest way: download the ready-made program from the
[releases page](https://github.com/extiop/git2mail/releases): no
installation needed. If you already have the Rust toolchain, you can instead
install from crates.io:

```
cargo install git2mail --locked
```

Prebuilt binaries are also attached to each
[release](https://github.com/extiop/git2mail/releases).

## Design principles

- **GitHub REST API only.** No HTML scraping, no binary git dependency:
  every fact git2mail reports comes from the documented API.
- **Minimal dependencies.** Everything doable with `std` is done with
  `std`; every dependency is taken with `default-features = false` and
  explicit features. Errors are hand-made (an `#[non_exhaustive] enum`
  with explicit `From` conversions), panics never occur on the runtime
  path, and the test suite runs fully offline against a local HTTP mock.
- **Blocking I/O with bounded parallelism.** Scans use `reqwest::blocking`
  over `std` threads; the multi-repository search fan-out spawns
  `min(live_token_count, repository_count)` workers, one live token per
  worker, draining a shared queue of repositories. No async runtime.

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

## Interrupting a run

Ctrl-C aborts the run immediately: nothing is written, not even a partial
report, so a truncated scan can never look complete. Re-run the same
command to start over.
