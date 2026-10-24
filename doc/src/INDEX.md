# Introduction

git2mail extracts the email addresses a GitHub account exposes through its
public activity: repository commits, profile events, and code search. It is
a command-line tool:

```
git2mail scan   --url <github URL> [--token …|--token-file …] [--json <path>]
git2mail search --query <q> [--language <l>] [--limit N]
                [--token …|--token-file …] [--json <path>]
```

`scan` accepts a repository URL or a profile URL; `search` runs a
repository search query and scans every result.

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
  `min(token_count, repository_count)` workers, one dedicated token per
  worker, draining a shared queue of repositories. No async runtime.

## Tokens

Authentication is optional. With no token, requests are anonymous and
subject to GitHub's low anonymous rate limits. Tokens come from `--token`,
or from a JSON file passed to `--token-file` (see
[`tokens.example.json`](https://github.com/extiop/git2mail/blob/main/tokens.example.json));
the format of each token is validated at startup and a token that fails validation
aborts the run before any request is sent.

All tokens are managed by a token pool that allocates them round-robin and
reacts to rate limiting; [GitHub API usage](API.md) specifies the exact
behavior.
