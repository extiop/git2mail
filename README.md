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

Find developers' public email addresses from GitHub, for recruitment, sales, journalism and open-source research.

# Introduction

git2mail is an OSINT tool (OSINT, open-source intelligence, means investigating using only information the public can already see) that finds developers' email addresses from GitHub repositories and profiles. It reads commit metadata through the GitHub API to retrieve author emails, supporting both single and multi-token authentication for large-scale investigations.

> ⚠️ **Responsible use.** git2mail collects only publicly available data
through the GitHub REST API. Use it only for purposes that are lawful and
respectful of the people whose data it shows, for example identifying and
contacting open-source contributors, with a clear introduction and an easy
way to say no, in accordance with the
[GitHub Terms of Service](https://docs.github.com/en/site-policy/github-terms/github-terms-of-service)
and applicable privacy and anti-spam laws. You are solely responsible for
your use.

# Repository

This repository contains:

* `src`: the Rust source code implementing git2mail
* `doc`: the user guide sources, published at https://extiop.github.io/git2mail/
* `.github`: Continuous Integration needs, community files and issue/PR templates
* `.cargo`: Cargo configuration for cross-platform builds
* `tokens.example.json`: example token file showing the multi-token format

## 👁️ Philosophy

git2mail is built for anyone who needs to reach developers (recruiters, sales teams, sourcing specialists, journalists) as well as for fast large-scale open-source research. It can be used with multiple personal access tokens (tokens you create from your own GitHub account settings, <https://github.com/settings/tokens>), so you are no longer tied to a single account and can fetch a large number of emails.

### ⚡ Performances

In the current state of development (synchronous requests, multi-token round-robin with automatic rotation on rate limits and skipping of exhausted tokens), on a big repository https://github.com/denoland/deno : 
- More than 15 000 commits analyzed in **less than a minute** to find **more than 900 emails**

The `search` subcommand scans the found repositories in parallel with one worker per token: each worker owns a dedicated token and pulls repositories from a shared queue, so every token budget is used without contention. Mono-repository and mono-profile scans stay sequential.

## 🚀 Quickstart

1. Download the ready-made program for your computer (Windows, macOS or Linux) from [git2mail releases](https://github.com/extiop/git2mail/releases): unzip it and put the file in a folder you can find. No installation needed: the commands below are run in a terminal (see the [user guide](https://extiop.github.io/git2mail/) for what a terminal is and how to open one)

OR

1. Install [Rust](https://doc.rust-lang.org/cargo/getting-started/installation.html)
2. Get the optimized build for lightning-fast queries:

    ```bash
    git clone https://github.com/extiop/git2mail
    cd git2mail
    cargo build --release
    ```

    Or, you can install its release version directly:

    ```bash
    git clone https://github.com/extiop/git2mail
    cd git2mail
    cargo install --path .
    ```

    Or, via crates.io packages

    ```bash
    cargo install git2mail
    ```

THEN

1. Check [examples](https://github.com/extiop/git2mail#-examples) below
2. Scan your targets

## 📖 Examples

### 🎯 GitHub profile as a target

Fetch some commits or profile events without authentication:

```bash
git2mail scan --url "$TARGET_URL"
```

Note that the URL parameter can be a GitHub repository URL or a profile URL, for instance:

```bash
git2mail scan --url https://github.com/denoland/deno

git2mail scan --url https://github.com/denoland
```

Use a specific token to be authenticated and fetch a large amount of commits:

```bash
git2mail scan --url "$TARGET_URL" --token "$YOUR_TOKEN"
```

The repository URL must follow the following format:

```bash
git://github.com/some-user/my-repo[.git]
git@github.com:some-user/my-repo[.git]
https://github.com/some-user/my-repo[.git]
ssh://git@domain.com/group/app[.git]
```

A trailing `.git` suffix is kept verbatim as part of the repository name: it is passed through to the GitHub API request and included in the output file name (`results/repository/some-user_my-repo.git`).

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

With dummy values:

```bash
git2mail scan --url https://github.com/denoland/deno --token-file tokens.json
```

To also get a JSON report (a structured text file you can open in any text editor, and other software can read) in addition to the on-screen results:

```bash
git2mail scan --url "$TARGET_URL" --json "$YOUR_REPORT_PATH"
```

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

In this mode, your results are saved in a `results/profile/$author` folder inside the folder you ran the command from. If a repository is defined, it will be at `results/repository/$author_$repository`.

### 🏷️ Metadata as a keyword

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

### 🔎 Advanced search qualifiers

The `search` subcommand also accepts the optional qualifiers of [GitHub's advanced search](https://github.com/search/advanced). They all compose with `--query`, `--language` and `--limit`, and only the ones you provide are appended to the GitHub query:

| Flag | Qualifier | Example values |
| --- | --- | --- |
| `--stars <RANGE>` | `stars:` | `>100`, `>=50`, `10..50`, `100..*` |
| `--forks <RANGE>` | `forks:` | `>10`, `5..20` |
| `--size <KB>` | `size:` | `>1000`, `100..5000` |
| `--created <DATE>` | `created:` | `>2020-01-01`, `>=2020`, `2019-01-01..2020-01-01` |
| `--pushed <DATE>` | `pushed:` | `>2024-01-01`, `>=2023` |
| `--license <ID>` | `license:` | `mit`, `apache-2.0` |
| `--topic <NAME>` | `topic:` | `osint`, `recon` |
| `--user <LOGIN>` | `user:` | `extiop` |
| `--org <LOGIN>` | `org:` | `acme` |

For instance, to scan well-established MIT-licensed Rust repositories of one organization, recently pushed:

```bash
git2mail search --query nmap --language Rust --stars '>100' --license mit --org acme --pushed '>2024-01-01' --token-file tokens.json
```

To target one user's repositories on a topic:

```bash
git2mail search --query nmap --topic osint --user extiop --token-file tokens.json
```

`--user` and `--org` are mutually exclusive (the GitHub search API accepts only one owner filter). Values are validated client-side before any request: an obviously malformed range or date (say `--stars abc` or `--created 2020-13-01`) fails fast with a clear `invalid search qualifier` error instead of silently returning no result from the API. Count and date ranges follow the GitHub search range syntax (`>`, `>=`, `<`, `<=`, `start..end`, with `*` for an open end); dates accept the `YYYY`, `YYYY-MM` and `YYYY-MM-DD` granularities. Note that the qualifiers are not part of the output file name: results are stored per query/language, so two runs differing only by their qualifiers write to the same `results/keyword/$query_$language` file, and the last run overwrites the previous one.

### 🔗 Developer correlation

Every scan also aggregates its results per author (issue #5): for each author found in the scanned commits, it correlates the attributes git2mail already collects: the emails they used, the repositories they were seen in with their primary language, the first repository where they appeared and their total commit count. Authors are sorted by commit count and each author's languages are ordered dominant first, so the report answers "who are the main developers behind this topic, and what do they write in?".

The report lives in the opt-in `--json` output, as a `correlation` object added on top of the unchanged legacy fields:

```bash
git2mail search --query nmap --language Rust --token-file tokens.json --json report.json
```

```json
{
  "target": "nmap",
  "mode": "search",
  "emails": ["alice@example.com"],
  "scanned": { "repos": 2, "pages": 3 },
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

The primary language comes free with the repository-search metadata, so `search` runs attribute a language to every repository; `scan` (repository/profile) runs do not spend an extra API call on it and report `null` instead. The same author seen in several repositories (across pages, workers or scan stages) is merged: emails deduplicated, hit counts summed. The terminal log also prints a short summary of the top authors with their dominant language; the plain-text result files keep the legacy one-email-per-line format, byte-identical.

## 🙋 How it works

git2mail uses GitHub repositories metadata regarding commits to get developers' email. git2mail reads the commit history of a GitHub repository and collects the email addresses its developers left there.

This process can be extended to multiple repositories, notably with custom queries. The latter can be done with GitHub metadata such as its language. You can also adjust your terminal output by adding a limit number of repositories scanned.

The GitHub API rate limit for non authenticated users is 60 requests per hour. Thus, if you search classic repositories such as [ripgrep](https://github.com/BurntSushi/ripgrep), which has thousands of commits currently, you better use a GitHub or GitHub App account, and generate one token **per account** following this [GitHub API documentation](https://docs.github.com/en/rest/overview/resources-in-the-rest-api#rate-limiting). Be aware that your token does not need any access to any of your repositories. Anonymous access is supported (`--token ""`), but non authenticated requests are very limited, so tokens remain the practical way to run a real scan. Bear in mind that the rate limit is defined as the number of requests per hour **per account**.

Note that with one token, you can make 5000 requests to the GitHub API per hour; that is the number of commits you can fetch with it. If you need to crawl more commits, you better get multiple tokens. To do so, add tokens from additional accounts you own, within what GitHub's Terms of Service allow. For instance, to analyze the [Go programming language repository](https://github.com/golang/go), you need at least 11 tokens as there is roughly 53 000 commits available at the time I write this documentation.

This project can be combined with other OSINT tools. For instance, you can use git2mail to retrieve some Gmail addresses and then, do further investigation for some of them with [GHunt](https://github.com/mxrch/ghunt).

### ❗ Data quality

One's email can be spoofed in commits: an address read in a commit proves
nothing about who owns the mailbox. Cross-check with the correlation report
(`--json`) before drawing conclusions.

## 🔒 Prevention

Harden your account privacy by enabling these [settings](https://github.com/settings/emails):

- ✔️ Keep my email addresses private
- ✔️ Block command line pushes that expose my email

These settings protect only future commits: an address you committed with
before stays in the repository's history and clones. Scan your own profile
with this tool to see what is exposed, and rewrite old history (for example
with `git filter-repo`) if you need it gone.

## 🎬 Limitations

This project is limited to GitHub repositories.

## 🏎️ Roadmap

- [x] From a GitHub repository, search for commits and email of authors with GitHub metadata and parsing
- [x] From a GitHub keyword search, retrieve GitHub repositories URLs
- [x] Handle properly errors and limit, or even remove, panics
- [x] Correlate emails, language and project preferences: per-author correlation report (emails, repositories with their primary language, first seen repository, commit counts) in the `--json` output, plus a top-authors terminal summary (see the [correlation section](#-developer-correlation) (issue #5)
- [x] Support more advanced parameters (_cf._ <https://github.com/search/advanced>): `--stars`, `--forks`, `--size`, `--created`, `--pushed`, `--license`, `--topic`, `--user`/`--org` on the `search` subcommand (issue #6)

## 💭 Thoughts

- Fuzzing to find my code vulnerabilities
- ~~Async queries~~ **resolved by design** (issue #4): parallel requests run on std threads with one dedicated token per worker (the v0.5.0 refactor); async was considered and rejected, as per-token parallelism is enough for network I/O at this scale and adds no dependency

## 💻 Contributing

Please if you want to bring your stone to the building, read and follow [`CONTRIBUTING.md`](.github/CONTRIBUTING.md).

## ⚖️ License

This project is free software, and is released under the terms of the LGPL (GNU Lesser General Public License) version 3 or (at your option) any later version.
