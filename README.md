<div align="center">
  <img src="https://www.zupimages.net/up/22/23/qzk2.png" alt="git2mail logo"/>
</div>

[![Build & test](https://github.com/exti0p/git2mail/workflows/Build%20&%20test/badge.svg)](https://github.com/exti0p/git2mail/actions)
[![Cargo git2mail](https://img.shields.io/badge/crates.io-git2mail-red)](
https://crates.io/crates/git2mail)
[![Documentation git2mail](https://img.shields.io/badge/docs.rs-git2mail-blue)](
https://docs.rs/git2mail)

Lean, fast and safe developers' email finder.

## 👁️ Philosophy

In opposition to https://github.com/mxrch/GitFive, git2mail is meant to be extremely fast for bulk offensive reconnaissance or OSINT. It can be used with multiple tokens (not only linked to one account then) to fetch a huge amount of emails.

### ⚡ Performances

As of current development (monothreaded and synchronous requests), on a big repository https://github.com/denoland/deno : 
- More than 11 750 commits analyzed in **less than a minute**
- Found **more than 760 emails**

## 🚀 Quickstart

1. Get your executable according to your requirements with [git2mail releases](https://github.com/exti0p/git2mail/releases)

OR

1. Install [Rust](https://doc.rust-lang.org/cargo/getting-started/installation.html)
2. Get the optimized build for lightning-fast queries:

    ```bash
    git clone https://github.com/exti0p/git2mail
    cd git2mail
    cargo build --release
    ```

    Or, you can install its release version directly:

    ```bash
    git clone https://github.com/exti0p/git2mail
    cd git2mail
    cargo install --path .
    ```

    Or, via crates.io packages

    ```bash
    cargo install git2mail
    ```

THEN

1. Check [examples](https://github.com/exti0p/git2mail#-examples) below
2. Scan your targets

## 📖 Examples

### 🎯 GitHub profile as a target

Fetch some commits or profile events without authentication:

```bash
./git2mail --url "$TARGET_URL"
```

Note that the URL parameter can be a GitHub repository URL or a profile URL, for instance:

```bash
./git2mail --url https://github.com/denoland/deno

./git2mail --url https://github.com/denoland
```

Use a specific token to be authenticated and fetch a large amount of commits:

```bash
./git2mail --url "$TARGET_URL" --token "$YOUR_TOKEN"
```

The repository URL must follow the following format:

```bash
git://github.com/some-user/my-repo[.git]
git@github.com:some-user/my-repo[.git]
https://github.com/some-user/my-repo[.git]
ssh://git@domain.com/group/app[.git]
```

The profile URL must follow the following format:

```bash
git://github.com/some-user
git@github.com:some-user
https://github.com/some-user
ssh://git@domain.com/group
```

And if you have multiple tokens, you can custom `tokens.example.json` to scrape a lot of commits:

```bash
./git2mail --url "$TARGET_URL" --token-file "$YOUR_TOKEN_FILE"
```

With dummy values:

```bash
./git2mail --url https://github.com/denoland/deno --token-file /tmp/tokens.json
```

`tokens.example.json` content, which is available at the root of the project:

```json
{
    "0": "ghp_Pl8xhFwtqbxtoiia8fWwudtgO6EqOb2GdVSf",
    "1": "ghp_kNxrCSGcajrOwtqbxtoiiaMQKkAjKA0WPVWP",
    "2": "ghp_5Pht6hDRNWpuTJHcxCVwtqbxtoiiaI0vBxVB",
    "3": "ghp_KUO6f0z13fwtqbxtoiiawtqbxtoiia0zQgcl",
    "4": "ghp_ZYCsgDDDs3p3bLyBmmGwtqbxtoiia84ZmVMN",
    "5": "ghp_ljP40my9r5VnHUywtwtqbxtoiia5Iq2HdSYt",
    "6": "ghp_VAfWGNkwtqbxtoiiad430JF4PbOk9j3I4uj5",
    "7": "ghp_Adwtqbxtoiiavdp3RznGdeGEuOzxwA0bkXDr",
    "8": "ghp_GjFwtqbxtoiiawtqbxtoiiaHuQjkyY00SVHD",
    "9": "ghp_uiQR88z5IgLLicvcx8wtqbxtoiiaQ705O1Nb"
}
```

In this mode, your results will be stored per profile with the following relative path, from project root: `results/profile/$author`. If a repository is defined, it will be at `results/repository/$author_$repository`.

### 🏷️ Metadata as a keyword

You want to search, for instance, for some Rust developers that create `nmap` related tools:

```bash
./git2mail --query nmap --language Rust --token-file /tmp/tokens.json
```

You can also limit the number of repositories scanned this way, for instance:

```bash
./git2mail --query nmap --language Rust --token-file /tmp/tokens.json --limit 5
```

In this mode, your results will be stored per query with the following relative path, from project root: `results/keyword/$query`. If a language is defined, it will be at `results/keyword/$query_$language`.

## 🙋 How it works

git2mail uses GitHub repositories metadata regarding commits to get developers' email. It browses a repository and scrapes developers' email through its commits.

This process can be extended to multiple repositories, notably with custom queries. The latter can be done with GitHub metadata such as its language. You can also adjust your terminal output by adding a limit number of repositories scanned.

The GitHub API rate limit for non authenticated users is 60 requests per hour. Thus, if you search classic repositories such as [ripgrep](https://github.com/BurntSushi/ripgrep), which has thousands of commits currently, you better use a GitHub or GitHub App account, and generate one token **per account** following this [GitHub API documentation](https://docs.github.com/en/rest/overview/resources-in-the-rest-api#rate-limiting). Be aware that your token does not need any access to any of your repositories. Therefore, I decided to force the use of tokens as non authenticated requests are very limited. Bear in mind that the rate limit is defined as the number of requests per hour **per account**.

Note that with one token, you can request 5000 times the GitHub API per hour, this is the number of commits you can fetch with it. If you need to crawl more commits, you better get multiple tokens. To do so, you can use temporary emails in order to create multiple accounts. For instance, to analyze the [Go programming language repository](https://github.com/golang/go), you need at least 11 tokens as there is roughly 53 000 commits available at the time I write this documentation.

This project can be combined with other OSINT tools. For instance, you can use git2mail to retrieve some Gmail addresses and then, do further investigation for some of them with [GHunt](https://github.com/mxrch/ghunt).

### ❗ Disclaimer

One's email can be spoofed in commits.

## 🔒 Prevention

Harden your account privacy by enabling these [settings](https://github.com/settings/emails):

- ✔️ Keep my email addresses private
- ✔️ Block command line pushes that expose my email

## 🎬 Limitations

This project is limited to GitHub repositories.

## 🏎️ Roadmap

- [x] From a GitHub repository, search for commits and email of authors with GitHub metadata and parsing
- [x] From a GitHub keyword search, retrieve GitHub repositories URLs
- [x] Handle properly errors and limit, or even remove, panics
- [ ] Correlate emails, language and project preferences with `results/$language/$author` which contains `$author` email
- [ ] Support more advanced parameters (_cf._ <https://github.com/search/advanced>)

## 💭 Thoughts

- Fuzzing to find my code vulnerabilities
- Process even faster requests with async queries ? If too much requests are done with the same token, will all the sent requests, after the API rate limited the token, be refused ? If so, async is a bad idea. Or will it only just accept requests until the rate limit is reached, like synchronous requests ?

## 💻 Contributing

Please if you want to bring your stone to the building, read and follow `CONTRIBUTING.md`.

## ⚖️ License

This project is free software, and is released under the terms of the LGPL (GNU Lesser General Public License) version 3 or (at your option) any later version.
