//! `git2mail` command-line interface: `scan` a GitHub URL, `search`
//! repositories by keyword, run the full `user` profile investigation or
//! the `org` organization investigation, then write the found developers'
//! emails to the `results/` outputs (see the lib crate for the
//! implementation).
use clap::{Parser, Subcommand};
use git2mail::email;
use git2mail::errors::Error;
use git2mail::org;
use git2mail::output;
use git2mail::parsers;
use git2mail::sources::{ScanOutcome, Scanner, SearchQualifiers};
use git2mail::user;
use log::info;
use std::path::PathBuf;

/// CLI parameters shared by every subcommand.
#[derive(clap::Args)]
struct SharedArgs {
    /// Authenticate with your GitHub token (raises the limit from 60 to
    /// 5000 requests/hour). Create one at github.com/settings/tokens.
    /// Typing it here leaves it visible in your shell history and to other
    /// programs — prefer `--token-file`; when both are given, the --token
    /// value is used unless it is empty or only spaces (then --token-file
    /// is read). `--token ""` on its own runs anonymously
    #[arg(short, long)]
    token: Option<String>,
    /// File holding one or more GitHub tokens, e.g. {"0": "ghp_…"} — each
    /// token adds 5000 requests/hour; copy tokens.example.json to get
    /// started (create tokens at github.com/settings/tokens)
    #[arg(long, value_name = "TOKENS_JSON")]
    token_file: Option<PathBuf>,
    /// Also write a JSON report at this path (a structured text file any
    /// editor can open): the found emails plus a per-author summary for
    /// `scan`/`search`, the traced accounts for `email`/`emails`, the full
    /// profile investigation for `user`, the organization investigation for
    /// `org`; the path `-` prints the report on screen instead
    #[arg(long, value_name = "PATH")]
    json: Option<PathBuf>,
}

#[derive(Parser)]
#[command(
    name = "git2mail",
    author,
    version,
    about = "Find developers' public email addresses on GitHub — from repositories, profiles, organizations and keyword searches",
    arg_required_else_help = true,
    after_help = "Examples:
  git2mail scan --url https://github.com/denoland/deno
  git2mail search --query nmap --language rust
  git2mail user janedoe
  git2mail org acme   (every developer behind one company)
  git2mail email jane@acme.com
  git2mail emails addresses.txt   (bulk: one address per line in the file)
Run `git2mail <subcommand> --help` for every option."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
// The search subcommand legitimately carries the nine optional advanced
// qualifier flags the scan subcommand does not have; boxing them for the
// lint would only obscure the CLI definition.
#[expect(clippy::large_enum_variant)]
enum Command {
    /// Scan a GitHub repository or profile URL for developers' emails
    /// (results land in ./results/…; --json <path> writes a report wherever
    /// you want)
    Scan {
        /// GitHub repository or profile URL you want to scan
        #[arg(short, long)]
        url: String,
        #[command(flatten)]
        shared: SharedArgs,
    },
    /// Trace one email address back to its GitHub account (best effort:
    /// GitHub has no email search, so matching repositories are guessed
    /// from the address, then their commits are checked). One lookup can
    /// spend up to 500 requests: a token is strongly recommended. The
    /// result prints on screen; add `--json <path>` (or `--json -`) to
    /// save it
    Email {
        /// Email address you want to trace back to its GitHub account
        address: String,
        #[command(flatten)]
        shared: SharedArgs,
    },
    /// Trace many email addresses at once (one per line in the file):
    /// same lookup as `email`, run in parallel over your tokens. The
    /// report prints on screen; add `--json <path>` (or `--json -`) to
    /// save it
    Emails {
        /// File containing the email addresses to trace back, one per line
        /// (`#` comments allowed)
        #[arg(value_name = "FILE")]
        file: PathBuf,
        #[command(flatten)]
        shared: SharedArgs,
    },
    /// Investigate a GitHub profile: past identities, real and guessed
    /// email addresses, other accounts, SSH keys, outside repositories.
    /// A token is strongly recommended: the walk spends dozens of
    /// requests and aborts on a spent anonymous allowance.
    ///
    /// The full report prints on screen (add `--json <path>` or `--json -`
    /// to save it): past usernames and names found in the account's commit
    /// noreply addresses (like 12345+jane@users.noreply.github.com — the
    /// address GitHub puts in commits when you keep your email private),
    /// real email addresses used, likely addresses guessed from the
    /// person's name, other accounts that may belong to the same person,
    /// public SSH keys and work on other people's repositories
    User {
        /// GitHub username you want to investigate
        username: String,
        /// Try extra guessed email shapes built from the person's name,
        /// e.g. `{last}{first}` or `{first}.{initial}{last}` (repeatable;
        /// checked against GitHub like the built-in ones)
        #[arg(long, value_name = "PATTERN", value_parser = variant_pattern_value)]
        variant_pattern: Vec<String>,
        #[command(flatten)]
        shared: SharedArgs,
    },
    /// Investigate a GitHub organization: its public members, its public
    /// repositories and the developers' emails found scanning them (the
    /// emails are also saved to the file results/org/<org>; add `--json`
    /// for the full report). A token is strongly recommended: the walk
    /// covers every listed repository and aborts on a spent anonymous
    /// allowance.
    Org {
        /// GitHub organization name — the word in its page address, e.g.
        /// `acme` in github.com/acme
        org: String,
        /// Scan only the first N repositories (default: every one — big
        /// organizations take a long time, so try `--limit 10` first)
        #[arg(
            long,
            value_parser = clap::builder::RangedU64ValueParser::<usize>::new().range(1..)
        )]
        limit: Option<usize>,
        #[command(flatten)]
        shared: SharedArgs,
    },
    /// Search GitHub repositories by keyword and scan them for developers' emails
    Search {
        /// Keywords describing the repositories you want (GitHub matches
        /// them against repository names, descriptions and topics — to
        /// investigate one person, use the `user` subcommand)
        #[arg(short, long, value_parser = non_empty_query)]
        query: String,
        /// Only search repositories written in this language (e.g. `rust`)
        #[arg(short, long)]
        language: Option<String>,
        /// Only scan the first N repositories found (default: 5)
        #[arg(
            long,
            default_value_t = 5,
            value_parser = clap::builder::RangedU64ValueParser::<usize>::new().range(1..)
        )]
        limit: usize,
        /// Filter repositories by star count, GitHub search range syntax
        /// (e.g. `>100`, `>=50`, `10..50`, `100..*`)
        #[arg(long, value_name = "RANGE")]
        stars: Option<String>,
        /// Filter repositories by fork count, same syntax as `--stars`
        /// (e.g. `>10`, `5..20`)
        #[arg(long, value_name = "RANGE")]
        forks: Option<String>,
        /// Filter repositories by size in kilobytes, GitHub search range syntax
        /// (e.g. `>1000`, `100..5000`), like `--stars`
        #[arg(long, value_name = "RANGE")]
        size: Option<String>,
        /// Filter repositories by creation date, GitHub search date syntax
        /// (e.g. `>2020-01-01`, `>=2020`, `2019-01-01..2020-01-01`)
        #[arg(long, value_name = "DATE_RANGE")]
        created: Option<String>,
        /// Filter repositories by last-push date, same syntax as `--created`
        /// (e.g. `>2024-01-01`, `>=2023`)
        #[arg(long, value_name = "DATE_RANGE")]
        pushed: Option<String>,
        /// Filter repositories by license (e.g. `mit`, `apache-2.0`)
        #[arg(long, value_name = "ID")]
        license: Option<String>,
        /// Filter repositories by topic (e.g. `osint`, `recon`)
        #[arg(long, value_name = "NAME")]
        topic: Option<String>,
        /// Restrict the search to one user's repositories (e.g. `--user octocat`;
        /// mutually exclusive with `--org`)
        #[arg(long, value_name = "LOGIN", conflicts_with = "org")]
        user: Option<String>,
        /// Restrict the search to one organization's repositories
        /// (e.g. `--org acme`; mutually exclusive with `--user`)
        #[arg(long, value_name = "ORG")]
        org: Option<String>,
        #[command(flatten)]
        shared: SharedArgs,
    },
}

/// Rejects an empty or whitespace-only `--query`: it would compose a bare
/// `q=` the search API answers with a raw 422, so the rejection happens
/// client-side, before any request. The value is kept as typed otherwise.
fn non_empty_query(value: &str) -> Result<String, String> {
    if value.trim().is_empty() {
        Err("the query must not be empty".to_string())
    } else {
        Ok(value.to_string())
    }
}

/// The clap value parser of `user --variant-pattern`: the same client-side
/// rejection as the library validation, surfaced as a clap usage error
/// (exit 2). Deliberately not the runtime qualifier path (--stars, --created
/// and the like are validated against the API response shape and exit 1):
/// two different validation layers, two different exits.
fn variant_pattern_value(pattern: &str) -> Result<String, String> {
    user::validate_variant_pattern(pattern).map_err(|err| match err {
        // the bare detail, escaping kept: clap already frames the rejection
        // ("invalid value … for '--variant-pattern'"), the variant's own
        // "invalid --variant-pattern" prefix would state the flag twice
        Error::InvalidVariantPattern(details) => format!("{details:?}"),
        other => other.to_string(),
    })?;
    Ok(pattern.to_string())
}

/// Writes one JSON report when a `--json` path was requested, warning (not
/// failing) on a write error: the caller surfaces its own primary error
/// instead (the findings must not vanish from both outputs at once).
fn write_json_best_effort<T: serde::Serialize>(path: Option<&PathBuf>, report: &T) {
    if let Some(path) = path
        && let Err(json_err) = output::write_report_json(path, report)
    {
        log::warn!("the JSON report could not be written either: {json_err}");
    }
}

/// Runs one single-report subcommand (`email`, `emails`, `user`): builds
/// the scanner from the shared `--token`/`--token-file` options, produces
/// the report through `produce` and writes the JSON deliverable when
/// `--json` was requested.
///
/// # Errors
///
/// Returns the first failure of the scanner build, the report production
/// or the JSON write. Never panics.
fn run_report_command<T: serde::Serialize>(
    shared: &SharedArgs,
    produce: impl FnOnce(&Scanner) -> Result<T, Error>,
) -> Result<(), Error> {
    let scanner = Scanner::new(shared.token.as_deref(), shared.token_file.as_deref())?;
    let report = produce(&scanner)?;
    if let Some(path) = shared.json.as_ref() {
        output::write_report_json(path, &report)?;
    }
    Ok(())
}

fn run() -> Result<(), Error> {
    let cli = Cli::parse();
    // the startup line goes through the logger after clap: a `--help` or
    // `--version` exit above must print only what was asked for, never a
    // stray "Starting git2mail!" banner above the help text
    info!("Starting git2mail!");
    // every subcommand carries the same shared `--json` option: reject a
    // target that can never succeed (an existing directory) before spending
    // the run's API budget on a report that cannot be written
    let json: Option<&PathBuf> = match &cli.command {
        Command::Scan { shared, .. }
        | Command::Email { shared, .. }
        | Command::Emails { shared, .. }
        | Command::User { shared, .. }
        | Command::Org { shared, .. }
        | Command::Search { shared, .. } => shared.json.as_ref(),
    };
    if let Some(path) = json {
        output::ensure_report_target(path)?;
    }

    match cli.command {
        Command::Scan { url, shared } => {
            let scanner = Scanner::new(shared.token.as_deref(), shared.token_file.as_deref())?;
            // parsed once: the author/repository names also build the output
            // file name
            let author = parsers::get_author(url.clone())?;
            let repository = parsers::get_repository(url.clone())?;
            let outcome = scanner.scan_parts(&author, &repository)?;

            let (mode, file_name) = if repository.is_empty() {
                ("profile", author)
            } else {
                ("repository", format!("{author}_{repository}"))
            };
            write_outputs(&url, mode, mode, &file_name, outcome, shared.json, &scanner)
        }
        Command::Email { address, shared } => {
            run_report_command(&shared, |scanner| email::reverse(scanner, &address))
        }
        Command::Emails { file, shared } => {
            // the bulk run writes its own partial report on an abort: the
            // lookups already paid for must reach the requested --json file
            // even when the run fails (mirroring the scan path's guard),
            // then the abort error still propagates
            let scanner = Scanner::new(shared.token.as_deref(), shared.token_file.as_deref())?;
            let (report, failure) = email::reverse_bulk_with_partial(
                &scanner,
                git2mail::consts::GITHUB_API_BASE,
                &file,
            );
            if let Some(path) = shared.json.as_ref() {
                if failure.is_some() {
                    write_json_best_effort(Some(path), &report);
                } else {
                    output::write_report_json(path, &report)?;
                }
            }
            match failure {
                Some(err) => Err(err),
                None => Ok(()),
            }
        }
        Command::User {
            username,
            variant_pattern,
            shared,
        } => run_report_command(&shared, |scanner| {
            user::investigate(scanner, &username, &variant_pattern)
        }),
        Command::Org {
            org: org_login,
            limit,
            shared,
        } => {
            let scanner = Scanner::new(shared.token.as_deref(), shared.token_file.as_deref())?;
            let report = org::investigate(&scanner, &org_login, limit)?;
            // the same one-email-per-line result file the scan subcommands
            // write: the outreach workflow needs a paste-able list, not a
            // terminal wall or a JSON file. An empty list is a successful
            // run (user/email parity): log_summary already printed the
            // org-scoped [-] no-results line, and NoResults' person-oriented
            // advice does not apply to an org the user chose deliberately —
            // only a real write failure surfaces. The JSON report is
            // attempted in EVERY case: an explicit `--json` deliverable must
            // not vanish on the empty run (the org scan spends the most API
            // budget of any subcommand — scan-path parity). write_text logs
            // the path itself: log nothing extra here
            let org_text = output::write_text("org", &report.org.login, &report.emails.all);
            if matches!(&org_text, Err(err) if !matches!(err, Error::NoResults)) {
                // the text write failed: the user-requested JSON report must
                // still be written (scan-path parity with `write_outputs` —
                // the findings must not vanish from both outputs at once);
                // a JSON failure on top is warned about, then the text
                // error is surfaced
                write_json_best_effort(shared.json.as_ref(), &report);
                org_text.map(|_| ())?;
            } else {
                // text written (or nothing found): the JSON deliverable is
                // propagated like on the scan path — a requested report that
                // could not be written must fail the run, not vanish
                if let Some(path) = shared.json.as_ref() {
                    output::write_report_json(path, &report)?;
                }
                // `NoResults` is success here (see the comment above): the
                // enclosing `if` already filtered out every other `Err`
            }
            Ok(())
        }
        Command::Search {
            query,
            language,
            limit,
            stars,
            forks,
            size,
            created,
            pushed,
            license,
            topic,
            user,
            org,
            shared,
        } => {
            let language = language.unwrap_or_default();
            let qualifiers = SearchQualifiers {
                stars,
                forks,
                size,
                created,
                pushed,
                license,
                topic,
                user,
                org,
            };
            let scanner = Scanner::new(shared.token.as_deref(), shared.token_file.as_deref())?;
            let outcome = scanner.search(&query, &language, &qualifiers, limit)?;

            let file_name = if language.is_empty() {
                query.clone()
            } else {
                format!("{query}_{language}")
            };
            write_outputs(
                &query,
                "search",
                "keyword",
                &file_name,
                outcome,
                shared.json,
                &scanner,
            )
        }
    }
}

/// Writes the scan results: the legacy text file (unchanged format), plus the
/// opt-in JSON report when `--json` is provided.
///
/// The JSON report is written even when the scan found nothing (with empty
/// `emails`): the user opted into it, and the text output being skipped for
/// lack of results must not take it down. The scan still ends with
/// [`Error::NoResults`] in that case.
fn write_outputs(
    target: &str,
    mode: &str,
    directory: &str,
    file_name: &str,
    outcome: ScanOutcome,
    json: Option<PathBuf>,
    scanner: &Scanner,
) -> Result<(), Error> {
    // one JSON report writer for both paths below: the report is written
    // either propagated (`?`) or best-effort (warn-only), per the caller
    let write_scan_report_json = |path: &PathBuf| {
        output::write_scan_report_json(
            path,
            target,
            mode,
            &outcome.emails,
            outcome.repos_scanned,
            scanner.requests_made(),
            outcome.partial,
            &outcome.correlation,
        )
    };
    let text_result = output::write_text(directory, file_name, &outcome.emails);
    if matches!(&text_result, Err(err) if !matches!(err, Error::NoResults)) {
        // the legacy text write failed: the user-requested JSON report must
        // still be written, so a successful scan's findings do not vanish
        // from both outputs at once (the JSON write itself would have
        // succeeded — e.g. a stray file blocking the `results/` layout, or
        // a read-only CWD). The text failure stays the surfaced error; if
        // the JSON write fails too, it is warned about on top of it
        if let Some(path) = json
            && let Err(json_err) = write_scan_report_json(&path)
        {
            log::warn!("the JSON report could not be written either: {json_err}");
        }
        // the terminal summary carries the correlation findings the failed
        // text file no longer does: print it before the early return
        outcome.correlation.log_summary();
        return text_result.map(|_| ());
    }
    // every non-`NoResults` error early-returned above, so `is_ok()` is
    // exactly "the legacy text file was written" — without a panicking
    // fallback arm that a future condition widening would turn live
    let text_written = text_result.is_ok();
    if let Some(path) = json {
        write_scan_report_json(&path)?;
    }
    // terminal-only summary of the correlated attributes (top authors with
    // their dominant language): the plain-text files stay unchanged
    outcome.correlation.log_summary();
    if text_written {
        Ok(())
    } else {
        Err(Error::NoResults)
    }
}

/// Builds the global logger exactly the way `main` installs it: the
/// human-readable terminal report goes through `log::info!`, so the default
/// is the `info` level (the report is visible without any environment
/// setup), while `RUST_LOG` keeps its precedence when it is set (the
/// `filter_level` directive is replaced by the ones parsed from
/// `RUST_LOG`). Returned unbuilt so tests can pin the effective default
/// filter without installing a global logger.
fn build_logger() -> pretty_env_logger::env_logger::Builder {
    // the value is only read: mutating the environment in tests would race
    // the other tests' concurrent `getenv` calls (which is why `set_var` is
    // `unsafe`), so the ambient value is injected as a parameter instead
    build_logger_with_ambient_filter(std::env::var("RUST_LOG").ok().as_deref())
}

/// The same builder with the ambient `RUST_LOG` value injected: `None` (or a
/// blank value) leaves the default `info` filter, a set value replaces it
/// entirely (the same semantics as parsing the variable). Tests inject the
/// value instead of mutating the process environment.
fn build_logger_with_ambient_filter(
    rust_log: Option<&str>,
) -> pretty_env_logger::env_logger::Builder {
    // `pretty_env_logger` re-exports its `env_logger` dependency
    // (`#[doc(hidden)] pub extern crate`), which lets the helper name the
    // returned builder type without adding a direct dependency
    let mut builder = pretty_env_logger::formatted_builder();
    // The terminal report vocabulary is `[+]` success / `[-]` error /
    // `[!]` warning / `[.]` informational listing, so a
    // warning must carry its own scannable marker (`[!]`) — otherwise a
    // partial-scan warning looks like progress chatter once colors are
    // stripped (redirect, screen reader, plain terminal). The marker is
    // applied here at the format level (one site) instead of editing every
    // `warn!` call: warn/error lines get the marker, other levels print
    // their message as-is (the `[+]` report lines already carry their own).
    // Documented in doc/src/OUTPUT.md.
    builder.format(|buf, record| {
        use std::io::Write as _;
        let marker = match record.level() {
            log::Level::Warn => "[!] ",
            log::Level::Error => "[-] ",
            _ => "",
        };
        writeln!(buf, "{}{}", marker, record.args())
    });
    if let Some(filter) = rust_log.map(str::trim).filter(|value| !value.is_empty()) {
        builder.parse_filters(filter);
    } else {
        // the env_logger 0.10 builder methods take `&mut self`: configure in
        // place, then move the builder out
        builder.filter_level(log::LevelFilter::Info);
    }
    builder
}

fn main() {
    build_logger().init();

    if let Err(err) = run() {
        // one terminal line only: the logger would repeat the same failure
        // under the default `info` level (visible as a second ERROR line)
        eprintln!("[-] {err}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    // Tests may unwrap, expect and panic freely: a failing assertion must
    // be loud, so the zero-panic lints do not apply to the test modules.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn the_logger_defaults_to_info_and_rust_log_replaces_it() {
        // the ambient RUST_LOG value is injected as a parameter instead of
        // mutating the process environment: `set_var` is `unsafe` because
        // `setenv`/`getenv` are not synchronized on all platforms, and the
        // other tests of the suite call `getenv` concurrently (through
        // `std::env::temp_dir` and the like)
        // without RUST_LOG, the terminal report's `info` level is the
        // default: the report is visible without any environment setup
        let default_filter = build_logger_with_ambient_filter(None).build().filter();
        // a set RUST_LOG replaces the default instead of being ANDed with
        // it (the `filter_level` directive is replaced by the parsed ones)
        let rust_log_filter = build_logger_with_ambient_filter(Some("error"))
            .build()
            .filter();
        // a blank RUST_LOG behaves like an unset one (env_logger ignores a
        // blank filter), so the default applies
        let blank_filter = build_logger_with_ambient_filter(Some("  "))
            .build()
            .filter();
        assert_eq!(
            default_filter,
            log::LevelFilter::Info,
            "the report must be visible without any environment setup"
        );
        assert_eq!(
            rust_log_filter,
            log::LevelFilter::Error,
            "RUST_LOG must keep its precedence when it is set"
        );
        assert_eq!(blank_filter, log::LevelFilter::Info);
    }

    #[test]
    fn search_rejects_a_zero_limit() {
        let cli = Cli::try_parse_from(["git2mail", "search", "--query", "nmap", "--limit", "0"]);
        assert!(
            cli.is_err(),
            "--limit 0 would only fetch one page for nothing"
        );
    }

    #[test]
    fn search_accepts_a_positive_limit() {
        let cli = Cli::try_parse_from(["git2mail", "search", "--query", "nmap", "--limit", "5"]);
        assert!(cli.is_ok());
    }

    #[test]
    fn scan_requires_a_url() {
        let cli = Cli::try_parse_from(["git2mail", "scan"]);
        assert!(cli.is_err(), "a scan without --url has no target");
    }

    #[test]
    fn search_rejects_an_empty_query() {
        for bad in ["", "   ", "\t\n"] {
            let cli = Cli::try_parse_from(["git2mail", "search", "--query", bad]);
            assert!(
                cli.is_err(),
                "an empty {bad:?} query would reach the API as a raw 422"
            );
        }
    }

    #[test]
    fn search_keeps_a_query_with_surrounding_whitespace_as_typed() {
        // only a whitespace-only query is rejected: trimming the value
        // would silently rewrite what the user searched for
        let cli = Cli::try_parse_from(["git2mail", "search", "--query", " nmap "])
            .expect("a query with surrounding whitespace must parse");
        let Command::Search { query, .. } = cli.command else {
            panic!("expected the search subcommand");
        };
        assert_eq!(query, " nmap ");
    }

    #[test]
    fn search_requires_a_query() {
        let cli = Cli::try_parse_from(["git2mail", "search"]);
        assert!(cli.is_err(), "a search without --query has no target");
    }

    #[test]
    fn an_unknown_subcommand_is_rejected() {
        let cli = Cli::try_parse_from(["git2mail", "recon", "--url", "https://github.com/a/b"]);
        assert!(
            cli.is_err(),
            "the old flat flags are gone: only subcommands exist"
        );
    }

    #[test]
    fn scan_accepts_the_shared_flags() {
        let cli = Cli::try_parse_from([
            "git2mail",
            "scan",
            "--url",
            "https://github.com/a/b",
            "--token",
            "ghp_x",
            "--json",
            "report.json",
        ])
        .expect("scan must accept the shared flags");
        let Command::Scan { url, shared } = cli.command else {
            panic!("expected the scan subcommand");
        };
        assert_eq!(url, "https://github.com/a/b");
        assert_eq!(shared.token.as_deref(), Some("ghp_x"));
        assert_eq!(
            shared.json.as_deref(),
            Some(std::path::Path::new("report.json"))
        );
    }

    #[test]
    fn search_accepts_the_shared_flags() {
        let cli = Cli::try_parse_from([
            "git2mail",
            "search",
            "--query",
            "nmap",
            "--language",
            "Rust",
            "--token-file",
            "tokens.json",
        ])
        .expect("search must accept the shared flags");
        let Command::Search {
            query,
            language,
            limit,
            shared,
            ..
        } = cli.command
        else {
            panic!("expected the search subcommand");
        };
        assert_eq!(query, "nmap");
        assert_eq!(language.as_deref(), Some("Rust"));
        assert_eq!(limit, 5, "the documented default limit applies");
        assert_eq!(
            shared.token_file.as_deref(),
            Some(std::path::Path::new("tokens.json"))
        );
        assert_eq!(shared.token, None);
        assert_eq!(shared.json, None);
    }

    #[test]
    fn search_accepts_the_advanced_qualifier_flags() {
        let cli = Cli::try_parse_from([
            "git2mail",
            "search",
            "--query",
            "nmap",
            "--language",
            "Rust",
            "--stars",
            ">100",
            "--forks",
            "10..50",
            "--size",
            "100..5000",
            "--created",
            ">2020-01-01",
            "--pushed",
            ">=2023",
            "--license",
            "mit",
            "--topic",
            "osint",
            "--user",
            "octocat",
        ])
        .expect("search must accept the advanced qualifier flags");
        let Command::Search {
            stars,
            forks,
            size,
            created,
            pushed,
            license,
            topic,
            user,
            org,
            ..
        } = cli.command
        else {
            panic!("expected the search subcommand");
        };
        assert_eq!(stars.as_deref(), Some(">100"));
        assert_eq!(forks.as_deref(), Some("10..50"));
        assert_eq!(size.as_deref(), Some("100..5000"));
        assert_eq!(created.as_deref(), Some(">2020-01-01"));
        assert_eq!(pushed.as_deref(), Some(">=2023"));
        assert_eq!(license.as_deref(), Some("mit"));
        assert_eq!(topic.as_deref(), Some("osint"));
        assert_eq!(user.as_deref(), Some("octocat"));
        assert_eq!(org, None);
    }

    #[test]
    fn search_defaults_to_no_qualifier() {
        let cli = Cli::try_parse_from(["git2mail", "search", "--query", "nmap"])
            .expect("a plain search must parse");
        let Command::Search {
            stars,
            forks,
            size,
            created,
            pushed,
            license,
            topic,
            user,
            org,
            ..
        } = cli.command
        else {
            panic!("expected the search subcommand");
        };
        assert_eq!(stars, None);
        assert_eq!(forks, None);
        assert_eq!(size, None);
        assert_eq!(created, None);
        assert_eq!(pushed, None);
        assert_eq!(license, None);
        assert_eq!(topic, None);
        assert_eq!(user, None);
        assert_eq!(org, None);
    }

    #[test]
    fn search_rejects_user_and_org_together() {
        let cli = Cli::try_parse_from([
            "git2mail", "search", "--query", "nmap", "--user", "octocat", "--org", "acme",
        ]);
        assert!(
            cli.is_err(),
            "GitHub's search API accepts only one owner filter"
        );
    }

    #[test]
    fn user_accepts_the_shared_flags_and_a_positional_username() {
        let cli = Cli::try_parse_from([
            "git2mail",
            "user",
            "jane-doe",
            "--token",
            "ghp_x",
            "--json",
            "report.json",
        ])
        .expect("the user subcommand must parse");
        let Command::User {
            username,
            shared,
            variant_pattern: _,
        } = cli.command
        else {
            panic!("expected the user subcommand");
        };
        assert_eq!(username, "jane-doe");
        assert_eq!(shared.token.as_deref(), Some("ghp_x"));
        assert_eq!(
            shared.json.as_deref(),
            Some(std::path::Path::new("report.json"))
        );
    }

    #[test]
    fn user_requires_a_username() {
        let cli = Cli::try_parse_from(["git2mail", "user"]);
        assert!(
            cli.is_err(),
            "a user investigation without a target has no sense"
        );
    }

    #[test]
    fn a_malformed_variant_pattern_is_rejected_at_parse_time() {
        // the clap value_parser must carry the client-side validation: a
        // reverted value_parser would only fail later (or never) — this pins
        // the parse-time rejection (exit 2, usage error, no network)
        for pattern in ["{first", "{unknown}", "{first} {last}", "a}b{first}"] {
            let cli =
                Cli::try_parse_from(["git2mail", "user", "jane", "--variant-pattern", pattern]);
            assert!(
                cli.is_err(),
                "the malformed pattern {pattern:?} must be rejected at parse time"
            );
        }
        // the length cap is enforced by the same value parser
        let pattern = "x".repeat(129) + "{first}";
        let cli = Cli::try_parse_from(["git2mail", "user", "jane", "--variant-pattern", &pattern]);
        assert!(
            cli.is_err(),
            "an overlong pattern must be rejected at parse time"
        );
    }

    #[test]
    fn org_accepts_the_shared_flags_a_positional_login_and_an_optional_limit() {
        let cli = Cli::try_parse_from([
            "git2mail",
            "org",
            "acme",
            "--token",
            "ghp_x",
            "--limit",
            "5",
            "--json",
            "report.json",
        ])
        .expect("the org subcommand must parse");
        let Command::Org { org, limit, shared } = cli.command else {
            panic!("expected the org subcommand");
        };
        assert_eq!(org, "acme");
        assert_eq!(limit, Some(5));
        assert_eq!(shared.token.as_deref(), Some("ghp_x"));
        assert_eq!(
            shared.json.as_deref(),
            Some(std::path::Path::new("report.json"))
        );
    }

    #[test]
    fn org_defaults_to_no_limit() {
        let cli = Cli::try_parse_from(["git2mail", "org", "acme"])
            .expect("a plain org investigation must parse");
        let Command::Org { org, limit, .. } = cli.command else {
            panic!("expected the org subcommand");
        };
        assert_eq!(org, "acme");
        assert_eq!(limit, None, "without --limit every repository is listed");
    }

    #[test]
    fn org_rejects_a_zero_limit() {
        let cli = Cli::try_parse_from(["git2mail", "org", "acme", "--limit", "0"]);
        assert!(
            cli.is_err(),
            "--limit 0 would only fetch one page for nothing"
        );
    }

    #[test]
    fn org_requires_a_login() {
        let cli = Cli::try_parse_from(["git2mail", "org"]);
        assert!(
            cli.is_err(),
            "an organization investigation without a target has no sense"
        );
    }

    #[test]
    fn email_accepts_the_shared_flags_and_a_positional_address() {
        let cli = Cli::try_parse_from([
            "git2mail",
            "email",
            "jane@acme.com",
            "--token",
            "ghp_x",
            "--json",
            "report.json",
        ])
        .expect("the email subcommand must parse");
        let Command::Email { address, shared } = cli.command else {
            panic!("expected the email subcommand");
        };
        assert_eq!(address, "jane@acme.com");
        assert_eq!(shared.token.as_deref(), Some("ghp_x"));
        assert_eq!(
            shared.json.as_deref(),
            Some(std::path::Path::new("report.json"))
        );
    }

    #[test]
    fn email_requires_an_address() {
        let cli = Cli::try_parse_from(["git2mail", "email"]);
        assert!(
            cli.is_err(),
            "a reverse lookup without a target has no sense"
        );
    }

    #[test]
    fn emails_accepts_the_shared_flags_and_a_positional_file() {
        let cli = Cli::try_parse_from([
            "git2mail",
            "emails",
            "addresses.txt",
            "--token-file",
            "tokens.json",
            "--json",
            "report.json",
        ])
        .expect("the emails subcommand must parse");
        let Command::Emails { file, shared } = cli.command else {
            panic!("expected the emails subcommand");
        };
        assert_eq!(file, std::path::PathBuf::from("addresses.txt"));
        assert_eq!(
            shared.token_file.as_deref(),
            Some(std::path::Path::new("tokens.json"))
        );
        assert_eq!(
            shared.json.as_deref(),
            Some(std::path::Path::new("report.json"))
        );
    }

    #[test]
    fn emails_requires_a_file() {
        let cli = Cli::try_parse_from(["git2mail", "emails"]);
        assert!(
            cli.is_err(),
            "a bulk reverse lookup without a file has no sense"
        );
    }

    #[test]
    fn help_lists_all_subcommands() {
        use clap::CommandFactory as _;
        let help = Cli::command().render_help().to_string();
        for subcommand in ["scan", "search", "user", "org", "email", "emails"] {
            assert!(
                help.contains(subcommand),
                "the help must present the {subcommand} subcommand"
            );
        }
    }

    #[test]
    fn help_documents_the_advanced_qualifier_flags() {
        use clap::CommandFactory as _;
        // the flags live on the search subcommand, not on the top-level help
        let mut search = Cli::command()
            .find_subcommand("search")
            .expect("the search subcommand must exist")
            .clone();
        let help = search.render_help().to_string();
        for flag in [
            "--stars",
            "--forks",
            "--size",
            "--created",
            "--pushed",
            "--license",
            "--topic",
            "--user",
            "--org",
        ] {
            assert!(help.contains(flag), "the help must document {flag}");
        }
        // the value names are part of the help contract too: `--size` is
        // named by its range syntax (`--size <RANGE>`, like `--stars` and
        // `--forks`) and the date flags by theirs (`<DATE_RANGE>`) — a
        // reverted `value_name` falls back to clap's default placeholder
        // (a bare `<SIZE>`), which this pins against
        for flag_value in ["--stars <RANGE>", "--forks <RANGE>", "--size <RANGE>"] {
            assert!(
                help.contains(flag_value),
                "the help must name {flag_value} by its range syntax"
            );
        }
        for flag_value in ["--created <DATE_RANGE>", "--pushed <DATE_RANGE>"] {
            assert!(
                help.contains(flag_value),
                "the help must name {flag_value} by its date-range syntax"
            );
        }
        // the user subcommand must document the custom variant patterns
        // (repeatable flag, PATTERN value name)
        let mut user = Cli::command()
            .find_subcommand("user")
            .expect("the user subcommand must exist")
            .clone();
        let user_help = user.render_help().to_string();
        assert!(
            user_help.contains("--variant-pattern <PATTERN>"),
            "the user help must document --variant-pattern <PATTERN>: {user_help}"
        );
    }

    #[test]
    fn the_json_help_lists_every_subcommand_report_shape() {
        use clap::CommandFactory as _;
        // the --json flag is shared: its help must enumerate the report
        // shape of every subcommand that writes one
        let mut search = Cli::command()
            .find_subcommand("search")
            .expect("the search subcommand must exist")
            .clone();
        let help = search.render_help().to_string();
        for mention in ["scan", "search", "email", "emails", "user", "org"] {
            assert!(
                help.contains(mention),
                "the --json help must mention the {mention} report shape"
            );
        }
    }

    #[test]
    fn write_outputs_writes_the_json_report_even_without_results() {
        let scanner = Scanner::new(None, None).expect("anonymous scanner must build");
        let outcome = ScanOutcome::default();
        let json_path = std::env::temp_dir().join(format!(
            "git2mail_main_test_{}_empty_report.json",
            std::process::id()
        ));

        let error = write_outputs(
            "target",
            "search",
            "keyword",
            "query",
            outcome,
            Some(json_path.clone()),
            &scanner,
        )
        .expect_err("an empty scan must still report no result");
        assert!(matches!(error, Error::NoResults));

        // the opt-in JSON report exists, with empty emails
        let report: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&json_path).expect("report must exist"))
                .expect("report must be valid JSON");
        assert_eq!(report["emails"], serde_json::json!([]));
        std::fs::remove_file(&json_path).ok();
    }

    /// A CWD-isolated body for the tests that exercise the legacy
    /// `results/` layout: the text writer writes relative to the current
    /// directory, so the blocker-file scenarios must not touch the real
    /// workspace (the lock keeps parallel tests from racing the chdir).
    /// Same idea as `output.rs`'s `in_temp_cwd`, kept local: the two
    /// fixtures isolate different output layouts and must not share a lock
    /// (their chdirs are orthogonal).
    fn in_temp_cwd<T>(f: impl FnOnce() -> T) -> T {
        use std::path::Path;
        use std::sync::{Mutex, OnceLock};
        static CWD_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        let lock = CWD_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let original = std::env::current_dir().expect("test setup: current dir");
        let temp =
            std::env::temp_dir().join(format!("git2mail_main_cwd_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp);
        std::fs::create_dir_all(&temp).expect("test setup: temp cwd");
        std::env::set_current_dir(&temp).expect("test setup: enter temp cwd");
        // panic-safe restore: a test panicking inside `f` must not leave the
        // process CWD inside the temp directory the teardown deletes (every
        // later `current_dir()` of the suite would then fail with NotFound)
        struct RestoreCwd<'a>(&'a Path);
        impl Drop for RestoreCwd<'_> {
            fn drop(&mut self) {
                let _ = std::env::set_current_dir(self.0);
            }
        }
        let _restore = RestoreCwd(&original);
        let result = f();
        drop(_restore);
        std::env::set_current_dir(&original).expect("test teardown: restore cwd");
        let _ = std::fs::remove_dir_all(&temp);
        drop(lock);
        result
    }

    #[test]
    fn write_outputs_still_writes_the_json_report_when_the_text_output_fails() {
        // a stray file named `results` (planted by a previous `--json
        // results` run, or a read-only CWD) blocks the legacy text layout:
        // the scan itself succeeded, so the user-requested JSON report must
        // still be written — a hard text-write failure used to abort before
        // `write_scan_report_json`, discarding the successful scan's findings from both
        // outputs at once. The text failure stays the surfaced error
        in_temp_cwd(|| {
            std::fs::write("results", "not a directory").expect("test setup: blocker file");
            let scanner = Scanner::new(None, None).expect("anonymous scanner must build");
            let outcome = ScanOutcome {
                emails: vec!["dev@example.com".to_string()],
                repos_scanned: 1,
                ..ScanOutcome::default()
            };
            let json_path = std::env::temp_dir().join(format!(
                "git2mail_main_test_{}_blocked_report.json",
                std::process::id()
            ));
            let _ = std::fs::remove_file(&json_path);

            let error = write_outputs(
                "target",
                "repository",
                "repository",
                "acme_lib",
                outcome,
                Some(json_path.clone()),
                &scanner,
            )
            .expect_err("the blocked text write must surface");
            assert!(
                matches!(error, Error::OutputWrite(ref details) if details.contains("results")),
                "the text failure must stay the surfaced error: {error:?}"
            );

            // ... but the JSON report exists, with the scan's findings
            let report: serde_json::Value = serde_json::from_str(
                &std::fs::read_to_string(&json_path).expect("the JSON report must exist"),
            )
            .expect("report must be valid JSON");
            assert_eq!(report["emails"], serde_json::json!(["dev@example.com"]));
            assert_eq!(report["scanned"]["repos"], 1);
            std::fs::remove_file(&json_path).ok();
        });
    }
}
