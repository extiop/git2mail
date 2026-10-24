//! `git2mail` command-line interface: `scan` a GitHub URL or `search`
//! repositories by keyword, then write the found developers' emails to
//! the `results/` outputs (see the lib crate for the implementation).
use clap::{Parser, Subcommand};
use git2mail::errors::Error;
use git2mail::output;
use git2mail::parsers;
use git2mail::sources::{ScanOutcome, Scanner, SearchQualifiers};
use log::info;
use std::path::PathBuf;

/// CLI parameters shared by the `scan` and `search` subcommands.
#[derive(clap::Args)]
struct SharedArgs {
    /// Authenticate with your GitHub token (raises the limit from 60 to
    /// 5000 requests/hour; create one at github.com/settings/tokens —
    /// visible in your shell history and process list: prefer
    /// `--token-file`; wins over --token-file when both are given;
    /// `--token ""` forces anonymous)
    #[arg(short, long)]
    token: Option<String>,
    /// File holding one or more GitHub tokens, e.g. {"0": "ghp_…"} — each
    /// token adds 5000 requests/hour; copy tokens.example.json to get
    /// started (create tokens at github.com/settings/tokens)
    #[arg(long, value_name = "TOKENS_JSON")]
    token_file: Option<PathBuf>,
    /// Also write a JSON report at this path (a structured text file any
    /// editor can open): the found emails plus a per-author summary (each
    /// developer's emails, repositories and main language). The text
    /// output is skipped when the scan finds nothing; the JSON report
    /// still is
    #[arg(long, value_name = "PATH")]
    json: Option<PathBuf>,
}

#[derive(Parser)]
#[command(
    name = "git2mail",
    author,
    version,
    about,
    arg_required_else_help = true,
    after_help = "Examples:\n  git2mail scan --url https://github.com/denoland/deno\n  git2mail search --query nmap --language rust\nRun `git2mail <command> --help` for every option."
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
    ///
    /// Examples:
    ///   git2mail scan --url https://github.com/denoland/deno
    ///   git2mail scan --url https://github.com/denoland --token-file tokens.json
    ///
    /// Results are written to ./results/<mode>/<name>; without a token the
    /// scan runs anonymously (GitHub: 60 requests/hour).
    Scan {
        /// GitHub repository or profile URL you want to scan
        #[arg(short, long)]
        url: String,
        #[command(flatten)]
        shared: SharedArgs,
    },
    /// Search GitHub repositories by keyword and scan them for developers' emails
    Search {
        /// Query to find interesting GitHub repositories for you
        #[arg(short, long)]
        query: String,
        /// Select a language to enhance your repository searches
        #[arg(short, long)]
        language: Option<String>,
        /// Defines the limit of scanned repositories
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
        /// Filter repositories by size in kilobytes, same syntax as
        /// `--stars` (e.g. `>1000`, `100..5000`)
        #[arg(long, value_name = "KB")]
        size: Option<String>,
        /// Filter repositories by creation date (e.g. `>2020-01-01`,
        /// `>=2020`, `2019-01-01..2020-01-01`)
        #[arg(long, value_name = "DATE")]
        created: Option<String>,
        /// Filter repositories by last-push date, same syntax as `--created`
        /// (e.g. `>2024-01-01`, `>=2023`)
        #[arg(long, value_name = "DATE")]
        pushed: Option<String>,
        /// Filter repositories by license (e.g. `mit`, `apache-2.0`)
        #[arg(long, value_name = "ID")]
        license: Option<String>,
        /// Filter repositories by topic (e.g. `osint`, `recon`)
        #[arg(long, value_name = "NAME")]
        topic: Option<String>,
        /// Restrict the search to one user's repositories (e.g. `--user extiop`)
        #[arg(long, value_name = "LOGIN", conflicts_with = "org")]
        user: Option<String>,
        /// Restrict the search to one organization's repositories
        /// (e.g. `--org acme`)
        #[arg(long, value_name = "LOGIN")]
        org: Option<String>,
        #[command(flatten)]
        shared: SharedArgs,
    },
}

fn run() -> Result<(), Error> {
    let cli = Cli::parse();

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
    let text_written = match output::write_text(directory, file_name, &outcome.emails) {
        Ok(_) => true,
        Err(Error::NoResults) => false,
        Err(err) => {
            // the legacy text write failed: the user-requested JSON report
            // must still be written, so a successful scan's findings do not
            // vanish from both outputs at once. The text failure stays the
            // surfaced error; a JSON failure on top is warned about
            if let Some(path) = json
                && let Err(json_err) = output::write_json(
                    &path,
                    target,
                    mode,
                    &outcome.emails,
                    outcome.repos_scanned,
                    scanner.requests_made(),
                    &outcome.correlation,
                )
            {
                log::warn!("the JSON report could not be written either: {json_err}");
            }
            return Err(err);
        }
    };
    if let Some(path) = json {
        output::write_json(
            &path,
            target,
            mode,
            &outcome.emails,
            outcome.repos_scanned,
            scanner.requests_made(),
            &outcome.correlation,
        )?;
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

/// Builds the terminal logger: the default is the `info` level so the
/// report is visible without any environment setup (a plain
/// `pretty_env_logger::init()` filters everything below `error` and a
/// successful scan would print nothing at all); a set `RUST_LOG` replaces
/// the default, like the env_logger precedence users already know. The
/// ambient value is injected as a parameter so the contract stays testable
/// without mutating the process environment.
fn build_logger_with_ambient_filter(
    rust_log: Option<&str>,
) -> pretty_env_logger::env_logger::Builder {
    // `pretty_env_logger` re-exports its `env_logger` dependency
    // (`#[doc(hidden)] pub extern crate`), which lets the helper name the
    // returned builder type without adding a direct dependency
    let mut builder = pretty_env_logger::formatted_builder();
    if let Some(filter) = rust_log.map(str::trim).filter(|value| !value.is_empty()) {
        builder.parse_filters(filter);
    } else {
        // the env_logger builder methods take `&mut self`: configure in
        // place, then move the builder out
        builder.filter_level(log::LevelFilter::Info);
    }
    builder
}

fn main() {
    let ambient = std::env::var("RUST_LOG").ok();
    build_logger_with_ambient_filter(ambient.as_deref()).init();
    info!("Starting git2mail!");

    if let Err(err) = run() {
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
            "a set RUST_LOG must replace the default, not be ANDed with it"
        );
        assert_eq!(
            blank_filter,
            log::LevelFilter::Info,
            "a blank RUST_LOG must behave like an unset one"
        );
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
            "extiop",
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
        assert_eq!(user.as_deref(), Some("extiop"));
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
            "git2mail", "search", "--query", "nmap", "--user", "extiop", "--org", "acme",
        ]);
        assert!(
            cli.is_err(),
            "GitHub's search API accepts only one owner filter"
        );
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
    }

    #[test]
    fn help_lists_both_subcommands() {
        use clap::CommandFactory as _;
        let help = Cli::command().render_help().to_string();
        assert!(
            help.contains("scan"),
            "the help must present the scan subcommand"
        );
        assert!(
            help.contains("search"),
            "the help must present the search subcommand"
        );
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
}
