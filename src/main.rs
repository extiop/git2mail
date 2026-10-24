//! `git2mail` command-line interface: `scan` a GitHub URL or `search`
//! repositories by keyword, then write the found developers' emails to
//! the `results/` outputs (see the lib crate for the implementation).
use clap::{Parser, Subcommand};
use git2mail::errors::Error;
use git2mail::output;
use git2mail::parsers;
use git2mail::sources::{ScanOutcome, Scanner};
use log::{error, info};
use std::path::PathBuf;

/// CLI parameters shared by the `scan` and `search` subcommands.
#[derive(clap::Args)]
struct SharedArgs {
    /// Authenticate to the GitHub API with your GitHub token
    #[arg(short, long)]
    token: Option<String>,
    /// JSON file that contains your GitHub tokens to authenticate to the GitHub API
    #[arg(long)]
    token_file: Option<PathBuf>,
    /// Also write a JSON report at this path (the text output is always written)
    #[arg(long, value_name = "PATH")]
    json: Option<PathBuf>,
}

#[derive(Parser)]
#[command(name = "git2mail", author, version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Scan a GitHub repository or profile URL for developers' emails
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
            shared,
        } => {
            let language = language.unwrap_or_default();
            let scanner = Scanner::new(shared.token.as_deref(), shared.token_file.as_deref())?;
            let outcome = scanner.search(&query, &language, limit)?;

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
        Err(err) => return Err(err),
    };
    if let Some(path) = json {
        output::write_json(
            &path,
            target,
            mode,
            &outcome.emails,
            outcome.repos_scanned,
            scanner.requests_made(),
        )?;
    }
    if text_written {
        Ok(())
    } else {
        Err(Error::NoResults)
    }
}

fn main() {
    pretty_env_logger::init();
    info!("Starting git2mail!");

    if let Err(err) = run() {
        error!("git2mail run failed: {err}");
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
