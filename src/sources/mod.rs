//! High-level scans: turn a user request into GitHub API calls.
//!
//! The three scans live in private modules of their own, all built on the
//! single [`crate::github::fetch_paginated`] loop of the [`crate::github`]
//! module:
//!
//! - `repository`: the commits of one repository, the building block of the
//!   other scans;
//! - `profile`: a profile's events, falling back to its repositories'
//!   commits when no email shows up in the events;
//! - `search`: the repositories matching a query, scanned in parallel
//!
//! The found emails are handed to the `output` writers by `main`.

mod profile;
mod repository;
mod search;

pub(crate) use search::percent_encode;

use crate::consts::{GITHUB_API_BASE, NOREPLY_DOMAIN};
use crate::correlate::{Correlation, CorrelationBuilder, RepoContribution};
use crate::errors::Error;
use crate::github::{Client, TokenPool};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

pub use search::SearchQualifiers;
// internals shared with the reverse-email lookup (`src/email.rs`): the
// repository-search listing and the worker-pool sizing glue, reused as-is
// instead of duplicated
pub(crate) use search::{
    SEARCH_RESULT_CEILING, SearchHit, parse_search_page, search_q, worker_count,
};
// internals shared with the `user` investigation: the per-repository commit
// budget reused as-is instead of duplicated
pub(crate) use repository::MAX_COMMIT_PAGES;

/// Listings are fetched 100 items per page, the GitHub API maximum.
pub(crate) const PER_PAGE: u16 = 100;

/// Outcome of a scan: the emails found, how many repositories were scanned
/// and the per-author correlation report built along the way (issue #5).
#[derive(Debug, Default)]
pub struct ScanOutcome {
    /// Emails found during the scan, deduplicated and sorted.
    pub emails: Vec<String>,
    /// Number of repositories whose commits were scanned.
    pub repos_scanned: usize,
    /// Per-author correlation report: authors, emails, repositories with
    /// their primary language and commit counts. Empty when no author could
    /// be attributed (for instance a profile scan that found its emails in
    /// the events alone).
    pub correlation: Correlation,
    /// Whether the scan kept a partial result: `true` when a parallel scan
    /// returned its findings although a dedicated token died mid-scan, so
    /// whole listed repositories may have been left unscanned (surfaced as
    /// `scanned.partial` in the JSON report; the sequential scans are always
    /// complete — they abort on any scan-wide failure).
    pub partial: bool,
}

/// A GitHub scanner built from the CLI parameters.
pub struct Scanner {
    client: Client,
    /// Successful API requests made by the scan workers, on top of
    /// the ones made through the shared client (added to the JSON report).
    worker_requests: AtomicUsize,
}

impl Scanner {
    /// Creates a scanner from the user parameters; tokens are validated at
    /// startup, so an invalid token fails before any scan.
    ///
    /// `token` wins over `token_file` when both are provided (a warning is
    /// logged: a stale `--token` in a wrapper script must not silently
    /// downgrade a multi-token pool run to one token); when neither is, the
    /// scan runs anonymously (60 req/h).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidTokenFormat`] when `token` or a token of the
    /// file does not follow the expected format, and [`Error::Http`] when
    /// the HTTP client cannot be built. Never panics.
    pub fn new(token: Option<&str>, token_file: Option<&Path>) -> Result<Self, Error> {
        // the same paste-artifact rule as `TokenPool::from_token`: a
        // whitespace-only --token is no token at all, so it must fall
        // through to the token file or the anonymous warning
        let token = token.map(str::trim).filter(|token| !token.is_empty());
        if token.is_some() && token_file.is_some() {
            log::warn!(
                "--token overrides --token-file: only the single --token is used for this run"
            );
        }
        let pool = if let Some(token) = token {
            TokenPool::from_token(token)?
        } else if let Some(token_file) = token_file {
            TokenPool::from_token_file(token_file)?
        } else {
            log::warn!(
                "no token provided: running anonymously, limited to 60 requests/hour — \
                 create one at github.com/settings/tokens and use --token or \
                 --token-file <tokens.json> for 5000 requests/hour each"
            );
            TokenPool::anonymous()
        };
        let client = Client::new(pool)?;
        Ok(Self {
            client,
            worker_requests: AtomicUsize::new(0),
        })
    }

    /// Counts successful requests made by the scan workers, on top
    /// of the ones made through the shared client.
    pub(crate) fn add_worker_requests(&self, requests: usize) {
        self.worker_requests.fetch_add(requests, Ordering::Relaxed);
    }

    /// Read-only access to the shared client, for the scan modules.
    pub(crate) fn client(&self) -> &Client {
        &self.client
    }

    /// How many successful GitHub API requests were made so far, i.e. roughly
    /// how many pages were fetched (reported in the JSON output).
    pub fn requests_made(&self) -> usize {
        self.client.requests_made() + self.worker_requests.load(Ordering::Relaxed)
    }

    /// Scans the already-parsed parts of a GitHub URL: a repository scan, or
    /// a profile scan when the repository part is empty. Callers (the CLI)
    /// parse the URL once — the author/repository names also build the
    /// output file names — and go through this method.
    ///
    /// # Errors
    ///
    /// Returns the failure of the underlying scan: [`Error::NotFound`] for a
    /// missing resource, [`Error::PrivateOrUnavailable`] for a private one,
    /// [`Error::EmptyRepository`] when the repository itself has no commits
    /// (GitHub answers 409 on its commits listing),
    /// [`Error::RateLimitExhausted`] once no token of the pool is usable, or
    /// an [`Error::Http`] transport failure. Never panics.
    pub fn scan_parts(&self, author: &str, repository: &str) -> Result<ScanOutcome, Error> {
        // scan profile case, as there is no repository
        if repository.is_empty() {
            return profile::scan_profile(self, author);
        }

        let scan = repository::scan_repository(self.client(), GITHUB_API_BASE, author, repository)?;
        // single-repository scan: the primary language would cost one extra
        // API call on the repository metadata, so the correlation reports it
        // as unknown (documented delta, issue #5)
        let mut correlation = CorrelationBuilder::new();
        correlation.add_repo(RepoContribution {
            name: format!("{author}/{repository}"),
            language: None,
            authors: scan.authors,
        });
        Ok(ScanOutcome {
            emails: scan.emails,
            repos_scanned: 1,
            correlation: correlation.finish(),
            partial: false,
        })
    }

    /// Fetches the repositories matching a user request (a `query` with an
    /// optional `language` and advanced [`SearchQualifiers`], up to `limit`
    /// repositories) and scans them.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidSearchQualifier`] when a provided qualifier
    /// value is malformed (rejected client-side, before any network
    /// request). Otherwise the same failures as [`Scanner::scan_parts`]: a
    /// scan-wide failure aborts the scan, while a dead dedicated token
    /// alone does not (the parallel scan keeps the emails found so far).
    /// Never panics.
    pub fn search(
        &self,
        query: &str,
        language: &str,
        qualifiers: &SearchQualifiers,
        limit: usize,
    ) -> Result<ScanOutcome, Error> {
        search::aggregate_search(self, query, language, qualifiers, limit)
    }
}

/// Whether an email sits on the GitHub noreply domain (`users.noreply.github.com`):
/// case-insensitive exact match on the domain only, no subdomain look-alike.
/// The single noreply rule of the crate — the same test the `user`
/// investigation applies to its noreply technique and the reverse email
/// lookup to its upfront rejection.
pub(crate) fn is_noreply_email(email: &str) -> bool {
    email
        .trim_matches('"')
        .rsplit_once('@')
        .is_some_and(|(_, domain)| domain.eq_ignore_ascii_case(NOREPLY_DOMAIN))
}

/// Whether an email is usable: non-empty, free of control characters and
/// whitespace (a crafted newline-carrying payload would inject lines into
/// the one-email-per-line plain output), not a GitHub `noreply` address, and
/// shaped like an address: exactly one `@` separating a non-empty local part
/// from a non-empty domain (the same structural rule the `email` subcommand
/// enforces in its upfront `split_email` rejection, so the scan paths can
/// never report as a found email a bare username or garbage string that the
/// `email` subcommand itself would reject as invalid — git permits
/// arbitrary author-email fields, and a domainless value like `jdoe` is
/// not a mailbox). The shared acceptance rule of the plain output and of
/// the correlation report, so both always stay consistent. A commit email
/// that merely contains `noreply` in its local part
/// (`john.noreply@acme.com`) is a real mailbox and must be kept: only the
/// exact noreply domain is excluded.
pub(crate) fn is_usable_email(email: &str) -> bool {
    let email = email.trim_matches('"');
    if email.is_empty()
        || email.chars().any(|c| c.is_control() || c.is_whitespace())
        || is_noreply_email(email)
    {
        return false;
    }
    match email.split_once('@') {
        Some((local, domain)) => !local.is_empty() && !domain.is_empty() && !domain.contains('@'),
        None => false,
    }
}

/// Keeps a found email when it is usable: non-empty, shaped like an
/// address, not a GitHub `noreply` address and not already found — the
/// dedup is case-insensitive (the same mailbox seen as `dev@example.com`
/// and `Dev@example.com` is one entry), matching the `user` investigation
/// and the bulk `emails` reverse lookup, which both key emails lowercased.
pub(crate) fn keep_email(emails: &mut Vec<String>, email: &str) {
    let email = email.trim_matches('"');
    if is_usable_email(email) && !emails.iter().any(|found| found.eq_ignore_ascii_case(email)) {
        emails.push(email.to_string());
    }
}

/// Merges newly found emails into the accumulated list, preventing
/// duplicates from different pages or repositories — case-insensitively
/// (the same dedup rule as [`keep_email`], so one mailbox can never be
/// counted twice because two pages disagree on its casing).
pub(crate) fn merge_emails(found_emails: &mut Vec<String>, new_emails: Vec<String>) {
    for email in new_emails {
        if !found_emails
            .iter()
            .any(|found| found.eq_ignore_ascii_case(&email))
        {
            found_emails.push(email);
        }
    }
}

/// Sorts found emails alphabetically, case-insensitively (legacy order).
pub(crate) fn sort_emails(emails: &mut [String]) {
    emails.sort_by_key(|a| a.to_lowercase());
}

#[cfg(test)]
mod tests {
    // Tests may unwrap, expect and panic freely: a failing assertion must
    // be loud, so the zero-panic lints do not apply to the test modules.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn is_usable_email_rejects_only_the_exact_noreply_domain() {
        assert!(is_usable_email("dev@example.com"));
        // a `noreply`-looking local part is a real mailbox, not a GitHub
        // noreply address: it must not be dropped by substring luck
        assert!(is_usable_email("john.noreply@acme.com"));
        // a subdomain look-alike is not the noreply domain
        assert!(is_usable_email("dev@xusers.noreply.github.com"));
        assert!(!is_usable_email("12345+dev@users.noreply.github.com"));
        assert!(!is_usable_email("12345+dev@USERS.NOREPLY.GITHUB.COM"));
        // quoted commit emails are unwrapped before the test
        assert!(!is_usable_email("\"12345+dev@users.noreply.github.com\""));
        assert!(!is_usable_email(""));
        // a crafted control character or whitespace would inject lines into
        // the one-email-per-line plain output: never kept, whatever the
        // (necessarily hostile) payload
        assert!(!is_usable_email("dev@x.com\n evil@x.com"));
        assert!(!is_usable_email("dev\t@x.com"));
        assert!(!is_usable_email("dev@x.com\u{1b}[31m"));
    }

    #[test]
    fn is_usable_email_requires_exactly_one_at_sign_like_the_email_subcommand() {
        // the `email` subcommand rejects these strings as invalid addresses
        // (`split_email`: missing '@', empty local part or domain, a second
        // '@' in the domain): the shared scan rule must reject them too, so
        // a domainless commit-email field (git permits any string, e.g. a
        // bare username) can never be reported as a found email
        assert!(!is_usable_email("jdoe"));
        assert!(!is_usable_email("no-at-sign"));
        assert!(!is_usable_email("@example.com"));
        assert!(!is_usable_email("dev@"));
        assert!(!is_usable_email("dev@x@com"));
        assert!(is_usable_email("dev@example.com"));
        // a quoted email is unwrapped before the test
        assert!(is_usable_email("\"dev@example.com\""));
        assert!(!is_usable_email("\"jdoe\""));
    }

    #[test]
    fn keep_email_filters_noreply_and_duplicates() {
        let mut emails: Vec<String> = Vec::new();
        keep_email(&mut emails, "dev@example.com");
        keep_email(&mut emails, "dev@example.com");
        keep_email(&mut emails, "12345+dev@users.noreply.github.com");
        keep_email(&mut emails, "");
        assert_eq!(emails, vec!["dev@example.com".to_string()]);
    }

    #[test]
    fn keep_email_and_merge_emails_deduplicate_case_variants_like_the_user_path() {
        // the user investigation and the bulk emails lookup key emails
        // lowercased: one mailbox seen through two casings must count once
        // everywhere, not twice on the scan paths and once on the user path
        let mut emails: Vec<String> = Vec::new();
        keep_email(&mut emails, "arwin.tio@adroll.com");
        keep_email(&mut emails, "Arwin.tio@adroll.com");
        assert_eq!(emails, vec!["arwin.tio@adroll.com".to_string()]);
        // the first spelling seen wins: the plain output keeps what the
        // commits carried first, sorted case-insensitively afterwards
        merge_emails(&mut emails, vec!["ARWIN.TIO@ADROLL.COM".to_string()]);
        assert_eq!(emails, vec!["arwin.tio@adroll.com".to_string()]);
        // a genuinely different mailbox is still kept, whatever its casing
        keep_email(&mut emails, "dev@ADROLL.com");
        assert_eq!(emails.len(), 2);
    }

    #[test]
    fn merge_emails_deduplicates_across_pages() {
        let mut emails = vec!["b@b.b".to_string()];
        merge_emails(&mut emails, vec!["a@a.a".to_string(), "b@b.b".to_string()]);
        assert_eq!(emails, vec!["b@b.b".to_string(), "a@a.a".to_string()]);
    }

    #[test]
    fn scanner_new_warns_when_token_overrides_the_token_file() {
        // a stale --token in a wrapper script must not silently downgrade a
        // multi-token pool run to one token: the override is logged (the
        // token file is never read, so the path needs not exist)
        let (scanner, lines) = crate::test_logger::capture(|| {
            Scanner::new(Some("ghp_valid"), Some(Path::new("tokens-unused.json")))
        });
        let scanner = scanner.expect("the scanner must build");
        assert_eq!(scanner.requests_made(), 0);
        assert!(
            lines
                .iter()
                .any(|line| line.contains("--token overrides --token-file")),
            "the override warning must be logged, got: {lines:?}"
        );
        // no warning when the two sources are not in conflict
        let (_, lines) = crate::test_logger::capture(|| Scanner::new(Some("ghp_valid"), None));
        assert!(!lines.iter().any(|line| line.contains("--token overrides")));
    }

    #[test]
    fn sort_emails_sorts_case_insensitively() {
        // the sort is the legacy stable lowercase sort
        let mut emails: Vec<String> = vec![
            "Zed@x.x".to_string(),
            "alice@y.y".to_string(),
            "bob@z.z".to_string(),
        ];
        sort_emails(&mut emails);
        assert_eq!(
            emails,
            vec![
                "alice@y.y".to_string(),
                "bob@z.z".to_string(),
                "Zed@x.x".to_string()
            ]
        );
    }

    #[test]
    fn scanner_new_treats_a_whitespace_only_token_as_no_token() {
        // a whitespace-only --token is no token at all: the anonymous
        // warning fires (no invalid-token error, no silent downgrade), and
        // a token file is honored instead of being overridden
        let (scanner, lines) = crate::test_logger::capture(|| Scanner::new(Some("   "), None));
        let scanner = scanner.expect("a whitespace-only token falls back to anonymous");
        assert_eq!(scanner.requests_made(), 0);
        assert!(
            lines
                .iter()
                .any(|line| line.contains("no token provided: running anonymously")),
            "the anonymous warning must be logged, got: {lines:?}"
        );
        // the file fallback actually reads the file: write a real one
        let path =
            std::env::temp_dir().join(format!("git2mail_ws_token_{}.json", std::process::id()));
        std::fs::write(&path, r#"{ "0": "ghp_valid" }"#).unwrap();
        let (scanner, lines) =
            crate::test_logger::capture(|| Scanner::new(Some("   "), Some(&path)));
        drop(std::fs::remove_file(&path));
        let scanner = scanner.expect("the whitespace-only token must fall back to the file");
        assert_eq!(scanner.requests_made(), 0);
        assert!(
            !lines
                .iter()
                .any(|line| line.contains("--token overrides --token-file")),
            "a whitespace-only --token must not warn about overriding the file, got: {lines:?}"
        );
    }

    #[test]
    fn scanner_rejects_an_invalid_token_before_any_scan() {
        assert!(matches!(
            Scanner::new(Some("not_a_token"), None),
            Err(Error::InvalidTokenFormat(_))
        ));
    }

    #[test]
    fn scanner_builds_an_anonymous_client_without_token() {
        let scanner = Scanner::new(None, None).expect("anonymous scanner must build");
        assert!(scanner.client().tokens().is_empty());
    }
}
