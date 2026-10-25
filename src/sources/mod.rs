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

use crate::correlate::{Correlation, CorrelationBuilder, RepoContribution};
use crate::errors::Error;
use crate::github::{Client, TokenPool};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

pub use search::SearchQualifiers;

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
    /// `token` wins over `token_file` when both are provided; when neither
    /// is, the scan runs anonymously (60 req/h).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidTokenFormat`] when `token` or a token of the
    /// file does not follow the expected format, and [`Error::Http`] when
    /// the HTTP client cannot be built. Never panics.
    pub fn new(token: Option<&str>, token_file: Option<&Path>) -> Result<Self, Error> {
        let pool = if let Some(token) = token.filter(|token| !token.is_empty()) {
            TokenPool::from_token(token)?
        } else if let Some(token_file) = token_file {
            TokenPool::from_token_file(token_file)?
        } else {
            log::warn!(
                "no token provided: running anonymously, limited to 60 requests/hour \
                 (use --token or --token-file <tokens.json> for 5000 requests/hour each)"
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
    /// [`Error::RateLimitExhausted`] once no token of the pool is usable, or
    /// an [`Error::Http`] transport failure. Never panics.
    pub fn scan_parts(&self, author: &str, repository: &str) -> Result<ScanOutcome, Error> {
        // scan profile case, as there is no repository
        if repository.is_empty() {
            return profile::scan_profile(self, author);
        }

        let scan = repository::scan_repository(self.client(), author, repository)?;
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

/// Whether an email is usable: non-empty and not a GitHub `noreply` address.
/// The shared acceptance rule of the plain output and of the correlation
/// report, so both always stay consistent.
pub(crate) fn is_usable_email(email: &str) -> bool {
    let email = email.trim_matches('"');
    // a crafted commit email with control characters or whitespace (a
    // newline would forge extra lines in the one-email-per-line result
    // file, an ESC would inject terminal sequences) is never usable: the
    // plain output and the correlation report only carry real addresses
    !email.is_empty()
        && !email.contains("noreply")
        && email.bytes().all(|byte| {
            byte.is_ascii_graphic() || byte.is_ascii_alphanumeric() || byte == b'@' || byte == b'.'
        })
}

/// Keeps a found email when it is usable: non-empty, not a GitHub `noreply`
/// address and not already found.
pub(crate) fn keep_email(emails: &mut Vec<String>, email: &str) {
    if is_usable_email(email) && !emails.iter().any(|found| found == email.trim_matches('"')) {
        emails.push(email.trim_matches('"').to_string());
    }
}

/// Merges newly found emails into the accumulated list, preventing duplicates
/// from different pages or repositories.
pub(crate) fn merge_emails(found_emails: &mut Vec<String>, new_emails: Vec<String>) {
    for email in new_emails {
        if !found_emails.contains(&email) {
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
    fn keep_email_filters_noreply_and_duplicates() {
        let mut emails: Vec<String> = Vec::new();
        keep_email(&mut emails, "dev@example.com");
        keep_email(&mut emails, "dev@example.com");
        keep_email(&mut emails, "12345+dev@users.noreply.github.com");
        keep_email(&mut emails, "");
        assert_eq!(emails, vec!["dev@example.com".to_string()]);
    }

    #[test]
    fn merge_emails_deduplicates_across_pages() {
        let mut emails = vec!["b@b.b".to_string()];
        merge_emails(&mut emails, vec!["a@a.a".to_string(), "b@b.b".to_string()]);
        assert_eq!(emails, vec!["b@b.b".to_string(), "a@a.a".to_string()]);
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
