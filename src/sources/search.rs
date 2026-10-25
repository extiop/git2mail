//! Search scan: the repositories matching a query, scanned in parallel.

use crate::correlate::{Correlation, CorrelationBuilder, RepoContribution};
use crate::errors::Error;
use crate::github::fetch_paginated;
use crate::parsers;
use crate::sources::{PER_PAGE, ScanOutcome, Scanner, merge_emails, sort_emails};
use serde_json::Value;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};

/// Comparison prefixes accepted in front of a qualifier value (count or
/// date), following the github.com/search/advanced semantics. `>=` and
/// `<=` must be tried before `>` and `<`.
const COMPARISON_PREFIXES: [&str; 4] = [">=", "<=", ">", "<"];

/// Optional GitHub repository-search qualifiers, following the
/// [advanced search](https://github.com/search/advanced) semantics.
///
/// Every provided field appends one `name:value` qualifier to the `q`
/// parameter of the search request (for instance `stars:>100`); unset
/// fields contribute nothing. The qualifiers compose with the `--query`,
/// `--language` and `--limit` search parameters.
///
/// Values are validated client-side by [`SearchQualifiers::validate`]
/// before any network request: an obviously malformed range or date fails
/// with [`Error::InvalidSearchQualifier`] instead of reaching the API.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SearchQualifiers {
    /// Repository star count, e.g. `>100`, `>=50`, `10..50` or `100..*`.
    pub stars: Option<String>,
    /// Repository fork count, same range syntax as `stars`.
    pub forks: Option<String>,
    /// Repository size in kilobytes, same range syntax as `stars`.
    pub size: Option<String>,
    /// Repository creation date, e.g. `>2020-01-01`, `>=2020` or
    /// `2019-01-01..2020-01-01`.
    pub created: Option<String>,
    /// Repository last-push date, same date syntax as `created`.
    pub pushed: Option<String>,
    /// Repository license identifier, e.g. `mit` or `apache-2.0`.
    pub license: Option<String>,
    /// Repository topic, e.g. `osint`.
    pub topic: Option<String>,
    /// Restrict the search to one user's repositories (login).
    pub user: Option<String>,
    /// Restrict the search to one organization's repositories (login).
    pub org: Option<String>,
}

impl SearchQualifiers {
    /// Validates every provided qualifier value client-side, before any
    /// network request: a malformed range, an impossible date or a name
    /// holding forbidden characters fails fast instead of surfacing as a
    /// mysterious empty result set from the API.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidSearchQualifier`] describing the first
    /// malformed value. Never panics.
    pub fn validate(&self) -> Result<(), Error> {
        for (name, value) in self.provided() {
            match name {
                "stars" | "forks" | "size" => validate_count_range(name, value)?,
                "created" | "pushed" => validate_date_range(name, value)?,
                _ => validate_name(name, value)?,
            }
        }
        Ok(())
    }

    /// The provided qualifiers as `(qualifier name, raw value)` pairs, in
    /// the fixed order they are appended to the `q` parameter. Empty values
    /// contribute nothing and are never sent: they do not even reach
    /// [`Self::validate`], which only sees non-empty values.
    fn provided(&self) -> Vec<(&'static str, &str)> {
        [
            ("stars", &self.stars),
            ("forks", &self.forks),
            ("size", &self.size),
            ("created", &self.created),
            ("pushed", &self.pushed),
            ("license", &self.license),
            ("topic", &self.topic),
            ("user", &self.user),
            ("org", &self.org),
        ]
        .into_iter()
        .filter_map(|(name, value)| {
            value
                .as_deref()
                .filter(|value| !value.is_empty())
                .map(|value| (name, value))
        })
        .collect()
    }
}

/// Builds the [`Error::InvalidSearchQualifier`] for one rejected value.
fn invalid_qualifier(name: &str, value: &str, expected: &str) -> Error {
    Error::InvalidSearchQualifier(format!("{name} {value:?}: expected {expected}"))
}

/// Whether a string is a non-empty run of ASCII digits.
fn is_digits(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit())
}

/// Strips a leading comparison prefix (`>`, `>=`, `<`, `<=`) from a value.
fn strip_comparison(value: &str) -> &str {
    COMPARISON_PREFIXES
        .iter()
        .find_map(|prefix| value.strip_prefix(prefix))
        .unwrap_or(value)
}

/// Validates a `stars`/`forks`/`size` value: either a standalone count with
/// an optional comparison prefix (`100`, `>100`, `<=50`), or an `a..b`
/// range whose sides are a count or `*` for open-ended (`10..50`, `100..*`).
fn validate_count_range(name: &str, value: &str) -> Result<(), Error> {
    const EXPECTED: &str = "a count like >100 or a range like 10..50";
    if let Some((low, high)) = value.split_once("..") {
        if (low == "*" || is_digits(low)) && (high == "*" || is_digits(high)) {
            return Ok(());
        }
        return Err(invalid_qualifier(name, value, EXPECTED));
    }
    if is_digits(strip_comparison(value)) {
        return Ok(());
    }
    Err(invalid_qualifier(name, value, EXPECTED))
}

/// Validates one date of a `created`/`pushed` qualifier at the granularities
/// the GitHub search accepts: `YYYY`, `YYYY-MM` or `YYYY-MM-DD`, with
/// obviously impossible months/days rejected (including days beyond the
/// length of the month, leap years included).
fn is_date(value: &str) -> bool {
    let parts: Vec<&str> = value.split('-').collect();
    match parts.as_slice() {
        [year] => year.len() == 4 && is_digits(year),
        [year, month] => is_date_year_month(year, month),
        [year, month, day] => {
            is_date_year_month(year, month)
                && is_digits(day)
                && day.len() == 2
                && day
                    .parse::<u32>()
                    .is_ok_and(|day| (1..=days_in_month(year, month)).contains(&day))
        }
        _ => false,
    }
}

/// The number of days of one `YYYY`/`MM` month (hand-rolled, no new
/// dependency), with the standard leap-year rule. The callers only
/// invoke it after [`is_date_year_month`] validated the pair, so the parses
/// always succeed; the fallbacks keep the helper panic-free anyway.
fn days_in_month(year: &str, month: &str) -> u32 {
    match month.parse::<u32>() {
        Ok(1 | 3 | 5 | 7 | 8 | 10 | 12) => 31,
        Ok(4 | 6 | 9 | 11) => 30,
        Ok(2) => {
            let year = year.parse::<u32>().unwrap_or(0);
            let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
            if leap { 29 } else { 28 }
        }
        _ => 0,
    }
}

/// Whether a `YYYY`/`MM` pair of a date is well-formed.
fn is_date_year_month(year: &str, month: &str) -> bool {
    year.len() == 4
        && is_digits(year)
        && is_digits(month)
        && month.len() == 2
        && month
            .parse::<u32>()
            .is_ok_and(|month| (1..=12).contains(&month))
}

/// Validates a `created`/`pushed` value: either a standalone date with an
/// optional comparison prefix (`2020-01-01`, `>=2020`), or a `date..date`
/// range whose sides are a date or `*` for open-ended
/// (`2019-01-01..2020-01-01`, `2019-01-01..*`).
fn validate_date_range(name: &str, value: &str) -> Result<(), Error> {
    const EXPECTED: &str = "a date like >=2020-01-01 or a range like 2019-01-01..2020-01-01";
    if let Some((low, high)) = value.split_once("..") {
        // comparison and range are mutually exclusive forms on GitHub
        // search: a prefix on a range side would not be a valid qualifier,
        // so the sides are validated as plain dates, without stripping
        if (low == "*" || is_date(low)) && (high == "*" || is_date(high)) {
            return Ok(());
        }
        return Err(invalid_qualifier(name, value, EXPECTED));
    }
    if is_date(strip_comparison(value)) {
        return Ok(());
    }
    Err(invalid_qualifier(name, value, EXPECTED))
}

/// Validates a `license`/`topic`/`user`/`org` value: a non-empty name of
/// ASCII letters, digits, `-`, `_` or `.` (covers `mit`, `apache-2.0`,
/// `osint` and GitHub logins), with no whitespace or separator character
/// that would silently break the `name:value` qualifier.
fn validate_name(name: &str, value: &str) -> Result<(), Error> {
    const EXPECTED: &str = "a name like mit, osint or acme";
    if value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        return Ok(());
    }
    Err(invalid_qualifier(name, value, EXPECTED))
}

/// Get repositories according to a user request made with metadata
/// (`query` + optional `language` and [`SearchQualifiers`], up to `limit`
/// repositories).
///
/// For each found repository, it scans it and gets its developers emails,
/// then deduplicates and sorts the concatenated result, and builds the
/// per-author correlation report (issue #5) with the primary language each
/// search result already carries.
pub(crate) fn aggregate_search(
    scanner: &Scanner,
    query: &str,
    language: &str,
    qualifiers: &SearchQualifiers,
    limit: usize,
) -> Result<ScanOutcome, Error> {
    // fail fast on a malformed qualifier before any network request
    qualifiers.validate()?;
    // stop fetching as soon as the user limit is reached: the next pages
    // would only be requested to be thrown away
    let hits: Vec<SearchHit> = fetch_paginated(
        scanner.client(),
        |page| search_url(query, language, qualifiers, page),
        parse_search_page,
        Some(limit),
    )?;

    let (mut found_emails, repos_scanned, correlation) = scanner.scan_repositories(&hits)?;
    sort_emails(&mut found_emails);

    Ok(ScanOutcome {
        emails: found_emails,
        repos_scanned,
        correlation,
    })
}

/// One repository candidate of a search listing: its `html_url` plus the
/// primary language GitHub reports for it — free correlation metadata
/// (issue #5), no extra API call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SearchHit {
    pub(crate) url: String,
    pub(crate) language: Option<String>,
}

/// Builds the search endpoint URL for `page`.
fn search_url(query: &str, language: &str, qualifiers: &SearchQualifiers, page: u16) -> String {
    format!(
        "https://api.github.com/search/repositories?q={}&per_page={PER_PAGE}&page={page}",
        search_q(query, language, qualifiers)
    )
}

/// Builds the `q` parameter of the search endpoint: the percent-encoded user
/// query first, then the optional `language:` qualifier, then the provided
/// advanced qualifiers (`name:value` parts, space-joined as `+` in the URL).
/// The user-supplied values are percent-encoded: a raw `&`, `#`, `+` or
/// space would be split, truncated or rewritten server-side instead of being
/// part of the query.
fn search_q(query: &str, language: &str, qualifiers: &SearchQualifiers) -> String {
    let mut q = percent_encode(query);
    if !language.is_empty() {
        q.push_str("+language:");
        q.push_str(&percent_encode(language));
    }
    for (name, value) in qualifiers.provided() {
        q.push('+');
        q.push_str(name);
        q.push(':');
        q.push_str(&percent_encode(value));
    }
    q
}

/// Extracts the `html_url` of every repository of a search page (`items`)
/// with the primary language GitHub reports for it, together with the raw
/// number of items the page held: the raw count is the end-of-listing signal
/// of `fetch_paginated`. A rejected search (`{"items": null}`) holds no raw
/// item and ends the listing.
fn parse_search_page(json: &Value) -> Result<(Vec<SearchHit>, usize), Error> {
    let Some(items) = json.get("items").and_then(Value::as_array) else {
        return Ok((Vec::new(), 0));
    };
    let repositories = items
        .iter()
        .filter_map(|item| {
            let url = item.get("html_url").and_then(Value::as_str)?;
            let language = item
                .get("language")
                .and_then(Value::as_str)
                .map(str::to_string);
            Some(SearchHit {
                url: url.to_string(),
                language,
            })
        })
        .collect();
    Ok((repositories, items.len()))
}

/// Percent-encodes a user-supplied string for safe interpolation in a URL
/// query parameter (hand-rolled, no new dependency): every byte
/// outside the RFC 3986 unreserved set becomes `%XX`.
fn percent_encode(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(byte as char);
            }
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}

impl Scanner {
    /// Scans the given repositories in parallel: a pool of
    /// `min(nb_tokens, nb_repositories)` workers (`std::thread::scope`),
    /// each owning exactly one dedicated token through its own
    /// [`crate::github::Client`] — no shared mutable token state, no
    /// contention. The repositories are distributed through a
    /// `std::sync::mpsc` work queue: every worker pulls the next repository
    /// from the channel until it is drained. The mono-repository /
    /// mono-profile scans stay sequential.
    ///
    /// An anonymous scan (no token) runs a single worker on the shared
    /// anonymous quota. A worker whose dedicated token runs dry
    /// ([`Error::RateLimitExhausted`]) or is rejected by the API (HTTP 401 on
    /// a revoked/invalid token) stops pulling work but does not fail the
    /// scan: the other workers' tokens keep draining the queue and the
    /// emails found so far are returned. A repository that cannot be scanned
    /// on its own (404 of a stale search-index entry, 403 of a private
    /// repository or a token without the right scope) is skipped with a
    /// warning and does not stop the worker: the failure is resource-scoped,
    /// the token stays valid for the remaining repositories. Any other
    /// worker error aborts the whole scan, as the sequential scan did.
    ///
    /// Returns the emails found (deduplicated), the number of repositories
    /// actually scanned, and the per-author correlation report built from
    /// the workers' contributions (issue #5), for the JSON report.
    pub(crate) fn scan_repositories(
        &self,
        repositories: &[SearchHit],
    ) -> Result<(Vec<String>, usize, Correlation), Error> {
        if repositories.is_empty() {
            return Ok((Vec::new(), 0, Correlation::default()));
        }
        let workers = worker_count(self.client.tokens().len(), repositories.len());

        // work queue: every repository hit is sent once, then the sender is
        // dropped, so `recv` returns `Err` once the queue is drained — the
        // workers' natural stop signal
        let (work_tx, work_rx) = mpsc::channel::<SearchHit>();
        for hit in repositories {
            if work_tx.send(hit.clone()).is_err() {
                break;
            }
        }
        drop(work_tx);
        let work_rx = Arc::new(Mutex::new(work_rx));

        let (result_tx, result_rx) = mpsc::channel::<WorkerReport>();
        // set as soon as a worker fails, so the others stop pulling work
        let aborted = AtomicBool::new(false);

        std::thread::scope(|scope| {
            // shared state, borrowed by every worker closure
            let work_rx = &work_rx;
            let aborted = &aborted;
            for worker in 0..workers {
                let dedicated_token = self.client.tokens().dedicated_token(worker);
                let result_tx = result_tx.clone();
                scope.spawn(move || {
                    let report = Self::scan_worker_queue(dedicated_token, work_rx, aborted);
                    let _ = result_tx.send(report);
                });
            }
        });
        drop(result_tx); // the scope joined every worker: no more reports

        // every worker sent exactly one report
        let reports: Vec<WorkerReport> = (0..workers)
            .map(|_| {
                result_rx.recv().unwrap_or_else(|_| WorkerReport {
                    emails: Vec::new(),
                    requests: 0,
                    repos_scanned: 0,
                    contributions: Vec::new(),
                    failure: Some(Error::WorkerFailed(
                        "scan worker did not report".to_string(),
                    )),
                    token_died: false,
                })
            })
            .collect();
        let (result, worker_requests, repos_scanned, correlation) = reduce_worker_reports(reports);
        self.add_worker_requests(worker_requests);
        result.map(|emails| (emails, repos_scanned, correlation))
    }

    /// Worker body: owns one dedicated token through its own
    /// client, pulls the next repository from the shared `mpsc` work queue
    /// and scans it, until the queue is drained or another worker failed.
    /// Returns everything it found, the per-author contributions of the
    /// repositories it scanned (issue #5), how many successful requests its
    /// client made and, when it hit one, the failure that ended it.
    fn scan_worker_queue(
        dedicated_token: Option<&str>,
        work_rx: &Arc<Mutex<mpsc::Receiver<SearchHit>>>,
        aborted: &AtomicBool,
    ) -> WorkerReport {
        let client = match Self::worker_client(dedicated_token) {
            Ok(client) => client,
            Err(err) => {
                return WorkerReport {
                    emails: Vec::new(),
                    requests: 0,
                    repos_scanned: 0,
                    contributions: Vec::new(),
                    failure: Some(err),
                    token_died: false,
                };
            }
        };
        let mut found_emails: Vec<String> = Vec::new();
        let mut repos_scanned = 0usize;
        let mut contributions: Vec<RepoContribution> = Vec::new();

        loop {
            // stop pulling work as soon as any worker failed fatally: the
            // scan is going to error out anyway
            if aborted.load(Ordering::Relaxed) {
                break;
            }
            // the mutex only guards pulling one hit off the channel; the
            // queue is fully populated upfront, so `recv` never blocks long
            let hit = {
                let Ok(receiver) = work_rx.lock() else {
                    break; // poisoned queue: stop pulling work
                };
                receiver.recv().ok() // `None` once the queue is drained
            };
            let Some(hit) = hit else {
                break; // the shared queue is empty: this worker is done
            };
            // keep the URL around for the skip warning: the parser helpers
            // take it by value
            let repository_url = hit.url.clone();
            let author = match parsers::get_author(repository_url.clone()) {
                Ok(author) => author,
                Err(err) => {
                    aborted.store(true, Ordering::Relaxed);
                    return Self::worker_report(
                        &client,
                        found_emails,
                        contributions,
                        repos_scanned,
                        Some(err),
                        false,
                    );
                }
            };
            let repository = match parsers::get_repository(repository_url.clone()) {
                Ok(repository) => repository,
                Err(err) => {
                    aborted.store(true, Ordering::Relaxed);
                    return Self::worker_report(
                        &client,
                        found_emails,
                        contributions,
                        repos_scanned,
                        Some(err),
                        false,
                    );
                }
            };
            let scan = match super::repository::scan_repository(&client, &author, &repository) {
                Ok(scan) => scan,
                Err(err) => match classify_failure(&err) {
                    // this worker's dedicated token budget is its own: once
                    // it dies the worker stops pulling work, but the other
                    // workers' tokens keep draining the queue, so the failure
                    // is not fatal and the emails found so far are kept
                    FailureAction::TokenDied => {
                        return Self::worker_report(
                            &client,
                            found_emails,
                            contributions,
                            repos_scanned,
                            Some(err),
                            true,
                        );
                    }
                    // the failure is scoped to this repository (deleted,
                    // private, token without the right scope): skip it like
                    // the profile fallback does, the token stays valid for
                    // the remaining repositories
                    FailureAction::SkipRepository => {
                        log::warn!(
                            "skipping repository {}: {}",
                            crate::output::sanitize_log_text(&repository_url),
                            crate::output::sanitize_log_text(&err.to_string())
                        );
                        continue;
                    }
                    FailureAction::AbortScan => {
                        aborted.store(true, Ordering::Relaxed);
                        return Self::worker_report(
                            &client,
                            found_emails,
                            contributions,
                            repos_scanned,
                            Some(err),
                            false,
                        );
                    }
                },
            };
            merge_emails(&mut found_emails, scan.emails);
            contributions.push(RepoContribution {
                name: format!("{author}/{repository}"),
                language: hit.language,
                authors: scan.authors,
            });
            repos_scanned += 1;
        }
        Self::worker_report(
            &client,
            found_emails,
            contributions,
            repos_scanned,
            None,
            false,
        )
    }

    /// Bundles what a worker found, the per-author contributions of its
    /// scanned repositories (issue #5), how many requests its client made,
    /// how many repositories it fully scanned and the failure that ended it
    /// (if any) into its final report.
    fn worker_report(
        client: &crate::github::Client,
        emails: Vec<String>,
        contributions: Vec<RepoContribution>,
        repos_scanned: usize,
        failure: Option<Error>,
        token_died: bool,
    ) -> WorkerReport {
        WorkerReport {
            emails,
            requests: client.requests_made(),
            repos_scanned,
            contributions,
            failure,
            token_died,
        }
    }

    /// Builds the client a worker exclusively owns for its dedicated token
    /// (single-token pool, no shared state); an anonymous scan (no token)
    /// runs one worker on the shared anonymous quota.
    fn worker_client(dedicated_token: Option<&str>) -> Result<crate::github::Client, Error> {
        match dedicated_token {
            Some(token) => crate::github::Client::new(crate::github::TokenPool::from_token(token)?),
            None => crate::github::Client::anonymous(),
        }
    }
}

/// What a scan worker must do when scanning one repository fails.
enum FailureAction {
    /// The worker's dedicated token died (spent quota, or HTTP 401 on a
    /// revoked/invalid token): stop the worker, keep its findings, let the
    /// other tokens drain the queue.
    TokenDied,
    /// The failure is scoped to this repository only (a 404 of a stale
    /// search-index entry, a 403 for a private repository or a token without
    /// the right scope): skip it and keep pulling work. A 403 is
    /// resource-scoped, not token-scoped: with a fine-grained PAT or one
    /// inaccessible repository among the results, the token stays valid for
    /// the remaining repositories.
    SkipRepository,
    /// Unexpected failure: abort the whole scan.
    AbortScan,
}

/// Classifies a repository scan failure. An HTTP 403 maps to
/// [`Error::PrivateOrUnavailable`] and is skipped, not treated as a dead
/// token: only an HTTP 401 means the token itself was rejected by the API
/// (tokens are only format-validated at startup).
fn classify_failure(err: &Error) -> FailureAction {
    match err {
        // the API layer maps an HTTP 401 to the dedicated status-less
        // `Error::TokenRejected` before any `Error::Http` could carry the
        // status, so a revoked dedicated token must be classified HERE —
        // the raw-401 arm would be dead code and the worker would abort
        // the whole scan instead of dying alone
        Error::RateLimitExhausted | Error::TokenRejected => FailureAction::TokenDied,
        Error::NotFound | Error::PrivateOrUnavailable => FailureAction::SkipRepository,
        _ => FailureAction::AbortScan,
    }
}

/// What one scan worker reports back: the emails it found, the per-author
/// contributions of the repositories it scanned (issue #5), how many
/// successful requests its client made, how many repositories it fully
/// scanned, and the failure that ended it (if any) — a worker keeps its
/// partial findings even when it failed.
struct WorkerReport {
    emails: Vec<String>,
    requests: usize,
    /// Repositories this worker fully scanned: even a worker whose token
    /// died mid-scan may have made real progress that must not be thrown
    /// away with its failure.
    repos_scanned: usize,
    /// The per-author contributions of the scanned repositories (issue #5).
    contributions: Vec<RepoContribution>,
    failure: Option<Error>,
    /// Whether the failure ended the worker because its own dedicated token
    /// died (spent quota or rejected token) rather than a scan-wide error:
    /// the other workers' tokens can keep draining the queue.
    token_died: bool,
}

/// Reduces the workers' reports into the scan result, the total number of
/// successful requests they made, the total number of repositories they
/// actually scanned (the JSON report must not overstate coverage by counting
/// repositories that were skipped or never pulled) and the per-author
/// correlation report built from their contributions (issue #5).
///
/// A worker whose dedicated token died ([`Error::RateLimitExhausted`], or a
/// rejected token) does not fail the scan: the other workers' tokens keep
/// draining the queue and the emails found so far are returned (possibly
/// partial). Any other failure aborts the scan, as does a token death with
/// no worker left having made any progress (single anonymous worker, or
/// every token dead before scanning anything).
fn reduce_worker_reports(
    reports: Vec<WorkerReport>,
) -> (Result<Vec<String>, Error>, usize, usize, Correlation) {
    let mut found_emails: Vec<String> = Vec::new();
    let mut requests = 0usize;
    let mut repos_scanned = 0usize;
    let mut correlation = CorrelationBuilder::new();
    let mut failure: Option<Error> = None;
    let mut only_token_deaths = true;
    let mut any_progress = false;
    for report in reports {
        merge_emails(&mut found_emails, report.emails);
        requests += report.requests;
        repos_scanned += report.repos_scanned;
        correlation.add_all(report.contributions);
        // a worker that scanned at least one repository made real progress,
        // even if its token died on a later request: its findings must not
        // be discarded with its failure
        any_progress = any_progress || report.repos_scanned > 0 || report.failure.is_none();
        if let Some(err) = report.failure {
            if !report.token_died {
                only_token_deaths = false;
            }
            if failure.is_none() {
                failure = Some(err);
            }
        }
    }
    let result = match failure {
        // every failure is a dead dedicated token and at least one worker
        // made progress on its own token: return the (possibly partial)
        // result instead of throwing the work away
        Some(_) if only_token_deaths && any_progress => {
            log::warn!(
                "a scan worker's dedicated token died (rate limit or rejection): the other tokens may not have covered every repository"
            );
            Ok(found_emails)
        }
        Some(err) => Err(err),
        None => Ok(found_emails),
    };
    (result, requests, repos_scanned, correlation.finish())
}

/// How many workers scan the repositories: one per available
/// token, capped by the number of repositories; an anonymous scan (no token)
/// runs a single worker on the shared anonymous quota.
fn worker_count(tokens: usize, repositories: usize) -> usize {
    tokens.max(1).min(repositories)
}

#[cfg(test)]
mod tests {
    // Tests may unwrap, expect and panic freely: a failing assertion must
    // be loud, so the zero-panic lints do not apply to the test modules.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::github::mock;
    use std::sync::Arc;

    #[test]
    fn search_url_percent_encodes_query_and_language() {
        assert_eq!(
            search_url("rust & go #1", "C++", &SearchQualifiers::default(), 2),
            "https://api.github.com/search/repositories?q=rust%20%26%20go%20%231+language:C%2B%2B&per_page=100&page=2"
        );
    }

    #[test]
    fn search_url_omits_the_language_qualifier_when_absent() {
        assert_eq!(
            search_url("nmap", "", &SearchQualifiers::default(), 1),
            "https://api.github.com/search/repositories?q=nmap&per_page=100&page=1"
        );
    }

    #[test]
    fn search_url_appends_every_provided_qualifier_in_a_fixed_order() {
        let qualifiers = SearchQualifiers {
            stars: Some(">100".to_string()),
            pushed: Some(">2024-01-01".to_string()),
            license: Some("mit".to_string()),
            topic: Some("osint".to_string()),
            org: Some("acme".to_string()),
            ..SearchQualifiers::default()
        };
        assert_eq!(
            search_url("nmap", "Rust", &qualifiers, 1),
            "https://api.github.com/search/repositories?q=nmap+language:Rust+stars:%3E100+pushed:%3E2024-01-01+license:mit+topic:osint+org:acme&per_page=100&page=1"
        );
    }

    #[test]
    fn search_url_percent_encodes_the_qualifier_values() {
        let qualifiers = SearchQualifiers {
            topic: Some("machine learning".to_string()),
            user: Some("a&b".to_string()),
            ..SearchQualifiers::default()
        };
        let url = search_url("nmap", "", &qualifiers, 1);
        assert!(
            url.contains("q=nmap+topic:machine%20learning+user:a%26b"),
            "the qualifier values must be percent-encoded: {url}"
        );
    }

    #[test]
    fn search_q_omits_every_unset_qualifier() {
        assert_eq!(search_q("nmap", "", &SearchQualifiers::default()), "nmap");
        let one_qualifier = SearchQualifiers {
            stars: Some("10..50".to_string()),
            ..SearchQualifiers::default()
        };
        assert_eq!(search_q("nmap", "", &one_qualifier), "nmap+stars:10..50");
    }

    #[test]
    fn validate_accepts_every_documented_qualifier_shape() {
        let qualifiers = SearchQualifiers {
            stars: Some(">=5000".to_string()),
            forks: Some("10..50".to_string()),
            size: Some("100..*".to_string()),
            created: Some(">2020-01-01".to_string()),
            pushed: Some("2019-01-01..2020-01-01".to_string()),
            license: Some("apache-2.0".to_string()),
            topic: Some("osint".to_string()),
            user: Some("extiop".to_string()),
            org: Some("acme".to_string()),
        };
        qualifiers
            .validate()
            .expect("every documented shape must validate");
    }

    #[test]
    fn validate_accepts_year_and_month_date_granularities_and_open_ranges() {
        for value in [
            ">=2020",
            "2020-01",
            "2020-01-15",
            "2019-01-01..*",
            "*..2024",
            "2020-02-29",
            "2000-02-29",
            "2019-01-01..2020-12-31",
        ] {
            let qualifiers = SearchQualifiers {
                created: Some(value.to_string()),
                ..SearchQualifiers::default()
            };
            qualifiers
                .validate()
                .unwrap_or_else(|err| panic!("{value} must validate: {err}"));
        }
    }

    #[test]
    fn validate_accepts_an_empty_qualifier_set() {
        SearchQualifiers::default()
            .validate()
            .expect("no qualifier must always validate");
    }

    #[test]
    fn validate_rejects_malformed_count_ranges() {
        for value in ["abc", ">", "..50", "10..", "1..2..3", ">10..50"] {
            let qualifiers = SearchQualifiers {
                stars: Some(value.to_string()),
                ..SearchQualifiers::default()
            };
            let error = qualifiers
                .validate()
                .expect_err("a malformed count range must be rejected");
            assert!(
                matches!(&error, Error::InvalidSearchQualifier(details) if details.contains("stars")),
                "wrong error for {value:?}: {error}"
            );
        }
    }

    #[test]
    fn validate_rejects_impossible_dates() {
        for value in [
            "2020-13-01",
            "2020-00-01",
            "2020-01-32",
            "20200101",
            "abc",
            ">>",
            ">2020-01-01..2021-01-01",
            ">=2020..*",
            "2020-02-30",
            "2021-04-31",
            "2019-02-29",
        ] {
            let qualifiers = SearchQualifiers {
                pushed: Some(value.to_string()),
                ..SearchQualifiers::default()
            };
            let error = qualifiers
                .validate()
                .expect_err("an impossible date must be rejected");
            assert!(
                matches!(&error, Error::InvalidSearchQualifier(details) if details.contains("pushed")),
                "wrong error for {value:?}: {error}"
            );
        }
    }

    #[test]
    fn validate_rejects_names_with_forbidden_characters() {
        for (name, value) in [
            ("license", "MIT OR Apache"),
            ("topic", "osint;drop"),
            ("user", "a b"),
            ("org", "acme/co"),
        ] {
            let qualifiers = SearchQualifiers {
                license: (name == "license").then(|| value.to_string()),
                topic: (name == "topic").then(|| value.to_string()),
                user: (name == "user").then(|| value.to_string()),
                org: (name == "org").then(|| value.to_string()),
                ..SearchQualifiers::default()
            };
            let error = qualifiers
                .validate()
                .expect_err("a name with forbidden characters must be rejected");
            assert!(
                matches!(&error, Error::InvalidSearchQualifier(details) if details.contains(name)),
                "wrong error for {name}={value:?}: {error}"
            );
        }
    }

    #[test]
    fn percent_encode_keeps_unreserved_bytes_and_escapes_the_rest() {
        assert_eq!(percent_encode("nmap"), "nmap");
        assert_eq!(percent_encode("rust & go"), "rust%20%26%20go");
        assert_eq!(percent_encode("C++"), "C%2B%2B");
        assert_eq!(percent_encode("#tag"), "%23tag");
        assert_eq!(percent_encode("a-_.~z"), "a-_.~z");
    }

    #[test]
    fn parse_search_page_extracts_items_html_urls_and_languages() {
        let json: Value = serde_json::json!({
            "total_count": 2,
            "items": [
                { "html_url": "https://github.com/a/one", "language": "Rust" },
                { "html_url": "https://github.com/b/two" }
            ]
        });
        let (hits, raw_count) = parse_search_page(&json).expect("parsing must succeed");
        assert_eq!(
            hits,
            vec![
                SearchHit {
                    url: "https://github.com/a/one".to_string(),
                    language: Some("Rust".to_string()),
                },
                SearchHit {
                    url: "https://github.com/b/two".to_string(),
                    language: None,
                },
            ]
        );
        assert_eq!(raw_count, 2);
    }

    #[test]
    fn parse_search_page_rejected_search_ends_the_listing() {
        // GitHub returns {"items": null} for a rejected search: parsed as an
        // empty page, it ends the listing instead of erroring
        let json: Value = serde_json::json!({ "items": null });
        let (hits, raw_count) = parse_search_page(&json).expect("parsing must succeed");
        assert!(hits.is_empty());
        assert_eq!(raw_count, 0, "no raw item: the listing ends");
    }

    #[test]
    fn worker_count_is_capped_by_tokens_and_repositories() {
        // one worker per token, but never more than repositories to scan
        assert_eq!(worker_count(3, 5), 3);
        assert_eq!(worker_count(5, 2), 2);
        // an anonymous scan runs a single worker on the shared quota
        assert_eq!(worker_count(0, 5), 1);
        assert_eq!(worker_count(0, 0), 0);
    }

    #[test]
    fn the_composed_qualifiers_reach_the_wire_and_the_limit_stops_the_listing() {
        // same composition as aggregate_search's listing stage, against a
        // mock server so no real GitHub call is ever made
        let qualifiers = SearchQualifiers {
            stars: Some(">100".to_string()),
            license: Some("mit".to_string()),
            ..SearchQualifiers::default()
        };
        let q = search_q("nmap", "Rust", &qualifiers);
        let requests: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&requests);
        let (address, server) = mock::serve_requests(move |index, request| {
            if let Some(request_line) = request.first()
                && let Ok(mut requests) = recorded.lock()
            {
                requests.push(request_line.clone());
            }
            let body = match index {
                0 => r#"{"total_count": 3, "items": [{"html_url": "https://github.com/a/one"}, {"html_url": "https://github.com/b/two"}]}"#,
                1 => r#"{"total_count": 3, "items": [{"html_url": "https://github.com/c/three"}]}"#,
                _ => r#"{"total_count": 3, "items": null}"#,
            }
            .to_string();
            (200, vec![], body)
        });

        let client = crate::github::Client::anonymous().expect("client must build");
        let hits: Vec<SearchHit> = fetch_paginated(
            &client,
            |page| format!("{address}/search/repositories?q={q}&per_page={PER_PAGE}&page={page}"),
            parse_search_page,
            Some(3),
        )
        .expect("the listing must succeed");

        // --limit 3: two content pages (2 + 1 items) were enough, no third
        // page was requested to be thrown away
        assert_eq!(hits.len(), 3);
        let requests = requests.lock().expect("request log must lock");
        assert_eq!(requests.len(), 2, "the limit must stop the listing early");
        assert!(
            requests[0].contains("q=nmap+language:Rust+stars:%3E100+license:mit"),
            "the composed qualifiers must reach the wire percent-encoded: {}",
            requests[0]
        );
        assert!(
            requests[1].contains("page=2"),
            "pages must be walked in order"
        );
        server.join();
    }

    #[test]
    fn unset_qualifiers_never_reach_the_wire() {
        let q = search_q("nmap", "", &SearchQualifiers::default());
        let requests: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&requests);
        let (address, server) = mock::serve_requests(move |_index, request| {
            if let Some(request_line) = request.first()
                && let Ok(mut requests) = recorded.lock()
            {
                requests.push(request_line.clone());
            }
            (200, vec![], r#"{"items": null}"#.to_string())
        });

        let client = crate::github::Client::anonymous().expect("client must build");
        let hits: Vec<SearchHit> = fetch_paginated(
            &client,
            |page| format!("{address}/search/repositories?q={q}&per_page={PER_PAGE}&page={page}"),
            parse_search_page,
            Some(5),
        )
        .expect("the listing must succeed");

        assert!(hits.is_empty());
        let requests = requests.lock().expect("request log must lock");
        assert!(
            requests[0].contains("q=nmap&per_page=100"),
            "no qualifier must be appended when none is set: {}",
            requests[0]
        );
        assert!(!requests[0].contains("stars:"));
        server.join();
    }

    fn report(emails: &[&str], failure: Option<Error>) -> WorkerReport {
        // token_died mirrors the worker behavior: a rate-limited dedicated
        // token is the canonical "this worker's token died" failure
        let token_died = matches!(failure, Some(Error::RateLimitExhausted));
        WorkerReport {
            emails: emails.iter().map(|email| email.to_string()).collect(),
            requests: 1,
            repos_scanned: 0,
            contributions: Vec::new(),
            failure,
            token_died,
        }
    }

    fn progressed_report(emails: &[&str], repos: usize, failure: Option<Error>) -> WorkerReport {
        let token_died = failure.is_some();
        WorkerReport {
            emails: emails.iter().map(|email| email.to_string()).collect(),
            requests: 1,
            repos_scanned: repos,
            contributions: Vec::new(),
            failure,
            token_died,
        }
    }

    #[test]
    fn a_rate_limited_worker_does_not_discard_the_other_workers_emails() {
        let reports = vec![
            report(&["a@a.a"], Some(Error::RateLimitExhausted)),
            report(&["b@b.b"], None),
            report(&[], None),
        ];
        let (result, requests, ..) = reduce_worker_reports(reports);
        // the drained token fails one worker, but the scan keeps its emails
        let emails = result.expect("the scan must not fail");
        assert_eq!(emails.len(), 2);
        assert_eq!(requests, 3);
    }

    #[test]
    fn a_rate_limit_without_any_progress_fails_the_scan() {
        // single anonymous worker, or every token spent before scanning
        // anything: nothing to return
        let reports = vec![report(&["a@a.a"], Some(Error::RateLimitExhausted))];
        let (result, ..) = reduce_worker_reports(reports);
        assert!(matches!(result, Err(Error::RateLimitExhausted)));
    }

    #[test]
    fn a_complete_result_survives_every_worker_token_dying() {
        // quota died on each worker's final request: the queue was fully
        // drained, so the collected emails must not be thrown away
        let reports = vec![
            progressed_report(&["a@a.a"], 3, Some(Error::RateLimitExhausted)),
            progressed_report(&["b@b.b"], 2, Some(Error::RateLimitExhausted)),
        ];
        let (result, requests, ..) = reduce_worker_reports(reports);
        let emails = result.expect("a complete result must be kept");
        assert_eq!(emails.len(), 2);
        assert_eq!(requests, 2);
    }

    #[test]
    fn a_rejected_token_does_not_abort_the_workers_that_made_progress() {
        // a token death on a dedicated token (spent quota here; an HTTP 401
        // rejection is reported the same way) stops only its worker: the
        // healthy workers' partial result is kept
        let reports = vec![
            progressed_report(&["a@a.a"], 1, Some(Error::RateLimitExhausted)),
            report(&["b@b.b"], None),
        ];
        let (result, ..) = reduce_worker_reports(reports);
        let emails = result.expect("the healthy workers' emails must be kept");
        assert_eq!(emails.len(), 2);
    }

    #[test]
    fn a_resource_scoped_failure_is_skipped_not_treated_as_a_dead_token() {
        // a 403 (private repository, token without the right scope) and a
        // 404 (stale search-index entry) are scoped to the repository, not
        // to the token: the worker skips them and keeps pulling work
        assert!(matches!(
            classify_failure(&Error::PrivateOrUnavailable),
            FailureAction::SkipRepository
        ));
        assert!(matches!(
            classify_failure(&Error::PrivateOrUnavailable),
            FailureAction::SkipRepository
        ));
        assert!(matches!(
            classify_failure(&Error::NotFound),
            FailureAction::SkipRepository
        ));
        assert!(matches!(
            classify_failure(&Error::NotFound),
            FailureAction::SkipRepository
        ));
    }

    #[test]
    fn classify_failure_stops_the_worker_only_on_real_token_deaths() {
        // a spent quota stops the worker; so does a token the API rejected
        // outright (HTTP 401, surfaced as the dedicated `Error::TokenRejected`)
        assert!(matches!(
            classify_failure(&Error::RateLimitExhausted),
            FailureAction::TokenDied
        ));
        assert!(
            matches!(
                classify_failure(&Error::TokenRejected),
                FailureAction::TokenDied
            ),
            "a rejected token dies alone, it must not abort the scan"
        );
        // any unexpected failure aborts the whole scan
        assert!(matches!(
            classify_failure(&Error::InvalidUrl("nope".to_string())),
            FailureAction::AbortScan
        ));
        assert!(matches!(
            classify_failure(&Error::WorkerFailed("did not report".to_string())),
            FailureAction::AbortScan
        ));
    }

    #[test]
    fn a_non_rate_limit_failure_fails_the_scan() {
        let reports = vec![
            report(&["a@a.a"], Some(Error::RateLimitExhausted)),
            report(&["b@b.b"], Some(Error::InvalidUrl("nope".to_string()))),
            report(&[], None),
        ];
        let (result, ..) = reduce_worker_reports(reports);
        // a failure other than a drained token aborts the scan: the first
        // reported failure wins, so the scan errors out either way
        assert!(matches!(
            result,
            Err(Error::RateLimitExhausted | Error::InvalidUrl(_))
        ));
    }

    #[test]
    fn reduce_worker_reports_sums_the_repositories_actually_scanned() {
        // the JSON report must not overstate coverage: skipped or
        // unscanned repositories are not counted
        let reports = vec![
            progressed_report(&["a@a.a"], 2, None),
            progressed_report(&["b@b.b"], 1, Some(Error::RateLimitExhausted)),
            report(&[], None),
        ];
        let (result, _, repos_scanned, _) = reduce_worker_reports(reports);
        result.expect("the scan must not fail");
        assert_eq!(repos_scanned, 3);
    }
}

#[cfg(test)]
mod correlation_tests {
    // Tests may unwrap, expect and panic freely: a failing assertion must
    // be loud, so the zero-panic lints do not apply to the test modules.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::correlate::CommitAuthor;

    /// Builds a worker report carrying one scanned repository's contribution.
    fn contribution_report(
        emails: &[&str],
        repo: &str,
        language: Option<&str>,
        authors: &[(&str, &str, usize)],
    ) -> WorkerReport {
        WorkerReport {
            emails: emails.iter().map(|email| email.to_string()).collect(),
            requests: 1,
            repos_scanned: 1,
            contributions: vec![RepoContribution {
                name: repo.to_string(),
                language: language.map(str::to_string),
                authors: authors
                    .iter()
                    .map(|(name, email, hits)| CommitAuthor {
                        name: (*name).to_string(),
                        email: (*email).to_string(),
                        hits: *hits,
                    })
                    .collect(),
            }],
            failure: None,
            token_died: false,
        }
    }

    #[test]
    fn reduce_worker_reports_aggregates_the_contributions_across_workers() {
        // two workers, each scanning one repository where the same author
        // appears with the same email and different primary languages
        let reports = vec![
            contribution_report(
                &["alice@x.com"],
                "a/one",
                Some("Rust"),
                &[("Alice", "alice@x.com", 2)],
            ),
            contribution_report(
                &["alice@x.com", "bob@y.y"],
                "b/two",
                Some("Go"),
                &[("Alice", "alice@x.com", 1), ("Bob", "bob@y.y", 1)],
            ),
        ];

        let (result, requests, repos_scanned, correlation) = reduce_worker_reports(reports);
        let emails = result.expect("the scan must not fail");
        assert_eq!(
            emails,
            vec!["alice@x.com".to_string(), "bob@y.y".to_string()]
        );
        assert_eq!(requests, 2);
        assert_eq!(repos_scanned, 2);

        // the same author seen by two different workers is merged: emails
        // deduplicated, hits summed, both languages kept dominant first
        assert_eq!(correlation.authors.len(), 2);
        let alice = &correlation.authors[0];
        assert_eq!(alice.author, "Alice");
        assert_eq!(alice.total_hits, 3);
        assert_eq!(alice.emails, vec!["alice@x.com".to_string()]);
        assert_eq!(alice.languages, vec!["Rust".to_string(), "Go".to_string()]);
        assert_eq!(correlation.authors[1].author, "Bob");
    }

    #[test]
    fn a_worker_whose_token_died_still_keeps_its_contributions() {
        // a dead dedicated token does not throw away the contributions of the
        // repositories its worker already scanned
        let mut report = contribution_report(
            &["alice@x.com"],
            "a/one",
            Some("Rust"),
            &[("Alice", "alice@x.com", 1)],
        );
        report.failure = Some(Error::RateLimitExhausted);
        report.token_died = true;

        let (result, _, _, correlation) = reduce_worker_reports(vec![report, {
            contribution_report(&["bob@y.y"], "b/two", Some("Go"), &[("Bob", "bob@y.y", 1)])
        }]);

        result.expect("a token death with progress keeps the scan result");
        assert_eq!(correlation.authors.len(), 2);
        assert_eq!(correlation.authors[0].first_seen_repo, "a/one");
        assert_eq!(correlation.authors[1].first_seen_repo, "b/two");
    }
}
