//! Search scan: the repositories matching a query, scanned in parallel.

use crate::errors::Error;
use crate::github::fetch_paginated;
use crate::parsers;
use crate::sources::{PER_PAGE, ScanOutcome, Scanner, merge_emails, sort_emails};
use serde_json::Value;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};

/// Get repositories according to a user request made with metadata
/// (`query` + optional `language`, up to `limit` repositories).
///
/// For each found repository, it scans it and gets its developers emails,
/// then deduplicates and sorts the concatenated result.
pub(crate) fn aggregate_search(
    scanner: &Scanner,
    query: &str,
    language: &str,
    limit: usize,
) -> Result<ScanOutcome, Error> {
    // stop fetching as soon as the user limit is reached: the next pages
    // would only be requested to be thrown away
    let repositories: Vec<String> = fetch_paginated(
        scanner.client(),
        |page| search_url(query, language, page),
        parse_search_page,
        Some(limit),
    )?;

    let (mut found_emails, repos_scanned) = scanner.scan_repositories(&repositories)?;
    sort_emails(&mut found_emails);

    Ok(ScanOutcome {
        emails: found_emails,
        repos_scanned,
    })
}

/// Builds the search endpoint URL for `page`. The user-supplied query and
/// language are percent-encoded: a raw `&`, `#`, `+` or space would be
/// split, truncated or rewritten server-side instead of being part of the
/// query.
fn search_url(query: &str, language: &str, page: u16) -> String {
    let mut q = percent_encode(query);
    if !language.is_empty() {
        q.push_str("+language:");
        q.push_str(&percent_encode(language));
    }
    format!("https://api.github.com/search/repositories?q={q}&per_page={PER_PAGE}&page={page}")
}

/// Extracts the `html_url` of every repository of a search page (`items`),
/// together with the raw number of items the page held: the raw count is the
/// end-of-listing signal of `fetch_paginated`. A rejected search
/// (`{"items": null}`) holds no raw item and ends the listing.
fn parse_search_page(json: &Value) -> Result<(Vec<String>, usize), Error> {
    let Some(items) = json.get("items").and_then(Value::as_array) else {
        return Ok((Vec::new(), 0));
    };
    let repositories = items
        .iter()
        .filter_map(|item| item.get("html_url").and_then(Value::as_str))
        .map(str::to_string)
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
    /// Returns the emails found (deduplicated) and the number of
    /// repositories actually scanned, for the JSON report.
    pub(crate) fn scan_repositories(
        &self,
        repositories: &[String],
    ) -> Result<(Vec<String>, usize), Error> {
        if repositories.is_empty() {
            return Ok((Vec::new(), 0));
        }
        let workers = worker_count(self.client.tokens().len(), repositories.len());

        // work queue: every repository URL is sent once, then the sender is
        // dropped, so `recv` returns `Err` once the queue is drained — the
        // workers' natural stop signal
        let (work_tx, work_rx) = mpsc::channel::<String>();
        for repository_url in repositories {
            if work_tx.send(repository_url.clone()).is_err() {
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
                    failure: Some(Error::WorkerFailed(
                        "scan worker did not report".to_string(),
                    )),
                    token_died: false,
                })
            })
            .collect();
        let (result, worker_requests, repos_scanned) = reduce_worker_reports(reports);
        self.add_worker_requests(worker_requests);
        result.map(|emails| (emails, repos_scanned))
    }

    /// Worker body: owns one dedicated token through its own
    /// client, pulls the next repository from the shared `mpsc` work queue
    /// and scans it, until the queue is drained or another worker failed.
    /// Returns everything it found, how many successful requests its client
    /// made and, when it hit one, the failure that ended it.
    fn scan_worker_queue(
        dedicated_token: Option<&str>,
        work_rx: &Arc<Mutex<mpsc::Receiver<String>>>,
        aborted: &AtomicBool,
    ) -> WorkerReport {
        let client = match Self::worker_client(dedicated_token) {
            Ok(client) => client,
            Err(err) => {
                return WorkerReport {
                    emails: Vec::new(),
                    requests: 0,
                    repos_scanned: 0,
                    failure: Some(err),
                    token_died: false,
                };
            }
        };
        let mut found_emails: Vec<String> = Vec::new();
        let mut repos_scanned = 0usize;

        loop {
            // stop pulling work as soon as any worker failed fatally: the
            // scan is going to error out anyway
            if aborted.load(Ordering::Relaxed) {
                break;
            }
            // the mutex only guards pulling one URL off the channel; the
            // queue is fully populated upfront, so `recv` never blocks long
            let repository_url = {
                let Ok(receiver) = work_rx.lock() else {
                    break; // poisoned queue: stop pulling work
                };
                receiver.recv().ok() // `None` once the queue is drained
            };
            let Some(repository_url) = repository_url else {
                break; // the shared queue is empty: this worker is done
            };
            // keep the URL around for the skip warning: the parser helpers
            // take it by value
            let author = match parsers::get_author(repository_url.clone()) {
                Ok(author) => author,
                Err(err) => {
                    aborted.store(true, Ordering::Relaxed);
                    return Self::worker_report(
                        &client,
                        found_emails,
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
                        repos_scanned,
                        Some(err),
                        false,
                    );
                }
            };
            let emails = match super::repository::scan_repository(&client, &author, &repository) {
                Ok(emails) => emails,
                Err(err) => match classify_failure(&err, dedicated_token.is_some()) {
                    // this worker's dedicated token budget is its own: once
                    // it dies the worker stops pulling work, but the other
                    // workers' tokens keep draining the queue, so the failure
                    // is not fatal and the emails found so far are kept
                    FailureAction::TokenDied => {
                        return Self::worker_report(
                            &client,
                            found_emails,
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
                        log::warn!("skipping repository {repository_url}: {err}");
                        continue;
                    }
                    FailureAction::AbortScan => {
                        aborted.store(true, Ordering::Relaxed);
                        return Self::worker_report(
                            &client,
                            found_emails,
                            repos_scanned,
                            Some(err),
                            false,
                        );
                    }
                },
            };
            merge_emails(&mut found_emails, emails);
            repos_scanned += 1;
        }
        Self::worker_report(&client, found_emails, repos_scanned, None, false)
    }

    /// Bundles what a worker found, how many requests its client made, how
    /// many repositories it fully scanned and the failure that ended it (if
    /// any) into its final report.
    fn worker_report(
        client: &crate::github::Client,
        emails: Vec<String>,
        repos_scanned: usize,
        failure: Option<Error>,
        token_died: bool,
    ) -> WorkerReport {
        WorkerReport {
            emails,
            requests: client.requests_made(),
            repos_scanned,
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
fn classify_failure(err: &Error, dedicated_token: bool) -> FailureAction {
    match err {
        Error::RateLimitExhausted => FailureAction::TokenDied,
        Error::Http(http)
            if dedicated_token && http.status() == Some(reqwest::StatusCode::UNAUTHORIZED) =>
        {
            FailureAction::TokenDied
        }
        Error::NotFound | Error::PrivateOrUnavailable => FailureAction::SkipRepository,
        _ => FailureAction::AbortScan,
    }
}

/// What one scan worker reports back: the emails it found, how many
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
    failure: Option<Error>,
    /// Whether the failure ended the worker because its own dedicated token
    /// died (spent quota or rejected token) rather than a scan-wide error:
    /// the other workers' tokens can keep draining the queue.
    token_died: bool,
}

/// Reduces the workers' reports into the scan result, the total number of
/// successful requests they made and the total number of repositories they
/// actually scanned (the JSON report must not overstate coverage by counting
/// repositories that were skipped or never pulled).
///
/// A worker whose dedicated token died ([`Error::RateLimitExhausted`], or a
/// rejected token) does not fail the scan: the other workers' tokens keep
/// draining the queue and the emails found so far are returned (possibly
/// partial). Any other failure aborts the scan, as does a token death with
/// no worker left having made any progress (single anonymous worker, or
/// every token dead before scanning anything).
fn reduce_worker_reports(reports: Vec<WorkerReport>) -> (Result<Vec<String>, Error>, usize, usize) {
    let mut found_emails: Vec<String> = Vec::new();
    let mut requests = 0usize;
    let mut repos_scanned = 0usize;
    let mut failure: Option<Error> = None;
    let mut only_token_deaths = true;
    let mut any_progress = false;
    for report in reports {
        merge_emails(&mut found_emails, report.emails);
        requests += report.requests;
        repos_scanned += report.repos_scanned;
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
    (result, requests, repos_scanned)
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

    #[test]
    fn search_url_percent_encodes_query_and_language() {
        assert_eq!(
            search_url("rust & go #1", "C++", 2),
            "https://api.github.com/search/repositories?q=rust%20%26%20go%20%231+language:C%2B%2B&per_page=100&page=2"
        );
    }

    #[test]
    fn search_url_omits_the_language_qualifier_when_absent() {
        assert_eq!(
            search_url("nmap", "", 1),
            "https://api.github.com/search/repositories?q=nmap&per_page=100&page=1"
        );
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
    fn parse_search_page_extracts_items_html_urls() {
        let json: Value = serde_json::json!({
            "total_count": 2,
            "items": [
                { "html_url": "https://github.com/a/one" },
                { "html_url": "https://github.com/b/two" }
            ]
        });
        let repositories = parse_search_page(&json).expect("parsing must succeed");
        assert_eq!(
            repositories.0,
            vec![
                "https://github.com/a/one".to_string(),
                "https://github.com/b/two".to_string()
            ]
        );
        assert_eq!(repositories.1, 2);
    }

    #[test]
    fn parse_search_page_rejected_search_ends_the_listing() {
        // GitHub returns {"items": null} for a rejected search: parsed as an
        // empty page, it ends the listing instead of erroring
        let json: Value = serde_json::json!({ "items": null });
        let repositories = parse_search_page(&json).expect("parsing must succeed");
        assert!(repositories.0.is_empty());
        assert_eq!(repositories.1, 0, "no raw item: the listing ends");
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

    fn report(emails: &[&str], failure: Option<Error>) -> WorkerReport {
        // token_died mirrors the worker behavior: a rate-limited dedicated
        // token is the canonical "this worker's token died" failure
        let token_died = matches!(failure, Some(Error::RateLimitExhausted));
        WorkerReport {
            emails: emails.iter().map(|email| email.to_string()).collect(),
            requests: 1,
            repos_scanned: 0,
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
        let (result, requests, _) = reduce_worker_reports(reports);
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
        let (result, _, _) = reduce_worker_reports(reports);
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
        let (result, requests, _) = reduce_worker_reports(reports);
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
        let (result, _, _) = reduce_worker_reports(reports);
        let emails = result.expect("the healthy workers' emails must be kept");
        assert_eq!(emails.len(), 2);
    }

    #[test]
    fn a_resource_scoped_failure_is_skipped_not_treated_as_a_dead_token() {
        // a 403 (private repository, token without the right scope) and a
        // 404 (stale search-index entry) are scoped to the repository, not
        // to the token: the worker skips them and keeps pulling work
        assert!(matches!(
            classify_failure(&Error::PrivateOrUnavailable, true),
            FailureAction::SkipRepository
        ));
        assert!(matches!(
            classify_failure(&Error::PrivateOrUnavailable, false),
            FailureAction::SkipRepository
        ));
        assert!(matches!(
            classify_failure(&Error::NotFound, true),
            FailureAction::SkipRepository
        ));
        assert!(matches!(
            classify_failure(&Error::NotFound, false),
            FailureAction::SkipRepository
        ));
    }

    #[test]
    fn classify_failure_stops_the_worker_only_on_real_token_deaths() {
        // a spent quota stops the worker, dedicated token or not
        assert!(matches!(
            classify_failure(&Error::RateLimitExhausted, true),
            FailureAction::TokenDied
        ));
        assert!(matches!(
            classify_failure(&Error::RateLimitExhausted, false),
            FailureAction::TokenDied
        ));
        // any unexpected failure aborts the whole scan
        assert!(matches!(
            classify_failure(&Error::InvalidUrl("nope".to_string()), true),
            FailureAction::AbortScan
        ));
        assert!(matches!(
            classify_failure(&Error::WorkerFailed("did not report".to_string()), false),
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
        let (result, _, _) = reduce_worker_reports(reports);
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
        let (result, _, repos_scanned) = reduce_worker_reports(reports);
        result.expect("the scan must not fail");
        assert_eq!(repos_scanned, 3);
    }
}
