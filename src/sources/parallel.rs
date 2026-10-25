//! The parallel repository scan: the token-dedicated worker pool shared by
//! the keyword search, the `org` investigation and the reverse-email
//! candidates (one worker per live token, one dedicated
//! [`crate::github::Client`] per worker, a shared `std::sync::mpsc` work
//! queue). The reduction folds the workers' reports into one
//! [`ParallelScanResult`], with the honest partial semantics: a scan that
//! kept its findings although a dedicated token died reports `partial`,
//! never a complete-looking result.

use crate::correlate::{Correlation, CorrelationBuilder, RepoContribution, RepoScan};
use crate::errors::Error;
use crate::parsers;
use crate::sanitize::log_safe;
use crate::sources::{EmailList, Scanner, sort_emails};
use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;

/// What a parallel repository scan returns: the deduplicated emails found,
/// the emails found per repository (`owner/name` full name → sorted
/// emails, only the repositories where at least one email showed up), the
/// number of repositories actually scanned, the per-author correlation
/// report and the partial-token-death flag: `true` when the scan
/// returned its result although a dedicated token died with progress, so
/// whole repositories may have been left unscanned (`false` when the
/// surviving workers covered every listed repository). Callers with a
/// complete-report contract (the `org` investigation) use the flag to abort
/// instead of silently missing repositories.
#[derive(Debug)]
pub(crate) struct ParallelScanResult {
    /// The deduplicated emails found across the scanned repositories.
    pub(crate) emails: Vec<String>,
    /// The emails found per repository, keyed by the `owner/name` full name
    /// the scan reports; only repositories where at least one email showed
    /// up are listed.
    pub(crate) per_repository: BTreeMap<String, Vec<String>>,
    /// The number of repositories actually scanned.
    pub(crate) repos_scanned: usize,
    /// The per-author correlation report.
    pub(crate) correlation: Correlation,
    /// The partial-token-death flag (see the type documentation).
    pub(crate) partial: bool,
    /// The real death error behind the partial flag (a token death, not
    /// necessarily a spent allowance): callers re-raising the flag abort
    /// with this cause instead of a misattributed rate-limit error.
    pub(crate) death_error: Option<Error>,
}

pub(crate) type ParallelScan = Result<ParallelScanResult, Error>;

/// What [`reduce_worker_reports`] folds the workers' reports into: the scan
/// result ([`ParallelScanResult`]'s fields) plus the total number of
/// successful worker requests, reported in the JSON output, and the
/// partial-token-death flag (see [`ParallelScanResult`]).
pub(crate) struct ReducedReports {
    /// `Ok` when the scan produced a (possibly partial) result, `Err` when
    /// it aborted.
    result: Result<Vec<String>, Error>,
    per_repository: BTreeMap<String, Vec<String>>,
    worker_requests: usize,
    repos_scanned: usize,
    skipped: usize,
    correlation: Correlation,
    partial: bool,
    death_error: Option<Error>,
}

/// One repository candidate handed to the parallel scan (a search
/// listing entry, an org listing entry or a reverse-lookup candidate): its
/// `html_url` plus the
/// primary language GitHub reports for it — free correlation metadata,
/// no extra API call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RepoHit {
    pub(crate) url: String,
    pub(crate) language: Option<String>,
}

impl Scanner {
    /// Scans the given repositories in parallel against one API
    /// base URL: the production callers pass `https://api.github.com`, and
    /// the offline tests run this same code against a loopback mock. A pool
    /// of `min(nb_tokens, nb_repositories)` workers (`std::thread::scope`),
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
    /// repository or a token without the right scope, 409 of an empty
    /// repository) is skipped with a warning and does not stop the worker:
    /// the failure is resource-scoped, the token stays valid for the
    /// remaining repositories. Any other worker error aborts the whole scan,
    /// as the sequential scan did.
    ///
    /// # Errors
    ///
    /// A scan-wide failure aborts the scan, while a dead dedicated token
    /// alone does not (the parallel scan keeps the emails found so far).
    /// `skip_transient` decides how a transport-level failure (a connection
    /// refused or dropped, a timeout) is classified: `true` skips the one
    /// repository with a warning (the search fan-out keeps going over a
    /// network hiccup), `false` aborts the scan (the complete-report
    /// contracts — `org` — can never silently miss a whole repository).
    pub(crate) fn scan_repositories_at(
        &self,
        base: &str,
        repositories: &[RepoHit],
        skip_transient: bool,
    ) -> ParallelScan {
        if repositories.is_empty() {
            return Ok(ParallelScanResult {
                emails: Vec::new(),
                per_repository: BTreeMap::new(),
                repos_scanned: 0,
                correlation: Correlation::default(),
                partial: false,
                death_error: None,
            });
        }
        let tokens = self.client.tokens();
        // Each worker is dedicated the next *live* token when any token is
        // live (see [`TokenPool::live_indices`]): a token the listing phase
        // retired or parked must not own a worker slot while healthy tokens
        // sit beyond the worker range — with fewer listed repositories than
        // tokens, every spawned worker could otherwise own a dead token and
        // abort the whole scan without a single request. When every token is
        // dead (or the pool is anonymous) the positional assignment is kept:
        // the all-dead fallback still spawns the documented worker count so
        // the reduction fails loudly with [`Error::RateLimitExhausted`]
        // instead of silently reporting an empty scan, and the anonymous
        // pool (no tokens at all) keeps its single shared-quota worker.
        // The live-token assignment, the spawn-failure degradation and the
        // exactly-one-report-per-worker collection live in the shared
        // [`crate::github::pool`] runner.
        let reports: Vec<ScanWorkerReport> = crate::github::pool::run_token_worker_pool(
            tokens,
            repositories.iter().cloned(),
            |cause| ScanWorkerReport::failed(Error::WorkerFailed(cause.to_string())),
            |work_rx, aborted, dedicated_token, start_dead| {
                Self::scan_worker_queue(
                    dedicated_token,
                    base,
                    work_rx,
                    aborted,
                    start_dead,
                    skip_transient,
                )
            },
        );
        let reduced = reduce_worker_reports(reports);
        self.add_worker_requests(reduced.worker_requests);
        // the partial flag's documented meaning is "whole listed repositories
        // may have been left unscanned" (`scanned.partial` in the JSON
        // report): when the surviving workers fully drained the queue —
        // every listed repository was scanned or warn-skipped — the token
        // death lost no repository, and a complete report must not carry a
        // false truncation alarm. The judgment is made here where the
        // listing size is known (the reducers do not see it); the `org`
        // caller aborts on any token death instead of judging coverage
        let partial =
            reduced.partial && reduced.repos_scanned + reduced.skipped < repositories.len();
        reduced.result.map(|emails| ParallelScanResult {
            emails,
            per_repository: reduced.per_repository,
            repos_scanned: reduced.repos_scanned,
            correlation: reduced.correlation,
            partial,
            death_error: reduced.death_error,
        })
    }

    /// Worker body: owns one dedicated token through its own
    /// client, pulls the next repository from the shared `mpsc` work queue
    /// and scans it, until the queue is drained or another worker failed.
    /// Returns everything it found, the per-author contributions of the
    /// repositories it scanned, how many successful requests its
    /// client made and, when it hit one, the failure that ended it.
    fn scan_worker_queue(
        dedicated_token: Option<&str>,
        base: &str,
        work_rx: &Mutex<mpsc::Receiver<RepoHit>>,
        aborted: &AtomicBool,
        start_dead: bool,
        skip_transient: bool,
    ) -> ScanWorkerReport {
        let client = match Self::worker_client(dedicated_token) {
            Ok(client) => client,
            Err(err) => {
                return ScanWorkerReport::failed(err);
            }
        };
        if start_dead {
            // the dedicated token was already unusable when the worker
            // spawned: report the death without pulling a repository, so the
            // other workers cover the whole queue instead of one repository
            // being lost to a doomed request
            return WorkerAccum::default().finish(&client, Some(Error::RateLimitExhausted), true);
        }
        let mut accum = WorkerAccum::default();

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
            // a listing-derived URL the parsers reject (a hostile or
            // truncated entry) is scoped to this entry: skip it with a
            // warning like any resource-scoped failure, never abort the
            // whole scan for one malformed listing line (the same
            // warn-and-count rule the org listing applies to its entries;
            // transport and scan failures below still abort)
            // one parse for both parts: a listing-derived URL the parsers
            // reject (a hostile or truncated entry) is scoped to this entry
            let (author, repository) = match parsers::parse_github_url(&repository_url) {
                Ok(parts) => parts,
                Err(err) => {
                    log::warn!(
                        "skipping repository {}: {}",
                        log_safe(&repository_url),
                        log_safe(&err.to_string())
                    );
                    accum.skipped += 1;
                    continue;
                }
            };
            // a profile-shaped listing entry carries no repository: skip it
            // like any malformed listing line (a scan cannot scan a profile)
            let repository = match repository {
                Some(repository) => repository,
                None => {
                    log::warn!(
                        "skipping repository {}: it carries no repository part",
                        log_safe(&repository_url)
                    );
                    accum.skipped += 1;
                    continue;
                }
            };
            let scan = match super::repository::scan_repository(&client, base, &author, &repository)
            {
                Ok(scan) => scan,
                Err(err) => match classify_failure(&err, skip_transient) {
                    // this worker's dedicated token budget is its own: once
                    // it dies the worker stops pulling work, but the other
                    // workers' tokens keep draining the queue, so the failure
                    // is not fatal and the emails found so far are kept
                    FailureAction::TokenDied => {
                        return accum.finish(&client, Some(err), true);
                    }
                    // the failure is scoped to this repository (deleted,
                    // private, token without the right scope): skip it like
                    // the profile fallback does, the token stays valid for
                    // the remaining repositories. The skip is counted so a
                    // caller with a complete-report contract can tell a
                    // covered repository from one that was never scanned
                    FailureAction::SkipRepository => {
                        // the URL and the error text are API-derived: they
                        // are sanitized like every other log site, so a
                        // hostile payload can never forge or recolor a log
                        // line
                        log::warn!(
                            "skipping repository {}: {}",
                            log_safe(&repository_url),
                            log_safe(&err.to_string())
                        );
                        accum.skipped += 1;
                        continue;
                    }
                    FailureAction::AbortScan => {
                        aborted.store(true, Ordering::Relaxed);
                        return accum.finish(&client, Some(err), false);
                    }
                },
            };
            accum.absorb(scan, &author, &repository, hit.language);
        }
        accum.finish(&client, None, false)
    }

    /// Builds the client a worker exclusively owns for its dedicated token
    /// (single-token pool, no shared state); an anonymous scan (no token)
    /// runs one worker on the shared anonymous quota.
    pub(crate) fn worker_client(
        dedicated_token: Option<&str>,
    ) -> Result<crate::github::Client, Error> {
        match dedicated_token {
            Some(token) => crate::github::Client::new(crate::github::TokenPool::from_token(token)?),
            None => crate::github::Client::anonymous(),
        }
    }
}

/// What a scan worker must do when scanning one repository fails.
pub(crate) enum FailureAction {
    /// The worker's token died (spent quota, or the token rejected by the
    /// API with nothing to rotate to): stop the worker, keep its findings,
    /// let the other tokens drain the queue.
    TokenDied,
    /// The failure is scoped to this repository only (a 404 of a stale
    /// search-index entry, a 403 for a private repository or a token without
    /// the right scope, or the 409 of an empty repository — GitHub answers
    /// 409 Conflict on `/commits` when the repository has no commits): skip
    /// it and keep pulling work. A 403 is resource-scoped, not token-scoped:
    /// with a fine-grained PAT or one inaccessible repository among the
    /// results, the token stays valid for the remaining repositories.
    SkipRepository,
    /// Unexpected failure: abort the whole scan.
    AbortScan,
}

/// Classifies a repository scan failure. An HTTP 403 maps to
/// [`Error::PrivateOrUnavailable`] and is skipped, not treated as a dead
/// token: only a token-scoped death ([`Error::RateLimitExhausted`],
/// [`Error::RateLimitPaused`], or [`Error::TokenRejected`] — the API refused
/// the token itself; tokens are only format-validated at startup) stops the
/// worker.
pub(crate) fn classify_failure(err: &Error, skip_transient: bool) -> FailureAction {
    match err {
        Error::RateLimitExhausted | Error::RateLimitPaused | Error::TokenRejected => {
            FailureAction::TokenDied
        }
        Error::NotFound | Error::PrivateOrUnavailable | Error::EmptyRepository => {
            FailureAction::SkipRepository
        }
        // A transport-level error (connection refused or dropped, timeout)
        // is transient. For the search fan-out it skips the one repository
        // with a warning: the other workers and the findings already made
        // survive a one-second network hiccup, and the skip is counted and
        // logged. A complete-report caller (`org`) keeps the documented
        // contract instead: a transport failure aborts, so its report can
        // never silently miss whole repositories.
        Error::Http(http)
            if skip_transient
                && http.status().is_none()
                && (http.is_connect() || http.is_timeout() || http.is_request()) =>
        {
            FailureAction::SkipRepository
        }
        _ => FailureAction::AbortScan,
    }
}

/// What one worker accumulated across the repositories it pulled off the
/// shared queue: the merged email list, the per-author contributions, the
/// scan/skip counters.
#[derive(Default)]
pub(crate) struct WorkerAccum {
    emails: EmailList,
    contributions: Vec<RepoContribution>,
    repos_scanned: usize,
    skipped: usize,
}

impl WorkerAccum {
    /// Merges one scanned repository into the accumulation.
    fn absorb(&mut self, scan: RepoScan, author: &str, repository: &str, language: Option<String>) {
        self.emails.merge(scan.emails);
        self.contributions.push(RepoContribution {
            name: format!("{author}/{repository}"),
            language,
            authors: scan.authors,
        });
        self.repos_scanned += 1;
    }

    /// Bundles what a worker found, the per-author contributions of its
    /// scanned repositories, how many requests its client made,
    /// how many repositories it fully scanned, how many it warn-skipped as
    /// resource-scoped and the failure that ended it (if any) into its
    /// final report.
    fn finish(
        self,
        client: &crate::github::Client,
        failure: Option<Error>,
        token_died: bool,
    ) -> ScanWorkerReport {
        ScanWorkerReport::new(
            client,
            self.emails.into_vec(),
            self.contributions,
            self.repos_scanned,
            self.skipped,
            failure,
            token_died,
        )
    }
}

/// What one scan worker reports back: the emails it found, the per-author
/// contributions of the repositories it scanned, how many
/// successful requests its client made, how many repositories it fully
/// scanned, and the failure that ended it (if any) — a worker keeps its
/// partial findings even when it failed.
pub(crate) struct ScanWorkerReport {
    emails: Vec<String>,
    requests: usize,
    /// Repositories this worker fully scanned: even a worker whose token
    /// died mid-scan may have made real progress that must not be thrown
    /// away with its failure.
    repos_scanned: usize,
    /// Repositories this worker warn-skipped as resource-scoped (deleted,
    /// private, token without the right scope, empty): covered work that a
    /// caller with a complete-report contract must count as covered, not as
    /// work never pulled.
    skipped: usize,
    /// The per-author contributions of the scanned repositories.
    contributions: Vec<RepoContribution>,
    failure: Option<Error>,
    /// Whether the failure ended the worker because its own dedicated token
    /// died (spent quota or rejected token) rather than a scan-wide error:
    /// the other workers' tokens can keep draining the queue.
    token_died: bool,
}
impl ScanWorkerReport {
    /// The degradation report of a worker that never scanned anything:
    /// the spawn-refusal closure and the client-build failure both start
    /// from this empty shape (one constructor instead of three re-enumerated
    /// 7-field literals that could drift apart).
    fn failed(failure: Error) -> Self {
        Self {
            emails: Vec::new(),
            requests: 0,
            repos_scanned: 0,
            skipped: 0,
            contributions: Vec::new(),
            failure: Some(failure),
            token_died: false,
        }
    }

    fn new(
        client: &crate::github::Client,
        emails: Vec<String>,
        contributions: Vec<RepoContribution>,
        repos_scanned: usize,
        skipped: usize,
        failure: Option<Error>,
        token_died: bool,
    ) -> Self {
        Self {
            emails,
            requests: client.requests_made(),
            repos_scanned,
            skipped,
            contributions,
            failure,
            token_died,
        }
    }
}

/// Reduces the workers' reports into the scan result, the emails found per
/// repository (derived from the per-repository contributions before they
/// feed the correlation report, which merges authors across repositories),
/// the total number of successful requests they made, the total number of
/// repositories they actually scanned (the JSON report must not overstate
/// coverage by counting repositories that were skipped or never pulled), the
/// total number of repositories they warn-skipped as resource-scoped and the
/// per-author correlation report built from their contributions.
///
/// A worker whose dedicated token died ([`Error::RateLimitExhausted`], or a
/// rejected token) does not fail the scan: the other workers' tokens keep
/// draining the queue and the emails found so far are returned (possibly
/// partial). Any other failure aborts the scan, as does a token death with
/// no worker left having made any progress (single anonymous worker, or
/// every token dead before scanning anything).
pub(crate) fn reduce_worker_reports(reports: Vec<ScanWorkerReport>) -> ReducedReports {
    let mut found_emails = EmailList::new();
    let mut per_repository: BTreeMap<String, Vec<String>> = BTreeMap::new();
    // the O(1) membership mirror of the per-repository lists (same design
    // as the found-emails accumulator: an adversarial search plants many
    // identical author emails across one repository's contributions)
    let mut per_repository_seen: BTreeMap<String, std::collections::HashSet<String>> =
        BTreeMap::new();
    let mut requests = 0usize;
    let mut repos_scanned = 0usize;
    let mut skipped = 0usize;
    let mut correlation = CorrelationBuilder::new();
    let mut failure: Option<Error> = None;
    let mut failure_is_token_death = false;
    let mut only_token_deaths = true;
    let mut any_progress = false;
    let mut partial_token_death = false;
    for report in reports {
        // the per-repository emails are derived from the contributions
        // before the correlation builder consumes them: the correlation
        // merges an author across repositories, which would lose which
        // email was used where
        for contribution in &report.contributions {
            let entry = per_repository.entry(contribution.name.clone()).or_default();
            let seen = per_repository_seen
                .entry(contribution.name.clone())
                .or_default();
            for author in &contribution.authors {
                if seen.insert(author.email.to_lowercase()) {
                    entry.push(author.email.clone());
                }
            }
        }
        found_emails.merge(report.emails);
        requests += report.requests;
        repos_scanned += report.repos_scanned;
        skipped += report.skipped;
        correlation.add_all(report.contributions);
        // a worker that scanned at least one repository made real progress,
        // even if its token died on a later request: its findings must not
        // be discarded with its failure
        any_progress = any_progress || report.repos_scanned > 0 || report.failure.is_none();
        if let Some(err) = report.failure {
            if !report.token_died {
                only_token_deaths = false;
            }
            // first-arrival attribution can misreport the scan-wide cause
            // when a token death and a genuine abort-class failure coexist:
            // a non-token-death failure is the more informative one, so it
            // replaces an already-recorded token death
            if failure.is_none() || (failure_is_token_death && !report.token_died) {
                failure = Some(err);
                failure_is_token_death = report.token_died;
            }
        }
    }
    let mut death_error = None;
    let result = match failure {
        // every failure is a dead dedicated token and at least one worker
        // made progress on its own token: return the (possibly partial)
        // result instead of throwing the work away
        Some(err) if only_token_deaths && any_progress => {
            log::warn!(
                "one token ran out or was refused mid-scan: results may be incomplete. The JSON report marks the run \"scanned.partial\" only when a listed repository was left unscanned"
            );
            partial_token_death = true;
            death_error = Some(err);
            Ok(found_emails.into_vec())
        }
        Some(err) => Err(err),
        None => Ok(found_emails.into_vec()),
    };
    // deterministic order inside every per-repository list, and no noise
    // entry for a repository whose commits held no usable email
    for emails in per_repository.values_mut() {
        sort_emails(emails);
    }
    per_repository.retain(|_, emails| !emails.is_empty());
    ReducedReports {
        result,
        per_repository,
        worker_requests: requests,
        repos_scanned,
        skipped,
        correlation: correlation.finish(),
        partial: partial_token_death,
        death_error,
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
    ) -> ScanWorkerReport {
        ScanWorkerReport {
            emails: emails.iter().map(|email| email.to_string()).collect(),
            requests: 1,
            repos_scanned: 1,
            skipped: 0,
            contributions: vec![RepoContribution {
                name: repo.to_string(),
                language: language.map(str::to_string),
                authors: authors
                    .iter()
                    .map(|(name, email, hits)| CommitAuthor {
                        name: (*name).to_string(),
                        email: (*email).to_string(),
                        hits: *hits,
                        last_commit_date: None,
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

        let reduced = reduce_worker_reports(reports);
        let emails = reduced.result.expect("the scan must not fail");
        assert_eq!(
            emails,
            vec!["alice@x.com".to_string(), "bob@y.y".to_string()]
        );
        assert_eq!(reduced.worker_requests, 2);
        assert_eq!(reduced.repos_scanned, 2);

        // the same author seen by two different workers is merged: emails
        // deduplicated, hits summed, both languages kept dominant first
        assert_eq!(reduced.correlation.authors.len(), 2);
        let alice = &reduced.correlation.authors[0];
        assert_eq!(alice.author, "Alice");
        assert_eq!(alice.total_hits, 3);
        assert_eq!(alice.emails, vec!["alice@x.com".to_string()]);
        assert_eq!(alice.languages, vec!["Rust".to_string(), "Go".to_string()]);
        assert_eq!(reduced.correlation.authors[1].author, "Bob");
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

        let reduced = reduce_worker_reports(vec![report, {
            contribution_report(&["bob@y.y"], "b/two", Some("Go"), &[("Bob", "bob@y.y", 1)])
        }]);

        reduced
            .result
            .expect("a token death with progress keeps the scan result");
        assert_eq!(reduced.correlation.authors.len(), 2);
        assert_eq!(reduced.correlation.authors[0].first_seen_repo, "a/one");
        assert_eq!(reduced.correlation.authors[1].first_seen_repo, "b/two");
    }

    #[test]
    fn reduce_worker_reports_derives_the_emails_found_per_repository() {
        // the per-repository attribution comes from the contributions before
        // the correlation merges the authors across repositories: an author
        // using two emails in two repositories must be reported per repo
        let reports = vec![
            contribution_report(
                &[],
                "a/one",
                Some("Rust"),
                &[("Alice", "alice@x.com", 2), ("Alice", "alice@y.com", 1)],
            ),
            contribution_report(&[], "b/two", None, &[("Bob", "bob@y.y", 1)]),
            // a worker that scanned nothing contributes no repository
            ScanWorkerReport {
                emails: Vec::new(),
                requests: 0,
                repos_scanned: 0,
                skipped: 0,
                contributions: Vec::new(),
                failure: None,
                token_died: false,
            },
        ];

        let reduced = reduce_worker_reports(reports);
        reduced.result.expect("the scan must not fail");
        assert_eq!(
            reduced.per_repository.get("a/one"),
            Some(&vec!["alice@x.com".to_string(), "alice@y.com".to_string()])
        );
        assert_eq!(
            reduced.per_repository.get("b/two"),
            Some(&vec!["bob@y.y".to_string()])
        );
        assert_eq!(reduced.per_repository.len(), 2);
    }
}

#[cfg(test)]
mod tests {
    // Tests may unwrap, expect and panic freely: a failing assertion must
    // be loud, so the zero-panic lints do not apply to the test modules.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn report(emails: &[&str], failure: Option<Error>) -> ScanWorkerReport {
        // token_died mirrors the worker behavior: a rate-limited dedicated
        // token is the canonical "this worker's token died" failure
        let token_died = matches!(failure, Some(Error::RateLimitExhausted));
        ScanWorkerReport {
            emails: emails.iter().map(|email| email.to_string()).collect(),
            requests: 1,
            repos_scanned: 0,
            skipped: 0,
            contributions: Vec::new(),
            failure,
            token_died,
        }
    }

    fn progressed_report(
        emails: &[&str],
        repos: usize,
        failure: Option<Error>,
    ) -> ScanWorkerReport {
        let token_died = failure.is_some();
        ScanWorkerReport {
            emails: emails.iter().map(|email| email.to_string()).collect(),
            requests: 1,
            repos_scanned: repos,
            skipped: 0,
            contributions: Vec::new(),
            failure,
            token_died,
        }
    }

    #[test]
    fn a_rate_limited_worker_does_not_discard_the_other_workers_emails() {
        let (reduced, lines) = crate::test_logger::capture(|| {
            reduce_worker_reports(vec![
                report(&["a@a.a"], Some(Error::RateLimitExhausted)),
                report(&["b@b.b"], None),
                report(&[], None),
            ])
        });
        // the drained token fails one worker, but the scan keeps its emails
        let emails = reduced.result.expect("the scan must not fail");
        assert_eq!(emails.len(), 2);
        assert_eq!(reduced.worker_requests, 3);
        // the warning names the machine-readable flag (doc/src/OUTPUT.md:
        // "the matching warning names the flag in the log"): a dropped
        // mention must fail this test
        assert!(reduced.partial);
        assert!(
            lines.iter().any(|line| line.contains("scanned.partial")),
            "the partial warning must name the flag: {lines:?}"
        );
    }

    #[test]
    fn a_rate_limit_without_any_progress_fails_the_scan() {
        // single anonymous worker, or every token spent before scanning
        // anything: nothing to return
        let reports = vec![report(&["a@a.a"], Some(Error::RateLimitExhausted))];
        let reduced = reduce_worker_reports(reports);
        assert!(matches!(reduced.result, Err(Error::RateLimitExhausted)));
    }

    #[test]
    fn warn_skipped_repositories_count_as_covered_work_for_the_callers() {
        // a caller with a complete-report contract (the org investigation)
        // judges the kept partial result against the listed repositories: a
        // repository warn-skipped as resource-scoped (deleted, private or
        // empty) is covered work, not work the dead token never reached
        let covered = ScanWorkerReport {
            emails: vec!["b@b.b".to_string()],
            requests: 1,
            repos_scanned: 0,
            skipped: 1,
            contributions: Vec::new(),
            failure: None,
            token_died: false,
        };
        let reduced = reduce_worker_reports(vec![
            progressed_report(&["a@a.a"], 1, Some(Error::RateLimitExhausted)),
            covered,
        ]);
        reduced
            .result
            .expect("covered work must not be thrown away");
        assert!(reduced.partial, "the death is still reported to the caller");
        assert_eq!(
            (reduced.repos_scanned, reduced.skipped),
            (1, 1),
            "scanned + skipped covers the two listed repositories"
        );

        // a dead worker's own gap (its in-flight repository) is neither
        // scanned nor skipped: scanned + skipped stays below the listing and
        // the caller must abort instead of writing a complete-looking report
        let reduced = reduce_worker_reports(vec![
            progressed_report(&["a@a.a"], 1, Some(Error::RateLimitExhausted)),
            report(&["b@b.b"], None),
        ]);
        reduced.result.expect("the scan itself still succeeds");
        assert!(reduced.partial);
        assert_eq!(
            reduced.repos_scanned + reduced.skipped,
            1,
            "one listed repository was left uncovered: the caller aborts"
        );
    }

    #[test]
    fn a_complete_result_survives_every_worker_token_dying() {
        // quota died on each worker's final request: the queue was fully
        // drained, so the collected emails must not be thrown away
        let reports = vec![
            progressed_report(&["a@a.a"], 3, Some(Error::RateLimitExhausted)),
            progressed_report(&["b@b.b"], 2, Some(Error::RateLimitExhausted)),
        ];
        let reduced = reduce_worker_reports(reports);
        let emails = reduced.result.expect("a complete result must be kept");
        assert_eq!(emails.len(), 2);
        assert_eq!(reduced.worker_requests, 2);
    }

    #[test]
    fn a_partial_result_kept_after_a_token_death_is_flagged_for_callers() {
        // callers with a complete-report contract (the `org` investigation)
        // must be able to tell a partial kept result from a complete one
        let partial = vec![
            progressed_report(&["a@a.a"], 1, Some(Error::RateLimitExhausted)),
            report(&["b@b.b"], None),
        ];
        let reduced = reduce_worker_reports(partial);
        reduced
            .result
            .expect("the healthy workers' emails must be kept");
        assert!(reduced.partial, "a kept partial result must be flagged");
        assert!(
            reduced.death_error.is_some(),
            "the caller must receive the real death cause"
        );

        let complete = vec![report(&["a@a.a"], None), report(&["b@b.b"], None)];
        let reduced = reduce_worker_reports(complete);
        reduced.result.expect("the scan must not fail");
        assert!(
            !reduced.partial && reduced.death_error.is_none(),
            "a result kept without any token death is not partial"
        );
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
        let reduced = reduce_worker_reports(reports);
        let emails = reduced
            .result
            .expect("the healthy workers' emails must be kept");
        assert_eq!(emails.len(), 2);
    }

    #[test]
    fn a_resource_scoped_failure_is_skipped_not_treated_as_a_dead_token() {
        // a 403 (private repository, token without the right scope), a
        // 404 (stale search-index entry) and a 409 (empty repository) are
        // scoped to the repository, not to the token: the worker skips them
        // and keeps pulling work
        assert!(matches!(
            classify_failure(&Error::PrivateOrUnavailable, true),
            FailureAction::SkipRepository
        ));
        assert!(matches!(
            classify_failure(&Error::NotFound, true),
            FailureAction::SkipRepository
        ));
        assert!(matches!(
            classify_failure(&Error::EmptyRepository, true),
            FailureAction::SkipRepository
        ));
    }

    #[test]
    fn classify_failure_stops_the_worker_only_on_real_token_deaths() {
        // a spent quota stops the worker, dedicated token or not; so does a
        // token the API rejected outright (HTTP 401 surfaced as
        // [`Error::TokenRejected`])
        assert!(matches!(
            classify_failure(&Error::RateLimitExhausted, true),
            FailureAction::TokenDied
        ));
        assert!(matches!(
            classify_failure(&Error::TokenRejected, true),
            FailureAction::TokenDied
        ));
        // any unexpected failure aborts the whole scan
        assert!(matches!(
            classify_failure(&Error::InvalidUrl("nope".to_string()), true),
            FailureAction::AbortScan
        ));
        assert!(matches!(
            classify_failure(&Error::WorkerFailed("did not report".to_string()), true),
            FailureAction::AbortScan
        ));
    }

    #[test]
    fn a_transport_error_skips_its_repository_instead_of_aborting_the_scan() {
        // a connection refused (nothing listens on port 1) is a transient
        // network condition, not a scan-fatal one: the repository is
        // skipped, the other workers keep going
        let client = reqwest::blocking::Client::new();
        let err = client
            .get("http://127.0.0.1:1/")
            .send()
            .expect_err("nothing listens on port 1");
        let err = Error::from(err);
        assert!(
            matches!(classify_failure(&err, true), FailureAction::SkipRepository),
            "a transport-level error is transient and must skip, not abort"
        );
        // a complete-report caller (`org`) keeps the documented contract: a
        // transport failure aborts, so its report can never silently miss a
        // whole repository
        assert!(
            matches!(classify_failure(&err, false), FailureAction::AbortScan),
            "the complete-report contract must abort on a transport error"
        );
    }

    #[test]
    fn an_abort_failure_is_preferred_over_an_earlier_token_death() {
        // first-arrival attribution would report the scan-wide cause as a
        // mere rate limit when a genuine abort-class failure coexists: the
        // non-token-death failure is the more informative one and wins
        let reports = vec![
            progressed_report(&["a@a.a"], 1, Some(Error::RateLimitExhausted)),
            report(&["b@b.b"], Some(Error::InvalidUrl("nope".to_string()))),
        ];
        let reduced = reduce_worker_reports(reports);
        assert!(matches!(reduced.result, Err(Error::InvalidUrl(_))));
    }

    #[test]
    fn a_non_rate_limit_failure_fails_the_scan() {
        let reports = vec![
            report(&["a@a.a"], Some(Error::RateLimitExhausted)),
            report(&["b@b.b"], Some(Error::InvalidUrl("nope".to_string()))),
            report(&[], None),
        ];
        let reduced = reduce_worker_reports(reports);
        // a failure other than a drained token aborts the scan: the first
        // reported failure wins, so the scan errors out either way
        assert!(matches!(
            reduced.result,
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
        let reduced = reduce_worker_reports(reports);
        reduced.result.expect("the scan must not fail");
        assert_eq!(reduced.repos_scanned, 3);
    }
}
