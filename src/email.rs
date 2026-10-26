//! Reverse email lookup (100% API - no new
//! dependency, hand-made errors, zero runtime panics).
//!
//! GitHub has no email search API, so the lookup is a **documented
//! heuristic** that reconstructs candidate repositories and then verifies
//! them by commits:
//!
//! 1. **Candidate repositories**: the repository search endpoint is queried
//!    with the tokens of the email local part (split on `.`, `_`, `-` and
//!    `+`, e.g. `jane.dupont` → `jane dupont`), with the raw local part when
//!    it differs (e.g. `janedupont`) and with the domain itself
//!    (`acme.com`) - at most three queries. The repositories whose name,
//!    description or topics mention these tokens become candidates, with
//!    no local cap: every repository the search serves (bounded by GitHub's
//!    1000-result search window per query) is a candidate.
//! 2. **Commit verification**: every candidate repository's (default-branch)
//!    commits are scanned for a commit whose author email is exactly the
//!    target: the local part ASCII case-insensitively, the domain matched
//!    exactly (no subdomain look-alike), and the lookup stops early once
//!    the strongest attribution is found. The listing is never narrowed by the
//!    commits API `author` parameter: the commit author login is not
//!    necessarily the email local part, and a narrowing would silently drop
//!    the target's own commits (false negatives). Each candidate's
//!    default-branch history is walked to its end (no local budget).
//! 3. **Account resolution**: a matching commit whose API payload embeds a
//!    GitHub author object resolves the account with the `commit-author`
//!    confidence; when the author object is absent (deleted account), the
//!    repository owner is only a **weak** candidate (`repo-owner-weak`
//!    confidence, never overstated).
//!
//! Anti-false-positive rules: GitHub noreply addresses are rejected upfront
//! (they never carry a real mailbox - the `user` subcommand's noreply
//! technique covers them), a malformed address is rejected client-side
//! before any request, the email match is exact, and the `confidence`
//! field states only what the API payload actually proved. An unmatched
//! address is reported as unmatched (a finding, not an error).
//!
//! # API-only deltas (documented)
//!
//! - the commit walk covers the default branch only (per-branch walking multiplies the request cost and is not attempted);
//! - the candidates are limited to repositories whose name, description
//!   or topics mention the local-part tokens or the domain: an email never
//!   used in a public commit of one of those candidates cannot be found;
//! - the `repo-owner-weak` attribution is a heuristic: the repository owner
//!   committed the matching email but the commit carries no GitHub author
//!   object, so the login behind it is only presumed (and a repository
//!   owner may be an organization rather than a user - resolve the account
//!   type before acting on a weak attribution);

use crate::consts::GITHUB_API_BASE;
use crate::errors::Error;
use crate::github::{Client, fetch_paginated_with_page_size};
use crate::parsers;
use crate::sanitize::log_safe;
use crate::sources::{
    PER_PAGE, SEARCH_RESULT_CEILING, Scanner, SearchQualifiers, parse_search_page, search_q,
};
use serde::Serialize;
use serde_json::Value;
use std::cell::Cell;
use std::cell::RefCell;
use std::collections::HashSet;
use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;

/// Confidence of an account resolved through the commit author object
/// embedded in the API response: the strongest attribution.
const CONFIDENCE_COMMIT_AUTHOR: &str = "commit-author";

/// Confidence of an account presumed from the repository owner when the
/// matching commit carries no GitHub author object: a weak, explicitly
/// flagged heuristic.
const CONFIDENCE_REPO_OWNER_WEAK: &str = "repo-owner-weak";

/// Plain-words translation of a confidence grade for the terminal lines a
/// non-technical user reads; the JSON `confidence` field keeps the raw
/// machine-readable value.
fn confidence_plain(confidence: &str) -> &'static str {
    if confidence == CONFIDENCE_COMMIT_AUTHOR {
        "confirmed by a commit"
    } else {
        "uncertain: guessed from the repository owner"
    }
}

/// The GitHub account behind a matched email, with the confidence of the
/// attribution (`commit-author` or `repo-owner-weak`). The `id` is only
/// known when the API payload embedded the commit author object (`null` for
/// a weak attribution).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Account {
    /// The GitHub login of the attributed account.
    pub login: String,
    /// The numeric GitHub id, when the API payload carried it.
    pub id: Option<u64>,
    /// How the account was attributed: `commit-author` (the matching commit
    /// embedded this GitHub author object) or `repo-owner-weak` (the
    /// repository owner, a heuristic candidate only - and a repository
    /// owner may be an organization rather than a user: resolve the
    /// account type before acting on a weak attribution).
    pub confidence: String,
}

/// The evidence backing an [`Account`] attribution: the repository and the
/// exact commit where the target email was seen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Evidence {
    /// The repository holding the matching commit (`owner/name`).
    pub repository: String,
    /// The matching commit sha, when the API payload carried one.
    pub commit_sha: Option<String>,
    /// The commit author email that matched the target (as found in the
    /// commit).
    pub author_email: String,
}

/// The reverse-lookup report of one email address: the resolved account
/// (`null` when unmatched), the evidence behind it and every candidate
/// account encountered along the way.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EmailReport {
    /// The when/what of the report (generation timestamp, tool version).
    #[serde(flatten)]
    pub provenance: crate::output::Provenance,
    /// The looked-up email address, as provided and trimmed of surrounding
    /// whitespace (the CLI argument is trimmed before the lookup runs).
    pub email: String,
    /// The resolved GitHub account, or `null` when no matching commit was
    /// found (an unmatched address is a finding, not an error).
    pub account: Option<Account>,
    /// The repository and commit proving the attribution, when matched.
    pub evidence: Option<Evidence>,
    /// Every candidate account encountered, in encounter order (a weak
    /// attribution found before the strong one keeps both listed here).
    #[serde(rename = "candidates")]
    pub candidate_accounts: Vec<Account>,
}

/// The `matched`/`unmatched`/`skipped` counts of a bulk reverse lookup.
/// `total` only counts processed addresses: work a stopped worker never
/// reached is reported as `skipped`, never as a verified no-match (the same
/// honesty rule as the 0.5.0 `scanned.repos` fix).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct BulkSummary {
    /// How many addresses were actually processed (`matched + unmatched`).
    pub total: usize,
    /// How many addresses resolved to a GitHub account.
    pub matched: usize,
    /// How many addresses were processed and found no matching commit.
    pub unmatched: usize,
    /// How many addresses could not be processed at all (a worker stopped
    /// early and no other token reached them): reported with a warning,
    /// absent from [`BulkReport::results`], never counted as unmatched.
    pub skipped: usize,
}

/// The bulk (`emails <file>`) reverse-lookup report: one result per
/// processed address, in file order, plus the matched/unmatched/skipped
/// summary (an address a stopped worker never reached is skipped, not
/// unmatched - see [`BulkSummary::skipped`]).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct BulkReport {
    /// The when/what of the report (generation timestamp, tool version).
    #[serde(flatten)]
    pub provenance: crate::output::Provenance,
    /// One report per processed address, in file order. Addresses that were
    /// never processed are absent (they are listed in
    /// [`BulkReport::skipped_addresses`], counted in
    /// [`BulkSummary::skipped`] and warned about in the log).
    pub results: Vec<EmailReport>,
    /// The addresses a stopped worker never reached, in file order - the
    /// inventory behind [`BulkSummary::skipped`]: an operator re-running the
    /// interrupted lookups must not have to diff two files to find them.
    pub skipped_addresses: Vec<String>,
    /// The matched/unmatched/skipped counts.
    pub summary: BulkSummary,
}

/// Runs the reverse lookup of one email address and logs the terminal
/// report.
///
/// # Errors
///
/// Returns [`Error::NoreplyEmail`] for a GitHub noreply address (rejected
/// upfront) and [`Error::InvalidEmail`] for a malformed one (both rejected
/// client-side, before any network request). Otherwise the same API failures
/// as the other scans: [`Error::NotFound`],
/// [`Error::PrivateOrUnavailable`], [`Error::RateLimitExhausted`],
/// [`Error::TokenRejected`] or [`Error::Http`], plus
/// [`Error::InvalidProfile`] when a candidate's commits payload is not a
/// JSON array (an intermediary or a shape change, not an empty page). A
/// candidate repository that is private, deleted or
/// empty (GitHub answers 409 on its commits listing) is skipped with a
/// warning.
pub fn reverse(scanner: &Scanner, address: &str) -> Result<EmailReport, Error> {
    let (report, searched) = reverse_at(scanner.client(), GITHUB_API_BASE, address)?;
    log_report(&report, searched);
    Ok(report)
}

/// Runs the bulk reverse lookup of the addresses of `path` (one address per
/// line, `#` comments and blank lines ignored) over the token pool - the
/// same worker-per-token parallelism as the parallel `search` - and logs the
/// terminal report.
///
/// Noreply and malformed lines are skipped with a warning (they cannot be
/// reversed, they are not scan failures); duplicated addresses are
/// deduplicated. Unmatched addresses are reported as unmatched, not errors.
///
/// # Errors
///
/// Returns [`Error::Io`] when the file cannot be read, and the same API
/// failures as [`reverse`] (including [`Error::TokenRejected`]). A worker
/// whose dedicated token died (spent quota
/// or rejected token) stops pulling work while the other tokens keep
/// draining the queue; the addresses it never reached are reported as
/// skipped with a warning (counted in the summary's `skipped`, absent from
/// `results`: never-processed work is never counted as unmatched). Any
/// other worker failure - including the OS refusing to spawn a worker
/// ([`Error::WorkerFailed`]) - aborts the bulk run.
pub fn reverse_bulk(scanner: &Scanner, path: &Path) -> Result<BulkReport, Error> {
    // library convenience over [`reverse_bulk_with_partial`]: on an abort
    // the partial report is logged, then only the error propagates (the
    // CLI path uses the tuple form to reach the `--json` file too)
    let (report, failure) = reverse_bulk_with_partial(scanner, GITHUB_API_BASE, path);
    if let Some(err) = failure {
        return Err(err);
    }
    Ok(report)
}

/// The bulk reverse lookup exposing partial results: on an abort-class
/// failure (a transport error, a malformed payload) the lookups already
/// paid for travel back in the report alongside the error, so a CLI caller
/// can still write the requested `--json` file. Token deaths never land
/// here: they keep their own workers' findings and the scan drains on.
/// Logs the terminal report either way.
pub fn reverse_bulk_with_partial(
    scanner: &Scanner,
    base: &str,
    path: &Path,
) -> (BulkReport, Option<Error>) {
    let addresses = match read_addresses(path) {
        Ok(addresses) => addresses,
        Err(err) => return (BulkReport::default(), Some(err)),
    };
    // name the shape of the spend before it starts: three candidate
    // searches per address (each bounded by GitHub's 1000-result search
    // window) and a full history walk per candidate repository - the only
    // ceilings are GitHub's, so the honest cost statement is the shape,
    // not a fabricated number
    if !addresses.is_empty() {
        log::info!(
            "[.] reverse lookups for {} addresses: up to 3 candidate searches each (duplicates collapse, GitHub's 1000-result ceiling per query) and a full history walk per candidate repository (until a commit-author match ends the lookup early), shared across the token pool",
            addresses.len()
        );
    }
    if addresses.is_empty() {
        log::info!(
            "[-] no usable email address in {}",
            log_safe(&path.display().to_string())
        );
        return (BulkReport::default(), None);
    }
    let (report, failure) = reverse_bulk_at(scanner, base, &addresses);
    if failure.is_some() && !report.results.is_empty() {
        log::warn!(
            "the bulk run aborted early: the results computed before the failure follow ({} of {} addresses checked)",
            report.results.len(),
            addresses.len()
        );
    }
    log_bulk_report(&report);
    (report, failure)
}

/// The reverse lookup itself, driven against one API base URL: [`reverse`]
/// is the production entry point (`https://api.github.com`) and the offline
/// tests run this same code against a loopback mock. Returns the report and
/// how many candidate repositories were actually verified.
///
/// # Errors
///
/// The same failures as [`reverse`].
fn reverse_at(client: &Client, base: &str, address: &str) -> Result<(EmailReport, usize), Error> {
    let (local, domain) = split_email(address)?;
    let queries = candidate_queries(local, domain);

    // stage 1: candidate repositories from the local-part tokens and the
    // domain, deduplicated by URL, NO local cap. The listing is driven
    // through the page-size-aware loop: its short-page end and its
    // raw-count ceiling keep the walk inside GitHub's documented
    // 1000-result search window, so an over-abundant query can neither
    // reach the out-of-window 422 page nor cost the candidates its pages
    // already fetched (a plain raw walk would discard them with a warning
    // after burning ~11 wasted requests)
    let mut hits: Vec<crate::sources::RepoHit> = Vec::new();
    let mut seen_urls: HashSet<String> = HashSet::new();
    for query in queries {
        // per-query seen set, seeded with the candidates already kept and
        // dropped when the query fails, so the hits of its fetched pages
        // stay available to the next query
        let seen = RefCell::new(seen_urls.clone());
        // raw listed items of this query, counted as the pages stream in:
        // the sibling listings' honesty rule - when a query fails mid-walk,
        // the skip warning must say how many listed candidates it discarded
        let listed = Cell::new(0usize);
        // raw items of this query INCLUDING repeats, to detect the
        // documented 1000-result window cut (a query that fills the window
        // must say so instead of ending silently: candidates beyond it were
        // never seen)
        let raw_seen = Cell::new(0usize);
        match fetch_paginated_with_page_size(
            client,
            |page| {
                format!(
                    "{base}/search/repositories?q={}&per_page={PER_PAGE}&page={page}",
                    search_q(&query, "", &SearchQualifiers::default())
                )
            },
            |json| {
                // include_forks = true, deliberately unlike `user`/`org`/
                // `search`: the reverse lookup wants ANY repository carrying
                // the address, and the subject's commits often live in forks
                // of their own upstream work
                let (page_hits, raw_count) = parse_search_page(json, true)?;
                listed.set(listed.get() + page_hits.len());
                raw_seen.set(raw_seen.get() + raw_count);
                let mut fresh: Vec<crate::sources::RepoHit> = Vec::new();
                {
                    let mut seen = seen.borrow_mut();
                    for hit in page_hits {
                        if seen.insert(hit.url.clone()) {
                            fresh.push(hit);
                        }
                    }
                }
                Ok((fresh, raw_count))
            },
            // the raw ceiling guards the documented 1000-result window (an
            // all-duplicates walk must still stop instead of reaching the
            // out-of-window 422)
            Some(SEARCH_RESULT_CEILING),
            PER_PAGE,
        ) {
            Ok(page_hits) => {
                for hit in page_hits {
                    seen_urls.insert(hit.url.clone());
                    hits.push(hit);
                }
            }
            // a rejected or unavailable search query costs its candidates,
            // not the whole lookup: the next query may still run. The hits
            // its earlier pages already fetched cannot be recovered from the
            // paginated loop, so they are discarded - but the warning must
            // say how many were thrown away (same honesty rule as the
            // sibling search/user listings)
            Err(Error::NotFound | Error::PrivateOrUnavailable) => {
                log::warn!(
                    "candidate search {query:?} unavailable: skipping this query ({} listed candidates discarded)",
                    listed.get()
                );
            }
            // a query the API rejected outright (an over-long or odd local
            // part composed into an invalid `q`) is query-scoped too, not a
            // scan-wide failure: the next query may still run. Deliberately
            // NOT the shared `crate::sources::classify_search_window_422`
            // (sources/mod.rs): a 422 must stay scoped to this one query
            Err(Error::Http(err))
                if err.status() == Some(reqwest::StatusCode::UNPROCESSABLE_ENTITY) =>
            {
                log::warn!(
                    "candidate search {query:?} rejected by the API: skipping this query ({} listed candidates discarded)",
                    listed.get()
                );
            }
            Err(err) => return Err(err),
        }
        if raw_seen.get() >= SEARCH_RESULT_CEILING {
            // the walk ended on the window cut, not on a listing end: a
            // further page of the SAME query would answer the out-of-window
            // 422, but the window may hide candidates the lookup never saw
            // (hedged: an exact hit proves nothing about a further page)
            log::warn!(
                "candidate search {query:?} reached GitHub's 1000-result window: candidates beyond it were not seen"
            );
        }
    }

    // stage 2: commit verification of every candidate repository
    let mut strong: Option<(Account, Evidence)> = None;
    let mut weak: Option<(Account, Evidence)> = None;
    let mut candidates: Vec<Account> = Vec::new();
    let mut searched = 0usize;
    'repositories: for hit in &hits {
        let (owner, repository) = match repository_parts(&hit.url) {
            Ok(parts) => parts,
            Err(_) => {
                log::warn!(
                    "skipping candidate with unexpected url {}",
                    log_safe(&hit.url)
                );
                continue;
            }
        };
        // the page-size-aware walk ends on a short final page: no local
        // budget, the only ceilings are GitHub's
        let commits: Vec<CommitEntry> = match fetch_paginated_with_page_size(
            client,
            |page| {
                // owner/repository come from parsing the candidate's
                // `html_url` (API-derived): percent-encoding keeps a hostile
                // `?`, `#`, `&` or `/` from re-targeting the authenticated
                // request to another path or query
                format!(
                    "{base}/repos/{}/{}/commits?per_page={PER_PAGE}&page={page}",
                    crate::sources::percent_encode(owner.as_str()),
                    crate::sources::percent_encode(repository.as_str())
                )
            },
            |json| {
                let (page_commits, raw_count) = parse_candidate_commit_page(json)?;
                Ok((page_commits, raw_count))
            },
            None,
            PER_PAGE,
        ) {
            Ok(commits) => commits,
            // resource-scoped failure (deleted, private or empty candidate -
            // GitHub answers 409 on /commits for a repository with no
            // commits): skip it and keep verifying the remaining candidates
            Err(err @ (Error::NotFound | Error::PrivateOrUnavailable | Error::EmptyRepository)) => {
                log::warn!(
                    "skipping repository {}/{}: {err}",
                    log_safe(owner.as_str()),
                    log_safe(repository.as_str())
                );
                continue;
            }
            Err(err) => return Err(err),
        };
        searched += 1;
        let Some(commit) = commits.into_iter().find(|commit| {
            commit
                .author_email
                .as_deref()
                .is_some_and(|email| email_matches(email, local, domain))
        }) else {
            continue;
        };
        let evidence = Evidence {
            repository: format!("{owner}/{repository}"),
            commit_sha: commit.sha.clone(),
            // the matching predicate guarantees a parsable author email
            author_email: commit.author_email.clone().unwrap_or_default(),
        };
        match &commit.author_login {
            Some(login) => {
                strong = Some((
                    Account {
                        login: login.clone(),
                        id: commit.author_id,
                        confidence: CONFIDENCE_COMMIT_AUTHOR.to_string(),
                    },
                    evidence,
                ));
                // a commit-author attribution is the strongest confidence:
                // scanning further repositories cannot improve it
                break 'repositories;
            }
            None => {
                // the commit matched but the API payload embeds no author
                // object (deleted account): the repository owner is only a
                // weak candidate, flagged as such
                let account = Account {
                    login: owner,
                    id: None,
                    confidence: CONFIDENCE_REPO_OWNER_WEAK.to_string(),
                };
                push_candidate_account(&mut candidates, account.clone());
                if weak.is_none() {
                    weak = Some((account, evidence));
                }
            }
        }
    }

    if let Some((account, _)) = &strong {
        push_candidate_account(&mut candidates, account.clone());
    }
    let (account, evidence) = match strong {
        Some((account, evidence)) => (Some(account), Some(evidence)),
        None => match weak {
            Some((account, evidence)) => (Some(account), Some(evidence)),
            None => (None, None),
        },
    };
    Ok((
        EmailReport {
            provenance: crate::output::Provenance::now(env!("CARGO_PKG_VERSION")),
            email: address.trim().to_string(),
            account,
            evidence,
            candidate_accounts: candidates,
        },
        searched,
    ))
}

/// Splits and validates one email address client-side, before any network
/// request: exactly one `@`, non-empty local part and domain, no whitespace.
/// A GitHub noreply address is rejected upfront with
/// [`Error::NoreplyEmail`]: it never carries a real mailbox.
///
/// # Errors
///
/// Returns [`Error::InvalidEmail`] and [`Error::NoreplyEmail`] as described.
fn split_email(address: &str) -> Result<(&str, &str), Error> {
    // paste artifacts are trimmed like everywhere else: a quoted target
    // (`"jane@acme.com"` copied with its shell quotes) must resolve to the
    // same address as the bare one
    let address = address.trim().trim_matches('"');
    if address.is_empty() {
        return Err(Error::InvalidEmail("empty address".to_string()));
    }
    if address.chars().any(char::is_whitespace) {
        return Err(Error::InvalidEmail(format!(
            "{address:?}: whitespace is not allowed"
        )));
    }
    let Some((local, domain)) = address.split_once('@') else {
        return Err(Error::InvalidEmail(format!("{address:?}: missing '@'")));
    };
    if local.is_empty() || domain.is_empty() || domain.contains('@') {
        return Err(Error::InvalidEmail(format!(
            "{address:?}: expected exactly one '@' with a non-empty local part and domain"
        )));
    }
    if crate::sources::is_noreply_email(address) {
        return Err(Error::NoreplyEmail(address.to_string()));
    }
    Ok((local, domain))
}

/// Derives the candidate repository-search queries of one email: the
/// local-part tokens joined (`jane.dupont` → `jane dupont`), then the raw
/// local part when it differs (`janedupont`), then the domain
/// (`acme.com`). Deduplicated, in that order.
fn candidate_queries(local: &str, domain: &str) -> Vec<String> {
    let mut queries: Vec<String> = Vec::new();
    let mut push = |query: String| {
        if !query.is_empty() && !queries.contains(&query) {
            queries.push(query);
        }
    };
    let tokens: Vec<&str> = local
        .split(['.', '_', '-', '+'])
        .filter(|t| !t.is_empty())
        .collect();
    if !tokens.is_empty() {
        push(tokens.join(" "));
    }
    // the raw local part only when it holds something searchable (a
    // symbol-only local part like `...-` is noise, not a query)
    if local.chars().any(|c| c.is_ascii_alphanumeric()) {
        push(local.to_string());
    }
    push(domain.to_string());
    queries
}

/// Whether a commit email matches the target: the local part ASCII
/// case-insensitively, the domain matched exactly (full-string ASCII
/// case-insensitive equality - no subdomain look-alike). Quoted emails are
/// unwrapped first, like everywhere else in the crate.
fn email_matches(candidate_email: &str, local: &str, domain: &str) -> bool {
    let candidate_email = candidate_email.trim_matches('"');
    match candidate_email.rsplit_once('@') {
        Some((candidate_local, candidate_domain)) => {
            candidate_local.eq_ignore_ascii_case(local)
                && candidate_domain.eq_ignore_ascii_case(domain)
        }
        None => false,
    }
}

/// One commit of a candidate repository's default-branch listing: what is
/// needed to resolve and evidence the account when its author email matches
/// the target. Every commit of a page is kept (whatever its author email):
/// the per-author attribution of the correlation report is built from the
/// full listing, not only from the matching commits.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CommitEntry {
    /// The commit sha (the evidence), when the payload carried one.
    sha: Option<String>,
    /// The login of the GitHub author object embedded in the API response,
    /// when present (absent for a deleted account → weak attribution).
    author_login: Option<String>,
    /// The id of the embedded GitHub author object, when present.
    author_id: Option<u64>,
    /// The commit author email, when the payload carried a parsable one.
    author_email: Option<String>,
}

/// Extracts every commit of a `/commits` page, with the raw item count (the
/// end-of-listing signal of `fetch_paginated`). Every commit of the page is
/// kept whatever its author email (the per-author attribution and the
/// noreply technique feed from the full listing), and the walk has no local
/// budget: it covers the candidate's full default-branch history and ends
/// when GitHub's listing ends. A 200
/// body that is not a JSON array is an intermediary or a shape change, not
/// an empty page, and fails explicitly instead of silently ending the
/// lookup as a complete-looking no-match (the same explicit-requirement
/// rule as every other listing of the crate).
fn parse_candidate_commit_page(json: &Value) -> Result<(Vec<CommitEntry>, usize), Error> {
    let Some(items) = json.as_array() else {
        return Err(Error::InvalidProfile(
            "commits payload: not an array".to_string(),
        ));
    };
    let commits = items
        .iter()
        .map(|item| {
            // the embedded author object: absent, null (deleted account) or
            // a full GitHub user payload - `Value::get` on a null returns
            // `None`
            let author = item.get("author");
            CommitEntry {
                sha: item.get("sha").and_then(Value::as_str).map(str::to_string),
                author_login: author
                    .and_then(|author| author.get("login"))
                    .and_then(Value::as_str)
                    .map(str::to_string),
                author_id: author
                    .and_then(|author| author.get("id"))
                    .and_then(Value::as_u64),
                author_email: item
                    .get("commit")
                    .and_then(|commit| commit.get("author"))
                    .and_then(|author| author.get("email"))
                    .and_then(Value::as_str)
                    .map(str::to_string),
            }
        })
        .collect();
    Ok((commits, items.len()))
}

/// Extracts the `owner`/`name` parts of a candidate repository from its
/// `html_url`, reusing the URL parsers of the crate.
///
/// # Errors
///
/// Returns [`Error::InvalidUrl`] when the URL does not parse as a
/// repository.
fn repository_parts(url: &str) -> Result<(String, String), Error> {
    let (owner, repository) = parsers::parse_github_url(url)?;
    let repository = repository
        .ok_or_else(|| Error::InvalidUrl(format!("{url}: candidate url has no repository part")))?;
    if repository.is_empty() {
        return Err(Error::InvalidUrl(format!(
            "{url}: candidate url has no repository part"
        )));
    }
    Ok((owner, repository))
}

/// Adds one candidate to the list, deduplicating on
/// `(login, id, confidence)` so the same account seen through several
/// repositories is listed once.
fn push_candidate_account(candidates: &mut Vec<Account>, account: Account) {
    if !candidates.iter().any(|seen| {
        seen.login == account.login
            && seen.id == account.id
            && seen.confidence == account.confidence
    }) {
        candidates.push(account);
    }
}

/// Logs the human-readable terminal report of one reverse lookup. Every
/// untrusted string (login, repository, sha, email) is sanitized first, so a
/// hostile commit or repository can never forge log lines.
fn log_report(report: &EmailReport, searched: usize) {
    // one rendering of an optional account id: "unknown" when absent
    let id_label = |id: Option<u64>| id.map_or_else(|| "unknown".to_string(), |id| id.to_string());
    log::info!("============ EMAIL REVERSE LOOKUP ============");
    log::info!("[+] target: {}", log_safe(&report.email));
    log::info!("[+] candidate repositories verified: {searched}");
    match &report.account {
        Some(account) => {
            log::info!(
                "[+] account: @{} (id {}, match: {})",
                log_safe(&account.login),
                id_label(account.id),
                confidence_plain(&account.confidence)
            );
            if let Some(evidence) = &report.evidence {
                log::info!(
                    "[+] proof: commit {} in {} (author email {})",
                    evidence
                        .commit_sha
                        .as_deref()
                        .map(log_safe)
                        .unwrap_or_else(|| "unknown sha".to_string()),
                    log_safe(&evidence.repository),
                    log_safe(&evidence.author_email)
                );
            }
            if account.confidence == CONFIDENCE_REPO_OWNER_WEAK {
                log::info!(
                    "[!] uncertain match: the commit does not name a GitHub account, so the repository owner is only a likely candidate"
                );
            }
        }
        None => log::info!(
            "[-] no GitHub account matched this email (the lookup only sees candidate repositories whose name or description mention the address: no match is not proof of absence)"
        ),
    }
    for candidate in &report.candidate_accounts {
        // the resolved account is kept in the JSON candidates list for the
        // evidence trail: the terminal summary must not re-list it as an
        // "other" candidate
        if report.account.as_ref().is_some_and(|account| {
            account.login == candidate.login
                && account.id == candidate.id
                && account.confidence == candidate.confidence
        }) {
            continue;
        }
        log::info!(
            "[.] other candidate: @{} (id {}, match: {})",
            log_safe(&candidate.login),
            id_label(candidate.id),
            confidence_plain(&candidate.confidence)
        );
    }
}

/// Logs the human-readable terminal report of a bulk reverse lookup: one
/// line per processed address, then the matched/unmatched/skipped summary.
fn log_bulk_report(report: &BulkReport) {
    log::info!("============ EMAILS REVERSE LOOKUP ============");
    for email_report in &report.results {
        match &email_report.account {
            Some(account) => log::info!(
                "[+] {} -> @{} (match: {})",
                log_safe(&email_report.email),
                log_safe(&account.login),
                confidence_plain(&account.confidence)
            ),
            None => log::info!(
                "[-] {}: no GitHub account found (the lookup only sees candidate repositories mentioning the address: no match is not proof of absence)",
                log_safe(&email_report.email)
            ),
        }
    }
    log::info!(
        "[+] summary: {} found / {} not found / {} not checked",
        report.summary.matched,
        report.summary.unmatched,
        report.summary.skipped
    );
}

/// Upper bound on a bulk addresses file read: a bulk list is a text file of
/// one address per line (100k addresses are a realistic OSINT input, a few
/// megabytes at most). A FIFO (`--emails mypipe`) would block forever with
/// no diagnostic and a character device like `/dev/zero` (valid UTF-8 NUL
/// bytes) grows the read without bound until the process is killed -
/// neither is ever an address list, so both fail fast like any other
/// invalid input.
const MAX_ADDRESSES_FILE_BYTES: u64 = 64 * 1024 * 1024;

/// Reads the addresses of a bulk file: one address per line, `#` comments
/// and blank lines ignored, duplicates deduplicated. Noreply and malformed
/// lines are skipped with a warning: they cannot be reversed, and one bad
/// line must not fail the whole file.
///
/// # Errors
///
/// Returns [`Error::Io`] when the file cannot be read.
/// The read_file_error hint every addresses-file failure carries: the
/// expected format, so the user knows what the reader accepts.
const ADDRESSES_HINT: &str = "one email address per line, # comments allowed";

fn read_addresses(path: &Path) -> Result<Vec<String>, Error> {
    // the read failure names the file (see `read_file_error` in errors),
    // like the token-file reader: a bare "No such file or directory" would
    // leave the user guessing which typed input failed
    let metadata = std::fs::metadata(path)
        .map_err(|err| crate::errors::read_file_error(path, err, ADDRESSES_HINT))?;
    // bounded per the MAX_ADDRESSES_FILE_BYTES rationale
    if !metadata.is_file() {
        return Err(crate::errors::read_file_error(
            path,
            std::io::Error::other("not a regular file"),
            ADDRESSES_HINT,
        ));
    }
    if metadata.len() > MAX_ADDRESSES_FILE_BYTES {
        return Err(crate::errors::read_file_error(
            path,
            std::io::Error::other(format!(
                "file is {} bytes, the maximum is {MAX_ADDRESSES_FILE_BYTES}",
                metadata.len()
            )),
            ADDRESSES_HINT,
        ));
    }
    let content = std::fs::read_to_string(path)
        .map_err(|err| crate::errors::read_file_error(path, err, ADDRESSES_HINT))?;
    // Windows editors (Notepad, Excel exports) prepend a UTF-8 BOM: left in
    // place it silently becomes part of the first address (or breaks comment
    // detection on the first line), so the first target of the list is lost
    // with no warning.
    let content = content.strip_prefix('\u{feff}').unwrap_or(&content);
    let mut addresses: Vec<String> = Vec::new();
    // the lookup is case-insensitive: the same address with a different
    // casing is one target, not two. The lowercased keys live in a set so
    // the dedup stays linear - a linear scan over the accumulated addresses
    // per line made large bulk lists (100k lines are a realistic OSINT
    // input) freeze the run in quadratic parsing before the first network
    // call.
    let mut seen: HashSet<String> = HashSet::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match split_email(line) {
            Ok(address) => {
                // dedup on the split_email-normalized form (quotes unwrapped
                // and trimmed): `"jane@acme.com"` and `jane@acme.com` are
                // the same mailbox and must not cost two lookups
                if seen.insert(format!("{}@{}", address.0, address.1).to_ascii_lowercase()) {
                    addresses.push(line.to_string());
                }
            }
            Err(Error::NoreplyEmail(_)) => {
                log::warn!(
                    "skipping {line:?}: GitHub noreply addresses cannot be reversed (the `user` subcommand can still identify the account behind this kind of address)"
                );
            }
            Err(err) => log::warn!("skipping {line:?}: {err}"),
        }
    }
    Ok(addresses)
}

/// Whether a per-email failure of a bulk worker is a token-scoped death
/// (the worker's token died: spent quota, or the API rejected the token
/// with nothing to rotate to) - the worker then stops and keeps its
/// findings while the other tokens drain the queue. Per-repository and
/// per-query resource-scoped failures are already handled inside
/// [`reverse_at`], so anything else that escapes is a scan-wide condition
/// and must abort the whole bulk run.
fn bulk_failure_is_token_death(err: &Error) -> bool {
    matches!(
        err,
        Error::RateLimitExhausted | Error::RateLimitPaused | Error::TokenRejected
    )
}

/// What one bulk worker reports back: the per-address results it produced
/// (with their file indexes), how many successful requests its client made,
/// and the failure that ended it (if any) - a worker keeps its partial
/// findings even when it failed.
struct BulkWorkerReport {
    results: Vec<(usize, EmailReport)>,
    requests: usize,
    failure: Option<Error>,
    token_died: bool,
}

/// Runs the bulk reverse lookup of `addresses` over the token pool (
/// parallelism, reused from the parallel `search`): a pool of
/// `min(nb_tokens, nb_addresses)` workers, each owning exactly one dedicated
/// token through its own client, pulling `(file index, address)` pairs from
/// a shared `mpsc` work queue until it is drained.
///
/// Returns the report and the abort-class failure that ended it, if any:
/// on an abort the report holds the lookups completed before the failure
/// (token deaths do not end the run and never reach this return).
fn reverse_bulk_at(
    scanner: &Scanner,
    base: &str,
    addresses: &[String],
) -> (BulkReport, Option<Error>) {
    if addresses.is_empty() {
        return (BulkReport::default(), None);
    }
    let tokens = scanner.client().tokens();
    // The live-token assignment, the spawn-failure degradation and the
    // exactly-one-report-per-worker collection live in the shared
    // [`crate::github::pool`] runner (the same seam as the parallel scan):
    // a token the pool already retired or parked must not own a worker slot
    // while healthy tokens sit beyond the worker range - with fewer
    // addresses than tokens, every spawned worker could otherwise own a
    // dead token and abort the whole bulk run without a single request.
    let reports: Vec<BulkWorkerReport> = crate::github::pool::run_token_worker_pool(
        tokens,
        addresses
            .iter()
            .enumerate()
            .map(|(index, address)| (index, address.clone())),
        |cause| BulkWorkerReport {
            results: Vec::new(),
            requests: 0,
            failure: Some(Error::WorkerFailed(format!("bulk reverse {cause}"))),
            token_died: false,
        },
        |work_rx, aborted, dedicated_token, start_dead| {
            bulk_worker(dedicated_token, base, work_rx, aborted, start_dead)
        },
    );
    let (slots, failure, worker_requests) = reduce_bulk_reports(reports, addresses);
    scanner.add_worker_requests(worker_requests);

    // an address a stopped worker never reached is skipped (with a
    // warning): it was never searched, so it must not be counted as a
    // verified no-match
    let mut results: Vec<EmailReport> = Vec::with_capacity(addresses.len());
    let mut matched = 0usize;
    let mut skipped_addresses: Vec<String> = Vec::new();
    for (index, slot) in slots.into_iter().enumerate() {
        match slot {
            Some(email_report) => {
                if email_report.account.is_some() {
                    matched += 1;
                }
                results.push(email_report);
            }
            None => {
                // the inventory of the never-processed addresses travels in
                // the report (not just the count): an operator re-running
                // the interrupted lookups must not have to diff two files
                skipped_addresses.push(addresses[index].clone());
                log::warn!(
                    "email {} could not be checked (its lookup was interrupted): counted as skipped, not unmatched",
                    log_safe(&addresses[index])
                );
            }
        }
    }
    let summary = BulkSummary {
        total: results.len(),
        matched,
        unmatched: results.len() - matched,
        skipped: skipped_addresses.len(),
    };
    let report = BulkReport {
        provenance: crate::output::Provenance::now(env!("CARGO_PKG_VERSION")),
        skipped_addresses,
        results,
        summary,
    };
    if let Some(err) = failure {
        // an abort-class failure must not erase the lookups already paid
        // for: the partial report travels back alongside the error (the
        // caller writes it to the requested --json file and logs it), so a
        // transient timeout at address 300 of 500 does not erase addresses
        // 1-299. The unchecked addresses are already named by the skip
        // warnings above
        return (report, Some(err));
    }
    (report, None)
}

/// Worker body: owns one dedicated token through its own client, pulls the
/// next `(index, address)` pair from the shared `mpsc` work queue and runs
/// the reverse lookup on it, until the queue is drained or another worker
/// failed.
fn bulk_worker(
    dedicated_token: Option<&str>,
    base: &str,
    work_rx: &Mutex<mpsc::Receiver<(usize, String)>>,
    aborted: &AtomicBool,
    start_dead: bool,
) -> BulkWorkerReport {
    let client = match Scanner::worker_client(dedicated_token) {
        Ok(client) => client,
        Err(err) => {
            return BulkWorkerReport {
                results: Vec::new(),
                requests: 0,
                failure: Some(err),
                token_died: false,
            };
        }
    };
    if start_dead {
        // the dedicated token was already unusable when the worker spawned:
        // report the death without pulling (and doomed-losing) any address
        return BulkWorkerReport {
            results: Vec::new(),
            requests: 0,
            failure: Some(Error::RateLimitExhausted),
            token_died: true,
        };
    }
    let mut results: Vec<(usize, EmailReport)> = Vec::new();
    loop {
        // stop pulling work as soon as any worker failed fatally: the bulk
        // run is going to error out anyway
        if aborted.load(Ordering::Relaxed) {
            break;
        }
        // the mutex only guards pulling one pair off the channel; the queue
        // is fully populated upfront, so `recv` never blocks long
        let item = {
            let Ok(receiver) = work_rx.lock() else {
                break; // poisoned queue: stop pulling work
            };
            receiver.recv().ok() // `None` once the queue is drained
        };
        let Some((index, address)) = item else {
            break; // the shared queue is empty: this worker is done
        };
        match reverse_at(&client, base, &address) {
            Ok((report, _searched)) => results.push((index, report)),
            Err(err) => {
                let token_died = bulk_failure_is_token_death(&err);
                if !token_died {
                    aborted.store(true, Ordering::Relaxed);
                }
                return BulkWorkerReport {
                    results,
                    requests: client.requests_made(),
                    failure: Some(err),
                    token_died,
                };
            }
        }
    }
    BulkWorkerReport {
        results,
        requests: client.requests_made(),
        failure: None,
        token_died: false,
    }
}

/// Reduces the workers' reports into the per-address slots (`None` when the
/// address was never processed) and the total number of successful requests
/// they made.
///
/// A worker whose dedicated token died does not fail the bulk run: the other
/// workers' tokens keep draining the queue and the results found so far are
/// returned (possibly partial). Any other failure aborts the bulk run, as
/// does a token death with no worker left having made any progress.
fn reduce_bulk_reports(
    reports: Vec<BulkWorkerReport>,
    addresses: &[String],
) -> (Vec<Option<EmailReport>>, Option<Error>, usize) {
    let mut slots: Vec<Option<EmailReport>> = (0..addresses.len()).map(|_| None).collect();
    let mut requests = 0usize;
    let mut failure: Option<Error> = None;
    let mut failure_is_token_death = false;
    let mut only_token_deaths = true;
    let mut any_progress = false;
    for report in reports {
        requests += report.requests;
        // a worker that processed at least one address made real progress,
        // even if its token died on a later request: its findings must not
        // be discarded with its failure
        any_progress = any_progress || !report.results.is_empty() || report.failure.is_none();
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
        for (index, email_report) in report.results {
            if index < slots.len() {
                slots[index] = Some(email_report);
            }
        }
    }
    let (slots, failure) = match failure {
        // every failure is a dead dedicated token and at least one worker
        // made progress on its own token: return the (possibly partial)
        // result instead of throwing the work away. The "coverage may be
        // incomplete" warning is gated on the slots that were actually left
        // unfilled: a token death whose sibling workers filled every slot
        // lost no address, so no incompleteness is warned (the same
        // coverage judgment as the parallel scan's partial flag)
        Some(_) if only_token_deaths && any_progress => {
            if slots.iter().any(Option::is_none) {
                log::warn!(
                    "some addresses were not checked: one of the tokens ran out or was refused mid-run - rerun the command to cover the rest"
                );
            }
            (slots, None)
        }
        // an abort-class failure still carries the lookups already computed
        // in `slots`: the caller logs the partial report (when it holds
        // anything) before propagating the failure, so a timeout at address
        // 300 of 500 does not erase addresses 1-299
        Some(err) => (slots, Some(err)),
        None => (slots, None),
    };
    (slots, failure, requests)
}

#[cfg(test)]
mod tests {
    // Tests may unwrap, expect and panic freely: a failing assertion must
    // be loud, so the zero-panic lints do not apply to the test modules.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use std::sync::Arc;

    // ---- address validation ----

    #[test]
    fn split_email_accepts_usual_addresses() {
        assert_eq!(
            split_email("jane@acme.com").expect("must parse"),
            ("jane", "acme.com")
        );
        // surrounding whitespace is trimmed
        assert_eq!(
            split_email("  jane@acme.com\n").expect("must parse"),
            ("jane", "acme.com")
        );
        // paste artifacts too: a quoted target resolves to the same address
        assert_eq!(
            split_email("\"jane@acme.com\"").expect("must parse"),
            ("jane", "acme.com")
        );
    }

    #[test]
    fn split_email_rejects_malformed_addresses_before_any_request() {
        for bad in [
            "",
            "   ",
            "no-at-sign",
            "a@@b.c",
            "@acme.com",
            "jane@",
            "ja ne@acme.com",
        ] {
            let error = split_email(bad).expect_err("a malformed address must be rejected");
            assert!(
                matches!(error, Error::InvalidEmail(_)),
                "wrong error for {bad:?}: {error}"
            );
        }
    }

    #[test]
    fn split_email_rejects_noreply_addresses_upfront() {
        for noreply in [
            "12345+jane@users.noreply.github.com",
            "12345@users.noreply.github.com",
            "12345+jane@USERS.NOREPLY.GITHUB.COM",
        ] {
            let error = split_email(noreply).expect_err("a noreply address must be rejected");
            assert!(matches!(error, Error::NoreplyEmail(_)));
        }
        // a subdomain look-alike is not the noreply domain
        assert!(split_email("jane@xusers.noreply.github.com").is_ok());
    }

    // ---- candidate queries ----

    #[test]
    fn candidate_queries_derives_tokens_local_part_and_domain() {
        assert_eq!(
            candidate_queries("jane.dupont", "acme.com"),
            vec![
                "jane dupont".to_string(),
                "jane.dupont".to_string(),
                "acme.com".to_string()
            ]
        );
    }

    #[test]
    fn candidate_queries_collapses_identical_forms_and_keeps_the_raw_local_part() {
        // "jane" alone: the token join and the raw local part are the same
        assert_eq!(
            candidate_queries("jane", "acme.com"),
            vec!["jane".to_string(), "acme.com".to_string()]
        );
        // separators produce tokens, and the raw form is kept too
        assert_eq!(
            candidate_queries("jane_dupont", "acme.com"),
            vec![
                "jane dupont".to_string(),
                "jane_dupont".to_string(),
                "acme.com".to_string()
            ]
        );
        // empty-ish local parts only yield what exists
        assert_eq!(
            candidate_queries("...-", "acme.com"),
            vec!["acme.com".to_string()]
        );
    }

    // ---- email matching ----

    #[test]
    fn email_matches_is_exact_on_the_domain_and_loose_on_the_local_part() {
        assert!(email_matches("jane@acme.com", "jane", "acme.com"));
        assert!(email_matches("JANE@acme.com", "jane", "acme.com"));
        assert!(email_matches("\"jane@acme.com\"", "jane", "acme.com"));
        // a subdomain look-alike must not match the exact domain
        assert!(!email_matches("jane@mail.acme.com", "jane", "acme.com"));
        assert!(!email_matches("jane@acme.com.evil.com", "jane", "acme.com"));
        // the local part is case-insensitive but must still be the same
        assert!(!email_matches("jane.doe@acme.com", "jane", "acme.com"));
        assert!(!email_matches("bob@acme.com", "jane", "acme.com"));
    }

    // ---- commit page parsing ----

    #[test]
    fn parse_commit_page_extracts_every_commit_with_its_author_object() {
        let json: Value = serde_json::json!([
            {
                "sha": "abc123",
                "author": { "login": "janedoe", "id": 42 },
                "commit": { "author": { "email": "jane@acme.com" } }
            },
            { "sha": "def456", "commit": { "author": { "email": "bob@other.org" } } },
            { "sha": "ghi789", "commit": { "author": { "email": "JANE@ACME.COM" } } },
            { "sha": "jkl012", "commit": {} }
        ]);
        let (commits, raw_count) =
            parse_candidate_commit_page(&json).expect("parsing must succeed");
        assert_eq!(raw_count, 4);
        assert_eq!(
            commits,
            vec![
                CommitEntry {
                    sha: Some("abc123".to_string()),
                    author_login: Some("janedoe".to_string()),
                    author_id: Some(42),
                    author_email: Some("jane@acme.com".to_string()),
                },
                // a non-matching commit is kept too: every commit counts
                // toward the page budget, whatever its author email
                CommitEntry {
                    sha: Some("def456".to_string()),
                    author_login: None,
                    author_id: None,
                    author_email: Some("bob@other.org".to_string()),
                },
                CommitEntry {
                    sha: Some("ghi789".to_string()),
                    author_login: None,
                    author_id: None,
                    author_email: Some("JANE@ACME.COM".to_string()),
                },
                // a commit without a parsable author email is kept as well
                CommitEntry {
                    sha: Some("jkl012".to_string()),
                    author_login: None,
                    author_id: None,
                    author_email: None,
                },
            ]
        );
    }

    #[test]
    fn parse_commit_page_handles_a_null_author_object_and_quoted_emails() {
        // "author": null (deleted account) must parse to no author login/id
        let json: Value = serde_json::json!([
            {
                "sha": "abc123",
                "author": null,
                "commit": { "author": { "email": "\"jane@acme.com\"" } }
            }
        ]);
        let (commits, raw_count) =
            parse_candidate_commit_page(&json).expect("parsing must succeed");
        assert_eq!(raw_count, 1);
        assert_eq!(
            commits,
            vec![CommitEntry {
                sha: Some("abc123".to_string()),
                author_login: None,
                author_id: None,
                author_email: Some("\"jane@acme.com\"".to_string()),
            }]
        );
    }

    #[test]
    fn parse_commit_page_non_matching_page_keeps_its_raw_count() {
        // a page without any matching commit must not end the listing
        let json: Value = serde_json::json!([
            { "commit": { "author": { "email": "bob@other.org" } } },
            { "commit": {} }
        ]);
        let (commits, raw_count) =
            parse_candidate_commit_page(&json).expect("parsing must succeed");
        assert_eq!(commits.len(), 2);
        assert_eq!(raw_count, 2, "the listing must continue past this page");
    }

    #[test]
    fn parse_commit_page_fails_explicitly_on_a_body_that_is_not_an_array() {
        // a 200 body that is not a JSON array (captive portal, proxy, shape
        // change) is not an empty page: it must fail explicitly instead of
        // silently ending the lookup as a complete-looking no-match
        for body in [
            serde_json::json!({}),
            serde_json::json!("[]"),
            serde_json::json!(null),
        ] {
            let error = parse_candidate_commit_page(&body)
                .expect_err("a non-array body must fail explicitly");
            assert!(matches!(error, Error::InvalidProfile(details) if details.contains("array")));
        }
    }

    // ---- repository parts ----

    #[test]
    fn repository_parts_extracts_owner_and_name_from_html_urls() {
        assert_eq!(
            repository_parts("https://github.com/acme/lib").expect("must parse"),
            ("acme".to_string(), "lib".to_string())
        );
        assert!(repository_parts("https://github.com/acme").is_err());
    }

    #[test]
    fn repository_parts_rejects_dot_segments() {
        // a `..` part survives percent-encoding and the shape regexes, but
        // the url crate normalizes `{base}/repos/../X/commits` into
        // `{base}/X/commits`: a hostile `html_url` carrying one would
        // silently re-target the authenticated request to another
        // api.github.com path - the exact re-targeting the caller's
        // documented invariant forbids (rejected at the parse boundary by
        // the parsers' dot-segment guard)
        for url in [
            "https://github.com/../anything/repo",
            "https://github.com/acme/..",
            "https://github.com/./repo",
        ] {
            let error = repository_parts(url).expect_err("a dot segment must be rejected");
            assert!(
                error.to_string().contains("dot segment"),
                "unexpected error for {url}: {error}"
            );
        }
    }

    // ---- candidate deduplication ----

    #[test]
    fn push_candidate_deduplicates_the_same_account() {
        let mut candidates = Vec::new();
        let account = Account {
            login: "janedoe".to_string(),
            id: Some(42),
            confidence: CONFIDENCE_COMMIT_AUTHOR.to_string(),
        };
        push_candidate_account(&mut candidates, account.clone());
        push_candidate_account(&mut candidates, account);
        assert_eq!(candidates.len(), 1);
    }

    // ---- bulk file parsing ----

    #[test]
    fn read_addresses_parses_comments_blanks_and_deduplicates() {
        let path = std::env::temp_dir().join(format!(
            "git2mail_email_read_test_{}.txt",
            std::process::id()
        ));
        std::fs::write(
            &path,
            "# a comment\njane@acme.com\n\n  \nJANE@acme.com\nbob@other.org\n# another\n12345+jane@users.noreply.github.com\nbad-address\n",
        )
        .expect("test setup: write temp file");
        let addresses = read_addresses(&path).expect("reading must succeed");
        std::fs::remove_file(&path).ok();
        // comments/blanks skipped, duplicates deduplicated, noreply and
        // malformed lines skipped with a warning instead of failing the file
        assert_eq!(
            addresses,
            vec!["jane@acme.com".to_string(), "bob@other.org".to_string()]
        );
    }

    #[test]
    fn read_addresses_strips_a_leading_utf8_bom() {
        // Windows editors (Notepad, Excel exports) prepend a UTF-8 BOM to
        // every file: left in place it corrupts the first address (the BOM
        // silently becomes part of the local part) and breaks comment
        // detection on the first line, so the first target of a bulk list is
        // silently lost with exit 0 and no warning.
        let path = std::env::temp_dir().join(format!(
            "git2mail_email_read_bom_test_{}.txt",
            std::process::id()
        ));
        std::fs::write(&path, "\u{feff}jane@acme.com\nbob@other.org\n")
            .expect("test setup: write temp file");
        let addresses = read_addresses(&path).expect("reading must succeed");
        std::fs::remove_file(&path).ok();
        // the first address survives its BOM
        assert_eq!(
            addresses,
            vec!["jane@acme.com".to_string(), "bob@other.org".to_string()]
        );

        std::fs::write(&path, "\u{feff}# comment\njane@acme.com\n")
            .expect("test setup: write temp file");
        let addresses = read_addresses(&path).expect("reading must succeed");
        std::fs::remove_file(&path).ok();
        // a BOM before the first comment line keeps the comment a comment
        assert_eq!(addresses, vec!["jane@acme.com".to_string()]);
    }

    #[test]
    fn read_addresses_rejects_oversized_files() {
        // the read is bounded by metadata before any byte is buffered: a
        // mispointed huge file (or a character device like /dev/zero, whose
        // NUL bytes are valid UTF-8) must fail fast with a named-file error
        // instead of growing memory without bound until the OOM killer
        // steps in
        let path = std::env::temp_dir().join(format!(
            "git2mail_email_read_oversized_test_{}.txt",
            std::process::id()
        ));
        let file = std::fs::File::create(&path).expect("test setup: create temp file");
        file.set_len(MAX_ADDRESSES_FILE_BYTES + 1)
            .expect("test setup: size the sparse temp file");
        drop(file);
        let error = read_addresses(&path).expect_err("an oversized file must be rejected");
        std::fs::remove_file(&path).ok();
        assert!(
            error.to_string().contains("the maximum is"),
            "the error must name the bound: {error}"
        );
    }

    #[test]
    fn read_addresses_rejects_a_non_regular_file() {
        // a directory is never an address list: it fails fast with the
        // same named-file error contract as any other read problem (a FIFO
        // would block forever - not portably testable here, the metadata
        // guard covers it with the same check)
        let path = std::env::temp_dir();
        let error = read_addresses(&path).expect_err("a directory must be rejected");
        assert!(
            error.to_string().contains("not a regular file"),
            "the error must name the problem: {error}"
        );
    }

    #[test]
    fn read_addresses_stays_linear_on_large_files() {
        // the case-insensitive dedup must not scan the accumulated addresses
        // per line (O(n²)): a 100k-line bulk list is a realistic OSINT input,
        // and a quadratic scan froze the run for tens of minutes of
        // CPU-bound parsing before the first network call. The deduplicated
        // linear form parses such a file in well under the generous bound
        // below; the bound only fails when the scan regresses to quadratic.
        let path = std::env::temp_dir().join(format!(
            "git2mail_email_read_large_test_{}.txt",
            std::process::id()
        ));
        let content: String = (0..100_000)
            .map(|i| format!("user{i:05}@example.com\n"))
            .collect();
        std::fs::write(&path, &content).expect("test setup: write temp file");
        let started = std::time::Instant::now();
        let addresses = read_addresses(&path).expect("reading must succeed");
        let elapsed = started.elapsed();
        std::fs::remove_file(&path).ok();
        assert_eq!(addresses.len(), 100_000);
        assert!(
            elapsed < std::time::Duration::from_secs(30),
            "parsing 100k unique addresses took {elapsed:?}: the dedup regressed to a quadratic scan"
        );
    }

    // ---- bulk failure classification and reduction ----

    #[test]
    fn bulk_failure_is_token_death_only_on_real_token_deaths() {
        // a spent quota stops the worker; so does a token the API rejected
        // outright (HTTP 401 surfaced as [`Error::TokenRejected`])
        assert!(bulk_failure_is_token_death(&Error::RateLimitExhausted));
        assert!(bulk_failure_is_token_death(&Error::TokenRejected));
        // any other failure aborts the bulk run (per-repository and
        // per-query failures are already handled inside reverse_at)
        assert!(!bulk_failure_is_token_death(&Error::InvalidEmail(
            "no".to_string()
        )));
    }

    fn bulk_report_at(index: usize, login: Option<&str>) -> (usize, EmailReport) {
        (
            index,
            EmailReport {
                provenance: crate::output::Provenance::now(env!("CARGO_PKG_VERSION")),
                email: "jane@acme.com".to_string(),
                account: login.map(|login| Account {
                    login: login.to_string(),
                    id: Some(42),
                    confidence: CONFIDENCE_COMMIT_AUTHOR.to_string(),
                }),
                evidence: None,
                candidate_accounts: Vec::new(),
            },
        )
    }

    #[test]
    fn reduce_bulk_reports_fills_the_slots_by_file_index() {
        let addresses = [
            "a@a.a".to_string(),
            "b@b.b".to_string(),
            "c@c.c".to_string(),
        ];
        let reports = vec![
            BulkWorkerReport {
                results: vec![bulk_report_at(0, Some("a")), bulk_report_at(2, None)],
                requests: 5,
                failure: None,
                token_died: false,
            },
            BulkWorkerReport {
                results: vec![bulk_report_at(1, Some("b"))],
                requests: 3,
                failure: None,
                token_died: false,
            },
        ];
        let (slots, failure, requests) = reduce_bulk_reports(reports, &addresses);
        assert!(failure.is_none());
        assert_eq!(requests, 8);
        assert!(slots.iter().all(|slot| slot.is_some()));
        assert!(slots[0].as_ref().expect("slot 0").account.is_some());
        assert!(slots[1].as_ref().expect("slot 1").account.is_some());
        assert!(slots[2].as_ref().expect("slot 2").account.is_none());
    }

    #[test]
    fn a_dead_token_keeps_the_other_workers_results_but_not_as_a_failure() {
        let addresses = ["a@a.a".to_string(), "b@b.b".to_string()];
        let reports = vec![
            BulkWorkerReport {
                results: vec![bulk_report_at(0, Some("a"))],
                requests: 2,
                failure: Some(Error::RateLimitExhausted),
                token_died: true,
            },
            BulkWorkerReport {
                results: vec![bulk_report_at(1, None)],
                requests: 2,
                failure: None,
                token_died: false,
            },
        ];
        let (slots, failure, _) = reduce_bulk_reports(reports, &addresses);
        assert!(failure.is_none());
        assert!(slots[0].as_ref().expect("slot 0").account.is_some());
    }

    #[test]
    fn a_non_token_failure_aborts_the_bulk_run() {
        let addresses = ["a@a.a".to_string()];
        let reports = vec![BulkWorkerReport {
            results: Vec::new(),
            requests: 1,
            failure: Some(Error::InvalidEmail("no".to_string())),
            token_died: false,
        }];
        let (slots, failure, _) = reduce_bulk_reports(reports, &addresses);
        assert!(matches!(failure, Some(Error::InvalidEmail(_))));
        assert!(slots.iter().all(Option::is_none));
    }

    #[test]
    fn a_token_death_without_any_progress_fails_the_bulk_run() {
        let addresses = ["a@a.a".to_string()];
        let reports = vec![BulkWorkerReport {
            results: Vec::new(),
            requests: 1,
            failure: Some(Error::RateLimitExhausted),
            token_died: true,
        }];
        let (slots, failure, _) = reduce_bulk_reports(reports, &addresses);
        assert!(matches!(failure, Some(Error::RateLimitExhausted)));
        assert!(slots.iter().all(Option::is_none));
    }

    #[test]
    fn an_abort_failure_is_preferred_over_an_earlier_token_death_in_the_bulk_run() {
        // first-arrival attribution would report the scan-wide cause as a
        // mere rate limit when a genuine abort-class failure coexists: the
        // non-token-death failure is the more informative one and wins
        let addresses = ["a@a.a".to_string()];
        let reports = vec![
            BulkWorkerReport {
                results: vec![bulk_report_at(0, Some("a"))],
                requests: 1,
                failure: Some(Error::RateLimitExhausted),
                token_died: true,
            },
            BulkWorkerReport {
                results: Vec::new(),
                requests: 1,
                failure: Some(Error::InvalidUrl("nope".to_string())),
                token_died: false,
            },
        ];
        let (slots, failure, _) = reduce_bulk_reports(reports, &addresses);
        assert!(matches!(failure, Some(Error::InvalidUrl(_))));
        // the token-death worker's computed result survives the abort
        assert!(slots[0].as_ref().expect("slot 0").account.is_some());
    }

    #[test]
    fn a_dead_leading_token_never_starves_a_short_address_list() {
        // the bulk twin of the parallel scan's positional worker→token
        // mapping bug: with fewer addresses than tokens, the only worker
        // slot must go to a live token, not to the token the pool already
        // retired during the run - otherwise the whole bulk run aborts
        // without a single request while a healthy token sits unused
        let (address, server) = crate::github::mock::serve_requests(move |_index, request| {
            if crate::github::mock::request_header(request, "Authorization") == Some("token ghp_a")
            {
                panic!("a retired token must not be handed to a bulk worker");
            }
            let line = request.first().map(String::as_str).unwrap_or("");
            if line.contains("/search/repositories") {
                if crate::github::mock::request_line_page(request) > 1 {
                    return (200, vec![], r#"{"items": null}"#.to_string());
                }
                return (
                    200,
                    vec![],
                    r#"{"items": [{"html_url": "https://github.com/acme/lib"}]}"#.to_string(),
                );
            }
            if line.contains("/repos/acme/lib/commits") {
                return match crate::github::mock::request_line_page(request) {
                    1 => (
                        200,
                        vec![],
                        mock_commits_body(&commit_json(
                            "abc123",
                            "jane@acme.com",
                            serde_json::json!({ "login": "janedoe", "id": 42 }),
                        )),
                    ),
                    _ => (200, vec![], "[]".to_string()),
                };
            }
            (404, vec![], String::new())
        });

        let token_path = std::env::temp_dir().join(format!(
            "git2mail_email_starved_tokens_{}.json",
            std::process::id()
        ));
        std::fs::write(&token_path, r#"{"0": "ghp_a", "1": "ghp_b"}"#)
            .expect("test setup: write token file");
        let scanner = Scanner::new(None, Some(&token_path)).expect("scanner must build");
        std::fs::remove_file(&token_path).ok();
        scanner.client().tokens().mark_exhausted(0);

        let (report, failure) = reverse_bulk_at(&scanner, &address, &["jane@acme.com".to_string()]);
        assert!(
            failure.is_none(),
            "the live token must process the single listed address"
        );
        server.join();

        assert_eq!(report.summary.total, 1);
        assert_eq!(report.summary.matched, 1);
        assert_eq!(report.summary.skipped, 0);
    }

    #[test]
    fn a_worker_whose_dedicated_token_was_already_dead_makes_no_doomed_request() {
        // a dedicated token the pool already retired never reaches the wire:
        // the worker reports its death without pulling (and doomed-losing)
        // an address, and with a single dead token the bulk run fails
        let (address, server) = crate::github::mock::serve_requests(move |_index, _request| {
            panic!("no request may reach the API with a retired dedicated token");
        });

        let token_path = std::env::temp_dir().join(format!(
            "git2mail_email_dead_tokens_{}.json",
            std::process::id()
        ));
        std::fs::write(&token_path, r#"{"0": "ghp_a"}"#).expect("test setup: write token file");
        let scanner = Scanner::new(None, Some(&token_path)).expect("scanner must build");
        std::fs::remove_file(&token_path).ok();
        scanner.client().tokens().mark_exhausted(0);

        let (_, failure) = reverse_bulk_at(&scanner, &address, &["jane@acme.com".to_string()]);
        let error =
            failure.expect("a single dead token must fail the bulk run without any request");
        assert!(matches!(error, Error::RateLimitExhausted));
        assert_eq!(server.join(), 0, "no doomed request may reach the wire");
    }

    // ---- JSON shapes ----

    #[test]
    fn email_report_serializes_the_documented_json_shape() {
        let report = EmailReport {
            provenance: crate::output::Provenance::now(env!("CARGO_PKG_VERSION")),
            email: "jane@acme.com".to_string(),
            account: Some(Account {
                login: "janedoe".to_string(),
                id: Some(42),
                confidence: "commit-author".to_string(),
            }),
            evidence: Some(Evidence {
                repository: "acme/lib".to_string(),
                commit_sha: Some("abc123".to_string()),
                author_email: "jane@acme.com".to_string(),
            }),
            candidate_accounts: vec![Account {
                login: "janedoe".to_string(),
                id: Some(42),
                confidence: "commit-author".to_string(),
            }],
        };
        let json = serde_json::to_value(&report).expect("must serialize");
        assert_eq!(json["email"], "jane@acme.com");
        assert_eq!(json["account"]["login"], "janedoe");
        assert_eq!(json["account"]["id"], 42);
        assert_eq!(json["account"]["confidence"], "commit-author");
        assert_eq!(json["evidence"]["repository"], "acme/lib");
        assert_eq!(json["evidence"]["commit_sha"], "abc123");
        assert_eq!(json["evidence"]["author_email"], "jane@acme.com");
        assert_eq!(json["candidates"][0]["confidence"], "commit-author");
        // the provenance is universal (doc/src/OUTPUT.md: every report
        // carries it, the one-address report included): a dropped field
        // must fail this shape test
        assert_eq!(json["tool_version"], env!("CARGO_PKG_VERSION"));
        assert!(
            json["generated_at"]
                .as_str()
                .is_some_and(|stamp| stamp.len() == 20 && stamp.ends_with('Z'))
        );

        // the weak attribution carries a null id and never overstates
        let weak = EmailReport {
            provenance: crate::output::Provenance::now(env!("CARGO_PKG_VERSION")),
            email: "jane@acme.com".to_string(),
            account: Some(Account {
                login: "acme".to_string(),
                id: None,
                confidence: "repo-owner-weak".to_string(),
            }),
            evidence: None,
            candidate_accounts: Vec::new(),
        };
        let json = serde_json::to_value(&weak).expect("must serialize");
        assert_eq!(json["account"]["confidence"], "repo-owner-weak");
        assert!(json["account"]["id"].is_null());

        // unmatched: account and evidence are null
        let unmatched = EmailReport {
            provenance: crate::output::Provenance::now(env!("CARGO_PKG_VERSION")),
            email: "jane@acme.com".to_string(),
            account: None,
            evidence: None,
            candidate_accounts: Vec::new(),
        };
        let json = serde_json::to_value(&unmatched).expect("must serialize");
        assert!(json["account"].is_null());
        assert!(json["evidence"].is_null());
        assert_eq!(json["candidates"], serde_json::json!([]));
    }

    #[test]
    fn bulk_report_serializes_the_list_plus_summary_shape() {
        let report = BulkReport {
            provenance: crate::output::Provenance::now(env!("CARGO_PKG_VERSION")),
            skipped_addresses: Vec::new(),
            results: vec![EmailReport {
                provenance: crate::output::Provenance::now(env!("CARGO_PKG_VERSION")),
                email: "jane@acme.com".to_string(),
                account: None,
                evidence: None,
                candidate_accounts: Vec::new(),
            }],
            summary: BulkSummary {
                total: 1,
                matched: 0,
                unmatched: 1,
                skipped: 0,
            },
        };
        let json = serde_json::to_value(&report).expect("must serialize");
        assert_eq!(json["results"][0]["email"], "jane@acme.com");
        assert!(json["results"][0]["account"].is_null());
        assert_eq!(
            json["summary"],
            serde_json::json!({"total": 1, "matched": 0, "unmatched": 1, "skipped": 0})
        );
        // the provenance is universal: top level AND per results entry
        // (each entry stamps the moment its own lookup finished)
        assert_eq!(json["tool_version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(
            json["results"][0]["tool_version"],
            env!("CARGO_PKG_VERSION")
        );
        assert!(
            json["skipped_addresses"]
                .as_array()
                .is_some_and(Vec::is_empty)
        );
    }

    #[test]
    fn the_terminal_report_sanitizes_the_untrusted_strings_it_prints() {
        // the CHANGELOG 0.7.0 claim is pinned at the wiring level, not only
        // at the sanitizer helper: a dropped `log_safe()` call must fail
        // this test (capturing logger, see `crate::test_logger`)
        let report = EmailReport {
            provenance: crate::output::Provenance::now(env!("CARGO_PKG_VERSION")),
            email: "jane@acme.com".to_string(),
            account: Some(Account {
                login: "ev\u{1b}[31mil\n".to_string(),
                id: Some(42),
                confidence: CONFIDENCE_COMMIT_AUTHOR.to_string(),
            }),
            evidence: Some(Evidence {
                repository: "acme/lib".to_string(),
                commit_sha: Some("abc123".to_string()),
                author_email: "jane@acme.com".to_string(),
            }),
            candidate_accounts: Vec::new(),
        };
        let (_, lines) = crate::test_logger::capture(|| log_report(&report, 1));
        assert!(
            !lines
                .iter()
                .any(|line| line.contains('\x1b') || line.contains('\n')),
            "a hostile payload must not forge or recolor a log line: {lines:?}"
        );
        assert!(
            lines.iter().any(|line| line.contains("ev_[31mil_")),
            "{lines:?}"
        );
    }

    // ---- offline end-to-end coverage (loopback mock, no real GitHub call) ----

    fn mock_commits_body(commits: &str) -> String {
        format!("[{commits}]")
    }

    fn commit_json(sha: &str, email: &str, author: serde_json::Value) -> String {
        serde_json::json!({
            "sha": sha,
            "author": author,
            "commit": { "author": { "email": email } }
        })
        .to_string()
    }

    #[test]
    fn a_match_found_via_the_commit_author_object_resolves_the_account() {
        let (address, server) = crate::github::mock::serve_requests(move |index, request| {
            let line = request.first().map(String::as_str).unwrap_or("");
            if line.contains("/search/repositories") {
                if crate::github::mock::request_line_page(request) > 1 {
                    return (200, vec![], r#"{"items": null}"#.to_string());
                }
                return (
                    200,
                    vec![],
                    r#"{"items": [{"html_url": "https://github.com/acme/lib"}]}"#.to_string(),
                );
            }
            if line.contains("/repos/acme/lib/commits") {
                return match crate::github::mock::request_line_page(request) {
                    1 => (
                        200,
                        vec![],
                        mock_commits_body(&commit_json(
                            "abc123",
                            "jane@acme.com",
                            serde_json::json!({ "login": "janedoe", "id": 42 }),
                        )),
                    ),
                    _ => (200, vec![], "[]".to_string()),
                };
            }
            let _ = index;
            (404, vec![], String::new())
        });

        let client = crate::github::Client::anonymous().expect("client must build");
        let (report, searched) =
            reverse_at(&client, &address, "jane@acme.com").expect("the lookup must succeed");
        server.join();

        assert_eq!(searched, 1);
        assert_eq!(report.email, "jane@acme.com");
        let account = report.account.expect("the commit author must resolve");
        assert_eq!(account.login, "janedoe");
        assert_eq!(account.id, Some(42));
        assert_eq!(account.confidence, "commit-author");
        let evidence = report.evidence.expect("the evidence must be present");
        assert_eq!(evidence.repository, "acme/lib");
        assert_eq!(evidence.commit_sha.as_deref(), Some("abc123"));
        assert_eq!(evidence.author_email, "jane@acme.com");
        assert_eq!(report.candidate_accounts.len(), 1);
        assert_eq!(report.candidate_accounts[0].confidence, "commit-author");
    }

    #[test]
    fn a_rejected_422_candidate_search_costs_its_query_not_the_whole_lookup() {
        // GitHub answers a rejected `q` (an over-long or odd local part) with
        // a 422: per the module's own "a rejected query costs its candidates"
        // rule, the lookup must skip that query and let the next one run
        // instead of aborting the whole reverse lookup with a raw HTTP error
        let (address, server) = crate::github::mock::serve_requests(move |_index, request| {
            let line = request.first().map(String::as_str).unwrap_or("");
            if line.contains("/search/repositories") {
                if line.contains("q=jane%20dupont") {
                    // the local-part-tokens query is rejected outright
                    return (
                        422,
                        vec![],
                        r#"{"message": "Validation Failed"}"#.to_string(),
                    );
                }
                if crate::github::mock::request_line_page(request) > 1 {
                    return (200, vec![], r#"{"items": null}"#.to_string());
                }
                return (
                    200,
                    vec![],
                    r#"{"items": [{"html_url": "https://github.com/acme/lib"}]}"#.to_string(),
                );
            }
            if line.contains("/repos/acme/lib/commits") {
                return match crate::github::mock::request_line_page(request) {
                    1 => (
                        200,
                        vec![],
                        mock_commits_body(&commit_json(
                            "abc123",
                            "jane.dupont@acme.com",
                            serde_json::json!({ "login": "janedoe", "id": 42 }),
                        )),
                    ),
                    _ => (200, vec![], "[]".to_string()),
                };
            }
            (404, vec![], String::new())
        });

        let client = crate::github::Client::anonymous().expect("client must build");
        let (report, searched) =
            reverse_at(&client, &address, "jane.dupont@acme.com").expect("the lookup must succeed");
        server.join();

        // the raw-local-part query ran after the rejected one and resolved
        // the account through its candidate's commits
        assert_eq!(searched, 1);
        let account = report.account.expect("the commit author must resolve");
        assert_eq!(account.login, "janedoe");
        assert_eq!(account.confidence, "commit-author");
    }

    #[test]
    fn a_409_empty_candidate_repository_is_skipped_and_the_lookup_continues() {
        // GitHub answers 409 Conflict on /commits for a repository with no
        // commits: a candidate in that state must be skipped with a warning
        // and the remaining candidates still verified, not abort the whole
        // reverse lookup with a raw HTTP error
        let (address, server) = crate::github::mock::serve_requests(move |_index, request| {
            let line = request.first().map(String::as_str).unwrap_or("");
            if line.contains("/search/repositories") {
                if crate::github::mock::request_line_page(request) > 1 {
                    return (200, vec![], r#"{"items": null}"#.to_string());
                }
                return (
                    200,
                    vec![],
                    r#"{"items": [{"html_url": "https://github.com/acme/empty"}, {"html_url": "https://github.com/acme/lib"}]}"#.to_string(),
                );
            }
            if line.contains("/repos/acme/empty/commits") {
                // the empty candidate: GitHub's documented 409
                return (
                    409,
                    vec![],
                    r#"{"message": "Git Repository is empty."}"#.to_string(),
                );
            }
            if line.contains("/repos/acme/lib/commits") {
                return match crate::github::mock::request_line_page(request) {
                    1 => (
                        200,
                        vec![],
                        mock_commits_body(&commit_json(
                            "abc123",
                            "jane@acme.com",
                            serde_json::json!({ "login": "janedoe", "id": 42 }),
                        )),
                    ),
                    _ => (200, vec![], "[]".to_string()),
                };
            }
            (404, vec![], String::new())
        });

        let client = crate::github::Client::anonymous().expect("client must build");
        let (report, searched) = reverse_at(&client, &address, "jane@acme.com")
            .expect("an empty candidate must not abort the lookup");
        server.join();

        // the 409 candidate was skipped without being counted as verified;
        // the lookup continued to the next candidate and matched there
        assert_eq!(searched, 1);
        let account = report.account.expect("the lookup must continue");
        assert_eq!(account.login, "janedoe");
        assert_eq!(account.confidence, "commit-author");
    }

    #[test]
    fn a_404_deleted_candidate_repository_is_skipped_and_the_lookup_continues() {
        // mirror of the 409 test: a candidate whose /commits listing answers
        // 404 (a deleted repository, or a stale search-index entry) is
        // resource-scoped too - it must be skipped with a warning and the
        // remaining candidates still verified, not abort the whole reverse
        // lookup with a raw HTTP error
        let (address, server) = crate::github::mock::serve_requests(move |_index, request| {
            let line = request.first().map(String::as_str).unwrap_or("");
            if line.contains("/search/repositories") {
                if crate::github::mock::request_line_page(request) > 1 {
                    return (200, vec![], r#"{"items": null}"#.to_string());
                }
                return (
                    200,
                    vec![],
                    r#"{"items": [{"html_url": "https://github.com/acme/deleted"}, {"html_url": "https://github.com/acme/lib"}]}"#.to_string(),
                );
            }
            if line.contains("/repos/acme/deleted/commits") {
                // the deleted candidate: GitHub's 404
                return (404, vec![], String::new());
            }
            if line.contains("/repos/acme/lib/commits") {
                return match crate::github::mock::request_line_page(request) {
                    1 => (
                        200,
                        vec![],
                        mock_commits_body(&commit_json(
                            "abc123",
                            "jane@acme.com",
                            serde_json::json!({ "login": "janedoe", "id": 42 }),
                        )),
                    ),
                    _ => (200, vec![], "[]".to_string()),
                };
            }
            (404, vec![], String::new())
        });

        let client = crate::github::Client::anonymous().expect("client must build");
        let (report, searched) = reverse_at(&client, &address, "jane@acme.com")
            .expect("a deleted candidate must not abort the lookup");
        server.join();

        // the 404 candidate was skipped without being counted as verified;
        // the lookup continued to the next candidate and matched there
        assert_eq!(searched, 1);
        let account = report.account.expect("the lookup must continue");
        assert_eq!(account.login, "janedoe");
        assert_eq!(account.confidence, "commit-author");
    }

    #[test]
    fn a_commit_without_an_author_object_falls_back_to_a_weak_repo_owner_candidate() {
        let (address, server) = crate::github::mock::serve_requests(move |index, request| {
            let line = request.first().map(String::as_str).unwrap_or("");
            if line.contains("/search/repositories") {
                if crate::github::mock::request_line_page(request) > 1 {
                    return (200, vec![], r#"{"items": null}"#.to_string());
                }
                return (
                    200,
                    vec![],
                    r#"{"items": [{"html_url": "https://github.com/acme/lib"}]}"#.to_string(),
                );
            }
            if line.contains("/repos/acme/lib/commits") {
                // a deleted account: the commit matched but "author" is null
                return match crate::github::mock::request_line_page(request) {
                    1 => (
                        200,
                        vec![],
                        mock_commits_body(&commit_json(
                            "def456",
                            "jane@acme.com",
                            serde_json::Value::Null,
                        )),
                    ),
                    _ => (200, vec![], "[]".to_string()),
                };
            }
            let _ = index;
            (404, vec![], String::new())
        });

        let client = crate::github::Client::anonymous().expect("client must build");
        let (report, searched) =
            reverse_at(&client, &address, "jane@acme.com").expect("the lookup must succeed");
        server.join();

        assert_eq!(searched, 1);
        let account = report.account.expect("the weak candidate must surface");
        assert_eq!(account.login, "acme");
        assert_eq!(
            account.id, None,
            "a weak attribution never fabricates an id"
        );
        assert_eq!(account.confidence, "repo-owner-weak");
        assert_eq!(
            report.evidence.expect("evidence").commit_sha.as_deref(),
            Some("def456")
        );
    }

    #[test]
    fn an_unmatched_address_is_reported_as_unmatched_not_an_error() {
        let (address, server) = crate::github::mock::serve_requests(move |index, request| {
            let line = request.first().map(String::as_str).unwrap_or("");
            if line.contains("/search/repositories") {
                if crate::github::mock::request_line_page(request) > 1 {
                    return (200, vec![], r#"{"items": null}"#.to_string());
                }
                return (
                    200,
                    vec![],
                    r#"{"items": [{"html_url": "https://github.com/acme/lib"}]}"#.to_string(),
                );
            }
            if line.contains("/repos/acme/lib/commits") {
                return match crate::github::mock::request_line_page(request) {
                    1 => (
                        200,
                        vec![],
                        mock_commits_body(&commit_json(
                            "def456",
                            "bob@other.org",
                            serde_json::json!({ "login": "bob", "id": 7 }),
                        )),
                    ),
                    _ => (200, vec![], "[]".to_string()),
                };
            }
            let _ = index;
            (404, vec![], String::new())
        });

        let client = crate::github::Client::anonymous().expect("client must build");
        let (report, searched) = reverse_at(&client, &address, "jane@acme.com")
            .expect("an unmatched address is not an error");
        server.join();

        assert_eq!(
            searched, 1,
            "the repository was verified even without a match"
        );
        assert!(report.account.is_none());
        assert!(report.evidence.is_none());
        assert!(report.candidate_accounts.is_empty());
    }

    #[test]
    fn noreply_addresses_are_rejected_before_any_network_request() {
        // no mock server: any request would panic the test by connection
        // refusal, proving nothing reaches the wire
        let client = crate::github::Client::anonymous().expect("client must build");
        let error = reverse_at(
            &client,
            "http://127.0.0.1:1",
            "12345+jane@users.noreply.github.com",
        )
        .expect_err("a noreply address must be rejected upfront");
        assert!(matches!(error, Error::NoreplyEmail(_)));
    }

    #[test]
    fn the_commits_listing_is_never_narrowed_by_an_author_filter() {
        // the commits API `author` parameter would silently drop the target's
        // own commits whenever the commit author login differs from the email
        // local part (the exact false negative the heuristic must not have):
        // the listing is always fetched unfiltered, whatever the local shape
        let requests: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&requests);
        let (address, server) = crate::github::mock::serve_requests(move |_index, request| {
            if let Some(line) = request.first()
                && let Ok(mut log) = recorded.lock()
            {
                log.push(line.clone());
            }
            let line = request.first().map(String::as_str).unwrap_or("");
            if line.contains("/search/repositories") {
                if crate::github::mock::request_line_page(request) > 1 {
                    return (200, vec![], r#"{"items": null}"#.to_string());
                }
                return (
                    200,
                    vec![],
                    r#"{"items": [{"html_url": "https://github.com/acme/lib"}]}"#.to_string(),
                );
            }
            if line.contains("/repos/acme/lib/commits") {
                return (200, vec![], "[]".to_string());
            }
            (404, vec![], String::new())
        });

        let client = crate::github::Client::anonymous().expect("client must build");
        // "jane" follows GitHub's username shape and "jane.dupont" cannot be
        // a login: neither may narrow the commits listing
        reverse_at(&client, &address, "jane@acme.com").expect("the lookup must succeed");
        reverse_at(&client, &address, "jane.dupont@acme.com").expect("the lookup must succeed");
        server.join();

        let requests = requests.lock().expect("request log must lock");
        let commit_requests: Vec<&String> = requests
            .iter()
            .filter(|line| line.contains("/repos/acme/lib/commits"))
            .collect();
        assert_eq!(commit_requests.len(), 2);
        assert!(
            commit_requests.iter().all(|line| !line.contains("author=")),
            "no commits listing may be narrowed by an author filter: {commit_requests:?}"
        );
    }

    #[test]
    fn the_lookup_stops_early_once_a_commit_author_attribution_is_found() {
        let (address, server) = crate::github::mock::serve_requests(move |index, request| {
            let line = request.first().map(String::as_str).unwrap_or("");
            if line.contains("/search/repositories") {
                // two candidate repositories returned
                if crate::github::mock::request_line_page(request) > 1 {
                    return (200, vec![], r#"{"items": null}"#.to_string());
                }
                return (
                    200,
                    vec![],
                    r#"{"items": [{"html_url": "https://github.com/acme/lib"}, {"html_url": "https://github.com/acme/other"}]}"#.to_string(),
                );
            }
            if line.contains("/repos/acme/lib/commits") {
                return match crate::github::mock::request_line_page(request) {
                    1 => (
                        200,
                        vec![],
                        mock_commits_body(&commit_json(
                            "abc123",
                            "jane@acme.com",
                            serde_json::json!({ "login": "janedoe", "id": 42 }),
                        )),
                    ),
                    _ => (200, vec![], "[]".to_string()),
                };
            }
            if line.contains("/repos/acme/other/commits") {
                // a strong match in the first repository must make the
                // lookup stop before ever requesting this one
                panic!("the second repository must not be requested after a strong match");
            }
            let _ = index;
            (404, vec![], String::new())
        });

        let client = crate::github::Client::anonymous().expect("client must build");
        let (report, searched) =
            reverse_at(&client, &address, "jane@acme.com").expect("the lookup must succeed");
        let handled = server.join();

        assert_eq!(report.account.expect("matched").login, "janedoe");
        assert_eq!(searched, 1, "only the first repository was verified");
        // one search page per query (each page is short, so it ends its
        // listing without the empty page) plus 1 commits page with the match,
        // which is short too: its listing ends on the short page and the
        // trailing empty-page request is never spent (the page-size-aware
        // walk - up to one wasted request per candidate is material against
        // the anonymous hourly budget)
        assert_eq!(handled, 3);
    }

    #[test]
    fn a_candidate_query_that_fills_the_1000_result_window_warns_about_it() {
        // the documented search window: a query whose raw items fill it
        // (10 full pages of 100) stops on the window cut, not on a listing
        // end - the warning must say candidates beyond it were never seen
        // instead of ending silently
        let (address, server) = crate::github::mock::serve_requests(move |_index, request| {
            let line = request.first().map(String::as_str).unwrap_or("");
            if line.contains("/search/repositories") {
                let items: Vec<String> = (0..100)
                    .map(|i| format!(r#"{{"html_url": "https://github.com/acme/repo{}"}}"#, i))
                    .collect();
                return (
                    200,
                    vec![],
                    format!(r#"{{"items": [{}]}}"#, items.join(",")),
                );
            }
            if line.contains("/repos/acme/") {
                return (200, vec![], "[]".to_string());
            }
            (404, vec![], String::new())
        });

        let client = crate::github::Client::anonymous().expect("client must build");
        let ((report, _searched), lines) = crate::test_logger::capture(|| {
            reverse_at(&client, &address, "jane@acme.com").expect("the lookup must succeed")
        });
        server.join();

        assert!(report.account.is_none());
        assert!(
            lines
                .iter()
                .any(|line| line.contains("reached GitHub's 1000-result window")),
            "the window cut must warn about the candidates it hid: {lines:?}"
        );
    }

    #[test]
    fn a_full_page_of_distinct_candidates_is_kept_whole_with_no_local_cap() {
        // no local candidate cap: every candidate the search serves is
        // verified. A full page of 100 distinct candidates on the first
        // query keeps all 100 (the old 50-budget would have thrown half),
        // and the walk continues to the next page instead of ending on the
        // budget's short-page signal
        let requests: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&requests);
        let (address, server) = crate::github::mock::serve_requests(move |_index, request| {
            if let Some(line) = request.first()
                && let Ok(mut log) = recorded.lock()
            {
                log.push(line.clone());
            }
            let line = request.first().map(String::as_str).unwrap_or("");
            if line.contains("/search/repositories") {
                let page = crate::github::mock::request_line_page(request);
                if page == 1 {
                    let items: Vec<String> = (0..100)
                        .map(|i| format!(r#"{{"html_url": "https://github.com/acme/repo{i}"}}"#))
                        .collect();
                    return (
                        200,
                        vec![],
                        format!(r#"{{"items": [{}]}}"#, items.join(",")),
                    );
                }
                // page 2: the short page that ends the listing
                return (200, vec![], r#"{"items": []}"#.to_string());
            }
            if line.contains("/repos/acme/") {
                return (200, vec![], "[]".to_string());
            }
            (404, vec![], String::new())
        });

        let client = crate::github::Client::anonymous().expect("client must build");
        let ((report, searched), _lines) = crate::test_logger::capture(|| {
            reverse_at(&client, &address, "jane@acme.com").expect("the lookup must succeed")
        });
        server.join();

        assert!(report.account.is_none());
        assert_eq!(
            searched, 100,
            "every candidate the first query serves must be verified"
        );
        let requests = requests.lock().expect("request log must lock");
        assert_eq!(
            requests
                .iter()
                .filter(|line| line.contains("/search/"))
                .count(),
            4,
            "a full page must NOT end the walk: each of the address's two \
             queries (the local part, the domain) walks its own page 1 + \
             the page-2 listing end"
        );
    }

    #[test]
    fn raw_duplicates_inside_one_page_never_dilute_the_candidates() {
        // a page mixing 50 distinct candidates with 50 repeats of the
        // first: deduplication keeps the 50 distinct ones and the raw
        // repeats change nothing (the raw count still feeds the walk's
        // pagination, not the candidate list)
        let (address, server) = crate::github::mock::serve_requests(move |_index, request| {
            let line = request.first().map(String::as_str).unwrap_or("");
            if line.contains("/search/repositories") {
                let mut items: Vec<String> = (0..50)
                    .map(|i| format!(r#"{{"html_url": "https://github.com/acme/repo{i}"}}"#))
                    .collect();
                items.extend(
                    (0..50).map(|_| r#"{"html_url": "https://github.com/acme/repo0"}"#.to_string()),
                );
                return (
                    200,
                    vec![],
                    format!(r#"{{"items": [{}]}}"#, items.join(",")),
                );
            }
            if line.contains("/repos/acme/") {
                return (200, vec![], "[]".to_string());
            }
            (404, vec![], String::new())
        });

        let client = crate::github::Client::anonymous().expect("client must build");
        let ((_, searched), _lines) = crate::test_logger::capture(|| {
            reverse_at(&client, &address, "jane@acme.com").expect("the lookup must succeed")
        });
        server.join();

        assert_eq!(searched, 50);
    }

    #[test]
    fn the_commit_verification_walks_each_candidates_full_history() {
        let (address, server) = crate::github::mock::serve_requests(move |_index, request| {
            let line = request.first().map(String::as_str).unwrap_or("");
            if line.contains("/search/repositories") {
                // a full page of 100 hits, all the same repository: the
                // candidate cap is filled by the first query (and the dedup
                // keeps one candidate), so the listing ends on the next,
                // empty page
                let page = crate::github::mock::request_line_page(request);
                return if page == 1 {
                    let items: Vec<String> = (0..100)
                        .map(|_| r#"{"html_url": "https://github.com/acme/lib"}"#.to_string())
                        .collect();
                    (
                        200,
                        vec![],
                        format!(r#"{{"items": [{}]}}"#, items.join(",")),
                    )
                } else {
                    (200, vec![], r#"{"items": []}"#.to_string())
                };
            }
            if line.contains("/repos/acme/") {
                // 11 full pages of commits, none matching the target, then
                // the short 12th page that ends the listing: the candidate's
                // FULL history is walked (the old 10-page budget would have
                // cut the last two pages)
                let page = crate::github::mock::request_line_page(request);
                let count = if page <= 11 { 100 } else { 37 };
                let commits: Vec<String> = (0..count)
                    .map(|i| {
                        commit_json(
                            &format!("sha{page}-{i}"),
                            "bob@other.org",
                            serde_json::json!({ "login": "bob", "id": 7 }),
                        )
                    })
                    .collect();
                return (200, vec![], format!("[{}]", commits.join(",")));
            }
            (404, vec![], String::new())
        });

        let client = crate::github::Client::anonymous().expect("client must build");
        let (report, searched) =
            reverse_at(&client, &address, "jane@acme.com").expect("the lookup must succeed");
        let handled = server.join();

        assert!(report.account.is_none());
        assert_eq!(searched, 1);
        // each of the two queries walks its full listing (a page of raw
        // duplicates must not stop the walk before the fresh hits of its
        // later pages): a full page then the empty page that ends it, plus
        // the candidate's full 12-page history (11 full + 1 short)
        assert_eq!(handled, 4 + 12);
    }

    #[test]
    fn duplicate_hits_are_deduplicated_and_fresh_candidates_are_all_kept() {
        // the second query's page leads with the two candidates the first
        // query already collected: deduplication keeps the FRESH candidates
        // behind them, so no stale cap hides the candidates the duplicates
        // would have evicted
        let (address, server) = crate::github::mock::serve_requests(move |_index, request| {
            let line = request.first().map(String::as_str).unwrap_or("");
            if line.contains("/search/repositories") {
                let page = crate::github::mock::request_line_page(request);
                if line.contains("q=jane%20dupont") {
                    // first query: two candidate repositories, then the
                    // empty page that ends the listing
                    return if page == 1 {
                        (
                            200,
                            vec![],
                            r#"{"items": [{"html_url": "https://github.com/acme/one"}, {"html_url": "https://github.com/acme/two"}]}"#.to_string(),
                        )
                    } else {
                        (200, vec![], r#"{"items": []}"#.to_string())
                    };
                }
                if line.contains("q=jane.dupont") {
                    // second query: the page leads with the two
                    // already-collected candidates, then 98 distinct new
                    // ones: all 98 fresh candidates are kept - the page
                    // leads with duplicates but no cap throws anything away
                    let mut items: Vec<String> = vec![
                        r#"{"html_url": "https://github.com/acme/one"}"#.to_string(),
                        r#"{"html_url": "https://github.com/acme/two"}"#.to_string(),
                    ];
                    items.extend(
                        (0..98).map(|i| {
                            format!(r#"{{"html_url": "https://github.com/acme/lib{i}"}}"#)
                        }),
                    );
                    return (
                        200,
                        vec![],
                        format!(r#"{{"items": [{}]}}"#, items.join(",")),
                    );
                }
                // the domain query's listing
                return (200, vec![], r#"{"items": []}"#.to_string());
            }
            if line.contains("/repos/") {
                // empty commit listing for every candidate
                return (200, vec![], "[]".to_string());
            }
            (404, vec![], String::new())
        });

        let client = crate::github::Client::anonymous().expect("client must build");
        let (report, searched) =
            reverse_at(&client, &address, "jane.dupont@acme.com").expect("the lookup must succeed");
        server.join();

        assert!(report.account.is_none());
        assert_eq!(
            searched, 100,
            "the two lead duplicates are deduplicated, the 98 fresh candidates are all kept (no cap eats them)"
        );
    }

    #[test]
    fn a_full_page_of_duplicates_keeps_the_query_walk_alive() {
        // the second query's first page holds only candidates the first
        // query already collected: the raw duplicates must not stop the
        // walk (nor eat its budget) before the fresh hits of its second
        // page are reached
        let (address, server) = crate::github::mock::serve_requests(move |_index, request| {
            let line = request.first().map(String::as_str).unwrap_or("");
            if line.contains("/search/repositories") {
                let page = crate::github::mock::request_line_page(request);
                if line.contains("q=jane%20dupont") {
                    // first query: three candidate repositories, then the
                    // empty page that ends the listing
                    return if page == 1 {
                        (
                            200,
                            vec![],
                            r#"{"items": [{"html_url": "https://github.com/acme/one"}, {"html_url": "https://github.com/acme/two"}, {"html_url": "https://github.com/acme/three"}]}"#
                                .to_string(),
                        )
                    } else {
                        (200, vec![], r#"{"items": []}"#.to_string())
                    };
                }
                if line.contains("q=acme.com") {
                    // the third query is never reached in a meaningful way:
                    // answer an empty listing
                    return (200, vec![], r#"{"items": []}"#.to_string());
                }
                // second query: a full page of raw hits that are all
                // duplicates of the first query's candidates, then a short
                // page with two fresh ones
                return if page == 1 {
                    let items: Vec<String> = (0..100)
                        .map(|i| {
                            format!(
                                r#"{{"html_url": "https://github.com/acme/{}"}}"#,
                                ["one", "two", "three"][i % 3]
                            )
                        })
                        .collect();
                    (
                        200,
                        vec![],
                        format!(r#"{{"items": [{}]}}"#, items.join(",")),
                    )
                } else {
                    (
                        200,
                        vec![],
                        r#"{"items": [{"html_url": "https://github.com/acme/four"}, {"html_url": "https://github.com/acme/five"}]}"#
                            .to_string(),
                    )
                };
            }
            if line.contains("/repos/") {
                // empty commit listing for every candidate
                return (200, vec![], "[]".to_string());
            }
            (404, vec![], String::new())
        });

        let client = crate::github::Client::anonymous().expect("client must build");
        let (report, searched) =
            reverse_at(&client, &address, "jane.dupont@acme.com").expect("the lookup must succeed");
        let handled = server.join();

        assert!(report.account.is_none());
        assert_eq!(
            searched, 5,
            "the fresh hits of the second page must be reached past the full page of duplicates"
        );
        // first query: page 1 (short) ends its listing; second query: the
        // full page of duplicates keeps the walk alive, the short page 2
        // ends it; the third query ends on its empty page; then one empty
        // commit listing per candidate
        assert_eq!(handled, 4 + 5);
    }

    #[test]
    fn all_distinct_candidates_survive_across_a_querys_pages() {
        // two full pages per query, the same listing served to each of the
        // address's three queries (the folded name, the raw local part, the
        // domain): 30 distinct candidates on the first page (the rest are
        // its own repeats), then 70 distinct ones on the second (plus
        // repeats): NO cap truncates anything - all 100 distinct candidates
        // are kept, and each query's walk continues to the short page that
        // ends the listing
        let (address, server) = crate::github::mock::serve_requests(move |_index, request| {
            let line = request.first().map(String::as_str).unwrap_or("");
            if line.contains("/search/repositories") {
                let page = crate::github::mock::request_line_page(request);
                let items: Vec<String> = match page {
                    1 => {
                        // the 30 distinct candidates first, then 70 repeats
                        // of the first one to fill the page
                        let mut items: Vec<String> = (0..30)
                            .map(|i| {
                                format!(r#"{{"html_url": "https://github.com/acme/repo{i}"}}"#)
                            })
                            .collect();
                        let first = items[0].clone();
                        items.resize(100, first);
                        items
                    }
                    2 => {
                        // 70 fresh candidates, then 30 repeats of the first
                        // one to fill the page
                        let mut items: Vec<String> = (30..100)
                            .map(|i| {
                                format!(r#"{{"html_url": "https://github.com/acme/repo{i}"}}"#)
                            })
                            .collect();
                        let first = items[0].clone();
                        items.resize(100, first);
                        items
                    }
                    // the short page that ends the listing
                    _ => return (200, vec![], r#"{"items": []}"#.to_string()),
                };
                return (
                    200,
                    vec![],
                    format!(r#"{{"items": [{}]}}"#, items.join(",")),
                );
            }
            if line.contains("/repos/") {
                return (200, vec![], "[]".to_string());
            }
            (404, vec![], String::new())
        });

        let client = crate::github::Client::anonymous().expect("client must build");
        let (report, searched) =
            reverse_at(&client, &address, "jane@acme.com").expect("the lookup must succeed");
        let handled = server.join();

        assert!(report.account.is_none());
        assert_eq!(
            searched, 100,
            "every distinct candidate across the query's pages must be kept (no cap)"
        );
        // each of the three queries walks page 1 + the short page 2 that
        // ends its listing (6 search pages), plus one empty commit listing
        // per candidate
        assert_eq!(handled, 6 + 100);
    }

    #[test]
    fn bulk_reverse_runs_over_multiple_tokens_in_parallel_and_keeps_the_file_order() {
        let authorizations: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&authorizations);
        let (address, server) = crate::github::mock::serve_requests(move |index, request| {
            if let Some(auth) = crate::github::mock::request_header(request, "Authorization")
                && let Ok(mut log) = recorded.lock()
            {
                log.push(auth.to_string());
            }
            // one fast worker can drain the whole two-address queue before
            // the other worker's thread is first scheduled (loopback
            // processing takes milliseconds, a thread start under a loaded
            // test runner can take tens or hundreds): every request of this
            // test - searches included - is issued by a bulk worker's own
            // client, so parking every response except the very first gives
            // the fast worker a long hold on its address and leaves the
            // second worker time to claim the other one
            if index > 0 {
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            let line = request.first().map(String::as_str).unwrap_or("");
            if line.contains("/search/repositories") {
                // each address resolves to its own repository
                if crate::github::mock::request_line_page(request) > 1 {
                    return (200, vec![], r#"{"items": null}"#.to_string());
                }
                let repo = if line.contains("q=alice") {
                    "acme/one"
                } else {
                    "acme/two"
                };
                return (
                    200,
                    vec![],
                    format!(r#"{{"items": [{{"html_url": "https://github.com/{repo}"}}]}}"#),
                );
            }
            if line.contains("/repos/acme/one/commits") {
                return match crate::github::mock::request_line_page(request) {
                    1 => (
                        200,
                        vec![],
                        mock_commits_body(&commit_json(
                            "sha1",
                            "alice@acme.com",
                            serde_json::json!({ "login": "alicegh", "id": 1 }),
                        )),
                    ),
                    _ => (200, vec![], "[]".to_string()),
                };
            }
            if line.contains("/repos/acme/two/commits") {
                return match crate::github::mock::request_line_page(request) {
                    1 => (
                        200,
                        vec![],
                        mock_commits_body(&commit_json(
                            "sha2",
                            "bob@acme.com",
                            serde_json::json!({ "login": "bobgh", "id": 2 }),
                        )),
                    ),
                    _ => (200, vec![], "[]".to_string()),
                };
            }
            (404, vec![], String::new())
        });

        // two tokens: two workers, one dedicated token each
        let token_path = std::env::temp_dir().join(format!(
            "git2mail_email_bulk_tokens_{}.json",
            std::process::id()
        ));
        std::fs::write(&token_path, r#"{"0": "ghp_a", "1": "ghp_b"}"#)
            .expect("test setup: write token file");
        let scanner = Scanner::new(None, Some(&token_path)).expect("scanner must build");
        std::fs::remove_file(&token_path).ok();

        let (report, failure) = reverse_bulk_at(
            &scanner,
            &address,
            &["alice@acme.com".to_string(), "bob@acme.com".to_string()],
        );
        assert!(failure.is_none(), "the bulk run must succeed");
        server.join();

        // the results are in file order, whatever worker picked what
        assert_eq!(report.results.len(), 2);
        assert_eq!(report.results[0].email, "alice@acme.com");
        assert_eq!(
            report.results[0].account.as_ref().expect("matched").login,
            "alicegh"
        );
        assert_eq!(report.results[1].email, "bob@acme.com");
        assert_eq!(
            report.results[1].account.as_ref().expect("matched").login,
            "bobgh"
        );
        assert_eq!(
            report.summary,
            BulkSummary {
                total: 2,
                matched: 2,
                unmatched: 0,
                skipped: 0
            }
        );

        // both dedicated tokens were used by the workers
        let authorizations = authorizations.lock().expect("request log must lock");
        assert!(
            authorizations.iter().any(|a| a.contains("ghp_a"))
                && authorizations.iter().any(|a| a.contains("ghp_b")),
            "both dedicated tokens must be exercised by the workers: {authorizations:?}"
        );
    }

    #[test]
    fn a_401_on_a_dedicated_token_ends_only_its_bulk_worker() {
        // the 0.5.0 contract, bulk shape: one revoked token stops its own
        // worker while the other tokens keep draining the address queue; the
        // address the dead worker never finished is reported as skipped,
        // never as a verified no-match
        let (address, server) = crate::github::mock::serve_requests(move |_index, request| {
            let line = request.first().map(String::as_str).unwrap_or("");
            if line.contains("/search/repositories") {
                // the revoked token's address: the API rejects every request
                if line.contains("q=dead") || line.contains("q=evil") {
                    return (401, vec![], String::new());
                }
                // the healthy address's candidate queries
                if crate::github::mock::request_line_page(request) > 1 {
                    return (200, vec![], r#"{"items": null}"#.to_string());
                }
                return (
                    200,
                    vec![],
                    r#"{"items": [{"html_url": "https://github.com/acme/one"}]}"#.to_string(),
                );
            }
            if line.contains("/repos/acme/one/commits") {
                return match crate::github::mock::request_line_page(request) {
                    1 => (
                        200,
                        vec![],
                        mock_commits_body(&commit_json(
                            "sha1",
                            "jane@acme.com",
                            serde_json::json!({ "login": "janedoe", "id": 9 }),
                        )),
                    ),
                    _ => (200, vec![], "[]".to_string()),
                };
            }
            (404, vec![], String::new())
        });

        // two dedicated tokens: whichever worker pulls the 401ing address
        // stops; the other one drains the remaining addresses
        let token_path = std::env::temp_dir().join(format!(
            "git2mail_email_bulk_401_tokens_{}.json",
            std::process::id()
        ));
        std::fs::write(&token_path, r#"{"0": "ghp_a", "1": "ghp_b"}"#)
            .expect("test setup: write token file");
        let scanner = Scanner::new(None, Some(&token_path)).expect("scanner must build");
        std::fs::remove_file(&token_path).ok();

        let (report, failure) = reverse_bulk_at(
            &scanner,
            &address,
            &["dead@evil.com".to_string(), "jane@acme.com".to_string()],
        );
        assert!(
            failure.is_none(),
            "one revoked token must not abort the bulk run"
        );
        server.join();

        // the healthy address was fully processed and matched
        assert_eq!(report.results.len(), 1);
        assert_eq!(report.results[0].email, "jane@acme.com");
        assert_eq!(
            report.results[0].account.as_ref().expect("matched").login,
            "janedoe"
        );
        // the 401ing address was never processed: skipped, not unmatched
        assert_eq!(
            report.summary,
            BulkSummary {
                total: 1,
                matched: 1,
                unmatched: 0,
                skipped: 1
            }
        );
    }

    #[test]
    fn an_address_a_dead_worker_never_reached_is_skipped_not_unmatched() {
        let (address, server) = crate::github::mock::serve_requests(move |_index, request| {
            let line = request.first().map(String::as_str).unwrap_or("");
            if line.contains("/search/repositories") {
                // the first address resolves normally (its two queries)...
                if !line.contains("q=bob") {
                    if line.contains("q=alice")
                        && crate::github::mock::request_line_page(request) == 1
                    {
                        return (
                            200,
                            vec![],
                            r#"{"items": [{"html_url": "https://github.com/acme/one"}]}"#
                                .to_string(),
                        );
                    }
                    return (200, vec![], r#"{"items": null}"#.to_string());
                }
                // ...but the second address's first search request hits the
                // exhausted quota: the single worker's token died with the
                // second address still in the queue
                return (
                    403,
                    vec![("X-RateLimit-Remaining".to_string(), "0".to_string())],
                    String::new(),
                );
            }
            if line.contains("/repos/acme/one/commits") {
                return match crate::github::mock::request_line_page(request) {
                    1 => (
                        200,
                        vec![],
                        mock_commits_body(&commit_json(
                            "sha1",
                            "alice@x.com",
                            serde_json::json!({ "login": "alicegh", "id": 1 }),
                        )),
                    ),
                    _ => (200, vec![], "[]".to_string()),
                };
            }
            (404, vec![], String::new())
        });

        // one token: one worker, so the queue is not drained after its death
        let token_path = std::env::temp_dir().join(format!(
            "git2mail_email_skip_tokens_{}.json",
            std::process::id()
        ));
        std::fs::write(&token_path, r#"{"0": "ghp_a"}"#).expect("test setup: write token file");
        let scanner = Scanner::new(None, Some(&token_path)).expect("scanner must build");
        std::fs::remove_file(&token_path).ok();

        let (report, failure) = reverse_bulk_at(
            &scanner,
            &address,
            &["alice@x.com".to_string(), "bob@x.com".to_string()],
        );
        assert!(
            failure.is_none(),
            "a dead dedicated token with progress must not fail the bulk run"
        );
        server.join();

        // the processed address is reported normally; the address the worker
        // never reached is skipped: absent from `results` and counted as
        // `skipped`, never as a verified no-match
        assert_eq!(report.results.len(), 1);
        assert_eq!(report.results[0].email, "alice@x.com");
        assert_eq!(
            report.results[0].account.as_ref().expect("matched").login,
            "alicegh"
        );
        assert_eq!(
            report.summary,
            BulkSummary {
                total: 1,
                matched: 1,
                unmatched: 0,
                skipped: 1
            }
        );
    }

    #[test]
    fn an_abort_class_failure_logs_the_partial_bulk_results() {
        let (address, server) = crate::github::mock::serve_requests(move |_index, request| {
            let line = request.first().map(String::as_str).unwrap_or("");
            if line.contains("/search/repositories") {
                // the second address's first search request hits a transient
                // server error: an abort-class failure, not a token death
                if line.contains("q=doomed") {
                    return (500, vec![], String::new());
                }
                if line.contains("q=alice") && crate::github::mock::request_line_page(request) == 1
                {
                    return (
                        200,
                        vec![],
                        r#"{"items": [{"html_url": "https://github.com/acme/one"}]}"#.to_string(),
                    );
                }
                return (200, vec![], r#"{"items": null}"#.to_string());
            }
            if line.contains("/repos/acme/one/commits") {
                return match crate::github::mock::request_line_page(request) {
                    1 => (
                        200,
                        vec![],
                        mock_commits_body(&commit_json(
                            "sha1",
                            "alice@acme.com",
                            serde_json::json!({ "login": "alicegh", "id": 1 }),
                        )),
                    ),
                    _ => (200, vec![], "[]".to_string()),
                };
            }
            (404, vec![], String::new())
        });

        // one token: one worker processes the addresses in file order, so
        // the first lookup is complete when the second one aborts the run
        let scanner = Scanner::new(None, None).expect("scanner must build");
        let addresses_path = std::env::temp_dir().join(format!(
            "git2mail_bulk_abort_test_{}.txt",
            std::process::id()
        ));
        std::fs::write(&addresses_path, "alice@acme.com\ndoomed@acme.com\n")
            .expect("test setup: write addresses file");
        let ((report, failure), lines) = crate::test_logger::capture(|| {
            reverse_bulk_with_partial(&scanner, &address, &addresses_path)
        });
        assert!(failure.is_some(), "a 5xx mid-run must abort the bulk run");
        assert_eq!(
            report.results.len(),
            1,
            "the lookup completed before the failure must travel back with the error"
        );

        // the CLI wiring (main.rs) writes the partial report best-effort to
        // the requested --json file before propagating the abort: pin that
        // the tuple's report serializes to a usable file (the parity the
        // threat-intelligence persona asked for: 299 paid-for attributions
        // must not live only in a scrolled terminal)
        let json_path = std::env::temp_dir().join(format!(
            "git2mail_bulk_abort_json_{}.json",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&json_path);
        crate::output::write_report_json(&json_path, &report)
            .expect("the partial report must serialize");
        let parsed: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(&json_path).expect("the partial JSON must exist"),
        )
        .expect("the partial report must be valid JSON");
        assert_eq!(parsed["results"].as_array().map(Vec::len), Some(1));
        // the skipped inventory travels in the report, not only in the log:
        // an operator re-running the interrupted lookups reads the addresses
        // from the JSON instead of diffing two files
        assert_eq!(
            parsed["skipped_addresses"],
            serde_json::json!(["doomed@acme.com"])
        );
        assert_eq!(parsed["summary"]["skipped"], 1);
        // the provenance stamps the partial report too
        assert_eq!(parsed["tool_version"], env!("CARGO_PKG_VERSION"));
        std::fs::remove_file(&json_path).ok();
        std::fs::remove_file(&addresses_path).ok();
        server.join();

        // the address computed before the failure was logged, not erased:
        // the partial report is announced, then printed
        assert!(
            lines
                .iter()
                .any(|line| line.contains("the bulk run aborted early")),
            "the partial report must be announced: {lines:?}"
        );
        assert!(
            lines.iter().any(|line| line.contains("alicegh")),
            "the completed lookup must appear in the partial report: {lines:?}"
        );
    }
}
