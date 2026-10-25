//! Search scan: the repositories matching a query, scanned in parallel.

use crate::consts::GITHUB_API_BASE;
use crate::correlate::{Correlation, CorrelationBuilder, RepoContribution, RepoScan};
use crate::errors::Error;
use crate::github::fetch_paginated_with_page_size;
use crate::output::sanitize_log_text as log_safe;
use crate::parsers;
use crate::sources::{PER_PAGE, ScanOutcome, Scanner, merge_emails, sort_emails};
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};

/// Comparison prefixes accepted in front of a qualifier value (count or
/// date), following the github.com/search/advanced semantics. `>=` and
/// `<=` must be tried before `>` and `<`.
const COMPARISON_PREFIXES: [&str; 4] = [">=", "<=", ">", "<"];

/// What a parallel repository scan returns: the deduplicated emails found,
/// the emails found per repository (`owner/name` full name → sorted
/// emails, only the repositories where at least one email showed up), the
/// number of repositories actually scanned, the per-author correlation
/// report (issue #5) and the partial-token-death flag: `true` when the scan
/// returned its result although a dedicated token died with progress, so
/// whole repositories may have been left unscanned (`false` when the
/// surviving workers covered every listed repository). Callers with a
/// complete-report contract (the `org` investigation) use the flag to abort
/// instead of silently missing repositories.
pub(crate) type ParallelScan = Result<
    (
        Vec<String>,
        BTreeMap<String, Vec<String>>,
        usize,
        usize,
        Correlation,
        bool,
        // the real death error behind the partial flag (a token death, not
        // necessarily a spent allowance): callers re-raising the flag abort
        // with this cause instead of a misattributed rate-limit error
        Option<Error>,
    ),
    Error,
>;

/// What [`reduce_worker_reports`] folds the workers' reports into: the scan
/// result ([`ParallelScan`]'s payload plus the total number of successful
/// worker requests, reported in the JSON output) and the
/// partial-token-death flag (see [`ParallelScan`]).
type ReducedReports = (
    Result<Vec<String>, Error>,
    BTreeMap<String, Vec<String>>,
    usize,
    usize,
    usize,
    Correlation,
    bool,
    // the real death error behind the partial flag
    Option<Error>,
);

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
                _ => validate_name_value(name, value)?,
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
            // an inverted numeric range (`50..10`) is well-formed but
            // meaningless: GitHub answers it with a raw 422, so it is
            // rejected here like every other malformed value, with the
            // qualifier error naming the offending input. The sides are
            // compared as digit strings (longer is greater; equal lengths
            // compare lexicographically, which orders equal-length digit
            // strings numerically): a parse-based comparison would let a
            // low side past `u64` (`18446744073709551616..1`) through,
            // because `None > Some(_)` is always false
            if is_digits(low)
                && is_digits(high)
                // leading zeros are notation, not magnitude (`0500` is
                // `500`): strip them before the string comparison, an
                // empty side is zero
                && {
                    let low = low.trim_start_matches('0');
                    let high = high.trim_start_matches('0');
                    low.len() > high.len()
                        || (low.len() == high.len() && low > high)
                }
            {
                return Err(invalid_qualifier(name, value, EXPECTED));
            }
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
            // an inverted date range (`2020-01-01..2019-01-01`) is
            // well-formed but meaningless — and worse than the numeric
            // case: GitHub does not answer it with a raw 422, it silently
            // swaps the sides, so the scan would quietly cover the opposite
            // window (live-verified: `created:2020-01-01..2019-01-01` lists
            // 2019 repositories with no warning). The same
            // well-formed-but-meaningless class as the inverted numeric
            // range is therefore rejected here, with the qualifier error
            // naming the offending input. Only same-granularity sides are
            // compared: ISO dates of equal length order lexicographically
            // exactly like chronologically, while a mixed-granularity range
            // (`2020-01..2020`, January 2020 through year 2020) is not
            // provably inverted.
            if low.len() == high.len() && low > high {
                return Err(invalid_qualifier(name, value, EXPECTED));
            }
            return Ok(());
        }
        return Err(invalid_qualifier(name, value, EXPECTED));
    }
    if is_date(strip_comparison(value)) {
        return Ok(());
    }
    Err(invalid_qualifier(name, value, EXPECTED))
}

/// Validates a `license`/`topic`/`user`/`org` value. A `user`/`org` value
/// must be a valid GitHub login (ASCII letters, digits or hyphens — the
/// same rule as the `user` target, reused from
/// [`crate::user::validate_username`]): a login with `.` or `_` would
/// silently match nothing. A `license`/`topic` value may hold separators
/// (`apache-2.0`, `osint_2024`) but must hold at least one alphanumeric
/// character: a separator-only value (`...`, `--`) would silently match
/// nothing.
fn validate_name_value(name: &str, value: &str) -> Result<(), Error> {
    if name == "user" || name == "org" {
        return crate::user::validate_username(value)
            .map_err(|_| invalid_qualifier(name, value, "a GitHub login like octocat or acme"));
    }
    const EXPECTED: &str = "a name like mit, osint or acme";
    let allowed = value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
    let has_alphanumeric = value.chars().any(|c| c.is_ascii_alphanumeric());
    if allowed && has_alphanumeric {
        return Ok(());
    }
    Err(invalid_qualifier(name, value, EXPECTED))
}

/// GitHub's documented search ceiling: the repository search never serves
/// more than 1000 results, and a page requested past that window is
/// answered with a 422 instead of an empty page.
pub(crate) const SEARCH_RESULT_CEILING: usize = 1000;

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
    aggregate_search_at(scanner, GITHUB_API_BASE, query, language, qualifiers, limit)
}

/// Fetches the search listing for the query: capped at `ceiling` (GitHub
/// never serves more than 1000 search results, so the over-ceiling page is
/// never requested — the API answers it with a raw 422, and the extra
/// pages would only be thrown away anyway). The page-size-aware loop also
/// ends the listing on a short final page and counts raw items toward the
/// cap, so a total that is not a multiple of the page size can no longer
/// walk into the out-of-window request and cost the hits already collected
/// (they are preserved instead). The hits are counted as they stream in so
/// the defensive 422 fallback can report how many it had to discard.
///
/// # Errors
///
/// A page-1 422 (nothing collected) is the API rejecting the query itself
/// — in practice a nonexistent or inaccessible `--user`/`--org` login (the
/// API's own body says "The listed users cannot be searched…", but the raw
/// reqwest error discards it, leaving a typo'd target indistinguishable
/// from a tool failure): surfaced as [`Error::SearchRejected`] instead of
/// the raw HTTP error. A window 422 past the ceiling ends the listing with
/// a warning instead of aborting the whole search with a raw HTTP error
/// (same parity as the user investigation's external-contributions
/// search); the hits collected so far are deliberately kept by this
/// function's own caller instead of thrown away with the page (the
/// defensive fallback inside the paginated loop cannot recover them — a
/// chosen design, not a limitation). Every other failure propagates.
/// Never panics.
fn fetch_search_hits(
    client: &crate::github::Client,
    base: &str,
    query: &str,
    language: &str,
    qualifiers: &SearchQualifiers,
    ceiling: usize,
) -> Result<Vec<SearchHit>, Error> {
    let collected = std::cell::Cell::new(0usize);
    let hits = match fetch_paginated_with_page_size(
        client,
        |page| search_url(base, query, language, qualifiers, page),
        |json| {
            let (page_hits, raw_count) = parse_search_page(json)?;
            collected.set(collected.get() + page_hits.len());
            Ok((page_hits, raw_count))
        },
        Some(ceiling),
        PER_PAGE,
    ) {
        Ok(hits) => hits,
        Err(Error::Http(err))
            if err.status() == Some(reqwest::StatusCode::UNPROCESSABLE_ENTITY) =>
        {
            if collected.get() == 0 {
                return Err(Error::SearchRejected);
            }
            log::warn!(
                "search stopped at GitHub's 1000-result limit: {} already-found repositories were dropped",
                collected.get()
            );
            Vec::new()
        }
        Err(err) => return Err(err),
    };
    Ok(hits)
}

/// The same search, driven against one API base URL: [`aggregate_search`]
/// is the production entry point (`https://api.github.com`) and the offline
/// tests run this same code against a loopback mock (the same split as
/// [`Scanner::scan_repositories_at`]).
///
/// # Errors
///
/// The same failures as the parallel scan: a scan-wide failure aborts the
/// scan, while a dead dedicated token alone does not; the ceiling and 422
/// semantics are [`fetch_search_hits`]'s. Never panics.
pub(crate) fn aggregate_search_at(
    scanner: &Scanner,
    base: &str,
    query: &str,
    language: &str,
    qualifiers: &SearchQualifiers,
    limit: usize,
) -> Result<ScanOutcome, Error> {
    // fail fast on a malformed qualifier before any network request
    qualifiers.validate()?;
    // a --limit above the ceiling truncates the run silently otherwise: the
    // user asked for more repositories than GitHub can ever serve, and the
    // report must say the cap applied (the README documents the ceiling
    // generally; the terminal run should say when it actually bites)
    if limit > SEARCH_RESULT_CEILING {
        log::warn!(
            "GitHub never returns more than {SEARCH_RESULT_CEILING} results per search (--limit {limit} cannot be honored): repositories beyond the first {SEARCH_RESULT_CEILING} are not scanned"
        );
    }
    // GitHub never serves more than 1000 search results: cap the listing so
    // the over-ceiling page is never requested (the API answers it with a
    // raw 422, and the extra pages would only be thrown away anyway). The
    // page-size-aware loop also ends the listing on a short final page and
    // counts raw items toward the cap; the ceiling and 422 semantics are
    // [`fetch_search_hits`]'s
    let hits = fetch_search_hits(
        scanner.client(),
        base,
        query,
        language,
        qualifiers,
        limit.min(SEARCH_RESULT_CEILING),
    )?;

    let (mut found_emails, _, repos_scanned, _, correlation, partial, _) =
        scanner.scan_repositories_at(base, &hits, true)?;
    sort_emails(&mut found_emails);

    Ok(ScanOutcome {
        emails: found_emails,
        repos_scanned,
        correlation,
        partial,
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

/// Builds the search endpoint URL for `page` against `base` (the
/// production base or a test mock).
fn search_url(
    base: &str,
    query: &str,
    language: &str,
    qualifiers: &SearchQualifiers,
    page: u16,
) -> String {
    format!(
        "{base}/search/repositories?q={}&per_page={PER_PAGE}&page={page}",
        search_q(query, language, qualifiers)
    )
}

/// Builds the `q` parameter of the search endpoint: the percent-encoded user
/// query first, then the optional `language:` qualifier, then the provided
/// advanced qualifiers (`name:value` parts, space-joined as `+` in the URL).
/// The user-supplied values are percent-encoded: a raw `&`, `#`, `+` or
/// space would be split, truncated or rewritten server-side instead of being
/// part of the query.
pub(crate) fn search_q(query: &str, language: &str, qualifiers: &SearchQualifiers) -> String {
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
/// item and ends the listing. A 200 body without an `items` field at all, or
/// with an `items` field that is neither an array nor `null`, is an
/// intermediary or a shape change, not an empty page, and fails explicitly
/// instead of yielding a complete-looking empty result (the same
/// explicit-requirement rule as the org/user listings).
///
/// # Errors
///
/// Returns [`Error::InvalidProfile`] when the body carries no `items` field
/// or an `items` field that is neither an array nor `null`. Never panics.
pub(crate) fn parse_search_page(json: &Value) -> Result<(Vec<SearchHit>, usize), Error> {
    let Some(items) = json.get("items") else {
        return Err(Error::InvalidProfile(
            "search payload: no `items` field".to_string(),
        ));
    };
    let Some(items) = items.as_array() else {
        if items.is_null() {
            // a rejected search (`{"items": null}`) is a documented empty page
            return Ok((Vec::new(), 0));
        }
        // any other non-array shape is an intermediary or a shape change,
        // not an empty page: it must fail explicitly instead of silently
        // ending the listing as a complete-looking empty result
        return Err(Error::InvalidProfile(
            "search payload: `items` is not an array".to_string(),
        ));
    };
    // a listing-derived html_url is untrusted API data: an entry without
    // a usable URL is skipped with a warning, never silently — the same
    // warn-and-count rule the org and user listings apply to malformed
    // entries (the raw count still includes it so pagination keeps its
    // end-of-listing signal)
    let mut repositories = Vec::new();
    let mut malformed = 0usize;
    for item in items {
        let Some(url) = item.get("html_url").and_then(Value::as_str) else {
            malformed += 1;
            continue;
        };
        let language = item
            .get("language")
            .and_then(Value::as_str)
            .map(str::to_string);
        repositories.push(SearchHit {
            url: url.to_string(),
            language,
        });
    }
    if malformed > 0 {
        log::warn!("malformed search-listing entries skipped: {malformed}");
    }
    Ok((repositories, items.len()))
}

/// Percent-encodes a user- or API-derived string for safe interpolation in
/// a URL (hand-rolled, no new dependency): every byte outside the
/// RFC 3986 unreserved set becomes `%XX`. Shared by the query-composition
/// sites and by the API path segments (`/repos/{author}/{repository}/…`)
/// built from parser- or listing-derived names: a hostile `html_url` or
/// listing `name` carrying `?`, `#`, `&` or `/` must not re-target the
/// authenticated request to another path or query.
pub(crate) fn percent_encode(value: &str) -> String {
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
    /// Never panics.
    pub(crate) fn scan_repositories_at(
        &self,
        base: &str,
        repositories: &[SearchHit],
        skip_transient: bool,
    ) -> ParallelScan {
        if repositories.is_empty() {
            return Ok((
                Vec::new(),
                BTreeMap::new(),
                0,
                0,
                Correlation::default(),
                false,
                None,
            ));
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
        let live = tokens.live_indices();
        let workers = worker_count(
            if live.is_empty() {
                tokens.len()
            } else {
                live.len()
            },
            repositories.len(),
        );

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
                // the `worker`-th live token when any token is live; the
                // positional token otherwise (the all-dead fallback keeps
                // the loud all-workers-dead reduction). `None` is the
                // anonymous quota (no tokens at all)
                let assigned = live.get(worker).copied().unwrap_or(worker);
                let dedicated_token = tokens.dedicated_token(assigned);
                // a dedicated token the shared client retired or parked
                // during the listing phase never spawns a worker doomed to
                // a dead first request: the worker reports the death without
                // pulling (and doomed-losing) a repository from the queue.
                // An anonymous quota the listing phase retired or parked is
                // guarded the same way (its worker owns no dedicated token,
                // so it must consult the shared anonymous index)
                let start_dead = match dedicated_token {
                    Some(_) => tokens.is_exhausted(assigned),
                    None => tokens.is_exhausted(crate::github::client::ANONYMOUS_INDEX),
                };
                let worker_tx = result_tx.clone();
                // `Builder::spawn_scoped` instead of `scope.spawn`: the OS
                // refusing the thread creation must degrade to a reported
                // failure, not panic out of the documented never-panic
                // contract
                match std::thread::Builder::new().spawn_scoped(scope, move || {
                    let report = Self::scan_worker_queue(
                        dedicated_token,
                        base,
                        work_rx,
                        aborted,
                        start_dead,
                        skip_transient,
                    );
                    let _ = worker_tx.send(report);
                }) {
                    Ok(_handle) => {}
                    Err(_) => {
                        // no thread for this worker: report the prepared
                        // failure, so the reduction still receives exactly
                        // one report per worker instead of hanging on a
                        // missing one
                        let _ = result_tx.send(WorkerReport {
                            emails: Vec::new(),
                            requests: 0,
                            repos_scanned: 0,
                            skipped: 0,
                            contributions: Vec::new(),
                            failure: Some(Error::WorkerFailed(
                                "the OS refused to spawn a scan worker".to_string(),
                            )),
                            token_died: false,
                        });
                    }
                }
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
                    skipped: 0,
                    contributions: Vec::new(),
                    failure: Some(Error::WorkerFailed(
                        "scan worker did not report".to_string(),
                    )),
                    token_died: false,
                })
            })
            .collect();
        let (
            result,
            per_repository,
            worker_requests,
            repos_scanned,
            skipped,
            correlation,
            partial,
            death_error,
        ) = reduce_worker_reports(reports);
        self.add_worker_requests(worker_requests);
        // the partial flag's documented meaning is "whole listed repositories
        // may have been left unscanned" (`scanned.partial` in the JSON
        // report): when the surviving workers fully drained the queue —
        // every listed repository was scanned or warn-skipped — the token
        // death lost no repository, and a complete report must not carry a
        // false truncation alarm. The judgment is made here where the
        // listing size is known (the reducers do not see it); the `org`
        // caller aborts on any token death instead of judging coverage
        let partial = partial && repos_scanned + skipped < repositories.len();
        result.map(|emails| {
            (
                emails,
                per_repository,
                repos_scanned,
                skipped,
                correlation,
                partial,
                death_error,
            )
        })
    }

    /// Worker body: owns one dedicated token through its own
    /// client, pulls the next repository from the shared `mpsc` work queue
    /// and scans it, until the queue is drained or another worker failed.
    /// Returns everything it found, the per-author contributions of the
    /// repositories it scanned (issue #5), how many successful requests its
    /// client made and, when it hit one, the failure that ended it.
    fn scan_worker_queue(
        dedicated_token: Option<&str>,
        base: &str,
        work_rx: &Arc<Mutex<mpsc::Receiver<SearchHit>>>,
        aborted: &AtomicBool,
        start_dead: bool,
        skip_transient: bool,
    ) -> WorkerReport {
        let client = match Self::worker_client(dedicated_token) {
            Ok(client) => client,
            Err(err) => {
                return WorkerReport {
                    emails: Vec::new(),
                    requests: 0,
                    repos_scanned: 0,
                    skipped: 0,
                    contributions: Vec::new(),
                    failure: Some(err),
                    token_died: false,
                };
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
            let author = match parsers::get_author(repository_url.clone()) {
                Ok(author) => author,
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
            let repository = match parsers::get_repository(repository_url.clone()) {
                Ok(repository) => repository,
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
enum FailureAction {
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
/// token: only a token-scoped death ([`Error::RateLimitExhausted`], or
/// [`Error::TokenRejected`] — the API refused the token itself; tokens are
/// only format-validated at startup) stops the worker.
fn classify_failure(err: &Error, skip_transient: bool) -> FailureAction {
    match err {
        Error::RateLimitExhausted | Error::TokenRejected => FailureAction::TokenDied,
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
struct WorkerAccum {
    emails: Vec<String>,
    contributions: Vec<RepoContribution>,
    repos_scanned: usize,
    skipped: usize,
}

impl WorkerAccum {
    /// Merges one scanned repository into the accumulation.
    fn absorb(&mut self, scan: RepoScan, author: &str, repository: &str, language: Option<String>) {
        merge_emails(&mut self.emails, scan.emails);
        self.contributions.push(RepoContribution {
            name: format!("{author}/{repository}"),
            language,
            authors: scan.authors,
        });
        self.repos_scanned += 1;
    }

    /// Bundles what a worker found, the per-author contributions of its
    /// scanned repositories (issue #5), how many requests its client made,
    /// how many repositories it fully scanned, how many it warn-skipped as
    /// resource-scoped and the failure that ended it (if any) into its
    /// final report.
    fn finish(
        self,
        client: &crate::github::Client,
        failure: Option<Error>,
        token_died: bool,
    ) -> WorkerReport {
        WorkerReport::new(
            client,
            self.emails,
            self.contributions,
            self.repos_scanned,
            self.skipped,
            failure,
            token_died,
        )
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
    /// Repositories this worker warn-skipped as resource-scoped (deleted,
    /// private, token without the right scope, empty): covered work that a
    /// caller with a complete-report contract must count as covered, not as
    /// work never pulled.
    skipped: usize,
    /// The per-author contributions of the scanned repositories (issue #5).
    contributions: Vec<RepoContribution>,
    failure: Option<Error>,
    /// Whether the failure ended the worker because its own dedicated token
    /// died (spent quota or rejected token) rather than a scan-wide error:
    /// the other workers' tokens can keep draining the queue.
    token_died: bool,
}
impl WorkerReport {
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
/// per-author correlation report built from their contributions (issue #5).
///
/// A worker whose dedicated token died ([`Error::RateLimitExhausted`], or a
/// rejected token) does not fail the scan: the other workers' tokens keep
/// draining the queue and the emails found so far are returned (possibly
/// partial). Any other failure aborts the scan, as does a token death with
/// no worker left having made any progress (single anonymous worker, or
/// every token dead before scanning anything).
fn reduce_worker_reports(reports: Vec<WorkerReport>) -> ReducedReports {
    let mut found_emails: Vec<String> = Vec::new();
    let mut per_repository: BTreeMap<String, Vec<String>> = BTreeMap::new();
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
            for author in &contribution.authors {
                if !entry.contains(&author.email) {
                    entry.push(author.email.clone());
                }
            }
        }
        merge_emails(&mut found_emails, report.emails);
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
            Ok(found_emails)
        }
        Some(err) => Err(err),
        None => Ok(found_emails),
    };
    // deterministic order inside every per-repository list, and no noise
    // entry for a repository whose commits held no usable email
    for emails in per_repository.values_mut() {
        sort_emails(emails);
    }
    per_repository.retain(|_, emails| !emails.is_empty());
    (
        result,
        per_repository,
        requests,
        repos_scanned,
        skipped,
        correlation.finish(),
        partial_token_death,
        death_error,
    )
}

/// How many workers scan the repositories: one per available
/// token, capped by the number of repositories; an anonymous scan (no token)
/// runs a single worker on the shared anonymous quota.
pub(crate) fn worker_count(tokens: usize, repositories: usize) -> usize {
    tokens.max(1).min(repositories)
}

#[cfg(test)]
mod tests {
    // Tests may unwrap, expect and panic freely: a failing assertion must
    // be loud, so the zero-panic lints do not apply to the test modules.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::github::fetch_paginated;
    use crate::github::mock;
    use std::sync::Arc;

    /// A full page of 100 commits all attributing the same `(name, email)`
    /// pair: the page-size-aware commit listing only ends on a short page,
    /// and GitHub serves full pages until the last one, so multi-page mock
    /// listings must serve full pages to reproduce the real walk.
    fn full_commit_page(name: &str, email: &str) -> (u16, Vec<(String, String)>, String) {
        let commits: Vec<String> = (0..100)
            .map(|_| {
                format!(r#"{{"commit": {{"author": {{"name": "{name}", "email": "{email}"}}}}}}"#)
            })
            .collect();
        (200, vec![], format!("[{}]", commits.join(",")))
    }

    #[test]
    fn search_url_percent_encodes_query_and_language() {
        assert_eq!(
            search_url(
                GITHUB_API_BASE,
                "rust & go #1",
                "C++",
                &SearchQualifiers::default(),
                2,
            ),
            "https://api.github.com/search/repositories?q=rust%20%26%20go%20%231+language:C%2B%2B&per_page=100&page=2"
        );
    }

    #[test]
    fn search_url_omits_the_language_qualifier_when_absent() {
        assert_eq!(
            search_url(GITHUB_API_BASE, "nmap", "", &SearchQualifiers::default(), 1),
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
            search_url(GITHUB_API_BASE, "nmap", "Rust", &qualifiers, 1),
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
        let url = search_url(GITHUB_API_BASE, "nmap", "", &qualifiers, 1);
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
            user: Some("octocat".to_string()),
            org: Some("acme".to_string()),
        };
        qualifiers
            .validate()
            .expect("every documented shape must validate");
    }

    /// An inverted date range is rejected client-side like every other
    /// malformed qualifier: GitHub silently swaps the sides of a reversed
    /// `created`/`pushed` range instead of answering a 422 (live-verified:
    /// `created:2020-01-01..2019-01-01` lists 2019 repositories), so a run
    /// would quietly scan the opposite window with no warning at all. Pinned
    /// at every granularity the API accepts, plus the mixed-granularity and
    /// open-ended shapes that stay valid.
    #[test]
    fn validate_rejects_inverted_date_ranges_at_every_granularity() {
        for (name, value) in [
            ("created", "2020-01-01..2019-01-01"),
            ("created", "2020..2019"),
            ("created", "2020-02..2020-01"),
            ("pushed", "2024-01-01..2023-01-01"),
            ("pushed", "2021-06-15..2021-06-14"),
        ] {
            let qualifiers = SearchQualifiers {
                created: (name == "created").then(|| value.to_string()),
                pushed: (name == "pushed").then(|| value.to_string()),
                ..SearchQualifiers::default()
            };
            let error = qualifiers
                .validate()
                .expect_err("an inverted date range must be rejected");
            assert!(
                matches!(&error, Error::InvalidSearchQualifier(details) if details.contains(name)),
                "wrong error for {name} {value:?}: {error}"
            );
        }
        // same-length sides are compared lexicographically, which for ISO
        // dates is exactly chronological order; a mixed-granularity range is
        // not provably inverted (January 2020 through year 2020 is valid)
        // and must keep validating, like every open-ended or equal-sided
        // range.
        for value in [
            "2019-01-01..2020-01-01",
            "2019..2020",
            "2020-01..2020",
            "2020..2020",
            "2020-01-01..*",
            "*..2019",
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
        for value in [
            "abc",
            ">",
            "..50",
            "10..",
            "1..2..3",
            ">10..50",
            // an inverted range is well-formed but meaningless: left
            // unvalidated it would surface as a raw GitHub 422 instead of
            // the qualifier error every other malformed value gets
            "50..10",
            // the same inversion past `u64`: a parse-based comparison would
            // read the low side as `None` and accept the range
            "18446744073709551616..1",
        ] {
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
    fn validate_count_range_inversion_is_overflow_proof() {
        // the inversion check compares digit strings, never parsed integers:
        // a low side past `u64` parses to `None` and `None > Some(_)` is
        // always false, so a parse-based check would accept the inverted
        // range and spend a whole run on a guaranteed 422
        for value in [
            "18446744073709551616..1", // 2^64..1, both sides plain digits
            "99999999999999999999999999..0",
            "18446744073709551616..18446744073709551615",
        ] {
            let qualifiers = SearchQualifiers {
                stars: Some(value.to_string()),
                ..SearchQualifiers::default()
            };
            let error = qualifiers
                .validate()
                .expect_err("an overflow-inverted range must be rejected");
            assert!(
                matches!(&error, Error::InvalidSearchQualifier(details) if details.contains("stars")),
                "wrong error for {value:?}: {error}"
            );
        }
        // the string comparison must not reject the valid ranges around the
        // `u64` boundary either
        for value in [
            "1..18446744073709551615",
            "18446744073709551615..*",
            "0..18446744073709551616",
            "18446744073709551615..18446744073709551616",
        ] {
            let qualifiers = SearchQualifiers {
                stars: Some(value.to_string()),
                ..SearchQualifiers::default()
            };
            qualifiers
                .validate()
                .expect("a valid range past the u64 boundary must be accepted");
        }
    }

    #[test]
    fn leading_zeros_are_notation_not_magnitude_in_count_ranges() {
        // `0500` is `500`: the inversion comparison strips leading zeros
        // before comparing, so a zero-padded valid range is accepted and a
        // zero-padded inverted one is still rejected
        for value in ["0500..999", "005..010", "000..*"] {
            let qualifiers = SearchQualifiers {
                stars: Some(value.to_string()),
                ..SearchQualifiers::default()
            };
            qualifiers
                .validate()
                .expect("a zero-padded valid range must be accepted");
        }
        let qualifiers = SearchQualifiers {
            stars: Some("0500..9".to_string()),
            ..SearchQualifiers::default()
        };
        let error = qualifiers
            .validate()
            .expect_err("a zero-padded inverted range must still be rejected");
        assert!(
            matches!(&error, Error::InvalidSearchQualifier(details) if details.contains("stars"))
        );
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
    fn validate_rejects_logins_with_characters_github_logins_cannot_hold() {
        // a `.`/`_` login would silently match nothing: GitHub logins are
        // ASCII letters, digits or hyphens only (same rule as the `user`
        // target)
        for (name, value) in [
            ("user", "a..b"),
            ("user", "ja_ne"),
            ("org", "acme".repeat(40).as_str()),
            ("org", "-acme"),
            ("user", "acme-"),
            ("org", "ac--me"),
        ] {
            let qualifiers = SearchQualifiers {
                user: (name == "user").then(|| value.to_string()),
                org: (name == "org").then(|| value.to_string()),
                ..SearchQualifiers::default()
            };
            let error = qualifiers
                .validate()
                .expect_err("an impossible login must be rejected");
            assert!(
                matches!(&error, Error::InvalidSearchQualifier(details) if details.contains(name)),
                "wrong error for {name}={value:?}: {error}"
            );
        }
    }

    #[test]
    fn validate_rejects_separator_only_names() {
        // a separator-only value would silently match nothing: at least one
        // alphanumeric character is required
        for value in ["...", "--", "_", ".-_."] {
            let qualifiers = SearchQualifiers {
                topic: Some(value.to_string()),
                ..SearchQualifiers::default()
            };
            let error = qualifiers
                .validate()
                .expect_err("a separator-only name must be rejected");
            assert!(
                matches!(&error, Error::InvalidSearchQualifier(details) if details.contains("topic")),
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
    fn parse_search_page_warns_on_malformed_entries_and_keeps_the_rest() {
        // an item without a usable html_url is skipped with a warning,
        // never silently: the raw count still includes it so pagination
        // keeps its end-of-listing signal (same warn-and-count rule as the
        // org and user listings)
        let json: Value = serde_json::json!({
            "total_count": 3,
            "items": [
                { "html_url": "https://github.com/a/one", "language": "Rust" },
                { "language": "Go" },
                { "other": true }
            ]
        });
        let (outcome, lines) = crate::test_logger::capture(|| parse_search_page(&json));
        let (hits, raw_count) = outcome.expect("parsing must succeed");
        assert_eq!(
            hits,
            vec![SearchHit {
                url: "https://github.com/a/one".to_string(),
                language: Some("Rust".to_string()),
            }]
        );
        assert_eq!(raw_count, 3);
        assert!(
            lines
                .iter()
                .any(|line| line.contains("malformed search-listing entries skipped: 2")),
            "the malformed entries must be reported: {lines:?}"
        );
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
    fn parse_search_page_fails_explicitly_on_a_body_without_items() {
        // a 200 body without an `items` field (captive portal, shape change)
        // is not an empty page: it must fail explicitly instead of silently
        // ending the search as a successful empty result
        for body in [
            serde_json::json!({}),
            serde_json::json!("[]"),
            serde_json::json!([]),
        ] {
            let error =
                parse_search_page(&body).expect_err("a payload without items must fail explicitly");
            assert!(matches!(error, Error::InvalidProfile(details) if details.contains("items")));
        }
    }

    #[test]
    fn parse_search_page_fails_explicitly_on_a_non_array_items_field() {
        // an `items` field that is present but neither an array nor `null`
        // is a shape change, not a rejected search: treating it as an empty
        // page would end the listing as a complete-looking empty result
        for body in [
            serde_json::json!({"items": {}}),
            serde_json::json!({"items": 42}),
            serde_json::json!({"items": "x"}),
        ] {
            let error =
                parse_search_page(&body).expect_err("a non-array items must fail explicitly");
            assert!(matches!(error, Error::InvalidProfile(details) if details.contains("array")));
        }
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
    fn a_short_final_search_page_ends_the_listing_before_the_out_of_window_page() {
        // a page holding fewer items than the page size is the last page of
        // the listing: a total that is not a multiple of the page size used
        // to keep the walk alive up to the page past GitHub's 1000-result
        // window, which the API answers with a raw 422 — silently discarding
        // every hit collected so far through the defensive fallback. The
        // short-page rule ends the listing instead, and the hits are kept
        let (address, server) = mock::serve_requests(move |_index, request| {
            let line = request.first().map(String::as_str).unwrap_or("");
            if line.contains("/repos/a/one/commits") || line.contains("/repos/a/two/commits") {
                // the candidates' commit listings: empty, they end at once
                return (200, vec![], "[]".to_string());
            }
            if line.contains("/search/repositories") {
                return match crate::github::mock::request_line_page(request) {
                    1 => (
                        200,
                        vec![],
                        r#"{"total_count": 3000, "items": [{"html_url": "https://github.com/a/one"}, {"html_url": "https://github.com/a/two"}]}"#.to_string(),
                    ),
                    // any further page is past the documented window: the
                    // mock answers it with the documented raw 422
                    _ => (
                        422,
                        vec![],
                        r#"{"message": "Only the first 1000 search results are available"}"#
                            .to_string(),
                    ),
                };
            }
            (404, vec![], String::new())
        });

        let scanner =
            crate::sources::Scanner::new(None, None).expect("anonymous scanner must build");
        let outcome = aggregate_search_at(
            &scanner,
            &address,
            "nmap",
            "",
            &SearchQualifiers::default(),
            5,
        )
        .expect("a short final page must end the listing without a 422");
        // both collected hits were scanned (the mock's commit listings are
        // empty, so no email is found)
        assert_eq!(outcome.repos_scanned, 2);
        // the two commit listings plus exactly one search page: the short
        // page 1 ended the listing, the out-of-window page 2 (a raw 422 in
        // the mock) was never requested
        assert_eq!(server.join(), 3);
    }

    #[test]
    fn a_malformed_listing_url_is_skipped_with_a_warning_not_an_abort() {
        // one listing entry with a present-but-unparseable html_url is
        // scoped to that entry: it is skipped with a warning (the same
        // warn-and-count rule as any resource-scoped failure) and the other
        // hits are scanned, instead of one malformed line aborting the
        // whole scan and discarding every finding
        let (address, server) = mock::serve_requests(move |_index, request| {
            let line = request.first().map(String::as_str).unwrap_or("");
            if line.contains("/repos/a/one/commits") || line.contains("/repos/a/two/commits") {
                return (200, vec![], "[]".to_string());
            }
            if line.contains("/search/repositories") {
                return match crate::github::mock::request_line_page(request) {
                    1 => (
                        200,
                        vec![],
                        r#"{"total_count": 2, "items": [{"html_url": "https://github.com/a/one"}, {"html_url": "https://github.com/"}]}"#.to_string(),
                    ),
                    _ => (200, vec![], r#"{"items": null}"#.to_string()),
                };
            }
            (404, vec![], String::new())
        });

        let scanner =
            crate::sources::Scanner::new(None, None).expect("anonymous scanner must build");
        let (outcome, lines) = crate::test_logger::capture(|| {
            aggregate_search_at(
                &scanner,
                &address,
                "nmap",
                "",
                &SearchQualifiers::default(),
                5,
            )
        });
        let outcome = outcome.expect("one malformed entry must not abort the scan");
        server.join();

        // the sane entry was scanned; the malformed one was skipped
        assert_eq!(outcome.repos_scanned, 1);
        assert!(
            lines
                .iter()
                .any(|line| line.contains("skipping repository https://github.com/")),
            "the malformed entry must be reported with its sanitized URL: {lines:?}"
        );
    }

    #[test]
    fn the_search_ceiling_caps_the_listing_and_keeps_the_collected_hits() {
        // the 1000-result ceiling is the cap even when --limit is far above
        // it: the mock answers the full 100 items of pages 1..10 and the
        // documented raw 422 past the window. A missing cap (or a cap
        // counted in parsed items that a parser under-fills) would request
        // page 11 and, through the defensive fallback, silently discard the
        // 1000 hits already collected
        let (address, server) = mock::serve_requests(move |_index, request| {
            let line = request.first().map(String::as_str).unwrap_or("");
            if line.contains("/repos/a/") && line.contains("/commits") {
                // the candidates' commit listings: empty, they end at once
                return (200, vec![], "[]".to_string());
            }
            if line.contains("/search/repositories") {
                let page = crate::github::mock::request_line_page(request);
                if page > 10 {
                    // the documented over-ceiling answer: must never be
                    // requested, the cap stops the listing first
                    return (
                        422,
                        vec![],
                        r#"{"message": "Only the first 1000 search results are available"}"#
                            .to_string(),
                    );
                }
                let items: Vec<String> = (0..100)
                    .map(|i| format!(r#"{{"html_url": "https://github.com/a/rep{page}-{i}"}}"#))
                    .collect();
                return (
                    200,
                    vec![],
                    format!(r#"{{"total_count": 5000, "items": [{}]}}"#, items.join(",")),
                );
            }
            (404, vec![], String::new())
        });

        let scanner =
            crate::sources::Scanner::new(None, None).expect("anonymous scanner must build");
        // captured: this run emits the cap warning (limit above the
        // ceiling), and an uncaptured sibling's lines would pollute any
        // parallel capture through the process-wide logger
        let (outcome, _lines) = crate::test_logger::capture(|| {
            aggregate_search_at(
                &scanner,
                &address,
                "nmap",
                "",
                &SearchQualifiers::default(),
                5000,
            )
        });
        outcome
            .as_ref()
            .expect("the ceiling must cap the listing and keep its hits");
        // the full capped listing survived: 1000 repositories scanned, not
        // the empty result a 422-discard would produce
        assert_eq!(
            outcome.expect("capped run must succeed").repos_scanned,
            1000
        );
        // 10 search pages (one per 100-result page up to the cap) plus one
        // commit listing per scanned repository; page 11 was never requested
        assert_eq!(server.join(), 10 + 1000);
    }

    #[test]
    fn the_ceiling_cap_warns_when_the_limit_exceeds_it() {
        // a --limit above the 1000-result ceiling truncates the run: the
        // cap must say so on the terminal (and stay silent when the limit
        // fits under the ceiling)
        let (address, server) = mock::serve_requests(move |_index, request| {
            let line = request.first().map(String::as_str).unwrap_or("");
            if line.contains("/repos/a/") && line.contains("/commits") {
                return (200, vec![], "[]".to_string());
            }
            if line.contains("/search/repositories") {
                return (
                    200,
                    vec![],
                    r#"{"total_count": 2, "items": [{"html_url": "https://github.com/a/one"}, {"html_url": "https://github.com/a/two"}]}"#.to_string(),
                );
            }
            (404, vec![], String::new())
        });
        let scanner =
            crate::sources::Scanner::new(None, None).expect("anonymous scanner must build");
        let (outcome, lines) = crate::test_logger::capture(|| {
            aggregate_search_at(
                &scanner,
                &address,
                "nmap",
                "",
                &SearchQualifiers::default(),
                1001,
            )
        });
        outcome.expect("the capped search must succeed");
        assert!(
            lines
                .iter()
                .any(|line| line.contains("never returns more than 1000 results")),
            "the cap warning must be logged, got: {lines:?}"
        );
        // a limit within the ceiling does not warn
        let (_, lines) = crate::test_logger::capture(|| {
            aggregate_search_at(
                &scanner,
                &address,
                "nmap",
                "",
                &SearchQualifiers::default(),
                1000,
            )
        });
        assert!(!lines.iter().any(|line| line.contains("1000-result limit")));
        // two runs: one search page plus one commit listing per repository
        assert_eq!(server.join(), 2 * (1 + 2));
    }

    #[test]
    fn a_page1_422_fails_the_search_explicitly_instead_of_an_empty_scan() {
        // the defensive 422 fallback only covers the out-of-window page: a
        // 422 on the very first page (nothing collected yet) can never be a
        // ceiling 422 — the API rejected the query itself (an over-long or
        // otherwise invalid `q`). It must propagate instead of degrading
        // into a complete-looking empty report with exit 0
        let (address, server) = mock::serve_requests(move |_index, _request| {
            (
                422,
                vec![],
                r#"{"message": "Validation Failed"}"#.to_string(),
            )
        });

        let scanner =
            crate::sources::Scanner::new(None, None).expect("anonymous scanner must build");
        let error = aggregate_search_at(
            &scanner,
            &address,
            &"x".repeat(300),
            "",
            &SearchQualifiers::default(),
            5,
        )
        .expect_err("a query the API rejected must fail the search");
        // the rejection is the crafted error: a typo'd --user/--org login or
        // an invalid q must not surface as raw reqwest jargon
        assert!(
            matches!(error, Error::SearchRejected),
            "unexpected error: {error:?}"
        );
        assert!(
            error.to_string().contains("422") && error.to_string().contains("--user`/`--org"),
            "unexpected message: {error}"
        );
        // the walk stopped at the rejected first page
        assert_eq!(server.join(), 1);
    }

    #[test]
    fn a_422_past_the_first_page_ends_the_search_with_the_discard_warning() {
        // the defensive 422 fallback's collected>0 branch: a full page 1
        // followed by a raw 422 on page 2 (never reachable for GitHub's
        // documented paging, hence the defensiveness) ends the search with
        // a warning instead of aborting it with a raw HTTP error — and it
        // must not silently yield a complete-looking empty report without
        // at least being pinned here (a mutation deleting the branch would
        // turn the 422 into a scan-wide abort)
        let (address, server) = mock::serve_requests(move |_index, request| {
            let line = request.first().map(String::as_str).unwrap_or("");
            if line.contains("/search/repositories") {
                if crate::github::mock::request_line_page(request) > 1 {
                    return (
                        422,
                        vec![],
                        r#"{"message": "Only the first 1000 search results are available"}"#
                            .to_string(),
                    );
                }
                let items: Vec<String> = (0..100)
                    .map(|i| format!(r#"{{"html_url": "https://github.com/a/rep-{i}"}}"#))
                    .collect();
                return (
                    200,
                    vec![],
                    format!(r#"{{"items": [{}]}}"#, items.join(",")),
                );
            }
            (404, vec![], String::new())
        });

        let scanner =
            crate::sources::Scanner::new(None, None).expect("anonymous scanner must build");
        // a limit above one page keeps the walk alive past the full page 1,
        // where the mock answers the documented out-of-window 422
        let outcome = aggregate_search_at(
            &scanner,
            &address,
            "nmap",
            "",
            &SearchQualifiers::default(),
            101,
        )
        .expect("a mid-walk 422 must end the search, not abort it");

        // the fallback discarded the collected hits: an empty (warned-about)
        // listing, not a scan-wide failure
        assert_eq!(outcome.repos_scanned, 0);
        assert!(outcome.emails.is_empty());
        assert!(!outcome.partial);
        // exactly two search pages were requested, no repository scan
        assert_eq!(server.join(), 2);
    }

    #[test]
    fn a_401_on_a_dedicated_token_ends_only_its_worker() {
        // the 0.5.0 contract, end to end: one revoked token stops its own
        // worker while the other tokens keep draining the queue
        let (address, server) = mock::serve_requests(move |_index, request| {
            let line = request.first().map(String::as_str).unwrap_or("");
            if line.contains("/repos/a/one/commits") {
                // the revoked token's repository: the API rejects it
                return (401, vec![], String::new());
            }
            if line.contains("/repos/a/two/commits") {
                return match crate::github::mock::request_line_page(request) {
                    1 => full_commit_page("Bob", "bob@x.com"),
                    _ => (200, vec![], "[]".to_string()),
                };
            }
            if line.contains("/repos/a/three/commits") {
                return match crate::github::mock::request_line_page(request) {
                    1 => full_commit_page("Carol", "carol@x.com"),
                    _ => (200, vec![], "[]".to_string()),
                };
            }
            (404, vec![], String::new())
        });

        // two dedicated tokens: whichever worker pulls the 401ing repository
        // stops; the other one drains the remaining repositories
        let token_path = std::env::temp_dir().join(format!(
            "git2mail_search_401_tokens_{}.json",
            std::process::id()
        ));
        std::fs::write(&token_path, r#"{"0": "ghp_a", "1": "ghp_b"}"#)
            .expect("test setup: write token file");
        let scanner = Scanner::new(None, Some(&token_path)).expect("scanner must build");
        std::fs::remove_file(&token_path).ok();

        let hits: Vec<SearchHit> = ["one", "two", "three"]
            .into_iter()
            .map(|repo| SearchHit {
                url: format!("https://github.com/a/{repo}"),
                language: None,
            })
            .collect();
        let (emails, _, repos_scanned, _, _, _, _) = scanner
            .scan_repositories_at(&address, &hits, true)
            .expect("one revoked token must not abort the scan");

        // the revoked token's repository was left unscanned, the two healthy
        // ones were scanned and kept their emails
        assert_eq!(repos_scanned, 2);
        assert_eq!(
            emails,
            vec!["bob@x.com".to_string(), "carol@x.com".to_string()]
        );
        // the 401ing repository's single doomed request, plus both pages of
        // each healthy repository's commit listing
        assert_eq!(server.join(), 1 + 2 + 2);
    }

    #[test]
    fn a_token_the_listing_already_spent_gets_no_dedicated_worker_requests() {
        // a dedicated token the shared client retired during the listing
        // phase never spawns a worker doomed to a dead first request: the
        // remaining tokens cover the whole queue, and the retired secret
        // never reaches the wire again
        let (address, server) = mock::serve_requests(move |_index, request| {
            if mock::request_header(request, "Authorization") == Some("token ghp_a") {
                panic!("a retired token must not be handed to a worker");
            }
            let line = request.first().map(String::as_str).unwrap_or("");
            if line.contains("/repos/a/one/commits") {
                return match crate::github::mock::request_line_page(request) {
                    1 => (
                        200,
                        vec![],
                        r#"[{"commit": {"author": {"name": "Alice", "email": "alice@x.com"}}}]"#
                            .to_string(),
                    ),
                    _ => (200, vec![], "[]".to_string()),
                };
            }
            if line.contains("/repos/a/two/commits") {
                return match crate::github::mock::request_line_page(request) {
                    1 => (
                        200,
                        vec![],
                        r#"[{"commit": {"author": {"name": "Bob", "email": "bob@x.com"}}}]"#
                            .to_string(),
                    ),
                    _ => (200, vec![], "[]".to_string()),
                };
            }
            (404, vec![], String::new())
        });

        let token_path = std::env::temp_dir().join(format!(
            "git2mail_search_dead_tokens_{}.json",
            std::process::id()
        ));
        std::fs::write(&token_path, r#"{"0": "ghp_a", "1": "ghp_b"}"#)
            .expect("test setup: write token file");
        let scanner = Scanner::new(None, Some(&token_path)).expect("scanner must build");
        std::fs::remove_file(&token_path).ok();
        // the shared client spent the first token during the listing phase
        scanner.client().tokens().mark_exhausted(0);

        let hits: Vec<SearchHit> = ["one", "two"]
            .into_iter()
            .map(|repo| SearchHit {
                url: format!("https://github.com/a/{repo}"),
                language: None,
            })
            .collect();
        let (emails, _, repos_scanned, .., partial) = scanner
            .scan_repositories_at(&address, &hits, true)
            .expect("the live token must cover the whole queue");
        server.join();

        // the retired token's worker pulled nothing, so the live worker
        // scanned both repositories: no repository was lost to a doomed
        // request, and the complete coverage must not raise a false
        // `scanned.partial` truncation alarm (the flag means whole listed
        // repositories may have been left unscanned — here none was)
        assert_eq!(repos_scanned, 2);
        assert_eq!(emails.len(), 2);
        assert!(
            partial.is_none(),
            "a token death that left no listed repository uncovered is not a partial scan"
        );
    }

    #[test]
    fn a_dead_leading_token_never_starves_a_short_repository_list() {
        // with fewer listed repositories than tokens, the worker pool must
        // not map worker i onto pool token i positionally: a token the
        // listing phase retired would then own the only worker slot and
        // abort the whole scan without a single request, while healthy
        // tokens beyond the worker range sit unused. The single worker slot
        // must go to the first *live* token instead
        let (address, server) = mock::serve_requests(move |_index, request| {
            if mock::request_header(request, "Authorization") == Some("token ghp_a") {
                panic!("a retired token must not be handed to a worker");
            }
            let line = request.first().map(String::as_str).unwrap_or("");
            if line.contains("/repos/a/one/commits") {
                return match crate::github::mock::request_line_page(request) {
                    1 => (
                        200,
                        vec![],
                        r#"[{"commit": {"author": {"name": "Alice", "email": "alice@x.com"}}}]"#
                            .to_string(),
                    ),
                    _ => (200, vec![], "[]".to_string()),
                };
            }
            (404, vec![], String::new())
        });

        let token_path = std::env::temp_dir().join(format!(
            "git2mail_search_starved_tokens_{}.json",
            std::process::id()
        ));
        std::fs::write(&token_path, r#"{"0": "ghp_a", "1": "ghp_b"}"#)
            .expect("test setup: write token file");
        let scanner = Scanner::new(None, Some(&token_path)).expect("scanner must build");
        std::fs::remove_file(&token_path).ok();
        // the shared client spent the first token during the listing phase
        scanner.client().tokens().mark_exhausted(0);

        let hits: Vec<SearchHit> = ["one"]
            .into_iter()
            .map(|repo| SearchHit {
                url: format!("https://github.com/a/{repo}"),
                language: None,
            })
            .collect();
        let (emails, _, repos_scanned, .., partial) = scanner
            .scan_repositories_at(&address, &hits, true)
            .expect("the live token must scan the single listed repository");
        server.join();

        assert_eq!(repos_scanned, 1);
        assert_eq!(emails, vec!["alice@x.com".to_string()]);
        assert!(partial.is_none());
    }

    #[test]
    fn a_start_dead_worker_with_uncovered_repositories_still_flags_the_partial_scan() {
        // the tightening of the partial flag must not swallow a real
        // truncation: the start-dead first worker is joined by a second
        // token dying mid-scan, so one listed repository is left unscanned
        // and the flag must stay raised for the callers (the org contract)
        let (address, server) = mock::serve_requests(move |_index, request| {
            let line = request.first().map(String::as_str).unwrap_or("");
            if line.contains("/repos/a/one/commits") {
                return match crate::github::mock::request_line_page(request) {
                    1 => (
                        200,
                        vec![],
                        r#"[{"commit": {"author": {"name": "Alice", "email": "alice@x.com"}}}]"#
                            .to_string(),
                    ),
                    _ => (200, vec![], "[]".to_string()),
                };
            }
            if line.contains("/repos/a/two/commits") || line.contains("/repos/a/three/commits") {
                // the second token's quota dies on its next repository: the
                // worker stops, `three` is never pulled
                return (
                    429,
                    vec![("Retry-After".to_string(), "60".to_string())],
                    String::new(),
                );
            }
            (404, vec![], String::new())
        });

        let token_path = std::env::temp_dir().join(format!(
            "git2mail_search_partial_tokens_{}.json",
            std::process::id()
        ));
        std::fs::write(&token_path, r#"{"0": "ghp_a", "1": "ghp_b"}"#)
            .expect("test setup: write token file");
        let scanner = Scanner::new(None, Some(&token_path)).expect("scanner must build");
        std::fs::remove_file(&token_path).ok();
        // the shared client spent the first token during the listing phase
        scanner.client().tokens().mark_exhausted(0);

        let hits: Vec<SearchHit> = ["one", "two", "three"]
            .into_iter()
            .map(|repo| SearchHit {
                url: format!("https://github.com/a/{repo}"),
                language: None,
            })
            .collect();
        let (emails, _, repos_scanned, _, _, partial, _) = scanner
            .scan_repositories_at(&address, &hits, true)
            .expect("the kept partial result is returned");
        server.join();

        // one repository scanned, two left uncovered by the two dead tokens
        assert_eq!(repos_scanned, 1);
        assert_eq!(emails.len(), 1);
        assert!(
            partial,
            "a token death that left listed repositories unscanned is a partial scan"
        );
    }

    #[test]
    fn the_worker_skip_warning_sanitizes_the_untrusted_repository_url() {
        // the parallel-scan skip warning prints the hit URL, which the URL
        // parser accepts with arbitrary non-`/`/`:` bytes: a dropped
        // `log_safe()` call must fail the suite (capturing logger, same
        // wiring-level pin as the terminal report)
        let (address, server) = mock::serve_requests(move |_index, request| {
            let line = request.first().map(String::as_str).unwrap_or("");
            if line.contains("/repos/a/hostile") {
                // the hostile-URL repository: a resource-scoped 404 that
                // lands in the skip warning, ESC opener and all
                return (404, vec![], String::new());
            }
            if line.contains("/repos/a/full/commits") {
                return match crate::github::mock::request_line_page(request) {
                    1 => (
                        200,
                        vec![],
                        r#"[{"commit": {"author": {"name": "Alice", "email": "alice@x.com"}}}]"#
                            .to_string(),
                    ),
                    _ => (200, vec![], "[]".to_string()),
                };
            }
            (404, vec![], String::new())
        });

        let scanner =
            crate::sources::Scanner::new(None, None).expect("anonymous scanner must build");
        let hits = vec![
            SearchHit {
                url: "https://github.com/a/hostile\u{1b}[31mname".to_string(),
                language: None,
            },
            SearchHit {
                url: "https://github.com/a/full".to_string(),
                language: None,
            },
        ];
        let (outcome, lines) =
            crate::test_logger::capture(|| scanner.scan_repositories_at(&address, &hits, true));
        let (emails, _, repos_scanned, _, _, _, _) =
            outcome.expect("a resource-scoped failure must not abort the scan");
        server.join();

        // the hostile repository was skipped, the healthy one scanned
        assert_eq!(emails, vec!["alice@x.com".to_string()]);
        assert_eq!(repos_scanned, 1);
        assert!(
            !lines.iter().any(|line| line.contains('\x1b')),
            "a hostile hit URL must not carry an ESC sequence into the log: {lines:?}"
        );
        assert!(
            lines
                .iter()
                .any(|line| line.contains("skipping repository") && line.contains("_[31mname")),
            "the sanitized skip warning must be printed: {lines:?}"
        );
    }

    #[test]
    fn a_409_empty_repository_is_skipped_during_a_scan() {
        // GitHub answers 409 Conflict on /commits for a repository with no
        // commits: a search hit in that state must be skipped like a deleted
        // or private one, not abort the whole scan with a raw HTTP error
        let (address, server) = mock::serve_requests(move |_index, request| {
            let line = request.first().map(String::as_str).unwrap_or("");
            if line.contains("/repos/a/empty/commits") {
                // the empty repository: GitHub's documented 409
                return (
                    409,
                    vec![],
                    r#"{"message": "Git Repository is empty."}"#.to_string(),
                );
            }
            if line.contains("/repos/a/full/commits") {
                return match crate::github::mock::request_line_page(request) {
                    1 => (
                        200,
                        vec![],
                        r#"[{"commit": {"author": {"name": "Alice", "email": "alice@x.com"}}}]"#
                            .to_string(),
                    ),
                    _ => (200, vec![], "[]".to_string()),
                };
            }
            if line.contains("/search/repositories") {
                return match crate::github::mock::request_line_page(request) {
                    1 => (
                        200,
                        vec![],
                        r#"{"items": [{"html_url": "https://github.com/a/empty"}, {"html_url": "https://github.com/a/full"}]}"#.to_string(),
                    ),
                    _ => (200, vec![], r#"{"items": null}"#.to_string()),
                };
            }
            (404, vec![], String::new())
        });

        let scanner =
            crate::sources::Scanner::new(None, None).expect("anonymous scanner must build");
        let outcome = aggregate_search_at(
            &scanner,
            &address,
            "nmap",
            "",
            &SearchQualifiers::default(),
            5,
        )
        .expect("an empty repository must not abort the scan");
        server.join();

        // the empty repository was skipped (not counted as scanned) and the
        // scan continued with the next one
        assert_eq!(outcome.emails, vec!["alice@x.com".to_string()]);
        assert_eq!(
            outcome.repos_scanned, 1,
            "the skipped repository is not counted as scanned"
        );
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
            skipped: 0,
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
            skipped: 0,
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
        let (result, _, requests, ..) = reduce_worker_reports(reports);
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
    fn warn_skipped_repositories_count_as_covered_work_for_the_callers() {
        // a caller with a complete-report contract (the org investigation)
        // judges the kept partial result against the listed repositories: a
        // repository warn-skipped as resource-scoped (deleted, private or
        // empty) is covered work, not work the dead token never reached
        let covered = WorkerReport {
            emails: vec!["b@b.b".to_string()],
            requests: 1,
            repos_scanned: 0,
            skipped: 1,
            contributions: Vec::new(),
            failure: None,
            token_died: false,
        };
        let (result, _, _, repos_scanned, skipped, _, partial, _) = reduce_worker_reports(vec![
            progressed_report(&["a@a.a"], 1, Some(Error::RateLimitExhausted)),
            covered,
        ]);
        result.expect("covered work must not be thrown away");
        assert!(partial, "the death is still reported to the caller");
        assert_eq!(
            (repos_scanned, skipped),
            (1, 1),
            "scanned + skipped covers the two listed repositories"
        );

        // a dead worker's own gap (its in-flight repository) is neither
        // scanned nor skipped: scanned + skipped stays below the listing and
        // the caller must abort instead of writing a complete-looking report
        let (result, _, _, repos_scanned, skipped, _, partial, _) = reduce_worker_reports(vec![
            progressed_report(&["a@a.a"], 1, Some(Error::RateLimitExhausted)),
            report(&["b@b.b"], None),
        ]);
        result.expect("the scan itself still succeeds");
        assert!(partial);
        assert_eq!(
            repos_scanned + skipped,
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
        let (result, _, requests, ..) = reduce_worker_reports(reports);
        let emails = result.expect("a complete result must be kept");
        assert_eq!(emails.len(), 2);
        assert_eq!(requests, 2);
    }

    #[test]
    fn a_partial_result_kept_after_a_token_death_is_flagged_for_callers() {
        // callers with a complete-report contract (the `org` investigation)
        // must be able to tell a partial kept result from a complete one
        let partial = vec![
            progressed_report(&["a@a.a"], 1, Some(Error::RateLimitExhausted)),
            report(&["b@b.b"], None),
        ];
        let (result, .., partial_token_death, death_error) = reduce_worker_reports(partial);
        result.expect("the healthy workers' emails must be kept");
        assert!(partial_token_death, "a kept partial result must be flagged");
        assert!(
            death_error.is_some(),
            "the caller must receive the real death cause"
        );

        let complete = vec![report(&["a@a.a"], None), report(&["b@b.b"], None)];
        let (result, .., partial_token_death, death_error) = reduce_worker_reports(complete);
        result.expect("the scan must not fail");
        assert!(
            !partial_token_death && death_error.is_none(),
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
        let (result, ..) = reduce_worker_reports(reports);
        let emails = result.expect("the healthy workers' emails must be kept");
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
        let (result, ..) = reduce_worker_reports(reports);
        assert!(matches!(result, Err(Error::InvalidUrl(_))));
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
        let (result, _, _, repos_scanned, ..) = reduce_worker_reports(reports);
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

        let (result, _, requests, repos_scanned, _, correlation, ..) =
            reduce_worker_reports(reports);
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

        let (result, _, _, _, _, correlation, ..) = reduce_worker_reports(vec![report, {
            contribution_report(&["bob@y.y"], "b/two", Some("Go"), &[("Bob", "bob@y.y", 1)])
        }]);

        result.expect("a token death with progress keeps the scan result");
        assert_eq!(correlation.authors.len(), 2);
        assert_eq!(correlation.authors[0].first_seen_repo, "a/one");
        assert_eq!(correlation.authors[1].first_seen_repo, "b/two");
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
            WorkerReport {
                emails: Vec::new(),
                requests: 0,
                repos_scanned: 0,
                skipped: 0,
                contributions: Vec::new(),
                failure: None,
                token_died: false,
            },
        ];

        let (result, per_repository, ..) = reduce_worker_reports(reports);
        result.expect("the scan must not fail");
        assert_eq!(
            per_repository.get("a/one"),
            Some(&vec!["alice@x.com".to_string(), "alice@y.com".to_string()])
        );
        assert_eq!(
            per_repository.get("b/two"),
            Some(&vec!["bob@y.y".to_string()])
        );
        assert_eq!(per_repository.len(), 2);
    }
}
