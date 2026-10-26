//! Search scan: the repositories matching a query, fed to the shared
//! parallel worker pool ([`super::parallel`]).

use crate::consts::GITHUB_API_BASE;
use crate::errors::Error;
use crate::github::fetch_paginated_with_page_size;
use crate::sources::{PER_PAGE, RepoHit, ScanOutcome, Scanner, sort_emails};
use serde::Serialize;
use serde_json::Value;

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
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
pub struct SearchQualifiers {
    /// Repository star count, e.g. `>100`, `>=50`, `10..50` or `100..*`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stars: Option<String>,
    /// Repository fork count, same range syntax as `stars`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub forks: Option<String>,
    /// Repository size in kilobytes, same range syntax as `stars`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<String>,
    /// Repository creation date, e.g. `>2020-01-01`, `>=2020` or
    /// `2019-01-01..2020-01-01`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,
    /// Repository last-push date, same date syntax as `created`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pushed: Option<String>,
    /// Repository license identifier, e.g. `mit` or `apache-2.0`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,
    /// Repository topic, e.g. `osint`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub topic: Option<String>,
    /// Restrict the search to one user's repositories (login).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// Restrict the search to one organization's repositories (login).
    #[serde(skip_serializing_if = "Option::is_none")]
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
    /// malformed value.
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
/// per-author correlation report with the primary language each
/// search result already carries.
pub(crate) fn aggregate_search(
    scanner: &Scanner,
    query: &str,
    language: &str,
    qualifiers: &SearchQualifiers,
    limit: usize,
    include_forks: bool,
) -> Result<ScanOutcome, Error> {
    aggregate_search_at(
        scanner,
        GITHUB_API_BASE,
        query,
        language,
        qualifiers,
        limit,
        include_forks,
    )
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
/// search): the hits already collected are discarded with the warning
/// naming how many were dropped — they are unrecoverable from the
/// paginated loop's error path, and the completed-but-empty outcome is the
/// documented shape (doc/src/API.md). Every other failure propagates.
fn fetch_search_hits(
    client: &crate::github::Client,
    base: &str,
    query: &str,
    language: &str,
    qualifiers: &SearchQualifiers,
    ceiling: usize,
    include_forks: bool,
) -> Result<Vec<RepoHit>, Error> {
    let collected = std::cell::Cell::new(0usize);
    let hits = match fetch_paginated_with_page_size(
        client,
        |page| search_url(base, query, language, qualifiers, page),
        |json| {
            let (page_hits, raw_count) = parse_search_page(json, include_forks)?;
            // the RAW item count feeds the 422 classifier, not the parsed
            // hits (the same seam rule as `fetch_external_hits`): a fully
            // malformed page followed by a window 422 must not be
            // misclassified as a page-1 rejection
            collected.set(collected.get() + raw_count);
            Ok((page_hits, raw_count))
        },
        Some(ceiling),
        PER_PAGE,
    ) {
        Ok(hits) => hits,
        Err(err) => {
            match crate::sources::classify_search_window_422(&err, collected.get()) {
                // a page-1 422 is the API rejecting the query itself — in
                // practice a nonexistent or inaccessible `--user`/`--org`
                // login: surfaced as [`Error::SearchRejected`] instead of
                // the raw HTTP error
                Some(crate::sources::SearchWindow422::Reject) => {
                    return Err(Error::SearchRejected);
                }
                // a window 422 past the ceiling ends the listing with a
                // warning instead of aborting the whole search with a raw
                // HTTP error (same parity as the user investigation's
                // external-contributions search): the hits already
                // collected are discarded with the warning naming how many
                // were dropped (they are unrecoverable from the paginated
                // loop's error path)
                Some(crate::sources::SearchWindow422::Cut) => {
                    log::warn!(
                        "search stopped at GitHub's 1000-result limit: {} already-found repositories were dropped",
                        collected.get()
                    );
                    Vec::new()
                }
                None => return Err(err),
            }
        }
    };
    if collected.get() >= SEARCH_RESULT_CEILING {
        // the DOCUMENTED 1000-result window was reached in the listing's
        // NORMAL completion path (a `--limit` below the ceiling is the
        // user's own choice, not a truncation: it must never fire this
        // warning — hence the constant, not the passed `ceiling`). The
        // listing was cut at GitHub's documented window, so it must say so
        // instead of looking complete — the same cap-reached warning the
        // external-contributions walk emits (the defensive 422 branch
        // above only covers the pathological classifier-miss path)
        log::warn!(
            "the search was cut at GitHub's documented {SEARCH_RESULT_CEILING}-result window: repositories beyond the first {SEARCH_RESULT_CEILING} matches were not scanned"
        );
    }
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
/// semantics are [`fetch_search_hits`]'s.
pub(crate) fn aggregate_search_at(
    scanner: &Scanner,
    base: &str,
    query: &str,
    language: &str,
    qualifiers: &SearchQualifiers,
    limit: usize,
    include_forks: bool,
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
        include_forks,
    )?;

    let scan = scanner.scan_repositories_at(base, &hits, true)?;
    let mut found_emails = scan.emails;
    sort_emails(&mut found_emails);

    Ok(ScanOutcome {
        emails: found_emails,
        per_repository: scan.per_repository,
        repos_scanned: scan.repos_scanned,
        correlation: scan.correlation,
        partial: scan.partial,
    })
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
/// or an `items` field that is neither an array nor `null`.
pub(crate) fn parse_search_page(
    json: &Value,
    include_forks: bool,
) -> Result<(Vec<RepoHit>, usize), Error> {
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
    // GitHub's repository search INCLUDES forks: like the `user` and `org`
    // listings, forked entries are skipped with a warning unless the caller
    // opted in — a fork's default-branch commits mirror the upstream
    // history, so scanning them would burn the per-repository commit budget
    // on other projects' developers and report them under the fork's name
    let mut repositories = Vec::new();
    let mut malformed = 0usize;
    let mut forks = 0usize;
    for item in items {
        if !include_forks && item.get("fork").and_then(Value::as_bool) == Some(true) {
            forks += 1;
            continue;
        }
        let Some(url) = item.get("html_url").and_then(Value::as_str) else {
            malformed += 1;
            continue;
        };
        let language = item
            .get("language")
            .and_then(Value::as_str)
            .map(str::to_string);
        repositories.push(RepoHit {
            url: url.to_string(),
            language,
        });
    }
    if malformed > 0 {
        log::warn!("malformed search-listing entries skipped: {malformed}");
    }
    if forks > 0 {
        let plural = if forks > 1 {
            "repositories"
        } else {
            "repository"
        };
        log::warn!(
            "{forks} forked {plural} skipped (their history is upstream's): pass --include-forks to scan them"
        );
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

#[cfg(test)]
mod tests {
    // Tests may unwrap, expect and panic freely: a failing assertion must
    // be loud, so the zero-panic lints do not apply to the test modules.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::github::fetch_paginated;
    use crate::github::mock;
    use crate::github::pool::worker_count;
    use std::sync::{Arc, Mutex};

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
        let (hits, raw_count) = parse_search_page(&json, false).expect("parsing must succeed");
        assert_eq!(
            hits,
            vec![
                RepoHit {
                    url: "https://github.com/a/one".to_string(),
                    language: Some("Rust".to_string()),
                },
                RepoHit {
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
        let (outcome, lines) = crate::test_logger::capture(|| parse_search_page(&json, false));
        let (hits, raw_count) = outcome.expect("parsing must succeed");
        assert_eq!(
            hits,
            vec![RepoHit {
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
        let (hits, raw_count) = parse_search_page(&json, false).expect("parsing must succeed");
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
            let error = parse_search_page(&body, false)
                .expect_err("a payload without items must fail explicitly");
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
            let error = parse_search_page(&body, false)
                .expect_err("a non-array items must fail explicitly");
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
    fn a_forked_search_entry_is_skipped_with_a_warning_and_the_opt_in_scans_it() {
        // GitHub's repository search includes forks: like the `user` and
        // `org` listings, a fork is skipped with a warning (its commits
        // mirror the upstream history) unless the caller opted in — the
        // flag's value must reach the PARSER, not just the scanner
        let (address, server) = mock::serve_requests(move |_index, request| {
            let line = request.first().map(String::as_str).unwrap_or("");
            if line.contains("/search/repositories") {
                return match crate::github::mock::request_line_page(request) {
                    1 => (
                        200,
                        vec![],
                        r#"{"total_count": 2, "items": [{"html_url": "https://github.com/a/forked", "fork": true}, {"html_url": "https://github.com/a/one"}]}"#.to_string(),
                    ),
                    _ => (200, vec![], r#"{"items": null}"#.to_string()),
                };
            }
            if line.contains("/repos/a/one/commits") {
                return match crate::github::mock::request_line_page(request) {
                    1 => (
                        200,
                        vec![],
                        format!(
                            "[{}]",
                            r#"{"sha": "abc", "commit": {"author": {"name": "Alice", "email": "alice@acme.com"}}}"#
                        ),
                    ),
                    _ => (200, vec![], "[]".to_string()),
                };
            }
            if line.contains("/repos/a/forked/commits") {
                return match crate::github::mock::request_line_page(request) {
                    1 => (
                        200,
                        vec![],
                        r#"[{"sha": "def", "commit": {"author": {"name": "Forker", "email": "forker@example.com"}}}]"#.to_string(),
                    ),
                    _ => (200, vec![], "[]".to_string()),
                };
            }
            (404, vec![], String::new())
        });

        let scanner =
            crate::sources::Scanner::new(None, None).expect("anonymous scanner must build");

        // default: the fork is skipped with the remedy-naming warning
        let (outcome, lines) = crate::test_logger::capture(|| {
            aggregate_search_at(
                &scanner,
                &address,
                "nmap",
                "",
                &SearchQualifiers::default(),
                5,
                false,
            )
        });
        let outcome = outcome.expect("the fork-free search must succeed");
        assert_eq!(outcome.repos_scanned, 1);
        assert!(
            outcome.emails == vec!["alice@acme.com".to_string()],
            "the fork's upstream emails must not reach the default report"
        );
        assert!(
            lines.iter().any(|line| {
                line.contains("1 forked repository skipped (their history is upstream's): pass --include-forks to scan them")
            }),
            "the fork skip must name the remedy: {lines:?}"
        );

        // opt-in: the fork is scanned like any other repository
        let (outcome, lines) = crate::test_logger::capture(|| {
            aggregate_search_at(
                &scanner,
                &address,
                "nmap",
                "",
                &SearchQualifiers::default(),
                5,
                true,
            )
        });
        let outcome = outcome.expect("the opted-in search must succeed");
        server.join();

        assert_eq!(outcome.repos_scanned, 2);
        assert!(
            outcome.emails.contains(&"forker@example.com".to_string()),
            "the opted-in run must scan the fork: {outcome:?}"
        );
        assert!(
            !lines.iter().any(|line| line.contains("forked repo")),
            "nothing was skipped: no fork warning may fire: {lines:?}"
        );
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
            false,
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
                false,
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
                false,
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
                false,
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
                false,
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
            false,
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
        let (outcome, lines) = crate::test_logger::capture(|| {
            aggregate_search_at(
                &scanner,
                &address,
                "nmap",
                "",
                &SearchQualifiers::default(),
                101,
                false,
            )
        });
        let outcome = outcome.expect("a mid-walk 422 must end the search, not abort it");

        // the fallback discarded the collected hits: an empty (warned-about)
        // listing, not a scan-wide failure — and the discard is NAMED with
        // its count (a deleted or garbled warn must fail this test)
        assert_eq!(outcome.repos_scanned, 0);
        assert!(outcome.emails.is_empty());
        assert!(!outcome.partial);
        assert!(
            lines.iter().any(|line| {
                line.contains("search stopped at GitHub's 1000-result limit: 100 already-found repositories were dropped")
            }),
            "the discard warning must name the dropped count: {lines:?}"
        );
        // exactly two search pages were requested, no repository scan
        assert_eq!(server.join(), 2);
    }

    #[test]
    fn a_full_page_of_forks_still_advances_the_listing() {
        // the raw count feeds the pagination contract: a page of PER_PAGE
        // SKIPPED forks must still read as a full page, or the walk would
        // end early and the page-2 non-fork repository would never be
        // scanned (pin against a regression to the parsed-hits count)
        let forks = (0..PER_PAGE)
            .map(|i| format!(r#"{{"html_url": "https://github.com/a/fork{i}", "fork": true}}"#))
            .collect::<Vec<_>>()
            .join(",");
        let fork_line = format!(
            r#"{{"total_count": {}, "items": [{}]}}"#,
            PER_PAGE + 1,
            forks
        );
        let (address, _server) = mock::serve_requests(move |_index, request| {
            let line = request.first().map(String::as_str).unwrap_or("");
            if line.contains("/search/repositories") {
                return match crate::github::mock::request_line_page(request) {
                    1 => (200, vec![], fork_line.clone()),
                    2 => (
                        200,
                        vec![],
                        r#"{"total_count": 101, "items": [{"html_url": "https://github.com/a/one"}]}"#.to_string(),
                    ),
                    _ => (200, vec![], r#"{"total_count": 101, "items": []}"#.to_string()),
                };
            }
            if line.contains("/repos/a/one/commits") {
                return match crate::github::mock::request_line_page(request) {
                    1 => (
                        200,
                        vec![],
                        r#"[{"sha": "abc", "commit": {"author": {"name": "Alice", "email": "alice@acme.com"}}}]"#.to_string(),
                    ),
                    _ => (200, vec![], "[]".to_string()),
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
                150,
                false,
            )
        });
        let outcome = outcome.expect("the full-fork-page walk must reach page 2");
        assert_eq!(
            outcome.repos_scanned, 1,
            "page 2's non-fork repository must be scanned despite a full page of skipped forks"
        );
        assert!(
            outcome.emails == vec!["alice@acme.com".to_string()],
            "unexpected emails: {outcome:?}"
        );
        assert!(
            lines
                .iter()
                .any(|line| line.contains("forked repositories skipped")),
            "the full-fork-page warning must name the remedy: {lines:?}"
        );
    }

    #[test]
    fn a_fully_malformed_page_followed_by_a_window_422_is_not_a_page1_rejection() {
        // the raw-count seam rule (the same trap `fetch_external_hits`
        // documents): the classifier must see the RAW item count, not the
        // parsed hits, or a page whose every entry is malformed followed by
        // a window 422 would be misclassified as a page-1 rejection and
        // abort a healthy search with a "query rejected" lie
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
                // a full page whose every entry lacks `html_url`: zero
                // parsed hits, but 100 RAW items
                let items: Vec<String> = (0..100).map(|i| format!(r#"{{"id": {i}}}"#)).collect();
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
        let outcome = aggregate_search_at(
            &scanner,
            &address,
            "nmap",
            "",
            &SearchQualifiers::default(),
            101,
            false,
        )
        .expect("raw items were collected: a window 422 must not surface as a page-1 rejection");

        // the Cut arm ran (warn + end of listing), not the Reject arm; and
        // exactly two search pages were requested
        assert_eq!(outcome.repos_scanned, 0);
        assert!(outcome.emails.is_empty());
        assert_eq!(server.join(), 2);
    }

    #[test]
    fn reaching_the_search_ceiling_on_the_normal_path_warns_about_the_truncation() {
        // the honesty rule of the caps: a listing that fills the entire
        // documented search window (exactly the ceiling) must say so even
        // when no 422 ever fires — the identical seam
        // (`fetch_external_hits`) warns on its normal cap path
        let (address, server) = mock::serve_requests(move |_index, request| {
            let line = request.first().map(String::as_str).unwrap_or("");
            if line.contains("/search/repositories") {
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
        // 10 full pages of 100: the listing ends exactly at the ceiling
        let (hits, lines) = crate::test_logger::capture(|| {
            fetch_search_hits(
                scanner.client(),
                &address,
                "nmap",
                "",
                &SearchQualifiers::default(),
                SEARCH_RESULT_CEILING,
                false,
            )
        });
        let hits = hits.expect("the capped listing must complete");
        server.join();

        assert_eq!(hits.len(), SEARCH_RESULT_CEILING);
        assert!(
            lines
                .iter()
                .any(|line| { line.contains("cut at GitHub's documented 1000-result window") }),
            "the normal-path ceiling warning must fire: {lines:?}"
        );
    }

    #[test]
    fn a_limit_below_the_ceiling_never_fires_the_documented_window_warning() {
        // the user's own --limit is not a truncation: a default-size run
        // (--limit 5) collecting exactly 5 matches must stay silent (the
        // warning names GitHub's documented window, never the passed limit)
        let (address, server) = mock::serve_requests(move |_index, request| {
            let line = request.first().map(String::as_str).unwrap_or("");
            if line.contains("/search/repositories") {
                let items: Vec<String> = (0..5)
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
        let (hits, lines) = crate::test_logger::capture(|| {
            fetch_search_hits(
                scanner.client(),
                &address,
                "nmap",
                "",
                &SearchQualifiers::default(),
                5,
                false,
            )
        });
        let hits = hits.expect("the short listing must complete");
        server.join();

        assert_eq!(hits.len(), 5);
        assert!(
            !lines.iter().any(|line| line.contains("documented")),
            "a user-chosen --limit is not a truncation: no window warning: {lines:?}"
        );
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

        let hits: Vec<RepoHit> = ["one", "two", "three"]
            .into_iter()
            .map(|repo| RepoHit {
                url: format!("https://github.com/a/{repo}"),
                language: None,
            })
            .collect();
        let scan = scanner
            .scan_repositories_at(&address, &hits, true)
            .expect("one revoked token must not abort the scan");
        let emails = &scan.emails;
        let repos_scanned = scan.repos_scanned;

        // the revoked token's repository was left unscanned, the two healthy
        // ones were scanned and kept their emails
        assert_eq!(repos_scanned, 2);
        assert_eq!(
            emails,
            &vec!["bob@x.com".to_string(), "carol@x.com".to_string()]
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

        let hits: Vec<RepoHit> = ["one", "two"]
            .into_iter()
            .map(|repo| RepoHit {
                url: format!("https://github.com/a/{repo}"),
                language: None,
            })
            .collect();
        let scan = scanner
            .scan_repositories_at(&address, &hits, true)
            .expect("the live token must cover the whole queue");
        let (emails, repos_scanned, partial) = (&scan.emails, scan.repos_scanned, scan.death_error);
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

        let hits: Vec<RepoHit> = ["one"]
            .into_iter()
            .map(|repo| RepoHit {
                url: format!("https://github.com/a/{repo}"),
                language: None,
            })
            .collect();
        let scan = scanner
            .scan_repositories_at(&address, &hits, true)
            .expect("the live token must scan the single listed repository");
        server.join();

        assert_eq!(scan.repos_scanned, 1);
        assert_eq!(scan.emails, vec!["alice@x.com".to_string()]);
        assert!(scan.death_error.is_none());
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

        let hits: Vec<RepoHit> = ["one", "two", "three"]
            .into_iter()
            .map(|repo| RepoHit {
                url: format!("https://github.com/a/{repo}"),
                language: None,
            })
            .collect();
        let scan = scanner
            .scan_repositories_at(&address, &hits, true)
            .expect("the kept partial result is returned");
        server.join();

        // one repository scanned, two left uncovered by the two dead tokens
        assert!(scan.partial);
        assert_eq!(scan.emails.len(), 1);
        assert!(
            scan.partial,
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
            RepoHit {
                url: "https://github.com/a/hostile\u{1b}[31mname".to_string(),
                language: None,
            },
            RepoHit {
                url: "https://github.com/a/full".to_string(),
                language: None,
            },
        ];
        let (outcome, lines) =
            crate::test_logger::capture(|| scanner.scan_repositories_at(&address, &hits, true));
        let scan = outcome.expect("a resource-scoped failure must not abort the scan");
        server.join();

        // the hostile repository was skipped, the healthy one scanned
        assert_eq!(scan.emails, vec!["alice@x.com".to_string()]);
        assert_eq!(scan.repos_scanned, 1);
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
            false,
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
        let hits: Vec<RepoHit> = fetch_paginated(
            &client,
            |page| format!("{address}/search/repositories?q={q}&per_page={PER_PAGE}&page={page}"),
            |json| parse_search_page(json, true),
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
        let hits: Vec<RepoHit> = fetch_paginated(
            &client,
            |page| format!("{address}/search/repositories?q={q}&per_page={PER_PAGE}&page={page}"),
            |json| parse_search_page(json, true),
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
}
