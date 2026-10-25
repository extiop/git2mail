//! Profile scan: a profile's events, falling back to its repositories.

use crate::consts::GITHUB_API_BASE;
use crate::correlate::{CorrelationBuilder, RepoContribution};
use crate::errors::Error;
use crate::github::{fetch_paginated, fetch_paginated_with_page_size};
use crate::output::sanitize_log_text as log_safe;
use crate::parsers;
use crate::sources::{PER_PAGE, Scanner, keep_email, merge_emails, sort_emails};
use serde_json::Value;

/// GitHub caps the events timeline at 300 events (REST activity/events
/// docs: "The timeline will include up to 300 events"): requesting past the
/// cap is answered with a raw 422 instead of an empty page. With the API
/// maximum `per_page=100`, a prolific user serves exactly three full pages,
/// and the plain paginated walk used to request page 4 and abort the whole
/// profile scan with a raw HTTP error — discarding the emails already
/// extracted from the 300 events and skipping the repositories fallback
/// (live repro: sindresorhus, yyx990803) — exactly for the most active
/// users, the primary OSINT targets. The walk therefore ends at the cap
/// (the raw-count limit below makes the out-of-window page unreachable),
/// and a 422 that still slips through is treated as the end of the listing
/// when events were already collected — the same window-422 parity the
/// search seams apply to their documented 1000-result ceiling.
const EVENTS_CEILING: usize = 300;

/// Fetches a GitHub profile and its events, via GitHub API.
///
/// It checks the events' metadata to hopefully retrieve the owner's email.
/// GitHub caps the events timeline (300 events over the recent window), so
/// the events technique only sees that documented cap — the scan stays
/// complete within it and falls back to all the user's repositories'
/// commits, which can lead to retrieve multiple developers emails.
pub(crate) fn scan_profile(scanner: &Scanner, author: &str) -> Result<super::ScanOutcome, Error> {
    scan_profile_at(scanner, GITHUB_API_BASE, author)
}

/// The same profile scan, driven against one API base URL: [`scan_profile`]
/// is the production entry point (`https://api.github.com`) and the offline
/// tests run this same code against a loopback mock (the same split as the
/// other scan entry points).
///
/// # Errors
///
/// Returns the failures of the underlying listings and repository scans:
/// a repository that cannot be scanned on its own (deleted, private or
/// empty — GitHub answers 409 on its commits listing) is skipped with a
/// warning, but a rate-limit or transport failure is a scan-wide condition
/// and aborts the scan instead of yielding a complete-looking partial
/// result. Never panics.
pub(crate) fn scan_profile_at(
    scanner: &Scanner,
    base: &str,
    author: &str,
) -> Result<super::ScanOutcome, Error> {
    let mut found_emails: Vec<String> = Vec::new();
    let mut correlation = CorrelationBuilder::new();

    // the events walk ends at GitHub's documented timeline cap (see
    // [`EVENTS_CEILING`]): the raw-count limit stops the listing at the cap
    // so the out-of-window page is never requested, and a 422 that still
    // slips through is treated as the end of the listing when events were
    // already collected (the emails are kept through the shared RefCell the
    // parse closure feeds). A page-1 422 can never be a window 422 (nothing
    // was collected): the API rejected the request itself, and it fails
    // explicitly instead of yielding a complete-looking empty scan
    let collected_emails = std::cell::RefCell::new(Vec::new());
    // the raw listed-event count, threaded out of the parse closure like the
    // sibling repository-budget walks do: the raw-count limit inside the
    // paginated loop silently ends the walk at the cap on a 200, so the
    // boundary (like the repository budget's) must be warned about instead
    // of looking like a complete listing
    let raw_seen = std::cell::Cell::new(0usize);
    let page_emails: Vec<String> = match fetch_paginated_with_page_size(
        scanner.client(),
        |page| {
            // `author` comes from the CLI's URL parser: percent-encoding
            // keeps a hostile `?`, `#` or space in it from re-targeting the
            // authenticated request to another path or query
            format!(
                "{base}/users/{}/events?per_page={PER_PAGE}&page={page}",
                crate::sources::percent_encode(author)
            )
        },
        |json| {
            let (emails, raw) = parse_event_page(json)?;
            collected_emails.borrow_mut().extend(emails.iter().cloned());
            raw_seen.set(raw_seen.get() + raw);
            Ok((emails, raw))
        },
        Some(EVENTS_CEILING),
        PER_PAGE,
    ) {
        Ok(emails) => {
            if raw_seen.get() >= EVENTS_CEILING {
                // the raw count reached the cap: the walk was cut at
                // GitHub's documented timeline window (a user with exactly
                // `EVENTS_CEILING` events also lands here — the "may"
                // phrasing keeps the warning honest for that boundary case
                // too, like the sibling repository budget). Say so instead
                // of letting the events stage look complete
                log::warn!(
                    "GitHub only exposes the most recent {EVENTS_CEILING} events of a profile: older events may not have been scanned"
                );
            }
            emails
        }
        Err(Error::Http(err))
            if err.status() == Some(reqwest::StatusCode::UNPROCESSABLE_ENTITY) =>
        {
            let collected = collected_emails.take();
            if collected.is_empty() {
                return Err(Error::Http(err));
            }
            log::warn!(
                "GitHub only exposes the most recent {EVENTS_CEILING} events of a profile: keeping the emails already collected"
            );
            collected
        }
        Err(err) => return Err(err),
    };
    merge_emails(&mut found_emails, page_emails);

    // if no email found with profile events, check all user repositories commits
    let mut repos_scanned: usize = 0;
    if found_emails.is_empty() {
        let repositories: Vec<String> = fetch_paginated(
            scanner.client(),
            |page| {
                format!(
                    "{base}/users/{}/repos?per_page={PER_PAGE}&page={page}",
                    crate::sources::percent_encode(author)
                )
            },
            parse_repository_page,
            None,
        )?;
        for repository_url in &repositories {
            match parse_repository_parts(repository_url) {
                Ok((repository_author, repository)) => {
                    match super::repository::scan_repository(
                        scanner.client(),
                        base,
                        &repository_author,
                        &repository,
                    ) {
                        Ok(scan) => {
                            merge_emails(&mut found_emails, scan.emails);
                            correlation.add_repo(RepoContribution {
                                name: format!("{repository_author}/{repository}"),
                                // the /repos listing metadata does not carry
                                // the primary language: it would cost one
                                // extra API call per repository (issue #5)
                                language: None,
                                authors: scan.authors,
                            });
                            repos_scanned += 1;
                        }
                        // one resource-scoped failure (deleted, private or
                        // empty repository — GitHub answers 409 on its
                        // commits listing) must not abort the whole fallback
                        // scan and discard the emails already collected from
                        // other repos; a rate-limit or transport failure is a
                        // scan-wide condition and propagates, so the scan can
                        // never silently truncate to a partial result
                        Err(
                            err @ (Error::NotFound
                            | Error::PrivateOrUnavailable
                            | Error::EmptyRepository),
                        ) => {
                            log::warn!("skipping repository {}: {err}", log_safe(repository_url));
                        }
                        Err(err) => return Err(err),
                    }
                }
                // one unparsable URL must not abort the whole fallback scan
                Err(err) => {
                    log::warn!("skipping repository {}: {err}", log_safe(repository_url))
                }
            }
        }
    }

    sort_emails(&mut found_emails);
    Ok(super::ScanOutcome {
        emails: found_emails,
        repos_scanned,
        correlation: correlation.finish(),
        // the profile scan is sequential: it aborts on any scan-wide failure,
        // so it can never keep a partial result
        partial: false,
    })
}

/// Parses the author/repository parts of a fallback repository URL, as the
/// building block of the profile repositories fallback.
fn parse_repository_parts(repository_url: &str) -> Result<(String, String), Error> {
    let repository_author = parsers::get_author(repository_url.to_string())?;
    let repository = parsers::get_repository(repository_url.to_string())?;
    Ok((repository_author, repository))
}

/// Extracts the emails found in a `/users/{author}/events` page: at most one
/// email per event, taken from its `payload.commits[].author.email` metadata,
/// like the legacy scan did. A 200 body that is not a JSON array is an
/// intermediary or a shape change, not an empty page, and fails explicitly
/// instead of silently ending the scan as a complete-looking zero-email
/// result (the same explicit-requirement rule as every other listing).
fn parse_event_page(json: &Value) -> Result<(Vec<String>, usize), Error> {
    let Some(items) = json.as_array() else {
        return Err(Error::InvalidProfile(
            "events payload: not an array".to_string(),
        ));
    };
    let mut emails: Vec<String> = Vec::new();
    for event in items {
        let Some(commits) = event
            .get("payload")
            .and_then(|payload| payload.get("commits"))
            .and_then(Value::as_array)
        else {
            continue;
        };
        for commit in commits {
            let Some(email) = commit
                .get("author")
                .and_then(|author| author.get("email"))
                .and_then(Value::as_str)
            else {
                continue;
            };
            keep_email(&mut emails, email);
            break; // first email found per event, like the legacy scan
        }
    }
    // the raw event count is the end-of-listing signal: an events page whose
    // no event carries a usable email must not end the listing
    Ok((emails, items.len()))
}

/// Extracts the `html_url` of every repository of a `/repos` page. A 200
/// body that is not a JSON array is an intermediary or a shape change, not
/// an empty page, and fails explicitly instead of silently skipping the
/// fallback scan as a complete-looking zero-repository result.
fn parse_repository_page(json: &Value) -> Result<(Vec<String>, usize), Error> {
    let Some(items) = json.as_array() else {
        return Err(Error::InvalidProfile(
            "repositories payload: not an array".to_string(),
        ));
    };
    let repositories = items
        .iter()
        .filter_map(|item| item.get("html_url").and_then(Value::as_str))
        .map(str::to_string)
        .collect();
    Ok((repositories, items.len()))
}

#[cfg(test)]
mod tests {
    // Tests may unwrap, expect and panic freely: a failing assertion must
    // be loud, so the zero-panic lints do not apply to the test modules.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::github::mock;

    #[test]
    fn parse_event_page_takes_one_email_per_event() {
        let json: Value = serde_json::json!([
            {
                "payload": {
                    "commits": [
                        { "author": { "email": "first@example.com" } },
                        { "author": { "email": "second@example.com" } }
                    ]
                }
            },
            { "payload": { "commits": [] } },
            { "type": "PushEvent" }
        ]);
        let emails = parse_event_page(&json).expect("parsing must succeed");
        assert_eq!(emails.0, vec!["first@example.com".to_string()]);
        assert_eq!(emails.1, 3, "raw event count, usable emails or not");
    }

    #[test]
    fn parse_repository_page_extracts_html_urls() {
        let json: Value = serde_json::json!([
            { "html_url": "https://github.com/extiop/ctf" },
            { "name": "no url here" }
        ]);
        let repositories = parse_repository_page(&json).expect("parsing must succeed");
        assert_eq!(
            repositories.0,
            vec!["https://github.com/extiop/ctf".to_string()]
        );
        assert_eq!(repositories.1, 2, "raw item count, with or without url");
    }

    #[test]
    fn the_events_and_repositories_pages_fail_explicitly_on_a_non_array_body() {
        // a 200 body that is not a JSON array (captive portal, proxy, shape
        // change) is not an empty page: it must fail explicitly instead of
        // silently ending the scan as a complete-looking zero result
        for body in [
            serde_json::json!({}),
            serde_json::json!("[]"),
            serde_json::json!(null),
        ] {
            let event_error = parse_event_page(&body).expect_err("events must fail");
            let repos_error = parse_repository_page(&body).expect_err("repos must fail");
            assert!(
                matches!(&event_error, Error::InvalidProfile(details) if details.contains("array")),
                "unexpected events error: {event_error:?}"
            );
            assert!(
                matches!(&repos_error, Error::InvalidProfile(details) if details.contains("array")),
                "unexpected repos error: {repos_error:?}"
            );
        }
    }

    #[test]
    fn the_fallback_scan_skips_one_dead_repository_and_counts_the_scanned_ones() {
        // the events hold no email, so the scan falls back to the user's
        // repositories: one of them is deleted (404) and must be skipped
        // with a warning, the other one is scanned and keeps its emails
        let (address, server) = mock::serve_requests(move |_index, request| {
            let line = request.first().map(String::as_str).unwrap_or("");
            if line.contains("/users/dev/events") {
                return (200, vec![], "[]".to_string());
            }
            if line.contains("/users/dev/repos") {
                return match crate::github::mock::request_line_page(request) {
                    1 => (
                        200,
                        vec![],
                        r#"[{"html_url": "https://github.com/dev/empty"}, {"html_url": "https://github.com/dev/full"}]"#.to_string(),
                    ),
                    _ => (200, vec![], "[]".to_string()),
                };
            }
            if line.contains("/repos/dev/empty/commits") {
                // GitHub's documented 409 for a repository with no commits
                return (409, vec![], String::new());
            }
            if line.contains("/repos/dev/full/commits") {
                return match crate::github::mock::request_line_page(request) {
                    1 => {
                        // a full page of 100 commits (all attributing the
                        // same email): the page-size-aware commit listing
                        // only ends on a short page, and GitHub serves full
                        // pages until the last one
                        let commits: Vec<String> = (0..100)
                            .map(|_| {
                                r#"{"commit": {"author": {"name": "Dev", "email": "dev@x.com"}}}"#
                                    .to_string()
                            })
                            .collect();
                        (200, vec![], format!("[{}]", commits.join(",")))
                    }
                    _ => (200, vec![], "[]".to_string()),
                };
            }
            (404, vec![], String::new())
        });

        let scanner = Scanner::new(None, None).expect("anonymous scanner must build");
        let outcome =
            scan_profile_at(&scanner, &address, "dev").expect("the fallback must succeed");
        // the deleted repository was skipped (not counted as scanned), the
        // other one was scanned and its email kept
        assert_eq!(outcome.emails, vec!["dev@x.com".to_string()]);
        assert_eq!(outcome.repos_scanned, 1);
        assert_eq!(server.join(), 6);
    }

    #[test]
    fn a_rate_limit_mid_fallback_aborts_the_profile_scan_instead_of_truncating_it() {
        // a token parked by a secondary rate limit when the fallback scan
        // reaches the second repository: the skip must NOT swallow it, the
        // scan aborts with the rate-limit error instead of exiting with a
        // complete-looking partial result
        let (address, server) = mock::serve_requests(move |_index, request| {
            let line = request.first().map(String::as_str).unwrap_or("");
            if line.contains("/users/dev/events") {
                return (200, vec![], "[]".to_string());
            }
            if line.contains("/users/dev/repos") {
                // page 1 holds the two repositories, page 2 ends the listing:
                // the mock must behave like the API, or fetch_paginated walks
                // every u16 page of the listing
                return match crate::github::mock::request_line_page(request) {
                    1 => (
                        200,
                        vec![],
                        r#"[{"html_url": "https://github.com/dev/one"}, {"html_url": "https://github.com/dev/two"}]"#.to_string(),
                    ),
                    _ => (200, vec![], "[]".to_string()),
                };
            }
            if line.contains("/repos/dev/one/commits") {
                return (200, vec![], "[]".to_string());
            }
            if line.contains("/repos/dev/two/commits") {
                return (
                    429,
                    vec![("Retry-After".to_string(), "60".to_string())],
                    String::new(),
                );
            }
            (404, vec![], String::new())
        });

        let scanner = Scanner::new(None, None).expect("anonymous scanner must build");
        let error = scan_profile_at(&scanner, &address, "dev")
            .expect_err("a rate limit mid-fallback must abort the scan");
        server.join();
        assert!(
            matches!(error, Error::RateLimitExhausted),
            "unexpected error: {error:?}"
        );
    }

    #[test]
    fn the_events_walk_stops_at_the_documented_300_event_timeline_cap() {
        // GitHub caps the events timeline at 300 events: per_page=100 serves
        // exactly three full pages and the request past the cap is answered
        // with the documented raw 422 (live repro: the profile scan of any
        // prolific user used to abort with 'HTTP 422' on page 4, discarding
        // the emails already extracted). The raw-count limit must end the
        // walk at the cap so the out-of-window page is never requested, and
        // the collected emails must reach the report
        let (address, server) = mock::serve_requests(move |index, _request| {
            match index {
            0..=2 => {
                let events: Vec<String> = (0..100)
                    .map(|_| {
                        r#"{"payload": {"commits": [{"author": {"email": "dev@x.com"}}]}}"#
                            .to_string()
                    })
                    .collect();
                (200, vec![], format!("[{}]", events.join(",")))
            }
            // the out-of-cap request: if a regression walks into it, the
            // scan fails and the handled-count assert below fails too
            _ => (
                422,
                vec![],
                r#"{"message": "In order to keep the API fast for everyone, pagination is limited for this resource."}"#
                    .to_string(),
            ),
        }
        });

        let scanner = Scanner::new(None, None).expect("anonymous scanner must build");
        // the cap ends the walk silently inside the paginated loop: the
        // warning must fire on the raw-count boundary too, not only on the
        // defensive-422 branch (a complete-looking events stage would
        // otherwise hide the cut)
        let (outcome, lines) = crate::test_logger::capture(|| {
            scan_profile_at(&scanner, &address, "dev").expect("the cap must end the walk")
        });
        // the events' emails are kept (so the repositories fallback never
        // runs), and exactly the three in-window pages were requested
        assert_eq!(outcome.emails, vec!["dev@x.com".to_string()]);
        assert_eq!(outcome.repos_scanned, 0);
        assert_eq!(
            server.join(),
            3,
            "the out-of-cap page 4 request must never be issued"
        );
        assert!(
            lines
                .iter()
                .any(|line| line.contains("most recent 300 events")),
            "the cap must warn on the raw-count boundary, got: {lines:?}"
        );
    }

    #[test]
    fn a_window_422_mid_events_keeps_the_collected_emails_instead_of_aborting() {
        // defensive fallback (the cap makes it unreachable for GitHub's
        // documented behavior, mirroring the search seams): a 422 past the
        // window ends the listing with a warning and keeps the emails
        // already collected instead of aborting the whole profile scan
        let (address, server) = mock::serve_requests(move |index, _request| match index {
            0 => {
                let events: Vec<String> = (0..100)
                    .map(|_| {
                        r#"{"payload": {"commits": [{"author": {"email": "dev@x.com"}}]}}"#
                            .to_string()
                    })
                    .collect();
                (200, vec![], format!("[{}]", events.join(",")))
            }
            _ => (
                422,
                vec![],
                r#"{"message": "pagination is limited for this resource"}"#.to_string(),
            ),
        });

        let scanner = Scanner::new(None, None).expect("anonymous scanner must build");
        let outcome = scan_profile_at(&scanner, &address, "dev")
            .expect("a window 422 must end the listing, not abort the scan");
        assert_eq!(outcome.emails, vec!["dev@x.com".to_string()]);
        assert_eq!(server.join(), 2);
    }

    #[test]
    fn a_page1_events_422_fails_the_scan_explicitly_instead_of_an_empty_scan() {
        // with nothing collected, a 422 can never be a window 422: the API
        // rejected the request itself, and it must fail explicitly instead
        // of degrading into a complete-looking zero-email report
        let (address, server) =
            mock::serve_requests(move |_index, _request| (422, vec![], String::new()));

        let scanner = Scanner::new(None, None).expect("anonymous scanner must build");
        let error = scan_profile_at(&scanner, &address, "dev")
            .expect_err("a page-1 422 must fail the scan");
        assert!(
            matches!(&error, Error::Http(http) if http.status() == Some(reqwest::StatusCode::UNPROCESSABLE_ENTITY)),
            "unexpected error: {error:?}"
        );
        assert_eq!(server.join(), 1);
    }
}
