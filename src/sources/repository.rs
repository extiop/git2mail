//! Repository commits scan: the emails of a repository's commit authors,
//! plus the per-author attribution consumed by the correlation report
//! (issue #5).

use crate::correlate::{CommitAuthor, RepoScan};
use crate::errors::Error;
use crate::github::{Client, fetch_paginated_with_page_size};
use crate::output::sanitize_log_text as log_safe;
use crate::sources::{PER_PAGE, is_usable_email, merge_emails, sort_emails};
use serde_json::Value;
use std::cell::Cell;

/// Cap on the number of commit pages one repository scan lists (the same
/// honesty budget as the reverse lookup's candidate verification): only the
/// most recent `MAX_COMMIT_PAGES * PER_PAGE` commits of the default branch
/// are walked, so a single large repository (or an `org` scan across many
/// of them) can never burn the whole hourly token pool on one commit
/// history and abort a nearly-complete investigation with
/// [`Error::RateLimitExhausted`]. When the budget cuts the walk, a warning
/// says the history may be incomplete instead of the scan silently
/// pretending it saw all of it.
pub(crate) const MAX_COMMIT_PAGES: usize = 10;

/// Fetches a GitHub repository's commits pages and returns the authors'
/// emails, deduplicated, noreply addresses excluded, sorted, together with
/// the per-author attribution (name, email, commit count) of the
/// correlation report.
///
/// `base` is the API base URL: the production callers pass the GitHub API
/// base, and the offline tests run this same code against a loopback mock.
///
/// The listing is capped at [`MAX_COMMIT_PAGES`] pages of commits (counted
/// in raw commits): when the budget cuts the walk, a warning says the
/// history may be incomplete instead of the scan silently pretending it
/// saw all of it.
pub(crate) fn scan_repository(
    client: &Client,
    base: &str,
    author: &str,
    repository: &str,
) -> Result<RepoScan, Error> {
    // one CommitAuthor per kept commit: pages are merged below, summing the
    // hits of every (name, email) pair across pages. The raw commit count
    // streams through this cell so a budget cut can be warned about after
    // the walk
    let listed_commits = Cell::new(0usize);
    let commit_ceiling = MAX_COMMIT_PAGES * usize::from(PER_PAGE);
    let kept_commits: Vec<CommitAuthor> = fetch_paginated_with_page_size(
        client,
        |page| {
            // the names are parser- or listing-derived (a profile's repos
            // listing, an email candidate's `html_url`): percent-encoding
            // keeps a hostile `?`, `#`, `&` or `/` from re-targeting the
            // authenticated request to another path or query
            format!(
                "{base}/repos/{}/{}/commits?per_page={PER_PAGE}&page={page}",
                crate::sources::percent_encode(author),
                crate::sources::percent_encode(repository)
            )
        },
        |json| {
            let (page_authors, raw_count) = parse_commit_page(json)?;
            listed_commits.set(listed_commits.get() + raw_count);
            Ok((page_authors, raw_count))
        },
        Some(commit_ceiling),
        PER_PAGE,
    )?;
    if listed_commits.get() >= commit_ceiling {
        // the raw-count ceiling was reached: the walk was cut at the
        // repository budget (a repository with exactly `commit_ceiling`
        // commits also lands here — the "may" phrasing keeps the warning
        // honest for that boundary case too). Say so instead of letting the
        // report look complete
        log::warn!(
            "repository {}/{}: only the most recent {} commits were scanned (built-in limit), older commits may hold emails that were missed",
            log_safe(author),
            log_safe(repository),
            listed_commits.get()
        );
    }

    // merge sums the hits of a (name, email) pair seen on several pages
    let mut authors: Vec<CommitAuthor> = Vec::new();
    for author in kept_commits {
        merge_author(&mut authors, author);
    }
    // the legacy email list: every kept email, deduplicated, sorted
    let mut found_emails: Vec<String> = Vec::new();
    merge_emails(
        &mut found_emails,
        authors.iter().map(|author| author.email.clone()).collect(),
    );
    // sort alphabetically found emails
    sort_emails(&mut found_emails);
    // deterministic attribution order: by author name, then email
    authors.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.email.cmp(&b.email)));
    Ok(RepoScan {
        emails: found_emails,
        authors,
    })
}

/// Merges one author attribution into an accumulated list, summing the
/// commit hits of an already-known (name, email) pair.
fn merge_author(authors: &mut Vec<CommitAuthor>, author: CommitAuthor) {
    if let Some(existing) = authors
        .iter_mut()
        .find(|existing| existing.name == author.name && existing.email == author.email)
    {
        existing.hits += author.hits;
    } else {
        authors.push(author);
    }
}

/// Extracts the kept commit authors from a `/commits` page (one
/// [`CommitAuthor`] with one hit per kept commit), together with the raw
/// number of commits the page holds: the raw count is the end-of-listing
/// signal of `fetch_paginated`, so a page whose every author uses a
/// `noreply` address (parsed to zero authors) does not end the listing.
/// A 200 body that is not a JSON array is an intermediary or a shape
/// change, not an empty page, and fails explicitly instead of silently
/// ending the scan as a complete-looking zero-email result (the same
/// explicit-requirement rule as every other listing of the crate).
fn parse_commit_page(json: &Value) -> Result<(Vec<CommitAuthor>, usize), Error> {
    let Some(items) = json.as_array() else {
        return Err(Error::InvalidProfile(
            "commits payload: not an array".to_string(),
        ));
    };
    let mut authors: Vec<CommitAuthor> = Vec::new();
    for item in items {
        let Some(author) = item.get("commit").and_then(|commit| commit.get("author")) else {
            continue;
        };
        let Some(email) = author.get("email").and_then(Value::as_str) else {
            continue;
        };
        // the exact acceptance rule of the plain output (shared helper), so
        // the correlation only ever attributes emails the legacy list keeps
        if !is_usable_email(email) {
            continue;
        }
        let email = email.trim_matches('"');
        let name = author
            .get("name")
            .and_then(Value::as_str)
            .filter(|name| !name.is_empty())
            .unwrap_or(email);
        authors.push(CommitAuthor {
            name: name.to_string(),
            email: email.to_string(),
            hits: 1,
        });
    }
    Ok((authors, items.len()))
}

#[cfg(test)]
mod tests {
    // Tests may unwrap, expect and panic freely: a failing assertion must
    // be loud, so the zero-panic lints do not apply to the test modules.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn parse_commit_page_extracts_commit_author_emails() {
        let json: Value = serde_json::json!([
            { "commit": { "author": { "email": "dev@example.com" } } },
            { "commit": { "author": { "email": "12345+dev@users.noreply.github.com" } } },
            { "commit": { "author": {} } },
            { "other": true }
        ]);
        let (authors, raw_count) = parse_commit_page(&json).expect("parsing must succeed");
        let emails: Vec<String> = authors.iter().map(|author| author.email.clone()).collect();
        assert_eq!(emails, vec!["dev@example.com".to_string()]);
        assert_eq!(raw_count, 4);
    }

    #[test]
    fn parse_commit_page_empty_array_ends_the_listing() {
        let (authors, raw_count) =
            parse_commit_page(&serde_json::json!([])).expect("parsing must succeed");
        assert!(authors.is_empty());
        assert_eq!(raw_count, 0);
    }

    #[test]
    fn parse_commit_page_fails_explicitly_on_a_body_that_is_not_an_array() {
        // a 200 body that is not a JSON array (captive portal, proxy, shape
        // change) is not an empty page: it must fail explicitly instead of
        // silently ending the scan as a complete-looking zero-email result
        for body in [
            serde_json::json!({}),
            serde_json::json!("[]"),
            serde_json::json!(null),
        ] {
            let error =
                parse_commit_page(&body).expect_err("a non-array body must fail explicitly");
            assert!(matches!(error, Error::InvalidProfile(details) if details.contains("array")));
        }
    }

    #[test]
    fn scan_repository_percent_encodes_the_author_and_repository_path_segments() {
        // the names composed into the API path can be parser- or
        // listing-derived: a hostile `?`, `#`, `&` or space must be
        // percent-encoded, never passed raw (it would re-target the
        // authenticated request to another path or query)
        let (address, server) = crate::github::mock::serve_requests(move |_index, request| {
            let request_line = &request[0];
            assert!(
                request_line.starts_with("GET /repos/a%3Fb/c%23d%26e/commits?"),
                "unexpected request line: {request_line}"
            );
            (200, vec![], "[]".to_string())
        });

        let client = crate::github::Client::anonymous().expect("client must build");
        scan_repository(&client, &address, "a?b", "c#d&e")
            .expect("the encoded names must still scan");
        server.join();
    }

    #[test]
    fn a_trailing_slash_url_scans_the_existing_repository_end_to_end() {
        // the pasted URL `https://github.com/octocat/hello-world/` must reach the
        // API as `/repos/octocat/hello-world/commits`, not the unresolvable
        // `/repos/octocat/hello-world%2F/commits` (a guaranteed 404 on an existing
        // repository): the parser trims the paste artifact, the scan runs
        // on the real name
        let (address, server) = crate::github::mock::serve_requests(move |_index, request| {
            let request_line = &request[0];
            assert!(
                request_line.starts_with("GET /repos/octocat/hello-world/commits?"),
                "unexpected request line: {request_line}"
            );
            (200, vec![], "[]".to_string())
        });

        let client = crate::github::Client::anonymous().expect("client must build");
        let author =
            crate::parsers::get_author("https://github.com/octocat/hello-world/".to_string())
                .expect("the pasted URL must parse");
        let repository =
            crate::parsers::get_repository("https://github.com/octocat/hello-world/".to_string())
                .expect("the pasted URL must parse");
        scan_repository(&client, &address, &author, &repository)
            .expect("the trimmed name must still scan");
        server.join();
    }

    #[test]
    fn parse_commit_page_drops_hostile_emails_at_the_parse_seam() {
        // the plain-output acceptance rule is enforced here, in
        // `parse_commit_page` (not only in the `is_usable_email` helper):
        // a commit email carrying a control character (a crafted newline
        // would inject lines into the one-email-per-line results file) or
        // whitespace must never be kept
        let json: Value = serde_json::json!([
            { "commit": { "author": { "email": "dev@x.com\n evil@x.com" } } },
            { "commit": { "author": { "email": "dev@x.com\u{1b}[31m" } } },
            { "commit": { "author": { "email": "dev\t@x.com" } } },
            { "commit": { "author": { "email": "dev @x.com" } } },
            { "commit": { "author": { "email": "real@x.com" } } },
            // git permits any author-email string: a domainless value (a
            // bare username, seen live in real commit payloads) is not a
            // mailbox and must never be reported as a found email — the
            // `email` subcommand itself rejects it as invalid
            { "commit": { "author": { "name": "Thomas", "email": "jdoe" } } }
        ]);
        let (authors, raw_count) = parse_commit_page(&json).expect("parsing must succeed");
        // the raw count still counts the page's commits (end-of-listing
        // signal), but only the usable email is kept
        assert_eq!(raw_count, 6);
        assert_eq!(
            authors,
            vec![CommitAuthor {
                name: "real@x.com".to_string(),
                email: "real@x.com".to_string(),
                hits: 1,
            }]
        );
    }

    #[test]
    fn parse_commit_page_keeps_the_raw_count_of_a_noreply_only_page() {
        // a noreply-only page parses to zero emails but still holds commits:
        // its raw item count must not be reported as zero, or the listing
        // would silently end before the pages holding real emails
        let (authors, raw_count) = parse_commit_page(&serde_json::json!([
            { "commit": { "author": { "email": "12345+dev@users.noreply.github.com" } } },
            { "commit": { "author": {} } }
        ]))
        .expect("parsing must succeed");
        assert!(authors.is_empty());
        assert_eq!(raw_count, 2);
    }

    #[test]
    fn parse_commit_page_attributes_authors_with_name_fallback() {
        let json: Value = serde_json::json!([
            { "commit": { "author": { "name": "Alice", "email": "alice@x.com" } } },
            { "commit": { "author": { "name": "", "email": "noname@y.y" } } },
            { "commit": { "author": { "name": "Bob", "email": "12345+b@users.noreply.github.com" } } }
        ]);
        let (page, raw_count) = parse_commit_page(&json).expect("parsing must succeed");
        assert_eq!(raw_count, 3);
        // the nameless author falls back to the email as the author key, and
        // the noreply address is excluded
        assert_eq!(
            page,
            vec![
                CommitAuthor {
                    name: "Alice".to_string(),
                    email: "alice@x.com".to_string(),
                    hits: 1,
                },
                CommitAuthor {
                    name: "noname@y.y".to_string(),
                    email: "noname@y.y".to_string(),
                    hits: 1,
                },
            ]
        );
    }

    #[test]
    fn merge_author_sums_hits_of_known_pairs_and_keeps_new_ones() {
        let mut authors = vec![CommitAuthor {
            name: "Alice".to_string(),
            email: "alice@x.com".to_string(),
            hits: 1,
        }];
        merge_author(
            &mut authors,
            CommitAuthor {
                name: "Alice".to_string(),
                email: "alice@x.com".to_string(),
                hits: 2,
            },
        );
        merge_author(
            &mut authors,
            CommitAuthor {
                name: "Bob".to_string(),
                email: "bob@y.y".to_string(),
                hits: 1,
            },
        );
        assert_eq!(
            authors,
            vec![
                CommitAuthor {
                    name: "Alice".to_string(),
                    email: "alice@x.com".to_string(),
                    hits: 3,
                },
                CommitAuthor {
                    name: "Bob".to_string(),
                    email: "bob@y.y".to_string(),
                    hits: 1,
                },
            ]
        );
    }

    #[test]
    fn scan_repository_commit_listing_is_capped_per_repository() {
        // a repository whose history never ends (every page holds 100
        // commits with a fresh, usable email) must not walk its entire
        // commit history: the repository budget caps the listing at
        // MAX_COMMIT_PAGES pages counted in raw commits, and the walk stops
        // instead of draining the token pool page after page
        let (address, server) = crate::github::mock::serve_requests(move |index, _request| {
            let commits: Vec<String> = (0..100)
                .map(|i| {
                    format!(
                        r#"{{"commit": {{"author": {{"name": "Dev{}", "email": "dev{}{}@x.com"}}}}}}"#,
                        index, index, i
                    )
                })
                .collect();
            (200, vec![], format!("[{}]", commits.join(",")))
        });

        let client = crate::github::Client::anonymous().expect("client must build");
        let scan = scan_repository(&client, &address, "octocat", "huge")
            .expect("the capped listing must succeed");
        let handled = server.join();

        // the ceiling is reached on the 10th full page: no 11th request, no
        // empty page to wait for
        assert_eq!(handled, MAX_COMMIT_PAGES);
        // every kept author of the capped pages is reported
        assert_eq!(scan.authors.len(), MAX_COMMIT_PAGES * 100);
        assert_eq!(scan.emails.len(), MAX_COMMIT_PAGES * 100);
    }

    #[test]
    fn fetch_paginated_pages_merge_their_author_hits_across_pages() {
        let (address, server) = crate::github::mock::serve_requests(move |index, _request| {
            // two content pages then the empty one ending the listing: the
            // same (name, email) pair shows up on both pages
            let body = match index {
                0 => r#"[{"commit": {"author": {"name": "Alice", "email": "alice@x.com"}}},
                         {"commit": {"author": {"name": "Bob", "email": "bob@y.y"}}}]"#
                    .to_string(),
                1 => r#"[{"commit": {"author": {"name": "Alice", "email": "alice@x.com"}}}]"#
                    .to_string(),
                _ => "[]".to_string(),
            };
            (200, vec![], body)
        });

        let client = crate::github::Client::anonymous().expect("client must build");
        let kept_commits: Vec<CommitAuthor> = crate::github::fetch_paginated(
            &client,
            |page| format!("{address}/commits?page={page}"),
            parse_commit_page,
            None,
        )
        .expect("the listing must succeed");

        // the same fold as scan_repository: hits of a (name, email) pair are
        // summed across pages, and the legacy email list stays deduplicated
        let mut authors: Vec<CommitAuthor> = Vec::new();
        for author in kept_commits {
            merge_author(&mut authors, author);
        }
        assert_eq!(
            authors,
            vec![
                CommitAuthor {
                    name: "Alice".to_string(),
                    email: "alice@x.com".to_string(),
                    hits: 2,
                },
                CommitAuthor {
                    name: "Bob".to_string(),
                    email: "bob@y.y".to_string(),
                    hits: 1,
                },
            ]
        );
        let mut emails: Vec<String> = Vec::new();
        merge_emails(
            &mut emails,
            authors.iter().map(|author| author.email.clone()).collect(),
        );
        assert_eq!(
            emails,
            vec!["alice@x.com".to_string(), "bob@y.y".to_string()]
        );
        server.join();
    }
}
