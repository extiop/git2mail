//! Repository commits scan: the emails of a repository's commit authors,
//! plus the per-author attribution consumed by the correlation report
//!.

use crate::correlate::{CommitAuthor, RepoScan};
use crate::errors::Error;
use crate::github::{Client, fetch_paginated_with_page_size};
use crate::sources::{EmailList, PER_PAGE, is_usable_email};
use serde_json::Value;

/// Fetches a GitHub repository's commits pages and returns the authors'
/// emails, deduplicated, noreply addresses excluded, sorted, together with
/// the per-author attribution (name, email, commit count) of the
/// correlation report.
///
/// `base` is the API base URL: the production callers pass the GitHub API
/// base, and the offline tests run this same code against a loopback mock.
///
/// The listing walks the repository's full default-branch history: it ends
/// when GitHub's listing ends (a short page), with no local budget.
pub(crate) fn scan_repository(
    client: &Client,
    base: &str,
    author: &str,
    repository: &str,
) -> Result<RepoScan, Error> {
    // one CommitAuthor per kept commit: pages are merged below, summing the
    // hits of every (name, email) pair across pages. No local budget: the
    // walk ends when GitHub's listing ends (a short page)
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
            Ok((page_authors, raw_count))
        },
        None,
        PER_PAGE,
    )?;

    // merge sums the hits of a (name, email) pair seen on several pages
    let mut authors: Vec<CommitAuthor> = Vec::new();
    for author in kept_commits {
        merge_author(&mut authors, author);
    }
    // the legacy email list: every kept email, deduplicated, sorted (the
    // O(1)-membership accumulator: the adversarial worst case plants
    // thousands of distinct addresses across the pages)
    let mut found_emails = EmailList::new();
    found_emails.merge(authors.iter().map(|author| author.email.clone()).collect());
    found_emails.sort();
    // deterministic attribution order: by author name, then email
    authors.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.email.cmp(&b.email)));
    Ok(RepoScan {
        emails: found_emails.into_vec(),
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
            last_commit_date: author
                .get("date")
                .and_then(Value::as_str)
                .map(str::to_string),
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
    fn parse_commit_page_carries_the_commit_author_date() {
        // the data-freshness field: the raw ISO 8601 stamp of the payload,
        // absent (None) when the page carries none
        let json: Value = serde_json::json!([
            {
                "commit": {
                    "author": {
                        "email": "dev@example.com",
                        "date": "2024-06-01T12:00:00Z"
                    }
                }
            },
            { "commit": { "author": { "email": "other@example.com" } } }
        ]);
        let (authors, _) = parse_commit_page(&json).expect("parsing must succeed");
        assert_eq!(
            authors[0].last_commit_date.as_deref(),
            Some("2024-06-01T12:00:00Z"),
            "the commit date must reach the correlation input"
        );
        assert_eq!(authors[1].last_commit_date, None);
    }

    #[test]
    fn the_correlation_merge_keeps_the_most_recent_commit_date() {
        // the same author seen on several pages/repositories: the report
        // carries the MAXIMUM date (ISO 8601 UTC stamps order
        // lexicographically = chronologically), never the first-seen one
        let mut builder = crate::correlate::CorrelationBuilder::new();
        let contribution = |date: Option<&str>| crate::correlate::RepoContribution {
            name: "acme/one".to_string(),
            language: None,
            authors: vec![crate::correlate::CommitAuthor {
                name: "Alice".to_string(),
                email: "alice@acme.com".to_string(),
                hits: 1,
                last_commit_date: date.map(str::to_string),
            }],
        };
        builder.add_repo(contribution(Some("2024-01-01T00:00:00Z")));
        builder.add_repo(contribution(Some("2025-03-15T10:30:00Z")));
        builder.add_repo(contribution(Some("2023-12-31T23:59:59Z")));
        builder.add_repo(contribution(None));
        let correlation = builder.finish();
        assert_eq!(
            correlation.authors[0].last_commit_date.as_deref(),
            Some("2025-03-15T10:30:00Z"),
            "the most recent date must win the merge"
        );
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
            // mailbox and must never be reported as a found email - the
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
                last_commit_date: None,
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
                    last_commit_date: None,
                },
                CommitAuthor {
                    name: "noname@y.y".to_string(),
                    email: "noname@y.y".to_string(),
                    hits: 1,
                    last_commit_date: None,
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
            last_commit_date: None,
        }];
        merge_author(
            &mut authors,
            CommitAuthor {
                name: "Alice".to_string(),
                email: "alice@x.com".to_string(),
                hits: 2,
                last_commit_date: None,
            },
        );
        merge_author(
            &mut authors,
            CommitAuthor {
                name: "Bob".to_string(),
                email: "bob@y.y".to_string(),
                hits: 1,
                last_commit_date: None,
            },
        );
        assert_eq!(
            authors,
            vec![
                CommitAuthor {
                    name: "Alice".to_string(),
                    email: "alice@x.com".to_string(),
                    hits: 3,
                    last_commit_date: None,
                },
                CommitAuthor {
                    name: "Bob".to_string(),
                    email: "bob@y.y".to_string(),
                    hits: 1,
                    last_commit_date: None,
                },
            ]
        );
    }

    #[test]
    fn scan_repository_walks_the_full_history_with_no_local_budget() {
        // a repository whose history spans more than the old built-in
        // budget (10 pages) must be walked to the END: the only ceilings
        // are GitHub's (pagination ends on a short page), never a local
        // constant - 11 full pages plus the short 12th are all scanned
        let (address, server) = crate::github::mock::serve_requests(move |index, _request| {
            let page = index + 1;
            let per_page = if page < 12 { 100 } else { 37 };
            let commits: Vec<String> = (0..per_page)
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
            .expect("the full walk must succeed");
        let handled = server.join();

        // 11 full pages + the short 12th that ends the listing
        assert_eq!(handled, 12);
        assert_eq!(scan.authors.len(), 11 * 100 + 37);
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
                    last_commit_date: None,
                },
                CommitAuthor {
                    name: "Bob".to_string(),
                    email: "bob@y.y".to_string(),
                    hits: 1,
                    last_commit_date: None,
                },
            ]
        );
        let mut emails = EmailList::new();
        emails.merge(authors.iter().map(|author| author.email.clone()).collect());
        let emails = emails.into_vec();
        assert_eq!(
            emails,
            vec!["alice@x.com".to_string(), "bob@y.y".to_string()]
        );
        server.join();
    }
}
