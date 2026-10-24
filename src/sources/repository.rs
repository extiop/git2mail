//! Repository commits scan: the emails of a repository's commit authors,
//! plus the per-author attribution consumed by the correlation report
//! (issue #5).

use crate::correlate::{CommitAuthor, RepoScan};
use crate::errors::Error;
use crate::github::{Client, fetch_paginated};
use crate::sources::{PER_PAGE, is_usable_email, merge_emails, sort_emails};
use serde_json::Value;

/// Fetches a GitHub repository's commits pages and returns the authors'
/// emails, deduplicated, noreply addresses excluded, sorted, together with
/// the per-author attribution (name, email, commit count) of the
/// correlation report.
pub(crate) fn scan_repository(
    client: &Client,
    author: &str,
    repository: &str,
) -> Result<RepoScan, Error> {
    // one CommitAuthor per kept commit: pages are merged below, summing the
    // hits of every (name, email) pair across pages
    let kept_commits: Vec<CommitAuthor> = fetch_paginated(
        client,
        |page| {
            format!(
                "https://api.github.com/repos/{author}/{repository}/commits?per_page={PER_PAGE}&page={page}"
            )
        },
        parse_commit_page,
        None,
    )?;

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
///
/// Every kept email is attributed to its author name (the correlation
/// report, issue #5): a commit with no author name falls back to the email
/// itself as the author key, so every kept email is correlated.
fn parse_commit_page(json: &Value) -> Result<(Vec<CommitAuthor>, usize), Error> {
    let mut authors: Vec<CommitAuthor> = Vec::new();
    let Some(items) = json.as_array() else {
        return Ok((authors, 0));
    };
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
