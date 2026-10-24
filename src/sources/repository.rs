//! Repository commits scan: the emails of a repository's commit authors.

use crate::errors::Error;
use crate::github::{Client, fetch_paginated};
use crate::sources::{PER_PAGE, merge_emails, sort_emails};
use serde_json::Value;

/// Fetches a GitHub repository's commits pages and returns the authors'
/// emails, deduplicated, noreply addresses excluded, sorted.
pub(crate) fn scan_repository(
    client: &Client,
    author: &str,
    repository: &str,
) -> Result<Vec<String>, Error> {
    let page_emails: Vec<String> = fetch_paginated(
        client,
        |page| {
            format!(
                "https://api.github.com/repos/{author}/{repository}/commits?per_page={PER_PAGE}&page={page}"
            )
        },
        parse_commit_page,
        None,
    )?;

    // merge deduplicates across pages
    let mut found_emails: Vec<String> = Vec::new();
    merge_emails(&mut found_emails, page_emails);
    // sort alphabetically found emails
    sort_emails(&mut found_emails);
    Ok(found_emails)
}

/// Extracts the commit authors' emails from a `/commits` page, together with
/// the raw number of commits it holds: the raw count is the end-of-listing
/// signal of `fetch_paginated`, so a page whose every author uses a `noreply`
/// address (parsed to zero emails) does not end the listing.
fn parse_commit_page(json: &Value) -> Result<(Vec<String>, usize), Error> {
    let mut emails: Vec<String> = Vec::new();
    let Some(items) = json.as_array() else {
        return Ok((emails, 0));
    };
    for item in items {
        let Some(email) = item
            .get("commit")
            .and_then(|commit| commit.get("author"))
            .and_then(|author| author.get("email"))
            .and_then(Value::as_str)
        else {
            continue;
        };
        crate::sources::keep_email(&mut emails, email);
    }
    Ok((emails, items.len()))
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
        let (emails, raw_count) = parse_commit_page(&json).expect("parsing must succeed");
        assert_eq!(emails, vec!["dev@example.com".to_string()]);
        assert_eq!(raw_count, 4);
    }

    #[test]
    fn parse_commit_page_empty_array_ends_the_listing() {
        let (emails, raw_count) =
            parse_commit_page(&serde_json::json!([])).expect("parsing must succeed");
        assert!(emails.is_empty());
        assert_eq!(raw_count, 0);
    }

    #[test]
    fn parse_commit_page_keeps_the_raw_count_of_a_noreply_only_page() {
        // a noreply-only page parses to zero emails but still holds commits:
        // its raw item count must not be reported as zero, or the listing
        // would silently end before the pages holding real emails
        let (emails, raw_count) = parse_commit_page(&serde_json::json!([
            { "commit": { "author": { "email": "12345+dev@users.noreply.github.com" } } },
            { "commit": { "author": {} } }
        ]))
        .expect("parsing must succeed");
        assert!(emails.is_empty());
        assert_eq!(raw_count, 2);
    }
}
