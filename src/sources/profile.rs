//! Profile scan: a profile's events, falling back to its repositories.

use crate::errors::Error;
use crate::github::fetch_paginated;
use crate::parsers;
use crate::sources::{PER_PAGE, Scanner, keep_email, merge_emails, sort_emails};
use serde_json::Value;

/// Fetches a GitHub profile and its events, via GitHub API.
///
/// It gets every event from it and checks their metadata to hopefully
/// retrieve the owner's email. If no email is found with profile events,
/// it checks all the user's repositories commits, which can lead to
/// retrieve multiple developers emails.
pub(crate) fn scan_profile(scanner: &Scanner, author: &str) -> Result<super::ScanOutcome, Error> {
    let mut found_emails: Vec<String> = Vec::new();

    let page_emails: Vec<String> = fetch_paginated(
        scanner.client(),
        |page| {
            format!("https://api.github.com/users/{author}/events?per_page={PER_PAGE}&page={page}")
        },
        parse_event_page,
        None,
    )?;
    merge_emails(&mut found_emails, page_emails);

    // if no email found with profile events, check all user repositories commits
    let mut repos_scanned: usize = 0;
    if found_emails.is_empty() {
        let repositories: Vec<String> = fetch_paginated(
            scanner.client(),
            |page| {
                format!(
                    "https://api.github.com/users/{author}/repos?per_page={PER_PAGE}&page={page}"
                )
            },
            parse_repository_page,
            None,
        )?;
        for repository_url in &repositories {
            match scan_repository_url(scanner.client(), repository_url) {
                Ok(emails) => {
                    merge_emails(&mut found_emails, emails);
                    repos_scanned += 1;
                }
                // one failing repository (deleted, private, unparsable URL…)
                // must not abort the whole fallback scan and discard the
                // emails already collected from the events or other repos
                Err(err) => log::warn!("skipping repository {repository_url}: {err}"),
            }
        }
    }

    sort_emails(&mut found_emails);
    Ok(super::ScanOutcome {
        emails: found_emails,
        repos_scanned,
    })
}

/// Scans one repository URL (parse its author/repository parts, then fetch
/// its commits), as the building block of the profile repositories fallback.
fn scan_repository_url(
    client: &crate::github::Client,
    repository_url: &str,
) -> Result<Vec<String>, Error> {
    let repository_author = parsers::get_author(repository_url.to_string())?;
    let repository = parsers::get_repository(repository_url.to_string())?;
    super::repository::scan_repository(client, &repository_author, &repository)
}

/// Extracts the emails found in a `/users/{author}/events` page: at most one
/// email per event, taken from its `payload.commits[].author.email` metadata,
/// like the legacy scan did.
fn parse_event_page(json: &Value) -> Result<(Vec<String>, usize), Error> {
    let mut emails: Vec<String> = Vec::new();
    let Some(items) = json.as_array() else {
        return Ok((emails, 0));
    };
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

/// Extracts the `html_url` of every repository of a `/repos` page.
fn parse_repository_page(json: &Value) -> Result<(Vec<String>, usize), Error> {
    let Some(items) = json.as_array() else {
        return Ok((Vec::new(), 0));
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
}
