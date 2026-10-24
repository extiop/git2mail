//! Per-author attribute correlation (issue #5, roadmap 0.6.0): aggregates
//! the scan results per author with the attributes git2mail already
//! collects — the repositories scanned, their primary language (when the
//! search API metadata reports it) and the commit counts — into a
//! per-author correlation report.
//!
//! The report is exposed in the opt-in `--json` output (the `correlation`
//! object, on top of the unchanged legacy fields) and summarized in the
//! terminal log (top authors with their dominant language). The plain-text
//! result files keep the legacy one-email-per-line format, byte-identical.
//!
//! The aggregation is pure and infallible: it performs no I/O, never panics
//! and therefore defines no error variant (the crate philosophy: hand-made
//! errors only where something can actually fail).

use log::info;
use serde::Serialize;
use std::collections::HashMap;

/// One commit author as attributed by a repository scan: the author name the
/// commits expose (falling back to the email when the commit carries no
/// name), the kept email (deduplicated, noreply excluded, like the legacy
/// result) and the number of commits exposing that name/email pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitAuthor {
    /// The commit author name (or the email itself when the commit has none).
    pub name: String,
    /// The kept commit author email.
    pub email: String,
    /// How many commits of the scan exposed this name/email pair.
    pub hits: usize,
}

/// Result of scanning one repository: the legacy deduplicated email list
/// (the unchanged plain-text output) plus the per-author attribution
/// consumed by the correlation report.
#[derive(Debug, Default)]
pub struct RepoScan {
    /// Kept emails, deduplicated across pages and sorted alphabetically
    /// (case-insensitively), exactly as the legacy scan returned them.
    pub emails: Vec<String>,
    /// The authors behind those emails, with their per-repository commit
    /// counts, sorted by name then email for a deterministic report.
    pub authors: Vec<CommitAuthor>,
}

/// One repository scan's contribution to the correlation report: its
/// `owner/name`, its primary language (only when known, i.e. coming from the
/// search API metadata; a repository or profile scan contributes `None`
/// rather than spending an extra API call on it) and the authors its
/// commits exposed.
#[derive(Debug)]
pub struct RepoContribution {
    /// The repository `owner/name`.
    pub name: String,
    /// The repository primary language, when the scan knows it.
    pub language: Option<String>,
    /// The authors the repository's commits exposed.
    pub authors: Vec<CommitAuthor>,
}

/// One repository an author was seen in, with its primary language.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RepoLanguage {
    /// The repository `owner/name`.
    pub name: String,
    /// The repository primary language, `null` when the scan could not know
    /// it (repository and profile scans do not fetch it).
    pub language: Option<String>,
}

/// The per-author correlation report (issue #5): the `correlation` object of
/// the opt-in `--json` output, on top of the unchanged legacy fields.
#[derive(Debug, Default, Serialize)]
pub struct Correlation {
    /// One entry per author, sorted by descending commit count (then author
    /// name, case-insensitively, so the report is deterministic).
    pub authors: Vec<AuthorReport>,
}

impl Correlation {
    /// How many authors the terminal summary shows.
    pub const SUMMARY_TOP: usize = 5;

    /// Logs a human-readable summary of the top authors with their dominant
    /// language (terminal output only: the plain-text result files stay
    /// byte-identical to the legacy format). Silent when no author was
    /// correlated.
    pub fn log_summary(&self) {
        if self.authors.is_empty() {
            return;
        }
        let summary: Vec<String> = self
            .authors
            .iter()
            .take(Self::SUMMARY_TOP)
            .map(|author| {
                let email = author
                    .emails
                    .first()
                    .map(String::as_str)
                    .unwrap_or("no email");
                let language = author
                    .languages
                    .first()
                    .map(String::as_str)
                    .unwrap_or("unknown language");
                format!(
                    "{} <{email}> — {language}, {} commits",
                    crate::output::sanitize_log_text(&author.author),
                    author.total_hits
                )
            })
            .collect();
        info!("[+] Top authors: {}", summary.join("; "));
    }
}

/// One author's correlated attributes (one entry of
/// [`Correlation::authors`]).
#[derive(Debug, Serialize)]
pub struct AuthorReport {
    /// The author name the commits expose (the report key). Same-name
    /// authors are merged: an OSINT heuristic, like GitHub's own
    /// name-based suggestions.
    pub author: String,
    /// Every email this author used across the scanned repositories, sorted
    /// alphabetically (case-insensitively).
    pub emails: Vec<String>,
    /// The repositories the author was seen in, in scan order.
    pub repos: Vec<RepoLanguage>,
    /// The languages of those repositories, weighted by the author's commit
    /// count in them and ordered dominant (most commits) first; ties are
    /// broken alphabetically for a deterministic report.
    pub languages: Vec<String>,
    /// The first repository (in scan order) where the author was seen. With
    /// a parallel multi-token search, scan order follows worker completion
    /// and may vary between runs.
    pub first_seen_repo: String,
    /// The total number of kept commits by this author across all the
    /// scanned repositories.
    pub total_hits: usize,
}

/// The mutable per-author aggregate behind one [`AuthorReport`].
#[derive(Default)]
struct AuthorAggregate {
    emails: Vec<String>,
    repos: Vec<RepoLanguage>,
    first_seen_repo: Option<String>,
    total_hits: usize,
    /// Commit hits per repository language (languages only; repositories
    /// with an unknown language contribute nothing).
    language_hits: HashMap<String, usize>,
}

/// Accumulates the per-repository contributions of a scan into the
/// per-author correlation report.
#[derive(Default)]
pub struct CorrelationBuilder {
    authors: HashMap<String, AuthorAggregate>,
}

impl CorrelationBuilder {
    /// Creates an empty aggregation.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds every repository contribution of a scan stage, in order.
    pub fn add_all(&mut self, contributions: impl IntoIterator<Item = RepoContribution>) {
        for contribution in contributions {
            self.add_repo(contribution);
        }
    }

    /// Merges one repository's contribution into the aggregates: the same
    /// author seen in several repositories (across pages, workers or scan
    /// stages) is merged — emails deduplicated, repositories deduplicated
    /// and hit counts summed.
    pub fn add_repo(&mut self, contribution: RepoContribution) {
        for author in contribution.authors {
            let aggregate = self.authors.entry(author.name).or_default();
            if !aggregate.emails.iter().any(|email| email == &author.email) {
                aggregate.emails.push(author.email);
            }
            if !aggregate
                .repos
                .iter()
                .any(|repo| repo.name == contribution.name)
            {
                aggregate.repos.push(RepoLanguage {
                    name: contribution.name.clone(),
                    language: contribution.language.clone(),
                });
            }
            if aggregate.first_seen_repo.is_none() {
                aggregate.first_seen_repo = Some(contribution.name.clone());
            }
            aggregate.total_hits += author.hits;
            if let Some(language) = &contribution.language {
                *aggregate.language_hits.entry(language.clone()).or_insert(0) += author.hits;
            }
        }
    }

    /// Folds the accumulated aggregates into the final report: authors
    /// sorted by descending commit count (then name, for determinism),
    /// emails sorted alphabetically and languages ordered dominant first.
    pub fn finish(self) -> Correlation {
        let mut authors: Vec<AuthorReport> = self
            .authors
            .into_iter()
            .map(|(name, aggregate)| {
                let mut emails = aggregate.emails;
                emails.sort_by_key(|email| email.to_lowercase());
                let mut languages: Vec<(String, usize)> =
                    aggregate.language_hits.into_iter().collect();
                languages.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
                AuthorReport {
                    author: name,
                    emails,
                    repos: aggregate.repos,
                    languages: languages
                        .into_iter()
                        .map(|(language, _)| language)
                        .collect(),
                    first_seen_repo: aggregate.first_seen_repo.unwrap_or_default(),
                    total_hits: aggregate.total_hits,
                }
            })
            .collect();
        authors.sort_by(|a, b| {
            b.total_hits
                .cmp(&a.total_hits)
                .then_with(|| a.author.to_lowercase().cmp(&b.author.to_lowercase()))
        });
        Correlation { authors }
    }
}

#[cfg(test)]
mod tests {
    // Tests may unwrap, expect and panic freely: a failing assertion must
    // be loud, so the zero-panic lints do not apply to the test modules.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    /// Builds one repository contribution from `(name, email, hits)` triples.
    fn contribution(
        repo: &str,
        language: Option<&str>,
        authors: &[(&str, &str, usize)],
    ) -> RepoContribution {
        RepoContribution {
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
        }
    }

    #[test]
    fn aggregation_merges_authors_across_repositories_and_dedupes() {
        // same author in two repositories (the aggregation across pages,
        // workers and scan stages), with an email repeated in both
        let mut builder = CorrelationBuilder::new();
        builder.add_repo(contribution(
            "a/one",
            Some("Rust"),
            &[("Alice", "alice@x.com", 2), ("Bob", "bob@y.y", 1)],
        ));
        builder.add_repo(contribution(
            "b/two",
            Some("Go"),
            &[("Alice", "alice@x.com", 1), ("Alice", "ali@z.z", 3)],
        ));

        let correlation = builder.finish();
        assert_eq!(correlation.authors.len(), 2);
        // dominant author first: Alice (6 commits) before Bob (1)
        let alice = &correlation.authors[0];
        assert_eq!(alice.author, "Alice");
        assert_eq!(alice.total_hits, 6);
        // emails deduplicated and sorted alphabetically
        assert_eq!(
            alice.emails,
            vec!["ali@z.z".to_string(), "alice@x.com".to_string()]
        );
        // repositories in scan order, first seen first
        assert_eq!(alice.first_seen_repo, "a/one");
        assert_eq!(
            alice.repos,
            vec![
                RepoLanguage {
                    name: "a/one".to_string(),
                    language: Some("Rust".to_string()),
                },
                RepoLanguage {
                    name: "b/two".to_string(),
                    language: Some("Go".to_string()),
                },
            ]
        );
        // the second author keeps its own email and repository
        let bob = &correlation.authors[1];
        assert_eq!(bob.author, "Bob");
        assert_eq!(bob.emails, vec!["bob@y.y".to_string()]);
        assert_eq!(bob.total_hits, 1);
        assert_eq!(bob.first_seen_repo, "a/one");
    }

    #[test]
    fn languages_are_ordered_dominant_first_with_alphabetical_ties() {
        let mut builder = CorrelationBuilder::new();
        // Go: 1 + 3 = 4 hits, Rust: 2 hits, C: 2 hits (tie with Rust)
        builder.add_repo(contribution(
            "a/one",
            Some("Rust"),
            &[("Alice", "alice@x.com", 2)],
        ));
        builder.add_repo(contribution(
            "b/two",
            Some("Go"),
            &[("Alice", "alice@x.com", 1)],
        ));
        builder.add_repo(contribution(
            "c/three",
            Some("C"),
            &[("Alice", "alice@x.com", 2)],
        ));
        builder.add_repo(contribution(
            "d/four",
            Some("Go"),
            &[("Alice", "alice@x.com", 3)],
        ));
        // repositories with an unknown language contribute no language
        builder.add_repo(contribution("e/five", None, &[("Alice", "alice@x.com", 9)]));

        let correlation = builder.finish();
        let alice = &correlation.authors[0];
        assert_eq!(
            alice.languages,
            vec!["Go".to_string(), "C".to_string(), "Rust".to_string()]
        );
        // the hits of the unknown-language repository still count
        assert_eq!(alice.total_hits, 17);
    }

    #[test]
    fn authors_are_sorted_by_descending_hits_then_name() {
        let mut builder = CorrelationBuilder::new();
        builder.add_repo(contribution(
            "a/one",
            Some("Rust"),
            &[
                ("zed", "zed@z.z", 1),
                ("Bob", "b@b.b", 3),
                ("alice", "a@a.a", 3),
            ],
        ));

        let correlation = builder.finish();
        let names: Vec<&str> = correlation
            .authors
            .iter()
            .map(|author| author.author.as_str())
            .collect();
        // equal hit counts tie-break case-insensitively by name
        assert_eq!(names, vec!["alice", "Bob", "zed"]);
    }

    #[test]
    fn the_report_serializes_the_documented_json_shape() {
        let mut builder = CorrelationBuilder::new();
        builder.add_repo(contribution(
            "a/one",
            Some("Rust"),
            &[("Alice", "alice@x.com", 2)],
        ));
        let value = serde_json::to_value(builder.finish()).expect("report must serialize");

        let authors = value["authors"].as_array().expect("authors array");
        assert_eq!(authors.len(), 1);
        let alice = &authors[0];
        assert_eq!(alice["author"], "Alice");
        assert_eq!(alice["emails"], serde_json::json!(["alice@x.com"]));
        assert_eq!(
            alice["repos"],
            serde_json::json!([{ "name": "a/one", "language": "Rust" }])
        );
        assert_eq!(alice["languages"], serde_json::json!(["Rust"]));
        assert_eq!(alice["first_seen_repo"], "a/one");
        assert_eq!(alice["total_hits"], 2);
        // serde_json objects keep their keys alphabetically sorted (no
        // `preserve_order` feature): the documented shape is this key set
        let mut keys: Vec<&str> = alice
            .as_object()
            .expect("author object")
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec![
                "author",
                "emails",
                "first_seen_repo",
                "languages",
                "repos",
                "total_hits"
            ]
        );
    }

    #[test]
    fn an_empty_aggregation_serializes_to_an_empty_authors_array() {
        let value = serde_json::to_value(Correlation::default()).expect("must serialize");
        assert_eq!(value["authors"], serde_json::json!([]));
    }

    #[test]
    fn a_contribution_without_usable_authors_changes_nothing() {
        let mut builder = CorrelationBuilder::new();
        builder.add_repo(contribution("a/one", Some("Rust"), &[]));
        let correlation = builder.finish();
        assert!(correlation.authors.is_empty());
    }
}
