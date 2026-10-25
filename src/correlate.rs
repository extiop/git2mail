//! Per-author attribute correlation (issue #5): aggregates
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

use crate::output::sanitize_log_text as log_safe;
use log::info;
use serde::Serialize;
use std::collections::{HashMap, HashSet};

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
    /// correlated. Every interpolated string is sanitized first by the
    /// shared log sanitizer plus a summary-shape neutralization (see
    /// `summary_field`): a hostile commit author name or email can never
    /// forge or spoof terminal-report lines. Never panics.
    pub fn log_summary(&self) {
        if self.authors.is_empty() {
            return;
        }
        // one line per author, not one joined line: a single ";"-joined
        // line is unscannable once the terminal wraps it, and hostile to
        // screen readers — each author gets its own `[+] Top author N:`
        // line, so the reader navigates entry by entry
        for (index, entry) in self.summary_entries().iter().enumerate() {
            info!("[+] Top author {}: {}", index + 1, entry);
        }
    }

    /// Sanitizes one metadata field of a summary entry: beyond the shared
    /// log sanitizer (control characters become `_`), the characters that
    /// make up the summary's own line shape (`;`, `—` and `<`/`>` — the
    /// field separators of the `name <email> — language, N commits` entry
    /// format) are neutralized too, so a hostile author name like
    /// `Alice <a@x.com> — Rust, 999 commits; Fake Dev` renders as one
    /// visibly mangled field instead of extra plausible "top author"
    /// entries. Never panics.
    fn summary_field(text: &str) -> String {
        log_safe(text).replace([';', '—', '<', '>'], "_")
    }

    /// The sanitized `name <email> — language, N commits` entries the
    /// terminal summary is built from. The author name and email come
    /// straight from hostile commit metadata and the language from the
    /// search API payload, so all three go through [`Self::summary_field`]
    /// (shared log sanitizer plus summary-shape neutralization), like every
    /// other terminal-report site of the crate. Never panics.
    fn summary_entries(&self) -> Vec<String> {
        self.authors
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
                    "{} <{}> — {}, {} commits",
                    Self::summary_field(&author.author),
                    Self::summary_field(email),
                    Self::summary_field(language),
                    author.total_hits
                )
            })
            .collect()
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
    /// Exact-match membership set mirroring `emails`: the per-author email
    /// dedup must stay O(1) — the reduce is single-threaded and the email
    /// list is unbounded across repositories (commit metadata is fully
    /// attacker-controlled), so the previous linear `Vec::any` scan made a
    /// hostile multi-repository scan quadratic in the analyst's CPU
    /// (measured: ~4x wall time per doubling of repositories).
    email_set: HashSet<String>,
    repos: Vec<RepoLanguage>,
    /// Exact-match membership set of the repository names in `repos`:
    /// same dedup-cost rule as `email_set` (an author seen in many
    /// repositories must not pay a linear scan per incoming repository).
    repo_name_set: HashSet<String>,
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
            // the contains checks guard the clones: a repository with many
            // already-seen authors must not pay a String clone per author
            // per repo
            if !aggregate.email_set.contains(&author.email) {
                aggregate.email_set.insert(author.email.clone());
                aggregate.emails.push(author.email);
            }
            if !aggregate.repo_name_set.contains(&contribution.name) {
                aggregate.repo_name_set.insert(contribution.name.clone());
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
                // the language key clone is hoisted out of the dedup: the
                // entry lookup borrows first, the clone happens only when a
                // new entry is needed
                let hits = aggregate.language_hits.entry(language.clone()).or_insert(0);
                *hits += author.hits;
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
                // precomputed lowercase keys: sorting must not allocate a
                // temporary String per element per comparison; the raw
                // string breaks the ties the lowercase key cannot (exact-
                // match dedup keeps case variants), so the order is a total
                // order and the report is deterministic run-to-run
                let mut emails = aggregate.emails;
                emails.sort_by_cached_key(|email| (email.to_lowercase(), email.clone()));
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
        // precomputed lowercase keys: the comparator must not allocate a
        // temporary String per author per comparison; the raw name breaks
        // the ties (case-variant names with equal hits) so the JSON report
        // and the summary are deterministic run-to-run, whatever order the
        // HashMap iterated in
        authors.sort_by_cached_key(|author| {
            (
                std::cmp::Reverse(author.total_hits),
                author.author.to_lowercase(),
                author.author.clone(),
            )
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
    fn the_author_and_email_orders_are_total_and_deterministic() {
        // case-variant names with equal hits tie on the lowercase key: the
        // raw name must break the tie, or the stable sort keeps the
        // HashMap's per-process randomized iteration order and the JSON
        // report varies run-to-run (same hole for exact-case email
        // variants, which the exact-match dedup keeps both of)
        let mut builder = CorrelationBuilder::new();
        // two case-variant authors, equal hits: the lowercase tie-break
        builder.add_repo(contribution(
            "a/one",
            None,
            &[("alice", "alice@x.com", 2), ("Alice", "alice@x.com", 2)],
        ));
        // one author holding two case-variant emails: the exact-match dedup
        // keeps both, the lowercase key ties on them
        builder.add_repo(contribution(
            "a/one",
            None,
            &[("Zed", "zed@x.com", 1), ("Zed", "ZED@x.com", 1)],
        ));

        let correlation = builder.finish();
        assert_eq!(
            correlation
                .authors
                .iter()
                .map(|author| author.author.as_str())
                .collect::<Vec<_>>(),
            vec!["Alice", "alice", "Zed"],
            "the raw name must break the lowercase tie (uppercase first in ASCII)"
        );
        assert_eq!(
            correlation.authors[2].emails,
            vec!["ZED@x.com".to_string(), "zed@x.com".to_string()],
            "the raw email must break the lowercase tie"
        );
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

    #[test]
    fn the_terminal_summary_sanitizes_hostile_commit_metadata() {
        // the author name, email and language come from commit metadata and
        // search payloads a hostile repository controls: control characters
        // (ANSI escape openers, carriage returns forging report lines) must
        // never survive into the terminal summary
        let mut builder = CorrelationBuilder::new();
        builder.add_repo(contribution(
            "a/one",
            Some("Rust\u{1b}[31m"),
            &[("\u{1b}[31mAlice\r[+] pwned", "a@x.com\rX", 3)],
        ));
        let entries = builder.finish().summary_entries();
        assert_eq!(entries.len(), 1);
        let entry = &entries[0];
        // the control characters (ESC opening the ANSI sequence, the CR
        // forging a report line) are replaced; the printable remainder is
        // inert
        assert_eq!(
            entry,
            "_[31mAlice_[+] pwned <a@x.com_X> — Rust_[31m, 3 commits"
        );
        assert!(
            !entry.chars().any(char::is_control),
            "no control character may survive: {entry:?}"
        );
    }

    #[test]
    fn a_hostile_author_name_cannot_forge_extra_summary_entries_or_fields() {
        // the summary line joins sanitized entries with `; ` and shapes each
        // one as `name <email> — language, N commits`: a hostile author name
        // carrying those printable delimiters must not render as visually
        // distinct extra "top author" entries inside the single summary line
        let mut builder = CorrelationBuilder::new();
        builder.add_repo(contribution(
            "a/one",
            Some("Rust"),
            &[(
                "Alice <a@x.com> — Rust, 999 commits; Fake Dev",
                "real@x.com",
                3,
            )],
        ));
        let entries = builder.finish().summary_entries();
        assert_eq!(entries.len(), 1);
        let entry = &entries[0];
        // every summary-shape delimiter inside the hostile metadata is
        // neutralized (the comma of the fixed `language, N commits` shape
        // stays: it cannot forge an entry without the `;` separator, and
        // stripping it would mangle legitimate names like `Acme, Inc`)
        assert_eq!(
            entry,
            "Alice _a@x.com_ _ Rust, 999 commits_ Fake Dev <real@x.com> — Rust, 3 commits"
        );
        assert_eq!(entry.matches(';').count(), 0);
        assert_eq!(entry.matches("—").count(), 1);
        assert_eq!(entry.matches('<').count(), 1);
        assert_eq!(entry.matches('>').count(), 1);
    }

    #[test]
    fn the_terminal_summary_sanitizes_every_top_author() {
        // all SUMMARY_TOP entries go through the sanitizer, not only the
        // first one
        let mut builder = CorrelationBuilder::new();
        for i in 0..(Correlation::SUMMARY_TOP + 1) as u64 {
            builder.add_repo(contribution(
                &format!("r{i}"),
                None,
                &[(
                    &format!("name{i}"),
                    &format!("a{i}@x.com"),
                    (100 - i) as usize,
                )],
            ));
        }
        let entries = builder.finish().summary_entries();
        assert_eq!(entries.len(), Correlation::SUMMARY_TOP);
        for entry in &entries {
            assert!(!entry.chars().any(char::is_control));
        }
    }

    /// The cross-repository aggregation must stay near-linear: the same
    /// hostile author display name seen with N distinct emails across N
    /// repositories (fully forgeable commit metadata: one name, one unique
    /// email per commit) must not cost a linear scan of the unbounded
    /// per-author accumulator per incoming author. The pre-fix quadratic
    /// dedup measured ~4x wall time per repository doubling (160 crafted
    /// repositories ≈ 113 s of pure release-build CPU, dwarfing the scan's
    /// entire network cost); the hash-set dedup handles the same shape in
    /// milliseconds. The generous ceiling keeps the assertion stable on a
    /// loaded runner while still failing the quadratic version by orders of
    /// magnitude (a reintroduced linear scan blows past it within seconds).
    #[test]
    fn add_repo_stays_near_linear_on_a_hostile_shared_name_with_unique_emails() {
        const REPOS: usize = 100;
        const AUTHORS_PER_REPO: usize = 1000;
        let began = std::time::Instant::now();
        let mut builder = CorrelationBuilder::new();
        for repo in 0..REPOS {
            let authors: Vec<CommitAuthor> = (0..AUTHORS_PER_REPO)
                .map(|n| CommitAuthor {
                    name: "John Smith".to_string(),
                    email: format!("user{}@repo{repo}.example.com", repo * AUTHORS_PER_REPO + n),
                    hits: 1,
                })
                .collect();
            builder.add_repo(RepoContribution {
                name: format!("org/repo{repo}"),
                language: Some("Rust".to_string()),
                authors,
            });
        }
        let report = builder.finish();
        let elapsed = began.elapsed();
        // correctness invariants unchanged by the dedup structure
        assert_eq!(report.authors.len(), 1, "one shared name, one aggregate");
        let author = &report.authors[0];
        assert_eq!(author.emails.len(), REPOS * AUTHORS_PER_REPO);
        assert_eq!(author.repos.len(), REPOS);
        assert_eq!(author.total_hits, REPOS * AUTHORS_PER_REPO);
        assert_eq!(author.first_seen_repo, "org/repo0");
        assert!(
            elapsed.as_secs() < 10,
            "aggregation became super-linear: {REPOS} repositories took {elapsed:?}"
        );
    }
}
