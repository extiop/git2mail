//! Full profile investigation of a GitHub user :
//! 100% API — no clone, no scraping, no new dependency).
//!
//! `git2mail user <username>` investigates one profile and reports:
//!
//! - the profile itself (`GET /users/{u}`);
//! - the **usernames/names history** through the validated *noreply
//!   technique*: the target's own repositories' commits are
//!   scanned (reusing the 0.5.0 access layer) and every author/committer
//!   email shaped `<id>+<username>@users.noreply.github.com` whose numeric
//!   `id` equals the target's id reveals a past username (and the commit
//!   name seen with it), together with the repository where it was seen;
//! - the **emails** used on the target's repositories (the 0.5.0
//!   technique), including machine-local ones (UPN-like
//!   `jeanpierre@My-Computer.local`), flagged by a documented heuristic;
//! - the **email variants** combinatorics (first/last/initial name parts
//!   crossed with the domains deduced from the found emails),
//!   the domains deduced from the emails already found, split into the ones
//!   actually observed in commits (`matched`) and the generated-but-unseen
//!   ones (`generated`);
//! - the **potential secondary accounts**: recurring co-authors across the
//!   target's repositories and other `id+username` noreply pairs whose id
//!   differs from the target's but whose username or names overlap the
//!   target's own names (both are heuristics, reported with their evidence);
//! - the public **SSH keys** (`GET /users/{u}/keys`, paginated);
//! - the **external contributions**: commits authored by the target outside
//!   their own repositories (`search/commits q=author:<user> -user:<user>`,
//!   paginated, capped at GitHub's documented 1000-result search ceiling),
//!   attributed to the repositories found.
//!
//! # API-only deltas (documented)
//!
//! - the REST commits API exposes the default branch only (the clone-based tools iterate
//!   all branches), so the history and emails are the ones visible on the
//!   default branches;
//! - the noreply history only reveals usernames for targets that committed
//!   at least once with the `id+username@users.noreply.github.com` form.
//!
//! The investigation never panics: every fallible operation returns
//! [`crate::errors::Error`]. A repository that cannot be scanned on its own
//! (a private or deleted repository, an empty one — GitHub answers 409 on
//! its commits listing) is skipped with a warning instead of aborting the
//! report, like the profile fallback scan does; a rate-limit
//! or transport failure is a scan-wide condition and aborts the
//! investigation, so a token parked by a secondary rate limit can never
//! yield a complete-looking report silently missing whole repositories.
//!
//! # Request budget
//!
//! Unlike the reverse-email heuristic (which caps itself at 50 candidate
//! repositories), the `user` and `org` investigations are exhaustive on
//! their listings: the target's repositories and the organization's members
//! and repositories walk every page until the API answers the empty
//! end-of-listing page. Two budgets bound the rest, so that no single step
//! can burn the whole hourly token pool and abort a nearly-complete
//! investigation:
//!
//! - every listed repository's default-branch commit walk is capped at 10
//!   pages of 100 commits (the `sources::repository::MAX_COMMIT_PAGES` ×
//!   `sources::PER_PAGE` budget shared by every repository scan) — and a
//!   warning says the history may be incomplete when the budget cuts the
//!   walk;
//! - the external-contributions search is capped at GitHub's documented
//!   1000-result search window.
//!
//! A prolific target therefore costs requests proportionally to its public
//! history — bounded by the token pool, the API rate limits and these two
//! budgets.

use crate::consts::{GITHUB_API_BASE, NOREPLY_DOMAIN, WEB_FLOW_EMAIL};
use crate::errors::Error;
use crate::github::{Client, fetch_paginated, fetch_paginated_with_page_size};
use crate::output::sanitize_log_text as log_safe;
use crate::sources::{MAX_COMMIT_PAGES, PER_PAGE, Scanner, is_usable_email};
use log::info;
use reqwest::StatusCode;
use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// The `profile` object of the investigation report: the fields of
/// `GET /users/{u}` that carry OSINT value. Absent fields are `null`.
#[derive(Debug, Clone, Serialize)]
pub struct Profile {
    /// The profile login (unique, case-insensitive).
    pub login: String,
    /// The numeric GitHub id: the stable key of the noreply technique.
    pub id: u64,
    /// The display name set by the account ("Jane Dupont").
    pub name: Option<String>,
    /// The company field.
    pub company: Option<String>,
    /// The blog URL field.
    pub blog: Option<String>,
    /// The location field.
    pub location: Option<String>,
    /// The public email field.
    pub email: Option<String>,
    /// The bio field.
    pub bio: Option<String>,
    /// The Twitter/X username field.
    pub twitter_username: Option<String>,
    /// How many public repositories the account owns.
    pub public_repos: u64,
    /// The account creation date (ISO 8601).
    pub created_at: Option<String>,
    /// The GitHub account type (`User`, `Organization`, `Bot`).
    #[serde(rename = "type")]
    pub account_type: Option<String>,
}

/// One username of the `usernames_history`: a login the target committed
/// with (noreply `<id>+<username>` form, id matching the target's), the
/// names seen with it and the repositories where it appeared.
#[derive(Debug, Clone, Serialize)]
pub struct UsernameSighting {
    /// The username revealed by the noreply email.
    pub username: String,
    /// The commit names seen with this username (normalized: lowercased,
    /// ASCII-folded — see the variants section of the README).
    pub names: Vec<String>,
    /// The target's repositories where this username was seen.
    pub repos: Vec<String>,
}

/// One name of the `names_history`: a commit name seen with the target's
/// id (noreply form or legacy `<id>@users.noreply.github.com` form), and
/// the repositories where it appeared.
#[derive(Debug, Clone, Serialize)]
pub struct NameSighting {
    /// The commit name, normalized (lowercased, ASCII-folded).
    pub name: String,
    /// The target's repositories where this name was seen.
    pub repos: Vec<String>,
}

/// One email of the `emails` (and `local_identities`) lists: an email found
/// on the target's repositories' commits, the names seen with it and the
/// repositories where it appeared.
#[derive(Debug, Clone, Serialize)]
pub struct EmailSighting {
    /// The email as found in the commits.
    pub email: String,
    /// The commit names seen with this email (normalized).
    pub names: Vec<String>,
    /// The target's repositories where this email was seen.
    pub repos: Vec<String>,
}

/// One variant email of the `variants.matched` list: a generated
/// `first/last × domain` combination that was actually observed among the
/// target's commit emails.
#[derive(Debug, Clone, Serialize)]
pub struct VariantMatch {
    /// The variant email, matched against an observed commit email
    /// (case-insensitively).
    pub email: String,
    /// The pattern that generated it (`first.last`, `firstlast`,
    /// `initiallast`, `first_last`, `initial_last`, `first`, `last`,
    /// `initial.last` — the built-in variants combinatorics).
    pub pattern: String,
    /// The domain the variant was generated for.
    pub domain: String,
}

/// The `variants` object: the email variants combinatorics
/// (`{first}.{last}`, `{first}{last}`, `{initial}{last}`, `{first}_{last}`,
/// `{initial}_{last}`, `{first}`, `{last}`, `{initial}.{last}`) applied to
/// the first/last names extracted from the profile name and the commit
/// names seen with the target's id (noreply technique), crossed with the
/// domains deduced from the emails already found on the target (noreply
/// excluded).
#[derive(Debug, Clone, Serialize)]
pub struct Variants {
    /// Generated variant emails that were actually observed in the target's
    /// commits.
    pub matched: Vec<VariantMatch>,
    /// Generated variant emails that were never observed (candidates to
    /// check elsewhere, not findings).
    pub generated: Vec<String>,
}

/// One candidate secondary account of the `secondary_accounts` list, with
/// the evidence that flagged it. Both detection kinds are heuristics.
#[derive(Debug, Clone, Serialize)]
pub struct SecondaryAccount {
    /// How the candidate was detected: `co-author` (an email seen in two or
    /// more of the target's repositories whose names never overlap the
    /// target's own names), `noreply-username` (a noreply pair whose id
    /// differs from the target's but whose username matches a known target
    /// username) or `noreply-name` (same, but only the commit names match a
    /// known target name).
    pub kind: String,
    /// The identity behind the candidate: the email itself for `co-author`,
    /// or the `id+username@users.noreply.github.com` noreply address for the
    /// noreply kinds.
    pub identity: String,
    /// The names seen with this identity (normalized).
    pub names: Vec<String>,
    /// The target's repositories where this identity was seen (the evidence).
    pub repos: Vec<String>,
}

/// One public SSH key of the `ssh_keys` list (`GET /users/{u}/keys`).
#[derive(Debug, Clone, Serialize)]
pub struct SshKey {
    /// The GitHub key id.
    pub id: u64,
    /// The public key material (`ssh-ed25519 AAAA…`, `ssh-rsa AAAA…`).
    pub key: String,
    /// The user-set key title.
    pub title: Option<String>,
    /// When the key was added to the account (ISO 8601).
    pub created_at: Option<String>,
}

/// One repository of the `external_contributions` list: a repository
/// outside the target's own account holding commits authored by the target
/// (`search/commits q=author:<user> -user:<user>`).
#[derive(Debug, Clone, Serialize)]
pub struct ExternalContribution {
    /// The repository `owner/name`.
    pub repository: String,
    /// The repository HTML URL, when the search result carried one.
    pub url: Option<String>,
    /// How many authored commits the search listing exposed for this
    /// repository (at most the number of listed pages × page size: the
    /// listing caps the count, the repository is the finding).
    pub commits: usize,
}

/// The full investigation report: the terminal summary sections and the
/// enriched `--json` shape, documented in the README.
#[derive(Debug, Clone, Serialize)]
pub struct UserReport {
    /// The investigated profile.
    pub profile: Profile,
    /// The usernames history revealed by the noreply technique.
    pub usernames_history: Vec<UsernameSighting>,
    /// The names history seen with the target's id.
    pub names_history: Vec<NameSighting>,
    /// The emails found on the target's repositories (noreply addresses
    /// excluded: they feed the histories instead).
    pub emails: Vec<EmailSighting>,
    /// The email variants, matched and generated.
    pub variants: Variants,
    /// The potential secondary accounts, with their evidence.
    pub secondary_accounts: Vec<SecondaryAccount>,
    /// The public SSH keys of the account.
    pub ssh_keys: Vec<SshKey>,
    /// The external contributions of the target.
    pub external_contributions: Vec<ExternalContribution>,
    /// The machine-local identities (UPN-like) among the found emails,
    /// flagged by the documented heuristic.
    pub local_identities: Vec<EmailSighting>,
}

/// Runs the full investigation of one GitHub user: fetches the profile,
/// walks the target's repositories' commits (noreply technique and emails),
/// lists the external contributions and the SSH keys, then builds the
/// report and logs the terminal summary.
///
/// # Errors
///
/// Returns [`Error::InvalidUsername`] when `username` is not a valid GitHub
/// username (rejected client-side, before any network request),
/// [`Error::Organization`] when the profile is an organization (the message
/// points at the dedicated `org` subcommand), [`Error::NotFound`] for a
/// missing profile, [`Error::PrivateOrUnavailable`] or
/// [`Error::RateLimitExhausted`] / [`Error::Http`] for the corresponding API
/// failures. A repository that is private, deleted or empty (GitHub answers
/// 409 on its commits listing) is skipped with a warning and does not abort
/// the investigation; a rate-limit or transport failure aborts it, so the
/// report can never silently miss whole repositories. Never panics.
/// Run a full investigation of a GitHub user's profile: usernames/names
/// history (noreply technique), emails and their variants, potential
/// secondary accounts, public SSH keys and external contributions.
///
/// `custom_variant_patterns` are the caller-supplied `--variant-pattern`
/// templates (e.g. `{last}{first}`), appended to the built-in patterns;
/// they are validated here (syntax and a 64-pattern cap) so a library
/// caller gets the same client-side rejection as the CLI.
pub fn investigate(
    scanner: &Scanner,
    username: &str,
    custom_variant_patterns: &[String],
) -> Result<UserReport, Error> {
    investigate_at_with_patterns(
        scanner.client(),
        GITHUB_API_BASE,
        username,
        custom_variant_patterns,
    )
}

/// GitHub's documented search ceiling: the REST search API only serves the
/// first 1000 results of a query — a page past that window (page × per_page
/// above 1000) answers `422 Only the first 1000 search results are
/// available`. The external-contributions listing is capped there, so the
/// over-limit page is never requested and a prolific external contributor
/// cannot abort a complete investigation at its last step.
const SEARCH_RESULT_LIMIT: usize = 1000;

/// The investigation itself, driven against one API base URL: [`investigate`]
/// is the production entry point (`https://api.github.com`), and the offline
/// tests run this same code against a loopback mock. The custom variant
/// patterns are validated here (syntax and [`MAX_CUSTOM_VARIANT_PATTERNS`]
/// cap) before any network request, exactly like the username.
///
/// # Errors
///
/// The same failures as [`investigate`]. Never panics.
fn investigate_at_with_patterns(
    client: &Client,
    base: &str,
    username: &str,
    custom_variant_patterns: &[String],
) -> Result<UserReport, Error> {
    validate_username(username)?;
    if custom_variant_patterns.len() > MAX_CUSTOM_VARIANT_PATTERNS {
        return Err(Error::InvalidVariantPattern(format!(
            "at most {MAX_CUSTOM_VARIANT_PATTERNS} custom variant patterns are allowed ({} given)",
            custom_variant_patterns.len()
        )));
    }
    for pattern in custom_variant_patterns {
        validate_variant_pattern(pattern)?;
    }

    // 404 maps to Error::NotFound inside the client: a missing profile is
    // the clean failure the CLI reports
    let profile_json = client.get_json(&format!("{base}/users/{username}"))?;
    let profile = parse_profile(&profile_json)?;
    if profile.account_type.as_deref() == Some("Organization") {
        return Err(Error::Organization(profile.login.clone()));
    }

    let mut investigation = Investigation::new(profile);
    investigation.custom_variant_patterns = custom_variant_patterns.to_vec();

    // the target's own repositories, then their default-branch commits
    let repositories: Vec<String> = fetch_paginated(
        client,
        |page| format!("{base}/users/{username}/repos?per_page={PER_PAGE}&page={page}"),
        parse_repository_page,
        None,
    )?;
    for full_name in &repositories {
        let Some((owner, repository)) = full_name.split_once('/') else {
            // the listing payload is API-derived: sanitize it like every
            // other untrusted string before it reaches the log
            log::warn!(
                "skipping repository with unexpected name {}",
                log_safe(full_name)
            );
            continue;
        };
        // the same per-repository commit budget as every other repository
        // scan ([MAX_COMMIT_PAGES]): the walk sits mid-investigation (the
        // SSH keys and the external contributions come after), so a single
        // large repository must not burn the whole hourly token pool on one
        // commit history and abort a nearly-complete investigation
        let listed_commits = std::cell::Cell::new(0usize);
        let commit_ceiling = MAX_COMMIT_PAGES * usize::from(PER_PAGE);
        let commits: Vec<CommitPeople> = match fetch_paginated_with_page_size(
            client,
            |page| {
                // the full name is API-derived (the repos listing):
                // percent-encoding keeps a hostile `?`, `#`, `&` or `/` in it
                // from re-targeting the authenticated request
                format!(
                    "{base}/repos/{}/{}/commits?per_page={PER_PAGE}&page={page}",
                    crate::sources::percent_encode(owner),
                    crate::sources::percent_encode(repository)
                )
            },
            |json| {
                let (page_people, raw_count) = parse_people_page(json)?;
                listed_commits.set(listed_commits.get() + raw_count);
                Ok((page_people, raw_count))
            },
            Some(commit_ceiling),
            PER_PAGE,
        ) {
            Ok(commits) => {
                if listed_commits.get() >= commit_ceiling {
                    // the raw-count ceiling was reached: the walk was cut at
                    // the repository budget (a repository with exactly
                    // `commit_ceiling` commits also lands here — the "may"
                    // phrasing keeps the warning honest for that boundary
                    // case too). Say so instead of letting the report look
                    // complete
                    log::warn!(
                        "repository {}: only the most recent {} commits were scanned (built-in limit), older commits may hold emails that were missed",
                        log_safe(full_name),
                        listed_commits.get()
                    );
                }
                commits
            }
            // a resource-scoped failure (a private, deleted or empty
            // repository — GitHub answers 409 on /commits for a repository
            // with no commits) must not abort the whole investigation and
            // discard what other repos already gave; a rate-limit or
            // transport failure is a scan-wide condition and propagates, so
            // a token parked by a secondary rate limit can never yield a
            // complete-looking report whose usernames/emails history
            // silently missed repositories
            Err(err @ (Error::NotFound | Error::PrivateOrUnavailable | Error::EmptyRepository)) => {
                log::warn!("skipping repository {}: {err}", log_safe(full_name));
                continue;
            }
            Err(err) => return Err(err),
        };
        for commit in commits {
            investigation.absorb_commit(full_name, &commit);
        }
    }

    // external contributions: commits authored by the target outside their
    // own repositories (the search-based noreply technique). The listing
    // is capped at GitHub's documented 1000-result search ceiling, and the
    // page-size-aware loop ends it on a short final page while counting raw
    // items toward the cap, so the over-limit page is never requested and a
    // prolific external contributor can neither abort a complete
    // investigation at its last step nor cost the contributions already
    // found. The documented 422 the API answers past the ceiling is still
    // treated as the end of the listing (a defensive fallback: the cap, the
    // short-page end and the raw-count limit make it unreachable for
    // GitHub's documented behavior) — but only when contributions were
    // already collected: a page-1 422 is the API rejecting the query, and
    // it fails the investigation explicitly instead
    let external_hits: Vec<ExternalHit> = {
        // the hits are counted as they stream in so the defensive 422
        // fallback can tell a window 422 (contributions collected, listing
        // cut past the documented ceiling) from a page-1 422, which can
        // never be a window 422 and must fail explicitly instead of
        // yielding a complete-looking report without its
        // external-contributions section
        let collected = std::cell::Cell::new(0usize);
        match fetch_paginated_with_page_size(
            client,
            |page| {
                format!(
                    "{base}/search/commits?q=author%3A{username}+-user%3A{username}&per_page={PER_PAGE}&page={page}"
                )
            },
            |json| {
                let (page_hits, raw_count) = parse_external_page(json)?;
                collected.set(collected.get() + page_hits.len());
                Ok((page_hits, raw_count))
            },
            Some(SEARCH_RESULT_LIMIT),
            PER_PAGE,
        ) {
            Ok(hits) => hits,
            Err(Error::Http(err)) if err.status() == Some(StatusCode::UNPROCESSABLE_ENTITY) => {
                if collected.get() == 0 {
                    return Err(Error::Http(err));
                }
                log::warn!(
                    "external contributions cut at GitHub's 1000-result search ceiling: {} collected contributions discarded",
                    collected.get()
                );
                Vec::new()
            }
            Err(err) => return Err(err),
        }
    };
    let mut external: BTreeMap<String, (usize, Option<String>)> = BTreeMap::new();
    for hit in external_hits {
        let entry = external.entry(hit.repository).or_insert((0, None));
        entry.0 += 1;
        if entry.1.is_none() {
            entry.1 = hit.url;
        }
    }
    let external_contributions = external
        .into_iter()
        .map(|(repository, (commits, url))| ExternalContribution {
            repository,
            url,
            commits,
        })
        .collect();

    // public SSH keys
    let ssh_keys: Vec<SshKey> = fetch_paginated(
        client,
        |page| format!("{base}/users/{username}/keys?per_page={PER_PAGE}&page={page}"),
        parse_keys_page,
        None,
    )?;

    let report = investigation.finish(external_contributions, ssh_keys);
    report.log_summary();
    Ok(report)
}

/// Validates a GitHub username client-side, before any network request:
/// 1 to 39 ASCII letters, digits or hyphens, without a leading or trailing
/// hyphen and without consecutive hyphens (GitHub's documented username
/// rules). Used both for the `user` target and for the commit-forged
/// noreply username payloads (see [`parse_noreply`]): a shape GitHub could
/// never have issued must not plant a bogus past username.
pub(crate) fn validate_username(username: &str) -> Result<(), Error> {
    let valid = !username.is_empty()
        && username.len() <= 39
        && !username.starts_with('-')
        && !username.ends_with('-')
        && !username.contains("--")
        && username
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-');
    if valid {
        Ok(())
    } else {
        Err(Error::InvalidUsername(username.to_string()))
    }
}

/// Extracts the documented profile fields from a `GET /users/{u}` body.
/// `login` and `id` are required: the noreply technique keys on the id and
/// the report on the login, so a partial body without them must fail
/// explicitly instead of silently producing a report with an empty login
/// and an id (`0`) that can never match. Every other field is optional: a
/// partial body yields `None`s instead of failing the whole investigation.
///
/// # Errors
///
/// Returns [`Error::InvalidProfile`] when `login` or `id` is missing from
/// the payload. Never panics.
fn parse_profile(json: &Value) -> Result<Profile, Error> {
    let string_field = |name: &str| {
        json.get(name)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
    };
    let login = json
        .get("login")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| Error::InvalidProfile("missing `login`".to_string()))?
        .to_string();
    let id = json
        .get("id")
        .and_then(Value::as_u64)
        .ok_or_else(|| Error::InvalidProfile("missing `id`".to_string()))?;
    Ok(Profile {
        login,
        id,
        name: string_field("name"),
        company: string_field("company"),
        blog: string_field("blog"),
        location: string_field("location"),
        email: string_field("email"),
        bio: string_field("bio"),
        twitter_username: string_field("twitter_username"),
        public_repos: json
            .get("public_repos")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        created_at: string_field("created_at"),
        account_type: string_field("type"),
    })
}

/// Extracts the `full_name` of every repository of a `/repos` page,
/// together with the raw item count (the end-of-listing signal of
/// `fetch_paginated`). GitHub returns `[]` for an empty listing: a 200 body
/// that is not an array at all is an intermediary or a shape change, not an
/// empty page, and must fail explicitly instead of yielding a
/// complete-looking zero-repository report (the same explicit-requirement
/// rule as the `org` investigation's listings).
///
/// # Errors
///
/// Returns [`Error::InvalidProfile`] when the body is not a JSON array.
/// Never panics.
fn parse_repository_page(json: &Value) -> Result<(Vec<String>, usize), Error> {
    let Some(items) = json.as_array() else {
        return Err(Error::InvalidProfile(
            "repositories payload: not an array".to_string(),
        ));
    };
    let repositories = items
        .iter()
        .filter_map(|item| item.get("full_name").and_then(Value::as_str))
        .map(str::to_string)
        .collect();
    Ok((repositories, items.len()))
}

/// The people a single commit exposes: both the author and the committer
/// name/email pairs (the noreply technique reads the committer too).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CommitPeople {
    pub(crate) author_name: Option<String>,
    pub(crate) author_email: Option<String>,
    pub(crate) committer_name: Option<String>,
    pub(crate) committer_email: Option<String>,
}

/// Extracts the author and committer identities of every commit of a
/// `/commits` page, together with the raw item count. Unlike the 0.5.0
/// email scan, noreply addresses are kept: they are the noreply technique's
/// raw material. The per-commit parsing stays tolerant (a commit whose
/// identity fields cannot be read is skipped), but a 200 body that is not a
/// JSON array is an intermediary or a shape change, not an empty page, and
/// fails explicitly like the other listings of the investigation instead of
/// silently ending a repository's commit walk as a complete-looking empty
/// result.
///
/// # Errors
///
/// Returns [`Error::InvalidProfile`] when the body is not a JSON array.
/// Never panics.
fn parse_people_page(json: &Value) -> Result<(Vec<CommitPeople>, usize), Error> {
    let mut people: Vec<CommitPeople> = Vec::new();
    let Some(items) = json.as_array() else {
        return Err(Error::InvalidProfile(
            "commits payload: not an array".to_string(),
        ));
    };
    for item in items {
        let Some(commit) = item.get("commit") else {
            continue;
        };
        let field = |role: &str, name: &str| {
            commit
                .get(role)
                .and_then(|role| role.get(name))
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
        };
        people.push(CommitPeople {
            author_name: field("author", "name"),
            author_email: field("author", "email"),
            committer_name: field("committer", "name"),
            committer_email: field("committer", "email"),
        });
    }
    Ok((people, items.len()))
}

/// One external-contribution search hit: the repository holding a commit
/// authored by the target.
#[derive(Debug)]
struct ExternalHit {
    repository: String,
    url: Option<String>,
}

/// Extracts the external repositories of a `search/commits` page: the
/// repository `full_name` and `html_url` of every listed commit, with the
/// raw item count. A rejected search (`{"items": null}`) ends the listing.
/// A 200 body without an `items` field at all, or with an `items` field that
/// is neither an array nor `null`, is an intermediary or a shape change, not
/// an empty page, and fails explicitly (the same rule as
/// [`crate::sources::search`]'s `parse_search_page`) instead of yielding a
/// complete-looking report whose external-contributions section silently
/// went missing.
///
/// # Errors
///
/// Returns [`Error::InvalidProfile`] when the body carries no `items` field
/// or an `items` field that is neither an array nor `null`. Never panics.
fn parse_external_page(json: &Value) -> Result<(Vec<ExternalHit>, usize), Error> {
    let Some(items) = json.get("items") else {
        return Err(Error::InvalidProfile(
            "external payload: no `items` field".to_string(),
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
            "external payload: `items` is not an array".to_string(),
        ));
    };
    let hits = items
        .iter()
        .filter_map(|item| {
            let repository = item.get("repository")?;
            Some(ExternalHit {
                repository: repository
                    .get("full_name")
                    .and_then(Value::as_str)?
                    .to_string(),
                url: repository
                    .get("html_url")
                    .and_then(Value::as_str)
                    .map(str::to_string),
            })
        })
        .collect();
    Ok((hits, items.len()))
}

/// Extracts the public SSH keys of a `/users/{u}/keys` page, with the raw
/// item count. An item missing its `id` or `key` material is skipped (a
/// partial payload is not reported with a fake `id` 0 that can never
/// match), mirroring the explicit-requirement strictness applied to the
/// profile's `login`/`id`. A 200 body that is not a JSON array is an
/// intermediary or a shape change, not an empty listing, and fails
/// explicitly like the other listings of the investigation (the per-commit
/// parsing stays tolerant: a commit it cannot read is skipped).
///
/// # Errors
///
/// Returns [`Error::InvalidProfile`] when the body is not a JSON array.
/// Never panics.
fn parse_keys_page(json: &Value) -> Result<(Vec<SshKey>, usize), Error> {
    let Some(items) = json.as_array() else {
        return Err(Error::InvalidProfile(
            "keys payload: not an array".to_string(),
        ));
    };
    let string_field =
        |item: &Value, name: &str| item.get(name).and_then(Value::as_str).map(str::to_string);
    let keys = items
        .iter()
        .filter_map(|item| {
            let id = item.get("id").and_then(Value::as_u64)?;
            let key = item.get("key").and_then(Value::as_str)?;
            Some(SshKey {
                id,
                key: key.to_string(),
                title: string_field(item, "title"),
                created_at: string_field(item, "created_at"),
            })
        })
        .collect();
    Ok((keys, items.len()))
}

// the noreply test is the shared exact-domain rule of the crate
// (`crate::sources::is_noreply_email`, subsumed by the `is_usable_email`
// gate of `absorb_identity`): the same test [`parse_noreply`] applies.

/// Folds one commit name for the report, trimmed (a hostile whitespace-only
/// name like `"   "` must not plant noise in the histories) and dropped when
/// nothing remains.
fn folded_commit_name(name: &str) -> Option<String> {
    let folded = fold_name(name.trim());
    (!folded.is_empty()).then_some(folded)
}

impl UserReport {
    /// Logs the human-readable terminal report: one section per finding
    /// family (PROFILE / USERNAMES HISTORY / EMAILS / VARIANTS / SECONDARY
    /// ACCOUNTS / SSH KEYS / EXTERNAL CONTRIBUTIONS), with the local
    /// identities flagged inside the EMAILS section. Silent on empty
    /// sections. Every untrusted string (commit metadata, profile fields,
    /// key titles) is sanitized first: control characters become `_`, so a
    /// hostile commit can never forge or spoof log lines. Never panics.
    fn log_summary(&self) {
        let profile = &self.profile;
        info!("============ PROFILE ============");
        info!(
            "[+] login: {} (id {})",
            log_safe(&profile.login),
            profile.id
        );
        for (label, field) in [
            ("name", &profile.name),
            ("company", &profile.company),
            ("blog", &profile.blog),
            ("location", &profile.location),
            ("email", &profile.email),
            ("bio", &profile.bio),
            ("twitter", &profile.twitter_username),
            ("created at", &profile.created_at),
        ] {
            if let Some(value) = field {
                info!("[+] {label}: {}", log_safe(value));
            }
        }
        info!(
            "[+] type: {}",
            profile
                .account_type
                .as_deref()
                .map(log_safe)
                .unwrap_or_else(|| "unknown".to_string())
        );
        info!("[+] public repos: {}", profile.public_repos);

        info!("============ USERNAMES HISTORY ============");
        if self.usernames_history.is_empty() {
            info!(
                "[-] no past username found (their commits use GitHub's hide-my-email address, which does not reveal old usernames)"
            );
        }
        for sighting in &self.usernames_history {
            info!(
                "[+] {}: names [{}], repos [{}]",
                log_safe(&sighting.username),
                log_safe(&sighting.names.join(", ")),
                log_safe(&sighting.repos.join(", "))
            );
        }

        info!("============ EMAILS ============");
        if self.emails.is_empty() {
            info!("[-] no email found on the target's repositories");
        }
        for sighting in &self.emails {
            info!(
                "[+] {}: names [{}], repos [{}]",
                log_safe(&sighting.email),
                log_safe(&sighting.names.join(", ")),
                log_safe(&sighting.repos.join(", "))
            );
        }
        for sighting in &self.local_identities {
            info!(
                "[!] local identity (heuristic): {} (names [{}], repos [{}])",
                log_safe(&sighting.email),
                log_safe(&sighting.names.join(", ")),
                log_safe(&sighting.repos.join(", "))
            );
        }

        info!("============ VARIANTS ============");
        if self.variants.matched.is_empty() && self.variants.generated.is_empty() {
            info!("[-] no name/domain pair to generate variants from");
        }
        for variant in &self.variants.matched {
            info!(
                "[+] confirmed (seen in their commits): {} (pattern {}, domain {})",
                log_safe(&variant.email),
                variant.pattern,
                log_safe(&variant.domain)
            );
        }
        for email in &self.variants.generated {
            info!(
                "[!] guessed, not confirmed: {} (do not contact this address without checking it first)",
                log_safe(email)
            );
        }

        info!("============ SECONDARY ACCOUNTS ============");
        if self.secondary_accounts.is_empty() {
            info!("[-] no secondary account candidate");
        }
        for account in &self.secondary_accounts {
            info!(
                "[?] {} ({}): names [{}], repos [{}]",
                log_safe(&account.identity),
                account.kind,
                log_safe(&account.names.join(", ")),
                log_safe(&account.repos.join(", "))
            );
        }

        info!("============ SSH KEYS ============");
        if self.ssh_keys.is_empty() {
            info!("[-] no public SSH key");
        }
        for key in &self.ssh_keys {
            info!(
                "[+] {} ({}): {}",
                key.title
                    .as_deref()
                    .map(log_safe)
                    .unwrap_or_else(|| "untitled".to_string()),
                key.created_at
                    .as_deref()
                    .map(log_safe)
                    .unwrap_or_else(|| "unknown date".to_string()),
                log_safe(&key.key)
            );
        }

        info!("============ EXTERNAL CONTRIBUTIONS ============");
        if self.external_contributions.is_empty() {
            info!("[-] no external contribution found");
        }
        for contribution in &self.external_contributions {
            info!(
                "[+] {}: {} commits ({})",
                log_safe(&contribution.repository),
                contribution.commits,
                contribution
                    .url
                    .as_deref()
                    .map(log_safe)
                    .unwrap_or_else(|| "no url".to_string())
            );
        }
    }
}

/// Parses a GitHub noreply email into its numeric owner id and, when the
/// modern `<id>+<username>` form is used, the username it carries:
///
/// - `12345+jane@users.noreply.github.com` → `(12345, Some("jane"))`;
/// - `12345@users.noreply.github.com` (legacy pre-2017 form) →
///   `(12345, None)`: it reveals the id only, so callers fall back to the
///   current username;
/// - any other email (real address, wrong domain, non-numeric id, empty
///   username) → `None`.
///
/// The username is only accepted when it follows GitHub's full username
/// shape (1-39 ASCII letters, digits or hyphens, without leading/trailing
/// or consecutive hyphens — see [`validate_username`]):
/// commit author emails are free-form and attacker-influenceable, so a
/// payload like `42+jane doe@users.noreply.github.com` or `42+j--ane@…`
/// must never plant a bogus past username in the report. Such an email
/// falls back to the legacy id-only handling (`(42, None)`).
fn parse_noreply(email: &str) -> Option<(u64, Option<&str>)> {
    let (local, domain) = email.rsplit_once('@')?;
    if !domain.eq_ignore_ascii_case(NOREPLY_DOMAIN) {
        return None;
    }
    if let Some((id, username)) = local.split_once('+') {
        let id = id.parse::<u64>().ok()?;
        if username.is_empty() {
            return None;
        }
        if validate_username(username).is_ok() {
            Some((id, Some(username)))
        } else {
            // not a possible GitHub username: keep the id (legacy handling)
            // but never record the free-form payload as a past username
            Some((id, None))
        }
    } else {
        let id = local.parse::<u64>().ok()?;
        Some((id, None))
    }
}

/// Whether an email looks machine-local (UPN-like, e.g.
/// `jeanpierre@My-Computer.local`). **Documented heuristic**: a domain
/// ending with `.local` or `.lan` (mDNS/Windows workgroup conventions), or
/// a single-label domain with no dot at all (`jeanpierre@mycomputer`).
/// A dotful public-looking domain is never flagged, and a false positive
/// only adds one candidate to the `local_identities` list.
fn is_local_identity(email: &str) -> bool {
    let Some((_, domain)) = email.rsplit_once('@') else {
        return false;
    };
    let domain = domain.to_ascii_lowercase();
    domain.ends_with(".local") || domain.ends_with(".lan") || !domain.contains('.')
}

/// ASCII-folds a name for email-variant generation: lowercased, and the
/// accents stripped **only for the common Latin-1 range** (hand-rolled, no
/// unicode crate), plus the Latin digraphs `ß`→`ss`, `æ`→`ae` and
/// `œ`→`oe` and the stroke letters `ø`→`o`. Any other script (Cyrillic,
/// CJK, …) is kept raw: the variants generated from it simply will not
/// match ASCII emails, which is the honest behavior.
fn fold_name(name: &str) -> String {
    let mut folded = String::with_capacity(name.len());
    for c in name.to_lowercase().chars() {
        match c {
            'à'..='å' => folded.push('a'),
            'ç' => folded.push('c'),
            'è'..='ë' => folded.push('e'),
            'ì'..='ï' => folded.push('i'),
            'ñ' => folded.push('n'),
            'ò'..='ö' => folded.push('o'),
            'ø' => folded.push('o'),
            'ù'..='ü' => folded.push('u'),
            'ý' | 'ÿ' => folded.push('y'),
            'ß' => folded.push_str("ss"),
            'æ' => folded.push_str("ae"),
            'œ' => folded.push_str("oe"),
            other => folded.extend(other.to_lowercase()),
        }
    }
    folded
}

/// The variant engine's input caps. Commit names and commit emails are
/// attacker-forgeable and uncapped (one merged PR can plant thousands of
/// name spellings and email domains), and the combinatorics multiply
/// every known name pair by every deduced email domain: measured on the
/// uncapped engine, 300 planted names × 300 planted domains produce
/// 361,200 variants and seconds of CPU (extrapolating to a hostile
/// 5,000-commit PR: tens of millions of variants, minutes-to-hours of CPU
/// and a multi-gigabyte report). A real target has a handful of name
/// spellings and mail domains; beyond the caps the extra inputs are
/// attacker noise, so the engine is bounded deterministically (sorted
/// pairs, most-sighted domains first) with a warning when a cap bites.
const MAX_VARIANT_NAME_PAIRS: usize = 64;

/// See [`MAX_VARIANT_NAME_PAIRS`]: the per-scan cap on the distinct email
/// domains fed to the variant engine (most-sighted domains first, ties
/// broken alphabetically, noreply excluded as before).
const MAX_VARIANT_DOMAINS: usize = 64;

/// See [`MAX_VARIANT_NAME_PAIRS`]: the cap on the report's generated-variant
/// list. Matching is unaffected: every capped combination is still tested
/// against the observed emails, so a variant beyond the list cap can still
/// be reported as matched.
const MAX_GENERATED_VARIANTS: usize = 1000;

/// The cap on the caller-supplied custom variant patterns
/// (`user --variant-pattern`): the patterns are analyst input, not forgeable
/// commit metadata, but the same combinatorics warning applies — every
/// pattern multiplies every capped name pair by every capped domain, so an
/// absurd pattern count would only slow the analyst's own machine down and
/// bloat the report past the generated-list cap. 64 keeps the useful
/// conventions of a whole team and fails fast beyond.
const MAX_CUSTOM_VARIANT_PATTERNS: usize = 64;

/// Validates one caller-supplied custom variant pattern
/// (`user --variant-pattern`). A pattern is a template with `{first}`,
/// `{last}` and `{initial}` placeholders (e.g. `{last}{first}` produces
/// `doejohn@…`); braces are only allowed as placeholders, only printable
/// ASCII is allowed (`@`, whitespace, control and zero-width characters
/// would forge a candidate address no mail system could ever have
/// produced, or worse inject into the report), and the expansion is
/// lowercased at generation time so the literal part matches observed
/// emails case-insensitively like the built-ins. The rejection is
/// client-side, before any network request.
///
/// # Errors
///
/// [`Error::InvalidVariantPattern`] with a description of the first problem
/// found. Never panics.
pub fn validate_variant_pattern(pattern: &str) -> Result<(), Error> {
    if pattern.trim().is_empty() {
        return Err(Error::InvalidVariantPattern("the pattern is empty".into()));
    }
    if pattern.chars().any(char::is_whitespace) {
        return Err(Error::InvalidVariantPattern(format!(
            "whitespace is not allowed in {pattern}"
        )));
    }
    if pattern.contains('@') {
        return Err(Error::InvalidVariantPattern(format!(
            "'@' is not allowed in {pattern}: the domain comes from the deduced domains, not \
             from the pattern"
        )));
    }
    if let Some(character) = pattern
        .chars()
        .find(|character| !character.is_ascii_graphic())
    {
        return Err(Error::InvalidVariantPattern(format!(
            "only printable ASCII is allowed, found {} in {pattern}",
            character
        )));
    }
    let mut placeholders = 0usize;
    let mut rest = pattern;
    while let Some(open) = rest.find('{') {
        let after = &rest[open + 1..];
        let Some(close) = after.find('}') else {
            return Err(Error::InvalidVariantPattern(format!(
                "unclosed '{{' in {pattern}"
            )));
        };
        match &after[..close] {
            "first" | "last" | "initial" => placeholders += 1,
            other => {
                return Err(Error::InvalidVariantPattern(format!(
                    "unknown placeholder {{{other}}} in {pattern} (expected {{first}}, \
                     {{last}} or {{initial}})"
                )));
            }
        }
        rest = &after[close + 1..];
    }
    if placeholders == 0 {
        return Err(Error::InvalidVariantPattern(format!(
            "the pattern {pattern} carries no {{first}}/{{last}}/{{initial}} placeholder"
        )));
    }
    // a stray '}' (with or without a matching '{') is not a valid placeholder
    // and would silently pass into the generated address
    if pattern.matches('}').count() != placeholders {
        return Err(Error::InvalidVariantPattern(format!(
            "a '}}' outside a placeholder is not allowed in {pattern}"
        )));
    }
    Ok(())
}

/// Generates the variant emails of one `(first, last)` name pair
/// for one domain, in the fixed built-in order (first.last, firstlast,
/// initiallast, first_last, initial_last, first, last, initial.last),
/// followed by the caller-supplied custom patterns in their CLI order
/// (e.g. `{last}{first}`), deduplicated
/// (a first name equal to the last one, or a single-letter first name,
/// collapse several patterns onto the same email). With no last name, only
/// the bare `{first}` pattern makes sense among the built-ins, and the
/// custom patterns requiring a last name are skipped.
fn generate_variants(
    first: &str,
    last: &str,
    domain: &str,
    custom_patterns: &[String],
) -> Vec<(String, String)> {
    let initial = first.chars().next().map(String::from).unwrap_or_default();
    let emails: Vec<(String, &'static str)> = if last.is_empty() {
        vec![(format!("{first}@{domain}"), "first")]
    } else {
        vec![
            (format!("{first}.{last}@{domain}"), "first.last"),
            (format!("{first}{last}@{domain}"), "firstlast"),
            (format!("{initial}{last}@{domain}"), "initiallast"),
            (format!("{first}_{last}@{domain}"), "first_last"),
            (format!("{initial}_{last}@{domain}"), "initial_last"),
            (format!("{first}@{domain}"), "first"),
            (format!("{last}@{domain}"), "last"),
            (format!("{initial}.{last}@{domain}"), "initial.last"),
        ]
    };
    let mut generated: Vec<(String, String)> = Vec::new();
    for (email, pattern) in emails {
        if !generated.iter().any(|(seen, _)| seen == &email) {
            generated.push((email, pattern.to_string()));
        }
    }
    // the custom patterns come after the built-ins, in their CLI order;
    // the pattern label in the report is the template itself:
    // self-documenting, and distinguishable from the built-in patterns
    for template in custom_patterns {
        if let Some(local) = expand_pattern(template, first, last, &initial) {
            let email = format!("{local}@{domain}");
            if !generated.iter().any(|(seen, _)| seen == &email) {
                generated.push((email, template.clone()));
            }
        }
    }
    generated
}

/// Expands one custom variant template into the local part of one name
/// pair's candidate address: `{first}`, `{last}` and `{initial}` are
/// replaced by the folded name parts (the `@domain` is appended by the
/// caller, like the built-ins), and the whole expansion is lowercased so
/// the literal part of the template matches observed emails
/// case-insensitively, exactly like the built-ins (`J.{last}` must match
/// the observed `j.dupont@acme.com`, not miss it). A template requiring a
/// last name is skipped (not an error) when the pair carries none, exactly
/// like the built-ins collapse in that case.
fn expand_pattern(template: &str, first: &str, last: &str, initial: &str) -> Option<String> {
    if template.contains("{last}") && last.is_empty() {
        return None;
    }
    let expanded = template
        .replace("{first}", first)
        .replace("{last}", last)
        .replace("{initial}", initial)
        .to_lowercase();
    (!expanded.is_empty()).then_some(expanded)
}

/// Folds one already-folded name into its `(first, last)` variant pair.
fn folded_pair(folded: &str) -> Option<(String, String)> {
    let tokens: Vec<&str> = folded.split_whitespace().collect();
    if tokens.is_empty() {
        return None;
    }
    let last = if tokens.len() == 1 {
        ""
    } else {
        tokens[tokens.len() - 1]
    };
    Some((tokens[0].to_string(), last.to_string()))
}

/// The names and repositories accumulated behind one identity.
#[derive(Default)]
struct Accum {
    names: BTreeSet<String>,
    repos: BTreeSet<String>,
    /// Raw sighting count: one per absorbed commit identity carrying this
    /// email/name. Unlike the distinct-name/repo counts, it cannot be
    /// inflated by one commit per planted spelling: the variant-engine
    /// input rankings use it so planted volume cannot outweigh a real,
    /// heavily-sighted domain or name (see [`MAX_VARIANT_NAME_PAIRS`]).
    sightings: usize,
}

/// A noreply `id+username` pair seen on the target's repositories whose id
/// differs from the target's: a secondary-account candidate kept until the
/// end of the scan, when the accumulated target names/usernames are
/// complete enough to judge the overlap.
struct OtherNoreply {
    id: u64,
    username: Option<String>,
    people: Accum,
}

/// The mutable aggregation state of one investigation. Everything is keyed
/// and sorted deterministically (`BTree*`) so the report is stable.
struct Investigation {
    /// The investigated profile, returned verbatim in the report.
    profile: Profile,
    /// Every username the target is known to have used: the profile login
    /// plus the usernames revealed by the noreply technique.
    known_usernames: BTreeSet<String>,
    /// Every normalized name the target is known to have used: the profile
    /// name plus the commit names seen with the target's id.
    known_names: BTreeSet<String>,
    /// username → names and repositories where seen.
    usernames: BTreeMap<String, Accum>,
    /// normalized name → repositories where seen.
    names: BTreeMap<String, Accum>,
    /// lowercase email → display email, names and repositories where seen.
    emails: BTreeMap<String, (String, Accum)>,
    /// noreply pairs with a foreign id, pending the overlap judgment.
    other_noreplies: Vec<OtherNoreply>,
    /// Index into `other_noreplies` by `(id, lowercased username)`: the
    /// pending-pair lookup must stay O(1) — the own-repositories commit
    /// walk is uncapped and commit emails are attacker-forgeable, so the
    /// previous linear `Vec::position` scan (which even lowercased both
    /// sides on every comparison) made a hostile or merely huge target
    /// quadratic in the analyst's CPU. `None` and `Some(username)` stay
    /// distinct keys, exactly like the previous predicate: a foreign id
    /// seen once in the legacy form and once in the modern form is two
    /// pending pairs.
    other_noreply_index: HashMap<(u64, Option<String>), usize>,
    /// Caller-supplied custom variant patterns (`user --variant-pattern`),
    /// already validated by [`investigate_at_with_patterns`]; appended to the built-in
    /// built-ins by the variant engine in [`Investigation::finish`].
    custom_variant_patterns: Vec<String>,
}

impl Investigation {
    /// Starts an empty investigation seeded with the profile's login and
    /// name (both feed the secondary-account overlap checks and the variant
    /// generation).
    fn new(profile: Profile) -> Self {
        let mut known_usernames = BTreeSet::new();
        known_usernames.insert(profile.login.to_lowercase());
        let mut known_names = BTreeSet::new();
        if let Some(folded) = profile.name.as_deref().and_then(folded_commit_name) {
            known_names.insert(folded);
        }
        Self {
            profile,
            known_usernames,
            known_names,
            usernames: BTreeMap::new(),
            names: BTreeMap::new(),
            emails: BTreeMap::new(),
            other_noreplies: Vec::new(),
            other_noreply_index: HashMap::new(),
            custom_variant_patterns: Vec::new(),
        }
    }

    /// Absorbs one commit of one target repository: both the author and the
    /// committer identities feed the histories, the email list and the
    /// secondary-account candidates.
    fn absorb_commit(&mut self, repo: &str, commit: &CommitPeople) {
        self.absorb_identity(
            repo,
            commit.author_name.as_deref(),
            commit.author_email.as_deref(),
        );
        self.absorb_identity(
            repo,
            commit.committer_name.as_deref(),
            commit.committer_email.as_deref(),
        );
    }

    /// Absorbs one (name, email) identity of a commit, dispatching it to
    /// the right bucket: target noreply → histories, foreign noreply →
    /// pending candidates, other emails → the email list (from which the
    /// local identities and the recurring co-authors are derived).
    fn absorb_identity(&mut self, repo: &str, name: Option<&str>, email: Option<&str>) {
        let Some(email) = email
            .map(|email| email.trim_matches('"'))
            .filter(|email| !email.is_empty())
        else {
            return;
        };
        match parse_noreply(email) {
            Some((id, Some(username))) => {
                if id == self.profile.id {
                    self.record_target_username(username, name, repo);
                } else {
                    self.record_other_noreply(id, Some(username), name, repo);
                }
            }
            Some((id, None)) => {
                if id == self.profile.id {
                    // legacy `<id>@users.noreply.github.com` form: it only
                    // reveals the current username
                    let login = self.profile.login.to_lowercase();
                    self.record_target_username(&login, name, repo);
                } else {
                    // a foreign legacy pair still carries a name that can
                    // match a known target name: keep it pending like the
                    // modern form instead of dropping the sighting
                    self.record_other_noreply(id, None, name, repo);
                }
            }
            None => {
                if !is_usable_email(email) {
                    // not a usable mailbox: a bare username or garbage string
                    // (git permits any author-email field), a whitespace- or
                    // control-bearing payload, or a GitHub noreply address
                    // whose id could not be parsed. The same structural
                    // acceptance rule the scan paths enforce through
                    // `keep_email`: the email list is documented as
                    // noreply-free and well-shaped, and a domainless value
                    // the `email` subcommand itself would reject as invalid
                    // must never be reported as a found email (nor feed the
                    // variant engine a garbage "domain")
                    return;
                }
                self.record_email(email, name, repo);
            }
        }
    }

    /// Records one username of the target revealed by a matching noreply
    /// email: the username, the commit name seen with it and the
    /// repository.
    fn record_target_username(&mut self, username: &str, name: Option<&str>, repo: &str) {
        let username = username.to_lowercase();
        self.known_usernames.insert(username.clone());
        let entry = self.usernames.entry(username).or_default();
        if let Some(name) = name.and_then(folded_commit_name) {
            self.known_names.insert(name.clone());
            let name_entry = self.names.entry(name.clone()).or_default();
            name_entry.sightings += 1;
            name_entry.repos.insert(repo.to_string());
            entry.names.insert(name);
        }
        entry.repos.insert(repo.to_string());
    }

    /// Keeps a foreign-id noreply pair pending: the overlap with the
    /// target's names/usernames is only judged once the scan is complete.
    /// The entry is found through the `(id, lowercased username)` index in
    /// O(1) (usernames are matched case-insensitively, like the
    /// known-username check in `finish`), then mutated through its index.
    fn record_other_noreply(
        &mut self,
        id: u64,
        username: Option<&str>,
        name: Option<&str>,
        repo: &str,
    ) {
        let key = (id, username.map(str::to_lowercase));
        let index = match self.other_noreply_index.get(&key) {
            Some(&index) => index,
            None => {
                let index = self.other_noreplies.len();
                self.other_noreplies.push(OtherNoreply {
                    id,
                    username: username.map(str::to_string),
                    people: Accum::default(),
                });
                self.other_noreply_index.insert(key, index);
                index
            }
        };
        let entry = &mut self.other_noreplies[index];
        if let Some(name) = name.and_then(folded_commit_name) {
            entry.people.names.insert(name);
        }
        entry.people.repos.insert(repo.to_string());
    }

    /// Records one regular email found on the target's repositories, with
    /// the name it was seen with and the repository.
    fn record_email(&mut self, email: &str, name: Option<&str>, repo: &str) {
        let key = email.to_lowercase();
        let entry = self
            .emails
            .entry(key)
            .or_insert_with(|| (email.to_string(), Accum::default()));
        if let Some(name) = name.and_then(folded_commit_name) {
            entry.1.names.insert(name);
        }
        entry.1.repos.insert(repo.to_string());
        // raw sighting: one per absorbed commit identity. The variant
        // engine's domain ranking reads it (see `finish`): distinct-name
        // counts were attacker-inflatable with one commit per planted name
        entry.1.sightings += 1;
    }

    /// Folds the aggregation into the final report: the local identities
    /// and recurring co-authors are derived from the email list, the
    /// pending foreign noreply pairs are judged against the complete
    /// target-name sets, and the variants are generated and matched.
    fn finish(mut self, external: Vec<ExternalContribution>, ssh_keys: Vec<SshKey>) -> UserReport {
        // raw sighting weight per known name, read before the names history
        // consumes the accumulators: the variant engine's pair ranking (see
        // the variants block below) needs the counts
        let name_weights: BTreeMap<String, usize> = self
            .names
            .iter()
            .map(|(name, accum)| (name.clone(), accum.sightings))
            .collect();
        let sightings = |accum: &Accum| {
            (
                accum.names.iter().cloned().collect(),
                accum.repos.iter().cloned().collect(),
            )
        };

        let usernames_history = std::mem::take(&mut self.usernames)
            .into_iter()
            .map(|(username, accum)| {
                let (names, repos) = sightings(&accum);
                UsernameSighting {
                    username,
                    names,
                    repos,
                }
            })
            .collect();
        let names_history = std::mem::take(&mut self.names)
            .into_iter()
            .map(|(name, accum)| NameSighting {
                name,
                repos: accum.repos.into_iter().collect(),
            })
            .collect();

        // the variant domains and matching keys are read from the email
        // list before it is consumed by the sightings below. The domains
        // are ranked by raw sighting weight (one point per absorbed commit
        // identity carrying the domain): a real mail domain accumulates
        // sightings across the target's commits, while planting one commit
        // per junk domain — or per planted name on a junk domain — cannot
        // outweigh it the way distinct-name/repo counts allowed
        let email_keys: BTreeSet<String> = self.emails.keys().cloned().collect();
        let mut domain_weights: BTreeMap<String, usize> = BTreeMap::new();
        for (key, (_, accum)) in &self.emails {
            let Some((_, domain)) = key.rsplit_once('@') else {
                continue;
            };
            if domain.eq_ignore_ascii_case(NOREPLY_DOMAIN) {
                continue;
            }
            *domain_weights.entry(domain.to_string()).or_default() += accum.sightings;
        }
        let mut ranked_domains: Vec<(String, usize)> = domain_weights.into_iter().collect();
        ranked_domains.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        let mut domains: Vec<String> = ranked_domains
            .into_iter()
            .map(|(domain, _)| domain)
            .collect();
        if domains.len() > MAX_VARIANT_DOMAINS {
            log::warn!(
                "address guessing covered only the top {MAX_VARIANT_DOMAINS} email domains ({} seen): the least common domains were skipped",
                domains.len()
            );
            domains.truncate(MAX_VARIANT_DOMAINS);
        }

        let mut local_identities = Vec::new();
        let mut secondary_accounts: Vec<SecondaryAccount> = Vec::new();
        let mut email_sightings: Vec<EmailSighting> = Vec::new();
        for (key, (display, accum)) in std::mem::take(&mut self.emails) {
            let (names, repos) = sightings(&accum);
            if is_local_identity(&key) {
                local_identities.push(EmailSighting {
                    email: display.clone(),
                    names: names.clone(),
                    repos: repos.clone(),
                });
            }
            // co-author heuristic: an email recurring across two or more of
            // the target's repositories whose names never overlap the
            // target's own names. The web-flow identity
            // (noreply@github.com, name "github") is excluded: it is the
            // automation stamp GitHub puts on UI commits, it recurs on any
            // profile with web-flow commits, and reporting it as a
            // secondary account of the target is misleading OSINT noise
            // (the email itself stays in the emails list: it IS an
            // observed commit email)
            if repos.len() >= 2
                && key != WEB_FLOW_EMAIL
                && names.iter().all(|name| !self.known_names.contains(name))
            {
                secondary_accounts.push(SecondaryAccount {
                    kind: "co-author".to_string(),
                    identity: display.clone(),
                    names: names.clone(),
                    repos: repos.clone(),
                });
            }
            email_sightings.push(EmailSighting {
                email: display,
                names,
                repos,
            });
        }
        let other_noreplies = std::mem::take(&mut self.other_noreplies);
        for other in other_noreplies {
            let identity = match &other.username {
                Some(username) => format!("{}+{username}@{NOREPLY_DOMAIN}", other.id),
                None => format!("{}@{NOREPLY_DOMAIN}", other.id),
            };
            let kind = if other
                .username
                .as_deref()
                .map(str::to_lowercase)
                .is_some_and(|username| self.known_usernames.contains(&username))
            {
                "noreply-username"
            } else if other
                .people
                .names
                .iter()
                .any(|name| self.known_names.contains(name))
            {
                "noreply-name"
            } else {
                continue;
            };
            let (names, repos) = sightings(&other.people);
            secondary_accounts.push(SecondaryAccount {
                kind: kind.to_string(),
                identity,
                names,
                repos,
            });
        }

        // variants: every known name pair crossed with every domain deduced
        // from the found emails (noreply excluded), matched against the
        // observed emails (case-insensitively). Both input dimensions are
        // capped (see the MAX_VARIANT_* constants): commit names and commit
        // emails are forgeable and uncapped, and the raw combinatorics
        // multiplied them into an analyst-machine DoS. Name pairs are
        // ranked by raw sighting weight (sum of the sighted counts of the
        // names folding to the pair) instead of alphabetically: one merged
        // PR of alphabetically-first junk names must not evict the real
        // pair. The profile name is API-derived and unforgable, so its pair
        // is always kept first, above the cap
        let known_names = std::mem::take(&mut self.known_names);
        // One O(N) pass: fold every name once and accumulate its raw
        // sighting weight into its (first, last) pair. The previous
        // per-pair ranking re-scanned and re-folded ALL known names for
        // EVERY distinct pair — quadratic in the uncapped, target-forgeable
        // commit-name count (the per-repository walk cap bounds one
        // repository, but the target's own repositories multiply it), all
        // paid BEFORE the MAX_VARIANT_NAME_PAIRS truncation below
        // a BTreeMap keeps the pair iteration deterministic (pair asc), so
        // the stable weight sort below resolves equal weights
        // deterministically — a dropped tie-break cannot hide behind
        // HashMap's randomized order
        let mut pair_weights: BTreeMap<(String, String), usize> = BTreeMap::new();
        for name in &known_names {
            if let Some(pair) = folded_pair(&fold_name(name)) {
                *pair_weights.entry(pair).or_default() +=
                    name_weights.get(name).copied().unwrap_or(0);
            }
        }
        let mut weighted_pairs: Vec<((String, String), usize)> = pair_weights.into_iter().collect();
        weighted_pairs.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        let mut pairs: Vec<(String, String)> =
            weighted_pairs.into_iter().map(|(pair, _)| pair).collect();
        let profile_pair = self
            .profile
            .name
            .as_deref()
            .and_then(folded_commit_name)
            .and_then(|name| folded_pair(&name));
        if let Some(profile_pair) = profile_pair {
            pairs.retain(|pair| pair != &profile_pair);
            pairs.insert(0, profile_pair);
        }
        if pairs.len() > MAX_VARIANT_NAME_PAIRS {
            log::warn!(
                "address guessing used only the top {MAX_VARIANT_NAME_PAIRS} name spellings ({} seen): the least common spellings were skipped",
                pairs.len()
            );
            pairs.truncate(MAX_VARIANT_NAME_PAIRS);
        }
        let mut matched: Vec<VariantMatch> = Vec::new();
        let mut matched_emails: BTreeSet<String> = BTreeSet::new();
        let mut generated: BTreeSet<String> = BTreeSet::new();
        for (first, last) in pairs {
            for domain in &domains {
                for (email, pattern) in
                    generate_variants(&first, &last, domain, &self.custom_variant_patterns)
                {
                    if email_keys.contains(&email) {
                        // two known names can collapse onto the same
                        // generated address ("Jane Dupont" → (jane, dupont)
                        // and "J Dupont" → (j, dupont) both produce
                        // jdupont@…): the email is reported once, with the
                        // pattern of the first built-in-ordered pair that hit it
                        if matched_emails.insert(email.clone()) {
                            matched.push(VariantMatch {
                                email,
                                pattern,
                                domain: domain.clone(),
                            });
                        }
                    } else if generated.len() < MAX_GENERATED_VARIANTS {
                        // the generated list is capped (a hostile target must
                        // not be able to inflate the report without bound);
                        // the matching above keeps running so a variant
                        // beyond the cap can still be reported as matched
                        generated.insert(email);
                    }
                }
            }
        }
        if generated.len() >= MAX_GENERATED_VARIANTS {
            if self.custom_variant_patterns.is_empty() {
                log::warn!(
                    "the list of guessed addresses stops at {MAX_GENERATED_VARIANTS} entries: extra guesses are not listed (confirmed addresses are unaffected)"
                );
            } else {
                log::warn!(
                    "the list of guessed addresses stops at {MAX_GENERATED_VARIANTS} entries: extra guesses are not listed (confirmed addresses are unaffected); the built-in patterns alone can fill this list on a broad target, so custom --variant-pattern guesses that were confirmed are still reported but some unconfirmed ones may be missing from the list"
                );
            }
        }

        UserReport {
            profile: self.profile,
            usernames_history,
            names_history,
            emails: email_sightings,
            variants: Variants {
                matched,
                generated: generated.into_iter().collect(),
            },
            secondary_accounts,
            ssh_keys,
            external_contributions: external,
            local_identities,
        }
    }
}

#[cfg(test)]
mod tests {
    // Tests may unwrap, expect and panic freely: a failing assertion must
    // be loud, so the zero-panic lints do not apply to the test modules.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    // ---- noreply parsing: every shape ----

    #[test]
    fn parse_noreply_recognizes_the_id_username_form() {
        assert_eq!(
            parse_noreply("12345+jane@users.noreply.github.com"),
            Some((12345, Some("jane")))
        );
    }

    #[test]
    fn parse_noreply_recognizes_the_legacy_id_only_form() {
        assert_eq!(
            parse_noreply("12345@users.noreply.github.com"),
            Some((12345, None))
        );
    }

    #[test]
    fn parse_noreply_rejects_every_non_noreply_shape() {
        assert_eq!(parse_noreply("jane@example.com"), None);
        assert_eq!(parse_noreply("12345+jane@evil.com"), None);
        // a subdomain look-alike must not pass the exact-domain check
        assert_eq!(parse_noreply("12345+jane@xusers.noreply.github.com"), None);
        assert_eq!(
            parse_noreply("12345+jane@users.noreply.github.com.evil.com"),
            None
        );
        assert_eq!(parse_noreply("no-id@users.noreply.github.com"), None);
        assert_eq!(parse_noreply("+jane@users.noreply.github.com"), None);
        assert_eq!(parse_noreply("12345+@users.noreply.github.com"), None);
        assert_eq!(parse_noreply("12345+jane"), None);
    }

    #[test]
    fn parse_noreply_falls_back_to_the_id_when_the_username_is_not_a_github_username() {
        // commit author emails are free-form: a hostile or malformed
        // username payload must never become a past username in the report
        assert_eq!(
            parse_noreply("42+old.name@users.noreply.github.com"),
            Some((42, None))
        );
        assert_eq!(
            parse_noreply("42+jane doe@users.noreply.github.com"),
            Some((42, None))
        );
        assert_eq!(
            parse_noreply("42+jane+doe@users.noreply.github.com"),
            Some((42, None))
        );
        assert_eq!(
            parse_noreply(
                "42+a-very-long-username-past-the-39-character-limit@users.noreply.github.com"
            ),
            Some((42, None))
        );
        // the charset alone is not enough: GitHub never issues usernames
        // with a leading/trailing hyphen or consecutive hyphens, so a
        // commit-forged payload of that shape falls back to the id only
        assert_eq!(
            parse_noreply("42+-jane@users.noreply.github.com"),
            Some((42, None))
        );
        assert_eq!(
            parse_noreply("42+jane-@users.noreply.github.com"),
            Some((42, None))
        );
        assert_eq!(
            parse_noreply("42+j--ane@users.noreply.github.com"),
            Some((42, None))
        );
        // the valid charset still passes through verbatim
        assert_eq!(
            parse_noreply("42+Jane-Doe9@users.noreply.github.com"),
            Some((42, Some("Jane-Doe9")))
        );
    }

    // ---- local identity heuristic ----

    #[test]
    fn is_local_identity_flags_the_documented_machine_local_domains() {
        assert!(is_local_identity("jeanpierre@My-Computer.local"));
        assert!(is_local_identity("jeanpierre@box.lan"));
        assert!(is_local_identity("jeanpierre@mycomputer"));
        assert!(!is_local_identity("jeanpierre@example.com"));
        assert!(!is_local_identity("jeanpierre@mail.example.com"));
        assert!(!is_local_identity("jeanpierre@my-pc.corp"));
        assert!(!is_local_identity("no-domain-at-all"));
    }

    // ---- ASCII folding ----

    #[test]
    fn fold_name_strips_common_latin_accents_and_keeps_other_scripts() {
        assert_eq!(fold_name("Jérôme Dupont"), "jerome dupont");
        assert_eq!(fold_name("ÀÉÎÕÜ"), "aeiou");
        assert_eq!(fold_name("Straße"), "strasse");
        assert_eq!(fold_name("Œuvre ærø"), "oeuvre aero");
        assert_eq!(fold_name("Søren"), "soren");
        // non-Latin scripts are kept raw (documented delta, no unicode crate)
        assert_eq!(fold_name("山田"), "山田");
    }

    // ---- variant generation ----

    #[test]
    fn generate_variants_produces_the_documented_combinatorics_in_order() {
        let variants = generate_variants("jean", "dupont", "acme.com", &[]);
        assert_eq!(
            variants,
            vec![
                ("jean.dupont@acme.com".to_string(), "first.last".to_string()),
                ("jeandupont@acme.com".to_string(), "firstlast".to_string()),
                ("jdupont@acme.com".to_string(), "initiallast".to_string()),
                ("jean_dupont@acme.com".to_string(), "first_last".to_string()),
                ("j_dupont@acme.com".to_string(), "initial_last".to_string()),
                ("jean@acme.com".to_string(), "first".to_string()),
                ("dupont@acme.com".to_string(), "last".to_string()),
                ("j.dupont@acme.com".to_string(), "initial.last".to_string()),
            ]
        );
    }

    #[test]
    fn generate_variants_is_deterministic_and_deduplicates() {
        let a = generate_variants("jean", "dupont", "acme.com", &[]);
        let b = generate_variants("jean", "dupont", "acme.com", &[]);
        assert_eq!(a, b, "the generation must be deterministic");
        // a single-letter first name collapses the initial patterns onto the
        // full-name ones: deduplicated, the fixed order is preserved
        let collapsed = generate_variants("j", "dupont", "acme.com", &[]);
        let emails: Vec<&str> = collapsed.iter().map(|(email, _)| email.as_str()).collect();
        assert_eq!(
            emails.len(),
            emails
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
        );
        assert_eq!(emails[0], "j.dupont@acme.com");
    }

    #[test]
    fn generate_variants_with_no_last_name_only_generates_the_bare_first() {
        assert_eq!(
            generate_variants("jean", "", "acme.com", &[]),
            vec![("jean@acme.com".to_string(), "first".to_string())]
        );
    }

    #[test]
    fn custom_patterns_are_applied_after_the_builtins_in_cli_order() {
        let variants = generate_variants(
            "jean",
            "dupont",
            "acme.com",
            &[
                "{last}{first}".to_string(),
                "{first}.{initial}{last}".to_string(),
            ],
        );
        // the built-in patterns keep their documented order, the custom patterns
        // come after, in their CLI order, labeled by their own template
        assert_eq!(
            variants[variants.len() - 2..],
            [
                (
                    "dupontjean@acme.com".to_string(),
                    "{last}{first}".to_string()
                ),
                (
                    "jean.jdupont@acme.com".to_string(),
                    "{first}.{initial}{last}".to_string()
                ),
            ]
        );
        // a custom pattern collapsing onto a built-in is deduplicated away
        let collapsed =
            generate_variants("jean", "dupont", "acme.com", &["{first}{last}".to_string()]);
        assert_eq!(
            collapsed
                .iter()
                .filter(|(_, p)| p == "{first}{last}")
                .count(),
            0
        );
    }

    #[test]
    fn custom_patterns_requiring_a_last_name_are_skipped_without_one() {
        assert_eq!(
            generate_variants("jean", "", "acme.com", &["{last}{first}".to_string()]),
            vec![("jean@acme.com".to_string(), "first".to_string())]
        );
        // one not requiring it still applies
        assert_eq!(
            generate_variants("jean", "", "acme.com", &["{first}x".to_string()]),
            vec![
                ("jean@acme.com".to_string(), "first".to_string()),
                ("jeanx@acme.com".to_string(), "{first}x".to_string()),
            ]
        );
    }

    #[test]
    fn validate_variant_pattern_accepts_the_documented_templates() {
        for pattern in [
            "{first}",
            "{last}",
            "{initial}",
            "{last}{first}",
            "{first}.{initial}{last}",
        ] {
            assert!(
                validate_variant_pattern(pattern).is_ok(),
                "{pattern} must be accepted"
            );
        }
    }

    #[test]
    fn validate_variant_pattern_rejects_every_malformed_shape() {
        for pattern in [
            "",
            "   ",
            "jean",             // no placeholder
            "{first",           // unclosed
            "{unknown}",        // unknown placeholder
            "{first}{last}{x}", // one unknown among known ones
            "{first}@{last}",   // '@' would forge an unusable address
            "{first} {last}",   // whitespace ditto
            "a}b{first}",       // stray '}' outside a placeholder
        ] {
            assert!(
                validate_variant_pattern(pattern).is_err(),
                "{pattern} must be rejected"
            );
        }
        // the rejection names the allowed placeholders (the message is the
        // only documentation the terminal error carries)
        let err = validate_variant_pattern("{unknown}").unwrap_err();
        assert!(err.to_string().contains("{first}"));
    }

    #[test]
    fn the_custom_pattern_count_is_capped() {
        let patterns: Vec<String> = (0..MAX_CUSTOM_VARIANT_PATTERNS + 1)
            .map(|index| format!("{{first}}x{index}"))
            .collect();
        let err = investigate_at_with_patterns(
            &Client::anonymous().expect("the anonymous client must always build"),
            "http://127.0.0.1:1",
            "octocat",
            &patterns,
        )
        .unwrap_err();
        assert!(err.to_string().contains("custom variant patterns"));
    }

    #[test]
    fn the_library_path_rejects_a_malformed_custom_pattern_before_any_network_call() {
        // removing the validation loop from investigate_at_with_patterns must
        // fail a test: a loopback base that answers nothing guarantees the
        // rejection is client-side, before any request is issued
        let err = investigate_at_with_patterns(
            &Client::anonymous().expect("the anonymous client must always build"),
            "http://127.0.0.1:1",
            "octocat",
            &["{first".to_string()],
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("invalid --variant-pattern"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn the_custom_pattern_literal_part_matches_case_insensitively() {
        // the expansion is lowercased: a mixed-case literal template must
        // produce a lowercased candidate that the observed-email keys
        // (lowercased) can match — a case-sensitive expansion would silently
        // classify it as generated instead of matched. (A template expanding
        // onto a built-in candidate, like "J.{last}" → j.dupont@, is
        // deduplicated against the built-in, so a distinct literal is used.)
        let variants = generate_variants("jane", "dupont", "acme.com", &["J.{last}x".to_string()]);
        assert!(
            variants
                .iter()
                .any(|(email, pattern)| email == "j.dupontx@acme.com" && pattern == "J.{last}x"),
            "expected the lowercased expansion in {variants:?}"
        );
    }

    #[test]
    fn validate_variant_pattern_rejects_control_and_non_ascii_characters() {
        for pattern in [
            "{first}\u{200b}{last}", // zero-width space (Cf, not whitespace)
            "\u{1b}{first}",         // ESC (Cc): would inject into the JSON report
            "{first}\u{00e9}",       // non-ASCII letter: no real mailbox carries one
        ] {
            assert!(
                validate_variant_pattern(pattern).is_err(),
                "{pattern} must be rejected"
            );
        }
        // printable ASCII outside the placeholders stays fine
        assert!(validate_variant_pattern("A-B_9.{last}").is_ok());
    }

    #[test]
    fn folded_pairs_take_the_first_and_last_tokens() {
        // the variant pairs are built from the first and last token of the
        // folded name: a single-token name yields `(name, "")` (first and
        // last collapse), and a longer name collapses onto the two-token
        // spelling's pair
        assert_eq!(
            folded_pair(&fold_name("Jane Dupont")),
            Some(("jane".to_string(), "dupont".to_string()))
        );
        assert_eq!(
            folded_pair(&fold_name("jd")),
            Some(("jd".to_string(), String::new()))
        );
        assert_eq!(
            folded_pair(&fold_name("Jane Marie Dupont")),
            Some(("jane".to_string(), "dupont".to_string()))
        );
        assert_eq!(folded_pair(&fold_name("   ")), None);
    }

    // ---- profile parsing and org differentiator ----

    #[test]
    fn parse_profile_reads_the_documented_fields() {
        let json: Value = serde_json::json!({
            "login": "JaneDoe",
            "id": 42,
            "name": "Jane Doe",
            "company": "Acme",
            "blog": "https://jane.example",
            "location": "Paris",
            "email": "jane@example.com",
            "bio": "dev",
            "twitter_username": "janedoe",
            "public_repos": 7,
            "created_at": "2015-01-01T00:00:00Z",
            "type": "User"
        });
        let profile = parse_profile(&json).expect("the full payload must parse");
        assert_eq!(profile.login, "JaneDoe");
        assert_eq!(profile.id, 42);
        assert_eq!(profile.name.as_deref(), Some("Jane Doe"));
        assert_eq!(profile.public_repos, 7);
        assert_eq!(profile.account_type.as_deref(), Some("User"));
    }

    #[test]
    fn an_organization_profile_is_rejected_with_a_clear_error() {
        // the org differentiator: the `user` subcommand must
        // fail with a clear message pointing at the now-existing `org`
        // subcommand
        let json: Value = serde_json::json!({ "login": "acme", "id": 7, "type": "Organization" });
        let profile = parse_profile(&json).expect("the payload must parse");
        assert!(matches!(
            profile.account_type.as_deref(),
            Some("Organization")
        ));
        let error = Error::Organization(profile.login.clone());
        assert!(error.to_string().contains("acme"));
        assert!(error.to_string().contains("`org` subcommand"));
    }

    #[test]
    fn investigate_at_rejects_an_organization_target_with_the_org_subcommand_pointer() {
        // the org differentiator must be executed by the real investigation
        // entry point: deleting the `type == "Organization"` branch (i.e.
        // reverting the fix) must fail this test with a full nonsense
        // investigation instead of the documented clear error
        let (address, server) = crate::github::mock::serve_requests(move |_index, _request| {
            (
                200,
                vec![],
                r#"{"login": "acme", "id": 7, "type": "Organization"}"#.to_string(),
            )
        });

        let client = crate::github::Client::anonymous().expect("client must build");
        let error = investigate_at_with_patterns(&client, &address, "acme", &[])
            .expect_err("an organization target must be rejected");
        server.join();
        assert!(
            matches!(&error, Error::Organization(login) if login == "acme"),
            "unexpected error: {error:?}"
        );
        assert!(
            error.to_string().contains("`org` subcommand"),
            "the message must point at the dedicated `org` subcommand: {error}"
        );
    }

    #[test]
    fn parse_profile_requires_the_login_and_the_id() {
        // a payload without the target's identity must fail explicitly: a
        // report with an empty login and id 0 would silently never match
        // any noreply email
        for partial in [
            serde_json::json!({ "id": 42, "type": "User" }),
            serde_json::json!({ "login": "jane", "type": "User" }),
            serde_json::json!({ "login": "", "id": 42 }),
        ] {
            let error = parse_profile(&partial).expect_err("a partial payload must fail");
            assert!(matches!(error, Error::InvalidProfile(_)));
        }
    }

    #[test]
    fn validate_username_rejects_bad_targets_before_any_request() {
        assert!(validate_username("jane-doe-1").is_ok());
        for bad in [
            "", "jane doe", "a/b", "über", "jane?doe",
            // GitHub's username shape: no leading/trailing hyphen, no
            // consecutive hyphens — a name GitHub could never have issued
            "-jane", "jane-", "j--ane", "-",
        ] {
            assert!(
                matches!(validate_username(bad), Err(Error::InvalidUsername(_))),
                "{bad:?} must be rejected"
            );
        }
    }

    // ---- commit people parsing ----

    #[test]
    fn parse_people_page_extracts_author_and_committer_identities() {
        let json: Value = serde_json::json!([
            {
                "commit": {
                    "author": { "name": "Jane Doe", "email": "12345+jane@users.noreply.github.com" },
                    "committer": { "name": "Jane Doe", "email": "jane@example.com" }
                }
            },
            { "commit": { "author": { "name": "Bob", "email": "bob@y.y" } } },
            { "other": true }
        ]);
        let (people, raw_count) = parse_people_page(&json).expect("parsing must succeed");
        assert_eq!(raw_count, 3, "raw item count, even without identities");
        assert_eq!(
            people[0],
            CommitPeople {
                author_name: Some("Jane Doe".to_string()),
                author_email: Some("12345+jane@users.noreply.github.com".to_string()),
                committer_name: Some("Jane Doe".to_string()),
                committer_email: Some("jane@example.com".to_string()),
            }
        );
        assert_eq!(people[1].committer_email, None);
    }

    #[test]
    fn parse_people_page_empty_array_ends_the_listing() {
        let (people, raw_count) =
            parse_people_page(&serde_json::json!([])).expect("parsing must succeed");
        assert!(people.is_empty());
        assert_eq!(raw_count, 0);
    }

    // ---- keys and external contributions parsing ----

    #[test]
    fn parse_keys_page_extracts_the_documented_fields() {
        let json: Value = serde_json::json!([
            { "id": 1, "key": "ssh-ed25519 AAAA", "title": "laptop", "created_at": "2020-01-01T00:00:00Z" },
            { "id": 2, "key": "ssh-rsa BBBB" },
            // a partial payload without an id is skipped, not reported with
            // a fake id 0 that could never match (raw count unchanged)
            { "key": "ssh-ed25519 CCCC" },
            { "id": null, "key": "ssh-ed25519 DDDD" }
        ]);
        let (keys, raw_count) = parse_keys_page(&json).expect("parsing must succeed");
        assert_eq!(raw_count, 4);
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].id, 1);
        assert_eq!(keys[0].key, "ssh-ed25519 AAAA");
        assert_eq!(keys[0].title.as_deref(), Some("laptop"));
        assert_eq!(keys[1].title, None);
    }

    #[test]
    fn a_non_array_200_listing_body_fails_the_user_listings_explicitly() {
        // GitHub returns `[]` for an empty listing: a non-array 200 body is
        // an intermediary (proxy, captive portal) or a shape change, and
        // must never be read as a legitimate empty page (the same rule as
        // the `org` investigation's listings)
        for json in [
            serde_json::json!({ "message": "HTML error page" }),
            serde_json::json!("not a listing"),
        ] {
            let error =
                parse_repository_page(&json).expect_err("a non-array repositories body must fail");
            assert!(
                matches!(&error, Error::InvalidProfile(details) if details.contains("array")),
                "unexpected error: {error:?}"
            );
            let error = parse_people_page(&json).expect_err("a non-array commits body must fail");
            assert!(
                matches!(&error, Error::InvalidProfile(details) if details.contains("array")),
                "unexpected error: {error:?}"
            );
            let error = parse_keys_page(&json).expect_err("a non-array keys body must fail");
            assert!(
                matches!(&error, Error::InvalidProfile(details) if details.contains("array")),
                "unexpected error: {error:?}"
            );
        }
    }

    #[test]
    fn parse_external_page_extracts_repositories_and_urls() {
        let json: Value = serde_json::json!({
            "total_count": 2,
            "items": [
                { "repository": { "full_name": "acme/lib", "html_url": "https://github.com/acme/lib" } },
                { "repository": { "full_name": "other/proj" } }
            ]
        });
        let (hits, raw_count) = parse_external_page(&json).expect("parsing must succeed");
        assert_eq!(raw_count, 2);
        assert_eq!(hits[0].repository, "acme/lib");
        assert_eq!(hits[0].url.as_deref(), Some("https://github.com/acme/lib"));
        assert_eq!(hits[1].url, None);
    }

    #[test]
    fn parse_external_page_rejected_search_ends_the_listing() {
        let (hits, raw_count) = parse_external_page(&serde_json::json!({ "items": null }))
            .expect("parsing must succeed");
        assert!(hits.is_empty());
        assert_eq!(raw_count, 0);
    }

    #[test]
    fn parse_external_page_missing_items_field_fails_explicitly() {
        // a rejected search (`{"items": null}`) legitimately ends the
        // listing, but a 200 body without an `items` field at all is an
        // intermediary or a shape change: it must fail like the sibling
        // `parse_search_page` instead of silently ending the
        // external-contributions listing as a complete-looking empty result
        for body in [serde_json::json!({}), serde_json::json!("not a listing")] {
            let error = parse_external_page(&body).expect_err("a payload without items must fail");
            assert!(
                matches!(&error, Error::InvalidProfile(details) if details.contains("items")),
                "unexpected error: {error:?}"
            );
        }
    }

    #[test]
    fn parse_external_page_fails_explicitly_on_a_non_array_items_field() {
        // an `items` field that is present but neither an array nor `null`
        // is a shape change, not a rejected search: treating it as an empty
        // page would silently drop the whole external-contributions section
        for body in [
            serde_json::json!({"items": {}}),
            serde_json::json!({"items": 42}),
        ] {
            let error = parse_external_page(&body).expect_err("a non-array items must fail");
            assert!(
                matches!(&error, Error::InvalidProfile(details) if details.contains("array")),
                "unexpected error: {error:?}"
            );
        }
    }

    // ---- the investigation state machine ----

    /// A minimal `jane` profile with id 42.
    fn jane_profile() -> Profile {
        parse_profile(&serde_json::json!({
            "login": "jane", "id": 42, "name": "Jane Dupont", "type": "User"
        }))
        .expect("the minimal profile must parse")
    }

    /// Builds a CommitPeople from (author name, author email) and
    /// (committer name, committer email) tuples.
    fn people(author: (&str, &str), committer: (&str, &str)) -> CommitPeople {
        CommitPeople {
            author_name: Some(author.0.to_string()),
            author_email: Some(author.1.to_string()),
            committer_name: Some(committer.0.to_string()),
            committer_email: Some(committer.1.to_string()),
        }
    }

    #[test]
    fn absorb_commit_aggregates_the_noreply_history() {
        let mut investigation = Investigation::new(jane_profile());
        investigation.absorb_commit(
            "jane/old",
            &people(
                ("Jane D.", "42+oldname@users.noreply.github.com"),
                ("Jane Dupont", "42@users.noreply.github.com"),
            ),
        );
        investigation.absorb_commit(
            "jane/new",
            &people(
                ("Jane Dupont", "42@users.noreply.github.com"),
                ("Jane Dupont", "42@users.noreply.github.com"),
            ),
        );

        let report = investigation.finish(Vec::new(), Vec::new());
        // two usernames revealed: the id+username form on page one, and the
        // legacy id-only form attributed to the current login
        let usernames: Vec<&str> = report
            .usernames_history
            .iter()
            .map(|sighting| sighting.username.as_str())
            .collect();
        assert_eq!(usernames, vec!["jane", "oldname"]);
        let oldname = &report.usernames_history[1];
        assert_eq!(oldname.names, vec!["jane d.".to_string()]);
        assert_eq!(oldname.repos, vec!["jane/old".to_string()]);
        // names history aggregated across the repositories
        let names: Vec<&str> = report
            .names_history
            .iter()
            .map(|sighting| sighting.name.as_str())
            .collect();
        assert_eq!(names, vec!["jane d.", "jane dupont"]);
        let jane = &report.names_history[1];
        // repositories are reported sorted (BTree-backed aggregation)
        assert_eq!(
            jane.repos,
            vec!["jane/new".to_string(), "jane/old".to_string()]
        );
        // no real email was absorbed
        assert!(report.emails.is_empty());
        assert!(report.local_identities.is_empty());
    }

    #[test]
    fn absorb_commit_collects_emails_names_and_local_identities() {
        let mut investigation = Investigation::new(jane_profile());
        investigation.absorb_commit(
            "jane/one",
            &people(
                ("Jane", "jeanpierre@My-Computer.local"),
                ("Co Worker", "co@acme.com"),
            ),
        );
        investigation.absorb_commit(
            "jane/two",
            &people(("Co Worker", "CO@acme.com"), ("Jane", "jane@gmail.com")),
        );

        let report = investigation.finish(Vec::new(), Vec::new());
        // the same email is deduplicated (case-insensitively) across repos
        assert_eq!(report.emails.len(), 3);
        let co = report
            .emails
            .iter()
            .find(|sighting| sighting.email == "co@acme.com")
            .expect("co@acme.com must be kept");
        assert_eq!(co.names, vec!["co worker".to_string()]);
        assert_eq!(
            co.repos,
            vec!["jane/one".to_string(), "jane/two".to_string()]
        );
        // the UPN-like email is flagged by the heuristic
        assert_eq!(report.local_identities.len(), 1);
        assert_eq!(
            report.local_identities[0].email,
            "jeanpierre@My-Computer.local"
        );
        // the co-author heuristic: co@acme.com recurs across two repos and
        // never carries a target name
        assert_eq!(report.secondary_accounts.len(), 1);
        assert_eq!(report.secondary_accounts[0].kind, "co-author");
        assert_eq!(report.secondary_accounts[0].identity, "co@acme.com");
    }

    #[test]
    fn the_web_flow_identity_is_never_a_secondary_account() {
        // noreply@github.com (name "github") is the automation stamp GitHub
        // puts on UI commits: it recurs across two or more repositories on
        // any profile with web-flow commits and never carries a target
        // name, so the co-author heuristic flagged it as a secondary
        // account of the target (live repro: user elibenporat reported
        // secondary_accounts[0].identity == "noreply@github.com"). It
        // stays in the emails list — it IS an observed commit email — but
        // it is automation, not a person
        let mut investigation = Investigation::new(jane_profile());
        investigation.absorb_identity("jane/one", Some("GitHub"), Some("noreply@github.com"));
        investigation.absorb_identity("jane/two", Some("GitHub"), Some("noreply@github.com"));
        let report = investigation.finish(Vec::new(), Vec::new());
        assert!(
            report
                .secondary_accounts
                .iter()
                .all(|account| account.identity != "noreply@github.com"),
            "the web-flow automation identity must not be a secondary account: {:?}",
            report.secondary_accounts
        );
        // it is still honestly listed as an observed commit email
        assert!(
            report
                .emails
                .iter()
                .any(|sighting| sighting.email == "noreply@github.com")
        );
    }

    #[test]
    fn absorb_commit_applies_the_shared_is_usable_email_rule_to_the_user_path() {
        // the scan paths never report a domainless or garbage commit-email
        // field as a found email (`keep_email` → `is_usable_email`): the
        // `user` investigation must enforce the same rule, or the report's
        // email list would contain entries the `email` subcommand itself
        // rejects as invalid addresses (live repro: `user <target>` reported
        // bare usernames, `nomail`, `mauric“e`… as found emails), and the junk
        // "domains" would feed the variant engine
        let mut investigation = Investigation::new(jane_profile());
        for email in [
            "jdoe",
            "not-an-email",
            "dev@x@com",
            "@example.com",
            "dev@",
            "dev@x.com\nFORGED LINE",
            "  dev@x.com  ",
            "42+jane@users.noreply.github.com",
            "unparsable@users.noreply.github.com",
        ] {
            investigation.absorb_identity("jane/one", Some("Jane"), Some(email));
        }
        // the one well-shaped mailbox is still kept, unharmed
        investigation.absorb_identity("jane/one", Some("Jane"), Some("dev@ok.com"));

        let report = investigation.finish(Vec::new(), Vec::new());
        let emails: Vec<&str> = report
            .emails
            .iter()
            .map(|sighting| sighting.email.as_str())
            .collect();
        assert_eq!(
            emails,
            vec!["dev@ok.com"],
            "garbage must be dropped: {emails:?}"
        );
        // the junk "domains" must not leak into the generated variants
        assert!(
            report
                .variants
                .generated
                .iter()
                .all(|variant| variant.ends_with("@ok.com"))
        );
    }

    #[test]
    fn foreign_noreply_pairs_become_secondary_candidates_on_overlap() {
        let mut investigation = Investigation::new(jane_profile());
        // username overlap: a foreign id carrying the target's known username
        investigation.absorb_commit(
            "jane/one",
            &people(
                ("Jane", "999+jane@users.noreply.github.com"),
                ("Jane", "42@users.noreply.github.com"),
            ),
        );
        // name overlap: a foreign id with an unknown username but the
        // target's known name
        investigation.absorb_commit(
            "jane/two",
            &people(
                ("Jane Dupont", "777+ghost@users.noreply.github.com"),
                ("Jane Dupont", "42@users.noreply.github.com"),
            ),
        );
        // no overlap at all: dropped
        investigation.absorb_commit(
            "jane/two",
            &people(
                ("Stranger", "555+stranger@users.noreply.github.com"),
                ("Stranger", "stranger@x.x"),
            ),
        );

        let report = investigation.finish(Vec::new(), Vec::new());
        assert_eq!(report.secondary_accounts.len(), 2);
        let username_hit = report
            .secondary_accounts
            .iter()
            .find(|account| account.kind == "noreply-username")
            .expect("the username overlap must be reported");
        assert_eq!(username_hit.identity, "999+jane@users.noreply.github.com");
        let name_hit = report
            .secondary_accounts
            .iter()
            .find(|account| account.kind == "noreply-name")
            .expect("the name overlap must be reported");
        assert_eq!(name_hit.identity, "777+ghost@users.noreply.github.com");
    }

    #[test]
    fn a_foreign_legacy_noreply_pair_can_fire_the_noreply_name_heuristic() {
        // the legacy `<id>@users.noreply.github.com` form with a foreign id
        // carries a name that can match a known target name: it must be
        // judged like the modern form instead of being dropped entirely
        let mut investigation = Investigation::new(jane_profile());
        investigation.absorb_commit(
            "jane/one",
            &people(
                ("Jane Dupont", "888@users.noreply.github.com"),
                ("Jane Dupont", "42@users.noreply.github.com"),
            ),
        );
        let report = investigation.finish(Vec::new(), Vec::new());
        assert_eq!(report.secondary_accounts.len(), 1);
        assert_eq!(report.secondary_accounts[0].kind, "noreply-name");
        assert_eq!(
            report.secondary_accounts[0].identity,
            "888@users.noreply.github.com"
        );
    }

    #[test]
    fn foreign_noreply_candidates_are_deduplicated_case_insensitively() {
        // the same foreign account seen with different identity casing must
        // yield one candidate (the known-username match in `finish` is
        // already case-insensitive)
        let mut investigation = Investigation::new(jane_profile());
        investigation.absorb_commit(
            "jane/one",
            &people(
                ("Jane", "999+Jane@users.noreply.github.com"),
                ("Jane", "42@users.noreply.github.com"),
            ),
        );
        investigation.absorb_commit(
            "jane/two",
            &people(
                ("Jane", "999+jane@users.noreply.github.com"),
                ("Jane", "42@users.noreply.github.com"),
            ),
        );
        let report = investigation.finish(Vec::new(), Vec::new());
        assert_eq!(report.secondary_accounts.len(), 1);
        assert_eq!(report.secondary_accounts[0].kind, "noreply-username");
        // the first-seen casing is kept for the reported identity
        assert_eq!(
            report.secondary_accounts[0].identity,
            "999+Jane@users.noreply.github.com"
        );
        // both repositories are kept as evidence
        assert_eq!(
            report.secondary_accounts[0].repos,
            vec!["jane/one".to_string(), "jane/two".to_string()]
        );
    }

    #[test]
    fn a_malformed_noreply_email_never_leaks_into_the_email_list() {
        // a noreply address whose id cannot be parsed is not a real mailbox:
        // `emails` is documented as noreply-free, whatever the payload
        let mut investigation = Investigation::new(jane_profile());
        investigation.absorb_commit(
            "jane/one",
            &people(
                ("Jane", "no-id@users.noreply.github.com"),
                ("Jane", "99999999999999999999999@users.noreply.github.com"),
            ),
        );
        let report = investigation.finish(Vec::new(), Vec::new());
        assert!(report.emails.is_empty());
        assert!(report.usernames_history.is_empty());
        assert!(report.names_history.is_empty());
    }

    #[test]
    fn whitespace_only_commit_names_are_dropped() {
        // a hostile whitespace-only commit name must not plant noise in the
        // histories or in the variant generation (the profile has no name,
        // so no variant can come from anywhere else)
        let profile = parse_profile(&serde_json::json!({
            "login": "jane", "id": 42, "type": "User"
        }))
        .expect("the nameless profile must parse");
        let mut investigation = Investigation::new(profile);
        investigation.absorb_commit(
            "jane/one",
            &people(
                ("   ", "42@users.noreply.github.com"),
                (" \t ", "jane@gmail.com"),
            ),
        );
        let report = investigation.finish(Vec::new(), Vec::new());
        assert!(report.names_history.is_empty());
        assert!(report.usernames_history[0].names.is_empty());
        assert!(report.emails[0].names.is_empty());
        // with no usable name left, no variant is generated at all
        assert!(report.variants.matched.is_empty());
        assert!(report.variants.generated.is_empty());
    }

    #[test]
    fn finish_matches_the_observed_variants_and_lists_the_generated_ones() {
        let mut investigation = Investigation::new(jane_profile());
        // jane.dupont@acme.com is observed in a commit: the first.last
        // variant must land in `matched`, the others in `generated`
        investigation.absorb_commit(
            "jane/one",
            &people(
                ("Jane Dupont", "Jane.Dupont@ACME.com"),
                ("Jane Dupont", "42@users.noreply.github.com"),
            ),
        );
        let report = investigation.finish(Vec::new(), Vec::new());
        let matched: Vec<&str> = report
            .variants
            .matched
            .iter()
            .map(|variant| variant.email.as_str())
            .collect();
        assert_eq!(matched, vec!["jane.dupont@acme.com"]);
        assert_eq!(report.variants.matched[0].pattern, "first.last");
        assert_eq!(report.variants.matched[0].domain, "acme.com");
        // the generated-but-unseen candidates for the same name/domain
        let generated: Vec<&str> = report
            .variants
            .generated
            .iter()
            .map(|email| email.as_str())
            .collect();
        assert!(generated.contains(&"janedupont@acme.com"));
        assert!(generated.contains(&"jdupont@acme.com"));
        assert!(generated.contains(&"jane_dupont@acme.com"));
        assert!(generated.contains(&"j_dupont@acme.com"));
        assert!(generated.contains(&"jane@acme.com"));
        assert!(generated.contains(&"dupont@acme.com"));
        assert!(generated.contains(&"j.dupont@acme.com"));
        // the noreply domain never feeds the variant domains
        assert!(generated.iter().all(|email| !email.contains("noreply")));
    }

    #[test]
    fn the_weight_ranking_pins_the_most_sighted_non_profile_pair_and_the_tie_break() {
        // the profile name is deliberately irrelevant ("Zed"): the ranking
        // under test is the raw-sighting weight of the planted pairs, not
        // the profile-pair-first protection (which the sibling test covers).
        // Both planted pairs generate the SAME candidate jdoe@acme.com at
        // DIFFERENT built-in pattern positions: ("jdoe", "") via `first`, ("j", "doe") via
        // `firstlast`. A mutant that drops or inverts the weight `sort_by`
        // fails the first scenario; a mutant that drops the pair-asc
        // tie-break fails the second.
        let observed = |inv: &mut Investigation| {
            inv.absorb_commit(
                "zed/three",
                &people(
                    ("Zed", "jdoe@acme.com"),
                    ("Zed", "7+seen@users.noreply.github.com"),
                ),
            );
        };
        let attribution = |report: &UserReport| {
            report
                .variants
                .matched
                .iter()
                .find(|variant| variant.email == "jdoe@acme.com")
                .expect("the observed candidate must be matched")
                .pattern
                .clone()
        };

        // most-sighted wins: ("jdoe", "") sighted 3 times beats
        // ("j", "doe") sighted twice
        let mut investigation = Investigation::new(
            parse_profile(&serde_json::json!({
                "login": "zed", "id": 7, "name": "Zed", "type": "User"
            }))
            .expect("the minimal profile must parse"),
        );
        for repo in ["zed/one", "zed/two", "zed/four"] {
            investigation.absorb_commit(
                repo,
                &people(
                    ("Jdoe", "7+s0@users.noreply.github.com"),
                    ("Else", "999+e0@users.noreply.github.com"),
                ),
            );
        }
        for repo in ["zed/one", "zed/two"] {
            investigation.absorb_commit(
                repo,
                &people(
                    ("J Doe", "7+s1@users.noreply.github.com"),
                    ("Else", "999+e1@users.noreply.github.com"),
                ),
            );
        }
        observed(&mut investigation);
        let report = investigation.finish(Vec::new(), Vec::new());
        assert_eq!(
            attribution(&report),
            "first",
            "the most-sighted pair (jdoe, \"\") must win the attribution: {:?}",
            report.variants.matched
        );

        // equal weights: the pair-asc tie-break decides — ("j", "doe")
        // sorts before ("jdoe", ""), so `firstlast` is attributed
        let mut tied = Investigation::new(
            parse_profile(&serde_json::json!({
                "login": "zed", "id": 7, "name": "Zed", "type": "User"
            }))
            .expect("the minimal profile must parse"),
        );
        tied.absorb_commit(
            "zed/one",
            &people(
                ("Jdoe", "7+s0@users.noreply.github.com"),
                ("Else", "999+e0@users.noreply.github.com"),
            ),
        );
        tied.absorb_commit(
            "zed/two",
            &people(
                ("J Doe", "7+s1@users.noreply.github.com"),
                ("Else", "999+e1@users.noreply.github.com"),
            ),
        );
        observed(&mut tied);
        let report = tied.finish(Vec::new(), Vec::new());
        assert_eq!(
            attribution(&report),
            "firstlast",
            "equal weights must tie-break on the pair tuple ascending: {:?}",
            report.variants.matched
        );
    }

    #[test]
    fn matched_variants_are_deduplicated_across_name_pairs() {
        let mut investigation = Investigation::new(jane_profile());
        // the profile name "Jane Dupont" yields the pair ("jane", "dupont"),
        // whose initiallast pattern generates jdupont@acme.com; the commit
        // name "J Dupont" seen with the target's id yields ("j", "dupont"),
        // whose firstlast pattern generates the SAME email, also observed in
        // a commit. The two patterns must not list the email twice in
        // `variants.matched`
        investigation.absorb_commit(
            "jane/one",
            &people(
                ("Jane Dupont", "42+old@users.noreply.github.com"),
                ("J Dupont", "42+cur@users.noreply.github.com"),
            ),
        );
        investigation.absorb_commit(
            "jane/two",
            &people(
                ("Jane Dupont", "jdupont@acme.com"),
                ("Jane Dupont", "42@users.noreply.github.com"),
            ),
        );
        let report = investigation.finish(Vec::new(), Vec::new());
        let jdupont: Vec<&VariantMatch> = report
            .variants
            .matched
            .iter()
            .filter(|variant| variant.email == "jdupont@acme.com")
            .collect();
        assert_eq!(
            jdupont.len(),
            1,
            "the same email must not be listed twice with two patterns"
        );
        // the most-sighted pair wins the attribution (sighting-weight
        // ranking, not alphabetical): ("jane", "dupont") carries 3 raw
        // name sightings against 2 for ("j", "dupont"), so its built-in pattern
        // initiallast attributes the email
        assert_eq!(jdupont[0].pattern, "initiallast");
        assert_eq!(jdupont[0].domain, "acme.com");
    }

    #[test]
    fn planted_names_cannot_evict_the_real_variant_pair() {
        // P1 repro: one merged PR planting MAX_VARIANT_NAME_PAIRS + junk
        // names, each a single commit carrying the target's public noreply
        // id, truncated the real (jane, dupont) pair away when pairs were
        // ranked alphabetically — the target's own variant matches
        // disappeared from the report. Pairs are now ranked by raw sighting
        // weight, and the profile name is API-derived and unforgable: its
        // pair always survives the cap
        let mut investigation = Investigation::new(jane_profile());
        // the real observed email matches the real name pair's variant
        investigation.absorb_identity(
            "jane/one",
            Some("Jane Dupont"),
            Some("jane.dupont@acme.com"),
        );
        for i in 0..(MAX_VARIANT_NAME_PAIRS + 10) {
            investigation.absorb_identity(
                "jane/planted",
                Some(&format!("Aaa{i:03} Noise")),
                Some(&format!("42+spam{i:03}@users.noreply.github.com")),
            );
        }
        let report = investigation.finish(Vec::new(), Vec::new());
        assert!(
            report
                .variants
                .matched
                .iter()
                .any(|variant| variant.email == "jane.dupont@acme.com"),
            "the real pair must survive the planted names, matched: {:?}",
            report.variants.matched
        );
    }

    #[test]
    fn planted_domains_cannot_outweigh_a_raw_sighted_domain_by_name_count() {
        // P1 repro (weight inflation): the old weight counted DISTINCT names
        // + repos, so 65 junk domains with 5 planted names each (old weight
        // 7, from 325 commits in one PR) outweighed a real domain seen with
        // only 2 names (old weight 3) and evicted it from every variant.
        // Domains are now weighted by RAW commit sightings: the real
        // domain's 6 sightings beat each junk domain's 5, and beating it
        // costs the attacker one commit per sighting per junk domain
        let mut investigation = Investigation::new(jane_profile());
        for i in 0..6 {
            let name = if i % 2 == 0 {
                "Jane Dupont"
            } else {
                "J Dupont"
            };
            investigation.absorb_identity("jane/real", Some(name), Some("jane@acme.com"));
        }
        for d in 0..(MAX_VARIANT_DOMAINS + 1) {
            for n in 0..5 {
                investigation.absorb_identity(
                    "jane/planted",
                    Some(&format!("Noise{n}")),
                    Some(&format!("n{d}x{n}@d{d:03}.evil.example")),
                );
            }
        }
        let report = investigation.finish(Vec::new(), Vec::new());
        assert!(
            report
                .variants
                .generated
                .iter()
                .any(|variant| variant.ends_with("@acme.com"))
                || report
                    .variants
                    .matched
                    .iter()
                    .any(|variant| variant.domain == "acme.com"),
            "the raw-sighted real domain must survive the planted domains"
        );
    }

    #[test]
    fn the_variant_combinatorics_are_bounded_against_forgeable_commit_metadata() {
        // commit names and commit emails are forgeable and uncapped (one
        // merged PR can plant thousands of both): the uncapped engine grew
        // quadratically with the planted inputs (measured: 300 planted
        // names x 300 planted domains -> 361,200 variants, seconds of CPU
        // on a debug build). The engine must stay bounded: the caps limit
        // the expanded surface deterministically while the matching keeps
        // covering every capped combination
        let mut investigation = Investigation::new(jane_profile());
        for i in 0..300usize {
            investigation.absorb_identity(
                "jane/planted",
                Some(&format!("Spam{i:04} Name")),
                Some("42+jane@users.noreply.github.com"),
            );
            investigation.absorb_identity(
                "jane/planted",
                Some("Other"),
                Some(&format!("someone@d{i:04}.evil.example")),
            );
        }
        // the caps warn during finish, so the whole aggregation runs captured
        let (report, lines) =
            crate::test_logger::capture(|| investigation.finish(Vec::new(), Vec::new()));
        report.log_summary();
        // the generated list can never exceed its cap, whatever the planted
        // input volume (the uncapped engine produced 361,200 here)
        assert!(
            report.variants.generated.len() <= MAX_GENERATED_VARIANTS,
            "the generated-variant list must stay capped, got {}",
            report.variants.generated.len()
        );
        // both input caps bit, and the run says so instead of silently
        // truncating
        assert!(
            lines
                .iter()
                .any(|line| line.contains("top 64 email domains")),
            "the domain-cap warning must be logged, got: {lines:?}"
        );
        assert!(
            lines
                .iter()
                .any(|line| line.contains("top 64 name spellings")),
            "the name-pair-cap warning must be logged, got: {lines:?}"
        );
        assert!(
            lines
                .iter()
                .any(|line| line.contains("guessed addresses stops at 1000 entries")),
            "the generated-list cap warning must be logged, got: {lines:?}"
        );
    }

    #[test]
    fn the_variant_domains_are_ranked_by_sighting_weight_not_volume() {
        // a hostile merged PR can plant hundreds of one-commit domains to
        // crowd the engine's input: the cap keeps the most-sighted domains
        // (the target's real ones, seen across many commits and names) and
        // drops the planted one-sighting noise, alphabetically-last
        let mut investigation = Investigation::new(jane_profile());
        // the real domain: many sightings (names x repos weight)
        investigation.absorb_identity("jane/one", Some("Jane Dupont"), Some("jane@acme.com"));
        investigation.absorb_identity("jane/two", Some("J Dupont"), Some("jane@acme.com"));
        investigation.absorb_identity("jane/three", Some("Jane Dupont"), Some("jane@acme.com"));
        // planted noise: alphabetically-first one-sighting domains that must
        // not evict acme.com when the cap truncates
        for i in 0..(MAX_VARIANT_DOMAINS + 10) {
            investigation.absorb_identity(
                "jane/planted",
                Some("Noise"),
                Some(&format!("x@d{i:03}.evil.example")),
            );
        }
        let report = investigation.finish(Vec::new(), Vec::new());
        assert!(
            report
                .variants
                .generated
                .iter()
                .any(|variant| variant.ends_with("@acme.com")),
            "the most-sighted domain must survive the cap, got: {:?}",
            &report.variants.generated[..report.variants.generated.len().min(5)]
        );
    }

    #[test]
    fn finish_folds_unicode_names_for_the_variants() {
        let profile = parse_profile(&serde_json::json!({
            "login": "jdoe", "id": 42, "name": "Jérôme Dupont", "type": "User"
        }))
        .expect("the profile must parse");
        let mut investigation = Investigation::new(profile);
        investigation.absorb_commit(
            "jdoe/one",
            &people(
                ("Jérôme Dupont", "jerome.dupont@acme.com"),
                ("Jérôme Dupont", "42@users.noreply.github.com"),
            ),
        );
        let report = investigation.finish(Vec::new(), Vec::new());
        // the folded generated variant matches the observed ASCII email
        assert_eq!(report.variants.matched.len(), 1);
        assert_eq!(report.variants.matched[0].email, "jerome.dupont@acme.com");
        // the folded name feeds the names history too
        assert_eq!(report.names_history[0].name, "jerome dupont");
    }

    // ---- offline end-to-end: pagination, 404 and org detection ----

    #[test]
    fn history_aggregates_across_commit_pages_and_repositories() {
        use crate::github::mock::{request_line_page, serve_requests};

        // the mock walks: profile page, repos page, 3 commit pages of
        // jane/one (the username is spread over two pages), an empty commit
        // page ending that listing, 1 commit page of jane/two, an empty one,
        // an empty search page, an empty keys page
        let (address, server) = serve_requests(move |_index, request| {
            let path = request.first().map(String::as_str).unwrap_or("");
            let page = request_line_page(request);
            if path.contains("/users/jane ") || path.starts_with("GET /users/jane?") {
                return (
                    200,
                    vec![],
                    r#"{"login": "jane", "id": 42, "name": "Jane Dupont", "type": "User"}"#
                        .to_string(),
                );
            }
            if path.contains("/users/jane/repos") {
                let body = match page {
                    1 => r#"[{"full_name": "jane/one"}, {"full_name": "jane/two"}]"#,
                    _ => "[]",
                };
                return (200, vec![], body.to_string());
            }
            if path.contains("/repos/jane/one/commits") {
                let body = match page {
                    1 => {
                        r#"[{"commit": {"author": {"name": "Jane", "email": "42+oldname@users.noreply.github.com"}}}]"#
                    }
                    2 => {
                        r#"[{"commit": {"author": {"name": "Jane Dupont", "email": "42+oldname@users.noreply.github.com"}}}]"#
                    }
                    _ => "[]",
                };
                return (200, vec![], body.to_string());
            }
            if path.contains("/repos/jane/two/commits") {
                let body = match page {
                    1 => {
                        r#"[{"commit": {"author": {"name": "Jane Dupont", "email": "42@users.noreply.github.com"}, "committer": {"name": "Jane Dupont", "email": "jane@gmail.com"}}}]"#
                    }
                    _ => "[]",
                };
                return (200, vec![], body.to_string());
            }
            // search/commits and /keys listings: empty
            (200, vec![], "[]".to_string())
        });

        let client = crate::github::Client::anonymous().expect("client must build");
        // the investigation hits api.github.com: the URL building is tested
        // through the same parse + pagination path instead, by running the
        // listing stages against the mock base URL
        let profile_json = client
            .get_json(&format!("{address}/users/jane"))
            .expect("profile must be fetched");
        let profile = parse_profile(&profile_json).expect("profile must be fetched");
        assert_eq!(profile.id, 42);
        let mut investigation = Investigation::new(profile);

        let repositories: Vec<String> = fetch_paginated(
            &client,
            |page| format!("{address}/users/jane/repos?page={page}"),
            parse_repository_page,
            None,
        )
        .expect("the repos listing must succeed");
        assert_eq!(
            repositories,
            vec!["jane/one".to_string(), "jane/two".to_string()]
        );
        for full_name in &repositories {
            let (owner, repository) = full_name.split_once('/').expect("full_name must parse");
            let commits: Vec<CommitPeople> = fetch_paginated(
                &client,
                |page| format!("{address}/repos/{owner}/{repository}/commits?page={page}"),
                parse_people_page,
                None,
            )
            .expect("the commits listing must succeed");
            for commit in commits {
                investigation.absorb_commit(full_name, &commit);
            }
        }

        let report = investigation.finish(Vec::new(), Vec::new());
        // the same username seen on two pages of the same repository is
        // merged, and both repositories contribute
        let oldname = report
            .usernames_history
            .iter()
            .find(|sighting| sighting.username == "oldname")
            .expect("the noreply username must be revealed");
        assert_eq!(oldname.repos, vec!["jane/one".to_string()]);
        assert_eq!(
            oldname.names,
            vec!["jane".to_string(), "jane dupont".to_string()]
        );
        let jane = report
            .usernames_history
            .iter()
            .find(|sighting| sighting.username == "jane")
            .expect("the legacy form must attribute the current username");
        assert_eq!(jane.names, vec!["jane dupont".to_string()]);
        assert_eq!(report.emails.len(), 1);
        assert_eq!(report.emails[0].email, "jane@gmail.com");
        server.join();
    }

    #[test]
    fn the_search_listing_is_capped_at_github_s_1000_result_ceiling() {
        use crate::github::mock::serve_requests;
        // GitHub answers 422 past the first 1000 search results (page ×
        // per_page > 1000): the mock does the same, so a missing pagination
        // cap (requesting page 11) would abort the investigation loudly
        let (address, server) = serve_requests(move |_index, request| {
            let page = request
                .first()
                .and_then(|line| line.split("page=").last())
                .and_then(|rest| rest.split(' ').next())
                .and_then(|page| page.parse::<u16>().ok())
                .unwrap_or(0);
            let path = request.first().map(String::as_str).unwrap_or("");
            if path.contains("/users/jane ") || path.starts_with("GET /users/jane?") {
                return (
                    200,
                    vec![],
                    r#"{"login": "jane", "id": 42, "type": "User"}"#.to_string(),
                );
            }
            if path.contains("/users/jane/repos") {
                let body = if page == 1 {
                    r#"[{"full_name": "jane/one"}]"#
                } else {
                    "[]"
                };
                return (200, vec![], body.to_string());
            }
            if path.contains("/repos/jane/one/commits") {
                return (200, vec![], "[]".to_string());
            }
            if path.contains("/search/commits") {
                if page > 10 {
                    // the documented over-ceiling answer: must never be
                    // requested, the 1000-result cap stops the listing first
                    return (422, vec![], String::new());
                }
                let items: Vec<String> = (0..100)
                    .map(|i| {
                        // unique names across pages, so the report lists
                        // every one of the 1000 capped results
                        format!(
                            r#"{{"repository": {{"full_name": "acme/lib{page}-{i}", "html_url": "https://github.com/acme/lib{page}-{i}"}}}}"#
                        )
                    })
                    .collect();
                return (
                    200,
                    vec![],
                    format!(r#"{{"items": [{}]}}"#, items.join(",")),
                );
            }
            (200, vec![], "[]".to_string())
        });

        let client = crate::github::Client::anonymous().expect("client must build");
        let report = investigate_at_with_patterns(&client, &address, "jane", &[])
            .expect("the ceiling must cap the listing");
        // exactly the first 1000 search results, and page 11 never requested
        assert_eq!(report.external_contributions.len(), 1000);
        server.join();
    }

    #[test]
    fn the_user_commit_walk_is_capped_per_repository() {
        use crate::github::mock::serve_requests;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        // the same per-repository commit budget as every other repository
        // scan: the mock serves endless full commit pages, so an uncapped
        // walk would request page after page forever (the test would hang
        // instead of failing) — the commit-request counter makes the cut
        // loud, and the missing budget would also abort the investigation
        // before its SSH keys and external contributions
        let commit_requests = Arc::new(AtomicUsize::new(0));
        let (address, server) = {
            let commit_requests = Arc::clone(&commit_requests);
            serve_requests(move |_index, request| {
                let path = request.first().map(String::as_str).unwrap_or("");
                // the request line carries `per_page=100&page=N`: the last
                // `page=` segment is the page number (`request_line_page`
                // would grab the `per_page` value instead)
                let page = request
                    .first()
                    .and_then(|line| line.split("page=").last())
                    .and_then(|rest| rest.split(' ').next())
                    .and_then(|page| page.parse::<u16>().ok())
                    .unwrap_or(0);
                if path.contains("/users/jane ") || path.starts_with("GET /users/jane?") {
                    return (
                        200,
                        vec![],
                        r#"{"login": "jane", "id": 42, "type": "User"}"#.to_string(),
                    );
                }
                if path.contains("/users/jane/repos") {
                    let body = if page == 1 {
                        r#"[{"full_name": "jane/huge"}]"#
                    } else {
                        "[]"
                    };
                    return (200, vec![], body.to_string());
                }
                if path.contains("/repos/jane/huge/commits") {
                    commit_requests.fetch_add(1, Ordering::Relaxed);
                    // every page holds 100 commits sharing the target's
                    // noreply id, so the capped pages still feed the
                    // noreply technique
                    let items: Vec<String> = (0..100)
                        .map(|i| {
                            format!(
                                r#"{{"commit": {{"author": {{"name": "Dev {page}-{i}", "email": "42+dev@users.noreply.github.com"}}}}}}"#
                            )
                        })
                        .collect();
                    return (200, vec![], format!("[{}]", items.join(",")));
                }
                if path.contains("/search/commits") {
                    return (200, vec![], r#"{"items": []}"#.to_string());
                }
                // /keys listing: empty
                (200, vec![], "[]".to_string())
            })
        };

        let client = crate::github::Client::anonymous().expect("client must build");
        let (report, lines) = crate::test_logger::capture(|| {
            investigate_at_with_patterns(&client, &address, "jane", &[])
        });
        let report = report.expect("the capped commit walk must still investigate");
        server.join();

        // exactly the MAX_COMMIT_PAGES full pages: no page 11, no empty page
        // to wait for
        assert_eq!(
            commit_requests.load(Ordering::Relaxed),
            crate::sources::MAX_COMMIT_PAGES
        );
        // the capped commits still feed the noreply technique
        assert!(
            report
                .usernames_history
                .iter()
                .any(|sighting| sighting.username == "dev"),
            "the capped pages must still feed the usernames history: {:?}",
            report.usernames_history
        );
        // the budget cut is warned about instead of the report silently
        // pretending the repository history is complete
        assert!(
            lines
                .iter()
                .any(|line| line.contains("only the most recent 1000 commits")),
            "the capped walk must warn about the incomplete history: {lines:?}"
        );
    }

    #[test]
    fn a_422_past_the_search_ceiling_does_not_abort_the_investigation() {
        use crate::github::mock::serve_requests;
        // defensive fallback: even if the over-ceiling page is somehow
        // requested, the documented 422 ends the search listing (with a
        // warning) instead of aborting a complete investigation — the
        // contributions collected before the cut are kept. A page-1 422
        // (a query the API rejected outright) is a different failure: it
        // must propagate instead of yielding a complete-looking report
        // without its external-contributions section
        let (address, server) = serve_requests(move |_index, request| {
            let path = request.first().map(String::as_str).unwrap_or("");
            if path.contains("/users/jane ") || path.starts_with("GET /users/jane?") {
                return (
                    200,
                    vec![],
                    r#"{"login": "jane", "id": 42, "type": "User"}"#.to_string(),
                );
            }
            if path.contains("/users/jane/repos") {
                return (200, vec![], "[]".to_string());
            }
            if path.contains("/search/commits") {
                let page = request
                    .first()
                    .and_then(|line| line.split("page=").last())
                    .and_then(|rest| rest.split(' ').next())
                    .and_then(|page| page.parse::<u16>().ok())
                    .unwrap_or(0);
                return if page == 1 {
                    let items: Vec<String> = (0..100)
                        .map(|i| format!(r#"{{"repository": {{"full_name": "acme/lib{i}"}}}}"#))
                        .collect();
                    (
                        200,
                        vec![],
                        format!(r#"{{"items": [{}]}}"#, items.join(",")),
                    )
                } else {
                    // the documented over-ceiling answer
                    (422, vec![], String::new())
                };
            }
            (200, vec![], "[]".to_string())
        });

        let client = crate::github::Client::anonymous().expect("client must build");
        let report = investigate_at_with_patterns(&client, &address, "jane", &[])
            .expect("a 422 must not abort the report");
        // the investigation completes; the hits collected before the cut
        // cannot be recovered from the paginated loop, so the section ends
        // up empty — the point of the page-1 content is that this is a
        // window 422 (contributions were being listed), not a page-1
        // rejection, which fails the investigation instead
        assert!(report.external_contributions.is_empty());
        server.join();
    }

    #[test]
    fn a_page1_422_on_the_external_search_fails_the_investigation() {
        use crate::github::mock::serve_requests;
        // a 422 on the very first page can never be a ceiling 422 (nothing
        // collected yet): the API rejected the search itself, and it must
        // fail explicitly instead of yielding a complete-looking report
        // whose external-contributions section silently went missing
        let (address, server) = serve_requests(move |_index, request| {
            let path = request.first().map(String::as_str).unwrap_or("");
            if path.contains("/users/jane ") || path.starts_with("GET /users/jane?") {
                return (
                    200,
                    vec![],
                    r#"{"login": "jane", "id": 42, "type": "User"}"#.to_string(),
                );
            }
            if path.contains("/users/jane/repos") {
                return (200, vec![], "[]".to_string());
            }
            if path.contains("/search/commits") {
                return (422, vec![], String::new());
            }
            (200, vec![], "[]".to_string())
        });

        let client = crate::github::Client::anonymous().expect("client must build");
        let error = investigate_at_with_patterns(&client, &address, "jane", &[])
            .expect_err("a page-1 422 must fail the investigation");
        assert!(
            matches!(error, Error::Http(ref err) if err.status() == Some(StatusCode::UNPROCESSABLE_ENTITY)),
            "unexpected error: {error:?}"
        );
        server.join();
    }

    #[test]
    fn a_short_final_external_page_ends_the_listing_and_keeps_the_contributions() {
        use crate::github::mock::serve_requests;
        // 150 contributions across two pages: page 2 holds fewer items than
        // the page size, so it is the last page of the listing. Requesting
        // the page after it (which the old parsed-item limit did whenever
        // the total was not a multiple of the page size) would answer the
        // mock's documented out-of-window 422 and silently discard every
        // contribution found so far; the short-page rule ends the listing
        // and the 150 hits are kept
        let (address, server) = serve_requests(move |_index, request| {
            let path = request.first().map(String::as_str).unwrap_or("");
            let page = request
                .first()
                .and_then(|line| line.split("page=").last())
                .and_then(|rest| rest.split(' ').next())
                .and_then(|page| page.parse::<u16>().ok())
                .unwrap_or(0);
            if path.contains("/users/jane ") || path.starts_with("GET /users/jane?") {
                return (
                    200,
                    vec![],
                    r#"{"login": "jane", "id": 42, "type": "User"}"#.to_string(),
                );
            }
            if path.contains("/users/jane/repos") || path.contains("/repos/jane/one/commits") {
                return (200, vec![], "[]".to_string());
            }
            if path.contains("/search/commits") {
                let count = match page {
                    1 => 100,
                    2 => 50,
                    // the documented over-ceiling answer: must never be
                    // requested, the short page 2 ends the listing first
                    _ => return (422, vec![], String::new()),
                };
                let items: Vec<String> = (0..count)
                    .map(|i| {
                        format!(
                            r#"{{"repository": {{"full_name": "acme/lib{page}-{i}", "html_url": "https://github.com/acme/lib{page}-{i}"}}}}"#
                        )
                    })
                    .collect();
                return (
                    200,
                    vec![],
                    format!(r#"{{"items": [{}]}}"#, items.join(",")),
                );
            }
            (200, vec![], "[]".to_string())
        });

        let client = crate::github::Client::anonymous().expect("client must build");
        let report = investigate_at_with_patterns(&client, &address, "jane", &[])
            .expect("a short final page must keep the contributions");
        // every contribution of both pages survived the listing
        assert_eq!(report.external_contributions.len(), 150);
        // exactly the two content pages were requested (plus the profile,
        // the empty repos listing and the keys listing that end at once)
        assert_eq!(server.join(), 5);
    }

    #[test]
    fn a_404_profile_surfaces_as_not_found() {
        use crate::github::mock::serve_requests;
        let (address, server) =
            serve_requests(move |_index, _request| (404, vec![], String::new()));

        let client = crate::github::Client::anonymous().expect("client must build");
        let error = client
            .get_json(&format!("{address}/users/ghost"))
            .expect_err("a missing profile must fail");
        assert!(matches!(error, Error::NotFound));
        server.join();
    }

    #[test]
    fn a_429_mid_repo_scan_aborts_the_investigation() {
        use crate::github::mock::serve_requests;
        // the token is parked by a secondary rate limit exactly when the
        // commits of the target's first repository are fetched: every
        // commit fetch during the park window fails, so the per-repository
        // skip must NOT swallow it — a complete-looking report silently
        // missing the whole history would be far worse than a failure
        let (address, server) = serve_requests(move |_index, request| {
            // unlike `request_line_page`, take the LAST `page=` occurrence:
            // the investigation URLs carry `per_page=`, which the naive
            // first-match parse would read as the page number
            let page = request
                .first()
                .and_then(|line| line.split("page=").last())
                .and_then(|rest| rest.split(' ').next())
                .and_then(|page| page.parse::<u16>().ok())
                .unwrap_or(0);
            let path = request.first().map(String::as_str).unwrap_or("");
            if path.contains("/users/jane ") {
                return (
                    200,
                    vec![],
                    r#"{"login": "jane", "id": 42, "type": "User"}"#.to_string(),
                );
            }
            if path.contains("/users/jane/repos") {
                let body = if page == 1 {
                    r#"[{"full_name": "jane/one"}]"#
                } else {
                    "[]"
                };
                return (200, vec![], body.to_string());
            }
            if path.contains("/repos/jane/one/commits") {
                return (
                    429,
                    vec![("Retry-After".to_string(), "60".to_string())],
                    String::new(),
                );
            }
            (200, vec![], "[]".to_string())
        });

        let client = crate::github::Client::anonymous().expect("client must build");
        let error = investigate_at_with_patterns(&client, &address, "jane", &[])
            .expect_err("a rate limit mid-scan must abort the investigation");
        assert!(matches!(error, Error::RateLimitExhausted));
        server.join();
    }

    #[test]
    fn a_private_repository_is_skipped_but_a_transport_error_is_not() {
        use crate::github::mock::serve_requests;
        // jane/two answers a plain 403 (private repository): a
        // resource-scoped failure is skipped with a warning and the rest of
        // the investigation (here, the external contributions) still runs
        let (address, server) = serve_requests(move |_index, request| {
            // the LAST `page=` occurrence: the URLs carry `per_page=` too
            let page = request
                .first()
                .and_then(|line| line.split("page=").last())
                .and_then(|rest| rest.split(' ').next())
                .and_then(|page| page.parse::<u16>().ok())
                .unwrap_or(0);
            let path = request.first().map(String::as_str).unwrap_or("");
            if path.contains("/users/jane ") {
                return (
                    200,
                    vec![],
                    r#"{"login": "jane", "id": 42, "type": "User"}"#.to_string(),
                );
            }
            if path.contains("/users/jane/repos") {
                let body = if page == 1 {
                    r#"[{"full_name": "jane/two"}]"#
                } else {
                    "[]"
                };
                return (200, vec![], body.to_string());
            }
            if path.contains("/repos/jane/two/commits") {
                return (403, vec![], String::new());
            }
            // search/commits: one hit page then the empty end of listing
            if path.contains("/search/commits") {
                let body = if page == 1 {
                    r#"{"items": [{"repository": {"full_name": "acme/lib", "html_url": "https://github.com/acme/lib"}}]}"#
                } else {
                    "{\"items\": null}"
                };
                return (200, vec![], body.to_string());
            }
            (200, vec![], "[]".to_string())
        });

        let client = crate::github::Client::anonymous().expect("client must build");
        let report = investigate_at_with_patterns(&client, &address, "jane", &[])
            .expect("a private repo must not abort");
        assert!(report.emails.is_empty());
        assert_eq!(report.external_contributions.len(), 1);
        assert_eq!(report.external_contributions[0].repository, "acme/lib");
        server.join();
    }

    #[test]
    fn an_empty_repository_is_skipped_but_the_walk_continues() {
        use crate::github::mock::serve_requests;
        // jane/empty answers the documented 409 Conflict on its commits
        // listing (repository with no commits): a resource-scoped failure
        // is skipped with a warning and the per-repository walk continues
        // with the next repository, whose commits still feed the report
        let (address, server) = serve_requests(move |_index, request| {
            // the LAST `page=` occurrence: the URLs carry `per_page=` too
            let page = request
                .first()
                .and_then(|line| line.split("page=").last())
                .and_then(|rest| rest.split(' ').next())
                .and_then(|page| page.parse::<u16>().ok())
                .unwrap_or(0);
            let path = request.first().map(String::as_str).unwrap_or("");
            if path.contains("/users/jane ") {
                return (
                    200,
                    vec![],
                    r#"{"login": "jane", "id": 42, "type": "User"}"#.to_string(),
                );
            }
            if path.contains("/users/jane/repos") {
                let body = if page == 1 {
                    r#"[{"full_name": "jane/empty"}, {"full_name": "jane/real"}]"#
                } else {
                    "[]"
                };
                return (200, vec![], body.to_string());
            }
            if path.contains("/repos/jane/empty/commits") {
                // GitHub's exact 409 body for a repository without commits
                return (
                    409,
                    vec![],
                    r#"{"message": "Git Repository is empty.", "documentation_url": "https://docs.github.com/rest/commits/commits#list-commits"}"#.to_string(),
                );
            }
            if path.contains("/repos/jane/real/commits") {
                let body = if page == 1 {
                    r#"[{"commit": {"author": {"name": "Jane Dupont", "email": "jane@acme.com"}}}]"#
                } else {
                    "[]"
                };
                return (200, vec![], body.to_string());
            }
            if path.contains("/search/commits") {
                // search/commits listing: empty (the shape the API answers
                // for a search with no hit — an `items` array, even empty,
                // unlike the bare-array plain listings)
                return (200, vec![], r#"{"items": []}"#.to_string());
            }
            // /keys listing: empty
            (200, vec![], "[]".to_string())
        });

        let client = crate::github::Client::anonymous().expect("client must build");
        let report = investigate_at_with_patterns(&client, &address, "jane", &[])
            .expect("an empty repo must not abort");
        // the walk continued past the 409: the next repository's email is
        // in the report, and the skipped one contributed nothing
        assert_eq!(report.emails.len(), 1);
        assert_eq!(report.emails[0].email, "jane@acme.com");
        assert_eq!(report.emails[0].repos, vec!["jane/real".to_string()]);
        server.join();
    }

    #[test]
    fn the_listing_skip_warning_sanitizes_the_untrusted_repository_name() {
        use crate::github::mock::serve_requests;
        // the per-repository skip warning prints the API-derived full name:
        // a dropped `log_safe()` call must fail the suite (capturing logger,
        // same wiring-level pin as the terminal report)
        let (address, server) = serve_requests(move |_index, request| {
            let path = request.first().map(String::as_str).unwrap_or("");
            if path.contains("/users/jane ") {
                return (
                    200,
                    vec![],
                    r#"{"login": "jane", "id": 42, "type": "User"}"#.to_string(),
                );
            }
            if path.contains("/users/jane/repos") {
                // a hostile full name without a `/` hits the unparsable-name
                // skip warning, carrying an ESC opener to be neutered
                let body = if path.contains("page=1 ") {
                    r#"[{"full_name": "jane/real"}, {"full_name": "hostile\u001b[31mname"}]"#
                } else {
                    "[]"
                };
                return (200, vec![], body.to_string());
            }
            if path.contains("/repos/jane/real/commits") {
                let body = if path.contains("page=1 ") {
                    r#"[{"commit": {"author": {"name": "Jane", "email": "jane@acme.com"}}}]"#
                } else {
                    "[]"
                };
                return (200, vec![], body.to_string());
            }
            if path.contains("/search/commits") {
                return (200, vec![], r#"{"items": []}"#.to_string());
            }
            (200, vec![], "[]".to_string())
        });

        let client = crate::github::Client::anonymous().expect("client must build");
        let (report, lines) = crate::test_logger::capture(|| {
            investigate_at_with_patterns(&client, &address, "jane", &[])
        });
        let report = report.expect("the hostile name must be skipped, not fatal");
        server.join();

        assert_eq!(report.emails.len(), 1);
        assert!(
            !lines.iter().any(|line| line.contains('\x1b')),
            "a hostile listing name must not carry an ESC sequence into the log: {lines:?}"
        );
        assert!(
            lines
                .iter()
                .any(|line| line.contains("skipping repository") && line.contains("_[31mname")),
            "the sanitized skip warning must be printed: {lines:?}"
        );
    }

    #[test]
    fn ssh_keys_are_paginated() {
        use crate::github::mock::{request_line_page, serve_requests};
        let (address, server) = serve_requests(move |_index, request| {
            if !request.first().unwrap_or(&String::new()).contains("/keys") {
                return (200, vec![], "[]".to_string());
            }
            match request_line_page(request) {
                1 => (
                    200,
                    vec![],
                    r#"[{"id": 1, "key": "ssh-ed25519 AAAA", "title": "laptop"}]"#.to_string(),
                ),
                2 => (
                    200,
                    vec![],
                    r#"[{"id": 2, "key": "ssh-rsa BBBB", "title": "desktop"}]"#.to_string(),
                ),
                _ => (200, vec![], "[]".to_string()),
            }
        });

        let client = crate::github::Client::anonymous().expect("client must build");
        let keys: Vec<SshKey> = fetch_paginated(
            &client,
            |page| format!("{address}/users/jane/keys?page={page}"),
            parse_keys_page,
            None,
        )
        .expect("the keys listing must succeed");
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].title.as_deref(), Some("laptop"));
        assert_eq!(keys[1].title.as_deref(), Some("desktop"));
        server.join();
    }

    #[test]
    fn the_terminal_report_sanitizes_the_untrusted_strings_it_prints() {
        // the CHANGELOG 0.7.0 claim is pinned at the wiring level, not only
        // at the sanitizer helper: a dropped `log_safe()` call must fail
        // this test (capturing logger, see `crate::test_logger`)
        let profile = parse_profile(&serde_json::json!({
            "login": "jane", "id": 42,
            "name": "Jane\u{1b}[31mDupont\n",
            "type": "User"
        }))
        .expect("the profile must parse");
        let report = Investigation::new(profile).finish(Vec::new(), Vec::new());
        let (_, lines) = crate::test_logger::capture(|| report.log_summary());
        assert!(
            !lines
                .iter()
                .any(|line| line.contains('\x1b') || line.contains('\n')),
            "a hostile profile field must not forge or recolor a log line: {lines:?}"
        );
        assert!(
            lines.iter().any(|line| line.contains("_[31mDupont_")),
            "the sanitized name must be printed: {lines:?}"
        );
    }

    #[test]
    fn the_report_serializes_the_documented_json_shape() {
        let profile = jane_profile();
        let report = Investigation::new(profile).finish(Vec::new(), Vec::new());
        let value = serde_json::to_value(&report).expect("report must serialize");
        let mut keys: Vec<&str> = value
            .as_object()
            .expect("report object")
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec![
                "emails",
                "external_contributions",
                "local_identities",
                "names_history",
                "profile",
                "secondary_accounts",
                "ssh_keys",
                "usernames_history",
                "variants",
            ]
        );
        let mut variant_keys: Vec<&str> = value["variants"]
            .as_object()
            .expect("variants object")
            .keys()
            .map(String::as_str)
            .collect();
        variant_keys.sort_unstable();
        assert_eq!(variant_keys, vec!["generated", "matched"]);
        let mut profile_keys: Vec<&str> = value["profile"]
            .as_object()
            .expect("profile object")
            .keys()
            .map(String::as_str)
            .collect();
        profile_keys.sort_unstable();
        assert_eq!(
            profile_keys,
            vec![
                "bio",
                "blog",
                "company",
                "created_at",
                "email",
                "id",
                "location",
                "login",
                "name",
                "public_repos",
                "twitter_username",
                "type",
            ]
        );
    }

    /// The foreign-noreply pending lookup must stay near-linear: every
    /// commit of the target's own repositories carries attacker-forgeable
    /// identity metadata, and the own-repositories commit walk is uncapped,
    /// so a hostile commit stream with a distinct foreign noreply id per
    /// commit (trivial to push once) must not pay a linear scan of the
    /// pending-pair list per commit — the pre-fix `Vec::position` scan even
    /// lowercased both username sides on every comparison (measured: the
    /// isolated cost grew ~3.5x per doubling of commits, ~65 s of CPU at
    /// 100k commits). The generous ceiling keeps the assertion stable on a
    /// loaded runner while failing the quadratic version by orders of
    /// magnitude.
    #[test]
    fn absorb_commit_stays_near_linear_on_distinct_foreign_noreply_ids() {
        const COMMITS: usize = 40_000;
        let began = std::time::Instant::now();
        let mut investigation = Investigation::new(jane_profile());
        for n in 0..COMMITS {
            // ids start above the profile id (42): a commit whose noreply id
            // equals the target's id feeds the target's own history, not the
            // pending foreign pairs under test
            let id = 1000 + n;
            investigation.absorb_commit(
                "jane/big",
                &CommitPeople {
                    // the profile's exact name: every distinct foreign pair
                    // is judged as a `noreply-name` secondary account, so
                    // the report count pins the dedup below
                    author_name: Some("Jane Dupont".to_string()),
                    author_email: Some(format!("{id}+user{n}@users.noreply.github.com")),
                    committer_name: Some("Jane Dupont".to_string()),
                    committer_email: Some(format!("{id}+user{n}@users.noreply.github.com")),
                },
            );
        }
        let report = investigation.finish(Vec::new(), Vec::new());
        let elapsed = began.elapsed();
        // correctness invariants unchanged by the lookup structure: every
        // distinct foreign (id, username) pair is one pending candidate,
        // judged against the target's names in the report
        assert_eq!(report.secondary_accounts.len(), COMMITS);
        assert!(
            elapsed.as_secs() < 10,
            "foreign-noreply absorption became super-linear: {COMMITS} commits took {elapsed:?}"
        );
    }

    /// The variant-engine pair ranking must stay near-linear too: the
    /// commit names feeding the ranking are attacker-forgeable and
    /// uncapped (the per-repository walk cap bounds one repository, but
    /// the target owns many), and the ranking ran BEFORE the
    /// `MAX_VARIANT_NAME_PAIRS` truncation — the pre-fix ranking
    /// re-scanned and re-folded every known name for every distinct pair
    /// (quadratic: ~10^5 planted names ≈ 10^10 `fold_name` calls, tens of
    /// minutes of analyst CPU after ~500 API requests). The generous
    /// ceiling keeps the assertion stable on a loaded runner while
    /// failing the quadratic version by orders of magnitude.
    #[test]
    fn finish_pair_ranking_stays_near_linear_on_planted_names() {
        const NAMES: usize = 40_000;
        let began = std::time::Instant::now();
        let mut investigation = Investigation::new(jane_profile());
        for i in 0..NAMES {
            investigation.absorb_identity(
                "jane/planted",
                Some(&format!("Spam{i:05} Noise")),
                Some(&format!("42+spam{i:05}@users.noreply.github.com")),
            );
        }
        let report = investigation.finish(Vec::new(), Vec::new());
        let elapsed = began.elapsed();
        // correctness invariants unchanged by the ranking structure: every
        // planted name is one names-history entry (the profile name is not
        // a commit sighting, and the noreply addresses never reach the
        // documented noreply-free emails list)
        assert_eq!(report.names_history.len(), NAMES);
        assert!(report.emails.is_empty());
        assert!(
            elapsed.as_secs() < 10,
            "variant pair ranking became super-linear: {NAMES} planted names took {elapsed:?}"
        );
    }
}
