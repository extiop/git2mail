//! The `user` investigation's API payload parsers: one function per
//! listing (profile, repositories, commit people, external contributions,
//! SSH keys), each explicit about the shapes it accepts and the malformed
//! entries it skips. Every payload is untrusted API data: the parsers
//! bound the field sizes and the caller sanitizes what it logs.

use super::report::{Profile, SshKey};
use crate::errors::Error;
use serde_json::Value;

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

/// The shared listing guard: a 200 body that is not a JSON array is an
/// intermediary or a shape change, not an empty page, and must fail
/// explicitly (the error text names the payload, per call site).
///
/// # Errors
///
/// Returns [`Error::InvalidProfile`] with `message` when the body is not a
/// JSON array.
pub(crate) fn require_array<'a>(json: &'a Value, message: &str) -> Result<&'a [Value], Error> {
    match json.as_array() {
        Some(items) => Ok(items.as_slice()),
        None => Err(Error::InvalidProfile(message.to_string())),
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
/// the payload.
pub(crate) fn parse_profile(json: &Value) -> Result<Profile, Error> {
    let string_field = |name: &str| {
        json.get(name)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
    };
    let login = string_field("login")
        .ok_or_else(|| Error::InvalidProfile("missing `login`".to_string()))?;
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
pub(crate) fn parse_user_repos_page(
    json: &Value,
    include_forks: bool,
) -> Result<(Vec<String>, usize), Error> {
    let items = require_array(json, "repositories payload: not an array")?;
    // the listing contract is completeness: an entry without its `full_name`
    // is skipped, but counted and warned about (the count stays the
    // end-of-listing signal of `fetch_paginated`) instead of silently
    // shrinking the investigated set — the same explicit rule the org and
    // search listings apply to malformed entries. A forked repository is
    // skipped too unless the caller opted in (`--include-forks`, the same
    // opt-in as the org investigation): its default branch mirrors the
    // upstream history the REST commits API exposes, so scanning it burns
    // the commit budget on data that is not the target's and its upstream
    // authors would pollute the co-author heuristics with false secondary
    // accounts — the same public-listing rule the search and org walks apply
    let mut repositories = Vec::new();
    let mut malformed = 0usize;
    let mut forks = 0usize;
    for item in items {
        if !include_forks && item.get("fork").and_then(Value::as_bool) == Some(true) {
            forks += 1;
            continue;
        }
        match item.get("full_name").and_then(Value::as_str) {
            Some(name) => repositories.push(name.to_string()),
            None => malformed += 1,
        }
    }
    if malformed > 0 {
        let plural = if malformed > 1 { "entries" } else { "entry" };
        log::warn!("{malformed} malformed {plural} skipped in the repositories listing");
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
pub(crate) fn parse_people_page(json: &Value) -> Result<(Vec<CommitPeople>, usize), Error> {
    let mut people: Vec<CommitPeople> = Vec::new();
    let mut malformed = 0usize;
    let items = require_array(json, "commits payload: not an array")?;
    for item in items {
        let Some(commit) = item.get("commit") else {
            // an entry without its commit object carries no identity at
            // all: skipped with a warning, never silently (the same
            // warn-and-count rule the org and search listings apply)
            malformed += 1;
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
    if malformed > 0 {
        log::warn!("{malformed} malformed entries skipped in the commits listing");
    }
    Ok((people, items.len()))
}

/// One external-contribution search hit: the repository holding a commit
/// authored by the target.
#[derive(Debug)]
pub(crate) struct ExternalHit {
    pub(crate) repository: String,
    pub(crate) url: Option<String>,
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
/// or an `items` field that is neither an array nor `null`.
pub(crate) fn parse_external_page(json: &Value) -> Result<(Vec<ExternalHit>, usize), Error> {
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
    let mut hits = Vec::new();
    let mut malformed = 0usize;
    for item in items {
        let Some(repository) = item.get("repository").and_then(Value::as_object) else {
            malformed += 1;
            continue;
        };
        let Some(full_name) = repository.get("full_name").and_then(Value::as_str) else {
            malformed += 1;
            continue;
        };
        hits.push(ExternalHit {
            repository: full_name.to_string(),
            url: repository
                .get("html_url")
                .and_then(Value::as_str)
                .map(str::to_string),
        });
    }
    if malformed > 0 {
        let plural = if malformed > 1 { "entries" } else { "entry" };
        log::warn!("{malformed} malformed {plural} skipped in the external contributions listing");
    }
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
pub(crate) fn parse_keys_page(json: &Value) -> Result<(Vec<SshKey>, usize), Error> {
    let items = require_array(json, "keys payload: not an array")?;
    // the public endpoint documents exactly {id, key}: the title and
    // creation date exist only on the authenticated `/user/keys` listing,
    // so nothing here may claim them. An entry missing `id` or `key` is
    // skipped with a warning like every other listing's malformed entries,
    // never silently
    let mut keys = Vec::new();
    let mut malformed = 0usize;
    for item in items {
        let Some((id, key)) = item
            .get("id")
            .and_then(Value::as_u64)
            .zip(item.get("key").and_then(Value::as_str))
        else {
            malformed += 1;
            continue;
        };
        keys.push(SshKey {
            id,
            key: key.to_string(),
        });
    }
    if malformed > 0 {
        let plural = if malformed > 1 { "entries" } else { "entry" };
        log::warn!("{malformed} malformed {plural} skipped in the SSH keys listing");
    }
    Ok((keys, items.len()))
}
