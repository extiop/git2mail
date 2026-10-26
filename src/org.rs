//! Organization investigation: the public
//! members, the public repositories and the developers' emails found in
//! their commits - 100% API (no clone, no scraping, no new dependency).
//!
//! `git2mail org <org>` reuses the same building blocks as the rest of
//! the crate:
//!
//! - the organization itself (`GET /orgs/{org}`; a 404 is a clean
//!   [`crate::errors::Error::NotFound`]);
//! - the **public members** (`GET /orgs/{org}/public_members`, paginated);
//! - the **public repositories** (`GET /orgs/{org}/repos`, paginated,
//!   capped by the optional `--limit`);
//! - the **emails** found scanning those repositories' commits with the
//!   same worker-per-token parallelism as the parallel `search`
//!   (`src/sources`, token-worker pool), reported per repository and
//!   globally.
//!
//! The investigation never panics: every fallible operation returns
//! [`crate::errors::Error`]. A repository that cannot be scanned on its own
//! (a private or deleted repository, a stale listing entry, an empty one -
//! GitHub answers 409 on its commits listing) is skipped with
//! a warning instead of aborting the report, like the parallel search
//! does; a rate-limit or transport failure is a scan-wide condition and
//! aborts the investigation, so a token parked by a secondary rate limit
//! can never yield a complete-looking report silently missing whole
//! repositories. Like the `user` investigation (and unlike the
//! search-bounded reverse-email heuristic), the listings (the
//! organization's members and repositories) walk every page; each listed
//! repository's commit walk covers the full default-branch history with no
//! local budget, like every other repository scan.

use crate::consts::GITHUB_API_BASE;
use crate::errors::Error;
use crate::github::fetch_paginated;
use crate::parsers::is_safe_repository_name;
use crate::sanitize::log_safe;
use crate::sources::{PER_PAGE, RepoHit, Scanner, sort_emails};
use crate::user::validate_username;
use log::info;
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;

/// The `org` object of the investigation report: the fields of
/// `GET /orgs/{org}` that carry OSINT value. Absent fields are `null`.
#[derive(Debug, Clone, Serialize)]
pub struct OrgInfo {
    /// The organization login (unique, case-insensitive).
    pub login: String,
    /// The display name set by the organization ("Acme Corp").
    pub name: Option<String>,
    /// The blog URL field.
    pub blog: Option<String>,
}

/// The `emails` object of the investigation report: the emails found
/// scanning the organization's repositories, per repository and globally.
#[derive(Debug, Clone, Serialize)]
pub struct OrgEmails {
    /// Emails found per repository, keyed by the `owner/name` full name the
    /// scan infrastructure reports (the scan workers parse the repository
    /// URL, so the key always carries the owner even for a forked
    /// repository). Only the repositories where at least one email showed
    /// up are listed. Repositories and emails are sorted deterministically.
    pub per_repository: BTreeMap<String, Vec<String>>,
    /// Every email found, deduplicated and sorted (the legacy order:
    /// case-insensitive alphabetical).
    pub all: Vec<String>,
}

/// The `scanned` object of the investigation report: how much the scan
/// actually covered.
#[derive(Debug, Clone, Serialize)]
pub struct OrgScanned {
    /// Number of repositories whose commits were actually scanned
    /// (skipped or never-scanned repositories are not counted).
    pub repos: usize,
    /// Number of successful GitHub API requests made by the whole
    /// investigation (org info, members, repositories listing and the
    /// workers' commit pages), i.e. roughly how many pages were fetched.
    pub pages: usize,
}

/// The full organization investigation report: the terminal summary
/// sections and the `--json` shape, documented in the user guide (ORG.md
/// page).
#[derive(Debug, Clone, Serialize)]
pub struct OrgReport {
    /// The when/what of the report (generation timestamp, tool version).
    #[serde(flatten)]
    pub provenance: crate::output::Provenance,
    /// The investigated organization.
    pub org: OrgInfo,
    /// The public member logins (`GET /orgs/{org}/public_members`).
    pub members: Vec<String>,
    /// The public repository names (`GET /orgs/{org}/repos`).
    pub repositories: Vec<String>,
    /// The emails found scanning the repositories, per repository and
    /// globally.
    pub emails: OrgEmails,
    /// The scan coverage (repositories actually scanned, pages fetched).
    pub scanned: OrgScanned,
    /// The per-author correlation built from the scanned commits (author,
    /// emails, repositories, commit counts): the remediation view an org
    /// auditor needs to attribute an exposure to a person.
    pub correlation: crate::correlate::Correlation,
}

/// Runs the full investigation of one GitHub organization: fetches the org
/// info, lists the public members and the public repositories, scans the
/// repositories' commits in parallel over the token pool, then builds the
/// report and logs the terminal summary.
///
/// # Errors
///
/// Returns [`Error::InvalidUsername`] when `org` is not a valid GitHub
/// login (rejected client-side, before any network request - GitHub
/// organizations follow the same login shape as users),
/// [`Error::NotFound`] for a missing organization,
/// [`Error::PrivateOrUnavailable`] or [`Error::RateLimitExhausted`] /
/// [`Error::Http`] for the corresponding API failures. The skip-vs-abort
/// contract is the module-level one. The kept partial result of a
/// parallel scan whose dedicated token died mid-scan aborts with the
/// token's real death error (a revoked token is not a spent allowance).
/// `limit` (the optional `--limit`) caps the number of listed
/// repositories.
pub fn investigate(
    scanner: &Scanner,
    org: &str,
    limit: Option<usize>,
    include_forks: bool,
) -> Result<OrgReport, Error> {
    investigate_at(scanner, GITHUB_API_BASE, org, limit, include_forks)
}

/// The investigation itself, driven against one API base URL:
/// [`investigate`] is the production entry point (`https://api.github.com`),
/// and the offline tests run this same code against a loopback mock. It
/// filters the raw listing (see [`is_safe_repository_name`]), composes the
/// scan hits with the API's canonical login and scans them through
/// [`scan_org_repositories`].
///
/// # Errors
///
/// The same failures as [`investigate`].
///
/// Filters the raw listing (untrusted API data: an entry whose name is
/// empty, a dot segment or carries a path separator or query/fragment
/// would corrupt the composed scan URL, see [`is_safe_repository_name`],
/// and desynchronize the per-repository report keys from what was
/// scanned), then scans the safe repositories with the parallel search's
/// token-worker pool: every repository becomes a GitHub URL hit the
/// workers parse and scan, exactly like a search result.
fn scan_org_repositories(
    scanner: &Scanner,
    base: &str,
    repositories: &[String],
    canonical_login: &str,
) -> crate::sources::ParallelScan {
    let safe_repositories: Vec<&String> = repositories
        .iter()
        .filter(|repository| {
            if is_safe_repository_name(repository) {
                true
            } else {
                log::warn!(
                    "skipping a malformed org listing entry: {}",
                    log_safe(repository)
                );
                false
            }
        })
        .collect();
    let hits: Vec<RepoHit> = safe_repositories
        .iter()
        .map(|repository| RepoHit {
            url: format!("https://github.com/{}/{repository}", canonical_login),
            language: None,
        })
        .collect();
    scanner.scan_repositories_at(base, &hits, false)
}

fn investigate_at(
    scanner: &Scanner,
    base: &str,
    org: &str,
    limit: Option<usize>,
    include_forks: bool,
) -> Result<OrgReport, Error> {
    let client = scanner.client();
    validate_username(org)?;

    // 404 maps to Error::NotFound inside the client: a missing organization
    // is the clean failure the CLI reports
    let org_json = client.get_json(&format!("{base}/orgs/{org}"))?;
    let info = parse_org(&org_json)?;
    // the API-derived login is re-checked against the username shape before
    // it is composed into the per-repository scan hits: a hostile or
    // shape-changed body carrying a slash-bearing or otherwise invalid login
    // ("other-org/sub") must fail the investigation explicitly instead of
    // silently re-scanning a different owner's repositories and keying the
    // results under the requested org's report
    validate_username(&info.login).map_err(|_| {
        Error::InvalidProfile(format!(
            "organization payload: the login does not follow GitHub's username shape: {}",
            log_safe(&info.login)
        ))
    })?;

    let members: Vec<String> = fetch_paginated(
        client,
        |page| format!("{base}/orgs/{org}/public_members?per_page={PER_PAGE}&page={page}"),
        parse_members_page,
        None,
    )?;

    let repositories: Vec<String> = fetch_paginated(
        client,
        |page| {
            // type=public is explicit: the endpoint defaults to type=all,
            // so an authenticated token able to see the org's private
            // repositories would otherwise leak their names into the report
            // inventory and burn a doomed 403 request (or worse) per one of
            // them - the documented contract is the public repositories
            format!("{base}/orgs/{org}/repos?type=public&per_page={PER_PAGE}&page={page}")
        },
        |json| parse_repos_page(json, include_forks),
        limit,
    )?;

    // the API resolves the org through redirects: a shape-valid login that
    // differs from the requested one (beyond casing) is either a rename or
    // a response the caller should know about - warn, then scan what the
    // API actually returned
    if !info.login.eq_ignore_ascii_case(org) {
        log::warn!(
            "the API resolved '{}' to '{}': scanning the resolved organization",
            log_safe(org),
            log_safe(&info.login)
        );
    }
    let feedback = scan_org_repositories(scanner, base, &repositories, &info.login)?;
    // token death mid-scan: the skip-vs-abort contract is the module-level
    // one, but a partial kept after a dedicated token died may have left
    // repositories unscanned - abort with the token's real death error
    // instead of writing a complete-looking report (a revoked token is not
    // a spent allowance)
    if let Some(death_error) = feedback.death_error {
        return Err(death_error);
    }
    let mut all = feedback.emails;
    sort_emails(&mut all);

    let report = OrgReport {
        provenance: crate::output::Provenance::now(env!("CARGO_PKG_VERSION")),
        org: info,
        members,
        repositories,
        emails: OrgEmails {
            per_repository: feedback.per_repository,
            all,
        },
        scanned: OrgScanned {
            repos: feedback.repos_scanned,
            pages: scanner.requests_made(),
        },
        correlation: feedback.correlation,
    };
    report.log_summary();
    Ok(report)
}

/// Extracts the documented organization fields from a `GET /orgs/{org}`
/// body. `login` is required: the report keys on it, so a partial body
/// without it must fail explicitly instead of silently producing a report
/// with an empty login. Every other field is optional: a partial body
/// yields `None`s instead of failing the whole investigation.
///
/// # Errors
///
/// Returns [`Error::InvalidProfile`] when `login` is missing from the
/// payload.
fn parse_org(json: &Value) -> Result<OrgInfo, Error> {
    let string_field = |name: &str| {
        json.get(name)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
    };
    let login = string_field("login").ok_or_else(|| {
        Error::InvalidProfile("organization payload: missing `login`".to_string())
    })?;
    Ok(OrgInfo {
        login,
        name: string_field("name"),
        blog: string_field("blog"),
    })
}

/// Extracts the `login` of every member of a `/orgs/{org}/public_members` page,
/// together with the raw item count (the end-of-listing signal of
/// `fetch_paginated`). An item without a login is skipped, not reported
/// with an empty one. GitHub returns `[]` for an empty listing: a 200 body
/// that is not an array at all is an intermediary or a shape change, not an
/// empty page, and must fail explicitly instead of yielding a
/// complete-looking zero-member report.
///
/// # Errors
///
/// Returns [`Error::InvalidProfile`] when the body is not a JSON array.
fn parse_members_page(json: &Value) -> Result<(Vec<String>, usize), Error> {
    parse_string_field_page(json, "login", "members")
}

/// Extracts the repository `name` of every repository of a
/// `/orgs/{org}/repos` page, together with the raw item count. A
/// repository of an organization listing always sits under the
/// organization, so the plain `name` is the report's key (the scan workers
/// re-derive the full `owner/name` themselves from the repository URL).
/// A 200 body that is not a JSON array is an intermediary or a shape
/// change, not an empty page, and must fail explicitly.
///
/// # Errors
///
/// Returns [`Error::InvalidProfile`] when the body is not a JSON array.
fn parse_repos_page(json: &Value, include_forks: bool) -> Result<(Vec<String>, usize), Error> {
    let Some(items) = json.as_array() else {
        return Err(Error::InvalidProfile(
            "repositories payload: not an array".to_string(),
        ));
    };
    // the same hostile-listing discipline as the user investigation's
    // repositories listing: entries without a usable name are malformed
    // (warned, never silent), and forked repositories are skipped unless the
    // caller opted in (`--include-forks`) - `type=public` includes forks,
    // whose default-branch commits mirror the upstream history, so upstream
    // developers' emails would otherwise land in the org's report unmarked
    let mut repositories = Vec::new();
    let mut malformed = 0usize;
    let mut forks = 0usize;
    for item in items {
        let name = item.get("name").and_then(Value::as_str);
        if !include_forks && item.get("fork").and_then(Value::as_bool) == Some(true) {
            forks += 1;
            continue;
        }
        match name {
            Some(name) if !name.is_empty() => repositories.push(name.to_string()),
            _ => malformed += 1,
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

/// Extracts one string field of every item of a listing page, together
/// with the raw item count (the end-of-listing signal of
/// `fetch_paginated`). Items without the field are skipped, not reported.
/// A 200 body that is not a JSON array is an intermediary or a shape
/// change, not an empty page, and must fail explicitly.
///
/// # Errors
///
/// Returns [`Error::InvalidProfile`] when the body is not a JSON array.
fn parse_string_field_page(
    json: &Value,
    field: &str,
    label: &str,
) -> Result<(Vec<String>, usize), Error> {
    let Some(items) = json.as_array() else {
        return Err(Error::InvalidProfile(format!(
            "{label} payload: not an array"
        )));
    };
    let values = items
        .iter()
        .filter_map(|item| item.get(field).and_then(Value::as_str))
        .map(str::to_string)
        .collect();
    Ok((values, items.len()))
}

impl OrgReport {
    /// Logs the human-readable terminal report: one section per finding
    /// family (ORG / MEMBERS / REPOSITORIES / EMAILS found per repository
    /// and globally). Silent on empty sections. Every untrusted string
    /// (API-derived logins, names, repository names, emails) is sanitized
    /// first: control characters become `_`, so a hostile payload can
    /// never forge or spoof log lines.
    fn log_summary(&self) {
        info!("============ ORG ============");
        info!("[+] login: {}", log_safe(&self.org.login));
        if let Some(name) = &self.org.name {
            info!("[+] name: {}", log_safe(name));
        }
        if let Some(blog) = &self.org.blog {
            info!("[+] blog: {}", log_safe(blog));
        }

        info!("============ MEMBERS ============");
        if self.members.is_empty() {
            info!(
                "[-] no public member listed (the organization may keep this list private - the emails below come from the repositories)"
            );
        }
        for member in &self.members {
            info!("[+] {}", log_safe(member));
        }

        info!("============ REPOSITORIES ============");
        if self.repositories.is_empty() {
            info!("[-] no public repository listed");
        }
        for repository in &self.repositories {
            info!("[+] {}", log_safe(repository));
        }

        info!("============ EMAILS ============");
        if self.emails.all.is_empty() {
            info!(
                "[-] no email found in these repositories' commits - scan again with more tokens (--token / --token-file), or a higher --limit if you set one"
            );
        }
        for (repository, emails) in &self.emails.per_repository {
            info!(
                "[+] {}: {}",
                log_safe(repository),
                log_safe(&emails.join(", "))
            );
        }
        if !self.emails.all.is_empty() {
            info!(
                "[+] {} distinct email(s) found globally: {}",
                self.emails.all.len(),
                log_safe(&self.emails.all.join(", "))
            );
        }
    }
}

#[cfg(test)]
mod tests {
    // Tests may unwrap, expect and panic freely: a failing assertion must
    // be loud, so the zero-panic lints do not apply to the test modules.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::github::mock::{request_header, serve_requests};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    /// The org-info mock body every investigation starts from: the same
    /// literal served verbatim at each listing test's fallback arm.
    const ACME_ORG_INFO: &str = r#"{"login": "acme", "name": "Acme Corp"}"#;

    fn commit_json(name: &str, email: &str) -> String {
        serde_json::json!({ "commit": { "author": { "name": name, "email": email } } }).to_string()
    }

    /// A full page of 100 commits: the page-size-aware commit listing only
    /// ends on a short page, and GitHub serves full pages until the last
    /// one, so multi-page mock listings must serve full pages to reproduce
    /// the real walk. Every even commit attributes the real email, every
    /// odd one a noreply address (excluded from the kept emails).
    fn full_commit_page(name: &str, email: &str) -> String {
        let commits: Vec<String> = (0..100)
            .map(|i| {
                if i % 2 == 0 {
                    commit_json(name, email)
                } else {
                    commit_json(name, &format!("12345+{name}@users.noreply.github.com"))
                }
            })
            .collect();
        format!("[{}]", commits.join(","))
    }

    /// Builds a Scanner over one or two dedicated tokens, like the CLI
    /// would from a token file.
    fn token_scanner(second: bool) -> Scanner {
        let tokens = if second {
            r#"{"0": "ghp_a", "1": "ghp_b"}"#
        } else {
            r#"{"0": "ghp_a"}"#
        };
        // a unique path per call: two tests running concurrently must not
        // write/remove the same token file under each other's feet
        static CALLS: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "git2mail_org_tokens_{}_{}_{}.json",
            std::process::id(),
            second,
            CALLS.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&path, tokens).expect("test setup: write token file");
        let scanner = Scanner::new(None, Some(&path)).expect("scanner must build");
        std::fs::remove_file(&path).ok();
        scanner
    }

    #[test]
    fn the_terminal_report_sanitizes_the_untrusted_strings_it_prints() {
        // the CHANGELOG 0.7.0 claim is pinned at the wiring level, not only
        // at the sanitizer helper: a dropped `log_safe()` call must fail
        // this test (capturing logger, see `crate::test_logger`)
        let report = OrgReport {
            provenance: crate::output::Provenance::now(env!("CARGO_PKG_VERSION")),
            org: OrgInfo {
                login: "acme\u{1b}[31m".to_string(),
                name: Some("Acme\nCorp".to_string()),
                blog: None,
            },
            members: vec!["al\u{202E}ice".to_string()],
            repositories: Vec::new(),
            emails: OrgEmails {
                per_repository: BTreeMap::new(),
                all: Vec::new(),
            },
            scanned: OrgScanned { repos: 0, pages: 0 },
            correlation: crate::correlate::Correlation::default(),
        };
        let (_, lines) = crate::test_logger::capture(|| report.log_summary());
        assert!(
            !lines
                .iter()
                .any(|line| line.contains('\x1b') || line.contains('\n')),
            "a hostile payload must not forge or recolor a log line: {lines:?}"
        );
        assert!(
            lines.iter().any(|line| line.contains("acme_[31m")),
            "{lines:?}"
        );
        assert!(
            lines.iter().any(|line| line.contains("Acme_Corp")),
            "{lines:?}"
        );
        assert!(
            lines.iter().any(|line| line.contains("al_ice")),
            "{lines:?}"
        );
    }

    #[test]
    fn a_missing_organization_is_a_clean_not_found() {
        let (address, server) = serve_requests(move |_index, _request| {
            (404, vec![], r#"{"message": "Not Found"}"#.to_string())
        });

        let scanner = Scanner::new(None, None).expect("anonymous scanner must build");
        let error = investigate_at(&scanner, &address, "acme", None, false)
            .expect_err("a missing organization must fail");
        assert!(matches!(error, Error::NotFound));
        server.join();
    }

    #[test]
    fn a_hostile_org_payload_login_fails_the_scan_explicitly() {
        // a shape-valid request can still receive a hostile body: a slash-
        // bearing API-derived login must fail the investigation explicitly,
        // not be composed into scan hits that would silently re-scan another
        // owner's repositories under the requested org's report
        let (address, server) = serve_requests(move |_index, _request| {
            (
                200,
                vec![],
                r#"{"login": "other-org/sub", "name": "Acme"}"#.to_string(),
            )
        });

        let scanner = Scanner::new(None, None).expect("anonymous scanner must build");
        let error = investigate_at(&scanner, &address, "acme", None, false)
            .expect_err("a hostile login payload must fail");
        let shape_rejected = matches!(error, Error::InvalidProfile(ref details) if details.contains("username shape"));
        assert!(shape_rejected, "unexpected error: {error:?}");
        server.join();
    }

    #[test]
    fn an_invalid_org_login_is_rejected_before_any_network_request() {
        let scanner = Scanner::new(None, None).expect("anonymous scanner must build");
        for bad in ["", "acme corp", "a/b", "-acme", "ac--me"] {
            let error = investigate_at(&scanner, "http://127.0.0.1:1", bad, None, false)
                .expect_err("must fail");
            assert!(
                matches!(error, Error::InvalidUsername(_)),
                "{bad:?} must be rejected client-side"
            );
        }
    }

    #[test]
    fn a_partial_org_payload_fails_explicitly() {
        let (address, server) = serve_requests(move |_index, _request| {
            (200, vec![], r#"{"name": "Acme"}"#.to_string())
        });

        let scanner = Scanner::new(None, None).expect("anonymous scanner must build");
        let error = investigate_at(&scanner, &address, "acme", None, false)
            .expect_err("a payload without login must fail");
        assert!(matches!(
            &error,
            Error::InvalidProfile(details) if details.contains("login")
        ));
        server.join();
    }

    #[test]
    fn a_200_body_that_is_not_an_array_fails_the_listing_explicitly() {
        // GitHub returns `[]` for an empty listing: a non-array 200 body is
        // an intermediary (proxy, captive portal) or a shape change, and
        // must never be read as a legitimate empty page
        for endpoint in ["members", "repos"] {
            let (address, server) = serve_requests(move |_index, request| {
                let line = request.first().map(String::as_str).unwrap_or("");
                if line.contains("/orgs/acme/public_members") {
                    if endpoint == "members" {
                        return (200, vec![], r#"{"message": "HTML error page"}"#.to_string());
                    }
                    return (200, vec![], "[]".to_string());
                }
                if line.contains("/orgs/acme/repos") {
                    if endpoint == "repos" {
                        return (200, vec![], r#"{"message": "HTML error page"}"#.to_string());
                    }
                    return (200, vec![], "[]".to_string());
                }
                // org info
                (200, vec![], ACME_ORG_INFO.to_string())
            });

            let scanner = Scanner::new(None, None).expect("anonymous scanner must build");
            let error = investigate_at(&scanner, &address, "acme", None, false)
                .expect_err("a non-array body must fail the listing");
            server.join();
            assert!(
                matches!(&error, Error::InvalidProfile(details) if details.contains("array")),
                "unexpected error for {endpoint}: {error:?}"
            );
        }
    }

    #[test]
    fn members_are_listed_across_pages() {
        let (address, server) = serve_requests(move |_index, request| {
            let line = request.first().map(String::as_str).unwrap_or("");
            if line.contains("/orgs/acme/public_members") {
                let body = match crate::github::mock::request_line_page(request) {
                    1 => r#"[{"login": "alice"}, {"login": "bob"}]"#.to_string(),
                    2 => r#"[{"login": "carol"}, {"no_login": true}]"#.to_string(),
                    _ => "[]".to_string(),
                };
                return (200, vec![], body);
            }
            // org info, then the (empty) repos listing
            if line.contains("/orgs/acme/repos") {
                return (200, vec![], "[]".to_string());
            }
            (
                200,
                vec![],
                r#"{"login": "acme", "name": "Acme Corp", "blog": "https://acme.example"}"#
                    .to_string(),
            )
        });

        let scanner = Scanner::new(None, None).expect("anonymous scanner must build");
        let report = investigate_at(&scanner, &address, "acme", None, false)
            .expect("the listing must succeed");
        server.join();

        assert_eq!(report.org.login, "acme");
        assert_eq!(report.org.name.as_deref(), Some("Acme Corp"));
        assert_eq!(report.org.blog.as_deref(), Some("https://acme.example"));
        // the member without a login is skipped, not reported empty
        assert_eq!(
            report.members,
            vec!["alice".to_string(), "bob".to_string(), "carol".to_string()]
        );
        assert!(report.repositories.is_empty());
        assert_eq!(report.scanned.repos, 0);
    }

    #[test]
    fn repositories_are_listed_across_pages_and_respect_the_limit() {
        let requested_pages: Arc<Mutex<Vec<u16>>> = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&requested_pages);
        let (address, server) = serve_requests(move |_index, request| {
            let line = request.first().map(String::as_str).unwrap_or("");
            if line.contains("/orgs/acme/repos") {
                if let Ok(mut pages) = recorded.lock() {
                    pages.push(crate::github::mock::request_line_page(request));
                }
                let body = match crate::github::mock::request_line_page(request) {
                    1 => r#"[{"name": "one"}, {"name": "two"}]"#.to_string(),
                    2 => r#"[{"name": "three"}]"#.to_string(),
                    _ => "[]".to_string(),
                };
                return (200, vec![], body);
            }
            if line.contains("/orgs/acme/public_members") {
                return (200, vec![], "[]".to_string());
            }
            if line.contains("/commits") {
                // the commit listings are out of scope here: a 404 is
                // skipped by the scan workers like a deleted repository
                return (404, vec![], String::new());
            }
            // org info
            (200, vec![], ACME_ORG_INFO.to_string())
        });

        let scanner = token_scanner(false);
        let report = investigate_at(&scanner, &address, "acme", Some(1), false)
            .expect("the listing must succeed");

        // --limit 1: the first page held 2 items but only 1 is kept, and no
        // second page was ever requested to be thrown away
        assert_eq!(report.repositories, vec!["one".to_string()]);
        let pages = requested_pages.lock().expect("page log must lock");
        assert_eq!(
            pages.as_slice(),
            &[1],
            "the limit must stop the listing early: {pages:?}"
        );
        // the scan of the listed repository hit a 404: skipped with a
        // warning, counted as scanned nowhere
        assert_eq!(report.scanned.repos, 0);
        assert!(report.emails.all.is_empty());
        assert!(report.emails.per_repository.is_empty());
        server.join();
    }

    #[test]
    fn the_org_repositories_are_scanned_in_parallel_and_reported_per_repository() {
        let authorizations: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&authorizations);
        let (address, server) = serve_requests(move |index, request| {
            if let Some(auth) = request_header(request, "Authorization")
                && let Ok(mut log) = recorded.lock()
            {
                log.push(auth.to_string());
            }
            // one fast worker can scan both listed repositories before the
            // other worker's thread is first scheduled (loopback processing
            // takes milliseconds, a thread start under a loaded test runner
            // can take tens or hundreds): park every request AFTER the
            // org-info call (the workers' commit pages AND the shared
            // client's members/repos listings) so the worker that claims one
            // repository is held long enough for the second worker to claim
            // the other hit, even on a saturated runner. The org-info
            // request (index 0) runs before any worker exists: delaying it
            // would only add latency, not widen the race window
            if index > 0 {
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            let line = request.first().map(String::as_str).unwrap_or("");
            if line.contains("/orgs/acme/public_members") {
                return match crate::github::mock::request_line_page(request) {
                    1 => (200, vec![], r#"[{"login": "alice"}]"#.to_string()),
                    _ => (200, vec![], "[]".to_string()),
                };
            }
            if line.contains("/orgs/acme/repos") {
                return match crate::github::mock::request_line_page(request) {
                    1 => (
                        200,
                        vec![],
                        r#"[{"name": "one"}, {"name": "two"}]"#.to_string(),
                    ),
                    _ => (200, vec![], "[]".to_string()),
                };
            }
            if line.contains("/repos/acme/one/commits") {
                return match crate::github::mock::request_line_page(request) {
                    1 => (200, vec![], full_commit_page("Alice", "alice@acme.com")),
                    _ => (200, vec![], "[]".to_string()),
                };
            }
            if line.contains("/repos/acme/two/commits") {
                return match crate::github::mock::request_line_page(request) {
                    1 => (200, vec![], full_commit_page("Bob", "bob@acme.com")),
                    _ => (200, vec![], "[]".to_string()),
                };
            }
            // org info
            (200, vec![], ACME_ORG_INFO.to_string())
        });

        // two tokens: two workers, one dedicated token each
        let scanner = token_scanner(true);
        let report =
            investigate_at(&scanner, &address, "acme", None, false).expect("the scan must succeed");
        server.join();

        assert_eq!(report.org.login, "acme");
        assert_eq!(report.members, vec!["alice".to_string()]);
        assert_eq!(
            report.repositories,
            vec!["one".to_string(), "two".to_string()]
        );
        // the noreply address is excluded, the real emails are sorted
        assert_eq!(
            report.emails.all,
            vec!["alice@acme.com".to_string(), "bob@acme.com".to_string()]
        );
        assert_eq!(
            report.emails.per_repository.get("acme/one"),
            Some(&vec!["alice@acme.com".to_string()])
        );
        assert_eq!(
            report.emails.per_repository.get("acme/two"),
            Some(&vec!["bob@acme.com".to_string()])
        );
        // both listed repositories were actually scanned
        assert_eq!(report.scanned.repos, 2);
        // org info (1) + members (2) + repos listing (2) + the two
        // repositories' commit pages (2 each)
        assert_eq!(report.scanned.pages, 9);

        // both dedicated tokens were exercised by the workers
        let authorizations = authorizations.lock().expect("request log must lock");
        assert!(
            authorizations.iter().any(|auth| auth.contains("ghp_a"))
                && authorizations.iter().any(|auth| auth.contains("ghp_b")),
            "both dedicated tokens must be exercised: {authorizations:?}"
        );
    }

    #[test]
    fn a_token_dying_mid_scan_aborts_the_investigation_instead_of_a_partial_report() {
        // the org contract: the report can never silently miss whole
        // repositories. A single dedicated token parked by a secondary rate
        // limit after scanning one of two listed repositories must abort the
        // investigation (the reused parallel scan alone would have returned
        // a complete-looking partial report)
        let (address, server) = serve_requests(move |_index, request| {
            let line = request.first().map(String::as_str).unwrap_or("");
            if line.contains("/orgs/acme/repos") {
                return match crate::github::mock::request_line_page(request) {
                    1 => (
                        200,
                        vec![],
                        r#"[{"name": "one"}, {"name": "two"}]"#.to_string(),
                    ),
                    _ => (200, vec![], "[]".to_string()),
                };
            }
            if line.contains("/orgs/acme/public_members") {
                return (200, vec![], "[]".to_string());
            }
            if line.contains("/repos/acme/one/commits") {
                // page 1 holds one commit, page 2 ends the listing: the mock
                // must behave like the API, or fetch_paginated walks every
                // u16 page of the listing
                return match crate::github::mock::request_line_page(request) {
                    1 => (
                        200,
                        vec![],
                        format!("[{}]", commit_json("Alice", "alice@acme.com")),
                    ),
                    _ => (200, vec![], "[]".to_string()),
                };
            }
            if line.contains("/repos/acme/two/commits") {
                // the only token is parked by a secondary rate limit exactly
                // when the second repository's commits are fetched
                return (
                    429,
                    vec![("Retry-After".to_string(), "60".to_string())],
                    String::new(),
                );
            }
            // org info
            (200, vec![], ACME_ORG_INFO.to_string())
        });

        let scanner = token_scanner(false);
        let error = investigate_at(&scanner, &address, "acme", None, false)
            .expect_err("a secondary-limit park mid-scan must abort the investigation");
        server.join();
        assert!(
            matches!(error, Error::RateLimitPaused),
            "a secondary-park stop must surface the dedicated paused error: {error:?}"
        );
    }

    #[test]
    fn a_kept_partial_result_after_a_token_death_aborts_with_the_real_cause() {
        // the reduction keeps a partial result when a dedicated token dies
        // with progress, whatever the death cause: the org caller must
        // re-raise THAT cause. A revoked token (401 → `TokenRejected`) must
        // not be misreported as "allowance used up - wait for the window"
        let (address, server) = serve_requests(move |_index, request| {
            let line = request.first().map(String::as_str).unwrap_or("");
            if line.contains("/orgs/acme/repos") {
                return match crate::github::mock::request_line_page(request) {
                    1 => (
                        200,
                        vec![],
                        r#"[{"name": "one"}, {"name": "two"}]"#.to_string(),
                    ),
                    _ => (200, vec![], "[]".to_string()),
                };
            }
            if line.contains("/orgs/acme/public_members") {
                return (200, vec![], "[]".to_string());
            }
            if line.contains("/repos/acme/one/commits") {
                // page 1 makes real progress, page 2 ends the listing
                return match crate::github::mock::request_line_page(request) {
                    1 => (
                        200,
                        vec![],
                        format!("[{}]", commit_json("Alice", "alice@acme.com")),
                    ),
                    _ => (200, vec![], "[]".to_string()),
                };
            }
            if line.contains("/repos/acme/two/commits") {
                // the dedicated token is revoked: the sole token cannot
                // rotate, so the request surfaces `TokenRejected`
                return (401, vec![], r#"{"message": "Bad credentials"}"#.to_string());
            }
            // org info
            (200, vec![], ACME_ORG_INFO.to_string())
        });

        let scanner = token_scanner(false);
        let error = investigate_at(&scanner, &address, "acme", None, false)
            .expect_err("a kept partial result must abort the org scan");
        server.join();
        assert!(
            matches!(error, Error::TokenRejected),
            "the real death cause must surface, not a generic rate-limit error: {error:?}"
        );
    }

    #[test]
    fn a_shape_valid_foreign_login_is_warned_not_silent() {
        // a shape-valid login differing from the requested org (beyond
        // casing) is a rename or an unexpected response: the terminal must
        // say so instead of scanning a foreign org silently
        let (address, server) = serve_requests(move |_index, request| {
            let line = request.first().map(String::as_str).unwrap_or("");
            if line.contains("/orgs/acme/repos") {
                return match crate::github::mock::request_line_page(request) {
                    1 => (200, vec![], r#"[{"name": "one"}]"#.to_string()),
                    _ => (200, vec![], "[]".to_string()),
                };
            }
            if line.contains("/orgs/acme/public_members") {
                return (200, vec![], "[]".to_string());
            }
            if line.contains("/repos/evilcorp/one/commits") {
                return match crate::github::mock::request_line_page(request) {
                    1 => (
                        200,
                        vec![],
                        format!("[{}]", commit_json("Alice", "alice@evilcorp.com")),
                    ),
                    _ => (200, vec![], "[]".to_string()),
                };
            }
            // org info: shape-valid foreign login (same casing, different name)
            (
                200,
                vec![],
                r#"{"login": "evilcorp", "name": "Evil Corp"}"#.to_string(),
            )
        });

        let scanner = token_scanner(false);
        let (outcome, lines) =
            crate::test_logger::capture(|| investigate_at(&scanner, &address, "acme", None, false));
        let report = outcome.expect("a shape-valid foreign login must not abort the scan");
        server.join();

        assert_eq!(report.org.login, "evilcorp");
        assert!(
            lines
                .iter()
                .any(|line| line.contains("resolved 'acme' to 'evilcorp'")),
            "the resolution must be warned: {lines:?}"
        );
    }

    #[test]
    fn the_scan_hits_carry_the_canonical_organization_login() {
        // the user types `ACME`, the API canonicalizes to `acme`: the
        // per-repository keys must agree with `report.org.login`, not echo
        // the casing of the input
        let (address, server) = serve_requests(move |_index, request| {
            let line = request.first().map(String::as_str).unwrap_or("");
            if line.contains("/orgs/ACME/repos") {
                return match crate::github::mock::request_line_page(request) {
                    1 => (200, vec![], r#"[{"name": "one"}]"#.to_string()),
                    _ => (200, vec![], "[]".to_string()),
                };
            }
            if line.contains("/orgs/ACME/public_members") {
                return (200, vec![], "[]".to_string());
            }
            if line.contains("/repos/acme/one/commits") {
                // page 1 holds one commit, page 2 ends the listing: the mock
                // must behave like the API, or fetch_paginated walks every
                // u16 page of the listing
                return match crate::github::mock::request_line_page(request) {
                    1 => (
                        200,
                        vec![],
                        format!("[{}]", commit_json("Alice", "alice@acme.com")),
                    ),
                    _ => (200, vec![], "[]".to_string()),
                };
            }
            // org info: the canonical login is lowercase
            (200, vec![], ACME_ORG_INFO.to_string())
        });

        let scanner = token_scanner(false);
        let report =
            investigate_at(&scanner, &address, "ACME", None, false).expect("the scan must succeed");
        server.join();

        assert_eq!(report.org.login, "acme");
        assert_eq!(report.repositories, vec!["one".to_string()]);
        assert_eq!(
            report.emails.per_repository.get("acme/one"),
            Some(&vec!["alice@acme.com".to_string()]),
            "the per-repository key must carry the canonical login"
        );
    }

    #[test]
    fn a_malformed_listing_name_is_skipped_with_a_warning_not_a_failure() {
        // wiring test for the listing filter: a hostile ".." name would
        // otherwise corrupt the composed scan URL and abort the whole org
        // scan (the parsers reject it at composition time). The filter must
        // warn-skip the entry so the scan completes on the sane repositories
        let (address, server) = serve_requests(move |_index, request| {
            let line = request.first().map(String::as_str).unwrap_or("");
            if line.contains("/orgs/acme/repos") {
                return match crate::github::mock::request_line_page(request) {
                    1 => (
                        200,
                        vec![],
                        r#"[{"name": ".."}, {"name": "one"}]"#.to_string(),
                    ),
                    _ => (200, vec![], "[]".to_string()),
                };
            }
            if line.contains("/orgs/acme/public_members") {
                return (200, vec![], "[]".to_string());
            }
            if line.contains("/repos/acme/one/commits") {
                return match crate::github::mock::request_line_page(request) {
                    1 => (
                        200,
                        vec![],
                        format!("[{}]", commit_json("Alice", "alice@acme.com")),
                    ),
                    _ => (200, vec![], "[]".to_string()),
                };
            }
            // org info
            (200, vec![], ACME_ORG_INFO.to_string())
        });

        let scanner = token_scanner(false);
        let (outcome, lines) =
            crate::test_logger::capture(|| investigate_at(&scanner, &address, "acme", None, false));
        let report = outcome.expect("the scan must succeed despite the malformed entry");
        server.join();

        // the inventory keeps the raw listing (the report must reflect what
        // the org actually lists); the malformed entry is only excluded from
        // the scanned set
        assert_eq!(
            report.repositories,
            vec!["..".to_string(), "one".to_string()]
        );
        assert_eq!(report.scanned.repos, 1, "only the sane entry is scanned");
        assert_eq!(
            report.emails.per_repository.get("acme/one"),
            Some(&vec!["alice@acme.com".to_string()])
        );
        assert!(
            !report
                .emails
                .per_repository
                .keys()
                .any(|key| key.contains("..")),
            "the malformed entry must never be scanned"
        );
        assert!(
            lines
                .iter()
                .any(|line| line.contains("skipping a malformed org listing entry")),
            "the malformed entry must be reported: {lines:?}"
        );
    }

    #[test]
    fn the_repositories_listing_requests_only_public_repositories() {
        // the endpoint defaults to type=all: without the explicit type=public
        // parameter an authenticated token able to see private repositories
        // would leak their names into the report and burn a doomed request
        // per one of them - the wire format is pinned here
        let requests: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&requests);
        let (address, server) = serve_requests(move |_index, request| {
            if let Some(line) = request.first()
                && let Ok(mut log) = recorded.lock()
            {
                log.push(line.clone());
            }
            let line = request.first().map(String::as_str).unwrap_or("");
            if line.contains("/orgs/acme/repos") {
                return match crate::github::mock::request_line_page(request) {
                    1 => (200, vec![], r#"[{"name": "one"}]"#.to_string()),
                    _ => (200, vec![], "[]".to_string()),
                };
            }
            if line.contains("/orgs/acme/public_members") {
                return (200, vec![], "[]".to_string());
            }
            if line.contains("/repos/acme/one/commits") {
                return match crate::github::mock::request_line_page(request) {
                    1 => (
                        200,
                        vec![],
                        format!("[{}]", commit_json("Alice", "alice@acme.com")),
                    ),
                    _ => (200, vec![], "[]".to_string()),
                };
            }
            // org info
            (200, vec![], ACME_ORG_INFO.to_string())
        });

        let scanner = token_scanner(false);
        let report =
            investigate_at(&scanner, &address, "acme", None, false).expect("the scan must succeed");
        server.join();

        assert_eq!(report.org.login, "acme");
        let requests = requests.lock().expect("the request log must lock");
        assert!(
            requests
                .iter()
                .any(|line| line.contains("/orgs/acme/repos?type=public&")),
            "the repositories listing must request type=public: {requests:?}"
        );
    }

    #[test]
    fn an_opted_in_fork_is_scanned_like_any_other_repository() {
        // `--include-forks`: the same listing holding a fork is scanned in
        // full when the caller opted in - the fork's own commits are the
        // caller's explicit choice, and the skipped-forks warning must not
        // fire (nothing was skipped)
        let (address, server) = serve_requests(move |_index, request| {
            let line = request.first().map(String::as_str).unwrap_or("");
            if line.contains("/orgs/acme/repos") {
                return match crate::github::mock::request_line_page(request) {
                    1 => (
                        200,
                        vec![],
                        r#"[{"name": "upstream-fork", "fork": true}, {"name": "one"}]"#.to_string(),
                    ),
                    _ => (200, vec![], "[]".to_string()),
                };
            }
            if line.contains("/orgs/acme/public_members") {
                return (200, vec![], "[]".to_string());
            }
            if line.contains("/repos/acme/upstream-fork/commits") {
                return match crate::github::mock::request_line_page(request) {
                    1 => (
                        200,
                        vec![],
                        format!("[{}]", commit_json("Forker", "forker@example.com")),
                    ),
                    _ => (200, vec![], "[]".to_string()),
                };
            }
            if line.contains("/repos/acme/one/commits") {
                return match crate::github::mock::request_line_page(request) {
                    1 => (
                        200,
                        vec![],
                        format!("[{}]", commit_json("Alice", "alice@acme.com")),
                    ),
                    _ => (200, vec![], "[]".to_string()),
                };
            }
            (
                200,
                vec![],
                r#"{"login": "acme", "name": "Acme Corp"}"#.to_string(),
            )
        });

        let scanner = token_scanner(false);
        let (outcome, lines) =
            crate::test_logger::capture(|| investigate_at(&scanner, &address, "acme", None, true));
        let report = outcome.expect("the opted-in scan must succeed");
        server.join();

        // both repositories were scanned, the fork's emails reported like
        // any other repository's
        assert_eq!(report.scanned.repos, 2, "the fork must be scanned");
        assert_eq!(
            report.emails.per_repository.get("acme/upstream-fork"),
            Some(&vec!["forker@example.com".to_string()])
        );
        assert!(
            !lines.iter().any(|line| line.contains("forked")),
            "nothing was skipped: no fork warning may fire: {lines:?}"
        );
    }

    #[test]
    fn a_forked_listing_entry_is_skipped_with_a_warning() {
        // `type=public` includes forks: a fork's default-branch commits
        // mirror the upstream history, so upstream developers' emails would
        // land in the org's report unmarked. The listing filter skips them
        // with a warning (the same discipline as the user investigation)
        let (address, server) = serve_requests(move |_index, request| {
            let line = request.first().map(String::as_str).unwrap_or("");
            if line.contains("/orgs/acme/repos") {
                return match crate::github::mock::request_line_page(request) {
                    1 => (
                        200,
                        vec![],
                        r#"[{"name": "upstream-fork", "fork": true}, {"name": "one"}]"#.to_string(),
                    ),
                    _ => (200, vec![], "[]".to_string()),
                };
            }
            if line.contains("/orgs/acme/public_members") {
                return (200, vec![], "[]".to_string());
            }
            if line.contains("/repos/acme/one/commits") {
                return match crate::github::mock::request_line_page(request) {
                    1 => (
                        200,
                        vec![],
                        format!("[{}]", commit_json("Alice", "alice@acme.com")),
                    ),
                    _ => (200, vec![], "[]".to_string()),
                };
            }
            (
                200,
                vec![],
                r#"{"login": "acme", "name": "Acme Corp"}"#.to_string(),
            )
        });

        let scanner = token_scanner(false);
        let (outcome, lines) =
            crate::test_logger::capture(|| investigate_at(&scanner, &address, "acme", None, false));
        let report = outcome.expect("the scan must succeed despite the fork");
        server.join();

        // the fork never reaches the scanned set: only the sane entry is
        // scanned and reported
        assert_eq!(report.scanned.repos, 1, "the fork must not be scanned");
        assert_eq!(
            report.emails.per_repository.get("acme/one"),
            Some(&vec!["alice@acme.com".to_string()])
        );
        assert!(
            !report
                .emails
                .per_repository
                .keys()
                .any(|key| key.contains("upstream-fork")),
            "the fork must never be scanned"
        );
        assert!(
            lines
                .iter()
                .any(|line| line.contains("1 forked repository skipped")),
            "the fork must be announced: {lines:?}"
        );
    }

    #[test]
    fn the_report_serializes_the_documented_json_shape() {
        let report = OrgReport {
            provenance: crate::output::Provenance::now(env!("CARGO_PKG_VERSION")),
            org: OrgInfo {
                login: "acme".to_string(),
                name: Some("Acme Corp".to_string()),
                blog: None,
            },
            members: vec!["alice".to_string()],
            repositories: vec!["one".to_string(), "two".to_string()],
            emails: OrgEmails {
                per_repository: BTreeMap::from([(
                    "acme/one".to_string(),
                    vec!["alice@acme.com".to_string()],
                )]),
                all: vec!["alice@acme.com".to_string()],
            },
            correlation: crate::correlate::Correlation {
                authors: vec![crate::correlate::AuthorReport {
                    author: "Alice".to_string(),
                    emails: vec!["alice@acme.com".to_string()],
                    repos: vec![crate::correlate::RepoLanguage {
                        name: "acme/one".to_string(),
                        language: None,
                    }],
                    languages: Vec::new(),
                    first_seen_repo: "acme/one".to_string(),
                    total_hits: 1,
                    last_commit_date: None,
                }],
            },
            scanned: OrgScanned { repos: 1, pages: 5 },
        };

        let parsed: Value = serde_json::to_value(&report).expect("the report must serialize");
        assert_eq!(parsed["org"]["login"], "acme");
        assert_eq!(parsed["org"]["name"], "Acme Corp");
        assert_eq!(parsed["org"]["blog"], serde_json::Value::Null);
        assert_eq!(parsed["members"], serde_json::json!(["alice"]));
        assert_eq!(parsed["repositories"], serde_json::json!(["one", "two"]));
        assert_eq!(
            parsed["emails"]["per_repository"],
            serde_json::json!({ "acme/one": ["alice@acme.com"] })
        );
        assert_eq!(
            parsed["emails"]["all"],
            serde_json::json!(["alice@acme.com"])
        );
        assert_eq!(parsed["scanned"]["repos"], 1);
        assert_eq!(parsed["scanned"]["pages"], 5);
        // the per-author correlation is additive (the remediation view an
        // org auditor needs): person, emails, repositories, counts
        assert_eq!(
            parsed["correlation"]["authors"][0]["author"],
            serde_json::json!("Alice")
        );
        assert_eq!(
            parsed["correlation"]["authors"][0]["emails"],
            serde_json::json!(["alice@acme.com"])
        );
        // the provenance is universal (doc/src/OUTPUT.md: every report
        // carries it): a dropped field must fail this shape test
        assert_eq!(parsed["tool_version"], env!("CARGO_PKG_VERSION"));
        assert!(
            parsed["generated_at"]
                .as_str()
                .is_some_and(|stamp| stamp.len() == 20 && stamp.ends_with('Z'))
        );
    }
}
