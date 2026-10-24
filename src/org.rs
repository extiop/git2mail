//! Organization investigation ): the public
//! members, the public repositories and the developers' emails found in
//! their commits — 100% API (no clone, no scraping, no new dependency).
//!
//! No comparable OSINT tool supports organizations: `git2mail org <org>`
//! fills that gap with the same building blocks as the rest of the crate:
//!
//! - the organization itself (`GET /orgs/{org}`; a 404 is a clean
//!   [`crate::errors::Error::NotFound`]);
//! - the **public members** (`GET /orgs/{org}/members`, paginated);
//! - the **public repositories** (`GET /orgs/{org}/repos`, paginated,
//!   capped by the optional `--limit`);
//! - the **emails** found scanning those repositories' commits with the
//!   same worker-per-token parallelism as the parallel `search`
//!   (`src/sources`, token-worker pool), reported per repository and
//!   globally.
//!
//! The investigation never panics: every fallible operation returns
//! [`crate::errors::Error`]. A repository that cannot be scanned on its own
//! (a private or deleted repository, a stale listing entry, an empty one —
//! GitHub answers 409 on its commits listing) is skipped with
//! a warning instead of aborting the report, like the parallel search
//! does; a rate-limit or transport failure is a scan-wide condition and
//! aborts the investigation, so a token parked by a secondary rate limit
//! can never yield a complete-looking report silently missing whole
//! repositories. Like the `user` investigation (and unlike the capped
//! reverse-email heuristic), the listings (the organization's members and
//! repositories) walk every page; each listed repository's commit walk is
//! capped at the shared per-repository budget (10 pages of 100 commits,
//! `crate::sources::repository::MAX_COMMIT_PAGES`), like every other
//! repository scan.

use crate::consts::GITHUB_API_BASE;
use crate::errors::Error;
use crate::github::fetch_paginated;
use crate::output::sanitize_log_text as log_safe;
use crate::sources::{PER_PAGE, Scanner, SearchHit, sort_emails};
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
/// sections and the `--json` shape, documented in the README.
#[derive(Debug, Clone, Serialize)]
pub struct OrgReport {
    /// The investigated organization.
    pub org: OrgInfo,
    /// The public member logins (`GET /orgs/{org}/members`).
    pub members: Vec<String>,
    /// The public repository names (`GET /orgs/{org}/repos`).
    pub repositories: Vec<String>,
    /// The emails found scanning the repositories, per repository and
    /// globally.
    pub emails: OrgEmails,
    /// The scan coverage (repositories actually scanned, pages fetched).
    pub scanned: OrgScanned,
}

/// Runs the full investigation of one GitHub organization: fetches the org
/// info, lists the public members and the public repositories, scans the
/// repositories' commits in parallel over the token pool, then builds the
/// report and logs the terminal summary.
///
/// # Errors
///
/// Returns [`Error::InvalidUsername`] when `org` is not a valid GitHub
/// login (rejected client-side, before any network request — GitHub
/// organizations follow the same login shape as users),
/// [`Error::NotFound`] for a missing organization,
/// [`Error::PrivateOrUnavailable`] or [`Error::RateLimitExhausted`] /
/// [`Error::Http`] for the corresponding API failures. A repository that
/// is private or deleted or empty (GitHub answers 409 on its commits
/// listing) is skipped with a warning and does not abort the
/// investigation; a rate-limit or transport failure aborts it, so the
/// report can never silently miss whole repositories — including the kept
/// partial result of a parallel scan whose dedicated token died mid-scan
/// (it is reported as [`Error::RateLimitExhausted`] too, unless the dead
/// token's workers had already covered every listed repository). `limit`
/// (the optional `--limit`) caps the number of listed repositories. Never
/// panics.
pub fn investigate(scanner: &Scanner, org: &str, limit: Option<usize>) -> Result<OrgReport, Error> {
    investigate_at(scanner, GITHUB_API_BASE, org, limit)
}

/// The investigation itself, driven against one API base URL:
/// [`investigate`] is the production entry point (`https://api.github.com`),
/// and the offline tests run this same code against a loopback mock.
///
/// # Errors
///
/// The same failures as [`investigate`]. Never panics.
fn investigate_at(
    scanner: &Scanner,
    base: &str,
    org: &str,
    limit: Option<usize>,
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
        |page| format!("{base}/orgs/{org}/members?per_page={PER_PAGE}&page={page}"),
        parse_members_page,
        None,
    )?;

    let repositories: Vec<String> = fetch_paginated(
        client,
        |page| format!("{base}/orgs/{org}/repos?per_page={PER_PAGE}&page={page}"),
        parse_repos_page,
        limit,
    )?;

    // the repositories are scanned with the parallel search's token-worker
    // pool: every repository becomes a GitHub URL hit the workers parse and
    // scan, exactly like a search result. The hits carry the canonical
    // login from the API (`info.login`), not the login as typed: the
    // per-repository keys of the report then always agree with
    // `report.org.login`, whatever casing the user typed
    let hits: Vec<SearchHit> = repositories
        .iter()
        .map(|repository| SearchHit {
            url: format!("https://github.com/{}/{repository}", info.login),
            language: None,
        })
        .collect();
    let (all, per_repository, repos_scanned, skipped, _, token_death_partial) =
        scanner.scan_repositories_at(base, &hits, false)?;
    // the org contract (module doc and README): the report can never
    // silently miss whole repositories. A repository that cannot be scanned
    // on its own is legitimately skipped (counted in `skipped`), but a scan
    // that kept a partial result after a dedicated token died mid-scan may
    // have left repositories unscanned: abort with the rate-limit error
    // instead of writing a complete-looking report, like any other
    // rate-limit failure. A listed repository counts as covered only when it
    // was actually scanned or explicitly skipped: work never pulled or left
    // unfinished by a dead token is neither
    if token_death_partial && repos_scanned + skipped < repositories.len() {
        return Err(Error::RateLimitExhausted);
    }
    let mut all = all;
    sort_emails(&mut all);

    let report = OrgReport {
        org: info,
        members,
        repositories,
        emails: OrgEmails {
            per_repository,
            all,
        },
        scanned: OrgScanned {
            repos: repos_scanned,
            pages: scanner.requests_made(),
        },
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
/// payload. Never panics.
fn parse_org(json: &Value) -> Result<OrgInfo, Error> {
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
        .ok_or_else(|| Error::InvalidProfile("organization payload: missing `login`".to_string()))?
        .to_string();
    Ok(OrgInfo {
        login,
        name: string_field("name"),
        blog: string_field("blog"),
    })
}

/// Extracts the `login` of every member of a `/orgs/{org}/members` page,
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
/// Never panics.
fn parse_members_page(json: &Value) -> Result<(Vec<String>, usize), Error> {
    let Some(items) = json.as_array() else {
        return Err(Error::InvalidProfile(
            "members payload: not an array".to_string(),
        ));
    };
    let members = items
        .iter()
        .filter_map(|item| item.get("login").and_then(Value::as_str))
        .map(str::to_string)
        .collect();
    Ok((members, items.len()))
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
/// Never panics.
fn parse_repos_page(json: &Value) -> Result<(Vec<String>, usize), Error> {
    let Some(items) = json.as_array() else {
        return Err(Error::InvalidProfile(
            "repositories payload: not an array".to_string(),
        ));
    };
    let repositories = items
        .iter()
        .filter_map(|item| item.get("name").and_then(Value::as_str))
        .map(str::to_string)
        .collect();
    Ok((repositories, items.len()))
}

impl OrgReport {
    /// Logs the human-readable terminal report: one section per finding
    /// family (ORG / MEMBERS / REPOSITORIES / EMAILS found per repository
    /// and globally). Silent on empty sections. Every untrusted string
    /// (API-derived logins, names, repository names, emails) is sanitized
    /// first: control characters become `_`, so a hostile payload can
    /// never forge or spoof log lines. Never panics.
    fn log_summary(&self) {
        info!("============ ORG ============");
        info!("[+] GitHub name: {}", log_safe(&self.org.login));
        if let Some(name) = &self.org.name {
            info!("[+] name: {}", log_safe(name));
        }
        if let Some(blog) = &self.org.blog {
            info!("[+] blog: {}", log_safe(blog));
        }

        info!("============ MEMBERS ============");
        if self.members.is_empty() {
            info!(
                "[-] no public member listed (most companies hide this list — the emails below come from the repositories)"
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
                "[-] no email found in these repositories' commits — try more repositories or add tokens"
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

    /// Extracts the `page=` query parameter of a mock request line,
    /// robust to further parameters after it and to `per_page` sharing the
    /// `page=` substring.
    fn page_param(request: &[String]) -> u16 {
        request
            .first()
            .map(|line| line.trim_end_matches(" HTTP/1.1"))
            .and_then(|line| line.split('?').nth(1))
            .and_then(|query| {
                query.split('&').find_map(|param| {
                    param
                        .strip_prefix("page=")
                        .and_then(|page| page.parse().ok())
                })
            })
            .unwrap_or(0)
    }

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
        let error = investigate_at(&scanner, &address, "acme", None)
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
        let error = investigate_at(&scanner, &address, "acme", None)
            .expect_err("a hostile login payload must fail");
        let shape_rejected = matches!(error, Error::InvalidProfile(ref details) if details.contains("username shape"));
        assert!(shape_rejected, "unexpected error: {error:?}");
        server.join();
    }

    #[test]
    fn an_invalid_org_login_is_rejected_before_any_network_request() {
        let scanner = Scanner::new(None, None).expect("anonymous scanner must build");
        for bad in ["", "acme corp", "a/b", "-acme", "ac--me"] {
            let error =
                investigate_at(&scanner, "http://127.0.0.1:1", bad, None).expect_err("must fail");
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
        let error = investigate_at(&scanner, &address, "acme", None)
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
                if line.contains("/orgs/acme/members") {
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
                (
                    200,
                    vec![],
                    r#"{"login": "acme", "name": "Acme Corp"}"#.to_string(),
                )
            });

            let scanner = Scanner::new(None, None).expect("anonymous scanner must build");
            let error = investigate_at(&scanner, &address, "acme", None)
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
            if line.contains("/orgs/acme/members") {
                let body = match page_param(request) {
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
        let report =
            investigate_at(&scanner, &address, "acme", None).expect("the listing must succeed");
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
                    pages.push(page_param(request));
                }
                let body = match page_param(request) {
                    1 => r#"[{"name": "one"}, {"name": "two"}]"#.to_string(),
                    2 => r#"[{"name": "three"}]"#.to_string(),
                    _ => "[]".to_string(),
                };
                return (200, vec![], body);
            }
            if line.contains("/orgs/acme/members") {
                return (200, vec![], "[]".to_string());
            }
            if line.contains("/commits") {
                // the commit listings are out of scope here: a 404 is
                // skipped by the scan workers like a deleted repository
                return (404, vec![], String::new());
            }
            // org info
            (
                200,
                vec![],
                r#"{"login": "acme", "name": "Acme Corp"}"#.to_string(),
            )
        });

        let scanner = token_scanner(false);
        let report =
            investigate_at(&scanner, &address, "acme", Some(1)).expect("the listing must succeed");

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
                std::thread::sleep(std::time::Duration::from_millis(300));
            }
            let line = request.first().map(String::as_str).unwrap_or("");
            if line.contains("/orgs/acme/members") {
                return match page_param(request) {
                    1 => (200, vec![], r#"[{"login": "alice"}]"#.to_string()),
                    _ => (200, vec![], "[]".to_string()),
                };
            }
            if line.contains("/orgs/acme/repos") {
                return match page_param(request) {
                    1 => (
                        200,
                        vec![],
                        r#"[{"name": "one"}, {"name": "two"}]"#.to_string(),
                    ),
                    _ => (200, vec![], "[]".to_string()),
                };
            }
            if line.contains("/repos/acme/one/commits") {
                return match page_param(request) {
                    1 => (200, vec![], full_commit_page("Alice", "alice@acme.com")),
                    _ => (200, vec![], "[]".to_string()),
                };
            }
            if line.contains("/repos/acme/two/commits") {
                return match page_param(request) {
                    1 => (200, vec![], full_commit_page("Bob", "bob@acme.com")),
                    _ => (200, vec![], "[]".to_string()),
                };
            }
            // org info
            (
                200,
                vec![],
                r#"{"login": "acme", "name": "Acme Corp"}"#.to_string(),
            )
        });

        // two tokens: two workers, one dedicated token each
        let scanner = token_scanner(true);
        let report =
            investigate_at(&scanner, &address, "acme", None).expect("the scan must succeed");
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
                return match page_param(request) {
                    1 => (
                        200,
                        vec![],
                        r#"[{"name": "one"}, {"name": "two"}]"#.to_string(),
                    ),
                    _ => (200, vec![], "[]".to_string()),
                };
            }
            if line.contains("/orgs/acme/members") {
                return (200, vec![], "[]".to_string());
            }
            if line.contains("/repos/acme/one/commits") {
                // page 1 holds one commit, page 2 ends the listing: the mock
                // must behave like the API, or fetch_paginated walks every
                // u16 page of the listing
                return match page_param(request) {
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
            (
                200,
                vec![],
                r#"{"login": "acme", "name": "Acme Corp"}"#.to_string(),
            )
        });

        let scanner = token_scanner(false);
        let error = investigate_at(&scanner, &address, "acme", None)
            .expect_err("a token death mid-scan must abort the investigation");
        server.join();
        assert!(
            matches!(error, Error::RateLimitExhausted),
            "unexpected error: {error:?}"
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
                return match page_param(request) {
                    1 => (200, vec![], r#"[{"name": "one"}]"#.to_string()),
                    _ => (200, vec![], "[]".to_string()),
                };
            }
            if line.contains("/orgs/ACME/members") {
                return (200, vec![], "[]".to_string());
            }
            if line.contains("/repos/acme/one/commits") {
                // page 1 holds one commit, page 2 ends the listing: the mock
                // must behave like the API, or fetch_paginated walks every
                // u16 page of the listing
                return match page_param(request) {
                    1 => (
                        200,
                        vec![],
                        format!("[{}]", commit_json("Alice", "alice@acme.com")),
                    ),
                    _ => (200, vec![], "[]".to_string()),
                };
            }
            // org info: the canonical login is lowercase
            (
                200,
                vec![],
                r#"{"login": "acme", "name": "Acme Corp"}"#.to_string(),
            )
        });

        let scanner = token_scanner(false);
        let report =
            investigate_at(&scanner, &address, "ACME", None).expect("the scan must succeed");
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
    fn the_report_serializes_the_documented_json_shape() {
        let report = OrgReport {
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
    }
}
