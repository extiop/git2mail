use crate::errors::Error;
use regex::Regex;
use std::sync::LazyLock;

/// Cuts a pasted URL down to its address: leading/trailing whitespace is
/// trimmed and the github.com page-navigation paste artifacts (`?query`,
/// `#fragment` — `?tab=repositories`, `?plain=1#L12`, `#readme`…) are
/// stripped, before either regex runs. Applied to both URL shapes so a
/// `?tab=repositories` suffix on a profile URL is classified as a profile
/// (no repository part) instead of a repository whose name holds the whole
/// artifact, and so neither shape reaches the API percent-encoding a
/// guaranteed-404 request. No GitHub login or repository name contains
/// `?`, `#` or surrounding whitespace, so the cut can never mangle a real
/// target (unlike the `.git` suffix, which is kept verbatim, documented).
fn normalize_pasted_url(github_url: &str) -> &str {
    // `split` always yields at least one item: the fallback is the
    // never-panic degradation the crate's zero-panic lints require
    github_url
        .trim()
        .split(['?', '#'])
        .next()
        .unwrap_or(github_url)
}

/// Upper bound on the URL length the parsers accept. A GitHub URL this tool
/// can act on is a few dozen characters (login ≤ 39, repository name ≤ 100,
/// plus scheme and paste artifacts); the capture-slot extraction over the
/// regexes' greedy tail group costs on the order of a microsecond per
/// character, so a megabyte-scale paste or hostile API-supplied `html_url`
/// would otherwise burn seconds of CPU per parse before failing as
/// unparseable anyway. Past the bound the URL fails with the same
/// [`Error::InvalidUrl`] the shape regexes produce, immediately.
const MAX_URL_LEN: usize = 2048;

/// Fails an over-long URL before the regexes run: same [`Error::InvalidUrl`]
/// contract as a shape mismatch, without the per-character parse cost.
fn check_url_len(github_url: &str) -> Result<(), Error> {
    if github_url.len() > MAX_URL_LEN {
        return Err(Error::InvalidUrl(format!(
            "URL is too long ({} bytes, the maximum is {MAX_URL_LEN})",
            github_url.len()
        )));
    }
    Ok(())
}

/// The only hosts a web URL may point at (case-insensitively, the `www.`
/// alias included): the documented web URL formats are all github.com.
const WEB_URL_HOSTS: [&str; 2] = ["github.com", "www.github.com"];

/// Rejects a http(s), `git://`, `ftp` or `ftps` URL whose host is not
/// github.com, before any regex or API work. The parsers used to accept any host: a pasted
/// `https://gitlab.com/a/b` was silently re-targeted onto api.github.com
/// and the scan reported "GitHub resource not found" after a guaranteed-404
/// run — telling the user a *GitHub* resource was missing when the actual
/// problem is that the URL was never a GitHub one (live repro). The
/// documented `ssh://git@github.com/...` form keeps parsing; any other
/// `ssh://` host is rejected with the same named error (the API base is
/// hardcoded to api.github.com, so a self-hosted remote would be scanned
/// against the github.com namesake), and scheme-less (`git@github.com:…`)
/// and other-scheme URLs keep the current behavior.
fn check_url_host(github_url: &str) -> Result<(), Error> {
    let Some((scheme, rest)) = github_url.split_once("://") else {
        // no scheme (`git@github.com:octocat/hello-world`): nothing to judge here
        return Ok(());
    };
    // an `ssh://` remote to a NON-GitHub host is the same wrong-target scan
    // the scheme-less rejection exists for: the API base is hardcoded to
    // api.github.com, so scanning a GitLab/Gitea remote's ssh:// URL would
    // silently hit the github.com NAMESAKE with the user's own token. The
    // documented `ssh://git@github.com/...` passthrough keeps parsing
    // (github.com passes the host check below); any other ssh:// host gets
    // the same named error
    if scheme.eq_ignore_ascii_case("ssh") {
        let authority = rest.split('/').next().unwrap_or("");
        let host = authority
            .rsplit_once('@')
            .map_or(authority, |(_, host)| host)
            .to_ascii_lowercase();
        // a port on an ssh:// authority gets the same dedicated message as
        // the http(s) branch (github.com:22 is github.com on the WRONG
        // port, not a non-GitHub host)
        if host.contains(':') {
            return Err(Error::InvalidUrl(format!(
                "unsupported port in {host}: git2mail talks to the GitHub API on the standard port only"
            )));
        }
        if !WEB_URL_HOSTS.contains(&host.as_str()) {
            return Err(Error::InvalidUrl(format!(
                "unsupported host {host}: an ssh:// remote to a non-GitHub host would be scanned against the github.com namesake"
            )));
        }
    }
    if !matches!(
        scheme.to_ascii_lowercase().as_str(),
        "http" | "https" | "git" | "ftp" | "ftps"
    ) {
        return Ok(());
    }
    // the authority ends at the first `/` (or paste artifact, cut by
    // normalize_pasted_url upstream); the userinfo is split on its own `@`
    // first, so a `user:pass@host` prefix (whose `:` would otherwise be
    // mistaken for a port separator) does not hide the host
    let authority = rest.split('/').next().unwrap_or("");
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host)
        .to_ascii_lowercase();
    if host.is_empty() || WEB_URL_HOSTS.contains(&host.as_str()) {
        // an empty authority is not a host problem: the shape regexes
        // produce their usual errors for it
        return Ok(());
    }
    // an explicit port is its own, more precise rejection: the URL clearly
    // points at github.com but on a port the API client cannot use
    if host.contains(':') {
        return Err(Error::InvalidUrl(format!(
            "unsupported port in {host}: git2mail talks to the GitHub API on the standard port only"
        )));
    }
    Err(Error::InvalidUrl(format!(
        "unsupported host {host}: git2mail only investigates github.com URLs"
    )))
}

/// Whether a URL part is a dot segment: never a valid GitHub login or
/// repository name, and normalized away by the url crate when the API path
/// is built, which would silently re-target the authenticated request to
/// another api.github.com path (a hostile or malformed listing-derived
/// `html_url` can carry one).
fn is_dot_segment(part: &str) -> bool {
    part == "." || part == ".."
}

/// Rejects a shape-valid URL whose target is not GitHub. Two gaps the
/// host check cannot see, because they hide one regex group deeper:
/// a scheme-less paste naming another forge (`gitlab.com/octocat/hello-world`) is
/// scanned against the github.com namesake of its path — the same
/// wrong-target class [`check_url_host`] closes for scheme'd URLs (its own
/// guard only runs on a `://`); and a dot segment (`.`/`..`) in the author
/// or repository slot survives every check, then the url crate collapses
/// `{base}/repos/../X/commits` into `{base}/X/commits` when the API path
/// is built, silently re-targeting the authenticated request. The
/// documented `git@github.com:owner/repo` SCP form (github.com host, no
/// dot segment) and a bare `owner/repository` (no dot in the host slot)
/// still parse. The `ssh://git@github.com/…` passthrough is
/// untouched: this helper only fires on scheme-less URLs, and the `ssh://`
/// host judgment lives entirely in [`check_url_host`] (GitHub remotes
/// only).
fn check_url_target(github_url: &str, captures: &regex::Captures<'_>) -> Result<(), Error> {
    let host = captures.get(5).map_or("", |item| item.as_str());
    if !github_url.contains("://")
        && host.contains('.')
        && !WEB_URL_HOSTS.contains(&host.to_ascii_lowercase().as_str())
    {
        return Err(Error::InvalidUrl(format!(
            "unsupported host {host}: git2mail only investigates github.com URLs"
        )));
    }
    let dot_segment = captures
        .get(6)
        .is_some_and(|item| is_dot_segment(item.as_str()))
        || captures
            .get(7)
            .is_some_and(|item| item.as_str().split('/').any(is_dot_segment));
    if dot_segment {
        return Err(Error::InvalidUrl(
            "a dot segment is not a valid GitHub owner or repository name".to_string(),
        ));
    }
    Ok(())
}

/// Whether a listing-derived repository name can be composed into a scan
/// URL: non-empty, no dot segment (the url crate normalizes `..` into a
/// re-targeted request) and no path separator or query/fragment
/// introducer (a `?`/`#` would silently truncate the scanned repository
/// and desynchronize the per-repository report keys). GitHub listing
/// names never carry any of these: an entry that does is a broken or
/// hostile payload, skipped with a warning by the composing caller.
pub(crate) fn is_safe_repository_name(name: &str) -> bool {
    !name.is_empty() && !is_dot_segment(name) && !name.contains(['/', '?', '#'])
}

/// GitHub project URL (with a repository part).
// The one allowed `expect` of the crate: a static regex failing to compile
// is a programming error that no runtime error handling can recover from.
#[expect(clippy::expect_used)]
static GITHUB_URL: LazyLock<Regex> = LazyLock::new(|| {
    // Compiled once at first use: a static regex failing to compile is a
    // programming error, hence the one `expect` allowed at static
    // initialization. The scheme group is matched
    // case-insensitively by spelling both cases out (the crate's `regex`
    // build has no `unicode-case` feature, so `(?i:)` is unavailable, and
    // the scope is the scheme only, so logins keep their case): RFC 3986
    // makes the scheme case-insensitive, and `HTTPS://GITHUB.COM/…` must
    // parse exactly like its lowercase form (the host already does).
    Regex::new(
        r"^(([hH][tT][tT][pP][sS]?|[sS][sS][hH]|[gG][iI][tT]|[fF][tT][pP][sS]?)://)?(([^/@]+)@)?([^/:]+)[/:]([^/:]+)/(.+)(git)?$",
    )
    .expect("static GitHub URL regex must compile")
});

/// GitHub profile URL (only an author).
// Same as [`GITHUB_URL`]: static-regex compilation cannot fail at runtime.
#[expect(clippy::expect_used)]
static GITHUB_URL_PROFILE: LazyLock<Regex> = LazyLock::new(|| {
    // scheme case-insensitivity: same rule (and same hand-spelled classes)
    // as [`GITHUB_URL`]
    Regex::new(
        r"^(([hH][tT][tT][pP][sS]?|[sS][sS][hH]|[gG][iI][tT]|[fF][tT][pP][sS]?)://)?(([^/@]+)@)?([^/:]+)[/:]([^/:]+)$",
    )
    .expect("static GitHub profile URL regex must compile")
});

/// Parses a GitHub URL once into its `(author, repository)` parts: the
/// shared normalize-validate-match pass behind [`get_author`] and
/// [`get_repository`]. `repository` is `Some` only for a repository URL
/// (a profile URL yields `None`); a trailing `/` paste artifact on the
/// repository part is trimmed, while the `.git` suffix is kept verbatim
/// (documented behavior).
///
/// # Errors
///
/// Returns [`Error::InvalidUrl`] when the URL matches neither a repository
/// nor a profile shape (or is empty). Never panics.
pub fn parse_github_url(github_url: &str) -> Result<(String, Option<String>), Error> {
    let github_url = normalize_pasted_url(github_url);
    check_url_len(github_url)?;
    check_url_host(github_url)?;
    if let Some(captures) = GITHUB_URL.captures(github_url) {
        check_url_target(github_url, &captures)?;
        // the author is group 6, the repository group 7
        let author = captures
            .get(6)
            .map(|item| item.as_str().to_string())
            .ok_or_else(|| {
                Error::InvalidUrl(
                    "this URL does not point to a GitHub repository or profile — use \
                     https://github.com/owner/repository or https://github.com/owner"
                        .to_string(),
                )
            })?;
        let repository = captures
            .get(7)
            .map(|item| {
                // a trailing `/` is a trivially common paste artifact
                // (`https://github.com/octocat/hello-world/`), never part of a
                // repository name: left in, it would be percent-encoded
                // into an unresolvable `/repos/octocat/hello-world%2F/commits`
                // request (a guaranteed 404 on an existing repository).
                // Unlike the `.git` suffix, which is kept verbatim
                // (documented behavior), it can never be part of a name.
                item.as_str().trim_end_matches('/')
            })
            .filter(|name| !name.is_empty())
            .map(String::from)
            // a URL that matched the repository shape but carries no
            // repository after trimming (`…/octocat//`) is a malformed
            // paste, not a profile: the author is right there but the target
            // is still unusable
            .ok_or_else(|| {
                Error::InvalidUrl(
                    "this URL does not point to a GitHub repository or profile — use a URL like https://github.com/owner/repository".to_string(),
                )
            })?;
        return Ok((author, Some(repository)));
    }
    match GITHUB_URL_PROFILE.captures(github_url) {
        Some(captures) => {
            check_url_target(github_url, &captures)?;
            let author = captures
                .get(6)
                .map(|item| item.as_str().to_string())
                .ok_or_else(|| Error::InvalidUrl("author could not be found".to_string()))?;
            Ok((author, None))
        }
        // a profile URL pasted with a trailing `/` fails the regex while the
        // identical paste artifact on a repository URL is trimmed elsewhere:
        // name the actual fix instead of blaming an author that is right
        // there in the URL
        None if github_url.ends_with('/') => Err(Error::InvalidUrl(
            "profile URL ends with '/': remove the trailing slash, e.g. https://github.com/some-user"
                .to_string(),
        )),
        None => Err(Error::InvalidUrl(
            "this URL does not point to a GitHub repository or profile — use \
             https://github.com/owner/repository or https://github.com/owner"
                .to_string(),
        )),
    }
}

/// From a project URL, retrieves its author with regex processing.
///
/// # Errors
///
/// Returns [`Error::InvalidUrl`] when the URL matches neither a repository
/// nor a profile shape (or is empty). Never panics.
pub fn get_author(github_url: String) -> Result<String, Error> {
    parse_github_url(&github_url).map(|(author, _)| author)
}

/// From a project URL, retrieves its repository with regex processing.
///
/// A profile URL has no repository part: an empty string is returned in that
/// case (this is how callers distinguish a profile scan from a scan).
///
/// # Errors
///
/// Returns [`Error::InvalidUrl`] when the URL matches neither a repository
/// nor a profile shape (or is empty). Never panics.
pub fn get_repository(github_url: String) -> Result<String, Error> {
    // a profile URL has no repository part: an empty string is returned in
    // that case (this is how callers distinguish a profile scan from a
    // repository scan)
    parse_github_url(&github_url).map(|(_, repository)| repository.unwrap_or_default())
}

#[cfg(test)]
mod tests {
    // Tests may unwrap, expect and panic freely: a failing assertion must
    // be loud, so the zero-panic lints do not apply to the test modules.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::errors::Error;

    // author

    #[test]
    fn get_author_and_get_repository_reject_an_over_long_url() {
        // the capture-slot extraction over the regexes' greedy tail group
        // costs on the order of a microsecond per character: a megabyte-scale
        // paste (or hostile API-supplied html_url) must hit the length bound
        // and fail immediately, not burn seconds of CPU per parse before
        // failing as unparseable anyway
        let padded = format!("https://github.com/octocat/{}", "r".repeat(10_000));
        let error = get_author(padded.clone()).expect_err("an over-long URL must be rejected");
        assert!(matches!(error, Error::InvalidUrl(details) if details.contains("too long")));
        let error = get_repository(padded).expect_err("an over-long URL must be rejected");
        assert!(matches!(error, Error::InvalidUrl(details) if details.contains("too long")));
        // a long-but-bounded URL still parses: the bound only stops the
        // pathological tail
        let long_but_valid = format!("https://github.com/octocat/{}", "r".repeat(2000));
        assert_eq!(
            get_author(long_but_valid.clone()).expect("a bounded URL must still parse"),
            "octocat"
        );
        assert_eq!(
            get_repository(long_but_valid).expect("a bounded URL must still parse"),
            "r".repeat(2000)
        );
        // the bound applies to the normalized URL: paste artifacts cut
        // before the check do not count against it
        let artifact_padded = format!(
            "https://github.com/octocat/hello-world?{}",
            "x".repeat(10_000)
        );
        assert_eq!(
            get_repository(artifact_padded).expect("the trimmed URL must still parse"),
            "hello-world"
        );
    }

    #[test]
    fn get_author_userinfo_does_not_hide_the_host() {
        // a `user:pass@host` prefix must not be mistaken for a port-bearing
        // authority (the old split-on-':' took `user` for the host): the
        // real host is judged, and a foreign host under userinfo is refused
        assert_eq!(
            get_author("https://user:pass@github.com/octocat/hello-world".to_string())
                .expect("the userinfo prefix must not hide github.com"),
            "octocat"
        );
        let error = get_author("https://github.com@evil.com/octocat/hello-world".to_string())
            .expect_err("the rightmost @ wins: evil.com is not github.com");
        assert!(
            matches!(&error, Error::InvalidUrl(details) if details.contains("evil.com")),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn get_author_rejects_an_explicit_port_with_a_dedicated_message() {
        // the guard used to reject a port-bearing URL with the generic
        // "unsupported host github.com:443" wording, which read like a
        // wrong-target complaint; the port now has its own message
        let error = get_author("https://github.com:443/octocat/hello-world".to_string())
            .expect_err("a port-bearing URL must be rejected");
        assert!(
            matches!(&error, Error::InvalidUrl(details) if details.contains("port")),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn get_author_git() {
        assert_eq!(
            get_author("git://github.com/octocat/hello-world".to_string()).expect("must parse"),
            "octocat"
        );
    }

    #[test]
    fn get_author_git_at() {
        assert_eq!(
            get_author("git@github.com/octocat/hello-world".to_string()).expect("must parse"),
            "octocat"
        );
    }

    #[test]
    fn get_author_https() {
        assert_eq!(
            get_author("https://github.com/octocat/hello-world".to_string()).expect("must parse"),
            "octocat"
        );
    }

    #[test]
    fn get_author_ssh() {
        assert_eq!(
            get_author("ssh://github.com/octocat/hello-world".to_string()).expect("must parse"),
            "octocat"
        );
    }

    #[test]
    fn get_author_rejects_an_ssh_port_with_the_dedicated_message() {
        // github.com:22 is github.com on the WRONG port, not a non-GitHub
        // host: the ssh branch must name the port, not accuse the host
        let error = get_author("ssh://github.com:22/octocat/hello-world".to_string())
            .expect_err("a port-bearing ssh URL must be rejected");
        assert!(
            matches!(&error, Error::InvalidUrl(details) if details.contains("port")),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn get_author_rejects_a_trailing_dot_host() {
        // DNS resolves github.com. to github.com: the host allowlist must
        // not, so the trailing-dot form cannot smuggle past the guard
        for url in [
            "https://github.com./octocat/hello-world",
            "github.com./octocat/hello-world",
        ] {
            let error =
                get_author(url.to_string()).expect_err("a trailing-dot host must be rejected");
            assert!(
                matches!(&error, Error::InvalidUrl(details) if details.contains("unsupported host")),
                "unexpected error: {error}"
            );
        }
    }

    #[test]
    fn get_author_rejects_a_protocol_relative_url() {
        // no scheme and no user@host shape: rejected by URL shape (fails
        // closed even though the host is GitHub's)
        assert!(matches!(
            get_author("//github.com/octocat/hello-world".to_string()),
            Err(Error::InvalidUrl(_))
        ));
    }

    #[test]
    fn get_author_too_short() {
        assert!(matches!(
            get_author("https://github.com".to_string()),
            Err(Error::InvalidUrl(_))
        ));
    }

    #[test]
    fn get_author_too_long() {
        // author is not retrieved as expected
        assert_eq!(
            get_author("https://github.com/github/octocat/hello-world".to_string())
                .expect("must parse"),
            "github"
        );
    }

    #[test]
    fn get_author_swapped() {
        // author is not retrieved as expected as author and repository are swapped
        assert_eq!(
            get_author("https://github.com/hello-world/octocat".to_string()).expect("must parse"),
            "hello-world"
        );
    }

    #[test]
    fn get_author_scp_like_ssh_url() {
        // common SSH shorthand with a colon separator
        assert_eq!(
            get_author("git@github.com:octocat/hello-world".to_string()).expect("must parse"),
            "octocat"
        );
    }

    #[test]
    fn get_author_without_scheme() {
        assert_eq!(
            get_author("github.com/octocat/hello-world".to_string()).expect("must parse"),
            "octocat"
        );
    }

    #[test]
    fn get_author_with_user_info() {
        assert_eq!(
            get_author("https://user@github.com/octocat/hello-world".to_string())
                .expect("must parse"),
            "octocat"
        );
    }

    #[test]
    fn get_author_trailing_slash() {
        assert_eq!(
            get_author("https://github.com/octocat/hello-world/".to_string()).expect("must parse"),
            "octocat"
        );
    }

    #[test]
    fn get_author_profile_url() {
        assert_eq!(
            get_author("https://github.com/octocat".to_string()).expect("must parse"),
            "octocat"
        );
    }

    #[test]
    fn get_author_profile_url_trailing_slash_is_rejected() {
        // a profile URL has no name after its separator, so a trailing `/`
        // cannot be trimmed away like the repository case: the paste
        // artifact is rejected outright instead of resolving into a
        // guaranteed-404 request against an empty name
        assert!(matches!(
            get_author("https://github.com/octocat/".to_string()),
            Err(Error::InvalidUrl(_))
        ));
    }

    #[test]
    fn get_author_empty_url() {
        assert!(get_author("".to_string()).is_err());
    }

    #[test]
    fn get_author_no_path_at_all() {
        assert!(get_author("https://github.com/".to_string()).is_err());
    }

    #[test]
    fn get_author_and_get_repository_reject_a_non_github_host_in_a_scheme_less_url() {
        // the scheme'd host guard cannot see a scheme-less paste: its
        // judgment only runs on a `://`, so `gitlab.com/octocat/hello-world` used to
        // be scanned against the github.com namesake of its path — the same
        // wrong-target class, hidden one regex group deeper (the guard's
        // own test only covered scheme'd URLs)
        for url in [
            "gitlab.com/octocat/hello-world",
            "GitLab.com/octocat/hello-world",
            "git@gitlab.com:octocat/hello-world",
            "github.com.evil.com/octocat/hello-world",
        ] {
            let error =
                get_author(url.to_string()).expect_err("a non-github host must be rejected");
            assert!(
                matches!(&error, Error::InvalidUrl(details) if details.contains("unsupported host")),
                "unexpected error for {url}: {error:?}"
            );
        }
        // a bare `owner/repository` (no dot in the host slot) and the
        // documented `git@github.com:owner/repo` SCP form still parse
        assert!(get_author("octocat/hello-world".to_string()).is_ok());
        assert_eq!(
            get_author("git@github.com:octocat/hello-world".to_string()).expect("must parse"),
            "octocat"
        );
    }

    #[test]
    fn get_author_and_get_repository_reject_dot_segments() {
        // a dot segment is never a valid login or repository name: the url
        // crate normalizes `{base}/repos/../X/commits` into
        // `{base}/X/commits`, so a hostile or malformed listing `html_url`
        // carrying one would silently re-target the authenticated request
        // to another api.github.com path
        for url in [
            "https://github.com/../repo",
            "https://github.com/./repo",
            "https://github.com/owner/..",
            "git@github.com:../octocat/hello-world",
            // EMBEDDED dot segments: the repository capture is `(.+)`, so a
            // hostile `a/../b` rides inside a shape-valid name — and
            // percent_encode leaves `.` untouched (RFC 3986 unreserved), so
            // the url crate still collapses it at request-build time
            "https://github.com/octocat/a/../b",
            "https://github.com/octocat/a/../..",
            "https://github.com/octocat/../a/b",
        ] {
            let error =
                get_author(url.to_string()).expect_err("a dot-segment part must be rejected");
            assert!(
                matches!(&error, Error::InvalidUrl(details) if details.contains("dot segment")),
                "unexpected error for {url}: {error:?}"
            );
            let error =
                get_repository(url.to_string()).expect_err("a dot-segment part must be rejected");
            assert!(
                matches!(&error, Error::InvalidUrl(details) if details.contains("dot segment")),
                "unexpected error for {url}: {error:?}"
            );
        }
    }

    #[test]
    fn is_safe_repository_name_rejects_url_corrupting_names() {
        for name in ["", ".", "..", "a/b", "x?y", "x#y"] {
            assert!(!is_safe_repository_name(name), "{name:?} must be rejected");
        }
        for name in ["hello-world", "my.repo", "git2mail"] {
            assert!(is_safe_repository_name(name), "{name:?} must be accepted");
        }
    }

    #[test]
    fn get_author_rejects_a_non_github_web_host_instead_of_retargeting_the_scan() {
        // the regexes do not enforce the host, and any-host parsing used to
        // silently re-target the scan onto api.github.com: a pasted
        // `https://gitlab.com/a/b` (or any other forge) reported "GitHub
        // resource not found" after a guaranteed-404 run, telling the user
        // a GitHub resource was missing when the URL was never a GitHub one
        // (live repro). A http(s)/git:// URL on another host is now rejected
        // with the offending host named, before any scan runs
        for url in [
            "https://gitlab.com/octocat/hello-world",
            "http://gitlab.com/octocat/hello-world",
            "git://gitlab.com/octocat/hello-world",
            "https://github.com.evil.com/octocat/hello-world",
            "HTTPS://GitLab.COM/octocat",
        ] {
            let error =
                get_author(url.to_string()).expect_err("a non-github web host must be rejected");
            assert!(
                matches!(&error, Error::InvalidUrl(details) if details.contains("unsupported host")),
                "unexpected error for {url}: {error:?}"
            );
            let error = get_repository(url.to_string())
                .expect_err("a non-github web host must be rejected");
            assert!(
                matches!(&error, Error::InvalidUrl(details) if details.contains("unsupported host")),
                "unexpected error for {url}: {error:?}"
            );
        }
        // the error names the offending host
        let error = get_author("https://gitlab.com/octocat/hello-world".to_string())
            .expect_err("must fail");
        assert!(
            error.to_string().contains("gitlab.com"),
            "the error must name the offending host: {error}"
        );
        // the github.com hosts are accepted, case-insensitively, `www.`
        // alias included
        assert_eq!(
            get_author("https://GitHub.com/octocat/hello-world".to_string()).expect("must parse"),
            "octocat"
        );
        assert_eq!(
            get_author("https://www.github.com/octocat/hello-world".to_string())
                .expect("must parse"),
            "octocat"
        );
        // the documented ssh:// passthrough covers GitHub remotes only
        assert_eq!(
            get_author("ssh://git@github.com/octocat/hello-world".to_string()).expect("must parse"),
            "octocat"
        );
        // an ssh:// remote to a NON-GitHub host is rejected: the API base is
        // hardcoded to api.github.com, so scanning it would silently hit the
        // github.com NAMESAKE with the user's own token attached
        let error = get_author("ssh://git@domain.com/group/app".to_string())
            .expect_err("a non-GitHub ssh:// host must be rejected");
        assert!(
            error.to_string().contains("domain.com"),
            "the error must name the host: {error}"
        );
        // and so is the scheme-less documented form
        assert_eq!(
            get_author("git@github.com:octocat/hello-world".to_string()).expect("must parse"),
            "octocat"
        );
    }

    #[test]
    fn get_author_errors_are_typed() {
        // stringly-typed errors are gone: the error is the crate Error
        match get_author("https://github.com".to_string()) {
            Err(Error::InvalidUrl(details)) => {
                assert_eq!(
                    details,
                    "this URL does not point to a GitHub repository or profile — use \
                     https://github.com/owner/repository or https://github.com/owner"
                );
            }
            other => panic!("expected Error::InvalidUrl, got {other:?}"),
        }
    }

    // repository

    #[test]
    fn get_repository_git_protocol() {
        assert_eq!(
            get_repository("git://github.com/octocat/hello-world".to_string()).expect("must parse"),
            "hello-world"
        );
    }

    #[test]
    fn get_repository_git_at_syntax() {
        assert_eq!(
            get_repository("git@github.com/octocat/hello-world".to_string()).expect("must parse"),
            "hello-world"
        );
    }

    #[test]
    fn get_repository_https_url() {
        assert_eq!(
            get_repository("https://github.com/octocat/hello-world".to_string())
                .expect("must parse"),
            "hello-world"
        );
    }

    #[test]
    fn get_repository_no_project() {
        assert_eq!(
            get_repository("https://github.com/octocat".to_string()).expect("must parse"),
            ""
        );
    }

    #[test]
    fn get_repository_profile_trailing_slash_is_rejected() {
        // the same profile-shape rejection seen from the repository parser:
        // a lone trailing `/` after the author is not a repository name
        assert!(matches!(
            get_repository("https://github.com/octocat/".to_string()),
            Err(Error::InvalidUrl(_))
        ));
    }

    #[test]
    fn get_repository_swapped() {
        // repository is not retrieved as expected as author and repository are swapped
        assert_eq!(
            get_repository("https://github.com/hello-world/octocat".to_string())
                .expect("must parse"),
            "octocat"
        );
    }

    #[test]
    fn get_repository_scp_like_ssh_url() {
        // common SSH shorthand with a colon separator
        assert_eq!(
            get_repository("git@github.com:octocat/hello-world".to_string()).expect("must parse"),
            "hello-world"
        );
    }

    #[test]
    fn get_repository_without_scheme() {
        assert_eq!(
            get_repository("github.com/octocat/hello-world".to_string()).expect("must parse"),
            "hello-world"
        );
    }

    #[test]
    fn get_repository_trailing_slash_is_trimmed() {
        // a trailing `/` is a paste artifact, never part of a repository
        // name: percent-encoding it (`hello-world%2F`) would make the scan a
        // guaranteed 404 on an existing repository
        assert_eq!(
            get_repository("https://github.com/octocat/hello-world/".to_string())
                .expect("must parse"),
            "hello-world"
        );
        // several trailing slashes are paste noise too, and a name made only
        // of slashes is not a repository
        assert_eq!(
            get_repository("https://github.com/octocat/hello-world//".to_string())
                .expect("must parse"),
            "hello-world"
        );
        assert!(matches!(
            get_repository("https://github.com/octocat//".to_string()),
            Err(Error::InvalidUrl(_))
        ));
    }

    #[test]
    fn get_repository_strips_query_and_fragment_paste_artifacts() {
        // github.com page-navigation paste artifacts (`?tab=readme-ov-file`,
        // `?plain=1#L12`, `#readme`) are never part of a repository name:
        // left in, they are percent-encoded into an unresolvable
        // `/repos/octocat/Hello-World%3Ftab%3D…` request — a misleading
        // "GitHub resource not found" on an existing repository (live
        // repro). No GitHub repository name contains `?` or `#`.
        for url in [
            "https://github.com/octocat/Hello-World?tab=readme-ov-file",
            "https://github.com/octocat/Hello-World?plain=1#L12",
            "https://github.com/octocat/Hello-World#readme",
            "https://github.com/octocat/Hello-World/",
        ] {
            assert_eq!(
                get_repository(url.to_string()).expect("must parse"),
                "Hello-World",
                "wrong repository for {url}"
            );
            assert_eq!(
                get_author(url.to_string()).expect("must parse"),
                "octocat",
                "wrong author for {url}"
            );
        }
    }

    #[test]
    fn get_repository_git_suffix_is_still_kept_verbatim() {
        // the documented `.git` passthrough is unaffected by the trailing-
        // slash trim: only slashes are trimmed, never a `.git` suffix
        assert_eq!(
            get_repository("https://github.com/octocat/hello-world.git".to_string())
                .expect("must parse"),
            "hello-world.git"
        );
        assert_eq!(
            get_repository("https://github.com/octocat/hello-world.git/".to_string())
                .expect("must parse"),
            "hello-world.git"
        );
    }

    #[test]
    fn get_repository_nested_path_is_kept() {
        assert_eq!(
            get_repository("https://github.com/octocat/hello-world/internal/tool".to_string())
                .expect("must parse"),
            "hello-world/internal/tool"
        );
    }

    #[test]
    fn get_repository_with_user_info() {
        assert_eq!(
            get_repository("https://user@github.com/octocat/hello-world".to_string())
                .expect("must parse"),
            "hello-world"
        );
    }

    #[test]
    fn get_repository_empty_url() {
        assert!(get_repository("".to_string()).is_err());
    }

    // scheme case-insensitivity (RFC 3986): an uppercase-scheme URL must
    // parse exactly like its lowercase form, with the login/repository case
    // preserved (the host already matched case-insensitively)
    #[test]
    fn get_author_and_repository_accept_an_uppercase_scheme() {
        for url in [
            "HTTPS://GITHUB.COM/Octocat/Hello-World",
            "Http://GitHub.com/Octocat/Hello-World",
            "SSH://github.com/Octocat/Hello-World",
            "GIT@GitHub.com:Octocat/Hello-World",
        ] {
            assert_eq!(
                get_author(url.to_string()).expect("must parse"),
                "Octocat",
                "wrong author for {url}"
            );
            assert_eq!(
                get_repository(url.to_string()).expect("must parse"),
                "Hello-World",
                "wrong repository for {url}"
            );
        }
    }

    // the single most-pasted profile URL suffix (`?tab=repositories`) and
    // its fragment cousin must classify the URL as a profile (no repository
    // part), not as a repository named after the artifact-stripped author —
    // the pre-fix behavior sent `/repos/{author}/{author}/commits` and
    // failed with a misleading "GitHub resource not found" on an existing
    // profile (live repro)
    #[test]
    fn get_repository_profile_paste_artifacts_resolve_to_profile_mode() {
        for url in [
            "https://github.com/octocat?tab=repositories",
            "https://github.com/octocat#repositories",
            "https://github.com/octocat?tab=repositories&foo=1#bar",
        ] {
            assert_eq!(
                get_repository(url.to_string()).expect("must parse"),
                "",
                "{url} must resolve to a profile scan"
            );
            assert_eq!(
                get_author(url.to_string()).expect("must parse"),
                "octocat",
                "wrong author for {url}"
            );
        }
    }

    // surrounding whitespace is a paste artifact too: a trailing space is
    // otherwise percent-encoded into a guaranteed-404 `%20` request (live
    // repro on the repository shape)
    #[test]
    fn get_author_and_repository_strip_surrounding_whitespace() {
        assert_eq!(
            get_author("  https://github.com/octocat/Hello-World\t".to_string())
                .expect("must parse"),
            "octocat"
        );
        assert_eq!(
            get_repository("https://github.com/octocat/Hello-World ".to_string())
                .expect("must parse"),
            "Hello-World"
        );
        assert_eq!(
            get_repository("https://github.com/octocat ".to_string()).expect("must parse"),
            "",
            "a whitespace-padded profile URL stays a profile"
        );
    }
}
