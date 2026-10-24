use crate::errors::Error;
use regex::Regex;
use std::sync::LazyLock;

/// GitHub project URL (with a repository part).
// The one allowed `expect` of the crate: a static regex failing to compile
// is a programming error that no runtime error handling can recover from.
#[expect(clippy::expect_used)]
static GITHUB_URL: LazyLock<Regex> = LazyLock::new(|| {
    // Compiled once at first use: a static regex failing to compile is a
    // programming error, hence the one `expect` allowed at static
    // initialization.
    Regex::new(r"^((https?|ssh|git|ftps?)://)?(([^/@]+)@)?([^/:]+)[/:]([^/:]+)/(.+)(git)?$")
        .expect("static GitHub URL regex must compile")
});

/// GitHub profile URL (only an author).
// Same as [`GITHUB_URL`]: static-regex compilation cannot fail at runtime.
#[expect(clippy::expect_used)]
static GITHUB_URL_PROFILE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^((https?|ssh|git|ftps?)://)?(([^/@]+)@)?([^/:]+)[/:]([^/:]+)$")
        .expect("static GitHub profile URL regex must compile")
});

/// From a project URL, retrieves its author with regex processing.
///
/// # Errors
///
/// Returns [`Error::InvalidUrl`] when the URL matches neither a repository
/// nor a profile shape (or is empty). Never panics.
pub fn get_author(github_url: String) -> Result<String, Error> {
    if let Some(captures) = GITHUB_URL.captures(&github_url) {
        // we know that it is in group 6 that the author is
        return captures
            .get(6)
            .map(|item| item.as_str().to_string())
            .ok_or_else(|| Error::InvalidUrl("repository author not found".to_string()));
    }
    match GITHUB_URL_PROFILE.captures(&github_url) {
        Some(captures) => captures
            .get(6)
            .map(|item| item.as_str().to_string())
            .ok_or_else(|| Error::InvalidUrl("author could not be found".to_string())),
        None => Err(Error::InvalidUrl("repository author not found".to_string())),
    }
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
    if let Some(captures) = GITHUB_URL.captures(&github_url) {
        // we know that it is in group 7 that the repository is
        return captures
            .get(7)
            .map(|item| item.as_str().to_string())
            .ok_or_else(|| Error::InvalidUrl("repository name not found".to_string()));
    }
    // only author case, URL targets an user profile: there is no repository
    match get_author(github_url) {
        Ok(_) => Ok(String::new()),
        Err(err) => Err(err),
    }
}

#[cfg(test)]
mod tests {
    // Tests may unwrap, expect and panic freely: a failing assertion must
    // be loud, so the zero-panic lints do not apply to the test modules.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;
    use crate::errors::Error;

    // author

    #[test]
    fn get_author_git() {
        assert_eq!(
            get_author("git://github.com/extiop/ctf".to_string()).expect("must parse"),
            "extiop"
        );
    }

    #[test]
    fn get_author_git_at() {
        assert_eq!(
            get_author("git@github.com/extiop/ctf".to_string()).expect("must parse"),
            "extiop"
        );
    }

    #[test]
    fn get_author_https() {
        assert_eq!(
            get_author("https://github.com/extiop/ctf".to_string()).expect("must parse"),
            "extiop"
        );
    }

    #[test]
    fn get_author_ssh() {
        assert_eq!(
            get_author("ssh://github.com/extiop/ctf".to_string()).expect("must parse"),
            "extiop"
        );
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
            get_author("https://github.com/github/extiop/ctf".to_string()).expect("must parse"),
            "github"
        );
    }

    #[test]
    fn get_author_swapped() {
        // author is not retrieved as expected as author and repository are swapped
        assert_eq!(
            get_author("https://github.com/ctf/extiop".to_string()).expect("must parse"),
            "ctf"
        );
    }

    #[test]
    fn get_author_scp_like_ssh_url() {
        // common SSH shorthand with a colon separator
        assert_eq!(
            get_author("git@github.com:extiop/ctf".to_string()).expect("must parse"),
            "extiop"
        );
    }

    #[test]
    fn get_author_without_scheme() {
        assert_eq!(
            get_author("github.com/extiop/ctf".to_string()).expect("must parse"),
            "extiop"
        );
    }

    #[test]
    fn get_author_with_user_info() {
        assert_eq!(
            get_author("https://user@github.com/extiop/ctf".to_string()).expect("must parse"),
            "extiop"
        );
    }

    #[test]
    fn get_author_trailing_slash() {
        assert_eq!(
            get_author("https://github.com/extiop/ctf/".to_string()).expect("must parse"),
            "extiop"
        );
    }

    #[test]
    fn get_author_profile_url() {
        assert_eq!(
            get_author("https://github.com/extiop".to_string()).expect("must parse"),
            "extiop"
        );
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
    fn get_author_any_host_is_accepted() {
        // the regex does not enforce the host: current behavior keeps parsing
        assert_eq!(
            get_author("https://gitlab.com/extiop/ctf".to_string()).expect("must parse"),
            "extiop"
        );
    }

    #[test]
    fn get_author_errors_are_typed() {
        // stringly-typed errors are gone: the error is the crate Error
        match get_author("https://github.com".to_string()) {
            Err(Error::InvalidUrl(details)) => {
                assert_eq!(details, "repository author not found");
            }
            other => panic!("expected Error::InvalidUrl, got {other:?}"),
        }
    }

    // repository

    #[test]
    fn get_get_repository_git() {
        assert_eq!(
            get_repository("git://github.com/extiop/ctf".to_string()).expect("must parse"),
            "ctf"
        );
    }

    #[test]
    fn get_get_repository_git_at() {
        assert_eq!(
            get_repository("git@github.com/extiop/ctf".to_string()).expect("must parse"),
            "ctf"
        );
    }

    #[test]
    fn get_get_repository_https() {
        assert_eq!(
            get_repository("https://github.com/extiop/ctf".to_string()).expect("must parse"),
            "ctf"
        );
    }

    #[test]
    fn get_repository_no_project() {
        assert_eq!(
            get_repository("https://github.com/extiop".to_string()).expect("must parse"),
            ""
        );
    }

    #[test]
    fn get_repository_too_long() {
        // repository is not retrieved as expected
        assert_eq!(
            get_repository("https://github.com/github/extiop/ctf".to_string()).expect("must parse"),
            "extiop/ctf"
        );
    }

    #[test]
    fn get_repository_swapped() {
        // repository is not retrieved as expected as author and repository are swapped
        assert_eq!(
            get_repository("https://github.com/ctf/extiop".to_string()).expect("must parse"),
            "extiop"
        );
    }

    #[test]
    fn get_repository_scp_like_ssh_url() {
        // common SSH shorthand with a colon separator
        assert_eq!(
            get_repository("git@github.com:extiop/ctf".to_string()).expect("must parse"),
            "ctf"
        );
    }

    #[test]
    fn get_repository_without_scheme() {
        assert_eq!(
            get_repository("github.com/extiop/ctf".to_string()).expect("must parse"),
            "ctf"
        );
    }

    #[test]
    fn get_repository_git_suffix_is_kept() {
        // the `(git)?` optional suffix is absorbed by the greedy `(.+)` group:
        // current behavior keeps it in the repository name
        assert_eq!(
            get_repository("https://github.com/extiop/ctf.git".to_string()).expect("must parse"),
            "ctf.git"
        );
    }

    #[test]
    fn get_repository_trailing_slash_is_kept() {
        assert_eq!(
            get_repository("https://github.com/extiop/ctf/".to_string()).expect("must parse"),
            "ctf/"
        );
    }

    #[test]
    fn get_repository_nested_path_is_kept() {
        assert_eq!(
            get_repository("https://github.com/extiop/ctf/internal/tool".to_string())
                .expect("must parse"),
            "ctf/internal/tool"
        );
    }

    #[test]
    fn get_repository_with_user_info() {
        assert_eq!(
            get_repository("https://user@github.com/extiop/ctf".to_string()).expect("must parse"),
            "ctf"
        );
    }

    #[test]
    fn get_repository_empty_url() {
        assert!(get_repository("".to_string()).is_err());
    }
}
