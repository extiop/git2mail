use lazy_static::lazy_static;
use regex::Regex;

struct RegexFields;

impl RegexFields {
    const GITHUB_URL: &'static str =
        r"^((https?|ssh|git|ftps?)://)?(([^/@]+)@)?([^/:]+)[/:]([^/:]+)/(.+)(git)?$";
    const GITHUB_URL_PROFILE: &'static str =
        r"^((https?|ssh|git|ftps?)://)?(([^/@]+)@)?([^/:]+)[/:]([^/:]+)$";
}

/// From a project URL, retrieves its author with regex processing.
pub fn get_author(github_url: &str) -> &str {
    lazy_static! {
        static ref REGEX: Regex = match Regex::new(RegexFields::GITHUB_URL) {
            Ok(regex) => regex,
            _ => panic!("[-] Regex processing went wrong!"),
        };
        static ref REGEX_PROFILE: Regex = match Regex::new(RegexFields::GITHUB_URL_PROFILE) {
            Ok(regex) => regex,
            _ => panic!("[-] Regex processing went wrong!"),
        };
    }
    let author: &str = match REGEX.captures(github_url) {
        Some(captures) => {
            // we know that it is in group 6 that the author
            match captures.get(6) {
                Some(item) => item.as_str(),
                _ => panic!("[-] Repository author not found, aborting scan"),
            }
        }
        _ => match REGEX_PROFILE.captures(github_url) {
            Some(captures) => match captures.get(6) {
                Some(item) => item.as_str(),
                _ => panic!("[-] Author could not be found, aborting scan"),
            },
            _ => panic!("[-] Repository author not found, aborting scan"),
        },
    };
    author
}

/// From a project URL, retrieves its repository with regex processing.
pub fn get_repository(github_url: &str) -> &str {
    lazy_static! {
        static ref REGEX: Regex = match Regex::new(RegexFields::GITHUB_URL) {
            Ok(regex) => regex,
            _ => panic!("[-] Regex processing went wrong!"),
        };
    }
    let repository: &str = match REGEX.captures(github_url) {
        Some(captures) => {
            // we know that it is in group 7 that the author
            match captures.get(7) {
                Some(item) => item.as_str(),
                _ => panic!("[-] Repository name not found, aborting scan"),
            }
        }
        _ => {
            // only author case, URL targets an user profile
            if !get_author(github_url).is_empty() {
                ""
            } else {
                panic!("[-] Repository name not found, aborting scan");
            }
        }
    };
    repository
}

#[cfg(test)]
mod tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;

    // author

    #[test]
    fn get_author_git() {
        assert_eq!(get_author("git://github.com/exti0p/ctf"), "exti0p");
    }

    #[test]
    fn get_author_git_at() {
        assert_eq!(get_author("git@github.com/exti0p/ctf"), "exti0p");
    }

    #[test]
    fn get_author_https() {
        assert_eq!(get_author("https://github.com/exti0p/ctf"), "exti0p");
    }

    #[test]
    fn get_author_ssh() {
        assert_eq!(get_author("ssh://github.com/exti0p/ctf"), "exti0p");
    }

    #[test]
    #[should_panic(expected = "[-] Repository author not found, aborting scan")]
    fn get_author_too_short() {
        assert_eq!(get_author("https://github.com"), "exti0p");
    }

    #[test]
    fn get_author_too_long() {
        // author is not retrieved as expected
        assert_eq!(get_author("https://github.com/github/exti0p/ctf"), "github");
    }

    #[test]
    fn get_author_swapped() {
        // author is not retrieved as expected as author and repository are swapped
        assert_eq!(get_author("https://github.com/ctf/exti0p"), "ctf");
    }

    // repository

    #[test]
    fn get_get_repository_git() {
        assert_eq!(get_repository("git://github.com/exti0p/ctf"), "ctf");
    }

    #[test]
    fn get_get_repository_git_at() {
        assert_eq!(get_repository("git@github.com/exti0p/ctf"), "ctf");
    }

    #[test]
    fn get_get_repository_https() {
        assert_eq!(get_repository("https://github.com/exti0p/ctf"), "ctf");
    }

    #[test]
    fn get_get_repository_ssh() {
        assert_eq!(get_repository("ssh://github.com/exti0p/ctf"), "ctf");
    }

    #[test]
    // #[should_panic(expected = "[-] Repository name not found, aborting scan")]
    fn get_repository_no_project() {
        assert_eq!(get_repository("https://github.com/exti0p"), "");
    }

    #[test]
    fn get_repository_too_long() {
        // repository is not retrieved as expected
        assert_eq!(
            get_repository("https://github.com/github/exti0p/ctf"),
            "exti0p/ctf"
        );
    }

    #[test]
    fn get_repository_swapped() {
        // repository is not retrieved as expected as author and repository are swapped
        assert_eq!(get_repository("https://github.com/ctf/exti0p"), "exti0p");
    }
}
