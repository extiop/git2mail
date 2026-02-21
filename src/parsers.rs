use regex::Regex;

struct RegexFields;

impl RegexFields {
    const GITHUB_URL: &'static str =
        r"^((https?|ssh|git|ftps?)://)?(([^/@]+)@)?([^/:]+)[/:]([^/:]+)/(.+)(git)?$";
    const GITHUB_URL_PROFILE: &'static str =
        r"^((https?|ssh|git|ftps?)://)?(([^/@]+)@)?([^/:]+)[/:]([^/:]+)$";
}

/// From a project URL, retrieves its author with regex processing.
pub fn get_author<'a>(github_url: String) -> Result<String, &'a str> {
    match Regex::new(RegexFields::GITHUB_URL) {
        Ok(regex) => {
            match Regex::new(RegexFields::GITHUB_URL_PROFILE) {
                Ok(regex_profile) => {
                    match regex.captures(github_url.as_str()) {
                        Some(captures) => {
                            // we know that it is in group 6 that the author is
                            match captures.get(6) {
                                Some(item) => Ok(item.as_str().to_string()),
                                _ => Err("[-] Repository author not found, aborting scan"),
                            }
                        }
                        _ => match regex_profile.captures(github_url.as_str()) {
                            Some(captures) => match captures.get(6) {
                                Some(item) => Ok(item.as_str().to_string()),
                                _ => Err("[-] Author could not be found, aborting scan"),
                            },
                            _ => Err("[-] Repository author not found, aborting scan"),
                        },
                    }
                }
                _ => Err("[-] Regex processing went wrong!"),
            }
        }
        _ => Err("[-] Regex processing went wrong!"),
    }
}

/// From a project URL, retrieves its repository with regex processing.
pub fn get_repository<'a>(github_url: String) -> Result<String, &'a str> {
    match Regex::new(RegexFields::GITHUB_URL) {
        Ok(regex) => {
            match regex.captures(github_url.as_str()) {
                Some(captures) => {
                    // we know that it is in group 7 that the author
                    match captures.get(7) {
                        Some(item) => Ok(item.as_str().to_string()),
                        _ => Err("[-] Repository name not found, aborting scan"),
                    }
                }
                _ => {
                    // only author case, URL targets an user profile
                    if !get_author(github_url)?.is_empty() {
                        Ok("".to_string())
                    } else {
                        Err("[-] Repository name not found, aborting scan")
                    }
                }
            }
        }
        _ => Err("[-] Regex processing went wrong!"),
    }
}

#[cfg(test)]
mod tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;

    // author

    #[test]
    fn get_author_git() {
        assert_eq!(
            get_author("git://github.com/extiop/ctf".to_string()),
            Ok("extiop".to_string())
        );
    }

    #[test]
    fn get_author_git_at() {
        assert_eq!(
            get_author("git@github.com/extiop/ctf".to_string()),
            Ok("extiop".to_string())
        );
    }

    #[test]
    fn get_author_https() {
        assert_eq!(
            get_author("https://github.com/extiop/ctf".to_string()),
            Ok("extiop".to_string())
        );
    }

    #[test]
    fn get_author_ssh() {
        assert_eq!(
            get_author("ssh://github.com/extiop/ctf".to_string()),
            Ok("extiop".to_string())
        );
    }

    #[test]
    fn get_author_too_short() {
        assert_eq!(
            get_author("https://github.com".to_string()),
            Err("[-] Repository author not found, aborting scan")
        );
    }

    #[test]
    fn get_author_too_long() {
        // author is not retrieved as expected
        assert_eq!(
            get_author("https://github.com/github/extiop/ctf".to_string()),
            Ok("github".to_string())
        );
    }

    #[test]
    fn get_author_swapped() {
        // author is not retrieved as expected as author and repository are swapped
        assert_eq!(
            get_author("https://github.com/ctf/extiop".to_string()),
            Ok("ctf".to_string())
        );
    }

    // repository

    #[test]
    fn get_get_repository_git() {
        assert_eq!(
            get_repository("git://github.com/extiop/ctf".to_string()),
            Ok("ctf".to_string())
        );
    }

    #[test]
    fn get_get_repository_git_at() {
        assert_eq!(
            get_repository("git@github.com/extiop/ctf".to_string()),
            Ok("ctf".to_string())
        );
    }

    #[test]
    fn get_get_repository_https() {
        assert_eq!(
            get_repository("https://github.com/extiop/ctf".to_string()),
            Ok("ctf".to_string())
        );
    }

    #[test]
    fn get_get_repository_ssh() {
        assert_eq!(
            get_repository("ssh://github.com/extiop/ctf".to_string()),
            Ok("ctf".to_string())
        );
    }

    #[test]
    fn get_repository_no_project() {
        assert_eq!(
            get_repository("https://github.com/extiop".to_string()),
            Ok("".to_string())
        );
    }

    #[test]
    fn get_repository_too_long() {
        // repository is not retrieved as expected
        assert_eq!(
            get_repository("https://github.com/github/extiop/ctf".to_string()),
            Ok("extiop/ctf".to_string())
        );
    }

    #[test]
    fn get_repository_swapped() {
        // repository is not retrieved as expected as author and repository are swapped
        assert_eq!(
            get_repository("https://github.com/ctf/extiop".to_string()),
            Ok("extiop".to_string())
        );
    }
}
