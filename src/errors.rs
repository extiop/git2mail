//! Hand-made error handling, MLA-style (no `thiserror`, no `anyhow`).
//!
//! Every fallible operation of the crate returns `Result<T, Error>` with this
//! single error type, so callers only have to handle one enum.

use std::fmt;
use std::io;
use std::path::Path;

/// All the errors the crate can produce.
#[non_exhaustive]
#[derive(Debug)]
pub enum Error {
    /// Filesystem or other I/O failure.
    Io(io::Error),
    /// JSON (de)serialization failure.
    Json(serde_json::Error),
    /// HTTP request failure (transport, non-success status, body decoding).
    Http(reqwest::Error),
    /// A GitHub URL could not be parsed.
    InvalidUrl(String),
    /// A GitHub token does not follow the expected `ghp_…`/`github_pat_…` format.
    /// The payload is a masked token excerpt, never the full secret.
    InvalidTokenFormat(String),
    /// A `--token-file` is structurally unusable: not a JSON object of
    /// numeric indexes to token strings, or holding no usable token. The
    /// payload describes the structural problem — it is deliberately a
    /// different variant from [`Error::InvalidTokenFormat`], whose display
    /// message points at the token *value* format (a hint that would send
    /// the user looking at a perfectly fine token when the file's *shape*
    /// is what is wrong).
    InvalidTokenFile(String),
    /// Every token of the pool has been rate-limited (HTTP 403/429).
    RateLimitExhausted,
    /// The run stopped because every token of the pool was **parked** by a
    /// secondary rate limit (GitHub's per-minute search quota or an abuse
    /// window): the allowances are not spent, the tokens come back on their
    /// own within minutes. Distinct from [`Error::RateLimitExhausted`],
    /// whose display names an hourly allowance and a one-hour wait — the
    /// wrong advice after a per-minute search storm, and a misdiagnosis of
    /// a healthy pool.
    RateLimitPaused,
    /// GitHub answered HTTP 401 Unauthorized and no other token of the pool
    /// could take over: the credentials themselves were rejected (a revoked,
    /// expired, or scope-less token). Distinct from
    /// [`Error::InvalidTokenFormat`], which is the client-side shape check:
    /// a well-formed token can still be refused by the API, and the crafted
    /// message must point at the token instead of surfacing raw reqwest
    /// jargon with no next step.
    TokenRejected,
    /// GitHub answered HTTP 422 on the first page of a repository search:
    /// the query itself was rejected by the API — most often a nonexistent
    /// or inaccessible `--user`/`--org` login, otherwise an invalid
    /// qualifier combination or an over-long `q`. The raw reqwest message
    /// for this case reads like a tool failure while GitHub's own response
    /// body ("The listed users cannot be searched…") explains the one-
    /// character cause; the crafted message carries that explanation.
    SearchRejected,
    /// The requested GitHub resource does not exist (clean 404).
    NotFound,
    /// The requested GitHub resource is private or unavailable
    /// (a 403 that is not a rate limit; a clean 404 maps to [`Error::NotFound`]).
    PrivateOrUnavailable,
    /// The requested GitHub repository is empty: GitHub answers HTTP 409
    /// Conflict on a `/commits` listing when the repository holds no commit
    /// at all ("Git Repository is empty"). A resource-scoped condition, not
    /// a failure of the token or the pool, skipped like
    /// [`Error::NotFound`] by every resource-scoped caller.
    EmptyRepository,
    /// A search or scan returned no result.
    NoResults,
    /// A `search` qualifier value is malformed (a bad count range, an
    /// impossible date, a name with forbidden characters…). Rejected
    /// client-side, before any network request.
    InvalidSearchQualifier(String),
    /// Writing an output file failed.
    OutputWrite(String),
    /// A scan worker failed in an unexpected way (e.g. it never reported
    /// back through its result channel).
    WorkerFailed(String),
    /// The requested profile is a GitHub organization, not a user: the
    /// `user` subcommand investigates user profiles only, and points at the
    /// dedicated `org` subcommand. The payload is the organization login.
    Organization(String),
    /// A `user` target is not a valid GitHub username (rejected client-side,
    /// before any network request).
    InvalidUsername(String),
    /// A GitHub profile payload is unusable: a required field is missing
    /// (`login` or `id` for a user, `login` for an organization, or a
    /// listing payload of an unexpected shape), so the investigation cannot
    /// run on an unidentified target. The payload describes the problem.
    InvalidProfile(String),
    /// An `email`/`emails` target is not a usable email address (empty,
    /// missing `@`, whitespace…). Rejected client-side, before any network
    /// request. The payload describes the problem.
    InvalidEmail(String),
    /// An `email`/`emails` target sits on the GitHub noreply domain: such an
    /// address never carries a real mailbox and cannot be reversed. The
    /// payload is the rejected address.
    NoreplyEmail(String),
    /// A `user --variant-pattern` template is malformed: empty, without any
    /// placeholder, carrying an unknown placeholder, or containing `@` or
    /// whitespace (either would forge an unusable candidate address).
    /// Rejected client-side, before any network request. The payload
    /// describes the problem.
    InvalidVariantPattern(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(err) => write!(f, "{err}"),
            Error::Json(err) => write!(f, "JSON error: {err}"),
            Error::Http(err) => {
                if err.is_decode() {
                    // a response arrived but is not the JSON GitHub sends:
                    // the classic real-world cause is an intercepted
                    // connection (captive portal, corporate proxy) answering
                    // with an HTML login page, which the generic
                    // "check your internet connection" advice would mislead
                    write!(
                        f,
                        "could not read GitHub's response: {err} — the \
                         connection may be intercepted or filtered (captive \
                         portal, corporate proxy): try again, possibly on \
                         another network"
                    )
                } else {
                    write!(
                        f,
                        "could not reach GitHub: {err} — check your internet \
                         connection and try again (on a corporate network, a \
                         proxy or firewall may have refused the request)"
                    )
                }
            }
            Error::InvalidUrl(details) => write!(
                f,
                // Debug escaping, like the sibling user-typed variants: the
                // payload may echo the user-typed URL (e.g. the host of a
                // rejected `--url`, which `split_email` does not sanitize)
                // and is printed to the terminal, so control characters (an
                // ESC opener must not recolor or retitle the terminal)
                // must not pass raw. The surrounding quotes the Debug form
                // adds are trimmed back off: a crafted sentence must read
                // as prose, not as a quoted string
                "invalid GitHub URL: {}",
                format!("{details:?}").trim_matches('"').trim_end()
            ),
            Error::InvalidTokenFormat(masked) => {
                write!(
                    f,
                    // Debug escaping, like the sibling user-typed variants:
                    // the masked excerpt comes from an arbitrary rejected
                    // `--token`/token-file value and is printed to the
                    // terminal, so control characters (an ESC opener in the
                    // first four characters) must not pass raw
                    "invalid token format (expected `ghp_…` or \
                     `github_pat_…`): {masked:?} — copy a fresh token from \
                     github.com/settings/tokens"
                )
            }
            Error::InvalidTokenFile(details) => {
                write!(
                    f,
                    // Debug escaping: the payload echoes a file key/value
                    // excerpt the user typed and is printed to the terminal
                    "invalid token file: {details:?}"
                )
            }
            Error::RateLimitExhausted => {
                write!(
                    f,
                    "GitHub allowed no more requests: every token's allowance \
                     is used up (without --token: the shared anonymous \
                     allowance is spent) — wait up to one hour for the \
                     limit to reset, or add more tokens with --token / \
                     --token-file; emails found before the limit may \
                     not be saved"
                )
            }
            Error::RateLimitPaused => {
                write!(
                    f,
                    "GitHub paused every token with a secondary rate limit (too many \
                     requests in a short window): the allowances are not spent and \
                     the tokens come back within minutes — wait a few minutes and \
                     rerun the command; results found before the pause may not be \
                     saved"
                )
            }
            Error::TokenRejected => {
                write!(
                    f,
                    "GitHub refused the token (HTTP 401 Unauthorized): it is revoked, \
                     expired or mistyped — create a new token \
                     on GitHub and check your --token or --token-file value"
                )
            }
            Error::SearchRejected => {
                write!(
                    f,
                    // single-line string, like the TokenRejected arm above
                    "GitHub rejected the search (HTTP 422): the `--user`/`--org` login may not \
                     exist or be accessible, or a filter is invalid — check the target and the \
                     search filters"
                )
            }
            Error::NotFound => {
                write!(
                    f,
                    "GitHub resource not found — check the spelling of the \
                     user, organization or repository name (a URL ending in \
                     .git also produces this: drop the suffix)"
                )
            }
            Error::PrivateOrUnavailable => {
                write!(
                    f,
                    "GitHub resource is private or unavailable — the repository may be \
                     private, the token lacks access to it, or a network intermediary \
                     refused the request"
                )
            }
            Error::EmptyRepository => {
                write!(f, "GitHub repository is empty (no commits)")
            }
            Error::NoResults => {
                write!(
                    f,
                    "no email found: this target's public GitHub activity shows no \
                     address — for a person, try git2mail user <username>; \
                     for an address you already have, git2mail email <address>"
                )
            }
            Error::InvalidSearchQualifier(details) => {
                write!(f, "invalid search filter: {details}")
            }
            Error::OutputWrite(details) => write!(f, "failed to write output: {details}"),
            Error::WorkerFailed(details) => {
                write!(
                    f,
                    "an unexpected internal error stopped the scan: {details} — \
                     please run the command again"
                )
            }
            Error::Organization(login) => write!(
                f,
                // Debug escaping, like the sibling user-typed variants: the
                // payload is API-derived (a captive portal can serve a hostile
                // profile body) and printed to the terminal, so control
                // characters must not pass raw
                "{login:?} is a GitHub organization: use the `org` subcommand to investigate \
                 organizations (the `user` subcommand investigates user profiles only)"
            ),
            Error::InvalidUsername(name) => write!(
                f,
                // Debug escaping, like the sibling client-side-rejection
                // variants: the rejected payload is user-typed and printed
                // to the terminal, so control characters must not pass raw
                "invalid GitHub username: {name:?} (expected 1-39 ASCII letters, digits or hyphens, \
                 without a leading/trailing hyphen or consecutive hyphens)"
            ),
            Error::InvalidProfile(details) => {
                write!(
                    f,
                    "GitHub returned an unusable payload for this account: \
                     {details} — try again later"
                )
            }
            Error::InvalidEmail(details) => write!(f, "invalid email address: {details}"),
            Error::InvalidVariantPattern(details) => write!(
                f,
                // Debug escaping, like the sibling client-side-rejection
                // variants: the rejected payload is user-typed and printed
                // to the terminal, so control characters must not pass raw
                "invalid --variant-pattern: {details:?} (use the {{first}}, {{last}} and \
                 {{initial}} placeholders, without '@' or whitespace)"
            ),
            Error::NoreplyEmail(address) => write!(
                f,
                // Debug escaping, like the sibling client-side-rejection
                // variants: the rejected payload is user-typed and printed
                // to the terminal, so control characters (ESC, BEL and
                // friends, which `split_email` does not reject) must never
                // pass raw into the terminal (terminal-title/ANSI injection)
                "cannot reverse {address:?}: GitHub noreply addresses never carry a real mailbox \
                 (the `user` subcommand can still identify the account behind this kind of address)"
            ),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(err) => Some(err),
            Error::Json(err) => Some(err),
            Error::Http(err) => Some(err),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::Io(err)
    }
}

/// Names the file in a read failure: a bare "No such file or directory
/// (os error 2)" leaves the user guessing which of the typed inputs
/// failed, while every sibling token-file error names the file. The
/// not-UTF-8 case gets the encoding hint (a file saved as "UTF-16 LE" by
/// a Windows editor cannot be read as UTF-8). The path is Debug-escaped
/// like every user-typed payload echoed to the terminal (control
/// characters must not pass raw).
pub(crate) fn read_file_error(path: &Path, err: io::Error, missing_hint: &str) -> Error {
    let hint = if err.kind() == io::ErrorKind::NotFound {
        // the most common first-run mistake: the highest-frequency case
        // gets the most explicit guidance — each caller names its own
        // remedy (a token file and a bulk addresses file are set up
        // differently, and the same reader serves both)
        format!(
            " — check the path: the file must exist in the folder you ran \
             the command from ({missing_hint})"
        )
    } else if err.kind() == io::ErrorKind::InvalidData {
        " (is the file UTF-8-encoded? a file saved as UTF-16 cannot be read)".to_string()
    } else {
        String::new()
    };
    // "I/O error" and a bare os-error code mean nothing to a
    // non-developer: say what operation failed and name the file
    Error::Io(io::Error::new(
        err.kind(),
        format!("cannot read the file {path:?}: {err}{hint}"),
    ))
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Error::Json(err)
    }
}

impl From<reqwest::Error> for Error {
    fn from(err: reqwest::Error) -> Self {
        Error::Http(err)
    }
}

#[cfg(test)]
mod tests {
    // Tests may unwrap, expect and panic freely: a failing assertion must
    // be loud, so the zero-panic lints do not apply to the test modules.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use std::error::Error as _;

    #[test]
    fn display_is_readable_for_every_variant() {
        let io_error = Error::Io(io::Error::other("disk on fire"));
        assert_eq!(io_error.to_string(), "disk on fire");

        let search_qualifier =
            Error::InvalidSearchQualifier("stars abc: expected a number or range".to_string())
                .to_string();
        assert!(
            search_qualifier.starts_with("invalid search filter: ")
                && search_qualifier.contains("stars abc"),
            "unexpected InvalidSearchQualifier rendering: {search_qualifier}"
        );

        let rate_limit = Error::RateLimitExhausted.to_string();
        assert!(
            rate_limit.contains("every token's allowance is used up")
                && rate_limit.contains("--token-file"),
            "the rate-limit error must carry its plain-language cause and its \
             next step: {rate_limit}"
        );
        // the paused variant is distinct from the exhausted one: the tokens
        // are parked, not spent, and the wait is minutes, not an hour
        let paused = Error::RateLimitPaused.to_string();
        assert!(
            paused.contains("secondary rate limit")
                && paused.contains("wait a few minutes")
                && !paused.contains('\n'),
            "unexpected message: {paused}"
        );
        // the rejected-token variant carries the status and the next step
        // (create a new token), not raw reqwest jargon — and stays on one
        // terminal line (`eprintln!("[-] {err}")` cannot re-indent an
        // embedded newline, which would raggedly hard-wrap the message)
        let token_rejected = Error::TokenRejected.to_string();
        assert!(
            token_rejected.contains("401 Unauthorized")
                && token_rejected.contains("create a new token")
                && !token_rejected.contains('\n'),
            "unexpected message: {token_rejected}"
        );
        // the rejected-search variant names the likely causes (a typo'd
        // --user/--org login reads like a tool failure in the raw message)
        // and stays on one terminal line, like the TokenRejected arm
        let search_rejected = Error::SearchRejected.to_string();
        assert!(
            search_rejected.contains("--user`/`--org")
                && search_rejected.contains("422")
                && !search_rejected.contains('\n'),
            "unexpected message: {search_rejected}"
        );
        assert!(
            Error::NotFound.to_string().contains("check the spelling"),
            "the not-found error must carry its next step"
        );
        let no_results = Error::NoResults.to_string();
        assert!(
            no_results.contains("no email found") && no_results.contains("git2mail email"),
            "the no-result error must explain that the target is live"
        );
        assert!(
            Error::PrivateOrUnavailable
                .to_string()
                .contains("the token lacks access"),
            "the private-resource error must name the token-scope possibility"
        );
        assert_eq!(
            Error::EmptyRepository.to_string(),
            "GitHub repository is empty (no commits)"
        );
        assert_eq!(
            Error::InvalidUrl("nope".to_string()).to_string(),
            // the surrounding Debug quotes are trimmed back off: a crafted
            // sentence must read as prose, not as a quoted string
            "invalid GitHub URL: nope"
        );
        // the host of a rejected --url is user-typed and echoed to the
        // terminal: control characters are Debug-escaped, not printed raw
        // (terminal-title/ANSI injection, live repro: an ESC in the host
        // passed raw into the terminal)
        assert_eq!(
            Error::InvalidUrl("unsupported host gitlab.com\u{1b}[31mINJECTED: ...".to_string())
                .to_string(),
            "invalid GitHub URL: unsupported host gitlab.com\\u{1b}[31mINJECTED: ..."
        );
        assert_eq!(
            Error::InvalidTokenFormat("ghp_***".to_string()).to_string(),
            "invalid token format (expected `ghp_…` or `github_pat_…`): \"ghp_***\" — copy a fresh token from github.com/settings/tokens"
        );
        // the --variant-pattern payload is user-typed and echoed raw inside
        // the details sentence: the whole payload must be Debug-escaped ONCE
        // at the Display hop (a newline stays a visible \n, a control
        // character stays \u{...}, never a real line break or ANSI opener)
        assert_eq!(
            Error::InvalidVariantPattern(
                "whitespace is not allowed in {last}\n{first}".to_string()
            )
            .to_string(),
            "invalid --variant-pattern: \"whitespace is not allowed in {last}\\n{first}\" (use the {first}, {last} and {initial} placeholders, without '@' or whitespace)"
        );
        assert_eq!(
            Error::InvalidVariantPattern(
                "only printable ASCII is allowed, found \u{1b} in \u{1b}{first}".to_string()
            )
            .to_string(),
            "invalid --variant-pattern: \"only printable ASCII is allowed, found \\u{1b} in \\u{1b}{first}\" (use the {first}, {last} and {initial} placeholders, without '@' or whitespace)"
        );
        assert_eq!(
            Error::InvalidTokenFile("token file key \"foo\" is not a numeric index".to_string())
                .to_string(),
            "invalid token file: \"token file key \\\"foo\\\" is not a numeric index\""
        );
        // the masked excerpt comes from an arbitrary rejected value echoed to
        // the terminal: control characters are Debug-escaped, not printed raw
        assert_eq!(
            Error::InvalidTokenFormat("\x1b[31***".to_string()).to_string(),
            "invalid token format (expected `ghp_…` or `github_pat_…`): \"\\u{1b}[31***\" — copy a fresh token from github.com/settings/tokens"
        );
        assert_eq!(
            Error::OutputWrite("results/x".to_string()).to_string(),
            "failed to write output: results/x"
        );
        assert_eq!(
            Error::WorkerFailed("did not report".to_string()).to_string(),
            "an unexpected internal error stopped the scan: did not report — please run the command again"
        );
        assert!(
            Error::Organization("acme".to_string())
                .to_string()
                .contains("`org` subcommand")
        );
        // the payload is API-derived and echoed to the terminal: control
        // characters are Debug-escaped, not printed raw (log forging)
        let org_error = Error::Organization("a\nb".to_string()).to_string();
        assert!(org_error.contains("is a GitHub organization") && !org_error.contains("a\nb is"));
        assert_eq!(
            Error::InvalidUsername("a b".to_string()).to_string(),
            "invalid GitHub username: \"a b\" (expected 1-39 ASCII letters, digits or hyphens, without \
             a leading/trailing hyphen or consecutive hyphens)"
        );
        // control characters are escaped, not printed raw to the terminal
        assert_eq!(
            Error::InvalidUsername("a\nb".to_string()).to_string(),
            "invalid GitHub username: \"a\\nb\" (expected 1-39 ASCII letters, digits or hyphens, without \
             a leading/trailing hyphen or consecutive hyphens)"
        );
        assert_eq!(
            Error::InvalidProfile("missing `id`".to_string()).to_string(),
            "GitHub returned an unusable payload for this account: missing \
             `id` — try again later"
        );
        assert_eq!(
            Error::InvalidEmail("no at sign".to_string()).to_string(),
            "invalid email address: no at sign"
        );
        assert_eq!(
            Error::NoreplyEmail("1@users.noreply.github.com".to_string()).to_string(),
            "cannot reverse \"1@users.noreply.github.com\": GitHub noreply addresses never carry a \
             real mailbox (the `user` subcommand can still identify the account behind this kind of \
             address)"
        );
        // the payload is user-typed and echoed to the terminal: control
        // characters (which split_email does not reject) are Debug-escaped,
        // not printed raw (terminal-title/ANSI injection)
        assert_eq!(
            Error::NoreplyEmail("\x1b]0;pwned\x07@users.noreply.github.com".to_string())
                .to_string(),
            "cannot reverse \"\\u{1b}]0;pwned\\u{7}@users.noreply.github.com\": GitHub noreply addresses never carry a \
             real mailbox (the `user` subcommand can still identify the account behind this kind of \
             address)"
        );
    }

    #[test]
    fn read_file_error_names_the_file_and_hints_the_encoding() {
        // a missing token-file/emails file must not surface as a bare
        // "No such file or directory" with no path (every sibling token
        // error names the file), and the not-UTF-8 case (a Windows editor's
        // "UTF-16 LE" save) must hint at the encoding
        let missing = read_file_error(
            Path::new("nope.json"),
            io::Error::from(io::ErrorKind::NotFound),
            "for tokens: copy tokens.example.json to tokens.json and paste \
             your tokens from github.com/settings/tokens",
        );
        assert_eq!(
            missing.to_string(),
            "cannot read the file \"nope.json\": entity not found — check the \
             path: the file must exist in the folder you ran the command from \
             (for tokens: copy tokens.example.json to tokens.json and paste \
             your tokens from github.com/settings/tokens)"
        );
        // the remedy is the caller's: a bulk addresses file gets its own
        // guidance, not the token-file one
        let missing_addresses = read_file_error(
            Path::new("addresses.txt"),
            io::Error::from(io::ErrorKind::NotFound),
            "one email address per line, # comments allowed",
        );
        assert_eq!(
            missing_addresses.to_string(),
            "cannot read the file \"addresses.txt\": entity not found — check \
             the path: the file must exist in the folder you ran the command \
             from (one email address per line, # comments allowed)"
        );
        let not_utf8 = read_file_error(
            Path::new("emails.txt"),
            io::Error::new(
                io::ErrorKind::InvalidData,
                "stream did not contain valid UTF-8",
            ),
            "",
        );
        assert_eq!(
            not_utf8.to_string(),
            "cannot read the file \"emails.txt\": stream did not contain valid UTF-8 \
             (is the file UTF-8-encoded? a file saved as UTF-16 cannot be read)"
        );
    }

    #[test]
    fn from_conversions_wrap_the_inner_error() {
        let io_error = io::Error::other("boom");
        let error: Error = io_error.into();
        assert!(matches!(error, Error::Io(_)));
        assert!(error.source().is_some());

        let json_error: Error = serde_json::from_str::<serde_json::Value>("not json")
            .expect_err("must fail")
            .into();
        assert!(matches!(json_error, Error::Json(_)));

        // an invalid URL fails at request-build time, deterministically and
        // without any I/O (no loopback connection needed in tests)
        let http_error: Error = reqwest::blocking::Client::new()
            .get("not a valid url")
            .build()
            .expect_err("invalid URL must fail before any I/O")
            .into();
        assert!(matches!(http_error, Error::Http(_)));
    }
}
