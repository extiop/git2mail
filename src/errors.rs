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
    /// Every token of the pool has been rate-limited (HTTP 403/429).
    RateLimitExhausted,
    /// The requested GitHub resource does not exist (clean 404).
    NotFound,
    /// The requested GitHub resource is private or unavailable
    /// (a 403 that is not a rate limit; a clean 404 maps to [`Error::NotFound`]).
    PrivateOrUnavailable,
    /// The token file is not a usable JSON file (malformed JSON, wrong
    /// shape, unusable keys). The payload names the file and the problem.
    InvalidTokenFile(String),
    /// The GitHub API rejected the token itself (HTTP 401): the token is
    /// revoked, invalid, or expired. Distinct from a rate limit: the token
    /// is the problem, not its quota.
    TokenRejected,
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
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(err) => write!(f, "I/O error: {err}"),
            Error::Json(err) => write!(f, "JSON error: {err}"),
            Error::Http(err) => {
                write!(
                    f,
                    "could not reach GitHub: {err} — check your internet \
                     connection and try again"
                )
            }
            Error::InvalidUrl(details) => write!(f, "invalid GitHub URL: {details:?}"),
            Error::InvalidTokenFormat(masked) => {
                write!(
                    f,
                    "invalid token format (expected `ghp_…` or `github_pat_…`): {masked:?}"
                )
            }
            Error::InvalidTokenFile(details) => {
                write!(f, "invalid token file: {details:?}")
            }
            Error::TokenRejected => {
                write!(
                    f,
                    "GitHub rejected this token (HTTP 401 Unauthorized): it is revoked, \
                     invalid or expired — check or rotate it"
                )
            }
            Error::RateLimitExhausted => {
                write!(
                    f,
                    "GitHub allowed no more requests this hour: every token's \
                     allowance is used up — wait for the hour to reset, or add \
                     more tokens with --token / --token-file"
                )
            }
            Error::NotFound => {
                write!(
                    f,
                    "GitHub resource not found — check the spelling of the \
                 user, organization or repository name"
                )
            }
            Error::PrivateOrUnavailable => {
                write!(
                    f,
                    "GitHub resource is private or unavailable — the repository may be \
                     private, or the token lacks access to it"
                )
            }
            Error::NoResults => {
                write!(
                    f,
                    "no email found for this target: the repositories and the profile \
                     are live but expose no public address"
                )
            }
            Error::InvalidSearchQualifier(details) => {
                write!(f, "invalid search qualifier: {details}")
            }
            Error::OutputWrite(details) => write!(f, "failed to write output: {details}"),
            Error::WorkerFailed(details) => {
                write!(
                    f,
                    "an unexpected internal error stopped the scan: {details} — \
                     please run the command again"
                )
            }
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

/// Wraps a file-read failure so the message names the file: a bare
/// "No such file or directory (os error 2)" would leave the user guessing
/// which typed input failed. A UTF-16-saved file gets its own hint (a
/// Windows editor cannot be read as UTF-8). The path is Debug-escaped
/// like every user-typed payload echoed to the terminal (control
/// characters must not pass raw).
pub(crate) fn read_file_error(path: &Path, err: io::Error) -> Error {
    let hint = if err.kind() == io::ErrorKind::InvalidData {
        " (is the file UTF-8-encoded? a file saved as UTF-16 cannot be read)"
    } else {
        ""
    };
    Error::Io(io::Error::new(err.kind(), format!("{path:?}: {err}{hint}")))
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
        assert_eq!(io_error.to_string(), "I/O error: disk on fire");

        assert!(
            Error::RateLimitExhausted
                .to_string()
                .contains("every token's allowance is used up")
        );
        assert!(
            Error::NotFound
                .to_string()
                .contains("check the spelling of the user")
        );
        assert_eq!(
            Error::InvalidUrl("nope".to_string()).to_string(),
            "invalid GitHub URL: \"nope\""
        );
        assert_eq!(
            Error::InvalidTokenFormat("ghp_***".to_string()).to_string(),
            "invalid token format (expected `ghp_…` or `github_pat_…`): \"ghp_***\""
        );
        assert_eq!(
            Error::InvalidSearchQualifier("stars: >abc".to_string()).to_string(),
            "invalid search qualifier: stars: >abc"
        );
        assert_eq!(
            Error::OutputWrite("results/x".to_string()).to_string(),
            "failed to write output: results/x"
        );
        assert!(
            Error::Json(serde_json::from_str::<serde_json::Value>("bad").unwrap_err())
                .to_string()
                .starts_with("JSON error:"),
            "the JSON arm wraps the serde message"
        );
        // a blocked connect (nothing listens on port 1) goes through the
        // plain-language Http arm
        let http_err = reqwest::blocking::Client::new()
            .get("http://127.0.0.1:1/")
            .send()
            .expect_err("nothing listens on port 1");
        assert!(
            Error::Http(http_err)
                .to_string()
                .contains("could not reach GitHub"),
            "the Http arm carries the plain-language network cause"
        );
        assert!(
            Error::InvalidTokenFile("token file key \"foo\" is not a numeric index".to_string())
                .to_string()
                .starts_with("invalid token file:"),
            "the invalid token file arm quotes its payload"
        );
        assert!(
            Error::TokenRejected
                .to_string()
                .contains("GitHub rejected this token (HTTP 401 Unauthorized)")
                && Error::TokenRejected
                    .to_string()
                    .contains("check or rotate it"),
            "the rejected-token arm carries status and next step"
        );
        assert!(
            Error::PrivateOrUnavailable
                .to_string()
                .contains("the token lacks access"),
            "the private-resource arm names the token-scope possibility"
        );
        assert!(
            Error::NoResults.to_string().contains("no email found"),
            "the no-result arm explains that the target is live"
        );
        assert_eq!(
            Error::WorkerFailed("did not report".to_string()).to_string(),
            "an unexpected internal error stopped the scan: did not report — please run the command again"
        );
    }

    #[test]
    fn read_file_error_names_the_file_and_hints_the_encoding() {
        // the read failure names the typed input, so the user knows which
        // file to fix; a UTF-16-saved file gets its own hint
        let err = read_file_error(
            Path::new("tokens.json"),
            io::Error::new(io::ErrorKind::NotFound, "no such file"),
        );
        let message = err.to_string();
        assert!(
            message.contains("tokens.json") && message.contains("no such file"),
            "unexpected message: {message}"
        );
        let err = read_file_error(
            Path::new("tokens.json"),
            io::Error::new(
                io::ErrorKind::InvalidData,
                "stream does not represent valid UTF-8",
            ),
        );
        assert!(
            err.to_string().contains("UTF-16"),
            "the invalid-data case must hint at the encoding: {}",
            err
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
