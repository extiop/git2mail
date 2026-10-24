//! Hand-made error handling, MLA-style (no `thiserror`, no `anyhow`).
//!
//! Every fallible operation of the crate returns `Result<T, Error>` with this
//! single error type, so callers only have to handle one enum.

use std::fmt;
use std::io;

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
    /// A search or scan returned no result.
    NoResults,
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
            Error::Http(err) => write!(f, "HTTP error: {err}"),
            Error::InvalidUrl(details) => write!(f, "invalid GitHub URL: {details}"),
            Error::InvalidTokenFormat(masked) => {
                write!(
                    f,
                    "invalid token format (expected `ghp_…` or `github_pat_…`): {masked}"
                )
            }
            Error::RateLimitExhausted => {
                write!(
                    f,
                    "rate limit exceeded and no more token available in the pool"
                )
            }
            Error::NotFound => write!(f, "GitHub resource not found"),
            Error::PrivateOrUnavailable => {
                write!(f, "GitHub resource is private or unavailable")
            }
            Error::NoResults => write!(f, "no result found"),
            Error::OutputWrite(details) => write!(f, "failed to write output: {details}"),
            Error::WorkerFailed(details) => write!(f, "scan worker failed: {details}"),
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
                .contains("no more token")
        );
        assert_eq!(Error::NotFound.to_string(), "GitHub resource not found");
        assert_eq!(
            Error::InvalidUrl("nope".to_string()).to_string(),
            "invalid GitHub URL: nope"
        );
        assert_eq!(
            Error::InvalidTokenFormat("ghp_***".to_string()).to_string(),
            "invalid token format (expected `ghp_…` or `github_pat_…`): ghp_***"
        );
        assert_eq!(
            Error::OutputWrite("results/x".to_string()).to_string(),
            "failed to write output: results/x"
        );
        assert_eq!(
            Error::WorkerFailed("did not report".to_string()).to_string(),
            "scan worker failed: did not report"
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
