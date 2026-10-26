//! OSINT tool to find a GitHub user's email.
//!
//! It reads repositories' commit metadata through the GitHub REST API to
//! collect developers' email addresses.
//!
//! # Panics
//!
//! No public item of this crate panics at runtime: every fallible operation
//! returns [`errors::Error`], and the panicking paths are denied at compile
//! time by the strict clippy lints (see `Cargo.toml`). The only exceptions
//! are the two documented `expect` allowances on the static-regex
//! [`std::sync::LazyLock`] initializers in [`parsers`], whose compilation
//! cannot fail at runtime.

//! # Library usage
//!
//! The public doors are [`sources::Scanner`] (build it from tokens, then
//! call `scan_parts` for one repository/profile or `search` for a keyword
//! query) and the investigation entry points of the [`email`], [`user`] and
//! [`org`] modules. Every fallible call returns [`errors::Error`]; the reports
//! serialize to the documented JSON shapes. The `Error` display strings
//! are written for a terminal user (they carry next steps), not for
//! programmatic matching - match on the variant, not the text.
//!
//! ```no_run
//! use git2mail::sources::Scanner;
//!
//! let scanner = Scanner::new(Some("ghp_your_token"), None)?;
//! let outcome = scanner.scan_parts("denoland", "deno")?;
//! for email in &outcome.emails {
//!     println!("{email}");
//! }
//! # Ok::<(), git2mail::errors::Error>(())
//! ```
//!
//!

// The pure core lives in the workspace's `core/` crate (compilable to
// `wasm32-unknown-unknown`, see the web bindings): these re-exports keep the
// crate's public API at its historical paths, so `git2mail::parsers`,
// `git2mail::correlate` and friends keep resolving exactly as before.
pub use git2mail_core::{consts, correlate, errors, parsers, provenance};
// The log-safety module stays crate-private at the same path for the
// crate's own modules (`crate::sanitize::log_safe`), as it always was.
use git2mail_core::sanitize;
// The test-only capturing logger moved with the pure core; the crate's own
// tests keep resolving it at `crate::test_logger`.
#[cfg(test)]
pub(crate) use git2mail_core::test_logger;

/// Reverse email lookup: reconstructs
/// candidate repositories from the address (documented heuristic - GitHub
/// has no email search API) and verifies them by commits to resolve the
/// GitHub account behind an email, with an honest confidence level.
pub mod email;

/// GitHub API access: token pool, HTTP client and the single paginated loop.
pub mod github;

/// Organization investigation: the public members, the public repositories and the
/// developers' emails found in their commits, scanned with the token-worker
/// pool - 100% API.
pub mod org;

/// Result writers: legacy text files and opt-in JSON reports.
pub mod output;

/// High-level scans: turn a user request (URL or query) into GitHub API
/// calls through the `github` module and hand the results to the `output`
/// writers.
pub mod sources;

/// Full profile investigation of a GitHub user:
/// usernames/names history through the noreply technique, email
/// variants, secondary-account candidates, SSH keys and external
/// contributions - 100% API, documented deltas included.
pub mod user;
