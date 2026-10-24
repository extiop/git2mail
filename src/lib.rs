//! OSINT tool to find a GitHub user's email.
//!
//! It uses GitHub repositories metadata regarding commits to get developers' email.
//! It browses a repository and scrapes developers' email through its commits.
//!
//! # Panics
//!
//! No public item of this crate panics at runtime: every fallible operation
//! returns [`errors::Error`], and the panicking paths are denied at compile
//! time by the strict clippy lints (see `Cargo.toml`). The only exceptions
//! are the two documented `expect` allowances on the static-regex
//! [`std::sync::LazyLock`] initializers in [`parsers`], whose compilation
//! cannot fail at runtime.

/// MLA-style hand-made error type shared by the whole crate.
pub mod errors;

/// GitHub API access: token pool, HTTP client and the single paginated loop.
pub mod github;

/// Result writers: legacy text files and opt-in JSON reports.
pub mod output;

/// High-level scans: turn a user request (URL or query) into GitHub API
/// calls through the `github` module and hand the results to the `output`
/// writers.
pub mod sources;

/// The `parsers` module exists to handle some strings and returns requested parts of it
/// For instance, it gets, from a given repository URL, its author and project name.
pub mod parsers;
