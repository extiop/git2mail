//! Pure core of git2mail: the std-only logic shared by the CLI crate and
//! the WASM bindings (`web/wasm`). No HTTP client and no network I/O:
//! everything here compiles to `wasm32-unknown-unknown` (pinned in CI), so
//! the browser site applies exactly the same rules as the CLI - the same
//! URL parsing, the same email/noreply discipline, the same sanitization -
//! without duplicating them in JavaScript. The sole filesystem/thread
//! users are the test-only capture helpers of [`test_logger`], which are
//! inert unless a test calls them.
//!
//! The CLI crate re-exports these modules at their historical paths
//! (`git2mail::parsers`, `git2mail::user::variants`…), so its public API is
//! unchanged; the WASM bindings consume the modules directly.

/// Shared constants of the project (the GitHub API base URL and the noreply
/// domain), defined once instead of duplicated per module.
pub mod consts;

/// Per-author attribute correlation: aggregates the scan results
/// per author with the repositories scanned, their primary language and the
/// commit counts, for the opt-in JSON report and the terminal summary.
pub mod correlate;

/// MLA-style hand-made error type shared by the whole workspace.
pub mod errors;

/// API payload parsers of the `user` investigation (profile, listing pages,
/// commit people): pure JSON-to-struct decoding with no I/O.
pub mod parsing;

/// The `parsers` module exists to handle some strings and returns requested parts of it
/// For instance, it gets, from a given repository URL, its author and project name.
pub mod parsers;

/// Report provenance: the UTC timestamp and tool version stamps carried by
/// every JSON report.
pub mod provenance;

/// The enriched report structs of the `user` investigation (profile,
/// identity histories, variants, secondary accounts, SSH keys, external
/// contributions) and their terminal summary - pure serializable data.
pub mod report;

/// The shared email acceptance rules of the project: whether an email is
/// usable (`is_usable_email`) and the single noreply rule
/// (`is_noreply_email`). One owner, so the plain output, the correlation
/// report, the `user` investigation, the reverse lookup and the web scan
/// always stay consistent.
pub mod rules;

/// Log-safety for strings derived from untrusted metadata, and the output
/// file-name sanitizer.
pub mod sanitize;

/// The email-variant engine of the `user` investigation: capped
/// combinatorics of plausible spellings, ranked by sighting weight.
pub mod variants;

/// Test-only capturing logger: pins the terminal-report sanitization and
/// the cap announcements at the wiring level. Not cfg(test)-gated: a
/// dependency crate's tests compile their dependencies without
/// `cfg(test)`, so the module must exist in normal builds (it is inert
/// unless a test calls `capture`.
pub mod test_logger;
