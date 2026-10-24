//! Shared constants of the crate: the GitHub API endpoints and the domains
//! the email heuristics special-case, defined once instead of duplicated
//! per module.

/// The GitHub API base URL the production runs hit.
pub(crate) const GITHUB_API_BASE: &str = "https://api.github.com";

/// The GitHub noreply domain: addresses on it never carry a real mailbox
/// (they feed the username/names histories of the `user` investigation and
/// are rejected upfront by the reverse email lookup).
pub(crate) const NOREPLY_DOMAIN: &str = "users.noreply.github.com";

/// The web-flow commit identity GitHub stamps on commits made through its
/// UI (name `github`, address `noreply@github.com`): it is automation, not
/// a mailbox, and never a co-author/secondary account of the target.
pub(crate) const WEB_FLOW_EMAIL: &str = "noreply@github.com";
