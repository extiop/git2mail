//! The shared email acceptance rules of the project. One owner: the plain
//! output, the correlation report, the `user` investigation, the reverse
//! email lookup and the web scan all test their emails through these two
//! functions, so they can never drift apart.

use crate::consts::NOREPLY_DOMAIN;

/// Whether an email sits on the GitHub noreply domain (`users.noreply.github.com`):
/// case-insensitive exact match on the domain only, no subdomain look-alike.
/// The single noreply rule of the crate - the same test the `user`
/// investigation applies to its noreply technique and the reverse email
/// lookup to its upfront rejection.
pub fn is_noreply_email(email: &str) -> bool {
    email
        .trim_matches('"')
        .rsplit_once('@')
        .is_some_and(|(_, domain)| domain.eq_ignore_ascii_case(NOREPLY_DOMAIN))
}

/// Whether an email is usable: non-empty, free of control characters and
/// whitespace (a crafted newline-carrying payload would inject lines into
/// the one-email-per-line plain output), not a GitHub `noreply` address, and
/// shaped like an address: exactly one `@` separating a non-empty local part
/// from a non-empty domain (the same structural rule the `email` subcommand
/// enforces in its upfront `split_email` rejection, so the scan paths can
/// never report as a found email a bare username or garbage string that the
/// `email` subcommand itself would reject as invalid - git permits
/// arbitrary author-email fields, and a domainless value like `jdoe` is
/// not a mailbox). The shared acceptance rule of the plain output, of the
/// correlation report and of the `user` investigation's commit emails, so
/// all of them always stay consistent. A commit email
/// that merely contains `noreply` in its local part
/// (`john.noreply@acme.com`) is a real mailbox and must be kept: only the
/// exact noreply domain is excluded.
pub fn is_usable_email(email: &str) -> bool {
    let email = email.trim_matches('"');
    if email.is_empty()
        || email.chars().any(|c| c.is_control() || c.is_whitespace())
        || is_noreply_email(email)
    {
        return false;
    }
    match email.split_once('@') {
        Some((local, domain)) => !local.is_empty() && !domain.is_empty() && !domain.contains('@'),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    // Tests may unwrap, expect and panic freely: a failing assertion must
    // be loud, so the zero-panic lints do not apply to the test modules.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn is_usable_email_rejects_only_the_exact_noreply_domain() {
        assert!(is_usable_email("dev@example.com"));
        // a `noreply`-looking local part is a real mailbox, not a GitHub
        // noreply address: it must not be dropped by substring luck
        assert!(is_usable_email("john.noreply@acme.com"));
        // a subdomain look-alike is not the noreply domain
        assert!(is_usable_email("dev@xusers.noreply.github.com"));
        assert!(!is_usable_email("12345+dev@users.noreply.github.com"));
        assert!(!is_usable_email("12345+dev@USERS.NOREPLY.GITHUB.COM"));
        // quoted commit emails are unwrapped before the test
        assert!(!is_usable_email("\"12345+dev@users.noreply.github.com\""));
        assert!(!is_usable_email(""));
        // a crafted control character or whitespace would inject lines into
        // the one-email-per-line plain output: never kept, whatever the
        // (necessarily hostile) payload
        assert!(!is_usable_email("dev@x.com\n evil@x.com"));
        assert!(!is_usable_email("dev\t@x.com"));
        assert!(!is_usable_email("dev@x.com\u{1b}[31m"));
    }

    #[test]
    fn is_usable_email_requires_exactly_one_at_sign_like_the_email_subcommand() {
        // the `email` subcommand rejects these strings as invalid addresses
        // (`split_email`: missing '@', empty local part or domain, a second
        // '@' in the domain): the shared scan rule must reject them too, so
        // a domainless commit-email field (git permits any string, e.g. a
        // bare username) can never be reported as a found email
        assert!(!is_usable_email("jdoe"));
        assert!(!is_usable_email("no-at-sign"));
        assert!(!is_usable_email("@example.com"));
        assert!(!is_usable_email("dev@"));
        assert!(!is_usable_email("dev@x@com"));
        assert!(is_usable_email("dev@example.com"));
        // a quoted email is unwrapped before the test
        assert!(is_usable_email("\"dev@example.com\""));
        assert!(!is_usable_email("\"jdoe\""));
    }
}
