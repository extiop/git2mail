//! The `user` investigation's report: the documented JSON shape (one
//! struct per finding family), the terminal summary (`log_summary`) and
//! the noreply/local-identity/folded-name helpers the engine and the
//! variants share.

use crate::sanitize::log_safe;
use log::info;
use serde::Serialize;

/// The `profile` object of the investigation report: the fields of
/// `GET /users/{u}` that carry OSINT value. Absent fields are `null`
/// (`public_repos` defaults to `0`).
#[derive(Debug, Clone, Serialize)]
pub struct Profile {
    /// The profile login (unique, case-insensitive).
    pub login: String,
    /// The numeric GitHub id: the stable key of the noreply technique.
    pub id: u64,
    /// The display name set by the account ("Jane Dupont").
    pub name: Option<String>,
    /// The company field.
    pub company: Option<String>,
    /// The blog URL field.
    pub blog: Option<String>,
    /// The location field.
    pub location: Option<String>,
    /// The public email field.
    pub email: Option<String>,
    /// The bio field.
    pub bio: Option<String>,
    /// The Twitter/X username field.
    pub twitter_username: Option<String>,
    /// How many public repositories the account owns.
    pub public_repos: u64,
    /// The account creation date (ISO 8601).
    pub created_at: Option<String>,
    /// The GitHub account type (`User`, `Organization`, `Bot`).
    #[serde(rename = "type")]
    pub account_type: Option<String>,
}

/// One username of the `usernames_history`: a login the target committed
/// with (noreply `<id>+<username>` form, id matching the target's), the
/// names seen with it and the repositories where it appeared.
#[derive(Debug, Clone, Serialize)]
pub struct UsernameSighting {
    /// The username revealed by the noreply email.
    pub username: String,
    /// The commit names seen with this username (normalized: lowercased,
    /// ASCII-folded — see the variants section of the README).
    pub names: Vec<String>,
    /// The target's repositories where this username was seen.
    pub repos: Vec<String>,
}

/// One name of the `names_history`: a commit name seen with the target's
/// id (noreply form or legacy `<id>@users.noreply.github.com` form), and
/// the repositories where it appeared.
#[derive(Debug, Clone, Serialize)]
pub struct NameSighting {
    /// The commit name, normalized (lowercased, ASCII-folded).
    pub name: String,
    /// The target's repositories where this name was seen.
    pub repos: Vec<String>,
}

/// One email of the `emails` (and `local_identities`) lists: an email found
/// on the target's repositories' commits, the names seen with it and the
/// repositories where it appeared.
#[derive(Debug, Clone, Serialize)]
pub struct EmailSighting {
    /// The email as found in the commits.
    pub email: String,
    /// The commit names seen with this email (normalized).
    pub names: Vec<String>,
    /// The target's repositories where this email was seen.
    pub repos: Vec<String>,
}

/// One variant email of the `variants.matched` list: a generated
/// `first/last × domain` combination that was actually observed among the
/// target's commit emails.
#[derive(Debug, Clone, Serialize)]
pub struct VariantMatch {
    /// The variant email, matched against an observed commit email
    /// (case-insensitively).
    pub email: String,
    /// The pattern that generated it (`first.last`, `firstlast`,
    /// `initiallast`, `first_last`, `initial_last`, `first`, `last`,
    /// `initial.last` — the built-in variants combinatorics).
    pub pattern: String,
    /// The domain the variant was generated for.
    pub domain: String,
}

/// The `variants` object: the email variants combinatorics
/// (`{first}.{last}`, `{first}{last}`, `{initial}{last}`, `{first}_{last}`,
/// `{initial}_{last}`, `{first}`, `{last}`, `{initial}.{last}`) applied to
/// the first/last names extracted from the profile name and the commit
/// names seen with the target's id (noreply technique), crossed with the
/// domains deduced from the emails already found on the target (noreply
/// excluded).
#[derive(Debug, Clone, Serialize)]
pub struct Variants {
    /// Generated variant emails that were actually observed in the target's
    /// commits.
    pub matched: Vec<VariantMatch>,
    /// Generated variant emails that were never observed (candidates to
    /// check elsewhere, not findings).
    pub generated: Vec<String>,
}

/// One candidate secondary account of the `secondary_accounts` list, with
/// the evidence that flagged it. Both detection kinds are heuristics.
#[derive(Debug, Clone, Serialize)]
pub struct SecondaryAccount {
    /// How the candidate was detected: `co-author` (an email seen in two or
    /// more of the target's repositories whose names never overlap the
    /// target's own names), `noreply-username` (a noreply pair whose id
    /// differs from the target's but whose username matches a known target
    /// username) or `noreply-name` (same, but only the commit names match a
    /// known target name).
    pub kind: String,
    /// The identity behind the candidate: the email itself for `co-author`,
    /// or the `id+username@users.noreply.github.com` noreply address for the
    /// noreply kinds.
    pub identity: String,
    /// The names seen with this identity (normalized).
    pub names: Vec<String>,
    /// The target's repositories where this identity was seen (the evidence).
    pub repos: Vec<String>,
}

/// One public SSH key of the `ssh_keys` list (`GET /users/{u}/keys`).
#[derive(Debug, Clone, Serialize)]
pub struct SshKey {
    /// The GitHub key id.
    pub id: u64,
    /// The public key material (`ssh-ed25519 AAAA…`, `ssh-rsa AAAA…`).
    pub key: String,
}

/// One repository of the `external_contributions` list: a repository
/// outside the target's own account holding commits authored by the target
/// (`search/commits q=author:<user> -user:<user>`).
#[derive(Debug, Clone, Serialize)]
pub struct ExternalContribution {
    /// The repository `owner/name`.
    pub repository: String,
    /// The repository HTML URL, when the search result carried one.
    pub url: Option<String>,
    /// How many authored commits the search listing exposed for this
    /// repository (at most the number of listed pages × page size: the
    /// listing caps the count, the repository is the finding).
    pub commits: usize,
}

/// The full investigation report: the terminal summary sections and the
/// enriched `--json` shape, documented in the user guide (USER.md page).
#[derive(Debug, Clone, Serialize)]
pub struct UserReport {
    /// The when/what of the report (generation timestamp, tool version).
    #[serde(flatten)]
    pub provenance: crate::output::Provenance,
    /// The investigated profile.
    pub profile: Profile,
    /// The usernames history revealed by the noreply technique.
    pub usernames_history: Vec<UsernameSighting>,
    /// The names history seen with the target's id.
    pub names_history: Vec<NameSighting>,
    /// The emails found on the target's repositories (noreply addresses
    /// excluded: they feed the histories instead).
    pub emails: Vec<EmailSighting>,
    /// The email variants, matched and generated.
    pub variants: Variants,
    /// The potential secondary accounts, with their evidence.
    pub secondary_accounts: Vec<SecondaryAccount>,
    /// The public SSH keys of the account.
    pub ssh_keys: Vec<SshKey>,
    /// The external contributions of the target.
    pub external_contributions: Vec<ExternalContribution>,
    /// The machine-local identities (UPN-like) among the found emails,
    /// flagged by the documented heuristic.
    pub local_identities: Vec<EmailSighting>,
}

/// Runs the full investigation of one GitHub user: fetches the profile,
/// walks the target's repositories' commits (noreply technique and emails),
/// lists the external contributions and the SSH keys, then builds the
/// report and logs the terminal summary.
///
/// The report carries the usernames/names history (noreply technique), the
/// emails and their variants, potential secondary accounts, the public SSH
/// keys and the external contributions.
///
/// `custom_variant_patterns` are the caller-supplied `--variant-pattern`
/// templates (e.g. `{last}{first}`), appended to the built-in patterns;
/// they are validated here (syntax and a 64-pattern cap) so a library
/// caller gets the same client-side rejection as the CLI.
///
/// # Errors
///
/// Returns [`Error::InvalidUsername`] when `username` is not a valid GitHub
/// username (rejected client-side, before any network request),
/// [`Error::Organization`] when the profile is an organization (the message
/// points at the dedicated `org` subcommand), [`Error::NotFound`] for a
/// missing profile, [`Error::PrivateOrUnavailable`] or
/// [`Error::RateLimitExhausted`] / [`Error::Http`] for the corresponding API
/// failures. The skip-vs-abort contract (unscannable repositories, rate
impl UserReport {
    /// Logs the human-readable terminal report: one section per finding
    /// family (PROFILE / USERNAMES HISTORY / EMAILS / VARIANTS / SECONDARY
    /// ACCOUNTS / SSH KEYS / EXTERNAL CONTRIBUTIONS), with the local
    /// identities flagged inside the EMAILS section. An empty section prints
    /// its own explicit `[-]` line instead of disappearing silently. Every
    /// untrusted string (commit metadata, profile fields)
    /// is sanitized first: control characters become `_`, so a
    /// hostile commit can never forge or spoof log lines.
    pub(crate) fn log_summary(&self) {
        let profile = &self.profile;
        info!("============ PROFILE ============");
        info!(
            "[+] login: {} (id {})",
            log_safe(&profile.login),
            profile.id
        );
        for (label, field) in [
            ("name", &profile.name),
            ("company", &profile.company),
            ("blog", &profile.blog),
            ("location", &profile.location),
            ("email", &profile.email),
            ("bio", &profile.bio),
            ("twitter", &profile.twitter_username),
            ("created at", &profile.created_at),
        ] {
            if let Some(value) = field {
                info!("[+] {label}: {}", log_safe(value));
            }
        }
        info!(
            "[+] type: {}",
            profile
                .account_type
                .as_deref()
                .map(log_safe)
                .unwrap_or_else(|| "unknown".to_string())
        );
        info!("[+] public repos: {}", profile.public_repos);

        info!("============ USERNAMES HISTORY ============");
        if self.usernames_history.is_empty() {
            info!(
                "[-] no past username found (no scanned commit carries an <id>+<username> noreply address)"
            );
        }
        for sighting in &self.usernames_history {
            info!(
                "[+] {}: names [{}], repos [{}]",
                log_safe(&sighting.username),
                log_safe(&sighting.names.join(", ")),
                log_safe(&sighting.repos.join(", "))
            );
        }

        info!("============ EMAILS ============");
        if self.emails.is_empty() {
            info!("[-] no email found on the target's repositories");
        }
        for sighting in &self.emails {
            info!(
                "[+] {}: names [{}], repos [{}]",
                log_safe(&sighting.email),
                log_safe(&sighting.names.join(", ")),
                log_safe(&sighting.repos.join(", "))
            );
        }
        for sighting in &self.local_identities {
            info!(
                "[!] local identity (heuristic): {} (names [{}], repos [{}])",
                log_safe(&sighting.email),
                log_safe(&sighting.names.join(", ")),
                log_safe(&sighting.repos.join(", "))
            );
        }

        info!("============ VARIANTS ============");
        if self.variants.matched.is_empty() && self.variants.generated.is_empty() {
            info!("[-] no name/domain pair to generate variants from");
        }
        for variant in &self.variants.matched {
            info!(
                "[+] confirmed (seen in their commits): {} (pattern {}, domain {})",
                log_safe(&variant.email),
                variant.pattern,
                log_safe(&variant.domain)
            );
        }
        for email in &self.variants.generated {
            info!(
                "[!] guessed, not confirmed: {} (do not contact this address without checking it first)",
                log_safe(email)
            );
        }

        info!("============ SECONDARY ACCOUNTS ============");
        if self.secondary_accounts.is_empty() {
            info!("[-] no secondary account candidate");
        }
        // these are heuristics, not confirmations: a junior analyst must
        // never read a possible alias as an established fact
        info!(
            "[.] the accounts below are candidates suggested by name overlap, not confirmed links"
        );
        for account in &self.secondary_accounts {
            info!(
                "[.] possible account: {} ({}): names [{}], repos [{}]",
                log_safe(&account.identity),
                account.kind,
                log_safe(&account.names.join(", ")),
                log_safe(&account.repos.join(", "))
            );
        }

        info!("============ SSH KEYS ============");
        if self.ssh_keys.is_empty() {
            info!("[-] no public SSH key");
        }
        for key in &self.ssh_keys {
            info!("[+] {}", log_safe(&key.key));
        }

        info!("============ EXTERNAL CONTRIBUTIONS ============");
        if self.external_contributions.is_empty() {
            info!("[-] no external contribution found");
        }
        for contribution in &self.external_contributions {
            info!(
                "[+] {}: {} commits ({})",
                log_safe(&contribution.repository),
                contribution.commits,
                contribution
                    .url
                    .as_deref()
                    .map(log_safe)
                    .unwrap_or_else(|| "no url".to_string())
            );
        }
    }
}
