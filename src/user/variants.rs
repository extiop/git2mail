//! The email variant engine: the likely email spellings a person named
//! that way would plausibly use, built from the names and mail domains the
//! investigation observed, matched against the observed emails. Both input
//! dimensions are capped (commit names and commit emails are
//! attacker-forgeable and uncapped: one merged PR can plant thousands of
//! name spellings and domains, and the combinatorics multiply them into an
//! analyst-machine DoS), ranked by raw sighting weight, and the generated
//! list itself is capped, with a warning when a cap bites.

use crate::errors::Error;
use std::collections::{BTreeMap, BTreeSet};

use super::report::{VariantMatch, Variants};
use super::{fold_name, folded_commit_name};

/// Upper bound on one caller-supplied `--variant-pattern` template: a
/// longer pattern can only be pathological (the generated local-part must
/// fit RFC 5321's 64-byte bound anyway), and every count in the engine is
/// capped against hostile input — so is this one.
pub(crate) const MAX_VARIANT_PATTERN_BYTES: usize = 128;

/// The variant engine's input caps. Commit names and commit emails are
/// attacker-forgeable and uncapped (one merged PR can plant thousands of
/// name spellings and email domains), and the combinatorics multiply
/// every known name pair by every deduced email domain: measured on the
/// uncapped engine, 300 planted names × 300 planted domains produce
/// 361,200 variants and seconds of CPU (extrapolating to a hostile
/// 5,000-commit PR: tens of millions of variants, minutes-to-hours of CPU
/// and a multi-gigabyte report). A real target has a handful of name
/// spellings and mail domains; beyond the caps the extra inputs are
/// attacker noise, so the engine is bounded deterministically (sorted
/// pairs, most-sighted domains first) with a warning when a cap bites.
pub(crate) const MAX_VARIANT_NAME_PAIRS: usize = 64;

/// See [`MAX_VARIANT_NAME_PAIRS`]: the per-scan cap on the distinct email
/// domains fed to the variant engine (most-sighted domains first, ties
/// broken alphabetically, noreply excluded as before).
pub(crate) const MAX_VARIANT_DOMAINS: usize = 64;

/// See [`MAX_VARIANT_NAME_PAIRS`]: the cap on the report's generated-variant
/// list. Matching is unaffected: every capped combination is still tested
/// against the observed emails, so a variant beyond the list cap can still
/// be reported as matched.
pub(crate) const MAX_GENERATED_VARIANTS: usize = 1000;

/// The cap on the caller-supplied custom variant patterns
/// (`user --variant-pattern`): the patterns are analyst input, not forgeable
/// commit metadata, but the same combinatorics warning applies — every
/// pattern multiplies every capped name pair by every capped domain, so an
/// absurd pattern count would only slow the analyst's own machine down and
/// bloat the report past the generated-list cap. 64 keeps the useful
/// conventions of a whole team and fails fast beyond.
pub(crate) const MAX_CUSTOM_VARIANT_PATTERNS: usize = 64;

/// Validates one caller-supplied custom variant pattern
/// (`user --variant-pattern`). A pattern is a template with `{first}`,
/// `{last}` and `{initial}` placeholders (e.g. `{last}{first}` produces
/// `doejohn@…`); braces are only allowed as placeholders, only printable
/// ASCII is allowed (`@`, whitespace, control and zero-width characters
/// would forge a candidate address no mail system could ever have
/// produced, or worse inject into the report), and the expansion is
/// lowercased at generation time so the literal part matches observed
/// emails case-insensitively like the built-ins. The rejection is
/// client-side, before any network request.
///
/// # Errors
///
/// [`Error::InvalidVariantPattern`] with a description of the first problem
/// found.
pub fn validate_variant_pattern(pattern: &str) -> Result<(), Error> {
    // every count in the engine is capped against hostile metadata: a
    // pattern is CLI input, so the cap is a client-side rejection (the
    // generated local-part fits well under RFC 5321's 64-byte local-part
    // bound anyway — a longer pattern can only be pathological)
    if pattern.len() > MAX_VARIANT_PATTERN_BYTES {
        return Err(Error::InvalidVariantPattern(format!(
            "the pattern is {} bytes, the maximum is {MAX_VARIANT_PATTERN_BYTES}",
            pattern.len()
        )));
    }
    if pattern.trim().is_empty() {
        return Err(Error::InvalidVariantPattern("the pattern is empty".into()));
    }
    if pattern.chars().any(char::is_whitespace) {
        return Err(Error::InvalidVariantPattern(format!(
            "whitespace is not allowed in {pattern}"
        )));
    }
    if pattern.contains('@') {
        return Err(Error::InvalidVariantPattern(format!(
            "'@' is not allowed in {pattern}: the domain comes from the deduced domains, not \
             from the pattern"
        )));
    }
    if let Some(character) = pattern
        .chars()
        .find(|character| !character.is_ascii_graphic())
    {
        return Err(Error::InvalidVariantPattern(format!(
            "only printable ASCII is allowed, found {} in {pattern}",
            character
        )));
    }
    let mut placeholders = 0usize;
    let mut rest = pattern;
    while let Some(open) = rest.find('{') {
        let after = &rest[open + 1..];
        let Some(close) = after.find('}') else {
            return Err(Error::InvalidVariantPattern(format!(
                "unclosed '{{' in {pattern}"
            )));
        };
        match &after[..close] {
            "first" | "last" | "initial" => placeholders += 1,
            other => {
                return Err(Error::InvalidVariantPattern(format!(
                    "unknown placeholder {{{other}}} in {pattern} (expected {{first}}, \
                     {{last}} or {{initial}})"
                )));
            }
        }
        rest = &after[close + 1..];
    }
    if placeholders == 0 {
        return Err(Error::InvalidVariantPattern(format!(
            "the pattern {pattern} carries no {{first}}/{{last}}/{{initial}} placeholder"
        )));
    }
    // a stray '}' (with or without a matching '{') is not a valid placeholder
    // and would silently pass into the generated address
    if pattern.matches('}').count() != placeholders {
        return Err(Error::InvalidVariantPattern(format!(
            "a '}}' outside a placeholder is not allowed in {pattern}"
        )));
    }
    Ok(())
}

/// Generates the variant emails of one `(first, last)` name pair
/// for one domain, in the fixed built-in order (first.last, firstlast,
/// initiallast, first_last, initial_last, first, last, initial.last),
/// followed by the caller-supplied custom patterns in their CLI order
/// (e.g. `{last}{first}`), deduplicated
/// (a first name equal to the last one, or a single-letter first name,
/// collapse several patterns onto the same email). With no last name, only
/// the bare `{first}` pattern makes sense among the built-ins, and the
/// custom patterns requiring a last name are skipped.
pub(crate) fn generate_variants(
    first: &str,
    last: &str,
    domain: &str,
    custom_patterns: &[String],
) -> Vec<(String, String)> {
    let initial = first.chars().next().map(String::from).unwrap_or_default();
    let emails: Vec<(String, &'static str)> = if last.is_empty() {
        vec![(format!("{first}@{domain}"), "first")]
    } else {
        vec![
            (format!("{first}.{last}@{domain}"), "first.last"),
            (format!("{first}{last}@{domain}"), "firstlast"),
            (format!("{initial}{last}@{domain}"), "initiallast"),
            (format!("{first}_{last}@{domain}"), "first_last"),
            (format!("{initial}_{last}@{domain}"), "initial_last"),
            (format!("{first}@{domain}"), "first"),
            (format!("{last}@{domain}"), "last"),
            (format!("{initial}.{last}@{domain}"), "initial.last"),
        ]
    };
    let mut generated: Vec<(String, String)> = Vec::new();
    for (email, pattern) in emails {
        if !generated.iter().any(|(seen, _)| seen == &email) {
            generated.push((email, pattern.to_string()));
        }
    }
    // the custom patterns come after the built-ins, in their CLI order;
    // the pattern label in the report is the template itself:
    // self-documenting, and distinguishable from the built-in patterns
    for template in custom_patterns {
        if let Some(local) = expand_pattern(template, first, last, &initial) {
            let email = format!("{local}@{domain}");
            if !generated.iter().any(|(seen, _)| seen == &email) {
                generated.push((email, template.clone()));
            }
        }
    }
    generated
}

/// Expands one custom variant template into the local part of one name
/// pair's candidate address: `{first}`, `{last}` and `{initial}` are
/// replaced by the folded name parts (the `@domain` is appended by the
/// caller, like the built-ins), and the whole expansion is lowercased so
/// the literal part of the template matches observed emails
/// case-insensitively, exactly like the built-ins (`J.{last}` must match
/// the observed `j.dupont@acme.com`, not miss it). A template requiring a
/// last name is skipped (not an error) when the pair carries none, exactly
/// like the built-ins collapse in that case.
pub(crate) fn expand_pattern(
    template: &str,
    first: &str,
    last: &str,
    initial: &str,
) -> Option<String> {
    if template.contains("{last}") && last.is_empty() {
        return None;
    }
    let expanded = template
        .replace("{first}", first)
        .replace("{last}", last)
        .replace("{initial}", initial)
        .to_lowercase();
    (!expanded.is_empty()).then_some(expanded)
}

/// Folds one already-folded name into its `(first, last)` variant pair.
pub(crate) fn pair_from_folded_name(folded: &str) -> Option<(String, String)> {
    let tokens: Vec<&str> = folded.split_whitespace().collect();
    if tokens.is_empty() {
        return None;
    }
    let last = if tokens.len() == 1 {
        ""
    } else {
        tokens[tokens.len() - 1]
    };
    Some((tokens[0].to_string(), last.to_string()))
}

pub(crate) fn build_variants(
    known_names: BTreeSet<String>,
    name_weights: &BTreeMap<String, usize>,
    profile_name: Option<&str>,
    domains: Vec<String>,
    email_keys: BTreeSet<String>,
    custom_variant_patterns: &[String],
) -> Variants {
    // One O(N) pass: fold every name once and accumulate its raw
    // sighting weight into its (first, last) pair. The previous
    // per-pair ranking re-scanned and re-folded ALL known names for
    // EVERY distinct pair — quadratic in the uncapped, target-forgeable
    // commit-name count (the per-repository walk cap bounds one
    // repository, but the target's own repositories multiply it), all
    // paid BEFORE the MAX_VARIANT_NAME_PAIRS truncation below
    // a BTreeMap keeps the pair iteration deterministic (pair asc), so
    // the stable weight sort below resolves equal weights
    // deterministically — a dropped tie-break cannot hide behind
    // HashMap's randomized order
    let mut pair_weights: BTreeMap<(String, String), usize> = BTreeMap::new();
    for name in &known_names {
        if let Some(pair) = pair_from_folded_name(&fold_name(name)) {
            *pair_weights.entry(pair).or_default() += name_weights.get(name).copied().unwrap_or(0);
        }
    }
    let mut weighted_pairs: Vec<((String, String), usize)> = pair_weights.into_iter().collect();
    weighted_pairs.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let mut pairs: Vec<(String, String)> =
        weighted_pairs.into_iter().map(|(pair, _)| pair).collect();
    let profile_pair = profile_name
        .and_then(folded_commit_name)
        .and_then(|name| pair_from_folded_name(&name));
    if let Some(profile_pair) = profile_pair {
        pairs.retain(|pair| pair != &profile_pair);
        pairs.insert(0, profile_pair);
    }
    if pairs.len() > MAX_VARIANT_NAME_PAIRS {
        log::warn!(
            "address guessing used only the top {MAX_VARIANT_NAME_PAIRS} name spellings ({} seen): the least common spellings were skipped",
            pairs.len()
        );
        pairs.truncate(MAX_VARIANT_NAME_PAIRS);
    }
    let mut matched: Vec<VariantMatch> = Vec::new();
    let mut matched_emails: BTreeSet<String> = BTreeSet::new();
    let mut generated: BTreeSet<String> = BTreeSet::new();
    for (first, last) in pairs {
        for domain in &domains {
            for (email, pattern) in
                generate_variants(&first, &last, domain, custom_variant_patterns)
            {
                if email_keys.contains(&email) {
                    // two known names can collapse onto the same
                    // generated address ("Jane Dupont" → (jane, dupont)
                    // and "J Dupont" → (j, dupont) both produce
                    // jdupont@…): the email is reported once, with the
                    // pattern of the first built-in-ordered pair that hit it
                    if matched_emails.insert(email.clone()) {
                        matched.push(VariantMatch {
                            email,
                            pattern,
                            domain: domain.clone(),
                        });
                    }
                } else if generated.len() < MAX_GENERATED_VARIANTS {
                    // the generated list is capped (a hostile target must
                    // not be able to inflate the report without bound);
                    // the matching above keeps running so a variant
                    // beyond the cap can still be reported as matched
                    generated.insert(email);
                }
            }
        }
    }
    if generated.len() >= MAX_GENERATED_VARIANTS {
        if custom_variant_patterns.is_empty() {
            log::warn!(
                "the list of guessed addresses stops at {MAX_GENERATED_VARIANTS} entries: extra guesses are not listed (confirmed addresses are unaffected)"
            );
        } else {
            log::warn!(
                "the list of guessed addresses stops at {MAX_GENERATED_VARIANTS} entries: extra guesses are not listed (confirmed addresses are unaffected); the built-in patterns alone can fill this list on a broad target, so custom --variant-pattern guesses that were confirmed are still reported but some unconfirmed ones may be missing from the list"
            );
        }
    }
    Variants {
        matched,
        generated: generated.into_iter().collect(),
    }
}
