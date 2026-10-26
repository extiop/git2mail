//! WebAssembly bindings for the git2mail web site: exposes the pure core
//! (URL rules, email/noreply discipline, payload parsing) to the browser,
//! so the site applies exactly the same rules as the CLI. The bindings
//! land with the site's scan page; the GUI itself stays in web languages
//! (ANSSI-FR/MLA issue #138's recommended shape). WASI 0.3 + `jco`
//! remains the documented escape route if the binding model evolves.
//!
//! The surface is deliberately tiny and string-typed: JSON in, JSON out,
//! no JS objects imported into Rust - the glue drives `fetch`, pagination
//! (the CLI's own page-number walk, ending on a short page) and the
//! rate-limit display from the exposed `X-RateLimit-*` headers.

use wasm_bindgen::prelude::wasm_bindgen;

/// Validates a pasted GitHub URL and extracts its target, applying exactly
/// the CLI's paste-artifact rules (trailing `/` trimmed, `?`/`#` leftovers
/// stripped, `.git` passed through verbatim, foreign hosts rejected…).
///
/// Returns a JSON object `{"owner": "…", "repository": "…"|"null"}` on
/// success, or the CLI's own error message (same text, terminal-safe) on
/// rejection.
#[wasm_bindgen]
pub fn normalize_url(input: &str) -> Result<String, String> {
    match git2mail_core::parsers::parse_github_url(input) {
        Ok((owner, repository)) => {
            Ok(serde_json::json!({ "owner": owner, "repository": repository }).to_string())
        }
        Err(error) => Err(error.to_string()),
    }
}

/// The shared email acceptance rule, applied before any address reaches a
/// result list: non-empty, no control character or whitespace, not a
/// GitHub noreply address (exact domain match, not substring luck), and
/// shaped like an address.
#[wasm_bindgen]
pub fn is_usable_email(address: &str) -> bool {
    git2mail_core::rules::is_usable_email(address)
}

/// Extracts the usable author identities of one `/commits` page, the same
/// rule the CLI's scan paths apply: the author email (never the
/// committer's - the scan contract), unquoted exactly like the CLI
/// reports it, filtered through the shared usable-email rule, with the
/// author name and the commit date for the results page.
///
/// `json` is one commits listing page (a JSON array). Returns a JSON array
/// of `{"email": "…", "name": "…"|"null", "date": "…"|"null"}`, or the
/// parse error message (a shape change must fail loudly, never yield a
/// complete-looking empty page).
///
/// Documented delta from the CLI: the per-page count of malformed
/// entries (a page whose `commit` objects are missing) is not part of
/// the return value - the browser glue cannot log it - so a malformed
/// entry is skipped silently here where the CLI warns; the parse-shape
/// failure (the dangerous case) still fails loudly.
#[wasm_bindgen]
pub fn extract_emails_from_commits(json: &str) -> Result<String, String> {
    let page: serde_json::Value = serde_json::from_str(json).map_err(|error| error.to_string())?;
    let (people, _raw_count) =
        git2mail_core::parsing::parse_people_page(&page).map_err(|error| error.to_string())?;
    let extracted: Vec<serde_json::Value> = people
        .iter()
        .filter_map(|commit| {
            // the CLI scan contract trims the git-permitted quoting before
            // reporting an address; emit exactly what the CLI would
            let email = commit
                .author_email
                .as_deref()
                .map(|e| e.trim_matches('"'))?;
            if !git2mail_core::rules::is_usable_email(email) {
                return None;
            }
            Some(serde_json::json!({
                "email": email,
                // the name is display data on the results page: the same
                // log-safety rule as the CLI's terminal report applies, so
                // a hostile commit can never carry bidi overrides or
                // invisible characters into the browser's DOM
                "name": commit
                    .author_name
                    .as_deref()
                    .map(git2mail_core::sanitize::log_safe),
                "date": commit.date,
            }))
        })
        .collect();
    serde_json::to_string(&extracted).map_err(|error| error.to_string())
}

/// Sanitizes a target name for a downloadable result file name, with the
/// CLI's exact rules: path separators and hostile characters replaced, a
/// Windows reserved device name prefixed, the anti-clobber hash for a
/// lossy replacement - so the browser's download carries the same file
/// name the CLI would write for the same target.
#[wasm_bindgen]
pub fn sanitize_file_name(name: &str) -> String {
    git2mail_core::sanitize::sanitize_file_name(name)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    /// The parity vectors live in `core/tests/vectors/` and pin the CLI
    /// crate's rules too - `core/tests/vectors_replay.rs` replays them
    /// through the real core parser. One file, both consumers, no drift
    /// possible.
    fn vectors(name: &str) -> Vec<serde_json::Value> {
        let path = format!(
            "{}/../../core/tests/vectors/{name}",
            env!("CARGO_MANIFEST_DIR")
        );
        let raw = std::fs::read_to_string(path).expect("the shared vector file must be readable");
        serde_json::from_str(&raw).expect("the shared vector file must be valid JSON")
    }

    #[test]
    fn the_shared_url_vectors_replay_through_the_binding() {
        for case in vectors("urls.json") {
            let input = case["input"].as_str().expect("a string input");
            match normalize_url(input) {
                Ok(json) => {
                    assert!(
                        case.get("expect_error").is_none(),
                        "vector {input:?} must be rejected, got {json}"
                    );
                    let parsed: serde_json::Value =
                        serde_json::from_str(&json).expect("the binding returns JSON");
                    assert_eq!(parsed["owner"], case["expect"]["owner"], "vector {input:?}");
                    assert_eq!(
                        parsed["repository"], case["expect"]["repository"],
                        "vector {input:?}"
                    );
                }
                Err(message) => assert!(
                    case.get("expect_error").is_some(),
                    "vector {input:?} must parse, it was rejected: {message}"
                ),
            }
        }
    }

    #[test]
    fn the_shared_email_vectors_replay_through_the_binding() {
        for case in vectors("emails.json") {
            let input = case["input"].as_str().expect("a string input");
            assert_eq!(
                is_usable_email(input),
                case["usable"].as_bool().expect("a boolean expectation"),
                "vector {input:?}"
            );
        }
    }

    #[test]
    fn the_shared_payload_vectors_replay_through_the_binding() {
        for case in vectors("payloads.json") {
            let input = serde_json::to_string(&case["input"]).expect("a JSON array");
            let extracted: serde_json::Value = serde_json::from_str(
                &extract_emails_from_commits(&input).expect("vector payloads must parse"),
            )
            .expect("the binding returns a JSON array");
            assert_eq!(extracted, case["expect"], "vector {}", case["name"]);
        }
    }

    #[test]
    fn the_shared_name_vectors_replay_through_the_binding() {
        for case in vectors("names.json") {
            let input = case["input"].as_str().expect("a string input");
            let name = sanitize_file_name(input);
            if let Some(expected) = case["expect"].as_str() {
                assert_eq!(name, expected, "vector {input:?}");
            }
            if let Some(prefix) = case["expect_prefix"].as_str() {
                assert!(
                    name.starts_with(prefix),
                    "vector {input:?}: {name} must start with {prefix}"
                );
            }
        }
    }

    #[test]
    fn a_hostile_author_name_is_sanitized_like_the_cli_report() {
        // bidi override and zero-width spacers become underscores, the
        // same rendering the CLI's terminal report produces
        let page = serde_json::json!([{
            "commit": { "author": { "name": "evil\u{202E}nimda\u{200B}x",
                                    "email": "dev@example.com" } }
        }]);
        let out = extract_emails_from_commits(&page.to_string()).expect("a page");
        let people: serde_json::Value = serde_json::from_str(&out).expect("an array");
        assert_eq!(people[0]["name"], "evil_nimda_x");
        assert_eq!(people[0]["email"], "dev@example.com");
    }

    #[test]
    fn a_malformed_payload_fails_loudly_never_as_an_empty_page() {
        let error = extract_emails_from_commits("not json").expect_err("must fail");
        assert!(
            error.contains("expected ident"),
            "unexpected message: {error}"
        );
        let error = extract_emails_from_commits("{}").expect_err("must fail");
        assert!(
            error.contains("not an array"),
            "a shape change must fail loudly: {error}"
        );
    }
}
