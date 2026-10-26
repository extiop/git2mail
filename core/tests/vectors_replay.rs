// Tests may unwrap, expect and panic freely: a failing assertion must
// be loud, so the zero-panic lints do not apply to the test modules.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Parity vectors: the same fixtures pin the CLI crate and the WASM
//! bindings, so the browser applies exactly the same URL, email and
//! payload rules as the CLI. `web/wasm`'s tests replay these files too -
//! a vector updated here without the bindings failing is impossible.

use git2mail_core::parsers::parse_github_url;
use git2mail_core::parsing::parse_people_page;
use git2mail_core::rules::is_usable_email;
use git2mail_core::sanitize::sanitize_file_name;
use serde_json::Value;

fn vectors(name: &str) -> Vec<Value> {
    let raw = std::fs::read_to_string(
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/").to_string() + name,
    )
    .expect("the shared vector file must be readable");
    serde_json::from_str(&raw).expect("the shared vector file must be valid JSON")
}

#[test]
fn the_shared_url_vectors_replay_through_the_real_parser() {
    for case in vectors("urls.json") {
        let input = case["input"].as_str().expect("a string input");
        match parse_github_url(input) {
            Ok((owner, repository)) => {
                assert!(
                    case.get("expect_error").is_none(),
                    "vector {input:?} must be rejected, got owner={owner} repo={repository:?}"
                );
                assert_eq!(owner, case["expect"]["owner"], "vector {input:?}");
                let expected_repo = case["expect"]["repository"].as_str();
                assert_eq!(repository.as_deref(), expected_repo, "vector {input:?}");
            }
            Err(_) => assert!(
                case.get("expect_error").is_some(),
                "vector {input:?} must parse, it was rejected"
            ),
        }
    }
}

#[test]
fn the_shared_email_vectors_replay_through_the_shared_rule() {
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
fn the_shared_payload_vectors_replay_through_the_real_parser() {
    for case in vectors("payloads.json") {
        let (people, raw_count) =
            parse_people_page(&case["input"]).expect("vector payloads must parse");
        assert_eq!(raw_count, case["raw_count"], "vector {}", case["name"]);
        // the web-scan extraction rule: the author email, only when the
        // shared usable-email rule keeps it, with the name and date
        let extracted: Vec<Value> = people
            .iter()
            .filter_map(|commit| {
                let email = commit
                    .author_email
                    .as_deref()
                    .map(|e| e.trim_matches('"'))?;
                if !is_usable_email(email) {
                    return None;
                }
                Some(serde_json::json!({
                    "email": email,
                    "name": commit.author_name,
                    "date": commit.date,
                }))
            })
            .collect();
        let expected = case["expect"].as_array().expect("an array expectation");
        assert_eq!(extracted, *expected, "vector {}", case["name"]);
    }
}

#[test]
fn the_shared_name_vectors_replay_through_the_real_sanitizer() {
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
