//! The single generic paginated fetch loop.
//!
//! All paginated GitHub API endpoints (commits, events, repos, search) go
//! through this one function instead of copying the fetch + token-rotation
//! logic four times.

use crate::errors::Error;
use crate::github::client::Client;
use serde_json::Value;

/// Fetches every page of a GitHub API listing.
///
/// - `build_url` maps a page number (starting at 1) to the request URL.
/// - `parse_page` extracts the items of interest from a page's JSON body; it
///   decides what an "item" is (`items` array, top-level array, …) and
///   returns the extracted items together with the raw number of items the
///   page contained.
/// - `limit` stops the listing early once that many items were collected;
///   `None` fetches every page.
///
/// The loop stops on the first page containing no raw item at all. Whether
/// `parse_page` managed to extract anything from those items must not end the
/// listing: a page whose every commit author uses a `noreply` address, say,
/// still holds commits, and the pages after it may hold real emails. A page
/// that legitimately holds no item at all (for instance a rejected search
/// returning `{"items": null}`) ends the listing: a partial result may then
/// be returned rather than an error.
///
/// On a rate-limit response the client rotates to its next token and retries;
/// when the token pool is exhausted the loop ends with
/// [`Error::RateLimitExhausted`] instead of spinning forever.
///
/// # Errors
///
/// The client's failures (`Error::Http`, `Error::Io` (an oversized
/// announced body), `Error::NotFound`, `Error::PrivateOrUnavailable`,
/// `Error::EmptyRepository`, `Error::RateLimitExhausted`,
/// `Error::TokenRejected`) plus any `parse_page` error. Never panics.
pub fn fetch_paginated<T, F>(
    client: &Client,
    build_url: impl Fn(u16) -> String,
    parse_page: F,
    limit: Option<usize>,
) -> Result<Vec<T>, Error>
where
    F: Fn(&Value) -> Result<(Vec<T>, usize), Error>,
{
    fetch_paginated_impl(client, build_url, parse_page, limit, 0)
}

/// The same paginated fetch, with page-size awareness for the search
/// endpoints (`per_page` is the `per_page` query parameter the request URLs
/// carry; `0` disables the two extra end conditions below).
///
/// The search API is the one listing family where walking one page too far
/// is not merely wasteful but lossy: once its documented 1000-result window
/// is crossed, it answers a raw `422` instead of an empty page, and a
/// defensive fallback would then have to throw the hits already collected
/// away. Two end conditions keep the walk inside the window:
///
/// - a page holding fewer raw items than `per_page` is the last page of the
///   listing (a total that is not a multiple of the page size used to keep
///   the walk alive up to the out-of-window request);
/// - the user `limit` counts **raw** listed items, not parsed ones - a
///   parser that drops listed items must not keep the walk alive past the
///   window either (the kept items are still truncated to `limit`).
///
/// The plain listings (commits, repos, members, keys) are answered with an
/// empty page past their end, so [`fetch_paginated`] needs neither condition
/// (the events walk is different: it uses the page-size-aware seam and its
/// raw-422 cap, documented in `sources/profile.rs`).
///
/// # Errors
///
/// The client's failures (`Error::Http`, `Error::Io` (an oversized
/// announced body), `Error::NotFound`, `Error::PrivateOrUnavailable`,
/// `Error::EmptyRepository`, `Error::RateLimitExhausted`,
/// `Error::TokenRejected`) plus any `parse_page` error. Never panics.
pub fn fetch_paginated_with_page_size<T, F>(
    client: &Client,
    build_url: impl Fn(u16) -> String,
    parse_page: F,
    limit: Option<usize>,
    per_page: u16,
) -> Result<Vec<T>, Error>
where
    F: Fn(&Value) -> Result<(Vec<T>, usize), Error>,
{
    fetch_paginated_impl(client, build_url, parse_page, limit, per_page)
}

/// The shared loop behind both entry points. The user `limit` is checked
/// against the raw listed items for the page-size-aware search seams
/// (`per_page > 0`) and against the kept items for the plain listings
/// (`per_page == 0`), whose pinned budget semantics stay unchanged.
fn fetch_paginated_impl<T, F>(
    client: &Client,
    build_url: impl Fn(u16) -> String,
    parse_page: F,
    limit: Option<usize>,
    per_page: u16,
) -> Result<Vec<T>, Error>
where
    F: Fn(&Value) -> Result<(Vec<T>, usize), Error>,
{
    let mut all_items: Vec<T> = Vec::new();
    let mut raw_seen: usize = 0;
    let mut page: u16 = 1;

    loop {
        let json: Value = client.get_json(&build_url(page))?;
        let (page_items, raw_item_count) = parse_page(&json)?;

        // No raw item on the page: we reached the end of the listing.
        if raw_item_count == 0 {
            return Ok(all_items);
        }
        raw_seen += raw_item_count;
        all_items.extend(page_items);

        // User limit reached: stop issuing requests, the next pages would
        // only be fetched to be thrown away. The page-size-aware search
        // seams count raw items (see [`fetch_paginated_with_page_size`]);
        // the plain listings keep counting the items kept so far.
        if let Some(limit) = limit
            && (if per_page > 0 {
                raw_seen >= limit
            } else {
                all_items.len() >= limit
            })
        {
            all_items.truncate(limit);
            return Ok(all_items);
        }

        // A short page is the last page of the listing: requesting past it
        // would only risk the search API's out-of-window 422. (GitHub's
        // search index can shift items between pages between requests, so a
        // transiently short middle page ends the listing early and a few
        // trailing results can be missed under index churn - an accepted
        // tradeoff: the condition preserves the hits already collected over
        // a lossy out-of-window walk, and the default small limits make it
        // immaterial.)
        if per_page > 0 && raw_item_count < usize::from(per_page) {
            return Ok(all_items);
        }

        // Guard against an absurd page count wrapping around: treat it as end
        // of listing rather than looping forever.
        match page.checked_add(1) {
            Some(next) => page = next,
            None => return Ok(all_items),
        }
    }
}

#[cfg(test)]
mod tests {
    // Tests may unwrap, expect and panic freely: a failing assertion must
    // be loud, so the zero-panic lints do not apply to the test modules.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::github::TokenPool;
    use crate::github::mock::{request_header, request_line_page, serve_requests, temp_token_file};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Parses a page of JSON strings, keeping the raw item count so the
    /// listing only ends on an actually empty page.
    fn parse_str_page(json: &Value) -> Result<(Vec<String>, usize), Error> {
        let items = json
            .as_array()
            .map(|array| {
                array
                    .iter()
                    .filter_map(|item| item.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        Ok((items, json.as_array().map_or(0, |a| a.len())))
    }

    #[test]
    fn fetch_paginated_stops_on_empty_page() {
        let (address, server) = serve_requests(move |index, _request| match index {
            0 => (200, vec![], r#"["page-one"]"#.to_string()),
            1 => (200, vec![], r#"["page-two"]"#.to_string()),
            _ => (200, vec![], "[]".to_string()),
        });

        let client = Client::anonymous().expect("client must build");
        let items: Vec<String> = fetch_paginated(
            &client,
            |page| format!("{address}/items?page={page}"),
            parse_str_page,
            None,
        )
        .expect("pagination must succeed");

        assert_eq!(items, vec!["page-one".to_string(), "page-two".to_string()]);
        // two content pages plus the empty page that ended the listing
        assert_eq!(
            client.requests_made(),
            3,
            "only successful pages are counted"
        );
        server.join();
    }

    #[test]
    fn fetch_paginated_rotates_token_on_rate_limit() {
        let (address, server) = serve_requests(move |_index, request| {
            let authorization = request_header(request, "Authorization").unwrap_or("");
            let page = request_line_page(request);
            match (authorization, page) {
                // first token is rate-limited (exhausted quota)…
                ("token ghp_a", _) => (
                    403,
                    vec![("X-RateLimit-Remaining".to_string(), "0".to_string())],
                    String::new(),
                ),
                // …so the request is retried with the next token
                (_, 1) => (200, vec![], r#"["after-rotation"]"#.to_string()),
                _ => (200, vec![], "[]".to_string()),
            }
        });

        // two tokens so the 403 can rotate to the second one
        let path = temp_token_file(r#"{"0": "ghp_a", "1": "ghp_b"}"#, 1);
        let pool = TokenPool::from_token_file(&path).expect("token file must load");
        std::fs::remove_file(&path).ok();
        let client = Client::new(pool).expect("client must build");
        let items: Vec<String> = fetch_paginated(
            &client,
            |page| format!("{address}/items?page={page}"),
            parse_str_page,
            None,
        )
        .expect("rotation must recover from the 403");

        assert_eq!(items, vec!["after-rotation".to_string()]);
        server.join();
    }

    #[test]
    fn exhausted_tokens_are_skipped_on_later_pages() {
        let (address, server) = serve_requests(move |_index, request| {
            let authorization = request_header(request, "Authorization").unwrap_or("");
            let page = request_line_page(request);
            if authorization == "token ghp_a" {
                // always rate-limited: marked exhausted after the first hit
                return (
                    403,
                    vec![("X-RateLimit-Remaining".to_string(), "0".to_string())],
                    String::new(),
                );
            }
            let body = match page {
                1 => r#"["one"]"#.to_string(),
                2 => r#"["two"]"#.to_string(),
                _ => "[]".to_string(),
            };
            (200, vec![], body)
        });

        let path = temp_token_file(r#"{"0": "ghp_a", "1": "ghp_b"}"#, 2);
        let pool = TokenPool::from_token_file(&path).expect("token file must load");
        std::fs::remove_file(&path).ok();
        let client = Client::new(pool).expect("client must build");
        let items: Vec<String> = fetch_paginated(
            &client,
            |page| format!("{address}/items?page={page}"),
            parse_str_page,
            None,
        )
        .expect("the live token must serve every page");

        assert_eq!(items, vec!["one".to_string(), "two".to_string()]);
        // page 1: one doomed request with the dead token, one with the live
        // one; pages 2 and 3 (empty): the dead token must be skipped, so
        // exactly 4 requests in total instead of 2 per page without memory
        let handled = server.join();
        assert_eq!(handled, 4, "exhausted tokens must be skipped");
    }

    #[test]
    fn fetch_paginated_rotates_on_429_and_honors_retry_after() {
        let (address, server) = serve_requests(move |_index, request| {
            let authorization = request_header(request, "Authorization").unwrap_or("");
            let page = request_line_page(request);
            if authorization == "token ghp_a" {
                // secondary rate limit: 429 with a `Retry-After` window longer
                // than the test, so the token stays parked for the whole scan
                return (
                    429,
                    vec![("Retry-After".to_string(), "60".to_string())],
                    String::new(),
                );
            }
            match page {
                1 => (200, vec![], r#"["after-429"]"#.to_string()),
                _ => (200, vec![], "[]".to_string()),
            }
        });

        // two tokens so the 429 can rotate to the second one
        let path = temp_token_file(r#"{"0": "ghp_a", "1": "ghp_b"}"#, 3);
        let pool = TokenPool::from_token_file(&path).expect("token file must load");
        std::fs::remove_file(&path).ok();
        let client = Client::new(pool).expect("client must build");
        let items: Vec<String> = fetch_paginated(
            &client,
            |page| format!("{address}/items?page={page}"),
            parse_str_page,
            None,
        )
        .expect("rotation must recover from the 429");

        assert_eq!(items, vec!["after-429".to_string()]);
        let handled = server.join();
        // page 1: one 429 with the first token, one 200 with the second one;
        // page 2: empty page served directly by the second token (the first
        // one is parked until its Retry-After window passes)
        assert_eq!(handled, 3);
    }

    #[test]
    fn secondary_rate_limited_token_is_reused_after_its_window() {
        // a secondary rate limit does not spend the token quota: once its
        // (already elapsed) `Retry-After` window is over, the token is live
        // again instead of being retired for the rest of the process
        let (address, server) = serve_requests(move |_index, request| {
            let authorization = request_header(request, "Authorization").unwrap_or("");
            let page = request_line_page(request);
            if authorization == "token ghp_a" {
                return (
                    429,
                    vec![("Retry-After".to_string(), "0".to_string())],
                    String::new(),
                );
            }
            match page {
                1 => (200, vec![], r#"["after-429"]"#.to_string()),
                _ => (200, vec![], "[]".to_string()),
            }
        });

        let path = temp_token_file(r#"{"0": "ghp_a", "1": "ghp_b"}"#, 4);
        let pool = TokenPool::from_token_file(&path).expect("token file must load");
        std::fs::remove_file(&path).ok();
        let client = Client::new(pool).expect("client must build");
        let items: Vec<String> = fetch_paginated(
            &client,
            |page| format!("{address}/items?page={page}"),
            parse_str_page,
            None,
        )
        .expect("rotation must recover from the 429");

        assert_eq!(items, vec!["after-429".to_string()]);
        let handled = server.join();
        // page 1: one 429 with the first token, one 200 with the second one;
        // page 2: the recovered first token is tried once more (429), then the
        // second one serves the empty page
        assert_eq!(handled, 4);
    }

    #[test]
    fn failed_responses_are_not_counted_as_successful_requests() {
        // a 401/5xx response propagates an error and must not inflate the
        // page count reported in the JSON output
        let (address, server) =
            serve_requests(move |_index, _request| (401, vec![], String::new()));

        let client = Client::anonymous().expect("client must build");
        let error = fetch_paginated(
            &client,
            |page| format!("{address}/items?page={page}"),
            |json: &Value| {
                Ok((
                    vec![json.as_array().map(|a| a.len()).unwrap_or(0)],
                    json.as_array().map_or(0, |a| a.len()),
                ))
            },
            None,
        )
        .expect_err("a 401 must fail");

        // the 401 surfaces as the crafted rejected-token error (anonymous
        // pool: nothing to rotate to), not as a raw HTTP error
        assert!(matches!(error, Error::TokenRejected));
        assert_eq!(client.requests_made(), 0, "a failed response is not a page");
        server.join();
    }

    #[test]
    fn fetch_paginated_maps_non_rate_limit_403_to_private_or_unavailable() {
        // a plain 403 (private repo, missing scope…) is permanent: it must
        // not be reported as a rate limit, and must not rotate the pool
        let (address, server) =
            serve_requests(move |_index, _request| (403, vec![], String::new()));

        let client = Client::new(TokenPool::from_token("ghp_a").expect("valid token"))
            .expect("client must build");
        let error = fetch_paginated(
            &client,
            |page| format!("{address}/items?page={page}"),
            |json: &Value| {
                Ok((
                    vec![json.as_array().map(|a| a.len()).unwrap_or(0)],
                    json.as_array().map_or(0, |a| a.len()),
                ))
            },
            None,
        )
        .expect_err("a plain 403 must fail");

        assert!(matches!(error, Error::PrivateOrUnavailable));
        let handled = server.join();
        assert_eq!(handled, 1, "a permanent 403 must not rotate the pool");
    }

    #[test]
    fn fetch_paginated_returns_rate_limit_exhausted_when_pool_is_drained() {
        let (address, server) = serve_requests(move |_index, _request| {
            (
                403,
                vec![("X-RateLimit-Remaining".to_string(), "0".to_string())],
                String::new(),
            )
        });

        let client = Client::new(TokenPool::from_token("ghp_a").expect("valid token"))
            .expect("client must build");
        let error = fetch_paginated(
            &client,
            |page| format!("{address}/items?page={page}"),
            |json: &Value| {
                Ok((
                    vec![json.as_array().map(|a| a.len()).unwrap_or(0)],
                    json.as_array().map_or(0, |a| a.len()),
                ))
            },
            None,
        )
        .expect_err("every token being rate-limited must fail");

        assert!(matches!(error, Error::RateLimitExhausted));
        server.join();
    }

    #[test]
    fn fetch_paginated_maps_404_to_not_found() {
        let (address, server) =
            serve_requests(move |_index, _request| (404, vec![], String::new()));

        let client = Client::anonymous().expect("client must build");
        let error = fetch_paginated(
            &client,
            |page| format!("{address}/items?page={page}"),
            |json: &Value| {
                Ok((
                    vec![json.as_array().map(|a| a.len()).unwrap_or(0)],
                    json.as_array().map_or(0, |a| a.len()),
                ))
            },
            None,
        )
        .expect_err("404 must surface as NotFound");

        assert!(matches!(error, Error::NotFound));
        server.join();
    }

    #[test]
    fn fetch_paginated_maps_a_409_on_a_commits_listing_to_empty_repository() {
        // GitHub answers 409 Conflict on a `/commits` listing when the
        // repository has no commits ("Git Repository is empty"): it must
        // surface as the dedicated EmptyRepository error - the resource-
        // scoped skip condition of every scan - not as a raw HTTP failure
        let (address, server) =
            serve_requests(move |_index, _request| (409, vec![], String::new()));

        let client = Client::anonymous().expect("client must build");
        let error = fetch_paginated(
            &client,
            |page| format!("{address}/repos/octocat/hello-world/commits?page={page}"),
            |json: &Value| {
                Ok((
                    vec![json.as_array().map(|a| a.len()).unwrap_or(0)],
                    json.as_array().map_or(0, |a| a.len()),
                ))
            },
            None,
        )
        .expect_err("409 must surface as EmptyRepository");

        assert!(matches!(error, Error::EmptyRepository));
        server.join();
    }

    #[test]
    fn a_409_from_an_endpoint_other_than_commits_is_a_raw_http_error() {
        // the "empty repository" meaning only holds for a `/commits`
        // listing: a 409 from any other endpoint (a broken or hostile
        // intermediary answering a members/repos/metadata request) must
        // surface as the raw HTTP error, not as a claim about a repository
        // the endpoint does not even list
        let (address, server) =
            serve_requests(move |_index, _request| (409, vec![], String::new()));

        let client = Client::anonymous().expect("client must build");
        for path in [
            "/orgs/acme/members?page=1",
            "/users/octocat/repos?page=1",
            "/repos/octocat/hello-world?page=1",
            "/search/repositories?q=x&per_page=100&page=1",
        ] {
            let error = fetch_paginated(
                &client,
                |page| format!("{address}{path}#{page}"),
                parse_str_page,
                None,
            )
            .expect_err("a non-commits 409 must surface as an HTTP error");
            assert!(
                matches!(&error, Error::Http(http) if http.status() == Some(reqwest::StatusCode::CONFLICT)),
                "unexpected error for {path}: {error:?}"
            );
        }
        server.join();
    }

    #[test]
    fn a_200_with_a_spent_quota_header_is_a_valid_page() {
        // GitHub sends `X-RateLimit-Remaining: 0` on the request that
        // consumes the last credit of the hour: that response is a valid
        // page, not a rate limit, and must not retire the token
        let (address, server) = serve_requests(move |_index, _request| {
            (
                200,
                vec![("X-RateLimit-Remaining".to_string(), "0".to_string())],
                match _index {
                    0 => r#"["last-credit-page"]"#.to_string(),
                    _ => "[]".to_string(),
                },
            )
        });

        let client = Client::anonymous().expect("client must build");
        let items: Vec<String> = fetch_paginated(
            &client,
            |page| format!("{address}/items?page={page}"),
            parse_str_page,
            None,
        )
        .expect("a successful page must be returned even with a spent-quota header");

        assert_eq!(items, vec!["last-credit-page".to_string()]);
        // two successful pages with the single anonymous token: had the
        // header been misread as a spent quota, the token would have been
        // retired and the fetch would have failed with RateLimitExhausted
        assert_eq!(client.requests_made(), 2);
        server.join();
    }

    #[test]
    fn an_absurd_retry_after_does_not_overflow_the_deadline() {
        // a hostile server can send a `Retry-After` whose seconds overflow
        // `Instant + Duration` (which panics): the header must be capped
        // instead of crashing the scan
        let (address, server) = serve_requests(move |_index, request| {
            let authorization = request_header(request, "Authorization").unwrap_or("");
            let page = request_line_page(request);
            if authorization == "token ghp_a" {
                return (
                    429,
                    vec![(
                        "Retry-After".to_string(),
                        "18446744073709551615".to_string(),
                    )],
                    String::new(),
                );
            }
            match page {
                1 => (200, vec![], r#"["after-hostile-429"]"#.to_string()),
                _ => (200, vec![], "[]".to_string()),
            }
        });

        let path = temp_token_file(r#"{"0": "ghp_a", "1": "ghp_b"}"#, 5);
        let pool = TokenPool::from_token_file(&path).expect("token file must load");
        std::fs::remove_file(&path).ok();
        let client = Client::new(pool).expect("client must build");
        let items: Vec<String> = fetch_paginated(
            &client,
            |page| format!("{address}/items?page={page}"),
            parse_str_page,
            None,
        )
        .expect("the capped Retry-After must rotate instead of panicking");

        assert_eq!(items, vec!["after-hostile-429".to_string()]);
        let handled = server.join();
        // page 1: one 429 with the first token (parked up to the ceiling),
        // one 200 with the second one; page 2: the parked token is skipped
        assert_eq!(handled, 3);
    }

    #[test]
    fn a_401_on_one_token_rotates_to_the_next_live_token() {
        // a revoked token in the pool is retired like a spent quota and the
        // request rotates to the next live token, mirroring the worker
        // pools' token-scoped 401 handling: one rejected token must not
        // abort a run while healthy tokens sit in the pool
        let (address, server) = serve_requests(move |_index, request| {
            let authorization = request_header(request, "Authorization").unwrap_or("");
            let page = request_line_page(request);
            if authorization == "token ghp_a" {
                // the revoked token: the API rejects it every time
                return (401, vec![], String::new());
            }
            match page {
                1 => (200, vec![], r#"["after-401"]"#.to_string()),
                _ => (200, vec![], "[]".to_string()),
            }
        });

        let path = temp_token_file(r#"{"0": "ghp_a", "1": "ghp_b"}"#, 6);
        let pool = TokenPool::from_token_file(&path).expect("token file must load");
        std::fs::remove_file(&path).ok();
        let client = Client::new(pool).expect("client must build");
        let items: Vec<String> = fetch_paginated(
            &client,
            |page| format!("{address}/items?page={page}"),
            parse_str_page,
            None,
        )
        .expect("the healthy token must serve the listing past the revoked one");

        assert_eq!(items, vec!["after-401".to_string()]);
        let handled = server.join();
        // page 1: one 401 with the revoked token, one 200 with the live one;
        // page 2: the revoked token is retired, the live one serves
        assert_eq!(handled, 3);
    }

    #[test]
    fn a_403_with_an_http_date_retry_after_is_a_transient_limit() {
        // the RFC 7231 HTTP-date form of `Retry-After` does not parse as
        // integer seconds, but the header still signals a transient
        // condition: the token is parked for the default window and the pool
        // rotates, instead of the response being treated as a permanent
        // private-resource refusal
        let (address, server) = serve_requests(move |_index, request| {
            let authorization = request_header(request, "Authorization").unwrap_or("");
            let page = request_line_page(request);
            if authorization == "token ghp_a" {
                return (
                    403,
                    vec![(
                        "Retry-After".to_string(),
                        "Wed, 21 Oct 2015 07:28:00 GMT".to_string(),
                    )],
                    String::new(),
                );
            }
            match page {
                1 => (200, vec![], r#"["after-date-403"]"#.to_string()),
                _ => (200, vec![], "[]".to_string()),
            }
        });

        let path = temp_token_file(r#"{"0": "ghp_a", "1": "ghp_b"}"#, 7);
        let pool = TokenPool::from_token_file(&path).expect("token file must load");
        std::fs::remove_file(&path).ok();
        let client = Client::new(pool).expect("client must build");
        let items: Vec<String> = fetch_paginated(
            &client,
            |page| format!("{address}/items?page={page}"),
            parse_str_page,
            None,
        )
        .expect("a Retry-After-carrying 403 must rotate instead of failing");

        assert_eq!(items, vec!["after-date-403".to_string()]);
        let handled = server.join();
        // page 1: one 403 with the parked token, one 200 with the live one;
        // page 2: the parked token is skipped (default park window), the
        // live one serves the empty page
        assert_eq!(handled, 3);
    }

    #[test]
    fn a_401_surfaces_as_the_crafted_rejected_token_error() {
        // a revoked or invalid token surfaces at request time as a 401: with
        // nothing to rotate to, the rejection must be the crafted
        // [`Error::TokenRejected`] (status and next step included), not raw
        // reqwest jargon the user cannot act on
        let (address, server) =
            serve_requests(move |_index, _request| (401, vec![], String::new()));

        let client = Client::new(TokenPool::from_token("ghp_a").expect("valid token"))
            .expect("client must build");
        let error = fetch_paginated(
            &client,
            |page| format!("{address}/items?page={page}"),
            |json: &Value| {
                Ok((
                    vec![json.as_array().map(|a| a.len()).unwrap_or(0)],
                    json.as_array().map_or(0, |a| a.len()),
                ))
            },
            None,
        )
        .expect_err("a 401 must fail");

        assert!(matches!(error, Error::TokenRejected));
        assert!(
            error.to_string().contains("401 Unauthorized")
                && error.to_string().contains("create a new token"),
            "unexpected message: {error}"
        );
        server.join();
    }

    #[test]
    fn a_page_without_usable_emails_does_not_end_the_listing() {
        // every commit of the first page uses a noreply address: the page is
        // parsed to zero emails but still holds raw items, so the listing
        // must continue and find the real email on the next page
        let (address, server) = serve_requests(move |index, _request| {
            match index {
            0 => (
                200,
                vec![],
                r#"[{"commit": {"author": {"email": "12345+dev@users.noreply.github.com"}}}, {"commit": {"author": {"email": "67890+other@users.noreply.github.com"}}}]"#.to_string(),
            ),
            1 => (
                200,
                vec![],
                r#"[{"commit": {"author": {"email": "dev@example.com"}}}]"#.to_string(),
            ),
            _ => (200, vec![], "[]".to_string()),
        }
        });

        let client = Client::anonymous().expect("client must build");
        let emails: Vec<String> = fetch_paginated(
            &client,
            |page| format!("{address}/commits?page={page}"),
            |json: &Value| {
                let items = json.as_array().map(|array| array.len()).unwrap_or(0);
                let mut emails: Vec<String> = Vec::new();
                for item in json.as_array().map(|array| array.as_slice()).unwrap_or(&[]) {
                    if let Some(email) = item
                        .get("commit")
                        .and_then(|commit| commit.get("author"))
                        .and_then(|author| author.get("email"))
                        .and_then(Value::as_str)
                        && !email.contains("noreply")
                    {
                        emails.push(email.to_string());
                    }
                }
                Ok((emails, items))
            },
            None,
        )
        .expect("the noreply-only page must not end the listing");

        assert_eq!(emails, vec!["dev@example.com".to_string()]);
        // noreply-only page, real-email page, then the empty page that ended
        // the listing
        assert_eq!(client.requests_made(), 3);
        server.join();
    }

    #[test]
    fn the_limit_stops_the_listing_without_fetching_extra_pages() {
        let (address, server) = serve_requests(move |index, _request| match index {
            0 => (200, vec![], r#"["one", "two", "three"]"#.to_string()),
            _ => (200, vec![], "[]".to_string()),
        });

        let client = Client::anonymous().expect("client must build");
        let items: Vec<String> = fetch_paginated(
            &client,
            |page| format!("{address}/items?page={page}"),
            parse_str_page,
            Some(2),
        )
        .expect("pagination must succeed");

        // the page held 3 items but the limit is 2: the second page must
        // never be requested
        assert_eq!(items, vec!["one".to_string(), "two".to_string()]);
        assert_eq!(client.requests_made(), 1, "no page fetched past the limit");
        server.join();
    }

    #[test]
    fn a_short_page_is_the_last_page_of_a_page_size_aware_listing() {
        // page 2 holds fewer raw items than the requested page size: it is
        // the last page of the listing, and page 3 (which the mock would
        // answer with the search API's out-of-window 422 shape) is never
        // requested
        let (address, server) = serve_requests(move |index, _request| match index {
            0 => (200, vec![], r#"["one", "two", "three"]"#.to_string()),
            1 => (200, vec![], r#"["four"]"#.to_string()),
            _ => (200, vec![], r#"{"message": "past the window"}"#.to_string()),
        });

        let client = Client::anonymous().expect("client must build");
        let items: Vec<String> = fetch_paginated_with_page_size(
            &client,
            |page| format!("{address}/items?page={page}"),
            parse_str_page,
            None,
            3,
        )
        .expect("the short page must end the listing");

        assert_eq!(
            items,
            vec![
                "one".to_string(),
                "two".to_string(),
                "three".to_string(),
                "four".to_string()
            ]
        );
        // the two content pages only: no page was fetched past the short one
        assert_eq!(server.join(), 2);
    }

    #[test]
    fn the_page_size_aware_limit_counts_raw_items_a_parser_drops() {
        // every listed item counts toward the user limit, kept or not: a
        // parser that drops listed items must not keep the walk alive up to
        // the search API's out-of-window request
        let (address, server) = serve_requests(move |index, _request| match index {
            0 => (200, vec![], r#"["drop", "drop", "keep"]"#.to_string()),
            _ => (200, vec![], r#"{"message": "past the window"}"#.to_string()),
        });

        let client = Client::anonymous().expect("client must build");
        let items: Vec<String> = fetch_paginated_with_page_size(
            &client,
            |page| format!("{address}/items?page={page}"),
            |json: &Value| {
                let raw = json.as_array().map_or(0, |a| a.len());
                let kept: Vec<String> = json
                    .as_array()
                    .map(|array| {
                        array
                            .iter()
                            .filter_map(|item| item.as_str())
                            .filter(|item| *item == "keep")
                            .map(str::to_string)
                            .collect()
                    })
                    .unwrap_or_default();
                Ok((kept, raw))
            },
            Some(3),
            3,
        )
        .expect("the raw count must stop the listing");

        // the page held 3 raw items: the limit is reached even though only 1
        // was kept, and the next page was never requested
        assert_eq!(items, vec!["keep".to_string()]);
        assert_eq!(server.join(), 1, "no page fetched past the raw limit");
    }

    #[test]
    fn a_403_secondary_response_without_retry_after_rotates_instead_of_failing() {
        // GitHub signals some secondary limits through a 403 abuse body with
        // no `Retry-After` header: the limit is transient, so the pool must
        // rotate instead of failing with a misleading "private or
        // unavailable"
        let (address, server) = serve_requests(move |_index, request| {
            let authorization = request_header(request, "Authorization").unwrap_or("");
            let page = request_line_page(request);
            if authorization == "token ghp_a" {
                return (
                    403,
                    vec![],
                    r#"{"message": "You have exceeded a secondary rate limit"}"#.to_string(),
                );
            }
            match page {
                1 => (200, vec![], r#"["after-403-secondary"]"#.to_string()),
                _ => (200, vec![], "[]".to_string()),
            }
        });

        let path = temp_token_file(r#"{"0": "ghp_a", "1": "ghp_b"}"#, 8);
        let pool = TokenPool::from_token_file(&path).expect("token file must load");
        std::fs::remove_file(&path).ok();
        let client = Client::new(pool).expect("client must build");
        let items: Vec<String> = fetch_paginated(
            &client,
            |page| format!("{address}/items?page={page}"),
            parse_str_page,
            None,
        )
        .expect("the abuse 403 must rotate to the next token");

        assert_eq!(items, vec!["after-403-secondary".to_string()]);
        let handled = server.join();
        // page 1: one 403 with the first token (parked, no header), one 200
        // with the second one; page 2: the parked first token is skipped, the
        // second one serves the empty page
        assert_eq!(handled, 3);
    }

    #[test]
    fn a_403_with_a_headerless_primary_limit_body_is_a_transient_limit() {
        // GitHub's primary-limit body ("API rate limit exceeded…") can reach
        // the client without its `X-RateLimit-Remaining` header (stripped by
        // a middlebox or a proxy) and without `Retry-After`: the response is
        // still a rate limit, not a permanent refusal - misclassifying it as
        // one would make a fully rate-limited scan skip every repository as
        // a resource-scoped failure and exit 0 with an empty report
        let (address, server) = serve_requests(move |_index, request| {
            let authorization = request_header(request, "Authorization").unwrap_or("");
            let page = request_line_page(request);
            if authorization == "token ghp_a" {
                return (
                    403,
                    vec![],
                    r#"{"message": "API rate limit exceeded for 1.2.3.4"}"#.to_string(),
                );
            }
            match page {
                1 => (200, vec![], r#"["after-headerless-403"]"#.to_string()),
                _ => (200, vec![], "[]".to_string()),
            }
        });

        let path = temp_token_file(r#"{"0": "ghp_a", "1": "ghp_b"}"#, 9);
        let pool = TokenPool::from_token_file(&path).expect("token file must load");
        std::fs::remove_file(&path).ok();
        let client = Client::new(pool).expect("client must build");
        let items: Vec<String> = fetch_paginated(
            &client,
            |page| format!("{address}/items?page={page}"),
            parse_str_page,
            None,
        )
        .expect("the headerless rate-limit 403 must rotate to the next token");

        assert_eq!(items, vec!["after-headerless-403".to_string()]);
        let handled = server.join();
        // page 1: one 403 with the first token (parked), one 200 with the
        // second one; page 2: the parked first token is skipped, the second
        // one serves the empty page
        assert_eq!(handled, 3);
    }

    #[test]
    fn an_anonymous_request_sends_no_authorization_header() {
        // the Authorization header is injected only when the token
        // is non-empty - an anonymous client must not leak an empty
        // `Authorization: token ` header (GitHub would 401 it, the mock
        // would not, so it is pinned explicitly here), and the centralized
        // User-Agent/Accept headers must be present
        let (address, server) = serve_requests(move |index, request| {
            if request_header(request, "Authorization").is_some()
                || request_header(request, "User-Agent").is_none()
                || request_header(request, "Accept").is_none()
            {
                return (500, vec![], String::new());
            }
            match index {
                0 => (200, vec![], r#"["anonymous-page"]"#.to_string()),
                _ => (200, vec![], "[]".to_string()),
            }
        });

        let client = Client::anonymous().expect("client must build");
        let items: Vec<String> = fetch_paginated(
            &client,
            |page| format!("{address}/items?page={page}"),
            parse_str_page,
            None,
        )
        .expect("an anonymous request must not carry an Authorization header");

        assert_eq!(items, vec!["anonymous-page".to_string()]);
        server.join();
    }

    #[test]
    fn a_secondary_limit_with_no_other_live_token_ends_the_fetch_immediately() {
        // single token: a 429 with a pending Retry-After window has nothing
        // to rotate to, so the fetch must end with RateLimitExhausted after
        // exactly one request - no doomed retry, no sleep
        let (address, server) = serve_requests(move |_index, _request| {
            (
                429,
                vec![("Retry-After".to_string(), "60".to_string())],
                String::new(),
            )
        });

        let client = Client::new(TokenPool::from_token("ghp_a").expect("valid token"))
            .expect("client must build");
        let error = fetch_paginated(
            &client,
            |page| format!("{address}/items?page={page}"),
            parse_str_page,
            None,
        )
        .expect_err("the single parked token must end the fetch");

        assert!(matches!(error, Error::RateLimitPaused));
        let handled = server.join();
        assert_eq!(handled, 1, "no doomed retry when nothing can rotate");
    }

    #[test]
    fn a_200_with_a_malformed_json_body_is_an_error_not_a_page() {
        let (address, server) =
            serve_requests(move |_index, _request| (200, vec![], "not json".to_string()));

        let client = Client::anonymous().expect("client must build");
        let error = fetch_paginated(
            &client,
            |page| format!("{address}/items?page={page}"),
            parse_str_page,
            None,
        )
        .expect_err("a malformed body must fail");

        // reqwest decodes the JSON body itself, so the failure surfaces as an
        // HTTP decode error (Error::Http with is_decode), not Error::Json -
        // the page must not be silently swallowed either way
        assert!(
            matches!(
                &error,
                Error::Http(http) if http.is_decode()
            ),
            "unexpected error: {error:?}"
        );
        server.join();
    }

    #[test]
    fn a_403_with_both_a_spent_quota_and_a_retry_after_is_a_primary_exhaustion() {
        // the quota check runs before the secondary-limit check: a 403
        // carrying both `X-RateLimit-Remaining: 0` and a `Retry-After` must
        // retire the token for the rest of the process, not only park it
        let retried = Arc::new(AtomicUsize::new(0));
        let (address, server) = {
            let retried = Arc::clone(&retried);
            serve_requests(move |_index, request| {
                let authorization = request_header(request, "Authorization").unwrap_or("");
                if authorization == "token ghp_a" {
                    retried.fetch_add(1, Ordering::Relaxed);
                    return (
                        403,
                        vec![
                            ("X-RateLimit-Remaining".to_string(), "0".to_string()),
                            // an already-elapsed window: a parked token would
                            // be live again on the very next request
                            ("Retry-After".to_string(), "0".to_string()),
                        ],
                        String::new(),
                    );
                }
                match request_line_page(request) {
                    1 | 2 => (200, vec![], r#"["page"]"#.to_string()),
                    _ => (200, vec![], "[]".to_string()),
                }
            })
        };

        let path = temp_token_file(r#"{"0": "ghp_a", "1": "ghp_b"}"#, 10);
        let pool = TokenPool::from_token_file(&path).expect("token file must load");
        std::fs::remove_file(&path).ok();
        let client = Client::new(pool).expect("client must build");
        let items: Vec<String> = fetch_paginated(
            &client,
            |page| format!("{address}/items?page={page}"),
            parse_str_page,
            None,
        )
        .expect("the healthy token must serve the listing");

        assert_eq!(items, vec!["page".to_string(), "page".to_string()]);
        server.join();
        // a retired token is never tried again: exactly one 403 exchange. Had
        // the response been misread as a secondary limit with an elapsed
        // Retry-After window, the token would have been parked only until
        // `Instant::now()` and retried on every later page
        assert_eq!(retried.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn a_search_quota_403_with_a_retry_after_parks_instead_of_retiring() {
        // The `/search/` endpoints run on a separate, per-minute quota: its
        // exhaustion 403 carries `X-RateLimit-Remaining: 0` (the *search*
        // quota's) and a `Retry-After` window that resets within seconds,
        // while the token's hourly core quota is untouched. Such a response
        // must park the token (transient), never retire it for the rest of
        // the process - a retirement would kill single-token runs and burn
        // multi-token pools one token per hot search minute.
        let (address, server) = serve_requests(move |index, request| {
            if index == 0 {
                return (
                    403,
                    vec![
                        ("X-RateLimit-Remaining".to_string(), "0".to_string()),
                        ("Retry-After".to_string(), "0".to_string()),
                    ],
                    String::new(),
                );
            }
            match request_line_page(request) {
                1 => (200, vec![], r#"["page"]"#.to_string()),
                _ => (200, vec![], "[]".to_string()),
            }
        });

        let client = Client::new(TokenPool::from_token("ghp_a").expect("valid token"))
            .expect("client must build");
        let items: Vec<String> = fetch_paginated(
            &client,
            |page| format!("{address}/search/repositories?q=x&page={page}"),
            parse_str_page,
            None,
        )
        .expect("a search-quota blip must not retire the token");

        assert_eq!(items, vec!["page".to_string()]);
        let handled = server.join();
        // the retried search page 1 plus the empty page 2 that ends the listing
        assert_eq!(handled, 3, "the token must be retried, not retired");
    }

    #[test]
    fn a_spent_search_quota_without_a_retry_after_fails_promptly_never_retiring() {
        // Live GitHub search exhaustion 403s do not always carry a
        // `Retry-After` header (live-captured: `x-ratelimit-resource:
        // search`, `x-ratelimit-remaining: 0`, the primary-limit body, no
        // window): the spent *search* quota is still transient (the core
        // quota is untouched, the window resets within seconds), so the
        // token is only parked. A sole parked token has nothing to rotate
        // to and sleeping would only delay the failure, so the fetch still
        // ends promptly with `RateLimitExhausted` - but the token itself
        // must survive the blip instead of being retired for the process.
        let (address, server) = serve_requests(move |_index, _request| {
            (
                403,
                vec![
                    ("X-RateLimit-Remaining".to_string(), "0".to_string()),
                    ("X-RateLimit-Resource".to_string(), "search".to_string()),
                ],
                "API rate limit exceeded for user ID 29679238.".to_string(),
            )
        });

        let client = Client::new(TokenPool::from_token("ghp_a").expect("valid token"))
            .expect("client must build");
        let error = fetch_paginated(
            &client,
            |page| format!("{address}/search/repositories?q=x&page={page}"),
            parse_str_page,
            None,
        )
        .expect_err("a sole parked token must end the fetch promptly");

        assert!(matches!(error, Error::RateLimitPaused));
        assert_eq!(server.join(), 1, "no doomed retry when nothing can rotate");
        // parked, not retired: the pool recovers once the window passes
        assert!(
            !client.tokens().is_retired(0),
            "the search-quota blip must not permanently retire the token"
        );
    }

    #[test]
    fn a_zero_retry_after_on_a_sole_token_gets_a_free_immediate_retry() {
        // RFC 7231 `Retry-After: 0` authorizes an immediate retry: the token
        // is already live again and sleeping would cost zero anyway, so one
        // extra request is paid instead of aborting the whole fetch
        let (address, server) = serve_requests(move |index, request| {
            if index == 0 {
                return (
                    429,
                    vec![("Retry-After".to_string(), "0".to_string())],
                    String::new(),
                );
            }
            match request_line_page(request) {
                1 => (200, vec![], r#"["retried"]"#.to_string()),
                _ => (200, vec![], "[]".to_string()),
            }
        });

        let client = Client::new(TokenPool::from_token("ghp_a").expect("valid token"))
            .expect("client must build");
        let items: Vec<String> = fetch_paginated(
            &client,
            |page| format!("{address}/items?page={page}"),
            parse_str_page,
            None,
        )
        .expect("a Retry-After of 0 must authorize a zero-cost retry");

        assert_eq!(items, vec!["retried".to_string()]);
        // the retried page 1 plus the empty page 2 that ends the listing
        let handled = server.join();
        assert_eq!(handled, 3);
    }

    #[test]
    fn a_plain_429_without_any_header_parks_never_refuses_permanently() {
        // GitHub's plain secondary-limit 429s carry no `Retry-After` and no
        // quota headers: the status alone must classify as TRANSIENT (a
        // park), never as a permanent refusal. Two headerless 429s drain a
        // two-token pool into the dedicated `RateLimitPaused` error (the
        // honest "every token is parked for a minutes-long window" failure);
        // the regression this pins is the classification flip to a
        // permanent 403-shaped `PrivateOrUnavailable`, which would abort
        // single-token scans on GitHub's ordinary headerless 429s.
        let (address, server) =
            serve_requests(move |_index, _request| (429, vec![], String::new()));

        let path = temp_token_file(r#"{"0": "ghp_a", "1": "ghp_b"}"#, 11);
        let pool = TokenPool::from_token_file(&path).expect("token file must load");
        std::fs::remove_file(&path).ok();
        let client = Client::new(pool).expect("client must build");
        let error = fetch_paginated(
            &client,
            |page| format!("{address}/items?page={page}"),
            parse_str_page,
            None,
        )
        .expect_err("a fully-parked pool fails with the paused error, not a refusal");

        assert!(
            matches!(error, Error::RateLimitPaused),
            "a headerless 429 must park (RateLimitPaused), never classify as a \
             permanent refusal: {error}"
        );
        // both tokens were parked by plain 429s, no page was ever served
        let handled = server.join();
        assert_eq!(handled, 2);
    }

    #[test]
    fn a_429_with_a_spent_quota_header_is_transient_not_a_retirement() {
        // A 429 means "slow down" (a transient condition), never "hourly
        // quota spent": even when it carries `X-RateLimit-Remaining: 0`, the
        // token must only be parked, not permanently retired. A hostile
        // proxy answering every request with `429` + `Remaining: 0` would
        // otherwise drain an N-token pool in N responses and kill every
        // later fetch although no quota was ever consumed. With an
        // already-elapsed `Retry-After: 0` window the parked token is live
        // again immediately, so the same token must serve the listing.
        let (address, server) = serve_requests(move |index, _request| {
            if index == 0 {
                return (
                    429,
                    vec![
                        ("X-RateLimit-Remaining".to_string(), "0".to_string()),
                        ("Retry-After".to_string(), "0".to_string()),
                    ],
                    String::new(),
                );
            }
            match request_line_page(_request) {
                1 => (200, vec![], r#"["recovered"]"#.to_string()),
                _ => (200, vec![], "[]".to_string()),
            }
        });

        let client = Client::new(TokenPool::from_token("ghp_a").expect("valid token"))
            .expect("client must build");
        let items: Vec<String> = fetch_paginated(
            &client,
            |page| format!("{address}/items?page={page}"),
            parse_str_page,
            None,
        )
        .expect("a 429 must park the token, never retire it");

        assert_eq!(items, vec!["recovered".to_string()]);
        let handled = server.join();
        assert_eq!(handled, 3, "the token must be retried, not retired");
    }

    #[test]
    fn a_core_url_with_a_search_named_repository_still_retires_on_a_spent_quota() {
        // the search-quota exemption is scoped to the URL *path*: a core
        // endpoint whose repository happens to be named `search`
        // (`/repos/{owner}/search/commits`) is not a `/search/` endpoint, so
        // its spent-quota `Retry-After` response stays a primary exhaustion
        // (a parking would re-pay one doomed request per park window on a
        // genuinely spent hourly quota)
        let (address, server) = serve_requests(move |_index, _request| {
            (
                403,
                vec![
                    ("X-RateLimit-Remaining".to_string(), "0".to_string()),
                    ("Retry-After".to_string(), "0".to_string()),
                ],
                String::new(),
            )
        });

        let client = Client::new(TokenPool::from_token("ghp_a").expect("valid token"))
            .expect("client must build");
        let error = fetch_paginated(
            &client,
            |page| format!("{address}/repos/owner/search/commits?page={page}"),
            parse_str_page,
            None,
        )
        .expect_err("a spent core quota must retire the token");

        assert!(matches!(error, Error::RateLimitExhausted));
        assert_eq!(server.join(), 1, "retired, not parked-and-retried");
    }
}
