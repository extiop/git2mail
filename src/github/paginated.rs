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
/// The client's failures (`Error::Http`, `Error::NotFound`,
/// `Error::PrivateOrUnavailable`, `Error::RateLimitExhausted`) plus any
/// `parse_page` error. Never panics.
pub fn fetch_paginated<T, F>(
    client: &Client,
    build_url: impl Fn(u16) -> String,
    parse_page: F,
    limit: Option<usize>,
) -> Result<Vec<T>, Error>
where
    F: Fn(&Value) -> Result<(Vec<T>, usize), Error>,
{
    let mut all_items: Vec<T> = Vec::new();
    let mut page: u16 = 1;

    loop {
        let json: Value = client.get_json(&build_url(page))?;
        let (page_items, raw_item_count) = parse_page(&json)?;

        // No raw item on the page: we reached the end of the listing.
        if raw_item_count == 0 {
            return Ok(all_items);
        }
        all_items.extend(page_items);

        // User limit reached: stop issuing requests, the next pages would
        // only be fetched to be thrown away.
        if let Some(limit) = limit
            && all_items.len() >= limit
        {
            all_items.truncate(limit);
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
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    pub(crate) fn serve_requests(
        respond: impl Fn(usize, &[String]) -> (u16, Vec<(String, String)>, String)
        + Send
        + Sync
        + 'static,
    ) -> (String, MockServer) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("test setup: bind mock server");
        let address = listener
            .local_addr()
            .expect("test setup: local addr")
            .to_string();
        let stop = Arc::new(AtomicBool::new(false));
        let handled = Arc::new(AtomicUsize::new(0));
        let last_activity = Arc::new(std::sync::Mutex::new(Instant::now()));
        let handles = Arc::new(std::sync::Mutex::new(Vec::new()));
        let respond = Arc::new(respond);

        {
            let stop = Arc::clone(&stop);
            let handled = Arc::clone(&handled);
            let last_activity = Arc::clone(&last_activity);
            let handles = Arc::clone(&handles);
            let respond = Arc::clone(&respond);
            std::thread::spawn(move || {
                listener
                    .set_nonblocking(true)
                    .expect("test setup: nonblocking listener");
                loop {
                    // the test asked for shutdown, the client went quiet for a
                    // long while (forgotten join safety net), or the hard
                    // overall deadline was reached
                    let quiet = handled.load(Ordering::Relaxed) > 0
                        && last_activity.lock().expect("test bookkeeping").elapsed()
                            > Duration::from_secs(10);
                    if stop.load(Ordering::Relaxed)
                        || quiet
                        || last_activity.lock().expect("test bookkeeping").elapsed()
                            > Duration::from_secs(30)
                    {
                        break;
                    }
                    let mut stream = match listener.accept() {
                        Ok((stream, _)) => {
                            *last_activity.lock().expect("test bookkeeping") = Instant::now();
                            stream
                        }
                        Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(5));
                            continue;
                        }
                        Err(_) => break,
                    };
                    // Keep-alive: serve every request of this connection before
                    // accepting a new one. One connection per scan instead of
                    // one per request avoids the Windows loopback connection
                    // aborts (10053) that rapid connect/close cycles trigger
                    // under parallel test load. The read timeout keeps the
                    // shutdown flags responsive while the connection idles
                    // between requests. Each connection runs on its own thread
                    // so a parallel worker's idle pooled connection never
                    // starves another worker's requests.
                    let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
                    let _ = stream.set_nodelay(true);
                    let handled = Arc::clone(&handled);
                    let last_activity = Arc::clone(&last_activity);
                    let respond = Arc::clone(&respond);
                    let stop = Arc::clone(&stop);
                    let connection = std::thread::spawn(move || {
                        let mut reader = BufReader::new(match stream.try_clone() {
                            Ok(reader) => reader,
                            Err(_) => return,
                        });
                        loop {
                            let mut request_lines: Vec<String> = Vec::new();
                            let mut closed = false;
                            // one accumulating buffer per request: a read
                            // timeout keeps whatever partial bytes were already
                            // read, so a request line split across the timeout
                            // is never lost
                            let mut line = String::new();
                            loop {
                                match reader.read_line(&mut line) {
                                    Ok(0) => {
                                        closed = true;
                                        break;
                                    }
                                    Err(ref err)
                                        if err.kind() == std::io::ErrorKind::WouldBlock
                                            || err.kind() == std::io::ErrorKind::TimedOut =>
                                    {
                                        // idle keep-alive connection: check the
                                        // shutdown flag, then keep reading
                                        // (`line` preserves any partial request
                                        // line)
                                        if stop.load(Ordering::Relaxed) {
                                            return;
                                        }
                                        continue;
                                    }
                                    Err(_) => {
                                        closed = true;
                                        break;
                                    }
                                    Ok(_) => {
                                        if !line.ends_with('\n') {
                                            continue;
                                        }
                                        if line.trim().is_empty() {
                                            break; // end of the request headers
                                        }
                                        request_lines.push(line.trim_end().to_string());
                                        line.clear();
                                    }
                                }
                            }
                            // HTTP clients may open extra idle connections that
                            // carry no request: do not count them as handled
                            // requests.
                            if !request_lines.is_empty() {
                                let index = handled.fetch_add(1, Ordering::Relaxed);
                                *last_activity.lock().expect("test bookkeeping") = Instant::now();
                                let (status, headers, body) = respond(index, &request_lines);
                                let reason = match status {
                                    200 => "OK",
                                    403 => "Forbidden",
                                    404 => "Not Found",
                                    429 => "Too Many Requests",
                                    _ => "Error",
                                };
                                let mut response = format!(
                                    "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n",
                                    body.len()
                                );
                                for (name, value) in &headers {
                                    response.push_str(&format!("{name}: {value}\r\n"));
                                }
                                response.push_str("\r\n");
                                response.push_str(&body);
                                let _ = stream.write_all(response.as_bytes());
                            }
                            if closed || stop.load(Ordering::Relaxed) {
                                return;
                            }
                        }
                    });
                    handles.lock().expect("test bookkeeping").push(connection);
                }
            })
        };
        (
            format!("http://{address}"),
            MockServer {
                stop,
                handled,
                handles,
            },
        )
    }

    /// Handle over a running mock server: [`MockServer::join`] asks the server
    /// to stop (no quiet window to wait out) and returns the number of requests
    /// it handled.
    pub(crate) struct MockServer {
        stop: Arc<std::sync::atomic::AtomicBool>,
        handled: Arc<AtomicUsize>,
        handles: Arc<std::sync::Mutex<Vec<std::thread::JoinHandle<()>>>>,
    }

    impl MockServer {
        /// Asks the server thread to stop and returns the number of requests it
        /// handled.
        pub(crate) fn join(self) -> usize {
            self.stop.store(true, Ordering::Relaxed);
            let handles = self
                .handles
                .lock()
                .expect("test bookkeeping")
                .drain(..)
                .collect::<Vec<_>>();
            for handle in handles {
                let _ = handle.join();
            }
            self.handled.load(Ordering::Relaxed)
        }
    }

    fn request_header<'a>(request_lines: &'a [String], name: &str) -> Option<&'a str> {
        let prefix = format!("{name}: ");
        request_lines
            .iter()
            .find(|line| line.to_lowercase().starts_with(&prefix.to_lowercase()))
            .map(|line| line[prefix.len()..].trim())
    }

    /// Extracts the `page=` query parameter of a mock request's request line
    /// (0 when absent or unparsable).
    fn request_line_page(request_lines: &[String]) -> u16 {
        request_lines
            .first()
            .and_then(|line| line.split("page=").nth(1))
            .and_then(|rest| rest.split(' ').next())
            .and_then(|page| page.parse().ok())
            .unwrap_or(0)
    }

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
            let request_line = request.first().map(String::as_str).unwrap_or("");
            let page = request_line
                .split("page=")
                .nth(1)
                .and_then(|rest| rest.split(' ').next())
                .unwrap_or("");
            match (authorization, page) {
                // first token is rate-limited (exhausted quota)…
                ("token ghp_a", _) => (
                    403,
                    vec![("X-RateLimit-Remaining".to_string(), "0".to_string())],
                    String::new(),
                ),
                // …so the request is retried with the next token
                (_, "1") => (200, vec![], r#"["after-rotation"]"#.to_string()),
                _ => (200, vec![], "[]".to_string()),
            }
        });

        // two tokens so the 403 can rotate to the second one
        let path = std::env::temp_dir().join(format!(
            "git2mail_paginated_test_{}.json",
            std::process::id()
        ));
        std::fs::write(&path, r#"{"0": "ghp_a", "1": "ghp_b"}"#)
            .expect("test setup: write temp file");
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
            let request_line = request.first().map(String::as_str).unwrap_or("");
            let page = request_line
                .split("page=")
                .nth(1)
                .and_then(|rest| rest.split(' ').next())
                .unwrap_or("");
            if authorization == "token ghp_a" {
                // always rate-limited: marked exhausted after the first hit
                return (
                    403,
                    vec![("X-RateLimit-Remaining".to_string(), "0".to_string())],
                    String::new(),
                );
            }
            let body = match page {
                "1" => r#"["one"]"#.to_string(),
                "2" => r#"["two"]"#.to_string(),
                _ => "[]".to_string(),
            };
            (200, vec![], body)
        });

        let path = std::env::temp_dir().join(format!(
            "git2mail_paginated_skip_test_{}.json",
            std::process::id()
        ));
        std::fs::write(&path, r#"{"0": "ghp_a", "1": "ghp_b"}"#)
            .expect("test setup: write temp file");
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
    fn a_429_with_a_spent_quota_header_is_transient_not_a_retirement() {
        // A 429 means "slow down" (a transient condition), never "hourly
        // quota spent": even when it carries `X-RateLimit-Remaining: 0`, the
        // token must only be parked, not permanently retired. A hostile
        // proxy answering every request with `429` + `Remaining: 0` would
        // otherwise drain an N-token pool in N responses and kill every
        // later fetch although no quota was ever consumed. With an
        // already-elapsed `Retry-After: 0` window the parked token is live
        // again immediately, so it must come back and serve a later page:
        // retired, it would never be allocated again.
        let authorizations: std::sync::Arc<std::sync::Mutex<Vec<String>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorded = std::sync::Arc::clone(&authorizations);
        let (address, server) = serve_requests(move |index, request| {
            recorded.lock().expect("test bookkeeping").push(
                request_header(request, "Authorization")
                    .unwrap_or_default()
                    .to_string(),
            );
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
            let request_line = request.first().map(String::as_str).unwrap_or("");
            let page = request_line
                .split("page=")
                .nth(1)
                .and_then(|rest| rest.split(' ').next())
                .unwrap_or("");
            match page {
                "1" => (200, vec![], r#"["one"]"#.to_string()),
                "2" => (200, vec![], r#"["two"]"#.to_string()),
                _ => (200, vec![], "[]".to_string()),
            }
        });

        let path = std::env::temp_dir().join(format!(
            "git2mail_paginated_429_park_test_{}.json",
            std::process::id()
        ));
        std::fs::write(&path, r#"{"0": "ghp_a", "1": "ghp_b"}"#)
            .expect("test setup: write temp file");
        let pool = TokenPool::from_token_file(&path).expect("token file must load");
        std::fs::remove_file(&path).ok();
        let client = Client::new(pool).expect("client must build");
        let items: Vec<String> = fetch_paginated(
            &client,
            |page| format!("{address}/items?page={page}"),
            parse_str_page,
            None,
        )
        .expect("a 429 must park the token, never retire it");

        assert_eq!(items, vec!["one".to_string(), "two".to_string()]);
        let handled = server.join();
        assert_eq!(handled, 4, "page 1, page 2, then the empty page");
        let auths = authorizations.lock().expect("test bookkeeping");
        assert_eq!(auths[0], "token ghp_a", "the 429 hit the first token");
        assert_eq!(
            auths[2], "token ghp_a",
            "the parked token must come back for page 2: parked, not retired"
        );
    }

    #[test]
    fn fetch_paginated_rotates_on_429_and_honors_retry_after() {
        let (address, server) = serve_requests(move |_index, request| {
            let authorization = request_header(request, "Authorization").unwrap_or("");
            let request_line = request.first().map(String::as_str).unwrap_or("");
            let page = request_line
                .split("page=")
                .nth(1)
                .and_then(|rest| rest.split(' ').next())
                .unwrap_or("");
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
                "1" => (200, vec![], r#"["after-429"]"#.to_string()),
                _ => (200, vec![], "[]".to_string()),
            }
        });

        // two tokens so the 429 can rotate to the second one
        let path = std::env::temp_dir().join(format!(
            "git2mail_paginated_429_test_{}.json",
            std::process::id()
        ));
        std::fs::write(&path, r#"{"0": "ghp_a", "1": "ghp_b"}"#)
            .expect("test setup: write temp file");
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
            let request_line = request.first().map(String::as_str).unwrap_or("");
            let page = request_line
                .split("page=")
                .nth(1)
                .and_then(|rest| rest.split(' ').next())
                .unwrap_or("");
            if authorization == "token ghp_a" {
                return (
                    429,
                    vec![("Retry-After".to_string(), "0".to_string())],
                    String::new(),
                );
            }
            match page {
                "1" => (200, vec![], r#"["after-429"]"#.to_string()),
                _ => (200, vec![], "[]".to_string()),
            }
        });

        let path = std::env::temp_dir().join(format!(
            "git2mail_paginated_429_recover_test_{}.json",
            std::process::id()
        ));
        std::fs::write(&path, r#"{"0": "ghp_a", "1": "ghp_b"}"#)
            .expect("test setup: write temp file");
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

        assert!(matches!(error, Error::Http(_)));
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
            let request_line = request.first().map(String::as_str).unwrap_or("");
            let page = request_line
                .split("page=")
                .nth(1)
                .and_then(|rest| rest.split(' ').next())
                .unwrap_or("");
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
                "1" => (200, vec![], r#"["after-hostile-429"]"#.to_string()),
                _ => (200, vec![], "[]".to_string()),
            }
        });

        let path = std::env::temp_dir().join(format!(
            "git2mail_paginated_429_overflow_test_{}.json",
            std::process::id()
        ));
        std::fs::write(&path, r#"{"0": "ghp_a", "1": "ghp_b"}"#)
            .expect("test setup: write temp file");
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
    fn a_401_error_carries_its_status_for_token_rejection_detection() {
        // a revoked or invalid token surfaces at request time as a 401: the
        // error must carry its status so the parallel scan can tell a dead
        // dedicated token from a scan-wide failure
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

        assert!(matches!(
            &error,
            Error::Http(http) if http.status() == Some(reqwest::StatusCode::UNAUTHORIZED)
        ));
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
    fn a_403_secondary_response_without_retry_after_rotates_instead_of_failing() {
        // GitHub signals some secondary limits through a 403 abuse body with
        // no `Retry-After` header: the limit is transient, so the pool must
        // rotate instead of failing with a misleading "private or
        // unavailable"
        let (address, server) = serve_requests(move |_index, request| {
            let authorization = request_header(request, "Authorization").unwrap_or("");
            let request_line = request.first().map(String::as_str).unwrap_or("");
            let page = request_line
                .split("page=")
                .nth(1)
                .and_then(|rest| rest.split(' ').next())
                .unwrap_or("");
            if authorization == "token ghp_a" {
                return (
                    403,
                    vec![],
                    r#"{"message": "You have exceeded a secondary rate limit"}"#.to_string(),
                );
            }
            match page {
                "1" => (200, vec![], r#"["after-403-secondary"]"#.to_string()),
                _ => (200, vec![], "[]".to_string()),
            }
        });

        let path = std::env::temp_dir().join(format!(
            "git2mail_paginated_403_secondary_test_{}.json",
            std::process::id()
        ));
        std::fs::write(&path, r#"{"0": "ghp_a", "1": "ghp_b"}"#)
            .expect("test setup: write temp file");
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
    fn an_anonymous_request_sends_no_authorization_header() {
        // the Authorization header is injected only when the token
        // is non-empty — an anonymous client must not leak an empty
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
        // exactly one request — no doomed retry, no sleep
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

        assert!(matches!(error, Error::RateLimitExhausted));
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
        // HTTP decode error (Error::Http with is_decode), not Error::Json —
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

        let path = std::env::temp_dir().join(format!(
            "git2mail_paginated_403_precedence_test_{}.json",
            std::process::id()
        ));
        std::fs::write(&path, r#"{"0": "ghp_a", "1": "ghp_b"}"#)
            .expect("test setup: write temp file");
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
}
