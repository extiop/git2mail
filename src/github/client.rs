//! GitHub API client: token pool, centralized headers and rate-limit rotation.

use crate::errors::Error;
use serde_json::Value;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// Pool index used for the anonymous (token-less) quota.
const ANONYMOUS_INDEX: usize = usize::MAX;

/// Accepted GitHub token prefixes.
/// Personal access tokens (classic) start with `ghp_`, fine-grained ones with
/// `github_pat_`.
const VALID_TOKEN_PREFIXES: [&str; 2] = ["ghp_", "github_pat_"];

/// Pool of GitHub API tokens with round-robin allocation.
///
/// Tokens are loaded either from a single `--token` string or from a JSON
/// token file (`{"0": "ghp_…", "1": "ghp_…", …}`, see `tokens.example.json`).
/// Every token is validated at load time, so an invalid format fails fast
/// instead of surfacing as a mysterious 401 later.
///
/// An empty pool means anonymous access: [`TokenPool::acquire`] then
/// returns an empty token, and the client sends no `Authorization` header.
#[derive(Debug)]
pub struct TokenPool {
    tokens: Vec<String>,
    /// Cursor for round-robin allocation. Atomic so the pool is ready for the
    /// worker-per-token concurrency planned for the next stage.
    cursor: AtomicUsize,
    /// Per-token exhaustion state: `None` for a token whose hourly quota is
    /// spent (permanently retired), `Some(deadline)` for a token parked until
    /// a `Retry-After` window passes (secondary rate limits, where the quota
    /// is not spent). Skipped by later [`TokenPool::acquire`] calls instead
    /// of costing one doomed request per page.
    exhausted: Mutex<HashMap<usize, Option<Instant>>>,
}

impl TokenPool {
    /// Builds a pool from a single token string. An empty token is allowed and
    /// yields anonymous access.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidTokenFormat`] when the token matches neither
    /// the `ghp_…` nor the `github_pat_…` prefix (the error payload is a
    /// masked excerpt, never the full secret). Never panics.
    pub fn from_token(token: &str) -> Result<Self, Error> {
        if token.is_empty() {
            return Ok(Self::anonymous());
        }
        Self::validate(token)?;
        Ok(Self {
            tokens: vec![token.to_string()],
            cursor: AtomicUsize::new(0),
            exhausted: Mutex::new(HashMap::new()),
        })
    }

    /// Builds a pool from a JSON token file.
    ///
    /// The file format is a JSON object mapping indexes to tokens, following
    /// the existing `tokens.example.json`:
    ///
    /// ```json
    /// { "0": "ghp_…", "1": "ghp_…" }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] when the file cannot be read, [`Error::Json`]
    /// when it is not valid JSON, and [`Error::InvalidTokenFormat`] when it
    /// is not an object of numeric indexes to `ghp_…`/`github_pat_…`
    /// strings. Validation happens at load time, so an invalid file fails
    /// before any scan. Never panics.
    pub fn from_token_file(path: &Path) -> Result<Self, Error> {
        let raw = std::fs::read_to_string(path)?;
        let parsed: Value = serde_json::from_str(&raw)?;
        let object = parsed.as_object().ok_or_else(|| {
            Error::InvalidTokenFormat(
                "token file must be a JSON object of indexes to tokens".to_string(),
            )
        })?;

        // Sort by numeric index so the pool order matches the file order even
        // past index 9 ("10" must come after "2"). Non-numeric keys are
        // rejected at startup instead of being silently kept.
        let mut entries: Vec<(usize, &Value)> = Vec::with_capacity(object.len());
        for (key, value) in object {
            let index = key.parse::<usize>().map_err(|_| {
                Error::InvalidTokenFormat(format!("token file key {key:?} is not a numeric index"))
            })?;
            entries.push((index, value));
        }
        entries.sort_by_key(|(index, _)| *index);

        let mut tokens: Vec<String> = Vec::new();
        for (index, value) in entries {
            let token = value.as_str().ok_or_else(|| {
                Error::InvalidTokenFormat(format!("token file entry {index} is not a string"))
            })?;
            // Empty entries behave like the empty `--token` case: they would
            // only grant anonymous access, so they are not kept in the pool.
            if token.is_empty() {
                continue;
            }
            Self::validate(token)?;
            tokens.push(token.to_string());
        }

        Ok(Self {
            tokens,
            cursor: AtomicUsize::new(0),
            exhausted: Mutex::new(HashMap::new()),
        })
    }

    /// Anonymous pool: no token at all.
    pub fn anonymous() -> Self {
        Self {
            tokens: Vec::new(),
            cursor: AtomicUsize::new(0),
            exhausted: Mutex::new(HashMap::new()),
        }
    }

    /// Checks a token format (`ghp_…` or `github_pat_…`).
    ///
    /// The error payload is a masked excerpt of the token so that no full
    /// secret ever leaks into logs.
    fn validate(token: &str) -> Result<(), Error> {
        if VALID_TOKEN_PREFIXES
            .iter()
            .any(|prefix| token.starts_with(prefix))
        {
            Ok(())
        } else {
            let masked: String = token.chars().take(4).collect();
            Err(Error::InvalidTokenFormat(format!("{masked}***")))
        }
    }

    /// Returns the next live token with its pool index, following round-robin
    /// allocation and skipping exhausted tokens. Returns `None` when every
    /// token (or the anonymous quota) has been exhausted.
    pub fn acquire(&self) -> Option<(usize, String)> {
        if self.tokens.is_empty() {
            if self.is_exhausted(ANONYMOUS_INDEX) {
                return None;
            }
            return Some((ANONYMOUS_INDEX, String::new()));
        }
        for _ in 0..self.tokens.len() {
            let index = self.cursor.fetch_add(1, Ordering::Relaxed) % self.tokens.len();
            if !self.is_exhausted(index) {
                return Some((index, self.tokens[index].clone()));
            }
        }
        None
    }

    /// Marks a token (or the anonymous quota) as permanently exhausted after
    /// its hourly quota was spent, so later requests skip it instead of paying
    /// a doomed request.
    pub fn mark_exhausted(&self, index: usize) {
        if let Ok(mut exhausted) = self.exhausted.lock() {
            exhausted.insert(index, None);
        }
    }

    /// Parks a token until `deadline` after a secondary rate-limit response:
    /// its quota is not spent, so it is only skipped until the deadline and
    /// becomes live again afterwards.
    pub fn mark_limited_until(&self, index: usize, deadline: Instant) {
        if let Ok(mut exhausted) = self.exhausted.lock() {
            exhausted.insert(index, Some(deadline));
        }
    }

    /// Whether a token index (or the anonymous quota) is currently unusable:
    /// either permanently retired, or parked until a pending `Retry-After`
    /// window passes. A poisoned lock is treated as "everything exhausted"
    /// to fail safe.
    fn is_exhausted(&self, index: usize) -> bool {
        let Ok(mut exhausted) = self.exhausted.lock() else {
            return true;
        };
        match exhausted.get(&index) {
            None => false,
            Some(None) => true,
            Some(Some(deadline)) => {
                if Instant::now() >= *deadline {
                    exhausted.remove(&index);
                    false
                } else {
                    true
                }
            }
        }
    }

    /// Whether at least one token other than `index` can still be acquired.
    pub fn has_other_live(&self, index: usize) -> bool {
        (0..self.tokens.len()).any(|other| other != index && !self.is_exhausted(other))
    }

    /// Returns the token at `index`, for exclusive ownership by one worker
    /// (concurrency: one dedicated token per worker, no contention).
    /// Returns `None` for an anonymous pool or an out-of-range index.
    pub fn dedicated_token(&self, index: usize) -> Option<&str> {
        self.tokens.get(index).map(String::as_str)
    }

    /// Number of distinct tokens in the pool.
    pub fn len(&self) -> usize {
        self.tokens.len()
    }

    /// Whether the pool holds no token (anonymous access).
    pub fn is_empty(&self) -> bool {
        self.tokens.is_empty()
    }

    /// How many times a request may be retried on 403/429 by rotating tokens:
    /// one attempt per token, or a single attempt when anonymous.
    pub fn attempts(&self) -> usize {
        self.tokens.len().max(1)
    }
}

/// HTTP client for the GitHub API.
///
/// It owns a [`TokenPool`] and centralizes the headers GitHub requires
/// (`User-Agent`, `Accept`) plus the `Authorization` header, which is only
/// injected when the current token is non-empty. Rate-limit responses
/// (403/429) trigger a rotation to the next token of the pool.
pub struct Client {
    http: reqwest::blocking::Client,
    tokens: TokenPool,
    /// Number of successful (2xx) requests made through this client; used to
    /// report how many pages were fetched in the JSON output.
    successful_requests: AtomicUsize,
}

impl Client {
    /// Headers recommended by the GitHub API to fetch it nicely.
    const USER_AGENT_HEADER: &'static str =
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:107.0) Gecko/20100101 Firefox/107.0";
    const GITHUB_ACCEPT_HEADER: &'static str = "application/vnd.github.v3+json";

    /// Total and connect timeout applied to every request, so a hung
    /// connection can never block a scan (or a worker) forever.
    const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

    /// Park window applied to a secondary-rate-limited token when the
    /// server provides no `Retry-After` header (GitHub sends none on plain
    /// 429s and on some abuse responses): long enough not to re-hammer the
    /// limit on every turn, short enough not to stall a follow-up scan.
    const DEFAULT_SECONDARY_PARK: Duration = Duration::from_secs(60);

    /// Ceiling applied to a server-provided `Retry-After` window: a hostile
    /// or broken server could send an absurd value (or one that overflows
    /// `Instant + Duration`, which panics), so the header is honored only up
    /// to one hour.
    const MAX_RETRY_AFTER: Duration = Duration::from_secs(60 * 60);

    /// Builds a client on top of the given token pool.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Http`] when the underlying HTTP client (its TLS
    /// backend) cannot be built. Never panics.
    pub fn new(tokens: TokenPool) -> Result<Self, Error> {
        let http = reqwest::blocking::Client::builder()
            .connect_timeout(Self::REQUEST_TIMEOUT)
            .timeout(Self::REQUEST_TIMEOUT)
            .build()?;
        Ok(Self {
            http,
            tokens,
            successful_requests: AtomicUsize::new(0),
        })
    }

    /// Builds an anonymous client (no token, 60 req/h rate limit).
    ///
    /// # Errors
    ///
    /// The same failures as [`Client::new`]. Never panics.
    pub fn anonymous() -> Result<Self, Error> {
        Self::new(TokenPool::anonymous())
    }

    /// Read-only access to the underlying token pool.
    pub fn tokens(&self) -> &TokenPool {
        &self.tokens
    }

    /// How many successful (2xx) requests were made through this client so
    /// far, i.e. roughly how many pages were fetched.
    pub fn requests_made(&self) -> usize {
        self.successful_requests.load(Ordering::Relaxed)
    }

    /// Performs a GET request and returns the decoded JSON body.
    ///
    /// # Errors
    ///
    /// Returns [`Error::RateLimitExhausted`] when every token of the pool is
    /// rate-limited, [`Error::NotFound`], [`Error::PrivateOrUnavailable`] and
    /// [`Error::Http`] for the response and transport failures (any other
    /// non-2xx status, including a rejected token answered with 401, surfaces
    /// as [`Error::Http`]). Rate-limit responses rotate to the next token
    /// of the pool and the request is retried with it. Two cases are
    /// distinguished:
    ///
    /// - primary quota exhaustion (403 with `X-RateLimit-Remaining: 0`): the
    ///   token is retired for the rest of the process, then we rotate;
    ///
    /// - secondary rate limit (429, a 403 with a `Retry-After` header, or a
    ///   403 whose abuse/secondary body says so without a header): the quota
    ///   is not spent, so the token is only parked until its window passes
    ///   (`Retry-After` honored as-is, or a short default window without a
    ///   header) and we rotate immediately to another live token when one
    ///   exists instead of sleeping (a wait would stall the whole scan for
    ///   nothing).
    ///
    /// A successful response whose `X-RateLimit-Remaining` happens to be `0`
    /// (the request that consumed the last credit of the hour) is a valid
    /// page, not a rate limit: its body is returned and the token stays
    /// usable.
    ///
    /// Once no token can be acquired, [`Error::RateLimitExhausted`] is
    /// returned (no infinite loop, no wasted sleep). Never panics.
    ///
    /// Any other 403 is permanent (private resource, missing token scope,
    /// SSO not authorized…) and maps to [`Error::PrivateOrUnavailable`].
    /// A 404 maps to [`Error::NotFound`].
    pub fn get_json(&self, url: &str) -> Result<Value, Error> {
        for _ in 0..self.tokens.attempts() {
            let Some((index, token)) = self.tokens.acquire() else {
                break; // every token of the pool is currently unusable
            };
            let response = self.send(url, &token)?;
            let status = response.status();

            // Only a 403/429 can announce rate limiting: the quota check is
            // gated on the status so a 200 whose `X-RateLimit-Remaining` is
            // `0` keeps its body and its token.
            if status == reqwest::StatusCode::FORBIDDEN
                || status == reqwest::StatusCode::TOO_MANY_REQUESTS
            {
                // A 429 is always a secondary (transient) limit, even with a
                // spent-quota header: classifying it as a primary exhaustion
                // would let a hostile proxy answering every request with
                // `429` + `Remaining: 0` permanently drain the whole pool one
                // token per response, although no hourly quota was ever
                // spent. The check is therefore gated on the status before
                // the quota header is consulted.
                if status != reqwest::StatusCode::TOO_MANY_REQUESTS
                    && Self::quota_exhausted(&response)
                {
                    // Primary rate limit: the hourly quota is spent, retire
                    // the token and rotate to the next one.
                    self.tokens.mark_exhausted(index);
                    continue;
                }
                let retry_after = Self::retry_after(&response);
                let body = response.text().unwrap_or_default();
                let secondary = status == reqwest::StatusCode::TOO_MANY_REQUESTS
                    || retry_after.is_some()
                    || Self::body_says_secondary(&body);
                if secondary {
                    // Park the token until its window passes (the quota is
                    // not spent) and rotate to the next live token.
                    let deadline =
                        Instant::now() + retry_after.unwrap_or(Self::DEFAULT_SECONDARY_PARK);
                    self.tokens.mark_limited_until(index, deadline);
                    if self.tokens.has_other_live(index) {
                        continue; // rotate to the next live token and retry
                    }
                    break; // nothing to rotate to: sleeping would only delay the failure
                }
                // Permanent 403 (private resource, missing token scope,
                // SSO not authorized…).
                return Err(Error::PrivateOrUnavailable);
            }
            if status == reqwest::StatusCode::NOT_FOUND {
                return Err(Error::NotFound);
            }
            let response = response.error_for_status()?;
            self.successful_requests.fetch_add(1, Ordering::Relaxed);
            return response.json::<Value>().map_err(Error::from);
        }
        Err(Error::RateLimitExhausted)
    }

    /// Whether a response body announces a transient secondary rate limit
    /// (GitHub's abuse and secondary-limit messages) rather than a permanent
    /// refusal: misclassifying those as a permanent 403 would fail the scan
    /// while another token still has budget.
    fn body_says_secondary(body: &str) -> bool {
        let body = body.to_ascii_lowercase();
        body.contains("secondary rate limit") || body.contains("abuse")
    }

    /// Whether a 403/429 response announces a spent hourly quota
    /// (`X-RateLimit-Remaining: 0`), as opposed to a transient secondary
    /// rate limit whose budget is not actually consumed.
    fn quota_exhausted(response: &reqwest::blocking::Response) -> bool {
        response
            .headers()
            .get("x-ratelimit-remaining")
            .and_then(|value| value.to_str().ok())
            == Some("0")
    }

    /// Parses a `Retry-After` header expressed in seconds, capped to
    /// [`Client::MAX_RETRY_AFTER`] so a hostile header can neither park a
    /// token forever nor overflow the `Instant + Duration` deadline (which
    /// would panic the scan).
    fn retry_after(response: &reqwest::blocking::Response) -> Option<Duration> {
        let value = response
            .headers()
            .get(reqwest::header::RETRY_AFTER)?
            .to_str()
            .ok()?
            .trim()
            .parse::<u64>()
            .ok()?;
        Some(Duration::from_secs(
            value.min(Self::MAX_RETRY_AFTER.as_secs()),
        ))
    }

    /// Sends one GET request with the centralized headers and an
    /// `Authorization` header only when the token is non-empty.
    fn send(&self, url: &str, token: &str) -> Result<reqwest::blocking::Response, Error> {
        let mut request = self
            .http
            .get(url)
            .header(reqwest::header::USER_AGENT, Self::USER_AGENT_HEADER)
            .header(reqwest::header::ACCEPT, Self::GITHUB_ACCEPT_HEADER);
        if !token.is_empty() {
            request = request.header(reqwest::header::AUTHORIZATION, format!("token {token}"));
        }
        Ok(request.send()?)
    }
}

#[cfg(test)]
mod tests {
    // Tests may unwrap, expect and panic freely: a failing assertion must
    // be loud, so the zero-panic lints do not apply to the test modules.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn temp_token_file(contents: &str, unique: u32) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "git2mail_token_pool_test_{}_{unique}.json",
            std::process::id()
        ));
        std::fs::write(&path, contents).expect("test setup: write temp file");
        path
    }

    #[test]
    fn from_token_accepts_valid_classic_token() {
        let pool = TokenPool::from_token("ghp_abcdefghij").expect("ghp_ token must be valid");
        assert_eq!(pool.len(), 1);
        assert!(!pool.is_empty());
        assert_eq!(pool.acquire(), Some((0, "ghp_abcdefghij".to_string())));
    }

    #[test]
    fn from_token_accepts_valid_fine_grained_token() {
        let pool = TokenPool::from_token("github_pat_abcdefghij")
            .expect("github_pat_ token must be valid");
        assert_eq!(pool.len(), 1);
        assert_eq!(
            pool.acquire(),
            Some((0, "github_pat_abcdefghij".to_string()))
        );
    }

    #[test]
    fn from_token_rejects_invalid_format() {
        let error = TokenPool::from_token("not_a_token").expect_err("must fail");
        assert!(matches!(error, Error::InvalidTokenFormat(masked) if masked == "not_***"));
    }

    #[test]
    fn from_token_empty_means_anonymous() {
        let pool = TokenPool::from_token("").expect("empty token must be accepted");
        assert!(pool.is_empty());
        assert_eq!(pool.acquire(), Some((ANONYMOUS_INDEX, String::new())));
        assert_eq!(pool.attempts(), 1);
    }

    #[test]
    fn from_token_file_loads_tokens_in_numeric_index_order() {
        let path = temp_token_file(
            r#"{"0": "ghp_first", "10": "ghp_tenth", "2": "ghp_second"}"#,
            1,
        );
        let pool = TokenPool::from_token_file(&path).expect("token file must load");
        std::fs::remove_file(&path).ok();

        assert_eq!(pool.len(), 3);
        // round-robin order follows numeric indexes: 0, 2, 10
        assert_eq!(pool.acquire(), Some((0, "ghp_first".to_string())));
        assert_eq!(pool.acquire(), Some((1, "ghp_second".to_string())));
        assert_eq!(pool.acquire(), Some((2, "ghp_tenth".to_string())));
        // then it wraps around
        assert_eq!(pool.acquire(), Some((0, "ghp_first".to_string())));
    }

    #[test]
    fn from_token_file_rejects_non_json_object() {
        let path = temp_token_file(r#"["ghp_first"]"#, 2);
        let error = TokenPool::from_token_file(&path).expect_err("must fail");
        std::fs::remove_file(&path).ok();
        assert!(matches!(error, Error::InvalidTokenFormat(_)));
    }

    #[test]
    fn from_token_file_rejects_invalid_token_format() {
        let path = temp_token_file(r#"{"0": "ghp_ok", "1": "oops"}"#, 3);
        let error = TokenPool::from_token_file(&path).expect_err("must fail");
        std::fs::remove_file(&path).ok();
        assert!(matches!(error, Error::InvalidTokenFormat(masked) if masked == "oops***"));
    }

    #[test]
    fn from_token_file_skips_empty_entries() {
        let path = temp_token_file(r#"{"0": "ghp_real", "1": ""}"#, 4);
        let pool = TokenPool::from_token_file(&path).expect("token file must load");
        std::fs::remove_file(&path).ok();
        assert_eq!(pool.len(), 1);
        assert_eq!(pool.acquire(), Some((0, "ghp_real".to_string())));
    }

    #[test]
    fn round_robin_allocation_cycles_through_the_pool() {
        let pool = TokenPool {
            tokens: vec!["ghp_a".to_string(), "ghp_b".to_string()],
            cursor: AtomicUsize::new(0),
            exhausted: Mutex::new(HashMap::new()),
        };
        assert_eq!(pool.acquire(), Some((0, "ghp_a".to_string())));
        assert_eq!(pool.acquire(), Some((1, "ghp_b".to_string())));
        assert_eq!(pool.acquire(), Some((0, "ghp_a".to_string())));
        assert_eq!(pool.attempts(), 2);
    }

    #[test]
    fn parked_token_becomes_live_again_after_its_deadline() {
        let pool = TokenPool {
            tokens: vec!["ghp_a".to_string(), "ghp_b".to_string()],
            cursor: AtomicUsize::new(0),
            exhausted: Mutex::new(HashMap::new()),
        };
        // a window already elapsed (Retry-After: 0) leaves the token live
        pool.mark_limited_until(0, Instant::now());
        assert!(!pool.is_exhausted(0));
        assert_eq!(pool.acquire(), Some((0, "ghp_a".to_string())));

        // a pending window skips the token without retiring it
        pool.mark_limited_until(0, Instant::now() + Duration::from_secs(60));
        assert!(pool.is_exhausted(0));
        assert!(pool.has_other_live(0));
        assert_eq!(pool.acquire(), Some((1, "ghp_b".to_string())));

        // a permanently retired token never comes back
        pool.mark_exhausted(1);
        assert!(pool.is_exhausted(1));
        assert!(!pool.has_other_live(1));
        assert!(pool.acquire().is_none());
    }

    #[test]
    fn acquire_skips_exhausted_tokens() {
        let pool = TokenPool {
            tokens: vec!["ghp_a".to_string(), "ghp_b".to_string()],
            cursor: AtomicUsize::new(0),
            exhausted: Mutex::new(HashMap::new()),
        };
        pool.mark_exhausted(0);
        let (index, token) = pool.acquire().expect("one live token must remain");
        assert_eq!(index, 1);
        assert_eq!(token, "ghp_b");
        // once every token is exhausted, nothing can be acquired
        pool.mark_exhausted(1);
        assert!(pool.acquire().is_none());
    }

    #[test]
    fn from_token_file_rejects_non_numeric_keys() {
        let path = temp_token_file(r#"{"0": "ghp_ok", "foo": "ghp_bad"}"#, 5);
        let error = TokenPool::from_token_file(&path).expect_err("must fail");
        std::fs::remove_file(&path).ok();
        assert!(matches!(error, Error::InvalidTokenFormat(details) if details.contains("foo")));
    }
}
