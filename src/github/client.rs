//! GitHub API client: token pool, centralized headers and rate-limit rotation.

use crate::errors::Error;
use serde_json::Value;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// Pool index used for the anonymous (token-less) quota. `pub(crate)` so the
/// parallel-scan worker pools can consult the anonymous quota's exhaustion
/// state before spawning a worker.
pub(crate) const ANONYMOUS_INDEX: usize = usize::MAX;

/// 1-based display of a pool index, safe for the anonymous quota whose
/// sentinel index is `usize::MAX` (an `index + 1` would overflow in debug
/// builds).
fn display_index(index: usize) -> usize {
    if index == ANONYMOUS_INDEX {
        0
    } else {
        index + 1
    }
}

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

impl std::fmt::Debug for TokenPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Tokens are secrets: the pool never debug-prints them, only how
        // many it holds (the crate masks token excerpts everywhere else
        // too). A derived Debug would print every full token string.
        f.debug_struct("TokenPool")
            .field(
                "tokens",
                &format_args!("{} masked token(s)", self.tokens.len()),
            )
            .field("cursor", &self.cursor)
            .field("exhausted", &self.exhausted)
            .finish()
    }
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
        // a token pasted with a leading/trailing space would pass startup
        // validation and then fail every request with a misleading
        // "rejected token" error: strip the paste artifacts first
        let token = token.trim();
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
    /// Returns [`Error::Io`] when the file cannot be read,
    /// [`Error::InvalidTokenFile`] when it is not valid JSON or not an
    /// object of numeric indexes to token strings (a structural problem of
    /// the file, deliberately distinct from the token-value
    /// [`Error::InvalidTokenFormat`] whose display hint would send the user
    /// looking at a perfectly fine token), and [`Error::InvalidTokenFormat`]
    /// when an entry does not follow the `ghp_…`/`github_pat_…` format.
    /// Validation happens at load time, so an invalid file fails before
    /// any scan. Never panics.
    pub fn from_token_file(path: &Path) -> Result<Self, Error> {
        // the read failure names the file (see `read_file_error`): a bare
        // "No such file or directory" would leave the user guessing which
        // typed input failed
        let raw = std::fs::read_to_string(path)
            .map_err(|err| crate::errors::read_file_error(path, err))?;
        // Windows editors (Notepad, PowerShell redirects) prepend a UTF-8
        // BOM: left in place, the JSON parse fails with a bare "expected
        // value at line 1 column 1" on a file that looks perfectly fine in
        // the editor that produced it. The same BOM-strip rule the bulk
        // emails reader applies (see `read_addresses` in `crate::email`).
        let raw = match raw.strip_prefix('\u{feff}') {
            Some(stripped) => stripped.to_string(),
            None => raw,
        };
        let parsed: Value = serde_json::from_str(&raw).map_err(|err| {
            // the malformed-JSON case is a broken file, not a broken value:
            // it belongs to the crafted "invalid token file" family, and it
            // must name the file (the bare serde message "expected value at
            // line 1 column 1" alone leaves the user guessing which input
            // failed). Debug-escaped like every InvalidTokenFile payload
            Error::InvalidTokenFile(format!("{}: {err}", path.display()))
        })?;
        let object = parsed.as_object().ok_or_else(|| {
            Error::InvalidTokenFile(
                "token file must be a JSON object of indexes to tokens".to_string(),
            )
        })?;

        // Sort by numeric index so the pool order matches the file order even
        // past index 9 ("10" must come after "2"). Non-numeric keys are
        // rejected at startup instead of being silently kept.
        let mut entries: Vec<(usize, &Value)> = Vec::with_capacity(object.len());
        for (key, value) in object {
            let index = key.parse::<usize>().map_err(|_| {
                Error::InvalidTokenFile(format!("token file key {key:?} is not a numeric index"))
            })?;
            entries.push((index, value));
        }
        entries.sort_by_key(|(index, _)| *index);

        let mut tokens: Vec<String> = Vec::new();
        for (index, value) in entries {
            let token = value.as_str().ok_or_else(|| {
                Error::InvalidTokenFile(format!("token file entry {index} is not a string"))
            })?;
            // same paste-artifact rule as `from_token`: spaces around a
            // token value would fail every request with a misleading
            // "rejected token" error
            let token = token.trim();
            // Empty entries behave like the empty `--token` case: they would
            // only grant anonymous access, so they are not kept in the pool.
            if token.is_empty() {
                continue;
            }
            Self::validate(token)?;
            // An identical token string under another index is the same
            // secret, not a second quota: keeping it would make a primary
            // exhaustion "rotate" to the same dead secret (one extra doomed
            // request per fetch) and let two parallel workers own the same
            // underlying quota. The first occurrence is kept, the duplicates
            // are dropped with a warning.
            if tokens.iter().any(|kept| kept == token) {
                log::warn!(
                    "duplicate token at index {index} in the token file: only the first copy is used"
                );
                continue;
            }
            tokens.push(token.to_string());
        }

        // A file yielding zero usable tokens (empty, or only empty/duplicate
        // entries) would silently downgrade the run to anonymous access at
        // 60 req/h and only surface much later as a confusing
        // `RateLimitExhausted`: failing fast here keeps the validation
        // promise of this constructor. An explicit empty `--token` stays the
        // documented way to request anonymous access.
        if tokens.is_empty() {
            return Err(Error::InvalidTokenFile(
                "token file contains no usable token (missing, empty or duplicated entries)"
                    .to_string(),
            ));
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

    /// Checks a token format (`ghp_…` or `github_pat_…`), and rejects
    /// control characters wherever they sit: a token carrying them (a
    /// CRLF-edited token file, a pasted newline) is accepted by the prefix
    /// check but fails later inside reqwest's header build with a cryptic
    /// `builder error` that never names the credential — rejecting it here
    /// keeps the fail-fast validation promise with the masked-excerpt
    /// convention.
    ///
    /// The error payload is a masked excerpt of the token so that no full
    /// secret ever leaks into logs.
    fn validate(token: &str) -> Result<(), Error> {
        if token.chars().any(char::is_control) {
            // the same masking rule as the prefix rejection: a short value
            // is masked entirely, a long one keeps only its 4-char excerpt
            let masked = if token.chars().count() > 8 {
                format!("{}***", token.chars().take(4).collect::<String>())
            } else {
                "***".to_string()
            };
            return Err(Error::InvalidTokenFormat(format!(
                "{masked} (contains a control character)"
            )));
        }
        if VALID_TOKEN_PREFIXES
            .iter()
            .any(|prefix| token.starts_with(prefix))
        {
            Ok(())
        } else if token.chars().count() > 8 {
            // Real tokens are far longer than the excerpt: only then may the
            // first four characters be shown. A short rejected value (a
            // typo like `--token abc`) would otherwise be echoed in full,
            // breaking the "never the full secret" contract.
            let masked: String = token.chars().take(4).collect();
            Err(Error::InvalidTokenFormat(format!("{masked}***")))
        } else {
            Err(Error::InvalidTokenFormat("***".to_string()))
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
    /// to fail safe. Also consulted before a dedicated token is handed to
    /// a scan worker, so a token the shared client retired or parked during
    /// the listing phase never spawns a worker doomed to a dead request.
    pub(crate) fn is_exhausted(&self, index: usize) -> bool {
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

    /// Test-only: whether a token is *permanently* retired (a spent hourly
    /// quota) as opposed to merely parked until a `Retry-After` window
    /// passes. The two states are indistinguishable through `is_exhausted`
    /// while a park window is pending, and the distinction is exactly what
    /// the search-quota exemption tests must pin.
    #[cfg(test)]
    pub(crate) fn is_retired(&self, index: usize) -> bool {
        matches!(
            self.exhausted
                .lock()
                .ok()
                .and_then(|exhausted| exhausted.get(&index).copied()),
            Some(None)
        )
    }

    /// Returns the pool indices of the tokens that are currently live
    /// (neither retired nor parked), in index order. The parallel worker
    /// pools use it to dedicate each worker a live token when possible: a
    /// token the listing phase retired or parked must not own a worker slot
    /// while healthy tokens sit beyond the worker range — with fewer work
    /// items than tokens, every spawned worker could otherwise own a dead
    /// token and abort the whole run without a single request, against the
    /// pool's "a dead token must not abort the run while healthy tokens sit
    /// in the pool" contract.
    pub(crate) fn live_indices(&self) -> Vec<usize> {
        (0..self.tokens.len())
            .filter(|&index| !self.is_exhausted(index))
            .collect()
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
    /// Rate-limit responses trigger a rotation to the next token of the
    /// pool. Two cases are distinguished:
    ///
    /// - primary quota exhaustion (403 with `X-RateLimit-Remaining: 0`): the
    ///   token is retired for the rest of the process, then we rotate —
    ///   except when the spent quota is the *search* quota: the `/search/`
    ///   endpoints run on a separate, per-minute quota whose exhaustion also
    ///   carries `Remaining: 0`, but the token's hourly core quota is
    ///   untouched there and the search window resets within seconds, so the
    ///   response is transient (park, don't retire). Live GitHub search
    ///   exhaustion 403s do not always carry a `Retry-After` header, so the
    ///   search classification keys on the request path or the
    ///   `X-RateLimit-Resource: search` header, never on the window header.
    ///   Retiring a healthy token over a hot search minute would kill
    ///   single-token runs and burn through multi-token pools one token per
    ///   minute. A 429 is never a primary exhaustion: 429 means "too many
    ///   requests, slow down" (a transient condition), so even a 429
    ///   carrying `Remaining: 0` parks the token instead of retiring it;
    ///
    /// - secondary rate limit (429, a 403 with a `Retry-After` header, or a
    ///   403 whose abuse/secondary body says so without a header): the quota
    ///   is not spent, so the token is only parked until its window passes
    ///   (`Retry-After` honored as-is, or a short default window without a
    ///   header) and we rotate immediately to another live token when one
    ///   exists instead of sleeping (a wait would stall the whole scan for
    ///   nothing). A window that has already elapsed (`Retry-After: 0`) is
    ///   retried immediately at no cost. Precedence: a 403 that also carries
    ///   the primary exhaustion's `X-RateLimit-Remaining: 0` is classified
    ///   as a primary limit first and retires the token even with the
    ///   `Retry-After` header — the hourly core quota is spent, and sleeping
    ///   for a potentially wrong, possibly hour-long window would be worse
    ///   than rotating to a healthy token;
    ///
    /// A successful response whose `X-RateLimit-Remaining` happens to be `0`
    /// (the request that consumed the last credit of the hour) is a valid
    /// page, not a rate limit: its body is returned and the token stays
    /// usable.
    ///
    /// An HTTP 401 means the token itself was rejected by the API (a revoked
    /// or invalid token): it is retired like a spent quota and the request
    /// rotates to the next live token when one exists — the same token-scoped
    /// semantics the parallel worker pools apply. With nothing to rotate to,
    /// the rejection surfaces as [`Error::TokenRejected`].
    ///
    /// Once no token can be acquired, [`Error::RateLimitExhausted`] is
    /// returned (no infinite loop, no wasted sleep).
    ///
    /// Any other 403 is permanent (private resource, missing token scope,
    /// SSO not authorized…) and maps to [`Error::PrivateOrUnavailable`].
    /// A 404 maps to [`Error::NotFound`]. A 409 on a `/commits` request maps
    /// to [`Error::EmptyRepository`] (GitHub answers 409 Conflict on a
    /// `/commits` listing when the repository has no commits); a 409 from
    /// any other endpoint has no repository-specific meaning, so it
    /// surfaces as the raw HTTP error.
    ///
    /// # Errors
    ///
    /// Every failure is enumerated above: [`Error::RateLimitExhausted`],
    /// [`Error::TokenRejected`], [`Error::PrivateOrUnavailable`],
    /// [`Error::NotFound`], [`Error::EmptyRepository`], [`Error::Json`] and
    /// [`Error::Http`]. Never panics.
    pub fn get_json(&self, url: &str) -> Result<Value, Error> {
        // One attempt per token, plus one extra round for the zero-cost retry
        // a `Retry-After: 0` (or any already-elapsed window) explicitly
        // authorizes: the park-deadline has then already passed, so retrying
        // costs no sleep. The +1 keeps even a hostile server answering every
        // retry with `Retry-After: 0` bounded (no infinite loop).
        for _ in 0..self.tokens.attempts() + 1 {
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
                let has_retry_after = response
                    .headers()
                    .get(reqwest::header::RETRY_AFTER)
                    .is_some();
                let retry_after = Self::retry_after(&response);
                let exhausted = Self::quota_exhausted(&response);
                // The `/search/` endpoints run on a separate, per-minute quota
                // whose exhaustion responses carry the *search* quota's
                // `X-RateLimit-Remaining: 0` — the token's hourly core quota
                // is then untouched, and the search window resets within
                // seconds. Retiring a healthy token over a hot search minute
                // would kill single-token runs and burn through multi-token
                // pools one token per minute, so a spent *search* quota is
                // always transient. Live GitHub search exhaustion 403s do not
                // always carry a `Retry-After` header, so the classification
                // keys on the request path or the `X-RateLimit-Resource:
                // search` header, never on the window header.
                // A 429 is always a secondary (transient) limit, even with a
                // spent-quota header: classifying it as a primary exhaustion
                // would let a hostile proxy answering every request with
                // `429` + `Remaining: 0` permanently drain the whole pool
                // one token per response, although no hourly quota was ever
                // spent. The check is therefore gated on the status before
                // the quota header is consulted.
                let spent_search_quota = exhausted
                    && (Self::is_search_endpoint(url)
                        || response
                            .headers()
                            .get("x-ratelimit-resource")
                            .and_then(|value| value.to_str().ok())
                            == Some("search"));
                if status != reqwest::StatusCode::TOO_MANY_REQUESTS
                    && exhausted
                    && !spent_search_quota
                {
                    // Primary rate limit: the hourly quota is spent, retire
                    // the token and rotate to the next one.
                    log::info!(
                        "token #{} has used up its hourly allowance{}",
                        display_index(index),
                        if self.tokens.has_other_live(index) {
                            ": switching to the next available token"
                        } else {
                            " and no other token is available"
                        }
                    );
                    self.tokens.mark_exhausted(index);
                    continue;
                }
                let body = response.text().unwrap_or_default();
                // Any 403/429 that survived the primary-exhaustion check
                // above and carries a `Retry-After` header is transient,
                // even when the value is not integer seconds (the RFC 7231
                // HTTP-date form parses to `None`): a `Retry-After` header
                // signals a retryable condition, so the token is parked for
                // the default window instead of the response being treated
                // as a permanent refusal. A spent search quota is transient
                // by the same token (see above), window header or not. A
                // core 403 with both `X-RateLimit-Remaining: 0` and
                // `Retry-After` never reaches this branch: the primary
                // classification above retires it (the hourly quota is
                // spent — sleeping for the wrong window would be worse).
                let secondary = status == reqwest::StatusCode::TOO_MANY_REQUESTS
                    || has_retry_after
                    || spent_search_quota
                    || Self::body_says_secondary(&body);
                if secondary {
                    // Park the token until its window passes (the quota is
                    // not spent) and rotate to the next live token.
                    let window = retry_after.unwrap_or(Self::DEFAULT_SECONDARY_PARK);
                    let deadline = Instant::now() + window;
                    log::info!(
                        "GitHub asked token #{} to slow down: pausing it for {} seconds, \
                         then switching to another token if one is available",
                        display_index(index),
                        window.as_secs()
                    );
                    self.tokens.mark_limited_until(index, deadline);
                    if self.tokens.has_other_live(index) {
                        continue; // rotate to the next live token and retry
                    }
                    if window == Duration::ZERO {
                        // A `Retry-After: 0` (or an already-elapsed window)
                        // leaves the token live again immediately: an immediate
                        // retry is explicitly authorized and costs no sleep
                        // (the extra loop round above bounds hostile servers).
                        continue;
                    }
                    break; // nothing to rotate to: sleeping would only delay the failure
                }
                // Permanent 403 (private resource, missing token scope,
                // SSO not authorized…).
                return Err(Error::PrivateOrUnavailable);
            }
            if status == reqwest::StatusCode::UNAUTHORIZED {
                // The token itself was rejected (revoked, invalid, expired):
                // retire it and rotate to the next live token when one
                // exists, mirroring the worker pools' token-scoped 401
                // handling. A revoked token in `tokens.json` must not abort
                // the whole run while healthy tokens sit in the pool.
                log::info!(
                    "token #{} was rejected by GitHub (HTTP 401){}",
                    display_index(index),
                    if self.tokens.has_other_live(index) {
                        ": switching to the next available token"
                    } else {
                        " and no other token is available"
                    }
                );
                self.tokens.mark_exhausted(index);
                if self.tokens.has_other_live(index) {
                    continue; // rotate to the next live token and retry
                }
                // Nothing to rotate to: the rejected token is surfaced as a
                // crafted error (the raw reqwest message — "HTTP status
                // client error (401 Unauthorized) for url (…)" — names no
                // next step and reads like a tool failure rather than a
                // credentials problem)
                return Err(Error::TokenRejected);
            }
            if status == reqwest::StatusCode::NOT_FOUND {
                return Err(Error::NotFound);
            }
            if status == reqwest::StatusCode::CONFLICT {
                // GitHub answers 409 Conflict on a `/commits` listing when
                // the repository has no commits ("Git Repository is empty"):
                // a resource-scoped condition the callers skip like a 404.
                // The mapping is scoped to the request path: a 409 from any
                // other endpoint (a broken or hostile intermediary) carries
                // no "empty repository" meaning, so it surfaces as the raw
                // HTTP error instead of a claim about a repository that the
                // endpoint does not even list
                if Self::is_commits_endpoint(url) {
                    return Err(Error::EmptyRepository);
                }
            }
            let response = response.error_for_status()?;
            self.successful_requests.fetch_add(1, Ordering::Relaxed);
            return response.json::<Value>().map_err(Error::from);
        }
        Err(Error::RateLimitExhausted)
    }

    /// Whether a response body announces a transient rate limit (GitHub's
    /// abuse and secondary-limit messages, or the primary-limit body whose
    /// `X-RateLimit-Remaining` header a middlebox stripped) rather than a
    /// permanent refusal: misclassifying those as a permanent 403 would fail
    /// the scan while another token still has budget — or, worse, make a
    /// fully rate-limited scan skip every repository as resource-scoped
    /// failures and exit 0 with a complete-looking empty report.
    fn body_says_secondary(body: &str) -> bool {
        let body = body.to_ascii_lowercase();
        body.contains("secondary rate limit")
            || body.contains("abuse")
            || body.contains("rate limit exceeded")
    }

    /// Whether the URL targets a `/commits` listing: the request path's
    /// last segment must be `commits` with the shape of one of the commit
    /// listings the crate composes (`/repos/{owner}/{repository}/commits`,
    /// or the `/search/commits` endpoint), so only the listings GitHub
    /// answers 409 on when the repository is empty are classified as
    /// commits endpoints — a 409 from any other endpoint (a listing that
    /// holds no repository at all, like `/orgs/{org}/members`, a repository
    /// metadata call, or `/repos/{owner}/commits`, which is the metadata of
    /// a repository *named* `commits`) must not be reported as an "empty
    /// repository".
    fn is_commits_endpoint(url: &str) -> bool {
        let without_scheme = url.split_once("://").map_or(url, |(_, rest)| rest);
        // the path starts at the first `/` after the host (same technique
        // as `is_search_endpoint`), so the host/port is never counted as a
        // path segment
        let Some(slash) = without_scheme.find('/') else {
            return false;
        };
        let path = &without_scheme[slash..];
        let path = path.split(['?', '#']).next().unwrap_or(path);
        let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        if segments.last() != Some(&"commits") {
            return false;
        }
        match segments.len() {
            // /search/commits (the commits search endpoint)
            2 => segments[0] == "search",
            // /repos/{owner}/{repository}/commits (a commit listing)
            4 => segments[0] == "repos",
            _ => false,
        }
    }

    /// Whether the URL targets one of the `/search/` endpoints: the request
    /// path must *start* with `/search/` after the host, so a core endpoint
    /// whose repository happens to be named `search`
    /// (`/repos/{owner}/search/commits`) is not misclassified as a search
    /// endpoint (its spent-quota `Retry-After` responses would then park
    /// the token for a doomed retry every window instead of retiring a
    /// genuinely spent hourly quota).
    fn is_search_endpoint(url: &str) -> bool {
        let without_scheme = url.split_once("://").map_or(url, |(_, rest)| rest);
        match without_scheme.find('/') {
            // the path starts at the first `/` after the host
            Some(slash) => without_scheme[slash..].starts_with("/search/"),
            None => false,
        }
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
    fn the_pool_debug_never_prints_the_tokens() {
        // a derived Debug would print every full token string: the pool only
        // exposes how many tokens it holds, like the masked excerpts of the
        // validation errors
        let pool = TokenPool::from_token("ghp_supersecretvalue").expect("valid token");
        let printed = format!("{pool:?}");
        assert!(
            !printed.contains("ghp_supersecretvalue"),
            "the debug output must not leak the token: {printed}"
        );
        assert!(printed.contains("1 masked token(s)"), "{printed}");
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
        assert!(matches!(error, Error::InvalidTokenFile(_)));
        // the shape problem must not be wrapped in the token-value hint:
        // "expected `ghp_…`" would send the user checking a perfectly fine
        // token instead of the file's structure
        assert!(
            !error.to_string().contains("ghp_"),
            "a token-file shape error must not carry the token-value format hint: {error}"
        );
    }

    #[test]
    fn from_token_file_accepts_a_utf8_bom_like_windows_editors_produce() {
        // Windows Notepad / PowerShell redirects prepend a UTF-8 BOM: the
        // raw bytes made serde_json fail with a bare "expected value at
        // line 1 column 1" on a file that looks fine in the editor that
        // produced it (the bulk-emails reader strips the same BOM). The
        // token file must load with the BOM stripped
        let path = temp_token_file("\u{feff}{\"0\": \"ghp_bom\"}", 8);
        let pool = TokenPool::from_token_file(&path).expect("a BOM-prefixed file must load");
        std::fs::remove_file(&path).ok();
        assert_eq!(pool.acquire(), Some((0, "ghp_bom".to_string())));
    }

    #[test]
    fn from_token_file_names_the_file_when_the_json_is_malformed() {
        // a genuinely malformed file surfaced as the bare serde jargon
        // ("JSON error: expected value at line 1 column 1") with no file
        // named: the failure belongs to the crafted "invalid token file"
        // family and must carry the path
        let path = temp_token_file("not json at all", 9);
        let error = TokenPool::from_token_file(&path).expect_err("must fail");
        std::fs::remove_file(&path).ok();
        assert!(matches!(error, Error::InvalidTokenFile(_)));
        assert!(
            error.to_string().contains(&path.display().to_string()),
            "the malformed-JSON error must name the file: {error}"
        );
    }

    #[test]
    fn from_token_file_rejects_invalid_token_format() {
        let path = temp_token_file(r#"{"0": "ghp_ok", "1": "oops"}"#, 3);
        let error = TokenPool::from_token_file(&path).expect_err("must fail");
        std::fs::remove_file(&path).ok();
        // a short rejected value is masked entirely: echoing it (even partly)
        // would reveal the full secret
        assert!(matches!(error, Error::InvalidTokenFormat(masked) if masked == "***"));
    }

    #[test]
    fn a_short_rejected_token_is_masked_entirely() {
        // the "never the full secret" contract: a rejected value of at most
        // 8 characters (a typo like `--token abc`) must not be echoed in
        // full under the 4-character excerpt
        let error = TokenPool::from_token("abc").expect_err("must fail");
        assert!(matches!(error, Error::InvalidTokenFormat(masked) if masked == "***"));
        let error = TokenPool::from_token("12345678").expect_err("must fail");
        assert!(matches!(error, Error::InvalidTokenFormat(masked) if masked == "***"));
        // long enough values keep their excerpt
        let error = TokenPool::from_token("not_a_token").expect_err("must fail");
        assert!(matches!(error, Error::InvalidTokenFormat(masked) if masked == "not_***"));
    }

    #[test]
    fn from_token_file_with_no_usable_token_fails_fast() {
        // a file yielding zero usable tokens would silently downgrade the
        // run to anonymous access (60 req/h) and only surface much later as
        // a confusing RateLimitExhausted: it must fail at load time instead
        for contents in [r#"{}"#, r#"{"0": ""}"#] {
            let path = temp_token_file(contents, 7);
            let error = TokenPool::from_token_file(&path).expect_err("must fail");
            std::fs::remove_file(&path).ok();
            assert!(
                matches!(error, Error::InvalidTokenFile(ref details) if details.contains("no usable token")),
                "unexpected error: {error:?}"
            );
        }
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
    fn from_token_file_deduplicates_identical_token_strings() {
        // two indexes holding the same secret are one token, not a second
        // quota: keeping both would make a primary exhaustion "rotate" to
        // the same dead secret and let two workers share one quota
        let path = temp_token_file(r#"{"0": "ghp_same", "1": "ghp_same", "2": "ghp_other"}"#, 6);
        let pool = TokenPool::from_token_file(&path).expect("token file must load");
        std::fs::remove_file(&path).ok();
        assert_eq!(pool.len(), 2);
        assert_eq!(pool.acquire(), Some((0, "ghp_same".to_string())));
        assert_eq!(pool.acquire(), Some((1, "ghp_other".to_string())));
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
        assert!(matches!(error, Error::InvalidTokenFile(details) if details.contains("foo")));
    }

    #[test]
    fn from_token_trims_paste_artifacts_and_treats_whitespace_only_as_anonymous() {
        // a token pasted with leading/trailing spaces must be trimmed, and
        // a whitespace-only value is no token at all: an empty pool
        let pool = TokenPool::from_token("  ghp_validprefixvalue  ").unwrap();
        assert_eq!(pool.tokens, vec!["ghp_validprefixvalue"]);
        let pool = TokenPool::from_token("   ").unwrap();
        assert!(pool.tokens.is_empty());
    }

    #[test]
    fn from_token_rejects_a_control_character_in_the_value() {
        // a CRLF-edited token file or a pasted newline passes the prefix
        // check but used to fail only inside reqwest's header build with a
        // cryptic `builder error` that never named the credential: it must
        // be rejected at load time instead
        for token in ["ghp_a\rb", "github_pat_x\ny", "ghp_a\u{0}b"] {
            let error = TokenPool::from_token(token).expect_err("must fail");
            assert!(
                matches!(&error, Error::InvalidTokenFormat(details) if details.contains("control character")),
                "unexpected error: {error:?}"
            );
        }
        // the masking convention holds on this path too (a NUL is not
        // whitespace, so the paste-artifact trim does not remove it: the
        // value stays a rejected control-character token)
        let error = TokenPool::from_token("ghp_long_enough_value\u{0}").expect_err("must fail");
        assert!(
            matches!(&error, Error::InvalidTokenFormat(masked) if masked.starts_with("ghp_***")),
            "unexpected error: {error:?}"
        );
    }

    #[test]
    fn is_commits_endpoint_matches_only_the_trailing_path_segment() {
        // the "empty repository" 409 meaning only holds for a `/commits`
        // listing: the classification must key on the request path's last
        // segment, not on `/commits` occurring anywhere in the URL
        assert!(Client::is_commits_endpoint(
            "https://api.github.com/repos/extiop/ctf/commits?per_page=100&page=1"
        ));
        assert!(Client::is_commits_endpoint(
            "http://127.0.0.1:8080/repos/a/b/commits"
        ));
        assert!(!Client::is_commits_endpoint(
            "https://api.github.com/orgs/acme/members?per_page=100&page=1"
        ));
        assert!(!Client::is_commits_endpoint(
            "https://api.github.com/users/extiop/repos"
        ));
        // a repository named `commits` is metadata, not a commit listing
        // (a listing always carries the `repos/{owner}/{repo}/commits`
        // shape): the segment count tells them apart
        assert!(!Client::is_commits_endpoint(
            "https://api.github.com/repos/extiop/commits"
        ));
        // a commit listing of a repository named `search` (the inverse of
        // the search-endpoint scoping case) is a commits endpoint
        assert!(Client::is_commits_endpoint(
            "https://api.github.com/repos/owner/search/commits?page=1"
        ));
        assert!(!Client::is_commits_endpoint("https://api.github.com"));
        assert!(!Client::is_commits_endpoint("not a url"));
    }

    #[test]
    fn is_search_endpoint_matches_only_the_leading_path_segment() {
        // the exemption must key on the request *path*, not on `/search/`
        // occurring anywhere in the URL: a core endpoint whose repository is
        // named `search` is not a search endpoint
        assert!(Client::is_search_endpoint(
            "https://api.github.com/search/repositories?q=x"
        ));
        assert!(Client::is_search_endpoint(
            "http://127.0.0.1:8080/search/commits?page=1"
        ));
        assert!(!Client::is_search_endpoint(
            "https://api.github.com/repos/owner/search/commits?page=1"
        ));
        assert!(!Client::is_search_endpoint(
            "https://search.example.com/repos/owner/commits"
        ));
        assert!(!Client::is_search_endpoint("https://api.github.com"));
        assert!(!Client::is_search_endpoint("not a url"));
    }

    #[test]
    fn a_search_quota_403_without_a_retry_after_parks_never_retires() {
        use crate::github::mock::serve_requests;
        // Live-captured shape of a hot search minute (real GitHub): a 403
        // with the *search* quota spent (`X-RateLimit-Resource: search`,
        // `X-RateLimit-Remaining: 0`), the primary-limit body, and NO
        // `Retry-After` header — GitHub's search exhaustion does not always
        // carry a window, so the search exemption cannot key on
        // `Retry-After` alone. The token's hourly core quota is untouched
        // there, so the token must only be parked (a pending deadline):
        // retiring it would permanently drain healthy tokens one per hot
        // search minute and abort runs while thousands of core requests
        // remain.
        let (address, server) = serve_requests(move |index, _request| {
            if index == 0 {
                return (
                    403,
                    vec![
                        ("X-RateLimit-Remaining".to_string(), "0".to_string()),
                        ("X-RateLimit-Resource".to_string(), "search".to_string()),
                    ],
                    "API rate limit exceeded for user ID 29679238.".to_string(),
                );
            }
            (200, vec![], r#"{"ok": true}"#.to_string())
        });

        let pool =
            TokenPool::from_token_file(&temp_token_file(r#"{"0": "ghp_a", "1": "ghp_b"}"#, 30))
                .expect("token file must load");
        let client = Client::new(pool).expect("client must build");
        let json = client
            .get_json(&format!("{address}/search/repositories?q=x"))
            .expect("the search-quota blip must rotate to the healthy token");
        assert_eq!(json["ok"], serde_json::json!(true));

        // The distinguishing contract: the blipped token is PARKED (a
        // pending deadline), not RETIRED (a permanent `None` entry) — it
        // must come back once the search window passes instead of being
        // lost for the rest of the process.
        let exhausted = client.tokens.exhausted.lock().expect("unpoisoned lock");
        assert!(
            matches!(exhausted.get(&0), Some(Some(_))),
            "a search-quota 403 without Retry-After must park the token, never retire it: {:?}",
            exhausted.get(&0)
        );
        drop(exhausted);
        server.join();
    }

    #[test]
    fn a_core_quota_403_without_a_retry_after_still_retires() {
        use crate::github::mock::serve_requests;
        // The search-quota exemption must not swallow a genuinely spent
        // *core* quota: a 403 with the hourly quota spent and no resource
        // header (the core default) stays a primary exhaustion even without
        // a `Retry-After` window — the token is retired for the process.
        let (address, server) = serve_requests(move |index, _request| {
            if index == 0 {
                return (
                    403,
                    vec![("X-RateLimit-Remaining".to_string(), "0".to_string())],
                    "API rate limit exceeded for user ID 29679238.".to_string(),
                );
            }
            (200, vec![], r#"{"ok": true}"#.to_string())
        });

        let pool =
            TokenPool::from_token_file(&temp_token_file(r#"{"0": "ghp_a", "1": "ghp_b"}"#, 31))
                .expect("token file must load");
        let client = Client::new(pool).expect("client must build");
        client
            .get_json(&format!("{address}/repos/owner/repo/commits"))
            .expect("the spent token must rotate to the healthy one");

        let exhausted = client.tokens.exhausted.lock().expect("unpoisoned lock");
        assert!(
            matches!(exhausted.get(&0), Some(None)),
            "a spent core quota must permanently retire the token: {:?}",
            exhausted.get(&0)
        );
        drop(exhausted);
        server.join();
    }
}
