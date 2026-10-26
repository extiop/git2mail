# GitHub API usage

## Requests

- Every endpoint is queried with `per_page=100` (the maximum page size).
- The `Authorization: token <token>` header is sent only when the request
  is bound to a token; anonymous requests omit it.
- User agent and `Accept` headers are set once, in the client.

## Pagination

All listings (repository commits, profile events, profile repositories,
search results) go through a single paginated loop:

1. fetch page `n`;
2. if the page is empty, the listing is complete;
3. otherwise parse it and continue with page `n + 1`.

Two guards bound the loop:

- **Short-page guard.** Listings fetched page by page (repository commits,
  profile events, search results, the `user` investigation's identity
  listings, the `email` candidate search, and the commit verification of
  one `email` candidate) stop when a page comes back underfilled,
  instead of walking into the error page GitHub serves past the real end
  of a listing. The simple listings (the profile fallback repository
  enumeration, the public repositories and keys of a `user`, organization
  members and repositories) end only when a page comes back empty.
- **Token-pool bound.** Every page request participates in the rate-limit
  handling below; the loop can never spin: when every token is exhausted,
  the scan fails with an explicit error instead of retrying forever.

## Network egress: proxies and Tor

The HTTP client honors the standard proxy environment variables exactly
the way the HTTP stack resolves them, and git2mail checks them at
startup, announces the proxy actually used, and loudly warns instead of
silently falling back when a configured proxy is unusable.

### What the stack honors

- `HTTPS_PROXY` (or `https_proxy`) is the primary variable for
  git2mail's traffic: the tool is HTTPS-only, so an `HTTP_PROXY` value
  is never used for it (announced as an informational note, since it
  usually means a proxy is configured but scoped elsewhere).
- `ALL_PROXY` (or `all_proxy`) is the fallback, used only when the
  primary variable is absent or unusable.
- Proxy schemes are **case-sensitive** and lowercase-only: `socks5://`,
  `socks5h://`, `socks4://`, `socks4a://`, `http://`, `https://` work;
  `SOCKS5://` is not recognized by the stack (a warning names it).
- A set-but-empty variable counts as set and shadows its lowercase
  twin: the run goes direct and the warning says so.
- A set `NO_PROXY` can bypass the proxy for some hosts: warned about
  when a proxy is in use.
- A set `REQUEST_METHOD` (the stack's CGI marker) makes the stack
  discard every proxy variable: warned about when any proxy variable is
  set.
- Proxy values are never logged: a proxy URL can carry embedded
  credentials.

### Tor

Route a run through Tor with a `socks5h` URL, no flag needed:

```bash
HTTPS_PROXY=socks5h://127.0.0.1:9050 git2mail scan --url "$TARGET_URL" --token-file tokens.json
```

`socks5h` asks the proxy to resolve hostnames (verified against the
bundled HTTP stack: the `socks5h` scheme maps to proxy-side DNS
resolution); plain `socks5` resolves hostnames locally, which leaks
every lookup's hostname to the local resolver — prefer `socks5h` for
Tor.

Two honesty notes, stated plainly:

- **The startup check proves the proxy at launch, not the whole run's
  path.** It resolves the environment exactly like the HTTP stack and
  announces the proxy in use, but it is not a continuous guarantee:
  before a sensitive run, verify your exit IP.
- **Anonymous runs through Tor are practically unusable**: GitHub's
  anonymous quota (about 60 requests per hour) is shared by every user
  of that exit node, so a shared exit is spent before your first scan
  finishes. With a token, the quota is per token (5,000 requests per
  hour), but expect more frequent secondary-limit pauses (the tool
  parks a token until its window passes and rotates to the next one);
  the park semantics are described in [Rate limits](#rate-limits).

GitHub applies the same rate limits and the same abuse detection
whatever the request's origin; this guide documents what the stack
honors, not techniques to avoid either.

## Rate limits

GitHub rate limits come in two flavors, and the client reacts to each one
differently.

### Primary limit (quota)

A `403` whose `x-ratelimit-remaining` header is `0` means a quota is
spent, and which quota decides the reaction:

- on the core endpoints, the token's hourly quota is spent: the token is
  **parked** until the instant the `x-ratelimit-reset` header names (capped
  at one hour so a hostile header cannot park it indefinitely), then
  returns automatically, and the request is retried with the next available
  token. A spent allowance is a pause, not a death: a long parallel scan
  gets its token back at the reset. When the header is absent (a middlebox
  stripped it), there is no known window to wait for: the token is
  **retired** (removed from the allocation pool for the rest of the run)
  instead of being retried on a guessed window. A retired token never
  comes back;
- on the `/search/` endpoints (or any response carrying
  `X-RateLimit-Resource: search`), the spent quota is the separate
  per-minute search quota: the token's hourly core quota is untouched, so
  the token is only **parked** for the short search window. Retiring a
  healthy token over a hot search minute would drain multi-token pools
  one token per minute.

When a run stops because every token is unusable, the error names the
cause: an hourly allowance drained pool stops with "every token's allowance
is used up" (`RateLimitExhausted`), while a pool parked by secondary
windows stops with the dedicated paused message ("wait a few minutes",
`RateLimitPaused`).

A `403` with `x-ratelimit-remaining` above `0` is a genuine refusal (for
example a private or missing resource) and is **not** treated as rate limiting, unless it carries a `Retry-After` header, the secondary-limit body, or a primary-limit body whose quota header a middlebox stripped (the body text "API rate limit exceeded" is treated as transient too, since the missing header makes the two indistinguishable); those cases park the token
instead (see below).

### Secondary limit (abuse detection)

A `429` is never treated as a spent quota, because "too many requests" is a transient condition, so the token is **parked**, never retired, even when
the response carries `x-ratelimit-remaining: 0`. The same holds for a
`403` carrying a `Retry-After` header or the documented secondary-limit
body without an exhausted core quota: the token is taken out of the
allocation pool until its window passes (`Retry-After` honored as-is,
capped at one hour so a hostile header cannot park a token indefinitely),
then returns automatically, and the request rotates immediately to another
live token when one exists. Parked tokens can still serve other workers
through the shared pool. A window that has already elapsed
(`Retry-After: 0`) is retried immediately at no cost. An HTTP `401`
(revoked or invalid token) retires the token like a spent quota.

When a request fails on a token and another token is available, the
request is transparently retried on the next token; the caller sees a
failure only when no token can serve the request.

## Caps and limits

| Limit | Value | Effect |
|-------|-------|--------|
| Events timeline | 300 events | GitHub caps profile events; the listing stops there honestly |
| Repository commits | full history | the default-branch walk ends when GitHub's listing ends (a short page); nothing is truncated locally |
| Search results | 1000 | GitHub's documented search ceiling; reaching it ends the listing with a warning |
| Reverse-email candidates | full listing | every candidate repository the search serves is verified, each over its full default-branch history (until a `commit-author` match ends the lookup early) |
| Name pairs x domains | 64 x 64 | variant-generation inputs are truncated before generation |
| Generated variants | 1000 | global cap on generated candidate addresses |
| Custom patterns | 64 | `--variant-pattern` accepts at most 64 patterns |
| Bulk addresses file | 64 MiB | a bulk addresses file larger than 64 MiB is refused before reading |
| URL length | 2048 bytes | a URL longer than 2048 bytes is rejected before any request |

## Search

`search` runs `q=<query>` against `https://api.github.com/search/repositories`.
`--language` appends the `language:` qualifier, and nine further qualifiers
compose with the query: `--stars`, `--forks` and `--size` take count ranges
(`>100`, `10..50`), `--created` and `--pushed` take date ranges
(`>2020-01-01`, `2019-01-01..2020-01-01`), and `--license`, `--topic`,
`--user` and `--org` take plain values. Every provided qualifier is
validated client-side before any request: a malformed range or an
impossible date fails fast with an explicit error instead of surfacing as
an empty result set from the API. `--limit` bounds how many repository
results are scanned.

A `422` on the first page means the API rejected the query itself (an
over-long or invalid `q`, or an inaccessible `--user`/`--org` login): the
run fails explicitly instead of degrading into an empty report. A `422`
past the first page is GitHub's documented window boundary: the scan ends
with an explicit warning that the collected repositories were discarded,
rather than reporting a truncated set as complete.
