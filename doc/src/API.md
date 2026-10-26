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
