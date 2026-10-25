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

One invariant bounds the loop:

- **Token-pool bound.** Every page request participates in the rate-limit
  handling below; the loop can never spin: when every token is exhausted,
  the scan fails with an explicit error instead of retrying forever.

## Rate limits

GitHub rate limits come in two flavors, and the client reacts to each one
differently.

### Primary limit (quota)

A `403` whose `x-ratelimit-remaining` header is `0` means the token's
hourly quota is spent. The token is **retired**: it is removed from the
allocation pool for the rest of the run, and the request is retried with
the next available token. A retired token never comes back. A `429` is
never treated as a spent quota, because "too many requests" is a transient condition, so a `429` parks the token instead, even when it carries
`x-ratelimit-remaining: 0` (see below).

A `403` with `x-ratelimit-remaining` above `0` is a genuine refusal (for
example a private or missing resource) and is **not** treated as rate
limiting, unless it carries a `Retry-After` header or the secondary-limit
body, which parks the token instead (see below).

### Secondary limit (abuse detection)

Short bursts of secondary rate limiting (`403`/`429` with a `Retry-After`
header, or the documented secondary-limit body) **park** the token: the
token is taken out of the allocation pool until the `Retry-After` delay
elapses, then returns automatically. Parked tokens can still serve other
workers through the shared pool. The honored delay is capped at one hour
so that a hostile header cannot park a token indefinitely.

When a request fails on a token and another token is available, the
request is transparently retried on the next token; the caller sees a
failure only when no token can serve the request.

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
results are scanned. A search request rejected by the API
(itself a `422 Validation Failed`) propagates as an explicit failure
instead of degrading into an empty report.
