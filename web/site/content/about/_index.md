+++
title = "About"
description = "What the git2mail web scan does with your data, what it stores (nothing), what GitHub sees, and how to verify all of it yourself."
+++

# About this page and its limits

## What happens when you scan

This page runs entirely in your browser: there is no server behind it
and nothing is stored - close the tab and nothing remains **on this
site**. You need no account and no token. It calls GitHub's public API **anonymously,
from your IP address** - and if you are signed in to GitHub in this
browser, GitHub can link the scan to your account.

The quota line shows GitHub's remaining anonymous allowance (about 60
requests per hour) exactly as GitHub reports it on every response.

## Who can see what

- **GitHub** sees every query, obviously.
- **A repository's owner** sees its aggregate traffic (views, clones),
  but that graph counts page views and clones, not API calls: the scan
  itself does not show up there. GitHub sees the queries; the owner's
  public graph does not.
- **GitHub Pages**, the service that hosts this page, records
  visitors' IP addresses in its own logs: "nothing is stored here"
  describes this site, not GitHub.
- **Nobody else**: no font, analytics, script or image comes from a
  third party - the page loads everything from its own address and
  talks to api.github.com only.

## Verify it yourself

Don't take this page's word: everything it claims about itself is
checkable in the browser.

- **View the source** of the scan page: the logic is one hand-written,
  fully readable JavaScript file (`js/scan.js`) plus a WebAssembly module
  and its generated loader, compiled from the CLI's own rule engine.
- **Read the Content-Security-Policy** meta tag at the top of the page
  source: the browser may connect to `api.github.com` and to this
  site's own address, and nothing else; scripts come from this site
  only.
- **Watch the Network tab** while scanning: every request the scan
  makes goes to api.github.com - the page's own files load from this
  site's address, and nothing else appears.
- **Search `js/scan.js` and the wasm module** for `localStorage`,
  `sessionStorage`, `cookie` or `indexedDB`: you will not find them -
  nothing is written to your machine by this site.

## The honest limit

The anonymous quota makes this page a discovery tool, not a bulk
scanner: scanning a large repository can use the whole hourly
allowance before it finishes. Every
scan result ends with the exact commands that go further; the
[guide](https://extiop.github.io/git2mail/guide/) documents what they do.

This tool collects only data that is already public. The full
responsibilities and caveats live in the guide: [responsible use](https://extiop.github.io/git2mail/guide/) and
[data quality, prevention and
limitations](https://extiop.github.io/git2mail/guide/QUALITY.html).
