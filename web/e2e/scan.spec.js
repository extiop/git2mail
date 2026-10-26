// E2E: the anonymous scan page against a same-origin GitHub mock.
// Every scenario pins a contract the spec states; the wasm carries the
// rules, so these tests also prove the bindings behave in a real browser.

const { test, expect } = require("@playwright/test");

const BASE = `http://127.0.0.1:${process.env.PORT || 8931}`;

const URL_INPUT = "#target-url";

async function scan(page, target) {
  await page.fill(URL_INPUT, target);
  await page.click("#scan-form button");
}

test.describe("the anonymous scan page", () => {
  test("no auto-run: a ?url= parameter pre-fills but never fires", async ({ page }) => {
    // the spy is attached BEFORE navigation: a fetch fired during page
    // load would otherwise be missed by the request-count assertion
    const requests = [];
    page.on("request", (r) => requests.push(r.url()));
    await page.goto(`${BASE}/?url=https://github.com/demo/normal`);
    await expect(page.locator(URL_INPUT)).toHaveValue("https://github.com/demo/normal");
    await expect(page.locator("#results")).toBeHidden();
    await page.waitForTimeout(500);
    expect(requests.filter((u) => u.includes("/repos/"))).toHaveLength(0);
  });

  test("the example links pre-fill a target without auto-run", async ({ page }) => {
    await page.goto(`${BASE}/`);
    const requests = [];
    page.on("request", (r) => requests.push(r.url()));
    await page.click("text=octocat/Hello-World");
    await page.waitForLoadState("load");
    // the link lands on /?url=... : the field is pre-filled, the scan
    // never fires until the visitor clicks Scan (the no-auto-run rule
    // the form itself is pinned by)
    await expect(page.locator(URL_INPUT)).toHaveValue("https://github.com/octocat/Hello-World");
    await expect(page.locator("#results")).toBeHidden();
    await page.waitForTimeout(300);
    expect(requests.filter((u) => u.includes("api.github.com") || u.includes("/repos/"))).toHaveLength(0);
  });

  test("a full repository scan renders the author cards and the honesty block", async ({ page }) => {
    await page.goto(`${BASE}/`);
    await scan(page, "https://github.com/demo/normal");
    await expect(page.locator("#results")).toBeVisible();
    // the usable author emails only: the quoted one trimmed, the noreply
    // and injection-carrying ones dropped
    await expect(page.locator("#authors")).toContainText("Jane Doe");
    await expect(page.locator("#authors")).toContainText("jane@example.com");
    await expect(page.locator("#authors")).toContainText("jane.quoted@example.com");
    await expect(page.locator("#authors")).not.toContainText("oldname");
    await expect(page.locator("#authors")).not.toContainText("evil@x.com");
    // the newline-carrying injection attempt is dropped whole: its author
    // name must not survive as a card either
    await expect(page.locator("#authors")).not.toContainText("Injection");
    // the honesty block and the funnel
    await expect(page.locator(".trust")).toContainText("old or faked");
    // plain words first, the mechanism named beside them
    await expect(page.locator(".trust")).toContainText("folds several changes into one merge");
    await expect(page.locator(".trust")).toContainText("the project's main line");
    await expect(page.locator(".trust")).toContainText("public events timeline");
    await expect(page.locator(".trust")).toContainText("the project's main line");
    // the funnel's commands run anonymous-first (the same budget this
    // page just used), each announced by its role; the token is the
    // follow-up note, not a prerequisite
    await expect(page.locator("#funnel")).toContainText(
      "git2mail email 'jane@example.com'",
    );
    await expect(page.locator("#funnel")).toContainText(
      "git2mail scan --url 'https://github.com/demo/normal'",
    );
    // no inert domain in this fixture: the demotion note stays absent
    await expect(page.locator("#funnel")).not.toContainText(
      "root@localhost, reserved test domains and similar",
    );
    await expect(page.locator("#funnel")).toContainText(
      "--token-file tokens.json",
    );
    // the evidence command carries its role line: what the visitor is
    // about to run and what it can honestly return, before running it
    await expect(page.locator("#funnel")).toContainText(
      "Which GitHub account uses this address",
    );
    await expect(page.locator("#funnel")).toContainText(
      "Finding nothing does not prove the address is unused",
    );
    // no downloaded file exists yet on THIS scan? normal has results, so
    // the bulk tip is present and true
    await expect(page.locator("#funnel")).toContainText("git2mail emails <file>");
    // the terminal status resolves (no eternal "Scanning…")
    await expect(page.locator("#status")).toContainText("Done:");
  });

  test("a re-run is a complete snapshot of the new run, never an accumulation", async ({ page }) => {
    await page.goto(`${BASE}/`);
    await scan(page, "https://github.com/demo/multi");
    await expect(page.locator("#status")).toContainText("Done: 100 unique");
    // a different target: "Jane Doe" only renders in run 2, so this
    // retried expectation doubles as the run-2 completion marker before
    // any one-shot read (no race with the previous render)
    await scan(page, "https://github.com/demo/normal");
    await expect(page.locator("#authors")).toContainText("Jane Doe");
    const authors = await page.locator("#authors").textContent();
    expect(authors).not.toContain("Alice");
    expect(authors).not.toContain("Bob");
    await expect(page.locator("#summary")).toContainText("4 commits read");
    await expect(page.locator("#summary")).toContainText("2 unique email");
    // a third run of a third target: "dev@example.com" only renders in
    // run 3 (demo/quoted) - the marker proves run 3 completed, then the
    // eviction checks prove the snapshot replaced runs 1 and 2 whole
    await scan(page, "https://github.com/demo/quoted");
    await expect(page.locator("#authors")).toContainText("dev@example.com");
    const authors3 = await page.locator("#authors").textContent();
    expect(authors3).not.toContain("Alice");
    expect(authors3).not.toContain("Bob");
    expect(authors3).not.toContain("Jane Doe");
    await expect(page.locator("#summary")).toContainText("1 unique email address");
  });

  test("a quoted author email is reported unquoted, like the CLI", async ({ page }) => {
    await page.goto(`${BASE}/`);
    await scan(page, "https://github.com/demo/quoted");
    await expect(page.locator("#authors")).toContainText("dev@example.com");
    const body = await page.locator("#authors").textContent();
    expect(body).not.toContain('"dev@example.com"');
  });

  test("a multi-page walk aggregates every page", async ({ page }) => {
    await page.goto(`${BASE}/`);
    const requests = [];
    page.on("request", (r) => requests.push(r.url()));
    await scan(page, "https://github.com/demo/multi");
    await expect(page.locator("#authors")).toContainText("Alice");
    await expect(page.locator("#authors")).toContainText("Bob");
    // the count is only reachable after absorbing page 2 (page 1 is FULL:
    // 100 commits): this is what pins the pagination loop itself
    await expect(page.locator("#summary")).toContainText("101 commits read");
    await expect(page.locator("#status")).toContainText("Done: 100 unique");
    // the walk requests GitHub's own page size, once per page (terminal
    // state first: the requests exist by then)
    expect(requests.filter((u) => u.includes("/repos/demo/multi/commits") && u.includes("per_page=100"))).toHaveLength(2);
  });

  test("the Link header feeds the ~N-requests estimate, never the walk length", async ({ page }) => {
    await page.goto(`${BASE}/`);
    await scan(page, "https://github.com/demo/estimate");
    // GitHub-shaped: page 1 carries Link rel="last" page=2 - the estimate
    // must announce it (the mock delays page 2 by 250 ms so the transient
    // status is observable without a race)
    await expect(page.locator("#status")).toContainText("about 2 requests");
    // the walk itself still ends on the short page, and the estimate is
    // only narration: the final state is the real aggregate
    await expect(page.locator("#status")).toContainText("Done: 101 unique");
    await expect(page.locator("#summary")).toContainText("101 commits read");
  });

  test("a noreply-only target reports zero results without a malformed funnel command", async ({ page }) => {
    await page.goto(`${BASE}/`);
    await scan(page, "https://github.com/demo/noreply");
    await expect(page.locator("#summary")).toContainText("no usable email found");
    await expect(page.locator("#funnel")).not.toContainText("email  --token-file");
    // zero results: no .log exists, so the funnel must not advertise it
    await expect(page.locator("#funnel")).not.toContainText("git2mail emails <file>");
    // nothing to copy or download when nothing was found: offering the
    // actions would let the page announce success on an empty clipboard
    await expect(page.locator("#actions")).toBeHidden();
  });

  test("a hostile author name cannot become a spreadsheet formula", async ({ page }) => {
    await page.goto(`${BASE}/`);
    await scan(page, "https://github.com/demo/inject");
    await expect(page.locator("#status")).toContainText("Done: 8 unique");
    // hostile emails (no whitespace: they pass the email rule) must never
    // reach the funnel as shell syntax: cmd.exe has no single quote, so
    // quoting alone cannot defuse &, $ or parentheses - unsafe values are
    // left out of the commands entirely and the note says so
    await expect(page.locator("#funnel")).not.toContainText("pwned");
    await expect(page.locator("#funnel")).not.toContainText("calc.exe");
    await expect(page.locator("#funnel")).not.toContainText("guarded.example");
    await expect(page.locator("#funnel")).toContainText(
      "The commands above do not include them: 5 values in this scan contain characters a terminal would misread. Download the results and run git2mail emails <file> on that file instead.",
    );
    // the inert-domain note: guarded.example is a reserved TLD and
    // x,com has no dot - the presentation-only demotion says so (the
    // data itself is unchanged everywhere)
    await expect(page.locator("#funnel")).toContainText(
      "root@localhost, reserved test domains and similar",
    );
    // the funnel says its commands embed third-party data
    await expect(page.locator("#funnel")).toContainText(
      "Read a command before you run it",
    );
    // a clean address still gets its quoted command
    await expect(page.locator("#funnel")).toContainText(
      "git2mail email 'jane@example.com'",
    );
    await page.context().grantPermissions(["clipboard-read", "clipboard-write"]);
    await page.click("#copy-list");
    // the leading = is neutralized (text marker), the injected tab is
    // flattened: the paste lands as data, never as a formula or a torn row
    expect(await page.evaluate(() => navigator.clipboard.readText()))
      // the injected tab never arrives: the wasm boundary already
      // rendered the hostile name through the CLI's log-safety rule
      .toBe("'=WEBSERVICE_(\"https://attacker.example\")\thostile@example.com\t2024-04-01\n" +
            "Shell Tip\tx$(touch${IFS}pwned)@guarded.example\t2024-04-02\n" +
            "Cmd Run\tx@y.com&calc.exe&\t2024-04-03\n" +
            "Backslash Tip\tx\\@x.com\t2024-04-04\n" +
            "Domain Junk\tdev@x,com\t2024-04-05\n" +
            "Dot Junk\tdev@..\t2024-04-07\n" +
            "Formula Mail\t'=x@y.com\t2024-04-06\n" +
            "Jane Doe\tjane@example.com\t2024-04-02");
    // the mail copy: the local part of a hostile address is RFC 5322
    // quoted (a backslash becomes a quoted pair, so one address stays
    // one recipient); an address whose DOMAIN is not a plain dot-atom
    // has no valid encoding and is left out, announced in the status
    await page.click("#copy-emails");
    expect(await page.evaluate(() => navigator.clipboard.readText()))
      .toBe("=x@y.com, hostile@example.com, jane@example.com, " +
            '"x\\\\"@x.com, ' +
            '"x$(touch${IFS}pwned)"@guarded.example');
    await expect(page.locator("#status")).toContainText(
      "3 addresses in this scan cannot be used in an email field",
    );
  });

  test("the downloaded provenance names the scanned target, not the edited field", async ({ page }) => {
    await page.goto(`${BASE}/`);
    await scan(page, "https://github.com/demo/normal");
    await expect(page.locator("#status")).toContainText("Done:");
    // a visitor naturally edits the field while reading results: the
    // file must still describe what was actually scanned (forged
    // provenance would defeat the header's whole purpose)
    await page.fill(URL_INPUT, "https://github.com/demo/ghost");
    const [download] = await Promise.all([
      page.waitForEvent("download"),
      page.click("#download-log"),
    ]);
    expect(download.suggestedFilename()).toBe("demo_normal.log");
    const stream = await download.createReadStream();
    const chunks = [];
    for await (const chunk of stream) chunks.push(chunk);
    const content = Buffer.concat(chunks).toString();
    expect(content).toContain("# target: https://github.com/demo/normal");
    expect(content).not.toContain("demo/ghost");
  });

  test("an empty repository is a named error, not a generic failure", async ({ page }) => {
    await page.goto(`${BASE}/`);
    await scan(page, "https://github.com/demo/empty");
    await expect(page.locator("#status")).toContainText("GitHub repository is empty");
  });

  test("a missing resource names the error", async ({ page }) => {
    await page.goto(`${BASE}/`);
    await scan(page, "https://github.com/demo/ghost");
    await expect(page.locator("#status")).toContainText("GitHub resource not found");
  });

  test("a /tree/ paste-artifact URL reaches the API and fails with the passthrough name", async ({ page }) => {
    await page.goto(`${BASE}/`);
    const requests = [];
    page.on("request", (r) => requests.push(r.url()));
    await scan(page, "https://github.com/demo/ghost/tree/main");
    // the nested path must pass through to the API untouched: pin the
    // exact request URL, not just the named error (a stripped /tree/
    // would otherwise 404 on the plain route and pass identically)
    await expect(page.locator("#status")).toContainText("GitHub resource not found");
    expect(requests.filter((u) => u.includes("/repos/demo/ghost/tree/main/commits"))).toHaveLength(1);
  });

  test("a secondary refusal is named as such, never dressed as the hourly quota", async ({ page }) => {
    await page.goto(`${BASE}/`);
    await scan(page, "https://github.com/demo/blocked");
    // the quota counter showed 30 on the refused response: claiming the
    // hourly quota ran out would be a factually wrong cause with a
    // wrong "resets at" instant - the page must say what happened
    await expect(page.locator("#status")).toContainText("a temporary rate limit");
    await expect(page.locator("#status")).not.toContainText("Quota exhausted");
    // the status line lives OUTSIDE the hidden results container: an
    // error with no data must be seen, not merely present in the DOM
    await expect(page.locator("#status")).toBeVisible();
    // the refusal landed on page 1: nothing was collected, so nothing is
    // partial - the results section must stay hidden, not show an empty
    // PARTIAL page
    await expect(page.locator("#results")).toBeHidden();
  });

  test("a quota death mid-walk yields the terminal PARTIAL state", async ({ page }) => {
    await page.goto(`${BASE}/`);
    await scan(page, "https://github.com/demo/quotadead");
    await expect(page.locator("#summary")).toContainText("PARTIAL:");
    await expect(page.locator("#status")).toContainText("Quota exhausted");
    await expect(page.locator("#status")).not.toContainText("Done:");
    // the partial page still carries the addresses collected before the death
    await page.context().grantPermissions(["clipboard-read", "clipboard-write"]);
    await page.click("#copy-list");
    expect(await page.evaluate(() => navigator.clipboard.readText()))
      .toContain("jane@example.com");
    // and the downloaded file must say it is partial: the artifact
    // outlives the page's warnings and must not pass for complete
    const [download] = await Promise.all([
      page.waitForEvent("download"),
      page.click("#download-log"),
    ]);
    const stream = await download.createReadStream();
    const chunks = [];
    for await (const chunk of stream) chunks.push(chunk);
    expect(Buffer.concat(chunks).toString()).toContain("# status: partial");
  });

  test("an inert commit domain is demoted in the funnel, never in the data", async ({ page }) => {
    await page.goto(`${BASE}/`);
    await scan(page, "https://github.com/demo/localart");
    await expect(page.locator("#status")).toContainText("Done: 3 unique");
    // the suggested commands lead with an address a person could answer:
    // root@localhost and ci@build.local follow (stable partition, order
    // only - no removal)
    // the suggested commands lead with an address a person could answer:
    // scan, then email jane, then the inert domains, then the user walk
    const commands = page.locator("#funnel .funnel-command");
    await expect(commands.nth(1)).toHaveText("git2mail email 'jane@example.com'");
    await expect(commands.nth(2)).toContainText("root@localhost");
    await expect(commands.nth(3)).toContainText("ci@build.local");
    // the demotion explains itself without labeling the data
    await expect(page.locator("#funnel")).toContainText(
      "Some addresses cannot receive mail",
    );
    // the data is byte-identical: card, spreadsheet paste and download
    await expect(page.locator("#authors")).toContainText("root@localhost");
    await page.context().grantPermissions(["clipboard-read", "clipboard-write"]);
    await page.click("#copy-list");
    expect(await page.evaluate(() => navigator.clipboard.readText()))
      .toContain("root@localhost");
    const [download] = await Promise.all([
      page.waitForEvent("download"),
      page.click("#download-log"),
    ]);
    const stream = await download.createReadStream();
    const chunks = [];
    for await (const chunk of stream) chunks.push(chunk);
    expect(Buffer.concat(chunks).toString()).toContain("root@localhost");
  });

  test("a quota death on the first request never claims an empty history", async ({ page }) => {
    await page.goto(`${BASE}/`);
    await scan(page, "https://github.com/demo/p1dead");
    await expect(page.locator("#summary")).toContainText("PARTIAL:");
    // the quota died on request 1: "exposed no commits" would be the one
    // false sentence on the page - the PARTIAL warning owns the story
    await expect(page.locator("#summary")).not.toContainText(
      "exposed no commits",
    );
  });

  test("a zero-result state explains itself according to what was read", async ({ page }) => {
    await page.goto(`${BASE}/`);
    // a repository whose default branch answers an empty listing: the
    // note must say nothing was read (the hidden-address explanation
    // would be a non-sequitur)
    await scan(page, "https://github.com/demo/quiet");
    await expect(page.locator("#summary")).toContainText("No commit seen");
    await expect(page.locator("#summary")).toContainText(
      "The default branch exposed no commits",
    );
    // a profile with no public push events: the timeline's recency is
    // the honest why, not the address filters
    await scan(page, "https://github.com/quiet");
    await expect(page.locator("#summary")).toContainText("No commit seen");
    await expect(page.locator("#summary")).toContainText(
      "only keeps recent activity",
    );
    // and when commits WERE read, the filters get their explanation
    await scan(page, "https://github.com/demo/noreply");
    await expect(page.locator("#summary")).toContainText(
      "The scan read the commits, but no email address appeared in them",
    );
    // the zero story is told once: the status does not recount it
    await expect(page.locator("#status")).toHaveText("Done.");
  });

  test("a profile walk attributes commits per event repository", async ({ page }) => {
    await page.goto(`${BASE}/`);
    await scan(page, "https://github.com/demo");
    await expect(page.locator("#authors")).toContainText("Jane Doe");
    const card = await page.locator(".author-card").first().textContent();
    // two repositories in the fixtures: the chip must say 2, not name one
    expect(card).toContain("2 repositories");
  });

  test("the capped profile walk announces the 300-event ceiling", async ({ page }) => {
    await page.goto(`${BASE}/`);
    await scan(page, "https://github.com/capped");
    await expect(page.locator("#summary")).toContainText("300 most recent public events");
  });

  test("the download carries the CLI-sanitized .log name and the provenance header", async ({ page }) => {
    await page.goto(`${BASE}/`);
    await scan(page, "https://github.com/demo/normal");
    // demo_normal is byte-unchanged by the sanitizer, so the E2E pins the
    // glue (base + ".log", the exact clean-name passthrough); the
    // sanitizer's TRANSFORMS are pinned by the wasm replay of the shared
    // names.json vectors, at both sides of the binding
    const [download] = await Promise.all([
      page.waitForEvent("download"),
      page.click("#download-log"),
    ]);
    expect(download.suggestedFilename()).toBe("demo_normal.log");
    const stream = await download.createReadStream();
    const chunks = [];
    for await (const chunk of stream) chunks.push(chunk);
    const content = Buffer.concat(chunks).toString();
    expect(content).toContain("# generated_at:");
    expect(content).toContain("# tool_version: web 0.8.0");
    expect(content).toContain("# target: https://github.com/demo/normal");
    // the file must self-describe its format and its completeness (the
    // provenance header carries the run's completeness, not quota trivia)
    expect(content).toContain(
      "# git2mail web scan - one email per line; a snapshot of one run, not a live file");
    expect(content).toContain("# status: complete");
    // the documented API delta travels with the file: repo walks cover
    // the default branch only
    expect(content).toContain("# scope: default branch history only");
    expect(content).not.toContain("# mode:");
    expect(content).toContain("jane@example.com");
  });

  test("the two copy actions emit the format their label names", async ({ page }) => {
    await page.goto(`${BASE}/`);
    await scan(page, "https://github.com/demo/normal");
    await expect(page.locator("#status")).toContainText("Done:");
    // every action button carries its hover tooltip: the destinations
    // are the interface, no button may be the unexplained one
    await expect(page.locator("#copy-emails")).toHaveAttribute("title", /Paste into the To:/);
    await expect(page.locator("#copy-list")).toHaveAttribute("title", /one row per address/);
    await expect(page.locator("#download-log")).toHaveAttribute("title", /one email per line/);
    await page.context().grantPermissions(["clipboard-read", "clipboard-write"]);
    // mail destination: comma-separated
    await page.click("#copy-emails");
    const mail = await page.evaluate(() => navigator.clipboard.readText());
    expect(mail.split(", ").sort().join("|"))
      .toBe("jane.quoted@example.com|jane@example.com");
    // spreadsheet destination: a TSV mapping (name, email, last seen) -
    // the paste into a sheet keeps the who behind each address
    await page.click("#copy-list");
    expect(await page.evaluate(() => navigator.clipboard.readText()))
      .toBe("Jane Doe\tjane@example.com\t2024-06-01\n" +
            "Jane Doe\tjane.quoted@example.com\t2024-05-01");

  });

  test("the page ships its own defenses: CSP meta present, no storage API reachable", async ({ page }) => {
    await page.goto(`${BASE}/`);
    const csp = await page.locator('meta[http-equiv="Content-Security-Policy"]').getAttribute("content");
    expect(csp).toContain("connect-src 'self' https://api.github.com");
    expect(csp).toContain("script-src 'self' 'wasm-unsafe-eval'");
    const scanSource = await page.evaluate(async () => {
      const response = await fetch("js/scan.js");
      return response.text();
    });
    expect(scanSource).not.toMatch(/localStorage|sessionStorage|indexedDB|document\.cookie/);
    // the mock's same-origin patch must be IN the served source: if the
    // source line drifted, the patch would silently no-op and the tests
    // would start hitting the real api.github.com (the CSP allows it) -
    // this fails fast instead, keeping the suite 100% offline
    expect(scanSource).toContain('GIT2MAIL_API_BASE ?? ""');
  });
});
