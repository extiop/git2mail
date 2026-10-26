// git2mail anonymous scan - the browser glue.
//
// Division of labor (the wasm carries the RULES, this file carries the I/O):
// - every rule (URL validation, the email/noreply discipline, payload
//   parsing, file-name sanitization) lives in the wasm module, compiled
//   from the same pure core the CLI uses - shared test vectors pin the
//   parity;
// - this file does what the browser is for: fetch, pagination, the DOM,
//   and nothing else. No storage of any kind, no third-party origin:
//   the only network destination is api.github.com.

import init, {
  extract_emails_from_commits,
  normalize_url,
  sanitize_file_name,
} from "../wasm/git2mail_wasm.js";

// The web release that stamped the downloadable results (the CLI reports
// its own version; the site stamps this one).
const SITE_VERSION = "0.8.0";

const API = window.GIT2MAIL_API_BASE ?? "https://api.github.com";
const PER_PAGE = 100;
// GitHub caps the profile events timeline at 300 events (its documented
// ceiling): three full pages, no more.
const EVENTS_MAX_PAGES = 3;
// The results page renders at most this many author cards (the email list
// and the copy/download actions always carry every address).
const MAX_CARDS = 100;
// The funnel renders at most this many per-email evidence commands, with
// the cut announced (the caps-say-so convention).
const MAX_FUNNEL_EMAILS = 10;
const MAX_SUMMARY_EMAILS = 6;
// the last completed run's deliverable (the list, its provenance, its
// completeness), captured at render time and read by the actions
let lastResult = null;

let wasmReady = null;
function wasm() {
  if (!wasmReady) {
    wasmReady = init().catch((error) => {
      // a failed warm-up (offline, blocked fetch) must not poison the
      // cache: the next Scan retries instead of replaying the rejection
      wasmReady = null;
      throw error;
    });
  }
  return wasmReady;
}

// ---------- DOM helpers ----------

const $ = (id) => document.getElementById(id);

function setStatus(text, kind) {
  const status = $("status");
  status.textContent = text;
  status.className = kind === "error" || kind === "partial" ? "warning" : "status-line";
}

// The quota line is glanceable and refreshed on every response: it is
// deliberately NOT a live region (a long walk would spam the screen
// reader); the status line above carries the narration.
function setQuota(remaining, resetAt) {
  const line = $("quota");
  if (remaining === null) {
    line.textContent = "";
    return;
  }
  // relative time, never a clock time: "resets at 18:21" while the
  // visitor's watch says 18:21 makes the page look broken (whose time
  // zone is that clock?) - "resets in N min" cannot lie
  let when = "";
  if (resetAt) {
    const minutes = Math.round((resetAt * 1000 - Date.now()) / 60000);
    when = minutes <= 0
      ? " - resets in less than a minute"
      : " - resets in " + minutes + " min";
  }
  line.textContent = "GitHub requests left this hour: " + remaining + when;
}

// ---------- request plumbing ----------

class QuotaExhausted extends Error {
  constructor(resetAt) {
    super("quota exhausted");
    this.resetAt = resetAt;
  }
}

async function githubFetch(url) {
  const response = await fetch(url, {
    headers: { Accept: "application/vnd.github+json" },
  });
  const remaining = response.headers.get("X-RateLimit-Remaining");
  const reset = response.headers.get("X-RateLimit-Reset");
  setQuota(remaining, reset ? Number(reset) : null);
  if (response.status === 403 || response.status === 429) {
    // two different refusals wear this status: the spent anonymous
    // hourly quota (remaining 0 - the CLI's token lifts it), and a
    // secondary rate or abuse limit (remaining > 0 - a token would not
    // lift it either); claiming the wrong cause would be a lie the
    // visitor can act on wrongly
    if (remaining === "0") {
      throw new QuotaExhausted(reset ? Number(reset) : null);
    }
    throw new Error(
      "GitHub slowed this scan: it hit a temporary rate limit, not the " +
        "hourly quota. Wait a little, then try again. A browser cannot " +
        "do more.",
    );
  }
  if (response.status === 404) {
    throw new Error(
      "GitHub resource not found: check the URL (a repository URL must " +
        "point at the repository root, not a subfolder path).",
    );
  }
  if (response.status === 409) {
    // the CLI contract: an empty repository answers 409 on /commits -
    // a resource-scoped condition, named as such
    throw new Error(
      "GitHub repository is empty - nothing to scan. Double-check the " +
        "URL: an empty repository has no commits on any branch.",
    );
  }
  if (!response.ok) {
    throw new Error(
      "GitHub answered " +
        response.status +
        " - try again (on a corporate network, a proxy or firewall may have refused the request).",
    );
  }
  const link = response.headers.get("Link");
  const body = await response.json();
  return { body, lastPage: parseLastPage(link) };
}

// The estimate only: the walk itself ends on a short page, exactly like
// the CLI. A GitHub Link header looks like
// <...?per_page=100&page=2>; rel="next", <...&page=42>; rel="last".
function parseLastPage(link) {
  if (!link) return null;
  const match = /[?&]page=(\d+)>;\s*rel="last"/.exec(link);
  return match ? Number(match[1]) : null;
}

// Git author dates keep their original UTC offset ("…T10:00:00+09:00"),
// so raw string comparison orders across offsets wrongly: compare the
// parsed instants, display the raw string.
function dateValue(date) {
  return date ? Date.parse(date) || 0 : 0;
}

// the two orderings the page renders by, named once: authors by commit
// count, entries by observation freshness (both descending)
const byCommitsDesc = (a, b) => b.count - a.count;
const byFreshestDesc = (a, b) => dateValue(b.date) - dateValue(a.date);

// the plural endings the copy builds by hand, in one place: singular
// stays bare, the suffix defaults to "s" ("addresses" passes "es")
function plural(count, word, suffix = "s") {
  return word + (count === 1 ? "" : suffix);
}

// ---------- the scan ----------

function emptyState() {
  return {
    emails: new Map(), // lowercased -> first-seen casing
    authors: new Map(), // key -> { label, count, lastDate, repos: Set, emails: Map(lower -> {email, date}) }
    rawCount: 0,
    partial: false,
    partialReason: "",
    capped: false,
  };
}

function absorb(state, pageJson, repositoryFullName) {
  const identities = JSON.parse(extract_emails_from_commits(JSON.stringify(pageJson)));
  state.rawCount += pageJson.length;
  for (const identity of identities) {
    const emailKey = identity.email.toLowerCase();
    if (!state.emails.has(emailKey)) state.emails.set(emailKey, identity.email);
    const label = identity.name && identity.name.trim() !== "" ? identity.name : identity.email;
    const authorKey = label.toLowerCase();
    const author =
      state.authors.get(authorKey) ||
      { label, count: 0, lastDate: null, repos: new Set(), emails: new Map() };
    author.count += 1;
    // per-email recency: the freshest observation leads the card, and the
    // display dedups case-insensitively while keeping the first casing
    const known = author.emails.get(emailKey);
    if (!known) {
      author.emails.set(emailKey, { email: identity.email, date: identity.date });
    } else if (identity.date && dateValue(identity.date) > dateValue(known.date)) {
      known.date = identity.date;
    }
    if (identity.date && dateValue(identity.date) > dateValue(author.lastDate)) {
      author.lastDate = identity.date;
    }
    if (repositoryFullName) author.repos.add(repositoryFullName);
    state.authors.set(authorKey, author);
  }
}

async function walkRepository(owner, repository, state) {
  const fullName = owner + "/" + repository;
  for (let page = 1; ; page++) {
    const { body, lastPage } = await githubFetch(
      `${API}/repos/${owner}/${repository}/commits?per_page=${PER_PAGE}&page=${page}`,
    );
    if (page === 1 && lastPage) {
      setStatus(
        "Scanning: this scan needs about " + lastPage + " requests" +
          (lastPage > 60 ? " - more than the anonymous hourly quota (60)" : "") +
          ".",
      );
    }
    // a 200 body that is not a listing is a shape change (a proxy, an
    // interception): it must fail loudly, never end the walk as a
    // complete-looking empty result - the same rule the core pins
    if (!Array.isArray(body)) {
      throw new Error("GitHub's response is not a commits listing - the shape changed or the connection was intercepted.");
    }
    if (body.length === 0) break;
    absorb(state, body, fullName);
    // a long walk must never look hung: page N of the estimate, live
    if (page > 1) {
      setStatus("Scanning: page " + page +
        (lastPage ? " of about " + lastPage : "") + "\u2026");
    }
    if (body.length < PER_PAGE) break; // the listing's end, exactly like the CLI
  }
}

async function walkProfile(owner, state) {
  for (let page = 1; page <= EVENTS_MAX_PAGES; page++) {
    const { body } = await githubFetch(
      `${API}/users/${owner}/events/public?per_page=${PER_PAGE}&page=${page}`,
    );
    if (!Array.isArray(body)) {
      throw new Error("GitHub's response is not an events listing - the shape changed or the connection was intercepted.");
    }
    if (body.length === 0) break;
    if (page > 1) setStatus("Scanning: page " + page + " of " + EVENTS_MAX_PAGES + "\u2026");
    // flatten each push event into a pseudo commit page, so the same wasm
    // extraction applies - absorbed PER EVENT with that event's own
    // repository name (a page mixes events from several repositories, and
    // attributing commits to the wrong repo would forge the cards' chips)
    for (const event of body) {
      if (event.type !== "PushEvent") continue;
      const commits = [];
      for (const commit of event.payload && event.payload.commits
        ? event.payload.commits
        : []) {
        commits.push({
          commit: {
            author: {
              name: commit.author ? commit.author.name : null,
              email: commit.author ? commit.author.email : null,
              date: event.created_at,
            },
          },
        });
      }
      if (commits.length > 0) {
        absorb(state, commits, event.repo && event.repo.name);
      }
    }
    if (body.length < PER_PAGE) break;
    if (page === EVENTS_MAX_PAGES) {
      state.capped = true;
    }
  }
}


// ---------- rendering ----------

function authorCards(state) {
  const authors = [...state.authors.values()].sort(byCommitsDesc);
  const container = $("authors");
  container.textContent = "";
  const shown = authors.slice(0, MAX_CARDS);
  for (const author of shown) {
    const card = document.createElement("div");
    card.className = "author-card";

    const head = document.createElement("div");
    head.className = "author-head";
    const monogram = document.createElement("span");
    monogram.className = "monogram";
    // decorative initial: a screen reader must hear the name, not the
    // letter twice
    monogram.setAttribute("aria-hidden", "true");
    monogram.textContent = author.label.slice(0, 1).toUpperCase();
    const name = document.createElement("strong");
    name.textContent = author.label;
    head.append(monogram, name);

    const chips = document.createElement("div");
    chips.className = "chips";
    const commits = document.createElement("span");
    commits.className = "chip";
    commits.textContent = author.count + " commit" + plural(author.count, "");
    chips.append(commits);
    if (author.repos.size > 0) {
      const repos = document.createElement("span");
      repos.className = "chip";
      const names = [...author.repos];
      repos.textContent =
        names.length === 1 ? names[0] : names.length + " repositories";
      repos.title = names.join(", ");
      // the tooltip never reaches keyboard or screen-reader users, and
      // aria-label on a span (role generic) is routinely ignored: the
      // repository names ride along as visually-hidden text instead
      const hidden = document.createElement("span");
      hidden.className = "visually-hidden";
      hidden.textContent = ": " + names.join(", ");
      repos.append(hidden);
      chips.append(repos);
    }
    if (author.lastDate) {
      const activity = document.createElement("span");
      activity.className = "chip";
      activity.textContent = "last activity " + author.lastDate.slice(0, 10);
      chips.append(activity);
    }
    head.append(chips);

    // the freshest email leads the card (a recruiter contacts the current
    // address, not a 2016 one)
    const emailEntries = [...author.emails.values()].sort(byFreshestDesc);
    const emails = document.createElement("div");
    for (const entry of emailEntries) {
      const line = document.createElement("div");
      line.textContent = entry.email;
      if (entry === emailEntries[0] && entry.date) {
        const marker = document.createElement("span");
        marker.className = "chip";
        marker.textContent = "last seen " + entry.date.slice(0, 10);
        line.append(" ", marker);
      }
      emails.append(line);
    }

    card.append(head, emails);
    container.append(card);
  }
  if (authors.length > MAX_CARDS) {
    const note = document.createElement("p");
    note.className = "warning";
    note.textContent =
      "The page stops at " + MAX_CARDS + " author cards (" + authors.length +
      " authors found); the copy and download actions below carry every address.";
    container.prepend(note);
  }
}

// A commit-email domain that cannot receive mail today (localhost,
// reserved TLDs such as .local/.invalid/.test/.example, a dot-less
// hostname like a container id): the address keeps its place in the
// cards, the list, the copy and the download - only the funnel's
// suggested commands lead with addresses a person could answer. A
// presentation heuristic, never a filter: core/src/rules.rs stays the
// only authority on which addresses are usable.
function plausiblyMailable(email) {
  const at = String(email).lastIndexOf("@");
  const domain = String(email).slice(at + 1).toLowerCase();
  return domain.includes(".") && !/(^|\.)localhost$/.test(domain) &&
    !/\.(local|invalid|test|example)$/.test(domain);
}

function renderFunnel(state, target, parsed) {
  const funnel = $("funnel");
  funnel.textContent = "";
  const title = document.createElement("h3");
  title.textContent = "Go further with the command-line tool";
  funnel.append(title);

  // before the commands: what the tool is and the one prerequisite -
  // nothing below runs without the binary
  const intro = document.createElement("p");
  intro.textContent =
    "This page is limited by GitHub's anonymous allowance. The " +
    "command-line tool can use a personal access token, which raises " +
    "the limit to 5,000 requests per hour. The commands below include " +
    "data taken from public commits. Read a command before you run " +
    "it. ";
  const getProgram = document.createElement("a");
  getProgram.href = "https://github.com/extiop/git2mail/releases";
  getProgram.textContent = "Get the program";
  intro.append(getProgram, document.createTextNode(", then:"));
  funnel.append(intro);

  // the commands, each announced by its one-line role: the reader needs
  // to know what a command does before pasting it. Two defenses stack:
  // every interpolated value is shell-quoted (a hostile commit email
  // must never reach a POSIX terminal as live syntax), and only values
  // built from a safe charset render at all. The second defense is the
  // load-bearing one on Windows: cmd.exe has no single quote, so no
  // quoting can protect a value that carries & | < > ^ % $ ( ) - such a
  // value is left out of the commands and the reader copies it from the
  // cards above instead
  const shellSafe = (text) => /^[A-Za-z0-9._+:@/-]+$/.test(String(text));
  const shellQuote = (text) => "'" + String(text).replace(/'/g, "'\\''") + "'";
  let withheld = 0;
  const commands = [];
  if (shellSafe(target)) {
    commands.push([
      "git2mail scan --url " + shellQuote(target),
      "The same scan, from your terminal.",
    ]);
  } else {
    withheld += 1;
  }
  const all = [...state.emails.values()];
  // mailable addresses lead the suggested commands: an inert domain is
  // honest data but poor advice, so the stable partition only reorders
  // (the cards, the list, the copy and the download keep every address)
  const emails = [
    ...all.filter(plausiblyMailable),
    ...all.filter((email) => !plausiblyMailable(email)),
  ];
  for (const email of emails.slice(0, MAX_FUNNEL_EMAILS)) {
    // the reverse lookup is the command that carries the confidence grades
    if (!shellSafe(email)) {
      withheld += 1;
      continue;
    }
    commands.push([
      "git2mail email " + shellQuote(email),
      // what the reverse lookup actually returns: the account behind the
      // address, with the matching commit as proof WHEN the search
      // finds one - it only sees candidate repositories whose name,
      // description or topics mention the address, so it can miss
      "Which GitHub account uses this address (an automated search: it " +
        "can miss. Finding nothing does not prove the address is unused).",
    ]);
  }
  if (shellSafe(parsed.owner)) {
    commands.push([
      "git2mail user " + shellQuote(parsed.owner),
      "A closer look at one account: the owner of the target - on a " +
        "profile URL, that account itself. The command does not look at " +
        "the other authors found in the commits.",
    ]);
  } else {
    withheld += 1;
  }
  for (const [command, role] of commands) {
    const line = document.createElement("div");
    const code = document.createElement("code");
    code.className = "funnel-command";
    code.textContent = command;
    const note = document.createElement("span");
    note.className = "funnel-role";
    note.textContent = role;
    // the role leads: the reader knows what a command does before the
    // boxed command invites the copy (oracle verdict 3-0, ROLE ABOVE)
    line.append(note, code);
    funnel.append(line);
  }
  if (withheld > 0) {
    const skipped = document.createElement("p");
    skipped.className = "scan-note";
    skipped.textContent =
      "The commands above do not include " +
      (withheld > 1 ? "them" : "it") + ": " +
      withheld + plural(withheld, " value") + " in this scan contain" +
      (withheld > 1 ? "" : "s") + " characters a terminal would misread. " +
      (emails.length > 0
        ? "Download the results and run git2mail emails <file> on that " +
          "file instead."
        : "Type one only into a bash or zsh window, in your own single " +
          "quotes.");
    funnel.append(skipped);
  }
  if (emails.length > MAX_FUNNEL_EMAILS) {
    const cut = document.createElement("p");
    cut.className = "warning";
    cut.textContent =
      "The list stops at " + MAX_FUNNEL_EMAILS + " address-lookup commands (" +
      emails.length + " addresses found): run git2mail email <address> for " +
      "any of the others - the copy and download actions carry every address.";
    funnel.append(cut);
  }
  if (all.some((email) => !plausiblyMailable(email))) {
    const inert = document.createElement("p");
    inert.className = "scan-note";
    inert.textContent =
      "Some addresses cannot receive mail (root@localhost, reserved " +
      "test domains and similar). The commits really contain them, but " +
      "mail to them rarely reaches a person.";
    funnel.append(inert);
  }

  // below the commands: the follow-ups. The token note first: the two
  // walks usually need more requests than the anonymous hour allows
  // (the file format stays in the guide this link lands on - the guide
  // is the single home for the deep topics)
  const token = document.createElement("p");
  token.className = "scan-note";
  token.textContent =
    "Without a token, GitHub allows about 60 requests per hour. The " +
    "email and user walks usually need more, so they stop part way. " +
    "Add --token-file tokens.json to any command to use a token instead - ";
  const getToken = document.createElement("a");
  getToken.href = "https://extiop.github.io/git2mail/guide/#tokens";
  getToken.textContent = "Get a token";
  token.append(getToken, document.createTextNode("."));
  funnel.append(token);

  // the bulk tip only when a .log exists: on a zero-result scan the
  // download action is hidden, so the tip would reference a file the
  // visitor cannot produce
  if (emails.length > 0) {
    const bulk = document.createElement("p");
    bulk.className = "scan-note";
    bulk.textContent =
      "The downloaded .log file is ready to use in the bulk command: ";
    const bulkDoc = document.createElement("a");
    bulkDoc.href = "https://extiop.github.io/git2mail/guide/EMAIL.html";
    bulkDoc.textContent = "git2mail emails <file>";
    bulk.append(bulkDoc, document.createTextNode(
      " - the command-line tool's documentation explains it.",
    ));
    funnel.append(bulk);
  }
}

function renderResults(state, target, parsed) {
  $("results").hidden = false;
  const emails = [...state.emails.values()].sort((a, b) =>
    a.toLowerCase().localeCompare(b.toLowerCase()),
  );

  const summary = $("summary");
  summary.textContent =
    (state.rawCount === 0
      ? "No commit seen"
      : state.rawCount + " commit" + plural(state.rawCount, "") + " read") +
    " - " +
    (emails.length === 0
      ? "no usable email found"
      : emails.length + " unique email address" + plural(emails.length, "", "es"));
  // the honesty warnings lead the deliverable: a visitor must read
  // "this list may be incomplete" before the address pills invite a copy
  if (state.capped) {
    const cap = document.createElement("p");
    cap.className = "warning";
    cap.textContent =
      "GitHub keeps only the 300 most recent public events for a " +
      "profile, so the scan stopped there.";
    summary.append(cap);
  }
  if (state.partial) {
    const partial = document.createElement("p");
    partial.className = "warning";
    partial.textContent =
      "PARTIAL: " + state.partialReason + " The scan stopped early, so " +
      "this list may be incomplete: some commits were never read.";
    summary.append(partial);
  }
  // the deliverable, visible immediately: a few freshest addresses as
  // pills; every address stays in the cards, the copy and the download
  if (emails.length > 0) {
    const freshest = [];
    for (const author of state.authors.values()) {
      for (const entry of author.emails.values()) {
        freshest.push(entry);
      }
    }
    freshest.sort(byFreshestDesc);
    const seen = new Set();
    const preview = document.createElement("div");
    preview.className = "chips email-preview";
    for (const entry of freshest) {
      const key = entry.email.toLowerCase();
      if (seen.has(key) || seen.size >= MAX_SUMMARY_EMAILS) continue;
      seen.add(key);
      const pill = document.createElement("span");
      pill.className = "chip email-pill";
      pill.textContent = entry.email;
      preview.append(pill);
    }
    if (emails.length > seen.size) {
      const more = document.createElement("span");
      more.className = "chip";
      more.textContent = "+ " + (emails.length - seen.size) + " more in the list below";
      preview.append(more);
    }
    summary.append(preview);
  } else if (state.rawCount === 0 && !state.partial) {
    // nothing was read at all: the hidden-address explanations would be
    // a non-sequitur here, the truth is that there was nothing to read.
    // A partial run keeps quiet instead: the quota may have died on the
    // very first request, and "exposed no commits" would then be the
    // one false sentence on an otherwise truthful page - the PARTIAL
    // warning below already owns that story
    const why = document.createElement("p");
    why.className = "scan-note";
    why.textContent = parsed.repository
      ? "The default branch exposed no commits through the anonymous API."
      : "No recent activity showed up in GitHub's public events feed " +
        "(it only keeps recent activity), so there was nothing to read.";
    summary.append(why);
  } else if (state.rawCount > 0) {
    // only a run that actually read commits may tell the filtered story:
    // a quota death on request 1 lands here too, and "commits were read"
    // would contradict the summary's own "No commit seen"
    const why = document.createElement("p");
    why.className = "scan-note";
    why.textContent =
      "The scan read the commits, but no email address appeared in them. " +
      "Many people hide their personal address on GitHub, which replaces " +
      "it with a private alias. Projects that combine several changes " +
      "into one merge also hide some names. All of this is deliberate. " +
      "The command-line tool's user command can often still find both " +
      "the addresses and the names.";
    summary.append(why);
  }

  // the render-time snapshot the actions read from: captured HERE, never
  // from the live input (a forwarded .log outlives the page's on-screen
  // warnings and must never describe a target the visitor edited into
  // the box after the scan, or pass a partial run off as complete)
  // the spreadsheet paste carries the mapping the cards show: one row
  // per address (name, email, last seen), authors by commit count,
  // emails freshest first - a bare email list would drop the who
  // spreadsheet-cell encoding: a hostile author name must not evaluate
  // as a formula when pasted (=, +, -, @) nor split the row (tabs and
  // newlines are the cell's own structure)
  const cell = (text) => {
    // flatten every C0 control (not just the tab that would tear the
    // row) into a space, then neutralize the formula/interpretation
    // triggers Excel, Calc and Sheets act on when a cell starts with
    // one of them
    const flat = String(text).replace(/[\x00-\x1f]+/g, " ");
    return /^[=+\-@]/.test(flat) ? "'" + flat : flat;
  };
  const rows = [];
  const sheetAuthors = [...state.authors.values()].sort(byCommitsDesc);
  for (const author of sheetAuthors) {
    const entries = [...author.emails.values()].sort(byFreshestDesc);
    for (const entry of entries) {
      rows.push(cell(author.label) + "\t" + cell(entry.email) + "\t" +
        cell(entry.date ? entry.date.slice(0, 10) : ""));
    }
  }
  lastResult = {
    list: emails.join("\n"),
    sheet: rows.join("\n"),
    target: "https://github.com/" + parsed.owner +
      (parsed.repository ? "/" + parsed.repository : ""),
    base: parsed.repository ? parsed.owner + "_" + parsed.repository : parsed.owner,
    status: state.partial ? "partial - " + state.partialReason : "complete",
    scope: parsed.repository
      ? "default branch history only"
      : "public events timeline" +
        (state.capped ? ", capped at 300 events" : ""),
  };
  // nothing to copy or download when the walk found no usable email:
  // a success toast on an empty clipboard would be a lie
  $("actions").hidden = emails.length === 0;
  authorCards(state);
  renderFunnel(state, target, parsed);

  // the walk ended: the aria-live status must say so, not keep "Scanning…" -
  // but a partial run's warning narration must survive (renderResults is
  // also called from the catch paths)
  if (!state.partial) {
    // on zero results the summary and the note below own the story -
    // counting zero twice in two different words is noise
    setStatus(
      emails.length === 0
        ? "Done."
        : "Done: " + emails.length + " unique email address" +
          plural(emails.length, "", "es") + " found.",
    );
  }
}

// ---------- actions ----------

function wireActions() {
  // two copy actions, named by destination: a mail composer's To:/Bcc:
  // field wants commas, a spreadsheet wants one email per row - one
  // format always fails one of the two, and a non-technical visitor
  // should never parse the word "separator"
  $("copy-emails").onclick = async () => {
    // a mail field is a comma-separated list of addr-specs: a comma tears
    // the list, a bare quote or angle bracket derails the composer's
    // tokenizer, and specials like parentheses can be swallowed as
    // comments (a silently wrong recipient). RFC 5322 quoting saves any
    // LOCAL part (a quoted string may carry anything, with " and \
    // escaped as quoted pairs) - but a domain has no quoting, so an
    // address whose domain is not a plain dot-atom cannot form a
    // recipient: it is left out of the copy (the download and the
    // spreadsheet keep it) and the status line says so. Only a plain
    // dot-atom local part ships raw - atext plus interior dots
    const ATEXT = /^[A-Za-z0-9!#$%&'*+\/=?^_`{|}~.-]+$/; // RFC 5322 atext + interior dots
    const mailSafe = (email) => {
      const at = email.lastIndexOf("@");
      const domain = email.slice(at + 1);
      // a plain dot-atom has no empty labels: leading/trailing dots and
      // double dots ("dev@..") are refused, not shipped raw
      if (!/^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*$/.test(domain)) return null;
      const local = email.slice(0, at);
      if (ATEXT.test(local) && !/^[.-]|[.-]$|\.\./.test(local)) return email;
      return '"' + local.replace(/(["\\])/g, "\\$1") + '"@' + domain;
    };
    const recipients = [];
    let malformed = 0;
    if (lastResult) {
      for (const email of lastResult.list.split("\n")) {
        const safe = mailSafe(email);
        if (safe === null) malformed += 1;
        else recipients.push(safe);
      }
    }
    if (recipients.length === 0) {
      // an empty paste would be a success claim about nothing
      setStatus(
        "No address in this scan can be pasted into an email field - " +
          "use Download results.",
        "error",
      );
      return;
    }
    try {
      await navigator.clipboard.writeText(recipients.join(", "));
      setStatus(
        "Email list copied for pasting into an email field." +
          (malformed > 0
            ? " " + malformed + plural(malformed, " address", "es") +
              " in this scan cannot be used in an email field" +
              " - the download and the spreadsheet copy keep them."
            : ""),
      );
    } catch {
      setStatus("The clipboard refused the copy - use the download button.", "error");
    }
  };
  $("copy-list").onclick = async () => {
    const emails = lastResult ? lastResult.sheet : "";
    try {
      await navigator.clipboard.writeText(emails);
      setStatus("Copied for a spreadsheet: one row per address (name, email, last seen).");
    } catch {
      // truthful fallback: the download keeps the addresses, but the
      // name-email-date mapping lives only in this copy
      setStatus(
        "The clipboard refused the copy - the download keeps the " +
          "addresses but not the name mapping.",
        "error",
      );
    }
  };
  $("download-log").onclick = () => {
    // a complete snapshot of the run (never an append-only log), with the
    // provenance block that makes a preserved file defensible. The
    // provenance comes from the render-time dataset, never from the live
    // input: the visitor may have started typing another target while
    // reading the results, and a header naming a target that was never
    // scanned would be forged evidence
    const header =
      "# git2mail web scan - one email per line; a snapshot of one run, " +
        "not a live file\n" +
      "# generated_at: " + new Date().toISOString() + " (UTC)\n" +
      "# tool_version: web " + SITE_VERSION + "\n" +
      "# target: " + (lastResult ? lastResult.target : "") + "\n" +
      "# status: " + (lastResult ? lastResult.status : "unknown") + "\n" +
      (lastResult && lastResult.scope
        ? "# scope: " + lastResult.scope + "\n"
        : "");
    const emails = lastResult ? lastResult.list : "";
    const base = lastResult ? lastResult.base : "results";
    const blob = new Blob([header + (emails ? emails + "\n" : "")], {
      type: "text/plain",
    });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = sanitize_file_name(base) + ".log";
    link.click();
    URL.revokeObjectURL(url);
    setStatus(
      "Downloaded. The file you saved contains personal data that only " +
        "you hold: keep it safe and delete it when you are done. The " +
        "site itself stores nothing.",
    );
  };
}

// ---------- wiring ----------

async function run(event) {
  event.preventDefault(); // no navigation, no query-string auto-run
  const target = $("target-url").value.trim();
  if (!target) return;
  // one walk at a time: a second click would spend the anonymous quota
  // on a duelling render whose result depends on finish order
  const scanButton = document.querySelector("#scan-form button");
  if (scanButton.disabled) return;
  scanButton.disabled = true;

  let parsed;
  try {
    // the prefill-click path (a ?url= visitor who never focused the
    // input) reaches the cold wasm fetch: say so instead of leaving a
    // disabled-looking-alive button and a silent wait
    if (!wasmReady) setStatus("Loading the scan engine…");
    await wasm();
    parsed = JSON.parse(normalize_url(target));
  } catch (error) {
    // a wasm-load failure (blocked resource, offline) must be VISIBLE
    // with a next step, never a silently dead button or a raw exception
    setStatus(
      "The scan engine failed to load - check your connection and try " +
        "again.",
      "error",
    );
    scanButton.disabled = false;
    return;
  }

  for (const id of ["summary", "authors", "funnel"]) {
    $(id).textContent = "";
  }
  lastResult = null;
  $("results").hidden = true;

  const state = emptyState();
  try {
    setStatus("Scanning…");
    if (parsed.repository) {
      await walkRepository(parsed.owner, parsed.repository, state);
    } else {
      await walkProfile(parsed.owner, state);
    }
  } catch (error) {
    if (error instanceof QuotaExhausted) {
      state.partial = true;
      state.partialReason = "GitHub's anonymous quota ran out" +
        (error.resetAt
          ? " (resets in " +
            Math.max(1, Math.round((error.resetAt * 1000 - Date.now()) / 60000)) +
            " min)"
          : "") +
        ".";
      setStatus(
        "Quota exhausted - wait for the hour to reset, scan a smaller " +
          "target, or use the command-line tool with a token (every " +
          "result page below names the exact command).",
        "partial",
      );
    } else {
      setStatus(error.message, "error");
      if (state.rawCount > 0) {
        state.partial = true;
        state.partialReason = "the walk stopped on an error.";
        renderResults(state, target, parsed);
      }
      scanButton.disabled = false;
      return;
    }
  }
  renderResults(state, target, parsed);
  scanButton.disabled = false;
}

document.addEventListener("DOMContentLoaded", () => {
  wireActions();
  $("scan-form").addEventListener("submit", run);
  // warm the wasm module on the first sign of intent: the fetch+compile
  // then hides behind the visitor's own typing instead of running while
  // the button looks dead
  const warm = () => wasm().catch(() => {});
  $("target-url").addEventListener("focus", warm, { once: true, passive: true });
  // a query parameter may PRE-FILL the field; nothing ever auto-runs
  const prefill = new URLSearchParams(location.search).get("url");
  if (prefill) $("target-url").value = prefill;
});
