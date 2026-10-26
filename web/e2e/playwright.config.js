// @ts-check
const { defineConfig } = require("@playwright/test");

const PORT = process.env.PORT || 8931;

module.exports = defineConfig({
  testDir: __dirname,
  timeout: 30_000,
  use: {
    baseURL: `http://127.0.0.1:${PORT}`,
    headless: true,
  },
  webServer: {
    // Rebuilds the site against the loopback origin (the production
    // `base_url` is baked into the pages as an absolute URL: served
    // anywhere else, the scan module would be cross-origin and dead),
    // then serves the throwaway build with the mock GitHub API.
    command: `sh -c '"\${ZOLA:-$HOME/.local/bin/zola}" build -u "http://127.0.0.1:${PORT}/" -o public-e2e --force && SITE_DIR="$PWD/public-e2e" exec node ../e2e/server.js'`,
    port: Number(PORT),
    // never reuse, in every environment: a lingering server from a prior
    // session would serve a stale public-e2e build with no signal -
    // concurrency on the same port is refused instead of silently shared
    reuseExistingServer: false,
    cwd: `${__dirname}/../site`,
  },
});
