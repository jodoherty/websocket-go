import { defineConfig, devices } from "@playwright/test";

// The demo server (and its throwaway certs + binary) is started in
// global-setup.ts, which binds the demo on ephemeral ports and records the
// actual base URL in process.env.WS_BASE_URL. Playwright re-evaluates this
// config in every worker, so any port allocated here would differ per worker
// — that is why the ports live in globalSetup (which runs once, before
// workers fork, and is inherited by them) rather than here.
export default defineConfig({
  testDir: "./tests",
  timeout: 30_000,
  reporter: "list",
  globalSetup: "./global-setup.ts",
  use: {
    // The demo uses a self-signed certificate; all contexts ignore cert
    // errors. Tests build absolute URLs from WS_BASE_URL, so no baseURL is
    // needed here.
    ignoreHTTPSErrors: true,
  },
  projects: [
    { name: "chromium", use: { ...devices["Desktop Chrome"] } },
    { name: "firefox", use: { ...devices["Desktop Firefox"] } },
  ],
});
