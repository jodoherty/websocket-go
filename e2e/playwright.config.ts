import { defineConfig, devices } from "@playwright/test";

// Every test project talks to the Go demo server over TLS. The server uses
// self-signed certificates, so all contexts ignore certificate errors;
// client certificates (for the mTLS endpoint) are configured per-context
// in the tests.
export default defineConfig({
  testDir: "./tests",
  timeout: 30_000,
  reporter: "list",
  use: {
    baseURL: "https://127.0.0.1:8443",
    ignoreHTTPSErrors: true,
  },
  projects: [
    { name: "chromium", use: { ...devices["Desktop Chrome"] } },
    { name: "firefox", use: { ...devices["Desktop Firefox"] } },
  ],
  webServer: {
    command: "./.bin/demo -addr 127.0.0.1:8443 -certs ./certs",
    url: "http://127.0.0.1:8444/health",
    timeout: 30_000,
    reuseExistingServer: true,
  },
});
