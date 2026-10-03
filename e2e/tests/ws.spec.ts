import { test, expect, type Page } from "@playwright/test";

const BASE = "wss://127.0.0.1:8443";
const TOKEN = process.env.DEMO_TOKEN ?? "demo-secret";

/**
 * Browsers send Origin on WebSocket handshakes, and the demo server applies
 * the default same-origin policy, so every test first loads the page served
 * by the demo server itself.
 */
async function sameOriginPage(page: Page) {
  await page.goto("/");
}

/** Connect, send one text message, resolve with the echo and the negotiated subprotocol. */
async function textEcho(page: Page, path: string, message: string, protocol = "vnc1"): Promise<{ reply: string; subprotocol: string }> {
  await sameOriginPage(page);
  return page.evaluate(
    async ({ base, path, message, protocol }) =>
      await new Promise<{ reply: string; subprotocol: string }>((resolve, reject) => {
        const ws = new WebSocket(base + path, protocol);
        const timer = setTimeout(() => reject(new Error("timed out waiting for echo")), 5_000);
        ws.onopen = () => ws.send(message);
        ws.onmessage = (e) => {
          clearTimeout(timer);
          const reply = String(e.data);
          const subprotocol = ws.protocol;
          ws.close();
          resolve({ reply, subprotocol });
        };
        ws.onerror = () => {
          clearTimeout(timer);
          reject(new Error(`websocket failed to open ${path}`));
        };
      }),
    { base: BASE, path, message, protocol }
  );
}

/** Connect and resolve with the first server-initiated message. */
async function firstServerMessage(page: Page, path: string): Promise<string> {
  await sameOriginPage(page);
  return page.evaluate(
    async ({ base, path }) =>
      await new Promise<string>((resolve, reject) => {
        const ws = new WebSocket(base + path);
        const timer = setTimeout(() => {
          ws.close();
          reject(new Error("timed out waiting for server message"));
        }, 5_000);
        ws.onmessage = (e) => {
          clearTimeout(timer);
          resolve(String(e.data));
        };
        ws.onerror = () => {
          clearTimeout(timer);
          reject(new Error(`websocket failed to open ${path}`));
        };
      }),
    { base: BASE, path }
  );
}

test("echo: text round-trip with subprotocol negotiation", async ({ page }) => {
  const { reply, subprotocol } = await textEcho(page, "/ws/echo", "hello, firefox");
  expect(reply).toBe("hello, firefox");
  expect(subprotocol).toBe("vnc1");
});

test("echo: binary round-trip, including 1 MiB messages", async ({ page }) => {
  await sameOriginPage(page);
  const result = await page.evaluate(
    async ({ base, path }) =>
      await new Promise<{ len: number; first: number; last: number }>((resolve, reject) => {
        const ws = new WebSocket(base + path, "binary");
        ws.binaryType = "arraybuffer";
        const timer = setTimeout(() => reject(new Error("timed out waiting for echo")), 10_000);
        ws.onopen = () => {
          const buf = new Uint8Array(1 << 20);
          for (let i = 0; i < buf.length; i++) buf[i] = (i * 7) & 0xff;
          ws.send(buf.buffer);
        };
        ws.onmessage = (e) => {
          const d = new Uint8Array(e.data as ArrayBuffer);
          clearTimeout(timer);
          ws.close();
          resolve({ len: d.length, first: d[0], last: d[d.length - 1] });
        };
        ws.onerror = () => {
          clearTimeout(timer);
          reject(new Error("websocket error"));
        };
      }),
    { base: BASE, path: "/ws/echo" }
  );
  expect(result.len).toBe(1 << 20);
  expect(result.first).toBe(0);
  expect(result.last).toBe((((1 << 20) - 1) * 7) & 0xff);
});

test("bearer: valid token upgrades; echo works", async ({ page }) => {
  const { reply } = await textEcho(page, `/ws/bearer?token=${TOKEN}`, "authenticated");
  expect(reply).toBe("authenticated");
});

test("bearer: bad token is refused before the upgrade", async ({ page }) => {
  await sameOriginPage(page);
  const opened = await page.evaluate(
    async ({ base }) =>
      await new Promise<boolean>((resolve) => {
        const ws = new WebSocket(base + "/ws/bearer?token=wrong");
        const timer = setTimeout(() => resolve(false), 5_000);
        ws.onopen = () => {
          clearTimeout(timer);
          resolve(true);
        };
        ws.onerror = () => {
          clearTimeout(timer);
          resolve(false);
        };
      }),
    { base: BASE }
  );
  expect(opened).toBe(false);
});

test("bearer: plain HTTP without token gets 401", async ({ request }) => {
  const resp = await request.get("/ws/bearer");
  expect(resp.status()).toBe(401);
});

test("bearer: valid token over plain HTTP is refused (403, origin/upgrade required)", async ({ request }) => {
  const resp = await request.get(`/ws/bearer?token=${TOKEN}`);
  expect(resp.status()).toBe(403);
});

/**
 * mTLS positive path (client certificate presented → session opens) is
 * covered by the Go e2e test in e2e/e2e_test.go: browsers refuse to
 * present client certificates on connections whose server certificate they
 * do not trust, and this suite intentionally uses a self-signed CA. What
 * the browser *can* verify is the rejection path, below.
 */
test("mtls: plain HTTP request without client certificate gets 403", async ({ request }) => {
  const resp = await request.get("/ws/mtls");
  expect(resp.status()).toBe(403);
});

test("mtls: websocket without client certificate is refused before the upgrade", async ({ page }) => {
  await sameOriginPage(page);
  const opened = await page.evaluate(
    async ({ base }) =>
      await new Promise<boolean>((resolve) => {
        const ws = new WebSocket(base + "/ws/mtls");
        const timer = setTimeout(() => resolve(false), 5_000);
        ws.onopen = () => {
          clearTimeout(timer);
          resolve(true);
        };
        ws.onerror = () => {
          clearTimeout(timer);
          resolve(false);
        };
      }),
    { base: BASE }
  );
  expect(opened).toBe(false);
});

test("goodbye: server sends a message then closes with 1001 going away", async ({ page }) => {
  await sameOriginPage(page);
  const result = await page.evaluate(
    async ({ base }) =>
      await new Promise<{ message: string; code: number; reason: string }>((resolve, reject) => {
        const ws = new WebSocket(base + "/ws/goodbye");
        const timer = setTimeout(() => reject(new Error("timed out waiting for close")), 5_000);
        let message = "";
        ws.onmessage = (e) => {
          message = String(e.data);
        };
        ws.onclose = (e) => {
          clearTimeout(timer);
          resolve({ message, code: e.code, reason: e.reason });
        };
        ws.onerror = () => {
          clearTimeout(timer);
          reject(new Error("websocket error"));
        };
      }),
    { base: BASE }
  );
  expect(result.message).toBe("hello");
  expect(result.code).toBe(1001);
  expect(result.reason).toBe("going away");
});
