// Starts the demo server on ephemeral ports for the browser e2e suite and
// records the actual base URL in process.env.WS_BASE_URL for the tests.
//
// This runs exactly once, in the main Playwright process, before workers
// fork — so the port it allocates is stable for the whole run and is
// inherited by every worker. (Playwright re-evaluates playwright.config.ts
// in each worker, which is why the ports cannot live there.)
//
// The demo is launched with -report pointing at a callback listener we
// reserve here; the demo binds its own listeners on :0 and reports the real
// addresses back over that reserved connection — the same port-report
// handshake the Go e2e uses. No fixed ports, no fixed paths: certs, the demo
// binary, and the whole workspace live in a fresh temp dir removed at
// teardown.
import { execFileSync, spawn } from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";

function rootDir(): string {
  return path.resolve(__dirname, "..");
}

// readReport accepts one connection on the reserved callback listener and
// reads one line of space-separated "host:port" addresses from it. The
// listener is bound before the demo launches, so the demo's connect
// completes in the kernel backlog and is delivered whenever we accept.
function readReport(listener: net.Server, timeoutMs: number): Promise<string[]> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      listener.close();
      reject(new Error("timed out waiting for the demo to report its ports"));
    }, timeoutMs);
    listener.on("connection", (conn) => {
      let data = "";
      conn.on("data", (chunk) => {
        data += chunk.toString();
      });
      conn.on("end", () => {
        clearTimeout(timer);
        listener.close();
        resolve(data.trim().split(/\s+/));
      });
      conn.on("error", () => {
        /* the demo closing the report connection is the expected end */
      });
    });
    listener.on("error", (e) => {
      clearTimeout(timer);
      reject(e);
    });
  });
}

export default async function globalSetup(): Promise<() => Promise<void>> {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ws-demo-"));
  const certDir = path.join(dir, "certs");
  const demoBin = path.join(dir, "demo");
  const root = rootDir();

  execFileSync("go", ["-C", root, "run", "./cmd/certgen", "-dir", certDir], { stdio: "inherit" });
  execFileSync("go", ["-C", root, "build", "-o", demoBin, "./cmd/demo"], { stdio: "inherit" });

  // Reserve the callback listener before launching the demo so its port is
  // guaranteed free for the report handshake.
  const callback = net.createServer();
  await new Promise<void>((resolve, reject) => {
    callback.once("error", reject);
    callback.listen(0, "127.0.0.1", resolve);
  });
  const callbackAddr = callback.address() as net.AddressInfo;
  const report = readReport(callback, 30_000);

  const demo = spawn(demoBin, [
    "-addr", "127.0.0.1:0",
    "-health-addr", "127.0.0.1:0",
    "-certs", certDir,
    "-report", `${callbackAddr.address}:${callbackAddr.port}`,
  ], { stdio: ["ignore", "inherit", "inherit"] });

  const addrs = await report;
  if (addrs.length !== 2) {
    throw new Error(`demo reported ${addrs.length} addresses, want 2`);
  }
  process.env.WS_BASE_URL = `wss://${addrs[0]}`;
  // The spec's same-origin page loads must hit the same server over plain
  // https; derive it from the same address.
  process.env.WS_HTTP_BASE_URL = `https://${addrs[0]}`;

  return async () => {
    if (demo.exitCode === null) {
      demo.kill("SIGKILL");
      await new Promise<void>((resolve) => demo.once("exit", () => resolve()));
    }
    fs.rmSync(dir, { recursive: true, force: true });
  };
}
