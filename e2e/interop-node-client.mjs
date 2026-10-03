// Cross-implementation interop: Node's `ws` library (a completely separate
// codebase) as the CLIENT, our Go server as the peer. The demo server must
// already be running (e2e_test.go's TestMain handles that when this runs
// under `go test`; pass the base address to run it standalone).
import WebSocket from "ws";

const BASE = process.argv[2] ?? "wss://127.0.0.1:18443";
const tlsOpts = BASE.startsWith("wss:") ? { rejectUnauthorized: false } : {};

const fails = [];

function open(url, opts = {}) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(url, {
      ...tlsOpts,
      origin: "https://127.0.0.1:18443",
      ...opts,
    });
    ws.on("open", () => resolve(ws));
    ws.on("error", (e) => reject(e));
  });
}

async function echo(url, message, { binary = false, headers } = {}) {
  const ws = await open(url, { headers });
  const reply = await new Promise((resolve, reject) => {
    ws.on("message", (d, isBinary) => {
      ws.close();
      resolve({ data: d, isBinary });
    });
    ws.on("error", (e) => reject(e));
    ws.send(message, binary ? { binary: true } : undefined);
  });
  ws.terminate();
  return reply;
}

// 1. text echo
let r = await echo(BASE + "/ws/echo", "hello from node");
if (String(r.data) !== "hello from node" || r.isBinary) {
  fails.push(`text echo: ${String(r.data)}`);
}

// 2. binary echo, 1 MiB
const big = Buffer.alloc(1 << 20);
for (let i = 0; i < big.length; i++) big[i] = (i * 7) & 0xff;
r = await echo(BASE + "/ws/echo", big, { binary: true });
if (!r.isBinary || !Buffer.from(r.data).equals(big)) {
  fails.push("binary echo mismatch");
}

// 3. subprotocol negotiation
const ws = await open(BASE + "/ws/echo", { protocols: ["vnc1"] });
if (ws.protocol !== "vnc1") fails.push(`subprotocol: ${ws.protocol}`);
ws.close();
await new Promise((r) => setTimeout(r, 200));

// 4. bearer token via header — something browsers cannot do
r = await echo(BASE + "/ws/bearer", "node bearer", {
  headers: { Authorization: "Bearer demo-secret" },
});
if (String(r.data) !== "node bearer") fails.push(`bearer echo: ${String(r.data)}`);

// 5. wrong token -> 401 before the upgrade
try {
  await open(BASE + "/ws/bearer", { headers: { Authorization: "Bearer wrong" } });
  fails.push("wrong bearer token opened a session");
} catch (e) {
  if (!/401/.test(String(e))) fails.push(`wrong token: expected 401, got ${e}`);
}

// 6. controlled close: 1001 "going away"
const gws = await open(BASE + "/ws/goodbye");
const close = await new Promise((resolve) =>
  gws.on("close", (code, reason) => resolve({ code, reason: reason.toString() }))
);
if (close.code !== 1001 || close.reason !== "going away") {
  fails.push(`goodbye close: ${JSON.stringify(close)}`);
}

if (fails.length > 0) {
  console.error("FAIL\n  " + fails.join("\n  "));
  process.exit(1);
}
console.log("node-client interop: all checks passed");
