// Cross-implementation interop: Node's `ws` library as the SERVER, our Go
// client as the peer. Binds an ephemeral (OS-assigned) port and reports the
// actual address to the harness over a reserved callback connection given as
// argv[2] (host:port), so the Go test learns the port without any fixed
// value — the same port-report handshake as cmd/demo's -report.
import { WebSocketServer } from "ws";
import net from "node:net";

const [cbHost, cbPort] = (process.argv[2] ?? "127.0.0.1:0").split(":");

// port: 0 asks the OS for an ephemeral port. perMessageDeflate: true accepts
// the Go client's compression offer so the interop exercises
// permessage-deflate in the Go-client -> Node-server direction as well.
const wss = new WebSocketServer({ port: 0, host: "127.0.0.1", perMessageDeflate: true });

wss.on("listening", () => {
  const addr = `127.0.0.1:${wss.address().port}`;
  console.log(`node server listening on ${addr}`);
  // The callback listener is bound and reserved by the harness before it
  // launched us, so this connect completes in the kernel backlog and the
  // report is delivered whenever the harness accepts.
  const sock = net.connect({ host: cbHost, port: Number(cbPort) }, () => {
    sock.write(`${addr}\n`);
    sock.end();
  });
  sock.on("error", (e) => {
    console.error("report error:", e.message);
    process.exit(1);
  });
});

wss.on("error", (e) => {
  console.error("server error:", e.message);
  process.exit(1);
});

wss.on("connection", (sock) => {
  sock.on("message", (data, isBinary) => {
    if (!isBinary && data.toString() === "close-me") {
      sock.close(4001, "bye from node");
      return;
    }
    sock.send(data, { binary: isBinary });
  });
});
