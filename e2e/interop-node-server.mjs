// Cross-implementation interop: Node's `ws` library as the SERVER, our Go
// client as the peer. Prints "ready" once the listener is up.
import { WebSocketServer } from "ws";

const port = Number(process.argv[2] ?? 18543);
const wss = new WebSocketServer({ port, host: "127.0.0.1" });

wss.on("listening", () => console.log("ready"));
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

console.log("ready");
