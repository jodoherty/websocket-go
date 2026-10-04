// Cross-implementation interop: Node's `ws` library as the SERVER, our Go
// client as the peer. Prints "ready" exactly once, from the "listening"
// event, so the word is true when it appears.
import { WebSocketServer } from "ws";

const port = Number(process.argv[2] ?? 18543);
// perMessageDeflate: true — accept the Go client's compression offer so the
// interop exercises permessage-deflate in the Go-client -> Node-server
// direction as well.
const wss = new WebSocketServer({ port, host: "127.0.0.1", perMessageDeflate: true });

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
