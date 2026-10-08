package ws

import (
	"bufio"
	"bytes"
	"net/http"
	"strings"
	"testing"
)

// FuzzReadFrame is a safety fuzz target for the frame decoder: arbitrary
// byte streams must never panic, index out of range, or loop forever —
// they may only produce a frame or an error. Run with:
//
//	go test ./ws -run '' -fuzz FuzzReadFrame -fuzztime 30s
func FuzzReadFrame(f *testing.F) {
	// Seeds: the RFC 6455 §5.7 examples, truncated forms, and control frames.
	seed := [][]byte{
		{0x81, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f},
		{0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58},
		{0x81},                         // truncated header
		{0x81, 0x7e, 0x00},             // truncated 16-bit length
		{0x81, 0x7e, 0xff, 0xff, 0x48}, // length longer than payload
		{0x80, 0x00},                   // continuation without start
		{0x82, 0x00},                   // empty binary
		{0x89, 0x80},                   // ping, no mask (client side violation)
		{0x8a, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58},
		{0x83, 0x00}, // reserved opcode
		{0x81, 0x03, 0x48, 0x65, 0x6c},
		{},
	}
	for _, s := range seed {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, data []byte) {
		// Exercise both sides of the masking rule on the same input. The
		// codec is a pure function of its stream: no connection state,
		// so this targets exactly the byte-level decoding logic.
		for _, isClient := range []bool{true, false} {
			fc := &frameCodec{
				br:       bufio.NewReader(bytes.NewReader(data)),
				isClient: isClient,
				maxMsg:   1 << 20,
			}
			// A single readFrame call may not panic; it returns either a
			// frame or an error.
			_, _ = fc.readFrame()
		}
	})
}

// fuzzStreamSeeds returns the byte streams every connection-level fuzz
// target starts from: legal frames, every close-frame shape (including
// the unusable ones), control traffic, fragmentation, reserved-bit and
// RSV1/compressed forms, truncated frames, and the extended-length
// encodings.
func fuzzStreamSeeds() [][]byte {
	return [][]byte{
		{0x81, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f},                         // text "Hello"
		{0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58}, // masked
		{0x88, 0x02, 0x03, 0xe8},                                           // close 1000
		{0x88, 0x00},                                                       // close, no status
		{0x88, 0x01, 0x03},                                                 // close, one-byte payload (violation)
		{0x88, 0x03, 0x03, 0xe8, 0xff},                                     // close, non-UTF-8 reason
		{0x88, 0x02, 0x03, 0xec},                                           // close 1004 (reserved, unusable)
		{0x88, 0x02, 0x13, 0x88},                                           // close 5000 (out of range)
		{0x89, 0x00},                                                       // ping
		{0x8a, 0x04, 'p', 'o', 'n', 'g'},                                   // pong with payload
		{0x01, 0x02, 'H', 'e', 0x80, 0x03, 'l', 'l', 'o'},                  // fragmented text
		{0x01, 0x02, 0x48, 0x65, 0x01, 0x02, 0x6c, 0x6c},                   // data frame mid-fragment
		{0xc1, 0x00},                                                       // RSV1 text (compressed marker)
		{0x80, 0x00},                                                       // continuation without start
		{0x83, 0x00},                                                       // reserved opcode
		{0xa1, 0x00},                                                       // RSV2 set
		{0x81, 0x05, 0x48},                                                 // truncated payload
		{0x81, 0x7e, 0x00, 0x08, 'H', 'e', 'l', 'l', 'o', 'H', 'i', '!'}, // 16-bit len
		{0x81, 0x7f, 0x01, 0, 0, 0, 0, 0, 0, 0, 0},                       // 64-bit len, too large
		{0x81, 0x7f, 0, 0, 0, 0, 0, 0, 0x01, 0x00},                       // 64-bit len, valid form
		{},
	}
}

// FuzzSessionRead is the session-level state-machine target: arbitrary byte
// streams are pumped through Session.ReadMessage until the stream ends or
// the connection fails — across all four variants of the read state (the
// masking side × the compressed negotiation). This is where sequence bugs
// live: fragmentation interleaved with close, RSV1 across frames, size and
// UTF-8 limits on reassembled messages, and close-code resolution. An
// input that panics or hangs any variant is a bug; the loop always
// terminates because every event consumes input and an error ends the
// connection.
func FuzzSessionRead(f *testing.F) {
	for _, s := range fuzzStreamSeeds() {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, data []byte) {
		for _, isClient := range []bool{true, false} {
			for _, compressed := range []bool{true, false} {
				fc := &fakeConn{data: data}
				raw := newRawConn(fc, fc, isClient, 1<<20, 0, 0)
				if compressed {
					raw.applyCompression()
				}
				session := newSession(raw, nil)
				for {
					_, _, err := session.ReadMessage()
					if err != nil {
						break
					}
				}
			}
		}
	})
}

// FuzzRawTraffic drives the raw face under a legal single-goroutine usage
// pattern: the ReadEvent loop with the write paths interleaved — data and
// control frames, fragmented writes, Pings and Pongs, and Close against any
// read state. The contract allows every write from any goroutine, so the
// interleaving exercises the close state machine, the fragmentation state
// (a continuation may only follow a start this connection sent), and
// writes after close. Every call must simply return; a panic is a bug.
func FuzzRawTraffic(f *testing.F) {
	for _, s := range fuzzStreamSeeds() {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, data []byte) {
		for _, isClient := range []bool{true, false} {
			fc := &fakeConn{data: data}
			raw := newRawConn(fc, fc, isClient, 1<<20, 0, 0)
			for step := 0; ; step++ {
				_, readErr := raw.ReadEvent()
				if readErr != nil {
					// Terminal: a last write against the dead state must
					// fast-fail, never panic or block.
					_ = raw.WriteText("done")
					_ = raw.Ping([]byte("x"))
					sayGoodbye(raw, StatusNormalClosure, "bye")

					return
				}
				if len(data) < 4 || step%3 != 0 {
					continue
				}
				chunk := data[:min(len(data), 32)]
				switch data[0] % 5 {
				case 0: // a data frame, possibly starting a fragment
					op := Op(data[1]) & 0x03 // OpContinuation, OpText, or OpBinary
					if op == OpContinuation {
						op = OpBinary
					}
					_ = raw.WriteFrame(op, chunk, data[2]&1 == 1)
				case 1:
					_ = raw.WriteMessage(OpBinary, chunk)
				case 2:
					_ = raw.Pong(chunk)
				case 3:
					_ = raw.Ping(chunk)
				default:
					_ = raw.Shutdown(1000+int(data[3])%3000, "fuzz")
				}
			}
		}
	})
}

// FuzzCompressionParams hammers the permessage-deflate (RFC 7692 §7.1)
// negotiation parsers with arbitrary strings, on both sides of the
// handshake: the offer parser, the server's response decision, and the
// client's verification of the 101 response. A malformed extension must
// fail the handshake — never panic, never index out of range.
func FuzzCompressionParams(f *testing.F) {
	f.Add("permessage-deflate")
	f.Add("permessage-deflate; client_no_context_takeover; server_no_context_takeover")
	f.Add("permessage-deflate; client_max_window_bits=15; server_max_window_bits=8")
	f.Add("permessage-deflate; client_max_window_bits=015")
	f.Add("permessage-deflate; server_max_window_bits")
	f.Add("permessage-deflate; server_max_window_bits=16")
	f.Add("permessage-deflate; x=1; x=2")
	f.Add("permessage-deflate;permessage-deflate")
	f.Fuzz(func(_ *testing.T, s string) {
		_, _ = parseCompressionParams(s)
		_, _ = negotiateCompression([]string{s})
		header := http.Header{extHeaderPlural: []string{s}, extHeaderSingular: []string{s}}
		_, _ = verifyCompressionResponse(true, splitExtensionGroups(header))
	})
}

// FuzzSubprotocolNegotiation hammers the RFC 6455 §1.9 subprotocol parsers
// with arbitrary strings: the server's selection from the client's request
// (which must never echo an invalid token into the 101), the client's
// verification of the server's echo, and the token grammar itself.
func FuzzSubprotocolNegotiation(f *testing.F) {
	f.Add("chat.v1, binary")
	f.Add("chat.v1, ,binary")
	f.Add("a,b, a")
	f.Add("chat.v1;binary")
	f.Add("chat.v1, chat.v1")
	f.Add("x.comma, y")
	f.Fuzz(func(_ *testing.T, s string) {
		_, _ = negotiateProtocol([]string{"chat.v1", "binary"}, s)
		_ = checkSubprotocolEcho([]string{"chat.v1", "binary"}, s)
		_ = validSubprotocol(s)
	})
}

// FuzzHandshakeResponse drives the client's 101-response parser with
// arbitrary bytes from a (potentially hostile) server: the accept key, the
// upgrade tokens, the subprotocol echo, and the extension response are all
// verified, and any mismatch must fail the dial — never panic.
func FuzzHandshakeResponse(f *testing.F) {
	f.Add([]byte("HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n" +
		"Sec-WebSocket-Protocol: chat.v1\r\n\r\n"))
	f.Add([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
	f.Add([]byte("HTTP/1.1 101"))
	f.Add([]byte("HTTP/1.1 101 Switching Protocols\r\n\r\n"))
	f.Fuzz(func(_ *testing.T, data []byte) {
		reader := bufio.NewReader(bytes.NewReader(data))
		_, _, _ = readHandshakeResponse(reader, "dGhlIHNhbXBsZSBub25jZQ==",
			[]string{"chat.v1", "binary"}, true)
	})
}

// FuzzDialURL drives the client's URL resolution and the handshake request
// builder with arbitrary URL strings. The security invariant being
// asserted: a URL that resolves to a dial target must never put a line
// break into the request line or the Host header, and a header value with
// a line break must be refused by the request builder rather than
// injected. (url.Parse rejects control characters upstream; this pins the
// end-to-end property instead of trusting that.)
func FuzzDialURL(f *testing.F) {
	f.Add("ws://example.com/ws")
	f.Add("wss://[::1]:8443/ws")
	f.Add("ws://user:pass@host:9/path?x=1")
	f.Add("ws:///")
	f.Add("ws://example.com")
	f.Add("wss://example.com#frag")
	f.Add("http://example.com")
	f.Fuzz(func(t *testing.T, s string) {
		host, path, isTLS, _, err := dialTarget(s)
		if err != nil {
			return
		}
		if strings.ContainsAny(host, "\r\n") || strings.ContainsAny(path, "\r\n") {
			t.Fatalf("line break in the dial target: host %q path %q", host, path)
		}
		headers := http.Header{}
		headers.Set("X-Auth", s) // the value is attacker-shaped; the builder must guard it
		var buf bytes.Buffer
		_, writeErr := writeHandshakeRequest(&buf, path, host, []string{"chat.v1"}, isTLS, headers)
		if writeErr != nil {
			return
		}
		request := buf.String()
		// The blank line that ends the header block must be the request's
		// final four bytes: an earlier blank line is a mid-request header
		// injection, a later one means bytes after the header block.
		if i := strings.Index(request, "\r\n\r\n"); i != len(request)-4 {
			t.Fatalf("blank line misplaced in the request (header injection): %q", request)
		}
	})
}
