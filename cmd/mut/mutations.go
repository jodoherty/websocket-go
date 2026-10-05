package main

// guardDropClause is the replacement clause for the guard-drop mutants:
// a condition that is syntactically present but never true.
const guardDropClause = "if false {"

// mutations is the curated registry for the ws/ws.go mutation gate. Each
// entry is one security-relevant rewrite of one spot in the source, with
// the invariant its survival would violate. Patterns must each occur
// exactly once in ws/ws.go; the runner refuses to run a stale entry
// (same discipline as cmd/mcdc's expr check).
//
// The sections follow the library's attack surface: the frame codec
// (masking, size, shape, RSV), message assembly (fragmentation, UTF-8,
// decompression bound), the close-code table and close state machine, the
// handshake (both directions), the subprotocol negotiation, the origin
// gate, and the compression negotiation.
func mutations() []mutation {
	all := make([]mutation, 0)
	for _, section := range [][]mutation{
		maskingMutations(),
		controlFrameMutations(),
		fragmentationMutations(),
		decompressionMutations(),
		closeFrameMutations(),
		closeCodeMutations(),
		closeStateMutations(),
		frameGuardMutations(),
		serverHandshakeMutations(),
		clientHandshakeMutations(),
		subprotocolMutations(),
		originMutations(),
		compressionNegotiationMutations(),
		optionMutations(),
	} {
		all = append(all, section...)
	}

	return all
}

func maskingMutations() []mutation {
	return []mutation{
		{
			Name:        "masking-rule-invert",
			Pattern:     "if masked == fc.isClient {",
			Replacement: "if masked != fc.isClient {",
			Invariant: "RFC 6455 §10.3: a peer frame is masked exactly when we are the " +
				"server; inverting the rule accepts unmasked client frames",
		},
		{
			Name:        "client-mask-drop",
			Pattern:     "if fc.isClient {\n\t\t_, randErr := rand.Read(fc.rand4[:])",
			Replacement: guardDropClause + "\n\t\t_, randErr := rand.Read(fc.rand4[:])",
			Invariant: "client frames must carry a mask key and the mask bit; " +
				"dropping both breaks the masking rule in the write direction",
		},
		{
			Name:        "frame-size-limit-flip",
			Pattern:     "if size > fc.maxMsg {",
			Replacement: "if size < fc.maxMsg {",
			Invariant: "an over-limit frame must be rejected; inverting the comparison " +
				"rejects under-limit frames and accepts over-limit ones",
		},
		{
			Name:        "frame-size-limit-boundary",
			Pattern:     "if size > fc.maxMsg {",
			Replacement: "if size >= fc.maxMsg {",
			Invariant:   "a frame of exactly MaxMessageSize is legal; the limit is inclusive",
		},
		{
			Name:        "len64-highbit-guard-invert",
			Pattern:     "if fc.len8[0] != 0 {",
			Replacement: "if fc.len8[0] == 0 {",
			Invariant:   "a 64-bit length with the high bit set exceeds int64 range and must be rejected",
		},
	}
}

func controlFrameMutations() []mutation {
	return []mutation{
		{
			Name:        "control-frame-fin-drop",
			Pattern:     "if frm.isControl() && (!frm.fin || size > maxControlPayload) {",
			Replacement: "if frm.isControl() && (frm.fin || size > maxControlPayload) {",
			Invariant:   "control frames must not be fragmented (FIN required); the flip accepts fragmented control frames",
		},
		{
			Name:        "control-frame-size-flip",
			Pattern:     "if frm.isControl() && (!frm.fin || size > maxControlPayload) {",
			Replacement: "if frm.isControl() && (!frm.fin || size < maxControlPayload) {",
			Invariant:   "a 125-byte control payload is legal; inverting the comparison accepts larger payloads",
		},
		{
			Name:        "control-payload-const-shift",
			Pattern:     "maxControlPayload = 125",
			Replacement: "maxControlPayload = 126",
			Invariant:   "the control-frame payload limit is 125 bytes (RFC 6455 §5.5)",
		},
		{
			Name:        "rsv23-check-invert",
			Pattern:     "if rsv&rsv23Mask != 0 {",
			Replacement: "if rsv&rsv23Mask == 0 {",
			Invariant:   "RSV2/RSV3 must be zero; inverting rejects every ordinary frame instead of the ones that set them",
		},
		{
			Name:        "rsv1-deflate-gate-drop",
			Pattern:     "if rsv1Set := rsv == rsv1Bit; rsv1Set && !fc.deflate {",
			Replacement: "if rsv1Set := rsv == rsv1Bit; rsv1Set {",
			Invariant: "RSV1 is legal only when permessage-deflate was negotiated; " +
				"without the gate a peer can mark messages compressed that were not",
		},
		{
			Name:        "compressed-control-invert",
			Pattern:     "if frm.compressed && frm.isControl() {",
			Replacement: "if frm.compressed && !frm.isControl() {",
			Invariant: "the compressed bit on a control frame must be a protocol error " +
				"(RFC 7692 §6); inverting rejects compressed data frames instead",
		},
		{
			Name: "ping-maxmsg-guard-drop",
			Pattern: "if int64(len(payload)) > c.fc.maxMsg {\n\t\t" +
				"return fmt.Errorf(\"%w: ping of %d bytes exceeds the %d byte limit\",",
			Replacement: guardDropClause + "\n\t\treturn fmt.Errorf(\"%w: ping of %d bytes exceeds the %d byte limit\",",
			Invariant: "Ping must respect the connection's message size limit, as the " +
				"read side applies it to every received frame, control frames included",
		},
		{
			Name: "pong-maxmsg-guard-drop",
			Pattern: "if int64(len(payload)) > c.fc.maxMsg {\n\t\t" +
				"return fmt.Errorf(\"%w: pong of %d bytes exceeds the %d byte limit\",",
			Replacement: guardDropClause + "\n\t\treturn fmt.Errorf(\"%w: pong of %d bytes exceeds the %d byte limit\",",
			Invariant: "Pong must respect the connection's message size limit, as the " +
				"read side applies it to every received frame, control frames included",
		},
	}
}

func fragmentationMutations() []mutation {
	return []mutation{
		{
			Name:        "continuation-no-start-invert",
			Pattern:     "if !c.inFrag {",
			Replacement: "if c.inFrag {",
			Invariant: "a continuation frame with no start must be a protocol error; " +
				"inverting rejects continuations mid-fragment instead",
		},
		{
			Name:        "data-during-fragment-drop",
			Pattern:     "if c.inFrag {",
			Replacement: guardDropClause,
			Invariant:   "a data frame while a message is in progress must be a protocol error (RFC 6455 §5.4)",
		},
		{
			Name:        "fragment-size-limit-flip",
			Pattern:     "if int64(len(c.fragBuf)+len(frm.payload)) > c.fc.maxMsg {",
			Replacement: "if int64(len(c.fragBuf)+len(frm.payload)) < c.fc.maxMsg {",
			Invariant:   "a fragmented message may not reassemble past MaxMessageSize; inverting accepts over-limit reassembly",
		},
		{
			Name:        "text-utf8-read-invert",
			Pattern:     "if msgOp == OpText && !utf8.Valid(out) {",
			Replacement: "if msgOp == OpText && utf8.Valid(out) {",
			Invariant: "RFC 6455 §5.6: invalid UTF-8 text must fail with 1007, valid text must pass; " +
				"inverting kills every valid text message and accepts invalid ones",
		},
		{
			Name:        "text-utf8-write-invert",
			Pattern:     "if opcode == OpText && !utf8.Valid(data) {",
			Replacement: "if opcode == OpText && utf8.Valid(data) {",
			Invariant:   "an OpText write that is not valid UTF-8 must be refused before the wire",
		},
	}
}

func decompressionMutations() []mutation {
	return []mutation{
		{
			Name:        "decompress-limit-flip",
			Pattern:     "if g.buf.Len()+len(p) > g.limit {",
			Replacement: "if g.buf.Len()+len(p) < g.limit {",
			Invariant: "the decompressed output must stop at MaxMessageSize " +
				"(decompression-bomb bound); inverting defeats the bound",
		},
		{
			Name:        "decompress-limit-boundary",
			Pattern:     "if g.buf.Len()+len(p) > g.limit {",
			Replacement: "if g.buf.Len()+len(p) >= g.limit {",
			Invariant:   "exactly MaxMessageSize of decompressed output is legal; the bound is inclusive",
		},
		{
			Name:        "deflate-tail-byte-flip",
			Pattern:     "0x01, 0x00, 0x00, 0xff, 0xff,",
			Replacement: "0x02, 0x00, 0x00, 0xff, 0xff,",
			Invariant: "the decompression tail's BFINAL byte completes the truncated stream; " +
				"a wrong byte breaks every compressed message",
		},
		{
			Name:        "compress-tail-check-boundary",
			Pattern:     "if len(stream) < truncateOctets {",
			Replacement: "if len(stream) <= truncateOctets {",
			Invariant: "a stream of exactly four bytes is the shortest legal flushed tail; " +
				"the check must reject only shorter streams",
		},
	}
}

func closeFrameMutations() []mutation {
	return []mutation{
		{
			Name:        "close-one-byte-shift",
			Pattern:     "if len(payload) == 1 {",
			Replacement: "if len(payload) == 2 {",
			Invariant: "a one-byte close payload is a protocol error (RFC 6455 §7.1.5); " +
				"shifting the check lets it through as a no-status close",
		},
		{
			Name:        "close-code-payload-shift",
			Pattern:     "if len(payload) >= closeCodeBytes {",
			Replacement: "if len(payload) > closeCodeBytes {",
			Invariant:   "a two-byte (code-only) close payload must be parsed; the shift sends it to the no-status branch",
		},
		{
			Name:        "close-code-endian-flip",
			Pattern:     "code := int(binary.BigEndian.Uint16(payload[:closeCodeBytes]))",
			Replacement: "code := int(binary.LittleEndian.Uint16(payload[:closeCodeBytes]))",
			Invariant:   "close codes are big-endian on the wire",
		},
		{
			Name:        "close-reason-utf8-drop",
			Pattern:     "if !utf8.Valid(payload[closeCodeBytes:]) {",
			Replacement: "if len(payload) == 0 {",
			Invariant: "RFC 6455 §7.1.5/§8.1: a non-UTF-8 close reason must fail the " +
				"connection with 1002, never be delivered to the application",
		},
		{
			Name:        "close-echo-swap",
			Pattern:     "_ = c.Close(code, reason)",
			Replacement: "_ = c.Close(StatusPolicyViolation, reason)",
			Invariant:   "the close reply must echo the peer's code; swapping in a fixed code corrupts every close handshake",
		},
		{
			Name:        "no-status-terminal-drop",
			Pattern:     "case StatusNormalClosure, StatusNoStatusReceived:",
			Replacement: "case StatusNormalClosure:",
			Invariant:   "a close frame without a status must read as a clean close (io.EOF), not a CloseError",
		},
	}
}

func closeCodeMutations() []mutation {
	return []mutation{
		{
			Name:        "close-code-min-shift",
			Pattern:     "closeCodeMin = 1000",
			Replacement: "closeCodeMin = 1001",
			Invariant:   "close codes are in 1000-4999 (RFC 6455 §7.4); 1000 is the normal closure",
		},
		{
			Name:        "close-code-max-shift",
			Pattern:     "closeCodeMax = 4999",
			Replacement: "closeCodeMax = 4998",
			Invariant:   "close codes are in 1000-4999 (RFC 6455 §7.4)",
		},
		{
			Name:        "usable-close-mustnotset-drop",
			Pattern:     "return code >= closeCodeMin && code <= closeCodeMax && !mustNotSetCloseCode(code)",
			Replacement: "return code >= closeCodeMin && code <= closeCodeMax",
			Invariant:   "must-not-set codes (1004, 1005, 1006, 1015) are unusable in a close payload",
		},
		{
			Name:        "mustnotset-drop-1015",
			Pattern:     "case closeCodeUnexpected, StatusNoStatusReceived, StatusAbnormalClosure, closeCodeTLSFailure:",
			Replacement: "case closeCodeUnexpected, StatusNoStatusReceived, StatusAbnormalClosure:",
			Invariant:   "1015 (library-designated TLS failure) must never appear as a status on the wire",
		},
		{
			Name:        "close-reason-boundary",
			Pattern:     "if len(reason) <= maxCloseReason {",
			Replacement: "if len(reason) < maxCloseReason {",
			Invariant: "a reason of exactly 123 bytes must pass untruncated " +
				"(2-byte code + 123 = the 125-byte close payload)",
		},
		{
			Name:        "close-reason-max-shift",
			Pattern:     "maxCloseReason    = 123",
			Replacement: "maxCloseReason    = 122",
			Invariant:   "the close payload caps at 125 bytes: 2-byte code + 123-byte reason",
		},
		{
			Name:        "close-reason-utf8-write-drop",
			Pattern:     "if !utf8.ValidString(reason) {",
			Replacement: guardDropClause,
			Invariant: "a non-UTF-8 outgoing close reason must be dropped (the frame " +
				"carries the code alone), never reach the wire",
		},
		{
			Name:        "close-write-timeout-zero",
			Pattern:     "closeWriteTimeout     = 5 * time.Second",
			Replacement: "closeWriteTimeout     = 0 * time.Second",
			Invariant:   "Close's close-frame write must stay bounded when the caller set no write timeout",
		},
	}
}

func closeStateMutations() []mutation {
	return []mutation{
		{
			Name:        "readevent-closed-check-invert",
			Pattern:     "func (c *RawConn) ReadEvent() (Event, error) {\n\tif c.state.Load() == stClosed {",
			Replacement: "func (c *RawConn) ReadEvent() (Event, error) {\n\tif c.state.Load() == stOpen {",
			Invariant:   "a read on a closed connection must fast-fail with the recorded error",
		},
		{
			Name:        "writeframe-closed-check-invert",
			Pattern:     "defer c.mu.Unlock()\n\tif c.state.Load() == stClosed {\n\t\treturn c.closedWriteErr()",
			Replacement: "defer c.mu.Unlock()\n\tif c.state.Load() == stOpen {\n\t\treturn c.closedWriteErr()",
			Invariant: "an internal write (pong, keepalive ping, close) on a closed connection " +
				"must return the recorded error",
		},
		{
			Name:        "writemessage-closed-check-invert",
			Pattern:     "c.mu.Lock()\n\tif c.state.Load() == stClosed {\n\t\tc.mu.Unlock()",
			Replacement: "c.mu.Lock()\n\tif c.state.Load() == stOpen {\n\t\tc.mu.Unlock()",
			Invariant: "a write on a closed connection must fail with the recorded error, " +
				"never succeed for a frame that is not sent",
		},
		{
			Name:        "closewith-store-invert",
			Pattern:     "c.state.Store(stClosed)\n\tc.closeErr = closeErrFor(code, reason)",
			Replacement: "c.state.Store(stOpen)\n\tc.closeErr = closeErrFor(code, reason)",
			Invariant:   "Close must mark the connection closed; storing stOpen leaves it open with a recorded error",
		},
		{
			Name:        "finish-store-invert",
			Pattern:     "if c.state.Load() == stOpen {\n\t\tc.state.Store(stClosed)\n\t\tc.closeErr = err",
			Replacement: "if c.state.Load() == stOpen {\n\t\tc.state.Store(stOpen)\n\t\tc.closeErr = err",
			Invariant: "finish must record the terminal state; skipping the store leaves " +
				"a torn state (error recorded, connection open)",
		},
	}
}

func frameGuardMutations() []mutation {
	return []mutation{
		{
			Name:        "ping-limit-drop",
			Pattern:     "if len(payload) > maxControlPayload {\n\t\treturn fmt.Errorf(\"%w: ping payload",
			Replacement: "if len(payload) > 10000 {\n\t\treturn fmt.Errorf(\"%w: ping payload",
			Invariant:   "a ping payload is capped at the 125-byte control-frame limit",
		},
		{
			Name:        "pong-limit-drop",
			Pattern:     "if len(payload) > maxControlPayload {\n\t\treturn fmt.Errorf(\"%w: pong payload",
			Replacement: "if len(payload) > 10000 {\n\t\treturn fmt.Errorf(\"%w: pong payload",
			Invariant:   "a pong payload is capped at the 125-byte control-frame limit",
		},
		{
			Name:        "writeframe-continuation-guard-drop",
			Pattern:     "if opcode == OpContinuation && !c.fragWriting {",
			Replacement: "if false && !c.fragWriting {",
			Invariant: "a continuation frame may only follow a start frame this connection sent " +
				"(RFC 6455 §5.4); the guard-drop accepts standalone continuations",
		},
		{
			Name:        "fragwriting-complete-drop",
			Pattern:     "c.fragWriting = more",
			Replacement: "c.fragWriting = true",
			Invariant:   "a complete frame must clear the fragmentation state; sticky state forbids legal continuations later",
		},
	}
}

func serverHandshakeMutations() []mutation {
	return []mutation{
		{
			Name:        "handshake-version-dup-allow",
			Pattern:     "if len(versions) > 1 {",
			Replacement: "if len(versions) > 2 {",
			Invariant:   "multiple Sec-WebSocket-Version lines are a malformed handshake; two lines must still be rejected",
		},
		{
			Name:        "handshake-key-dup-allow",
			Pattern:     "if len(keys) > 1 {",
			Replacement: "if len(keys) > 2 {",
			Invariant:   "multiple Sec-WebSocket-Key lines are a malformed handshake; two lines must still be rejected",
		},
		{
			Name:        "handshake-key-len-allow-long",
			Pattern:     "if decodeErr != nil || len(raw) != wsKeyBytes {",
			Replacement: "if decodeErr != nil || len(raw) < wsKeyBytes {",
			Invariant:   "the key must be the base64 of exactly 16 octets (RFC 6455 §4.1); longer keys must also be rejected",
		},
		{
			Name:        "handshake-body-drop",
			Pattern:     "if request.Body != http.NoBody {",
			Replacement: "if request.Body == http.NoBody {",
			Invariant: "a GET with a request body must be rejected before the hijack " +
				"(its bytes would be indistinguishable from frames)",
		},
		{
			Name:        "pipelined-bytes-allow",
			Pattern:     "if buf.Reader.Buffered() > 0 {",
			Replacement: "if buf.Reader.Buffered() > 16 {",
			Invariant:   "any unconsumed (pipelined) request bytes must abort the upgrade; a few bytes must not pass",
		},
		{
			Name:        "connection-token-split-flip",
			Pattern:     "for part := range strings.SplitSeq(value, \",\") {",
			Replacement: "for part := range strings.SplitSeq(value, \";\") {",
			Invariant:   "Connection/Upgrade header values are comma-separated token lists",
		},
	}
}

func clientHandshakeMutations() []mutation {
	return []mutation{
		{
			Name:        "accept-key-check-invert",
			Pattern:     "if accepts[0] != acceptKey(key) {",
			Replacement: "if accepts[0] == acceptKey(key) {",
			Invariant:   "the client must verify the accept key; inverting accepts any server",
		},
		{
			Name:        "accept-value-count-shift",
			Pattern:     "if len(accepts) != 1 {",
			Replacement: "if len(accepts) != 0 {",
			Invariant:   "the 101 must carry exactly one Sec-WebSocket-Accept value",
		},
		{
			Name:        "switching-status-invert",
			Pattern:     "if resp.StatusCode != http.StatusSwitchingProtocols {",
			Replacement: "if resp.StatusCode == http.StatusSwitchingProtocols {",
			Invariant:   "the client must require a 101 response",
		},
		{
			Name:        "ws-key-bytes-shift",
			Pattern:     "wsKeyBytes     = 16",
			Replacement: "wsKeyBytes     = 15",
			Invariant:   "the handshake key is 16 raw octets (RFC 6455 §4.1)",
		},
		{
			Name:        "ws-version-shift",
			Pattern:     "websocketVer   = \"13\"",
			Replacement: "websocketVer   = \"12\"",
			Invariant:   "only RFC 6455 version 13 is supported",
		},
		{
			Name:        "accept-guid-flip",
			Pattern:     "const wsGUID = \"258EAFA5-E914-47DA-95CA-C5AB0DC85B11\"",
			Replacement: "const wsGUID = \"258EAFA5-E914-47DA-95CA-C5AB0DC85B12\"",
			Invariant:   "the accept key is SHA-1(key + the RFC's fixed GUID); the §1.3 vector pins it",
		},
	}
}

func subprotocolMutations() []mutation {
	return []mutation{
		{
			Name:        "subproto-echo-drop",
			Pattern:     "if !slices.Contains(offered, selected) {",
			Replacement: "if !slices.Contains([]string{selected}, selected) {",
			Invariant: "RFC 6455 §1.9: the echoed subprotocol must be one the client offered; " +
				"the drop accepts any echo",
		},
		{
			Name:        "subproto-token-check-drop",
			Pattern:     "if !validSubprotocol(advertised) {",
			Replacement: guardDropClause,
			Invariant: "an advertised token that is not a valid token must fail the handshake " +
				"instead of being echoed into the 101",
		},
		{
			Name:        "subproto-token-separators-drop",
			Pattern:     "if r <= 0x20 || r >= 0x7f || strings.ContainsRune(subprotocolSeparators, r) {",
			Replacement: "if r <= 0x20 || r >= 0x7f {",
			Invariant: "RFC 2616 separators (a comma among them) may not appear in a subprotocol " +
				"token — a comma would split the header value",
		},
	}
}

func originMutations() []mutation {
	return []mutation{
		{
			Name:        "origin-check-drop",
			Pattern:     "return origin == scheme+\"://\"+request.Host",
			Replacement: "return true || origin == scheme+\"://\"+request.Host",
			Invariant:   "the default origin check must reject a cross-origin browser (cross-site WebSocket hijacking)",
		},
		{
			Name:        "origin-scheme-swap",
			Pattern:     "if request.TLS != nil {",
			Replacement: "if request.TLS == nil {",
			Invariant:   "the origin scheme must follow the transport: a TLS request is https, a plain one http",
		},
	}
}

func compressionNegotiationMutations() []mutation {
	return []mutation{
		{
			Name:        "window-bits-range-drop",
			Pattern:     "if err != nil || bits < 8 || bits > maxWindowBits {",
			Replacement: "if err != nil || bits < 8 {",
			Invariant:   "a window above 15 bits is out of range (RFC 7692 §7.1.2); 32 must be rejected",
		},
		{
			Name:        "deflate-double-offer-allow",
			Pattern:     "if idx > 0 {",
			Replacement: "if idx > 1 {",
			Invariant:   "permessage-deflate offered more than once must fail the handshake",
		},
		{
			Name:        "unoffered-extension-drop",
			Pattern:     "if !offered && len(groups) > 0 {",
			Replacement: "if !offered && len(groups) > 1 {",
			Invariant:   "the 101 must not select an extension the client never offered",
		},
		{
			Name:        "multi-extension-allow",
			Pattern:     "if len(groups) > 1 {",
			Replacement: "if len(groups) > 2 {",
			Invariant:   "the 101 must select permessage-deflate at most once; two extensions must fail the dial",
		},
		{
			Name:        "client-window-cap-drop",
			Pattern:     "if bits := params.clientWindowBits; bits != 0 && bits < maxWindowBits {",
			Replacement: "if bits := params.clientWindowBits; bits != 0 && bits < 8 {",
			Invariant:   "a server response that caps the client window below the full 15 bits must fail the dial",
		},
	}
}

func optionMutations() []mutation {
	return []mutation{
		{
			Name:        "sanitize-maxsize-zero-allow",
			Pattern:     "if cfg.MaxMessageSize <= 0 {",
			Replacement: "if cfg.MaxMessageSize < 0 {",
			Invariant:   "a non-positive message size must fall back to the default, never stay non-positive",
		},
		{
			Name:        "sanitize-idle-zero-defaults",
			Pattern:     "if cfg.IdleTimeout < 0 {",
			Replacement: "if cfg.IdleTimeout <= 0 {",
			Invariant:   "a zero idle timeout means keepalive disabled (documented), not the default",
		},
		{
			Name:        "write-timeout-default-zero",
			Pattern:     "defaultWriteTimeout   = 30 * time.Second",
			Replacement: "defaultWriteTimeout   = 0 * time.Second",
			Invariant:   "the default write bound must not be unbounded",
		},
	}
}
