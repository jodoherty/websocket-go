package main

// The MC/DC traceability registry. One entry per compound decision in
// the ws package; each pair traces one required independence pair to the
// test subtest that proves it. Vectors are truth assignments in
// condition order (the entry's conditions list); condition indexes refer
// to that list.
//
// main.go re-checks every entry against the current source: the
// expression and conditions must still match, the pair must still be a
// genuine independence pair of the current boolean structure, and the
// test and subtest must still exist. Any drift fails the gate.

// Test names referenced by the traces.
const (
	testControlFrame            = "TestMCDCControlFrame"
	testIsReadTimeout           = "TestMCDCIsReadTimeout"
	testWriteOpcode             = "TestMCDCWriteMessageOpcode"
	testCloseCodeRange          = "TestMCDCCloseCodeRange"
	testDialScheme              = "TestMCDCDialScheme"
	testMCDCCloseCode           = "TestMCDCCloseCode"
	testMCDCWebSocketKey        = "TestMCDCWebSocketKey"
	testMCDCSubprotocol         = "TestMCDCSubprotocol"
	testMCDCTextUTF8            = "TestMCDCTextUTF8"
	testMCDCUpgrade101          = "TestMCDCUpgrade101"
	testMCDCHandleCloseCode     = "TestMCDCHandleCloseCode"
	testMCDCRawWriteFrame       = "TestMCDCRawWriteFrame"
	testMCDCTruncateReason      = "TestMCDCTruncateReason"
	testMCDCStreamDeadlines     = "TestMCDCStreamDeadlines"
	testMCDCDeflateRSV          = "TestMCDCDeflateRSV"
	testMCDCDeflateControl      = "TestMCDCDeflateControl"
	testMCDCDeflateServerWindow = "TestMCDCDeflateServerWindow"
	testMCDCDeflateOffered      = "TestMCDCDeflateOffered"
	testMCDCDeflateWindowBits   = "TestMCDCDeflateWindowBits"
	testFragWriteStart          = "TestWriteRejectsDataStartDuringFragment"
	testUnquoteExtValue         = "TestUnquoteExtensionValue"
	testKeepaliveRetry          = "TestKeepaliveRetryAfterPartialFrame"
)

// Subtest names reused across more than one trace.
const (
	subtestDecode           = "decode"
	subtestBelow            = "below"
	subtestAbove            = "above"
	subtestCloseNotWritable = "close-not-writable"
)

// Condition strings reused across more than one trace.
const (
	condOpcodeText   = "opcode == OpText"
	condOpcodeBinary = "opcode == OpBinary"
	condOpCont       = "opcode == OpContinuation"
)

// pairTrace is one traced MC/DC independence pair.
type pairTrace struct {
	condition int    // the condition that varies independently
	from      []bool // assignment before the flip
	to        []bool // assignment after the flip
	test      string // test function that proves the pair
	subtest   string // t.Run subtest ("" = the whole function)
}

// decisionTrace is one traced compound decision.
type decisionTrace struct {
	expr       string
	conditions []string
	pairs      []pairTrace
}

// registry is the complete trace set: frame-path decisions plus
// close-code, handshake, and server-path decisions.
func registry() []decisionTrace {
	traces := frameTraces()
	traces = append(traces, closeTraces()...)
	traces = append(traces, handshakeTraces()...)
	traces = append(traces, textUTF8Traces()...)
	traces = append(traces, compressionTraces()...)
	traces = append(traces, rawWriteFrameTraces()...)
	traces = append(traces, writeFrameGuardTraces()...)
	traces = append(traces, keepaliveTraces()...)

	return append(traces, serverTraces()...)
}

// rawWriteFrameTraces covers the raw frame-write decisions in
// RawConn.WriteFrame: the writable opcode set, the control-frame shape,
// the standalone-continuation guard, and the fragment-aware UTF-8 rule.
func rawWriteFrameTraces() []decisionTrace {
	return []decisionTrace{
		// ws.go (WriteFrame): op == OpPing || op == OpPong
		{
			expr:       "opcode == OpPing || opcode == OpPong",
			conditions: []string{"opcode == OpPing", "opcode == OpPong"},
			pairs: []pairTrace{
				// A 126-byte ping is refused by the control limit; the same
				// size as a text frame passes (the ping condition flips the
				// case selection on).
				{0, []bool{false, false}, []bool{true, false}, testMCDCRawWriteFrame, "oversized-ping"},
				// A 126-byte pong is refused; the same size as a binary
				// frame passes (the pong condition flips the selection on).
				{1, []bool{false, false}, []bool{false, true}, testMCDCRawWriteFrame, "oversized-pong"},
			},
		},
		// ws.go (WriteFrame): op == OpText && !more
		{
			expr:       "opcode == OpText && !more",
			conditions: []string{condOpcodeText, "!more"},
			pairs: []pairTrace{
				// Invalid bytes as a single-frame OpText are refused; the
				// same bytes as OpBinary pass (the opcode condition flips).
				{0, []bool{true, true}, []bool{false, true}, testMCDCRawWriteFrame, "binary-passes-invalid-bytes"},
				// Invalid bytes in a text fragment pass — a boundary may
				// split a rune — while the same bytes single-framed are
				// refused (the more condition flips).
				{1, []bool{true, true}, []bool{true, false}, testMCDCRawWriteFrame, "text-fragment-passes"},
			},
		},
		// ws.go (WriteFrame): op == OpText && !more && !utf8.Valid(payload)
		{
			expr:       "opcode == OpText && !more && !utf8.Valid(payload)",
			conditions: []string{condOpcodeText, "!more", "!utf8.Valid(payload)"},
			pairs: []pairTrace{
				// Invalid single-frame text is refused; the same bytes as
				// OpBinary pass (the opcode condition flips).
				{0, []bool{true, true, true}, []bool{false, true, true}, testMCDCRawWriteFrame, "binary-passes-invalid-bytes"},
				// Invalid single-frame text is refused; invalid bytes in a
				// text fragment pass (the more condition flips).
				{1, []bool{true, true, true}, []bool{true, false, true}, testMCDCRawWriteFrame, "text-fragment-passes"},
				// Invalid single-frame text is refused; valid text passes
				// (the validity condition flips).
				{2, []bool{true, true, true}, []bool{true, true, false}, testMCDCRawWriteFrame, "valid-text"},
			},
		},
		// ws.go (WriteFrame): op == OpText || op == OpBinary || op == OpContinuation
		{
			expr:       "opcode == OpText || opcode == OpBinary || opcode == OpContinuation",
			conditions: []string{condOpcodeText, condOpcodeBinary, condOpCont},
			pairs: []pairTrace{
				// A text frame goes out; a close frame is refused (the
				// text condition flips the case selection).
				{0, []bool{true, false, false}, []bool{false, false, false}, testMCDCRawWriteFrame, subtestCloseNotWritable},
				// A binary frame goes out; a close frame is refused (the
				// binary condition flips the selection).
				{1, []bool{false, true, false}, []bool{false, false, false}, testMCDCRawWriteFrame, subtestCloseNotWritable},
				// A continuation after a start goes out; a close frame is
				// refused (the continuation condition flips the selection).
				{2, []bool{false, false, true}, []bool{false, false, false}, testMCDCRawWriteFrame, subtestCloseNotWritable},
			},
		},
		// ws.go (WriteFrame, nested sub-decision of the writable set):
		// op == OpText || op == OpBinary
		{
			expr:       "opcode == OpText || opcode == OpBinary",
			conditions: []string{condOpcodeText, condOpcodeBinary},
			pairs: []pairTrace{
				// A text frame goes out; a close frame is refused (the text
				// condition flips the sub-decision on).
				{0, []bool{true, false}, []bool{false, false}, testMCDCRawWriteFrame, subtestCloseNotWritable},
				// A binary frame goes out; a close frame is refused (the
				// binary condition flips the sub-decision on).
				{1, []bool{false, true}, []bool{false, false}, testMCDCRawWriteFrame, subtestCloseNotWritable},
			},
		},
		// ws.go (WriteFrame, write-state guard): op == OpContinuation && !c.fragWriting
		{
			expr:       "opcode == OpContinuation && !c.fragWriting",
			conditions: []string{"opcode == OpContinuation", "!c.fragWriting"},
			pairs: []pairTrace{
				// A continuation with no start in flight is refused; a
				// text frame without a start goes out (the opcode
				// condition flips the guard off).
				{0, []bool{false, true}, []bool{true, true}, testMCDCRawWriteFrame, "standalone-continuation"},
				// A continuation with no start is refused; the same frame
				// after a start goes out (the fragWriting condition flips
				// the guard off).
				{1, []bool{true, true}, []bool{true, false}, testMCDCRawWriteFrame, "continuation-after-text-start"},
			},
		},
	}
}

// writeFrameGuardTraces covers the finding-3 fragmented-write guards: a new
// data message cannot start while a fragment is in progress (RFC 6455 §5.4).
func writeFrameGuardTraces() []decisionTrace {
	return []decisionTrace{
		// ws.go (WriteFrame): a new data message cannot
		// start while a fragment is in progress; control frames may
		// interleave. Outer decision: c.fragWriting && (OpText || OpBinary).
		{
			expr:       "c.fragWriting && (opcode == OpText || opcode == OpBinary)",
			conditions: []string{"c.fragWriting", condOpcodeText, condOpcodeBinary},
			pairs: []pairTrace{
				// A data start mid-fragment is refused; the same frame with
				// no fragment in flight goes out (the fragWriting condition
				// flips the guard).
				{0, []bool{true, true, false}, []bool{false, true, false}, testFragWriteStart, ""},
				// A text start mid-fragment is refused; the same binary
				// frame is refused too, so flipping the text condition with
				// the binary off turns the guard on then off.
				{1, []bool{true, true, false}, []bool{true, false, false}, testFragWriteStart, ""},
				// Flipping the binary condition (text off) turns the guard
				// on then off.
				{2, []bool{true, false, true}, []bool{true, false, false}, testFragWriteStart, ""},
			},
		},
		// ws.go (WriteFrame writable set, second nested instance):
		// opcode == OpText || opcode == OpBinary
		{
			expr:       "opcode == OpText || opcode == OpBinary",
			conditions: []string{condOpcodeText, condOpcodeBinary},
			pairs: []pairTrace{
				// A text frame goes out; a close frame is refused (the text
				// condition flips the sub-decision on).
				{0, []bool{true, false}, []bool{false, false}, testMCDCRawWriteFrame, subtestCloseNotWritable},
				// A binary frame goes out; a close frame is refused (the
				// binary condition flips the sub-decision on).
				{1, []bool{false, true}, []bool{false, false}, testMCDCRawWriteFrame, subtestCloseNotWritable},
			},
		},
	}
}

// frameTraces covers the frame codec and message paths.
func frameTraces() []decisionTrace {
	return []decisionTrace{
		// ws.go: frm.isControl() && (!frm.fin || size > maxControlPayload)
		// Outer decision: three conditions; the inner OR is its own
		// decision with the last two.
		{
			expr:       "frm.isControl() && (!frm.fin || size > maxControlPayload)",
			conditions: []string{"frm.isControl()", "!frm.fin", "size > maxControlPayload"},
			pairs: []pairTrace{
				// non-FIN control frame rejected, same frame as data accepted.
				{0, []bool{true, true, false}, []bool{false, true, false}, testControlFrame, "isControl"},
				// FIN ping accepted, non-FIN ping rejected.
				{1, []bool{true, true, false}, []bool{true, false, false}, testControlFrame, "fin"},
				// 125-byte FIN control frame accepted, 126-byte rejected.
				{2, []bool{true, false, true}, []bool{true, false, false}, testControlFrame, "size"},
			},
		},
		{
			expr:       "!frm.fin || size > maxControlPayload",
			conditions: []string{"!frm.fin", "size > maxControlPayload"},
			pairs: []pairTrace{
				{0, []bool{true, false}, []bool{false, false}, testControlFrame, "fin"},
				{1, []bool{false, true}, []bool{false, false}, testControlFrame, "size"},
			},
		},
		// ws.go: errors.As(err, &nerr) && nerr.Timeout()
		{
			expr:       "errors.As(err, &nerr) && nerr.Timeout()",
			conditions: []string{"errors.As(err, &nerr)", "nerr.Timeout()"},
			pairs: []pairTrace{
				// a timeout net.Error vs. an error that is not a net.Error.
				{0, []bool{true, true}, []bool{false, true}, testIsReadTimeout, "as"},
				// a timeout net.Error vs. a non-timeout net.Error.
				{1, []bool{true, true}, []bool{true, false}, testIsReadTimeout, "timeout"},
			},
		},
		// ws.go: opcode != OpText && opcode != OpBinary
		{
			expr:       "opcode != OpText && opcode != OpBinary",
			conditions: []string{"opcode != OpText", "opcode != OpBinary"},
			pairs: []pairTrace{
				// OpText proceeds to the transport, OpPing is rejected.
				{0, []bool{false, true}, []bool{true, true}, testWriteOpcode, "notText"},
				// OpBinary proceeds to the transport, OpPing is rejected.
				{1, []bool{true, false}, []bool{true, true}, testWriteOpcode, "notBinary"},
			},
		},
	}
}

// closeTraces covers the close-code validation decisions and the close
// reason truncation.
func closeTraces() []decisionTrace {
	return []decisionTrace{
		// ws.go: code >= closeCodeMin && code <= closeCodeMax (nested in the
		// usableCloseCode decision)
		{
			expr:       "code >= closeCodeMin && code <= closeCodeMax",
			conditions: []string{"code >= closeCodeMin", "code <= closeCodeMax"},
			pairs: []pairTrace{
				// 999 (below range) fails with 1002; 1000 closes normally.
				{0, []bool{true, true}, []bool{false, true}, testMCDCCloseCode, "min"},
				// 5000 (above range) fails with 1002; 1000 closes normally.
				{1, []bool{true, true}, []bool{true, false}, testMCDCCloseCode, "max"},
			},
		},
		// ws.go: code < closeCodeMin || code > closeCodeMax
		{
			expr:       "code < closeCodeMin || code > closeCodeMax",
			conditions: []string{"code < closeCodeMin", "code > closeCodeMax"},
			pairs: []pairTrace{
				// 999 rejected, 1000 accepted (aboveMax false in both).
				{0, []bool{true, false}, []bool{false, false}, testCloseCodeRange, "belowMin"},
				// 5000 rejected, 1000 accepted (belowMin false in both).
				{1, []bool{false, true}, []bool{false, false}, testCloseCodeRange, "aboveMax"},
			},
		},
		// ws.go (truncateReason): n > 0 && !utf8.RuneStart(reason[n])
		{
			expr:       "n > 0 && !utf8.RuneStart(reason[n])",
			conditions: []string{"n > 0", "!utf8.RuneStart(reason[n])"},
			pairs: []pairTrace{
				// A 2-byte rune split across the bound backs off one byte;
				// a start byte at the bound does not.
				{1, []bool{true, true}, []bool{true, false}, testMCDCTruncateReason, "runeBoundary"},
				// An all-continuation (invalid UTF-8) reason runs the loop
				// down to n == 0 and yields the empty string.
				{0, []bool{true, true}, []bool{false, true}, testMCDCTruncateReason, "invalidUTF8"},
			},
		},
		// ws.go: code >= closeCodeMin && code <= closeCodeMax &&
		// !mustNotSetCloseCode(code)
		{
			expr:       "code >= closeCodeMin && code <= closeCodeMax && !mustNotSetCloseCode(code)",
			conditions: []string{"code >= closeCodeMin", "code <= closeCodeMax", "!mustNotSetCloseCode(code)"},
			pairs: []pairTrace{
				// 999 (below range) fails with 1002; 1000 closes normally.
				{0, []bool{true, true, true}, []bool{false, true, true}, testMCDCCloseCode, "min"},
				// 5000 (above range) fails with 1002; 1000 closes normally.
				{1, []bool{true, true, true}, []bool{true, false, true}, testMCDCCloseCode, "max"},
				// 1004 (must not be set on the wire) fails with 1002 and is
				// not echoed; 1000 closes normally.
				{2, []bool{true, true, true}, []bool{true, true, false}, testMCDCCloseCode, "forbidden"},
			},
		},
	}
}

// handshakeTraces covers the upgrader policy and the Dial scheme check.
func handshakeTraces() []decisionTrace {
	return []decisionTrace{
		// ws.go: parsed.Scheme != wsScheme && parsed.Scheme != wssScheme
		{
			expr:       "parsed.Scheme != wsScheme && parsed.Scheme != wssScheme",
			conditions: []string{"parsed.Scheme != wsScheme", "parsed.Scheme != wssScheme"},
			pairs: []pairTrace{
				// ws:// passes the check, http:// fails it (notWss true in both).
				{0, []bool{false, true}, []bool{true, true}, testDialScheme, "notWs"},
				// wss:// passes the check, http:// fails it (notWs true in both).
				{1, []bool{true, false}, []bool{true, true}, testDialScheme, "notWss"},
			},
		},
		// ws.go: decodeErr != nil || len(raw) != wsKeyBytes
		{
			expr:       "decodeErr != nil || len(raw) != wsKeyBytes",
			conditions: []string{"decodeErr != nil", "len(raw) != wsKeyBytes"},
			pairs: []pairTrace{
				// "!!!!" is not base64: 400. The same 16-byte key, well
				// formed, is accepted: 101.
				{0, []bool{true, false}, []bool{false, false}, testMCDCWebSocketKey, subtestDecode},
				// "QUFB" decodes to 3 bytes: 400. A 16-byte key is
				// accepted: 101.
				{1, []bool{false, true}, []bool{false, false}, testMCDCWebSocketKey, "len"},
			},
		},
		// ws.go: r <= 0x20 || r >= 0x7f ||
		// strings.ContainsRune(subprotocolSeparators, r) (validSubprotocol)
		{
			expr: "r <= 0x20 || r >= 0x7f || " +
				"strings.ContainsRune(subprotocolSeparators, r)",
			conditions: []string{
				"r <= 0x20",
				"r >= 0x7f",
				"strings.ContainsRune(subprotocolSeparators, r)",
			},
			pairs: []pairTrace{
				// A control character is rejected; the printable "a" is
				// accepted.
				{0, []bool{true, false, false}, []bool{false, false, false}, testMCDCSubprotocol, "low"},
				// DEL (0x7f) is rejected; the printable "a" is accepted.
				{1, []bool{false, true, false}, []bool{false, false, false}, testMCDCSubprotocol, "high"},
				// A double quote (a separator) is rejected; the
				// printable "a" is accepted.
				{2, []bool{false, false, true}, []bool{false, false, false}, testMCDCSubprotocol, "quote"},
			},
		},
		// ws.go: r <= 0x20 || r >= 0x7f (nested in the validSubprotocol
		// decision)
		{
			expr:       "r <= 0x20 || r >= 0x7f",
			conditions: []string{"r <= 0x20", "r >= 0x7f"},
			pairs: []pairTrace{
				// A control character is rejected; the printable "a" is
				// accepted.
				{0, []bool{true, false}, []bool{false, false}, testMCDCSubprotocol, "low"},
				// DEL (0x7f) is rejected; the printable "a" is accepted.
				{1, []bool{false, true}, []bool{false, false}, testMCDCSubprotocol, "high"},
			},
		},
		// ws.go: the negated "Upgrade"-token check OR the negated
		// "Connection"-token check on the 101 response. Concatenated so
		// the line stays under the lll limit; the evaluated string must
		// match the normalized source expression exactly.
		{
			expr: `!headerContainsToken(resp.Header, "Upgrade", "websocket") || ` +
				`!headerContainsToken(resp.Header, "Connection", "Upgrade")`,
			conditions: []string{
				`!headerContainsToken(resp.Header, "Upgrade", "websocket")`,
				`!headerContainsToken(resp.Header, "Connection", "Upgrade")`,
			},
			pairs: []pairTrace{
				// A 101 without "Upgrade: websocket" is rejected; with both
				// tokens it is accepted.
				{0, []bool{true, false}, []bool{false, false}, testMCDCUpgrade101, "upgrade"},
				// A 101 without "Connection: Upgrade" is rejected; with both
				// tokens it is accepted.
				{1, []bool{false, true}, []bool{false, false}, testMCDCUpgrade101, "connection"},
			},
		},
	}
}

// textUTF8Traces covers the RFC 6455 §5.6 text-UTF-8 decisions on both
// sides of the wire.
func textUTF8Traces() []decisionTrace {
	return []decisionTrace{
		// ws.go: opcode == OpText && !utf8.Valid(data) (WriteMessage)
		{
			expr:       "opcode == OpText && !utf8.Valid(data)",
			conditions: []string{condOpcodeText, "!utf8.Valid(data)"},
			pairs: []pairTrace{
				// An OpText write of invalid UTF-8 fails; the same bytes
				// as OpBinary succeed (the opcode flips the check on).
				{0, []bool{true, true}, []bool{false, true}, testMCDCTextUTF8, "write-opcode"},
				// An OpText write of invalid UTF-8 fails; valid text
				// succeeds (the validity flips the outcome).
				{1, []bool{true, true}, []bool{true, false}, testMCDCTextUTF8, "write-utf8"},
			},
		},
		// ws.go: msgOp == OpText && !utf8.Valid(out) (Conn.readData)
		{
			expr:       "msgOp == OpText && !utf8.Valid(out)",
			conditions: []string{"msgOp == OpText", "!utf8.Valid(out)"},
			pairs: []pairTrace{
				// Invalid bytes in a text frame fail with 1007; the same
				// bytes in a binary frame are delivered (the opcode flips
				// the check on).
				{0, []bool{true, true}, []bool{false, true}, testMCDCTextUTF8, "read-opcode"},
				// Invalid text fails with 1007; valid text is delivered
				// (the validity flips the outcome).
				{1, []bool{true, true}, []bool{true, false}, testMCDCTextUTF8, "read-utf8"},
			},
		},
	}
}

// serverTraces covers the server session-path decisions.
func serverTraces() []decisionTrace {
	return []decisionTrace{
		// ws.go (Handle): code < closeCodeMin || code > closeCodeMax
		{
			expr:       "code < closeCodeMin || code > closeCodeMax",
			conditions: []string{"code < closeCodeMin", "code > closeCodeMax"},
			pairs: []pairTrace{
				// 999 remapped to 1002, 1000 passed through unchanged.
				{0, []bool{true, false}, []bool{false, false}, testMCDCHandleCloseCode, "belowMin"},
				// 5000 remapped to 1002, 4999 passed through unchanged.
				{1, []bool{false, true}, []bool{false, false}, testMCDCHandleCloseCode, "aboveMax"},
			},
		},
		// ws.go (finishRaw): the deadline gate — a session is created only
		// when the deadline options are zero or the channel implements
		// DeadlineStream.
		{
			expr: "(u.idleTimeout > 0 || u.writeTimeout > 0) " +
				"&& !deadlineCapable(channel)",
			conditions: []string{"u.idleTimeout > 0", "u.writeTimeout > 0", "!deadlineCapable(channel)"},
			pairs: []pairTrace{
				// A bare stream with an idle window is refused; with the
				// window zeroed it is accepted.
				{0, []bool{false, false, true}, []bool{true, false, true}, testMCDCStreamDeadlines, "idle-set"},
				// A bare stream with a write bound is refused; with the
				// bound zeroed it is accepted.
				{1, []bool{false, false, true}, []bool{false, true, true}, testMCDCStreamDeadlines, "write-set"},
				// An idle window over a bare stream is refused; the same
				// window over a deadline-capable stream is accepted.
				{2, []bool{true, false, true}, []bool{true, false, false}, testMCDCStreamDeadlines, "capable"},
			},
		},
		// ws.go (finishRaw, nested sub-decision of the deadline gate):
		// u.idleTimeout > 0 || u.writeTimeout > 0
		{
			expr:       "u.idleTimeout > 0 || u.writeTimeout > 0",
			conditions: []string{"u.idleTimeout > 0", "u.writeTimeout > 0"},
			pairs: []pairTrace{
				// An idle window over a bare stream is refused; with the
				// window zeroed it is accepted.
				{0, []bool{false, false}, []bool{true, false}, testMCDCStreamDeadlines, "idle-set"},
				// A write bound over a bare stream is refused; with the
				// bound zeroed it is accepted.
				{1, []bool{false, false}, []bool{false, true}, testMCDCStreamDeadlines, "write-set"},
			},
		},
	}
}

// compressionTraces covers the permessage-deflate (RFC 7692) RSV state
// machine and the extension negotiation parsing.
func compressionTraces() []decisionTrace {
	return append(append(deflateFrameTraces(), windowBitsTraces()...), unquoteTraces()...)
}

// deflateFrameTraces covers the RSV state machine and the negotiation
// accept/decline decisions.
func deflateFrameTraces() []decisionTrace {
	return []decisionTrace{
		// ws.go (checkRSV): rsv1Set && !fc.deflate
		{
			expr:       "rsv1Set && !fc.deflate",
			conditions: []string{"rsv1Set", "!fc.deflate"},
			pairs: []pairTrace{
				// An RSV1 frame fails on a connection without the extension;
				// a plain frame on the same connection passes.
				{0, []bool{true, true}, []bool{false, true}, testMCDCDeflateRSV, "rsv1"},
				// The same RSV1 frame passes when negotiated and fails when
				// not.
				{1, []bool{true, false}, []bool{true, true}, testMCDCDeflateRSV, "deflate"},
			},
		},
		// ws.go (ReadMessage): frm.compressed && frm.isControl()
		{
			expr:       "frm.compressed && frm.isControl()",
			conditions: []string{"frm.compressed", "frm.isControl()"},
			pairs: []pairTrace{
				// An RSV1 ping is a protocol error; a plain ping is answered
				// with a pong.
				{0, []bool{true, true}, []bool{false, true}, testMCDCDeflateControl, "compressed"},
				// An RSV1 ping is a protocol error; an RSV1 data frame is a
				// valid compressed message.
				{1, []bool{true, true}, []bool{true, false}, testMCDCDeflateControl, "isControl"},
			},
		},
		// ws.go (negotiateCompression): bits != 0 && bits < maxWindowBits
		{
			expr:       "bits != 0 && bits < maxWindowBits",
			conditions: []string{"bits != 0", "bits < maxWindowBits"},
			pairs: []pairTrace{
				// No window demand is accepted; a 10-bit demand is declined.
				{0, []bool{false, true}, []bool{true, true}, testMCDCDeflateServerWindow, "bits"},
				// A 10-bit demand is declined; the full 15-bit demand is
				// accepted.
				{1, []bool{true, true}, []bool{true, false}, testMCDCDeflateServerWindow, "belowMax"},
			},
		},
		// ws.go (verifyCompressionResponse): !offered && len(groups) > 0
		{
			expr:       "!offered && len(groups) > 0",
			conditions: []string{"!offered", "len(groups) > 0"},
			pairs: []pairTrace{
				// An unoffered extension fails the dial; the same response is
				// accepted when the client offered it.
				{0, []bool{true, true}, []bool{false, true}, testMCDCDeflateOffered, "offered"},
				// With no offer, a response without the extension is accepted
				// and one with it fails.
				{1, []bool{true, false}, []bool{true, true}, testMCDCDeflateOffered, "groups"},
			},
		},
	}
}

// windowBitsTraces covers the parseWindowBits decisions: the digit check,
// the leading-zero check, and the range check on max_window_bits values.
func windowBitsTraces() []decisionTrace {
	return []decisionTrace{
		// ws.go (parseWindowBits): ch < '0' || ch > '9'
		{
			expr:       "ch < '0' || ch > '9'",
			conditions: []string{"ch < '0'", "ch > '9'"},
			pairs: []pairTrace{
				// "5" is a digit and fails the range check; "+" is not a
				// digit and fails the numeric check (RFC 7692 §7.1.2: 1*DIGIT).
				{0, []bool{false, false}, []bool{true, false}, testMCDCDeflateWindowBits, "plusSign"},
				// "5" is a digit and fails the range check; "A" is not a
				// digit and fails the numeric check.
				{1, []bool{false, false}, []bool{false, true}, testMCDCDeflateWindowBits, "nonDigit"},
			},
		},
		// ws.go (parseWindowBits): len(value) > 1 && value[0] == '0'
		{
			expr:       "len(value) > 1 && value[0] == '0'",
			conditions: []string{"len(value) > 1", "value[0] == '0'"},
			pairs: []pairTrace{
				// "010" is a leading zero; "0" skips the check and fails the
				// range check instead.
				{0, []bool{true, true}, []bool{false, true}, testMCDCDeflateWindowBits, "leadingZeroLen"},
				// "010" is a leading zero; "10" is a valid value.
				{1, []bool{true, true}, []bool{true, false}, testMCDCDeflateWindowBits, "leadingZeroFirst"},
			},
		},
		// ws.go (parseWindowBits): err != nil || bits < 8 ||
		// bits > maxWindowBits
		{
			expr:       "err != nil || bits < 8 || bits > maxWindowBits",
			conditions: []string{"err != nil", "bits < 8", "bits > maxWindowBits"},
			pairs: []pairTrace{
				// "abc" is not a number; "10" decodes in range.
				{0, []bool{true, false, false}, []bool{false, false, false}, testMCDCDeflateWindowBits, subtestDecode},
				// "7" is below the floor; "10" is in range.
				{1, []bool{false, true, false}, []bool{false, false, false}, testMCDCDeflateWindowBits, subtestBelow},
				// "16" is above the ceiling; "15" is in range.
				{2, []bool{false, false, true}, []bool{false, false, false}, testMCDCDeflateWindowBits, subtestAbove},
			},
		},
		// ws.go (parseWindowBits): err != nil || bits < 8 (nested: Go groups
		// a || b || c as (a || b) || c)
		{
			expr:       "err != nil || bits < 8",
			conditions: []string{"err != nil", "bits < 8"},
			pairs: []pairTrace{
				// "abc" is not a number; "10" decodes in range.
				{0, []bool{true, false}, []bool{false, false}, testMCDCDeflateWindowBits, subtestDecode},
				// "7" is below the floor; "10" is in range.
				{1, []bool{false, true}, []bool{false, false}, testMCDCDeflateWindowBits, subtestBelow},
			},
		},
	}
}

// unquoteTraces covers the RFC 6455 §9.1 quoted-string handling in
// unquoteExtensionValue: the not-quoted short-circuit, the invalid-escape and
// invalid-character checks.
func unquoteTraces() []decisionTrace {
	return []decisionTrace{
		// ws.go (unquoteExtensionValue): the not-quoted / empty short-circuit.
		// value == "" || value[0] != '"'
		{
			expr:       "value == \"\" || value[0] != '\"'",
			conditions: []string{"value == \"\"", "value[0] != '\"'"},
			pairs: []pairTrace{
				// An empty value short-circuits; a single unquoted char
				// returns as-is (the empty condition flips the guard).
				{0, []bool{true, false}, []bool{false, false}, testUnquoteExtValue, "empty-string"},
				// An unquoted token returns as-is; a quoted value is unescaped
				// (the quote condition flips the guard off).
				{1, []bool{false, true}, []bool{false, false}, testUnquoteExtValue, "plain-token"},
			},
		},
		// ws.go (unquoteExtensionValue): invalid-escape check, the outer
		// AND. next != '"' && next != '\\' && (next < 0x20 || next > 0x7e)
		{
			expr:       "next != '\"' && next != '\\\\' && (next < 0x20 || next > 0x7e)",
			conditions: []string{"next != '\"'", "next != '\\\\'", "next < 0x20", "next > 0x7e"},
			pairs: []pairTrace{
				// \\" is a legal escape; a non-quoted, non-backslash escape
				// with a control char is rejected (the quote condition flips
				// the check).
				{0, []bool{true, true, true, false}, []bool{false, true, true, false}, testUnquoteExtValue, "escape-quote"},
				// \\\\ is a legal escape; the same escape with a control char
				// is rejected (the backslash condition flips the check).
				{1, []bool{true, true, true, false}, []bool{true, false, true, false}, testUnquoteExtValue, "escape-backslash"},
				// a control char after a backslash is rejected; a printable
				// char after a backslash is legal (the low condition flips).
				{2, []bool{true, true, true, false}, []bool{true, true, false, false}, testUnquoteExtValue, "escape-control"},
				// a high char after a backslash is rejected; a printable char
				// after a backslash is legal (the high condition flips).
				{3, []bool{true, true, false, true}, []bool{true, true, false, false}, testUnquoteExtValue, "escape-high"},
			},
		},
		// ws.go (unquoteExtensionValue, nested sub-decision): next != '"' && next != '\\'
		{
			expr:       "next != '\"' && next != '\\\\'",
			conditions: []string{"next != '\"'", "next != '\\\\'"},
			pairs: []pairTrace{
				// \\" is legal; a control-char escape is rejected (the quote
				// condition flips the sub-decision off).
				{0, []bool{true, true}, []bool{false, true}, testUnquoteExtValue, "escape-quote"},
				// \\\\ is legal; a control-char escape is rejected (the
				// backslash condition flips the sub-decision off).
				{1, []bool{true, true}, []bool{true, false}, testUnquoteExtValue, "escape-backslash"},
			},
		},
		// ws.go (unquoteExtensionValue, nested sub-decision): next < 0x20 || next > 0x7e
		{
			expr:       "next < 0x20 || next > 0x7e",
			conditions: []string{"next < 0x20", "next > 0x7e"},
			pairs: []pairTrace{
				// a control char after a backslash is rejected; a printable
				// char is legal (the low condition flips the sub-decision on).
				{0, []bool{true, false}, []bool{false, false}, testUnquoteExtValue, "escape-control"},
				// a high char after a backslash is rejected; a printable char
				// is legal (the high condition flips the sub-decision on).
				{1, []bool{false, true}, []bool{false, false}, testUnquoteExtValue, "escape-high"},
			},
		},
		// ws.go (unquoteExtensionValue): invalid-character check, the outer
		// AND. ch != 0x09 && (ch < 0x20 || ch > 0x7e)
		{
			expr:       "ch != 0x09 && (ch < 0x20 || ch > 0x7e)",
			conditions: []string{"ch != 0x09", "ch < 0x20", "ch > 0x7e"},
			pairs: []pairTrace{
				// tab is the one permitted control char; a NUL is rejected
				// (the tab condition flips the check).
				{0, []bool{true, true, false}, []bool{false, true, false}, testUnquoteExtValue, "tab-char"},
				// a NUL is rejected; tab is legal (the low condition flips).
				{1, []bool{true, true, false}, []bool{true, false, false}, testUnquoteExtValue, "control-char"},
				// a high char is rejected; a printable char is legal (the high
				// condition flips).
				{2, []bool{true, false, true}, []bool{true, false, false}, testUnquoteExtValue, "high-char"},
			},
		},
		// ws.go (unquoteExtensionValue, nested sub-decision): ch < 0x20 || ch > 0x7e
		{
			expr:       "ch < 0x20 || ch > 0x7e",
			conditions: []string{"ch < 0x20", "ch > 0x7e"},
			pairs: []pairTrace{
				// a NUL is rejected; a printable char is legal (the low
				// condition flips the sub-decision on).
				{0, []bool{true, false}, []bool{false, false}, testUnquoteExtValue, "control-char"},
				// a high char is rejected; a printable char is legal (the high
				// condition flips the sub-decision on).
				{1, []bool{false, true}, []bool{false, false}, testUnquoteExtValue, "high-char"},
			},
		},
	}
}

// keepaliveTraces covers the keepalive probe/timeout read-loop decisions.
func keepaliveTraces() []decisionTrace {
	return []decisionTrace{
		// ws.go (readNextFrame): retry && c.fc.pulled > 0 — a keepalive
		// timeout that interrupted a frame whose bytes were already pulled
		// is unrecoverable; a clean timeout (nothing pulled) retries.
		{
			expr:       "retry && c.fc.pulled > 0",
			conditions: []string{"retry", "c.fc.pulled > 0"},
			pairs: []pairTrace{
				// A timeout after a partial frame fails the connection; the
				// same bytes with no timeout take the normal error path (the
				// retry condition flips the guard).
				{0, []bool{true, true}, []bool{false, true}, testKeepaliveRetry, "partial-frame"},
				// A timeout after a partial frame fails the connection; a
				// timeout with nothing pulled retries and delivers the frame
				// (the pulled condition flips the guard).
				{1, []bool{true, true}, []bool{true, false}, testKeepaliveRetry, "clean-retry"},
			},
		},
	}
}
