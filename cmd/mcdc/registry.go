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
	testMCDCDeflateRSV          = "TestMCDCDeflateRSV"
	testMCDCDeflateControl      = "TestMCDCDeflateControl"
	testMCDCDeflateServerWindow = "TestMCDCDeflateServerWindow"
	testMCDCDeflateClientWindow = "TestMCDCDeflateClientWindow"
	testMCDCDeflateOffered      = "TestMCDCDeflateOffered"
	testMCDCDeflateWindowBits   = "TestMCDCDeflateWindowBits"
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
	condOpcodeText = "opcode == OpText"
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
			conditions: []string{condOpcodeText, "opcode == OpBinary", "opcode == OpContinuation"},
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
			conditions: []string{condOpcodeText, "opcode == OpBinary"},
			pairs: []pairTrace{
				// A text frame goes out; a close frame is refused (the
				// text condition flips the sub-decision on).
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
	}
}

// compressionTraces covers the permessage-deflate (RFC 7692) RSV state
// machine and the extension negotiation parsing.
func compressionTraces() []decisionTrace {
	return append(deflateFrameTraces(), windowBitsTraces()...)
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
		// ws.go (verifyCompressionResponse): bits != 0 && bits <
		// maxWindowBits (the client-side twin of the server decision above;
		// identical expression, second occurrence in source order).
		{
			expr:       "bits != 0 && bits < maxWindowBits",
			conditions: []string{"bits != 0", "bits < maxWindowBits"},
			pairs: []pairTrace{
				// No window cap is accepted; a 10-bit cap fails the dial.
				{0, []bool{false, true}, []bool{true, true}, testMCDCDeflateClientWindow, "bits"},
				// A 10-bit cap fails the dial; the full 15-bit cap is
				// accepted.
				{1, []bool{true, true}, []bool{true, false}, testMCDCDeflateClientWindow, "belowMax"},
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

// windowBitsTraces covers the parseWindowBits decisions: the leading-zero
// check and the range check on max_window_bits values.
func windowBitsTraces() []decisionTrace {
	return []decisionTrace{
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
