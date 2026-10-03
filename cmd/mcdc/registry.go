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
	testControlFrame        = "TestMCDCControlFrame"
	testIsReadTimeout       = "TestMCDCIsReadTimeout"
	testWriteOpcode         = "TestMCDCWriteMessageOpcode"
	testCloseCodeRange      = "TestMCDCCloseCodeRange"
	testRequireCert         = "TestMCDCRequireClientCert"
	testDialScheme          = "TestMCDCDialScheme"
	testMCDCCloseCode       = "TestMCDCCloseCode"
	testMCDCWebSocketKey    = "TestMCDCWebSocketKey"
	testMCDCSubprotocol     = "TestMCDCSubprotocol"
	testMCDCUpgrade101      = "TestMCDCUpgrade101"
	testMCDCHandleCloseCode = "TestMCDCHandleCloseCode"
	testMCDCTruncateReason  = "TestMCDCTruncateReason"
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

	return append(traces, serverTraces()...)
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
		// ws.go: u.requireClientCert && ClientCert(request) == nil
		{
			expr:       "u.requireClientCert && ClientCert(request) == nil",
			conditions: []string{"u.requireClientCert", "ClientCert(request) == nil"},
			pairs: []pairTrace{
				// WithRequireClientCert without a certificate rejected; the
				// same request accepted without the option.
				{0, []bool{true, true}, []bool{false, true}, testRequireCert, "require"},
				// WithRequireClientCert with a certificate accepted; the
				// same upgrader without a certificate rejected.
				{1, []bool{true, false}, []bool{true, true}, testRequireCert, "cert"},
			},
		},
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
				{0, []bool{true, false}, []bool{false, false}, testMCDCWebSocketKey, "decode"},
				// "QUFB" decodes to 3 bytes: 400. A 16-byte key is
				// accepted: 101.
				{1, []bool{false, true}, []bool{false, false}, testMCDCWebSocketKey, "len"},
			},
		},
		// ws.go: r <= 0x20 || r >= 0x7f || r == '"' (validSubprotocol)
		{
			expr:       `r <= 0x20 || r >= 0x7f || r == '"'`,
			conditions: []string{"r <= 0x20", "r >= 0x7f", `r == '"'`},
			pairs: []pairTrace{
				// A control character is rejected; the printable "a" is
				// accepted.
				{0, []bool{true, false, false}, []bool{false, false, false}, testMCDCSubprotocol, "low"},
				// DEL (0x7f) is rejected; the printable "a" is accepted.
				{1, []bool{false, true, false}, []bool{false, false, false}, testMCDCSubprotocol, "high"},
				// A double quote is rejected; the printable "a" is
				// accepted.
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
