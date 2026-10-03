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
	testControlFrame   = "TestMCDCControlFrame"
	testIsReadTimeout  = "TestMCDCIsReadTimeout"
	testWriteOpcode    = "TestMCDCWriteMessageOpcode"
	testCloseCodeRange = "TestMCDCCloseCodeRange"
	testClosePayload   = "TestMCDCCloseCodePayload"
	testRequireCert    = "TestMCDCRequireClientCert"
	testDialScheme     = "TestMCDCDialScheme"
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
// handshake-path decisions.
func registry() []decisionTrace {
	traces := frameTraces()

	return append(traces, handshakeTraces()...)
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
		// ws.go: code != StatusNoStatusReceived && code != StatusAbnormalClosure
		{
			expr:       "code != StatusNoStatusReceived && code != StatusAbnormalClosure",
			conditions: []string{"code != StatusNoStatusReceived", "code != StatusAbnormalClosure"},
			pairs: []pairTrace{
				// 1005 carries no payload, 1000 carries code + reason.
				{0, []bool{false, true}, []bool{true, true}, testClosePayload, "noStatusReceived"},
				// 1006 carries no payload, 1000 carries code + reason.
				{1, []bool{true, false}, []bool{true, true}, testClosePayload, "abnormalClosure"},
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
	}
}
