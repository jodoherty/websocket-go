package ws

import (
	"encoding/binary"
	"errors"
	"testing"
)

// TestProtocolViolationCloseFrame pins RFC 6455 §7.1.7 at the Conn level:
// a frame-level protocol violation detected by ReadMessage is answered
// with a 1002 close frame before the transport is torn down — the peer
// sees a close frame, not a bare TCP close — and ReadMessage reports the
// close as a 1002.
func TestProtocolViolationCloseFrame(t *testing.T) {
	cases := []struct {
		name     string
		isClient bool // side reading the bad frame
		data     []byte
		// wantReason is the close frame's reason on the wire: the violation
		// text without the internal error prefix.
		wantReason string
	}{
		{"server reads unmasked frame", false, []byte{0x81, 0x02, 'H', 'i'},
			"frame masking violation"},
		{"client reads masked frame", true,
			[]byte{0x81, 0x85, 0, 1, 2, 3, 'H', 'i', 'X', 'X', 'X'},
			"frame masking violation"},
		{"RSV1 without negotiation", true, []byte{0xc1, 0x00},
			"RSV1 set without permessage-deflate negotiated"},
		{"RSV2 set", true, []byte{0xa1, 0x00}, "reserved bits 2 or 3 set"},
		{"invalid control frame", true, []byte{0x09, 0x00}, "invalid control frame"},
		{"unknown opcode", true, []byte{0x83, 0x00}, "unknown opcode 3"},
		{"frame too large", true, []byte{0x81, 127, 0x01, 0, 0, 0, 0, 0, 0, 0, 0},
			"frame too large"},
		// 1000 + a non-UTF-8 reason byte: §7.1.5 requires the reason be
		// UTF-8, so the close is a protocol violation, not a clean end.
		// The reader is the client side, so the peer's close frame is
		// unmasked (0x88 0x03 | code 1000 | 0xFF).
		{"close reason not valid UTF-8", true, []byte{0x88, 0x03, 0x03, 0xe8, 0xff},
			"close frame with non-UTF-8 reason"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fc := &fakeConn{data: tc.data}
			c := newSession(newRawConn(fc, fc, tc.isClient, 1<<20, 0, 0), nil)
			_, _, err := c.ReadMessage()
			var ce *CloseError
			if err == nil || !errors.As(err, &ce) || ce.Code != StatusProtocolError {
				t.Fatalf("ReadMessage error = %v, want CloseError 1002", err)
			}
			// The peer must see a 1002 close frame, not a bare TCP close.
			codec := newTestCodec(fc.written, !tc.isClient)
			frm, readErr := codec.readFrame()
			if readErr != nil {
				t.Fatalf("no close frame on the wire (%v): % x", readErr, fc.written)
			}
			if frm.opcode != OpClose || len(frm.payload) < closeCodeBytes {
				t.Fatalf("close frame = (opcode %d, % x), want OpClose with a status",
					frm.opcode, frm.payload)
			}
			if code := binary.BigEndian.Uint16(frm.payload); code != StatusProtocolError {
				t.Fatalf("close code = %d, want %d", code, StatusProtocolError)
			}
			if reason := string(frm.payload[closeCodeBytes:]); reason != tc.wantReason {
				t.Fatalf("close reason = %q, want %q", reason, tc.wantReason)
			}
		})
	}
}
