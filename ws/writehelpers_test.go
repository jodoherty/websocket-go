package ws

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
)

// decodeWrittenFrames decodes every frame the connection wrote to fc, in
// order. The connection is a server-side one, so its frames are unmasked.
func decodeWrittenFrames(t *testing.T, fc *fakeConn) []frame {
	t.Helper()
	codec := newTestCodec(fc.written, true)
	var out []frame
	for {
		frm, err := codec.readFrame()
		if err != nil {
			break
		}

		out = append(out, frm)
	}

	return out
}

// TestWriteHelpersWireFormat pins the wire encoding of the natural-typed
// write helpers: WriteText emits a text frame, WriteBinary a binary frame
// with the bytes untouched, WriteJSON a text frame carrying the JSON
// encoding; a failed WriteJSON marshal writes nothing and leaves the
// connection open.
func TestWriteHelpersWireFormat(t *testing.T) {
	t.Parallel()

	fc := &fakeConn{}
	c := newConn(fc, fc, false, 1<<20, 0, 0)

	err := c.WriteText("héllo ☃")
	if err != nil {
		t.Fatalf("WriteText: %v", err)
	}
	err = c.WriteBinary([]byte{0x00, 0xff, 0x01})
	if err != nil {
		t.Fatalf("WriteBinary: %v", err)
	}
	err = c.WriteJSON(map[string]int{"w": 42})
	if err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}

	frames := decodeWrittenFrames(t, fc)
	if len(frames) != 3 {
		t.Fatalf("wrote %d frames, want 3", len(frames))
	}
	if op, payload := frames[0].opcode, frames[0].payload; op != OpText || string(payload) != "héllo ☃" {
		t.Fatalf("WriteText frame = (%d, %q), want (1, \"héllo ☃\")", op, payload)
	}
	binOp, binPayload := frames[1].opcode, frames[1].payload
	wantBin := []byte{0x00, 0xff, 0x01}
	if binOp != OpBinary || !bytes.Equal(binPayload, wantBin) {
		t.Fatalf("WriteBinary frame = (%d, %x), want (2, %x)", binOp, binPayload, wantBin)
	}
	if frames[2].opcode != OpText {
		t.Fatalf("WriteJSON frame opcode = %d, want OpText", frames[2].opcode)
	}
	var decoded map[string]int
	unmarshalErr := json.Unmarshal(frames[2].payload, &decoded)
	if unmarshalErr != nil || decoded["w"] != 42 {
		t.Fatalf("WriteJSON payload = %q (%v), want {\"w\":42}", frames[2].payload, unmarshalErr)
	}
}

// TestWriteJSONMarshalFailure pins that a value json.Marshal cannot encode
// fails before anything reaches the wire: the error carries errBadJSON, no
// frame is written, and the connection stays open.
func TestWriteJSONMarshalFailure(t *testing.T) {
	t.Parallel()

	fc := &fakeConn{}
	c := newConn(fc, fc, false, 1<<20, 0, 0)

	err := c.WriteJSON(func() {})
	if err == nil {
		t.Fatal("WriteJSON of a func accepted, want marshal error")
	}
	if !errors.Is(err, errBadJSON) {
		t.Fatalf("error = %v, want errBadJSON", err)
	}
	if len(fc.written) != 0 {
		t.Fatalf("marshal failure wrote %d bytes; nothing may reach the wire", len(fc.written))
	}
	if c.Closed() {
		t.Fatal("marshal failure closed the connection; it should stay open")
	}
	err = c.WriteText("still open")
	if err != nil {
		t.Fatalf("write after failed marshal: %v, want success", err)
	}
}
