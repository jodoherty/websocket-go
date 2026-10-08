package ws

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestDecompressOracle pins the implementation's decompress() to the
// committed RSV1-model oracle (model/gen/deflate_oracle.json): the table
// is the receiver's decompression semantics on every wire the model can
// accumulate (all sequences of alphabet payloads up to the limit),
// generated from this same code. If decompress() ever changes, this test
// fails -- regenerate the oracle (the model's W6 self-check then pins
// the Python emulator to it), and regenerate the traces if the
// behavior the model depends on changed.
func TestDecompressOracle(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(filepath.Join("..", "model", "gen", "deflate_oracle.json"))
	if err != nil {
		t.Fatalf("read oracle: %v", err)
	}
	var rows []struct {
		Wire string `json:"wire"`
		Out  string `json:"out"`
		OK   bool   `json:"ok"`
	}
	err = json.Unmarshal(raw, &rows)
	if err != nil {
		t.Fatalf("parse oracle: %v", err)
	}
	if len(rows) == 0 {
		t.Fatal("oracle is empty")
	}

	conn := newRawConn(&fakeConn{}, &fakeConn{}, false, 1<<20, 0, 0)
	conn.applyCompression()

	for _, r := range rows {
		wire := hexToBytes(r.Wire)
		got, err := conn.decompress(wire)
		ok := err == nil
		if ok != r.OK {
			t.Fatalf("wire %s: decompress ok=%v, oracle ok=%v (%v)", r.Wire, ok, r.OK, err)
		}
		if ok && hexOf(got) != r.Out {
			t.Fatalf("wire %s: output %s, oracle %s", r.Wire, hexOf(got), r.Out)
		}
	}
}

func hexToBytes(s string) []byte {
	b := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		b[i/2] = hexNibble(s[i])<<4 | hexNibble(s[i+1])
	}
	return b
}

func hexNibble(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	default:
		return c - 'a' + 10
	}
}

func hexOf(b []byte) string {
	const digits = "0123456789abcdef"
	s := make([]byte, 0, len(b)*2)
	for _, x := range b {
		s = append(s, digits[x>>4], digits[x&0xf])
	}
	return string(s)
}
