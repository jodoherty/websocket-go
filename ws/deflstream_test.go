package ws

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

// TestDecompressStreamTable replays the exhaustive permessage-deflate
// data table (model/gen/deflate_stream.py, doc/DEFLATE-STREAM.md)
// against the live decompress pipeline: every 1- and 2-byte buffer.
//
// Each row carries two classifications:
//   - the implementation layer: the reference's model of what the
//     decompress loop does (status + payload/fault) -- asserted hard;
//     a mismatch is a model bug or an implementation bug;
//   - the spec layer: the RFC 7692 7.2.1 shape of the buffer
//     (complete/prefix/malformed) -- a COMPLETE buffer must be
//     accepted with the RFC payload (asserted hard); a
//     prefix/malformed buffer that is nevertheless accepted is a
//     permitted leniency (RFC 7692 has no decompression-failure
//     clause), counted in the warning ledger and checked against the
//     allowlist, like the MBT runners.

func TestDecompressStreamTable(t *testing.T) {
	t.Parallel()
	table, err := os.ReadFile("testdata/deflstream/oracle.json")
	if err != nil {
		t.Fatalf("read table: %v", err)
	}
	var tbl struct {
		MaxLen int         `json:"maxLen"`
		MaxMsg int         `json:"maxMsg"`
		Rows   [][5]string `json:"rows"`
	}
	err = json.Unmarshal(table, &tbl)
	if err != nil {
		t.Fatalf("parse table: %v", err)
	}
	if tbl.MaxLen == 0 || tbl.MaxMsg == 0 || len(tbl.Rows) == 0 {
		t.Fatalf("table is empty or malformed: %+v", tbl)
	}
	allowed := loadMBTNotes(t, "testdata/deflstream/NOTES.json")
	ledger := newMBTLedger()
	// The check runs after every subtest has finished (parallel subtests
	// complete before the parent's cleanup).
	t.Cleanup(func() { checkMBTWarnings(t, ledger, allowed) })
	for _, row := range tbl.Rows {
		t.Run(row[0], func(t *testing.T) {
			t.Parallel()
			runDeflStreamRow(t, row, tbl.MaxMsg, ledger)
		})
	}
}

func runDeflStreamRow(t *testing.T, row [5]string, maxMsg int, ledger *mbtLedger) {
	t.Helper()
	buf, err := hex.DecodeString(row[0])
	if err != nil {
		t.Fatalf("row hex: %v", err)
	}
	conn := newRawConn(&fakeConn{}, &fakeConn{}, false, int64(maxMsg), 0, 0)
	out, derr := conn.decompress(buf)

	// The implementation layer: exactly what the reference model claims.
	switch row[1] {
	case "ok":
		if derr != nil {
			t.Fatalf("want ok, got error: %v", derr)
		}
		want, _ := hex.DecodeString(row[2])
		if !bytes.Equal(out, want) {
			t.Fatalf("payload: got %x, want %x", out, want)
		}
	case "size":
		if derr == nil || !errors.Is(derr, errMessageTooBig) {
			t.Fatalf("want the size error, got %v", derr)
		}
	default: // eof, corrupt
		if derr == nil || !errors.Is(derr, errProtocol) {
			t.Fatalf("want a protocol error, got %v", derr)
		}
	}

	// The spec layer: the RFC 7692 7.2.1 shape.
	if row[3] == "complete" {
		if derr != nil {
			t.Fatalf("an RFC-compliant buffer was rejected: %v", derr)
		}
		want, _ := hex.DecodeString(row[4])
		if !bytes.Equal(out, want) {
			t.Fatalf("payload: got %x, want %x", out, want)
		}
		return
	}
	if derr == nil {
		// A prefix or malformed buffer the implementation accepts: a
		// MAY leniency (RFC 7692 assigns no failure handling).
		ledger.add("MAY:deflate-accept:"+row[4], row[0],
			row[3]+" "+row[4])
	}
}

// TestDecompressCompliantWires pins the receiver's semantics on the
// RFC 7692 7.2.1 compliant shape itself -- a complete byte-aligned
// stream plus the truncated empty stored header's first octet
// (0x00 or 0x01; the RFC leaves the appended block's BFINAL
// unspecified) -- which the exhaustive table cannot contain (the
// domain is 1-2 bytes; the minimal compliant buffer is three
// bytes). The reference classifier's W7 (model/gen/deflate.py)
// asserts the same shape against the part-1 reference; this pins the
// implementation's side of the bridge. The stored-block family keeps
// the pin table-independent: the RFC's literal fixed table and the
// implementation's canonical one decode fixed blocks differently
// (the documented 3.2.6 deviation), so a compliant fixed-block wire
// is not a payload-level bridge. The fixed-family group pins that
// deviation on the implementation's side instead: both wires carry
// the RFC-literal empty stream plus the compliant tail (spec
// payload: empty) while the canonical table delivers 0x10 and five
// 0x10s respectively.
func TestDecompressCompliantWires(t *testing.T) {
	t.Parallel()
	// stored block: the 5-byte aligned header (01, the two LEN
	// bytes little-endian, the two NLEN bytes) plus the data octets.
	cases := []struct {
		name string
		wire string
		want string
	}{{
		"stored-empty-tail-zero", "010000FFFF00", ""},
		{"stored-empty-tail-one", "010000FFFF01", ""},
		{"stored-A-tail-zero", "010100FEFF4100", "41"},
		{"stored-A-tail-one", "010100FEFF4101", "41"},
		// The same streams without the tail octet (the spec class
		// names tail-missing; the receiver accepts them -- the
		// table's MAY:deflate-accept:tail-missing ledger entry).
		{"stored-empty-no-tail", "010000FFFF", ""},
		{"stored-A-no-tail", "010100FEFF41", "41"},
		// The fixed-family compliant wires: the RFC-literal empty
		// final fixed block (13 00: EOB = 7-bit code 32, ending at
		// bit 10 with zero padding) plus the tail octet. Spec
		// payload: empty on both. The canonical table deviates
		// (3.2.6): 13 00 reads as literal 16 plus a non-final EOB
		// (the completion tail finishes the stream), and the 0x01
		// tail octet reads as length 4 / distance 1 (five 0x10)
		// plus the final EOB.
		{"fixed-empty-tail-zero", "130000", "10"},
		{"fixed-empty-tail-one", "130001", "1010101010"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			wire, err := hex.DecodeString(tc.wire)
			if err != nil {
				t.Fatalf("wire hex: %v", err)
			}
			want, _ := hex.DecodeString(tc.want)
			conn := newRawConn(&fakeConn{}, &fakeConn{}, false, 6, 0, 0)
			out, derr := conn.decompress(wire)
			if derr != nil {
				t.Fatalf("an RFC-compliant (or tail-missing) buffer was rejected: %v", derr)
			}
			if !bytes.Equal(out, want) {
				t.Fatalf("payload: got %x, want %x", out, want)
			}
		})
	}
}
