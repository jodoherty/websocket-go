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
