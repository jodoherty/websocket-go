package ws

import (
	"bufio"
	"bytes"
	"errors"
	"net"
	"strings"
	"testing"
)

// TestReadHandshakeResponseHead pins the bounded handshake-response head read
// (the client's defense against a header-flood memory DoS): a normal response
// is returned whole with the reader left at the first frame, an over-limit
// header set is rejected, an over-long single line is rejected, and a
// truncated set is rejected.
func TestReadHandshakeResponseHead(t *testing.T) {
	t.Parallel()

	const normal = "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: abc\r\n" +
		"\r\n"

	t.Run("normal: head returned, reader at first frame", func(t *testing.T) {
		t.Parallel()
		// Feed the 101 plus a first frame so we can prove the reader is
		// positioned right after the terminating blank line.
		src := normal + "FIRST-FRAME-BYTES\n"
		reader := bufio.NewReaderSize(bytes.NewReader([]byte(src)), bufSize)
		head, err := readHandshakeResponseHead(reader)
		if err != nil {
			t.Fatalf("read head: %v", err)
		}
		if string(head) != normal {
			t.Fatalf("head = %q, want exactly the status line + headers + blank line", head)
		}
		rest, readErr := reader.ReadSlice('\n')
		if readErr != nil {
			t.Fatalf("read first frame after head: %v", readErr)
		}
		if string(rest) != "FIRST-FRAME-BYTES\n" {
			t.Fatalf("frame after head = %q, want FIRST-FRAME-BYTES (reader mispositioned)", rest)
		}
	})

	t.Run("over-limit: header set beyond the cap is rejected", func(t *testing.T) {
		t.Parallel()
		// A header line repeated enough times to exceed the cap. Each line
		// is small; the accumulation trips handshakeHeaderLimit.
		var buf bytes.Buffer
		buf.WriteString("HTTP/1.1 200 OK\r\n")
		for buf.Len() < handshakeHeaderLimit {
			buf.WriteString("X-Pad: 00000000000000000000\r\n")
		}
		reader := bufio.NewReaderSize(bytes.NewReader(buf.Bytes()), bufSize)
		_, err := readHandshakeResponseHead(reader)
		if err == nil {
			t.Fatal("over-limit headers accepted, want an error")
		}
		if !errors.Is(err, errHandshakeFailed) {
			t.Fatalf("error = %v, want errors.Is(errHandshakeFailed)", err)
		}
	})

	t.Run("over-long-line: a single line past the buffer is rejected", func(t *testing.T) {
		t.Parallel()
		// A single header line longer than the reader's buffer: ReadSlice
		// reports ErrBufferFull and the head read rejects it.
		line := "X-Huge: " + strings.Repeat("a", 500) + "\r\n" // longer than the 64-byte buffer below
		src := "HTTP/1.1 200 OK\r\n" + line
		reader := bufio.NewReaderSize(bytes.NewReader([]byte(src)), 64)
		_, err := readHandshakeResponseHead(reader)
		if err == nil {
			t.Fatal("over-long header line accepted, want an error")
		}
		if !errors.Is(err, errHandshakeFailed) {
			t.Fatalf("error = %v, want errors.Is(errHandshakeFailed)", err)
		}
	})

	t.Run("truncated: no terminating blank line is rejected", func(t *testing.T) {
		t.Parallel()
		src := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n" // no blank line, then EOF
		reader := bufio.NewReaderSize(bytes.NewReader([]byte(src)), bufSize)
		_, err := readHandshakeResponseHead(reader)
		if err == nil {
			t.Fatal("truncated headers accepted, want an error")
		}
		if !errors.Is(err, errHandshakeFailed) {
			t.Fatalf("error = %v, want errors.Is(errHandshakeFailed)", err)
		}
	})
}

// TestDialRejectsHeaderFlood pins the bound end to end: a hostile server that
// streams an unbounded number of handshake headers is refused (and the
// connection closed) once the header set exceeds the cap, instead of being
// accumulated without limit. It must resolve quickly, not hang.
func TestDialRejectsHeaderFlood(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()

	done := make(chan error, 1)
	go func() {
		conn, acceptErr := l.Accept()
		if acceptErr != nil {
			done <- acceptErr

			return
		}
		defer conn.Close()
		// Drain the request (read to the end of the header set).
		br := bufio.NewReader(conn)
		for {
			line, readErr := br.ReadString('\n')
			if readErr != nil || strings.TrimSpace(line) == "" {
				break
			}
			_ = line
		}
		// Stream headers until the client's cap is exceeded, then stop.
		// Writes fail once the client has hung up; stop on the first error.
		_, wErr := conn.Write([]byte("HTTP/1.1 200 OK\r\n"))
		if wErr != nil {
			done <- wErr

			return
		}
		for range 1 << 20 { // far more than the cap in lines
			_, wErr = conn.Write([]byte("X-Flood: 00000000000000000000\r\n"))
			if wErr != nil {
				done <- wErr

				return
			}
		}
		done <- nil
	}()

	dialErr := dialRejectsFlood(t, l.Addr().String())
	if dialErr == nil {
		t.Fatal("Dial succeeded against a header flood, want a bounded rejection")
	}
	if !errors.Is(dialErr, errHandshakeFailed) {
		t.Fatalf("dial error = %v, want errors.Is(errHandshakeFailed)", dialErr)
	}
	// Drain the server goroutine so it cannot leak; its result is
	// unconstrained (it may have finished writing or hit a reset).
	<-done
}

// dialRejectsFlood dials the flood server with a timeout guard so a regression
// that removes the bound (and lets the client accumulate forever) fails the
// test instead of hanging it.
func dialRejectsFlood(t *testing.T, addr string) error {
	t.Helper()
	errCh := make(chan error, 1)
	go func() {
		_, err := Dial(t.Context(), "ws://"+addr+"/ws")
		errCh <- err
	}()
	select {
	case err := <-errCh:
		return err
	case <-t.Context().Done():
		t.Fatal("Dial did not return: the header-flood bound is not enforced")

		return nil
	}
}
