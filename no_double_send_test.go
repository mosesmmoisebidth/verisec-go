package verisec

import (
	"bufio"
	"context"
	"net"
	"strings"
	"sync/atomic"
	"testing"
)

// Go's net/http re-sends an idempotent GET by itself if a kept-alive connection drops after the request went
// out, which would charge a call twice. The transport sends GETs with a body that cannot be replayed, so
// net/http will not re-send them. This drops the connection right after the server receives the GET and asserts
// the server saw it only once and the client got an error (not a silent second call). A POST is checked too.
func TestGetIsSentExactlyOnceOnMidFlightDrop(t *testing.T) {
	assertSentOnce(t, "GET /v2/bin/", func(c *Client) error {
		_, err := c.Bin.Lookup(context.Background(), "424242")
		return err
	})
}

func TestPostIsNeverReSent(t *testing.T) {
	assertSentOnce(t, "POST /v2/cards/check", func(c *Client) error {
		_, err := c.Cards.Check(context.Background(), &CardCheckParams{Number: "4242424242424242"})
		return err
	})
}

// assertSentOnce runs a server that answers 200 to everything, except the first request whose line starts with
// dropLine: that connection is read then closed with no answer. It warms up a pooled connection, runs call, and
// checks the dropped request reached the server exactly once and call returned an error.
func assertSentOnce(t *testing.T, dropLine string, call func(*Client) error) {
	t.Helper()
	var hits int32
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveDrop(conn, &hits, dropLine)
		}
	}()

	client, err := New("sk_test_nodouble", WithBaseURL("http://"+ln.Addr().String()), WithMaxRetries(3))
	if err != nil {
		t.Fatal(err)
	}
	// warm up a kept-alive connection with a call that is not the dropped one
	if strings.HasPrefix(dropLine, "GET") {
		if _, err := client.Cards.Check(context.Background(), &CardCheckParams{Number: "4242424242424242"}); err != nil {
			t.Fatalf("warmup: %v", err)
		}
	} else {
		if _, err := client.Bin.Lookup(context.Background(), "424242"); err != nil {
			t.Fatalf("warmup: %v", err)
		}
	}

	if err := call(client); err == nil {
		t.Fatalf("expected an error from the dropped call, got nil (the call was silently re-sent)")
	}
	if n := atomic.LoadInt32(&hits); n != 1 {
		t.Fatalf("%q reached the server %d times, want exactly 1", dropLine, n)
	}
}

func serveDrop(conn net.Conn, hits *int32, dropLine string) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		var contentLength int
		for {
			h, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			h = strings.TrimRight(h, "\r\n")
			if h == "" {
				break
			}
			if n, ok := strings.CutPrefix(strings.ToLower(h), "content-length:"); ok {
				contentLength = atoiSafe(strings.TrimSpace(n))
			}
		}
		for i := 0; i < contentLength; i++ {
			if _, err := reader.ReadByte(); err != nil {
				return
			}
		}
		if strings.HasPrefix(line, dropLine) && atomic.AddInt32(hits, 1) == 1 {
			return // received, then the connection closes with no answer
		}
		body := []byte(`{"object":"ok"}`)
		resp := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " +
			itoa(len(body)) + "\r\n\r\n"
		if _, err := conn.Write(append([]byte(resp), body...)); err != nil {
			return
		}
	}
}

func atoiSafe(s string) int {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return n
		}
		n = n*10 + int(r-'0')
	}
	return n
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
