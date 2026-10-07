package wire

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/coder/websocket"
)

const (
	// KeepaliveInterval and KeepaliveTimeout: both ends ping, so each notices
	// a vanished peer -- a laptop that slept, a dropped dev tunnel -- within
	// about forty seconds, and fronts that reap idle connections keep seeing
	// traffic.
	KeepaliveInterval = 25 * time.Second
	KeepaliveTimeout  = 15 * time.Second
)

// Keepalive pings until the connection fails, then closes it so the reader
// unblocks. It must run beside a reader: coder/websocket processes pongs on
// the read path, so a ping on an unread connection always times out.
func Keepalive(ctx context.Context, c *websocket.Conn, interval, timeout time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			pctx, cancel := context.WithTimeout(ctx, timeout)
			err := c.Ping(pctx)
			cancel()
			if err != nil {
				// CloseNow, not Close: the peer is not answering, so waiting
				// for its half of a close handshake only delays the reader.
				_ = c.CloseNow()
				return
			}
		}
	}
}

// WriteMessage sends one control message.
func WriteMessage(ctx context.Context, c *websocket.Conn, m Message) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return c.Write(ctx, websocket.MessageText, b)
}

// ReadMessage reads one control message, refusing a data message in its place.
func ReadMessage(ctx context.Context, c *websocket.Conn) (Message, error) {
	typ, b, err := c.Read(ctx)
	if err != nil {
		return Message{}, err
	}
	if typ != websocket.MessageText {
		return Message{}, errors.New("expected a control message")
	}
	return ParseMessage(b)
}

// ParseMessage decodes the body of a text message.
func ParseMessage(b []byte) (Message, error) {
	var m Message
	if err := json.Unmarshal(b, &m); err != nil {
		return Message{}, fmt.Errorf("malformed control message: %w", err)
	}
	return m, nil
}
