package node

import (
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"

	"golang.zx2c4.com/wireguard/conn"

	"github.com/wargasipil/san_vpn/internal/wire"
)

const (
	// bindBatch is how many packets one receive call may return.
	bindBatch = 16
	// queueSize bounds the packets waiting in each direction. When it is full
	// packets are dropped, as a UDP socket's buffer would; WireGuard and the
	// TCP inside the tunnel already recover from loss, and blocking here
	// would stall WireGuard's own goroutines.
	queueSize = 1024
)

// errNoRelay is what Send returns while the relay connection is down.
var errNoRelay = errors.New("san_vpn: not connected to the relay")

type inbound struct {
	from   wire.Key
	packet []byte
}

// relayBind is WireGuard's network binding, carried by the relay.
//
// An endpoint is a peer's public key, so WireGuard's notion of "where a peer
// is" becomes "which key the relay should deliver to". Roaming, which in
// WireGuard means following a peer to a new address, has nothing to follow:
// the address is the key.
type relayBind struct {
	out       chan []byte
	in        chan inbound
	connected atomic.Bool

	mu        sync.Mutex
	closed    chan struct{}
	endpoints sync.Map // wire.Key -> *endpoint
}

func newRelayBind() *relayBind {
	b := &relayBind{
		out:    make(chan []byte, queueSize),
		in:     make(chan inbound, queueSize),
		closed: make(chan struct{}),
	}
	close(b.closed) // closed until Open
	return b
}

// Open is called by WireGuard when the device comes up, and again whenever it
// rebinds. The port means nothing here.
func (b *relayBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	select {
	case <-b.closed:
	default:
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	closed := make(chan struct{})
	b.closed = closed
	return []conn.ReceiveFunc{b.receiver(closed)}, port, nil
}

func (b *relayBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	select {
	case <-b.closed:
	default:
		close(b.closed)
	}
	return nil
}

func (b *relayBind) receiver(closed chan struct{}) conn.ReceiveFunc {
	return func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		var first inbound
		select {
		case <-closed:
			return 0, net.ErrClosed
		case first = <-b.in:
		}
		n := 0
		fill := func(p inbound) {
			sizes[n] = copy(packets[n], p.packet)
			eps[n] = b.endpoint(p.from)
			n++
		}
		fill(first)
		for n < len(packets) {
			select {
			case p := <-b.in:
				fill(p)
			default:
				return n, nil
			}
		}
		return n, nil
	}
}

func (b *relayBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	e, ok := ep.(*endpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}
	if !b.connected.Load() {
		return errNoRelay
	}
	for _, buf := range bufs {
		select {
		case b.out <- wire.Frame(e.key, buf):
		default:
		}
	}
	return nil
}

// deliver hands a packet from the relay to WireGuard.
func (b *relayBind) deliver(from wire.Key, packet []byte) {
	select {
	case b.in <- inbound{from: from, packet: packet}:
	default:
	}
}

func (b *relayBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	k, err := wire.ParseHexKey(strings.TrimSpace(s))
	if err != nil {
		return nil, err
	}
	return b.endpoint(k), nil
}

func (b *relayBind) endpoint(k wire.Key) *endpoint {
	if e, ok := b.endpoints.Load(k); ok {
		return e.(*endpoint)
	}
	e, _ := b.endpoints.LoadOrStore(k, newEndpoint(k))
	return e.(*endpoint)
}

func (b *relayBind) SetMark(uint32) error { return nil }
func (b *relayBind) BatchSize() int       { return bindBatch }

// endpoint is a peer, addressed by key.
type endpoint struct {
	key wire.Key
	ip  netip.Addr
}

// newEndpoint gives each key a stable, private IPv6 address. WireGuard's
// handshake rate limiter buckets by DstIP; without a distinct address per
// peer, one noisy peer would rate-limit everyone's handshakes.
func newEndpoint(k wire.Key) *endpoint {
	var a [16]byte
	a[0] = 0xfd
	copy(a[1:], k[:15])
	return &endpoint{key: k, ip: netip.AddrFrom16(a)}
}

func (e *endpoint) ClearSrc()           {}
func (e *endpoint) SrcToString() string { return "" }
func (e *endpoint) DstToString() string { return hex.EncodeToString(e.key[:]) }
func (e *endpoint) DstToBytes() []byte  { return e.key[:] }
func (e *endpoint) DstIP() netip.Addr   { return e.ip }
func (e *endpoint) SrcIP() netip.Addr   { return netip.Addr{} }
