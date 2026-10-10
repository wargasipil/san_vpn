package relay

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/wargasipil/san_vpn/internal/wire"
)

var now = time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)

func newState(t *testing.T, network string) *State {
	t.Helper()
	var s State
	if err := s.Init(netip.MustParsePrefix(network)); err != nil {
		t.Fatal(err)
	}
	return &s
}

// joinRequest is what a node would send for inv with a fresh key.
func joinRequest(t *testing.T, inv Invite) (wire.JoinRequest, wire.Key) {
	t.Helper()
	priv, err := wire.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	secret, err := wire.DecodeSecret(inv.Secret)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public()
	return wire.JoinRequest{Invite: inv.ID, PublicKey: pub, MAC: wire.JoinMAC(secret, inv.ID, pub)}, pub
}

func TestJoinAssignsAddressesInOrder(t *testing.T) {
	s := newState(t, "10.77.0.0/24")
	for i, name := range []string{"home", "office", "vps"} {
		inv, err := s.NewInvite(name, time.Hour, now)
		if err != nil {
			t.Fatal(err)
		}
		req, pub := joinRequest(t, inv)
		n, err := s.Join(req, now)
		if err != nil {
			t.Fatal(err)
		}
		want := netip.AddrFrom4([4]byte{10, 77, 0, byte(i + 1)})
		if n.Name != name || n.IP != want || n.PublicKey != pub {
			t.Fatalf("joined %+v, want %s at %s", n, name, want)
		}
	}
	if len(s.Invites) != 0 {
		t.Fatalf("%d invites left after all were used", len(s.Invites))
	}
}

func TestJoinRefusals(t *testing.T) {
	s := newState(t, "10.77.0.0/24")
	inv, err := s.NewInvite("home", time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := joinRequest(t, inv)

	t.Run("wrong mac", func(t *testing.T) {
		bad := req
		bad.MAC = append([]byte{}, req.MAC...)
		bad.MAC[0] ^= 1
		if _, err := s.Join(bad, now); !errors.Is(err, ErrUnknownInvite) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("someone else's key under a copied mac", func(t *testing.T) {
		bad := req
		other, _ := wire.GenerateKey()
		bad.PublicKey = other.Public()
		if _, err := s.Join(bad, now); !errors.Is(err, ErrUnknownInvite) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("expired", func(t *testing.T) {
		if _, err := s.Join(req, now.Add(2*time.Hour)); !errors.Is(err, ErrUnknownInvite) {
			t.Fatalf("got %v", err)
		}
	})
}

func TestInviteIsSpentAndExpiredOnesArePruned(t *testing.T) {
	s := newState(t, "10.77.0.0/24")
	inv, _ := s.NewInvite("home", time.Hour, now)
	req, _ := joinRequest(t, inv)
	if _, err := s.Join(req, now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Join(req, now); !errors.Is(err, ErrUnknownInvite) {
		t.Fatalf("second use: %v", err)
	}

	if _, err := s.NewInvite("later", time.Minute, now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.NewInvite("again", time.Hour, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if len(s.Invites) != 1 || s.Invites[0].Name != "again" {
		t.Fatalf("expired invite was not pruned: %+v", s.Invites)
	}
}

func TestNamesAreUnique(t *testing.T) {
	s := newState(t, "10.77.0.0/24")
	inv, _ := s.NewInvite("home", time.Hour, now)
	if _, err := s.NewInvite("home", time.Hour, now); err == nil {
		t.Fatal("two invites for one name")
	}
	req, _ := joinRequest(t, inv)
	if _, err := s.Join(req, now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.NewInvite("home", time.Hour, now); err == nil {
		t.Fatal("invited a name that is already a member")
	}
}

func TestOneKeyOneMember(t *testing.T) {
	s := newState(t, "10.77.0.0/24")
	a, _ := s.NewInvite("a", time.Hour, now)
	b, _ := s.NewInvite("b", time.Hour, now)
	req, pub := joinRequest(t, a)
	if _, err := s.Join(req, now); err != nil {
		t.Fatal(err)
	}
	secret, _ := wire.DecodeSecret(b.Secret)
	again := wire.JoinRequest{Invite: b.ID, PublicKey: pub, MAC: wire.JoinMAC(secret, b.ID, pub)}
	if _, err := s.Join(again, now); !errors.Is(err, ErrAlreadyMember) {
		t.Fatalf("same key joined twice: %v", err)
	}
}

func TestRemoveFreesTheAddress(t *testing.T) {
	s := newState(t, "10.77.0.0/24")
	for _, name := range []string{"a", "b"} {
		inv, _ := s.NewInvite(name, time.Hour, now)
		req, _ := joinRequest(t, inv)
		if _, err := s.Join(req, now); err != nil {
			t.Fatal(err)
		}
	}
	if what, err := s.Remove("a"); err != nil || what != "node" {
		t.Fatalf("remove a: %q %v", what, err)
	}
	inv, _ := s.NewInvite("c", time.Hour, now)
	if what, err := s.Remove("c"); err != nil || what != "invite" {
		t.Fatalf("remove invite c: %q %v", what, err)
	}
	inv, _ = s.NewInvite("c", time.Hour, now)
	req, _ := joinRequest(t, inv)
	n, err := s.Join(req, now)
	if err != nil {
		t.Fatal(err)
	}
	if n.IP != netip.MustParseAddr("10.77.0.1") {
		t.Fatalf("c got %s, want the freed 10.77.0.1", n.IP)
	}
	if _, err := s.Remove("nobody"); err == nil {
		t.Fatal("removed a name that does not exist")
	}
}

func TestNetworkFull(t *testing.T) {
	s := newState(t, "10.77.0.0/30") // two hosts: .1 and .2
	for i, name := range []string{"a", "b", "c"} {
		inv, err := s.NewInvite(name, time.Hour, now)
		if err != nil {
			t.Fatal(err)
		}
		req, _ := joinRequest(t, inv)
		_, err = s.Join(req, now)
		if i < 2 && err != nil {
			t.Fatal(err)
		}
		if i == 2 && !errors.Is(err, ErrNetworkFull) {
			t.Fatalf("third join in a /30: %v", err)
		}
	}
}

func TestValidName(t *testing.T) {
	for _, ok := range []string{"home", "office-jkt", "vps1", "a"} {
		if err := ValidName(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "Home", "-a", "a-", "a b", "kantor_pusat", "abcdefghijklmnopqrstuvwxyz0123456"} {
		if ValidName(bad) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestInitRejectsOddNetworks(t *testing.T) {
	var s State
	for _, p := range []string{"fd00::/64", "10.0.0.0/31", "10.0.0.0/4"} {
		if err := s.Init(netip.MustParsePrefix(p)); err == nil {
			t.Errorf("accepted %s", p)
		}
	}
}

// The network's DNS address is every member's, so it is never given to one.
func TestJoinSkipsTheDNSAddress(t *testing.T) {
	s := newState(t, "10.77.0.0/29") // hosts .1 to .6; .6 is the DNS address
	for i := range 6 {
		name := string(rune('a' + i))
		inv, err := s.NewInvite(name, time.Hour, now)
		if err != nil {
			t.Fatal(err)
		}
		req, _ := joinRequest(t, inv)
		n, err := s.Join(req, now)
		if i < 5 && (err != nil || n.IP != netip.AddrFrom4([4]byte{10, 77, 0, byte(i + 1)})) {
			t.Fatalf("join %d: %+v, %v", i, n, err)
		}
		if i == 5 && !errors.Is(err, ErrNetworkFull) {
			t.Fatalf("sixth join got %+v, %v; want the network full, .6 kept for DNS", n, err)
		}
	}
}
