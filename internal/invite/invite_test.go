package invite_test

import (
	"strings"
	"testing"

	"github.com/wargasipil/san_vpn/internal/invite"
	"github.com/wargasipil/san_vpn/internal/wire"
)

func sample(t *testing.T) invite.Invite {
	t.Helper()
	k, err := wire.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return invite.Invite{
		URL:      "https://abc123-8443.asse.devtunnels.ms",
		RelayKey: k.Public(),
		ID:       "0011223344556677",
		Secret:   "c2VjcmV0",
		Name:     "home",
	}
}

func TestRoundTrip(t *testing.T) {
	want := sample(t)
	blob, err := invite.Encode(want)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(blob, invite.Prefix) {
		t.Fatalf("%q does not start with %q", blob, invite.Prefix)
	}
	got, err := invite.Decode(blob)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("round trip gave %+v, want %+v", got, want)
	}
}

// Pasting picks up whitespace and newlines; that must not break it.
func TestDecodeToleratesPaste(t *testing.T) {
	blob, err := invite.Encode(sample(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{" " + blob, blob + "\n", "\t" + blob + "  \r\n"} {
		if _, err := invite.Decode(s); err != nil {
			t.Fatalf("Decode(%q): %v", s, err)
		}
	}
}

func TestDecodeRejectsJunk(t *testing.T) {
	cases := map[string]string{
		"empty":         "",
		"no prefix":     "aGVsbG8",
		"not base64":    invite.Prefix + "!!!!",
		"not json":      invite.Prefix + "aGVsbG8",
		"empty object":  invite.Prefix + "e30", // {}
		"san_tunnels's": "san1_e30",
	}
	for name, s := range cases {
		if _, err := invite.Decode(s); err == nil {
			t.Errorf("%s: Decode(%q) succeeded", name, s)
		}
	}
}

func TestEncodeRequiresRelayKey(t *testing.T) {
	i := sample(t)
	i.RelayKey = wire.Key{}
	if _, err := invite.Encode(i); err == nil {
		t.Fatal("encoded an invite that pins no relay")
	}
}
