// Package invite carries everything a new node needs to join, in one pasteable
// string.
//
// Joining by hand would mean copying a relay URL, the relay's public key and a
// one-time secret without mistyping any of them, and the relay key is the one
// people would skip -- which is exactly the one that lets the node tell the
// real relay from an impostor. Moving all of them together makes the safe path
// the easy one.
package invite

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/wargasipil/san_vpn/internal/wire"
)

// Prefix marks the string as ours. A fixed, searchable prefix is what lets
// secret scanners recognise one on sight, and an invite is a credential until
// it is used.
const Prefix = "sanvpn1_"

// Invite is the payload.
type Invite struct {
	// URL is the relay's base URL, http(s) or ws(s).
	URL string `json:"url"`
	// RelayKey is the relay's public key. The node checks the relay's proof
	// against it on every connection, so the invite pins the relay.
	RelayKey wire.Key `json:"relay_key"`
	// ID names the invite on the relay. It is not secret.
	ID string `json:"id"`
	// Secret proves the holder was invited. It never crosses the wire; the
	// join request carries a MAC made with it instead.
	Secret string `json:"secret"`
	// Name is the node name the relay will register. Informational: the relay
	// decides, from its own record of the invite.
	Name string `json:"name,omitempty"`
}

// Encode renders an invite as one pasteable token.
func Encode(i Invite) (string, error) {
	if err := i.validate(); err != nil {
		return "", err
	}
	b, err := json.Marshal(i)
	if err != nil {
		return "", fmt.Errorf("encode invite: %w", err)
	}
	return Prefix + base64.RawURLEncoding.EncodeToString(b), nil
}

// Decode parses one, tolerating the whitespace a copy-paste picks up.
func Decode(s string) (Invite, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, Prefix) {
		return Invite{}, fmt.Errorf("not a san_vpn invite: expected it to start with %q", Prefix)
	}
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(s, Prefix))
	if err != nil {
		return Invite{}, fmt.Errorf("decode invite: %w", err)
	}
	var i Invite
	if err := json.Unmarshal(b, &i); err != nil {
		return Invite{}, fmt.Errorf("parse invite: %w", err)
	}
	if err := i.validate(); err != nil {
		return Invite{}, err
	}
	return i, nil
}

func (i Invite) validate() error {
	switch {
	case i.URL == "":
		return errors.New("invite carries no relay url")
	case i.RelayKey.IsZero():
		return errors.New("invite carries no relay key")
	case i.ID == "" || i.Secret == "":
		return errors.New("invite carries no id or secret")
	}
	return nil
}
