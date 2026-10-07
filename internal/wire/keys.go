// Package wire is the protocol the relay and its nodes speak, kept in one place
// so neither side can drift from the other.
//
// It covers three things: the X25519 keys that name every party, the framing
// of WireGuard packets inside WebSocket messages, and the handshake a node and
// the relay use to prove those keys to each other.
package wire

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

// KeySize is the length of every key: X25519, as WireGuard uses.
const KeySize = 32

// Key is a private or public X25519 key.
//
// One key type for both halves keeps the call sites short; which half a value
// holds is in its name. A node's public key is its identity everywhere: in the
// relay's member list, in the frames the relay forwards, and as the WireGuard
// peer key on every other node. There is no second identifier to keep in sync.
type Key [KeySize]byte

// GenerateKey returns a new private key, clamped the way WireGuard clamps its
// own, so the same key works for the relay handshake and for the tunnel.
func GenerateKey() (Key, error) {
	var k Key
	if _, err := rand.Read(k[:]); err != nil {
		return Key{}, fmt.Errorf("generate key: %w", err)
	}
	k[0] &= 248
	k[31] = (k[31] & 127) | 64
	return k, nil
}

// Public derives the public key of a private key.
func (k Key) Public() Key {
	var pub Key
	b, err := curve25519.X25519(k[:], curve25519.Basepoint)
	if err != nil {
		// Only a low-order point can fail, and the basepoint is not one.
		panic(fmt.Sprintf("derive public key: %v", err))
	}
	copy(pub[:], b)
	return pub
}

// Shared is the Diffie-Hellman secret between this private key and a peer's
// public key. It fails for a low-order peer key, which would make the secret
// predictable to anyone.
func (k Key) Shared(peer Key) ([]byte, error) {
	b, err := curve25519.X25519(k[:], peer[:])
	if err != nil {
		return nil, fmt.Errorf("key agreement: %w", err)
	}
	return b, nil
}

// IsZero reports whether the key is unset.
func (k Key) IsZero() bool { return k == Key{} }

// String is standard base64, the form `wg` prints and people recognise.
func (k Key) String() string { return base64.StdEncoding.EncodeToString(k[:]) }

// Hex is the form WireGuard's configuration protocol (UAPI) expects.
func (k Key) Hex() string { return hex.EncodeToString(k[:]) }

// ParseKey reads the base64 form.
func ParseKey(s string) (Key, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return Key{}, fmt.Errorf("parse key: %w", err)
	}
	return keyFromBytes(b)
}

// ParseHexKey reads the UAPI form.
func ParseHexKey(s string) (Key, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return Key{}, fmt.Errorf("parse key: %w", err)
	}
	return keyFromBytes(b)
}

func keyFromBytes(b []byte) (Key, error) {
	if len(b) != KeySize {
		return Key{}, fmt.Errorf("parse key: %d bytes, want %d", len(b), KeySize)
	}
	var k Key
	copy(k[:], b)
	return k, nil
}

// MarshalText makes keys read naturally in JSON files.
func (k Key) MarshalText() ([]byte, error) { return []byte(k.String()), nil }

// UnmarshalText is the inverse of MarshalText.
func (k *Key) UnmarshalText(b []byte) error {
	if len(b) == 0 {
		*k = Key{}
		return nil
	}
	parsed, err := ParseKey(string(b))
	if err != nil {
		return err
	}
	*k = parsed
	return nil
}
