package auditchain

import (
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

// MinKeyBytes is the shortest HMAC secret accepted. SHA-256's block size is 64
// bytes and its output is 32; anything below 32 bytes weakens the construction
// for no operational gain, so it is refused at load time rather than accepted
// and quietly trusted.
const MinKeyBytes = 32

// keyIDPattern is what a key id may look like. It is stored on every entry and
// bound into the hash, so it is kept to a short, unambiguous alphabet: no
// separators the env spec uses, nothing case-sensitive to get wrong when an
// operator retypes it, and the same shape the database CHECK enforces.
var keyIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)

// Key is one HMAC key that can sign audit chain entries. ID is what a signed
// entry records so a later verification knows which secret to use; Secret is the
// raw key, which lives only in the API process's memory and never in the
// database the entries are stored in.
type Key struct {
	ID     string
	Secret []byte
}

// Keyring holds the key new entries are signed with plus every retired key still
// needed to verify entries already written. A nil *Keyring is the unkeyed
// deployment: entries are hashed with plain SHA-256, exactly as they were before
// keying existed, and every stored entry verifies the same way it always did.
//
// Rotation is additive: put the new key first and keep the old one in the ring.
// Entries written from then on carry the new id, entries written before it keep
// verifying under the old one, and no stored row is rewritten.
type Keyring struct {
	activeID string
	secrets  map[string][]byte
}

// NewKeyring builds a keyring whose first key is the active (signing) key and
// whose remaining keys are retired but still able to verify. It refuses an empty
// ring, a malformed or duplicate id, and a secret shorter than MinKeyBytes.
func NewKeyring(keys []Key) (*Keyring, error) {
	if len(keys) == 0 {
		return nil, fmt.Errorf("audit chain keyring: no keys")
	}
	kr := &Keyring{activeID: keys[0].ID, secrets: make(map[string][]byte, len(keys))}
	for _, k := range keys {
		if !keyIDPattern.MatchString(k.ID) {
			return nil, fmt.Errorf("audit chain keyring: invalid key id %q (want %s)", k.ID, keyIDPattern)
		}
		if len(k.Secret) < MinKeyBytes {
			return nil, fmt.Errorf("audit chain keyring: key %q secret is %d bytes, want at least %d", k.ID, len(k.Secret), MinKeyBytes)
		}
		if allZero(k.Secret) {
			return nil, fmt.Errorf("audit chain keyring: key %q secret must not be all zeros", k.ID)
		}
		if _, dup := kr.secrets[k.ID]; dup {
			return nil, fmt.Errorf("audit chain keyring: duplicate key id %q", k.ID)
		}
		kr.secrets[k.ID] = k.Secret
	}
	return kr, nil
}

// ParseKeyring reads a keyring from the `id:hex` list an operator configures,
// comma separated, active key first:
//
//	v2:9f8e...(64 hex chars),v1:1a2b...
//
// An empty or whitespace-only spec yields a nil keyring and no error: that is
// the unkeyed deployment, which is the default and not a misconfiguration.
func ParseKeyring(spec string) (*Keyring, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, nil
	}
	var keys []Key
	for part := range strings.SplitSeq(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		id, hexSecret, ok := strings.Cut(part, ":")
		if !ok {
			return nil, fmt.Errorf("audit chain keyring: entry %q is not id:hex", part)
		}
		secret, err := hex.DecodeString(strings.TrimSpace(hexSecret))
		if err != nil {
			return nil, fmt.Errorf("audit chain keyring: key %q secret is not hex: %w", id, err)
		}
		keys = append(keys, Key{ID: strings.TrimSpace(id), Secret: secret})
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("audit chain keyring: no keys in %q", spec)
	}
	return NewKeyring(keys)
}

// ActiveKeyID is the id new entries are signed with, or "" on a nil keyring
// (the unkeyed deployment).
func (kr *Keyring) ActiveKeyID() string {
	if kr == nil {
		return ""
	}
	return kr.activeID
}

// Secret returns the key with this id. An empty id means the unkeyed hash and
// always resolves, with a nil secret, so callers can treat legacy entries
// through the same path. A non-empty id this ring does not hold does not
// resolve, and the caller reports the entry as unverifiable rather than
// tampered.
func (kr *Keyring) Secret(id string) ([]byte, bool) {
	if id == "" {
		return nil, true
	}
	if kr == nil {
		return nil, false
	}
	secret, ok := kr.secrets[id]
	return secret, ok
}

// allZero reports whether every byte is zero, in constant time. An all-zero
// secret is the shape a placeholder or an uninitialized buffer takes, and it
// would make the HMAC trivially forgeable by anyone who guessed as much.
func allZero(b []byte) bool {
	return subtle.ConstantTimeCompare(b, make([]byte, len(b))) == 1
}
