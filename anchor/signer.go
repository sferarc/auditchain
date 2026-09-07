package anchor

import (
	"fmt"
	"strings"

	tnote "github.com/transparency-dev/formats/note"
	"golang.org/x/mod/sumdb/note"
)

// Signer signs checkpoints. It is deliberately a SEPARATE key from the audit
// chain's HMAC keyring (AUDIT_CHAIN_KEYS), and the separation is load bearing
// rather than tidy: one key signs individual entries, the other signs statements
// about the whole chain. A single key doing both would let anyone who could
// forge an entry also forge the anchor that is supposed to catch the forgery,
// which collapses the two layers into one.
//
// The key is Ed25519 in the note format the transparency-log ecosystem uses:
//
//	PRIVATE+KEY+<name>+<keyhash>+<base64>
//
// It has the same deployment requirement as the audit keyring. A signing key
// stored in the database it makes claims about protects nothing, because the
// adversary in this threat model is someone who can write to that database.
type Signer struct {
	signer   note.Signer
	verifier note.Verifier
}

// NewSigner parses a note-format Ed25519 private key. An empty spec yields a nil
// Signer and no error: that is the deployment with no anchor configured, which
// is the default and not a misconfiguration. Checkpoints are simply not emitted,
// and verification behaves exactly as it did before the anchor existed.
func NewSigner(spec string) (*Signer, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, nil
	}
	s, v, err := tnote.NewEd25519SignerVerifier(spec)
	if err != nil {
		return nil, fmt.Errorf("audit anchor signing key: %w", err)
	}
	return &Signer{signer: s, verifier: v}, nil
}

// Name is the key name embedded in the note, used in logs so an operator can
// tell which key a deployment holds without printing the key.
func (s *Signer) Name() string {
	if s == nil {
		return ""
	}
	return s.signer.Name()
}

// Sign returns the signed note for a checkpoint. The origin, the seq range and
// the root are all inside the signed body, so a note cannot be replayed for a
// different project, re-pointed at different leaves, or edited to claim a
// shorter chain.
//
// A checkpoint that does not validate is refused rather than signed. A signature
// over a range that means nothing is worse than no signature, because it is
// evidence somebody will later be asked to trust.
func (s *Signer) Sign(c Checkpoint) ([]byte, error) {
	if s == nil {
		return nil, fmt.Errorf("audit anchor: no signing key configured")
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	signed, err := note.Sign(&note.Note{Text: string(c.Marshal())}, s.signer)
	if err != nil {
		return nil, fmt.Errorf("audit anchor: sign checkpoint: %w", err)
	}
	return signed, nil
}

// Verify parses a signed note and returns the checkpoint it attests to, refusing
// anything not signed by this key or issued under a different origin.
//
// Verification runs against the note rather than against the columns stored
// beside it, so a row edited in the database (a narrower range, a different
// root) fails here instead of being read back as truth. That matters: the
// stored columns exist for indexing and for a human reading psql, and the note
// is the artifact that actually carries the claim.
func (s *Signer) Verify(signed []byte, origin string) (Checkpoint, error) {
	if s == nil {
		return Checkpoint{}, fmt.Errorf("audit anchor: no verification key configured")
	}
	n, err := note.Open(signed, note.VerifierList(s.verifier))
	if err != nil {
		return Checkpoint{}, fmt.Errorf("audit anchor: open checkpoint note: %w", err)
	}
	cp, err := UnmarshalCheckpoint([]byte(n.Text))
	if err != nil {
		return Checkpoint{}, err
	}
	if cp.Origin != origin {
		return Checkpoint{}, fmt.Errorf("audit anchor: checkpoint origin %q, want %q", cp.Origin, origin)
	}
	return cp, nil
}
