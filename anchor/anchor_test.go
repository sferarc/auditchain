package anchor

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

// testSigningKey is a fixed Ed25519 note key. It exists only in tests and is
// published in this file on purpose: a key checked into a repository is not a
// secret, and pretending otherwise by generating one per run would only make
// failures non-reproducible.
const testSigningKey = "PRIVATE+KEY+pgbeam-audit-anchor-test+2b9d51c4+AaWt0qpe+VWjqtUtAbDSWSx/NuHBat9BZ9gRNJViyVIL"

func testSigner(t *testing.T) *Signer {
	t.Helper()
	s, err := NewSigner(testSigningKey)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	if s == nil {
		t.Fatal("NewSigner returned nil for a non-empty key")
	}
	return s
}

// hashes builds n distinct entry-hash-shaped strings.
func hashes(n int) []string {
	out := make([]string, 0, n)
	for i := range n {
		out = append(out, strings.Repeat("0", 63)+string("0123456789abcdef"[i%16]))
	}
	return out
}

// TestRootIsOrderDependent is the property that makes the tree worth anything
// over a set hash: it commits to the chain's ORDER, not just its contents. Two
// chains holding the same entries in a different order must not produce the same
// root, or an adversary could reorder the audit trail freely.
func TestRootIsOrderDependent(t *testing.T) {
	forward, err := RootFromLeaves([]string{"a", "b", "c"})
	if err != nil {
		t.Fatalf("RootFromLeaves: %v", err)
	}
	reordered, err := RootFromLeaves([]string{"a", "c", "b"})
	if err != nil {
		t.Fatalf("RootFromLeaves: %v", err)
	}
	if bytes.Equal(forward, reordered) {
		t.Fatal("reordering the leaves did not change the root")
	}
}

// TestRootChangesWithEveryLeaf pins that no leaf is ignored. A tree that dropped
// one on the floor would still verify every other one and read as intact.
func TestRootChangesWithEveryLeaf(t *testing.T) {
	base := hashes(9)
	baseRoot, err := RootFromLeaves(base)
	if err != nil {
		t.Fatalf("RootFromLeaves: %v", err)
	}
	for i := range base {
		mutated := append([]string(nil), base...)
		mutated[i] = "ff" + mutated[i][2:]
		root, err := RootFromLeaves(mutated)
		if err != nil {
			t.Fatalf("RootFromLeaves: %v", err)
		}
		if bytes.Equal(root, baseRoot) {
			t.Fatalf("changing leaf %d did not change the root", i)
		}
	}
}

// TestTruncationChangesTheRoot is the finding this package exists for, expressed
// at the level of the maths: a prefix of a chain does not produce the chain's
// root. That is the property a bare hash chain lacks and why the anchor closes
// the gap.
func TestTruncationChangesTheRoot(t *testing.T) {
	full := hashes(8)
	fullRoot, err := RootFromLeaves(full)
	if err != nil {
		t.Fatalf("RootFromLeaves: %v", err)
	}
	for n := range len(full) {
		prefixRoot, err := RootFromLeaves(full[:n])
		if err != nil {
			t.Fatalf("RootFromLeaves: %v", err)
		}
		if bytes.Equal(prefixRoot, fullRoot) {
			t.Fatalf("a %d-leaf prefix produced the 8-leaf root", n)
		}
	}
}

// TestSignedCheckpointRoundTrips covers the note path: what was signed is what
// comes back, range included.
func TestSignedCheckpointRoundTrips(t *testing.T) {
	s := testSigner(t)
	root, err := RootFromLeaves(hashes(5))
	if err != nil {
		t.Fatalf("RootFromLeaves: %v", err)
	}
	cp := Checkpoint{Origin: testOrigin("prj_1"), StartSeq: 6, EndSeq: 10, Root: root}

	signed, err := s.Sign(cp)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	got, err := s.Verify(signed, testOrigin("prj_1"))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.StartSeq != cp.StartSeq || got.EndSeq != cp.EndSeq ||
		!bytes.Equal(got.Root, cp.Root) || got.Origin != cp.Origin {
		t.Fatalf("round trip changed the checkpoint: %+v want %+v", got, cp)
	}
	if got.Size() != 5 {
		t.Fatalf("size %d, want the 5 leaves the range covers", got.Size())
	}
}

// TestTheRangeIsInsideTheSignature is the property the whole format change rests
// on. A checkpoint means "these seqs", and if the seqs lived only in the columns
// beside the note, one UPDATE would re-point a valid signature at a different
// set of leaves: an adversary could claim a checkpoint covered the range they
// had already emptied, and verification would agree it could not be checked.
func TestTheRangeIsInsideTheSignature(t *testing.T) {
	s := testSigner(t)
	root, err := RootFromLeaves(hashes(4))
	if err != nil {
		t.Fatalf("RootFromLeaves: %v", err)
	}
	signed, err := s.Sign(Checkpoint{Origin: testOrigin("prj_1"), StartSeq: 10, EndSeq: 13, Root: root})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !bytes.Contains(signed, []byte("range 10 13\n")) {
		t.Fatalf("the signed body does not carry the range:\n%s", signed)
	}

	// Move the range down to a stretch of chain retention would have taken.
	edited := bytes.Replace(signed, []byte("range 10 13\n"), []byte("range 1 4\n"), 1)
	if bytes.Equal(edited, signed) {
		t.Fatal("test did not actually edit the range line")
	}
	if _, err := s.Verify(edited, testOrigin("prj_1")); err == nil {
		t.Fatal("a checkpoint with a rewritten range verified")
	}
}

// TestUnmarshalRefusesAnUnreadableStatement is the fail-closed half. Each of
// these is a note body whose meaning cannot be pinned down, and an ambiguous
// signed statement about tampering is worth less than none: a verifier would
// have to guess which leaves it covers.
func TestUnmarshalRefusesAnUnreadableStatement(t *testing.T) {
	root := bytes.Repeat([]byte{0xab}, 32)
	b64 := base64.StdEncoding.EncodeToString(root)

	for name, body := range map[string]string{
		"no range line":                testOrigin("prj_1") + "\n4\n" + b64 + "\n",
		"range not numeric":            testOrigin("prj_1") + "\n4\n" + b64 + "\nrange one four\n",
		"range too few parts":          testOrigin("prj_1") + "\n4\n" + b64 + "\nrange 10\n",
		"unknown keyword":              testOrigin("prj_1") + "\n4\n" + b64 + "\nspan 10 13\n",
		"ends before it starts":        testOrigin("prj_1") + "\n0\n" + b64 + "\nrange 13 10\n",
		"starts before the chain does": testOrigin("prj_1") + "\n5\n" + b64 + "\nrange 0 4\n",
		// The leaf count and the range describe the same thing, so a note where
		// they disagree is a note that says two things at once.
		"size disagrees with the range": testOrigin("prj_1") + "\n99\n" + b64 + "\nrange 10 13\n",
		"extra extension line":          testOrigin("prj_1") + "\n4\n" + b64 + "\nrange 10 13\nsomething 1\n",
	} {
		t.Run(name, func(t *testing.T) {
			if cp, err := UnmarshalCheckpoint([]byte(body)); err == nil {
				t.Fatalf("an unreadable checkpoint parsed as %+v", cp)
			}
		})
	}
}

// TestSignRefusesAnInvalidRange keeps a meaningless statement from being given a
// signature in the first place. A signed note is evidence somebody will later be
// asked to trust, so the refusal belongs at the point of issue as well as at the
// point of reading.
func TestSignRefusesAnInvalidRange(t *testing.T) {
	s := testSigner(t)
	root, err := RootFromLeaves(hashes(2))
	if err != nil {
		t.Fatalf("RootFromLeaves: %v", err)
	}
	for name, cp := range map[string]Checkpoint{
		"inverted":   {Origin: testOrigin("prj_1"), StartSeq: 9, EndSeq: 4, Root: root},
		"zero start": {Origin: testOrigin("prj_1"), StartSeq: 0, EndSeq: 4, Root: root},
		"no origin":  {StartSeq: 1, EndSeq: 4, Root: root},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := s.Sign(cp); err == nil {
				t.Fatal("an invalid checkpoint was signed")
			}
		})
	}
}

// TestVerifyRefusesAnotherProjectsCheckpoint pins the origin binding. Without it
// a checkpoint signed for a quiet project could be replayed against a busy one
// to make a truncated chain look anchored.
func TestVerifyRefusesAnotherProjectsCheckpoint(t *testing.T) {
	s := testSigner(t)
	root, err := RootFromLeaves(hashes(3))
	if err != nil {
		t.Fatalf("RootFromLeaves: %v", err)
	}
	signed, err := s.Sign(Checkpoint{Origin: testOrigin("prj_other"), StartSeq: 1, EndSeq: 3, Root: root})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, err := s.Verify(signed, testOrigin("prj_1")); err == nil {
		t.Fatal("a checkpoint issued for another project verified")
	}
}

// TestVerifyRefusesAnEditedNote proves the signature is what is trusted, not the
// text. An adversary who can write to the checkpoint table can change the
// numbers; they cannot re-sign them.
func TestVerifyRefusesAnEditedNote(t *testing.T) {
	s := testSigner(t)
	root, err := RootFromLeaves(hashes(8))
	if err != nil {
		t.Fatalf("RootFromLeaves: %v", err)
	}
	signed, err := s.Sign(Checkpoint{Origin: testOrigin("prj_1"), StartSeq: 1, EndSeq: 8, Root: root})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Claim the range only ever ran to five, which is exactly what a forger
	// wanting to hide three deleted entries would write.
	edited := bytes.Replace(signed, []byte("range 1 8\n"), []byte("range 1 5\n"), 1)
	if bytes.Equal(edited, signed) {
		t.Fatal("test did not actually edit the note body")
	}
	if _, err := s.Verify(edited, testOrigin("prj_1")); err == nil {
		t.Fatal("an edited checkpoint note verified")
	}
}

// TestNoSignerIsNotAnError pins the default deployment. An unset key means no
// anchor, which is a configuration state and not a failure, and it must not
// break startup.
func TestNoSignerIsNotAnError(t *testing.T) {
	for _, spec := range []string{"", "   ", "\n"} {
		s, err := NewSigner(spec)
		if err != nil {
			t.Fatalf("NewSigner(%q) errored: %v", spec, err)
		}
		if s != nil {
			t.Fatalf("NewSigner(%q) returned a signer", spec)
		}
		if s.Name() != "" {
			t.Fatal("nil signer reported a key name")
		}
	}
}

// TestMalformedSigningKeyIsRefused is the other half: a key that is present and
// wrong must stop the process rather than silently disabling the anchor, because
// an operator who set it believes it is on.
func TestMalformedSigningKeyIsRefused(t *testing.T) {
	if _, err := NewSigner("not-a-note-key"); err == nil {
		t.Fatal("a malformed signing key was accepted")
	}
}

// testOrigin builds an origin the way a caller would, under a namespace that
// belongs to nobody. Origin takes the namespace as an argument precisely so the
// library carries no product's name, so the tests supply one too.
func testOrigin(id string) string { return Origin("example/audit", id) }
