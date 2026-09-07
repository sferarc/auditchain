package auditchain

import "testing"

// testKeyring is a ring holding both sample secrets, active key "v2".
func testKeyring(t *testing.T) *Keyring {
	t.Helper()
	kr, err := ParseKeyring("v2:" + hexSecretB + ",v1:" + hexSecretA)
	if err != nil {
		t.Fatalf("ParseKeyring: %v", err)
	}
	return kr
}

// TestComputeKeyedIsNotTheUnkeyedHash asserts signing actually changes the
// construction: a keyed entry's hash is not the plain SHA-256 an adversary with
// database write access could recompute for themselves.
func TestComputeKeyedIsNotTheUnkeyedHash(t *testing.T) {
	t.Parallel()
	e := sampleEntry()
	secret, _ := testKeyring(t).Secret("v1")
	keyed := e.ComputeKeyed("v1", secret, GenesisPrevHash)
	if keyed == e.Compute(GenesisPrevHash) {
		t.Fatal("keyed hash equals the unkeyed hash")
	}
	if len(keyed) != 64 {
		t.Fatalf("keyed hash length = %d, want 64", len(keyed))
	}
}

// TestComputeKeyedEmptyKeyIsUnkeyed asserts the one call site the append path
// uses covers both deployments: no active key means the entry is hashed exactly
// as it was before keying existed.
func TestComputeKeyedEmptyKeyIsUnkeyed(t *testing.T) {
	t.Parallel()
	e := sampleEntry()
	if e.ComputeKeyed("", nil, GenesisPrevHash) != e.Compute(GenesisPrevHash) {
		t.Fatal("ComputeKeyed with no key differs from the unkeyed hash")
	}
}

// TestComputeKeyedBindsKeyAndSecret asserts both halves of the label are bound:
// the same content under a different secret, and under a different id, hash
// differently. Without the second, a stored entry could be relabelled to a key
// the verifier does not hold and pass as merely unverifiable.
func TestComputeKeyedBindsKeyAndSecret(t *testing.T) {
	t.Parallel()
	e := sampleEntry()
	kr := testKeyring(t)
	secretA, _ := kr.Secret("v1")
	secretB, _ := kr.Secret("v2")

	base := e.ComputeKeyed("v1", secretA, GenesisPrevHash)
	if base == e.ComputeKeyed("v1", secretB, GenesisPrevHash) {
		t.Error("hash unchanged when the secret changed")
	}
	if base == e.ComputeKeyed("v2", secretA, GenesisPrevHash) {
		t.Error("hash unchanged when the key id changed")
	}
}

// TestChainVerifierUnkeyed asserts an unkeyed deployment still verifies the
// entries it wrote, and still catches an edited one.
func TestChainVerifierUnkeyed(t *testing.T) {
	t.Parallel()
	e := sampleEntry()
	stored := e.Compute(GenesisPrevHash)

	if got := NewChainVerifier(nil, "").Check(e, "", GenesisPrevHash, stored); got != ChainOK {
		t.Fatalf("Check on an intact unkeyed entry = %q, want ok", got)
	}

	edited := editField(e, 5, Str("SELECT 2"))
	if got := NewChainVerifier(nil, "").Check(edited, "", GenesisPrevHash, stored); got != ChainHashMismatch {
		t.Fatalf("Check on an edited unkeyed entry = %q, want %q", got, ChainHashMismatch)
	}
}

// TestChainVerifierKeyed asserts a signed entry verifies under the key it names,
// including a retired key that no longer signs anything.
func TestChainVerifierKeyed(t *testing.T) {
	t.Parallel()
	kr := testKeyring(t)
	for _, keyID := range []string{"v1", "v2"} {
		e := sampleEntry()
		secret, _ := kr.Secret(keyID)
		stored := e.ComputeKeyed(keyID, secret, GenesisPrevHash)
		if got := NewChainVerifier(kr, "").Check(e, keyID, GenesisPrevHash, stored); got != ChainOK {
			t.Errorf("Check on an entry signed with %q = %q, want ok", keyID, got)
		}
	}
}

// TestChainVerifierEditedKeyedEntry asserts editing a signed entry is caught,
// and that the forger cannot repair it by rehashing: the recompute needs a
// secret the database does not hold.
func TestChainVerifierEditedKeyedEntry(t *testing.T) {
	t.Parallel()
	kr := testKeyring(t)
	e := sampleEntry()
	secret, _ := kr.Secret("v2")
	stored := e.ComputeKeyed("v2", secret, GenesisPrevHash)

	edited := editField(e, 11, Int(999))
	if got := NewChainVerifier(kr, "").Check(edited, "v2", GenesisPrevHash, stored); got != ChainHashMismatch {
		t.Fatalf("Check on an edited signed entry = %q, want %q", got, ChainHashMismatch)
	}
	// The unkeyed rehash a database writer can compute does not pass either.
	if got := NewChainVerifier(kr, "").Check(edited, "v2", GenesisPrevHash, edited.Compute(GenesisPrevHash)); got != ChainHashMismatch {
		t.Fatalf("Check accepted an unkeyed rehash under a key label: %q", got)
	}
}

// TestChainVerifierUnknownKey asserts an entry signed with a key this deployment
// does not hold is reported as unverifiable, not silently passed. A deployment
// with no keyring at all reads every signed entry the same way.
func TestChainVerifierUnknownKey(t *testing.T) {
	t.Parallel()
	e := sampleEntry()
	secret, _ := testKeyring(t).Secret("v1")
	stored := e.ComputeKeyed("v1", secret, GenesisPrevHash)

	if got := NewChainVerifier(nil, "").Check(e, "v1", GenesisPrevHash, stored); got != ChainUnknownKey {
		t.Fatalf("Check with no keyring = %q, want %q", got, ChainUnknownKey)
	}
	kr, err := ParseKeyring("v9:" + hexSecretB)
	if err != nil {
		t.Fatalf("ParseKeyring: %v", err)
	}
	if got := NewChainVerifier(kr, "").Check(e, "v1", GenesisPrevHash, stored); got != ChainUnknownKey {
		t.Fatalf("Check with the wrong key in the ring = %q, want %q", got, ChainUnknownKey)
	}
}

// TestChainVerifierKeyingCanBeSwitchedOn asserts the legitimate transition is
// accepted: entries written before the key, then entries written after it, in
// one chain.
func TestChainVerifierKeyingCanBeSwitchedOn(t *testing.T) {
	t.Parallel()
	kr := testKeyring(t)
	v := NewChainVerifier(kr, "")

	legacy := sampleEntry()
	if got := v.Check(legacy, "", GenesisPrevHash, legacy.Compute(GenesisPrevHash)); got != ChainOK {
		t.Fatalf("unkeyed prefix entry = %q, want ok", got)
	}
	signed := sampleEntry()
	signed.Seq = 2
	secret, _ := kr.Secret("v2")
	prev := legacy.Compute(GenesisPrevHash)
	if got := v.Check(signed, "v2", prev, signed.ComputeKeyed("v2", secret, prev)); got != ChainOK {
		t.Fatalf("first signed entry = %q, want ok", got)
	}
}

// chainStep is one entry in a scripted walk: which key signed it, if any.
func walkChain(t *testing.T, v *ChainVerifier, startSeq int64, prev string, keyIDs []string) string {
	t.Helper()
	kr := testKeyring(t)
	for i, keyID := range keyIDs {
		e := sampleEntry()
		e.Seq = startSeq + int64(i)
		secret, _ := kr.Secret(keyID)
		stored := e.ComputeKeyed(keyID, secret, prev)
		if got := v.Check(e, keyID, prev, stored); got != ChainOK {
			t.Fatalf("entry %d (key %q) = %q, want ok", e.Seq, keyID, got)
		}
		prev = stored
	}
	return prev
}

// TestChainVerifierFlagsUnsignedTail asserts the downgrade is reported when the
// chain ends in unkeyed entries after a signed one. That is what a forger who
// cannot sign produces: truncate the signed tail, continue with hashes they can
// compute. Each entry is individually well formed, so only the run at the end
// gives it away.
func TestChainVerifierFlagsUnsignedTail(t *testing.T) {
	t.Parallel()
	v := NewChainVerifier(testKeyring(t), "")
	walkChain(t, v, 1, GenesisPrevHash, []string{"v2", "v2", "", ""})

	seq, pending := v.PendingDowngradeSeq()
	if !pending {
		t.Fatal("no downgrade reported for an unsigned tail")
	}
	if seq != 3 {
		t.Fatalf("downgrade seq = %d, want 3 (where the unsigned run began)", seq)
	}
}

// TestChainVerifierForgivesInterleave asserts the enablement interleave is not a
// downgrade. Switching signing on is a rolling deploy, so signed and unsigned
// writers run side by side for a few minutes and leave a mixed run behind. A
// signed entry after the run vouches for it, because writing that entry needed
// the key. Without this, turning the feature on would fail verification of that
// window for good.
func TestChainVerifierForgivesInterleave(t *testing.T) {
	t.Parallel()
	v := NewChainVerifier(testKeyring(t), "")
	walkChain(t, v, 1, GenesisPrevHash, []string{"", "v2", "", "v2", "v2"})

	if seq, pending := v.PendingDowngradeSeq(); pending {
		t.Fatalf("downgrade reported at seq %d for an interleave a signed entry vouches for", seq)
	}
}

// TestChainVerifierInheritsPredecessorKey asserts a window that starts mid-chain
// still catches a downgrade inside it. Without the predecessor's key id,
// verifying a range that begins after signing started would read its unkeyed
// entries as an ordinary pre-keying prefix.
func TestChainVerifierInheritsPredecessorKey(t *testing.T) {
	t.Parallel()
	v := NewChainVerifier(testKeyring(t), "v2")
	walkChain(t, v, 57, GenesisPrevHash, []string{""})

	seq, pending := v.PendingDowngradeSeq()
	if !pending || seq != 57 {
		t.Fatalf("PendingDowngradeSeq = %d, %v; want 57, true", seq, pending)
	}
}

// TestChainVerifierNoDowngradeWithoutSigning asserts an entirely unkeyed chain
// never reports a downgrade: on a deployment holding no key, that is every
// entry, and the rule must stay silent.
func TestChainVerifierNoDowngradeWithoutSigning(t *testing.T) {
	t.Parallel()
	v := NewChainVerifier(nil, "")
	walkChain(t, v, 1, GenesisPrevHash, []string{"", "", ""})

	if seq, pending := v.PendingDowngradeSeq(); pending {
		t.Fatalf("downgrade reported at seq %d on an unkeyed chain", seq)
	}
}

// editField returns a copy of e with one field replaced, which is how these
// tests stand in for a stored record being altered after the fact. It copies the
// slice rather than writing through it, so a mutated case cannot leak into the
// next one.
func editField(e Entry, i int, f Field) Entry {
	fields := make([]Field, len(e.Fields))
	copy(fields, e.Fields)
	fields[i] = f
	return Entry{Seq: e.Seq, Fields: fields}
}
