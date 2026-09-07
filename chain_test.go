package auditchain

import (
	"strconv"
	"testing"
	"time"
)

// sampleEntry is a representative record: every field kind the package offers,
// including a present nullable, in a fixed order.
//
// The field sequence is deliberately the one PgBeam's audit log uses, because
// TestComputeUnkeyedIsFrozen pins the hash it produces and that constant was
// captured before this package encoded anything generically. Keeping the
// sequence is therefore a second, independent proof that the typed-field encoder
// reproduces the struct-shaped one it replaced, byte for byte.
func sampleEntry() Entry {
	cred := "cred_1"
	return Entry{
		Seq: 1,
		Fields: []Field{
			Str("aud_1"),
			Str("prj_1"),
			NullableStr(&cred),
			Str("iad"),
			Str("query"),
			Str("SELECT 1"),
			Str("SELECT $1"),
			Str("abc"),
			Str("select"),
			Str(""),
			Str(""),
			Int(1),
			Int(42),
			Float(1.5),
			Str("miss"),
			Str("10.0.0.1"),
			Str("sess_1"),
			Str("wire"),
			Time(time.Date(2026, 7, 15, 10, 0, 0, 123456000, time.UTC)),
		},
	}
}

// TestComputeDeterministic asserts the same entry and prev_hash always yield the
// same hash, and that the hash is a 64-char hex string.
func TestComputeDeterministic(t *testing.T) {
	t.Parallel()
	e := sampleEntry()
	h1 := e.Compute(GenesisPrevHash)
	h2 := e.Compute(GenesisPrevHash)
	if h1 != h2 {
		t.Fatalf("Compute not deterministic: %q != %q", h1, h2)
	}
	if len(h1) != 64 {
		t.Fatalf("hash length = %d, want 64", len(h1))
	}
}

// TestComputeUnkeyedIsFrozen pins the unkeyed encoding to a known vector. Every
// audit entry written before the chain could be signed carries a hash of this
// shape, and those rows are never rewritten, so a change to what the unkeyed
// form hashes would turn the whole existing trail into reported tampering. If
// this test fails, the encoding moved and the stored history moved with it.
func TestComputeUnkeyedIsFrozen(t *testing.T) {
	t.Parallel()
	const want = "1b1c602a50ceb3471440f9e3f3f7b6d9e394a23fb22626b1b048c36b38464757"
	if got := sampleEntry().Compute(GenesisPrevHash); got != want {
		t.Fatalf("unkeyed hash of the sample entry = %q, want %q", got, want)
	}
}

// TestComputeChangesWithPrev asserts the link matters: the same content chained
// onto a different prev_hash produces a different hash.
func TestComputeChangesWithPrev(t *testing.T) {
	t.Parallel()
	e := sampleEntry()
	if e.Compute(GenesisPrevHash) == e.Compute("11"+GenesisPrevHash[2:]) {
		t.Fatal("hash did not change when prev_hash changed")
	}
}

// TestComputeSensitiveToEveryField asserts that changing any one field changes
// the hash, so no part of a record can be tampered with without detection.
//
// It walks the field list by index rather than naming fields, which is what the
// typed-field encoding makes possible and is stronger than the named form it
// replaced: a field added to the record is covered the moment it exists, with no
// matching test case to remember to write.
func TestComputeSensitiveToEveryField(t *testing.T) {
	t.Parallel()
	base := sampleEntry()
	baseHash := base.Compute(GenesisPrevHash)

	if seqChanged := (Entry{Seq: base.Seq + 1, Fields: base.Fields}).Compute(GenesisPrevHash); seqChanged == baseHash {
		t.Error("changing seq did not change the hash, so a record could be moved to another position")
	}

	for i := range base.Fields {
		mutated := make([]Field, len(base.Fields))
		copy(mutated, base.Fields)
		// A string that no field in the sample holds, so the substitution is a
		// real change whatever the original field's kind was.
		mutated[i] = Str("\x00mutated-" + strconv.Itoa(i))

		if (Entry{Seq: base.Seq, Fields: mutated}).Compute(GenesisPrevHash) == baseHash {
			t.Errorf("mutating field %d did not change the hash", i)
		}
	}
}

// TestIntAndStringCollideByDesign records a property of this encoding that is
// easy to assume the other way round, and that a caller designing a field list
// needs to know.
//
// Int(7) and Str("7") produce identical bytes, because an integer is encoded as
// its length-prefixed decimal string. That is safe here and not an oversight:
// the field ORDER is fixed, so position already decides what a field means, and
// a field is only ever compared against the same field of another record. The
// collision would only matter if two records could disagree about which field
// sat at a given index, which is exactly what Entry's contract forbids.
//
// It also cannot be changed. The encoding is frozen by every hash already
// stored, so adding a kind tag now would invalidate them all.
func TestIntAndStringCollideByDesign(t *testing.T) {
	t.Parallel()
	asInt := Entry{Seq: 1, Fields: []Field{Int(7)}}.Compute(GenesisPrevHash)
	asStr := Entry{Seq: 1, Fields: []Field{Str("7")}}.Compute(GenesisPrevHash)
	if asInt != asStr {
		t.Fatal("Int and Str no longer share an encoding. That is a safer format, and it invalidates every hash already written: see the comment above.")
	}
}

// TestNullableCarriesPresence asserts the one kind that does NOT collide with a
// plain string. A nullable field writes a presence byte first, so an absent
// value and a present one cannot be swapped for each other.
func TestNullableCarriesPresence(t *testing.T) {
	t.Parallel()
	seven := "7"
	nullable := Entry{Seq: 1, Fields: []Field{NullableStr(&seven)}}.Compute(GenesisPrevHash)
	plain := Entry{Seq: 1, Fields: []Field{Str("7")}}.Compute(GenesisPrevHash)
	if nullable == plain {
		t.Fatal("a present nullable and a plain string hashed alike, so the presence byte is not being written")
	}
}

// TestLengthPrefixPreventsFieldSmuggling is the property the length prefix
// exists for: two records whose fields concatenate to the same characters must
// still hash differently, so a value cannot impersonate a different field
// layout.
func TestLengthPrefixPreventsFieldSmuggling(t *testing.T) {
	t.Parallel()
	split := Entry{Seq: 1, Fields: []Field{Str("ab"), Str("c")}}
	joined := Entry{Seq: 1, Fields: []Field{Str("a"), Str("bc")}}
	if split.Compute(GenesisPrevHash) == joined.Compute(GenesisPrevHash) {
		t.Fatal("two different field layouts with the same concatenation hashed alike")
	}
}

// TestComputeNullVsEmptyCredential asserts a NULL credential and a present empty
// string are not conflated (a canonicalization ambiguity would let one be
// swapped for the other without breaking the chain).
func TestComputeNullVsEmptyCredential(t *testing.T) {
	t.Parallel()
	empty := ""
	withNil := Entry{Seq: 1, Fields: []Field{NullableStr(nil)}}
	withEmpty := Entry{Seq: 1, Fields: []Field{NullableStr(&empty)}}
	if withNil.Compute(GenesisPrevHash) == withEmpty.Compute(GenesisPrevHash) {
		t.Fatal("NULL and empty-string credential produced the same hash")
	}
}

// TestNormalizeTS asserts sub-microsecond precision and non-UTC zones normalize
// to the value Postgres persists, so an insert-time hash matches a
// verification-time recompute of the stored row.
func TestNormalizeTS(t *testing.T) {
	t.Parallel()
	loc := time.FixedZone("x", 3600)
	in := time.Date(2026, 7, 15, 11, 0, 0, 123456789, loc)
	got := NormalizeTS(in)
	want := time.Date(2026, 7, 15, 10, 0, 0, 123456000, time.UTC)
	if !got.Equal(want) {
		t.Fatalf("NormalizeTS = %v, want %v", got, want)
	}
	// Compute must be invariant to zone/sub-microsecond noise once normalized.
	a := Entry{Seq: 1, Fields: []Field{Time(in)}}
	b := Entry{Seq: 1, Fields: []Field{Time(want)}}
	if a.Compute(GenesisPrevHash) != b.Compute(GenesisPrevHash) {
		t.Fatal("hash differs for timestamps that normalize equal")
	}
}

// TestIsChainHash pins the shape check the verifier leans on when it has to
// decide whether an unresolvable prev_hash could have come from the chain
// writer at all. Everything Compute and ComputeKeyed produce must pass, and
// anything hand-written into the column must not.
func TestIsChainHash(t *testing.T) {
	t.Parallel()
	if !IsChainHash(GenesisPrevHash) {
		t.Error("the genesis value must be a well-formed chain hash")
	}
	if !IsChainHash(sampleEntry().Compute(GenesisPrevHash)) {
		t.Error("a computed entry hash must be a well-formed chain hash")
	}
	for _, bad := range []string{
		"",
		"deadbeef",
		GenesisPrevHash + "0",
		GenesisPrevHash[:63],
		"z" + GenesisPrevHash[1:],
		"ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789",
	} {
		if IsChainHash(bad) {
			t.Errorf("IsChainHash(%q) = true, want false", bad)
		}
	}
}
