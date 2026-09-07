package auditchain

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"hash"
	"strconv"
	"time"
)

// GenesisPrevHash is the prev_hash of the first entry in a chain. It is a fixed,
// well-known value (64 hex zeros) so a genesis entry is recognizable and cannot
// be forged as continuing an earlier, deleted entry.
const GenesisPrevHash = "0000000000000000000000000000000000000000000000000000000000000000"

// chainHashLen is the length of a stored prev_hash or entry_hash: SHA-256 (or
// HMAC-SHA256) hex-encoded lowercase.
const chainHashLen = 2 * sha256.Size

// IsChainHash reports whether s has the shape a stored chain hash always has:
// exactly 64 lowercase hex characters, which is what Compute and ComputeKeyed
// emit and what GenesisPrevHash is. It says nothing about the value being the
// right hash for anything.
//
// It exists so a caller that has to decide what an unresolvable prev_hash means
// can refuse a malformed one outright instead of reasoning about it. An empty
// string (a record written before the chain existed) and anything hand-written
// into the column both fail here.
func IsChainHash(s string) bool {
	if len(s) != chainHashLen {
		return false
	}
	for i := range len(s) {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// fieldKind distinguishes the encodings a field can have. It is unexported: a
// caller picks an encoding by calling Str, NullableStr, Int, Float or Time, and
// cannot construct a Field with no encoding at all.
type fieldKind uint8

const (
	kindString fieldKind = iota
	kindNullableString
	kindInt
)

// Field is one value in an entry's canonical encoding.
//
// The zero Field is not usable and cannot be produced by this package's API,
// which is why the kind is unexported: a struct literal in a caller's package
// would otherwise silently encode as an empty string.
type Field struct {
	kind    fieldKind
	s       string
	i       int64
	present bool
}

// Str is a string field. Any bytes are allowed, including the separators a naive
// join would use, because the encoding is length-prefixed.
func Str(s string) Field { return Field{kind: kindString, s: s} }

// NullableStr distinguishes an absent value from an empty one, which a database
// NULL and an empty string need but a plain string cannot express. Encoding them
// identically would let one be substituted for the other without breaking the
// chain.
func NullableStr(s *string) Field {
	if s == nil {
		return Field{kind: kindNullableString}
	}
	return Field{kind: kindNullableString, s: *s, present: true}
}

// Int is an integer field, encoded as its decimal string.
func Int(i int64) Field { return Field{kind: kindInt, i: i} }

// Float is a floating point field, encoded as the shortest decimal string that
// round-trips. Provided so callers do not have to agree on a format separately:
// two encoders that disagree about float formatting produce two different hashes
// for the same record, and the disagreement only shows up as a verification
// failure much later.
func Float(f float64) Field { return Str(strconv.FormatFloat(f, 'g', -1, 64)) }

// Time is a timestamp field, normalized (see NormalizeTS) and encoded as
// RFC 3339 with nanoseconds.
//
// Normalizing here rather than at the call site is deliberate. The hash has to
// be reproducible from what the store actually persisted, so a caller who hashed
// a wall-clock time with more precision than the store keeps would write an
// entry that never verifies again.
func Time(t time.Time) Field { return Str(NormalizeTS(t).Format(time.RFC3339Nano)) }

// writeTo appends this field's canonical encoding to h.
func (f Field) writeTo(h hash.Hash) {
	switch f.kind {
	case kindNullableString:
		if !f.present {
			h.Write([]byte{0})
			return
		}
		h.Write([]byte{1})
		writeStr(h, f.s)
	case kindInt:
		writeStr(h, strconv.FormatInt(f.i, 10))
	default:
		writeStr(h, f.s)
	}
}

// Entry is one record's position in the chain and its content.
//
// Seq is the 1-based position within one chain. It is hashed first, ahead of
// every field, so a record cannot be moved to a different position without
// breaking its own hash.
//
// Fields is the content, in an order the caller fixes once and must never
// change. The order is part of the hash: reordering two fields, adding one, or
// removing one changes every hash written afterwards, and every entry already
// stored stops verifying. Treat the field list the way you would treat a
// database migration on a column you cannot drop.
type Entry struct {
	Seq    int64
	Fields []Field
}

// Compute returns the hex-encoded SHA-256 hash of this entry chained onto
// prevHash.
//
// This is the unkeyed form. It is evidence only against an adversary who cannot
// recompute it, and anyone who can write to the store can: edit a record, rehash
// it, rehash its successors, done. See ComputeKeyed.
func (e Entry) Compute(prevHash string) string {
	return e.compute("", nil, prevHash)
}

// ComputeKeyed returns the hex-encoded HMAC-SHA256 hash of this entry chained
// onto prevHash, under the key named keyID.
//
// The key closes the gap Compute leaves open: an adversary with write access to
// the store can still break the chain, but cannot repair it, because repairing
// it needs a secret that lives outside the store. Record which key signed each
// entry alongside it, and hand that id back at verification time.
//
// The id is hashed with the content, so an entry cannot be relabelled as signed
// by a different key, or by none, without breaking its own hash. An empty keyID
// with a nil secret is the unkeyed form and is byte-identical to Compute, so one
// call site can serve both a keyed and an unkeyed deployment.
func (e Entry) ComputeKeyed(keyID string, secret []byte, prevHash string) string {
	return e.compute(keyID, secret, prevHash)
}

func (e Entry) compute(keyID string, secret []byte, prevHash string) string {
	var h hash.Hash
	if keyID == "" {
		h = sha256.New()
	} else {
		h = hmac.New(sha256.New, secret)
	}
	writeInt(h, e.Seq)
	for _, f := range e.Fields {
		f.writeTo(h)
	}
	// The key id is bound into the content it signs, so relabelling a stored
	// entry changes what its own hash must be. Written only when keyed, which
	// keeps the unkeyed encoding byte-identical to what pre-keying entries were
	// hashed with. The two forms are already distinct constructions (SHA-256
	// against HMAC-SHA256), so nothing is ambiguous.
	if keyID != "" {
		writeStr(h, keyID)
	}
	// The link: prev_hash is appended raw (fixed-width hex) after all
	// length-prefixed content, exactly as the chain definition requires.
	h.Write([]byte(prevHash))
	return hex.EncodeToString(h.Sum(nil))
}

// NormalizeTS reduces a timestamp to UTC microseconds, which is the precision
// PostgreSQL's timestamptz persists. Store this exact value so a later
// verification recomputes the same hash. Callers on a store with different
// precision should normalize to that instead and encode with Str.
func NormalizeTS(t time.Time) time.Time { return t.UTC().Truncate(time.Microsecond) }

// writeStr writes an 8-byte big-endian length prefix followed by the raw bytes.
// The prefix is what makes the encoding unambiguous: without it, two records
// whose fields concatenate to the same bytes would hash identically, so a value
// containing the separator could impersonate a different field layout.
func writeStr(h hash.Hash, s string) {
	var lp [8]byte
	binary.BigEndian.PutUint64(lp[:], uint64(len(s)))
	h.Write(lp[:])
	h.Write([]byte(s))
}

// writeInt encodes an integer as its decimal string, length-prefixed, so it can
// never merge with an adjacent field.
func writeInt(h hash.Hash, v int64) {
	writeStr(h, strconv.FormatInt(v, 10))
}
