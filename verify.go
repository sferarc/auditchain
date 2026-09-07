package auditchain

import "crypto/hmac"

// ChainCheck is the outcome of verifying one stored entry against the hash it
// carries. The non-empty values are the machine-readable failure kinds the
// verification endpoint reports.
type ChainCheck string

const (
	// ChainOK means the entry's stored hash is the one its content produces
	// under the key it claims.
	ChainOK ChainCheck = ""
	// ChainHashMismatch means the content was edited after the fact.
	ChainHashMismatch ChainCheck = "hash_mismatch"
	// ChainUnknownKey means the entry was signed by a key this deployment does
	// not hold, so it can be neither confirmed nor called tampered. Reported as
	// a failure rather than skipped: an unverifiable stretch of the chain is not
	// an attested one, and silently passing it is how a key-shaped hole becomes
	// invisible.
	ChainUnknownKey ChainCheck = "unknown_key"
	// ChainKeyDowngrade means the chain ends in unkeyed entries that follow a
	// signed one. That is what a forger who cannot sign produces after
	// truncating a signed chain and continuing it with hashes they can compute.
	// It is reported by the caller at the end of the walk rather than returned
	// by Check, because an unkeyed entry mid-chain is not yet evidence of
	// anything: see PendingDowngradeSeq.
	ChainKeyDowngrade ChainCheck = "key_downgrade"
)

// ChainVerifier checks a project's entries in seq order, each under the key it
// records, and tracks whether the chain ends in a run of unsigned entries that
// no signed entry vouches for.
//
// It is stateful across a walk and not safe for concurrent use: one verifier per
// verification, entries fed in ascending seq.
type ChainVerifier struct {
	keys *Keyring
	// keyed records whether any entry so far (including the one before the
	// window, when the walk starts mid-chain) was signed.
	keyed bool
	// downgradeSeq is where the current run of unkeyed-after-signed entries
	// began, or 0 when there is no such run outstanding. A later signed entry
	// clears it.
	downgradeSeq int64
}

// NewChainVerifier returns a verifier for a walk whose immediate predecessor was
// signed by predecessorKeyID (empty when the entry before the window was unkeyed
// or there is none). Passing it matters: without it, a window that starts after
// the point where signing began would read its unsigned entries as an ordinary
// pre-keying prefix rather than as a downgrade.
//
// A nil keyring is the unkeyed deployment. It verifies unkeyed entries normally
// and reports every keyed one as ChainUnknownKey, which is the honest answer:
// that deployment cannot attest entries it has no key for.
func NewChainVerifier(keys *Keyring, predecessorKeyID string) *ChainVerifier {
	return &ChainVerifier{keys: keys, keyed: predecessorKeyID != ""}
}

// Check verifies one entry against its stored keyID, prevHash and entryHash, and
// advances the verifier's view of the chain. Entries must be passed in seq
// order. It reports only hash and key outcomes; sequence gaps and prev_hash
// links belong to the caller walking the chain, and the downgrade verdict to
// PendingDowngradeSeq once the walk is done.
func (v *ChainVerifier) Check(e Entry, keyID, prevHash, entryHash string) ChainCheck {
	if keyID == "" {
		if e.Compute(prevHash) != entryHash {
			return ChainHashMismatch
		}
		// An unkeyed entry after a signed one opens a run that has to be
		// vouched for by a later signed entry (see PendingDowngradeSeq).
		if v.keyed && v.downgradeSeq == 0 {
			v.downgradeSeq = e.Seq
		}
		return ChainOK
	}

	secret, ok := v.keys.Secret(keyID)
	if !ok {
		return ChainUnknownKey
	}
	// hmac.Equal rather than ==: the comparison is over a value derived from a
	// secret, and a constant-time compare costs nothing here.
	if !hmac.Equal([]byte(e.ComputeKeyed(keyID, secret, prevHash)), []byte(entryHash)) {
		return ChainHashMismatch
	}
	v.keyed = true
	// A valid signed entry vouches for the unkeyed run before it: producing this
	// entry needed the key, so whoever wrote it held the key while those entries
	// were already in the chain. This is what makes turning signing on a
	// non-event. A rolling deploy runs signed and unsigned writers side by side
	// for a few minutes, and without this the interleave they produce would be
	// indistinguishable from a forged tail and would fail verification of that
	// window for good.
	v.downgradeSeq = 0
	return ChainOK
}

// PendingDowngradeSeq returns the seq where the chain's trailing run of unkeyed
// entries began, and whether there is one. Non-zero at the end of a walk means
// the range ends in entries that follow a signed entry and are not vouched for
// by any signed entry after them, which is the shape of a truncated chain
// continued by someone without the key.
//
// A caller whose walk was bounded to a seq window should check whether the chain
// continues past the window with a signed entry before reporting: the run may
// simply be the enablement interleave, with the entry that vouches for it just
// outside the range asked about.
func (v *ChainVerifier) PendingDowngradeSeq() (int64, bool) {
	return v.downgradeSeq, v.downgradeSeq > 0
}
