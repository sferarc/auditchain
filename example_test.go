package auditchain_test

import (
	"fmt"
	"time"

	"github.com/sferarc/auditchain"
)

// A record is an ordered list of typed fields. The order is yours to choose and
// yours to keep: it is part of every hash you write.
func ExampleEntry_Compute() {
	entry := auditchain.Entry{
		Seq: 1,
		Fields: []auditchain.Field{
			auditchain.Str("alice"),
			auditchain.Str("deleted project"),
			auditchain.Int(1),
			auditchain.Time(time.Date(2026, 3, 1, 9, 30, 0, 0, time.UTC)),
		},
	}

	fmt.Println(entry.Compute(auditchain.GenesisPrevHash))
	// Output: 0700fd57f58097f350b39e4e26db1f2d699e73f575608cbdf21b85e4f467a2ca
}

// Chaining is the caller's loop: each record's hash becomes the next record's
// prev. Store the hash alongside the record.
func ExampleEntry_ComputeKeyed() {
	// A secret the database credentials do not grant. Hard-coded here only so
	// the example is runnable.
	secret := []byte("an-example-secret-at-least-32-byt")

	prev := auditchain.GenesisPrevHash
	for i, actor := range []string{"alice", "bob"} {
		entry := auditchain.Entry{
			Seq:    int64(i + 1),
			Fields: []auditchain.Field{auditchain.Str(actor)},
		}
		prev = entry.ComputeKeyed("v1", secret, prev)
	}

	fmt.Println(len(prev), auditchain.IsChainHash(prev))
	// Output: 64 true
}

// Verification walks the stored records in order, checking each against the hash
// it carries under the key it names. The verifier also reports a chain that ends
// in unsigned records after signed ones, which is what a forger who cannot sign
// produces.
func ExampleChainVerifier() {
	keys, err := auditchain.ParseKeyring("v1:" + "ab" + "cd" + "ef01" + "23456789" +
		"abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err != nil {
		fmt.Println("keyring:", err)
		return
	}
	keyID := keys.ActiveKeyID()
	secret, _ := keys.Secret(keyID)

	entry := auditchain.Entry{Seq: 1, Fields: []auditchain.Field{auditchain.Str("alice")}}
	stored := entry.ComputeKeyed(keyID, secret, auditchain.GenesisPrevHash)

	v := auditchain.NewChainVerifier(keys, "")
	fmt.Println("intact:", v.Check(entry, keyID, auditchain.GenesisPrevHash, stored) == auditchain.ChainOK)

	edited := auditchain.Entry{Seq: 1, Fields: []auditchain.Field{auditchain.Str("mallory")}}
	fmt.Println("edited:", auditchain.NewChainVerifier(keys, "").Check(edited, keyID, auditchain.GenesisPrevHash, stored))

	// Output:
	// intact: true
	// edited: hash_mismatch
}
