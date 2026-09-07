# auditchain

Tamper-evident append-only logs for Go.

```
go get github.com/sferarc/auditchain
```

The core package has **no dependencies outside the standard library**. The `anchor` subpackage adds Merkle checkpoints and pulls in the [transparency-dev](https://github.com/transparency-dev) libraries; you only pay for it if you import it.

## The threat model, first

This defends against an adversary who can **write to the store** but cannot reach the HMAC key.

That is the realistic shape of the problem. The database holding an audit log is usually reachable by more people, and more software, than the one process that writes it: a support tool with production credentials, a migration, a backup restore, an ORM console, anyone with the connection string.

It does **not** defend against an adversary who holds the key, and it says nothing about whether the records were truthful when written. It attests to what was recorded, not to what happened.

If your threat model is a corrupted disk rather than a person, you want checksums, not this.

## What it catches, and the one thing it does not

| Tampering | Detected | How |
| --- | --- | --- |
| Editing a record | yes | Its own hash stops matching. |
| Deleting from the middle | yes | The walk sees a gap in the sequence. |
| Editing, then rehashing the rest | yes, when keyed | Repairing the chain needs the HMAC key. |
| Truncating the tail, then continuing | yes, when keyed | `ChainKeyDowngrade`: a forger who cannot sign leaves unsigned records after signed ones. |
| **Truncating the tail and stopping** | **no** | Nothing inside a chain records how long it is supposed to be. |

The last row is not a defect in this implementation, and it is not specific to it. A prefix of a valid hash chain is a valid hash chain, so every hash-chain audit log has this property whether or not its documentation says so. Truncating and stopping is also the cheapest attack available, because stopping is free.

Closing it needs a statement that **leaves the store**, so it can be compared back against what the store still holds. That is the `anchor` subpackage.

## Usage

A record is an ordered list of typed fields. You choose the fields; the chain hashes them.

```go
entry := auditchain.Entry{
    Seq: 1,
    Fields: []auditchain.Field{
        auditchain.Str("alice"),
        auditchain.Str("deleted project"),
        auditchain.Int(1),
        auditchain.Time(time.Now()),
    },
}

hash := entry.ComputeKeyed(keyID, secret, prevHash)
```

Store `hash` next to the record. It becomes the next record's `prevHash`. The first record in a chain uses `auditchain.GenesisPrevHash`.

Verification walks stored records in order:

```go
v := auditchain.NewChainVerifier(keys, predecessorKeyID)
for _, r := range rows {
    switch v.Check(r.Entry, r.KeyID, r.PrevHash, r.EntryHash) {
    case auditchain.ChainOK:
    case auditchain.ChainHashMismatch: // the record was edited
    case auditchain.ChainUnknownKey:   // signed by a key this deployment lacks
    }
}
if seq, ok := v.PendingDowngradeSeq(); ok {
    // the chain ends in unsigned records that no signed record vouches for
}
```

### Field order is frozen

The order of `Fields` is part of every hash. Reordering, inserting or removing a field changes all future hashes and stops every stored record from verifying.

Fix the order once, write it down in one place, and pin it with a test against known hashes. Adding a column to your table does **not** mean adding a field here: that needs a version marker on the record and a verifier that selects the encoding by version.

### Keys

```go
keys, err := auditchain.ParseKeyring("v2:<64 hex>,v1:<64 hex>")
```

First key signs, the rest verify. Rotation is additive: prepend the new key and keep the old one. Records already written keep verifying under the key that signed them, and nothing is rewritten.

An empty spec yields a nil keyring, which is the unkeyed deployment. That is a valid configuration and not an error, but read the threat model above before choosing it.

### One property worth knowing

`Int(7)` and `Str("7")` produce identical bytes, because an integer is encoded as its length-prefixed decimal string. This is safe because the field order is fixed, so position already decides what a field means and a field is only ever compared against the same field of another record. It is called out because it is easy to assume the opposite.

Nullable fields are the exception: `NullableStr` writes a presence byte, so an absent value and a present one never hash alike.

## Anchoring

```go
import "github.com/sferarc/auditchain/anchor"
```

`anchor` builds a Merkle tree over a stretch of the chain and signs a checkpoint committing to it. A checkpoint covers a **range** of sequence numbers, not "everything so far", so that retention deleting old records does not make older checkpoints unverifiable. Checkpoints chain: the next starts where the last ended.

Two design notes, both counterintuitive enough to be worth stating:

**Advance the tree in a background job, not in the write transaction.** Tree state in the same store as the records is rolled back by the same adversary who rolls back the records, so maintaining it inline buys no integrity the signed checkpoint does not already carry, and puts risk on the write path for nothing.

**A verifier that holds the records should recompute the root, not check a consistency proof.** Consistency proofs exist for verifiers that do _not_ hold the leaves. If you have them, rebuilding the tree and comparing roots is stronger and needs no proof storage. Save consistency proofs for a third party auditing you from outside.

### Known blind spot

`compact.RangeFactory.NewRange` validates only the node count, and a compact range's node count is the popcount of its size, so restoring size 9 from a size 6 range is accepted. What actually catches an incoherent tree is the checkpoint comparison: a wrong state produces a wrong root, and the root is what the signature covers.

## Status and provenance

Developed for and used in production by [PgBeam](https://pgbeam.com), where it backs the audit trail for AI agent database access. It is maintained as a standalone library because the problem is not specific to that product.

Issues and pull requests are welcome here. Changes are synchronised with the repository it is developed in, so a merged pull request lands in both.

## License

Apache-2.0.
