// Package auditchain builds tamper-evident append-only logs.
//
// Each record is bound to its predecessor by a hash over its own content and the
// previous record's hash, so editing or deleting a record breaks every hash after
// it. The chain says nothing about what a record means: it hashes an ordered list
// of typed fields, and the caller decides what those fields are.
//
// # Threat model
//
// This defends against an adversary who can WRITE TO THE STORE but cannot reach
// the HMAC key. That is the realistic shape of the problem: the database holding
// an audit log is usually reachable by more people, and more software, than the
// process that writes it.
//
// An unkeyed chain (Entry.Compute) is only evidence against someone who cannot
// recompute it, and anyone with write access can: edit a record, rehash it,
// rehash its successors, done. Entry.ComputeKeyed closes that by making each hash
// an HMAC under a secret the store's own credentials do not grant. The same
// adversary can still break the chain, but cannot repair it.
//
// The key therefore has to live somewhere the store does not. A signing key kept
// in the database it makes claims about protects nothing.
//
// # What this catches, and the one thing it does not
//
//	Editing a record          caught. Its own hash stops matching.
//	Deleting from the middle  caught. The walk sees a gap in the sequence.
//	Truncating the tail and
//	  continuing unsigned     caught. ChainKeyDowngrade: a forger who cannot
//	                          sign leaves unsigned records after signed ones.
//	Truncating the tail and
//	  STOPPING                NOT CAUGHT.
//
// The last row is not a bug in this implementation. Nothing inside a hash chain
// records how long the chain is supposed to be, so a prefix of a valid chain is
// itself a valid chain. Every hash-chain audit log has this property, whether or
// not its documentation mentions it.
//
// Closing it needs a statement that LEAVES the store, so it can be compared back
// against what the store still holds. That is what the anchor subpackage does:
// it builds Merkle trees over stretches of the chain and signs checkpoints over
// them. A checkpoint kept only in the database an adversary can write to buys
// nothing, so the part that matters is shipping it somewhere else.
//
// # Field order is frozen
//
// The order of Entry.Fields is part of every hash. Reordering, inserting or
// removing a field changes all future hashes and stops every stored record from
// verifying. Fix the order once, write it down, and pin it with a test against
// known hashes. Adding a column to your table does not mean adding a field here;
// that needs a version marker on the record and a verifier that picks the
// encoding by version.
package auditchain
