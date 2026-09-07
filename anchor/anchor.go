// Package anchor turns a project's audit hash chain into Merkle trees and
// signs periodic statements about which stretch of that chain each tree covers.
//
// The chain in the parent package is tamper-evident against edits: change a
// stored row and its own hash stops matching, and under an HMAC key a forger who
// cannot sign cannot repair what they broke. It is not evidence against
// DELETION AT THE TIP. Nothing stored says how long a chain is supposed to be,
// seq is allocated as COALESCE(MAX(seq), 0) + 1, and the verify walk bounds
// itself with MAX(seq) over whatever survives, so a prefix of a valid chain is a
// valid chain. That is an inherent hash-chain property, which is why the fix has
// to come from outside the chain.
//
// The fix is a signed checkpoint: a statement that LEAVES the database, so it
// can be compared back against what the database still holds. A checkpoint
// stored only in the Postgres an adversary can write to buys nothing, which is
// why the emission path (SIEM export, webhooks, the WORM archive) is the
// load-bearing part and not the storage.
//
// # A checkpoint covers a seq range, not "everything so far"
//
// A checkpoint commits to the leaves for seq in [StartSeq, EndSeq] and to
// nothing else. The first shipped design signed (size, root) over the first
// `size` leaves of the chain, which reads as "everything so far", and that
// collided head-on with retention: DeleteExpiredAgentAuditLogsPerTier removes
// rows by ts, oldest first, so the leaves under an older checkpoint stop
// existing while the checkpoint still stands. The root could then never be
// recomputed, and verification reported root_mismatch (the endpoint that tells a
// customer their audit log was rewritten) on a chain nobody had touched.
//
// Scoping to a range fixes that without weakening the claim:
//
//   - Older signed statements stay verifiable for as long as their leaves are
//     retained, rather than becoming unverifiable the moment the chain's oldest
//     row ages out.
//   - Each checkpoint means exactly what it covers. A verifier holding one does
//     not have to know what the chain looked like before it.
//   - Checkpoints chain: the next one starts at EndSeq+1, so the segments
//     partition the chain and purging the oldest segment costs the newest
//     nothing.
//   - A checkpoint whose range has been purged is IDENTIFIABLE as such, by
//     comparing its range against the seqs still stored, so verification can say
//     "no longer retained, cannot be checked" instead of "tampered".
//
// Both ends of the range are inside the signed note (see Marshal), never only in
// the columns beside it. An adversary who could edit the stored start_seq would
// otherwise reinterpret which leaves a signature covers, which is the same
// mistake as trusting a stored size.
//
// The Merkle maths is github.com/transparency-dev/merkle (RFC 6962, the
// verification core under Trillian and the Sigstore logs) and the checkpoint
// serialization is github.com/transparency-dev/formats. Hand-rolling either was
// rejected for the reason the codebase already gives for pg_query_go:
// correctness is the product, and a subtly wrong proof is worse than no proof
// because it is a claim of integrity nobody will re-check.
package anchor

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/merkle/compact"
	"github.com/transparency-dev/merkle/rfc6962"
)

// originSeparator joins a caller's namespace to the log's own id.
const originSeparator = "/"

// rangeLineKeyword introduces the checkpoint extension line carrying the seq
// range. The note format reserves everything after the third line for
// extensions, and note signatures cover the whole text, so an extension line is
// signed exactly as the origin, size and root are.
const rangeLineKeyword = "range"

// Origin is the log identity a series of checkpoints is issued under, built
// from a namespace the caller owns and the id of the one log it names.
//
// It is signed as part of the note, which is what stops a checkpoint for one log
// being replayed as a checkpoint for another. Both halves matter: the namespace
// keeps two systems that happen to use the same ids apart, and the id keeps two
// logs inside one system apart.
//
// Pick a namespace that is yours and will not change, because changing it
// invalidates every checkpoint already signed under the old one. A reverse-DNS
// name or a product name are both reasonable; an environment name is not, since
// promoting a database between environments would then break its history.
func Origin(namespace, id string) string { return namespace + originSeparator + id }

// rangeFactory builds compact ranges over the RFC 6962 node hash. It is
// stateless and safe to share.
var rangeFactory = &compact.RangeFactory{Hash: rfc6962.DefaultHasher.HashChildren}

// LeafHash is the tree leaf for one audit entry: the RFC 6962 leaf hash of the
// entry's stored entry_hash, taken as the ASCII hex string exactly as the
// database holds it.
//
// The chain hash is NOT recomputed here and must not be. Its bytes are frozen
// (see the note on auditchain.Entry.Compute), so hashing the stored string is
// both cheaper than rebuilding it and immune to drift between two encodings of
// the same row. It also means the tree commits to the chain rather than to a
// second, parallel reading of the same content.
func LeafHash(entryHash string) []byte {
	return rfc6962.DefaultHasher.HashLeaf([]byte(entryHash))
}

// Tree is the Merkle tree over one segment of a project's chain, held in the
// compact form: the minimal set of perfect subtree roots covering the leaves
// appended so far. That is O(log n) hashes, so a segment of any length is built
// without holding its leaves.
type Tree struct {
	rng *compact.Range
}

// NewTree returns an empty tree, which is where every segment starts.
func NewTree() *Tree {
	return &Tree{rng: rangeFactory.NewEmptyRange(0)}
}

// Append adds one leaf. Leaves must arrive in seq order, which is what makes the
// tree a commitment to the chain's order and not merely to its contents.
func (t *Tree) Append(leaf []byte) error {
	if err := t.rng.Append(leaf, nil); err != nil {
		return fmt.Errorf("audit anchor: append leaf: %w", err)
	}
	return nil
}

// AppendEntryHash is Append for a stored entry_hash.
func (t *Tree) AppendEntryHash(entryHash string) error {
	return t.Append(LeafHash(entryHash))
}

// Size is the number of leaves appended so far.
func (t *Tree) Size() uint64 { return t.rng.End() }

// Root is the hash committing to every leaf appended so far. An empty tree
// returns the hasher's empty root, which is a defined value rather than an
// error.
func (t *Tree) Root() ([]byte, error) {
	root, err := t.rng.GetRootHash(nil)
	if err != nil {
		return nil, fmt.Errorf("audit anchor: compute root: %w", err)
	}
	return root, nil
}

// RootFromLeaves builds a tree from leaves in order and returns its root. It is
// what both halves use: the anchor pass over a fresh segment, and verification,
// which holds every leaf and so recomputes the root at the checkpoint's range
// rather than accepting a consistency proof. See VerifyAgainstCheckpoint.
func RootFromLeaves(entryHashes []string) ([]byte, error) {
	t := NewTree()
	for _, h := range entryHashes {
		if err := t.AppendEntryHash(h); err != nil {
			return nil, err
		}
	}
	return t.Root()
}

// Checkpoint is a signed statement that the entries at seq StartSeq through
// EndSeq of a project's chain existed, in that order, with Merkle root Root, at
// the moment it was signed.
//
// It says nothing about the entries outside that range, deliberately. See the
// package comment.
type Checkpoint struct {
	Origin   string
	StartSeq int64
	EndSeq   int64
	Root     []byte
}

// Size is the number of leaves the checkpoint covers. It is derived from the
// range rather than stored beside it, so the two cannot disagree.
func (c Checkpoint) Size() uint64 { return uint64(c.EndSeq - c.StartSeq + 1) }

// Validate refuses a checkpoint that cannot mean anything: no origin, a range
// that starts before the chain does, or one that ends before it starts. Called
// on both the signing and the verifying side, because a malformed range must
// never be signed and must never be accepted.
func (c Checkpoint) Validate() error {
	if c.Origin == "" {
		return fmt.Errorf("audit anchor: checkpoint has no origin")
	}
	if c.StartSeq < 1 {
		return fmt.Errorf("audit anchor: checkpoint start_seq %d is not a chain position", c.StartSeq)
	}
	if c.EndSeq < c.StartSeq {
		return fmt.Errorf("audit anchor: checkpoint range [%d, %d] ends before it starts", c.StartSeq, c.EndSeq)
	}
	return nil
}

// Marshal renders the checkpoint in the transparency-log note body format
// (origin, leaf count, base64 root) plus the range extension line, which is what
// gets signed:
//
//	pgbeam/audit/prj_1
//	15
//	<base64 root>
//	range 6 20
//
// The range is IN the signed body. A verifier that read it from the row beside
// the note would be trusting the adversary this mechanism exists to catch: one
// edited start_seq would re-point a valid signature at a different set of
// leaves.
func (c Checkpoint) Marshal() []byte {
	body := log.Checkpoint{Origin: c.Origin, Size: c.Size(), Hash: c.Root}.Marshal()
	return append(body, fmt.Appendf(nil, "%s %d %d\n", rangeLineKeyword, c.StartSeq, c.EndSeq)...)
}

// RootHex is the root as the hex string stored alongside the note, so an
// operator can compare it without base64-decoding a note body.
func (c Checkpoint) RootHex() string { return hex.EncodeToString(c.Root) }

// UnmarshalCheckpoint parses a note body back into a checkpoint, refusing
// anything it cannot read as one whole statement: a missing or malformed range
// line, a range that ends before it starts, or a leaf count that disagrees with
// the range it is supposed to describe. Every one of those is a signed statement
// whose meaning is ambiguous, and an ambiguous statement about tampering is
// worth less than none.
//
// Callers should reach it through Signer.Verify rather than directly: an
// unsigned body is a claim by whoever handed it over, which is precisely the
// party this whole mechanism does not trust.
func UnmarshalCheckpoint(body []byte) (Checkpoint, error) {
	var lc log.Checkpoint
	rest, err := lc.Unmarshal(body)
	if err != nil {
		return Checkpoint{}, fmt.Errorf("audit anchor: parse checkpoint body: %w", err)
	}
	start, end, err := parseRangeLine(rest)
	if err != nil {
		return Checkpoint{}, err
	}
	cp := Checkpoint{Origin: lc.Origin, StartSeq: start, EndSeq: end, Root: lc.Hash}
	if err := cp.Validate(); err != nil {
		return Checkpoint{}, err
	}
	if lc.Size != cp.Size() {
		return Checkpoint{}, fmt.Errorf(
			"audit anchor: checkpoint claims %d leaves over range [%d, %d], which holds %d",
			lc.Size, cp.StartSeq, cp.EndSeq, cp.Size())
	}
	return cp, nil
}

// parseRangeLine reads the `range <start> <end>` extension line. It is the only
// extension this format defines, so anything else in the trailing data is
// refused rather than skipped: an extension nobody understands may be changing
// what the note means.
func parseRangeLine(rest []byte) (int64, int64, error) {
	line := strings.TrimSuffix(string(rest), "\n")
	if line == "" {
		return 0, 0, fmt.Errorf("audit anchor: checkpoint carries no %s line", rangeLineKeyword)
	}
	if strings.Contains(line, "\n") {
		return 0, 0, fmt.Errorf("audit anchor: checkpoint carries unknown extension lines")
	}
	fields := strings.Fields(line)
	if len(fields) != 3 || fields[0] != rangeLineKeyword {
		return 0, 0, fmt.Errorf("audit anchor: checkpoint %s line is malformed: %q", rangeLineKeyword, line)
	}
	start, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("audit anchor: checkpoint start_seq %q: %w", fields[1], err)
	}
	end, err := strconv.ParseInt(fields[2], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("audit anchor: checkpoint end_seq %q: %w", fields[2], err)
	}
	return start, end, nil
}
