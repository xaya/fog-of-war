// Deterministic blinded membership testing over Curve25519 with x-only Elligator 2.
// Code by Xaya Developers; see LICENSE and the paper for scope and attribution.
//
// Honest parties compute whether their own element is in the peer's set. The
// results are directed and need not agree. This raw API does not authenticate
// inputs, validate peer points or prove privacy against active deviations.
// Duplicate points and query/set overlap are visible in the transcript.
//
// alpha = SHA256("DCHP" || seed || LE32(round)), masked to 252 bits, with zero
// replaced by one. Elements use H2C("DCHT" || LE16(code)); padding uses
// H2C("DCHD" || seed || LE32(round) || LE16(index)). The round-dependent pad
// avoids reusing raw dummy points after a single round's scalar is disclosed.
// Revealing the seed still exposes its whole epoch retrospectively.
//
// The tags and fixture describe the historical Dungeon Channel sight exchange,
// not the current game's sealed-envelope wire. Use independent random seeds per
// party and match; never reuse one after disclosure or round-counter wrap.
// Sorting and comparisons are data-dependent, so this is not constant-time.
// Merkle helpers share scratch storage: serialize their calls.
#pragma once

#include <cstdint>

namespace fow {

constexpr int HASH_BYTES = 32;

// ---------------------------------------------------------------------------
// Raw group operations (Montgomery u-coordinates, 32-byte little-endian, canonical)
// ---------------------------------------------------------------------------

// out = scalar * point, RFC 7748 ladder over 255 bits of `scalar` AS GIVEN, with no
// clamping, because these scalars must compose multiplicatively
// (a*(b*P) == b*(a*P)) and the points this library derives itself are
// cofactor-cleared; peer-supplied points are not validated. Clamping would
// also break auditability: the transcript must be a pure function of the derived
// scalar with no hidden transformation. Returns false only on a null argument.
bool scalarMult(const uint8_t scalar[32], const uint8_t point[32], uint8_t out[32]);

// Elligator 2 (Z = 2, x-only) of SHA-256 over `msg`, cofactor cleared by *8.
// Deterministic encoding intended to have unknown discrete logarithms. This is
// not the RFC 9380 uniform hash-to-curve suite; see the paper's assumptions.
void hashToPoint(const uint8_t* msg, uint32_t len, uint8_t out[32]);

// ---------------------------------------------------------------------------
// The test
// ---------------------------------------------------------------------------

// Sets are padded to this fixed size with dummies derived from (seed, round), so
// message length is independent of set size. Equality patterns remain visible;
// this does not establish constant-time execution.
constexpr int PET_PAD = 128;
constexpr int PET_POINT_BYTES = 32;
// One direction's first flight: the sorted blinded set S, then the blinded own
// element Q.
constexpr int PET_BUILD_BYTES = (PET_PAD + 1) * PET_POINT_BYTES;

// The round's blinding scalar: SHA256("DCHP" || seed || LE32(round)), top four bits
// cleared (< 2^252 < the subgroup order, so nonzero modulo it), never all-zero.
// Recomputable later from a revealed seed. The paper distinguishes this
// derivation from a proof of cross-round privacy.
void petScalar(const uint8_t seed[HASH_BYTES], uint16_t round, uint8_t out[32]);

// The curve point for an element code. Public, cacheable, secret-free.
void elementPoint(uint16_t code, uint8_t out[32]);

// FLIGHT 1: S = sort_by_bytes{ alpha_r * P_e : e in `elements`, padded to PET_PAD
// with blinded dummies D_{r,j} } -- all PET_PAD entries sorted TOGETHER, so the
// wire order never shows where the elements end and the pad begins -- followed by
// Q = alpha_r * P_own. Writes PET_BUILD_BYTES.
//
// `elements` are the codes this party is asking about: in a game, the tiles it can
// see, including its own. Duplicates are permitted but visible as repeated points.
// Returns PET_BUILD_BYTES, or -1 on invalid arguments or a set larger than PET_PAD.
int petBuild(const uint8_t seed[HASH_BYTES], uint16_t round, uint16_t ownElement,
             const uint16_t* elements, int count, uint8_t* out);

// FLIGHT 2: out = alpha_r * theirQ. Returns 0 or -1. Answer exactly one Q per
// seed, round and peer: this is a pure function and enforces no limit, and every
// extra answer is one more chosen-point read of this party's set.
int petRespond(const uint8_t seed[HASH_BYTES], uint16_t round,
               const uint8_t theirQ[32], uint8_t out[32]);

// THE BIT: is theirR present in { alpha_me * s : s in theirS }?
// theirS is their flight-1 set (PET_PAD entries), theirR their flight-2 response to
// MY Q. Returns 1 (their set contains my element), 0 (it does not), -1 (bad args).
//
// Both parties get the same answer when the underlying relation is symmetric, which
// defines a shared bit. Asymmetric relations give two directed results.
int petFinish(const uint8_t seed[HASH_BYTES], uint16_t round,
              const uint8_t* theirS, const uint8_t theirR[32]);

// ---------------------------------------------------------------------------
// Binding a party to the sighting bytes it really sent
// ---------------------------------------------------------------------------
//
// The value a party publishes is a MERKLE ROOT over its own flight, not
// a flat hash of it. The surrounding protocol must authenticate that root.
// A point (32 bytes), index (2) and path (256) prove one leaf in 290 bytes.
// This authenticates a transcript entry, not its correctness or a full dispute.
//
// BOTH flights are covered, and the flight-2 half is not padding. Poisoning the SET is
// only one of the two ways to flip a peer's bit. Answering with a doctored R works
// too, and needs no guess about the peer's position, so a commitment over the set
// alone would leave the cheaper attack unattributable.
//
// LEAF LAYOUT, which is wire contract:
//   0 .. PET_PAD-1   the blinded set S, in its canonical sorted order
//   PET_PAD          Q, the sender's own blinded element
//   PET_PAD+1        R, the flight-2 response
//   the rest         zero padding, up to PET_MERKLE_LEAVES
//
// Leaves and interior nodes are domain-separated by a 0x00 / 0x01 prefix byte so a
// node can never be reinterpreted as a leaf (the standard second-preimage defence),
// and the leaf index is inside the leaf preimage so an element cannot be moved to a
// different slot.
constexpr int PET_MERKLE_DEPTH = 8;                       // 2^8 = 256 >= 130 leaves
constexpr int PET_MERKLE_LEAVES = 1 << PET_MERKLE_DEPTH;
constexpr int PET_MERKLE_PATH_BYTES = PET_MERKLE_DEPTH * HASH_BYTES;
constexpr int PET_LEAF_Q = PET_PAD;                       // index of Q
constexpr int PET_LEAF_R = PET_PAD + 1;                   // index of R
constexpr int PET_LEAVES_USED = PET_PAD + 2;

// The root. flight1 is PET_BUILD_BYTES (S then Q); flight2 is the 32-byte response.
// Returns 0, or -1 on a null argument (out untouched).
int petFlightHash(const uint8_t* flight1, const uint8_t flight2[32],
                  uint8_t out[HASH_BYTES]);

// The sibling path for one leaf, bottom level first: PET_MERKLE_PATH_BYTES bytes.
// Returns 0, or -1 on a bad index or a null argument. Only the prover needs this; a
// verifier only ever checks a path.
int petMerklePath(const uint8_t* flight1, const uint8_t flight2[32], int leafIndex,
                  uint8_t* outPath);

// Recompute the root from one leaf and its path, and compare against `root`. This is
// the ONLY half of the tree a verifier runs, and it costs PET_MERKLE_DEPTH hashes.
// Returns 1 if the leaf really is at that index of that root, 0 if not, -1 on a bad
// argument. `leaf` is the 32-byte point claimed to sit at `leafIndex`.
int petMerkleVerify(int leafIndex, const uint8_t leaf[32], const uint8_t* path,
                    const uint8_t root[HASH_BYTES]);

} // namespace fow
