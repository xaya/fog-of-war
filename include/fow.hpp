// The blinded sighting test: a two-party private membership test over a small
// universe, on Curve25519 with x-only Elligator 2 hashing.
//
// WHAT IT COMPUTES. Two parties each hold one secret element and a set of elements.
// After one round trip both learn EXACTLY ONE BIT ("is your element in my set?")
// and nothing else -- under the hypotheses stated in paper/ sections 4 and 6; note
// in particular that a malicious party can aim its own question at any element it
// names. In a game that bit is "are we in sight of each other"; the library itself
// does not know or care where the sets came from.
//
// WHY HASH-TO-CURVE IS LOAD-BEARING. With P_e = H(e)*G the discrete log of every
// set element is PUBLIC, and a receiver of a blinded set {alpha*P_e} recovers the
// WHOLE set in about 3*|universe| scalar multiplications: take two elements, form
// {h_v^-1 * X_i} for every candidate v, and intersect. The intersection is
// alpha*G, after which every element labels itself. Elligator 2 gives points whose
// discrete logs nobody knows, which is the entire difference between blinding and
// encoding. Do not "simplify" this. See paper/ section 6, "Unknown discrete
// logarithms are load-bearing", and Remark 1.
//
// DETERMINISM IS THE POINT. Every byte these functions emit is a pure function of
// (seed, round, element, set): the blinding scalar is
// SHA256("DCHP" || seed || LE32(round)) masked to 252 bits, the pad dummies are
// H2C("DCHD" || seed || LE32(round) || LE16(i)), round-DEPENDENT on purpose: a
// surrounding protocol that ever publishes a round's alpha (the deployed game's
// disputes do) would otherwise unblind pad points that stay in service forever,
// and each recovered point replayed as a query reads a threshold bit about the
// current set size -- the one thing the fixed-size pad exists to hide. Element
// points are H2C("DCHT" || LE16(code)), round-free and precomputable, and the set
// is sorted by encoded bytes. That is what lets a later audit recompute any
// element from a revealed seed and attribute a byte that differs to whoever sent
// it. (The dummy preimage grew its round field on 2026-07-30, with the deployed
// game; the frozen vectors in tests/ moved with it.)
//
// The four-byte domain tags are the ones DEPLOYED in Xaya's dungeonchannel, kept
// verbatim so this reference implementation is byte-identical to the running game
// (tests/test_fow.cpp pins that with a vector taken from it). A different
// deployment should pick its own tags.
#pragma once

#include <cstdint>

namespace fow {

constexpr int HASH_BYTES = 32;

// ---------------------------------------------------------------------------
// Raw group operations (Montgomery u-coordinates, 32-byte little-endian, canonical)
// ---------------------------------------------------------------------------

// out = scalar * point, RFC 7748 ladder over 255 bits of `scalar` AS GIVEN, with no
// clamping, because these scalars must compose multiplicatively
// (a*(b*P) == b*(a*P)) and every point fed in is cofactor-cleared. Clamping would
// also break auditability: the transcript must be a pure function of the derived
// scalar with no hidden transformation. Returns false only on a null argument.
bool scalarMult(const uint8_t scalar[32], const uint8_t point[32], uint8_t out[32]);

// Elligator 2 (Z = 2, x-only) of SHA-256 over `msg`, cofactor cleared by *8.
// Deterministic, on-curve, dlog unknown to everyone including the caller.
void hashToPoint(const uint8_t* msg, uint32_t len, uint8_t out[32]);

// ---------------------------------------------------------------------------
// The test
// ---------------------------------------------------------------------------

// Sets are padded to this fixed size with dummies derived from (seed, round), so
// neither the message length nor the work done leaks anything about the sender's
// set size.
constexpr int PET_PAD = 128;
constexpr int PET_POINT_BYTES = 32;
// One direction's first flight: the sorted blinded set S, then the blinded own
// element Q.
constexpr int PET_BUILD_BYTES = (PET_PAD + 1) * PET_POINT_BYTES;

// The round's blinding scalar: SHA256("DCHP" || seed || LE32(round)), top four bits
// cleared (< 2^252, inside the prime-order group's scalar range for every practical
// purpose), never all-zero. Fresh every round, so linking one round's blinded
// element to the next is DDH; recomputable later from a revealed seed.
void petScalar(const uint8_t seed[HASH_BYTES], uint16_t round, uint8_t out[32]);

// The curve point for an element code. Public, cacheable, secret-free.
void elementPoint(uint16_t code, uint8_t out[32]);

// FLIGHT 1: S = sort_by_bytes{ alpha_r * P_e : e in `elements`, padded to PET_PAD
// with blinded dummies D_{r,j} } -- all PET_PAD entries sorted TOGETHER, so the
// wire order never shows where the elements end and the pad begins -- followed by
// Q = alpha_r * P_own. Writes PET_BUILD_BYTES.
//
// `elements` are the codes this party is asking about: in a game, the tiles it can
// see, INCLUDING its own. Duplicates are permitted and simply waste a slot. Returns
// PET_BUILD_BYTES, or -1 on a null argument or a set larger than PET_PAD.
int petBuild(const uint8_t seed[HASH_BYTES], uint16_t round, uint16_t ownElement,
             const uint16_t* elements, int count, uint8_t* out);

// FLIGHT 2: out = alpha_r * theirQ. Returns 0 or -1.
int petRespond(const uint8_t seed[HASH_BYTES], uint16_t round,
               const uint8_t theirQ[32], uint8_t out[32]);

// THE BIT: is theirR present in { alpha_me * s : s in theirS }?
// theirS is their flight-1 set (PET_PAD entries), theirR their flight-2 response to
// MY Q. Returns 1 (their set contains my element), 0 (it does not), -1 (bad args).
//
// Both parties get the same answer when the underlying relation is symmetric, which
// is what makes "the" shared bit well defined. An asymmetric relation is outside
// what this construction can express.
int petFinish(const uint8_t seed[HASH_BYTES], uint16_t round,
              const uint8_t* theirS, const uint8_t theirR[32]);

// ---------------------------------------------------------------------------
// Binding a party to the sighting bytes it really sent
// ---------------------------------------------------------------------------
//
// The value a party publishes is a MERKLE ROOT over its own flight, not
// a flat hash of it. Both bind the sender equally, since the surrounding protocol
// signs the message that carries it, but the root also lets a dispute prove ONE
// element without shipping the other 129. That is the difference between a 350-byte dispute and a 4.2 kB one,
// on chain and in state, and disputes are the only path that ever pays it.
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
void petFlightHash(const uint8_t* flight1, const uint8_t flight2[32],
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
