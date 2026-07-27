// The blinded sighting test: a two-party private membership test over a small
// universe, on Curve25519 with x-only Elligator 2 hashing.
//
// WHAT IT COMPUTES. Two parties each hold one secret element and a set of elements.
// After one round trip both learn EXACTLY ONE BIT ("is your element in my set?")
// and nothing else. In a game that bit is "are we in sight of each other"; the
// library itself does not know or care where the sets came from.
//
// WHY HASH-TO-CURVE IS LOAD-BEARING. With P_e = H(e)*G the discrete log of every
// set element is PUBLIC, and a receiver of a blinded set {alpha*P_e} recovers the
// WHOLE set in about 3*|universe| scalar multiplications: take two elements, form
// {h_v^-1 * X_i} for every candidate v, and intersect. The intersection is
// alpha*G, after which every element labels itself. Elligator 2 gives points whose
// discrete logs nobody knows, which is the entire difference between blinding and
// encoding. Do not "simplify" this. See paper/ section 6, Proposition 1.
//
// DETERMINISM IS THE POINT. Every byte these functions emit is a pure function of
// (seed, round, element, set): the blinding scalar is
// SHA256("DCHP" || seed || LE32(round)) masked to 252 bits, the pad dummies are
// H2C("DCHD" || seed || LE16(i)), round-INdependent on purpose so a client can
// precompute every curve point it will ever hash. Element points are
// H2C("DCHT" || LE16(code)), and the set is sorted by encoded bytes. That is what
// lets a later audit recompute any element from a revealed seed and attribute a
// byte that differs to whoever sent it.
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

// Sets are padded to this fixed size with seed-derived dummies, so neither the
// message length nor the work done leaks anything about the sender's set size.
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

// FLIGHT 1: S = sort_by_bytes{ alpha_r * P_e : e in `elements` }, padded to PET_PAD
// with blinded dummies, followed by Q = alpha_r * P_own. Writes PET_BUILD_BYTES.
//
// `elements` are the codes this party is asking about: in a game, the tiles it can
// see, INCLUDING its own. Duplicates are permitted and simply waste a slot. Returns
// PET_BUILD_BYTES, or -1 on a null argument or a set larger than PET_PAD.
int petBuild(const uint8_t seed[HASH_BYTES], uint16_t round, uint16_t ownElement,
             const uint16_t* elements, int count, uint8_t* out);

// FLIGHT 2: out = alpha_r * theirQ. Returns 0 or -1.
int petRespond(const uint8_t seed[HASH_BYTES], uint16_t round,
               const uint8_t theirQ[32], uint8_t out[32]);

// THE BIT: is alpha_me * theirR present in { alpha_me * s : s in theirS }?
// theirS is their flight-1 set (PET_PAD entries), theirR their flight-2 response to
// MY Q. Returns 1 (their set contains my element), 0 (it does not), -1 (bad args).
//
// Both parties get the same answer when the underlying relation is symmetric, which
// is what makes "the" shared bit well defined. An asymmetric relation is outside
// what this construction can express.
int petFinish(const uint8_t seed[HASH_BYTES], uint16_t round,
              const uint8_t* theirS, const uint8_t theirR[32]);

// SHA256("DCHV" || flight1 || flight2): the value a party publishes to bind itself
// to the bytes it actually sent, so a poisoned flight is attributable after the
// fact rather than deniable. Covering flight 2 is not optional, because returning a
// doctored R flips a peer's bit without touching the set.
void petFlightHash(const uint8_t* flight1, const uint8_t flight2[32],
                   uint8_t out[HASH_BYTES]);

} // namespace fow
