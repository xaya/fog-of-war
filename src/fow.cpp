// Curve25519 x-only arithmetic, Elligator 2, and the blinded sighting test.
// See include/fow.hpp for what this is and why hash-to-curve is load-bearing.
//
// The field code is the standard 5x51-bit representation (donna/ref10 lineage),
// written out here rather than vendored because the deployment this was extracted
// from imports nothing and vendors nothing. Products use unsigned __int128, which
// clang lowers to i64 pairs for wasm32: no imports, no intrinsics beyond the
// compiler.
//
// NOTHING HERE IS SECRET-DEPENDENT IN ITS BRANCHING except the final equality tests
// in petFinish, which decide the bit both sides are about to learn anyway. The
// ladder runs a fixed 255 iterations with arithmetic swaps; the Elligator
// exceptional case is a constant-time select in spirit if not in ceremony --
// consensus needs determinism first, and none of this runs under an attacker's
// stopwatch on a metered path.

#include "fow.hpp"
#include "sha256.hpp"

#include <cstring>

namespace fow {
namespace {

// ---------------------------------------------------------------------------
// Field arithmetic mod p = 2^255 - 19, 5 limbs of 51 bits
// ---------------------------------------------------------------------------
struct fe {
  uint64_t v[5];
};

constexpr uint64_t MASK51 = 0x7FFFFFFFFFFFFULL;

void feZero(fe& o) { for (int i = 0; i < 5; ++i) o.v[i] = 0; }
void feOne(fe& o) { o.v[0] = 1; for (int i = 1; i < 5; ++i) o.v[i] = 0; }
void feCopy(fe& o, const fe& a) { for (int i = 0; i < 5; ++i) o.v[i] = a.v[i]; }

void feAdd(fe& o, const fe& a, const fe& b) {
  for (int i = 0; i < 5; ++i) o.v[i] = a.v[i] + b.v[i];
}

// a - b, with 2p added first so no limb underflows (inputs weakly reduced).
void feSub(fe& o, const fe& a, const fe& b) {
  o.v[0] = a.v[0] + 0xFFFFFFFFFFFDAULL - b.v[0];
  o.v[1] = a.v[1] + 0xFFFFFFFFFFFFEULL - b.v[1];
  o.v[2] = a.v[2] + 0xFFFFFFFFFFFFEULL - b.v[2];
  o.v[3] = a.v[3] + 0xFFFFFFFFFFFFEULL - b.v[3];
  o.v[4] = a.v[4] + 0xFFFFFFFFFFFFEULL - b.v[4];
}

// Weak reduction: bring every limb under 2^51 (value stays < 2p-ish).
void feCarry(fe& o) {
  uint64_t c;
  c = o.v[0] >> 51; o.v[0] &= MASK51; o.v[1] += c;
  c = o.v[1] >> 51; o.v[1] &= MASK51; o.v[2] += c;
  c = o.v[2] >> 51; o.v[2] &= MASK51; o.v[3] += c;
  c = o.v[3] >> 51; o.v[3] &= MASK51; o.v[4] += c;
  c = o.v[4] >> 51; o.v[4] &= MASK51; o.v[0] += c * 19;
  c = o.v[0] >> 51; o.v[0] &= MASK51; o.v[1] += c;
}

void feMul(fe& o, const fe& a, const fe& b) {
  using u128 = unsigned __int128;
  const uint64_t a0 = a.v[0], a1 = a.v[1], a2 = a.v[2], a3 = a.v[3], a4 = a.v[4];
  const uint64_t b0 = b.v[0], b1 = b.v[1], b2 = b.v[2], b3 = b.v[3], b4 = b.v[4];
  const uint64_t a1_19 = a1 * 19, a2_19 = a2 * 19, a3_19 = a3 * 19, a4_19 = a4 * 19;

  u128 r0 = (u128)a0 * b0 + (u128)a4_19 * b1 + (u128)a3_19 * b2 + (u128)a2_19 * b3 + (u128)a1_19 * b4;
  u128 r1 = (u128)a1 * b0 + (u128)a0 * b1 + (u128)a4_19 * b2 + (u128)a3_19 * b3 + (u128)a2_19 * b4;
  u128 r2 = (u128)a2 * b0 + (u128)a1 * b1 + (u128)a0 * b2 + (u128)a4_19 * b3 + (u128)a3_19 * b4;
  u128 r3 = (u128)a3 * b0 + (u128)a2 * b1 + (u128)a1 * b2 + (u128)a0 * b3 + (u128)a4_19 * b4;
  u128 r4 = (u128)a4 * b0 + (u128)a3 * b1 + (u128)a2 * b2 + (u128)a1 * b3 + (u128)a0 * b4;

  uint64_t c;
  uint64_t o0 = (uint64_t)r0 & MASK51; c = (uint64_t)(r0 >> 51);
  r1 += c;
  uint64_t o1 = (uint64_t)r1 & MASK51; c = (uint64_t)(r1 >> 51);
  r2 += c;
  uint64_t o2 = (uint64_t)r2 & MASK51; c = (uint64_t)(r2 >> 51);
  r3 += c;
  uint64_t o3 = (uint64_t)r3 & MASK51; c = (uint64_t)(r3 >> 51);
  r4 += c;
  uint64_t o4 = (uint64_t)r4 & MASK51; c = (uint64_t)(r4 >> 51);
  o0 += c * 19;
  c = o0 >> 51; o0 &= MASK51; o1 += c;
  o.v[0] = o0; o.v[1] = o1; o.v[2] = o2; o.v[3] = o3; o.v[4] = o4;
}

void feSq(fe& o, const fe& a) { feMul(o, a, a); }

// Multiply by a small constant (fits 32 bits).
void feMulSmall(fe& o, const fe& a, uint32_t k) {
  using u128 = unsigned __int128;
  u128 r0 = (u128)a.v[0] * k;
  u128 r1 = (u128)a.v[1] * k;
  u128 r2 = (u128)a.v[2] * k;
  u128 r3 = (u128)a.v[3] * k;
  u128 r4 = (u128)a.v[4] * k;
  uint64_t c;
  uint64_t o0 = (uint64_t)r0 & MASK51; c = (uint64_t)(r0 >> 51); r1 += c;
  uint64_t o1 = (uint64_t)r1 & MASK51; c = (uint64_t)(r1 >> 51); r2 += c;
  uint64_t o2 = (uint64_t)r2 & MASK51; c = (uint64_t)(r2 >> 51); r3 += c;
  uint64_t o3 = (uint64_t)r3 & MASK51; c = (uint64_t)(r3 >> 51); r4 += c;
  uint64_t o4 = (uint64_t)r4 & MASK51; c = (uint64_t)(r4 >> 51);
  o0 += c * 19;
  c = o0 >> 51; o0 &= MASK51; o1 += c;
  o.v[0] = o0; o.v[1] = o1; o.v[2] = o2; o.v[3] = o3; o.v[4] = o4;
}

// Full (canonical) reduction into [0, p).
void feFreeze(fe& o) {
  feCarry(o);
  feCarry(o);
  // Now o < 2^255 + small. Conditionally subtract p (possibly twice).
  for (int pass = 0; pass < 2; ++pass) {
    // q = 1 if o >= p else 0. p = (2^51-19, 2^51-1, 2^51-1, 2^51-1, 2^51-1).
    uint64_t borrow;
    uint64_t t0 = o.v[0] - (MASK51 - 18);
    borrow = t0 >> 63;
    uint64_t t1 = o.v[1] - MASK51 - borrow;
    borrow = t1 >> 63;
    uint64_t t2 = o.v[2] - MASK51 - borrow;
    borrow = t2 >> 63;
    uint64_t t3 = o.v[3] - MASK51 - borrow;
    borrow = t3 >> 63;
    uint64_t t4 = o.v[4] - MASK51 - borrow;
    borrow = t4 >> 63;
    // borrow == 0 means o >= p: keep the subtracted limbs (masked back to 51 bits).
    const uint64_t keep = borrow - 1;  // all-ones if o >= p, else 0
    o.v[0] = (o.v[0] & ~keep) | ((t0 & MASK51) & keep);
    o.v[1] = (o.v[1] & ~keep) | ((t1 & MASK51) & keep);
    o.v[2] = (o.v[2] & ~keep) | ((t2 & MASK51) & keep);
    o.v[3] = (o.v[3] & ~keep) | ((t3 & MASK51) & keep);
    o.v[4] = (o.v[4] & ~keep) | ((t4 & MASK51) & keep);
  }
}

void feFromBytes(fe& o, const uint8_t in[32]) {
  uint64_t w[4];
  for (int i = 0; i < 4; ++i) {
    w[i] = 0;
    for (int j = 0; j < 8; ++j) w[i] |= (uint64_t)in[8 * i + j] << (8 * j);
  }
  o.v[0] = w[0] & MASK51;
  o.v[1] = ((w[0] >> 51) | (w[1] << 13)) & MASK51;
  o.v[2] = ((w[1] >> 38) | (w[2] << 26)) & MASK51;
  o.v[3] = ((w[2] >> 25) | (w[3] << 39)) & MASK51;
  o.v[4] = (w[3] >> 12) & MASK51;  // top bit of byte 31 dropped, RFC 7748 style
}

void feToBytes(uint8_t out[32], const fe& a) {
  fe t;
  feCopy(t, a);
  feFreeze(t);
  uint64_t w0 = t.v[0] | (t.v[1] << 51);
  uint64_t w1 = (t.v[1] >> 13) | (t.v[2] << 38);
  uint64_t w2 = (t.v[2] >> 26) | (t.v[3] << 25);
  uint64_t w3 = (t.v[3] >> 39) | (t.v[4] << 12);
  const uint64_t w[4] = {w0, w1, w2, w3};
  for (int i = 0; i < 4; ++i)
    for (int j = 0; j < 8; ++j) out[8 * i + j] = (uint8_t)(w[i] >> (8 * j));
}

bool feIsZero(const fe& a) {
  fe t;
  feCopy(t, a);
  feFreeze(t);
  uint64_t r = 0;
  for (int i = 0; i < 5; ++i) r |= t.v[i];
  return r == 0;
}

// Generic square-and-multiply, exponent little-endian bytes, top bit first from
// `bits - 1`. Slower than a dedicated chain and called nowhere hot enough for
// that to matter (invert: once per ladder; Euler: once per H2C).
void fePow(fe& o, const fe& base, const uint8_t* exp, int bits) {
  fe r, b;
  feOne(r);
  feCopy(b, base);
  for (int i = bits - 1; i >= 0; --i) {
    feSq(r, r);
    if ((exp[i >> 3] >> (i & 7)) & 1) feMul(r, r, b);
  }
  feCopy(o, r);
}

// p - 2 = 2^255 - 21, little-endian.
const uint8_t P_MINUS_2[32] = {
    0xEB, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F};

// (p - 1) / 2 = 2^254 - 10, little-endian.
const uint8_t P_MINUS_1_HALF[32] = {
    0xF6, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x3F};

void feInvert(fe& o, const fe& a) { fePow(o, a, P_MINUS_2, 255); }

// Euler's criterion. Zero counts as square (it is: 0 = 0^2).
bool feIsSquare(const fe& a) {
  if (feIsZero(a)) return true;
  fe e;
  fePow(e, a, P_MINUS_1_HALF, 255);
  fe one;
  feOne(one);
  fe diff;
  feSub(diff, e, one);
  return feIsZero(diff);
}

void feCswap(fe& a, fe& b, uint64_t swap) {
  const uint64_t mask = 0 - swap;  // 0 or all-ones
  for (int i = 0; i < 5; ++i) {
    const uint64_t x = mask & (a.v[i] ^ b.v[i]);
    a.v[i] ^= x;
    b.v[i] ^= x;
  }
}

// ---------------------------------------------------------------------------
// The Montgomery ladder (RFC 7748, no clamping; see the header)
// ---------------------------------------------------------------------------
constexpr uint32_t A24 = 121665;  // (486662 - 2) / 4

void ladder(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32]) {
  fe x1;
  feFromBytes(x1, point);

  fe x2, z2, x3, z3;
  feOne(x2);
  feZero(z2);
  feCopy(x3, x1);
  feOne(z3);

  uint64_t swap = 0;
  for (int t = 254; t >= 0; --t) {
    const uint64_t bit = (scalar[t >> 3] >> (t & 7)) & 1;
    swap ^= bit;
    feCswap(x2, x3, swap);
    feCswap(z2, z3, swap);
    swap = bit;

    fe A_, AA, B_, BB, E, C_, D_, DA, CB, tmp;
    feAdd(A_, x2, z2);        feCarry(A_);
    feSq(AA, A_);
    feSub(B_, x2, z2);        feCarry(B_);
    feSq(BB, B_);
    feSub(E, AA, BB);         feCarry(E);
    feAdd(C_, x3, z3);        feCarry(C_);
    feSub(D_, x3, z3);        feCarry(D_);
    feMul(DA, D_, A_);
    feMul(CB, C_, B_);

    feAdd(tmp, DA, CB);       feCarry(tmp);
    feSq(x3, tmp);
    feSub(tmp, DA, CB);       feCarry(tmp);
    feSq(tmp, tmp);
    feMul(z3, tmp, x1);

    feMul(x2, AA, BB);
    feMulSmall(tmp, E, A24);
    feAdd(tmp, AA, tmp);      feCarry(tmp);
    feMul(z2, E, tmp);
  }
  feCswap(x2, x3, swap);
  feCswap(z2, z3, swap);

  fe zi, r;
  feInvert(zi, z2);
  feMul(r, x2, zi);
  feToBytes(out, r);
}

// ---------------------------------------------------------------------------
// Elligator2 (x-only, Z = 2, A = 486662)
// ---------------------------------------------------------------------------
constexpr uint32_t CURVE_A = 486662;

void elligator2(uint8_t outX[32], const uint8_t in[32]) {
  fe u;
  feFromBytes(u, in);

  fe tv1;
  feSq(tv1, u);
  feMulSmall(tv1, tv1, 2);  // Z * u^2
  feCarry(tv1);

  // Exceptional case Z*u^2 == -1: the denominator 1 + tv1 would be zero. RFC 9380
  // sets tv1 = 0 there, mapping to x = -A.
  fe one, den;
  feOne(one);
  feAdd(den, tv1, one);
  feCarry(den);
  if (feIsZero(den)) {
    feZero(tv1);
    feAdd(den, tv1, one);
  }

  fe feA;
  feZero(feA);
  feA.v[0] = CURVE_A;

  // x1 = -A / (1 + Z*u^2)
  fe deninv, x1;
  feInvert(deninv, den);
  feMul(x1, feA, deninv);
  fe zero;
  feZero(zero);
  feSub(x1, zero, x1);
  feCarry(x1);

  // gx1 = x1^3 + A*x1^2 + x1
  fe x1sq, gx1, t;
  feSq(x1sq, x1);
  feMul(gx1, x1sq, x1);
  feMul(t, x1sq, feA);
  feAdd(gx1, gx1, t);
  feAdd(gx1, gx1, x1);
  feCarry(gx1);

  fe x;
  if (feIsSquare(gx1)) {
    feCopy(x, x1);
  } else {
    // x2 = -x1 - A, whose g(x2) is guaranteed square when g(x1) is not.
    feSub(x, zero, x1);
    feSub(x, x, feA);
    feCarry(x);
  }
  feToBytes(outX, x);
}

const uint8_t COFACTOR_8[32] = {8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

int cmp32(const uint8_t* a, const uint8_t* b) {
  for (int i = 0; i < 32; ++i) {
    if (a[i] < b[i]) return -1;
    if (a[i] > b[i]) return 1;
  }
  return 0;
}

void le32(uint8_t out[4], uint32_t v) {
  out[0] = (uint8_t)v;
  out[1] = (uint8_t)(v >> 8);
  out[2] = (uint8_t)(v >> 16);
  out[3] = (uint8_t)(v >> 24);
}

}  // namespace

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

bool scalarMult(const uint8_t scalar[32], const uint8_t point[32], uint8_t out[32]) {
  if (!scalar || !point || !out) return false;
  ladder(out, scalar, point);
  return true;
}

void hashToPoint(const uint8_t* msg, uint32_t len, uint8_t out[32]) {
  uint8_t h[HASH_BYTES];
  sha256(msg, len, h);
  uint8_t x[32];
  elligator2(x, h);
  ladder(out, COFACTOR_8, x);
}

void petScalar(const uint8_t seed[HASH_BYTES], uint16_t round, uint8_t out[32]) {
  uint8_t buf[4 + HASH_BYTES + 4];
  buf[0] = 'D'; buf[1] = 'C'; buf[2] = 'H'; buf[3] = 'P';
  std::memcpy(buf + 4, seed, HASH_BYTES);
  le32(buf + 4 + HASH_BYTES, round);
  sha256(buf, sizeof(buf), out);
  // < 2^252: inside the prime-order scalar range, uniformly enough for blinding.
  out[31] &= 0x0F;
  // All-zero would blind everything to the identity. Astronomically unlikely and
  // still handled, deterministically, so a later audit recomputes the same value.
  uint8_t acc = 0;
  for (int i = 0; i < 32; ++i) acc |= out[i];
  if (acc == 0) out[0] = 1;
}

void elementPoint(uint16_t code, uint8_t out[32]) {
  uint8_t buf[6];
  buf[0] = 'D'; buf[1] = 'C'; buf[2] = 'H'; buf[3] = 'T';
  buf[4] = (uint8_t)code;
  buf[5] = (uint8_t)(code >> 8);
  hashToPoint(buf, sizeof(buf), out);
}

namespace {

// DELIBERATELY ROUND-INDEPENDENT. Per-round freshness comes entirely from the
// blinding scalar (alpha_r changes every round, so alpha_r * D_i is unlinkable
// across rounds under DDH exactly as alpha_r * P_t is for a stationary tile).
// Keeping D_i fixed per seed means a client may precompute every curve point it
// will ever need, tiles and dummies both, and the per-round cost collapses
// to ladders alone, with no protocol change and no audit-rule change.
void dummyPoint(const uint8_t seed[HASH_BYTES], uint16_t i, uint8_t out[32]) {
  uint8_t buf[4 + HASH_BYTES + 2];
  buf[0] = 'D'; buf[1] = 'C'; buf[2] = 'H'; buf[3] = 'D';
  std::memcpy(buf + 4, seed, HASH_BYTES);
  buf[4 + HASH_BYTES] = (uint8_t)i;
  buf[4 + HASH_BYTES + 1] = (uint8_t)(i >> 8);
  hashToPoint(buf, sizeof(buf), out);
}

}  // namespace

int petBuild(const uint8_t seed[HASH_BYTES], uint16_t round, uint16_t ownElement,
             const uint16_t* elements, int count, uint8_t* out) {
  if (!seed || !out) return -1;
  if (count < 0 || count > PET_PAD) return -1;
  if (count > 0 && !elements) return -1;

  uint8_t alpha[32];
  petScalar(seed, round, alpha);

  // S: the blinded set, padded with blinded dummies to a fixed size. The dummies are
  // hashed to the curve exactly like real elements, so the work is constant
  // (PET_PAD maps + PET_PAD ladders) whatever the set size, so no timing tell either.
  static uint8_t entries[PET_PAD][PET_POINT_BYTES];
  for (int i = 0; i < PET_PAD; ++i) {
    uint8_t p[32];
    if (i < count) elementPoint(elements[i], p);
    else dummyPoint(seed, (uint16_t)i, p);
    ladder(entries[i], alpha, p);
  }

  // Canonical order: sort by encoded bytes. Independent of enumeration order, blind
  // to which entries are dummies, and recomputable by an audit.
  for (int i = 1; i < PET_PAD; ++i) {
    uint8_t key[PET_POINT_BYTES];
    std::memcpy(key, entries[i], PET_POINT_BYTES);
    int j = i - 1;
    while (j >= 0 && cmp32(entries[j], key) > 0) {
      std::memcpy(entries[j + 1], entries[j], PET_POINT_BYTES);
      --j;
    }
    std::memcpy(entries[j + 1], key, PET_POINT_BYTES);
  }
  for (int i = 0; i < PET_PAD; ++i)
    std::memcpy(out + i * PET_POINT_BYTES, entries[i], PET_POINT_BYTES);

  // Q: my own element, blinded with the same scalar.
  uint8_t pme[32];
  elementPoint(ownElement, pme);
  ladder(out + PET_PAD * PET_POINT_BYTES, alpha, pme);

  return PET_BUILD_BYTES;
}

int petRespond(const uint8_t seed[HASH_BYTES], uint16_t round,
               const uint8_t theirQ[32], uint8_t out[32]) {
  if (!seed || !theirQ || !out) return -1;
  uint8_t alpha[32];
  petScalar(seed, round, alpha);
  ladder(out, alpha, theirQ);
  return 0;
}

int petFinish(const uint8_t seed[HASH_BYTES], uint16_t round,
              const uint8_t* theirS, const uint8_t theirR[32]) {
  if (!seed || !theirS || !theirR) return -1;
  uint8_t alpha[32];
  petScalar(seed, round, alpha);
  int hit = 0;
  for (int i = 0; i < PET_PAD; ++i) {
    uint8_t m[32];
    ladder(m, alpha, theirS + i * PET_POINT_BYTES);
    if (cmp32(m, theirR) == 0) hit = 1;
  }
  return hit;
}

namespace {

const uint8_t TAG_PETFLIGHT[4] = {'D', 'C', 'H', 'V'};

// leaf = SHA256("DCHV" || 0x00 || LE16(index) || point). The index is INSIDE the
// preimage so an element cannot be replayed into a different slot, and the 0x00
// prefix keeps a leaf from ever colliding with an interior node.
void merkleLeaf(int index, const uint8_t point[32], uint8_t out[HASH_BYTES]) {
  uint8_t buf[4 + 1 + 2 + 32];
  int n = 0;
  for (int i = 0; i < 4; ++i) buf[n++] = TAG_PETFLIGHT[i];
  buf[n++] = 0x00;
  buf[n++] = static_cast<uint8_t>(index);
  buf[n++] = static_cast<uint8_t>(index >> 8);
  for (int i = 0; i < 32; ++i) buf[n++] = point[i];
  sha256(buf, static_cast<size_t>(n), out);
}

// node = SHA256("DCHV" || 0x01 || left || right).
void merkleNode(const uint8_t l[HASH_BYTES], const uint8_t r[HASH_BYTES],
                uint8_t out[HASH_BYTES]) {
  uint8_t buf[4 + 1 + HASH_BYTES + HASH_BYTES];
  int n = 0;
  for (int i = 0; i < 4; ++i) buf[n++] = TAG_PETFLIGHT[i];
  buf[n++] = 0x01;
  for (int i = 0; i < HASH_BYTES; ++i) buf[n++] = l[i];
  for (int i = 0; i < HASH_BYTES; ++i) buf[n++] = r[i];
  sha256(buf, static_cast<size_t>(n), out);
}

// The point at a leaf index: the set, then Q, then R, then zero padding. One place,
// so the root builder and the path builder cannot disagree about the layout.
const uint8_t* leafPoint(const uint8_t* flight1, const uint8_t flight2[32], int i) {
  static const uint8_t ZERO[32] = {0};
  if (i < PET_PAD) return flight1 + i * PET_POINT_BYTES;
  if (i == PET_LEAF_Q) return flight1 + PET_PAD * PET_POINT_BYTES;
  if (i == PET_LEAF_R) return flight2;
  return ZERO;
}

// The whole tree, bottom level first, packed into one buffer: level 0 is the 256
// leaf hashes, then 128, 64, ... 1. Static because 256 * 32 bytes is too much stack
// for a wasm reactor frame, and it is fully overwritten on every call, so nothing
// carries between calls, so determinism is preserved.
uint8_t g_tree[2 * PET_MERKLE_LEAVES][HASH_BYTES];

void buildTree(const uint8_t* flight1, const uint8_t flight2[32]) {
  for (int i = 0; i < PET_MERKLE_LEAVES; ++i)
    merkleLeaf(i, leafPoint(flight1, flight2, i), g_tree[i]);
  int base = 0, width = PET_MERKLE_LEAVES;
  while (width > 1) {
    const int next = base + width;
    for (int i = 0; i < width / 2; ++i)
      merkleNode(g_tree[base + 2 * i], g_tree[base + 2 * i + 1], g_tree[next + i]);
    base = next;
    width /= 2;
  }
}

}  // namespace

void petFlightHash(const uint8_t* flight1, const uint8_t flight2[32],
                   uint8_t out[HASH_BYTES]) {
  if (!flight1 || !flight2 || !out) return;
  buildTree(flight1, flight2);
  // The last node written is the root: levels are 256 + 128 + ... + 1 entries.
  for (int i = 0; i < HASH_BYTES; ++i) out[i] = g_tree[2 * PET_MERKLE_LEAVES - 2][i];
}

int petMerklePath(const uint8_t* flight1, const uint8_t flight2[32], int leafIndex,
                  uint8_t* outPath) {
  if (!flight1 || !flight2 || !outPath) return -1;
  if (leafIndex < 0 || leafIndex >= PET_MERKLE_LEAVES) return -1;
  buildTree(flight1, flight2);
  int base = 0, width = PET_MERKLE_LEAVES, idx = leafIndex;
  for (int d = 0; d < PET_MERKLE_DEPTH; ++d) {
    const int sib = idx ^ 1;
    for (int i = 0; i < HASH_BYTES; ++i)
      outPath[d * HASH_BYTES + i] = g_tree[base + sib][i];
    base += width;
    width /= 2;
    idx >>= 1;
  }
  return 0;
}

int petMerkleVerify(int leafIndex, const uint8_t leaf[32], const uint8_t* path,
                    const uint8_t root[HASH_BYTES]) {
  if (!leaf || !path || !root) return -1;
  if (leafIndex < 0 || leafIndex >= PET_MERKLE_LEAVES) return -1;
  uint8_t acc[HASH_BYTES];
  merkleLeaf(leafIndex, leaf, acc);
  int idx = leafIndex;
  for (int d = 0; d < PET_MERKLE_DEPTH; ++d) {
    const uint8_t* sib = path + d * HASH_BYTES;
    uint8_t next[HASH_BYTES];
    if ((idx & 1) == 0) merkleNode(acc, sib, next);
    else                merkleNode(sib, acc, next);
    for (int i = 0; i < HASH_BYTES; ++i) acc[i] = next[i];
    idx >>= 1;
  }
  return cmp32(acc, root) == 0 ? 1 : 0;
}

}  // namespace fow
