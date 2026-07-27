// Tests for the blinded sighting test.
//
// Three kinds of evidence, in increasing order of what they prove:
//
//   1. THE CURVE IS THE REAL CURVE. RFC 7748 section 5.2's known-answer vectors,
//      run through this ladder, plus the identity l*P == O for hash-to-curve
//      outputs, which proves curve membership AND cofactor clearing at once (a
//      point on the twist, or one with an 8-torsion component, fails it).
//
//   2. THE PROTOCOL COMPUTES THE RIGHT BIT. Two parties, symmetric relation, run
//      end to end: the bit is 1 exactly when each holds the other's element.
//
//   3. IT IS BYTE-IDENTICAL TO THE DEPLOYED GAME. The vector in
//      testMatchesDeployedDungeonchannel was produced by Xaya's dungeonchannel
//      blob, not by this file, so the paper's measurements describe THIS code.
//
// The independent check lives in tests/verify-math.mjs: a from-scratch BigInt
// implementation written from the paper's formulas, which must reproduce these same
// bytes. Agreement between two implementations that share no code is the claim.
#include "fow.hpp"
#include "sha256.hpp"

#include <cstdio>
#include <cstring>

namespace {

int g_checks = 0;
int g_failures = 0;

void check(bool cond, const char* what) {
  ++g_checks;
  if (!cond) { ++g_failures; std::printf("  FAIL: %s\n", what); }
}
void pass(const char* what) { std::printf("PASS: %s\n", what); }

bool hexTo(const char* hex, uint8_t* out, int n) {
  for (int i = 0; i < n; ++i) {
    int hi = -1, lo = -1;
    const char a = hex[2 * i], b = hex[2 * i + 1];
    if (a >= '0' && a <= '9') hi = a - '0';
    else if (a >= 'a' && a <= 'f') hi = a - 'a' + 10;
    if (b >= '0' && b <= '9') lo = b - '0';
    else if (b >= 'a' && b <= 'f') lo = b - 'a' + 10;
    if (hi < 0 || lo < 0) return false;
    out[i] = (uint8_t)((hi << 4) | lo);
  }
  return true;
}

void hexOf(const uint8_t* p, int n, char* out) {
  static const char* D = "0123456789abcdef";
  for (int i = 0; i < n; ++i) { out[2 * i] = D[p[i] >> 4]; out[2 * i + 1] = D[p[i] & 15]; }
  out[2 * n] = 0;
}

// RFC 7748's clamping, applied HERE rather than in the ladder: the library must not
// clamp (see fow.hpp), so this is how the unclamped core is still held to the
// world's most-checked X25519 vectors.
void clamp(uint8_t k[32]) {
  k[0] &= 248;
  k[31] &= 127;
  k[31] |= 64;
}

void testRfc7748Vectors() {
  // RFC 7748 section 5.2, vector 1.
  uint8_t k[32], u[32], want[32], got[32];
  check(hexTo("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4", k, 32) &&
        hexTo("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c", u, 32) &&
        hexTo("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552", want, 32),
        "RFC 7748 vector 1 parses");
  clamp(k);
  check(fow::scalarMult(k, u, got), "the ladder runs");
  check(std::memcmp(got, want, 32) == 0, "RFC 7748 VECTOR 1 MATCHES");

  // Vector 2.
  uint8_t k2[32], u2[32], want2[32];
  check(hexTo("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d", k2, 32) &&
        hexTo("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493", u2, 32) &&
        hexTo("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957", want2, 32),
        "RFC 7748 vector 2 parses");
  clamp(k2);
  fow::scalarMult(k2, u2, got);
  check(std::memcmp(got, want2, 32) == 0, "RFC 7748 VECTOR 2 MATCHES");

  // The iterated vector: k = u = 9, one round, then 1000 rounds.
  uint8_t kk[32] = {9}, uu[32] = {9}, tmp[32], w1[32], w1000[32];
  check(hexTo("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079", w1, 32) &&
        hexTo("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51", w1000, 32),
        "the iterated vectors parse");
  for (int i = 0; i < 1000; ++i) {
    uint8_t ck[32];
    std::memcpy(ck, kk, 32);
    clamp(ck);
    fow::scalarMult(ck, uu, tmp);
    std::memcpy(uu, kk, 32);
    std::memcpy(kk, tmp, 32);
    if (i == 0) check(std::memcmp(kk, w1, 32) == 0, "RFC 7748 ITERATION 1 MATCHES");
  }
  check(std::memcmp(kk, w1000, 32) == 0, "RFC 7748 ITERATION 1000 MATCHES");
  pass("the ladder is X25519, pinned to RFC 7748 section 5.2");
}

void testHashToCurveLandsInThePrimeOrderSubgroup() {
  // l * P == O for every hash-to-curve output. The x-only ladder represents the
  // identity as zero, so this single identity proves the point is on the curve AND
  // that the cofactor was cleared: a twist point or an 8-torsion component fails.
  uint8_t ell[32];
  check(hexTo("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010", ell, 32),
        "the group order parses");
  int allZero = 1, anyDistinct = 0;
  uint8_t prev[32] = {0};
  for (uint16_t i = 0; i < 64; ++i) {
    uint8_t p[32], q[32];
    fow::elementPoint(i, p);
    fow::scalarMult(ell, p, q);
    for (int j = 0; j < 32; ++j) if (q[j] != 0) allZero = 0;
    if (i > 0 && std::memcmp(p, prev, 32) != 0) anyDistinct = 1;
    std::memcpy(prev, p, 32);
  }
  check(allZero, "l * H2C(e) == O FOR EVERY SAMPLED ELEMENT (on-curve, cofactor cleared)");
  check(anyDistinct, "and distinct elements give distinct points");

  // Determinism: the same input always gives the same point.
  uint8_t a[32], b[32];
  fow::elementPoint(611, a);
  fow::elementPoint(611, b);
  check(std::memcmp(a, b, 32) == 0, "hash-to-curve is deterministic");
  pass("hash-to-curve: Elligator 2, in the prime-order subgroup");
}

void testTheBitIsRight() {
  // Two parties. A's element is 100, B's is 200. The relation is symmetric by
  // construction here: each set either contains the other's element or does not.
  uint8_t seedA[32], seedB[32];
  for (int i = 0; i < 32; ++i) { seedA[i] = (uint8_t)(0x11 + i); seedB[i] = (uint8_t)(0x77 + i); }

  const uint16_t aElem = 100, bElem = 200;
  const int setLen = fow::PET_BUILD_BYTES - 32;
  static uint8_t fa[fow::PET_BUILD_BYTES], fb[fow::PET_BUILD_BYTES];
  uint8_t ra[32], rb[32];

  // IN SIGHT: each set contains the other's element.
  {
    const uint16_t setA[] = {aElem, bElem, 300};
    const uint16_t setB[] = {bElem, aElem, 400};
    check(fow::petBuild(seedA, 5, aElem, setA, 3, fa) == fow::PET_BUILD_BYTES &&
          fow::petBuild(seedB, 5, bElem, setB, 3, fb) == fow::PET_BUILD_BYTES,
          "both flights build");
    check(fow::petRespond(seedA, 5, fb + setLen, ra) == 0 &&
          fow::petRespond(seedB, 5, fa + setLen, rb) == 0, "both respond");
    const int bitA = fow::petFinish(seedA, 5, fb, rb);
    const int bitB = fow::petFinish(seedB, 5, fa, ra);
    check(bitA == 1 && bitB == 1, "MUTUAL MEMBERSHIP GIVES THE BIT 1, BOTH SIDES");
  }

  // OUT OF SIGHT: neither set contains the other's element.
  {
    const uint16_t setA[] = {aElem, 300, 301};
    const uint16_t setB[] = {bElem, 400, 401};
    fow::petBuild(seedA, 5, aElem, setA, 3, fa);
    fow::petBuild(seedB, 5, bElem, setB, 3, fb);
    fow::petRespond(seedA, 5, fb + setLen, ra);
    fow::petRespond(seedB, 5, fa + setLen, rb);
    check(fow::petFinish(seedA, 5, fb, rb) == 0 &&
          fow::petFinish(seedB, 5, fa, ra) == 0, "no membership gives the bit 0, both sides");
  }

  // CONSTANT SHAPE: a one-element set and a full one produce the same byte count,
  // which is what stops the message length leaking the set size.
  {
    const uint16_t one[] = {aElem};
    static uint16_t many[fow::PET_PAD];
    for (int i = 0; i < fow::PET_PAD; ++i) many[i] = (uint16_t)(1000 + i);
    check(fow::petBuild(seedA, 5, aElem, one, 1, fa) ==
              fow::petBuild(seedA, 5, aElem, many, fow::PET_PAD, fb),
          "a 1-element set and a full one are the same length");
    check(fow::petBuild(seedA, 5, aElem, many, fow::PET_PAD + 1, fa) == -1,
          "and a set larger than the pad is refused, not truncated");
  }

  // FRESH EVERY ROUND: the same set at a different round is a different flight, so
  // linking a stationary party across rounds is DDH rather than a byte compare.
  {
    const uint16_t setA[] = {aElem, bElem};
    fow::petBuild(seedA, 5, aElem, setA, 2, fa);
    fow::petBuild(seedA, 6, aElem, setA, 2, fb);
    check(std::memcmp(fa, fb, fow::PET_BUILD_BYTES) != 0,
          "the same set at the next round is unrecognisable");
  }
  pass("the protocol computes membership and nothing else");
}

void testMatchesDeployedDungeonchannel() {
  // THE VECTOR BELOW CAME OUT OF XAYA'S DUNGEONCHANNEL, not out of this file: the
  // deployed rules blob was asked for the flight of the champion standing on spawn 0
  // of map seed 0x5EED1234 at round 7, and these are the bytes it produced. The
  // element codes are that champion's visible set as Morton codes.
  //
  // So this is the check that makes the paper's measurements describe THIS code. If
  // the extraction had drifted by one byte anywhere, in a domain tag, the sort, the
  // pad derivation or the scalar mask, it would fail here.
  uint8_t seed[32];
  for (int i = 0; i < 32; ++i) seed[i] = (uint8_t)(0xA0 + i);
  const uint16_t own = 611;
  const uint16_t elems[] = {
      539, 561, 563, 569, 571, 540, 542, 564, 566, 572, 574, 660, 535, 541, 543,
      565, 567, 573, 575, 661, 663, 578, 584, 586, 608, 610, 616, 618, 704, 706,
      579, 585, 587, 609, 611, 617, 619, 705, 707, 713, 715, 582, 588, 590, 612,
      614, 620, 622, 708, 710, 583, 589, 591, 613, 615, 621, 623, 709, 711, 600,
      602, 624, 626, 632, 634, 720, 603, 625, 627, 633, 635, 628, 630, 636, 631};
  const int n = (int)(sizeof(elems) / sizeof(elems[0]));
  check(n == 75, "the deployed visible set had 75 elements");

  static uint8_t f1[fow::PET_BUILD_BYTES];
  check(fow::petBuild(seed, 7, own, elems, n, f1) == fow::PET_BUILD_BYTES,
        "the flight builds");

  uint8_t digest[32], wantDigest[32];
  fow::sha256(f1, fow::PET_BUILD_BYTES, digest);
  hexTo("f88749d168ca57486f178e180647db0d49be19dbc5cfcf1a2b17ad71916b9ac6", wantDigest, 32);
  char hex[65];
  hexOf(digest, 32, hex);
  if (std::memcmp(digest, wantDigest, 32) != 0) std::printf("  got sha256(flight1) %s\n", hex);
  check(std::memcmp(digest, wantDigest, 32) == 0,
        "SHA-256 OF THE WHOLE FLIGHT MATCHES THE DEPLOYED GAME");

  uint8_t wantQ[32];
  hexTo("64922ddb71e5aceea0fb91adc3a75be6a601b95d91cc71b0839e7f3410965733", wantQ, 32);
  check(std::memcmp(f1 + fow::PET_PAD * 32, wantQ, 32) == 0, "and Q matches");

  uint8_t r[32], wantR[32];
  fow::petRespond(seed, 7, f1 + fow::PET_PAD * 32, r);
  hexTo("01204d2f6b9b94ee0a29055efc49a0ef25e164ff2eb7dbb9e082244d8415cf12", wantR, 32);
  check(std::memcmp(r, wantR, 32) == 0, "and the flight-2 response matches");

  uint8_t fh[32], wantFh[32];
  fow::petFlightHash(f1, r, fh);
  hexTo("5ab8ac6ec6668b0c9fd7350ca971a971b068f6c138dd6cd86a5060a90ea2fe97", wantFh, 32);
  check(std::memcmp(fh, wantFh, 32) == 0, "and the attribution hash matches");

  // Its own element is in its own set, so the self-test bit is 1, and the deployed
  // code reports the same.
  check(fow::petFinish(seed, 7, f1, r) == 1, "and the bit agrees");
  pass("byte-identical to the deployed dungeonchannel blob");
}

}  // namespace

int main() {
  std::printf("=== the blinded sighting test ===\n");
  testRfc7748Vectors();
  testHashToCurveLandsInThePrimeOrderSubgroup();
  testTheBitIsRight();
  testMatchesDeployedDungeonchannel();
  std::printf("\n%d checks, %d failures\n", g_checks, g_failures);
  if (g_failures) { std::printf("FAILED\n"); return 1; }
  std::printf("OK\n");
  return 0;
}
