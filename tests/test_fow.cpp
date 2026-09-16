// Tests for the blinded sighting test.
//
// RFC 7748 known answers, sampled group properties, directed membership and
// Merkle openings. The independent BigInt implementation checks the same
// historical fixture. These tests establish no general privacy theorem or
// compatibility with the current game's wire format.
#include "fow.hpp"
#include "sha256.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <initializer_list>

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
  pass("ladder matches RFC 7748 known answers with test-side clamping");
}

void testHashToCurveLandsInThePrimeOrderSubgroup() {
  // Check sampled nonidentity points. Zero output alone does not distinguish
  // the identity from every low-order input in an x-only ladder, so also check
  // (l-1)P has P's x-coordinate (negation in the prime-order subgroup).
  uint8_t ell[32];
  check(hexTo("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010", ell, 32),
        "the group order parses");
  uint8_t ellMinusOne[32];
  std::memcpy(ellMinusOne, ell, 32);
  --ellMinusOne[0];
  int allZero = 1, allNonzero = 1, allNegate = 1, anyDistinct = 0;
  uint8_t prev[32] = {0};
  for (uint16_t i = 0; i < 64; ++i) {
    uint8_t p[32], q[32];
    fow::elementPoint(i, p);
    uint8_t nonzero = 0;
    for (int j = 0; j < 32; ++j) nonzero |= p[j];
    if (!nonzero) allNonzero = 0;
    fow::scalarMult(ell, p, q);
    for (int j = 0; j < 32; ++j) if (q[j] != 0) allZero = 0;
    fow::scalarMult(ellMinusOne, p, q);
    if (std::memcmp(p, q, 32) != 0) allNegate = 0;
    if (i > 0 && std::memcmp(p, prev, 32) != 0) anyDistinct = 1;
    std::memcpy(prev, p, 32);
  }
  check(allZero, "l * H2C(e) == O FOR EVERY SAMPLED ELEMENT (on-curve, cofactor cleared)");
  check(allNonzero && allNegate, "sampled points are nonzero and (l-1)P has P's x-coordinate");
  check(anyDistinct, "and the sampled points are not all identical");

  // Determinism: the same input always gives the same point.
  uint8_t a[32], b[32];
  fow::elementPoint(611, a);
  fow::elementPoint(611, b);
  check(std::memcmp(a, b, 32) == 0, "hash-to-curve is deterministic");

  // The correctness theorem assumes distinct real elements give distinct
  // x-coordinates and no element gives the identity. The universe is 2^16 codes,
  // so check it exhaustively rather than sample it.
  static uint8_t all[65536][32];
  int zero = 0;
  for (uint32_t code = 0; code < 65536; ++code) {
    fow::elementPoint((uint16_t)code, all[code]);
    uint8_t acc = 0;
    for (int j = 0; j < 32; ++j) acc |= all[code][j];
    if (!acc) ++zero;
  }
  std::qsort(all, 65536, 32,
             [](const void* x, const void* y) { return std::memcmp(x, y, 32); });
  int dup = 0;
  for (int i = 1; i < 65536; ++i)
    if (std::memcmp(all[i - 1], all[i], 32) == 0) ++dup;
  check(zero == 0 && dup == 0,
        "ALL 65,536 ELEMENT POINTS ARE NONZERO AND PAIRWISE DISTINCT");
  pass("hash-to-curve: Elligator 2, in the prime-order subgroup, distinct over the universe");
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

  // FRESH EVERY ROUND: the same set at a different round is a different flight.
  // This is a byte compare only; the paper claims no cross-round theorem.
  {
    const uint16_t setA[] = {aElem, bElem};
    fow::petBuild(seedA, 5, aElem, setA, 2, fa);
    fow::petBuild(seedA, 6, aElem, setA, 2, fb);
    check(std::memcmp(fa, fb, fow::PET_BUILD_BYTES) != 0,
          "the same set at the next round differs byte-wise");
  }
  pass("honest membership and fixed payload sizes");
}

void testDirectedResultsAndInputBoundaries() {
  uint8_t seedA[32] = {1}, seedB[32] = {2};
  uint8_t fa[fow::PET_BUILD_BYTES], fb[fow::PET_BUILD_BYTES], ra[32], rb[32];
  const uint16_t setA[] = {0, 65535}, setB[] = {65535};
  const int qOffset = fow::PET_PAD * 32;
  for (uint16_t round : {uint16_t(0), uint16_t(65535)}) {
    check(fow::petBuild(seedA, round, 0, setA, 2, fa) == fow::PET_BUILD_BYTES &&
          fow::petBuild(seedB, round, 65535, setB, 1, fb) == fow::PET_BUILD_BYTES,
          "boundary elements and rounds build");
    fow::petRespond(seedA, round, fb + qOffset, ra);
    fow::petRespond(seedB, round, fa + qOffset, rb);
    check(fow::petFinish(seedA, round, fb, rb) == 0 &&
          fow::petFinish(seedB, round, fa, ra) == 1,
          "a directional relation gives different correct results");
  }
  const uint16_t reversed[] = {65535, 0};
  fow::petBuild(seedA, 65535, 0, reversed, 2, fb);
  check(std::memcmp(fa, fb, sizeof fa) == 0, "enumeration order does not change the flight");
  check(fow::petBuild(seedA, 0, 0, nullptr, 0, fb) == fow::PET_BUILD_BYTES,
        "an empty set builds with a null element pointer");
  fow::petBuild(seedB, 0, 65535, setB, 1, fa);
  fow::petRespond(seedA, 0, fa + qOffset, ra);
  check(fow::petFinish(seedB, 0, fb, ra) == 0, "an empty set has no membership");
  check(fow::petBuild(seedA, 0, 0, nullptr, 1, fa) == -1 &&
        fow::petBuild(seedA, 0, 0, setA, -1, fa) == -1,
        "missing elements and negative counts are refused");

  // Counterexamples delimit the paper's claims; the raw API is not a referee.
  const uint16_t duplicates[] = {0, 0};
  fow::petBuild(seedA, 0, 0, duplicates, 2, fa);
  int matches = 0;
  for (int i = 0; i < fow::PET_PAD; ++i)
    if (std::memcmp(fa + i * 32, fa + qOffset, 32) == 0) ++matches;
  check(matches == 2, "duplicate multiplicity and query/set overlap are visible");
  std::memset(fb, 0, sizeof fb);
  std::memset(rb, 0, sizeof rb);
  check(fow::petFinish(seedA, 0, fb, rb) == 1,
        "a forged zero set and response force a positive raw result");
  pass("directed correctness, input boundaries and explicit leakage examples");
}

void testHistoricalDungeonchannelVector() {
  // Historical fixture from Dungeon Channel revision 1ad3b7f (2026-08-01 14:54
  // UTC, the 128x128 map): spawn 0 = tile (120, 5) of map seed 0x5EED1234, round 7,
  // the omnidirectional radius-6 line-of-sight set of that tile as Morton codes,
  // in the game's own enumeration order. That revision's test suite pinned the same
  // root over these inputs. This test loads no map, rules or hosted WASM.
  uint8_t seed[32];
  for (int i = 0; i < 32; ++i) seed[i] = (uint8_t)(0xA0 + i);
  const uint16_t own = 10897;  // morton((120, 5)), 14 bits
  const uint16_t elems[] = {
      10790, 10796, 10798, 10884, 10886, 10892, 10894, 10791, 10797, 10799, 10885,
      10887, 10893, 10895, 10802, 10808, 10810, 10896, 10898, 10904, 10906, 10777,
      10779, 10801, 10803, 10809, 10811, 10897, 10899, 10905, 10907, 10806, 10812,
      10814, 10900, 10902, 10908, 10910, 10807, 10813, 10815, 10901, 10903, 10909,
      10911, 10850, 10856, 10858, 10944, 10946, 10952, 10954, 10945, 10948, 10949};
  const int n = (int)(sizeof(elems) / sizeof(elems[0]));
  check(n == 55, "the historical visible set had 55 elements");

  static uint8_t f1[fow::PET_BUILD_BYTES];
  check(fow::petBuild(seed, 7, own, elems, n, f1) == fow::PET_BUILD_BYTES,
        "the flight builds");

  uint8_t digest[32], wantDigest[32];
  fow::sha256(f1, fow::PET_BUILD_BYTES, digest);
  hexTo("106e8a31ba80abcab999bd08fd7637eba04c87232637416d74d325f0b541b7d9", wantDigest, 32);
  char hex[65];
  hexOf(digest, 32, hex);
  if (std::memcmp(digest, wantDigest, 32) != 0) std::printf("  got sha256(flight1) %s\n", hex);
  check(std::memcmp(digest, wantDigest, 32) == 0,
        "flight digest matches the historical fixture");

  uint8_t wantQ[32];
  hexTo("2ec31f4c132caefd3a05ae1a5fc40974437417b36dd7efde2e6d493c4d551417", wantQ, 32);
  check(std::memcmp(f1 + fow::PET_PAD * 32, wantQ, 32) == 0, "and Q matches");

  uint8_t r[32], wantR[32];
  fow::petRespond(seed, 7, f1 + fow::PET_PAD * 32, r);
  hexTo("fc91185d3b6994fda37920ebe2473849321249ca4d345bfedffde2319a73b12b", wantR, 32);
  check(std::memcmp(r, wantR, 32) == 0, "and the flight-2 response matches");

  uint8_t fh[32], wantFh[32];
  fow::petFlightHash(f1, r, fh);
  hexTo("81fdba4d86cb4be4dfc44adc3822dc9fce9bb06026316c8eedd3a6e9e1448fca", wantFh, 32);
  check(std::memcmp(fh, wantFh, 32) == 0, "and the commitment root matches");

  // Its own element is in its own set, so the historical self-test bit is 1.
  check(fow::petFinish(seed, 7, f1, r) == 1, "and the bit agrees");
  pass("matches the Dungeon Channel fixture of revision 1ad3b7f (2026-08-01)");
}


void testTheCommitmentIsAMerkleRoot() {
  // The commitment over a flight is a Merkle root rather than a flat hash, so a
  // dispute can prove ONE element without shipping the other 129. That is only worth
  // anything if the tree is rigid, so it is attacked here rather than exercised:
  // every used leaf must prove, no leaf may prove at the wrong index or against
  // another flight, and no tampered path or leaf may pass.
  uint8_t seedA[32], seedB[32];
  for (int i = 0; i < 32; ++i) { seedA[i] = (uint8_t)(0x11 + i); seedB[i] = (uint8_t)(0x77 + i); }
  const uint16_t setA[] = {100, 200, 300};
  const uint16_t setB[] = {200, 100, 400};
  const int setLen = fow::PET_BUILD_BYTES - 32;
  static uint8_t fa[fow::PET_BUILD_BYTES], fb[fow::PET_BUILD_BYTES];
  fow::petBuild(seedA, 5, 100, setA, 3, fa);
  fow::petBuild(seedB, 5, 200, setB, 3, fb);
  uint8_t ra[32], rb[32];
  fow::petRespond(seedA, 5, fb + setLen, ra);
  fow::petRespond(seedB, 5, fa + setLen, rb);

  uint8_t rootA[32], rootB[32];
  fow::petFlightHash(fa, ra, rootA);
  fow::petFlightHash(fb, rb, rootB);
  check(std::memcmp(rootA, rootB, 32) != 0, "different flights give different roots");

  int proved = 0;
  for (int i = 0; i < fow::PET_LEAVES_USED; ++i) {
    uint8_t path[fow::PET_MERKLE_PATH_BYTES];
    check(fow::petMerklePath(fa, ra, i, path) == 0, "a path builds");
    const uint8_t* leaf = (i < fow::PET_PAD) ? fa + i * 32
                        : (i == fow::PET_LEAF_Q) ? fa + fow::PET_PAD * 32 : ra;
    if (fow::petMerkleVerify(i, leaf, path, rootA) == 1) ++proved;
  }
  check(proved == fow::PET_LEAVES_USED,
        "EVERY USED LEAF PROVES: all 128 set entries, Q, and R");

  {
    uint8_t path[fow::PET_MERKLE_PATH_BYTES];
    fow::petMerklePath(fa, ra, 7, path);
    check(fow::petMerkleVerify(7, fa + 7 * 32, path, rootA) == 1, "leaf 7 proves at 7");
    check(fow::petMerkleVerify(8, fa + 7 * 32, path, rootA) == 0,
          "the same leaf does not prove at another index");
    check(fow::petMerkleVerify(3, fa + 3 * 32, path, rootB) == 0,
          "and a path does not prove against another flight's root");
  }

  {
    uint8_t path[fow::PET_MERKLE_PATH_BYTES];
    fow::petMerklePath(fa, ra, 11, path);
    int accepted = 0;
    for (int b = 0; b < fow::PET_MERKLE_PATH_BYTES; ++b) {
      uint8_t bad[fow::PET_MERKLE_PATH_BYTES];
      std::memcpy(bad, path, sizeof bad);
      bad[b] ^= 0x01;
      if (fow::petMerkleVerify(11, fa + 11 * 32, bad, rootA) != 0) ++accepted;
    }
    check(accepted == 0, "every single-byte tamper of a path is rejected");
  }

  // R is inside the tree, which is the point: answering with a doctored response
  // flips a peer's bit without touching the set, and needs no guess about where the
  // peer is, so it has to be attributable too.
  {
    uint8_t other[32], rootOther[32];
    std::memcpy(other, ra, 32);
    other[0] ^= 0x01;
    fow::petFlightHash(fa, other, rootOther);
    check(std::memcmp(rootA, rootOther, 32) != 0,
          "changing only the flight-2 response changes the root");
  }
  pass("all used Merkle leaves open and tested tampered witnesses fail");
}

}  // namespace

int main() {
  std::printf("=== the blinded sighting test ===\n");
  testRfc7748Vectors();
  testHashToCurveLandsInThePrimeOrderSubgroup();
  testTheBitIsRight();
  testDirectedResultsAndInputBoundaries();
  testTheCommitmentIsAMerkleRoot();
  testHistoricalDungeonchannelVector();
  std::printf("\n%d checks, %d failures\n", g_checks, g_failures);
  if (g_failures) { std::printf("FAILED\n"); return 1; }
  std::printf("OK\n");
  return 0;
}
