// AN INDEPENDENT IMPLEMENTATION, WRITTEN FROM THE PAPER.
//
// Nothing here shares a line with src/. The field arithmetic is BigInt rather than
// 5x51-bit limbs, the ladder is transcribed from RFC 7748 section 5, Elligator 2 is
// the x-only Z = 2 map the paper's section 4 ("Our instantiation") names and defers
// here, and every derivation follows the structure of section 4.1 -- with the
// deployed four-byte domain tags and little-endian encodings, which the paper
// abstracts and include/fow.hpp pins. It then checks all of it against the SAME
// vector the C++ tests use -- bytes that came out of the deployed dungeonchannel blob.
//
//   node tests/verify-math.mjs
//
// Two implementations that share no code, both reproducing the deployed bytes, is
// the actual claim. If the paper and the code ever diverge, this fails.

import { createHash } from "node:crypto";

let checks = 0, failures = 0;
const check = (ok, what) => {
  ++checks;
  if (!ok) { ++failures; console.log(`  FAIL: ${what}`); }
  return ok;
};

// ─── the field: F_p, p = 2^255 - 19 (paper section 4) ──────────────────────────
const P = (1n << 255n) - 19n;
const A = 486662n;
const ELL = (1n << 252n) + 27742317777372353535851937790883648493n;
const mod = (x, m = P) => ((x % m) + m) % m;
const pow = (b, e, m = P) => {
  let r = 1n; b = mod(b, m);
  while (e > 0n) { if (e & 1n) r = (r * b) % m; b = (b * b) % m; e >>= 1n; }
  return r;
};
const inv = (x) => pow(x, P - 2n);
const isSquare = (x) => mod(x) === 0n || pow(x, (P - 1n) / 2n) === 1n;

const sha256 = (buf) => createHash("sha256").update(buf).digest();
const leToBig = (b) => { let v = 0n; for (let i = b.length - 1; i >= 0; --i) v = (v << 8n) | BigInt(b[i]); return v; };
const bigToLe32 = (v) => { const o = new Uint8Array(32); for (let i = 0; i < 32; ++i) { o[i] = Number(v & 0xffn); v >>= 8n; } return o; };

// ─── the ladder: RFC 7748 section 5, UNCLAMPED, a fixed 255 iterations ─────────
// Unclamped is deliberate and is the paper's section 4: these scalars must compose
// multiplicatively, and the transcript has to be a pure function of the derived
// scalar so an audit can recompute it with no hidden transformation.
function ladder(scalarBytes, uBytes) {
  const k = leToBig(scalarBytes);
  const x1 = mod(leToBig(uBytes) & ((1n << 255n) - 1n));
  let x2 = 1n, z2 = 0n, x3 = x1, z3 = 1n, swap = 0n;
  for (let t = 254; t >= 0; --t) {
    const bit = (k >> BigInt(t)) & 1n;
    swap ^= bit;
    if (swap === 1n) { [x2, x3] = [x3, x2]; [z2, z3] = [z3, z2]; }
    swap = bit;
    const Aa = mod(x2 + z2), AA = mod(Aa * Aa);
    const Bb = mod(x2 - z2), BB = mod(Bb * Bb);
    const E = mod(AA - BB);
    const C = mod(x3 + z3), D = mod(x3 - z3);
    const DA = mod(D * Aa), CB = mod(C * Bb);
    x3 = mod((DA + CB) * (DA + CB));
    z3 = mod(x1 * (DA - CB) * (DA - CB));
    x2 = mod(AA * BB);
    z2 = mod(E * (AA + 121665n * E));
  }
  if (swap === 1n) { [x2, x3] = [x3, x2]; [z2, z3] = [z3, z2]; }
  return bigToLe32(mod(x2 * inv(z2)));
}

// ─── x-only Elligator 2, Z = 2 (paper section 4) ───────────────────────────────
function elligator2(inBytes) {
  const u = mod(leToBig(inBytes) & ((1n << 255n) - 1n));
  let tv1 = mod(2n * u * u);
  if (mod(tv1 + 1n) === 0n) tv1 = 0n;            // the exceptional case Zu^2 = -1
  const x1 = mod(-A * inv(mod(1n + tv1)));
  const gx1 = mod(x1 * x1 * x1 + A * x1 * x1 + x1);
  const x = isSquare(gx1) ? x1 : mod(-x1 - A);   // -x1 - A == x1*Z*u^2
  return bigToLe32(x);
}

const COFACTOR8 = (() => { const s = new Uint8Array(32); s[0] = 8; return s; })();
const H2C = (msg) => ladder(COFACTOR8, elligator2(sha256(msg)));

// ─── the derivations (paper section 4.1) ───────────────────────────────────────
const le16 = (v) => Uint8Array.from([v & 0xff, (v >> 8) & 0xff]);
const le32 = (v) => Uint8Array.from([v & 0xff, (v >> 8) & 0xff, (v >> 16) & 0xff, (v >> 24) & 0xff]);
const cat = (...xs) => { const n = xs.reduce((s, x) => s + x.length, 0); const o = new Uint8Array(n); let p = 0; for (const x of xs) { o.set(x, p); p += x.length; } return o; };
const ascii = (s) => Uint8Array.from([...s].map((c) => c.charCodeAt(0)));

const elementPoint = (code) => H2C(cat(ascii("DCHT"), le16(code)));
// The round is in the dummy preimage ON PURPOSE (the paper's eq. for D_{r,j}): a
// dispute publishes that round's alpha, and pad points that outlived their round
// would hand a chosen-query peer a standing threshold-bit read on the set size.
const dummyPoint = (seed, round, j) => H2C(cat(ascii("DCHD"), seed, le32(round), le16(j)));
const petScalar = (seed, round) => {
  const s = Uint8Array.from(sha256(cat(ascii("DCHP"), seed, le32(round))));
  s[31] &= 0x0f;                                  // < 2^252
  if (s.every((b) => b === 0)) s[0] = 1;          // measure-zero, still deterministic
  return s;
};

const PAD = 128;
function petBuild(seed, round, ownElement, elements) {
  const alpha = petScalar(seed, round);
  const entries = [];
  for (let i = 0; i < PAD; ++i)
    entries.push(ladder(alpha, i < elements.length ? elementPoint(elements[i])
                                                   : dummyPoint(seed, round, i)));
  entries.sort(Buffer.compare);                    // canonical order: encoded bytes
  return cat(...entries, ladder(alpha, elementPoint(ownElement)));
}
const petRespond = (seed, round, theirQ) => ladder(petScalar(seed, round), theirQ);
function petFinish(seed, round, theirS, theirR) {
  const alpha = petScalar(seed, round);
  for (let i = 0; i < PAD; ++i)
    if (Buffer.compare(Buffer.from(ladder(alpha, theirS.slice(i * 32, i * 32 + 32))),
                       Buffer.from(theirR)) === 0) return 1;
  return 0;
}
// The commitment is a MERKLE ROOT over the flight, not a flat hash: leaves 0..127 are
// the sorted blinded set, 128 is Q, 129 is R, then zero padding to 256. Leaf and node
// preimages are domain-separated (0x00 / 0x01) so a node can never be read as a leaf,
// and the leaf index is inside the leaf preimage so an element cannot be replayed into
// another slot. Written out here from the same description the C++ works from.
const MERKLE_DEPTH = 8;
const MERKLE_LEAVES = 1 << MERKLE_DEPTH;
const LEAF_Q = PAD;
const LEAF_R = PAD + 1;
const ZERO32 = new Uint8Array(32);
const merkleLeaf = (i, pt) =>
  sha256(cat(ascii("DCHV"), Uint8Array.from([0x00]), le16(i), pt));
const merkleNode = (l, r) => sha256(cat(ascii("DCHV"), Uint8Array.from([0x01]), l, r));
const leafPoint = (f1, f2, i) =>
  i < PAD ? f1.slice(i * 32, i * 32 + 32)
  : i === LEAF_Q ? f1.slice(PAD * 32, PAD * 32 + 32)
  : i === LEAF_R ? f2
  : ZERO32;
function merkleLevels(f1, f2) {
  const levels = [Array.from({ length: MERKLE_LEAVES }, (_v, i) => merkleLeaf(i, leafPoint(f1, f2, i)))];
  while (levels[levels.length - 1].length > 1) {
    const prev = levels[levels.length - 1], next = [];
    for (let i = 0; i < prev.length; i += 2) next.push(merkleNode(prev[i], prev[i + 1]));
    levels.push(next);
  }
  return levels;
}
const petFlightHash = (f1, f2) => merkleLevels(f1, f2)[MERKLE_DEPTH][0];
function merklePath(f1, f2, leafIndex) {
  const levels = merkleLevels(f1, f2);
  const out = [];
  let idx = leafIndex;
  for (let d = 0; d < MERKLE_DEPTH; ++d) { out.push(levels[d][idx ^ 1]); idx >>= 1; }
  return out;
}
function merkleVerify(leafIndex, leaf, path, root) {
  let acc = merkleLeaf(leafIndex, leaf), idx = leafIndex;
  for (const sib of path) {
    acc = (idx & 1) === 0 ? merkleNode(acc, sib) : merkleNode(sib, acc);
    idx >>= 1;
  }
  return Buffer.compare(Buffer.from(acc), Buffer.from(root)) === 0;
}

// ─── 1. the ladder really is X25519 ───────────────────────────────────────────
{
  const k = Uint8Array.from(Buffer.from("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4", "hex"));
  const u = Uint8Array.from(Buffer.from("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c", "hex"));
  k[0] &= 248; k[31] &= 127; k[31] |= 64;          // clamp in the harness, raw core
  check(Buffer.from(ladder(k, u)).toString("hex") ===
        "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
        "the BigInt ladder reproduces RFC 7748 vector 1");
}

// ─── 2. hash-to-curve lands in the prime-order subgroup ───────────────────────
{
  const ellBytes = bigToLe32(ELL);
  let allZero = true;
  for (let e = 0; e < 8; ++e)
    if (!ladder(ellBytes, elementPoint(e)).every((x) => x === 0)) allZero = false;
  check(allZero, "l * H2C(e) is the identity: on the curve, cofactor cleared");
}

// ─── 3. the deployed vector, recomputed from the paper's formulas + pinned tags ─
// These bytes came out of Xaya's dungeonchannel blob: the champion on spawn 0 of map
// seed 0x5EED1234 at round 7. The element codes are its visible set as Morton codes.
// Refrozen 2026-07-31 with the round-dependent pad: the flight digest and the root
// moved; Q and R did not, because neither contains a dummy.
{
  const seed = Uint8Array.from({ length: 32 }, (_v, i) => 0xa0 + i);
  const own = 611;
  const elems = [
    539, 561, 563, 569, 571, 540, 542, 564, 566, 572, 574, 660, 535, 541, 543,
    565, 567, 573, 575, 661, 663, 578, 584, 586, 608, 610, 616, 618, 704, 706,
    579, 585, 587, 609, 611, 617, 619, 705, 707, 713, 715, 582, 588, 590, 612,
    614, 620, 622, 708, 710, 583, 589, 591, 613, 615, 621, 623, 709, 711, 600,
    602, 624, 626, 632, 634, 720, 603, 625, 627, 633, 635, 628, 630, 636, 631];
  check(elems.length === 75, "the deployed visible set had 75 elements");

  const f1 = petBuild(seed, 7, own, elems);
  check(f1.length === (PAD + 1) * 32, "flight 1 is (N+1)*32 = 4128 bytes");
  check(Buffer.from(sha256(f1)).toString("hex") ===
        "6abe2e003620686b9bed5cb1027a6450c2cab56cf5900947f48fd7ed1ee32d15",
        "SHA-256 OF THE WHOLE FLIGHT MATCHES THE DEPLOYED BLOB");
  check(Buffer.from(f1.slice(PAD * 32)).toString("hex") ===
        "64922ddb71e5aceea0fb91adc3a75be6a601b95d91cc71b0839e7f3410965733",
        "and Q matches");

  const r = petRespond(seed, 7, f1.slice(PAD * 32));
  check(Buffer.from(r).toString("hex") ===
        "01204d2f6b9b94ee0a29055efc49a0ef25e164ff2eb7dbb9e082244d8415cf12",
        "and the flight-2 response matches");
  const root = petFlightHash(f1, r);
  check(Buffer.from(root).toString("hex") ===
        "9303f5c56a045f2f242b195a87584f5c286395c0d99ec402a46aeda18321a774",
        "and the commitment ROOT matches");
  // And the tree is usable: R proves against the root it just produced, and does not
  // prove at a neighbouring index.
  check(merkleVerify(LEAF_R, r, merklePath(f1, r, LEAF_R), root),
        "R proves against the root");
  check(!merkleVerify(LEAF_Q, r, merklePath(f1, r, LEAF_R), root),
        "and the same leaf does not prove at another index");
  check(petFinish(seed, 7, f1.slice(0, PAD * 32), r) === 1, "and the bit agrees");
}

// ─── 4. the protocol's correctness claim, end to end ──────────────────────────
{
  const sA = sha256(ascii("verify-a")), sB = sha256(ascii("verify-b"));
  const a = 100, b = 200, round = 5;
  const inSight = () => {
    const fa = petBuild(sA, round, a, [a, b, 300]);
    const fb = petBuild(sB, round, b, [b, a, 400]);
    const ra = petRespond(sA, round, fb.slice(PAD * 32));
    const rb = petRespond(sB, round, fa.slice(PAD * 32));
    return [petFinish(sA, round, fb.slice(0, PAD * 32), rb),
            petFinish(sB, round, fa.slice(0, PAD * 32), ra)];
  };
  const out = () => {
    const fa = petBuild(sA, round, a, [a, 300, 301]);
    const fb = petBuild(sB, round, b, [b, 400, 401]);
    const ra = petRespond(sA, round, fb.slice(PAD * 32));
    const rb = petRespond(sB, round, fa.slice(PAD * 32));
    return [petFinish(sA, round, fb.slice(0, PAD * 32), rb),
            petFinish(sB, round, fa.slice(0, PAD * 32), ra)];
  };
  const [ia, ib] = inSight();
  check(ia === 1 && ib === 1, "mutual membership gives the bit 1 on both sides");
  const [oa, ob] = out();
  check(oa === 0 && ob === 0, "no membership gives the bit 0 on both sides");
}

console.log(`\n${checks} checks, ${failures} failures`);
console.log(failures ? "FAILED" : "OK: the paper and the code agree, byte for byte");
process.exit(failures ? 1 : 0);
