// Independent BigInt arithmetic for the reference protocol. Known answers and
// counterexamples test the specified cases, not privacy or the current game's wire.

import { createHash } from "node:crypto";

let checks = 0, failures = 0;
const check = (ok, what) => {
  ++checks;
  if (!ok) { ++failures; console.log(`  FAIL: ${what}`); }
  return ok;
};

// ─── the field: F_p, p = 2^255 - 19 (paper section 2) ──────────────────────────
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
// Unclamped is deliberate and is the paper's section 2: these scalars must compose
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

// ─── x-only Elligator 2, Z = 2 (paper section 2) ───────────────────────────────
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

// ─── the derivations (paper section 2) ─────────────────────────────────────────
const le16 = (v) => Uint8Array.from([v & 0xff, (v >> 8) & 0xff]);
const le32 = (v) => Uint8Array.from([v & 0xff, (v >> 8) & 0xff, (v >> 16) & 0xff, (v >> 24) & 0xff]);
const cat = (...xs) => { const n = xs.reduce((s, x) => s + x.length, 0); const o = new Uint8Array(n); let p = 0; for (const x of xs) { o.set(x, p); p += x.length; } return o; };
const ascii = (s) => Uint8Array.from([...s].map((c) => c.charCodeAt(0)));

const elementPoint = (code) => H2C(cat(ascii("DCHT"), le16(code)));
// The round is in the dummy preimage ON PURPOSE (the paper's D_{i,r,j}): a
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
  let valid = true;
  for (let e = 0; e < 8; ++e) {
    const point = elementPoint(e), x = leToBig(point);
    if (x === 0n || x >= P || !isSquare(mod(x * x * x + A * x * x + x)) ||
        !ladder(ellBytes, point).every((v) => v === 0) ||
        Buffer.compare(ladder(bigToLe32(ELL - 1n), point), point) !== 0) valid = false;
  }
  check(valid, "sampled points are nonidentity, on-curve and satisfy the subgroup identities");
}

// ─── 3. the historical vector, recomputed from the formulas and pinned tags ─
// Historical fixture from Dungeon Channel revision 1ad3b7f (2026-08-01 14:54 UTC):
// spawn 0 = tile (120, 5) of map seed 0x5EED1234, round 7, its omnidirectional
// radius-6 sight set. No current game rules or hosted WASM are loaded.
{
  const seed = Uint8Array.from({ length: 32 }, (_v, i) => 0xa0 + i);
  const own = 10897;                                 // morton((120, 5)), 14 bits
  const elems = [
    10790, 10796, 10798, 10884, 10886, 10892, 10894, 10791, 10797, 10799, 10885,
    10887, 10893, 10895, 10802, 10808, 10810, 10896, 10898, 10904, 10906, 10777,
    10779, 10801, 10803, 10809, 10811, 10897, 10899, 10905, 10907, 10806, 10812,
    10814, 10900, 10902, 10908, 10910, 10807, 10813, 10815, 10901, 10903, 10909,
    10911, 10850, 10856, 10858, 10944, 10946, 10952, 10954, 10945, 10948, 10949];
  check(elems.length === 55, "the historical visible set had 55 elements");

  const f1 = petBuild(seed, 7, own, elems);
  check(f1.length === (PAD + 1) * 32, "flight 1 is (N+1)*32 = 4128 bytes");
  check(Buffer.from(sha256(f1)).toString("hex") ===
        "106e8a31ba80abcab999bd08fd7637eba04c87232637416d74d325f0b541b7d9",
        "flight digest matches the historical fixture");
  check(Buffer.from(f1.slice(PAD * 32)).toString("hex") ===
        "2ec31f4c132caefd3a05ae1a5fc40974437417b36dd7efde2e6d493c4d551417",
        "and Q matches");

  const r = petRespond(seed, 7, f1.slice(PAD * 32));
  check(Buffer.from(r).toString("hex") ===
        "fc91185d3b6994fda37920ebe2473849321249ca4d345bfedffde2319a73b12b",
        "and the flight-2 response matches");
  const root = petFlightHash(f1, r);
  check(Buffer.from(root).toString("hex") ===
        "81fdba4d86cb4be4dfc44adc3822dc9fce9bb06026316c8eedd3a6e9e1448fca",
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

// Directional and boundary cases, plus observable equality patterns.
{
  const sA = sha256(ascii("boundary-a")), sB = sha256(ascii("boundary-b"));
  const q = PAD * 32;
  for (const round of [0, 65535]) {
    const fa = petBuild(sA, round, 0, [0, 65535]);
    const fb = petBuild(sB, round, 65535, [65535]);
    check(petFinish(sA, round, fb, petRespond(sB, round, fa.slice(q))) === 0 &&
          petFinish(sB, round, fa, petRespond(sA, round, fb.slice(q))) === 1,
          "asymmetric membership is correct at the round and element boundaries");
    check(Buffer.compare(fa, petBuild(sA, round, 0, [65535, 0])) === 0,
          "set enumeration order does not change the flight");
  }
  const empty = petBuild(sA, 0, 0, []);
  const query = petBuild(sB, 0, 65535, [65535]);
  check(petFinish(sB, 0, empty, petRespond(sA, 0, query.slice(q))) === 0,
        "an empty padded set has no membership");
  const dup = petBuild(sA, 0, 0, [0, 0]);
  let matches = 0;
  for (let i = 0; i < PAD; ++i)
    if (Buffer.compare(dup.slice(i * 32, (i + 1) * 32), dup.slice(q)) === 0) ++matches;
  check(matches === 2, "duplicate multiplicity and query/set overlap are visible");
  check(petFinish(sA, 0, new Uint8Array(PAD * 32), ZERO32) === 1,
        "a forged zero set and response force a positive raw result");
}

// Counterexample: a public discrete-log encoding lets one response expose the set.
{
  const g = H2C(ascii("known-log-counterexample"));
  const ha = (e) => leToBig(sha256(ascii(`bad-map:${e}`))) % (ELL - 1n) + 1n;
  const alphaA = leToBig(petScalar(sha256(ascii("attacker")), 9));
  const alphaB = leToBig(petScalar(sha256(ascii("sender")), 9));
  const queryLog = mod(alphaA * ha(3), ELL);
  const response = ladder(bigToLe32(alphaB), ladder(bigToLe32(queryLog), g));
  const recoveredBase = ladder(bigToLe32(pow(queryLog, ELL - 2n, ELL)), response);
  check(Buffer.compare(recoveredBase, ladder(bigToLe32(alphaB), g)) === 0,
        "one response reveals the sender's blinded base under a known-log encoding");
  const hidden = [2, 5, 7];
  const set = hidden.map((e) => ladder(bigToLe32(mod(alphaB * ha(e), ELL)), g));
  const recovered = [];
  for (let e = 0; e < 10; ++e) {
    const candidate = ladder(bigToLe32(ha(e)), recoveredBase);
    if (set.some((point) => Buffer.compare(point, candidate) === 0)) recovered.push(e);
  }
  check(JSON.stringify(recovered) === JSON.stringify(hidden),
        "enumeration recovers all real elements, not just the intended membership bit");
}

console.log(`\n${checks} checks, ${failures} failures`);
console.log(failures ? "FAILED" : "OK: reference vectors and stated counterexamples pass");
process.exit(failures ? 1 : 0);
