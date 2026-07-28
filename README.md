# Fog of war without zero-knowledge proofs

A **blinded sighting test**: a two-party private membership test that lets two players in
a turn-based game learn *exactly one bit* about each other ("are we in sight?") and
nothing else. Reference implementation in ~500 lines of dependency-free C++17, plus the
paper that specifies it and an independent implementation that checks the paper against
the code byte for byte.

Extracted from the fog of war deployed in Xaya's `dungeonchannel`, and pinned to be
byte-identical to it.

## The problem this solves

Hidden information on a replicated state machine is awkward: every replica must verify
every transition, yet fog of war requires that positions stay secret. Commit-reveal hides
positions perfectly, and that is exactly what breaks the game. If neither player may
learn anything about the other before the endgame, two players six tiles apart **walk past
each other in the dark, every round, for the whole match**. In our own testbed, removing
all position disclosure produced 142 rounds of mutual line of sight in which neither
player was told anything.

So the requirement is a conjunction, and both halves have to hold at once:

1. **Nobody learns your position** unless they are close to you.
2. **Two players who *are* close both learn so**, in the same round, every round.

The usual answer to enforcing that on-chain is a zk-SNARK per move. We could not take it:
our referee is a zero-import WebAssembly blob metered at 66.3M fuel per call, and one
Groth16 verification measures at 73.6M. This is what we built instead.

## What the library gives you

Two parties, each holding one secret element and a set of elements. After one round trip
both learn one bit, *is my element in your set?*, and provably nothing else.

```cpp
#include "fow.hpp"

// Each party has a secret seed. Elements are 16-bit codes; in a game they are tiles
// (we use a Morton code), but the library neither knows nor cares.
uint8_t flightA[fow::PET_BUILD_BYTES];
fow::petBuild(seedA, round, myElement, myVisibleSet, count, flightA);   // flight 1
// ... exchange flight 1 with the peer, then answer their Q (its last 32 bytes) ...
uint8_t responseA[32];
fow::petRespond(seedA, round, theirQ, responseA);                       // flight 2
// ... exchange flight 2 ...
int inSight = fow::petFinish(seedA, round, theirSet, theirResponse);    // the bit
```

Both sides get the same answer whenever the underlying relation is symmetric, which is
what makes "the" shared bit well defined.

## How it works

The construction is the classical Diffie–Hellman private matching protocol of Meadows
(1986) and Huberman–Franklin–Hogg (1999), known today as ECDH-PSI. What is different here
is that it is **specialised from set intersection down to membership of a single element,
evaluated in both directions**, because a game needs one bit and not the overlap.

Writing `α` for a per-round blinding scalar and `P_e` for the curve point of element `e`:

| flight | A sends | B sends |
|---|---|---|
| 1 | `S_A = sort{ α_A·P_e : e ∈ set_A }` padded to 128, then `Q_A = α_A·P_a` | symmetric |
| 2 | `R_A = α_A·Q_B` | `R_B = α_B·Q_A` |

A then tests whether `R_B ∈ { α_A·s : s ∈ S_B }`. Since `α_A(α_B·P_e) = α_B(α_A·P_e)` on
the prime-order subgroup, that holds precisely when B's set contains A's element.

Three details carry most of the weight:

- **Elligator 2 hash-to-curve, not `H(e)·G`.** This is not a stylistic choice. With
  `P_e = H(e)·G` the discrete log of every element is public, and a receiver recovers the
  *entire* set in about `3·|universe|` scalar multiplications: take two blinded elements,
  form `{h_v⁻¹·X_i}` over all candidates `v`, and intersect. The intersection is `α·G`,
  after which every element labels itself. The paper states it plainly, calculation included; we found a
  live instance of it in a well-regarded reference implementation. Points whose discrete
  log nobody knows are the whole difference between blinding and encoding.
- **Fixed-size padding.** Sets are padded to 128 entries with seed-derived dummies hashed
  to the curve exactly like real elements, so neither the message length nor the work done
  leaks the set size.
- **Everything is derived, nothing is sampled.** The blinding scalar is
  `SHA256("DCHP" ‖ seed ‖ LE32(round))` masked to 252 bits; dummies are
  `H2C("DCHD" ‖ seed ‖ LE16(i))`, deliberately round-independent so a client can
  precompute every point it will ever hash. That determinism is what lets an audit later
  recompute any byte a party should have sent, which is how the deployment replaces an
  in-round proof with after-the-fact attribution.

## Attribution instead of zero-knowledge

The bit is an **instrument, never evidence**. Nothing in the deployed game is ever
convicted on someone's claim about what their sighting test said. Instead:

- every byte a party should send is a pure function of a seed it is already committed to
  reveal at the endgame, so an audit can recompute the honest transcript after the fact;
- `petFlightHash` binds a party to the bytes it actually sent (it goes in the party's own
  signed move), so a poisoned flight is attributable rather than deniable. It is a Merkle
  root over the flight, not a flat hash, so a verifier can check ONE supplied element
  with an 8-step path instead of rehashing all 129. One honest caveat, learned in
  deployment: only elements the PROVER can locate can ride a path. The accuser's claim
  about its peer's set works that way (~290 bytes); its claim about its OWN set does not,
  because locating the peer's element there requires the peer's still-hidden position —
  the bit's own privacy hides which element matched — so that half of a dispute ships
  the set whole and the referee scans, which the root has already made cheap to bind;
- convictions come from recomputing the public relation over positions fixed by
  commitments made *before* the round's information existed.

The measurement that shapes this: **rebuilding a whole flight inside the referee costs
~1.98 billion fuel, thirty times the entire per-call budget.** Verifying a *supplied*
flight against its committed hash and recomputing one named element costs 15.9M. So the
adjudication is necessarily "check one element of a flight someone hands you", not
"recompute the flight".

## What it does not do

Stated plainly, because these are the parts a reader should not have to discover:

- **Accumulated negatives leak, by construction.** Every "no" tells you the opponent is
  outside your visible set, and the constraints accumulate. Any protocol that guarantees
  encounters must leak at least the negatives. We measured it rather than assuming it
  away: an exact Bayesian attacker given every advantage still faces **211–925 candidate
  tiles**, and active probing located a moving player in **0 of 64 matches**.
- **No fairness or liveness.** A party can stall mid-exchange; the surrounding protocol
  needs a timeout that forfeits.
- **The relation must be symmetric.** Asymmetric sight ranges would make the two parties'
  bits legitimately disagree, and the shared-bit framing collapses.
- **Malicious inputs are not prevented, only attributed.** Nothing stops a party feeding a
  fabricated set; what stops it *paying* is the determinism and audit above. In the
  deployed game the signed-flight component is landing at the time of writing, so a
  fabricated flight is currently detectable-in-principle rather than punished.
- **Not constant-time in the hardened sense.** Branching is not secret-dependent except
  the final equality tests that decide the bit both sides are about to learn, but this was
  written for consensus determinism first, not for a side-channel adversary.

## Numbers

| | |
|---|---|
| flight 1 | 4,128 bytes; flight 2: 32 bytes; ≈8.3 kB per round both directions |
| per-party cost | 129 hash-to-curve maps + 259 ladder multiplications ≈ 100 ms in V8 |
| encounters | unnoticed mutual-sight rounds: **0** (142 before the test existed) |
| privacy | Bayesian attacker: 211–925 candidate tiles; located in 0 of 64 matches |
| referee cost, happy path | **zero**: the referee never verifies the exchange |

## Build and test

No dependencies beyond a C++17 compiler.

```sh
make test      # RFC 7748 vectors, the subgroup identity, the protocol end to end,
               # and byte-identity with the deployed dungeonchannel blob
make verify    # the independent BigInt implementation, written from the paper (needs node)
```

`make test` and `make verify` are two implementations that share no code, both reproducing
the same deployed bytes. That agreement is the claim; if the paper and the code ever
diverge, `make verify` fails.

## The paper

*Fog of War without Zero-Knowledge Proofs: A Blinded Mutual-Sighting Test for Trustless
Game Channels* is in [`paper/blinded-sighting-test.pdf`](paper/blinded-sighting-test.pdf).
It carries the protocol with a correctness theorem, the security analysis (including
the known-discrete-log break above), and the related work.

## Prior art, and what is ours

The double-blinding trick is old and good, and we claim none of it. It goes back to
Meadows' cryptographic matchmaking (1986) and Huberman, Franklin and Hogg's private
community matching (1999); it was formalised as private set intersection by Freedman,
Nissim and Pinkas (2004) and given linear-complexity DH instantiations by De Cristofaro
and Tsudik (2010); it runs at planetary scale in Google's Password Checkup and Apple's PSI
system. The closest prior art to our setting is Narayanan et al.'s private proximity
testing (NDSS 2011). Hidden information in adversarial games begins with Mental Poker
(1979); the modern blockchain example is Dark Forest, which takes the zk-SNARK road we
could not afford.

Our engineering entry point into this literature was Edward Thomson's open-source
[ECDH-PSI implementation](https://github.com/EdwardAThomson/Private-Set-Intersection), a
readable working embodiment of the classical protocol that let us prototype in days. What
we changed, and why, is in the paper's related-work section.

What is ours is the adaptation: the reduction to one bit run both ways, the fixed-size
padding, the seed-derived determinism that makes a transcript recomputable, and the
substitution of after-the-fact attribution for an in-round proof, which is what makes
fog of war affordable on a metered consensus engine.

Game channels, the setting all of this lives in, are due to Daniel Kraft:
[*Game Channels for Trustless Off-Chain Interactions in Decentralized Virtual Worlds*](https://ledgerjournal.org/ojs/ledger/article/download/15/64/397)
(PDF), Ledger 1:84–98 (2016), [doi:10.5195/ledger.2016.15](https://doi.org/10.5195/ledger.2016.15).

## Authors

Xaya Developers: Andrew Colosimo, Roy Crombleholme, Andrew Gore, Konstantin Gorskov,
and Daniel Kraft.

MIT licensed.
