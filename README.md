# Fog of war without zero-knowledge proofs

A deterministic C++17 reference for a blinded membership test, with a
[paper](paper/blinded-sighting-test.pdf) and an independent BigInt implementation.
Code by **Xaya Developers**, under the [MIT licence](LICENSE). The paper lists its
research authors separately.

Each party holds an element and a set. After exchanging two flights, A computes
whether A's element is in B's set, and B computes the reverse membership. In a
game those can be directed sighting results; they agree only for a symmetric
relation. Honest correctness is conditional on the group and encoding assumptions
stated in the paper. This library does not establish privacy against malicious
inputs or implement a complete game channel.

## Scope

This is the original sight-only instrument extracted from Dungeon Channel. Its
frozen test vector was produced by revision 1ad3b7f (2026-08-01 14:54 UTC) of the original
Dungeon Channel history, which the arcade repository's retained history does not
reach: an omnidirectional radius-6 sight set, before the facing beam. The
current [Dungeon Channel](https://github.com/xaya/arcade-dungeonchannel) (a
private repository) still reproduces that vector's set block and query with the
same per-element primitive, but its flight layout, Merkle tree and response
differ, it validates its published second-lock and victim points, and it uses sealed-envelope sight
delivery, a hearing block and additional settlement checks. Do not use this
library as a replacement for that game's current rules or treat its historical
vector as a current compatibility test. The paper's appendix lists the fixture.

The underlying DH matching technique is established prior art. The paper presents
an implementation and game-channel integration case study, with explicit limits.
It does not claim the first cryptographic fog of war, a new PSI primitive, or a
complete malicious-security proof. Its closest comparisons include
[OpenConflict](https://crypto.stanford.edu/~dabo/pubs/papers/onlinegames.pdf),
[Thomson's game proposal](https://edward-thomson.medium.com/preventing-cheaters-in-fog-of-war-games-69f202fbe107),
[financially backed covert security](https://eprint.iacr.org/2021/1652) and,
on the zero-knowledge road, [Dark Forest](https://blog.zkga.me/announcing-darkforest).

## Use

```cpp
#include "fow.hpp"

uint8_t flight[fow::PET_BUILD_BYTES];
fow::petBuild(seed, round, myElement, mySet, count, flight);

uint8_t response[32];
fow::petRespond(seed, round, theirQ, response);
int inTheirSet = fow::petFinish(seed, round, theirSet, theirResponse);
```

Check the return values and provide buffers of the sizes documented in
[the header](include/fow.hpp). Sets contain at most 128 16-bit element codes;
rounds are 16-bit values encoded as LE32 in the derivations. Seed each party and
match independently with secure randomness. Never wrap the round counter or
continue using a seed after it is disclosed.

The first flight is a sorted, padded set of 128 blinded points plus the query
point: 4,128 bytes. The response is 32 bytes. Both parties together exchange
8,320 payload bytes, excluding signatures and game metadata. The Merkle helper
commits the set, query and response; an indexed point opening is 290 bytes,
which is not the size of a complete game dispute.

## Security boundaries

- Deterministic derivation makes transcripts recomputable. A surrounding protocol
  must authenticate the actual delivered bytes, bind game inputs, manage seed
  disclosures and provide sound dispute and timeout rules.
- Revealing a seed exposes its epoch retrospectively, and a single disclosed
  round scalar exposes that round's set, query and real count. Re-key before
  further play if future positions must remain hidden; the reveal also fixes
  every sighting bit the revealer computed, which constrains its peers. Later
  penalties cannot undo a leak.
- Answer exactly one query per seed, round and peer. `petRespond` is a pure
  function and enforces no limit.
- Malicious queries read more than one tile: each response answers a chosen
  predicate over the responder's set and position, and a doctored response
  forces the peer's result to 0. The raw API does not validate point encodings
  or membership inputs; an all-zero forged set and response, or a single
  non-canonical zero among honest entries, always produces a positive result.
  The bit alone is never evidence of legal play.
- Padding fixes message length. Duplicate entries and query/set equality remain
  visible, and two parties' responses are equal exactly when their elements are
  equal, which anyone holding the transcript can see; repeated results and
  colluding observers can reveal more context.
- The code is not constant-time, and the Merkle helpers share scratch storage.
  Serialize calls to those helpers.

Do not replace hash-to-point with `H(element) * G`: when the discrete logarithm
is public, one response lets a requester enumerate the peer's entire set. The
independent tests demonstrate this failure.

## Build and verify

Requires a C++17 compiler supporting `unsigned __int128`; the independent check
also requires Node.js.

```sh
make test      # known answers, every element point (a few seconds), membership, the fixture, Merkle openings
make verify    # independent arithmetic over the same fixture and examples, plus the known-log break
make paper     # regenerate the PDF with Tectonic
```

Passing these checks supports the tested arithmetic and encodings. It does not
prove privacy, novelty, current-game compatibility, or every claim in the paper.
The paper separates exact byte/operation counts from historical measurements and
identifies the current platform limits by source revision.
