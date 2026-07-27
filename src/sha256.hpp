// Freestanding FIPS 180-4 SHA-256, integer-only, with no OS or library
// dependency beyond <cstddef>/<cstdint>. This is the only hash the judge uses:
// commitment binding (C_{p,r}), the per-seat commitment chain head, salt
// derivation (salt_{p,r} = SHA256(seed_p || LE32(r))) and any seed expansion
// for the deterministic dungeon generator.
//
// DETERMINISM CONTRACT
//   * integer-only; no float, no intrinsics, no table other than the FIPS
//     constants; fixed iteration order.
//   * no allocation, no I/O, no errno, no exceptions, so it is safe under
//     -fno-exceptions -fno-rtti and compiles into a ZERO-IMPORT wasm reactor.
//   * endian-independent: the message schedule is loaded big-endian byte by
//     byte and the digest is stored big-endian byte by byte, so the result is
//     identical on every leg (native g++, wasmtime, V8/WebCrypto mirror).
//   * cannot trap on hostile input: `len` is only ever used to walk the caller's
//     buffer forward; a null `data` is tolerated when `len == 0`.
//
// This is a direct adaptation of the production-proven ships_sha256 blob code
// (arcade-xayaships). Do not "optimise" the
// arithmetic: a one-bit change here is a consensus fork.
#pragma once

#include <cstddef>
#include <cstdint>

namespace fow {

// Digest size in bytes. Matches fow::HASH_BYTES in fow.hpp; declared
// here too so this header stands alone (the blob's crypto layer must not depend
// on the game contract).
constexpr size_t SHA256_DIGEST_BYTES = 32;
constexpr size_t SHA256_BLOCK_BYTES = 64;

// Incremental context. Fixed size, trivially copyable, no pointers, so it may
// live on the stack of a wasm reactor call. init/update*/final must be called in
// that order; update() may be called any number of times (including zero)
// before final(). A context is single-use: call init() again to reuse it.
//
// NOTE: this struct is never serialized. Nothing in the packed game state
// depends on its layout or padding.
struct Sha256Ctx {
  uint32_t state[8];
  uint64_t bitlen;
  uint8_t buffer[64];
  uint32_t bufferLen;
};

void sha256_init(Sha256Ctx& ctx);

// Absorbs len bytes. Safe with len == 0 (data may then be null).
void sha256_update(Sha256Ctx& ctx, const uint8_t* data, size_t len);

// Applies FIPS 180-4 padding and writes the 32-byte big-endian digest to out.
// The context is left spent; do not update() after final().
void sha256_final(Sha256Ctx& ctx, uint8_t out[32]);

// One-shot digest: SHA-256(data[0..len)) -> out[0..32). Identical result to the
// incremental form for any split of the same message.
void sha256(const uint8_t* data, size_t len, uint8_t out[32]);

} // namespace fow
