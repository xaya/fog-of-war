// Freestanding FIPS 180-4 SHA-256. Textbook, integer-only implementation --
// no OpenSSL/libcrypto, no platform intrinsics, fixed iteration order, so the
// result is identical on every leg (native g++, wasmtime, V8) that ever runs
// this code. See sha256.hpp for the public API and the determinism
// contract.
#include "sha256.hpp"

#include <cstring>

namespace fow {

namespace {

// FIPS 180-4 section 4.2.2 round constants (first 32 bits of the fractional
// parts of the cube roots of the first 64 primes).
constexpr uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

// FIPS 180-4 section 5.3.3 initial hash value.
constexpr uint32_t H0[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
};

// n is always in [1,31] at every call site below, so neither shift is UB.
inline uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

// Processes exactly one 64-byte block, updating state in place.
void processBlock(uint32_t state[8], const uint8_t block[64]) {
  uint32_t w[64];
  // Big-endian load, byte by byte: no endianness dependence, no unaligned load.
  for (int i = 0; i < 16; ++i) {
    w[i] = (static_cast<uint32_t>(block[4 * i]) << 24) |
           (static_cast<uint32_t>(block[4 * i + 1]) << 16) |
           (static_cast<uint32_t>(block[4 * i + 2]) << 8) |
           (static_cast<uint32_t>(block[4 * i + 3]));
  }
  for (int i = 16; i < 64; ++i) {
    const uint32_t s0 =
        rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
    const uint32_t s1 =
        rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }

  uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
  uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

  for (int i = 0; i < 64; ++i) {
    const uint32_t s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
    const uint32_t ch = (e & f) ^ ((~e) & g);
    const uint32_t temp1 = h + s1 + ch + K[i] + w[i];
    const uint32_t s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
    const uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
    const uint32_t temp2 = s0 + maj;

    h = g; g = f; f = e; e = d + temp1;
    d = c; c = b; b = a; a = temp1 + temp2;
  }

  state[0] += a; state[1] += b; state[2] += c; state[3] += d;
  state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

} // namespace

void sha256_init(Sha256Ctx& ctx) {
  for (int i = 0; i < 8; ++i) ctx.state[i] = H0[i];
  ctx.bitlen = 0;
  ctx.bufferLen = 0;
  std::memset(ctx.buffer, 0, sizeof(ctx.buffer));
}

void sha256_update(Sha256Ctx& ctx, const uint8_t* data, size_t len) {
  // Tolerates data == nullptr when len == 0 (hostile-input rule: never trap).
  if (len == 0 || data == nullptr) return;
  ctx.bitlen += static_cast<uint64_t>(len) * 8;

  size_t pos = 0;
  // Top up a partially-filled buffer first.
  if (ctx.bufferLen > 0) {
    const uint32_t need = 64 - ctx.bufferLen;
    const size_t take = need < len ? need : len;
    std::memcpy(ctx.buffer + ctx.bufferLen, data, take);
    ctx.bufferLen += static_cast<uint32_t>(take);
    pos += take;
    if (ctx.bufferLen == 64) {
      processBlock(ctx.state, ctx.buffer);
      ctx.bufferLen = 0;
    }
  }

  // Consume full blocks directly from the input.
  while (len - pos >= 64) {
    processBlock(ctx.state, data + pos);
    pos += 64;
  }

  // Buffer the remainder.
  const size_t rem = len - pos;
  if (rem > 0) {
    std::memcpy(ctx.buffer, data + pos, rem);
    ctx.bufferLen = static_cast<uint32_t>(rem);
  }
}

void sha256_final(Sha256Ctx& ctx, uint8_t out[32]) {
  const uint64_t bitlen = ctx.bitlen;

  // Append the 0x80 marker byte directly into the buffer (bypassing
  // sha256_update(), which would also, incorrectly, count it towards the
  // message bit length).
  uint32_t idx = ctx.bufferLen;
  ctx.buffer[idx++] = 0x80;

  if (idx > 56) {
    // Not enough room left for the 8-byte length in this block: zero-pad to a
    // full 64 bytes, process it, then start a fresh all-zero block.
    while (idx < 64) ctx.buffer[idx++] = 0x00;
    processBlock(ctx.state, ctx.buffer);
    idx = 0;
  }
  while (idx < 56) ctx.buffer[idx++] = 0x00;

  // 64-bit big-endian message length in bits.
  for (int i = 0; i < 8; ++i)
    ctx.buffer[56 + i] = static_cast<uint8_t>(bitlen >> (8 * (7 - i)));
  processBlock(ctx.state, ctx.buffer);

  for (int i = 0; i < 8; ++i) {
    out[4 * i] = static_cast<uint8_t>(ctx.state[i] >> 24);
    out[4 * i + 1] = static_cast<uint8_t>(ctx.state[i] >> 16);
    out[4 * i + 2] = static_cast<uint8_t>(ctx.state[i] >> 8);
    out[4 * i + 3] = static_cast<uint8_t>(ctx.state[i]);
  }
}

void sha256(const uint8_t* data, size_t len, uint8_t out[32]) {
  Sha256Ctx ctx;
  sha256_init(ctx);
  sha256_update(ctx, data, len);
  sha256_final(ctx, out);
}

} // namespace fow
