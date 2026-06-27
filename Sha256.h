/**
 * ============================================================
 *  GhostPort - Sha256.h
 *  Version: 3.0 (Milestone 3 - Cryptographic SPA)
 * ============================================================
 *
 *  A self-contained, header-only SHA-256 implementation.
 *  No external libraries (OpenSSL, Crypto++, etc.) required.
 *
 * ──────────────────────────────────────────────────────────
 *  THE MATH: How SHA-256 Actually Works
 * ──────────────────────────────────────────────────────────
 *
 *  SHA-256 is a Merkle–Damgård construction hash function.
 *  It maps an arbitrary-length input to a fixed 256-bit (32-byte)
 *  output (the "digest"), with these critical properties:
 *
 *    PREIMAGE RESISTANCE:
 *      Given digest H, it is computationally infeasible to find M
 *      such that SHA256(M) = H. An attacker can't reverse the hash
 *      to recover the secret key from an intercepted HMAC tag.
 *
 *    COLLISION RESISTANCE:
 *      It is infeasible to find M1 ≠ M2 such that SHA256(M1) = SHA256(M2).
 *      A forged packet can't accidentally produce the right HMAC.
 *
 *    AVALANCHE EFFECT:
 *      Flipping a single input bit changes ~50% of output bits randomly.
 *      Changing the timestamp by 1 second = completely different HMAC.
 *
 *  ALGORITHM OVERVIEW:
 *
 *    1. PAD: Extend the message so its length ≡ 448 (mod 512) bits,
 *       then append the original length as a 64-bit big-endian integer.
 *       This ensures the message fills complete 512-bit (64-byte) blocks.
 *
 *    2. COMPRESS: Process each 64-byte block through the compression
 *       function using 64 rounds of bit mixing. The state is 8×32-bit
 *       words (256 bits total), updated each round.
 *
 *    3. FINALIZE: After all blocks, serialize the 8 state words
 *       (big-endian) to produce the 32-byte digest.
 *
 *  NOTHING-UP-MY-SLEEVE NUMBERS:
 *    The constants K[0..63] and H0[0..7] are NOT arbitrary — they are
 *    derived mathematically from primes so no one can backdoor them:
 *      K[i]  = first 32 bits of fractional_part( cbrt(prime[i]) )
 *      H0[i] = first 32 bits of fractional_part( sqrt(prime[i]) )
 *
 *  AUTHOR:  Syed Haider Ali (FYP - GhostPort)
 * ============================================================
 */

#pragma once

#include <cstdint>
#include <cstring>    // memcpy, memset
#include <array>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>


// ─── SHA-256 Round Constants K[0..63] ─────────────────────────────────────────
//
//  Derived from: floor( cbrt(prime[i]) * 2^32 ) mod 2^32
//  for the first 64 primes: 2, 3, 5, 7, 11, 13, ...
//
//  Example: cbrt(2) = 1.2599...
//           fractional part = 0.2599...
//           × 2^32 = 0x428A2F98  ← that's K[0]
//
//  These provide cryptographic "entropy injection" into each round.
//  Because they come from a publicly verifiable formula, no one can
//  hide a trapdoor in them.
//
static constexpr uint32_t SHA256_K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// ─── SHA-256 Initial Hash Values H0[0..7] ─────────────────────────────────────
//
//  Derived from: floor( sqrt(prime[i]) * 2^32 ) mod 2^32
//  for the first 8 primes: 2, 3, 5, 7, 11, 13, 17, 19
//
//  Example: sqrt(2) = 1.41421356...
//           fractional part = 0.41421356...
//           × 2^32 = 0x6A09E667  ← that's H0[0]
//
//  These are the starting state of the hash. Each call begins
//  from this same fixed point, ensuring determinism.
//
static constexpr uint32_t SHA256_H0[8] = {
    0x6a09e667,   // sqrt( 2) — prime #1
    0xbb67ae85,   // sqrt( 3) — prime #2
    0x3c6ef372,   // sqrt( 5) — prime #3
    0xa54ff53a,   // sqrt( 7) — prime #4
    0x510e527f,   // sqrt(11) — prime #5
    0x9b05688c,   // sqrt(13) — prime #6
    0x1f83d9ab,   // sqrt(17) — prime #7
    0x5be0cd19    // sqrt(19) — prime #8
};


// ─── Sha256 Class ─────────────────────────────────────────────────────────────

/**
 * @class Sha256
 * @brief Header-only, stateless SHA-256 implementation.
 *
 * All methods are static — Sha256 is a pure function namespace, not an object.
 * Usage:
 *   auto digest = Sha256::hash(myData, myDataLen);
 *   auto hexStr = Sha256::toHexString(digest);
 */
class Sha256 {
public:
    /// A 32-byte (256-bit) digest result.
    using Digest = std::array<uint8_t, 32>;

    /**
     * @brief Compute SHA-256 hash of arbitrary data.
     *
     * This is the single public entry point. Internally:
     *   1. Copies state from H0
     *   2. Processes all complete 64-byte blocks
     *   3. Pads the final block(s)
     *   4. Serializes the state to 32 bytes
     *
     * @param data  Pointer to input bytes (can be nullptr if len == 0).
     * @param len   Number of input bytes.
     * @return      32-byte SHA-256 digest.
     */
    static Digest hash(const uint8_t* data, size_t len);

    /**
     * @brief Convenience overload for std::vector<uint8_t>.
     */
    static Digest hash(const std::vector<uint8_t>& data) {
        return hash(data.data(), data.size());
    }

    /**
     * @brief Convert a digest to a lowercase hex string for display.
     * @return e.g. "e3b0c44298fc1c149afbf4c8996fb924..."
     */
    static std::string toHexString(const Digest& d) {
        std::ostringstream oss;
        for (uint8_t b : d)
            oss << std::hex << std::setfill('0') << std::setw(2)
                << static_cast<unsigned>(b);
        return oss.str();
    }

private:
    static constexpr size_t BLOCK_BYTES = 64;   // 512-bit block

    // ── Bitwise building blocks ──────────────────────────────────────────────
    //
    //  ROTR(x, n) — Right-rotate x by n bits.
    //    This is the core non-linear operation. Unlike a shift, bits don't
    //    fall off the end — they wrap around. This creates circular diffusion.
    //    Example: ROTR(0b10110001, 2) = 0b01101100
    //
    static constexpr uint32_t ROTR(uint32_t x, int n) {
        return (x >> n) | (x << (32 - n));
    }

    // ── SHA-256 Sigma (Σ) and sigma (σ) functions ────────────────────────────
    //
    //  Capital Σ (Sigma) — used in the main round, operates on working vars:
    //
    //  Σ0(a) = ROTR(a,2) ⊕ ROTR(a,13) ⊕ ROTR(a,22)
    //  Σ1(e) = ROTR(e,6) ⊕ ROTR(e,11) ⊕ ROTR(e,25)
    //
    //  Small σ (sigma) — used in message schedule expansion:
    //
    //  σ0(x) = ROTR(x,7)  ⊕ ROTR(x,18) ⊕ (x >> 3)
    //  σ1(x) = ROTR(x,17) ⊕ ROTR(x,19) ⊕ (x >> 10)
    //
    //  The combination of rotations at DIFFERENT offsets ensures that
    //  every input bit influences many output bits (diffusion).
    //
    static constexpr uint32_t Sigma0(uint32_t x) { return ROTR(x,2)  ^ ROTR(x,13) ^ ROTR(x,22); }
    static constexpr uint32_t Sigma1(uint32_t x) { return ROTR(x,6)  ^ ROTR(x,11) ^ ROTR(x,25); }
    static constexpr uint32_t sigma0(uint32_t x) { return ROTR(x,7)  ^ ROTR(x,18) ^ (x >> 3);   }
    static constexpr uint32_t sigma1(uint32_t x) { return ROTR(x,17) ^ ROTR(x,19) ^ (x >> 10);  }

    // ── Choice and Majority functions ────────────────────────────────────────
    //
    //  Ch(x, y, z) — "Choice": for each bit position, x CHOOSES between
    //    the corresponding bit from y (if x=1) or z (if x=0).
    //    Algebraically: Ch(x,y,z) = (x & y) ^ (~x & z)
    //
    //  Maj(x, y, z) — "Majority": output bit is whichever value (0 or 1)
    //    appears in the majority of x, y, z at that bit position.
    //    Algebraically: Maj(x,y,z) = (x & y) ^ (x & z) ^ (y & z)
    //
    //  These functions introduce non-linearity — without them, SHA-256
    //  would be linear (and breakable via linear algebra).
    //
    static constexpr uint32_t Ch (uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (~x & z);         }
    static constexpr uint32_t Maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }

    /**
     * @brief Process one 64-byte block, updating the 8-word state in-place.
     *
     * THE CORE COMPRESSION FUNCTION:
     *
     *  PHASE 1 — MESSAGE SCHEDULE:
     *    From the 16 input words (W[0..15]), derive 48 more (W[16..63])
     *    using the σ functions. This "expands" the block so every input
     *    bit influences all 64 rounds.
     *
     *      W[i] = σ1(W[i-2]) + W[i-7] + σ0(W[i-15]) + W[i-16]   (i = 16..63)
     *
     *  PHASE 2 — ROUND FUNCTION (64 rounds):
     *    Working variables a,b,c,d,e,f,g,h start from current state.
     *    Each round computes two "temporary words":
     *
     *      T1 = h + Σ1(e) + Ch(e,f,g) + K[t] + W[t]
     *      T2 = Σ0(a) + Maj(a,b,c)
     *
     *    Then rotates: h=g, g=f, f=e, e=d+T1, d=c, c=b, b=a, a=T1+T2
     *
     *  PHASE 3 — STATE UPDATE:
     *    Add the working variables back into the state (Davies–Meyer):
     *      state[i] += working_var[i]
     *
     * @param state  Current 8-word (256-bit) hash state. Modified in place.
     * @param block  64-byte input block.
     */
    static void processBlock(uint32_t state[8], const uint8_t block[64]);
};


// ─── Implementation ───────────────────────────────────────────────────────────

inline void Sha256::processBlock(uint32_t state[8], const uint8_t block[64]) {

    // ── Phase 1: Build the message schedule W[0..63] ─────────────────────────
    uint32_t W[64];

    // W[0..15]: read 16 big-endian 32-bit words from the block.
    // "Big-endian" means most-significant byte comes first in memory.
    // We reconstruct each word from 4 bytes manually (portable — no htonl):
    for (int i = 0; i < 16; ++i) {
        W[i] = (uint32_t(block[i*4 + 0]) << 24)
             | (uint32_t(block[i*4 + 1]) << 16)
             | (uint32_t(block[i*4 + 2]) <<  8)
             |  uint32_t(block[i*4 + 3]);
    }

    // W[16..63]: expanded using the σ recurrence.
    // This ensures that every input byte influences rounds far beyond
    // where it first appears in the schedule.
    for (int i = 16; i < 64; ++i) {
        W[i] = sigma1(W[i-2]) + W[i-7] + sigma0(W[i-15]) + W[i-16];
    }

    // ── Phase 2: Initialize working variables from current state ─────────────
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

    // ── Phase 2: 64 rounds of bit mixing ─────────────────────────────────────
    for (int t = 0; t < 64; ++t) {
        //  T1 mixes: current "bottom" word h, non-linear e-path (Σ1, Ch),
        //            the round constant K[t], and the scheduled word W[t].
        uint32_t T1 = h + Sigma1(e) + Ch(e, f, g) + SHA256_K[t] + W[t];

        //  T2 mixes: non-linear a-path (Σ0, Maj).
        uint32_t T2 = Sigma0(a) + Maj(a, b, c);

        // Rotate all 8 variables down by one position.
        // This is a generalized "shift register" — each round, data flows
        // from h toward a, picking up new mixing at each step.
        h = g;
        g = f;
        f = e;
        e = d + T1;   // d gets the T1 injection (through e)
        d = c;
        c = b;
        b = a;
        a = T1 + T2;  // New 'a' combines both temp values
    }

    // ── Phase 3: Davies–Meyer feed-forward ───────────────────────────────────
    // Add the working variables BACK into the state.
    // This ensures the compression function is one-way: even if you know
    // the output state, you can't invert the 64 rounds to recover the input.
    state[0] += a;  state[1] += b;  state[2] += c;  state[3] += d;
    state[4] += e;  state[5] += f;  state[6] += g;  state[7] += h;
}


inline Sha256::Digest Sha256::hash(const uint8_t* data, size_t len) {

    // Initialize state to H0 (the fixed starting point).
    uint32_t state[8];
    memcpy(state, SHA256_H0, sizeof(state));

    // ── Process all complete 64-byte blocks ───────────────────────────────────
    size_t i = 0;
    for (; i + BLOCK_BYTES <= len; i += BLOCK_BYTES) {
        processBlock(state, data + i);
    }

    // ── Padding (Merkle–Damgård strengthening) ────────────────────────────────
    //
    //  After the last complete block, we must pad so the total length
    //  (in bits) is appended and the block aligns to 512 bits.
    //
    //  Padding scheme:
    //    1. Append bit '1'        → byte 0x80 immediately after message
    //    2. Append zero bytes     → until 8 bytes remain in block
    //    3. Append 64-bit length  → original bit length, big-endian
    //
    //  If the remainder is ≥ 56 bytes, there's not enough room for the
    //  length in this block, so we need TWO padding blocks.
    //
    uint8_t padBuf[128];
    memset(padBuf, 0, sizeof(padBuf));

    size_t remainder = len - i;
    memcpy(padBuf, data + i, remainder);   // Copy leftover bytes
    padBuf[remainder] = 0x80;              // Append the mandatory '1' bit

    // Determine if we need 1 or 2 padding blocks
    size_t padBlocks = (remainder < 56) ? 1 : 2;

    // Append original length in BITS as big-endian 64-bit integer
    // at the LAST 8 bytes of the final padding block.
    uint64_t bitLen = static_cast<uint64_t>(len) * 8;
    for (int j = 7; j >= 0; --j) {
        padBuf[padBlocks * 64 - 8 + (7 - j)] = static_cast<uint8_t>(bitLen >> (j * 8));
    }

    // Process padding block(s)
    processBlock(state, padBuf);
    if (padBlocks == 2) {
        processBlock(state, padBuf + 64);
    }

    // ── Serialize state to 32-byte digest (big-endian) ───────────────────────
    Digest digest;
    for (int j = 0; j < 8; ++j) {
        digest[j*4 + 0] = static_cast<uint8_t>(state[j] >> 24);
        digest[j*4 + 1] = static_cast<uint8_t>(state[j] >> 16);
        digest[j*4 + 2] = static_cast<uint8_t>(state[j] >>  8);
        digest[j*4 + 3] = static_cast<uint8_t>(state[j]       );
    }

    return digest;
}
