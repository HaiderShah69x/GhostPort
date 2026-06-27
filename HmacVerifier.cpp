/**
 * ============================================================
 *  GhostPort - HmacVerifier.cpp
 *  Version: 3.0 (Milestone 3 - Cryptographic SPA)
 * ============================================================
 *
 *  IMPLEMENTATION NOTES:
 *
 *  HMAC-SHA256 Construction (RFC 2104):
 *
 *    The HMAC formula in concrete C++ steps:
 *
 *    Step 1 — Derive K' (key padded to block size):
 *      If len(PSK) <= 64: K' = PSK || 0x00...0x00  (zero-pad to 64 bytes)
 *      If len(PSK)  > 64: K' = SHA256(PSK) || 0x00...0x00  (hash then pad)
 *      (Our PSK is exactly 32 bytes, so we always zero-pad.)
 *
 *    Step 2 — Inner hash:
 *      iKey     = K' XOR [0x36 × 64]
 *      innerMsg = iKey || message             (concatenation)
 *      innerHash = SHA256(innerMsg)
 *
 *    Step 3 — Outer hash (the final HMAC):
 *      oKey     = K' XOR [0x5C × 64]
 *      outerMsg = oKey || innerHash
 *      HMAC     = SHA256(outerMsg)
 *
 *  Why ipad = 0x36 and opad = 0x5C?
 *    These are NOT magic constants — they are the bit patterns 00110110
 *    and 01011100 respectively. The original HMAC paper (Bellare, Canetti,
 *    Krawczyk 1996) chose them because XOR-ing with these values produces
 *    different, non-trivially-related key derivatives for the inner and
 *    outer hash. Any two distinct constants with enough Hamming distance
 *    would work; these are the standardized choice (FIPS 198-1).
 *
 *  Total data hashed:
 *    Inner: 64 (iKey) + 10 (message) = 74 bytes → 2 SHA-256 blocks
 *    Outer: 64 (oKey) + 32 (innerHash) = 96 bytes → 2 SHA-256 blocks
 *    Total: 4 SHA-256 block compressions per HMAC computation.
 * ============================================================
 */

#include "HmacVerifier.h"

#include <iostream>
#include <iomanip>
#include <sstream>
#include <ctime>
#include <cstring>
#include <vector>


// ─── Helper: spaResultToString ────────────────────────────────────────────────

std::string spaResultToString(SpaResult result) {
    switch (result) {
        case SpaResult::VALID:            return "VALID ✓ (authentic, fresh, unique)";
        case SpaResult::INVALID_SIZE:     return "INVALID_SIZE (packet < 42 bytes)";
        case SpaResult::INVALID_MAGIC:    return "INVALID_MAGIC (not a GhostPort SPA packet)";
        case SpaResult::TIMESTAMP_STALE:  return "TIMESTAMP_STALE (outside 30s freshness window)";
        case SpaResult::REPLAY_DETECTED:  return "REPLAY_DETECTED (token already seen — replay attack!)";
        case SpaResult::HMAC_MISMATCH:    return "HMAC_MISMATCH (wrong key or forged packet)";
        default:                          return "UNKNOWN";
    }
}


// ─── Constructor ──────────────────────────────────────────────────────────────

HmacVerifier::HmacVerifier(const Psk& psk, int windowSeconds)
    : m_psk(psk)
    , m_windowSeconds(windowSeconds)
{
    std::cout << "[HmacVerifier] SPA engine initialized.\n";
    std::cout << "[HmacVerifier] PSK fingerprint (first 4 bytes): ";
    for (int i = 0; i < 4; ++i)
        std::cout << std::hex << std::setfill('0') << std::setw(2)
                  << static_cast<unsigned>(m_psk[i]);
    std::cout << std::dec << "...\n";
    std::cout << "[HmacVerifier] Replay window: " << m_windowSeconds << "s\n\n";
}


// ─── Core: HMAC-SHA256 Computation ───────────────────────────────────────────

/**
 * Full HMAC-SHA256 implementation.
 *
 * Visual walkthrough for our 10-byte SPA signed message M:
 *
 *   K' (64 bytes):  [0xDE 0xAD ... 0x11 0x00 0x00 ... 0x00]
 *                   ↑ 32 PSK bytes ↑     ↑ 32 zero bytes  ↑
 *
 *   iKey (64 bytes): K'[0] ^ 0x36, K'[1] ^ 0x36, ...
 *   oKey (64 bytes): K'[0] ^ 0x5C, K'[1] ^ 0x5C, ...
 *
 *   innerMsg = iKey ‖ M          → 74 bytes → 2 SHA-256 blocks
 *   innerHash = SHA256(innerMsg) → 32 bytes
 *
 *   outerMsg = oKey ‖ innerHash  → 96 bytes → 2 SHA-256 blocks
 *   HMAC     = SHA256(outerMsg)  → 32 bytes  ← this is the tag
 */
Sha256::Digest HmacVerifier::computeHmac(const uint8_t* message, size_t msgLen) const {
    constexpr size_t BLOCK = 64;   // SHA-256 block size

    // ── Step 1: Derive K' ─────────────────────────────────────────────────────
    //   Our PSK is 32 bytes ≤ 64, so we just zero-pad.
    uint8_t k_prime[BLOCK];
    memset(k_prime, 0, BLOCK);
    memcpy(k_prime, m_psk.data(), m_psk.size());   // copy 32 bytes, rest is 0

    // ── Step 2: Build inner padded key ────────────────────────────────────────
    uint8_t iKey[BLOCK];
    for (size_t i = 0; i < BLOCK; ++i) iKey[i] = k_prime[i] ^ 0x36u;

    // Build inner message: iKey(64) + message(msgLen)
    // Using insert() instead of resize+memcpy to avoid GCC -Wstringop-overflow
    // false positive on the size_t parameter (semantically identical).
    std::vector<uint8_t> innerMsg;
    innerMsg.reserve(BLOCK + msgLen);
    innerMsg.insert(innerMsg.end(), iKey, iKey + BLOCK);
    innerMsg.insert(innerMsg.end(), message, message + msgLen);
    Sha256::Digest innerHash = Sha256::hash(innerMsg.data(), innerMsg.size());

    // ── Step 4: Build outer padded key ────────────────────────────────────────
    uint8_t oKey[BLOCK];
    for (size_t i = 0; i < BLOCK; ++i) oKey[i] = k_prime[i] ^ 0x5Cu;

    // ── Step 5: Outer hash = SHA256(oKey ‖ innerHash) ─────────────────────────
    uint8_t outerMsg[BLOCK + 32];
    memcpy(outerMsg,         oKey,            BLOCK);   // first 64 bytes: outer key
    memcpy(outerMsg + BLOCK, innerHash.data(), 32);     // then inner hash (32 bytes)
    return Sha256::hash(outerMsg, BLOCK + 32);
}


// ─── Core: Constant-Time Comparison ──────────────────────────────────────────

/**
 * TIMING ATTACK BACKGROUND:
 *
 *   If we used: return memcmp(a, b, len) == 0;
 *
 *   An attacker who can measure response latency precisely enough
 *   could send many forged packets and notice that packets with the
 *   correct first byte take SLIGHTLY longer (because memcmp checks
 *   one more byte before returning). Over millions of attempts,
 *   this leaks the HMAC byte-by-byte in O(256 * 32) = 8192 queries.
 *
 *   The fix: XOR each byte pair (equal → 0, different → nonzero),
 *   OR all results into `diff`. Return diff == 0.
 *   The loop NEVER exits early — always touches all 32 bytes.
 *   Execution time is identical whether 0 or 31 bytes match.
 */
bool HmacVerifier::constantTimeEqual(const uint8_t* a, const uint8_t* b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; ++i) {
        diff |= (a[i] ^ b[i]);   // |= never reduces — a set bit stays set
    }
    return (diff == 0);
}


// ─── Core: Anti-Replay Cache Key ─────────────────────────────────────────────

std::string HmacVerifier::makeTokenKey(const std::string& ip, uint16_t port, uint32_t timestamp) {
    std::ostringstream oss;
    oss << ip << ":" << port << ":"
        << std::hex << std::uppercase << std::setfill('0') << std::setw(8)
        << timestamp;
    return oss.str();   // e.g. "192.168.1.42:7000:67A1B3C4"
}


// ─── Core: Verify ─────────────────────────────────────────────────────────────

/**
 * THE FULL SPA VERIFICATION PIPELINE:
 *
 *   RAW PAYLOAD
 *       │
 *       ▼
 *   [1] Size check      → INVALID_SIZE if < 42 bytes
 *       │
 *       ▼
 *   [2] Magic check     → INVALID_MAGIC if bytes[0..3] ≠ "GPSA"
 *       │
 *       ▼
 *   [3] Timestamp check → TIMESTAMP_STALE if |now - ts| > window
 *       │              (cheap check BEFORE expensive crypto)
 *       ▼
 *   [4] Replay check    → REPLAY_DETECTED if (IP, ts) seen before
 *       │
 *       ▼
 *   [5] HMAC compute    → compute HMAC-SHA256(PSK, bytes[0..9])
 *       │
 *       ▼
 *   [6] Constant-time   → HMAC_MISMATCH if computed ≠ received
 *       compare
 *       │
 *       ▼
 *   [7] Record token    → insert (IP, ts) into replay cache
 *       │
 *       ▼
 *       VALID ✓
 *
 * NOTE — Order of checks matters for security:
 *   We do timestamp check BEFORE HMAC to avoid expensive crypto
 *   on obviously stale packets (DoS mitigation).
 *   We do replay check BEFORE HMAC for the same reason.
 *   The HMAC check is always last — it's the most expensive step.
 */
SpaResult HmacVerifier::verify(const KnockEvent& event) {
    // ── Step 1 & 2: Parse and structural-validate the packet ─────────────────
    ParsedSpaPacket pkt = parseSpaPacket(event.payload.c_str(), event.payloadSize);

    if (!pkt.valid) {
        // parseSpaPacket returns valid=false for size or magic failures
        if (event.payloadSize < SPA_PACKET_SIZE) {
            return SpaResult::INVALID_SIZE;
        }
        return SpaResult::INVALID_MAGIC;
    }

    // ── Step 3: Timestamp freshness check ────────────────────────────────────
    //
    //   We compare the packet's timestamp against the SERVER'S current time.
    //   Both sides must have clocks within ~30s of each other (NTP recommended).
    //
    //   WHY uint32 + time_t and not steady_clock?
    //   The SPA timestamp is a Unix epoch uint32 from the CLIENT, so we must
    //   compare it against the server's wall-clock (system_clock), not a
    //   monotonic counter. We use steady_clock only for internal durations.
    //
    std::time_t nowEpoch   = std::time(nullptr);
    int64_t     tsDiff     = static_cast<int64_t>(nowEpoch)
                           - static_cast<int64_t>(pkt.timestamp);

    // Accept if |diff| <= window. Use abs for both future and past skew.
    if (tsDiff < 0) tsDiff = -tsDiff;
    if (tsDiff > static_cast<int64_t>(m_windowSeconds)) {
        std::cout << "[HmacVerifier] ⏰ TIMESTAMP_STALE from " << event.sourceIP
                  << " — skew: " << tsDiff << "s (max: " << m_windowSeconds << "s)\n";
        return SpaResult::TIMESTAMP_STALE;
    }

    // ── Step 4: Anti-replay cache check ──────────────────────────────────────
    std::string tokenKey = makeTokenKey(event.sourceIP, event.destPort, pkt.timestamp);
    if (m_seenTokens.count(tokenKey)) {
        std::cout << "[HmacVerifier] 🔁 REPLAY_DETECTED from " << event.sourceIP
                  << " (token " << tokenKey << " already used)\n";
        return SpaResult::REPLAY_DETECTED;
    }

    // ── Step 5: Compute expected HMAC ─────────────────────────────────────────
    //
    //   The signed region is bytes[0..9]: magic(4) + timestamp(4) + destPort(2)
    //   This binds the token to a specific port AND a specific time.
    //   A knock on port 7000 cannot be replayed on port 8000.
    //
    Sha256::Digest expectedHmac = computeHmac(pkt.signed_bytes, SPA_SIGNED_SIZE);

    // ── Step 6: Constant-time HMAC comparison ─────────────────────────────────
    if (!constantTimeEqual(expectedHmac.data(), pkt.hmac.data(), 32)) {
        std::cout << "[HmacVerifier] ✗ HMAC_MISMATCH from " << event.sourceIP
                  << " — forged or wrong PSK.\n";
        std::cout << "[HmacVerifier]   Expected : " << Sha256::toHexString(expectedHmac) << "\n";
        std::cout << "[HmacVerifier]   Received : " << hmacToHex(pkt.hmac) << "\n";
        return SpaResult::HMAC_MISMATCH;
    }

    // ── Step 7: Record token in anti-replay cache ─────────────────────────────
    m_seenTokens[tokenKey] = std::chrono::steady_clock::now();

    std::cout << "[HmacVerifier] ✅ SPA VALID from " << event.sourceIP
              << " — port " << event.destPort
              << ", ts=" << pkt.timestamp
              << ", skew=" << tsDiff << "s\n";

    return SpaResult::VALID;
}


// ─── Purge Expired Tokens ─────────────────────────────────────────────────────

int HmacVerifier::purgeExpiredTokens() {
    int purged = 0;
    auto now = std::chrono::steady_clock::now();
    auto it  = m_seenTokens.begin();

    while (it != m_seenTokens.end()) {
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                           now - it->second
                       ).count();
        if (elapsed > m_windowSeconds) {
            it = m_seenTokens.erase(it);
            ++purged;
        } else {
            ++it;
        }
    }

    return purged;
}

size_t HmacVerifier::cachedTokenCount() const {
    return m_seenTokens.size();
}
