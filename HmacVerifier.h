/**
 * ============================================================
 *  GhostPort - HmacVerifier.h
 *  Version: 3.0 (Milestone 3 - Cryptographic SPA)
 * ============================================================
 *
 *  PURPOSE:
 *    Declares the HmacVerifier class, which is the cryptographic
 *    gatekeeper of GhostPort. For every incoming knock, it:
 *
 *      1. Parses the SPA packet from the raw UDP payload
 *      2. Checks the timestamp freshness (replay-window defence)
 *      3. Looks up the (IP, timestamp) in the anti-replay cache
 *      4. Computes the expected HMAC-SHA256 using the PSK
 *      5. Does a CONSTANT-TIME comparison with the received HMAC
 *
 *  THE HMAC-SHA256 CONSTRUCTION:
 *
 *    HMAC(K, M) = H( (K' ⊕ opad) ‖ H( (K' ⊕ ipad) ‖ M ) )
 *
 *    Where:
 *      H     = SHA-256 (from Sha256.h)
 *      K     = Pre-Shared Key (32 bytes for GhostPort)
 *      K'    = K zero-padded to 64 bytes (SHA-256 block size)
 *      ipad  = 0x36 repeated 64 times  (inner padding)
 *      opad  = 0x5C repeated 64 times  (outer padding)
 *      M     = The signed message (magic + timestamp + destPort)
 *      ‖     = concatenation
 *
 *    WHY HMAC and not just SHA256(key + message)?
 *      A naive "prefix-MAC" SHA256(key ‖ message) is vulnerable to
 *      LENGTH EXTENSION ATTACKS: given SHA256(key ‖ M), an attacker
 *      can compute SHA256(key ‖ M ‖ padding ‖ M') without knowing the
 *      key. HMAC's double-hash structure defeats this completely.
 *
 *  PSK — PRE-SHARED KEY:
 *    A 32-byte secret shared between the GhostPort server and the
 *    authorized client. Never transmitted on the wire — only used
 *    to produce/verify HMAC tags. If an attacker doesn't have the PSK,
 *    they cannot forge a valid SPA packet.
 *
 *    PSK LAYOUT (in main.cpp):
 *      static const HmacVerifier::Psk PSK = {
 *          0xDE, 0xAD, ...   // 32 bytes of secret
 *      };
 *    In Milestone 6, this loads from /etc/ghostport/secret.key
 *
 *  ANTI-REPLAY PROTECTION:
 *    Even with a valid HMAC, an attacker could record a legitimate SPA
 *    packet and re-send it later. The two-layer defence:
 *
 *    LAYER 1 — Timestamp Window:
 *      The packet's timestamp must be within ±REPLAY_WINDOW_SECONDS of
 *      the server's current time. A packet older than 30 seconds is
 *      rejected. This limits the replay window to a wall-clock interval.
 *
 *    LAYER 2 — Seen-Token Cache:
 *      We record every (sourceIP, timestamp) pair we've accepted.
 *      If the same pair arrives again within the window, it's a replay.
 *      The cache is keyed by a string "IP:timestamp_hex".
 *      Entries are evicted when they become older than the window.
 *
 *  TIMING-SAFE COMPARISON:
 *    We use constantTimeEqual() instead of memcmp() for HMAC comparison.
 *    memcmp() short-circuits on the first differing byte, leaking timing
 *    information that an attacker could use to brute-force the HMAC
 *    byte-by-byte (a "timing oracle" attack).
 *    constantTimeEqual() ALWAYS takes O(n) time regardless of content.
 *
 *  AUTHOR:  Syed Haider Ali (FYP - GhostPort)
 * ============================================================
 */

#pragma once

#include "PacketListener.h"  // KnockEvent
#include "SpaPacket.h"       // ParsedSpaPacket, SPA_PACKET_SIZE
#include "Sha256.h"          // Sha256::Digest, Sha256::hash()

#include <array>
#include <map>
#include <string>
#include <cstdint>
#include <chrono>
#include <vector>


// ─── SPA Verification Result ──────────────────────────────────────────────────

/**
 * @enum SpaResult
 * @brief Detailed outcome of an SPA verification attempt.
 *
 * Returned by HmacVerifier::verify() so the caller knows exactly WHY
 * a packet was accepted or rejected (useful for logging and debugging).
 */
enum class SpaResult {
    VALID,            ///< Packet is authentic, fresh, and not a replay  ✓
    INVALID_SIZE,     ///< Payload too short to be an SPA packet
    INVALID_MAGIC,    ///< Magic bytes don't match — not a GhostPort SPA packet
    TIMESTAMP_STALE,  ///< Timestamp is outside the ±30s freshness window
    REPLAY_DETECTED,  ///< Valid HMAC but (IP, timestamp) was already seen
    HMAC_MISMATCH,    ///< HMAC does not match — wrong key or forged packet
};

/**
 * @brief Returns a human-readable description of a SpaResult.
 */
std::string spaResultToString(SpaResult result);


// ─── HmacVerifier Class ───────────────────────────────────────────────────────

/**
 * @class HmacVerifier
 * @brief Performs HMAC-SHA256 verification and anti-replay tracking.
 *
 * DESIGN:
 *   HmacVerifier is constructed with the PSK at startup and then
 *   called once per incoming knock via verify(). It is stateful only
 *   for the anti-replay cache (m_seenTokens).
 *
 * DEPENDENCY INJECTION:
 *   SequenceValidator holds an optional pointer to an HmacVerifier.
 *   When set, every processKnock() call goes through SPA verification
 *   first. If verification fails, the sequence state is NOT advanced.
 *   This prevents sequence-guessing attacks (enumeration via timing).
 */
class HmacVerifier {
public:
    /// The PSK is exactly 32 bytes (256 bits) — one SHA-256 block worth of key.
    static constexpr size_t PSK_BYTES = 32;
    using Psk = std::array<uint8_t, PSK_BYTES>;

    /// Replay window: accept timestamps within this many seconds of now.
    /// Must match the client's expectation.
    static constexpr int REPLAY_WINDOW_SECONDS = 30;

    /**
     * @brief Construct with a 32-byte Pre-Shared Key.
     *
     * @param psk            The shared secret.  NEVER log or display this.
     * @param windowSeconds  How many seconds either side of "now" a timestamp
     *                       is considered fresh. Default: 30.
     */
    explicit HmacVerifier(const Psk& psk, int windowSeconds = REPLAY_WINDOW_SECONDS);

    /**
     * @brief Verify a single incoming knock event for SPA authenticity.
     *
     * Full pipeline:
     *   parse → size check → magic check → timestamp freshness →
     *   anti-replay cache → HMAC computation → constant-time compare →
     *   record token → return result
     *
     * @param event  The raw knock event from PacketListener.
     * @return       Detailed SpaResult indicating accept or specific failure.
     */
    SpaResult verify(const KnockEvent& event);

    /**
     * @brief Evict anti-replay cache entries older than the window.
     *
     * Call this periodically to prevent unbounded cache growth.
     * In Milestone 5, this will run on a cleanup timer thread.
     *
     * @return  Number of entries purged.
     */
    int purgeExpiredTokens();

    /**
     * @brief Number of tokens currently in the anti-replay cache.
     */
    size_t cachedTokenCount() const;

    /**
     * @brief Compute an HMAC-SHA256 digest (public for client-side use).
     *
     * Given the PSK and a message, produces the 32-byte tag that the
     * client must embed in its SPA packet.
     *
     * @param message  Pointer to bytes to authenticate.
     * @param msgLen   Length of message.
     * @return         32-byte HMAC-SHA256 tag.
     */
    Sha256::Digest computeHmac(const uint8_t* message, size_t msgLen) const;

private:

    // ── Pre-Shared Key ────────────────────────────────────────────────────────
    Psk  m_psk;
    int  m_windowSeconds;

    // ── Anti-Replay Cache ─────────────────────────────────────────────────────
    //
    //  Key:   "sourceIP:timestamp_hex"  (e.g. "192.168.1.42:67A1B3C4")
    //  Value: steady_clock time point when we first accepted this token
    //
    //  WHY steady_clock here too?
    //    Same reason as SequenceValidator — we measure ELAPSED DURATION,
    //    not wall-clock time. A system clock adjustment won't cause
    //    cache entries to never expire (or to expire too early).
    //
    std::map<std::string, std::chrono::steady_clock::time_point> m_seenTokens;

    // ── Private Helpers ───────────────────────────────────────────────────────

    /**
     * @brief Build the anti-replay cache key for a given IP, port and timestamp.
     * @return e.g. "192.168.1.42:7000:67A1B3C4"
     */
    static std::string makeTokenKey(const std::string& ip, uint16_t port, uint32_t timestamp);

    /**
     * @brief TIMING-SAFE byte comparison.
     *
     * Compares len bytes of a and b in CONSTANT TIME.
     * Unlike memcmp(), this NEVER short-circuits — it always
     * examines all len bytes, regardless of where differences appear.
     *
     * This defeats timing-oracle attacks where an attacker sends
     * millions of guesses and measures response time to learn
     * how many bytes of their guess are correct.
     *
     * Implementation:
     *   XOR each byte pair → 0 means equal, non-zero means different.
     *   OR all XOR results into a single accumulator.
     *   Return (accumulator == 0).
     *
     * @return true if all len bytes are equal.
     */
    static bool constantTimeEqual(const uint8_t* a, const uint8_t* b, size_t len);
};
