/**
 * ============================================================
 *  GhostPort - SequenceValidator.h
 *  Version: 3.0 (Milestone 3 - Cryptographic SPA)
 * ============================================================
 *
 *  PURPOSE:
 *    Defines the SequenceValidator class, which is the "brain"
 *    of the port-knocking system. After PacketListener captures
 *    a raw UDP packet, this class decides:
 *
 *      1. [NEW M3] Is the SPA packet cryptographically valid? (HMAC-SHA256)
 *      2. Is this knock in the correct ORDER?
 *      3. Is the TIMING still valid? (within 30-second window)
 *      4. Has the FULL sequence been completed?
 *
 *  CORE DATA STRUCTURE — std::map<std::string, ClientState>:
 *
 *    Port knocking must track multiple clients simultaneously.
 *    Each client progresses through the knock sequence at their
 *    own pace. We use a std::map keyed by the client's source IP
 *    address. This gives us:
 *
 *      - O(log n) lookup by IP string (fast even for many clients)
 *      - Automatic sorted ordering (useful for log inspection)
 *      - Per-client isolation (one client's progress never
 *        affects another's)
 *
 *    CLIENT STATE MACHINE per IP:
 *
 *      IDLE ──► [knock port[0]] ──► STEP_1
 *           ──► [knock port[1]] ──► STEP_2    (must be within window)
 *           ──► [knock port[2]] ──► VALIDATED ✓
 *                               OR  EXPIRED / WRONG PORT → RESET
 *
 *  30-SECOND TIME WINDOW:
 *    After the FIRST valid knock, a timer starts. All subsequent
 *    knocks in the sequence MUST arrive within 30 seconds, or
 *    the sequence resets. This prevents replay attacks where an
 *    attacker captures one knock and waits indefinitely.
 *
 *  AUTHOR:  Syed Haider Ali (FYP - GhostPort)
 * ============================================================
 */

#pragma once

#include "PacketListener.h"   // For KnockEvent struct
// Forward declaration — avoids circular includes
class HmacVerifier;

#include <string>
#include <vector>
#include <map>
#include <chrono>
#include <functional>
#include <cstdint>
#include <mutex>


// ─── Knock Sequence Definition ────────────────────────────────────────────────

/**
 * @brief The required knock sequence for GhostPort v2.
 *
 * A client must send UDP packets to these ports IN ORDER
 * and WITHIN the time window to be granted access.
 *
 * These are chosen as non-standard, high ports unlikely to
 * conflict with real services. In Milestone 6 (Config), these
 * will be loaded from a config file.
 *
 * Default sequence:  7000  →  8000  →  9000
 */
static const std::vector<uint16_t> KNOCK_SEQUENCE = { 7000, 8000, 9000 };

/**
 * @brief Time window (seconds) within which the full knock
 *        sequence must be completed after the first knock.
 *
 * SECURITY NOTE:
 *   30 seconds is generous for a human or script, but short
 *   enough to defeat slow replay or timing-based attacks.
 *   In SPA (Milestone 3), this window will be tightened further
 *   using a cryptographic timestamp in the packet itself.
 */
static const int KNOCK_TIMEOUT_SECONDS = 30;


// ─── Per-Client State ─────────────────────────────────────────────────────────

/**
 * @struct ClientState
 * @brief  Tracks one client's progress through the knock sequence.
 *
 * One of these lives in our std::map for every IP address that
 * has sent at least one valid first knock.
 *
 * FIELDS:
 *   step         - Index into KNOCK_SEQUENCE of the NEXT expected knock.
 *                  0 = no knocks received yet (or reset).
 *                  3 = full sequence complete (for a 3-port sequence).
 *
 *   windowStart  - Timestamp of the FIRST valid knock in this sequence.
 *                  Used to enforce the 30-second window.
 *                  Meaningless when step == 0.
 */
struct ClientState {
    int  step;
    std::chrono::steady_clock::time_point windowStart;

    // Default: no progress yet
    ClientState() : step(0) {}
};


// ─── Validation Result ────────────────────────────────────────────────────────

/**
 * @enum ValidationResult
 * @brief The outcome of processing a single knock event.
 *
 * Used both internally and by callers (main.cpp) to decide
 * what action to take (log, grant access, ignore, etc.)
 */
enum class ValidationResult {
    STEP_ACCEPTED,     ///< Valid knock, sequence advanced (but not complete)
    SEQUENCE_COMPLETE, ///< All ports knocked correctly — grant access!
    WRONG_PORT,        ///< Knock arrived on wrong port — sequence reset
    TIMEOUT_RESET,     ///< 30-second window expired — sequence reset
    FIRST_KNOCK,       ///< First port in sequence received — window started
    SPA_REJECTED,      ///< [NEW M3] SPA crypto check failed — knock ignored
};

/**
 * @brief Returns a human-readable string for a ValidationResult.
 * @param result  The result to describe.
 * @return        Descriptive string for logging.
 */
std::string validationResultToString(ValidationResult result);


// ─── SequenceValidator Class ──────────────────────────────────────────────────

/**
 * @class SequenceValidator
 * @brief Validates multi-port knock sequences with a time window.
 *
 * USAGE PATTERN:
 *   1. Construct once at daemon startup.
 *   2. Call processKnock(event) inside the PacketListener callback
 *      for every incoming knock.
 *   3. Register a success callback via setAccessGrantedHandler() —
 *      this is fired when a client completes the full sequence.
 *
 * THREAD SAFETY NOTE:
 *   In Milestone 5 (multi-listener), access to m_clientStates
 *   will need a mutex. For now (single listener thread), it's safe.
 */
class SequenceValidator {
public:
    /**
     * @brief Construct with a specific knock sequence and timeout.
     *
     * @param sequence  Ordered list of ports to knock (default: KNOCK_SEQUENCE).
     * @param timeoutSeconds  Time window in seconds (default: KNOCK_TIMEOUT_SECONDS).
     */
    explicit SequenceValidator(
        std::vector<uint16_t> sequence     = KNOCK_SEQUENCE,
        int                   timeoutSec   = KNOCK_TIMEOUT_SECONDS
    );

    /**
     * @brief Register a callback to invoke when access is granted.
     *
     * The callback receives the IP address of the authenticated client.
     * In Milestone 4 (Firewall), this will trigger an iptables rule.
     *
     * @param handler  Callable accepting a const std::string& (IP address).
     */
    void setAccessGrantedHandler(std::function<void(const std::string&)> handler);

    /**
     * @brief [NEW M3] Attach an HmacVerifier for SPA gate enforcement.
     *
     * When set, every processKnock() call passes through SPA verification
     * BEFORE any sequence state is touched. A failed SPA check returns
     * SPA_REJECTED without advancing or resetting the client's state.
     * This prevents unauthenticated probing of the sequence state machine.
     *
     * @param verifier  Non-owning pointer to an HmacVerifier instance.
     *                  The SequenceValidator does NOT free this pointer.
     *                  Pass nullptr to disable SPA (testing only).
     */
    void setSpaVerifier(HmacVerifier* verifier);

    /**
     * @brief Process one incoming knock event.
     *
     * This is the core method. It:
     *   1. Looks up (or creates) the ClientState for event.sourceIP
     *   2. Checks for timeout expiry
     *   3. Validates the knocked port against the expected next port
     *   4. Advances or resets the sequence accordingly
     *   5. Fires the access-granted callback on completion
     *
     * @param event  The knock event from PacketListener.
     * @return       A ValidationResult describing what happened.
     */
    ValidationResult processKnock(const KnockEvent& event);

    /**
     * @brief Manually reset the sequence state for a specific IP.
     *
     * Useful for testing, or if we want to force a client to restart.
     *
     * @param ip  IP address string (e.g. "192.168.1.42").
     */
    void resetClient(const std::string& ip);

    /**
     * @brief Purge ALL expired client states from the tracking map.
     *
     * Should be called periodically to prevent unbounded map growth.
     * In Milestone 5, this will run on a dedicated cleanup timer thread.
     *
     * @return  Number of entries purged.
     */
    int purgeExpiredClients();

    /**
     * @brief Returns the number of IPs currently tracked in the map.
     * @return  Client count (includes partial-progress and stale entries).
     */
    size_t trackedClientCount() const;

    /**
     * @brief Get the configured knock sequence.
     * @return  Reference to the port sequence vector.
     */
    const std::vector<uint16_t>& getSequence() const;

    /**
     * @brief Get the configured timeout in seconds.
     * @return  Timeout value.
     */
    int getTimeoutSeconds() const;

private:
    // ── Configuration (set once at construction) ──────────────────────────────
    std::vector<uint16_t> m_sequence;       ///< The ordered port knock sequence
    int                   m_timeoutSeconds; ///< Maximum seconds for a sequence

    // ── Tracking Engine ───────────────────────────────────────────────────────
    /**
     * THE KEY DATA STRUCTURE:
     *
     *   std::map<std::string, ClientState>
     *     Key   → Source IP address ("192.168.1.42")
     *     Value → ClientState tracking step progress + window start time
     *
     * WHY std::map (not std::unordered_map)?
     *   - std::map is sorted by key, making log output deterministic
     *   - The overhead of tree vs hash is negligible for <1000 clients
     *   - std::map iterators remain valid after insertions/deletions
     *     (safe during purgeExpiredClients loop with careful iteration)
     *   - In Milestone 5, we may switch to unordered_map for throughput
     */
    std::map<std::string, ClientState> m_clientStates;

    // ── Access-Granted Callback ───────────────────────────────────────────────
    std::function<void(const std::string&)> m_accessGrantedHandler;

    // ── [NEW M3] SPA Verifier (optional) ─────────────────────────────────────
    //   Non-owning pointer. When non-null, processKnock() calls
    //   m_spaVerifier->verify(event) before touching any sequence state.
    HmacVerifier* m_spaVerifier = nullptr;

    mutable std::mutex m_mutex;   // Synchronizes multi-listener sequence validations

    // ── Private Helpers ───────────────────────────────────────────────────────

    /**
     * @brief Check if a ClientState's time window has expired.
     *
     * @param state  The client state to check.
     * @return       true if more than m_timeoutSeconds have passed
     *               since state.windowStart.
     */
    bool isExpired(const ClientState& state) const;

    /**
     * @brief Reset a client state back to step 0 (start).
     * @param state  Reference to the ClientState to reset.
     */
    void resetState(ClientState& state) const;
};
