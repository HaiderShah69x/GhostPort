/**
 * ============================================================
 *  GhostPort - SequenceValidator.cpp
 *  Version: 3.0 (Milestone 3 - Cryptographic SPA)
 * ============================================================
 *
 *  IMPLEMENTATION NOTES:
 *
 *  std::chrono::steady_clock vs std::chrono::system_clock:
 *    We deliberately use steady_clock (monotonic clock) instead of
 *    system_clock (wall-clock time). The key difference:
 *
 *      - system_clock CAN jump backward if the user sets the system
 *        time, or if NTP slews the clock. This would break our
 *        30-second timeout (a backward jump looks like no time passed).
 *
 *      - steady_clock NEVER goes backward. It only ever moves forward
 *        at a constant rate. Perfect for measuring durations.
 *
 *    In security code, we always prefer monotonic clocks for intervals.
 *
 *  Map Insertion Pattern (operator[]):
 *    When we do m_clientStates[ip], if "ip" is NOT in the map,
 *    std::map default-constructs a ClientState{} and inserts it.
 *    This is intentional — we rely on ClientState() setting step=0.
 *
 *  Iterator Invalidation During Purge:
 *    std::map::erase(iterator) returns the iterator to the NEXT
 *    element. This lets us safely erase during a forward iteration
 *    without invalidating the loop — unlike vector erase().
 * ============================================================
 */

#include "SequenceValidator.h"
#include "HmacVerifier.h"      // Full definition needed for m_spaVerifier->verify()

#include <iostream>
#include <iomanip>
#include <sstream>
#include <chrono>


// ─── Helper: Result to String ─────────────────────────────────────────────────

std::string validationResultToString(ValidationResult result) {
    switch (result) {
        case ValidationResult::FIRST_KNOCK:        return "FIRST_KNOCK (window opened)";
        case ValidationResult::STEP_ACCEPTED:      return "STEP_ACCEPTED (sequence advancing)";
        case ValidationResult::SEQUENCE_COMPLETE:  return "SEQUENCE_COMPLETE ✓ (ACCESS GRANTED)";
        case ValidationResult::WRONG_PORT:         return "WRONG_PORT (sequence reset)";
        case ValidationResult::TIMEOUT_RESET:      return "TIMEOUT_RESET (window expired, reset)";
        case ValidationResult::SPA_REJECTED:       return "SPA_REJECTED (crypto check failed — knock silently ignored)";
        default:                                   return "UNKNOWN";
    }
}


// ─── Constructor ──────────────────────────────────────────────────────────────

SequenceValidator::SequenceValidator(
    std::vector<uint16_t> sequence,
    int                   timeoutSec
)
    : m_sequence(std::move(sequence))
    , m_timeoutSeconds(timeoutSec)
{
    std::cout << "[SequenceValidator] Initialized.\n";
    std::cout << "[SequenceValidator] Knock sequence: ";
    for (size_t i = 0; i < m_sequence.size(); ++i) {
        std::cout << m_sequence[i];
        if (i + 1 < m_sequence.size()) std::cout << " → ";
    }
    std::cout << "\n";
    std::cout << "[SequenceValidator] Time window   : "
              << m_timeoutSeconds << " seconds\n\n";
}


// ─── Public API ───────────────────────────────────────────────────────────────

void SequenceValidator::setAccessGrantedHandler(
    std::function<void(const std::string&)> handler
) {
    m_accessGrantedHandler = std::move(handler);
}

void SequenceValidator::setSpaVerifier(HmacVerifier* verifier) {
    m_spaVerifier = verifier;
    if (verifier) {
        std::cout << "[SequenceValidator] SPA gate ENABLED.\n";
    } else {
        std::cout << "[SequenceValidator] SPA gate DISABLED (test mode).\n";
    }
}

const std::vector<uint16_t>& SequenceValidator::getSequence() const {
    return m_sequence;
}

int SequenceValidator::getTimeoutSeconds() const {
    return m_timeoutSeconds;
}

size_t SequenceValidator::trackedClientCount() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_clientStates.size();
}

void SequenceValidator::resetClient(const std::string& ip) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_clientStates.find(ip);
    if (it != m_clientStates.end()) {
        resetState(it->second);
    }
}


// ─── Core: Process Knock ──────────────────────────────────────────────────────

/**
 * This is the heart of the port-knocking state machine.
 *
 * STATE MACHINE DIAGRAM per client IP:
 *
 *   step=0 → receives port 7000 → step=1, start timer  [FIRST_KNOCK]
 *   step=1 → receives port 8000 → step=2               [STEP_ACCEPTED]
 *   step=2 → receives port 9000 → step=3 (complete!)   [SEQUENCE_COMPLETE]
 *
 *   At any step:
 *     if expired          → step=0, restart             [TIMEOUT_RESET]
 *     if wrong port       → step=0, no restart          [WRONG_PORT]
 *
 * IMPORTANT EDGE CASE — "wrong port at step 0":
 *   If a packet arrives on a port that is NOT the first knock port,
 *   we do NOT even insert a ClientState. This prevents attackers from
 *   filling our map by sending to random ports. Only a correct first
 *   knock creates a tracking entry.
 */
ValidationResult SequenceValidator::processKnock(const KnockEvent& event) {
    const std::string& ip       = event.sourceIP;
    const uint16_t     knocked  = event.destPort;

    // ── [NEW M3] SPA Cryptographic Gate ──────────────────────────────────────
    //
    //   BEFORE touching any sequence state, verify the SPA packet.
    //   On failure: return SPA_REJECTED WITHOUT resetting the client's
    //   sequence progress. This is critical — if we reset on bad crypto,
    //   an attacker could send garbage packets to knock other clients back
    //   to step 0 (a "denial-of-knock" attack).
    //
    //   An unauthenticated packet is treated as if it never arrived.
    //
    if (m_spaVerifier) {
        SpaResult spaResult = m_spaVerifier->verify(event);
        if (spaResult != SpaResult::VALID) {
            // Log at debug level only — don't make noise for random scanners
            std::cout << "[SequenceValidator] SPA gate rejected knock from "
                      << ip << ": " << spaResultToString(spaResult) << "\n";
            return ValidationResult::SPA_REJECTED;
        }
    }

    std::unique_lock<std::mutex> lock(m_mutex);

    // ── Guard: empty sequence (misconfiguration) ──────────────────────────────
    if (m_sequence.empty()) {
        std::cerr << "[SequenceValidator] ERROR: Knock sequence is empty!\n";
        return ValidationResult::WRONG_PORT;
    }

    // ── Step 1: Check if this is a "first knock" candidate ───────────────────
    //
    //   OPTIMIZATION: Before touching the map at all, check if the knocked
    //   port is the FIRST port in our sequence. If the client has no existing
    //   state AND this isn't the first port, we can discard immediately
    //   without inserting any entry. This keeps the map lean.
    //
    auto it = m_clientStates.find(ip);
    bool clientExists = (it != m_clientStates.end());

    if (!clientExists && knocked != m_sequence[0]) {
        // Random packet on a non-first-knock port — ignore completely
        // (Don't log to avoid noise from innocent scanners)
        return ValidationResult::WRONG_PORT;
    }

    // ── Step 2: Get-or-create the ClientState ─────────────────────────────────
    //
    //   operator[] default-constructs ClientState{step=0} if IP is new.
    //   After this line, 'state' is always a valid reference.
    //
    ClientState& state = m_clientStates[ip];

    // ── Step 3: Timeout Check ─────────────────────────────────────────────────
    //
    //   Only check timeout if the client has STARTED a sequence (step > 0).
    //   A client at step=0 has no active window to expire.
    //
    if (state.step > 0 && isExpired(state)) {
        std::cout << "[SequenceValidator] ⏰ TIMEOUT for " << ip
                  << " — sequence reset (was at step " << state.step << ").\n";

        resetState(state);

        // After reset, re-check: is this knock the correct first port?
        // (The client may have timed out and is now re-knocking correctly)
        if (knocked == m_sequence[0]) {
            // Fall through to the FIRST_KNOCK handling below
        } else {
            return ValidationResult::TIMEOUT_RESET;
        }
    }

    // ── Step 4: Validate the knocked port ────────────────────────────────────
    //
    //   state.step is the INDEX of the NEXT expected port.
    //   Example: if step=0, we expect m_sequence[0] (e.g. 7000).
    //
    uint16_t expectedPort = m_sequence[static_cast<size_t>(state.step)];

    if (knocked != expectedPort) {
        // ── WRONG PORT ───────────────────────────────────────────────────────
        std::cout << "[SequenceValidator] ✗ WRONG PORT from " << ip
                  << " — expected " << expectedPort
                  << ", got " << knocked
                  << ". Sequence reset.\n";
        resetState(state);
        return ValidationResult::WRONG_PORT;
    }

    // ── Step 5: Correct port — advance the sequence ───────────────────────────

    if (state.step == 0) {
        // ── FIRST KNOCK — start the 30-second window ─────────────────────────
        state.windowStart = std::chrono::steady_clock::now();
        state.step = 1;

        // Calculate when window expires (for display)
        std::cout << "[SequenceValidator] 🔑 FIRST KNOCK from " << ip
                  << " on port " << knocked
                  << ". Window open (" << m_timeoutSeconds << "s).\n";
        std::cout << "[SequenceValidator]    Progress: [1/"
                  << m_sequence.size() << "] "
                  << knocked << " ✓\n";

        return ValidationResult::FIRST_KNOCK;
    }

    // ── Intermediate or final knock ───────────────────────────────────────────
    state.step++;

    if (static_cast<size_t>(state.step) >= m_sequence.size()) {
        // ── SEQUENCE COMPLETE — ACCESS GRANTED ────────────────────────────────
        std::cout << "[SequenceValidator] ✅ SEQUENCE COMPLETE for " << ip
                  << "! All " << m_sequence.size()
                  << " ports knocked correctly.\n";

        // Calculate elapsed time for the log
        auto elapsed = std::chrono::steady_clock::now() - state.windowStart;
        double elapsedSec = std::chrono::duration<double>(elapsed).count();
        std::cout << "[SequenceValidator]    Elapsed: "
                  << std::fixed << std::setprecision(2)
                  << elapsedSec << "s / " << m_timeoutSeconds << "s window.\n";

        // Clean up — client is done, remove from map
        m_clientStates.erase(ip);

        // Fire the access-granted callback (Milestone 4: triggers firewall rule)
        auto handler = m_accessGrantedHandler;
        lock.unlock();

        if (handler) {
            handler(ip);
        }

        return ValidationResult::SEQUENCE_COMPLETE;

    } else {
        // ── INTERMEDIATE STEP ACCEPTED ────────────────────────────────────────
        std::cout << "[SequenceValidator] ✓ STEP " << state.step
                  << "/" << m_sequence.size()
                  << " accepted from " << ip
                  << " (port " << knocked << ").\n";

        // Show remaining time
        auto elapsed = std::chrono::steady_clock::now() - state.windowStart;
        double remaining = m_timeoutSeconds
            - std::chrono::duration<double>(elapsed).count();
        std::cout << "[SequenceValidator]    Time remaining: "
                  << std::fixed << std::setprecision(1)
                  << remaining << "s\n";

        return ValidationResult::STEP_ACCEPTED;
    }
}


// ─── Purge Expired Clients ────────────────────────────────────────────────────

/**
 * WHY THIS IS NEEDED:
 *   Consider a hostile scanner that sends millions of first-knock packets
 *   from spoofed IPs. Without purging, our map would grow unboundedly.
 *   By periodically calling this, we cap memory usage.
 *
 * SAFE ITERATION PATTERN:
 *   We use the erase-and-advance idiom:
 *     it = m_clientStates.erase(it);  // erase returns next valid iterator
 *   This is the correct way to erase from a std::map during iteration.
 *   DO NOT do: m_clientStates.erase(it); ++it; — undefined behavior!
 */
int SequenceValidator::purgeExpiredClients() {
    std::lock_guard<std::mutex> lock(m_mutex);
    int purged = 0;
    auto it = m_clientStates.begin();

    while (it != m_clientStates.end()) {
        // Only purge clients with an active (started) sequence
        if (it->second.step > 0 && isExpired(it->second)) {
            std::cout << "[SequenceValidator] 🧹 Purging expired entry for "
                      << it->first << "\n";
            it = m_clientStates.erase(it);   // Erase and advance
            ++purged;
        } else {
            ++it;
        }
    }

    return purged;
}


// ─── Private Helpers ──────────────────────────────────────────────────────────

bool SequenceValidator::isExpired(const ClientState& state) const {
    auto now     = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                       now - state.windowStart
                   ).count();
    return elapsed > m_timeoutSeconds;
}

void SequenceValidator::resetState(ClientState& state) const {
    state.step = 0;
    // windowStart is left as-is — it's irrelevant when step == 0
    // and will be overwritten on the next valid first knock.
}
