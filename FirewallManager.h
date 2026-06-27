/**
 * ============================================================
 *  GhostPort - FirewallManager.h
 *  Version: 4.0 (Milestone 4 - Windows Firewall Integration)
 * ============================================================
 *
 *  PURPOSE:
 *    Declares the FirewallManager class, which is the "fist"
 *    of GhostPort. Once HmacVerifier authenticates a client and
 *    SequenceValidator confirms the full knock sequence, this class:
 *
 *      1. Executes a  `netsh advfirewall firewall add rule`  command
 *         that punches a timed hole in the Windows Firewall for
 *         the specific authenticated source IP on TCP port 22 (SSH).
 *
 *      2. Launches a background revocation thread that sleeps
 *         until the access window expires, then executes
 *         `netsh advfirewall firewall delete rule` automatically.
 *
 *      3. Maintains a Zero-Trust posture: access is ALWAYS temporary.
 *         No rule survives beyond its expiry. Clean shutdown revokes
 *         all active rules immediately.
 *
 * ──────────────────────────────────────────────────────────
 *  COMMAND ENGINE: Why std::system() ?
 * ──────────────────────────────────────────────────────────
 *
 *  std::system(cmd) forks the process, executes cmd in a shell,
 *  and returns the shell's exit code. It is the simplest portable
 *  way to run an external command.
 *
 *  TRADE-OFFS vs CreateProcess() (for your FYP discussion):
 *
 *    std::system()                  CreateProcess()
 *    ─────────────────────────      ──────────────────────────────
 *    Simple, one call               More complex setup
 *    Goes through cmd.exe shell     Direct process, no shell
 *    Output goes to console         Output can be piped/captured
 *    Cannot capture stdout          Can inspect netsh return text
 *    Shell injection risk*          No injection risk
 *
 *  * The IP address injected into the command comes from
 *    inet_ntop() which ONLY produces valid "a.b.c.d" strings.
 *    There is NO shell injection risk for well-formed IPs.
 *    However, in Milestone 7 (production hardening) we would
 *    switch to CreateProcess() for robustness.
 *
 * ──────────────────────────────────────────────────────────
 *  REVOCATION ENGINE: Priority Queue + Condition Variable
 * ──────────────────────────────────────────────────────────
 *
 *  A background worker thread (`m_worker`) runs `revocationLoop()`.
 *  It blocks on a `std::condition_variable`, waking either when:
 *    a) A new rule is scheduled (notified by `grantAccess()`), or
 *    b) The nearest expiry time is reached (wait_until returns).
 *
 *  The pending revocations are stored in a MIN-HEAP
 *  (`std::priority_queue` with `std::greater<>`) ordered by
 *  expiry time. The soonest-to-expire rule is always at the top,
 *  so the thread only needs to look at one entry to know when to
 *  next wake up — O(log n) insert, O(1) peek.
 *
 *  RULE RE-GRANT HANDLING:
 *    If a client knocks again while their rule is still active
 *    (e.g. they SSH'd in and knocked again to refresh), we:
 *      1. Delete the old rule immediately
 *      2. Add a new rule with a fresh timer
 *      3. Push a new revocation entry to the queue
 *    When the old revocation entry fires, we check if the stored
 *    ruleName still matches the active rule for that IP. If it
 *    doesn't (because a new rule replaced it), we skip silently.
 *
 * ──────────────────────────────────────────────────────────
 *  NETSH COMMAND FORMAT:
 * ──────────────────────────────────────────────────────────
 *
 *  ADD:
 *    netsh advfirewall firewall add rule
 *        name="GhostPort-192-168-1-42-1749650441"
 *        dir=in  action=allow  protocol=TCP
 *        localport=22  remoteip=192.168.1.42
 *        enable=yes
 *        description="GhostPort: auto-expires in 30s"
 *
 *  DELETE:
 *    netsh advfirewall firewall delete rule
 *        name="GhostPort-192-168-1-42-1749650441"
 *
 *  REQUIRES: Administrator privileges (GhostPort runs as Admin
 *  anyway to bind raw UDP sockets).
 *
 *  AUTHOR:  Syed Haider Ali (FYP - GhostPort)
 * ============================================================
 */

#pragma once

#include <string>
#include <map>
#include <queue>
#include <vector>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>


// ─── FirewallManager Class ────────────────────────────────────────────────────

/**
 * @class FirewallManager
 * @brief Manages timed Windows Firewall rules for authenticated GhostPort clients.
 *
 * LIFECYCLE:
 *   1. Constructed at daemon startup — launches the revocation worker thread.
 *   2. grantAccess(ip) called from the access-granted callback.
 *   3. Revocation worker auto-calls revokeAccess() after the window expires.
 *   4. Destructor joins the worker thread and revokes all remaining rules.
 *
 * THREAD SAFETY:
 *   All public methods are thread-safe (protected by m_mutex).
 *   The revocation loop holds m_mutex and releases it during system() calls.
 */
class FirewallManager {
public:
    // ── Configuration Constants ───────────────────────────────────────────────

    /// How long (seconds) an injected firewall rule stays active.
    /// After this window, the rule is auto-deleted (Zero-Trust).
    static constexpr int DEFAULT_ACCESS_WINDOW_SECONDS = 30;

    /// The TCP port that gets unlocked for authenticated clients.
    /// Default: 22 (SSH). In Milestone 6, loaded from config file.
    static constexpr uint16_t DEFAULT_PROTECTED_PORT = 22;

    // ── Constructor / Destructor ──────────────────────────────────────────────

    /**
     * @brief Construct and immediately start the revocation worker thread.
     *
     * @param accessWindowSec  Seconds a rule stays active before auto-revocation.
     * @param protectedPort    TCP port to open for authenticated clients.
     */
    explicit FirewallManager(
        int      accessWindowSec = DEFAULT_ACCESS_WINDOW_SECONDS,
        uint16_t protectedPort   = DEFAULT_PROTECTED_PORT
    );

    /**
     * @brief Destructor.
     * Signals the worker thread to stop, joins it, then revokes ALL
     * remaining active rules (clean Zero-Trust shutdown).
     */
    ~FirewallManager();

    // Non-copyable — owns a std::thread and OS firewall rules
    FirewallManager(const FirewallManager&)            = delete;
    FirewallManager& operator=(const FirewallManager&) = delete;

    // ── Public API ────────────────────────────────────────────────────────────

    /**
     * @brief Inject a timed Windows Firewall rule for an authenticated client.
     *
     * Constructs and executes a `netsh advfirewall firewall add rule` command
     * allowing TCP traffic from clientIP to localport=m_protectedPort.
     * Then schedules automatic revocation after m_windowSeconds.
     *
     * If a rule for this IP already exists, it is replaced with a fresh one
     * (timer reset — client can re-authenticate to extend access).
     *
     * @param clientIP  Source IP of the authenticated client (from KnockEvent).
     * @return          true if netsh succeeded (exit code 0).
     */
    bool grantAccess(const std::string& clientIP);

    /**
     * @brief Immediately revoke a firewall rule by its exact rule name.
     *
     * Executes `netsh advfirewall firewall delete rule name="<ruleName>"`.
     * Called automatically by the revocation worker; also callable manually.
     *
     * @param ruleName  The exact rule name to delete (from makeRuleName()).
     * @return          true if the rule was found and deleted.
     */
    bool revokeAccess(const std::string& ruleName);

    /**
     * @brief Returns the number of currently active firewall rules.
     * Thread-safe.
     */
    size_t activeRuleCount() const;

    /**
     * @brief Returns the configured access window in seconds.
     */
    int accessWindowSeconds() const { return m_windowSeconds; }

    /**
     * @brief Returns the configured protected TCP port.
     */
    uint16_t protectedPort() const { return m_protectedPort; }

private:
    // ── Configuration ─────────────────────────────────────────────────────────
    int      m_windowSeconds;   ///< Access window duration in seconds
    uint16_t m_protectedPort;   ///< TCP port to open for authenticated clients

    // ── Revocation Queue Entry ────────────────────────────────────────────────
    /**
     * @struct RevocationEntry
     * @brief  One scheduled revocation job in the priority queue.
     *
     * Stores the expiry time point (steady_clock — monotonic, never jumps),
     * the client IP (for m_activeRules lookup), and the exact rule name
     * (needed by netsh delete).
     *
     * operator> is required by std::priority_queue with std::greater<>
     * to produce a MIN-HEAP (soonest expiry = highest priority = top).
     */
    struct RevocationEntry {
        std::chrono::steady_clock::time_point expiry;   ///< When to fire
        std::string ip;                                 ///< Client IP
        std::string ruleName;                           ///< Exact netsh rule name

        bool operator>(const RevocationEntry& o) const {
            return expiry > o.expiry;  // GREATER expiry = LOWER priority
        }
    };

    // ── Synchronisation ───────────────────────────────────────────────────────

    mutable std::mutex      m_mutex;   ///< Guards queue, activeRules, and m_running
    std::condition_variable m_cv;      ///< Wakes revocation loop on new entry or stop

    // ── Revocation Priority Queue (MIN-HEAP) ──────────────────────────────────
    //
    //   std::priority_queue<T, Container, Compare> where:
    //     T         = RevocationEntry
    //     Container = std::vector<RevocationEntry>  (the heap storage)
    //     Compare   = std::greater<RevocationEntry> → min-heap by expiry
    //
    //   WHY MIN-HEAP?
    //     We always want to process the EARLIEST expiry first.
    //     With std::greater, the element with the SMALLEST expiry time
    //     sits at the top — exactly what we need for our revocation loop.
    //     The loop only needs to call top() to know when to next wake up.
    //
    std::priority_queue<
        RevocationEntry,
        std::vector<RevocationEntry>,
        std::greater<RevocationEntry>
    > m_revocQueue;

    // ── Active Rules Tracking ─────────────────────────────────────────────────
    //
    //   Maps: sourceIP → current active rule name
    //   This lets us:
    //     1. Detect re-grants (IP already has a rule → delete old, add new)
    //     2. Validate revocation entries (check name still matches before deleting)
    //     3. Clean up all rules on shutdown
    //
    std::map<std::string, std::string> m_activeRules;

    // ── Revocation Worker Thread ──────────────────────────────────────────────
    std::atomic<bool> m_running{false};
    std::thread       m_worker;

    // ── Private Methods ───────────────────────────────────────────────────────

    /**
     * @brief The revocation worker thread function.
     *
     * Runs an infinite loop:
     *   1. If queue is empty: wait indefinitely (m_cv.wait)
     *   2. If queue non-empty: wait until top().expiry (m_cv.wait_until)
     *   3. On wake: process all entries whose expiry <= now()
     *   4. Unlock mutex, call revokeAccess(), relock
     * Exits when m_running == false and queue is empty.
     */
    void revocationLoop();

    /**
     * @brief Create a unique rule name for a given IP.
     *
     * Format: "GhostPort-<sanitized_ip>-<unix_timestamp>"
     * Example: "GhostPort-192-168-1-42-1749650441"
     *
     * The timestamp suffix ensures uniqueness if the same IP gets
     * re-granted before the old revocation entry fires.
     */
    static std::string makeRuleName(const std::string& ip);

    /**
     * @brief Replace dots in an IP address with hyphens for use in rule names.
     * "192.168.1.42" → "192-168-1-42"
     * (netsh rule names cannot contain dots reliably across all Windows versions)
     */
    static std::string sanitizeIP(const std::string& ip);

    /**
     * @brief Execute a shell command via std::system() with output suppressed.
     *
     * Appends " > nul 2>&1" to redirect both stdout and stderr to the
     * Windows null device, keeping GhostPort's console clean.
     *
     * @param cmd  The command string (e.g. "netsh advfirewall ...").
     * @return     true if the command exited with code 0 (success), false otherwise.
     */
    static bool runCommand(const std::string& cmd);

    /**
     * @brief Build the `netsh advfirewall firewall add rule` command string.
     * @param ruleName  The unique rule name (from makeRuleName()).
     * @param ip        The client source IP to allow.
     * @return          Complete netsh command string ready for runCommand().
     */
    std::string buildAddCommand(const std::string& ruleName,
                                const std::string& ip) const;

    /**
     * @brief Build the `netsh advfirewall firewall delete rule` command string.
     * @param ruleName  The exact rule name to delete.
     * @return          Complete netsh command string ready for runCommand().
     */
    static std::string buildDeleteCommand(const std::string& ruleName);
};
