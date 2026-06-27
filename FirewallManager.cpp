/**
 * ============================================================
 *  GhostPort - FirewallManager.cpp
 *  Version: 4.0 (Milestone 4 - Windows Firewall Integration)
 * ============================================================
 *
 *  IMPLEMENTATION NOTES:
 *
 *  COMMAND PIPELINE:
 *    We use std::system() which passes the command to cmd.exe.
 *    Appending " > nul 2>&1" suppresses netsh's output:
 *      >  nul    — redirect stdout  to Windows null device
 *      2>&1      — redirect stderr  to stdout (which goes to nul)
 *    This keeps GhostPort's console clean during rule operations.
 *
 *  REVOCATION LOOP DESIGN — The condition_variable dance:
 *
 *    The worker thread holds a std::unique_lock<std::mutex>.
 *    It calls m_cv.wait() or m_cv.wait_until() which ATOMICALLY:
 *      1. Releases the mutex (so grantAccess() can add to the queue)
 *      2. Blocks the thread until notified or deadline reached
 *      3. Re-acquires the mutex before returning
 *
 *    This is the ONLY correct way to wait on a shared queue in C++.
 *    A naive sleep loop would either busy-wait (CPU hog) or miss
 *    notifications (race condition).
 *
 *    WHY RELEASE MUTEX FOR system() CALL?
 *    std::system() can take 100-500ms to launch cmd.exe and netsh.
 *    Holding the mutex that long would block grantAccess() for other
 *    clients. We unlock before system(), relock after.
 *    This is safe because the RevocationEntry is a local copy (value
 *    semantics) — no dangling references after unlock.
 *
 *  ZERO-TRUST SHUTDOWN GUARANTEE:
 *    The destructor first signals m_running=false and notifies the
 *    worker, then joins it. After join(), the worker is confirmed
 *    dead. THEN we iterate m_activeRules and delete every remaining
 *    rule. Even if the daemon crashes (SIGKILL), the rules persist —
 *    in Milestone 7, a startup-time cleanup pass will find and delete
 *    any "GhostPort-*" rules left over from a previous run.
 * ============================================================
 */

#include "FirewallManager.h"

#include <iostream>
#include <iomanip>
#include <sstream>
#include <cstdlib>   // std::system()
#include <ctime>     // std::time()
#include <algorithm> // std::replace()


// ─── Static Helpers ───────────────────────────────────────────────────────────

/**
 * Replace dots in the IP with hyphens.
 * "192.168.1.42" → "192-168-1-42"
 *
 * WHY: netsh rule names are used as Windows Registry values.
 * Dots can cause issues with certain netsh versions and Registry paths.
 * Hyphens are safe in all Windows versions (XP through Server 2025).
 */
std::string FirewallManager::sanitizeIP(const std::string& ip) {
    std::string s = ip;
    std::replace(s.begin(), s.end(), '.', '-');
    return s;
}

/**
 * Create a timestamped rule name: "GhostPort-<sanitized_ip>-<ts>"
 *
 * WHY INCLUDE THE TIMESTAMP?
 *   If a client knocks twice quickly, the second grant creates a new rule
 *   with a different name. The first revocation entry fires later and checks
 *   whether the stored name still matches the active rule — it doesn't, so
 *   it skips silently. This prevents accidental deletion of the refreshed rule.
 *
 * Example: "GhostPort-192-168-1-42-1749650441"
 */
std::string FirewallManager::makeRuleName(const std::string& ip) {
    uint32_t ts = static_cast<uint32_t>(std::time(nullptr));
    std::ostringstream oss;
    oss << "GhostPort-" << sanitizeIP(ip) << "-" << ts;
    return oss.str();
}

/**
 * Build the netsh ADD command.
 *
 * Full command example:
 *   netsh advfirewall firewall add rule
 *       name="GhostPort-192-168-1-42-1749650441"
 *       dir=in action=allow protocol=TCP
 *       localport=22 remoteip=192.168.1.42
 *       enable=yes
 *       description="GhostPort: auto-expires in 30s"
 *
 * KEY PARAMETERS:
 *   dir=in        — Inbound rule (traffic coming FROM the client)
 *   action=allow  — Permit the traffic (not block)
 *   remoteip=     — Restrict to ONLY this source IP (pinpoint access)
 *   localport=    — Only open this specific port (not all ports)
 *   enable=yes    — Activate immediately
 */
std::string FirewallManager::buildAddCommand(const std::string& ruleName,
                                              const std::string& ip) const {
    std::ostringstream oss;
    oss << "netsh advfirewall firewall add rule"
        << " name=\""        << ruleName         << "\""
        << " dir=in"
        << " action=allow"
        << " protocol=TCP"
        << " localport="     << m_protectedPort
        << " remoteip="      << ip
        << " enable=yes"
        << " description=\"GhostPort: auto-expires in " << m_windowSeconds << "s\"";
    return oss.str();
}

/**
 * Build the netsh DELETE command.
 *
 * Full command example:
 *   netsh advfirewall firewall delete rule
 *       name="GhostPort-192-168-1-42-1749650441"
 *
 * netsh delete rule matches by name only — the exact rule name is
 * sufficient. No need to repeat dir/protocol/port.
 */
std::string FirewallManager::buildDeleteCommand(const std::string& ruleName) {
    return "netsh advfirewall firewall delete rule name=\"" + ruleName + "\"";
}

/**
 * Execute a command string via the Windows shell, suppressing all output.
 *
 * "> nul 2>&1" explanation:
 *   >  nul   — redirect file descriptor 1 (stdout) to NUL (discard)
 *   2>&1     — redirect file descriptor 2 (stderr) to FD 1 (which is now NUL)
 *   Net effect: complete silence — no netsh output on the GhostPort console.
 *
 * EXIT CODES from netsh advfirewall:
 *   0  — Success
 *   1  — Rule not found (delete of non-existent rule)
 *   other — Error (permissions, invalid syntax, etc.)
 *
 * @return true if std::system() returned exit code 0 (success), false otherwise.
 */
bool FirewallManager::runCommand(const std::string& cmd) {
    std::string fullCmd = cmd + " > nul 2>&1";
    return std::system(fullCmd.c_str()) == 0;
}


// ─── Constructor ──────────────────────────────────────────────────────────────

FirewallManager::FirewallManager(int accessWindowSec, uint16_t protectedPort)
    : m_windowSeconds(accessWindowSec)
    , m_protectedPort(protectedPort)
    , m_running(true)
    , m_worker(&FirewallManager::revocationLoop, this)
    //
    // The std::thread constructor takes a callable + args and immediately
    // launches the thread. We pass a member function pointer and `this`
    // so the thread calls this->revocationLoop() on its own stack.
    //
{
    std::cout << "[FirewallManager] Firewall engine initialized.\n";
    std::cout << "[FirewallManager] Protected port  : TCP/" << m_protectedPort << "\n";
    std::cout << "[FirewallManager] Access window   : " << m_windowSeconds << "s\n";
    std::cout << "[FirewallManager] Revocation mode : Auto (priority-queue thread)\n\n";
}


// ─── Destructor ───────────────────────────────────────────────────────────────

FirewallManager::~FirewallManager() {
    // Signal the worker thread to exit its loop
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_running = false;
    }
    m_cv.notify_all();   // Wake the worker so it sees m_running=false

    // Wait for the worker thread to finish cleanly
    if (m_worker.joinable()) {
        m_worker.join();
    }

    // Zero-Trust shutdown: revoke ALL remaining active rules
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_activeRules.empty()) {
        std::cout << "\n[FirewallManager] Shutdown: revoking "
                  << m_activeRules.size() << " active rule(s)...\n";
        for (auto& [ip, ruleName] : m_activeRules) {
            std::cout << "[FirewallManager]   Revoking: " << ruleName << "\n";
            runCommand(buildDeleteCommand(ruleName));
        }
        m_activeRules.clear();
        std::cout << "[FirewallManager] All rules revoked. Clean shutdown.\n";
    }
}


// ─── grantAccess ──────────────────────────────────────────────────────────────

bool FirewallManager::grantAccess(const std::string& clientIP) {
    std::lock_guard<std::mutex> lock(m_mutex);

    // ── Check for existing rule (re-grant / timer reset) ─────────────────────
    auto existing = m_activeRules.find(clientIP);
    if (existing != m_activeRules.end()) {
        std::cout << "[FirewallManager] Re-grant detected for " << clientIP
                  << " — deleting old rule " << existing->second << " and resetting timer.\n";
        runCommand(buildDeleteCommand(existing->second));
        m_activeRules.erase(existing);
    }

    // ── Build unique rule name ────────────────────────────────────────────────
    std::string ruleName = makeRuleName(clientIP);
    std::string addCmd   = buildAddCommand(ruleName, clientIP);

    // ── Display the command for educational transparency ──────────────────────
    std::cout << "[FirewallManager] Injecting rule : " << ruleName << "\n";
    std::cout << "[FirewallManager] netsh command  : " << addCmd   << "\n";

    // ── Execute the netsh add command ─────────────────────────────────────────
    bool success = runCommand(addCmd);

    if (!success) {
        std::cerr << "[FirewallManager] ERROR: netsh advfirewall returned a non-zero exit code.\n"
                  << "[FirewallManager] Is GhostPort running as Administrator?\n"
                  << "[FirewallManager] Run: Start-Process ghostport.exe -Verb RunAs\n";
        return false;
    }

    std::cout << "[FirewallManager] Rule ACTIVE: TCP/" << m_protectedPort
              << " from " << clientIP << " allowed for " << m_windowSeconds << "s.\n";

    // ── Track the active rule ─────────────────────────────────────────────────
    m_activeRules[clientIP] = ruleName;

    // ── Schedule auto-revocation ──────────────────────────────────────────────
    //
    //   Push a RevocationEntry to the min-heap.
    //   expiry = now + m_windowSeconds  (using steady_clock for monotonic timing)
    //
    auto expiry = std::chrono::steady_clock::now()
                + std::chrono::seconds(m_windowSeconds);

    m_revocQueue.push(RevocationEntry{ expiry, clientIP, ruleName });

    //   Notify the sleeping worker thread that a new entry is available.
    //   The worker will call wait_until(lock, expiry) and wake up at the right time.
    m_cv.notify_one();

    std::cout << "[FirewallManager] Auto-revocation scheduled in "
              << m_windowSeconds << "s.\n\n";

    return true;
}


// ─── revokeAccess ─────────────────────────────────────────────────────────────

bool FirewallManager::revokeAccess(const std::string& ruleName) {
    std::string delCmd = buildDeleteCommand(ruleName);

    std::cout << "[FirewallManager] Revoking rule: " << ruleName << "\n";
    int exitCode = runCommand(delCmd);

    if (exitCode == 0) {
        std::cout << "[FirewallManager] Rule revoked. Zero-Trust window closed.\n";
        return true;
    } else {
        // Exit code 1 = rule not found (already deleted manually or by OS restart)
        // This is NOT an error in production — log informatively.
        std::cout << "[FirewallManager] Rule " << ruleName
                  << " not found (exit " << exitCode
                  << ") — already deleted or never existed.\n";
        return false;
    }
}


// ─── revocationLoop (worker thread) ──────────────────────────────────────────

/**
 * THE REVOCATION LOOP — THREAD LIFECYCLE DIAGRAM:
 *
 *   THREAD START
 *       │
 *       ▼
 *   Acquire m_mutex
 *       │
 *       ├─[queue empty]──► m_cv.wait()          ◄─ blocks, releases mutex
 *       │                       │  (woken by grantAccess notify_one)
 *       │                       └──► re-acquire mutex, loop back
 *       │
 *       ├─[queue non-empty]──► m_cv.wait_until(top().expiry)
 *       │                           │  (woken by timeout OR new entry notify)
 *       │                           └──► re-acquire mutex
 *       │
 *       ├─[m_running == false]──► EXIT LOOP
 *       │
 *       └─[entries expired]──► for each expired entry:
 *               ├── check m_activeRules: is this rule still current?
 *               ├── if yes: erase from m_activeRules, UNLOCK mutex
 *               │             runCommand(delete)   ← no lock held during I/O
 *               │           RELOCK mutex
 *               └── if no:  skip (rule was replaced by a re-grant)
 *
 *   LOOP BACK TO TOP
 */
void FirewallManager::revocationLoop() {
    std::unique_lock<std::mutex> lock(m_mutex);

    while (m_running) {

        // ── Case 1: Nothing queued — wait for a new entry ─────────────────────
        if (m_revocQueue.empty()) {
            m_cv.wait(lock, [this] {
                return !m_revocQueue.empty() || !m_running;
            });
            continue;
        }

        // ── Case 2: Has entries — sleep until the nearest expiry ──────────────
        //
        //   wait_until releases the lock and blocks until either:
        //     a) m_cv.notify_one/all() is called (new entry added or shutdown)
        //     b) The deadline (top().expiry) is reached
        //
        //   On return, the lock is re-acquired.
        //   We then loop back to check m_running and process expired entries.
        //
        auto nextExpiry = m_revocQueue.top().expiry;
        m_cv.wait_until(lock, nextExpiry);

        if (!m_running) break;

        // ── Process all entries whose expiry <= now ───────────────────────────
        auto now = std::chrono::steady_clock::now();

        while (!m_revocQueue.empty() && m_revocQueue.top().expiry <= now) {
            RevocationEntry entry = m_revocQueue.top();   // copy by value
            m_revocQueue.pop();

            // Check if this entry's rule is still the CURRENT active rule for the IP.
            // If the client re-knocked, m_activeRules[ip] will have a DIFFERENT name.
            auto it = m_activeRules.find(entry.ip);
            if (it == m_activeRules.end() || it->second != entry.ruleName) {
                // This revocation is stale — the rule was already replaced or
                // manually deleted. Skip silently.
                std::cout << "[FirewallManager] Skipping stale revocation for "
                          << entry.ip << " (rule replaced or manually removed).\n";
                continue;
            }

            // Remove from active rules BEFORE unlocking
            m_activeRules.erase(it);

            // ── Unlock mutex for the blocking system() call ───────────────────
            //
            //   CRITICAL: std::system() takes 100-500ms on Windows.
            //   If we held the mutex, grantAccess() would block for other
            //   clients during that window. Release, do the I/O, relock.
            //
            //   `entry` was copied by value above — no dangling refs.
            //
            std::cout << "[FirewallManager] Access window expired for "
                      << entry.ip << " — auto-revoking...\n";

            lock.unlock();
            revokeAccess(entry.ruleName);
            lock.lock();
        }
    }

    std::cout << "[FirewallManager] Revocation worker thread exiting.\n";
}


// ─── Utility ──────────────────────────────────────────────────────────────────

size_t FirewallManager::activeRuleCount() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_activeRules.size();
}
