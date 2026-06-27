/**
 * ============================================================
 *  GhostPort - main.cpp
 *  Version: 4.0 (Milestone 4 - Windows Firewall Integration)
 * ============================================================
 *
 *  This is the entry point for the GhostPort daemon.
 *
 *  In v4.0, this program:
 *    1. Defines the 32-byte PSK for HMAC-SHA256
 *    2. Instantiates HmacVerifier (SPA gate)
 *    3. Instantiates SequenceValidator and wires the SPA gate
 *    4. Instantiates FirewallManager (netsh rule engine)
 *    5. Wires all three into a single access-granted callback
 *    6. Attaches PacketListener and starts the daemon
 *    7. Handles Ctrl+C (SIGINT) for graceful shutdown
 *
 *  NEW in v4.0:
 *    - FirewallManager injects timed TCP/22 inbound rules via netsh
 *    - Priority-queue revocation thread auto-deletes rules after 30s
 *    - Zero-Trust: access window is ALWAYS temporary
 *    - Mutex+condition_variable for safe multi-client concurrency
 *    - Clean shutdown revokes ALL active rules before exit
 * ============================================================
 */

#include "PacketListener.h"
#include "SequenceValidator.h"
#include "HmacVerifier.h"      // SPA cryptographic gate (Milestone 3)
#include "FirewallManager.h"   // Windows Firewall rule engine (Milestone 4)
#include "StateLedger.hpp"


#include <iostream>
#include <iomanip>
#include <sstream>
#include <csignal>
#include <ctime>
#include <string>
#include <algorithm>
#include <atomic>
#include <thread>
#include <vector>
#include <memory>

#ifdef _WIN32
#include <windows.h>
#include <debugapi.h>
#include <shlobj.h>    // IsUserAnAdmin() — Win32 shell privilege check
#pragma comment(lib, "Shell32.lib")
#endif

#include "ServiceWorker.hpp"  // SCM handshake, g_running, Install/UninstallService

// ─── Global shutdown flag ─────────────────────────────────────────────────────
//   Defined in ServiceWorker.cpp as std::atomic<bool> g_running{true}.
//   Declared extern via ServiceWorker.hpp so onSignal() and RunDaemonCore()
//   can signal a clean shutdown from both console-mode and service-mode paths.


// ─── Signal Handler ───────────────────────────────────────────────────────────

/**
 * @brief Called when the user presses Ctrl+C (sends SIGINT) or program terminates.
 * Gracefully stops the daemon rather than hard-killing the process.
 */
void onSignal(int signal) {
    if (signal == SIGINT || signal == SIGTERM) {
        std::cout << "\n[GhostPort] ⚠️  Interrupt received. Shutting down...\n";
        g_running = false;
    }
}


// ─── Utility: Current Timestamp String ───────────────────────────────────────

/**
 * @brief Returns the current local time as a formatted string.
 * @return e.g. "2026-06-11 14:32:07"
 */
std::string currentTimestamp() {
    std::time_t now = std::time(nullptr);
    std::tm localTime;

#ifdef _WIN32
    localtime_s(&localTime, &now);   // Thread-safe version on Windows
#else
    localtime_r(&now, &localTime);   // Thread-safe version on POSIX
#endif

    std::ostringstream oss;
    oss << std::put_time(&localTime, "%Y-%m-%d %H:%M:%S");
    return oss.str();
}


// ─── Utility: Hex Dump of Payload ─────────────────────────────────────────────

/**
 * @brief Converts raw bytes to a hex string for display.
 * In SPA (Milestone 3), this will show the encrypted knock signature.
 *
 * @param data  Pointer to raw bytes.
 * @param len   Number of bytes to display (capped for readability).
 * @return      Hex string e.g. "48 65 6C 6C 6F"
 */
std::string toHex(const char* data, size_t len) {
    constexpr size_t MAX_DISPLAY = 32;   // Show only first 32 bytes in console
    std::ostringstream oss;
    size_t displayLen = std::min(len, MAX_DISPLAY);

    for (size_t i = 0; i < displayLen; ++i) {
        oss << std::hex << std::uppercase << std::setfill('0')
            << std::setw(2)
            << static_cast<unsigned int>(static_cast<unsigned char>(data[i]));
        if (i + 1 < displayLen) oss << " ";
    }
    if (len > MAX_DISPLAY) oss << " ...";
    return oss.str();
}


// ─── Knock Event Handler ──────────────────────────────────────────────────────

/**
 * @brief This callback is fired by PacketListener for every incoming packet.
 *
 * v1.0: Simply log the event to stdout.
 * v2.0: This will validate the knock sequence order.
 * v3.0: This will verify the SPA cryptographic signature.
 *
 * @param event  The parsed knock event from PacketListener.
 */
void onKnockReceived(const KnockEvent& event) {
    // ── Separator for visual clarity ─────────────────────────────────────────
    std::cout << "┌────────────────────────────────────────────────────┐\n";
    std::cout << "│  🚨 KNOCK DETECTED                                  │\n";
    std::cout << "├────────────────────────────────────────────────────┤\n";

    // ── Source info ──────────────────────────────────────────────────────────
    std::cout << "│  ⏰ Time      : " << currentTimestamp() << "           │\n";
    std::cout << "│  🌐 Source IP : " << std::left << std::setw(36)
              << event.sourceIP  << "│\n";
    std::cout << "│  📤 Src Port  : " << std::left << std::setw(36)
              << event.sourcePort << "│\n";
    std::cout << "│  🚪 Dst Port  : " << std::left << std::setw(36)
              << event.destPort   << "│\n";

    // ── Payload info ─────────────────────────────────────────────────────────
    std::cout << "│  📦 Bytes     : " << std::left << std::setw(36)
              << event.payloadSize << "│\n";

    if (event.payloadSize > 0) {
        std::string hexPayload = toHex(event.payload.c_str(), event.payloadSize);
        std::cout << "│  🔢 Payload   : " << std::left << std::setw(36)
                  << hexPayload << "│\n";
    }

    std::cout << "└────────────────────────────────────────────────────┘\n\n";
}


// ─── Daemon Core ──────────────────────────────────────────────────────────────

/**
 * @brief Contains the full GhostPort multi-threaded runtime.
 *
 * Called from two contexts:
 *   1. Console mode  — invoked directly from main() after banner + admin check.
 *   2. Service mode  — invoked from ServiceWorker::ServiceMain() after the SCM
 *                      handshake is complete and stdout is redirected to log.
 *
 * Blocks until g_running becomes false (set by onSignal() or ServiceCtrlHandler).
 */
void RunDaemonCore() {

    // ── Register POSIX signal handlers (console mode) ─────────────────────────
    //   In service mode these are no-ops — the SCM uses ServiceCtrlHandler.
    std::signal(SIGINT,  onSignal);
    std::signal(SIGTERM, onSignal);

    // ── [M3] Define the Pre-Shared Key (PSK) ─────────────────────────────────
    //
    //   32-byte HMAC-SHA256 secret. NEVER hardcode in production.
    //   Milestone 6: loaded from C:\ProgramData\GhostPort\secret.key
    //
        static const HmacVerifier::Psk PSK = {{
        // Row 1: bytes  0-7
        0xDE, 0xAD, 0xBE, 0xEF,   0xCA, 0xFE, 0xBA, 0xBE,
        // Row 2: bytes  8-15
        0x01, 0x23, 0x45, 0x67,   0x89, 0xAB, 0xCD, 0xEF,
        // Row 3: bytes 16-23
        0xFE, 0xDC, 0xBA, 0x98,   0x76, 0x54, 0x32, 0x10,
        // Row 4: bytes 24-31
        0xAA, 0xBB, 0xCC, 0xDD,   0xEE, 0xFF, 0x11, 0x22
    }};

    // ── [M3] Instantiate the cryptographic SPA gate ───────────────────────────
    HmacVerifier spaVerifier(PSK);

    // ── Instantiate the knock sequence validator ──────────────────────────────
    SequenceValidator validator;
    validator.setSpaVerifier(&spaVerifier);

    // ── [M4] Instantiate the Windows Firewall rule engine ─────────────────────
    FirewallManager firewall;

    // ── Access-granted callback ───────────────────────────────────────────────
    validator.setAccessGrantedHandler([](const std::string& clientIP) {
        std::cout << "[SequenceValidator] Handshake complete — verified for "
                  << clientIP << "\n";
    });

    // ── Connection State Ledger + background cleanup thread ───────────────────
    StateLedger global_ledger;

    std::thread cleanup_thread([&global_ledger]() {
        while (g_running) {
            global_ledger.FlushExpiredNodes(5);
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    });
    cleanup_thread.detach();

    // ── Spawn concurrent UDP listeners for each knock-sequence port ───────────
    const std::vector<uint16_t>& ports = validator.getSequence();
    std::vector<std::unique_ptr<PacketListener>> listeners;
    bool allStarted = true;

    for (uint16_t port : ports) {
        auto listener = std::make_unique<PacketListener>(port, std::ref(global_ledger));
        listener->setKnockHandler([&validator, &firewall, &global_ledger](const KnockEvent& event) {

            std::string clientIP = event.sourceIP;
            // Strip trailing null bytes / whitespace from raw IP string
            size_t nullPos = clientIP.find('\0');
            if (nullPos != std::string::npos) clientIP = clientIP.substr(0, nullPos);
            while (!clientIP.empty() &&
                   (clientIP.back() ==  ' ' || clientIP.back() == '\r' || clientIP.back() == '\n'))
            {
                clientIP.pop_back();
            }

            std::cout << "[" << currentTimestamp() << "] "
                      << "Knock from " << clientIP
                      << " -> port " << event.destPort << "\n";

            if (event.destPort == 7000) {
                ValidationResult result = validator.processKnock(event);
                std::cout << "[SequenceValidator] Result: "
                          << validationResultToString(result) << "\n\n";
                if (result != ValidationResult::SPA_REJECTED)
                    global_ledger.RegisterKnock(clientIP, 7000);
            }
            else if (event.destPort == 8000) {
                if (!global_ledger.RegisterKnock(clientIP, 8000)) {
                    std::cout << "[GhostPort] Silent drop: " << clientIP
                              << " on port 8000 (ledger rejected)\n\n";
                    return;
                }
                ValidationResult result = validator.processKnock(event);
                std::cout << "[SequenceValidator] Result: "
                          << validationResultToString(result) << "\n\n";
            }
            else if (event.destPort == 9000) {
                if (global_ledger.RegisterKnock(clientIP, 9000)) {
                    ValidationResult result = validator.processKnock(event);
                    if (result == ValidationResult::SEQUENCE_COMPLETE) {
                        std::cout << "\n[GhostPort] ACCESS GRANTED for " << clientIP << "\n";
                        firewall.grantAccess(clientIP);
                    } else {
                        std::cout << "[GhostPort] Crypto verification failed on port 9000.\n";
                    }
                } else {
                    std::cout << "[GhostPort] Silent drop: " << clientIP
                              << " on port 9000 (Ledger Timing Reject)\n";
                }
            }
        });

        if (!listener->start()) {
            std::cerr << "[GhostPort] ERROR: Failed to start listener on port " << port << "\n";
            allStarted = false;
            break;
        }
        listeners.push_back(std::move(listener));
    }

    if (allStarted) {
        std::cout << "[GhostPort] All asynchronous multi-port listeners started.\n"
                  << "[GhostPort] Listening on ports: ";
        for (size_t i = 0; i < ports.size(); ++i)
            std::cout << "UDP/" << ports[i] << (i + 1 < ports.size() ? ", " : "");
        std::cout << "\n[GhostPort] Daemon running. Send SIGINT or SCM STOP to exit.\n\n";

        // ── Main wait loop — sleeps until g_running is cleared ────────────────
        while (g_running) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        std::cout << "\n[GhostPort] Shutdown signal received. Stopping listeners...\n";
    }

    // ── Graceful teardown ─────────────────────────────────────────────────────
    for (auto& listener : listeners)
        listener->stop();

    std::cout << "[GhostPort] All listeners stopped. Daemon core exited.\n";
}


// ─── Main Entry Point ─────────────────────────────────────────────────────────

/**
 * @brief Three-path dispatcher:
 *
 *   --install    Register GhostPort as an AUTO_START Win32 service.
 *   --uninstall  Delete the SCM service entry.
 *   (no args)    Attempt SCM StartServiceCtrlDispatcherA.
 *                  On SUCCESS  → service ran and exited cleanly.
 *                  On ERROR_FAILED_SERVICE_CONTROLLER_CONNECT
 *                              → not started by SCM; fall through to
 *                                interactive console mode with banner.
 */
int main(int argc, char* argv[]) {

#ifdef _WIN32
    OutputDebugStringA("[GHOSTPORT_DEBUG] main() entry point reached successfully.\n");
#endif

#ifdef _WIN32
    // ── CLI: --install ────────────────────────────────────────────────────────
    if (argc >= 2 && strcmp(argv[1], "--install") == 0) {
        SetConsoleOutputCP(CP_UTF8);
        SetConsoleCP(CP_UTF8);
        return InstallService();
    }

    // ── CLI: --uninstall ──────────────────────────────────────────────────────
    if (argc >= 2 && strcmp(argv[1], "--uninstall") == 0) {
        SetConsoleOutputCP(CP_UTF8);
        SetConsoleCP(CP_UTF8);
        return UninstallService();
    }

    // ── SCM mode: attempt dispatcher ──────────────────────────────────────────
    //
    //   StartServiceCtrlDispatcherA blocks until ALL service instances stop.
    //   The SCM spawns a thread calling ServiceMain(), which in turn calls
    //   RunDaemonCore() — the full listener loop runs inside that thread.
    //
    SERVICE_TABLE_ENTRYA svcTable[] = {
        { const_cast<LPSTR>(GHOSTPORT_SERVICE_NAME), ServiceMain },
        { nullptr, nullptr }
    };

    BOOL dispatchSuccess = FALSE;
    DWORD dispatchErr = 0;

    OutputDebugStringA("[GHOSTPORT_DEBUG] Attempting to invoke StartServiceCtrlDispatcherA.\n");

    try {
        dispatchSuccess = StartServiceCtrlDispatcherA(svcTable);
        if (!dispatchSuccess) {
            dispatchErr = GetLastError();
        }
    } catch (const std::exception& e) {
        std::cerr << "[-] Exception caught during StartServiceCtrlDispatcherA: " << e.what() << "\n";
        return 1;
    } catch (...) {
        std::cerr << "[-] Unknown exception caught during StartServiceCtrlDispatcherA.\n";
        return 1;
    }

    if (dispatchSuccess) {
        // Service ran and stopped cleanly via SCM
        return 0;
    }

    if (dispatchErr != ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
        // Unexpected SCM error — not a console fallback situation
        std::cerr << "[-] StartServiceCtrlDispatcherA failed unexpectedly (err "
                  << dispatchErr << ").\n";
        return 1;
    }

    // ── Console fallback: process was launched directly, not by SCM ───────────
    //   ERROR_FAILED_SERVICE_CONTROLLER_CONNECT means we are running
    //   interactively — proceed with the console banner + direct daemon mode.
    //
    SetConsoleOutputCP(CP_UTF8);   // UTF-8 rendering for box-drawing glyphs
    SetConsoleCP(CP_UTF8);

    // ── Administrator privilege guard (only in console fallback mode) ─────────
    if (!IsUserAnAdmin()) {
        std::cerr << "\n";
        std::cerr << "[-] CRITICAL ERROR: GhostPort requires elevated administrative\n";
        std::cerr << "    privileges to manipulate host firewall tables.\n";
        std::cerr << "    Please restart from an Elevated Command Prompt /\n";
        std::cerr << "    Administrator terminal.\n\n";
        return 1;
    }
    std::cout << "[GhostPort] Privilege check passed — running as Administrator.\n\n";
#endif

    // ── Banner ────────────────────────────────────────────────────────────────
    std::cout << "\t \u250c\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2510\n";
    std::cout << "\t \u2502   \u2588\u2588\u2588\u2588\u2588\u2588\u2557 \u2588\u2588\u2557  \u2588\u2588\u2557  \u2588\u2588\u2588\u2588\u2588\u2588\u2557  \u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557         \u2502\n";
    std::cout << "\t \u2502  \u2588\u2588\u2554\u2550\u2550\u2550\u2550\u255d \u2588\u2588\u2551  \u2588\u2588\u2551 \u2588\u2588\u2554\u2550\u2550\u2550\u2588\u2588\u2557 \u2588\u2588\u2554\u2550\u2550\u2550\u2550\u255d\u255a\u2550\u2550\u2588\u2588\u2554\u2550\u2550\u255d         \u2502\n";
    std::cout << "\t \u2502  \u2588\u2588\u2551  \u2588\u2588\u2588\u2557\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2551 \u2588\u2588\u2551   \u2588\u2588\u2551 \u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557   \u2588\u2588\u2551            \u2502\n";
    std::cout << "\t \u2502  \u2588\u2588\u2551   \u2588\u2588\u2551\u2588\u2588\u2554\u2550\u2550\u2588\u2588\u2551 \u2588\u2588\u2551   \u2588\u2588\u2551 \u255a\u2550\u2550\u2550\u2550\u2588\u2588\u2551   \u2588\u2588\u2551            \u2502\n";
    std::cout << "\t \u2502  \u255a\u2588\u2588\u2588\u2588\u2588\u2588\u2554\u255d\u2588\u2588\u2551  \u2588\u2588\u2551 \u255a\u2588\u2588\u2588\u2588\u2588\u2588\u2554\u255d \u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2551   \u2588\u2588\u2551            \u2502\n";
    std::cout << "\t \u2502   \u255a\u2550\u2550\u2550\u2550\u2550\u255d \u255a\u2550\u255d  \u255a\u2550\u255d  \u255a\u2550\u2550\u2550\u2550\u2550\u255d  \u255a\u2550\u2550\u2550\u2550\u2550\u2550\u255d   \u255a\u2550\u255d            \u2502\n";
    std::cout << "\t \u2502        \u2588\u2588\u2588\u2588\u2588\u2588\u2557  \u2588\u2588\u2588\u2588\u2588\u2588\u2557 \u2588\u2588\u2588\u2588\u2588\u2588\u2557 \u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557              \u2502\n";
    std::cout << "\t \u2502        \u2588\u2588\u2554\u2550\u2550\u2588\u2588\u2557\u2588\u2588\u2554\u2550\u2550\u2550\u2588\u2588\u2557\u2588\u2588\u2554\u2550\u2550\u2588\u2588\u2557\u255a\u2550\u2550\u2588\u2588\u2554\u2550\u2550\u255d              \u2502\n";
    std::cout << "\t \u2502        \u2588\u2588\u2588\u2588\u2588\u2588\u2554\u255d\u2588\u2588\u2551   \u2588\u2588\u2551\u2588\u2588\u2588\u2588\u2588\u2588\u2554\u255d   \u2588\u2588\u2551                 \u2502\n";
    std::cout << "\t \u2502        \u2588\u2588\u2554\u2550\u2550\u2550\u255d \u2588\u2588\u2551   \u2588\u2588\u2551\u2588\u2588\u2554\u2550\u2550\u2588\u2588\u2557   \u2588\u2588\u2557                 \u2502\n";
    std::cout << "\t \u2502        \u2588\u2588\u2551     \u255a\u2588\u2588\u2588\u2588\u2588\u2588\u2554\u255d\u2588\u2588\u2551  \u2588\u2588\u2551   \u2588\u2588\u2551                 \u2502\n";
    std::cout << "\t \u2502        \u255a\u2550\u255d      \u255a\u2550\u2550\u2550\u2550\u2550\u255d \u255a\u2550\u255d  \u255a\u2550\u255d   \u255a\u2550\u255d                 \u2502\n";
    std::cout << "\t \u251c\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2524\n";
    std::cout << "\t \u2502  GhostPort v5.0 \u2014 Authenticated Port-Knocking Daemon   \u2502\n";
    std::cout << "\t \u2502  Phase 3: Windows Service Daemon Mode                  \u2502\n";
    std::cout << "\t \u2502  FYP Project by Syed Haider Ali                        \u2502\n";
    std::cout << "\t \u2514\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2518\n\n";
    std::cout << "[GhostPort] Console mode — running interactively (not via SCM).\n";
    std::cout << "            To install as a service: ghostport_svc.exe --install\n\n";

    // ── Run the daemon directly in console mode ───────────────────────────────
    RunDaemonCore();
    return 0;
}