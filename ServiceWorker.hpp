/**
 * ============================================================
 *  GhostPort - ServiceWorker.hpp
 *  Version: 5.0 (Phase 3 — Windows Service Daemon)
 * ============================================================
 *
 *  PURPOSE:
 *    Declares the Windows Service Control Manager (SCM) contract
 *    for GhostPort. When the binary is started by the SCM, the
 *    dispatcher thread calls ServiceMain(), which:
 *
 *      1. Registers ServiceCtrlHandler() with the SCM.
 *      2. Redirects std::cout / std::cerr to the persistent log
 *         file at C:\ProgramData\GhostPort\engine.log.
 *      3. Signals SERVICE_RUNNING and executes RunDaemonCore().
 *      4. On stop request, sets g_running = false (same flag the
 *         console SIGINT handler uses) for a unified shutdown path.
 *
 *  INSTALL / UNINSTALL:
 *    InstallService()   — registers GhostPort as an AUTO_START
 *                         Win32 own-process service via CreateServiceA.
 *    UninstallService() — opens and deletes the SCM entry.
 *
 *  SHARED SHUTDOWN FLAG:
 *    g_running is defined in ServiceWorker.cpp and declared extern
 *    here so PacketListener threads and cleanup daemons can read it
 *    without including the full service machinery.
 * ============================================================
 */

#pragma once

#ifdef _WIN32

#include <windows.h>
#include <atomic>

// ─── Service Identity Constants ───────────────────────────────────────────────
constexpr const char* GHOSTPORT_SERVICE_NAME    = "GhostPort";
constexpr const char* GHOSTPORT_SERVICE_DISPLAY = "GhostPort Port-Knocking Daemon";
constexpr const char* GHOSTPORT_SERVICE_DESC    =
    "Authenticated port-knocking daemon with cryptographic SPA "
    "verification and timed Windows Firewall rule injection.";

constexpr const char* GHOSTPORT_LOG_DIR  = "C:\\ProgramData\\GhostPort";
constexpr const char* GHOSTPORT_LOG_PATH = "C:\\ProgramData\\GhostPort\\engine.log";

// ─── Shared Shutdown Flag ─────────────────────────────────────────────────────
//
//   Owned by ServiceWorker.cpp.  Every component that needs to observe the
//   daemon lifecycle (cleanup thread, listener loops, onSignal handler) reads
//   this flag — keeping the shutdown path identical for both console mode and
//   headless service mode.
//
extern std::atomic<bool> g_running;

// ─── SCM Entry Points ─────────────────────────────────────────────────────────

/**
 * @brief SCM dispatcher calls this when starting the service.
 *        Registers the control handler, inits logging, then
 *        calls RunDaemonCore() which blocks until g_running = false.
 */
void WINAPI ServiceMain(DWORD argc, LPTSTR* argv);

/**
 * @brief SCM calls this on SERVICE_CONTROL_STOP / SERVICE_CONTROL_SHUTDOWN.
 *        Sets g_running = false to trigger a clean listener teardown.
 */
void WINAPI ServiceCtrlHandler(DWORD request);

// ─── Log File Redirect ────────────────────────────────────────────────────────

/**
 * @brief Creates C:\ProgramData\GhostPort\ if needed, opens engine.log in
 *        append mode, and redirects std::cout / std::cerr into it.
 * @return true on success, false if the file cannot be opened.
 */
bool InitServiceLogging();

/**
 * @brief Writes a session-end footer, flushes, and restores the original
 *        stream buffers. Safe to call even if InitServiceLogging() failed.
 */
void ShutdownServiceLogging();

// ─── SCM Management Helpers ───────────────────────────────────────────────────

/**
 * @brief Registers GhostPort as an AUTO_START Win32 own-process service.
 *        Reads the current executable path via GetModuleFileNameA().
 * @return 0 on success, 1 on failure (error printed to stdout).
 */
int InstallService();

/**
 * @brief Opens and deletes the GhostPort SCM entry.
 * @return 0 on success, 1 on failure.
 */
int UninstallService();

// ─── Daemon Core (defined in main.cpp) ───────────────────────────────────────
//
//   Called by ServiceMain() after the SCM handshake is complete.
//   Contains the full multi-threaded StateLedger + PacketListener loop.
//
void RunDaemonCore();

#endif // _WIN32
