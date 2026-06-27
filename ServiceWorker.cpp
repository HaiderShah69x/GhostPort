/**
 * ============================================================
 *  GhostPort - ServiceWorker.cpp
 *  Version: 5.0 (Phase 3 — Windows Service Daemon)
 * ============================================================
 *
 *  IMPLEMENTATION NOTES:
 *
 *  SCM HANDSHAKE CONTRACT:
 *    When ghostport_svc.exe is started by the SCM (either at boot
 *    via AUTO_START or manually via `net start GhostPort`), the
 *    dispatcher thread calls ServiceMain() on a worker thread.
 *    ServiceMain must call RegisterServiceCtrlHandlerA() within
 *    the first 30 seconds or the SCM kills the process.
 *
 *  STATUS REPORTING:
 *    SetServiceStatus() must be called to advance through:
 *      START_PENDING → RUNNING → STOP_PENDING → STOPPED
 *    Each intermediate state includes a dwCheckPoint counter and
 *    a dwWaitHint telling the SCM how many ms to wait for the
 *    next status update.
 *
 *  LOG REDIRECT DESIGN:
 *    Services have no attached console. std::cout and std::cerr
 *    are redirected to C:\ProgramData\GhostPort\engine.log via
 *    rdbuf() stream buffer replacement. The original buffers are
 *    restored on shutdown so the runtime doesn't crash trying to
 *    flush to a null device.
 *
 *  SHUTDOWN PATH:
 *    ServiceCtrlHandler() sets g_running = false.
 *    RunDaemonCore()'s wait loop exits → listeners are stopped →
 *    ServiceMain() calls ShutdownServiceLogging() → SERVICE_STOPPED.
 * ============================================================
 */

#include "ServiceWorker.hpp"

#ifdef _WIN32

#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <atomic>
#include <thread>       // std::thread — daemon core isolation
#include <chrono>       // std::chrono::milliseconds — SCM wait loop
#include <filesystem>

// ─── Shared Shutdown Flag ─────────────────────────────────────────────────────
//   extern declaration in ServiceWorker.hpp — all translation units share this.
std::atomic<bool> g_running{true};


// ─── Service State ────────────────────────────────────────────────────────────
static SERVICE_STATUS        g_svcStatus     = {};
static SERVICE_STATUS_HANDLE g_svcHandle     = nullptr;


// ─── Log File State ───────────────────────────────────────────────────────────
static std::ofstream   g_logFile;
static std::streambuf* g_coutOrig = nullptr;
static std::streambuf* g_cerrOrig = nullptr;


// ─── Internal Helpers ─────────────────────────────────────────────────────────

static std::string svcTimestamp() {
    std::time_t now = std::time(nullptr);
    std::tm tm{};
    localtime_s(&tm, &now);
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

/**
 * @brief Report current service status to the SCM.
 *
 * dwCheckPoint increments for each intermediate state update — the SCM
 * resets its watchdog timer on every non-zero checkpoint change. Pass 0
 * for RUNNING and STOPPED (final states require checkpoint = 0).
 */
static void ReportStatus(DWORD state, DWORD exitCode = NO_ERROR, DWORD waitHintMs = 0) {
    static DWORD checkpoint = 1;

    g_svcStatus.dwServiceType      = SERVICE_WIN32_OWN_PROCESS;
    g_svcStatus.dwCurrentState     = state;
    g_svcStatus.dwWin32ExitCode    = exitCode;
    g_svcStatus.dwWaitHint         = waitHintMs;
    g_svcStatus.dwControlsAccepted =
        (state == SERVICE_START_PENDING) ? 0
                                         : SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    g_svcStatus.dwCheckPoint =
        (state == SERVICE_RUNNING || state == SERVICE_STOPPED) ? 0 : checkpoint++;

    SetServiceStatus(g_svcHandle, &g_svcStatus);
}


// ─── Log Redirect ─────────────────────────────────────────────────────────────

bool InitServiceLogging() {
    // Ensure log directory exists — create_directories is a no-op if it exists
    try {
        std::filesystem::create_directories("C:\\ProgramData\\GhostPort");
    } catch (const std::exception& ex) {
        std::string dbg = "[GhostPort] ERROR exception creating directories: " + std::string(ex.what()) + "\n";
        OutputDebugStringA(dbg.c_str());
    } catch (...) {
        OutputDebugStringA("[GhostPort] ERROR unknown exception creating directories.\n");
    }

    // Wrap the file open logic in a safety check to ensure it doesn't crash the program if the file handle is blocked
    try {
        g_logFile.open(GHOSTPORT_LOG_PATH, std::ios::app);
        if (!g_logFile.is_open()) {
            OutputDebugStringA("[GhostPort] ERROR: Cannot open engine.log (is_open failed).\n");
            return false;
        }
    } catch (const std::exception& ex) {
        std::string dbg = "[GhostPort] ERROR exception opening engine.log: " + std::string(ex.what()) + "\n";
        OutputDebugStringA(dbg.c_str());
        return false;
    } catch (...) {
        OutputDebugStringA("[GhostPort] ERROR unknown exception opening engine.log.\n");
        return false;
    }

    // Redirect both output streams into the log file buffer
    g_coutOrig = std::cout.rdbuf(g_logFile.rdbuf());
    g_cerrOrig = std::cerr.rdbuf(g_logFile.rdbuf());

    // Session header
    std::cout
        << "\n"
        << "============================================================\n"
        << "  GhostPort Service Session — STARTED: " << svcTimestamp() << "\n"
        << "============================================================\n";
    std::cout.flush();

    return true;
}

void ShutdownServiceLogging() {
    if (g_logFile.is_open()) {
        std::cout
            << "============================================================\n"
            << "  GhostPort Service Session — STOPPED: " << svcTimestamp() << "\n"
            << "============================================================\n\n";
        std::cout.flush();
    }

    // Restore original buffers before closing the file
    if (g_coutOrig) { std::cout.rdbuf(g_coutOrig); g_coutOrig = nullptr; }
    if (g_cerrOrig) { std::cerr.rdbuf(g_cerrOrig); g_cerrOrig = nullptr; }

    g_logFile.close();
}


// ─── ServiceCtrlHandler ───────────────────────────────────────────────────────

void WINAPI ServiceCtrlHandler(DWORD request) {
    switch (request) {

        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            std::cout << "[ServiceCtrlHandler] Stop/Shutdown control received.\n";
            std::cout.flush();
            // Notify SCM: we are stopping (give up to 10s for listener teardown)
            ReportStatus(SERVICE_STOP_PENDING, NO_ERROR, 10000);
            // Signal the daemon loop to exit cleanly
            g_running = false;
            break;

        case SERVICE_CONTROL_INTERROGATE:
            // SCM is asking for current status — reply with last known state
            SetServiceStatus(g_svcHandle, &g_svcStatus);
            break;

        default:
            break;
    }
}


// ─── ServiceMain ─────────────────────────────────────────────────────────────

void WINAPI ServiceMain(DWORD /*argc*/, LPTSTR* /*argv*/) {

    // 1. Register the control handler — MUST be the first SCM call
    g_svcHandle = RegisterServiceCtrlHandlerA(GHOSTPORT_SERVICE_NAME, ServiceCtrlHandler);
    if (!g_svcHandle) {
        OutputDebugStringA("[GhostPort] FATAL: RegisterServiceCtrlHandlerA failed.\n");
        return;
    }

    // 2. Acknowledge: we are starting (SCM gives 10s to reach RUNNING)
    ReportStatus(SERVICE_START_PENDING, NO_ERROR, 10000);

    // 3. Redirect console streams to persistent log file
    if (!InitServiceLogging()) {
        ReportStatus(SERVICE_STOPPED, ERROR_FILE_NOT_FOUND);
        return;
    }

    std::cout << "[ServiceWorker] SCM handshake complete.\n";
    std::cout << "[ServiceWorker] Spawning daemon core on isolated thread...\n";
    std::cout.flush();

    // 4. Spawn the core network listening loops onto an independent background thread.
    //    Detaching immediately releases ServiceMain from blocking inside RunDaemonCore(),
    //    allowing us to report SERVICE_RUNNING before the daemon's wait loop begins.
    //    ServiceMain itself then holds the SCM dispatcher alive via its own g_running
    //    watch loop below — the detached thread is NOT orphaned.
    std::thread workerThread(RunDaemonCore);
    workerThread.detach();

    // 5. Signal: RUNNING — report to SCM immediately after thread is live.
    //    The SCM watchdog is satisfied; error 2186 will not fire.
    ReportStatus(SERVICE_RUNNING);
    std::cout << "[ServiceWorker] SERVICE_RUNNING reported. Daemon thread active.\n";
    std::cout.flush();

    // 6. ServiceMain MUST NOT return while the service is running.
    //    Block here on g_running so StartServiceCtrlDispatcherA() in main() keeps
    //    the process alive. ServiceCtrlHandler() will set g_running = false on STOP.
    while (g_running) {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    // 7. Give the detached worker thread time to complete its listener teardown
    //    before we report SERVICE_STOPPED and the process exits.
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));

    // 8. Finalize logging and report: STOPPED
    std::cout << "[ServiceWorker] Daemon core exited. Service stopping.\n";
    std::cout.flush();
    ShutdownServiceLogging();

    ReportStatus(SERVICE_STOPPED);
}


// ─── InstallService ───────────────────────────────────────────────────────────

int InstallService() {
    // Resolve the full path of the current executable
    char exePath[MAX_PATH] = {};
    if (!GetModuleFileNameA(nullptr, exePath, MAX_PATH)) {
        std::cerr << "[-] InstallService: GetModuleFileNameA failed (err "
                  << GetLastError() << ").\n";
        return 1;
    }

    // Open the SCM with full access
    SC_HANDLE hScm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!hScm) {
        std::cerr << "[-] InstallService: OpenSCManagerA failed (err "
                  << GetLastError() << ").\n"
                  << "    Is this terminal running as Administrator?\n";
        return 1;
    }

    // Register the service entry
    SC_HANDLE hSvc = CreateServiceA(
        hScm,
        GHOSTPORT_SERVICE_NAME,          // Internal SCM key
        GHOSTPORT_SERVICE_DISPLAY,       // Display name in services.msc
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,       // Runs in its own process
        SERVICE_AUTO_START,              // Starts automatically at boot
        SERVICE_ERROR_NORMAL,            // Log error on failure, continue boot
        exePath,                         // Full path to ghostport_svc.exe
        nullptr,                         // No load-order group
        nullptr,                         // No tag identifier
        nullptr,                         // No dependencies
        nullptr,                         // LocalSystem account
        nullptr                          // No password
    );

    if (!hSvc) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_EXISTS) {
            std::cout << "[!] Service already installed. Use --uninstall first.\n";
        } else {
            std::cerr << "[-] CreateServiceA failed (err " << err << ").\n";
        }
        CloseServiceHandle(hScm);
        return 1;
    }

    // Optionally set the service description
    SERVICE_DESCRIPTIONA desc{};
    desc.lpDescription = const_cast<LPSTR>(GHOSTPORT_SERVICE_DESC);
    ChangeServiceConfig2A(hSvc, SERVICE_CONFIG_DESCRIPTION, &desc);

    std::cout << "[+] GhostPort service installed successfully.\n"
              << "[+] Executable : " << exePath << "\n"
              << "[+] Start type : AUTO_START (starts at next boot)\n"
              << "\n"
              << "    To start immediately:\n"
              << "      net start GhostPort\n"
              << "    Or via Services console:\n"
              << "      services.msc  →  GhostPort  →  Start\n";

    CloseServiceHandle(hSvc);
    CloseServiceHandle(hScm);
    return 0;
}


// ─── UninstallService ─────────────────────────────────────────────────────────

int UninstallService() {
    SC_HANDLE hScm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!hScm) {
        std::cerr << "[-] UninstallService: OpenSCManagerA failed (err "
                  << GetLastError() << ").\n";
        return 1;
    }

    SC_HANDLE hSvc = OpenServiceA(hScm, GHOSTPORT_SERVICE_NAME, SERVICE_ALL_ACCESS);
    if (!hSvc) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_DOES_NOT_EXIST) {
            std::cout << "[!] GhostPort service is not installed.\n";
        } else {
            std::cerr << "[-] OpenServiceA failed (err " << err << ").\n";
        }
        CloseServiceHandle(hScm);
        return 1;
    }

    // Stop the service first if it is running
    SERVICE_STATUS status{};
    if (QueryServiceStatus(hSvc, &status) &&
        status.dwCurrentState != SERVICE_STOPPED) {
        std::cout << "[*] Stopping GhostPort service before removal...\n";
        ControlService(hSvc, SERVICE_CONTROL_STOP, &status);
        Sleep(2000);   // Give the service time to stop
    }

    if (!DeleteService(hSvc)) {
        std::cerr << "[-] DeleteService failed (err " << GetLastError() << ").\n";
        CloseServiceHandle(hSvc);
        CloseServiceHandle(hScm);
        return 1;
    }

    std::cout << "[+] GhostPort service uninstalled successfully.\n"
              << "    SCM entry removed. The binary remains at its current path.\n";

    CloseServiceHandle(hSvc);
    CloseServiceHandle(hScm);
    return 0;
}

#endif // _WIN32
