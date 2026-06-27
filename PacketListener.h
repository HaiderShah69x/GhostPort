/**
 * ============================================================
 *  GhostPort - PacketListener.h
 *  Version: 1.0 (Milestone 1 - The Listener Engine)
 * ============================================================
 *
 *  PURPOSE:
 *    Defines the PacketListener class, which opens a raw UDP
 *    socket and captures every incoming knock packet. This is
 *    the "ears" of the GhostPort daemon — it sees everything
 *    before the OS network stack processes it.
 *
 *  NETWORKING CONCEPT:
 *    We use a standard BSD socket with:
 *      - AF_INET   → IPv4 address family
 *      - SOCK_DGRAM → UDP (connectionless) datagrams
 *    UDP is used for knocking because:
 *      1. It leaves NO connection state on the server (invisible)
 *      2. It is fire-and-forget — no TCP handshake to expose
 *      3. It is extremely fast for lightweight knock packets
 *
 *  AUTHOR:  Syed Haider Ali (FYP - GhostPort)
 * ============================================================
 */

#pragma once

class StateLedger;


#include <string>
#include <cstdint>
#include <functional>
#include <thread>

// ─── Platform-specific socket includes ───────────────────────────────────────
#ifdef _WIN32
    // Windows Sockets 2 (Winsock2) — the Windows equivalent of POSIX sockets
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #ifdef _MSC_VER
        #pragma comment(lib, "ws2_32.lib")  // Link against Winsock library
    #endif
    typedef int socklen_t;
#else
    // POSIX sockets — standard on Linux / macOS
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    typedef int SOCKET;
    #define INVALID_SOCKET (-1)
    #define SOCKET_ERROR   (-1)
#endif
// ─────────────────────────────────────────────────────────────────────────────


/**
 * @struct KnockEvent
 * @brief  A plain data structure representing a single knock attempt.
 *
 * Every time a UDP packet arrives on our listener port, we parse it
 * into a KnockEvent and hand it off to the registered callback.
 * This keeps our listener decoupled from business logic.
 */
struct KnockEvent {
    std::string sourceIP;    // Who knocked? (e.g. "192.168.1.42")
    uint16_t    sourcePort;  // Which port did they send FROM?
    uint16_t    destPort;    // Which port did they knock ON?
    std::string payload;     // Raw packet payload (will carry SPA data in v2+)
    size_t      payloadSize; // Payload length in bytes
};


/**
 * @class PacketListener
 * @brief Opens a UDP socket and listens for incoming knock packets.
 *
 * DESIGN PATTERN: Observer / Callback
 *   The listener does NOT decide what to do with a knock — it just
 *   detects it and fires a callback. The caller registers a handler
 *   via setKnockHandler(). This separation of concerns makes it easy
 *   to swap out validation logic without touching the listener.
 *
 * LIFECYCLE:
 *   1. Construct with a port number
 *   2. Call setKnockHandler() to register your event handler
 *   3. Call start() — this BLOCKS in a receive loop
 *   4. Call stop() from another thread or signal handler to exit cleanly
 */
class PacketListener {
public:
    /**
     * @brief Constructor.
     * @param listenPort  The UDP port this listener will bind to.
     *                    In Milestone 2, this will be our "knock port".
     */
    explicit PacketListener(uint16_t listenPort, StateLedger& ledger);

    /**
     * @brief Destructor. Ensures socket is closed and resources freed.
     */
    ~PacketListener();

    // ── Non-copyable (a socket is a unique OS resource) ──────────────────────
    PacketListener(const PacketListener&)            = delete;
    PacketListener& operator=(const PacketListener&) = delete;
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * @brief Register a callback to be invoked on every knock event.
     *
     * The callback receives a const reference to a KnockEvent.
     * std::function allows lambdas, free functions, or class methods.
     *
     * @param handler  Callable that accepts a KnockEvent.
     */
    void setKnockHandler(std::function<void(const KnockEvent&)> handler);

    /**
     * @brief Initialize the socket and start the blocking receive loop.
     *
     * BLOCKING CALL — run this on its own thread in Milestone 2+.
     * Returns false if socket initialization fails.
     *
     * @return true on clean shutdown, false on initialization error.
     */
    bool start();

    /**
     * @brief Signal the receive loop to exit gracefully.
     *
     * Thread-safe: sets an atomic flag read by the receive loop.
     */
    void stop();

    /**
     * @brief Check whether the listener is currently running.
     * @return true if actively listening.
     */
    bool isRunning() const;

private:
    uint16_t    m_port;       // UDP port we are bound to
    SOCKET      m_socket;     // The OS socket file descriptor
    bool        m_running;    // Receive-loop control flag
    std::thread m_thread;     // Background thread running receiveLoop()
    StateLedger& m_ledger;    // Reference to the shared connection ledger


    // Callback fired on every incoming knock packet
    std::function<void(const KnockEvent&)> m_knockHandler;

    /**
     * @brief Create, configure, and bind the UDP socket.
     * @return true on success, false on any socket error.
     */
    bool initSocket();

    /**
     * @brief Close and release the socket.
     */
    void closeSocket();

    /**
     * @brief The background thread receive loop.
     */
    void receiveLoop();
};
