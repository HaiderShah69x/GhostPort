/**
 * ============================================================
 *  GhostPort - PacketListener.cpp
 *  Version: 1.0 (Milestone 1 - The Listener Engine)
 * ============================================================
 *
 *  IMPLEMENTATION NOTES:
 *
 *  What is recvfrom()?
 *    Unlike TCP's recv(), which reads from an established connection,
 *    recvfrom() is designed for connectionless UDP sockets. It reads
 *    one datagram AND tells us exactly which IP:Port sent it.
 *    This is crucial — we need to know WHO knocked, not just WHAT
 *    they knocked.
 *
 *  What is sockaddr_in?
 *    A C structure that holds an IPv4 address + port in network byte
 *    order. "Network byte order" = Big Endian. Intel CPUs use Little
 *    Endian, so we use htons() (Host TO Network Short) to convert.
 *
 *  Buffer Size Choice (1024 bytes):
 *    A knock packet in SPA is tiny — typically < 100 bytes of HMAC
 *    signature + timestamp. 1024 bytes is generous for v1 safety.
 * ============================================================
 */

#include "PacketListener.h"

#include <iostream>
#include <cstring>   // memset()
#include <stdexcept>
#include "StateLedger.hpp"

// ─── Constructor ──────────────────────────────────────────────────────────────

PacketListener::PacketListener(uint16_t listenPort, StateLedger& ledger)
    : m_port(listenPort)
    , m_socket(INVALID_SOCKET)
    , m_running(false)
    , m_ledger(ledger)
{
    // On Windows, the Winsock library MUST be initialized before any
    // socket calls. WSAStartup() loads the WS2_32.dll runtime.
#ifdef _WIN32
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        throw std::runtime_error("[GhostPort] WSAStartup failed. Code: "
                                  + std::to_string(result));
    }
#endif
}


// ─── Destructor ───────────────────────────────────────────────────────────────

PacketListener::~PacketListener() {
    stop();
    closeSocket();

    // On Windows, every WSAStartup() must be paired with WSACleanup()
#ifdef _WIN32
    WSACleanup();
#endif
}


// ─── Public API ───────────────────────────────────────────────────────────────

void PacketListener::setKnockHandler(std::function<void(const KnockEvent&)> handler) {
    m_knockHandler = std::move(handler);
}

bool PacketListener::isRunning() const {
    return m_running;
}

void PacketListener::stop() {
    m_running = false;
    // Closing the socket forces recvfrom() to unblock and return an error
    closeSocket();
    if (m_thread.joinable()) {
        m_thread.join();
    }
}


// ─── Core: Socket Initialization ──────────────────────────────────────────────

bool PacketListener::initSocket() {
    // ── Step 1: Create a UDP socket ──────────────────────────────────────────
    //
    //   socket(domain, type, protocol):
    //     AF_INET    → IPv4 (use AF_INET6 for IPv6 / dual-stack in v2)
    //     SOCK_DGRAM → UDP (datagram socket — no connection, no guarantee)
    //     0          → Let OS pick the correct protocol (UDP for DGRAM)
    //
    m_socket = socket(AF_INET, SOCK_DGRAM, 0);

    if (m_socket == INVALID_SOCKET) {
        std::cerr << "[GhostPort] ERROR: Failed to create UDP socket.\n";
        return false;
    }

    // ── Step 2: Set SO_REUSEADDR socket option ────────────────────────────────
    //
    //   By default, if GhostPort crashes and restarts, the OS keeps the
    //   port in TIME_WAIT state for ~60 seconds. SO_REUSEADDR lets us
    //   re-bind immediately — essential for a production daemon.
    //
    int opt = 1;
    setsockopt(m_socket, SOL_SOCKET, SO_REUSEADDR,
               reinterpret_cast<const char*>(&opt), sizeof(opt));

    // ── Step 3: Configure the bind address ───────────────────────────────────
    //
    //   sockaddr_in defines WHERE our socket listens:
    //     sin_family → Must match socket domain (AF_INET)
    //     sin_addr   → INADDR_ANY = "listen on ALL network interfaces"
    //                  (e.g., eth0, lo, etc.) — change to a specific IP
    //                  to limit which interface handles knocks
    //     sin_port   → Port in network byte order (Big Endian)
    //                  htons() converts from host (little) to network (big)
    //
    sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));   // Zero out padding bits
    serverAddr.sin_family      = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port        = htons(m_port);

    // ── Step 4: Bind the socket to the address ───────────────────────────────
    //
    //   bind() registers our socket with the OS. After this call,
    //   the OS will route incoming UDP packets on m_port to our socket's
    //   receive buffer. If something else already owns the port, this fails.
    //
    if (bind(m_socket,
             reinterpret_cast<sockaddr*>(&serverAddr),
             sizeof(serverAddr)) == SOCKET_ERROR)
    {
        std::cerr << "[GhostPort] ERROR: bind() failed on port "
                  << m_port << ". Is it already in use?\n";
        closeSocket();
        return false;
    }

    return true;
}


// ─── Core: Receive Loop ───────────────────────────────────────────────────────

bool PacketListener::start() {
    if (!initSocket()) {
        return false;
    }

    m_running = true;
    m_thread = std::thread(&PacketListener::receiveLoop, this);
    return true;
}

void PacketListener::receiveLoop() {
    // Buffer to hold incoming UDP packet data
    // In SPA (Milestone 3), this will carry an encrypted, signed payload
    constexpr size_t BUFFER_SIZE = 1024;
    char buffer[BUFFER_SIZE];

    // Will be filled by recvfrom() with the sender's address
    sockaddr_in senderAddr;
    socklen_t   senderAddrLen = sizeof(senderAddr);

    std::cout << "[GhostPort] 👂 Listener active on UDP port "
              << m_port << ". Waiting for knocks...\n";

    // ── The Receive Loop ─────────────────────────────────────────────────────
    //
    //   recvfrom() BLOCKS here until a UDP datagram arrives.
    //   When a packet arrives:
    //     1. Data is copied into `buffer`
    //     2. `senderAddr` is populated with the sender's IP:Port
    //     3. Returns number of bytes received
    //
    //   On error (e.g., socket closed by stop()):
    //     Returns SOCKET_ERROR (-1) and we exit gracefully.
    //
    while (m_running) {
        memset(buffer, 0, BUFFER_SIZE);
        memset(&senderAddr, 0, sizeof(senderAddr));

        int bytesReceived = recvfrom(
            m_socket,
            buffer,
            BUFFER_SIZE - 1,          // Leave space for null terminator
            0,                        // Flags (0 = default blocking receive)
            reinterpret_cast<sockaddr*>(&senderAddr),
            &senderAddrLen
        );

        // Check if loop was stopped or socket was closed
        if (bytesReceived == SOCKET_ERROR) {
            if (m_running) {
                // Unexpected error — log it
                std::cerr << "[GhostPort] WARNING: recvfrom() error on port "
                          << m_port << ". Continuing...\n";
            }
            // If !m_running, stop() was called — exit cleanly
            break;
        }

        // ── Parse sender address ─────────────────────────────────────────────
        char senderIPBuf[INET_ADDRSTRLEN];

#ifdef _WIN32
        // Windows uses InetNtop instead of inet_ntoa for thread-safety
        InetNtop(AF_INET, &senderAddr.sin_addr, senderIPBuf, INET_ADDRSTRLEN);
#else
        inet_ntop(AF_INET, &senderAddr.sin_addr, senderIPBuf, INET_ADDRSTRLEN);
#endif

        // ── Build KnockEvent ─────────────────────────────────────────────────
        KnockEvent event;
        event.sourceIP   = std::string(senderIPBuf);
        event.sourcePort = ntohs(senderAddr.sin_port);
        event.destPort   = m_port;
        event.payload    = std::string(buffer, bytesReceived);
        event.payloadSize = static_cast<size_t>(bytesReceived);

        // ── Fire the registered callback ─────────────────────────────────────
        //   If no handler was registered, just skip silently
        if (m_knockHandler) {
            m_knockHandler(event);
        }
    }

    std::cout << "[GhostPort] 🛑 Listener on UDP port " << m_port << " shut down cleanly.\n";
}


// ─── Private: Close Socket ────────────────────────────────────────────────────

void PacketListener::closeSocket() {
    if (m_socket != INVALID_SOCKET) {
#ifdef _WIN32
        closesocket(m_socket);
#else
        close(m_socket);
#endif
        m_socket = INVALID_SOCKET;
    }
}
