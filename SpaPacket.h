/**
 * ============================================================
 *  GhostPort - SpaPacket.h
 *  Version: 4.0 (Milestone 4 - Windows Firewall Integration)
 * ============================================================
 *
 *  PURPOSE:
 *    Defines the exact binary layout of a GhostPort SPA packet
 *    as it appears on the wire (inside the UDP payload).
 *
 *  SPA PACKET WIRE FORMAT (42 bytes total):
 *
 *    ┌─────────┬──────────────┬───────────────────────────────┐
 *    │ Offset  │  Size (bytes)│  Field                        │
 *    ├─────────┼──────────────┼───────────────────────────────┤
 *    │    0    │      4       │  Magic  = 0x47 0x50 0x53 0x41 │
 *    │    4    │      4       │  Timestamp (Unix, big-endian) │
 *    │    8    │      2       │  Dest port (big-endian)       │
 *    │   10    │     32       │  HMAC-SHA256 signature        │
 *    └─────────┴──────────────┴───────────────────────────────┘
 *    Total: 42 bytes
 *
 *  WHAT THE HMAC SIGNS:
 *    The signature covers bytes[0..9] — magic + timestamp + destPort.
 *    This binds the token to a SPECIFIC port at a SPECIFIC time.
 *
 *    A knock captured on port 7000 CANNOT be replayed on port 8000,
 *    because the destPort field changes the signed message.
 *
 *  WHY BIG-ENDIAN?
 *    Network protocols (TCP, IP, UDP headers) are all big-endian
 *    (most significant byte first). We follow the same convention
 *    so any network tool or Wireshark capture reads values correctly.
 *    On x86 (little-endian), we must byte-swap when reading/writing.
 *
 *  AUTHOR:  Syed Haider Ali (FYP - GhostPort)
 * ============================================================
 */

#pragma once

#include <cstdint>
#include <cstring>
#include <array>
#include <string>
#include <sstream>
#include <iomanip>


// ─── SPA Protocol Constants ───────────────────────────────────────────────────

/// Magic header bytes: ASCII "GPSA" (GhostPort Single-packet Auth)
static constexpr uint8_t SPA_MAGIC[4] = { 0x47, 0x50, 0x53, 0x41 };

/// Total SPA packet size in bytes: 4 (magic) + 4 (ts) + 2 (port) + 32 (HMAC)
static constexpr size_t SPA_PACKET_SIZE = 42;

/// The signed payload region covers bytes 0..9 (everything except the HMAC)
static constexpr size_t SPA_SIGNED_SIZE = 10;

/// Offset within the packet where the HMAC signature begins
static constexpr size_t SPA_HMAC_OFFSET = 10;


// ─── ParsedSpaPacket ──────────────────────────────────────────────────────────

/**
 * @struct ParsedSpaPacket
 * @brief  The decoded fields of an SPA packet after parsing from raw bytes.
 *
 * This is what HmacVerifier works with. We parse the raw UDP payload
 * into this struct before any cryptographic validation.
 *
 * IMPORTANT: A successfully-parsed packet is NOT necessarily authentic.
 * Parsing only decodes the fields; HMAC verification is the authentication.
 */
struct ParsedSpaPacket {
    uint32_t               timestamp;    ///< Unix epoch timestamp (host byte order)
    uint16_t               destPort;     ///< Destination port (host byte order)
    std::array<uint8_t, 32> hmac;        ///< The 32-byte HMAC received in the packet
    uint8_t                signed_bytes[SPA_SIGNED_SIZE]; ///< Raw bytes that were signed
    bool                   valid;        ///< Did the packet pass structural parsing?

    ParsedSpaPacket() : timestamp(0), destPort(0), valid(false) {
        hmac.fill(0);
        memset(signed_bytes, 0, SPA_SIGNED_SIZE);
    }
};


// ─── Utility: Big-Endian Reader Helpers ──────────────────────────────────────

/**
 * @brief Read a 4-byte big-endian unsigned integer from a byte buffer.
 *
 * WHY NOT ntohl()?
 *   ntohl() (Network TO Host Long) does the same thing — converts from
 *   big-endian network order to host byte order. We implement it manually
 *   so this file has zero platform dependencies and works identically
 *   on both Windows (Winsock) and Linux.
 *
 *   Bit-shift version: reads byte[0] as most significant.
 *   On a little-endian machine:  byte[0]=0x01, [1]=0x02, [2]=0x03, [3]=0x04
 *   gives: (0x01 << 24) | (0x02 << 16) | (0x03 << 8) | 0x04 = 0x01020304 ✓
 */
inline uint32_t readBE32(const uint8_t* p) {
    return (uint32_t(p[0]) << 24)
         | (uint32_t(p[1]) << 16)
         | (uint32_t(p[2]) <<  8)
         |  uint32_t(p[3]);
}

/**
 * @brief Read a 2-byte big-endian unsigned short from a byte buffer.
 */
inline uint16_t readBE16(const uint8_t* p) {
    return static_cast<uint16_t>((uint16_t(p[0]) << 8) | uint16_t(p[1]));
}

/**
 * @brief Write a 4-byte big-endian uint32 into a byte buffer.
 */
inline void writeBE32(uint8_t* p, uint32_t v) {
    p[0] = static_cast<uint8_t>(v >> 24);
    p[1] = static_cast<uint8_t>(v >> 16);
    p[2] = static_cast<uint8_t>(v >>  8);
    p[3] = static_cast<uint8_t>(v      );
}

/**
 * @brief Write a 2-byte big-endian uint16 into a byte buffer.
 */
inline void writeBE16(uint8_t* p, uint16_t v) {
    p[0] = static_cast<uint8_t>(v >>  8);
    p[1] = static_cast<uint8_t>(v      );
}


// ─── SPA Packet Parser ────────────────────────────────────────────────────────

/**
 * @brief Parse raw UDP payload bytes into a ParsedSpaPacket.
 *
 * Performs structural validation only (magic, size).
 * DOES NOT verify the HMAC — that is HmacVerifier's job.
 *
 * @param rawData    Pointer to the raw UDP payload bytes.
 * @param rawLen     Length of the payload.
 * @return           Parsed packet (check .valid field).
 */
inline ParsedSpaPacket parseSpaPacket(const char* rawData, size_t rawLen) {
    ParsedSpaPacket pkt;

    // ── Check minimum size ────────────────────────────────────────────────────
    if (rawLen < SPA_PACKET_SIZE) {
        return pkt;   // valid = false
    }

    const uint8_t* buf = reinterpret_cast<const uint8_t*>(rawData);

    // ── Verify magic bytes ────────────────────────────────────────────────────
    //   A non-SPA UDP packet (e.g. a port scanner) won't have our magic.
    //   This lets us silently discard irrelevant traffic before touching crypto.
    if (memcmp(buf, SPA_MAGIC, 4) != 0) {
        return pkt;   // valid = false
    }

    // ── Extract fields ────────────────────────────────────────────────────────
    pkt.timestamp = readBE32(buf + 4);
    pkt.destPort  = readBE16(buf + 8);

    // Copy the 32-byte HMAC from offset 10
    memcpy(pkt.hmac.data(), buf + SPA_HMAC_OFFSET, 32);

    // Preserve the signed bytes (magic+timestamp+destPort) for HMAC verification
    memcpy(pkt.signed_bytes, buf, SPA_SIGNED_SIZE);

    pkt.valid = true;
    return pkt;
}


// ─── SPA Packet Builder (Client-side helper) ──────────────────────────────────

/**
 * @brief Build a complete SPA packet ready to send.
 *
 * Used by test utilities and the knock client script.
 * In production, the CLIENT runs this to construct a valid knock.
 *
 * @param timestamp   Unix epoch (seconds). Must match server's clock ±30s.
 * @param destPort    The port this packet will be knocked on.
 * @param hmac        The pre-computed 32-byte HMAC-SHA256 signature.
 * @return            42-byte packet buffer.
 */
inline std::array<uint8_t, SPA_PACKET_SIZE> buildSpaPacket(
    uint32_t                        timestamp,
    uint16_t                        destPort,
    const std::array<uint8_t, 32>&  hmac
) {
    std::array<uint8_t, SPA_PACKET_SIZE> pkt{};

    // Magic
    memcpy(pkt.data(), SPA_MAGIC, 4);

    // Timestamp (big-endian)
    writeBE32(pkt.data() + 4, timestamp);

    // Dest port (big-endian)
    writeBE16(pkt.data() + 8, destPort);

    // HMAC signature
    memcpy(pkt.data() + SPA_HMAC_OFFSET, hmac.data(), 32);

    return pkt;
}


// ─── Utility: Format HMAC as hex for display ──────────────────────────────────

inline std::string hmacToHex(const std::array<uint8_t, 32>& h) {
    std::ostringstream oss;
    for (uint8_t b : h)
        oss << std::hex << std::setfill('0') << std::setw(2)
            << static_cast<unsigned>(b);
    return oss.str();
}
