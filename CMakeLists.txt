cmake_minimum_required(VERSION 3.16)

# ─── Project Definition ───────────────────────────────────────────────────────
project(GhostPort
    VERSION     3.0.0
    DESCRIPTION "Authenticated Port-Knocking / SPA Daemon"
    LANGUAGES   CXX
)

# ─── C++ Standard ────────────────────────────────────────────────────────────
# C++17 for std::filesystem (used in Milestone 2+ for config files)
set(CMAKE_CXX_STANDARD          17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS        OFF)   # No GNU extensions — keep it portable

# ─── Compiler Warnings ────────────────────────────────────────────────────────
# Good security engineering starts with clean, warning-free code.
if(MSVC)
    # Visual Studio / MSVC
    add_compile_options(/W4 /WX)
else()
    # GCC / Clang
    add_compile_options(-Wall -Wextra -Wpedantic -Wshadow)
endif()

# ─── Source Files ─────────────────────────────────────────────────────────────
set(SOURCES
    src/main.cpp
    src/PacketListener.cpp
    src/SequenceValidator.cpp
    src/HmacVerifier.cpp
    src/FirewallManager.cpp
    src/StateLedger.cpp
)

set(HEADERS
    src/PacketListener.h
    src/SequenceValidator.h
    src/HmacVerifier.h
    src/SpaPacket.h
    src/Sha256.h
    src/FirewallManager.h
    src/StateLedger.hpp
)

# ─── Executable Target ────────────────────────────────────────────────────────
add_executable(ghostport ${SOURCES} ${HEADERS})

# ─── Include Directories ──────────────────────────────────────────────────────
target_include_directories(ghostport PRIVATE src)

# ─── Platform-Specific Libraries ─────────────────────────────────────────────
if(WIN32)
    # Winsock2 library — required for socket(), bind(), recvfrom() on Windows
    target_link_libraries(ghostport PRIVATE ws2_32)
    message(STATUS "[GhostPort] Building for Windows — linking ws2_32")
else()
    message(STATUS "[GhostPort] Building for POSIX — no extra socket libs needed")
endif()

# ─── Build Type Info ──────────────────────────────────────────────────────────
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()
message(STATUS "[GhostPort] Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "[GhostPort] Target: ghostport v${PROJECT_VERSION}")
