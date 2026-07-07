cmake_minimum_required(VERSION 3.20)
project(Firewall VERSION 2.0 LANGUAGES CXX)

# ── C++17 ──────────────────────────────────────────────────────────────────
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ── Compiler warnings ──────────────────────────────────────────────────────
if(MSVC)
    add_compile_options(/W4 /WX- /utf-8 /permissive-)
    # Suppress common warnings from third-party headers (httplib)
    add_compile_options(/wd4996 /wd4267 /wd4244)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# ── Include paths ──────────────────────────────────────────────────────────
include_directories(${CMAKE_SOURCE_DIR}/include)

# ── Source files ───────────────────────────────────────────────────────────
set(SOURCES
    src/main.cpp
    src/packet.cpp
    src/rule_engine.cpp
    src/logger.cpp
    src/config_parser.cpp
    src/nfq_capture.cpp
    src/api_server.cpp
    src/process_monitor.cpp
    src/dpi_engine.cpp
    src/port_scan_detector.cpp
    src/nat_engine.cpp
    src/vpn_manager.cpp
    src/traffic_shaper.cpp
    src/updater.cpp
)

# ── Executable ─────────────────────────────────────────────────────────────
# WIN32 keyword → /SUBSYSTEM:WINDOWS — suppresses the console window on Windows.
# The firewall runs silently; the dashboard opens in the browser automatically.
if(WIN32)
    add_executable(firewall WIN32 ${SOURCES})
else()
    add_executable(firewall ${SOURCES})
endif()

# ── Threads ────────────────────────────────────────────────────────────────
find_package(Threads REQUIRED)
target_link_libraries(firewall PRIVATE Threads::Threads)

# ── OpenSSL (Optional for HTTPS API Server) ────────────────────────────────
find_package(OpenSSL)
if(OpenSSL_FOUND)
    message(STATUS "Found OpenSSL: Enabling HTTPS API Server")
    target_link_libraries(firewall PRIVATE OpenSSL::SSL OpenSSL::Crypto)
    target_compile_definitions(firewall PRIVATE CPPHTTPLIB_OPENSSL_SUPPORT)
else()
    message(STATUS "OpenSSL NOT found: API Server will run in HTTP mode")
endif()

# ══════════════════════════════════════════════════════════════════════════════
#  Platform-specific configuration
# ══════════════════════════════════════════════════════════════════════════════

if(WIN32)
    # ── Windows ─────────────────────────────────────────────────────────────
    message(STATUS "Platform: Windows")

    # Winsock2 (ws2_32) — always needed
    target_link_libraries(firewall PRIVATE ws2_32)

    # iphlpapi — GetExtendedTcpTable/GetExtendedUdpTable (process_monitor)
    target_link_libraries(firewall PRIVATE iphlpapi)

    # psapi — QueryFullProcessImageName (process_monitor)
    target_link_libraries(firewall PRIVATE psapi)

    # shell32 — ShellExecuteW (open_browser in main.cpp)
    target_link_libraries(firewall PRIVATE shell32)

    # MinGW static runtime (no DLL dependency in the exe)
    if(MINGW)
        target_link_options(firewall PRIVATE -static -static-libgcc -static-libstdc++)
        message(STATUS "Toolchain: MinGW-w64 (static runtime)")
    endif()

    # ── WinDivert (optional — enables real packet blocking on Windows) ──────
    # Download WinDivert from https://reqrypt.org/windivert.html
    # and place WinDivert64.dll + WinDivert.lib next to the executable,
    # or set WINDIVERT_DIR in CMake cache to the extracted folder.
    if(DEFINED WINDIVERT_DIR AND EXISTS "${WINDIVERT_DIR}/include/windivert.h")
        message(STATUS "Found WinDivert at ${WINDIVERT_DIR} — real blocking enabled")
        target_include_directories(firewall PRIVATE "${WINDIVERT_DIR}/include")
        target_link_directories(firewall PRIVATE "${WINDIVERT_DIR}/x64")
        target_link_libraries(firewall PRIVATE WinDivert)
        target_compile_definitions(firewall PRIVATE HAVE_WINDIVERT)
    else()
        message(STATUS "WinDivert NOT found — observer mode only")
        message(STATUS "  To enable real blocking:")
        message(STATUS "    1. Download WinDivert from https://reqrypt.org/windivert.html")
        message(STATUS "    2. cmake .. -DWINDIVERT_DIR=<path>")
    endif()

    # Windows needs _WIN32_WINNT set (Vista+ for Winsock features used)
    target_compile_definitions(firewall PRIVATE
        _WIN32_WINNT=0x0A00   # Windows 10+ (required by httplib.h)
        _CRT_SECURE_NO_WARNINGS
    )

else()
    # ── Linux / macOS ────────────────────────────────────────────────────────
    message(STATUS "Platform: ${CMAKE_SYSTEM_NAME}")

    # libnetfilter_queue (optional — enables real blocking on Linux)
    find_library(NFQ_LIB NAMES netfilter_queue)
    if(NFQ_LIB)
        message(STATUS "Found libnetfilter_queue: ${NFQ_LIB} — real blocking enabled")
        target_compile_definitions(firewall PRIVATE HAVE_NFQUEUE)
        target_link_libraries(firewall PRIVATE ${NFQ_LIB})
    else()
        message(STATUS "libnetfilter_queue NOT found — raw socket observer mode only")
        message(STATUS "  Install with: sudo apt install libnetfilter-queue-dev")
    endif()

endif()

# ══════════════════════════════════════════════════════════════════════════════
#  Build assets (config + dashboard copied next to the executable)
# ══════════════════════════════════════════════════════════════════════════════
file(COPY config    DESTINATION ${CMAKE_BINARY_DIR})
file(COPY dashboard DESTINATION ${CMAKE_BINARY_DIR})
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/logs)
# Phase 2: cloud control plane bootstrap config
if(EXISTS "${CMAKE_SOURCE_DIR}/config/cloud_config.json")
    file(COPY "${CMAKE_SOURCE_DIR}/config/cloud_config.json"
         DESTINATION "${CMAKE_BINARY_DIR}/config")
endif()

# ══════════════════════════════════════════════════════════════════════════════
#  Testing
# ══════════════════════════════════════════════════════════════════════════════
enable_testing()

# Fetch GoogleTest
include(FetchContent)
FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/03597a01ee50ed33e9dfd640b249b4be3799d395.zip
)
# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

add_executable(test_engine 
    tests/test_engine.cpp 
    tests/test_packet.cpp 
    tests/test_vpn_crypto.cpp 
    tests/test_traffic_shaper.cpp
    src/packet.cpp 
    src/rule_engine.cpp 
    src/dpi_engine.cpp 
    src/port_scan_detector.cpp 
    src/traffic_shaper.cpp 
    src/vpn_manager.cpp
)
if(WIN32)
    target_link_libraries(test_engine PRIVATE ws2_32)
endif()
if(OpenSSL_FOUND)
    target_link_libraries(test_engine PRIVATE OpenSSL::SSL OpenSSL::Crypto)
endif()
target_include_directories(test_engine PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(test_engine PRIVATE gtest_main)

include(GoogleTest)
gtest_discover_tests(test_engine)

# Benchmark Engine
add_executable(benchmark_engine 
    tests/benchmark_engine.cpp 
    src/packet.cpp 
    src/rule_engine.cpp 
    src/dpi_engine.cpp 
    src/port_scan_detector.cpp 
    src/traffic_shaper.cpp 
    src/vpn_manager.cpp
)
target_include_directories(benchmark_engine PRIVATE ${CMAKE_SOURCE_DIR}/include)
if(WIN32)
    target_link_libraries(benchmark_engine PRIVATE ws2_32)
endif()
if(OpenSSL_FOUND)
    target_link_libraries(benchmark_engine PRIVATE OpenSSL::SSL OpenSSL::Crypto)
endif()

# ── Summary ────────────────────────────────────────────────────────────────
message(STATUS "")
message(STATUS "════════════════════════════════════════════")
message(STATUS " Firewall v2  build summary")
message(STATUS "════════════════════════════════════════════")
message(STATUS "  Build type : ${CMAKE_BUILD_TYPE}")
message(STATUS "  Compiler   : ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "  Standard   : C++${CMAKE_CXX_STANDARD}")
message(STATUS "")
message(STATUS "  Phase 2 Architecture:")
message(STATUS "    Pillar 1 ─ Port Demux (WinDivert DPI interceptor)")
message(STATUS "    Pillar 2 ─ BVUDP Batch-Verified UDP protocol stack")
message(STATUS "    Pillar 3 ─ Cloud Control Plane client")
message(STATUS "    Pillar 4 ─ Tamper-Proof Hash-Chain Ledger")
message(STATUS "    Crypto   ─ SHA-256 (header-only, zero deps)")
if(WIN32)
    message(STATUS "  Windows    : Observer mode (ws2_32)")
    message(STATUS "  Blocking   : WinDivert (set WINDIVERT_DIR to enable)")
    message(STATUS "")
    message(STATUS "  Run as Administrator in PowerShell:")
    message(STATUS "    cd cmake-build-debug")
    message(STATUS "    .\\firewall.exe")
    message(STATUS "  Cloud endpoint: set AEGIS_CONTROL_URL=http://your-api/config")
else()
    message(STATUS "  Linux      : NFQ mode available")
    message(STATUS "")
    message(STATUS "  iptables setup (run once before daemon):")
    message(STATUS "    sudo iptables -I INPUT   -j NFQUEUE --queue-num 0")
    message(STATUS "    sudo iptables -I OUTPUT  -j NFQUEUE --queue-num 0")
    message(STATUS "    sudo iptables -I FORWARD -j NFQUEUE --queue-num 0")
    message(STATUS "  Then: cd cmake-build-debug && sudo ./firewall")
endif()
message(STATUS "════════════════════════════════════════════")