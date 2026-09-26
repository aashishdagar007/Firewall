cmake_minimum_required(VERSION 3.20)
project(AegisXII VERSION 2.0 LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(MSVC)
    add_compile_options(/W4 /WX /utf-8 /permissive- /wd4996 /wd4267 /wd4244)
else()
    add_compile_options(-Wall -Wextra -Wpedantic -fstack-protector-strong)
    add_compile_definitions(_FORTIFY_SOURCE=2)
endif()

# ── Dependencies via FetchContent ──────────────────────────────────────────
include(FetchContent)

# SQLite3
FetchContent_Declare(sqlite3
    GIT_REPOSITORY https://github.com/azadkuh/sqlite-amalgamation.git
    # Pin to an immutable commit so clean builds resolve the same source.
    GIT_TAG        15d0ff10ebc7e7225eced1de84bb52137000899b
)
FetchContent_MakeAvailable(sqlite3)

# GLFW
set(GLFW_BUILD_DOCS OFF CACHE BOOL "" FORCE)
set(GLFW_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(GLFW_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
FetchContent_Declare(glfw
    GIT_REPOSITORY https://github.com/glfw/glfw.git
    GIT_TAG        7b6aead9fb88b3623e3b3725ebb42670cbe4c579
)
FetchContent_MakeAvailable(glfw)

# Dear ImGui
FetchContent_Declare(imgui
    GIT_REPOSITORY https://github.com/ocornut/imgui.git
    GIT_TAG        6d948ab47ecf984239af01434f3ed03808dbf188
)
FetchContent_MakeAvailable(imgui)

# ── Include paths ──────────────────────────────────────────────────────────
include_directories(
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/core/src
    ${CMAKE_SOURCE_DIR}/core/src/net
    ${CMAKE_SOURCE_DIR}/core/src/engine
    ${CMAKE_SOURCE_DIR}/core/src/util
    ${CMAKE_SOURCE_DIR}/core/src/persistence
    ${CMAKE_SOURCE_DIR}/core/src/ipc
    ${CMAKE_SOURCE_DIR}/core/src/kernel
    ${CMAKE_SOURCE_DIR}/gui/src
    ${sqlite3_SOURCE_DIR}
    ${glfw_SOURCE_DIR}/include
    ${imgui_SOURCE_DIR}
    ${imgui_SOURCE_DIR}/backends
)

# ── AddressSanitizer (ASan) ────────────────────────────────────────────────
option(ENABLE_ASAN "Enable AddressSanitizer" OFF)
if(ENABLE_ASAN)
    message(STATUS "AddressSanitizer enabled for extreme fuzzing/memory detection")
    if(MSVC)
        add_compile_options(/fsanitize=address)
    else()
        add_compile_options(-fsanitize=address -fno-omit-frame-pointer)
        add_link_options(-fsanitize=address)
    endif()
endif()

# ── Source files ───────────────────────────────────────────────────────────
set(IMGUI_SOURCES
    ${imgui_SOURCE_DIR}/imgui.cpp
    ${imgui_SOURCE_DIR}/imgui_demo.cpp
    ${imgui_SOURCE_DIR}/imgui_draw.cpp
    ${imgui_SOURCE_DIR}/imgui_tables.cpp
    ${imgui_SOURCE_DIR}/imgui_widgets.cpp
    ${imgui_SOURCE_DIR}/backends/imgui_impl_glfw.cpp
    ${imgui_SOURCE_DIR}/backends/imgui_impl_opengl3.cpp
)

file(GLOB_RECURSE CORE_SOURCES CONFIGURE_DEPENDS "core/src/*.cpp")
file(GLOB_RECURSE GUI_SOURCES CONFIGURE_DEPENDS "gui/src/*.cpp")

set(SOURCES
    src/main.cpp
    src/api_server.cpp
    src/ipc_server.cpp
    src/updater.cpp
    src/diode_threat_engine.cpp
    src/diode_streamer.cpp
    ${CORE_SOURCES}
    ${GUI_SOURCES}
    ${IMGUI_SOURCES}
)

# ── Executable ─────────────────────────────────────────────────────────────
if(WIN32)
    # Using WINDOWS subsystem hides the console window. 
    # For AegisXII, we might want it hidden when run normally (GUI pops up).
    add_executable(AegisXII WIN32 ${SOURCES})
else()
    add_executable(AegisXII ${SOURCES})
endif()

# ── Linking ────────────────────────────────────────────────────────────────
find_package(Threads REQUIRED)
target_link_libraries(AegisXII PRIVATE Threads::Threads SQLite3 glfw)

if(WIN32)
    if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        target_link_options(AegisXII PRIVATE -static -static-libgcc -static-libstdc++)
    endif()
    target_link_libraries(AegisXII PRIVATE ws2_32 iphlpapi psapi shell32 opengl32 wintrust)
    target_compile_definitions(AegisXII PRIVATE _WIN32_WINNT=0x0A00 _CRT_SECURE_NO_WARNINGS)

    if(DEFINED WINDIVERT_DIR)
        target_include_directories(AegisXII PRIVATE "${WINDIVERT_DIR}/include")
        target_link_directories(AegisXII PRIVATE "${WINDIVERT_DIR}/x64")
        target_link_libraries(AegisXII PRIVATE WinDivert)
        target_compile_definitions(AegisXII PRIVATE HAVE_WINDIVERT)
    endif()
endif()

find_package(OpenSSL)
if(OpenSSL_FOUND)
    target_link_libraries(AegisXII PRIVATE OpenSSL::SSL OpenSSL::Crypto)
    target_compile_definitions(AegisXII PRIVATE CPPHTTPLIB_OPENSSL_SUPPORT)
endif()

# ══════════════════════════════════════════════════════════════════════════════
#  Platform-specific configuration
# ══════════════════════════════════════════════════════════════════════════════

if(WIN32)
    # ── Windows ─────────────────────────────────────────────────────────────
    message(STATUS "Platform: Windows")

    # Winsock2 (ws2_32) — always needed
    target_link_libraries(AegisXII PRIVATE ws2_32)

    # Windows Security & Cryptography APIs (privilege checks, DACL, DPAPI)
    target_link_libraries(AegisXII PRIVATE advapi32 crypt32 winhttp)

    # iphlpapi — GetExtendedTcpTable/GetExtendedUdpTable (process_monitor)
    target_link_libraries(AegisXII PRIVATE iphlpapi)

    # psapi — QueryFullProcessImageName (process_monitor, pipe client verification)
    target_link_libraries(AegisXII PRIVATE psapi)

    # shell32 — ShellExecuteW (open_browser in main.cpp)
    target_link_libraries(AegisXII PRIVATE shell32)

    # MinGW static runtime (no DLL dependency in the exe)
    if(MINGW)
        target_link_options(AegisXII PRIVATE -static -static-libgcc -static-libstdc++)
        message(STATUS "Toolchain: MinGW-w64 (static runtime)")
    endif()

    # ── WinDivert (optional — enables real packet blocking on Windows) ──────
    # Download WinDivert from https://reqrypt.org/windivert.html
    # and place WinDivert64.dll + WinDivert.lib next to the executable,
    # or set WINDIVERT_DIR in CMake cache to the extracted folder.
    if(DEFINED WINDIVERT_DIR AND EXISTS "${WINDIVERT_DIR}/include/windivert.h")
        message(STATUS "Found WinDivert at ${WINDIVERT_DIR} — real blocking enabled")
        target_include_directories(AegisXII PRIVATE "${WINDIVERT_DIR}/include")
        target_link_directories(AegisXII PRIVATE "${WINDIVERT_DIR}/x64")
        target_link_libraries(AegisXII PRIVATE WinDivert)
        target_compile_definitions(AegisXII PRIVATE HAVE_WINDIVERT)
    else()
        message(STATUS "WinDivert NOT found — observer mode only")
        message(STATUS "  To enable real blocking:")
        message(STATUS "    1. Download WinDivert from https://reqrypt.org/windivert.html")
        message(STATUS "    2. cmake .. -DWINDIVERT_DIR=<path>")
    endif()

    # Windows needs _WIN32_WINNT set (Vista+ for Winsock features used)
    target_compile_definitions(AegisXII PRIVATE
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
        target_compile_definitions(AegisXII PRIVATE HAVE_NFQUEUE)
        target_link_libraries(AegisXII PRIVATE ${NFQ_LIB})
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
#  Tests
# ══════════════════════════════════════════════════════════════════════════════
include(CTest)
if(BUILD_TESTING)
    FetchContent_Declare(googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG        8ad598c73ad796e0d8280b082cebd82a630d73e3
    )
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)

    set(ENGINE_TEST_SOURCES
        core/src/net/packet.cpp
        core/src/engine/rule_engine.cpp
        core/src/engine/dpi_engine.cpp
        core/src/engine/port_scan_detector.cpp
        src/diode_threat_engine.cpp
        src/diode_streamer.cpp
    )
    add_executable(test_engine tests/test_engine.cpp ${ENGINE_TEST_SOURCES})
    target_link_libraries(test_engine PRIVATE Threads::Threads GTest::gtest_main)
    add_test(NAME rule_engine_test COMMAND test_engine)

    add_executable(test_packet tests/test_packet.cpp core/src/net/packet.cpp)
    target_link_libraries(test_packet PRIVATE GTest::gtest_main)
    add_test(NAME packet_parser_test COMMAND test_packet)

    add_executable(test_threat_detection
        tests/test_threat_detection.cpp
        src/diode_threat_engine.cpp
        src/diode_streamer.cpp
    )
    target_link_libraries(test_threat_detection PRIVATE Threads::Threads)
    add_test(NAME threat_detection_test COMMAND test_threat_detection)
    set_tests_properties(threat_detection_test PROPERTIES
        LABELS "diode;ai;threat-detection"
        TIMEOUT 60
    )

    add_executable(test_security
        tests/test_security.cpp
        core/src/net/packet.cpp
        core/src/engine/rule_engine.cpp
        core/src/engine/dpi_engine.cpp
        core/src/engine/port_scan_detector.cpp
        core/src/persistence/config_parser.cpp
        core/src/util/logger.cpp
        src/ipc_server.cpp
        src/updater.cpp
        src/diode_threat_engine.cpp
        src/diode_streamer.cpp
    )
    target_link_libraries(test_security PRIVATE Threads::Threads)
    add_test(NAME security_hardening_test COMMAND test_security)

    if(WIN32)
        target_link_libraries(test_engine PRIVATE ws2_32)
        target_link_libraries(test_packet PRIVATE ws2_32)
        target_link_libraries(test_threat_detection PRIVATE ws2_32)
        target_link_libraries(test_security PRIVATE ws2_32 advapi32 crypt32 winhttp iphlpapi psapi)
    endif()
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
