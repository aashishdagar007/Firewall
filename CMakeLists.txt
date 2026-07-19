cmake_minimum_required(VERSION 3.20)
project(AegisXII VERSION 2.0 LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

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
    GIT_TAG        master
)
FetchContent_MakeAvailable(sqlite3)

# GLFW
set(GLFW_BUILD_DOCS OFF CACHE BOOL "" FORCE)
set(GLFW_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(GLFW_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
FetchContent_Declare(glfw
    GIT_REPOSITORY https://github.com/glfw/glfw.git
    GIT_TAG        3.4
)
FetchContent_MakeAvailable(glfw)

# Dear ImGui
FetchContent_Declare(imgui
    GIT_REPOSITORY https://github.com/ocornut/imgui.git
    GIT_TAG        v1.90.8-docking
)
FetchContent_MakeAvailable(imgui)

# ── Include paths ──────────────────────────────────────────────────────────
include_directories(
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/core/src
    ${sqlite3_SOURCE_DIR}
    ${glfw_SOURCE_DIR}/include
    ${imgui_SOURCE_DIR}
    ${imgui_SOURCE_DIR}/backends
)

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

file(GLOB_RECURSE CORE_SOURCES "core/src/*.cpp")
file(GLOB_RECURSE GUI_SOURCES "gui/src/*.cpp")

set(SOURCES
    src/main.cpp
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
    target_link_libraries(AegisXII PRIVATE ws2_32 iphlpapi psapi shell32 opengl32)
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

file(COPY config DESTINATION ${CMAKE_BINARY_DIR})
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/logs)