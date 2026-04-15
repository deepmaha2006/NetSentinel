cmake_minimum_required(VERSION 3.15)
project(NetSentinel VERSION 1.0.0 LANGUAGES CXX)

# ── C++20 standard ───────────────────────────────────────────────────────────
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ── Release build flags for performance ──────────────────────────────────────
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# ── Boost dependencies ───────────────────────────────────────────────────────
find_package(Boost REQUIRED COMPONENTS
    program_options
    system
)

# ── Executable ───────────────────────────────────────────────────────────────
add_executable(NetSentinel
    main.cpp
    src/PortScanner.hpp
    src/PortScanner.cpp
)

target_include_directories(NetSentinel PRIVATE ${CMAKE_SOURCE_DIR}/src)

target_link_libraries(NetSentinel
    Boost::program_options
    Boost::system
)

# ── Windows: link to ws2_32 (Winsock) ────────────────────────────────────────
if(WIN32)
    target_link_libraries(NetSentinel ws2_32 mswsock)
endif()

# ── Compiler warnings ─────────────────────────────────────────────────────────
if(MSVC)
    target_compile_options(NetSentinel PRIVATE /W4)
else()
    target_compile_options(NetSentinel PRIVATE -Wall -Wextra -Wpedantic)
endif()

message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "Boost version: ${Boost_VERSION}")
