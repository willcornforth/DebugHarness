cmake_minimum_required(VERSION 3.25)
project(DebugHarness LANGUAGES CXX)

if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "debug_harness is x64-only (it reasons about 64-bit PE images and qwords)")
endif()

set(DEBUGHARNESS_TOP_LEVEL OFF)
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    set(DEBUGHARNESS_TOP_LEVEL ON)
endif()

option(DEBUGHARNESS_BUILD_TESTS "Build the debug_harness host tests" ${DEBUGHARNESS_TOP_LEVEL})

add_library(debug_harness STATIC
    src/expr.cpp
    src/http.cpp
    src/mem.cpp
    src/inspect.cpp
    src/live.cpp
    src/scan.cpp
    src/host.cpp
    src/game_thread_stub.cpp
)
add_library(debug_harness::debug_harness ALIAS debug_harness)

target_include_directories(debug_harness
    PUBLIC  ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src
)
target_compile_features(debug_harness PUBLIC cxx_std_23)
if(MSVC)
    # The source used /std:c++23preview; /std:c++latest is the CMake-portable spelling.
    # PUBLIC so the tests (and a consumer's TUs including our headers) agree on the
    # language level; warnings and conformance flags stay private to the library.
    target_compile_options(debug_harness PUBLIC /std:c++latest PRIVATE /permissive- /EHsc /W4)
    target_compile_definitions(debug_harness PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()
# Keep <Windows.h> from dragging in winsock 1 (the server uses winsock2) and min/max.
target_compile_definitions(debug_harness PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
target_link_libraries(debug_harness PUBLIC ws2_32)

# Optional ImGui panel (imgui/DebugHarnessPanel.*) -- not part of the library target.
# Built only when the consumer points DEBUGHARNESS_IMGUI_DIR at a Dear ImGui checkout.
# set(DEBUGHARNESS_IMGUI_DIR "" CACHE PATH "Dear ImGui source dir; enables the debug_harness_panel target")
# if(DEBUGHARNESS_IMGUI_DIR)
#     add_library(debug_harness_panel STATIC ...)
# endif()

if(DEBUGHARNESS_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
