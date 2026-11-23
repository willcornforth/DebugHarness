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
    src/server.cpp
    src/routes.cpp
    src/ui.cpp
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

# Optional ImGui panel (imgui/debug_harness_panel.*) -- not part of the library target.
# Built only when DEBUGHARNESS_IMGUI_DIR points at the directory holding the consumer's
# imgui.h. This target compiles ONLY the panel: it does not build Dear ImGui, create a
# context or pick a backend -- the consumer links its own imgui (same version as the
# headers in DEBUGHARNESS_IMGUI_DIR). Alternative without this target: add
# imgui/debug_harness_panel.cpp to the consumer's own project, with imgui.h and
# include/ on its include path, and link debug_harness.
set(DEBUGHARNESS_IMGUI_DIR "" CACHE PATH "Directory containing imgui.h; enables the debug_harness_imgui target")
if(DEBUGHARNESS_IMGUI_DIR)
    if(NOT EXISTS "${DEBUGHARNESS_IMGUI_DIR}/imgui.h")
        message(FATAL_ERROR "DEBUGHARNESS_IMGUI_DIR='${DEBUGHARNESS_IMGUI_DIR}' has no imgui.h")
    endif()
    add_library(debug_harness_imgui STATIC imgui/debug_harness_panel.cpp)
    add_library(debug_harness::imgui ALIAS debug_harness_imgui)
    target_include_directories(debug_harness_imgui
        PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/imgui ${DEBUGHARNESS_IMGUI_DIR}
    )
    target_link_libraries(debug_harness_imgui PUBLIC debug_harness)
    if(MSVC)
        target_compile_options(debug_harness_imgui PRIVATE /permissive- /EHsc /W4)
    endif()
endif()

option(DEBUGHARNESS_BUILD_EXAMPLES "Build examples/consumer (needs DEBUGHARNESS_IMGUI_DIR)" OFF)
if(DEBUGHARNESS_BUILD_EXAMPLES)
    add_subdirectory(examples/consumer)
endif()

if(DEBUGHARNESS_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
