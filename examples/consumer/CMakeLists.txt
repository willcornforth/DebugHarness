# Example consumer DLL. Not built by default: configure the top-level project with
#   -DDEBUGHARNESS_BUILD_EXAMPLES=ON -DDEBUGHARNESS_IMGUI_DIR=<dir containing imgui.h>
#
# A real consumer already compiles Dear ImGui (and its backends) as part of its own
# overlay. This example has no overlay, so it compiles the ImGui core sources itself
# purely to link; it creates no context and no backend -- that is the host's job.
if(NOT DEBUGHARNESS_IMGUI_DIR)
    message(FATAL_ERROR "examples/consumer needs DEBUGHARNESS_IMGUI_DIR (the host's Dear ImGui checkout)")
endif()

add_library(debug_harness_consumer SHARED
    consumer_dll.cpp
    # Stand-in for the host's own ImGui build:
    ${DEBUGHARNESS_IMGUI_DIR}/imgui.cpp
    ${DEBUGHARNESS_IMGUI_DIR}/imgui_draw.cpp
    ${DEBUGHARNESS_IMGUI_DIR}/imgui_tables.cpp
    ${DEBUGHARNESS_IMGUI_DIR}/imgui_widgets.cpp
)
target_link_libraries(debug_harness_consumer PRIVATE debug_harness_imgui)
if(MSVC)
    set_source_files_properties(consumer_dll.cpp PROPERTIES COMPILE_OPTIONS "/W4;/permissive-;/EHsc")
endif()
