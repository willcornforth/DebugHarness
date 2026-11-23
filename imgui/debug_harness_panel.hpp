#pragma once

#include <functional>
#include <string>

#include "debug_harness/ui.hpp"

// Optional Dear ImGui renderer for the Debug Harness window.
//
// NOT part of the debug_harness library target. Either build the `debug_harness_imgui`
// CMake target (configure with -DDEBUGHARNESS_IMGUI_DIR=<your imgui checkout>), or add
// imgui/debug_harness_panel.cpp straight to your own project. Either way it includes
// "imgui.h" from YOUR include path and links against YOUR ImGui: the harness never
// creates an ImGui context, a backend, a device or a window.
//
// Call these from inside your own ImGui frame -- between your ImGui::NewFrame() and
// ImGui::Render() -- on the render thread, with your context current:
//
//     debug_harness::on_frame();                       // drain run_on_game_thread jobs
//     if (show) debug_harness::panel::draw_window(&show);
namespace debug_harness::panel {

    // A whole window: ImGui::Begin(title, open) ... ImGui::End().
    void draw_window(bool* open, const char* title = "Debug Harness");

    // Just the contents, for embedding in a window (or tab) the host already began.
    void draw_contents();

    // The model the panel draws. Use it to pre-fill expressions, pin watches, or start
    // the server programmatically.
    ui::session& session();

    // Append a host section, drawn under a collapsing header after the built-in ones.
    // `draw` runs inside the panel's window with the host's ImGui context current.
    // Re-adding a name replaces its callback.
    void add_section(const std::string& name, std::function<void()> draw, bool default_open = false);
    void remove_section(const std::string& name);
}
