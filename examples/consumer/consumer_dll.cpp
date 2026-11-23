// Minimal consumer of debug_harness: a DLL that already lives inside a host process
// and already renders Dear ImGui from a hook of its own.
//
// THE IMGUI CONTEXT, THE PLATFORM/RENDERER BACKENDS, THE D3D DEVICE AND THE PRESENT
// HOOK ALL BELONG TO THE HOST DLL. debug_harness never creates or initialises any of
// them. All this file adds to an existing overlay is:
//
//   1. configure() once, from DllMain       -- stores callbacks only; DllMain-safe
//   2. register_route() for host endpoints  -- handlers marshal onto the render thread
//   3. on_frame() + panel::draw_window()    -- from the host's existing ImGui frame
//
// The exported consumer_on_imgui_frame() stands in for "the host's per-frame ImGui
// callback": in a real overlay these two calls go inside the function that already
// sits between ImGui::NewFrame() and ImGui::Render().

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <format>
#include <string>
#include <vector>

#include "imgui.h"

#include "debug_harness/harness.hpp"
#include "debug_harness/server.hpp"
#include "debug_harness_panel.hpp"

namespace {

    // Stand-in for host state worth inspecting: in a game this would be the local
    // player, the world, a manager singleton...
    struct host_state {
        uint64_t magic = 0x5453414F48ull; // "HOAST"
        uint32_t counter = 0;
        float health = 100.f;
        host_state* self = this;
    };
    host_state state;

    std::atomic<uint64_t> frame_count{0};
    bool show_panel = true;
    bool started_server = false;

    void host_log(debug_harness::log_level level, const std::string& message) {
        static const char* const names[] = {"debug", "info", "warning", "error"};
        OutputDebugStringA(std::format("[harness:{}] {}\n", names[static_cast<int>(level)], message).c_str());
    }

    // 1. configure. Called from DllMain: it only stores std::functions, so it takes no
    //    loader lock-sensitive action (no LoadLibrary, no threads, no sockets).
    void configure_harness() {
        debug_harness::host_config config;
        config.module_name = nullptr; // ida:/rva:/@base refer to the host exe; or name a module

        config.resolve_root = [](const std::string& name, uint64_t& out_value, std::string& out_note) {
            if (name != "host.state") return false;
            out_value = reinterpret_cast<uint64_t>(&state);
            out_note = "example host_state";
            return true;
        };
        config.enumerate_roots = [] {
            return std::vector<debug_harness::root_entry>{
                {"host.state", reinterpret_cast<uint64_t>(&state), true, "example host_state"}};
        };

        // Named addends, e.g. @host.state+State::OFF_HEALTH
        config.resolve_symbol = [](const std::string& qualified, uint64_t& out_value) {
            if (qualified == "State::OFF_COUNTER") out_value = offsetof(host_state, counter);
            else if (qualified == "State::OFF_HEALTH") out_value = offsetof(host_state, health);
            else if (qualified == "State::OFF_SELF") out_value = offsetof(host_state, self);
            else return false;
            return true;
        };
        config.enumerate_symbols = [] {
            return std::vector<debug_harness::symbol_entry>{
                {"State", "OFF_COUNTER", offsetof(host_state, counter)},
                {"State", "OFF_HEALTH", offsetof(host_state, health)},
                {"State", "OFF_SELF", offsetof(host_state, self)},
            };
        };

        config.log = host_log;
        debug_harness::configure(std::move(config));
    }

    // 2. A host-specific endpoint. Route handlers run on the server thread, so anything
    //    touching host state is posted to the render thread with run_on_game_thread and
    //    picked up by on_frame(). A host that stops rendering answers 504, not a hang.
    //    (This is the pattern a game-specific /script endpoint uses.)
    void register_host_routes() {
        debug_harness::register_route(
            "/host/state",
            [](const debug_harness::http::request& request, int& out_status) {
                uint32_t counter = 0;
                float health = 0.f;
                const bool bump = request.get_bool("bump", false);
                const bool ran = debug_harness::run_on_game_thread([&] {
                    if (bump) ++state.counter;
                    counter = state.counter;
                    health = state.health;
                });
                if (!ran) {
                    out_status = 504;
                    return std::string(R"({"ok":false,"error":"host did not run the job in time"})");
                }
                out_status = 200;
                debug_harness::json::writer json;
                json.begin_object()
                    .key("ok").boolean(true)
                    .key("frame").u64(frame_count.load())
                    .key("counter").u64(counter)
                    .key("health").num(health)
                    .end_object();
                return json.take();
            },
            "example host state, read on the render thread; ?bump=1 increments the counter");
    }

    // An extra section in the panel, drawn with the host's ImGui context current.
    void register_host_sections() {
        debug_harness::panel::add_section("Host state", [] {
            ImGui::Text("frame %llu", static_cast<unsigned long long>(frame_count.load()));
            ImGui::SliderFloat("health", &state.health, 0.f, 100.f);
            if (ImGui::Button("Bump counter")) ++state.counter;
            ImGui::SameLine();
            ImGui::Text("counter = %u", state.counter);
        }, true);
    }
}

// 3. The host's existing per-frame ImGui callback. Assumes the host has already called
//    its backends' NewFrame() and ImGui::NewFrame(), and will call ImGui::Render()
//    afterwards. The harness only draws into the frame.
extern "C" __declspec(dllexport) void consumer_on_imgui_frame() {
    ++frame_count;

    // Drains run_on_game_thread jobs. Call it every frame, even when the panel is
    // hidden, or host routes time out with 504.
    debug_harness::on_frame();

    // Start the listener from the render thread, not DllMain (it spawns a thread and
    // opens a socket). Loopback only. A real host might do this from a button instead:
    // the panel's Server section has one.
    if (!started_server) {
        started_server = true;
        debug_harness::panel::session().server.start();
    }

    if (ImGui::IsKeyPressed(ImGuiKey_Insert, false)) show_panel = !show_panel;
    if (show_panel) debug_harness::panel::draw_window(&show_panel);
}

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID) {
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(module);
        configure_harness();
        register_host_routes();
        register_host_sections();
        break;
    case DLL_PROCESS_DETACH:
        // Joining the server thread under the loader lock can deadlock; a real host
        // calls debug_harness::stop() from its own shutdown path before unloading.
        break;
    default:
        break;
    }
    return TRUE;
}
