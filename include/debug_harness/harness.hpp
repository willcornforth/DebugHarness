#pragma once
#include <cstdint>
#include <functional>
#include <string>
#include <vector>
#include "debug_harness/http.hpp"

namespace debug_harness {

    enum class log_level { debug, info, warning, error };

    struct root_entry {
        std::string name;
        uint64_t value = 0;
        bool valid = false;
        std::string note;
    };

    struct symbol_entry {  // one named constant, e.g. {"Player","OFF_HEALTH",0x130}
        std::string ns;  // "" for root-level names
        std::string name;
        uint64_t value = 0;
    };

    struct log_entry {
        uint64_t index = 0;
        log_level level = log_level::info;
        std::string text;
        uint64_t timestamp_ms = 0;
        std::string trace; // optional, already formatted
    };

    struct host_config {
        const char* module_name = nullptr; // module that ida:/rva:/@base/scan refer to; nullptr = main exe

        // "@name" roots. Called on the thread doing the evaluation (server or render thread).
        std::function<bool(const std::string& name, uint64_t& out_value, std::string& out_note)> resolve_root;
        std::function<std::vector<root_entry>()> enumerate_roots;

        // Named addends: "Ns::NAME" or bare "NAME".
        std::function<bool(const std::string& qualified, uint64_t& out_value)> resolve_symbol;
        std::function<std::vector<symbol_entry>()> enumerate_symbols;

        std::function<void(log_level, const std::string&)> log;
        std::function<std::vector<log_entry>()> log_entries; // enables GET /log
    };

    // Call once, before start(). May be called again (replaces the config); not thread-safe
    // against a running server -- stop() first.
    void configure(host_config config);
    const host_config& config();

    // Call ONCE PER FRAME from the host's render thread (e.g. top of its ImGui frame).
    // Drains jobs posted by run_on_game_thread. Cheap when idle.
    void on_frame();

    // Extra HTTP endpoints. `path` must start with '/'. Re-registering a path replaces it.
    // Handlers run on the server thread; use run_on_game_thread for anything touching host state.
    using route_handler = std::function<std::string(const http::request&, int& out_status)>;
    void register_route(const std::string& path, route_handler handler, const std::string& description = "");
    void unregister_route(const std::string& path);

    // Library logging helper; forwards to host_config::log when set.
    void log(log_level level, const std::string& message);
}
