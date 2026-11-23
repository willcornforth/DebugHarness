#include "harness.hpp"

#include "debug_harness/expr.hpp"
#include "debug_harness/harness.hpp"
#include "debug_harness/live.hpp"
#include "debug_harness/scan.hpp"
#include "internal/route_registry.hpp"

#include <Windows.h>

#include <string>
#include <vector>

namespace {
    struct config_reset {
        ~config_reset() { debug_harness::configure({}); }
    };

    std::string handler(const char* tag, const debug_harness::http::request&, int& out_status) {
        out_status = 200;
        return tag;
    }
}

TEST(host_base_root_resolves_to_the_module_base) {
    debug_harness::configure({});
    const auto result = debug_harness::expr::evaluate("@base", debug_harness::live::env());
    CHECK(result.ok);
    CHECK_EQ(result.address, reinterpret_cast<uint64_t>(GetModuleHandleA(nullptr)));
    CHECK(result.steps[0].note.find("debug_harness_tests") != std::string::npos);
}

TEST(host_base_wins_over_a_host_root_of_the_same_name) {
    config_reset reset;
    debug_harness::host_config config;
    config.resolve_root = [](const std::string&, uint64_t& out_value, std::string& out_note) {
        out_value = 0xBAD;
        out_note = "host";
        return true;
    };
    config.enumerate_roots = [] { return std::vector<debug_harness::root_entry>{{"base", 0xBAD, true, "host"}}; };
    debug_harness::configure(std::move(config));

    uint64_t value = 0;
    std::string note;
    CHECK(debug_harness::live::env().root("base", value, note));
    CHECK_EQ(value, reinterpret_cast<uint64_t>(GetModuleHandleA(nullptr)));
    CHECK_EQ(debug_harness::live::roots().size(), static_cast<size_t>(1));
}

TEST(host_module_name_selects_the_module) {
    config_reset reset;
    debug_harness::host_config config;
    config.module_name = "kernel32.dll";
    debug_harness::configure(std::move(config));

    const auto kernel32 = reinterpret_cast<uint64_t>(GetModuleHandleA("kernel32.dll"));
    CHECK(kernel32 != 0);
    CHECK_EQ(debug_harness::live::module_base(), kernel32);
    CHECK_EQ(debug_harness::live::env().module_base(), kernel32);

    const auto rva = debug_harness::expr::evaluate("rva:0x1000", debug_harness::live::env());
    CHECK(rva.ok);
    CHECK_EQ(rva.address, kernel32 + 0x1000);

    uintptr_t base = 0;
    size_t size = 0;
    CHECK(debug_harness::scan::module_range(base, size));
    CHECK_EQ(static_cast<uint64_t>(base), kernel32);

    // Every PE image starts with the DOS "MZ" magic, so a scan of the configured
    // module finds it at the very base.
    CHECK_EQ(static_cast<uint64_t>(debug_harness::scan::find_pattern("4D 5A")), kernel32);
}

TEST(host_unloaded_module_fails_cleanly) {
    config_reset reset;
    debug_harness::host_config config;
    config.module_name = "definitely_not_loaded_module.dll";
    debug_harness::configure(std::move(config));

    CHECK_EQ(debug_harness::live::module_base(), static_cast<uint64_t>(0));
    uint64_t value = 0;
    std::string note;
    CHECK(!debug_harness::live::env().root("base", value, note));
    CHECK(!note.empty());

    uintptr_t base = 0;
    size_t size = 0;
    CHECK(!debug_harness::scan::module_range(base, size));
    CHECK_EQ(debug_harness::scan::find_pattern("4D 5A"), static_cast<uintptr_t>(0));
}

TEST(host_resolve_root_and_symbol_are_consulted) {
    config_reset reset;
    std::vector<std::string> root_calls;
    std::vector<std::string> symbol_calls;
    uint64_t target = 0x1122334455667788ull;

    debug_harness::host_config config;
    config.resolve_root = [&](const std::string& name, uint64_t& out_value, std::string& out_note) {
        root_calls.push_back(name);
        if (name != "obj") return false;
        out_value = reinterpret_cast<uint64_t>(&target) - 0x10;
        out_note = "host obj";
        return true;
    };
    config.resolve_symbol = [&](const std::string& qualified, uint64_t& out_value) {
        symbol_calls.push_back(qualified);
        if (qualified != "Obj::OFF_FIELD") return false;
        out_value = 0x10;
        return true;
    };
    debug_harness::configure(std::move(config));

    const auto result = debug_harness::expr::evaluate("@obj[+Obj::OFF_FIELD]", debug_harness::live::env());
    CHECK(result.ok);
    CHECK_EQ(result.address, target);
    CHECK_STR_EQ(result.steps[0].note, "host obj");
    CHECK_EQ(root_calls.size(), static_cast<size_t>(1));
    CHECK_STR_EQ(root_calls[0], "obj");
    CHECK_EQ(symbol_calls.size(), static_cast<size_t>(1));
    CHECK_STR_EQ(symbol_calls[0], "Obj::OFF_FIELD");

    const auto unknown = debug_harness::expr::evaluate("@nope", debug_harness::live::env());
    CHECK(!unknown.ok);
    CHECK_EQ(root_calls.size(), static_cast<size_t>(2));
}

TEST(host_unknown_root_without_a_host_fails_cleanly) {
    debug_harness::configure({});
    const auto result = debug_harness::expr::evaluate("@local.player[+0x10]", debug_harness::live::env());
    CHECK(!result.ok);
    CHECK(result.error.find("unknown root") != std::string::npos);
    CHECK(result.steps.empty());

    const auto symbol = debug_harness::expr::evaluate("@base+Obj::OFF_FIELD", debug_harness::live::env());
    CHECK(!symbol.ok);
    CHECK(symbol.error.find("unknown offset name") != std::string::npos);
}

TEST(host_log_forwards_to_the_host_sink_and_is_a_noop_without_one) {
    config_reset reset;
    debug_harness::configure({});
    debug_harness::log(debug_harness::log_level::info, "dropped"); // must not crash

    std::vector<std::string> seen;
    debug_harness::log_level last_level = debug_harness::log_level::debug;
    debug_harness::host_config config;
    config.log = [&](debug_harness::log_level level, const std::string& text) {
        last_level = level;
        seen.push_back(text);
    };
    debug_harness::configure(std::move(config));
    debug_harness::log(debug_harness::log_level::warning, "hello");
    CHECK_EQ(seen.size(), static_cast<size_t>(1));
    CHECK_STR_EQ(seen[0], "hello");
    CHECK(last_level == debug_harness::log_level::warning);
}

TEST(host_on_frame_is_safe_to_call_when_idle) {
    debug_harness::on_frame();
    debug_harness::on_frame();
}

TEST(host_route_registry_register_replace_unregister_list) {
    debug_harness::register_route("/zeta", [](const debug_harness::http::request& r, int& s) { return handler("z1", r, s); },
                                "first zeta");
    debug_harness::register_route("/alpha", [](const debug_harness::http::request& r, int& s) { return handler("a", r, s); });

    debug_harness::http::request request;
    int status = 0;
    debug_harness::route_handler found;
    CHECK(debug_harness::detail::find_route("/zeta", found));
    CHECK_STR_EQ(found(request, status), "z1");
    CHECK_EQ(status, 200);

    // Re-registering replaces handler and description.
    debug_harness::register_route("/zeta", [](const debug_harness::http::request& r, int& s) { return handler("z2", r, s); },
                                "second zeta");
    CHECK(debug_harness::detail::find_route("/zeta", found));
    CHECK_STR_EQ(found(request, status), "z2");

    auto listed = debug_harness::detail::list_routes();
    CHECK_EQ(listed.size(), static_cast<size_t>(2));
    CHECK_STR_EQ(listed[0].first, "/alpha"); // sorted by path
    CHECK_STR_EQ(listed[0].second, "");
    CHECK_STR_EQ(listed[1].first, "/zeta");
    CHECK_STR_EQ(listed[1].second, "second zeta");

    debug_harness::unregister_route("/zeta");
    CHECK(!debug_harness::detail::find_route("/zeta", found));
    debug_harness::unregister_route("/never-registered"); // harmless
    listed = debug_harness::detail::list_routes();
    CHECK_EQ(listed.size(), static_cast<size_t>(1));

    debug_harness::unregister_route("/alpha");
    CHECK(debug_harness::detail::list_routes().empty());
}

TEST(host_route_registry_rejects_bad_paths_and_null_handlers) {
    debug_harness::register_route("nope", [](const debug_harness::http::request& r, int& s) { return handler("x", r, s); });
    debug_harness::register_route("", [](const debug_harness::http::request& r, int& s) { return handler("x", r, s); });
    debug_harness::register_route("/null", debug_harness::route_handler{});
    CHECK(debug_harness::detail::list_routes().empty());
}
