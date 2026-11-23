#include "harness.hpp"

#include "debug_harness/harness.hpp"
#include "debug_harness/http.hpp"
#include "debug_harness/mem.hpp"
#include "debug_harness/routes.hpp"

#include <Windows.h>

#include <format>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

    struct config_reset {
        ~config_reset() { debug_harness::configure({}); }
    };

    struct route_guard {
        std::string path;
        ~route_guard() { debug_harness::unregister_route(path); }
    };

    bool contains(const std::string& haystack, const std::string& needle) {
        return haystack.find(needle) != std::string::npos;
    }

    // Dispatch a raw request line the way the server would: parse, then route.
    std::string call(const std::string& method_and_target, int& out_status) {
        debug_harness::http::request request;
        std::string error;
        const std::string raw = method_and_target + " HTTP/1.0\r\n\r\n";
        if (!debug_harness::http::parse_request(raw, request, error))
            ::host_test::fail(__FILE__, __LINE__, "parse_request failed: " + error);
        return debug_harness::routes::dispatch(request, out_status);
    }
}

TEST(routes_ping_answers_ok) {
    debug_harness::configure({});
    int status = 0;
    const auto body = call("GET /ping", status);
    CHECK_EQ(status, 200);
    CHECK(contains(body, "\"ok\":true"));
    CHECK(contains(body, std::format("\"base\":\"0x{:X}\"", reinterpret_cast<uint64_t>(GetModuleHandleA(nullptr)))));
    CHECK(contains(body, "\"writesArmed\":false"));
}

TEST(routes_unknown_path_is_404_with_an_error_body) {
    int status = 0;
    const auto body = call("GET /nope", status);
    CHECK_EQ(status, 404);
    CHECK_STR_EQ(body, debug_harness::routes::error_body("no such endpoint: /nope"));
}

TEST(routes_error_body_is_ok_false_with_the_message) {
    CHECK_STR_EQ(debug_harness::routes::error_body("bad \"x\""), "{\"ok\":false,\"error\":\"bad \\\"x\\\"\"}");
}

TEST(routes_listing_includes_built_ins_and_registered_routes) {
    route_guard guard{"/test.listed"};
    debug_harness::register_route(
        guard.path, [](const debug_harness::http::request&, int&) { return std::string("{}"); }, "a test route");

    int status = 0;
    const auto body = call("GET /routes", status);
    CHECK_EQ(status, 200);
    CHECK(contains(body, "{\"path\":\"/ping\","));
    CHECK(contains(body, "{\"path\":\"/write\","));
    CHECK(contains(body, "{\"path\":\"/routes\","));
    CHECK(contains(body,
                   "{\"path\":\"/test.listed\",\"description\":\"a test route\",\"builtIn\":false,\"shadowed\":false}"));
    // Dropped from the library; a host re-adds them with register_route.
    CHECK(!contains(body, "\"/script\""));
    CHECK(!contains(body, "\"/camphase\""));

    const auto listed = debug_harness::routes::list();
    CHECK(listed.front().built_in);
    CHECK_STR_EQ(listed.front().path, "/ping");
    CHECK(!listed.back().built_in);
}

TEST(routes_registered_route_is_invoked_with_the_request) {
    route_guard guard{"/test.echo"};
    debug_harness::register_route(guard.path, [](const debug_harness::http::request& request, int& out_status) {
        out_status = 201;
        return "{\"echo\":\"" + request.get("v") + "\"}";
    });

    int status = 0;
    const auto body = call("GET /test.echo?v=hello", status);
    CHECK_EQ(status, 201);
    CHECK_STR_EQ(body, "{\"echo\":\"hello\"}");
}

TEST(routes_registered_route_cannot_shadow_a_built_in) {
    route_guard guard{"/ping"};
    debug_harness::register_route(guard.path, [](const debug_harness::http::request&, int&) {
        return std::string("{\"host\":true}");
    });

    int status = 0;
    const auto body = call("GET /ping", status);
    CHECK_EQ(status, 200);
    CHECK(!contains(body, "\"host\":true"));
    CHECK(contains(body, "\"writesArmed\""));

    bool found_shadowed = false;
    for (const auto& route : debug_harness::routes::list())
        if (route.path == "/ping" && !route.built_in) found_shadowed = route.shadowed;
    CHECK(found_shadowed);
    CHECK(contains(call("GET /routes", status), "\"path\":\"/ping\",\"description\":\"\",\"builtIn\":false,\"shadowed\":true"));
}

TEST(routes_handler_exception_becomes_500) {
    route_guard std_guard{"/test.throws"};
    route_guard any_guard{"/test.throws.int"};
    debug_harness::register_route(std_guard.path, [](const debug_harness::http::request&, int&) -> std::string {
        throw std::runtime_error("boom");
    });
    debug_harness::register_route(any_guard.path, [](const debug_harness::http::request&, int&) -> std::string {
        throw 42;
    });

    int status = 0;
    CHECK_STR_EQ(call("GET /test.throws", status), debug_harness::routes::error_body("handler threw: boom"));
    CHECK_EQ(status, 500);
    status = 0;
    CHECK_STR_EQ(call("GET /test.throws.int", status),
                 debug_harness::routes::error_body("handler threw an unknown exception"));
    CHECK_EQ(status, 500);
}

TEST(routes_log_without_a_host_provider_is_404) {
    debug_harness::configure({});
    int status = 0;
    const auto body = call("GET /log", status);
    CHECK_EQ(status, 404);
    CHECK_STR_EQ(body, debug_harness::routes::error_body("not provided by host"));
}

TEST(routes_log_serves_host_entries_from_since) {
    config_reset reset;
    debug_harness::host_config config;
    config.log_entries = [] {
        return std::vector<debug_harness::log_entry>{
            {5, debug_harness::log_level::info, "first", 100, ""},
            {6, debug_harness::log_level::warning, "second", 200, "at frame 0"},
            {7, debug_harness::log_level::error, "third", 300, ""},
        };
    };
    debug_harness::configure(std::move(config));

    int status = 0;
    auto body = call("GET /log", status);
    CHECK_EQ(status, 200);
    CHECK(contains(body, "\"total\":3"));
    CHECK(contains(body, "{\"index\":5,\"level\":\"INFO\",\"message\":\"first\",\"timestampMs\":100}"));
    CHECK(contains(body, "\"level\":\"WARN\",\"message\":\"second\",\"timestampMs\":200,\"trace\":\"at frame 0\""));

    body = call("GET /log?since=6", status);
    CHECK(!contains(body, "\"first\""));
    CHECK(contains(body, "\"second\""));
    CHECK(contains(body, "\"level\":\"ERROR\",\"message\":\"third\""));
}

TEST(routes_offsets_lists_and_filters_host_symbols) {
    config_reset reset;
    debug_harness::host_config config;
    config.enumerate_symbols = [] {
        return std::vector<debug_harness::symbol_entry>{
            {"Player", "OFF_HEALTH", 0x130},
            {"Player", "OFF_ARMOR", 0x138},
            {"", "GLOBAL_THING", 0x10},
        };
    };
    debug_harness::configure(std::move(config));

    int status = 0;
    auto body = call("GET /offsets", status);
    CHECK_EQ(status, 200);
    CHECK(contains(body, "{\"namespace\":\"Player\",\"name\":\"OFF_HEALTH\",\"qualified\":\"Player::OFF_HEALTH\","
                         "\"value\":\"0x130\"}"));
    CHECK(contains(body, "\"qualified\":\"GLOBAL_THING\""));
    CHECK(!contains(body, "\"note\""));

    body = call("GET /offsets?filter=Player::OFF_A", status);
    CHECK(contains(body, "OFF_ARMOR"));
    CHECK(!contains(body, "OFF_HEALTH"));
    CHECK(!contains(body, "GLOBAL_THING"));
}

TEST(routes_offsets_without_an_enumerator_is_an_empty_list_with_a_note) {
    debug_harness::configure({});
    int status = 0;
    const auto body = call("GET /offsets", status);
    CHECK_EQ(status, 200);
    CHECK(contains(body, "\"ok\":true"));
    CHECK(contains(body, "\"offsets\":[]"));
    CHECK(contains(body, "\"note\":"));
}

TEST(routes_chain_follows_a_local_buffer) {
    debug_harness::configure({});
    static uint64_t buffer[2] = {};
    buffer[0] = reinterpret_cast<uint64_t>(&buffer[1]);
    buffer[1] = 0x1234;
    const auto head = reinterpret_cast<uint64_t>(&buffer[0]);

    int status = 0;
    const auto body = call(std::format("GET /chain?e=va:0x{:X}%5B%5D", head), status);
    CHECK_EQ(status, 200);
    CHECK(contains(body, "\"ok\":true"));
    CHECK(contains(body, std::format("\"result\":\"0x{:X}\"", buffer[0])));
    CHECK(contains(body, "\"steps\":["));
    CHECK(contains(body, "\"deref\":true"));
}

TEST(routes_broken_chain_keeps_its_trace) {
    int status = 0;
    const auto body = call("GET /chain?e=va:0x1000%5B%5D", status);
    CHECK_EQ(status, 200);
    CHECK(contains(body, "\"ok\":false"));
    CHECK(contains(body, "\"result\":null"));
    CHECK(contains(body, "\"steps\":[{"));
}

TEST(routes_read_interprets_a_local_value) {
    static uint32_t value = 0xDEADBEEF;
    int status = 0;
    const auto body = call(std::format("GET /read?e=va:0x{:X}&as=u32&n=4", reinterpret_cast<uint64_t>(&value)), status);
    CHECK_EQ(status, 200);
    CHECK(contains(body, "\"read\":true"));
    CHECK(contains(body, "\"hex\":\"EF BE AD DE\""));
    CHECK(contains(body, std::format("\"value\":{}", value)));
}

TEST(routes_missing_parameter_is_400) {
    int status = 0;
    const auto body = call("GET /addr", status);
    CHECK_EQ(status, 400);
    CHECK_STR_EQ(body, debug_harness::routes::error_body("missing required parameter 'e'"));
}

TEST(routes_scan_finds_the_pe_header_at_the_module_base) {
    debug_harness::configure({});
    int status = 0;
    const auto body = call("GET /scan?p=4D+5A+90+00", status);
    CHECK_EQ(status, 200);
    CHECK(contains(body, std::format("\"va\":\"0x{:X}\"", reinterpret_cast<uint64_t>(GetModuleHandleA(nullptr)))));
    CHECK(contains(body, "\"rva\":\"0x0\""));
}

TEST(routes_write_is_refused_while_disarmed_and_on_get) {
    debug_harness::mem::arm_writes(false);
    int status = 0;
    CHECK_STR_EQ(call("GET /write?e=@base&v=00", status), debug_harness::routes::error_body("/write requires POST"));
    CHECK_EQ(status, 400);
    call("POST /write?e=@base&v=00", status);
    CHECK_EQ(status, 403);
}
